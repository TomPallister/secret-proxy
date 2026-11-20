"""Proxy-owned GitHub CLI (gh) login. Offline: fake GitHub endpoints only."""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mitmproxy import http

import addon
import client
import copilotcreds
import entry
import ghclicreds
import manage
from ghclicreds import GhCliAuthError, GhCliCredentials
from githubdevice import GitHubDeviceError
from secretstore import SecretManifest
from test_copilotcreds import Clock

REF = "secre" + "tref:"
REFERENCE = REF + ghclicreds.CANONICAL
GH_TOKEN = "gho_" + "clifixture" * 4
EXAMPLE = Path(addon.__file__).parent / "examples" / "github-manifest.json"


class FakeGitHub:
    def __init__(self):
        self.calls = []

    def __call__(self, url, *, method="GET", fields=None, headers=None, label="GitHub"):
        self.calls.append((method, url, dict(fields or {})))
        if url.endswith("/login/device/code"):
            return 200, {"device_code": "cli-device-code", "user_code": "WXYZ-9876", "interval": 5,
                         "verification_uri": "https://github.com/login/device", "expires_in": 900}
        if url.endswith("/login/oauth/access_token"):
            return 200, {"access_token": GH_TOKEN, "token_type": "bearer", "scope": "gist,read:org,repo"}
        raise AssertionError("unexpected URL")


def load(data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "manifest.json"
        path.write_text(json.dumps(data))
        return SecretManifest.load(path)


def full_access_manifest():
    """The documented read/write example: API writes, uploads and Git over HTTPS."""
    data = json.loads(EXAMPLE.read_text())
    data["secrets"][ghclicreds.CANONICAL]["placements"] = [
        {"kind": "header", "hosts": ["api.github.com", "uploads.github.com"], "name": "authorization",
         "template": "token {secret}"},
        {"kind": "basic-password", "hosts": ["github.com"], "username": "x-access-token"},
    ]
    data["secrets"]["GITHUB_TOKEN"] = {"placements": [{"kind": "header", "hosts": ["api.github.com"],
                                       "name": "authorization", "template": "Bearer {secret}", "methods": ["GET"]}]}
    return load(data)


class GhCliCredentialTests(unittest.TestCase):
    def test_device_login_uses_the_gh_client_id_and_scopes(self):
        fake, clock = FakeGitHub(), Clock()
        provider = GhCliCredentials(request=fake, clock=clock, sleep=clock.sleep)
        self.assertEqual(provider.status(), {"loggedIn": False, "scopes": []})
        with self.assertRaisesRegex(GhCliAuthError, "login required"):
            provider.get_token()
        self.assertEqual(provider.start()["userCode"], "WXYZ-9876")
        self.assertEqual(provider.poll(), {"scopes": ["gist", "read:org", "repo"]})
        self.assertEqual(fake.calls[0][2], {"client_id": ghclicreds.CLIENT_ID, "scope": "repo read:org gist"})
        self.assertEqual(fake.calls[1][2]["client_id"], ghclicreds.CLIENT_ID)
        self.assertEqual(provider.get_token(), GH_TOKEN)
        self.assertEqual(provider.status(), {"loggedIn": True, "scopes": ["gist", "read:org", "repo"]})
        self.assertNotIn(GH_TOKEN, json.dumps(provider.status()))
        with self.assertRaisesRegex(GhCliAuthError, "login required"):
            GhCliCredentials().get_token()  # a restarted proxy holds nothing

    def test_configured_scopes_and_domain(self):
        fake, clock = FakeGitHub(), Clock()
        provider = GhCliCredentials(domain="github.example.com", scopes=("repo",), request=fake,
                                    clock=clock, sleep=clock.sleep)
        with self.assertRaises(GitHubDeviceError):
            provider.start()  # verification URL is not on the configured domain
        self.assertEqual(fake.calls[0][1], "https://github.example.com/login/device/code")
        self.assertEqual(fake.calls[0][2]["scope"], "repo")


class GhCliManifestTests(unittest.TestCase):
    def base(self):
        return json.loads(EXAMPLE.read_text())

    def test_settings_and_defaults(self):
        self.assertEqual(load(self.base()).github_login("cli"),
                         {"domain": "github.com", "scopes": ("repo", "read:org", "gist")})
        data = self.base()
        del data["githubLogins"]["cli"]
        self.assertEqual(load(data).github_login("cli")["scopes"], ("repo", "read:org", "gist"))
        data["githubLogins"]["cli"] = {"scopes": ["repo", "workflow"]}
        self.assertEqual(load(data).github_login("cli")["scopes"], ("repo", "workflow"))

    def test_invalid_settings_fail_to_load(self):
        for scopes in ([], ["repo", "repo"], ["Repo"], ["repo scope"], "repo", [1]):
            data = self.base()
            data["githubLogins"]["cli"]["scopes"] = scopes
            with self.subTest(scopes=scopes), self.assertRaises(ValueError):
                load(data)
        data = self.base()
        del data["secrets"][ghclicreds.CANONICAL]["runtimeOnly"]
        with self.assertRaisesRegex(ValueError, "requires runtimeOnly"):
            load(data)

    def test_cli_only_manifest_intercepts_the_login_host(self):
        data = self.base()
        del data["githubLogins"]["copilot"]
        del data["secrets"][copilotcreds.CANONICAL]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(data))
            with patch.object(entry.addon, "SECRETS_FILE", path), \
                    patch.object(entry.addon, "AWS_OKTA_FILE", Path("/nonexistent/aws-okta.json")):
                patterns = entry._allow_hosts()
        self.assertIn(entry._host_pattern("github.com"), patterns)
        self.assertNotIn(entry._host_pattern("api.*.githubcopilot.com"), patterns)


class GhCliAddonTests(unittest.TestCase):
    @staticmethod
    def flow(host, method, path, auth=None, body=b"", headers=None):
        request = http.Request.make(method, "https://" + host + path, content=body, headers=headers or {})
        if auth:
            request.headers["Authorization"] = auth
        flow = http.HTTPFlow(None, None)
        flow.request = request
        return flow

    def use(self, manifest):
        class Resolver:
            def get(self, name):
                if name == "GITHUB_TOKEN":
                    return "vault-github-token"
                raise AssertionError("must not read the vault: " + name)
        self.clock = Clock()
        self.fake = FakeGitHub()
        self.generation = addon._StoreGeneration(manifest, Resolver(), addon._ProviderState())
        self.generation.providers.github["cli"] = GhCliCredentials(
            request=self.fake, clock=self.clock, sleep=self.clock.sleep)
        patcher = patch.object(addon, "_capture_generation", return_value=self.generation)
        patcher.start()
        self.addCleanup(patcher.stop)

    def setUp(self):
        self.use(SecretManifest.load(EXAMPLE))

    def send(self, flow):
        addon.requestheaders(flow)
        addon.request(flow)
        return flow

    def login(self):
        start = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github/start"))
        self.assertEqual(json.loads(start.response.content)["userCode"], "WXYZ-9876")
        done = self.send(self.flow(addon.SENTINEL_HOST, "POST", "/github/poll"))
        self.assertEqual(json.loads(done.response.content), {"status": "complete", "scopes": ["gist", "read:org", "repo"]})
        self.assertNotIn(GH_TOKEN.encode(), done.response.content)

    def test_status_route(self):
        with patch.dict(os.environ, {"SECRET_PROXY_INSTANCE_ID": "b" * 32}):
            before = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github/status"))
            self.assertEqual(json.loads(before.response.content), {"instance": "b" * 32, "loggedIn": False, "scopes": []})
            self.login()
            after = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github/status"))
            self.assertEqual(json.loads(after.response.content)["loggedIn"], True)
            self.assertNotIn(GH_TOKEN.encode(), after.response.content)

    def test_read_only_example_injects_only_reads_on_the_api(self):
        self.login()
        for template in ("token ", "Bearer "):
            read = self.send(self.flow("api.github.com", "GET", "/user", template + REFERENCE))
            self.assertIsNone(read.response)
            self.assertEqual(read.request.headers["authorization"], template + GH_TOKEN)
        for flow in (self.flow("api.github.com", "POST", "/graphql", "token " + REFERENCE, b"{}"),
                     self.flow("evil.example", "GET", "/user", "token " + REFERENCE),
                     self.flow("api.github.com", "GET", "/user", "x " + REFERENCE)):
            refused = self.send(flow)
            self.assertEqual(refused.response.status_code, 403)
            self.assertNotIn(GH_TOKEN, refused.request.headers["authorization"])

    def test_documented_full_access_example_covers_writes_and_git(self):
        self.use(full_access_manifest())
        self.login()
        write = self.send(self.flow("api.github.com", "POST", "/graphql", "token " + REFERENCE, b"{}"))
        self.assertIsNone(write.response)
        self.assertEqual(write.request.headers["authorization"], "token " + GH_TOKEN)
        basic = "Basic " + base64.b64encode(("x-access-token:" + REFERENCE).encode()).decode()
        push = self.send(self.flow("github.com", "POST", "/example/repo.git/git-receive-pack", basic, b"pack"))
        self.assertIsNone(push.response)
        self.assertEqual(base64.b64decode(push.request.headers["authorization"][6:]).decode(),
                         "x-access-token:" + GH_TOKEN)
        elsewhere = self.send(self.flow("gitlab.example.com", "GET", "/example/repo.git/info/refs", basic))
        self.assertEqual(elsewhere.response.status_code, 403)
        # The existing vault-stored GITHUB_TOKEN path is unchanged.
        vault = self.send(self.flow("api.github.com", "GET", "/user", "Bearer " + REF + "GITHUB_TOKEN"))
        self.assertIsNone(vault.response)
        self.assertEqual(vault.request.headers["authorization"], "Bearer vault-github-token")

    def test_gh_own_login_is_refused(self):
        bodies = (b"client_id=" + ghclicreds.CLIENT_ID.encode() + b"&scope=repo+read%3Aorg+gist",
                  b"client_id=" + ghclicreds.CLIENT_ID.encode() + b"&device_code=x&grant_type=device")
        for path, body in zip(("/login/device/code", "/login/oauth/access_token"), bodies):
            refused = self.send(self.flow("github.com", "POST", path, body=body,
                                          headers={"content-type": "application/x-www-form-urlencoded"}))
            self.assertEqual(refused.response.status_code, 403)
            self.assertEqual(json.loads(refused.response.content), {"error": "use_gh_login"})
        copilot = self.send(self.flow("github.com", "POST", "/login/device/code",
                                      body=b"client_id=" + copilotcreds.CLIENT_ID.encode(),
                                      headers={"content-type": "application/x-www-form-urlencoded"}))
        self.assertEqual(json.loads(copilot.response.content), {"error": "use_github_copilot_login"})
        self.assertEqual(self.fake.calls, [])

    def test_encoded_own_logins_are_refused_without_upstream_calls(self):
        for client_id, error in ((ghclicreds.CLIENT_ID, "use_gh_login"),
                                  (copilotcreds.CLIENT_ID, "use_github_copilot_login")):
            percent = "".join("%%%02x" % ord(char) for char in client_id)
            escaped = "".join("\\u%04x" % ord(char) for char in client_id)
            form = ("client_id=" + percent).encode()
            encoded_json = ('{"client_id":"' + escaped + '"}').encode()
            for endpoint in ("/login/device/code", "/login/oauth/access_token"):
                cases = [
                    (endpoint, form, {"content-type": "application/x-www-form-urlencoded"}),
                    (endpoint + "?client_id=" + percent, b"", {}),
                    (endpoint, encoded_json, {"content-type": "application/json"}),
                    # Request.make encodes content according to these headers.
                    (endpoint, form,
                     {"content-type": "application/x-www-form-urlencoded", "content-encoding": "gzip"}),
                    (endpoint, encoded_json,
                     {"content-type": "application/json", "content-encoding": "gzip"}),
                ]
                for path, body, headers in cases:
                    with self.subTest(client=client_id, path=path, headers=headers):
                        flow = self.flow("github.com", "POST", path, body=body, headers=headers)
                        self.assertEqual(flow.request.get_content(), body)
                        if headers.get("content-encoding") == "gzip":
                            self.assertNotEqual(flow.request.raw_content, body)
                        self.send(flow)
                        self.assertIsNotNone(flow.response, "encoded login must not reach GitHub")
                        self.assertEqual(flow.response.status_code, 403)
                        self.assertEqual(json.loads(flow.response.content), {"error": error})
        self.assertEqual(self.fake.calls, [])

    def test_logged_out_reference_fails_closed(self):
        request = self.send(self.flow("api.github.com", "GET", "/user", "token " + REFERENCE))
        self.assertEqual(request.response.status_code, 502)
        self.assertEqual(json.loads(request.response.content)["error"], "secret_proxy_injection_failed")

    def test_disabled_login_is_not_available(self):
        self.use(SecretManifest.load(Path(addon.__file__).parent / "examples" / "manifest.json"))
        route = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github/start"))
        self.assertEqual(route.response.status_code, 403)
        own = self.send(self.flow("github.com", "POST", "/login/device/code",
                                  body=b"client_id=" + ghclicreds.CLIENT_ID.encode(),
                                  headers={"content-type": "application/x-www-form-urlencoded"}))
        self.assertIsNone(own.response)


class GhCliClientTests(unittest.TestCase):
    def test_gh_token_variables_must_be_references(self):
        for key in client.GH_TOKEN_VARIABLES:
            client.validate_config({"sharedDir": "/unused", "port": 10260, "environment": {key: REFERENCE}})
            for value in ("gho_real", REFERENCE + " extra", "Bearer " + REFERENCE, ""):
                with self.subTest(key=key, value=value), self.assertRaises(client.ClientError):
                    client.validate_config({"sharedDir": "/unused", "port": 10260, "environment": {key: value}})

    def test_github_auth_status_fields(self):
        settings = {"instance": "candidate", "bootstrap": "/private/example/bootstrap.json", "op": "/opt/example/op"}
        status = {"instance": "a" * 32, "loggedIn": True, "scopes": ["repo"]}
        proxy = Mock()
        proxy.call.return_value = status
        ready = json.dumps({"status": "ready", "instance": "a" * 32}).encode()
        with patch.object(manage, "selected_client", return_value=proxy), \
                patch.object(manage, "private_read", return_value=ready), contextlib.redirect_stdout(io.StringIO()) as out:
            manage.execute(settings, "auth-status", provider="github")
            self.assertEqual(json.loads(out.getvalue()), status)
            proxy.call.assert_called_once_with("/github/status")
            for change in ({"scopes": "repo"}, {"scopes": ["bad scope"]}, {"token": "x"}):
                proxy.call.return_value = {**status, **change}
                with self.subTest(change=change), self.assertRaises(manage.ClientError):
                    manage.execute(settings, "auth-status", provider="github")


if __name__ == "__main__":
    unittest.main()
