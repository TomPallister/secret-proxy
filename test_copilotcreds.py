"""Proxy-owned GitHub Copilot login. Offline: fake GitHub endpoints only."""
import json
import os
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mitmproxy import http

import addon
import copilotcreds
import entry
import githubdevice
from copilotcreds import CopilotAuthError, CopilotCredentials
from githubdevice import DeviceFlow, GitHubDeviceError
from secretstore import SecretManifest

REF = "secre" + "tref:"
REFERENCE = REF + copilotcreds.CANONICAL
GITHUB_TOKEN = "gho_" + "fixture" * 6
EXAMPLE = Path(addon.__file__).parent / "examples" / "github-manifest.json"


def copilot_token(exp, endpoint="proxy.individual.githubcopilot.com", tid="fixture-tid"):
    return f"tid={tid};exp={exp};sku=fixture_seat;proxy-ep={endpoint};st=dotcom:" + "f" * 64


class FakeGitHub:
    """Scripted GitHub: records every call, never touches the network."""

    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.polls = []
        self.exchanges = 0
        self.exchange_status = 200
        self.endpoint = "proxy.individual.githubcopilot.com"
        self.models = {"data": [
            {"id": "model-a", "model_picker_enabled": True, "policy": {"state": "enabled"}},
            {"id": "model-b", "model_picker_enabled": False},
            {"id": "model-c", "model_picker_enabled": True, "capabilities": {"supports": {"tool_calls": False}}},
        ]}
        self.device = {"device_code": "device-code-fixture", "user_code": "ABCD-1234",
                       "verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 5}
        self.exchange_delay = 0

    def __call__(self, url, *, method="GET", fields=None, headers=None, label="GitHub"):
        self.calls.append((method, url, dict(fields or {}), dict(headers or {})))
        if url.endswith("/login/device/code"):
            return 200, dict(self.device)
        if url.endswith("/login/oauth/access_token"):
            answer = self.polls.pop(0) if self.polls else {"error": "authorization_pending"}
            return 200, answer
        if url.endswith(copilotcreds.EXCHANGE_PATH):
            assert headers["Authorization"] == "Bearer " + GITHUB_TOKEN
            if self.exchange_delay:
                time.sleep(self.exchange_delay)
            self.exchanges += 1
            if self.exchange_status != 200:
                return self.exchange_status, {"message": "fixture failure " + GITHUB_TOKEN}
            exp = int(self.clock()) + 1800
            return 200, {"token": copilot_token(exp, self.endpoint), "expires_at": exp, "refresh_in": 1500}
        if url.endswith("/models"):
            return 200, self.models
        raise AssertionError("unexpected URL")


class Clock:
    def __init__(self):
        self.now = 1_000_000.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def credentials(clock=None, fake=None, domain="github.com"):
    clock = clock or Clock()
    fake = fake or FakeGitHub(clock)
    return CopilotCredentials(domain=domain, request=fake, clock=clock, sleep=clock.sleep), fake, clock


def logged_in(clock=None, fake=None):
    provider, fake, clock = credentials(clock, fake)
    provider.start()
    fake.polls.append({"access_token": GITHUB_TOKEN, "token_type": "bearer", "scope": "read:user"})
    credential = provider.poll()
    return provider, fake, clock, credential


class DeviceFlowTests(unittest.TestCase):
    def flow(self, device=None):
        clock = Clock()
        fake = FakeGitHub(clock)
        if device:
            fake.device.update(device)
        return DeviceFlow(domain="github.com", client_id="Iv1.fixture", scopes=("read:user",),
                          user_agent="fixture", label="fixture", request=fake, clock=clock,
                          sleep=clock.sleep), fake, clock

    def test_start_returns_only_code_and_url(self):
        flow, fake, _clock = self.flow()
        self.assertEqual(flow.start(), {"userCode": "ABCD-1234", "verificationUri": "https://github.com/login/device",
                                        "expiresIn": 900, "interval": 5})
        self.assertEqual(fake.calls[0][2], {"client_id": "Iv1.fixture", "scope": "read:user"})

    def test_untrusted_device_responses_are_refused(self):
        for change in ({"verification_uri": "https://evil.example/login/device"},
                       {"verification_uri": "http://github.com/login/device"},
                       {"verification_uri": "javascript:alert(1)"}, {"user_code": "bad code"},
                       {"expires_in": 0}, {"expires_in": 99999}, {"interval": "5"}, {"device_code": None}):
            flow, _fake, _clock = self.flow(change)
            with self.subTest(change=change), self.assertRaises(GitHubDeviceError):
                flow.start()

    def test_poll_respects_interval_and_slow_down(self):
        flow, fake, clock = self.flow()
        flow.start()
        start = clock.now
        fake.polls += [{"error": "authorization_pending"}, {"error": "slow_down", "interval": 12},
                       {"error": "slow_down"}]
        self.assertIsNone(flow.poll())  # waits the first interval, then polls once
        self.assertEqual(clock.now - start, 5)
        self.assertIsNone(flow.poll())  # pending: next poll after 5 s
        self.assertEqual(clock.now - start, 10)
        self.assertEqual(flow.retry_after(), 12)
        self.assertIsNone(flow.poll(max_wait=10))  # 12 s exceeds max_wait: no upstream poll
        self.assertEqual(len([c for c in fake.calls if c[1].endswith("access_token")]), 2)
        self.assertIsNone(flow.poll(max_wait=20))
        self.assertEqual(flow.retry_after(), 17)  # slow_down without interval adds 5 s
        self.assertEqual([c[2]["grant_type"] for c in fake.calls if c[1].endswith("access_token")],
                         [githubdevice.DEVICE_GRANT] * 3)

    def test_expiry_denial_and_unknown_errors_end_the_login(self):
        for answer, reason in (({"error": "access_denied"}, "access_denied"),
                               ({"error": "expired_token"}, "expired_token"),
                               ({"error": "bad", "error_description": "secret detail"}, "login_failed")):
            flow, fake, _clock = self.flow()
            flow.start()
            fake.polls.append(answer)
            with self.subTest(answer=answer):
                with self.assertRaises(GitHubDeviceError) as raised:
                    flow.poll()
                self.assertEqual(raised.exception.reason, reason)
                self.assertNotIn("secret detail", str(raised.exception))
                with self.assertRaises(GitHubDeviceError) as again:
                    flow.poll()
                self.assertEqual(again.exception.reason, "no_login")
        flow, fake, clock = self.flow()
        flow.start()
        clock.now += 901
        with self.assertRaises(GitHubDeviceError) as raised:
            flow.poll()
        self.assertEqual(raised.exception.reason, "expired_token")
        self.assertFalse([c for c in fake.calls if c[1].endswith("access_token")])

    def test_request_errors_never_echo_upstream_content(self):
        with patch.object(githubdevice.urllib.request, "urlopen", side_effect=RuntimeError(GITHUB_TOKEN)):
            with self.assertRaises(GitHubDeviceError) as raised:
                githubdevice.request_json("https://github.com/login/device/code", method="POST", fields={})
        self.assertNotIn(GITHUB_TOKEN, str(raised.exception))
        self.assertEqual(raised.exception.reason, "unavailable")


class CopilotCredentialTests(unittest.TestCase):
    def test_login_returns_sealed_entry_with_real_exp_and_proxy_ep(self):
        provider, fake, clock, credential = logged_in()
        exp = int(clock.now) + 1800
        self.assertEqual(credential, {
            "type": "oauth", "refresh": REFERENCE,
            "access": f"tid={REFERENCE};exp={exp};proxy-ep=proxy.individual.githubcopilot.com",
            "expires": exp * 1000 - 300000, "availableModelIds": ["model-a"]})
        text = json.dumps(credential)
        for secret in (GITHUB_TOKEN, "fixture-tid", "f" * 64):
            self.assertNotIn(secret, text)
        self.assertEqual(copilotcreds.unseal("Bearer " + credential["access"]), "Bearer " + REFERENCE)
        self.assertEqual(provider.api_host(), "api.individual.githubcopilot.com")
        self.assertEqual(provider.get_token(), copilot_token(exp))
        # The device flow used the Copilot client ID and Pi's scope.
        self.assertEqual(fake.calls[0][2], {"client_id": copilotcreds.CLIENT_ID, "scope": "read:user"})
        self.assertEqual(fake.calls[2][3]["Copilot-Integration-Id"], "vscode-chat")

    def test_status_is_credential_free(self):
        provider, _fake, clock = credentials()
        self.assertEqual(provider.status(), {"loggedIn": False, "expiresAt": None, "refreshCount": 0, "lastRefreshAt": None})
        provider, _fake, clock, _credential = logged_in()
        status = provider.status()
        self.assertEqual(status, {"loggedIn": True, "expiresAt": int(clock.now) + 1800, "refreshCount": 0, "lastRefreshAt": None})
        self.assertNotIn(GITHUB_TOKEN, json.dumps(status))

    def test_refreshes_before_refresh_in_without_client_action(self):
        provider, fake, clock, _credential = logged_in()
        first = provider.get_token()
        clock.now += 1499
        self.assertEqual(provider.get_token(), first)
        self.assertEqual(fake.exchanges, 1)
        clock.now += 1
        second = provider.get_token()
        self.assertNotEqual(second, first)
        self.assertEqual(fake.exchanges, 2)
        self.assertEqual(provider.status()["refreshCount"], 1)
        self.assertEqual(provider.status()["lastRefreshAt"], int(clock.now))

    def test_concurrent_requests_during_refresh_make_one_exchange(self):
        provider, fake, clock, _credential = logged_in()
        clock.now += 1600
        fake.exchange_delay = 0.05
        results, barrier = [], threading.Barrier(12)

        def worker():
            barrier.wait()
            results.append(provider.get_token())
        threads = [threading.Thread(target=worker) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(fake.exchanges, 2)  # login + exactly one refresh
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(len(results), 12)

    def test_failed_refresh_keeps_a_valid_token_then_fails_closed(self):
        provider, fake, clock, _credential = logged_in()
        first = provider.get_token()
        clock.now += 1600
        fake.exchange_status = 500
        self.assertEqual(provider.get_token(), first)  # still valid for ~200 s
        self.assertEqual(provider.get_token(), first)  # backoff: no second exchange
        self.assertEqual(fake.exchanges, 2)
        clock.now += 200
        with self.assertRaises(CopilotAuthError):
            provider.get_token()

    def test_revoked_github_token_logs_out(self):
        provider, fake, clock, _credential = logged_in()
        clock.now += 1790
        fake.exchange_status = 401
        with self.assertRaises(CopilotAuthError):
            provider.get_token()
        self.assertFalse(provider.status()["loggedIn"])
        with self.assertRaisesRegex(CopilotAuthError, "login required"):
            provider.get_token()

    def test_no_copilot_subscription_fails_login(self):
        clock = Clock()
        fake = FakeGitHub(clock)
        fake.exchange_status = 404
        provider, _fake, _clock = credentials(clock, fake)
        provider.start()
        fake.polls.append({"access_token": GITHUB_TOKEN})
        with self.assertRaises(GitHubDeviceError) as raised:
            provider.poll()
        self.assertEqual(raised.exception.reason, "unavailable")
        self.assertFalse(provider.status()["loggedIn"])

    def test_restart_requires_login(self):
        with self.assertRaisesRegex(CopilotAuthError, "login required"):
            CopilotCredentials().get_token()

    def test_enterprise_domain_endpoints(self):
        clock = Clock()
        fake = FakeGitHub(clock)
        fake.device["verification_uri"] = "https://github.example.com/login/device"
        fake.endpoint = "proxy.enterprise.githubcopilot.com"
        provider, _fake, _clock = credentials(clock, fake, domain="github.example.com")
        provider.start()
        fake.polls.append({"access_token": GITHUB_TOKEN})
        credential = provider.poll()
        self.assertEqual(credential["enterpriseUrl"], "github.example.com")
        self.assertEqual([c[1] for c in fake.calls[:3]], [
            "https://github.example.com/login/device/code",
            "https://github.example.com/login/oauth/access_token",
            "https://api.github.example.com" + copilotcreds.EXCHANGE_PATH])
        self.assertEqual(provider.api_host(), "api.enterprise.githubcopilot.com")

    def test_token_field_parsing_and_sealing(self):
        self.assertEqual(copilotcreds.token_fields(copilot_token(123)), (123, "proxy.individual.githubcopilot.com"))
        self.assertEqual(copilotcreds.api_host("proxy.business.githubcopilot.com"), "api.business.githubcopilot.com")
        self.assertEqual(copilotcreds.api_host(None), "api.individual.githubcopilot.com")
        self.assertEqual(copilotcreds.api_host(None, "github.example.com"), "copilot-api.github.example.com")
        with self.assertRaises(CopilotAuthError):
            copilotcreds.token_fields("tid=x;exp=1;proxy-ep=bad_host!")
        sealed = copilotcreds.seal(123, None)
        self.assertTrue(copilotcreds.is_sealed(sealed))
        self.assertEqual(copilotcreds.unseal("Bearer " + sealed), "Bearer " + REFERENCE)
        for value in ("Bearer " + copilot_token(1), "tid=" + REFERENCE + ";exp=1;proxy-ep=x.example;extra=1",
                      "xtid=" + REFERENCE + ";exp=1"):
            self.assertEqual(copilotcreds.unseal(value), value)


class CopilotAddonTests(unittest.TestCase):
    @staticmethod
    def flow(host, method, path, auth=None, body=b"", headers=None):
        request = http.Request.make(method, "https://" + host + path, content=body, headers=headers or {})
        if auth:
            request.headers["Authorization"] = auth
        flow = http.HTTPFlow(None, None)
        flow.request = request
        return flow

    def setUp(self):
        manifest = SecretManifest.load(EXAMPLE)

        class Resolver:
            def get(self, name):
                raise AssertionError("must not read the vault: " + name)
        self.clock = Clock()
        self.fake = FakeGitHub(self.clock)
        self.generation = addon._StoreGeneration(manifest, Resolver(), addon._ProviderState())
        self.generation.providers.github["copilot"] = CopilotCredentials(
            request=self.fake, clock=self.clock, sleep=self.clock.sleep)
        self.patch = patch.object(addon, "_capture_generation", return_value=self.generation)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def send(self, flow):
        addon.requestheaders(flow)
        addon.request(flow)
        return flow

    def login(self):
        start = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github-copilot/start"))
        self.assertEqual(start.response.status_code, 200)
        self.assertEqual(json.loads(start.response.content)["userCode"], "ABCD-1234")
        self.assertNotIn(b"device-code-fixture", start.response.content)
        pending = self.send(self.flow(addon.SENTINEL_HOST, "POST", "/github-copilot/poll"))
        self.assertEqual(json.loads(pending.response.content), {"status": "pending", "retryAfter": 5})
        self.fake.polls.append({"access_token": GITHUB_TOKEN})
        done = self.send(self.flow(addon.SENTINEL_HOST, "POST", "/github-copilot/poll"))
        body = json.loads(done.response.content)
        self.assertEqual(body["status"], "complete")
        for secret in (GITHUB_TOKEN.encode(), b"fixture-tid", b"f" * 64):
            self.assertNotIn(secret, done.response.content)
        return body["credential"]

    def test_tokens_never_reach_logs_or_responses(self):
        with self.assertLogs("secret_proxy", level="DEBUG") as captured:
            credential = self.login()
            real = self.generation.providers.github["copilot"].get_token()
            responses = [self.send(self.flow("api.individual.githubcopilot.com", "POST", "/chat/completions",
                                             "Bearer " + credential["access"], b"{}")),
                         self.send(self.flow("api.github.com", "GET", copilotcreds.EXCHANGE_PATH, "Bearer " + REFERENCE)),
                         self.send(self.flow("api.github.com", "GET", copilotcreds.EXCHANGE_PATH, "Bearer " + GITHUB_TOKEN)),
                         self.send(self.flow("evil.example", "POST", "/x", "Bearer " + credential["access"], b"{}"))]
        text = "\n".join(captured.output)
        for secret in (GITHUB_TOKEN, real, "fixture-tid", "device-code-fixture"):
            self.assertNotIn(secret, text)
            for response in responses[1:]:
                self.assertNotIn(secret.encode(), response.response.content)

    def test_login_routes_and_status(self):
        with patch.dict(os.environ, {"SECRET_PROXY_INSTANCE_ID": "a" * 32}):
            status = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github-copilot/status"))
            self.assertEqual(json.loads(status.response.content), {"instance": "a" * 32, "loggedIn": False,
                             "expiresAt": None, "refreshCount": 0, "lastRefreshAt": None})
            self.login()
            status = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github-copilot/status"))
            self.assertTrue(json.loads(status.response.content)["loggedIn"])
            self.assertEqual(status.response.headers["cache-control"], "no-store")
        wrong = self.send(self.flow(addon.SENTINEL_HOST, "POST", "/github-copilot/start"))
        self.assertEqual(wrong.response.status_code, 405)
        query = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github-copilot/status?x=1"))
        self.assertEqual(query.response.status_code, 400)

    def test_failed_poll_reports_only_a_reason(self):
        self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github-copilot/start"))
        self.fake.polls.append({"error": "access_denied", "error_description": "fixture-detail"})
        self.clock.now += 5
        failed = self.send(self.flow(addon.SENTINEL_HOST, "POST", "/github-copilot/poll"))
        self.assertEqual(json.loads(failed.response.content), {"status": "failed", "reason": "access_denied"})

    def test_sealed_entry_injects_only_into_proxy_ep_host(self):
        credential = self.login()
        real = self.generation.providers.github["copilot"].get_token()
        for path in ("/models", "/chat/completions", "/responses"):
            request = self.send(self.flow("api.individual.githubcopilot.com", "POST", path,
                                          "Bearer " + credential["access"], b"{}"))
            self.assertIsNone(request.response, path)
            self.assertEqual(request.request.headers["authorization"], "Bearer " + real)
        # Allowed by the manifest wildcard, but not the token's own proxy-ep host.
        for host in ("api.business.githubcopilot.com", "api.githubcopilot.com", "evil.example"):
            other = self.send(self.flow(host, "POST", "/chat/completions", "Bearer " + credential["access"], b"{}"))
            self.assertEqual(other.response.status_code, 403, host)
            self.assertNotIn(real.encode(), other.response.content)
            self.assertNotIn(real, other.request.headers["authorization"])
        # The refresh reference works only where the token belongs, too.
        api = self.send(self.flow("api.github.com", "GET", "/user", "Bearer " + REFERENCE))
        self.assertEqual(api.response.status_code, 403)

    def test_exchange_is_answered_in_the_proxy_with_a_sealed_token(self):
        credential = self.login()
        exchanges = self.fake.exchanges
        answer = self.send(self.flow("api.github.com", "GET", copilotcreds.EXCHANGE_PATH, "Bearer " + credential["refresh"]))
        self.assertEqual(answer.response.status_code, 200)
        body = json.loads(answer.response.content)
        self.assertEqual(body["token"], credential["access"])
        self.assertEqual(body["expires_at"], int(self.clock.now) + 1800)
        self.assertEqual(body["endpoints"], {"api": "https://api.individual.githubcopilot.com"})
        self.assertNotIn(b"fixture-tid", answer.response.content)
        self.assertEqual(self.fake.exchanges, exchanges)  # not forwarded upstream
        # Pi's refresh after expiry: the proxy refreshes and returns a new sealed token.
        self.clock.now += 1600
        later = json.loads(self.send(self.flow("api.github.com", "GET", copilotcreds.EXCHANGE_PATH,
                                               "token " + REFERENCE)).response.content)
        self.assertNotEqual(later["token"], credential["access"])
        self.assertTrue(copilotcreds.is_sealed(later["token"]))
        self.assertEqual(self.fake.exchanges, exchanges + 1)

    def test_exchange_with_a_real_or_unknown_bearer_is_refused(self):
        self.login()
        for auth in ("Bearer " + GITHUB_TOKEN, "Bearer " + REF + "OTHER", None, "Bearer " + REFERENCE + "x"):
            refused = self.send(self.flow("api.github.com", "GET", copilotcreds.EXCHANGE_PATH, auth))
            self.assertEqual(refused.response.status_code, 403, auth)
            self.assertEqual(json.loads(refused.response.content), {"error": "use_github_copilot_login"})
        post = self.send(self.flow("api.github.com", "POST", copilotcreds.EXCHANGE_PATH, "Bearer " + REFERENCE))
        self.assertEqual(post.response.status_code, 403)

    def test_client_device_flow_with_the_copilot_client_id_is_refused(self):
        client_id = copilotcreds.CLIENT_ID
        forms = [("/login/device/code", f"client_id={client_id}&scope=read%3Auser".encode(),
                  {"content-type": "application/x-www-form-urlencoded"}),
                 ("/login/oauth/access_token", json.dumps({"client_id": client_id}).encode(),
                  {"content-type": "application/json"}),
                 ("/login/oauth/access_token?client_id=" + client_id, b"", {})]
        for path, body, headers in forms:
            refused = self.send(self.flow("github.com", "POST", path, body=body, headers=headers))
            self.assertEqual(refused.response.status_code, 403, path)
            self.assertEqual(json.loads(refused.response.content), {"error": "use_github_copilot_login"})
        other = self.send(self.flow("github.com", "POST", "/login/device/code", body=b"client_id=Ov23-other",
                                    headers={"content-type": "application/x-www-form-urlencoded"}))
        self.assertIsNone(other.response)
        self.assertEqual(self.fake.calls, [])

    def test_restart_makes_the_old_sealed_entry_fail_closed(self):
        credential = self.login()
        self.generation.providers.github["copilot"] = CopilotCredentials(request=self.fake, clock=self.clock)
        request = self.send(self.flow("api.individual.githubcopilot.com", "POST", "/chat/completions",
                                      "Bearer " + credential["access"], b"{}"))
        self.assertEqual(request.response.status_code, 502)
        self.assertEqual(json.loads(request.response.content)["error"], "secret_proxy_injection_failed")
        self.assertNotIn("fixture-tid", request.request.headers["authorization"])
        exchange = self.send(self.flow("api.github.com", "GET", copilotcreds.EXCHANGE_PATH, "Bearer " + REFERENCE))
        self.assertEqual(exchange.response.status_code, 403)

    def test_disabled_integration_changes_nothing(self):
        manifest = SecretManifest.load(Path(addon.__file__).parent / "examples" / "manifest.json")
        generation = addon._StoreGeneration(manifest, self.generation.resolver, addon._ProviderState())
        with patch.object(addon, "_capture_generation", return_value=generation):
            route = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/github-copilot/start"))
            self.assertEqual(route.response.status_code, 403)
            device = self.send(self.flow("github.com", "POST", "/login/device/code",
                                         body=("client_id=" + copilotcreds.CLIENT_ID).encode(),
                                         headers={"content-type": "application/x-www-form-urlencoded"}))
            self.assertIsNone(device.response)
            exchange = self.send(self.flow("api.github.com", "GET", copilotcreds.EXCHANGE_PATH, "Bearer real"))
            self.assertIsNone(exchange.response)
        self.assertEqual(self.fake.calls, [])

    def test_a_vault_secret_with_the_same_name_is_an_ordinary_secret(self):
        manifest_text = json.loads(EXAMPLE.read_text())
        del manifest_text["githubLogins"]
        del manifest_text["secrets"][copilotcreds.CANONICAL]["runtimeOnly"]
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(manifest_text))
            manifest = SecretManifest.load(path)
        self.assertIsNone(manifest.github_login("copilot"))

        class Resolver:
            def get(self, name):
                return "vault-value"
        generation = addon._StoreGeneration(manifest, Resolver(), addon._ProviderState())
        with patch.object(addon, "_capture_generation", return_value=generation):
            request = self.send(self.flow("api.business.githubcopilot.com", "GET", "/models", "Bearer " + REFERENCE))
            self.assertIsNone(request.response)
            self.assertEqual(request.request.headers["authorization"], "Bearer vault-value")


class CopilotManifestTests(unittest.TestCase):
    def load(self, data):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(data))
            return SecretManifest.load(path)

    def base(self):
        return json.loads(EXAMPLE.read_text())

    def test_example_enables_copilot(self):
        self.assertEqual(self.load(self.base()).github_login("copilot"), {"domain": "github.com"})
        data = self.base()
        del data["githubLogins"]
        self.assertEqual(self.load(data).github_login("copilot"), {"domain": "github.com"})

    def test_invalid_settings_fail_to_load(self):
        for change in ({"githubLogins": {"copilot": {"domain": "*.example.com"}}},
                       {"githubLogins": {"copilot": {"domain": "GitHub.example.com"}}},
                       {"githubLogins": {"copilot": {"domain": "localhost"}}},
                       {"githubLogins": {"copilot": {"other": 1}}},
                       {"githubLogins": {"unknown": {}}},
                       {"githubLogins": []}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.load({**self.base(), **change})
        data = self.base()
        del data["secrets"][copilotcreds.CANONICAL]["runtimeOnly"]
        with self.assertRaisesRegex(ValueError, "requires runtimeOnly"):
            self.load(data)
        data = self.base()
        data["secrets"]["OTHER_TOKEN"] = {"runtimeOnly": True, "placements": data["secrets"][copilotcreds.CANONICAL]["placements"]}
        with self.assertRaisesRegex(ValueError, "runtimeOnly is invalid"):
            self.load(data)

    def test_interception_hosts_are_added_only_when_enabled(self):
        with patch.object(entry.addon, "SECRETS_FILE", EXAMPLE), \
                patch.object(entry.addon, "AWS_OKTA_FILE", Path("/nonexistent/aws-okta.json")):
            patterns = entry._allow_hosts()
        self.assertIn(entry._host_pattern("github.com"), patterns)
        self.assertIn(entry._host_pattern("api.github.com"), patterns)
        self.assertIn(entry._host_pattern("api.*.githubcopilot.com"), patterns)
        with patch.object(entry.addon, "SECRETS_FILE", Path(addon.__file__).parent / "examples" / "manifest.json"), \
                patch.object(entry.addon, "AWS_OKTA_FILE", Path("/nonexistent/aws-okta.json")):
            patterns = entry._allow_hosts()
        self.assertNotIn(entry._host_pattern("github.com"), patterns)


if __name__ == "__main__":
    unittest.main()
