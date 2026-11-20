"""Scoped client tokens (issue #2): parsing, grant checks on every credential
path, and the unchanged single-token default.

A client using a secret, placement, login, signing or AWS target outside its
grants gets 403 and no secret is resolved. Offline: synthetic fixtures only.
"""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import clientgrants
from clientgrants import ClientConfigError
from secretstore import SecretManifest
from test_awsops_addon import ACCOUNT, AwsPolicyAddonTestCase
from test_injection import AddonTestCase, FakeResolver, make_flow

REF = "secre" + "tref:"
READER_TOKEN = "b" * 48


def manifest_document(clients=None, **extra):
    document = {
        "schemaVersion": 3,
        "account": {"vault": "Fixture"},
        "secrets": {
            "API_KEY": {"placements": [
                {"kind": "header", "hosts": ["api.example.com"], "name": "x-api-key", "template": "{secret}"},
                {"kind": "query", "hosts": ["api.example.com"], "name": "key", "template": "{secret}"},
            ]},
            "BASIC_PW": {"placements": [
                {"kind": "basic-password", "hosts": ["git.example.com"], "username": "x-access-token"},
            ]},
            "FORM_SECRET": {"placements": [
                {"kind": "form", "hosts": ["auth.example.com"], "name": "client_secret",
                 "template": "{secret}", "methods": ["POST"]},
            ]},
            "HOOK_URL": {"placements": [
                {"kind": "url-rewrite", "hosts": ["hooks.example.com"], "methods": ["POST"]},
            ]},
            "GIT_SIGNING_SSH_KEY": {"internalOnly": True, "valueField": "sshPrivateKey"},
            "CHATGPT_ACCESS_TOKEN": {"runtimeOnly": True, "placements": [
                {"kind": "header", "hosts": ["chatgpt.com"], "name": "authorization",
                 "template": "Bearer {secret}"},
            ]},
        },
    }
    if clients is not None:
        document["clients"] = clients
    document.update(extra)
    return document


SCOPED = {
    "default": {"all": True},
    "reader": {
        "secrets": {"API_KEY": {"placements": [0]}},
        "aws": [{"account": ACCOUNT, "role": "ReadOnly", "operations": ["sts:GetCallerIdentity"]}],
    },
    "hooks": {"secrets": {"HOOK_URL": True, "BASIC_PW": True, "FORM_SECRET": True}, "signing": True,
              "logins": ["chatgpt"], "aws": [{"account": ACCOUNT, "role": "*"}]},
    "nothing": {},
}


def load_manifest(document):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "manifest.json"
        path.write_text(json.dumps(document))
        return SecretManifest.load(path)


def as_client(flow, client, token=READER_TOKEN):
    flow.metadata["proxyauth"] = (clientgrants.username(client), token)
    return flow


class ParseTests(unittest.TestCase):
    def test_absent_section_means_one_unscoped_default_client(self):
        self.assertIsNone(load_manifest(manifest_document()).clients)

    def test_valid_section(self):
        policy = load_manifest(manifest_document(SCOPED)).clients
        self.assertEqual(policy.names(), ("default", "hooks", "nothing", "reader"))
        self.assertEqual(policy.named(), ("hooks", "nothing", "reader"))
        reader = policy.get("reader")
        self.assertTrue(reader.may_use_secret("API_KEY"))
        self.assertFalse(reader.may_use_secret("BASIC_PW"))
        self.assertEqual(reader.granted_placements("API_KEY"), frozenset({0}))
        self.assertFalse(reader.may_sign())
        self.assertFalse(reader.may_login("chatgpt"))
        self.assertTrue(policy.get("default").everything)
        self.assertIs(policy.get("unknown"), clientgrants.NO_GRANT)
        self.assertIs(policy.get(None), clientgrants.NO_GRANT)
        self.assertFalse(clientgrants.NO_GRANT.may_use_secret("API_KEY"))

    def test_invalid_sections_are_refused(self):
        cases = {
            "missing default": {"reader": {}},
            "empty": {},
            "not an object": [],
            "bad name": {"default": {"all": True}, "Reader": {}},
            "reserved user name": {"default": {"all": True}, "secret-proxy": {}},
            "unknown field": {"default": {"all": True}, "reader": {"hosts": []}},
            "all with grants": {"default": {"all": True, "signing": True}},
            "all false": {"default": {"all": False}},
            "unknown secret": {"default": {"all": True}, "r": {"secrets": {"NOPE": True}}},
            "internal secret": {"default": {"all": True}, "r": {"secrets": {"GIT_SIGNING_SSH_KEY": True}}},
            "bad index": {"default": {"all": True}, "r": {"secrets": {"API_KEY": {"placements": [2]}}}},
            "duplicate index": {"default": {"all": True}, "r": {"secrets": {"API_KEY": {"placements": [0, 0]}}}},
            "bool index": {"default": {"all": True}, "r": {"secrets": {"API_KEY": {"placements": [True]}}}},
            "grant false": {"default": {"all": True}, "r": {"secrets": {"API_KEY": False}}},
            "login not enabled": {"default": {"all": True}, "r": {"logins": ["github"]}},
            "unknown login": {"default": {"all": True}, "r": {"logins": ["ssh"]}},
            "signing not bool": {"default": {"all": True}, "r": {"signing": 1}},
            "aws account": {"default": {"all": True}, "r": {"aws": [{"account": "12", "role": "R"}]}},
            "aws role": {"default": {"all": True}, "r": {"aws": [{"account": ACCOUNT, "role": "a b"}]}},
            "aws operation": {"default": {"all": True}, "r": {"aws": [{"account": ACCOUNT, "role": "R",
                                                                       "operations": ["GetObject"]}]}},
            "aws missing role": {"default": {"all": True}, "r": {"aws": [{"account": ACCOUNT}]}},
            "too many": {"default": {"all": True}, **{f"c{i}": {} for i in range(16)}},
        }
        for label, clients in cases.items():
            with self.subTest(label):
                with self.assertRaises(ClientConfigError):
                    load_manifest(manifest_document(clients))

    def test_example_manifest_is_valid(self):
        policy = SecretManifest.load(Path(__file__).parent / "examples/clients-manifest.json").clients
        self.assertEqual(policy.names(), ("default", "issue-reader", "notifier"))
        self.assertEqual(policy.get("issue-reader").granted_placements("GITHUB_TOKEN"), frozenset({0}))

    def test_user_name_mapping(self):
        self.assertEqual(clientgrants.username("default"), "secret-proxy")
        self.assertEqual(clientgrants.username("reader"), "reader")
        self.assertEqual(clientgrants.client_for_username("secret-proxy"), "default")
        self.assertEqual(clientgrants.client_for_username("reader"), "reader")
        # "default" is never a proxy-auth user name; junk is unauthenticated.
        for user in ("default", "Reader", "", None, "a" * 40, "x:y"):
            self.assertIsNone(clientgrants.client_for_username(user))
        self.assertEqual(clientgrants.token_file_name("default"), "proxy-token")
        self.assertEqual(clientgrants.token_file_name("reader"), "proxy-token.reader")
        with self.assertRaises(ClientConfigError):
            clientgrants.token_file_name("../x")

    def test_aws_grant_matching(self):
        grant = clientgrants.AwsGrant("*", "ReadOnly", (("s3", "*"), ("sts", "GetCaller*")))
        self.assertTrue(grant.matches_target(ACCOUNT, "ReadOnly"))
        self.assertFalse(grant.matches_target(ACCOUNT, "Admin"))
        self.assertFalse(grant.matches_target(None, "ReadOnly"))
        self.assertTrue(grant.allows_operation("s3", "Unclassified"))
        self.assertTrue(grant.allows_operation("sts", "GetCallerIdentity"))
        self.assertFalse(grant.allows_operation("sts", "AssumeRole"))


class FlowClientTests(unittest.TestCase):
    def test_identity_comes_only_from_proxy_auth_metadata(self):
        import addon
        flow = make_flow("api.example.com", headers={"X-Client": "default"})
        self.assertIsNone(addon.flow_client(flow))
        flow.metadata["proxyauth"] = ("secret-proxy", "a" * 48)
        self.assertEqual(addon.flow_client(flow), "default")
        flow.metadata["proxyauth"] = ("reader", "b" * 48)
        self.assertEqual(addon.flow_client(flow), "reader")
        flow.metadata["proxyauth"] = "reader"
        self.assertIsNone(addon.flow_client(flow))


class ScopedAddonCase(AddonTestCase):
    VALUES = {"API_KEY": "real-api-key", "BASIC_PW": "real-basic", "FORM_SECRET": "real-form",
              "HOOK_URL": "https://hooks.example.com/services/T/B/x", "GIT_SIGNING_SSH_KEY": "key"}

    def use(self, clients=SCOPED):
        self.addon._manifest = load_manifest(manifest_document(clients))
        self.resolver = FakeResolver(dict(self.VALUES))
        self.addon._resolver = self.resolver
        self.addon._manifest_mtime = -1

    def assertRefused(self, flow, status=403):
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, status, flow.response.content)
        self.assertEqual(self.resolver.get_calls, [], "no secret may be resolved")
        self.assertNotIn(b"real-", flow.request.content or b"")
        for value in flow.request.headers.values():
            self.assertNotIn("real-", value)
        for value in flow.request.query.values():
            self.assertNotIn("real-", value)


def header_flow(client, **kw):
    return as_client(make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"}, **kw), client)


def query_flow(client):
    return as_client(make_flow("api.example.com", query={"key": REF + "API_KEY"}), client)


def basic_flow(client):
    value = base64.b64encode(("x-access-token:" + REF + "BASIC_PW").encode()).decode()
    return as_client(make_flow("git.example.com", headers={"Authorization": "Basic " + value}), client)


def form_flow(client):
    body = ("client_secret=" + REF + "FORM_SECRET").encode()
    return as_client(make_flow("auth.example.com", "/token", "POST", content=body,
                               content_type="application/x-www-form-urlencoded"), client)


def hook_flow(client):
    import addon
    return as_client(make_flow(addon.SENTINEL_HOST, "/HOOK_URL", "POST"), client)


class DefaultBehaviourTests(ScopedAddonCase):
    """No clients section: any authenticated (or test) identity has every grant."""

    def test_every_placement_works_without_a_clients_section(self):
        self.use(clients=None)
        for make, client in ((header_flow, "default"), (query_flow, "default"), (basic_flow, "default"),
                             (form_flow, "default"), (hook_flow, "default")):
            with self.subTest(make.__name__):
                self.resolver.get_calls.clear()
                flow = make(client)
                self.addon.request(flow)
                self.assertIsNone(flow.response, flow.response and flow.response.content)
                self.assertEqual(len(self.resolver.get_calls), 1)
        # Even without proxy-auth metadata (direct use, tests), nothing changes.
        flow = make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"})
        self.addon.request(flow)
        self.assertEqual(flow.request.headers["x-api-key"], "real-api-key")

    def test_default_client_with_all_keeps_every_grant(self):
        self.use()
        for make in (header_flow, query_flow, basic_flow, form_flow, hook_flow):
            with self.subTest(make.__name__):
                self.resolver.get_calls.clear()
                flow = make("default")
                self.addon.request(flow)
                self.assertIsNone(flow.response, flow.response and flow.response.content)


class SecretGrantTests(ScopedAddonCase):
    def test_ungranted_secret_is_refused_in_every_placement_kind(self):
        self.use()
        for make in (query_flow, basic_flow, form_flow, hook_flow):
            for client in ("reader", "nothing"):
                with self.subTest(make.__name__, client=client):
                    self.resolver.get_calls.clear()
                    flow = make(client)
                    self.addon.request(flow)
                    self.assertRefused(flow)
                    if make is not hook_flow:
                        self.assertEqual(json.loads(flow.response.content)["error"],
                                         "secret_proxy_placement_not_allowed")
        # A header placement the reader holds no grant for at all.
        self.resolver.get_calls.clear()
        flow = header_flow("nothing")
        self.addon.request(flow)
        self.assertRefused(flow)

    def test_unauthenticated_and_unknown_identities_get_nothing(self):
        self.use()
        for flow in (make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"}),
                     as_client(make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"}), "ghost")):
            with self.subTest(flow.metadata.get("proxyauth")):
                self.resolver.get_calls.clear()
                self.addon.request(flow)
                self.assertRefused(flow)

    def test_granted_placement_works_and_others_are_refused(self):
        self.use()
        flow = header_flow("reader")
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["x-api-key"], "real-api-key")
        # Placement 1 (query) of the same secret is not granted to reader.
        self.resolver.get_calls.clear()
        flow = query_flow("reader")
        self.addon.request(flow)
        self.assertRefused(flow)

    def test_granted_basic_form_and_url_rewrite_work(self):
        self.use()
        for make in (basic_flow, form_flow, hook_flow):
            with self.subTest(make.__name__):
                self.resolver.get_calls.clear()
                flow = make("hooks")
                self.addon.request(flow)
                self.assertIsNone(flow.response, flow.response and flow.response.content)
        flow = hook_flow("hooks")
        self.addon.request(flow)
        self.assertEqual(flow.request.host, "hooks.example.com")

    def test_streaming_path_refuses_before_resolving(self):
        self.use()
        for make in (header_flow, query_flow, basic_flow):
            with self.subTest(make.__name__):
                self.resolver.get_calls.clear()
                flow = make("nothing")
                flow.request.stream = True  # metadata is injected in requestheaders
                self.addon.requestheaders(flow)
                self.assertRefused(flow)
        flow = header_flow("reader")
        flow.request.stream = True
        self.addon.requestheaders(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["x-api-key"], "real-api-key")

    def test_http2_flow_uses_the_same_identity(self):
        self.use()
        flow = header_flow("nothing")
        flow.request.http_version = "HTTP/2.0"
        del flow.request.headers["Host"]
        self.addon.request(flow)
        self.assertRefused(flow)


class ProxyRouteTests(ScopedAddonCase):
    def test_git_signing_needs_the_signing_grant(self):
        import addon
        self.use()
        for client in ("reader", "nothing"):
            flow = as_client(make_flow(addon.SENTINEL_HOST, "/git/sign", "POST", content=b"tree x\n"), client)
            self.addon.request(flow)
            self.assertRefused(flow)
            self.assertEqual(json.loads(flow.response.content)["error"], "secret_proxy_client_not_granted")

    def test_git_signing_granted_client_reaches_the_signer(self):
        import addon
        self.use()
        flow = as_client(make_flow(addon.SENTINEL_HOST, "/git/sign", "POST", content=b"not a commit"), "hooks")
        self.addon.request(flow)
        # Past the grant: refused by gitsign itself, before any key lookup.
        self.assertEqual(flow.response.status_code, 400)

    def test_chatgpt_login_routes_need_the_login_grant(self):
        import addon
        self.use()
        with patch.object(addon.ChatGPTCredentials, "start", side_effect=AssertionError("login started")):
            for path, method in (("/chatgpt/start", "GET"), ("/chatgpt/finish", "POST"), ("/chatgpt/status", "GET")):
                with self.subTest(path):
                    flow = as_client(make_flow(addon.SENTINEL_HOST, path, method), "reader")
                    self.addon.request(flow)
                    self.assertRefused(flow)
        with patch.object(addon.ChatGPTCredentials, "start", return_value="https://auth.openai.com/oauth/authorize"):
            flow = as_client(make_flow(addon.SENTINEL_HOST, "/chatgpt/start"), "hooks")
            self.addon.request(flow)
            self.assertEqual(flow.response.status_code, 200)

    def test_health_is_available_to_every_authenticated_client(self):
        import addon
        self.use()
        with patch.dict("os.environ", {"SECRET_PROXY_INSTANCE_ID": "c" * 32}):
            flow = as_client(make_flow(addon.SENTINEL_HOST, "/health"), "nothing")
            self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 200)

    def test_github_login_and_copilot_exchange_need_grants(self):
        import addon
        import copilotcreds
        document = manifest_document({"default": {"all": True}, "reader": {}})
        document["secrets"]["GITHUB_COPILOT_SESSION_TOKEN"] = {"runtimeOnly": True, "placements": [
            {"kind": "header", "hosts": ["api.githubcopilot.com"], "name": "authorization",
             "template": "Bearer {secret}"}]}
        document["secrets"]["GH_CLI_OAUTH_TOKEN"] = {"runtimeOnly": True, "placements": [
            {"kind": "header", "hosts": ["api.github.com"], "name": "authorization",
             "template": "token {secret}"}]}
        self.addon._manifest = load_manifest(document)
        self.resolver = FakeResolver({})
        self.addon._resolver = self.resolver
        with patch.object(addon, "_github_provider", side_effect=AssertionError("provider used")):
            for path, method in (("/github/start", "GET"), ("/github/poll", "POST"),
                                 ("/github-copilot/status", "GET")):
                with self.subTest(path):
                    flow = as_client(make_flow(addon.SENTINEL_HOST, path, method), "reader")
                    self.addon.request(flow)
                    self.assertRefused(flow)
            flow = as_client(make_flow("api.github.com", copilotcreds.EXCHANGE_PATH, headers={
                "authorization": "Bearer " + REF + copilotcreds.CANONICAL}), "reader")
            self.addon.request(flow)
            self.assertRefused(flow)
            self.assertEqual(json.loads(flow.response.content)["error"], "secret_proxy_client_not_granted")

    def test_checkmarx_exchange_answer_needs_the_grant(self):
        import addon
        document = manifest_document({"default": {"all": True}, "reader": {}}, checkmarxRealm="fixture")
        document["secrets"]["CHECKMARX_API_KEY"] = {"internalOnly": True}
        document["secrets"]["CHECKMARX_ACCESS_TOKEN"] = {"derivedFrom": ["CHECKMARX_API_KEY"], "placements": [
            {"kind": "header", "hosts": ["cx.example.com"], "name": "authorization", "template": "Bearer {secret}"}]}
        self.addon._manifest = load_manifest(document)
        self.resolver = FakeResolver({})
        self.addon._resolver = self.resolver
        body = ("grant_type=refresh_token&client_id=ast-app&refresh_token=" + REF + "CHECKMARX_API_KEY").encode()
        with patch.object(addon, "_form_token_provider", side_effect=AssertionError("token minted")):
            flow = as_client(make_flow("cx.example.com", "/auth/realms/fixture/protocol/openid-connect/token",
                                       "POST", content=body,
                                       content_type="application/x-www-form-urlencoded"), "reader")
            self.addon.request(flow)
        self.assertRefused(flow)
        self.assertEqual(json.loads(flow.response.content)["error"], "secret_proxy_client_not_granted")


class AwsGrantTests(AwsPolicyAddonTestCase):
    def setUp(self):
        super().setUp()
        self.addon._manifest = load_manifest(manifest_document(SCOPED))
        self.okta_file.write_text(json.dumps({"default_account": ACCOUNT, "default_role": "ReadOnly"}))

    def caller(self, flow, client):
        return as_client(flow, client)

    def sts(self, client, action="GetCallerIdentity", **kw):
        body = f"Action={action}&Version=2011-06-15".encode()
        return self.caller(self.query_flow("sts", body, **kw), client)

    def test_role_outside_the_grant_is_refused_before_any_mint(self):
        for client in ("nothing", "ghost"):
            with self.subTest(client):
                flow = self.run_hooks(self.sts(client))
                self.assertDenied(flow, "sts:GetCallerIdentity")
                self.assertIn(b"is not granted this AWS account and role", flow.response.content)
        flow = self.run_hooks(self.sts("reader", role="Admin"))
        self.assertDenied(flow, "sts:GetCallerIdentity")

    def test_operation_outside_the_grant_is_refused_on_both_paths(self):
        flow = self.run_hooks(self.caller(self.json_flow("dynamodb", "DynamoDB_20120810.ListTables"), "reader"))
        self.assertDenied(flow, "dynamodb:ListTables")
        self.assertIn(b"is not granted dynamodb:ListTables", flow.response.content)
        # Streaming (x-amz-content-sha256, S3): re-signed in requestheaders.
        flow = self.caller(self.aws_flow("bucket.s3.eu-west-1.amazonaws.com", "s3", method="PUT",
                                         path="/key", sha256="UNSIGNED-PAYLOAD"), "reader")
        self.run_hooks(flow)
        self.assertDenied(flow, "s3:Unclassified")
        flow = self.caller(self.aws_flow("bucket.s3.eu-west-1.amazonaws.com", "s3", method="PUT", path="/key",
                                         sha256="UNSIGNED-PAYLOAD", http2=True), "nothing")
        self.run_hooks(flow)
        self.assertDenied(flow, "s3:Unclassified")

    def test_granted_role_and_operation_is_resigned(self):
        flow = self.run_hooks(self.sts("reader"))
        self.assertResigned(flow)
        self.provider.calls.clear()
        flow = self.caller(self.aws_flow("bucket.s3.eu-west-1.amazonaws.com", "s3", method="PUT", path="/key",
                                         sha256="UNSIGNED-PAYLOAD"), "hooks")
        self.run_hooks(flow)
        self.assertResigned(flow)

    def test_grant_cannot_be_widened_by_an_override(self):
        self.okta_file.write_text(json.dumps({
            "default_account": ACCOUNT, "default_role": "ReadOnly",
            "operation_overrides": [{"account": ACCOUNT, "role": "ReadOnly", "service": "sts",
                                     "operations": ["AssumeRole"]}]}))
        flow = self.run_hooks(self.sts("reader", action="AssumeRole"))
        self.assertDenied(flow, "sts:AssumeRole")
        self.assertIn(b"is not granted sts:AssumeRole", flow.response.content)

    def presigned(self, client, role="ReadOnly"):
        query = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                 "X-Amz-Credential": "secret-proxy-dummy-akid/20260101/eu-west-1/s3/aws4_request",
                 "X-Amz-Date": "20260101T000000Z", "X-Amz-Expires": "60", "X-Amz-SignedHeaders": "host",
                 "X-Amz-Security-Token": f"secretrole:{ACCOUNT}/{role}", "X-Amz-Signature": "00"}
        from test_injection import make_flow as plain
        return as_client(plain("bucket.s3.eu-west-1.amazonaws.com", "/key", query=query), client)

    def test_presigned_urls_need_an_unrestricted_grant(self):
        for client in ("reader", "nothing"):  # reader's grant lists operations
            with self.subTest(client):
                flow = self.presigned(client)
                self.addon.requestheaders(flow)
                self.assertEqual(flow.response.status_code, 403)
                self.assertIn(b"AccessDeniedException", flow.response.content)
                self.assertEqual(self.provider.calls, [])
                self.assertEqual(self.provider_lookups, 0)
        flow = self.presigned("hooks")
        self.addon.requestheaders(flow)
        self.assertIsNone(flow.response)
        self.assertIn(("get_creds", ACCOUNT, "ReadOnly"), self.provider.calls)


class RuntimeTokenTests(unittest.TestCase):
    def read(self, value):
        import os
        import runtime
        r, w = os.pipe()
        try:
            os.write(w, json.dumps(value).encode())
            os.close(w)
            w = -1
            return runtime.read_bootstrap(r, timeout=0.5)
        finally:
            os.close(r)
            if w != -1:
                os.close(w)

    def test_bootstrap_accepts_only_valid_distinct_client_tokens(self):
        good = {"op_token": "fixture", "proxy_token": "a" * 48, "client_tokens": {"reader": READER_TOKEN}}
        self.assertEqual(self.read(good), good)
        for tokens in ({"default": READER_TOKEN}, {"secret-proxy": READER_TOKEN}, {"Reader": READER_TOKEN},
                       {"reader": "a" * 48}, {"reader": READER_TOKEN, "hooks": READER_TOKEN},
                       {"reader": "short"}, [], {f"c{i}": f"{i:048x}" for i in range(17)}):
            with self.subTest(tokens=str(tokens)[:40]), self.assertRaises(ValueError):
                self.read({**good, "client_tokens": tokens})

    def test_htpasswd_is_unchanged_without_clients(self):
        import hashlib
        import runtime
        expected = "secret-proxy:{SHA}" + base64.b64encode(hashlib.sha1(b"a" * 48).digest()).decode() + "\n"
        self.assertEqual(runtime.htpasswd({"op_token": "x", "proxy_token": "a" * 48}, ()), expected)

    def test_htpasswd_has_one_line_per_client_and_must_match_the_manifest(self):
        import runtime
        from mitmproxy.utils import htpasswd
        capabilities = {"op_token": "x", "proxy_token": "a" * 48,
                        "client_tokens": {"reader": READER_TOKEN, "hooks": "c" * 48}}
        text = runtime.htpasswd(capabilities, ("hooks", "reader"))
        self.assertNotIn(READER_TOKEN, text)
        parsed = htpasswd.HtpasswdFile(text)
        self.assertTrue(parsed.check_password("secret-proxy", "a" * 48))
        self.assertTrue(parsed.check_password("reader", READER_TOKEN))
        self.assertTrue(parsed.check_password("hooks", "c" * 48))
        # A token authenticates only its own client.
        self.assertFalse(parsed.check_password("reader", "a" * 48))
        self.assertFalse(parsed.check_password("secret-proxy", READER_TOKEN))
        for named in (("reader",), ("hooks", "reader", "extra"), ()):
            with self.subTest(named=named), self.assertRaises(ClientConfigError):
                runtime.htpasswd(capabilities, named)


class HostTokenTests(unittest.TestCase):
    def setUp(self):
        import host
        self.host = host
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for name, value in (("SA_HOME", root / "home"), ("SHARED_ROOT", root / "shared")):
            patcher = patch.object(host, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.deployment = host.Deployment("candidate", "secagent", 10260)
        (self.deployment.private / "config").mkdir(parents=True)
        self.deployment.shared.mkdir(parents=True)

    def write_manifest(self, clients):
        (self.deployment.private / "config/manifest.json").write_text(json.dumps(manifest_document(clients)))

    def test_no_clients_section_creates_and_publishes_nothing(self):
        self.write_manifest(None)
        self.assertEqual(self.host.client_tokens(self.deployment, "a" * 48), {})
        self.assertFalse((self.deployment.private / "client-tokens").exists())
        self.host.publish_client_tokens(self.deployment, {})
        self.assertEqual(list(self.deployment.shared.iterdir()), [])

    def test_tokens_are_private_persistent_distinct_and_published_owner_only(self):
        import stat
        self.write_manifest(SCOPED)
        first = self.host.client_tokens(self.deployment, "a" * 48)
        self.assertEqual(sorted(first), ["hooks", "nothing", "reader"])
        self.assertEqual(len(set(first.values()) | {"a" * 48}), 4)
        directory = self.deployment.private / "client-tokens"
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for name in first:
            self.assertEqual(stat.S_IMODE((directory / name).stat().st_mode), 0o600)
        self.assertEqual(self.host.client_tokens(self.deployment, "a" * 48), first)  # survives restarts
        (self.deployment.shared / "proxy-token.retired").write_text("d" * 48 + "\n")
        (self.deployment.shared / "ready.json").write_text("{}")
        self.host.publish_client_tokens(self.deployment, first)
        published = sorted(p.name for p in self.deployment.shared.iterdir())
        self.assertEqual(published, ["proxy-token.hooks", "proxy-token.nothing", "proxy-token.reader", "ready.json"])
        for name, token in first.items():
            path = self.deployment.shared / ("proxy-token." + name)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(), token + "\n")

    def test_serve_sends_each_client_token_once_and_publishes_them(self):
        self.write_manifest(SCOPED)
        bundle = self.run_serve()
        self.assertEqual(sorted(bundle["client_tokens"]), ["hooks", "nothing", "reader"])
        for name, token in bundle["client_tokens"].items():
            self.assertEqual((self.deployment.shared / ("proxy-token." + name)).read_text(), token + "\n")
            self.assertNotEqual(token, bundle["proxy_token"])

    def test_serve_without_clients_sends_todays_bundle(self):
        self.write_manifest(None)
        # approver_token is the approvals capability (#3); it is never published.
        self.assertEqual(set(self.run_serve()), {"op_token", "proxy_token", "approver_token"})
        self.assertEqual(sorted(p.name for p in self.deployment.shared.iterdir()),
                         ["bundle.pem", "ca.pem", "proxy-token"])  # ready.json is removed on exit

    def run_serve(self):
        import io
        import subprocess
        private = self.deployment.private
        (private / "image.json").write_text(json.dumps({"image": "sha256:" + "e" * 64}))
        (private / "image.json").chmod(0o600)
        (private / "runtime-ca.pem").write_text("roots")
        ready = json.dumps({"status": "ready", "instance": "f" * 32}).encode()

        def engine(_deployment, *args, **_kw):
            if args[:2] == ("container", "exists"):
                return subprocess.CompletedProcess(args, 1, b"", b"")
            if args[-1] == "/tmp/secret-proxy/ready.json":
                return subprocess.CompletedProcess(args, 0, ready, b"")
            return subprocess.CompletedProcess(args, 0, b"ca", b"")

        class Child:
            def __init__(self, *_a, **_kw):
                self.stdin = io.BytesIO()
                self.stdin.close = lambda: None
                self.returncode = 0
                Child.last = self

            def poll(self):
                return None

            def wait(self, timeout=None):
                return 0

        with patch.object(self.host, "engine", side_effect=engine), \
                patch.object(self.host, "read_bootstrap", return_value={"op_token": "fixture", "proxy_token": "0" * 48}), \
                patch.object(self.host.subprocess, "Popen", Child), \
                patch("sys.stdout", io.StringIO()):
            self.host.serve(self.deployment)
        return json.loads(Child.last.stdin.getvalue())

    def test_a_token_equal_to_the_default_capability_is_refused(self):
        self.write_manifest(SCOPED)
        tokens = self.host.client_tokens(self.deployment, "a" * 48)
        with self.assertRaises(self.host.HostError):
            self.host.client_tokens(self.deployment, tokens["reader"])


class ClientCommandTests(unittest.TestCase):
    def shared(self, tmp):
        root = Path(tmp)
        for name, token in (("proxy-token", "a" * 48), ("proxy-token.reader", READER_TOKEN)):
            (root / name).write_text(token + "\n")
            (root / name).chmod(0o600)
        (root / "ca.pem").write_text("fixture certificate")
        return {"sharedDir": tmp, "port": 10260}

    def test_default_client_environment_is_unchanged(self):
        import client
        with tempfile.TemporaryDirectory() as tmp:
            env = client.client_env(self.shared(tmp))
        self.assertEqual(env["HTTPS_PROXY"], "http://secret-proxy:" + "a" * 48 + "@127.0.0.1:10260")

    def test_named_client_uses_only_its_own_token_and_user_name(self):
        import client
        with tempfile.TemporaryDirectory() as tmp:
            config = self.shared(tmp)
            env = client.client_env(config, "reader")
            self.assertEqual(env["HTTPS_PROXY"], "http://reader:" + READER_TOKEN + "@127.0.0.1:10260")
            self.assertNotIn("a" * 48, json.dumps(env))
            for bad in ("Reader", "../proxy-token", "secret-proxy", ""):
                with self.subTest(bad), self.assertRaises(client.ClientError):
                    client.client_env(config, bad)
            with self.assertRaises(OSError):
                client.client_env(config, "missing")
            (Path(tmp) / "proxy-token.reader").chmod(0o666)  # writable by others
            with self.assertRaises(client.ClientError):
                client.client_env(config, "reader")


class ManageClientTests(unittest.TestCase):
    def settings(self):
        return {"instance": "candidate", "bootstrap": "/private/example/bootstrap.json", "op": "/opt/example/op"}

    def test_client_option_passes_through_to_the_client_command(self):
        import manage
        with patch.object(manage.os, "execv") as execute:
            manage.execute(self.settings(), "run", ["--", "/usr/bin/true"], client_name="reader")
            self.assertEqual(execute.call_args.args[1], [
                manage.PYTHON, str(manage.ROOT / "current/client.py"),
                "--config", str(manage.SHARED_ROOT / "candidate/client.json"),
                "--client", "reader", "run", "--", "/usr/bin/true"])
            manage.execute(self.settings(), "run", ["--", "/usr/bin/true"])
            self.assertNotIn("--client", execute.call_args.args[1])
            manage.execute(self.settings(), "login", provider="github", client_name="reader")
            self.assertEqual(execute.call_args.args[1][-5:], ["--client", "reader", "login", "--provider", "github"])
        with self.assertRaises(manage.ClientError):
            manage.execute(self.settings(), "run", ["/usr/bin/true"], client_name="../x")
        with patch.object(manage, "execute") as run, patch.object(manage, "load_settings", return_value=self.settings()):
            manage.main(["run", "--client", "reader", "--", "/usr/bin/true"])
            self.assertEqual(run.call_args.args[4], "reader")
            manage.main(["status"])
            self.assertEqual(run.call_args.args[4], "default")


if __name__ == "__main__":
    unittest.main()
