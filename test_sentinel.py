"""Unit tests for secretref.invalid URL-rewrite sentinel.

RED phase: Tests for _manifest/_resolver API + secretref.invalid sentinel.
Run:  uv run --python 3.12 --with 'mitmproxy==11.1.3' python dev-env/secret-proxy/test_sentinel.py
"""
import os, sys, unittest
from types import SimpleNamespace
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
def url_secret(hosts, *, methods=None, paths=None):
    placement = {"kind": "url-rewrite", "hosts": hosts}
    if methods is not None:
        placement["methods"] = methods
    if paths is not None:
        placement["paths"] = paths
    return {"placements": [placement]}


class FakeManifest:
    """Fake manifest for URL-rewrite placement testing."""
    def __init__(self, entries: dict[str, dict]):
        self._entries = entries

    def canonical_name(self, name: str) -> str:
        if name in self._entries:
            return name
        raise KeyError(f"Unknown canonical name: '{name}'")

    @staticmethod
    def _host_matches(pattern, host):
        expected, actual = pattern.lower().split("."), host.lower().split(".")
        return len(expected) == len(actual) and all(
            left == "*" or left == right for left, right in zip(expected, actual)
        )

    def secret(self, name):
        if name not in self._entries:
            raise KeyError(f"Unknown canonical name: '{name}'")
        return SimpleNamespace(
            placements=[
                SimpleNamespace(
                    kind=placement["kind"],
                    methods=placement.get("methods", []),
                )
                for placement in self._entries[name].get("placements", [])
            ]
        )

    def has_placement_kind(self, name, kind):
        if name not in self._entries:
            raise KeyError(f"Unknown canonical name: '{name}'")
        return any(item["kind"] == kind for item in self._entries[name].get("placements", []))

    def placement_allowed(self, secret_name, **context):
        if secret_name not in self._entries:
            raise KeyError(f"Unknown canonical name: '{secret_name}'")
        for placement in self._entries[secret_name].get("placements", []):
            if placement["kind"] != context["kind"]:
                continue
            if not any(self._host_matches(pattern, context["host"]) for pattern in placement["hosts"]):
                continue
            if placement.get("methods") and context["method"].upper() not in placement["methods"]:
                continue
            if placement.get("paths") and not any(
                context["path"].startswith(pattern[:-1]) if pattern.endswith("*")
                else context["path"] == pattern
                for pattern in placement["paths"]
            ):
                continue
            return True
        return False


class FakeResolver:
    """Fake resolver tracking calls."""
    def __init__(self, values: dict[str, str] | None = None):
        self.values, self.get_calls = values or {}, []
    def get(self, name: str) -> str:
        self.get_calls.append(name)
        if name not in self.values: raise KeyError(f"Unknown secret: '{name}'")
        return self.values[name]
    def clear_cache(self) -> None: pass


def make_flow(host: str, path: str = "/", method: str = "GET", headers: dict | None = None):
    from mitmproxy.test import tflow
    flow = tflow.tflow()
    flow.request.method, flow.request.host, flow.request.port = method, host, 443
    flow.request.scheme, flow.request.path = "https", path
    flow.request.headers.clear()
    flow.request.headers["Host"] = host
    if headers:
        for k, v in headers.items(): flow.request.headers[k] = v
    flow.response = None
    return flow


class AddonTestCase(unittest.TestCase):
    def setUp(self):
        import addon
        from addon import PolicyViolation
        self.addon, self.PolicyViolation = addon, PolicyViolation
        self._orig = (getattr(addon, "_manifest", None), getattr(addon, "_resolver", None))
    def tearDown(self):
        self.addon._manifest, self.addon._resolver = self._orig

    def resolve(self, name, method="GET"):
        flow = make_flow("secretref.invalid", f"/{name}", method)
        return self.addon._sentinel_resolve(name, flow)


class TestSentinelResolve(AddonTestCase):
    def test_valid_name_resolves(self):
        self.addon._manifest = FakeManifest({"SLACK_WEBHOOK": url_secret(["hooks.slack.com"], methods=["POST"], paths=["/services/*"])})
        self.addon._resolver = FakeResolver({"SLACK_WEBHOOK": "https://hooks.slack.com/services/T/B/x"})
        scheme, host, port, path = self.resolve("SLACK_WEBHOOK", "POST")
        self.assertEqual((scheme, host, path), ("https", "hooks.slack.com", "/services/T/B/x"))
        self.assertIn("SLACK_WEBHOOK", self.addon._resolver.get_calls)

    def test_query_string_preserved(self):
        self.addon._manifest = FakeManifest({"API": url_secret(["api.example.com"])})
        self.addon._resolver = FakeResolver({"API": "https://api.example.com/v1?limit=10"})
        _, _, _, path = self.resolve("API")
        self.assertIn("limit=10", path)

    def test_custom_port_preserved(self):
        self.addon._manifest = FakeManifest({"SVC": url_secret(["internal.example.com"])})
        self.addon._resolver = FakeResolver({"SVC": "https://internal.example.com:8443/api"})
        _, _, port, _ = self.resolve("SVC")
        self.assertEqual(port, 8443)

    def test_wildcard_host_matches(self):
        self.addon._manifest = FakeManifest({"AWS": url_secret(["bedrock-runtime.*.amazonaws.com"])})
        self.addon._resolver = FakeResolver({"AWS": "https://bedrock-runtime.eu-west-1.amazonaws.com/m"})
        _, host, _, _ = self.resolve("AWS")
        self.assertEqual(host, "bedrock-runtime.eu-west-1.amazonaws.com")


class TestSentinelPolicyBlocking(AddonTestCase):
    def test_empty_hosts_blocked_before_lookup(self):
        resolver = FakeResolver({"GOCRYPTFS_PASSPHRASE": "secret"})
        self.addon._manifest = FakeManifest({"GOCRYPTFS_PASSPHRASE": {"internalOnly": True}})
        self.addon._resolver = resolver
        with self.assertRaises(self.PolicyViolation) as ctx:
            self.resolve("GOCRYPTFS_PASSPHRASE")
        self.assertEqual(ctx.exception.name, "GOCRYPTFS_PASSPHRASE")
        self.assertEqual(resolver.get_calls, [])

    def test_wrong_method_is_blocked_before_lookup(self):
        resolver = FakeResolver({"WEBHOOK": "https://hooks.slack.com/services/T/B/x"})
        self.addon._manifest = FakeManifest({
            "WEBHOOK": url_secret(
                ["hooks.slack.com"], methods=["POST"], paths=["/services/*"]
            )
        })
        self.addon._resolver = resolver
        with self.assertRaises(self.PolicyViolation):
            self.resolve("WEBHOOK", "GET")
        self.assertEqual(resolver.get_calls, [])

    def test_unknown_name_blocked(self):
        resolver = FakeResolver({})
        self.addon._manifest = FakeManifest({"OTHER": url_secret(["example.com"])})
        self.addon._resolver = resolver
        with self.assertRaises((self.addon.SecretReferenceError, KeyError)):
            self.resolve("NONEXISTENT")
        self.assertEqual(resolver.get_calls, [])

    def test_resolved_host_mismatch_blocked(self):
        resolver = FakeResolver({"WEBHOOK": "https://evil.example.com/exfil"})
        self.addon._manifest = FakeManifest({"WEBHOOK": url_secret(["hooks.slack.com"])})
        self.addon._resolver = resolver
        with self.assertRaises(self.PolicyViolation) as ctx:
            self.resolve("WEBHOOK")
        self.assertIn("WEBHOOK", resolver.get_calls)
        self.assertEqual(ctx.exception.host, "evil.example.com")


class TestSentinelUuidRejection(AddonTestCase):
    def test_uuid_rejected_before_lookup(self):
        resolver = FakeResolver({})
        self.addon._manifest = FakeManifest({"SECRET": url_secret(["example.com"])})
        self.addon._resolver = resolver
        with self.assertRaises(Exception):
            self.resolve("00000000-0000-4000-8000-000000000000")
        self.assertEqual(resolver.get_calls, [])


class TestSentinelRequestHook(AddonTestCase):
    def test_sentinel_rewrites_request(self):
        self.addon._manifest = FakeManifest({"SLACK_WEBHOOK": url_secret(["hooks.slack.com"], methods=["POST"], paths=["/services/*"])})
        self.addon._resolver = FakeResolver({"SLACK_WEBHOOK": "https://hooks.slack.com/services/T/B/x"})
        flow = make_flow("secretref.invalid", "/SLACK_WEBHOOK", "POST")
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.host, "hooks.slack.com")
        self.assertEqual(flow.request.path, "/services/T/B/x")

    def test_sentinel_internal_only_blocked(self):
        resolver = FakeResolver({"GOCRYPTFS_PASSPHRASE": "secret"})
        self.addon._manifest = FakeManifest({"GOCRYPTFS_PASSPHRASE": {"internalOnly": True}})
        self.addon._resolver = resolver
        flow = make_flow("secretref.invalid", "/GOCRYPTFS_PASSPHRASE")
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(resolver.get_calls, [])

    def test_sentinel_rejects_non_https_targets_before_rewrite(self):
        self.addon._manifest = FakeManifest({"WEBHOOK": url_secret(["allowed.example"], methods=["POST"], paths=["/path"])})
        resolver = FakeResolver()
        self.addon._resolver = resolver

        for scheme in ("http", "ftp", "file", "https+foo"):
            with self.subTest(scheme=scheme):
                resolver.values["WEBHOOK"] = f"{scheme}://allowed.example/path"
                flow = make_flow("secretref.invalid", "/WEBHOOK", "POST")
                original = (
                    flow.request.scheme,
                    flow.request.host,
                    flow.request.port,
                    flow.request.path,
                    flow.request.headers["Host"],
                )

                self.addon.request(flow)

                self.assertIsNotNone(flow.response)
                self.assertEqual(flow.response.status_code, 403)
                self.assertEqual(
                    (
                        flow.request.scheme,
                        flow.request.host,
                        flow.request.port,
                        flow.request.path,
                        flow.request.headers["Host"],
                    ),
                    original,
                )
                self.assertNotIn("allowed.example", flow.request.url)
                self.assertNotIn("allowed.example", flow.response.content.decode())

        self.assertEqual(resolver.get_calls, ["WEBHOOK"] * 4)


class TestRemovedProviderSpecificSentinel(AddonTestCase):
    def test_old_sentinel_host_is_not_resolved(self):
        resolver = FakeResolver(
            {"SLACK_WEBHOOK": "https://hooks.slack.com/services/T/B/x"}
        )
        self.addon._manifest = FakeManifest(
            {"SLACK_WEBHOOK": url_secret(["hooks.slack.com"], methods=["POST"], paths=["/services/*"])}
        )
        self.addon._resolver = resolver
        old_host = "bw" + "ref.invalid"
        flow = make_flow(old_host, "/legacy-webhook", "POST")

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.host, old_host)
        self.assertEqual(flow.request.path, "/legacy-webhook")
        self.assertEqual(resolver.get_calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
