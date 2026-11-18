"""Unit tests for secretref: pattern injection in addon.py.

Regression coverage for secretref injection and manifest/resolver generation handling.
Run:  uv run --python 3.12 --with 'mitmproxy==11.1.3' python dev-env/secret-proxy/test_addon_secretrefs.py
"""
import base64, json, logging, os, sys, tempfile, threading, unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secretstore import (
    SecretBackendError,
    SecretInfo,
    SecretManifest,
    SecretPlacement,
    SecretResolver,
)

class FakeManifest:
    def __init__(self, secrets: dict[str, dict]):
        self._secrets = secrets

    def canonical_name(self, name: str) -> str:
        if name in self._secrets:
            return name
        raise KeyError(f"Unknown canonical name: '{name}'")

    @staticmethod
    def _host_matches(pattern: str, host: str) -> bool:
        expected, actual = pattern.lower().split("."), host.lower().split(".")
        return len(expected) == len(actual) and all(
            left == "*" or left == right for left, right in zip(expected, actual)
        )

    def _hosts(self, name: str) -> list[str]:
        info = self._secrets[name]
        if "hosts" in info:  # Legacy test fixtures model the old broad policy.
            return info["hosts"]
        return [host for placement in info.get("placements", []) for host in placement["hosts"]]

    def host_allowed(self, name: str, host: str) -> bool:
        """Model the old host-only addon so new exploit tests start RED."""
        if name not in self._secrets:
            raise KeyError(f"Unknown canonical name: '{name}'")
        return any(self._host_matches(pattern, host) for pattern in self._hosts(name))

    def placement_allowed(self, secret_name: str, **context) -> bool:
        if secret_name not in self._secrets:
            raise KeyError(f"Unknown canonical name: '{secret_name}'")
        info = self._secrets[secret_name]
        if "placements" not in info:
            return self.host_allowed(secret_name, context["host"])
        for placement in info["placements"]:
            if placement["kind"] != context["kind"]:
                continue
            if not any(self._host_matches(pattern, context["host"]) for pattern in placement["hosts"]):
                continue
            if placement.get("methods") and context["method"].upper() not in placement["methods"]:
                continue
            paths = placement.get("paths", [])
            if paths and not any(
                context["path"].startswith(pattern[:-1]) if pattern.endswith("*")
                else context["path"] == pattern
                for pattern in paths
            ):
                continue
            kind = placement["kind"]
            if kind == "header" and (
                placement["name"].lower() != (context.get("name") or "").lower()
                or placement["template"] != context.get("template")
            ):
                continue
            if kind in {"query", "form"} and (
                placement["name"] != context.get("name")
                or placement["template"] != context.get("template")
            ):
                continue
            if kind == "basic-password" and placement.get("username") not in (
                None, context.get("username")
            ):
                continue
            return True
        return False

    def has_placement_kind(self, name: str, kind: str) -> bool:
        if name not in self._secrets:
            raise KeyError(f"Unknown canonical name: '{name}'")
        return any(item["kind"] == kind for item in self._secrets[name].get("placements", []))

    def secret(self, name: str) -> SecretInfo:
        if name not in self._secrets:
            raise KeyError(f"Unknown canonical name: '{name}'")
        info = self._secrets[name]
        placements = [SecretPlacement(**item) for item in info.get("placements", [])]
        return SecretInfo(
            name=name,
            account=info.get("account", "runtime"),
            placements=placements,
            internal_only=info.get("internalOnly", False),
            reference_prefix=info.get("referencePrefix"),
        )


class FakeResolver:
    def __init__(self, values: dict[str, str] | None = None):
        self.values, self.get_calls = values or {}, []
    def get(self, name: str) -> str:
        self.get_calls.append(name)
        if name not in self.values: raise KeyError(f"Unknown secret: '{name}'")
        return self.values[name]
    def clear_cache(self) -> None: pass


def make_flow(host: str, path: str = "/", method: str = "GET", headers: dict | None = None,
              query: dict | None = None, content: bytes | None = None, content_type: str | None = None):
    from mitmproxy.test import tflow
    flow = tflow.tflow()
    flow.request.method, flow.request.host, flow.request.port = method, host, 443
    flow.request.scheme, flow.request.path = "https", path
    flow.request.headers.clear()
    flow.request.headers["Host"] = host
    if headers:
        for k, v in headers.items(): flow.request.headers[k] = v
    if query:
        for k, v in query.items(): flow.request.query[k] = v
    if content is not None: flow.request.content = content
    if content_type: flow.request.headers["Content-Type"] = content_type
    flow.response = None
    return flow


class AddonTestCase(unittest.TestCase):
    def setUp(self):
        import addon
        self.addon = addon
        self._orig = {
            name: getattr(addon, name)
            for name in (
                "_manifest",
                "_resolver",
                "_load_secret_store",
                "GoogleTokenProvider",
                "_google_provider_singleton",
                "_aws_provider",
                "_aws_provider_tried",
                "_manifest_mtime",
                "_test_store_injected",
            )
        }
    def tearDown(self):
        for name, value in self._orig.items():
            setattr(self.addon, name, value)


class TestSanitisedLogging(unittest.TestCase):
    def test_addon_logs_to_stderr_without_persistent_file_handler(self):
        import addon

        self.assertFalse(
            any(isinstance(handler, logging.FileHandler) for handler in addon.log.handlers)
        )
        streams = [
            handler
            for handler in addon.log.handlers
            if type(handler) is logging.StreamHandler
        ]
        self.assertEqual(len(streams), 1)
        self.assertIs(streams[0].stream, sys.stderr)


class TestSecretStoreHotReload(unittest.TestCase):
    def setUp(self):
        import addon

        self.addon = addon
        self.tempdir = tempfile.TemporaryDirectory()
        self.secrets_file = Path(self.tempdir.name) / "secrets.json"
        with open(self.secrets_file, "w") as f:
            f.write("{}")

        self._original_globals = {
            name: getattr(addon, name)
            for name in (
                "SECRETS_FILE",
                "_manifest",
                "_resolver",
                "_manifest_mtime",
                "_google_provider_singleton",
                "_aws_provider",
                "_aws_provider_tried",
                "_test_store_injected",
            )
        }
        addon.SECRETS_FILE = self.secrets_file
        addon._manifest = None
        addon._resolver = None
        addon._manifest_mtime = -1.0
        addon._google_provider_singleton = None
        addon._aws_provider = None
        addon._aws_provider_tried = False
        addon._test_store_injected = False

        self.load_calls = []
        self.resolver_calls = []
        self.fail_load = False
        self.manifests = [object(), object()]
        self.resolvers = [object(), object()]

        def fake_load(path, env):
            self.load_calls.append((path, env))
            if self.fail_load:
                raise RuntimeError("reload failed")
            return self.manifests[len(self.load_calls) - 1]

        def fake_from_environment(manifest, env):
            self.resolver_calls.append((manifest, env))
            return self.resolvers[len(self.resolver_calls) - 1]

        self._env_patch = patch.dict(os.environ, {"SECRET_PROVIDER": "bitwarden"})
        self._load_patch = patch.object(SecretManifest, "load", side_effect=fake_load)
        self._resolver_patch = patch.object(
            SecretResolver, "from_environment", side_effect=fake_from_environment
        )
        self._env_patch.start()
        self._load_patch.start()
        self._resolver_patch.start()

    def tearDown(self):
        self._resolver_patch.stop()
        self._load_patch.stop()
        self._env_patch.stop()
        for name, value in self._original_globals.items():
            setattr(self.addon, name, value)
        self.tempdir.cleanup()

    def _set_mtime(self, value):
        os.utime(self.secrets_file, (value, value))

    def test_first_load_loads_manifest_and_resolver(self):
        self._set_mtime(100.0)

        self.addon._load_secret_store()

        self.assertEqual(len(self.load_calls), 1)
        self.assertEqual(len(self.resolver_calls), 1)
        self.assertIs(self.addon._manifest, self.manifests[0])
        self.assertIs(self.addon._resolver, self.resolvers[0])
        self.assertEqual(self.addon._manifest_mtime, 100.0)

    def test_concurrent_changed_mtime_reload_is_single_flight(self):
        self._set_mtime(100.0)
        self.addon._load_secret_store()
        self._set_mtime(200.0)

        manifest = object()
        resolver = object()
        load_calls = []
        resolver_calls = []
        call_lock = threading.Lock()
        load_entered = threading.Event()
        load_release = threading.Event()
        resolver_entered = threading.Event()
        resolver_release = threading.Event()

        def slow_load(path, env):
            with call_lock:
                load_calls.append((path, env))
            load_entered.set()
            if not load_release.wait(timeout=5):
                raise AssertionError("timed out waiting to release manifest load")
            return manifest

        def slow_from_environment(loaded_manifest, env):
            with call_lock:
                resolver_calls.append((loaded_manifest, env))
            resolver_entered.set()
            if not resolver_release.wait(timeout=5):
                raise AssertionError("timed out waiting to release resolver creation")
            return resolver

        SecretManifest.load.side_effect = slow_load
        SecretResolver.from_environment.side_effect = slow_from_environment
        results = [None] * 3
        errors = []

        def load_in_thread(index):
            try:
                results[index] = self.addon._load_secret_store()
            except BaseException as error:  # surface worker failures in the test
                errors.append(error)

        threads = [threading.Thread(target=load_in_thread, args=(index,)) for index in range(3)]
        for thread in threads:
            thread.start()

        try:
            self.assertTrue(load_entered.wait(timeout=5))
            self.assertEqual(len(load_calls), 1)
            self.assertTrue(all(thread.is_alive() for thread in threads))

            load_release.set()
            self.assertTrue(resolver_entered.wait(timeout=5))
            self.assertEqual(len(resolver_calls), 1)
            self.assertTrue(all(thread.is_alive() for thread in threads))
        finally:
            load_release.set()
            resolver_release.set()

        for thread in threads:
            thread.join(timeout=5)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(results, [None] * 3)
        self.assertEqual((len(load_calls), len(resolver_calls)), (1, 1))
        self.assertIs(self.addon._manifest, manifest)
        self.assertIs(self.addon._resolver, resolver)

    def test_unchanged_mtime_does_not_reload(self):
        self._set_mtime(100.0)
        self.addon._load_secret_store()

        self.addon._load_secret_store()

        self.assertEqual(len(self.load_calls), 1)
        self.assertEqual(len(self.resolver_calls), 1)

    def test_changed_mtime_reloads_and_resets_google_provider(self):
        self._set_mtime(100.0)
        self.addon._load_secret_store()
        self.addon._google_provider_singleton = object()
        self._set_mtime(200.0)

        self.addon._load_secret_store()

        self.assertEqual(len(self.load_calls), 2)
        self.assertEqual(len(self.resolver_calls), 2)
        self.assertIs(self.addon._manifest, self.manifests[1])
        self.assertIs(self.addon._resolver, self.resolvers[1])
        self.assertIsNone(self.addon._google_provider_singleton)
        self.assertEqual(self.addon._manifest_mtime, 200.0)

    def test_changed_mtime_successful_reload_resets_aws_provider(self):
        self._set_mtime(100.0)
        self.addon._load_secret_store()
        self.addon._aws_provider = object()
        self.addon._aws_provider_tried = True
        self._set_mtime(200.0)

        self.addon._load_secret_store()

        self.assertIsNone(self.addon._aws_provider)
        self.assertFalse(self.addon._aws_provider_tried)

    def test_unchanged_mtime_does_not_reset_aws_provider(self):
        self._set_mtime(100.0)
        self.addon._load_secret_store()
        provider = object()
        self.addon._aws_provider = provider
        self.addon._aws_provider_tried = True

        self.addon._load_secret_store()

        self.assertIs(self.addon._aws_provider, provider)
        self.assertTrue(self.addon._aws_provider_tried)
        self.assertEqual(len(self.load_calls), 1)
        self.assertEqual(len(self.resolver_calls), 1)

    def test_reload_exception_clears_stale_store_and_raises(self):
        self._set_mtime(100.0)
        self.addon._load_secret_store()
        self.addon._google_provider_singleton = object()
        self._set_mtime(200.0)
        self.fail_load = True

        with self.assertRaises(RuntimeError):
            self.addon._load_secret_store()

        self.assertIsNone(self.addon._manifest)
        self.assertIsNone(self.addon._resolver)
        self.assertIsNone(self.addon._google_provider_singleton)
        self.assertEqual(self.addon._manifest_mtime, 200.0)

    def test_reload_exception_resets_aws_provider(self):
        self._set_mtime(100.0)
        self.addon._load_secret_store()
        self.addon._aws_provider = object()
        self.addon._aws_provider_tried = True
        self._set_mtime(200.0)
        self.fail_load = True

        with self.assertRaises(RuntimeError):
            self.addon._load_secret_store()

        self.assertIsNone(self.addon._aws_provider)
        self.assertFalse(self.addon._aws_provider_tried)

    def test_changed_mtime_reload_retries_after_transient_factory_failure(self):
        self._set_mtime(100.0)
        self.addon._load_secret_store()
        stale_manifest = self.addon._manifest
        stale_resolver = self.addon._resolver
        self._set_mtime(200.0)
        changed_mtime = self.secrets_file.stat().st_mtime

        reloaded_manifest = object()
        reloaded_resolver = object()
        load_calls = []
        factory_calls = []

        def load_manifest(path, env):
            load_calls.append((path, env))
            return reloaded_manifest

        def make_resolver(manifest, env):
            factory_calls.append((manifest, env))
            if len(factory_calls) == 1:
                raise RuntimeError("transient resolver factory failure")
            return reloaded_resolver

        SecretManifest.load.side_effect = load_manifest
        SecretResolver.from_environment.side_effect = make_resolver

        with self.assertRaises(RuntimeError):
            self.addon._load_secret_store()

        self.assertIsNone(self.addon._manifest)
        self.assertIsNone(self.addon._resolver)
        self.assertIsNotNone(stale_manifest)
        self.assertIsNotNone(stale_resolver)
        self.assertEqual(self.secrets_file.stat().st_mtime, changed_mtime)

        # A transient failure must not poison the changed mtime: retry the
        # complete load/factory transaction without requiring another edit.
        self.addon._load_secret_store()

        self.assertEqual(len(load_calls), 2)
        self.assertEqual(len(factory_calls), 2)
        self.assertIs(factory_calls[0][0], reloaded_manifest)
        self.assertIs(factory_calls[1][0], reloaded_manifest)
        self.assertIs(self.addon._manifest, reloaded_manifest)
        self.assertIs(self.addon._resolver, reloaded_resolver)
        self.assertEqual(self.addon._manifest_mtime, changed_mtime)
        self.assertEqual(self.secrets_file.stat().st_mtime, changed_mtime)

    def test_injected_test_globals_with_sentinel_mtime_are_preserved(self):
        manifest, resolver = object(), object()
        self.addon._manifest = manifest
        self.addon._resolver = resolver
        self.addon._manifest_mtime = -1.0
        self.addon._test_store_injected = True

        self.addon._load_secret_store()

        self.assertIs(self.addon._manifest, manifest)
        self.assertIs(self.addon._resolver, resolver)
        self.assertEqual(self.addon._manifest_mtime, -1.0)
        self.assertEqual(self.load_calls, [])
        self.assertEqual(self.resolver_calls, [])

    def test_reload_publishes_new_generation_while_old_lookup_is_in_flight(self):
        host = "api.example.com"
        old_manifest = FakeManifest({"OLD_KEY": {"hosts": [host]}})
        new_manifest = FakeManifest({"NEW_KEY": {"hosts": [host]}})
        old_lookup_entered = threading.Event()
        old_lookup_release = threading.Event()
        reload_complete = threading.Event()
        reload_errors = []
        old_request_errors = []

        class SlowOldResolver(FakeResolver):
            def get(self, name):
                self.get_calls.append(name)
                old_lookup_entered.set()
                if not old_lookup_release.wait(timeout=5):
                    raise AssertionError("timed out waiting to release old lookup")
                return self.values[name]

        old_resolver = SlowOldResolver({"OLD_KEY": "old-real"})
        new_resolver = FakeResolver({"NEW_KEY": "new-real"})
        self.addon._manifest = old_manifest
        self.addon._resolver = old_resolver
        self.addon._manifest_mtime = 100.0
        self.addon._test_store_injected = False
        self._set_mtime(100.0)

        load_calls = []
        resolver_calls = []

        def load_new_manifest(path, env):
            load_calls.append((path, env))
            return new_manifest

        def make_new_resolver(manifest, env):
            resolver_calls.append((manifest, env))
            return new_resolver

        SecretManifest.load.side_effect = load_new_manifest
        SecretResolver.from_environment.side_effect = make_new_resolver
        old_flow = make_flow(host, headers={"X-Secret": "secretref:OLD_KEY"})

        def run_old_request():
            try:
                self.addon.request(old_flow)
            except BaseException as error:  # surface worker failures in the test
                old_request_errors.append(error)

        old_thread = threading.Thread(target=run_old_request)
        reload_thread = None
        old_thread.start()

        try:
            self.assertTrue(old_lookup_entered.wait(timeout=5))
            self._set_mtime(200.0)

            def reload_store():
                try:
                    self.addon._load_secret_store()
                except BaseException as error:  # surface worker failures in the test
                    reload_errors.append(error)
                finally:
                    reload_complete.set()

            reload_thread = threading.Thread(target=reload_store)
            reload_thread.start()

            # Publishing must not wait for an unrelated old resolver call. The
            # old request still owns its captured generation while this happens.
            self.assertTrue(
                reload_complete.wait(timeout=5),
                "store reload waited for the old resolver lookup",
            )
            self.assertEqual(reload_errors, [])
            self.assertEqual(len(load_calls), 1)
            self.assertEqual(len(resolver_calls), 1)
            self.assertIs(resolver_calls[0][0], new_manifest)
            self.assertIs(self.addon._manifest, new_manifest)
            self.assertIs(self.addon._resolver, new_resolver)

            new_flow = make_flow(host, headers={"X-Secret": "secretref:NEW_KEY"})
            self.addon.request(new_flow)
            self.assertIsNone(new_flow.response)
            self.assertEqual(new_flow.request.headers["X-Secret"], "new-real")

            old_lookup_release.set()
            old_thread.join(timeout=5)
            self.assertFalse(old_thread.is_alive())
            self.assertEqual(old_request_errors, [])
            self.assertIsNone(old_flow.response)
            self.assertEqual(old_flow.request.headers["X-Secret"], "old-real")
            self.assertEqual(old_resolver.get_calls, ["OLD_KEY"])
        finally:
            old_lookup_release.set()
            old_thread.join(timeout=5)
            if reload_thread is not None:
                reload_thread.join(timeout=5)


# --- Injection Tests (one per sink) ---

class TestHttpsTransportPolicy(AddonTestCase):
    def _http(self, flow):
        flow.request.scheme = "http"
        flow.request.port = 80
        return flow

    def _assert_blocked_before_generation(self, flow, hook_name="request"):
        original_host = flow.request.host
        original_path = flow.request.path
        original_headers = list(flow.request.headers.items(multi=True))
        original_content = flow.request.raw_content
        with patch.object(
            self.addon,
            "_capture_generation",
            wraps=self.addon._capture_generation,
        ) as capture:
            getattr(self.addon, hook_name)(flow)

        capture.assert_not_called()
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(
            json.loads(flow.response.content),
            {"error": "secret_proxy_https_required"},
        )
        self.assertEqual(flow.request.host, original_host)
        self.assertEqual(flow.request.path, original_path)
        self.assertEqual(
            list(flow.request.headers.items(multi=True)),
            original_headers,
        )
        self.assertEqual(flow.request.raw_content, original_content)

    def test_http_secret_injection_sinks_block_before_store_generation(self):
        host = "api.example.com"
        self.addon._manifest = FakeManifest({"API_KEY": {"hosts": [host]}})
        self.addon._resolver = FakeResolver({"API_KEY": "real-value"})
        basic = base64.b64encode(b"user:secretref:API_KEY").decode()
        cases = (
            ("header", self._http(make_flow(host, headers={"X-Secret": "secretref:API_KEY"}))),
            ("query", self._http(make_flow(host, query={"key": "secretref:API_KEY"}))),
            ("basic", self._http(make_flow(host, headers={"Authorization": f"Basic {basic}"}))),
            (
                "body",
                self._http(make_flow(
                    host,
                    method="POST",
                    content=b'{"key":"secretref:API_KEY"}',
                    content_type="application/json",
                )),
            ),
        )

        for name, flow in cases:
            with self.subTest(sink=name):
                self._assert_blocked_before_generation(flow)
        self.assertEqual(self.addon._resolver.get_calls, [])

    def test_reference_free_http_passthrough_does_not_load_secret_store(self):
        flow = self._http(make_flow("public.example.com"))
        with patch.object(
            self.addon,
            "_capture_generation",
            wraps=self.addon._capture_generation,
        ) as capture:
            self.addon.requestheaders(flow)
            self.addon.request(flow)

        capture.assert_not_called()
        self.assertIsNone(flow.response)

    def test_http_url_rewrite_blocks_before_resolution(self):
        self.addon._manifest = FakeManifest({
            "WEBHOOK": {"hosts": ["hooks.slack.com"]},
        })
        self.addon._resolver = FakeResolver({
            "WEBHOOK": "https://hooks.slack.com/services/example",
        })
        flow = self._http(make_flow("secretref.invalid", "/WEBHOOK", method="POST"))

        self._assert_blocked_before_generation(flow)

        self.assertEqual(self.addon._resolver.get_calls, [])

    def test_http_aws_signing_paths_block_before_provider_access(self):
        buffered = self._http(make_flow(
            "sts.eu-west-1.amazonaws.com",
            headers={"Authorization": "AWS4-HMAC-SHA256 dummy"},
        ))
        presigned = self._http(make_flow(
            "bucket.s3.eu-west-1.amazonaws.com",
            query={
                "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                "X-Amz-Signature": "dummy",
                "X-Amz-Security-Token": "secretrole:123456789012/role",
            },
        ))

        with patch.object(self.addon, "_get_aws_provider") as provider:
            self._assert_blocked_before_generation(buffered)
            self._assert_blocked_before_generation(presigned, "requestheaders")
        provider.assert_not_called()

    def test_http_guard_preserves_existing_proxy_response(self):
        flow = self._http(make_flow("api.example.com"))
        flow.response = self.addon.http.Response.make(
            407,
            b"proxy auth required",
            {"Proxy-Authenticate": 'Basic realm="proxy"'},
        )

        self.addon.requestheaders(flow)
        self.addon.request(flow)

        self.assertEqual(flow.response.status_code, 407)
        self.assertEqual(flow.response.headers["Proxy-Authenticate"], 'Basic realm="proxy"')
        self.assertEqual(flow.response.content, b"proxy auth required")

    def test_direct_http_aws_helpers_block_before_provider_access(self):
        presigned = self._http(make_flow("bucket.s3.eu-west-1.amazonaws.com"))
        signed = self._http(make_flow("sts.eu-west-1.amazonaws.com"))

        with patch.object(self.addon, "_get_aws_provider", return_value=None) as provider:
            self.addon._resign_presigned(presigned)
            result = self.addon._aws_resign_apply(signed, None)

        provider.assert_not_called()
        self.assertIsNone(result)
        for flow in (presigned, signed):
            self.assertEqual(flow.response.status_code, 403)
            self.assertEqual(
                json.loads(flow.response.content),
                {"error": "secret_proxy_https_required"},
            )


class TestInjectionPlacementEnforcement(AddonTestCase):
    @staticmethod
    def _header(host, name="authorization", template="Bearer {secret}", **extra):
        return {
            "kind": "header", "hosts": [host], "name": name,
            "template": template, **extra,
        }

    def _assert_policy_blocked_without_lookup(self, flow, resolver):
        original_headers = list(flow.request.headers.items(multi=True))
        original_path = flow.request.path
        original_content = flow.request.raw_content
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(resolver.get_calls, [])
        self.assertEqual(list(flow.request.headers.items(multi=True)), original_headers)
        self.assertEqual(flow.request.path, original_path)
        self.assertEqual(flow.request.raw_content, original_content)

    def test_slack_token_text_in_opaque_body_does_not_block_header_injection(self):
        token_name = "SLACK_TOKEN"
        resolver = FakeResolver({token_name: "xoxb-real"})
        self.addon._manifest = FakeManifest({token_name: {
            "placements": [self._header("slack.com", methods=["POST"], paths=["/api/*"])],
        }})
        self.addon._resolver = resolver
        body = json.dumps({"text": f"secretref:{token_name}"}).encode()
        flow = make_flow(
            "slack.com", "/api/chat.postMessage", "POST",
            headers={"Authorization": f"Bearer secretref:{token_name}"},
            content=body,
            content_type="application/json",
        )

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer xoxb-real")
        self.assertEqual(flow.request.content, body)
        self.assertEqual(resolver.get_calls, [token_name])

    def test_bedrock_secretref_text_in_model_prompt_passes_through(self):
        token_name = "BEDROCK_TOKEN"
        resolver = FakeResolver({token_name: "bedrock-real"})
        self.addon._manifest = FakeManifest({token_name: {
            "placements": [self._header(
                "bedrock-runtime.*.amazonaws.com", methods=["POST"], paths=["/model/*"],
            )],
        }})
        self.addon._resolver = resolver
        body = json.dumps({"prompt": f"repeat secretref:{token_name}"}).encode()
        flow = make_flow(
            "bedrock-runtime.eu-west-1.amazonaws.com", "/model/example/converse", "POST",
            content=body,
            content_type="application/json",
        )

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.content, body)
        self.assertEqual(resolver.get_calls, [])

    def test_github_token_is_rejected_from_arbitrary_metadata_sinks(self):
        token_name = "GITHUB_TOKEN"
        placement = self._header("api.github.com", template="token {secret}")
        cases = (
            make_flow("api.github.com", headers={"X-Store-Me": f"secretref:{token_name}"}),
            make_flow("api.github.com", query={"echo": f"secretref:{token_name}"}),
        )
        for flow in cases:
            with self.subTest(path=flow.request.path):
                resolver = FakeResolver({token_name: "github-real"})
                self.addon._manifest = FakeManifest({token_name: {"placements": [placement]}})
                self.addon._resolver = resolver
                self._assert_policy_blocked_without_lookup(flow, resolver)

    def test_github_secretref_text_in_opaque_issue_body_passes_through(self):
        token_name = "GITHUB_TOKEN"
        resolver = FakeResolver({token_name: "github-real"})
        self.addon._manifest = FakeManifest({token_name: {
            "placements": [self._header("api.github.com", template="token {secret}")],
        }})
        self.addon._resolver = resolver
        body = json.dumps({"body": f"secretref:{token_name}"}).encode()
        flow = make_flow(
            "api.github.com", "/repos/o/r/issues", "POST",
            content=body, content_type="application/json",
        )

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.content, body)
        self.assertEqual(resolver.get_calls, [])

    def test_form_secret_is_rejected_for_wrong_field_or_path(self):
        name = "WIZ_CLIENT_SECRET"
        placement = {
            "kind": "form", "hosts": ["auth.app.wiz.io"],
            "name": "client_secret", "template": "{secret}",
            "methods": ["POST"], "paths": ["/oauth/token"],
        }
        cases = (
            ("/oauth/token", "POST", "message"),
            ("/oauth/echo", "POST", "client_secret"),
            ("/oauth/token", "GET", "client_secret"),
        )
        for path, method, field in cases:
            with self.subTest(path=path, method=method, field=field):
                resolver = FakeResolver({name: "wiz-real"})
                self.addon._manifest = FakeManifest({name: {"placements": [placement]}})
                self.addon._resolver = resolver
                body = urlencode({field: f"secretref:{name}"}).encode()
                flow = make_flow(
                    "auth.app.wiz.io", path, method, content=body,
                    content_type="application/x-www-form-urlencoded",
                )
                self._assert_policy_blocked_without_lookup(flow, resolver)

    def test_malformed_form_reference_blocks_all_lookups(self):
        name = "WIZ_CLIENT_SECRET"
        resolver = FakeResolver({name: "wiz-real"})
        self.addon._manifest = FakeManifest({name: {"placements": [{
            "kind": "form", "hosts": ["auth.app.wiz.io"],
            "name": "client_secret", "template": "{secret}",
            "methods": ["POST"], "paths": ["/oauth/token"],
        }]}})
        self.addon._resolver = resolver
        body = urlencode({
            "client_secret": f"secretref:{name}",
            "other": "secretref",
        }).encode()
        flow = make_flow(
            "auth.app.wiz.io", "/oauth/token", "POST", content=body,
            content_type="application/x-www-form-urlencoded",
        )
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(resolver.get_calls, [])
        self.assertEqual(flow.request.raw_content, body)

    def test_basic_secret_is_rejected_in_username_component(self):
        name = "GIT_TOKEN"
        resolver = FakeResolver({name: "git-real"})
        self.addon._manifest = FakeManifest({name: {"placements": [{
            "kind": "basic-password", "hosts": ["github.com"],
            "username": "x-access-token",
        }]}})
        self.addon._resolver = resolver
        encoded = base64.b64encode(f"secretref:{name}:not-a-secret".encode()).decode()
        flow = make_flow("github.com", headers={"Authorization": f"Basic {encoded}"})
        self._assert_policy_blocked_without_lookup(flow, resolver)

    def test_opaque_body_text_does_not_prevent_allowed_metadata_lookup(self):
        name = "SLACK_TOKEN"
        resolver = FakeResolver({name: "xoxb-real"})
        self.addon._manifest = FakeManifest({name: {
            "placements": [self._header("slack.com")],
        }})
        self.addon._resolver = resolver
        body = json.dumps({"text": f"secretref:{name}"}).encode()
        flow = make_flow(
            "slack.com", "/api/chat.postMessage", "POST",
            headers={"Authorization": f"Bearer secretref:{name}"},
            content=body,
            content_type="application/json",
        )

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer xoxb-real")
        self.assertEqual(flow.request.content, body)
        self.assertEqual(resolver.get_calls, [name])

    def test_exact_declared_header_templates_remain_allowed(self):
        cases = ("Bearer {secret}", "token {secret}")
        for template in cases:
            with self.subTest(template=template):
                name = "GITHUB_TOKEN"
                prefix = template.replace("{secret}", "")
                resolver = FakeResolver({name: "github-real"})
                self.addon._manifest = FakeManifest({name: {
                    "placements": [self._header("api.github.com", template=template)],
                }})
                self.addon._resolver = resolver
                flow = make_flow("api.github.com", headers={
                    "Authorization": f"{prefix}secretref:{name}",
                })
                self.addon.request(flow)
                self.assertIsNone(flow.response)
                self.assertEqual(
                    flow.request.headers["Authorization"], f"{prefix}github-real",
                )


class TestHeaderInjection(AddonTestCase):
    def test_bearer_header_substitution(self):
        self.addon._manifest = FakeManifest({"SLACK_TOKEN": {"hosts": ["slack.com"]}})
        self.addon._resolver = FakeResolver({"SLACK_TOKEN": "xoxb-real"})
        flow = make_flow("slack.com", headers={"Authorization": "Bearer secretref:SLACK_TOKEN"})
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer xoxb-real")
        self.assertIn("SLACK_TOKEN", self.addon._resolver.get_calls)

    def test_custom_header_substitution(self):
        self.addon._manifest = FakeManifest({"FINOUT_KEY": {"hosts": ["app.finout.io"]}})
        self.addon._resolver = FakeResolver({"FINOUT_KEY": "finout-secret"})
        flow = make_flow("app.finout.io", headers={"x-finout-secret-key": "secretref:FINOUT_KEY"})
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["x-finout-secret-key"], "finout-secret")


class TestReferencePrefix(AddonTestCase):
    """Key-shaped references for clients that validate a key before sending it."""

    REF = "secret" + "ref:STRIPE_KEY"

    def use(self, **spec):
        self.addon._manifest = FakeManifest({"STRIPE_KEY": {"placements": [{
            "kind": "header", "hosts": ["api.stripe.com"], "name": "authorization",
            "template": "Bearer {secret}",
        }], **spec}})
        self.resolver = FakeResolver({"STRIPE_KEY": "sk_test_real"})
        self.addon._resolver = self.resolver

    def send(self, value):
        flow = make_flow("api.stripe.com", "/v1/customers", headers={"Authorization": value})
        self.addon.request(flow)
        return flow

    def test_declared_prefix_is_replaced_with_the_reference(self):
        self.use(referencePrefix="sk_test_")
        flow = self.send(f"Bearer sk_test_{self.REF}")
        self.assertIsNone(flow.response)
        self.assertEqual("Bearer sk_test_real", flow.request.headers["Authorization"])

    def test_bare_reference_still_works_when_a_prefix_is_declared(self):
        self.use(referencePrefix="sk_test_")
        flow = self.send(f"Bearer {self.REF}")
        self.assertIsNone(flow.response)
        self.assertEqual("Bearer sk_test_real", flow.request.headers["Authorization"])

    def test_undeclared_or_different_prefix_is_blocked_without_lookup(self):
        for spec, value in (
            ({}, f"Bearer sk_test_{self.REF}"),
            ({"referencePrefix": "sk_test_"}, f"Bearer rk_test_{self.REF}"),
        ):
            with self.subTest(spec=spec, value=value):
                self.use(**spec)
                flow = self.send(value)
                self.assertIsNotNone(flow.response)
                self.assertEqual(403, flow.response.status_code)
                self.assertEqual([], self.resolver.get_calls)
                self.assertNotIn("real", flow.request.headers["Authorization"])


class TestTransactionalMetadataInjection(AddonTestCase):
    def test_request_policy_failure_does_not_commit_prior_header_substitution(self):
        host = "api.example.com"
        first_original = "secretref:ALLOWED_KEY"
        second_original = "secretref:DENIED_KEY"
        self.addon._manifest = FakeManifest({
            "ALLOWED_KEY": {"hosts": [host]},
            "DENIED_KEY": {"hosts": ["other.example.com"]},
        })
        self.addon._resolver = FakeResolver({
            "ALLOWED_KEY": "allowed-real",
            "DENIED_KEY": "denied-real",
        })
        flow = make_flow(host, headers={
            "X-First-Secret": first_original,
            "X-Second-Secret": second_original,
        })

        self.addon.request(flow)

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.request.headers["X-First-Secret"], first_original)
        self.assertEqual(flow.request.headers["X-Second-Secret"], second_original)

    def test_opaque_body_text_does_not_block_transactional_metadata_substitution(self):
        host = "api.example.com"
        header_original = "secretref:ALLOWED_KEY"
        cases = (
            ("malformed", b'{"secret":"secretref:"}'),
            ("undeclared", b'{"secret":"secretref:DENIED_KEY"}'),
        )

        for name, body_original in cases:
            with self.subTest(body=name):
                self.addon._manifest = FakeManifest({
                    "ALLOWED_KEY": {"hosts": [host]},
                    "DENIED_KEY": {"hosts": ["other.example.com"]},
                })
                resolver = FakeResolver({"ALLOWED_KEY": "allowed-real"})
                self.addon._resolver = resolver
                flow = make_flow(
                    host,
                    method="POST",
                    headers={"X-Secret": header_original},
                    content=body_original,
                    content_type="application/json",
                )
                flow.request.headers["Content-Length"] = str(len(body_original))
                original_content_length = flow.request.headers["Content-Length"]

                self.addon.request(flow)

                self.assertIsNone(flow.response)
                self.assertEqual(flow.request.headers["X-Secret"], "allowed-real")
                self.assertEqual(flow.request.headers["Content-Length"], original_content_length)
                self.assertEqual(flow.request.content, body_original)
                self.assertEqual(resolver.get_calls, ["ALLOWED_KEY"])

    def test_requestheaders_policy_failure_does_not_commit_header_or_query_substitution(self):
        host = "api.example.com"
        header_original = "secretref:ALLOWED_KEY"
        query_original = "secretref:DENIED_KEY"
        self.addon._manifest = FakeManifest({
            "ALLOWED_KEY": {"hosts": [host]},
            "DENIED_KEY": {"hosts": ["other.example.com"]},
        })
        self.addon._resolver = FakeResolver({"ALLOWED_KEY": "allowed-real"})
        flow = make_flow(
            host,
            headers={"X-Secret": header_original},
            query={"secret": query_original},
        )
        flow.request.stream = True

        self.addon.requestheaders(flow)

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.request.headers["X-Secret"], header_original)
        self.assertEqual(flow.request.query["secret"], query_original)

    def test_requestheaders_commit_failure_rolls_back_all_request_metadata(self):
        host = "api.example.com"
        first_marker = "secretref:FIRST_KEY"
        second_marker = "secretref:SECOND_KEY"
        first_real = "first-real-secret"
        second_real = "second-real-secret"
        query_marker = "secretref:QUERY_KEY"
        query_real = "query-real-secret"
        path_original = "/v1/secretref:PATH_MARKER"
        body_original = b'{"payload":"secretref:BODY_MARKER"}'
        self.addon._manifest = FakeManifest({
            "FIRST_KEY": {"hosts": [host]},
            "SECOND_KEY": {"hosts": [host]},
            "QUERY_KEY": {"hosts": [host]},
        })
        self.addon._resolver = FakeResolver({
            "FIRST_KEY": first_real,
            "SECOND_KEY": second_real,
            "QUERY_KEY": query_real,
        })
        flow = make_flow(
            host,
            path=path_original,
            method="POST",
            headers={
                "X-First-Secret": first_marker,
                "X-Second-Secret": second_marker,
            },
            query={"secret": query_marker, "keep": "unchanged"},
            content=body_original,
            content_type="application/json",
        )
        flow.request.stream = True
        original_headers = list(flow.request.headers.items(multi=True))
        original_query = list(flow.request.query.items(multi=True))
        original_full_path = flow.request.path

        def partial_commit(partial_flow, plan):
            self.assertGreaterEqual(len(plan["headers"]), 2)
            self.assertEqual(len(plan["query"]), 1)
            first_name, first_value = plan["headers"][0]
            query_name, query_value = plan["query"][0]
            self.assertEqual(first_value, first_real)
            self.assertEqual(query_value, query_real)
            partial_flow.request.headers[first_name] = first_value
            partial_flow.request.query[query_name] = query_value
            raise ValueError("commit failed after header and query")

        with patch.object(self.addon, "_commit_request_metadata", side_effect=partial_commit):
            self.addon.requestheaders(flow)

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(list(flow.request.headers.items(multi=True)), original_headers)
        self.assertEqual(list(flow.request.query.items(multi=True)), original_query)
        self.assertEqual(flow.request.path, original_full_path)
        self.assertEqual(flow.request.raw_content, body_original)

        request_text = "\n".join([
            flow.request.path,
            *(f"{name}: {value}" for name, value in flow.request.headers.items(multi=True)),
            *(str(value) for value in flow.request.query.values()),
            (flow.request.raw_content or b"").decode("utf-8", errors="replace"),
        ])
        for real_secret in (first_real, second_real, query_real):
            self.assertNotIn(real_secret, request_text)
            self.assertNotIn(real_secret, flow.response.content.decode("utf-8"))


class TestStreamedMetadataInjection(AddonTestCase):
    def test_streamed_metadata_sinks_are_substituted_before_forwarding(self):
        host = "api.example.com"
        self.addon._manifest = FakeManifest({
            "HEADER_KEY": {"hosts": [host]},
            "QUERY_KEY": {"hosts": [host]},
            "BASIC_KEY": {"hosts": [host]},
        })
        self.addon._resolver = FakeResolver({
            "HEADER_KEY": "header-real",
            "QUERY_KEY": "query-real",
            "BASIC_KEY": "basic-real",
        })

        cases = [
            ("custom header", make_flow(host, headers={"X-Secret": "secretref:HEADER_KEY"}),
             lambda flow: self.assertEqual(flow.request.headers["X-Secret"], "header-real")),
            ("query", make_flow(host, query={"secret": "secretref:QUERY_KEY"}),
             lambda flow: self.assertEqual(flow.request.query["secret"], "query-real")),
        ]
        basic = base64.b64encode(b"user@example.com:secretref:BASIC_KEY").decode()
        cases.append((
            "basic auth",
            make_flow(host, headers={"Authorization": f"Basic {basic}"}),
            lambda flow: self.assertEqual(
                base64.b64decode(flow.request.headers["Authorization"][6:]).decode(),
                "user@example.com:basic-real",
            ),
        ))

        for name, flow, assertion in cases:
            with self.subTest(sink=name):
                flow.request.stream = True
                self.addon.requestheaders(flow)
                self.addon.request(flow)
                self.assertIsNone(flow.response)
                assertion(flow)

    def test_non_aws_streamed_body_fails_closed_before_forwarding(self):
        self.addon._manifest = FakeManifest({"API_KEY": {"hosts": ["api.example.com"]}})
        self.addon._resolver = FakeResolver({"API_KEY": "real-value"})
        flow = make_flow(
            "api.example.com",
            method="POST",
            content=b'{"token":"secretref:API_KEY"}',
            content_type="application/json",
        )
        flow.request.stream = True

        self.addon.requestheaders(flow)

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(
            json.loads(flow.response.content)["error"],
            "secret_proxy_streamed_body_unsupported",
        )
        self.assertIn(b"secretref:API_KEY", flow.request.raw_content)


class TestQueryInjection(AddonTestCase):
    def test_query_param_substitution(self):
        self.addon._manifest = FakeManifest({
            "PARSLY_KEY": {"hosts": ["api.parsely.com"]},
            "PARSLY_SECRET": {"hosts": ["api.parsely.com"]},
        })
        self.addon._resolver = FakeResolver({"PARSLY_KEY": "key-123", "PARSLY_SECRET": "secret-456"})
        flow = make_flow("api.parsely.com", "/analytics",
                        query={"apikey": "secretref:PARSLY_KEY", "secret": "secretref:PARSLY_SECRET"})
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.query["apikey"], "key-123")
        self.assertEqual(flow.request.query["secret"], "secret-456")


class TestBasicAuthInjection(AddonTestCase):
    def test_basic_auth_substitution(self):
        self.addon._manifest = FakeManifest({"JIRA_KEY": {"hosts": ["example.atlassian.net"]}})
        self.addon._resolver = FakeResolver({"JIRA_KEY": "jira-token-xyz"})
        creds = base64.b64encode(b"user@example.com:secretref:JIRA_KEY").decode()
        flow = make_flow("example.atlassian.net", headers={"Authorization": f"Basic {creds}"})
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        decoded = base64.b64decode(flow.request.headers["Authorization"][6:]).decode()
        self.assertEqual(decoded, "user@example.com:jira-token-xyz")


class TestFormBodyInjection(AddonTestCase):
    def test_form_body_substitution(self):
        self.addon._manifest = FakeManifest({
            "WIZ_CLIENT_ID": {"hosts": ["auth.app.wiz.io"]},
            "WIZ_CLIENT_SECRET": {"hosts": ["auth.app.wiz.io"]},
        })
        self.addon._resolver = FakeResolver({"WIZ_CLIENT_ID": "wiz-client", "WIZ_CLIENT_SECRET": "wiz-secret"})
        body = b"grant_type=client_credentials&client_id=secretref%3AWIZ_CLIENT_ID&client_secret=secretref%3AWIZ_CLIENT_SECRET"
        flow = make_flow("auth.app.wiz.io", "/oauth/token", "POST",
                        content=body, content_type="application/x-www-form-urlencoded")
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        form = dict(flow.request.urlencoded_form.items(multi=False))
        self.assertEqual(form.get("client_id"), "wiz-client")
        self.assertEqual(form.get("client_secret"), "wiz-secret")


class TestBodyFraming(AddonTestCase):
    @staticmethod
    def _form_manifest(host):
        return FakeManifest({"API_KEY": {"placements": [{
            "kind": "form", "hosts": [host], "name": "apiKey",
            "template": "{secret}",
        }]}})

    def _assert_content_length_tracks_rewritten_body(self, body, expected_value):
        host = "api.example.com"
        self.addon._manifest = self._form_manifest(host)
        self.addon._resolver = FakeResolver({"API_KEY": expected_value})
        flow = make_flow(
            host, "/v1", "POST", content=body,
            content_type="application/x-www-form-urlencoded",
        )
        flow.request.headers["Content-Length"] = str(len(body))
        original_length = flow.request.headers["Content-Length"]

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertNotEqual(len(flow.request.raw_content), int(original_length))
        self.assertEqual(
            flow.request.headers["Content-Length"],
            str(len(flow.request.raw_content)),
        )
        form = dict(flow.request.urlencoded_form.items(multi=False))
        self.assertEqual(form["apiKey"], expected_value)

    def test_form_body_rewrite_updates_explicit_content_length_atomically(self):
        body = b"apiKey=" + b"secretref%3AAPI_KEY"
        self._assert_content_length_tracks_rewritten_body(
            body, "a-different-length-real-value"
        )

    def test_chunked_form_rewrite_drops_conflicting_content_length(self):
        body = b"apiKey=" + b"secretref%3AAPI_KEY"
        host = "api.example.com"
        self.addon._manifest = self._form_manifest(host)
        self.addon._resolver = FakeResolver({"API_KEY": "a-different-length-real-value"})
        flow = make_flow(
            host,
            "/v1",
            "POST",
            headers={
                "Content-Length": str(len(body)),
                "Transfer-Encoding": "chunked",
            },
            content=body,
            content_type="application/x-www-form-urlencoded",
        )

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["Transfer-Encoding"], "chunked")
        self.assertNotIn("Content-Length", flow.request.headers)
        self.assertNotEqual(flow.request.raw_content, body)


class TestOpaqueBodyPassthrough(AddonTestCase):
    def test_json_body_reference_text_passes_through_without_lookup(self):
        resolver = FakeResolver({"API_KEY": "real-key"})
        self.addon._manifest = FakeManifest({"API_KEY": {"placements": [{
            "kind": "header", "hosts": ["api.example.com"],
            "name": "authorization", "template": "Bearer {secret}",
        }]}})
        self.addon._resolver = resolver
        body = json.dumps({"apiKey": "secretref:API_KEY", "data": "test"}).encode()
        flow = make_flow(
            "api.example.com", "/v1", "POST",
            content=body, content_type="application/json",
        )

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(resolver.get_calls, [])
        self.assertEqual(flow.request.content, body)

    def test_opaque_body_size_is_not_limited_by_form_injection_cap(self):
        resolver = FakeResolver({"API_KEY": "real-key"})
        self.addon._manifest = FakeManifest({"API_KEY": {"hosts": ["api.example.com"]}})
        self.addon._resolver = resolver
        body = b"x" * 65536 + b"secretref:API_KEY"
        flow = make_flow(
            "api.example.com", "/v1", "POST", content=body,
            content_type="application/json",
        )

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(resolver.get_calls, [])
        self.assertEqual(flow.request.content, body)


class TestNonblockingSecretResolution(AddonTestCase):
    def test_slow_secret_lookup_does_not_block_no_reference_passthrough(self):
        host = "api.example.com"
        lookup_entered = threading.Event()
        lookup_release = threading.Event()
        passthrough_complete = threading.Event()
        slow_errors = []
        passthrough_errors = []

        class SlowResolver(FakeResolver):
            def get(self, name):
                self.get_calls.append(name)
                lookup_entered.set()
                if not lookup_release.wait(timeout=5):
                    raise AssertionError("timed out waiting to release slow lookup")
                return self.values[name]

        self.addon._manifest = FakeManifest({"SLOW_KEY": {"hosts": [host]}})
        self.addon._resolver = SlowResolver({"SLOW_KEY": "slow-real"})
        self.addon._manifest_mtime = -1.0
        self.addon._test_store_injected = True
        slow_flow = make_flow(host, headers={"X-Secret": "secretref:SLOW_KEY"})
        passthrough_flow = make_flow(host, headers={"X-Request": "ordinary"})

        def run_slow_request():
            try:
                self.addon.request(slow_flow)
            except BaseException as error:  # surface worker failures in the test
                slow_errors.append(error)

        def run_passthrough_request():
            try:
                self.addon.request(passthrough_flow)
            except BaseException as error:  # surface worker failures in the test
                passthrough_errors.append(error)
            finally:
                passthrough_complete.set()

        slow_thread = threading.Thread(target=run_slow_request)
        passthrough_thread = None
        slow_thread.start()

        try:
            self.assertTrue(lookup_entered.wait(timeout=5))
            passthrough_thread = threading.Thread(target=run_passthrough_request)
            passthrough_thread.start()

            # No sleep: the event means the slow resolver is definitely inside
            # its blocking section, so this completion must be independent of it.
            self.assertTrue(
                passthrough_complete.wait(timeout=5),
                "passthrough request waited for the slow secret lookup",
            )
            self.assertEqual(passthrough_errors, [])
            self.assertIsNone(passthrough_flow.response)
        finally:
            lookup_release.set()
            slow_thread.join(timeout=5)
            if passthrough_thread is not None:
                passthrough_thread.join(timeout=5)

        self.assertFalse(slow_thread.is_alive())
        self.assertIsNotNone(passthrough_thread)
        self.assertFalse(passthrough_thread.is_alive())
        self.assertEqual(slow_errors, [])
        self.assertIsNone(slow_flow.response)
        self.assertEqual(slow_flow.request.headers["X-Secret"], "slow-real")


class TestAwsProviderSelection(AddonTestCase):
    def test_aws_provider_receives_current_resolver_get_bound_method(self):
        resolver = FakeResolver({"AWS_SECRET": "real-secret"})
        provider = object()
        original_globals = {
            name: getattr(self.addon, name)
            for name in ("AWS_OKTA_FILE", "_resolver", "_aws_provider", "_aws_provider_tried")
        }

        with tempfile.TemporaryDirectory() as tempdir:
            config_path = Path(tempdir) / "aws-okta.json"
            config_path.write_text("{}")
            self.addon._resolver = resolver
            self.addon._aws_provider = None
            self.addon._aws_provider_tried = False

            try:
                with (
                    patch.object(self.addon, "AWS_OKTA_FILE", config_path),
                    patch.object(
                        self.addon.AwsCredsProvider,
                        "from_config_file",
                        return_value=provider,
                    ) as factory,
                ):
                    self.assertIs(self.addon._get_aws_provider(), provider)

                    factory.assert_called_once()
                    path, callback = factory.call_args.args
                    self.assertEqual(path, str(config_path))
                    self.assertIs(getattr(callback, "__self__", None), resolver)
                    self.assertIs(getattr(callback, "__func__", None), FakeResolver.get)
                    self.assertEqual(callback, resolver.get)
                    self.assertIsNot(callback, self.addon._resolve)
                    self.assertEqual(callback("AWS_SECRET"), "real-secret")
            finally:
                for name, value in original_globals.items():
                    setattr(self.addon, name, value)


class TestAwsRealCredentialPassthrough(AddonTestCase):
    """A real AWS credential used inside the container must reach AWS exactly as the
    caller signed it. Re-signing exists to swap the container's DUMMY creds for
    minted STS creds; applying it to a real credential silently replaces it and the
    call then reports this container's role, which makes verifying a leaked or
    third-party key impossible."""

    REAL_AUTH = (
        "AWS4-HMAC-SHA256 Credential=EXAMPLE-REAL-KEY-ID-NOT-THE-DUMMY/20260927/eu-west-1/sts/"
        "aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef"
    )
    DUMMY_AUTH = (
        "AWS4-HMAC-SHA256 Credential=secret-proxy-dummy-akid-resigned-on-wire/"
        "20260927/eu-west-1/sts/aws4_request, SignedHeaders=host;x-amz-date, "
        "Signature=deadbeef"
    )

    def test_dummy_selector_token_is_ours(self):
        flow = make_flow("sts.eu-west-1.amazonaws.com", headers={
            "Authorization": self.REAL_AUTH,
            "x-amz-security-token": "secretrole:123456789012/ReadOnly",
        })
        self.assertTrue(self.addon._is_aws_sigv4_ours(flow))

    def test_dummy_akid_without_session_token_is_ours(self):
        flow = make_flow("sts.eu-west-1.amazonaws.com", headers={
            "Authorization": self.DUMMY_AUTH,
        })
        self.assertTrue(self.addon._is_aws_sigv4_ours(flow))

    def test_real_credential_is_not_ours(self):
        flow = make_flow("sts.eu-west-1.amazonaws.com", headers={
            "Authorization": self.REAL_AUTH,
            "x-amz-security-token": "FwoGZXIvYXdzEBEaREALSESSIONTOKEN",
        })
        self.assertTrue(self.addon._is_aws_sigv4(flow))
        self.assertFalse(self.addon._is_aws_sigv4_ours(flow))

    def test_real_credential_is_not_resigned_in_buffered_hook(self):
        flow = make_flow("sts.eu-west-1.amazonaws.com", headers={
            "Authorization": self.REAL_AUTH,
            "x-amz-security-token": "FwoGZXIvYXdzEBEaREALSESSIONTOKEN",
        })
        with (
            patch.object(self.addon, "_load_secret_store"),
            patch.object(self.addon, "_resign_aws") as resign,
        ):
            self.addon.request(flow)
        resign.assert_not_called()
        self.assertEqual(flow.request.headers["Authorization"], self.REAL_AUTH)

    def test_dummy_credential_is_still_resigned_in_buffered_hook(self):
        flow = make_flow("sts.eu-west-1.amazonaws.com", headers={
            "Authorization": self.DUMMY_AUTH,
            "x-amz-security-token": "secretrole:123456789012/ReadOnly",
        })
        with (
            patch.object(self.addon, "_load_secret_store"),
            patch.object(self.addon, "_resign_aws") as resign,
        ):
            self.addon.request(flow)
        resign.assert_called_once()

    def test_real_credential_is_not_resigned_in_streaming_hook(self):
        """The S3 / streaming path is where a pasted key is most likely used
        (`aws s3 cp`), so it must pass through there too."""
        flow = make_flow("bucket.s3.eu-west-1.amazonaws.com", "/key", method="PUT", headers={
            "Authorization": self.REAL_AUTH,
            "x-amz-security-token": "FwoGZXIvYXdzEBEaREALSESSIONTOKEN",
            "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        })
        with (
            patch.object(self.addon, "_load_secret_store"),
            patch.object(self.addon, "_aws_resign_apply") as apply_resign,
        ):
            self.addon.requestheaders(flow)
        apply_resign.assert_not_called()
        self.assertFalse(callable(flow.request.stream))
        self.assertEqual(flow.request.headers["Authorization"], self.REAL_AUTH)

    def test_dummy_credential_is_still_resigned_in_streaming_hook(self):
        flow = make_flow("bucket.s3.eu-west-1.amazonaws.com", "/key", method="PUT", headers={
            "Authorization": self.DUMMY_AUTH,
            "x-amz-security-token": "secretrole:123456789012/ReadOnly",
            "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        })
        with (
            patch.object(self.addon, "_load_secret_store"),
            patch.object(self.addon, "_aws_resign_apply", return_value=None) as apply_resign,
        ):
            self.addon.requestheaders(flow)
        apply_resign.assert_called_once()

    def test_real_credential_over_plaintext_is_still_refused(self):
        """Narrowing re-signing must not narrow transport policy: a real credential
        sent over http:// would otherwise be forwarded in cleartext."""
        flow = make_flow("sts.eu-west-1.amazonaws.com", headers={
            "Authorization": self.REAL_AUTH,
            "x-amz-security-token": "FwoGZXIvYXdzEBEaREALSESSIONTOKEN",
        })
        flow.request.scheme = "http"
        flow.request.port = 80
        self.assertTrue(self.addon._plaintext_request_needs_credentials(flow))
        with patch.object(self.addon, "_load_secret_store"):
            self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertNotEqual(flow.response.status_code, 200)


class TestAwsRequestheadersOrdering(AddonTestCase):
    def test_aws_metadata_substitution_precedes_buffered_resign(self):
        events = []
        self.addon._manifest = FakeManifest({"API_KEY": {"hosts": ["sts.amazonaws.com"]}})
        self.addon._resolver = FakeResolver({"API_KEY": "canonical-real"})
        flow = make_flow(
            "sts.amazonaws.com",
            "/",
            headers={
                "Authorization": "AWS4-HMAC-SHA256 dummy",
                # Marks the request as signed with the container's dummy creds, which
                # is what re-signing acts on; a real credential is passed through.
                "x-amz-security-token": "secretrole:123456789012/role",
                "X-Custom-Secret": "secretref:API_KEY",
            },
        )

        def fake_is_aws_sigv4(_flow):
            return True

        def fake_resign_aws(resign_flow):
            events.append(resign_flow.request.headers["X-Custom-Secret"])

        with (
            patch.object(self.addon, "_is_aws_sigv4", side_effect=fake_is_aws_sigv4),
            patch.object(self.addon, "_load_secret_store"),
            patch.object(self.addon, "_resign_aws", side_effect=fake_resign_aws),
        ):
            self.addon.requestheaders(flow)
            self.addon.request(flow)

        self.assertEqual(events, ["canonical-real"])


class TestAwsRequestheadersInitialization(AddonTestCase):
    def test_non_streaming_non_s3_aws_metadata_waits_for_buffered_hook(self):
        marker = "secretref:API_KEY"
        events = []
        self.addon._manifest = FakeManifest({"API_KEY": {"hosts": ["sts.amazonaws.com"]}})
        self.addon._resolver = FakeResolver({"API_KEY": "canonical-real"})
        flow = make_flow(
            "sts.amazonaws.com",
            "/",
            headers={
                "Authorization": "AWS4-HMAC-SHA256 dummy",
                # Marks the request as signed with the container's dummy creds, which
                # is what re-signing acts on; a real credential is passed through.
                "x-amz-security-token": "secretrole:123456789012/role",
                "X-Custom-Secret": marker,
            },
        )
        flow.request.stream = False
        self.assertNotIn("x-amz-content-sha256", flow.request.headers)

        def fake_resign_aws(resign_flow):
            events.append(resign_flow.request.headers["X-Custom-Secret"])

        with (
            patch.object(self.addon, "_is_aws_sigv4", return_value=True),
            patch.object(self.addon, "_is_aws_presigned_ours", return_value=False),
            patch.object(self.addon, "_load_secret_store"),
            patch.object(self.addon, "_resign_aws", side_effect=fake_resign_aws),
        ):
            self.addon.requestheaders(flow)
            self.assertEqual(flow.request.headers["X-Custom-Secret"], marker)

            self.addon.request(flow)

        self.assertEqual(events, ["canonical-real"])

    def test_first_aws_request_loads_store_before_buffered_resign(self):
        events = []
        flow = make_flow(
            "sts.amazonaws.com",
            "/",
            headers={"Authorization": "AWS4-HMAC-SHA256 dummy", "x-amz-security-token": "secretrole:123456789012/role"},
        )

        def fake_is_aws_sigv4(_flow):
            events.append("_is_aws_sigv4")
            return True

        def fake_load_secret_store():
            events.append("_load_secret_store")

        def fake_resign_aws(_flow):
            events.append("_resign_aws")

        # mitmproxy runs requestheaders before request. The first hook must
        # initialize the store; the later buffered hook must not re-sign before
        # that initialization. All AWS work is patched out here.
        with (
            patch.object(self.addon, "_is_aws_sigv4", side_effect=fake_is_aws_sigv4),
            patch.object(self.addon, "_load_secret_store", side_effect=fake_load_secret_store),
            patch.object(self.addon, "_resign_aws", side_effect=fake_resign_aws),
        ):
            self.addon.requestheaders(flow)
            self.assertIn("_load_secret_store", events)
            self.assertNotIn("_resign_aws", events)
            self.addon.request(flow)

        self.assertLess(events.index("_load_secret_store"), events.index("_resign_aws"))


# --- Policy Blocking ---

class TestWrongHostBlocking(AddonTestCase):
    def test_wrong_host_blocked_before_lookup(self):
        resolver = FakeResolver({"SLACK_TOKEN": "should-not-be-looked-up"})
        self.addon._manifest = FakeManifest({"SLACK_TOKEN": {"hosts": ["slack.com"]}})
        self.addon._resolver = resolver
        flow = make_flow("evil.example.com", headers={"Authorization": "Bearer secretref:SLACK_TOKEN"})
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(resolver.get_calls, [])
        body = json.loads(flow.response.content)
        self.assertEqual(body.get("error"), "secret_proxy_placement_not_allowed")
        self.assertEqual(body.get("name"), "SLACK_TOKEN")
        self.assertNotIn("alias", body)

    def test_empty_hosts_blocked_before_lookup(self):
        resolver = FakeResolver({"GOCRYPTFS_PASSPHRASE": "secret"})
        self.addon._manifest = FakeManifest({"GOCRYPTFS_PASSPHRASE": {"hosts": []}})
        self.addon._resolver = resolver
        flow = make_flow("any.host.com", headers={"Authorization": "Bearer secretref:GOCRYPTFS_PASSPHRASE"})
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(resolver.get_calls, [])


# --- Removed provider-specific reference protocol ---

class TestUnsupportedProviderSpecificReference(AddonTestCase):
    def test_old_reference_marker_is_not_resolved(self):
        resolver = FakeResolver({"SLACK_SEARCH_TOKEN": "must-not-be-read"})
        self.addon._manifest = FakeManifest(
            {"SLACK_SEARCH_TOKEN": {"hosts": ["slack.com"]}}
        )
        self.addon._resolver = resolver
        old_value = "Bearer " + "bw" + "ref:slack-search"
        flow = make_flow("slack.com", headers={"Authorization": old_value})

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["Authorization"], old_value)
        self.assertEqual(resolver.get_calls, [])


# --- UUID Rejection ---

class TestUuidRejection(AddonTestCase):
    def test_secretref_uuid_rejected(self):
        resolver = FakeResolver({})
        self.addon._manifest = FakeManifest({"SECRET": {"hosts": ["example.com"]}})
        self.addon._resolver = resolver
        uuid = "00000000-0000-4000-8000-000000000000"
        flow = make_flow("example.com", headers={"Authorization": f"Bearer secretref:{uuid}"})
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(resolver.get_calls, [])
        body = json.loads(flow.response.content)
        self.assertEqual(body.get("error"), "secret_proxy_injection_failed")
        self.assertIn("uuid", body.get("detail", "").lower())


# --- Malformed/Store Failure ---

class TestMalformedReference(AddonTestCase):
    def test_empty_secretref_header_returns_502_without_forwarding(self):
        resolver = FakeResolver({})
        self.addon._manifest = FakeManifest({"SECRET": {"hosts": ["api.example.com"]}})
        self.addon._resolver = resolver
        flow = make_flow("api.example.com", headers={"Authorization": "Bearer secretref:"})

        self.addon.request(flow)

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer secretref:")
        self.assertEqual(resolver.get_calls, [])

    def test_valid_reference_with_malformed_trailing_reference_blocks_request(self):
        resolver = FakeResolver({"API_KEY": "real-key"})
        self.addon._manifest = FakeManifest({"API_KEY": {"hosts": ["api.example.com"]}})
        self.addon._resolver = resolver
        value = "prefix secretref:API_KEY trailing secretref:"
        flow = make_flow("api.example.com", headers={"X-Custom-Secret": value})

        self.addon.request(flow)

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(flow.request.headers["X-Custom-Secret"], value)
        self.assertEqual(resolver.get_calls, [])
        self.assertNotIn("secretref:", flow.response.content.decode())


class TestSecretStoreLoadFailure(AddonTestCase):
    def test_secret_store_load_failure_returns_502(self):
        def fail_load():
            raise RuntimeError("secret store unavailable")

        self.addon._load_secret_store = fail_load
        flow = make_flow("api.example.com")

        self.addon.request(flow)

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        body = json.loads(flow.response.content)
        self.assertEqual(body.get("error"), "secret_proxy_injection_failed")


class TestLookupFailure(AddonTestCase):
    def test_lookup_failure_502_no_forwarding(self):
        class FailingResolver:
            get_calls = []
            def get(self, name):
                self.get_calls.append(name)
                raise SecretBackendError(f"Vault locked for '{name}'")
            def clear_cache(self): pass
        resolver = FailingResolver()
        self.addon._manifest = FakeManifest({"MISSING": {"hosts": ["api.example.com"]}})
        self.addon._resolver = resolver
        flow = make_flow("api.example.com", headers={"Authorization": "Bearer secretref:MISSING"})
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        body = json.loads(flow.response.content)
        self.assertEqual(body.get("error"), "secret_proxy_injection_failed")

    def test_provider_failure_redacts_provider_output_from_502_and_proxy_log(self):
        marker = "SENSITIVE_PROVIDER_OUTPUT"

        class FailingResolver:
            def get(self, name):
                raise RuntimeError(f"provider command failed: {marker}")

            def clear_cache(self):
                pass

        self.addon._manifest = FakeManifest({"MISSING": {"hosts": ["api.example.com"]}})
        self.addon._resolver = FailingResolver()
        flow = make_flow("api.example.com", headers={"Authorization": "Bearer secretref:MISSING"})

        with self.assertLogs("secret_proxy", level="WARNING") as logs:
            self.addon.request(flow)

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(json.loads(flow.response.content).get("error"), "secret_proxy_injection_failed")
        self.assertNotIn(marker, flow.response.content.decode())
        self.assertNotIn(marker, "\n".join(logs.output))


class TestAwsErrorDiagnostics(AddonTestCase):
    def test_aws_error_redacts_exception_from_502_and_proxy_log(self):
        marker = "SENSITIVE_PROVIDER_OUTPUT"
        flow = make_flow("sts.amazonaws.com")

        with self.assertLogs("secret_proxy", level="ERROR") as logs:
            self.addon._aws_error(flow, RuntimeError(f"provider output: {marker}"))

        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(json.loads(flow.response.content).get("error"), "secret_proxy_aws_resign_failed")
        self.assertNotIn(marker, flow.response.content.decode())
        self.assertNotIn(marker, "\n".join(logs.output))

    def test_aws_creds_error_is_403_with_its_safe_reason(self):
        # 5xx makes AWS SDKs retry, and each retry was another Okta login.
        from awscreds import AwsCredsError

        flow = make_flow("route53.amazonaws.com")
        err = AwsCredsError(
            "Okta logins suspended after okta_credentials_rejected",
            reason="okta_credentials_rejected", kind="suspended",
        )
        with self.assertLogs("secret_proxy", level="ERROR") as logs:
            self.addon._aws_error(flow, err)

        self.assertEqual(flow.response.status_code, 403)
        body = json.loads(flow.response.content)
        self.assertEqual(body.get("error"), "secret_proxy_aws_resign_failed")
        self.assertIn("okta_credentials_rejected", body.get("detail", ""))
        self.assertIn("reason=okta_credentials_rejected", "\n".join(logs.output))


# --- Derived secrets ---

class TestDerivedGoogleAccessToken(AddonTestCase):
    def test_google_access_token_resolves_canonical_sources_without_recursion(self):
        resolver = FakeResolver({
            "GOOGLE_CLIENT_ID": "client-id",
            "GOOGLE_CLIENT_SECRET": "client-secret",
            "GOOGLE_REFRESH_TOKEN": "refresh-token",
        })

        class FakeGoogleTokenProvider:
            def __init__(self, get_secret):
                self.get_secret = get_secret

            def get_token(self):
                for name in (
                    "GOOGLE_CLIENT_ID",
                    "GOOGLE_CLIENT_SECRET",
                    "GOOGLE_REFRESH_TOKEN",
                ):
                    self.get_secret(name)
                return "minted-access-token"

        self.addon._resolver = resolver
        self.addon.GoogleTokenProvider = FakeGoogleTokenProvider
        self.addon._google_provider_singleton = None

        self.assertEqual(self.addon._resolve("GOOGLE_ACCESS_TOKEN"), "minted-access-token")
        self.assertEqual(resolver.get_calls, [
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GOOGLE_REFRESH_TOKEN",
        ])


class TestDerivedAuth0ManagementToken(AddonTestCase):
    TENANT = "example.eu.auth0.com"
    REF = "secret" + "ref:AUTH0_MANAGEMENT_TOKEN"

    def setUp(self):
        super().setUp()
        for name in ("Auth0ManagementTokenProvider", "_store_generation"):
            self._orig[name] = getattr(self.addon, name)
        self.addon._store_generation = None
        self.constructed = []
        test = self

        class FakeAuth0Provider:
            def __init__(self, get_secret, *, domain):
                test.constructed.append(domain)
                self.get_secret = get_secret

            def get_token(self):
                self.get_secret("AUTH0_CLIENT_ID")
                self.get_secret("AUTH0_CLIENT_SECRET")
                return "minted-mgmt"

        self.addon.Auth0ManagementTokenProvider = FakeAuth0Provider
        self.resolver = FakeResolver({
            "AUTH0_CLIENT_ID": "cid",
            "AUTH0_CLIENT_SECRET": "csecret",
        })
        self.addon._resolver = self.resolver

    def use_hosts(self, hosts):
        self.addon._manifest = FakeManifest({
            "AUTH0_CLIENT_ID": {"internalOnly": True},
            "AUTH0_CLIENT_SECRET": {"internalOnly": True},
            "AUTH0_MANAGEMENT_TOKEN": {"placements": [{
                "kind": "header", "hosts": hosts, "name": "authorization",
                "template": "Bearer {secret}", "methods": ["GET", "POST"], "paths": ["/api/v2/*"],
            }]},
        })

    def test_mints_for_the_pinned_tenant_and_reuses_one_provider(self):
        self.use_hosts([self.TENANT])
        self.assertEqual("minted-mgmt", self.addon._resolve("AUTH0_MANAGEMENT_TOKEN"))
        self.assertEqual("minted-mgmt", self.addon._resolve("AUTH0_MANAGEMENT_TOKEN"))
        self.assertEqual([self.TENANT], self.constructed)

    def test_injects_the_minted_token_on_the_management_api(self):
        self.use_hosts([self.TENANT])
        flow = make_flow(self.TENANT, "/api/v2/clients", headers={"Authorization": f"Bearer {self.REF}"})
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual("Bearer minted-mgmt", flow.request.headers["Authorization"])

    def test_never_injects_off_the_management_api(self):
        self.use_hosts([self.TENANT])
        for host, path in ((self.TENANT, "/oauth/token"), ("evil.example", "/api/v2/clients")):
            with self.subTest(host=host, path=path):
                flow = make_flow(host, path, headers={"Authorization": f"Bearer {self.REF}"})
                self.addon.request(flow)
                self.assertIsNotNone(flow.response)
                self.assertNotIn("minted-mgmt", flow.request.headers.get("Authorization", ""))
        self.assertEqual([], self.constructed)

    def test_requires_exactly_one_exact_tenant_host(self):
        for hosts in (["*.eu.auth0.com"], [self.TENANT, "other.eu.auth0.com"]):
            with self.subTest(hosts=hosts):
                self.addon._store_generation = None
                self.use_hosts(hosts)
                with self.assertRaises(RuntimeError):
                    self.addon._resolve("AUTH0_MANAGEMENT_TOKEN")
        self.assertEqual([], self.constructed)


class TestProxyMintedAccessTokens(AddonTestCase):
    """OAuth exchanges run inside the proxy; replies never reach the container."""

    MARKER = "secret" + "ref:"
    CX_HOST = "example.cxone.cloud"
    CX_TOKEN_PATH = "/auth/realms/example/protocol/openid-connect/token"

    @staticmethod
    def jwt(claims, signature="c2lnbmF0dXJl"):
        def enc(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
        return f"{enc({'alg': 'RS256', 'typ': 'JWT'})}.{enc(claims)}.{signature}"

    def setUp(self):
        super().setUp()
        import oauthcreds
        self._orig["_store_generation"] = self.addon._store_generation
        self.addon._store_generation = None
        self.fetches = []
        self.replies = {}
        test = self

        def fake_fetch(provider, form):
            test.fetches.append((provider.spec.token_url, dict(form)))
            return dict(test.replies[provider.spec.token_url])

        patcher = patch.object(oauthcreds.FormTokenProvider, "_fetch", fake_fetch)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.api_key = self.jwt({"aud": f"https://{self.CX_HOST}/auth/realms/example",
                                 "azp": "ast-app", "typ": "Offline"}, "QVBJLUtFWS1TSUc")
        self.cx_access = self.jwt({"ast-base-url": f"https://{self.CX_HOST}",
                                   "tenant_name": "example"}, "QUNDRVNTLVNJRw")
        self.resolver = FakeResolver({
            "WIZ_CLIENT_ID": "wiz-client-id",
            "WIZ_CLIENT_SECRET": "wiz-client-secret",
            "CHECKMARX_API_KEY": self.api_key,
        })
        self.addon._resolver = self.resolver
        self.replies = {
            "https://auth.app.wiz.io/oauth/token": {"access_token": "wiz-minted", "expires_in": 86400},
            f"https://{self.CX_HOST}{self.CX_TOKEN_PATH}": {
                "access_token": self.cx_access, "expires_in": 300,
                "refresh_token": self.jwt({"typ": "Offline"}, "Uk9UQVRFRC1TSUc"),
            },
        }
        bearer = lambda hosts, **extra: {"placements": [{
            "kind": "header", "hosts": hosts, "name": "authorization",
            "template": "Bearer {secret}", **extra,
        }]}
        self.addon._manifest = FakeManifest({
            "WIZ_CLIENT_ID": {"internalOnly": True},
            "WIZ_CLIENT_SECRET": {"internalOnly": True},
            "WIZ_ACCESS_TOKEN": bearer(["api.us8.app.wiz.io"], methods=["POST"], paths=["/graphql"]),
            "CHECKMARX_API_KEY": {"internalOnly": True},
            "CHECKMARX_ACCESS_TOKEN": bearer([self.CX_HOST]),
        })
        self.addon._manifest.checkmarx_realm = "example"

    def every_real_value(self):
        values = set(self.resolver.values.values())
        for reply in self.replies.values():
            values.update(v for v in reply.values() if isinstance(v, str))
        for value in list(values):
            if value.count(".") == 2:
                values.add(value.rsplit(".", 1)[1])  # a signature alone is a credential
        return values

    def assert_reply_holds_no_credential(self, flow):
        body = flow.response.get_text()
        for value in self.every_real_value():
            self.assertNotIn(value, body)

    def form_flow(self, host, path, fields):
        return make_flow(host, path, "POST", content=urlencode(fields).encode(),
                         content_type="application/x-www-form-urlencoded")

    def test_wiz_access_token_is_minted_in_the_proxy_and_cached(self):
        for _ in range(2):
            flow = make_flow("api.us8.app.wiz.io", "/graphql", "POST",
                             headers={"Authorization": f"Bearer {self.MARKER}WIZ_ACCESS_TOKEN"})
            self.addon.request(flow)
            self.assertIsNone(flow.response)
            self.assertEqual("Bearer wiz-minted", flow.request.headers["Authorization"])
        self.assertEqual([("https://auth.app.wiz.io/oauth/token", {
            "grant_type": "client_credentials", "audience": "wiz-api",
            "client_id": "wiz-client-id", "client_secret": "wiz-client-secret",
        })], self.fetches)

    def test_container_can_no_longer_run_an_exchange_itself(self):
        cases = (
            ("auth.app.wiz.io", "/oauth/token", {
                "grant_type": "client_credentials",
                "client_id": self.MARKER + "WIZ_CLIENT_ID",
                "client_secret": self.MARKER + "WIZ_CLIENT_SECRET",
            }),
            (self.CX_HOST, "/auth/realms/other/protocol/openid-connect/token", {
                "grant_type": "refresh_token",
                "refresh_token": self.MARKER + "CHECKMARX_API_KEY",
            }),
        )
        for host, path, fields in cases:
            with self.subTest(host=host):
                flow = self.form_flow(host, path, fields)
                self.addon.request(flow)
                self.assertEqual(403, flow.response.status_code)
        self.assertEqual([], self.resolver.get_calls)
        self.assertEqual([], self.fetches)

    def test_minted_tokens_are_never_sent_off_their_pinned_host(self):
        cases = (
            ("evil.example", "/graphql", "WIZ_ACCESS_TOKEN"),
            ("api.us8.app.wiz.io", "/other", "WIZ_ACCESS_TOKEN"),
            ("evil.example", "/api/projects", "CHECKMARX_ACCESS_TOKEN"),
        )
        for host, path, name in cases:
            with self.subTest(host=host, name=name):
                flow = make_flow(host, path, "POST",
                                 headers={"Authorization": f"Bearer {self.MARKER}{name}"})
                self.addon.request(flow)
                self.assertEqual(403, flow.response.status_code)
        self.assertEqual([], self.fetches)

    def test_checkmarx_exchange_is_answered_with_sealed_tokens(self):
        import sealedjwt

        flow = self.form_flow(self.CX_HOST, self.CX_TOKEN_PATH, {
            "grant_type": "refresh_token", "client_id": "ast-app",
            "refresh_token": self.MARKER + "CHECKMARX_API_KEY",
        })
        self.addon.request(flow)
        self.assertEqual(200, flow.response.status_code)
        self.assert_reply_holds_no_credential(flow)
        reply = json.loads(flow.response.get_text())
        self.assertTrue(sealedjwt.is_sealed(reply["access_token"]))
        self.assertTrue(sealedjwt.is_sealed(reply["refresh_token"]))
        # The claims cx reads survive sealing; only the signature is gone.
        self.assertEqual(self.cx_access.rsplit(".", 1)[0], reply["access_token"].rsplit(".", 1)[0])
        self.assertEqual(self.api_key.rsplit(".", 1)[0], reply["refresh_token"].rsplit(".", 1)[0])
        self.assertEqual("ast-app", self.fetches[0][1]["client_id"])
        self.assertEqual(self.api_key, self.fetches[0][1]["refresh_token"])

        # cx then exchanges the sealed key itself: answered the same way, minted once.
        again = self.form_flow(self.CX_HOST, self.CX_TOKEN_PATH, {
            "grant_type": "refresh_token", "client_id": "ast-app",
            "refresh_token": reply["refresh_token"],
        })
        self.addon.request(again)
        self.assertEqual(200, again.response.status_code)
        self.assert_reply_holds_no_credential(again)
        self.assertEqual(1, len(self.fetches))

        # ...and calls the API with the sealed access token, which the proxy swaps.
        api = make_flow(self.CX_HOST, "/api/projects",
                        headers={"Authorization": "Bearer " + reply["access_token"]})
        self.addon.request(api)
        self.assertIsNone(api.response)
        self.assertEqual("Bearer " + self.cx_access, api.request.headers["Authorization"])

    def test_sealed_tokens_follow_the_same_placement_rules(self):
        import sealedjwt

        sealed_access = sealedjwt.seal(self.cx_access, "CHECKMARX_ACCESS_TOKEN")
        sealed_key = sealedjwt.seal(self.api_key, "CHECKMARX_API_KEY")
        cases = (
            ("evil.example", {"Authorization": "Bearer " + sealed_access}),
            (self.CX_HOST, {"Authorization": "Bearer " + sealed_key}),
            (self.CX_HOST, {"X-Token": sealed_access}),
        )
        for host, headers in cases:
            with self.subTest(host=host, headers=list(headers)):
                flow = make_flow(host, "/api/projects", headers=headers)
                self.addon.request(flow)
                self.assertEqual(403, flow.response.status_code)
                self.assertNotIn(self.cx_access, str(flow.request.headers))
        self.assertEqual([], self.fetches)

    def test_unrecognised_checkmarx_exchange_passes_through_untouched(self):
        flow = self.form_flow(self.CX_HOST, self.CX_TOKEN_PATH, {
            "grant_type": "refresh_token", "refresh_token": "dummy.dummy.dummy",
        })
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual([], self.resolver.get_calls)

    def test_proxy_mint_specs_match_the_manifest(self):
        from pathlib import Path
        manifest = SecretManifest.load(
            Path(self.addon.__file__).parent / "examples" / "derived-manifest.json",
        )
        for name in self.addon.FORM_TOKEN_NAMES:
            with self.subTest(name=name):
                spec = self.addon._form_token_spec(name, manifest)
                self.assertEqual(list(spec.sources), manifest.secret(name).derived_from)


# --- Sentinel (extra coverage) ---

class TestRemovedProviderSpecificSentinel(AddonTestCase):
    def test_old_sentinel_host_is_not_resolved(self):
        resolver = FakeResolver(
            {"SLACK_WEBHOOK": "https://hooks.slack.com/services/T/B/x"}
        )
        self.addon._manifest = FakeManifest(
            {"SLACK_WEBHOOK": {"hosts": ["hooks.slack.com"]}}
        )
        self.addon._resolver = resolver
        old_host = "bw" + "ref.invalid"
        flow = make_flow(old_host, "/example-webhook", "POST")

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.host, old_host)
        self.assertEqual(flow.request.path, "/example-webhook")
        self.assertEqual(resolver.get_calls, [])


class TestSentinelInRequestHook(AddonTestCase):
    def test_sentinel_uuid_rejected(self):
        resolver = FakeResolver({})
        self.addon._manifest = FakeManifest({"SECRET": {"hosts": ["example.com"]}})
        self.addon._resolver = resolver
        uuid = "00000000-0000-4000-8000-000000000000"
        flow = make_flow("secretref.invalid", f"/{uuid}")
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(resolver.get_calls, [])
        body = json.loads(flow.response.content)
        self.assertEqual(body.get("error"), "secret_proxy_injection_failed")
        self.assertIn("uuid", body.get("detail", "").lower())

    def test_sentinel_validates_resolved_host(self):
        self.addon._manifest = FakeManifest({"WEBHOOK": {"hosts": ["hooks.slack.com"]}})
        self.addon._resolver = FakeResolver({"WEBHOOK": "https://evil.example.com/exfil"})
        flow = make_flow("secretref.invalid", "/WEBHOOK")
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
