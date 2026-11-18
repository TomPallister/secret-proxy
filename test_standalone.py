"""Standalone configuration and lifetime-cache contracts; no real credentials."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from secretstore import SecretManifest, SecretResolver, OnePasswordBackend, SecretBackendError


def fixture():
    return {
        "schemaVersion": 3,
        "account": {"vault": "Automation"},
        "secrets": {"EXAMPLE_TOKEN": {
            "placements": [{"kind": "header", "hosts": ["api.example.com"],
                            "name": "authorization", "template": "Bearer {secret}"}]
        }},
    }


class StandaloneTests(unittest.TestCase):
    def load(self, data=None):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "manifest.json"
            p.write_text(json.dumps(fixture() if data is None else data))
            # Ambient dotfiles settings must not select a different configuration.
            return SecretManifest.load(p, env={"DEVENV_PROFILE": "unrelated"})

    def test_one_account_without_profiles_or_provider_switch(self):
        m = self.load()
        self.assertTrue(m.placement_allowed("EXAMPLE_TOKEN", kind="header",
            host="api.example.com", method="GET", path="/", name="Authorization",
            template="Bearer {secret}"))
        self.assertFalse(m.placement_allowed("EXAMPLE_TOKEN", kind="header",
            host="evil.example.com", method="GET", path="/", name="Authorization",
            template="Bearer {secret}"))

    def test_unknown_root_account_and_secret_keys_fail(self):
        for where in ("root", "account", "secret"):
            data = fixture()
            target = data if where == "root" else data["account"] if where == "account" else data["secrets"]["EXAMPLE_TOKEN"]
            target["unexpected"] = "value"
            with self.subTest(where=where), self.assertRaises(ValueError):
                self.load(data)

    def test_dependency_cycle_rejected(self):
        data = fixture()
        data["secrets"]["EXAMPLE_TOKEN"]["derivedFrom"] = ["EXAMPLE_TOKEN"]
        with self.assertRaises(ValueError):
            self.load(data)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "manifest.json"
            p.write_text(json.dumps(fixture()).replace('"schemaVersion": 3', '"schemaVersion": 3, "schemaVersion": 3'))
            with self.assertRaises(ValueError):
                SecretManifest.load(p)

    def test_static_values_live_until_explicit_cache_clear(self):
        backend = Mock()
        backend.get.side_effect = ["first", "second"]
        resolver = SecretResolver(self.load(), backend)
        with patch("secretstore.time.time", return_value=100):
            self.assertEqual(resolver.get("EXAMPLE_TOKEN"), "first")
        with patch("secretstore.time.time", return_value=10**10):
            self.assertEqual(resolver.get("EXAMPLE_TOKEN"), "first")
        backend.get.assert_called_once_with("EXAMPLE_TOKEN")
        resolver.clear_cache()
        self.assertEqual(resolver.get("EXAMPLE_TOKEN"), "second")

    def test_single_service_account_capability(self):
        runner = Mock()
        runner.run.side_effect = [
            Mock(returncode=0, stdout='[{"id":"fixture-id","title":"EXAMPLE_TOKEN"}]'),
            Mock(returncode=0, stdout='{"value":"fixture-value"}'),
        ]
        resolver = SecretResolver.from_environment(self.load(),
            env={"OP_SERVICE_ACCOUNT_TOKEN": "fixture-capability"}, runner=runner)
        self.assertEqual(resolver.get("EXAMPLE_TOKEN"), "fixture-value")
        for call in runner.run.call_args_list:
            self.assertEqual(call.kwargs["env"]["OP_SERVICE_ACCOUNT_TOKEN"], "fixture-capability")
            self.assertNotIn("fixture-capability", call.args[0])
            self.assertEqual(call.args[0][call.args[0].index("--vault") + 1], "Automation")

    def test_backend_cannot_read_derived_or_runtime_values(self):
        data = fixture()
        data["secrets"]["CHATGPT_ACCESS_TOKEN"] = {
            "runtimeOnly": True, "placements": [{"kind": "header", "hosts": ["chatgpt.com"],
            "name": "authorization", "template": "Bearer {secret}"}]}
        runner = Mock()
        backend = OnePasswordBackend(self.load(data), token="fixture", runner=runner)
        with self.assertRaises(SecretBackendError):
            backend.get("CHATGPT_ACCESS_TOKEN")
        runner.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
