import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import entry
from runtime import MAX_BOOTSTRAP, command, read_bootstrap


class RuntimeTests(unittest.TestCase):
    def read(self, content):
        r, w = os.pipe()
        try:
            # Small invalid bundles only; a pipe may have a small platform buffer.
            os.write(w, content)
            os.close(w)
            w = -1
            return read_bootstrap(r, timeout=0.2)
        finally:
            os.close(r)
            if w != -1:
                os.close(w)

    def test_bootstrap_exact_fields_and_types(self):
        good = {"op_token": "test-capability", "proxy_token": "a" * 48}
        self.assertEqual(self.read(json.dumps(good).encode()), good)
        for bad in ({}, {**good, "extra": 1}, {**good, "proxy_token": "bad"},
                    {**good, "op_token": "a\nb"}, {**good, "op_token": 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.read(json.dumps(bad).encode())
        with self.assertRaises(ValueError):
            self.read(b'{"op_token":"a","op_token":"b","proxy_token":"' + b'a'*48 + b'"}')

    def test_open_stdin_has_a_total_deadline(self):
        r, w = os.pipe()
        try:
            with self.assertRaisesRegex(ValueError, "timed out"):
                read_bootstrap(r, timeout=0.01)
        finally:
            os.close(r)
            os.close(w)

    def test_bounded_bootstrap(self):
        with patch("runtime.os.read", return_value=b"x" * (MAX_BOOTSTRAP + 1)), \
             patch("runtime.selectors.DefaultSelector") as selector:
            selector.return_value.__enter__.return_value.select.return_value = [1]
            with self.assertRaisesRegex(ValueError, "size limit"):
                read_bootstrap(0)

    def test_command_has_no_capabilities_and_does_not_inherit_host_secrets(self):
        with patch.dict(os.environ, {"UNRELATED_SECRET": "must-not-cross"}):
            argv, env = command(Path("/config"), Path("/state"), Path("/tmp/auth"), 10256,
                                {"op_token": "fixture-capability", "proxy_token": "a" * 48})
        self.assertNotIn("fixture-capability", str(argv))
        self.assertNotIn("a" * 48, str(argv))
        self.assertNotIn("UNRELATED_SECRET", env)
        self.assertEqual(env["OP_SERVICE_ACCOUNT_TOKEN"], "fixture-capability")
        self.assertIn("proxyauth=@/tmp/auth", argv)

    def test_interception_includes_denied_oauth_host(self):
        root = Path(__file__).parent
        with patch.object(entry.addon, "SECRETS_FILE", root / "examples/manifest.json"), \
             patch.object(entry.addon, "AWS_OKTA_FILE", root / "not-configured.json"):
            import re
            patterns = entry._allow_hosts()
            for host in ("auth.openai.com", "chatgpt.com", "api.github.com"):
                self.assertTrue(any(re.fullmatch(p, host) for p in patterns))
            for host in ("unrelated.example.com", "auth.openai.com.evil.example", "sts.amazonaws.com"):
                self.assertFalse(any(re.fullmatch(p, host) for p in patterns))

    def test_invalid_policy_aborts_interception_loading(self):
        from mitmproxy.exceptions import OptionsError
        with patch.object(entry.addon, "SECRETS_FILE", Path("/no-such-policy.json")):
            with self.assertRaises(OptionsError):
                entry.load(None)

    def test_aws_requires_explicit_approved_hosts_and_roles(self):
        from awscreds import AwsCredsProvider, AwsCredsError
        cfg = dict(okta_hosts=["example.okta.com"], default_app_url="https://example.okta.com/home/amazon_aws/example/1",
                   default_account="123456789012", default_role="ReadOnly", allowed_roles=["ReadOnly"],
                   OKTA_USERNAME="OKTA_USERNAME", OKTA_PASSWORD="OKTA_PASSWORD", OKTA_SECRET="OKTA_SECRET")
        AwsCredsProvider(cfg, lambda _: self.fail("must not read credentials during validation"))
        for key, value in (("okta_hosts", []), ("okta_hosts", ["*.okta.com"]),
                           ("allowed_roles", []), ("default_app_url", "https://evil.example/home/amazon_aws/example/1")):
            with self.subTest(key=key), self.assertRaises(AwsCredsError):
                AwsCredsProvider({**cfg, key: value}, lambda _: "unused")


if __name__ == "__main__":
    unittest.main()
