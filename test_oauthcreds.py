"""Unit tests for oauthcreds.py (proxy-side OAuth token minting)."""
import json
import os
import ssl
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auth0creds  # noqa: E402
import googlecreds  # noqa: E402
import oauthcreds  # noqa: E402

SPEC = oauthcreds.FormTokenSpec(
    token_url="https://auth.example.test/oauth/token",
    fields=(("grant_type", "client_credentials"),),
    secret_fields=(("client_id", "ID"), ("client_secret", "SECRET")),
    label="Example",
)


class _Reply:
    def __init__(self, body):
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestTlsContext(unittest.TestCase):
    def test_context_verifies_but_tolerates_non_strict_corporate_cas(self):
        context = oauthcreds.tls_context()
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertTrue(context.check_hostname)
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            self.assertFalse(context.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_every_minting_provider_uses_the_context(self):
        seen = []

        def fake_urlopen(request, timeout=None, context=None):
            seen.append(context)
            return _Reply({"access_token": "minted", "expires_in": 60})

        providers = (
            lambda: oauthcreds.FormTokenProvider(lambda name: "v", SPEC).get_token(),
            lambda: googlecreds.GoogleTokenProvider(lambda name: "v").get_token(),
            lambda: auth0creds.Auth0ManagementTokenProvider(
                lambda name: "v", domain="tenant.eu.auth0.com"
            ).get_token(),
        )
        with patch("urllib.request.urlopen", fake_urlopen):
            for mint in providers:
                self.assertEqual("minted", mint())
        self.assertEqual(3, len(seen))
        for context in seen:
            self.assertIsInstance(context, ssl.SSLContext)
            if hasattr(ssl, "VERIFY_X509_STRICT"):
                self.assertFalse(context.verify_flags & ssl.VERIFY_X509_STRICT)


class TestFormTokenProvider(unittest.TestCase):
    def test_mints_with_literal_and_secret_fields_then_caches(self):
        forms = []
        provider = oauthcreds.FormTokenProvider({"ID": "id", "SECRET": "sec"}.__getitem__, SPEC)
        provider._fetch = lambda form: forms.append(form) or {"access_token": "tok", "expires_in": 600}
        self.assertEqual("tok", provider.get_token())
        self.assertEqual("tok", provider.get_token())
        self.assertEqual([{"grant_type": "client_credentials", "client_id": "id",
                           "client_secret": "sec"}], forms)

    def test_transport_failure_names_the_reason_but_no_secret(self):
        def fail(request, timeout=None, context=None):
            raise urllib.error.URLError("certificate verify failed")

        provider = oauthcreds.FormTokenProvider(lambda name: "s3cr3t-value", SPEC)
        with patch("urllib.request.urlopen", fail):
            with self.assertRaises(oauthcreds.OAuthTokenError) as caught:
                provider.get_token()
        self.assertIn("certificate verify failed", str(caught.exception))
        self.assertNotIn("s3cr3t-value", str(caught.exception))

    def test_reply_without_access_token_fails_closed(self):
        provider = oauthcreds.FormTokenProvider(lambda name: "v", SPEC)
        provider._fetch = lambda form: {"error": "invalid_client"}
        with self.assertRaises(oauthcreds.OAuthTokenError) as caught:
            provider.get_token()
        self.assertIn("invalid_client", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
