"""No live OAuth calls or credential values in test output."""
import base64
import json
import unittest
from unittest.mock import patch

from mitmproxy import http

import addon
from chatgptcreds import ChatGPTAuthError, ChatGPTCredentials
from secretstore import SecretManifest
import sealedjwt


def jwt(account, signature):
    def b64(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    return b64({"alg": "RS256"}) + "." + b64({"https://api.openai.com/auth": {"chatgpt_account_id": account}}) + "." + signature


class TestChatGPTCredentials(unittest.TestCase):
    def setUp(self):
        self.time = [1000]
        self.calls = []
        self.responses = [
            {"access_token": jwt("account-1", "signature1"), "refresh_token": "refresh1", "expires_in": 3600},
            {"access_token": jwt("account-1", "signature2"), "refresh_token": "refresh2", "expires_in": 3600},
        ]
        def request(fields):
            self.calls.append(fields)
            return self.responses.pop(0)
        self.provider = ChatGPTCredentials(request=request, clock=lambda: self.time[0])

    def login(self):
        url = self.provider.start()
        query = dict(__import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(url.split("?", 1)[1]))
        self.assertEqual(query["code_challenge_method"], "S256")
        callback = "http://localhost:1455/auth/callback?code=one-time-code&state=" + query["state"]
        return self.provider.finish(callback)

    def test_login_seals_access_and_rotates_in_memory(self):
        credential = self.login()
        self.assertEqual(credential["refresh"], sealedjwt.MARKER + "CHATGPT_ACCESS_TOKEN")
        self.assertEqual(sealedjwt.unseal(credential["access"]), credential["refresh"])
        self.assertNotIn("signature1", json.dumps(credential))
        self.assertEqual(self.provider.get_token(), jwt("account-1", "signature1"))
        self.time[0] += 3500
        self.assertEqual(self.provider.get_token(), jwt("account-1", "signature2"))
        self.assertEqual(self.calls[1]["refresh_token"], "refresh1")
        self.assertEqual(self.provider.get_token(), jwt("account-1", "signature2"))

    def test_second_expiry_uses_rotated_refresh_and_original_sealed_reference(self):
        self.responses.append({"access_token": jwt("account-1", "signature3"),
                               "refresh_token": "refresh3", "expires_in": 3600})
        credential = self.login()
        for signature in ("signature2", "signature3"):
            self.time[0] += 3500
            self.assertEqual(self.provider.get_token(), jwt("account-1", signature))
        self.assertEqual([call["refresh_token"] for call in self.calls[1:]],
                         ["refresh1", "refresh2"])
        self.assertEqual(sealedjwt.unseal(credential["access"]),
                         sealedjwt.MARKER + "CHATGPT_ACCESS_TOKEN")
        for value in ("signature1", "signature2", "signature3", "refresh1", "refresh2", "refresh3"):
            self.assertNotIn(value, json.dumps(credential))

    def test_bad_state_consumes_pending_and_does_not_exchange(self):
        self.provider.start()
        with self.assertRaises(ChatGPTAuthError):
            self.provider.finish("http://localhost:1455/auth/callback?code=one&state=wrong")
        with self.assertRaises(ChatGPTAuthError):
            self.provider.finish("http://localhost:1455/auth/callback?code=one&state=wrong")
        self.assertEqual(self.calls, [])

    def test_refresh_failure_fails_closed(self):
        self.login()
        self.time[0] += 3500
        self.responses.clear()
        with self.assertRaises(IndexError):
            self.provider.get_token()
        with self.assertRaisesRegex(ChatGPTAuthError, "login required"):
            self.provider.get_token()

    def test_process_restart_requires_login(self):
        self.login()
        with self.assertRaisesRegex(ChatGPTAuthError, "login required"):
            ChatGPTCredentials(request=lambda _: None).get_token()


class TestChatGPTAddon(unittest.TestCase):
    @staticmethod
    def flow(host, method, path, auth=None, body=b""):
        request = http.Request.make(method, "https://" + host + path, content=body)
        if auth:
            request.headers["Authorization"] = auth
        flow = http.HTTPFlow(None, None)
        flow.request = request
        return flow

    def setUp(self):
        from pathlib import Path
        manifest = SecretManifest.load(Path(addon.__file__).parent / "examples" / "manifest.json")
        class Resolver:
            def get(self, name):
                raise AssertionError("must not read vault: " + name)
        self.generation = addon._StoreGeneration(manifest, Resolver(), addon._ProviderState())

    def test_proxy_only_login_and_token_endpoints_blocked(self):
        with patch.object(addon, "_capture_generation", return_value=self.generation):
            start = self.flow(addon.SENTINEL_HOST, "GET", "/chatgpt/start")
            addon.request(start)
            self.assertEqual(start.response.status_code, 200)
            url = json.loads(start.response.content)["url"]
            self.assertTrue(url.startswith("https://auth.openai.com/oauth/authorize?"))
            direct = self.flow("auth.openai.com", "POST", "/oauth/token", body=b"grant_type=authorization_code")
            addon.request(direct)
            self.assertEqual(direct.response.status_code, 403)
            raw = self.flow("chatgpt.com", "POST", "/backend-api/codex/responses", "Bearer raw.jwt.signature")
            addon.request(raw)
            self.assertEqual(raw.response.status_code, 403)
            self.assertFalse(self.generation.providers.chatgpt._refresh)

    def test_disabled_adapter_keeps_existing_login_behavior(self):
        manifest = SecretManifest("1password", {}, {})
        generation = addon._StoreGeneration(manifest, self.generation.resolver, addon._ProviderState())
        with patch.object(addon, "_capture_generation", return_value=generation):
            direct = self.flow("auth.openai.com", "POST", "/oauth/token", body=b"grant_type=authorization_code")
            addon.request(direct)
            self.assertIsNone(direct.response)
            start = self.flow(addon.SENTINEL_HOST, "GET", "/chatgpt/start")
            addon.request(start)
            self.assertEqual(start.response.status_code, 403)

    def test_sealed_auth_injects_only_at_codex_endpoint(self):
        provider = self.generation.providers.chatgpt
        provider._request = lambda fields: {
            "access_token": jwt("account-1", "real-signature"),
            "refresh_token": "opaque-refresh", "expires_in": 3600,
        }
        with patch.object(addon, "_capture_generation", return_value=self.generation):
            start = self.flow(addon.SENTINEL_HOST, "GET", "/chatgpt/start")
            addon.request(start)
            from urllib.parse import parse_qs, urlsplit
            state = parse_qs(urlsplit(json.loads(start.response.content)["url"]).query)["state"][0]
            callback = "http://localhost:1455/auth/callback?code=one-time&state=" + state
            finish = self.flow(addon.SENTINEL_HOST, "POST", "/chatgpt/finish", body=callback.encode())
            addon.request(finish)
            self.assertEqual(finish.response.status_code, 200)
            credential = json.loads(finish.response.content)
            self.assertNotIn("real-signature", json.dumps(credential))
            self.assertNotIn("opaque-refresh", json.dumps(credential))
            request = self.flow("chatgpt.com", "POST", "/backend-api/codex/responses",
                                "Bearer " + credential["access"])
            addon.requestheaders(request)
            addon.request(request)
            self.assertIsNone(request.response)
            self.assertEqual(request.request.headers["authorization"],
                             "Bearer " + jwt("account-1", "real-signature"))
            bad = self.flow("example.com", "POST", "/backend-api/codex/responses",
                            "Bearer " + credential["access"])
            addon.requestheaders(bad)
            addon.request(bad)
            self.assertEqual(bad.response.status_code, 403)

    def test_only_backend_codex_endpoint_can_inject(self):
        manifest = self.generation.manifest
        self.assertTrue(manifest.placement_allowed("CHATGPT_ACCESS_TOKEN", kind="header", host="chatgpt.com",
            method="POST", path="/backend-api/codex/responses", name="authorization", template="Bearer {secret}"))
        for host, path in (("evil.example", "/backend-api/codex/responses"), ("chatgpt.com", "/backend-api/other")):
            self.assertFalse(manifest.placement_allowed("CHATGPT_ACCESS_TOKEN", kind="header", host=host,
                method="POST", path=path, name="authorization", template="Bearer {secret}"))


if __name__ == "__main__":
    unittest.main()
