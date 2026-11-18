"""Proxy-owned ChatGPT Codex browser OAuth. Tokens exist only in this process's RAM.

The browser redirects to localhost:1455, which need not be listening: the user
pastes that URL into the client shim. The PKCE verifier and token exchange stay
inside the proxy. A proxy restart requires a new interactive login.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.parse
import urllib.request

import sealedjwt
from oauthcreds import tls_context

CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
TOKEN_URL = "https://auth.openai.com/oauth/token"
REDIRECT_URI = "http://localhost:1455/auth/callback"
CANONICAL = "CHATGPT_ACCESS_TOKEN"
CLAIM = "https://api.openai.com/auth"


class ChatGPTAuthError(Exception):
    pass


def _claims(token: str) -> str:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        account = payload[CLAIM]["chatgpt_account_id"]
        if not isinstance(account, str) or not account:
            raise ValueError()
        sealedjwt.seal(token, CANONICAL)
        return account
    except (ValueError, KeyError, TypeError, IndexError):
        raise ChatGPTAuthError("OpenAI did not issue a Codex access JWT with an account ID") from None


class ChatGPTCredentials:
    def __init__(self, request=None, clock=time.time):
        self._request = request or self._post
        self._clock = clock
        self._lock = threading.RLock()
        self._pending = None
        self._access = None
        self._refresh = None
        self._expires = 0.0
        self._account = None
        self._refresh_count = 0
        self._last_refresh_at = None
        self._last_refresh_due_at = None

    @staticmethod
    def _post(fields: dict) -> dict:
        req = urllib.request.Request(
            TOKEN_URL,
            data=urllib.parse.urlencode(fields).encode(),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=tls_context()) as response:
                result = json.loads(response.read(65537))
            if not isinstance(result, dict):
                raise ValueError()
            return result
        except Exception as error:
            # Never forward an upstream response body or exception (may contain a token).
            raise ChatGPTAuthError(f"OpenAI token exchange failed ({type(error).__name__})") from None

    def start(self) -> str:
        with self._lock:
            verifier = secrets.token_urlsafe(48)
            state = secrets.token_hex(16)
            self._pending = (state, verifier, self._clock() + 600)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            params = {
                "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
                "scope": "openid profile email offline_access", "code_challenge": challenge,
                "code_challenge_method": "S256", "state": state,
                "id_token_add_organizations": "true", "codex_cli_simplified_flow": "true",
                "originator": "pi",
            }
            return "https://auth.openai.com/oauth/authorize?" + urllib.parse.urlencode(params)

    def finish(self, callback: str) -> dict:
        with self._lock:
            pending = self._pending
            self._pending = None  # one attempt only, even on a failed exchange
            if not pending or pending[2] < self._clock():
                raise ChatGPTAuthError("Login expired; start again")
            try:
                url = urllib.parse.urlsplit(callback.strip())
                if (url.scheme, url.netloc, url.path) != ("http", "localhost:1455", "/auth/callback"):
                    raise ValueError()
                params = urllib.parse.parse_qs(url.query, strict_parsing=True)
                state, code = params["state"], params["code"]
                if len(state) != 1 or len(code) != 1 or not secrets.compare_digest(state[0], pending[0]) or not code[0]:
                    raise ValueError()
            except (ValueError, KeyError):
                raise ChatGPTAuthError("Invalid callback URL or OAuth state") from None
            response = self._request({
                "grant_type": "authorization_code", "client_id": CLIENT_ID,
                "code": code[0], "code_verifier": pending[1], "redirect_uri": REDIRECT_URI,
            })
            self._update(response)
            self._refresh_count = 0
            self._last_refresh_at = self._last_refresh_due_at = None
            return self._sealed_credential()

    def _update(self, response: dict) -> None:
        if not isinstance(response, dict):
            raise ChatGPTAuthError("Invalid OpenAI token response")
        access, refresh, ttl = response.get("access_token"), response.get("refresh_token"), response.get("expires_in")
        if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh or type(ttl) not in (int, float) or ttl <= 0:
            raise ChatGPTAuthError("OpenAI token response missing credentials or expiry")
        account = _claims(access)
        if self._account is not None and account != self._account:
            raise ChatGPTAuthError("OpenAI account changed during refresh")
        # Only publish a complete new pair. Never retry an old rotating refresh token.
        self._access, self._refresh, self._expires, self._account = access, refresh, self._clock() + ttl, account

    def _sealed_credential(self) -> dict:
        return {"type": "oauth", "access": sealedjwt.seal(self._access, CANONICAL),
                "refresh": sealedjwt.MARKER + CANONICAL, "accountId": self._account,
                "expires": 4102444800000}

    def status(self) -> dict:
        """Read-only lifecycle evidence: no tokens, claims, identities or network I/O."""
        with self._lock:
            return {'loggedIn': bool(self._access and self._refresh),
                    'expiresAt': int(self._expires) if self._access and self._refresh else None,
                    'refreshCount': self._refresh_count,
                    'lastRefreshAt': self._last_refresh_at,
                    'lastRefreshDueAt': self._last_refresh_due_at}

    def get_token(self) -> str:
        with self._lock:
            if not self._refresh:
                raise ChatGPTAuthError("ChatGPT login required; run chatgpt-login")
            if self._clock() + 120 >= self._expires:
                # Fail closed on an ambiguous exchange: the upstream may have rotated
                # the refresh token despite a lost response. Require browser login.
                refresh = self._refresh
                due_at = int(self._expires - 120)
                self._access = self._refresh = None
                self._expires = 0
                result = self._request({"grant_type": "refresh_token", "client_id": CLIENT_ID, "refresh_token": refresh})
                self._update(result)
                self._refresh_count += 1
                self._last_refresh_at = int(self._clock())
                self._last_refresh_due_at = due_at
            return self._access
