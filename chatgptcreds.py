"""Proxy-owned ChatGPT Codex browser OAuth. Tokens stay inside the proxy.

The browser redirects to localhost:1455, which need not be listening: the user
pastes that URL into the client shim. The PKCE verifier and token exchange stay
inside the proxy. By default tokens exist only in this process's RAM and a
proxy restart requires a new interactive login. With an opt-in login store
(loginstore.py) the rotating refresh token is also kept in a read/write vault
and the first use after a restart refreshes it once to restore the login.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import loginstore
import sealedjwt
from oauthcreds import tls_context

CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
TOKEN_URL = "https://auth.openai.com/oauth/token"
REDIRECT_URI = "http://localhost:1455/auth/callback"
CANONICAL = "CHATGPT_ACCESS_TOKEN"
CLAIM = "https://api.openai.com/auth"


log = logging.getLogger("secret_proxy.chatgpt")
# Failures that happen before a request reaches OpenAI: a refresh token
# offered again after one of these was never seen, so a restore may retry it.
_UNSENT = (socket.gaierror, ConnectionRefusedError, ssl.SSLCertVerificationError)


class ChatGPTAuthError(Exception):
    """*reason*: "rejected" (OpenAI refused it), "unreachable" (OpenAI never processed it) or None."""

    def __init__(self, message: str = "", reason: str | None = None):
        super().__init__(message)
        self.reason = reason


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
    def __init__(self, request=None, clock=time.time, store=None):
        self._request = request or self._post
        self._clock = clock
        # Optional loginstore.LoginStore; None keeps everything in RAM only.
        self._store = loginstore.persistence(store, "chatgpt", clock)
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
            reason = None
            if isinstance(error, urllib.error.HTTPError):
                # 429: not processed, so the token was not used. Other 4xx: refused.
                reason = "unreachable" if error.code == 429 else "rejected" if 400 <= error.code < 500 else None
            elif isinstance(error, urllib.error.URLError) and isinstance(error.reason, _UNSENT):
                reason = "unreachable"
            raise ChatGPTAuthError(f"OpenAI token exchange failed ({type(error).__name__})", reason) from None

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
            if self._store is not None:
                self._store.skip_restore()
                self._persist()
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

    def _persist(self) -> None:
        """Write the current refresh token to the store (never fails the caller)."""
        self._store.save(self._refresh, {"account_id": self._account})

    def _restore_locked(self) -> None:
        """Restore a stored login once: one refresh with the stored refresh token."""
        if self._store is None:
            return
        self._store.flush()
        if self._refresh:
            return
        found = self._store.take_restore()
        if found is None:
            return
        account = found.metadata.get("account_id")
        if not account:
            log.warning("secret_proxy: stored ChatGPT login has no account; run secret-proxy login chatgpt")
            return
        previous = self._account
        self._account = account  # _update refuses a refresh for another account
        try:
            self._update(self._request({"grant_type": "refresh_token", "client_id": CLIENT_ID,
                                        "refresh_token": found.value}))
        except ChatGPTAuthError as error:
            self._access = self._refresh = None
            self._expires = 0
            self._account = previous
            if error.reason == "unreachable":
                log.warning("secret_proxy: could not reach OpenAI to restore the stored ChatGPT login; will retry")
                self._store.restore_later()
            elif error.reason == "rejected":
                log.warning("secret_proxy: stored ChatGPT login is no longer valid; run secret-proxy login chatgpt")
            else:
                log.warning("secret_proxy: could not restore the stored ChatGPT login; run secret-proxy login chatgpt")
            return
        self._store.restored = True
        self._refresh_count = 0
        self._last_refresh_at = self._last_refresh_due_at = None
        log.info("secret_proxy: restored the ChatGPT login from the login vault")
        # The refresh rotated the token: store the new one at once.
        self._persist()

    def status(self) -> dict:
        """Lifecycle evidence only: no tokens, claims or identities.

        Without a login store there is no network I/O. With one, the first call
        after a start may restore the stored login.
        """
        with self._lock:
            self._restore_locked()
            value = {'loggedIn': bool(self._access and self._refresh),
                     'expiresAt': int(self._expires) if self._access and self._refresh else None,
                     'refreshCount': self._refresh_count,
                     'lastRefreshAt': self._last_refresh_at,
                     'lastRefreshDueAt': self._last_refresh_due_at}
            if self._store is not None:
                value.update(self._store.status())
            return value

    def logout(self) -> dict:
        """Forget the login in RAM and delete the stored item, if any."""
        with self._lock:
            self._pending = None
            self._access = self._refresh = self._account = None
            self._expires = 0
            self._refresh_count = 0
            self._last_refresh_at = self._last_refresh_due_at = None
            if self._store is None:
                return {"stored": False}
            self._store.skip_restore()
            self._store.delete()
            return {"stored": self._store.stored}

    def get_token(self) -> str:
        with self._lock:
            self._restore_locked()
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
                if self._store is not None:
                    self._persist()  # each refresh rotates the stored token
            return self._access
