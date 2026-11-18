"""Google OAuth access-token minting for secret_proxy.

The devenv container never holds any Google credential. It sends the canonical
placeholder `Authorization: Bearer secretref:GOOGLE_ACCESS_TOKEN`; addon.py
resolves that derived manifest entry by calling this provider, which exchanges
the provider-held client-id/secret + refresh-token for a short-lived access
token at Google's token endpoint and caches it. The derived
`GOOGLE_ACCESS_TOKEN` is injected on the wire and is only ever sent to
`*.googleapis.com`, as enforced by the manifest host policy.

This is the Google analogue of awscreds.AwsCredsProvider: the long-lived creds
(refresh token, client secret) and the derived short-lived access token both
stay inside the proxy — neither reaches the container. The selected secret
provider is hidden behind the injected resolver.

Secrets are resolved via an injected ``get_secret(name) -> value`` callable
(addon.py's resolver). Nothing is logged.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from oauthcreds import tls_context

log = logging.getLogger("secret_proxy.googlecreds")


class GoogleTokenError(Exception):
    pass


class GoogleTokenProvider:
    TOKEN_URL = "https://oauth2.googleapis.com/token"

    def __init__(
        self,
        get_secret: Callable[[str], str],
        *,
        client_id_secret_name: str = "GOOGLE_CLIENT_ID",
        client_secret_secret_name: str = "GOOGLE_CLIENT_SECRET",
        refresh_token_secret_name: str = "GOOGLE_REFRESH_TOKEN",
        skew: int = 120,
    ):
        self._get = get_secret
        self._cid_secret_name = client_id_secret_name
        self._csecret_secret_name = client_secret_secret_name
        self._rtoken_secret_name = refresh_token_secret_name
        self._skew = skew
        self._lock = threading.Lock()
        self._token: str | None = None
        self._exp: float = 0.0

    def get_token(self) -> str:
        """Return a cached access token, refreshing via Google's token endpoint
        when missing or within the refresh-skew of expiry."""
        now = time.time()
        if self._token and now < self._exp:
            return self._token
        with self._lock:
            now = time.time()
            if self._token and now < self._exp:
                return self._token
            token, ttl = self._mint()
            self._token = token
            self._exp = now + max(0, ttl - self._skew)
            return token

    def _mint(self) -> tuple[str, int]:
        form = {
            "grant_type": "refresh_token",
            "client_id": self._get(self._cid_secret_name),
            "client_secret": self._get(self._csecret_secret_name),
            "refresh_token": self._get(self._rtoken_secret_name),
        }
        obj = self._fetch(form)
        token = obj.get("access_token")
        if not token:
            detail = obj.get("error_description") or obj.get("error") or "no access_token in response"
            raise GoogleTokenError(f"Google token mint failed: {detail}")
        ttl = obj.get("expires_in", 3600)
        try:
            ttl = int(ttl)
        except (TypeError, ValueError):
            ttl = 3600
        return token, ttl

    def _fetch(self, form: dict) -> dict:
        """POST the token request and return the parsed JSON. Split out so tests
        can stub it. secret_proxy has direct egress + trusts Google's real cert."""
        data = urllib.parse.urlencode(form).encode("utf-8")
        req = urllib.request.Request(
            self.TOKEN_URL,
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=tls_context()) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            # Google returns JSON error bodies even on 4xx; surface the detail.
            try:
                return json.loads(e.read())
            except Exception:
                raise GoogleTokenError(f"token endpoint HTTP {e.code}")
        except Exception as e:  # noqa: BLE001
            raise GoogleTokenError(f"token request failed: {e}")
