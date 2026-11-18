"""Auth0 Management API access-token minting for secret_proxy.

The devenv container never holds an Auth0 credential. The Auth0 CLI runs with
``AUTH0_CLI_AUTH_MODE=env`` and ``AUTH0_API_TOKEN`` set to the canonical
placeholder for ``AUTH0_MANAGEMENT_TOKEN``, so it sends
``Authorization: Bearer <placeholder>`` to the tenant's Management API.
addon.py resolves that derived manifest entry by calling this provider, which
exchanges the provider-held machine-to-machine client id and secret for a
Management API token (client-credentials grant) and caches it until shortly
before it expires. The manifest pins the token to the tenant's /api/v2/ paths.

Neither the client secret nor the minted token reaches the container. Caching
also matters for quota: the Auth0 Free plan allows 1,000 machine-to-machine
tokens a month, and the CLI would otherwise mint one per command.

Secrets are resolved via an injected ``get_secret(name) -> value`` callable
(addon.py's resolver). Nothing secret is logged or included in errors.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Callable

from oauthcreds import tls_context

# A bare tenant host such as tenant.eu.auth0.com: letters, digits, dots and
# hyphens only, so a value like "tenant.example@evil.example" can never send
# the client secret to another host.
_TENANT_HOST_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.auth0\.com$")


class Auth0TokenError(Exception):
    pass


def validate_tenant_domain(domain: str) -> str:
    if not isinstance(domain, str) or not _TENANT_HOST_RE.match(domain):
        raise Auth0TokenError("Auth0 tenant domain must be a bare *.auth0.com host")
    return domain.lower()


class Auth0ManagementTokenProvider:
    def __init__(
        self,
        get_secret: Callable[[str], str],
        *,
        domain: str,
        client_id_secret_name: str = "AUTH0_CLIENT_ID",
        client_secret_secret_name: str = "AUTH0_CLIENT_SECRET",
        skew: int = 300,
    ):
        self._get = get_secret
        self._domain = validate_tenant_domain(domain)
        self._cid_secret_name = client_id_secret_name
        self._csecret_secret_name = client_secret_secret_name
        self._skew = skew
        self._lock = threading.Lock()
        self._token: str | None = None
        self._exp: float = 0.0

    @property
    def token_url(self) -> str:
        return f"https://{self._domain}/oauth/token"

    @property
    def audience(self) -> str:
        return f"https://{self._domain}/api/v2/"

    def get_token(self) -> str:
        """Return a cached Management API token, minting one when missing or
        within the refresh skew of expiry."""
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
        body = {
            "grant_type": "client_credentials",
            "client_id": self._get(self._cid_secret_name),
            "client_secret": self._get(self._csecret_secret_name),
            "audience": self.audience,
        }
        obj = self._fetch(body)
        minted = obj.get("access_token")
        if not isinstance(minted, str) or not minted:
            detail = obj.get("error_description") or obj.get("error") or "no access_token in response"
            raise Auth0TokenError(f"Auth0 token mint failed: {_safe(detail)}")
        ttl = obj.get("expires_in", 86400)
        try:
            ttl = int(ttl)
        except (TypeError, ValueError):
            ttl = 86400
        return minted, ttl

    def _fetch(self, body: dict) -> dict:
        """POST the token request and return the parsed JSON. Split out so tests
        can stub it. secret_proxy has direct egress and trusts Auth0's real cert."""
        req = urllib.request.Request(
            self.token_url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=tls_context()) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            # Auth0 returns JSON error bodies on 4xx; surface only the detail.
            try:
                return json.loads(error.read())
            except Exception:
                raise Auth0TokenError(f"token endpoint HTTP {error.code}")
        except Exception as error:  # noqa: BLE001
            raise Auth0TokenError(f"token request failed: {type(error).__name__}")


def _safe(detail: object) -> str:
    """Auth0 error descriptions are prose; keep them short and single-line."""
    return " ".join(str(detail).split())[:200]
