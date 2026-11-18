"""OAuth access-token minting for secret_proxy (form-encoded token endpoints).

Some APIs authenticate with a short-lived access token that the client first
exchanges for a long-lived credential at an OAuth token endpoint (Wiz client
credentials, a Checkmarx One API key, a Spotify refresh token). If the
container performed that exchange itself, the proxy would inject the long-lived
credential into the request and the token endpoint would send the minted
access token, and sometimes a reusable refresh token, straight back into the
container. That is a credential handed to the container, so those exchanges
never run there.

Instead the long-lived credentials are ``internalOnly`` manifest entries and a
derived entry (for example ``WIZ_ACCESS_TOKEN``) names the access token. The
container sends ``Authorization: Bearer <placeholder>``; addon.py resolves the
derived entry by calling a ``FormTokenProvider``, which performs the exchange
inside the proxy and caches the token until shortly before it expires. Neither
the long-lived credential nor the minted token reaches the container, and the
manifest host policy pins where the minted token may be sent.

Secrets are resolved via an injected ``get_secret(name) -> value`` callable
(addon.py's resolver). Nothing secret is logged or included in errors.
"""

from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable


class OAuthTokenError(Exception):
    pass


def tls_context() -> ssl.SSLContext:
    """Verifying TLS context for the proxy's own token requests.

    Behind a TLS-inspecting corporate proxy (Zscaler) the token host presents a
    certificate issued by the corporate CA, which the image trusts. Python 3.13
    turns on VERIFY_X509_STRICT by default, and that rejects the Zscaler CA
    ("Basic Constraints of CA cert not marked critical") although OpenSSL,
    curl and mitmproxy accept it. Clear only that flag: the chain, hostname
    and expiry are still fully verified against the system trust store.
    """
    context = ssl.create_default_context()
    context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return context


@dataclass(frozen=True)
class FormTokenSpec:
    """How to mint one derived access token.

    ``fields`` are literal form fields; ``secret_fields`` map a form field to
    the canonical secret whose value fills it. ``token_url`` must be https.
    """

    token_url: str
    fields: tuple[tuple[str, str], ...] = ()
    secret_fields: tuple[tuple[str, str], ...] = ()
    default_ttl: int = 3600
    skew: int = 120
    label: str = "OAuth"
    sources: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self):
        parsed = urllib.parse.urlsplit(self.token_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("token_url must be an https URL")
        object.__setattr__(self, "sources", tuple(name for _, name in self.secret_fields))


class FormTokenProvider:
    def __init__(self, get_secret: Callable[[str], str], spec: FormTokenSpec):
        self._get = get_secret
        self._spec = spec
        self._lock = threading.Lock()
        self._token: str | None = None
        self._exp: float = 0.0
        self._ttl_end: float = 0.0

    @property
    def spec(self) -> FormTokenSpec:
        return self._spec

    def get_token(self) -> str:
        """Return a cached access token, minting one when missing or within the
        refresh skew of expiry."""
        now = time.time()
        if self._token and now < self._exp:
            return self._token
        with self._lock:
            now = time.time()
            if self._token and now < self._exp:
                return self._token
            token, ttl = self._mint()
            self._token = token
            self._ttl_end = now + ttl
            self._exp = now + max(0, ttl - self._spec.skew)
            return token

    def remaining_seconds(self) -> int:
        """Seconds until the cached token itself expires (0 when none)."""
        return max(0, int(self._ttl_end - time.time())) if self._token else 0

    def _mint(self) -> tuple[str, int]:
        form = dict(self._spec.fields)
        for form_field, secret_name in self._spec.secret_fields:
            form[form_field] = self._get(secret_name)
        obj = self._fetch(form)
        token = obj.get("access_token") if isinstance(obj, dict) else None
        if not isinstance(token, str) or not token:
            detail = "no access_token in response"
            if isinstance(obj, dict):
                detail = obj.get("error_description") or obj.get("error") or detail
            raise OAuthTokenError(f"{self._spec.label} token mint failed: {_safe(detail)}")
        ttl = obj.get("expires_in", self._spec.default_ttl)
        try:
            ttl = int(ttl)
        except (TypeError, ValueError):
            ttl = self._spec.default_ttl
        return token, ttl

    def _fetch(self, form: dict) -> dict:
        """POST the token request and return the parsed JSON. Split out so tests
        can stub it. secret_proxy has direct egress and trusts the real cert."""
        req = urllib.request.Request(
            self._spec.token_url,
            data=urllib.parse.urlencode(form).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=tls_context()) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            # Token endpoints return JSON error bodies on 4xx; surface the detail.
            try:
                return json.loads(error.read())
            except Exception:
                raise OAuthTokenError(
                    f"{self._spec.label} token endpoint HTTP {error.code}"
                ) from None
        except Exception as error:  # noqa: BLE001
            # A URLError reason (TLS, DNS or connect failure) names no secret.
            reason = getattr(error, "reason", None)
            detail = f": {_safe(reason)}" if reason else ""
            raise OAuthTokenError(
                f"{self._spec.label} token request failed: {type(error).__name__}{detail}"
            ) from None


def _safe(detail: object) -> str:
    """Error descriptions are prose; keep them short and single-line."""
    return " ".join(str(detail).split())[:200]
