"""Proxy-owned GitHub Copilot login. GitHub and Copilot tokens stay in RAM.

Pi's ``github-copilot`` provider signs in with a GitHub device flow, exchanges
the long-lived GitHub token for a short-lived Copilot token at
``api.<domain>/copilot_internal/v2/token`` and calls the API host named by the
Copilot token's ``proxy-ep`` field. Here the proxy does the device flow and the
exchange. The client gets only *sealed* values:

* ``refresh`` is a plain reference, so Pi's own refresh call to the exchange
  endpoint reaches the proxy, which answers it without contacting GitHub;
* ``access`` keeps the Copilot token's shape and its real ``exp`` and
  ``proxy-ep`` fields (Pi reads the API base URL from ``proxy-ep``), with a
  reference in place of ``tid`` and no signature.

The real Copilot token is injected only into the API host derived from its own
``proxy-ep``. By default a proxy restart discards both tokens and requires a
new login. With an opt-in login store (loginstore.py) the GitHub token is also
kept in a read/write vault; the Copilot token is minted again from it after a
restart and is never stored.
"""

from __future__ import annotations

import base64
import logging
import re
import threading
import time

import githubdevice
import loginstore
from githubdevice import DeviceFlow, GitHubDeviceError

# The public OAuth client ID of the editor flow Pi copies, stored the way Pi
# stores it so the value is not mistaken for a credential.
CLIENT_ID = base64.b64decode("SXYxLmI1MDdhMDhjODdlY2ZlOTg=").decode("ascii")
SCOPES = ("read:user",)
CANONICAL = "GITHUB_COPILOT_SESSION_TOKEN"
MARKER = "secre" + "tref:"
DEFAULT_DOMAIN = "github.com"
EXCHANGE_PATH = "/copilot_internal/v2/token"
USER_AGENT = "GitHubCopilotChat/0.35.0"
COPILOT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Editor-Version": "vscode/1.107.0",
    "Editor-Plugin-Version": "copilot-chat/0.35.0",
    "Copilot-Integration-Id": "vscode-chat",
}
COPILOT_API_VERSION = "2026-06-01"
# Refresh this long before expiry. Pi treats a credential as expired five
# minutes early, so a token handed to Pi always outlives Pi's own skew.
EXPIRY_SKEW = 300
RETRY_DELAY = 10
_TOKEN_RE = re.compile(r"[\x21-\x7e]{16,8192}")
_SEALED_RE = re.compile(
    r"(?<![A-Za-z0-9_.;=:-])tid=(" + re.escape(MARKER) + r"[A-Za-z0-9._-]+);exp=([0-9]{1,12})"
    r"(?:;proxy-ep=([A-Za-z0-9.-]{1,253}))?(?![A-Za-z0-9_.;=:-])"
)


log = logging.getLogger("secret_proxy.copilot")


class CopilotAuthError(Exception):
    pass


def token_fields(token: str) -> tuple[int | None, str | None]:
    """Return the ``exp`` and ``proxy-ep`` fields of a Copilot token."""
    exp = re.search(r"(?:^|;)exp=([0-9]{1,12})(?=;|:|$)", token)
    endpoint = re.search(r"(?:^|;)proxy-ep=([^;:]+)", token)
    proxy_ep = endpoint.group(1).lower() if endpoint else None
    if proxy_ep is not None and not githubdevice.valid_domain(proxy_ep):
        raise CopilotAuthError("Copilot token names an invalid proxy endpoint")
    return (int(exp.group(1)) if exp else None), proxy_ep


def api_host(proxy_ep: str | None, domain: str = DEFAULT_DOMAIN) -> str:
    """The API host a client derives from ``proxy-ep``, exactly as Pi does."""
    if proxy_ep:
        return "api." + proxy_ep[len("proxy."):] if proxy_ep.startswith("proxy.") else proxy_ep
    return f"copilot-api.{domain}" if domain != DEFAULT_DOMAIN else "api.individual.githubcopilot.com"


def seal(exp: int, proxy_ep: str | None, canonical: str = CANONICAL) -> str:
    sealed = f"tid={MARKER}{canonical};exp={int(exp)}"
    return sealed + (f";proxy-ep={proxy_ep}" if proxy_ep else "")


def is_sealed(value: str) -> bool:
    return isinstance(value, str) and _SEALED_RE.fullmatch(value) is not None


def unseal(value: str) -> str:
    """Replace every sealed Copilot token in *value* with its plain reference."""
    if not isinstance(value, str) or "tid=" + MARKER not in value:
        return value
    return _SEALED_RE.sub(lambda match: match.group(1), value)


def _available_models(data: dict, allow_policy_fallback: bool) -> list[str] | None:
    """Model IDs Pi would list, from the catalog; None when it cannot tell."""
    items = data.get("data")
    if not isinstance(items, list):
        return None
    models = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", item["id"]):
            continue
        capabilities = item.get("capabilities") if isinstance(item.get("capabilities"), dict) else {}
        supports = capabilities.get("supports") if isinstance(capabilities.get("supports"), dict) else {}
        if supports.get("tool_calls") is False:
            continue
        policy = item.get("policy") if isinstance(item.get("policy"), dict) else {}
        models.append((item["id"], item.get("model_picker_enabled") is True, policy.get("state")))
    picker = [model for model, enabled, state in models if enabled and state != "disabled"]
    if picker or not allow_policy_fallback:
        return sorted(set(picker)) or None
    return sorted({model for model, _enabled, state in models if state == "enabled"}) or None


class CopilotCredentials:
    def __init__(self, domain: str = DEFAULT_DOMAIN, request=None, clock=time.time, sleep=time.sleep,
                 store=None):
        self.domain = domain
        # Optional loginstore.LoginStore; None keeps everything in RAM only.
        self._store = loginstore.persistence(store, "github-copilot", clock)
        self._request = request or githubdevice.request_json
        self._clock = clock
        self.device = DeviceFlow(domain=domain, client_id=CLIENT_ID, scopes=SCOPES,
                                 user_agent=USER_AGENT, label="GitHub Copilot",
                                 request=self._request, clock=clock, sleep=sleep)
        self._lock = threading.RLock()
        self._login_generation = 0
        self._github = None
        self._token = None
        self._expires_at = 0
        self._refresh_at = 0.0
        self._retry_at = 0.0
        self._refresh_count = 0
        self._last_refresh_at = None

    @property
    def exchange_host(self) -> str:
        return "api." + self.domain

    def start(self) -> dict:
        with self._lock:
            self._login_generation += 1
            self.device.cancel()
            return self.device.start()

    def poll(self, max_wait: float = 10.0) -> dict | None:
        """Finish a device login. Return the sealed client credential, or None."""
        with self._lock:
            generation = self._login_generation
        result = self.device.poll(max_wait)
        if result is None:
            return None
        with self._lock:
            # DeviceFlow guards cancellation during the network call. Also
            # guard the gap between its return and publishing the credentials.
            if generation != self._login_generation:
                raise GitHubDeviceError("no_login", "The login was replaced; start again")
            self._clear()
            self._github = result["access_token"]
            try:
                self._exchange()
            except CopilotAuthError:
                self._clear()
                raise GitHubDeviceError("unavailable", "GitHub did not issue a Copilot token for this account") from None
            self._refresh_count = 0
            self._last_refresh_at = None
            if self._store is not None:
                self._store.skip_restore()
                self._store.save(self._github, {"domain": self.domain})
            credential = self._sealed_credential()
            models = self._catalog()
        if models:
            credential["availableModelIds"] = models
        return credential

    def _clear(self) -> None:
        self._github = self._token = None
        self._expires_at, self._refresh_at, self._retry_at = 0, 0.0, 0.0

    def _exchange(self) -> None:
        now = self._clock()
        status, data = self._request(
            f"https://{self.exchange_host}{EXCHANGE_PATH}", method="GET", label="GitHub Copilot",
            headers={"Authorization": "Bearer " + self._github, **COPILOT_HEADERS},
        )
        if status == 401:
            self._clear()
            raise CopilotAuthError("GitHub rejected the login; run the GitHub Copilot login again")
        minted = data.get("token")
        expires_at, refresh_in = data.get("expires_at"), data.get("refresh_in")
        if status != 200 or not isinstance(minted, str) or not _TOKEN_RE.fullmatch(minted) or MARKER in minted:
            raise CopilotAuthError("GitHub returned no usable Copilot token")
        if type(expires_at) is not int or expires_at <= now:
            raise CopilotAuthError("GitHub returned an expired Copilot token")
        token_fields(minted)  # validates proxy-ep before the token is used
        refresh_at = expires_at - EXPIRY_SKEW
        if type(refresh_in) is int and refresh_in > 0:
            refresh_at = min(refresh_at, now + refresh_in)
        self._token, self._expires_at = minted, expires_at
        self._refresh_at = max(refresh_at, now + 30)

    def _catalog(self) -> list[str] | None:
        host = self.api_host()
        try:
            status, data = self._request(
                f"https://{host}/models", method="GET", label="GitHub Copilot",
                headers={"Authorization": "Bearer " + self._token, **COPILOT_HEADERS,
                         "X-GitHub-Api-Version": COPILOT_API_VERSION},
            )
        except GitHubDeviceError:
            return None
        if status != 200:
            return None
        return _available_models(data, host == "api.individual.githubcopilot.com")

    def _sealed_credential(self) -> dict:
        exp, proxy_ep = token_fields(self._token)
        credential = {"type": "oauth", "refresh": MARKER + CANONICAL,
                      "access": seal(exp if exp is not None else self._expires_at, proxy_ep),
                      "expires": self._expires_at * 1000 - EXPIRY_SKEW * 1000}
        if self.domain != DEFAULT_DOMAIN:
            credential["enterpriseUrl"] = self.domain
        return credential

    def _restore_locked(self) -> None:
        """Restore a stored GitHub token once; then mint a Copilot token from it."""
        if self._store is None:
            return
        self._store.flush()
        if self._github:
            if not self._token and self._clock() >= self._retry_at:
                self._mint_restored()
            return
        found = self._store.take_restore()
        if found is None:
            return
        if found.metadata.get("domain") != self.domain:
            log.warning("secret_proxy: stored GitHub Copilot login is for another domain; "
                        "run secret-proxy login github-copilot")
            return
        if not _TOKEN_RE.fullmatch(found.value):
            log.warning("secret_proxy: stored GitHub Copilot login is not usable; run secret-proxy login github-copilot")
            return
        self._github = found.value
        self._store.restored = True
        self._refresh_count = 0
        self._last_refresh_at = None
        self._mint_restored()

    def _mint_restored(self) -> None:
        try:
            self._exchange()
        except (CopilotAuthError, GitHubDeviceError):
            if not self._github:  # GitHub answered 401: the stored token is dead
                self._store.restored = False
                log.warning("secret_proxy: stored GitHub Copilot login is no longer valid; "
                            "run secret-proxy login github-copilot")
            else:
                self._retry_at = self._clock() + RETRY_DELAY
                log.warning("secret_proxy: could not mint a Copilot token from the stored login; will retry")
            return
        log.info("secret_proxy: restored the GitHub Copilot login from the login vault")

    def logout(self) -> dict:
        """Forget the login in RAM and delete the stored item, if any."""
        with self._lock:
            self._login_generation += 1
            self.device.cancel()
            self._clear()
            self._refresh_count = 0
            self._last_refresh_at = None
            if self._store is None:
                return {"stored": False}
            self._store.skip_restore()
            self._store.delete()
            return {"stored": self._store.stored}

    def api_host(self) -> str | None:
        """The one host the real token may be sent to, or None when logged out."""
        with self._lock:
            self._restore_locked()
            if not self._token:
                return None
            return api_host(token_fields(self._token)[1], self.domain)

    def get_token(self) -> str:
        """Return a valid Copilot token, refreshing once (under the lock) when due."""
        with self._lock:
            self._restore_locked()
            if self._github and not self._token:
                # Restored, but no Copilot token could be minted yet.
                raise CopilotAuthError("Copilot token refresh failed; retry shortly")
            if not self._github or not self._token:
                raise CopilotAuthError("GitHub Copilot login required; run secret-proxy login github-copilot")
            now = self._clock()
            if now < self._refresh_at:
                return self._token
            usable = now < self._expires_at - 30
            if now < self._retry_at:
                if usable:
                    return self._token
                raise CopilotAuthError("Copilot token refresh failed; retry shortly")
            try:
                self._exchange()
            except (CopilotAuthError, GitHubDeviceError):
                self._retry_at = now + RETRY_DELAY
                if self._token and usable:
                    return self._token
                raise CopilotAuthError("Copilot token refresh failed") from None
            self._refresh_count += 1
            self._last_refresh_at = int(now)
            return self._token

    def exchange_answer(self) -> dict:
        """What the proxy returns to a client's own exchange call: sealed only."""
        with self._lock:
            self.get_token()
            exp, proxy_ep = token_fields(self._token)
            return {"token": seal(exp if exp is not None else self._expires_at, proxy_ep),
                    "expires_at": self._expires_at,
                    "refresh_in": max(0, int(self._refresh_at - self._clock())),
                    "endpoints": {"api": "https://" + api_host(proxy_ep, self.domain)}}

    def status(self) -> dict:
        """Lifecycle evidence only: no tokens or identities. With a login store,
        the first call after a start may restore the stored login."""
        with self._lock:
            self._restore_locked()
            logged_in = bool(self._github and self._token)
            value = {"loggedIn": logged_in,
                     "expiresAt": int(self._expires_at) if logged_in else None,
                     "refreshCount": self._refresh_count,
                     "lastRefreshAt": self._last_refresh_at}
            if self._store is not None:
                value.update(self._store.status())
            return value
