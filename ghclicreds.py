"""Proxy-owned GitHub CLI (gh) login. The GitHub OAuth token stays in RAM.

The proxy runs a device flow with the GitHub CLI's public OAuth app client ID
and keeps the resulting token in memory. gh is given only a reference, for
example ``GH_TOKEN=<reference to GH_CLI_OAUTH_TOKEN>``, and the manifest's
placements decide where the real token is added (API headers, Git Basic
auth). By default the token is not stored and a restart requires a new login.
With an opt-in login store (loginstore.py) it is also kept in a read/write
vault and restored after a restart.
"""

from __future__ import annotations

import logging
import re
import threading
import time

import githubdevice
import loginstore
from githubdevice import DeviceFlow

# Public client ID of the GitHub CLI's OAuth app (it is in gh's source code).
CLIENT_ID = "178c6fc778ccc68e1d6a"
# gh's own minimum scopes for `gh auth login`.
DEFAULT_SCOPES = ("repo", "read:org", "gist")
CANONICAL = "GH_CLI_OAUTH_TOKEN"
DEFAULT_DOMAIN = "github.com"
USER_AGENT = "secret-proxy"


_TOKEN_RE = re.compile(r"[\x21-\x7e]{8,4096}")
log = logging.getLogger("secret_proxy.ghcli")


class GhCliAuthError(Exception):
    pass


class GhCliCredentials:
    def __init__(self, domain: str = DEFAULT_DOMAIN, scopes: tuple[str, ...] = DEFAULT_SCOPES,
                 request=None, clock=time.time, sleep=time.sleep, store=None):
        self.domain = domain
        self.requested_scopes = tuple(scopes)
        # Optional loginstore.LoginStore; None keeps the token in RAM only.
        self._store = loginstore.persistence(store, "github", clock)
        self.device = DeviceFlow(domain=domain, client_id=CLIENT_ID, scopes=tuple(scopes),
                                 user_agent=USER_AGENT, label="GitHub CLI",
                                 request=request or githubdevice.request_json,
                                 clock=clock, sleep=sleep)
        self._lock = threading.Lock()
        self._login_generation = 0
        self._token = None
        self._scopes = ()

    def start(self) -> dict:
        with self._lock:
            self._login_generation += 1
            self.device.cancel()
            return self.device.start()

    def poll(self, max_wait: float = 10.0) -> dict | None:
        """Finish a device login; return non-secret completion details or None."""
        with self._lock:
            generation = self._login_generation
        result = self.device.poll(max_wait)
        if result is None:
            return None
        with self._lock:
            # DeviceFlow guards cancellation during the network call. Also
            # guard the gap between its return and publishing the credentials.
            if generation != self._login_generation:
                raise githubdevice.GitHubDeviceError("no_login", "The login was replaced; start again")
            self._token, self._scopes = result["access_token"], result["scopes"]
            if self._store is not None:
                self._store.skip_restore()
                self._store.save(self._token, self._metadata())
        return {"scopes": list(result["scopes"])}

    def _metadata(self) -> dict:
        return {"domain": self.domain, "scopes": " ".join(self._scopes),
                "requested_scopes": " ".join(self.requested_scopes)}

    def _restore_locked(self) -> None:
        """Restore a stored token once, if it matches this login's settings."""
        if self._store is None:
            return
        self._store.flush()
        if self._token:
            return
        found = self._store.take_restore()
        if found is None:
            return
        scopes = tuple((found.metadata.get("scopes") or "").split())
        if (found.metadata.get("domain") != self.domain
                or found.metadata.get("requested_scopes") != " ".join(self.requested_scopes)
                or not all(githubdevice.valid_scope(scope) for scope in scopes)):
            log.warning("secret_proxy: stored GitHub CLI login was made with other settings; "
                        "run secret-proxy login github")
            return
        if not _TOKEN_RE.fullmatch(found.value):
            log.warning("secret_proxy: stored GitHub CLI login is not usable; run secret-proxy login github")
            return
        self._token, self._scopes = found.value, scopes
        self._store.restored = True
        log.info("secret_proxy: restored the GitHub CLI login from the login vault")

    def logout(self) -> dict:
        """Forget the login in RAM and delete the stored item, if any."""
        with self._lock:
            self._login_generation += 1
            self.device.cancel()
            self._token, self._scopes = None, ()
            if self._store is None:
                return {"stored": False}
            self._store.skip_restore()
            self._store.delete()
            return {"stored": self._store.stored}

    def get_token(self) -> str:
        with self._lock:
            self._restore_locked()
            if not self._token:
                raise GhCliAuthError("GitHub CLI login required; run secret-proxy login github")
            return self._token

    def status(self) -> dict:
        with self._lock:
            self._restore_locked()
            value = {"loggedIn": bool(self._token), "scopes": list(self._scopes) if self._token else []}
            if self._store is not None:
                value.update(self._store.status())
            return value
