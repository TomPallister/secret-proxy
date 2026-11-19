"""Proxy-owned GitHub CLI (gh) login. The GitHub OAuth token stays in RAM.

The proxy runs a device flow with the GitHub CLI's public OAuth app client ID
and keeps the resulting token in memory. gh is given only a reference, for
example ``GH_TOKEN=<reference to GH_CLI_OAUTH_TOKEN>``, and the manifest's
placements decide where the real token is added (API headers, Git Basic
auth). The token is not stored in the vault; a restart requires a new login.
"""

from __future__ import annotations

import threading
import time

import githubdevice
from githubdevice import DeviceFlow

# Public client ID of the GitHub CLI's OAuth app (it is in gh's source code).
CLIENT_ID = "178c6fc778ccc68e1d6a"
# gh's own minimum scopes for `gh auth login`.
DEFAULT_SCOPES = ("repo", "read:org", "gist")
CANONICAL = "GH_CLI_OAUTH_TOKEN"
DEFAULT_DOMAIN = "github.com"
USER_AGENT = "secret-proxy"


class GhCliAuthError(Exception):
    pass


class GhCliCredentials:
    def __init__(self, domain: str = DEFAULT_DOMAIN, scopes: tuple[str, ...] = DEFAULT_SCOPES,
                 request=None, clock=time.time, sleep=time.sleep):
        self.domain = domain
        self.device = DeviceFlow(domain=domain, client_id=CLIENT_ID, scopes=tuple(scopes),
                                 user_agent=USER_AGENT, label="GitHub CLI",
                                 request=request or githubdevice.request_json,
                                 clock=clock, sleep=sleep)
        self._lock = threading.Lock()
        self._token = None
        self._scopes = ()

    def start(self) -> dict:
        return self.device.start()

    def poll(self, max_wait: float = 10.0) -> dict | None:
        """Finish a device login; return non-secret completion details or None."""
        result = self.device.poll(max_wait)
        if result is None:
            return None
        with self._lock:
            self._token, self._scopes = result["access_token"], result["scopes"]
        return {"scopes": list(result["scopes"])}

    def get_token(self) -> str:
        with self._lock:
            if not self._token:
                raise GhCliAuthError("GitHub CLI login required; run secret-proxy login github")
            return self._token

    def status(self) -> dict:
        with self._lock:
            return {"loggedIn": bool(self._token), "scopes": list(self._scopes) if self._token else []}
