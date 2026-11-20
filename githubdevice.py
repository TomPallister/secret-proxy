"""Proxy-owned GitHub OAuth device flow (RFC 8628). Tokens stay in this process.

The client asks the proxy to start a login and receives only the user code and
verification URL. Every poll of GitHub's token endpoint happens here, at the
pace GitHub asks for (``interval`` and ``slow_down``) and only until the code
expires (``expires_in``). The resulting GitHub token never leaves the proxy.

Shared by the GitHub Copilot login (copilotcreds.py) and the GitHub CLI login
(ghclicreds.py); each supplies its own public OAuth client ID and scopes.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from oauthcreds import tls_context

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
DEFAULT_INTERVAL = 5
SLOW_DOWN_STEP = 5
MAX_EXPIRES_IN = 3600
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_USER_CODE_RE = re.compile(r"[A-Za-z0-9-]{4,32}")
_TOKEN_RE = re.compile(r"[\x21-\x7e]{8,4096}")
_SCOPE_RE = re.compile(r"[a-z0-9:_-]{1,64}")
# Failure reasons a client may see. Never an upstream body or description.
REASONS = frozenset({"expired_token", "access_denied", "login_failed", "no_login", "unavailable"})


class GitHubDeviceError(Exception):
    """A login failed. ``reason`` is one of REASONS; the message holds no secret."""

    def __init__(self, reason: str, message: str):
        self.reason = reason if reason in REASONS else "login_failed"
        super().__init__(message)


def valid_domain(domain: object) -> bool:
    """A lowercase DNS host name with at least two labels and no wildcard."""
    if not isinstance(domain, str) or len(domain) > 253:
        return False
    labels = domain.split(".")
    return len(labels) >= 2 and all(_LABEL_RE.fullmatch(label) for label in labels)


def valid_scope(scope: object) -> bool:
    return isinstance(scope, str) and _SCOPE_RE.fullmatch(scope) is not None


def request_json(url: str, *, method: str = "GET", fields: dict | None = None,
                 headers: dict | None = None, label: str = "GitHub") -> tuple[int, dict]:
    """Send one bounded request and return ``(status, json_object)``.

    Errors are reduced to an exception type name: an upstream response body
    or exception can contain a token and is never logged or forwarded.
    """
    data = urllib.parse.urlencode(fields).encode() if fields is not None else None
    merged = {"Accept": "application/json"}
    if data is not None:
        merged["Content-Type"] = "application/x-www-form-urlencoded"
    merged.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=merged)
    try:
        try:
            with urllib.request.urlopen(req, timeout=15, context=tls_context()) as response:
                status, body = response.status, response.read(262145)
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read(262145)
        if len(body) > 262144:
            raise ValueError()
        result = json.loads(body) if body else {}
        if not isinstance(result, dict):
            raise ValueError()
        return status, result
    except Exception as error:  # noqa: BLE001 - never echo upstream content
        raise GitHubDeviceError("unavailable", f"{label} request failed ({type(error).__name__})") from None


class DeviceFlow:
    """One pending device login at a time; ``poll`` returns the token once."""

    def __init__(self, *, domain: str, client_id: str, scopes: tuple[str, ...],
                 user_agent: str, label: str, request=None, clock=time.time, sleep=time.sleep):
        if not valid_domain(domain):
            raise ValueError("invalid GitHub domain")
        if not scopes or not all(valid_scope(scope) for scope in scopes):
            raise ValueError("invalid OAuth scopes")
        self.domain = domain
        self.client_id = client_id
        self.scopes = tuple(scopes)
        self._user_agent = user_agent
        self._label = label
        self._request = request or request_json
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()  # guards the pending state
        self._poll_lock = threading.Lock()  # one upstream poll at a time
        self._pending = None

    @property
    def device_code_url(self) -> str:
        return f"https://{self.domain}/login/device/code"

    @property
    def token_url(self) -> str:
        return f"https://{self.domain}/login/oauth/access_token"

    def _headers(self) -> dict:
        return {"User-Agent": self._user_agent}

    def start(self) -> dict:
        """Request a device code; return only what the person needs to see."""
        status, data = self._request(
            self.device_code_url, method="POST", headers=self._headers(), label=self._label,
            fields={"client_id": self.client_id, "scope": " ".join(self.scopes)},
        )
        device_code, user_code = data.get("device_code"), data.get("user_code")
        uri, expires_in, interval = data.get("verification_uri"), data.get("expires_in"), data.get("interval", DEFAULT_INTERVAL)
        try:
            if status != 200 or not isinstance(device_code, str) or not _TOKEN_RE.fullmatch(device_code):
                raise ValueError()
            if not isinstance(user_code, str) or not _USER_CODE_RE.fullmatch(user_code):
                raise ValueError()
            if type(expires_in) is not int or not 0 < expires_in <= MAX_EXPIRES_IN:
                raise ValueError()
            if type(interval) is not int or not 0 < interval <= 600:
                raise ValueError()
            parsed = urllib.parse.urlsplit(uri) if isinstance(uri, str) else None
            # The URL is shown to a person, so it must be GitHub's own HTTPS page.
            if (parsed is None or parsed.scheme != "https" or parsed.hostname != self.domain
                    or parsed.port is not None or parsed.username or parsed.password
                    or any(ord(char) < 33 for char in uri)):
                raise ValueError()
        except ValueError:
            raise GitHubDeviceError("unavailable", f"{self._label} returned an invalid device code") from None
        now = self._clock()
        with self._lock:
            self._pending = {"device_code": device_code, "deadline": now + expires_in,
                             "interval": interval, "next": now + interval}
        return {"userCode": user_code, "verificationUri": uri, "expiresIn": expires_in, "interval": interval}

    def cancel(self) -> None:
        with self._lock:
            self._pending = None

    def poll(self, max_wait: float = 10.0) -> dict | None:
        """Poll GitHub at most once. Return the token response, or None if pending.

        Waits until GitHub's next permitted poll time, but never longer than
        *max_wait*: a longer wait returns None without polling, and the client
        asks again. Raises GitHubDeviceError when the login cannot succeed.
        """
        with self._poll_lock:
            with self._lock:
                pending = self._pending
                if pending is None:
                    raise GitHubDeviceError("no_login", "No login in progress; start again")
                now = self._clock()
                if now >= pending["deadline"]:
                    self._pending = None
                    raise GitHubDeviceError("expired_token", "The device code expired; start again")
                wait = max(0.0, pending["next"] - now)
            if wait > max_wait:
                return None
            if wait:
                self._sleep(wait)
            with self._lock:
                if self._pending is not pending:
                    raise GitHubDeviceError("no_login", "The login was replaced; start again")
                if self._clock() >= pending["deadline"]:
                    self._pending = None
                    raise GitHubDeviceError("expired_token", "The device code expired; start again")
            try:
                status, data = self._request(
                    self.token_url, method="POST", headers=self._headers(), label=self._label,
                    fields={"client_id": self.client_id, "device_code": pending["device_code"],
                            "grant_type": DEVICE_GRANT},
                )
            except GitHubDeviceError:
                with self._lock:
                    pending["next"] = self._clock() + pending["interval"]
                raise
            with self._lock:
                if self._pending is not pending:
                    raise GitHubDeviceError("no_login", "The login was replaced; start again")
                token = data.get("access_token")
                if status == 200 and isinstance(token, str):
                    self._pending = None
                    if not _TOKEN_RE.fullmatch(token):
                        raise GitHubDeviceError("login_failed", f"{self._label} returned an invalid token")
                    scope = data.get("scope", "")
                    items = scope.split(",") if isinstance(scope, str) else []
                    granted = tuple(sorted({item.strip() for item in items if valid_scope(item.strip())}))
                    return {"access_token": token, "scopes": granted}
                error = data.get("error")
                if error == "authorization_pending":
                    pending["next"] = self._clock() + pending["interval"]
                    return None
                if error == "slow_down":
                    interval = data.get("interval")
                    if type(interval) is int and 0 < interval <= 600:
                        pending["interval"] = max(interval, pending["interval"])
                    else:
                        pending["interval"] += SLOW_DOWN_STEP
                    pending["next"] = self._clock() + pending["interval"]
                    return None
                self._pending = None
                reason = error if error in ("expired_token", "access_denied") else "login_failed"
                raise GitHubDeviceError(reason, f"{self._label} login failed ({reason})")

    def retry_after(self) -> int:
        """Seconds until the next permitted poll; 0 when none is pending."""
        with self._lock:
            if self._pending is None:
                return 0
            return max(0, int(self._pending["next"] - self._clock() + 0.999))


def form_or_query_mentions(flow_request, value: str) -> bool:
    """Whether *value* appears anywhere in a request's target or body.

    Used to refuse a client's own device flow for a proxy-owned client ID.
    Inspect raw bytes, percent-decoded form/query data and JSON strings after
    HTTP content decoding. Keep duplicate JSON fields: an ambiguous request
    naming the owned client anywhere must not reach the upstream token endpoint.
    """
    needle = value.encode("ascii")
    target = (flow_request.path or "").encode("utf-8", "surrogateescape")
    if needle in target or needle in urllib.parse.unquote_to_bytes(target):
        return True
    raw = flow_request.raw_content or b""
    if needle in raw:
        return True
    try:
        decoded = flow_request.get_content(strict=True) or b""
    except Exception:  # noqa: BLE001 - undecodable bodies are treated as a match
        return bool(raw)
    if needle in decoded or needle in urllib.parse.unquote_to_bytes(decoded):
        return True
    try:
        document = json.loads(decoded, object_pairs_hook=lambda pairs: pairs)
    except (ValueError, UnicodeError):
        return False
    except RecursionError:
        return True  # too deeply nested to inspect safely
    pending = [document]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and value in item:
            return True
        if isinstance(item, (list, tuple)):
            pending.extend(item)
    return False
