"""Opt-in persistence of proxy-owned logins in a separate read/write vault.

Off unless the manifest has ``loginStore``; then every proxy-owned login keeps
its long-lived token in one 1Password Login item in that vault, so a restart
does not need a new browser or device login:

* ChatGPT: the rotating refresh token, written back after every refresh;
* GitHub Copilot and GitHub CLI: the GitHub OAuth token.

Short-lived tokens (ChatGPT access, Copilot session) are never stored. The
value goes to ``op`` only as a JSON template on stdin, never in argv, and is
never logged. Clients still receive only references and sealed entries.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Mapping

from secretstore import DefaultCommandRunner, OP_CLI_PATH, OP_CONFIG_DIR, build_cli_env

# One Login item per login, with a fixed title. One proxy instance per vault.
TITLES = {
    "chatgpt": "SECRET_PROXY_LOGIN_CHATGPT",
    "github-copilot": "SECRET_PROXY_LOGIN_GITHUB_COPILOT",
    "github": "SECRET_PROXY_LOGIN_GITHUB",
}
# Non-secret text fields stored beside the value, used to check a restore.
METADATA = {
    "chatgpt": frozenset({"account_id"}),
    "github-copilot": frozenset({"domain"}),
    "github": frozenset({"domain", "scopes", "requested_scopes"}),
}
LABELS = {"chatgpt": "ChatGPT", "github-copilot": "GitHub Copilot", "github": "GitHub CLI"}
TIMEOUT = 20
MAX_VALUE = 16384
FIRST_RETRY = 60
MAX_RETRY = 1800
_VALUE_RE = re.compile(r"[\x21-\x7e]{1,%d}" % MAX_VALUE)
_META_RE = re.compile(r"[\x20-\x7e]{0,512}")
_ITEM_ID_RE = re.compile(r"[a-z0-9]{26}")

log = logging.getLogger("secret_proxy.loginstore")


class LoginStoreError(Exception):
    """A vault operation failed. Messages are fixed text: never values or op output."""


@dataclass(frozen=True)
class StoredLogin:
    value: str = field(repr=False)
    metadata: dict = field(default_factory=dict)


def _checked_metadata(kind: str, metadata: Mapping) -> dict:
    if not isinstance(metadata, Mapping) or set(metadata) - METADATA[kind]:
        raise LoginStoreError("invalid login metadata")
    for value in metadata.values():
        if not isinstance(value, str) or _META_RE.fullmatch(value) is None:
            raise LoginStoreError("invalid login metadata")
    return dict(metadata)


class LoginStore:
    """Read, write and delete the login items with the ``op`` CLI."""

    def __init__(self, vault: str, token: str, runner=None, runtime_env: Mapping | None = None):
        if not isinstance(vault, str) or not vault:
            raise LoginStoreError("a login vault is required")
        if not token:
            raise LoginStoreError("1Password service account capability is required")
        self.vault = vault
        self._token = token
        self._runtime_env = dict(runtime_env or {})
        self._runner = runner or DefaultCommandRunner()
        self._lock = threading.Lock()  # one vault operation at a time

    def _run(self, args: list, operation: str, value_input: str | None = None) -> str:
        env = build_cli_env(self._runtime_env, credential_name="OP_SERVICE_ACCOUNT_TOKEN",
                            credential=self._token)
        env["OP_CONFIG_DIR"] = OP_CONFIG_DIR
        try:
            result = self._runner.run([OP_CLI_PATH, *args], env=env, input=value_input, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            raise LoginStoreError(f"login vault {operation} timed out") from None
        except OSError:
            raise LoginStoreError(f"login vault {operation} could not run op") from None
        if result.returncode != 0:
            # op's stderr may echo input; report only the exit code.
            raise LoginStoreError(f"login vault {operation} failed (exit code {result.returncode})")
        return result.stdout if isinstance(result.stdout, str) else ""

    def _find(self, kind: str) -> str | None:
        title = TITLES[kind]
        try:
            items = json.loads(self._run(["item", "list", "--vault", self.vault, "--format=json"], "list"))
        except ValueError:
            raise LoginStoreError("login vault list returned invalid JSON") from None
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise LoginStoreError("login vault list returned an unexpected structure")
        matches = [item for item in items if item.get("title") == title]
        if len(matches) > 1:
            raise LoginStoreError(f"the login vault has more than one item titled {title}; remove the extra ones")
        if not matches:
            return None
        item_id = matches[0].get("id")
        if not isinstance(item_id, str) or _ITEM_ID_RE.fullmatch(item_id) is None:
            raise LoginStoreError(f"login vault item {title} has an invalid ID")
        return item_id

    def read(self, kind: str) -> StoredLogin | None:
        """The stored login, or None when there is no item. Raises LoginStoreError."""
        with self._lock:
            item_id = self._find(kind)
            if item_id is None:
                return None
            try:
                item = json.loads(self._run(["item", "get", item_id, "--vault", self.vault,
                                             "--format=json", "--reveal"], "read"))
            except ValueError:
                raise LoginStoreError("login vault read returned invalid JSON") from None
        title = TITLES[kind]
        if not isinstance(item, dict) or item.get("title") != title or item.get("category") != "LOGIN":
            raise LoginStoreError(f"login vault item {title} is not the expected Login item")
        fields = item.get("fields", [])
        if not isinstance(fields, list) or any(not isinstance(f, dict) for f in fields):
            raise LoginStoreError(f"login vault item {title} has invalid fields")
        values = [f.get("value") for f in fields if f.get("id") == "password" and f.get("purpose") == "PASSWORD"]
        if len(values) != 1 or not isinstance(values[0], str) or _VALUE_RE.fullmatch(values[0]) is None:
            raise LoginStoreError(f"login vault item {title} has no usable password field")
        metadata = {}
        for entry in fields:
            label = entry.get("label")
            if label in METADATA[kind] and entry.get("type") == "STRING":
                if label in metadata:
                    raise LoginStoreError(f"login vault item {title} has duplicate fields")
                metadata[label] = entry.get("value")
        try:
            metadata = _checked_metadata(kind, metadata)
        except LoginStoreError:
            raise LoginStoreError(f"login vault item {title} has invalid text fields") from None
        return StoredLogin(values[0], metadata)

    def save(self, kind: str, value: str, metadata: Mapping) -> None:
        """Create the item, or replace the one existing item's fields."""
        if not isinstance(value, str) or _VALUE_RE.fullmatch(value) is None:
            raise LoginStoreError("refusing to store an invalid login value")
        metadata = _checked_metadata(kind, metadata)
        fields = [{"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": value}]
        fields += [{"id": label, "type": "STRING", "label": label, "value": metadata[label]}
                   for label in sorted(metadata)]
        template = json.dumps({"title": TITLES[kind], "category": "LOGIN", "fields": fields})
        with self._lock:
            item_id = self._find(kind)
            if item_id is None:
                self._run(["item", "create", "--vault", self.vault, "--format=json", "-"], "create", template)
            else:
                self._run(["item", "edit", item_id, "--vault", self.vault, "--format=json"], "edit", template)

    def delete(self, kind: str) -> bool:
        """Delete the item; False when there was none."""
        with self._lock:
            item_id = self._find(kind)
            if item_id is None:
                return False
            self._run(["item", "delete", item_id, "--vault", self.vault], "delete")
            return True


class Persistence:
    """One login's use of the store: restore once, then write-behind with retry.

    Callers hold their provider lock, so a restore runs once per proxy start.
    A failed write keeps the login working in memory and is retried, with
    backoff, the next time the login is used. Nothing polls the vault.
    """

    def __init__(self, store: LoginStore, kind: str, clock=time.time):
        if kind not in TITLES:
            raise ValueError("unknown login kind")
        self.store = store
        self.kind = kind
        self.label = LABELS[kind]
        self._clock = clock
        self.stored = False  # the vault holds this login, as of the last read or write
        self.restored = False  # the current login came from the vault
        self._restore_done = False
        self._restore_at = 0.0
        self._restore_backoff = FIRST_RETRY
        self._pending = None  # ("save", value, metadata) or ("delete",)
        self._retry_at = 0.0
        self._backoff = FIRST_RETRY

    def take_restore(self) -> StoredLogin | None:
        """The stored login once per start; None if absent, unreadable or done."""
        if self._restore_done or self._clock() < self._restore_at:
            return None
        try:
            found = self.store.read(self.kind)
        except LoginStoreError as error:
            log.warning("secret_proxy: could not read the stored %s login (%s); will retry", self.label, error)
            self._restore_at = self._clock() + self._restore_backoff
            self._restore_backoff = min(self._restore_backoff * 2, MAX_RETRY)
            return None
        self._restore_done = True
        self.stored = found is not None
        return found

    def restore_later(self) -> None:
        """The upstream could not be reached: keep the stored login, try again later."""
        self._restore_done = False
        self._restore_at = self._clock() + self._restore_backoff
        self._restore_backoff = min(self._restore_backoff * 2, MAX_RETRY)

    def skip_restore(self) -> None:
        """A new login or a logout replaces whatever is stored."""
        self._restore_done = True
        self.restored = False

    def save(self, value: str, metadata: Mapping) -> bool:
        self._pending = ("save", value, dict(metadata))
        self._retry_at = 0.0
        self._backoff = FIRST_RETRY
        return self.flush()

    def delete(self) -> bool:
        self._pending = ("delete",)
        self._retry_at = 0.0
        self._backoff = FIRST_RETRY
        return self.flush()

    def flush(self) -> bool:
        """Attempt a pending write when due. True when nothing is left pending."""
        pending = self._pending
        if pending is None:
            return True
        if self._clock() < self._retry_at:
            return False
        try:
            if pending[0] == "save":
                self.store.save(self.kind, pending[1], pending[2])
                self.stored = True
            else:
                self.store.delete(self.kind)
                self.stored = False
        except LoginStoreError as error:
            action = "save" if pending[0] == "save" else "delete"
            if action == "delete":
                self.stored = True  # not confirmed gone: report it as still stored
            log.warning("secret_proxy: could not %s the stored %s login (%s); keeping the login in memory "
                        "and retrying", action, self.label, error)
            self._retry_at = self._clock() + self._backoff
            self._backoff = min(self._backoff * 2, MAX_RETRY)
            return False
        self._pending = None
        self._backoff = FIRST_RETRY
        return True

    def status(self) -> dict:
        return {"stored": self.stored, "restoredFromStore": self.restored}


def persistence(store: LoginStore | None, kind: str, clock=time.time) -> Persistence | None:
    return None if store is None else Persistence(store, kind, clock)
