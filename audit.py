"""Opt-in, tamper-evident audit log of security decisions (issue #6).

Off by default: without an enabled manifest ``audit`` section nothing here is
constructed and nothing is written anywhere.

When enabled, the proxy appends one JSON line per security decision to files
in its own private state (``/data/audit`` in the container: the proxy's
persistent volume, never ``/config`` and never a client-shared directory).
Directory 0700, files 0600, owned by the proxy user.

* Only an explicit allow-list of fields (:data:`FIELD_NAMES`) with fixed shapes
  can be written. Anything else is dropped and counted. Paths lose their query
  string and fragment here, every value is length-capped, and free text is not
  accepted: reasons are fixed codes and errors are exception class names. So a
  caller cannot write a secret value, header, body or query string by mistake.
* Hash chain: every line carries ``seq`` and ``prev`` (SHA-256 of the previous
  line's bytes). Each file starts with a header (format version, file number,
  boot nonce, start time, signing-key fingerprint) whose ``prev`` is the hash
  of the previous file's last line, so the files form one chain.
* Each file ends with a ``seal`` when the proxy stops cleanly or rotates the
  file. The seal carries an SSH signature (namespace ``secret-proxy-audit``)
  over the file's header hash, the seal's position and the last hash, made with
  an internalOnly SSH key from the store. Without the key the seal says why it
  is unsigned. A crash leaves an unsigned tail.
* Retention: a file is rotated when it reaches ``maxFileBytes`` or is a day
  old; the oldest files are deleted while the total exceeds ``maxTotalBytes``
  or they are older than ``maxAgeDays``.

``verify`` (also used by ``secret-proxy audit verify``) checks the chain and
the signatures against a public key you pin. ``export`` (run in a throwaway
container) writes the files to stdout for the host to copy out.

Pure standard library and Python 3.9 compatible: the macOS daily CLI imports it
to verify, and secretstore imports it to validate the manifest. Signing imports
``gitsign`` (cryptography) lazily, inside the container only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Tuple

FORMAT_VERSION = 1
NAMESPACE = "secret-proxy-audit"
FILE_RE = re.compile(r"audit-([0-9]{8})\.jsonl\Z")
MAX_LINE = 4096
MAX_PATH = 256
ROTATE_AGE_SECONDS = 86400

DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024
MIN_MAX_FILE_BYTES = 64 * 1024
MAX_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_AGE_DAYS = 90
MAX_MAX_AGE_DAYS = 3650
# Export bound: the retention maximum plus a margin for the current file.
MAX_EXPORT_BYTES = MAX_MAX_TOTAL_BYTES + MAX_MAX_FILE_BYTES + MAX_LINE

SETTINGS_FIELDS = frozenset({"enabled", "signingKey", "maxFileBytes", "maxTotalBytes", "maxAgeDays"})

EVENTS = frozenset({
    "inject", "aws", "egress", "approval", "login", "exchange", "sign", "grant", "transport",
})
DECISIONS = frozenset({
    "injected", "refused", "allowed", "denied", "failed", "signed", "answered",
    "started", "completed",
})
KEY_STATUSES = frozenset({"signed", "no-signing-key", "signing-key-unavailable", "signing-failed"})

_CANONICAL_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_CLIENT_RE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_HOST_RE = re.compile(r"[a-z0-9._:-]{1,253}\Z")
_METHOD_RE = re.compile(r"[A-Z]{1,16}\Z")
_FIELD_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_REASON_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_RULE_RE = re.compile(r"[A-Za-z0-9 _.:()\[\]/#*?=,-]{1,128}\Z")
_ERROR_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_ACCOUNT_RE = re.compile(r"(?:[0-9]{12}|-)\Z")
_ROLE_RE = re.compile(r"[A-Za-z0-9+=,.@_/-]{1,128}\Z")
_SERVICE_RE = re.compile(r"[A-Za-z0-9-]{1,64}\Z")
_OPERATION_RE = re.compile(r"[A-Za-z0-9_]{1,128}\Z")
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_INSTANCE_RE = re.compile(r"[0-9a-f]{32}\Z")
_FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_SIGNATURE_RE = re.compile(
    r"-----BEGIN SSH SIGNATURE-----\n(?:[A-Za-z0-9+/=]{1,76}\n){1,40}-----END SSH SIGNATURE-----\n\Z")

PLACEMENTS = frozenset({"header", "query", "form", "basic-password", "url-rewrite"})
CHOICES = frozenset({"deny-once", "allow-once", "allow-session", "deny-session", "session"})
APPROVAL_KINDS = frozenset({"secret", "aws", "egress"})
PROVIDERS = frozenset({"chatgpt", "github-copilot", "github", "checkmarx"})
OBJECTS = frozenset({"commit", "tag"})


class AuditConfigError(ValueError):
    """Invalid ``audit`` manifest section. Messages contain configuration text only."""


class AuditError(Exception):
    """The audit log cannot be used. Messages never contain logged values."""


# --- Configuration ----------------------------------------------------------

def _int_setting(value: Mapping, name: str, default: int, low: int, high: int) -> int:
    number = value.get(name, default)
    if type(number) is not int or not low <= number <= high:
        raise AuditConfigError(f"audit.{name} must be an integer from {low} to {high}")
    return number


def parse_settings(value: object, secrets: Optional[Mapping] = None) -> Optional[Dict]:
    """Validate the optional manifest ``audit`` section.

    Returns None when the section is absent or ``enabled`` is false (nothing is
    ever written), otherwise the normalised settings. *secrets* maps canonical
    names to manifest SecretInfo objects, to check ``signingKey``.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        raise AuditConfigError("audit must be a JSON object")
    unknown = set(value) - SETTINGS_FIELDS
    if unknown:
        raise AuditConfigError("audit has unknown fields: " + ", ".join(sorted(map(str, unknown))))
    if "enabled" not in value or type(value["enabled"]) is not bool:
        raise AuditConfigError("audit.enabled must be true or false")
    max_file = _int_setting(value, "maxFileBytes", DEFAULT_MAX_FILE_BYTES, MIN_MAX_FILE_BYTES, MAX_MAX_FILE_BYTES)
    max_total = _int_setting(value, "maxTotalBytes", max(DEFAULT_MAX_TOTAL_BYTES, max_file),
                             max_file, MAX_MAX_TOTAL_BYTES)
    max_age = _int_setting(value, "maxAgeDays", DEFAULT_MAX_AGE_DAYS, 1, MAX_MAX_AGE_DAYS)
    key = value.get("signingKey")
    if key is not None:
        if not isinstance(key, str) or _CANONICAL_RE.fullmatch(key) is None:
            raise AuditConfigError("audit.signingKey must be a canonical secret name")
        info = None if secrets is None else secrets.get(key)
        if secrets is not None and (
            info is None or not getattr(info, "internal_only", False)
            or getattr(info, "value_field", None) != "sshPrivateKey"
            or getattr(info, "derived_from", None)
        ):
            raise AuditConfigError(
                "audit.signingKey must name an internalOnly secret with valueField sshPrivateKey")
    if not value["enabled"]:
        return None
    return {"maxFileBytes": max_file, "maxTotalBytes": max_total, "maxAgeDays": max_age,
            "signingKey": key}


# --- The field allow-list ---------------------------------------------------

def _match(pattern):
    def check(value):
        if isinstance(value, str) and pattern.fullmatch(value):
            return value
        return None
    return check


def _member(allowed):
    def check(value):
        return value if isinstance(value, str) and value in allowed else None
    return check


def _client(value):
    return value if isinstance(value, str) and _CLIENT_RE.fullmatch(value) else None


def _host(value):
    if not isinstance(value, str):
        return None
    text = value.lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return text if _HOST_RE.fullmatch(text) else None


def _port(value):
    return value if type(value) is int and 1 <= value <= 65535 else None


def _method(value):
    if not isinstance(value, str):
        return None
    text = value.upper()
    return text if _METHOD_RE.fullmatch(text) else None


def clean_path(value: object) -> Optional[str]:
    """The path only: no query string or fragment, printable ASCII, capped."""
    if not isinstance(value, str):
        return None
    text = value
    for mark in ("?", "#"):
        text = text.split(mark, 1)[0]
    if not text:
        return None
    text = "".join(c if 33 <= ord(c) < 127 else "?" for c in text)
    if len(text) > MAX_PATH:
        text = text[: MAX_PATH - 3] + "..."
    return text


def _field_name(value):
    return value.lower() if isinstance(value, str) and _FIELD_RE.fullmatch(value) else None


def _flag(value):
    return value if type(value) is bool else None


_CHECKS = {
    "client": _client,
    "host": _host,
    "port": _port,
    "method": _method,
    "path": clean_path,
    "secret": _match(_CANONICAL_RE),
    "placement": _member(PLACEMENTS),
    "field": _field_name,
    "reason": _match(_REASON_RE),
    "rule": _match(_RULE_RE),
    "error": _match(_ERROR_RE),
    "account": _match(_ACCOUNT_RE),
    "role": _match(_ROLE_RE),
    "service": _match(_SERVICE_RE),
    "operation": _match(_OPERATION_RE),
    "overridden": _flag,
    "choice": _member(CHOICES),
    "kind": _member(APPROVAL_KINDS),
    "provider": _member(PROVIDERS),
    "object": _member(OBJECTS),
}
FIELD_NAMES = frozenset(_CHECKS)


def sanitize(fields: Mapping) -> Tuple[Dict, int]:
    """Keep only allow-listed, well-formed fields; return them and the drop count.

    A None value means "not applicable" and is skipped without counting.
    """
    kept: Dict = {}
    dropped = 0
    for name, value in fields.items():
        if value is None:
            continue
        check = _CHECKS.get(name) if isinstance(name, str) else None
        cleaned = check(value) if check is not None else None
        if cleaned is None:
            dropped += 1
            continue
        kept[name] = cleaned
    return kept, dropped


# --- Encoding ----------------------------------------------------------------

def canonical(entry: Mapping) -> bytes:
    """The exact bytes of one line, without its newline."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def seal_message(header_hash: str, seq: int, prev: str) -> bytes:
    """What a seal signs: the file (by its header hash), its position and last hash."""
    return ("secret-proxy-audit seal v1\n" + header_hash + "\n" + str(seq) + "\n" + prev + "\n").encode("ascii")


def iso_time(seconds: float) -> str:
    millis = int(round(seconds * 1000))
    whole, ms = divmod(millis, 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(whole)) + ".%03dZ" % ms


def public_key_line(text: str) -> str:
    """Normalise an OpenSSH Ed25519 public key to ``ssh-ed25519 <base64>``."""
    for raw in text.splitlines():
        parts = raw.strip().split()
        if not parts or parts[0].startswith("#"):
            continue
        if len(parts) < 2 or parts[0] != "ssh-ed25519":
            raise AuditError("the public key must be one OpenSSH ssh-ed25519 key")
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except (binascii.Error, ValueError):
            raise AuditError("the public key is not valid base64") from None
        if not blob.startswith(b"\x00\x00\x00\x0bssh-ed25519") or len(blob) != 51:
            raise AuditError("the public key is not an ssh-ed25519 key")
        return "ssh-ed25519 " + parts[1]
    raise AuditError("no public key found")


def fingerprint(public_key: str) -> str:
    """``SHA256:...`` as printed by ``ssh-keygen -l``."""
    blob = base64.b64decode(public_key_line(public_key).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


# --- Signing (container only) -----------------------------------------------

class SignerError(Exception):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


class SshSigner:
    """Signs seals with an OpenSSH Ed25519 private key from *key_provider*.

    The provider returns the key text (the proxy's cached secret lookup). The
    key itself is not kept here between calls.
    """

    def __init__(self, key_provider: Callable[[], str]):
        self._key_provider = key_provider

    def _key(self) -> str:
        try:
            key = self._key_provider()
        except Exception:  # noqa: BLE001 - provider errors never reach the log
            raise SignerError("signing-key-unavailable") from None
        if not isinstance(key, str):
            raise SignerError("signing-key-unavailable")
        return key

    def public_key(self) -> str:
        import gitsign
        try:
            return gitsign.public_key_line(self._key())
        except gitsign.GitSignError:
            raise SignerError("signing-failed") from None

    def sign(self, message: bytes) -> str:
        import gitsign
        try:
            return gitsign.sign_message(self._key(), message, NAMESPACE.encode("ascii"))
        except gitsign.GitSignError:
            raise SignerError("signing-failed") from None


# --- Writer -----------------------------------------------------------------

def _open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _read_regular(path: Path, limit: int) -> bytes:
    """Read a regular file without following symlinks, up to *limit* bytes."""
    fd = os.open(str(path), _open_flags())
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AuditError("not a regular audit file")
        if info.st_size > limit:
            raise AuditError("audit file too large")
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise AuditError("audit file too large")
        return data
    finally:
        os.close(fd)


def _last_complete_line(path: Path) -> Optional[bytes]:
    fd = os.open(str(path), _open_flags())
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        start = max(0, info.st_size - 4 * MAX_LINE)
        os.lseek(fd, start, os.SEEK_SET)
        data = b""
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    end = data.rfind(b"\n")
    if end < 0:
        return None
    begin = data.rfind(b"\n", 0, end) + 1
    if begin == 0 and start > 0:
        return None  # longer than any line we write: not ours
    return data[begin:end]


class AuditLog:
    """Append-only, hash-chained JSON lines in a private directory.

    Thread-safe. ``record`` writes and fsyncs one line before it returns, so an
    entry survives a crash of the proxy or the machine once the decision it
    records has been made.
    """

    def __init__(self, directory, settings: Mapping, instance: str,
                 signer: Optional[SshSigner] = None, clock: Callable[[], float] = time.time):
        if not isinstance(instance, str) or _INSTANCE_RE.fullmatch(instance) is None:
            raise AuditError("invalid instance identifier")
        self.directory = Path(directory)
        self.settings = dict(settings)
        self.instance = instance
        self.signer = signer
        self.clock = clock
        self._lock = threading.Lock()
        self._fd: Optional[int] = None
        self._path: Optional[Path] = None
        self._number = 0
        self._seq = 0
        self._prev = ""
        self._header_hash = ""
        self._size = 0
        self._started = 0.0
        self._file_dropped = 0
        self._closed = False
        self.dropped_total = 0
        self.healthy = True
        self.key_status = "no-signing-key"
        self.key_fingerprint: Optional[str] = None

    # -- files ---------------------------------------------------------------
    def _prepare_directory(self) -> None:
        os.makedirs(str(self.directory), mode=0o700, exist_ok=True)
        info = os.lstat(str(self.directory))
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise AuditError("the audit directory is not a directory")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise AuditError("the audit directory is not owned by the proxy user")
        os.chmod(str(self.directory), 0o700)

    def _files(self) -> List[Tuple[int, Path, os.stat_result]]:
        found = []
        for name in os.listdir(str(self.directory)):
            match = FILE_RE.fullmatch(name)
            if match is None:
                continue
            path = self.directory / name
            info = os.lstat(str(path))
            if stat.S_ISREG(info.st_mode):
                found.append((int(match.group(1)), path, info))
        return sorted(found, key=lambda item: item[0])

    def _prune(self) -> None:
        """Delete the oldest files only (never the current one), keeping the rest contiguous."""
        now = self.clock()
        files = self._files()
        total = sum(info.st_size for _n, _p, info in files)
        max_age = self.settings["maxAgeDays"] * 86400
        for _number, path, info in files:
            if path == self._path:
                break
            if total <= self.settings["maxTotalBytes"] and now - info.st_mtime <= max_age:
                break
            os.unlink(str(path))
            total -= info.st_size

    def _key_header(self) -> None:
        if self.signer is None:
            self.key_status, self.key_fingerprint = "no-signing-key", None
            return
        try:
            self.key_fingerprint = fingerprint(self.signer.public_key())
            self.key_status = "signed"
        except (SignerError, AuditError) as error:
            self.key_fingerprint = None
            self.key_status = getattr(error, "status", "signing-failed")

    def _new_file(self, prev: Optional[str]) -> None:
        self._number += 1
        path = self.directory / ("audit-%08d.jsonl" % self._number)
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(str(path), flags, 0o600)
        os.fchmod(fd, 0o600)
        self._fd, self._path = fd, path
        self._seq, self._size, self._file_dropped = 0, 0, 0
        self._started = self.clock()
        self._key_header()
        header = {
            "type": "header", "v": FORMAT_VERSION, "seq": 0, "n": self._number,
            "instance": self.instance, "t": iso_time(self._started), "prev": prev,
            "keyFingerprint": self.key_fingerprint,
            "keyStatus": "available" if self.key_status == "signed" else self.key_status,
        }
        line = canonical(header)
        if not self._append(line):
            # Never continue in a file without its header.
            self._close_file()
            try:
                os.unlink(str(path))
            except OSError:
                pass
            raise AuditError("could not write the audit log header")
        self._header_hash = self._prev

    def open(self) -> None:
        """Start a new file chained to the newest existing one."""
        with self._lock:
            self._prepare_directory()
            files = self._files()
            prev = None
            if files:
                self._number = files[-1][0]
                last = _last_complete_line(files[-1][1])
                prev = line_hash(last) if last is not None else None
            self._new_file(prev)
            self._prune()

    def _append(self, line: bytes) -> bool:
        if self._fd is None:
            return False
        data = line + b"\n"
        offset = self._size
        try:
            view = memoryview(data)
            while view:
                written = os.write(self._fd, view)
                view = view[written:]
            os.fsync(self._fd)
        except OSError:
            # Never leave a torn line in the chain: cut back to the last good one.
            try:
                os.ftruncate(self._fd, offset)
            except OSError:
                self._fd = None  # cannot repair: refuse every later write
            self.healthy = False
            return False
        self._size = offset + len(data)
        self._prev = line_hash(line)
        self.healthy = True
        return True

    def _seal(self, reason: str) -> None:
        seq = self._seq + 1
        signature, status = None, "no-signing-key"
        if self.signer is not None:
            try:
                signature = self.signer.sign(seal_message(self._header_hash, seq, self._prev))
                status = "signed"
            except SignerError as error:
                status = error.status
        entry = {"type": "seal", "seq": seq, "prev": self._prev, "t": iso_time(self.clock()),
                 "reason": reason, "entries": seq - 1, "dropped": self._file_dropped,
                 "signature": signature, "keyStatus": status}
        if self._append(canonical(entry)):
            self._seq = seq

    def _close_file(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
        self._fd = None

    def _rotate(self) -> None:
        self._seal("rotate")
        prev = self._prev
        self._close_file()
        self._new_file(prev)
        self._prune()

    # -- public ----------------------------------------------------------------
    def record(self, event: str, decision: str, fields: Mapping) -> bool:
        """Append one decision. Returns False when it could not be written."""
        kept, dropped = sanitize(fields)
        if event not in EVENTS:
            event, dropped = "invalid", dropped + 1
        if decision not in DECISIONS:
            decision, dropped = "invalid", dropped + 1
        with self._lock:
            if self._closed or self._fd is None:
                self.healthy = False
                return False
            now = self.clock()
            try:
                if (self._size >= self.settings["maxFileBytes"]
                        or now - self._started >= ROTATE_AGE_SECONDS):
                    self._rotate()
            except (OSError, AuditError):
                self.healthy = False
                return False
            entry = dict(kept)
            entry.update({"type": "event", "seq": self._seq + 1, "prev": self._prev,
                          "t": iso_time(now), "event": event, "decision": decision})
            if dropped:
                entry["dropped"] = dropped
            line = canonical(entry)
            if len(line) > MAX_LINE:
                return False
            if not self._append(line):
                return False
            self._seq += 1
            if dropped:
                self._file_dropped += dropped
                self.dropped_total += dropped
            return True

    def close(self, reason: str = "stop") -> None:
        """Seal (signed when the key is available) and close. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._fd is not None:
                self._seal(reason)
            self._close_file()


# --- Export (inside a throwaway container) ----------------------------------

def export(directory, out) -> int:
    """Write every audit file as one JSON line ``{"name","data"}``; return the count."""
    root = Path(directory)
    try:
        names = sorted(name for name in os.listdir(str(root)) if FILE_RE.fullmatch(name))
    except FileNotFoundError:
        return 0
    total = 0
    count = 0
    for name in names:
        info = os.lstat(str(root / name))
        if not stat.S_ISREG(info.st_mode):
            continue
        data = _read_regular(root / name, MAX_EXPORT_BYTES)
        total += len(data)
        if total > MAX_EXPORT_BYTES:
            raise AuditError("audit files exceed the export limit")
        out.write(json.dumps({"name": name, "data": base64.b64encode(data).decode("ascii")}).encode("ascii") + b"\n")
        count += 1
    out.flush()
    return count


def parse_export(data: bytes) -> List[Tuple[str, bytes]]:
    """Validate ``export`` output: names, base64, no duplicates, bounded size."""
    files: List[Tuple[str, bytes]] = []
    seen = set()
    total = 0
    for raw in data.splitlines():
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except ValueError:
            raise AuditError("invalid export record") from None
        if (not isinstance(item, dict) or set(item) != {"name", "data"}
                or not isinstance(item["name"], str) or FILE_RE.fullmatch(item["name"]) is None
                or not isinstance(item["data"], str) or item["name"] in seen):
            raise AuditError("invalid export record")
        try:
            content = base64.b64decode(item["data"], validate=True)
        except (binascii.Error, ValueError):
            raise AuditError("invalid export record") from None
        total += len(content)
        if total > MAX_EXPORT_BYTES:
            raise AuditError("export exceeds the size limit")
        seen.add(item["name"])
        files.append((item["name"], content))
    return files


def write_export(files: List[Tuple[str, bytes]], destination) -> Path:
    """Copy exported files into a new private directory (never overwrite)."""
    target = Path(destination)
    target.mkdir(mode=0o700)
    target.chmod(0o700)
    for name, content in files:
        fd = os.open(str(target / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
    return target


# --- Verification -----------------------------------------------------------

SSH_KEYGEN_PATH = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"


def ssh_keygen_verifier(public_key: str, ssh_keygen: Optional[str] = None,
                        timeout: float = 10) -> Callable[[bytes, str], bool]:
    """Check a seal signature with ``ssh-keygen -Y verify`` and the pinned key only."""
    key = public_key_line(public_key)
    executable = ssh_keygen or shutil.which("ssh-keygen", path=SSH_KEYGEN_PATH)
    if not executable:
        raise AuditError("ssh-keygen was not found; it is needed to check signatures")

    def verify(message: bytes, signature: str) -> bool:
        if not isinstance(signature, str) or _SIGNATURE_RE.fullmatch(signature) is None:
            return False
        with tempfile.TemporaryDirectory(prefix="audit-verify-") as tmp:
            allowed = Path(tmp) / "allowed_signers"
            allowed.write_text(f'{NAMESPACE} namespaces="{NAMESPACE}" {key}\n')
            sig = Path(tmp) / "seal.sig"
            sig.write_text(signature)
            try:
                result = subprocess.run(
                    [executable, "-Y", "verify", "-f", str(allowed), "-I", NAMESPACE,
                     "-n", NAMESPACE, "-s", str(sig)],
                    input=message, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=timeout, start_new_session=True,
                    env={"PATH": "/usr/bin:/bin"},
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
            return result.returncode == 0
    return verify


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class _FileReport:
    def __init__(self, name: str):
        self.name = name
        self.number = 0
        self.header_prev: Optional[str] = None
        self.header_hash = ""
        self.final_hash = ""
        self.fingerprint: Optional[str] = None
        self.events = 0
        self.seal: Optional[Dict] = None
        self.seal_seq = 0
        self.torn = False


class VerifyResult:
    """``status``: ``sealed``, ``unsigned-tail`` or ``invalid``."""

    def __init__(self):
        self.errors: List[str] = []
        self.notes: List[str] = []
        self.files = 0
        self.entries = 0
        self.tail = 0
        self.signed_through: Optional[str] = None
        self.status = "invalid"

    @property
    def exit_code(self) -> int:
        return {"sealed": 0, "unsigned-tail": 3}.get(self.status, 1)

    def lines(self) -> List[str]:
        out = ["ERROR: " + text for text in self.errors]
        out += ["note: " + text for text in self.notes]
        if self.status == "invalid":
            out.append("INVALID: the audit log was changed, is incomplete, or does not match the pinned key")
        elif self.status == "unsigned-tail":
            out.append(f"VALID CHAIN, UNSIGNED TAIL: {self.entries} entries in {self.files} files; "
                       + (f"signed through {self.signed_through}; " if self.signed_through else "no valid signature; ")
                       + f"{self.tail} entries after the last signature are not authenticated "
                       "(proxy still running, unclean stop, or no signing key)")
        else:
            out.append(f"VALID, SEALED: {self.entries} entries in {self.files} files, "
                       f"signed through {self.signed_through}")
        return out


def _check_file(name: str, data: bytes, result: VerifyResult) -> Optional[_FileReport]:
    report = _FileReport(name)
    lines = data.split(b"\n")
    last = lines.pop()
    if last:
        report.torn = True
        result.notes.append(f"{name}: an incomplete final line was ignored (interrupted write)")
    if not lines:
        result.errors.append(f"{name}: no complete entries")
        return None
    previous = None
    for index, line in enumerate(lines, 1):
        where = f"{name} line {index}"
        try:
            entry = json.loads(line, object_pairs_hook=_unique)
        except ValueError:
            result.errors.append(f"{where}: not a valid entry")
            return None
        if not isinstance(entry, dict) or canonical(entry) != line:
            result.errors.append(f"{where}: not in canonical form (edited?)")
            return None
        if entry.get("seq") != index - 1 or type(entry.get("seq")) is not int:
            result.errors.append(f"{where}: sequence {entry.get('seq')!r} where {index - 1} was expected "
                                 "(an entry was deleted, inserted or reordered)")
            return None
        kind = entry.get("type")
        if index == 1:
            if (kind != "header" or entry.get("v") != FORMAT_VERSION or type(entry.get("n")) is not int
                    or entry["n"] < 1 or not isinstance(entry.get("instance"), str)
                    or _INSTANCE_RE.fullmatch(entry["instance"]) is None
                    or not (entry.get("prev") is None or (isinstance(entry["prev"], str)
                                                          and _HASH_RE.fullmatch(entry["prev"])))
                    or not (entry.get("keyFingerprint") is None
                            or (isinstance(entry["keyFingerprint"], str)
                                and _FINGERPRINT_RE.fullmatch(entry["keyFingerprint"])))):
                result.errors.append(f"{where}: not a valid file header")
                return None
            report.number = entry["n"]
            report.header_prev = entry["prev"]
            report.fingerprint = entry["keyFingerprint"]
            report.header_hash = line_hash(line)
        else:
            if entry.get("prev") != previous:
                result.errors.append(f"{where}: does not follow the previous entry "
                                     "(an entry was edited, deleted, inserted or reordered)")
                return None
            if report.seal is not None:
                result.errors.append(f"{where}: entries after the seal")
                return None
            if kind == "event":
                report.events += 1
            elif kind == "seal":
                if (entry.get("entries") != index - 2 or entry.get("keyStatus") not in KEY_STATUSES
                        or not (entry.get("signature") is None or isinstance(entry["signature"], str))):
                    result.errors.append(f"{where}: not a valid seal")
                    return None
                report.seal = entry
                report.seal_seq = index - 1
            else:
                result.errors.append(f"{where}: unknown entry type")
                return None
        previous = line_hash(line)
    report.final_hash = previous or ""
    return report


def verify_files(files: List[Tuple[str, bytes]], public_key: str,
                 verifier: Optional[Callable[[bytes, str], bool]] = None) -> VerifyResult:
    """Verify an exported set of audit files against the pinned *public_key*."""
    result = VerifyResult()
    try:
        pinned = fingerprint(public_key)
    except AuditError as error:
        result.errors.append(str(error))
        return result
    if verifier is None:
        try:
            verifier = ssh_keygen_verifier(public_key)
        except AuditError as error:
            result.errors.append(str(error))
            return result
    if not files:
        result.errors.append("no audit files to verify")
        return result
    reports = []
    for name, data in files:
        report = _check_file(name, data, result)
        if report is None:
            return result
        reports.append(report)
    reports.sort(key=lambda item: item.number)
    numbers = [item.number for item in reports]
    if len(set(numbers)) != len(numbers):
        result.errors.append("two files claim the same file number")
        return result
    first = reports[0]
    if first.header_prev is None and first.number != 1:
        result.errors.append(f"{first.name}: has no predecessor but is not the first file")
        return result
    if first.header_prev is not None:
        result.notes.append(f"{first.number - 1} earlier file(s) are not present (deleted by retention, "
                            "or removed); their content cannot be checked")
    for before, after in zip(reports, reports[1:]):
        if after.number != before.number + 1:
            result.errors.append(f"file {before.number + 1} is missing between {before.name} and {after.name}")
            return result
        if after.header_prev != before.final_hash:
            result.errors.append(f"{after.name} does not follow {before.name} "
                                 "(a file is missing, truncated or was changed)")
            return result
    tail = 0
    signed_through = None
    for report in reports:
        if report.fingerprint is not None and report.fingerprint != pinned:
            result.errors.append(f"{report.name}: started with a different signing key ({report.fingerprint})")
            return result
        tail += report.events
        seal = report.seal
        if seal is None:
            continue
        if seal["signature"] is None:
            result.notes.append(f"{report.name}: sealed without a signature ({seal['keyStatus']})")
            continue
        message = seal_message(report.header_hash, report.seal_seq, seal["prev"])
        if not verifier(message, seal["signature"]):
            result.errors.append(f"{report.name}: the seal signature does not verify with the pinned public key")
            return result
        tail = 0
        signed_through = f"{report.name} entry {report.seal_seq}"
    result.files = len(reports)
    result.entries = sum(item.events for item in reports)
    result.tail = tail
    result.signed_through = signed_through
    last = reports[-1]
    if signed_through is not None and tail == 0 and last.seal is not None and last.seal["signature"] is not None:
        result.status = "sealed"
    else:
        result.status = "unsigned-tail"
    return result


def collect_paths(paths) -> List[Tuple[str, bytes]]:
    """Read audit files named directly or found in the given directories."""
    files: List[Tuple[str, bytes]] = []
    seen = set()
    for item in paths:
        path = Path(item)
        if path.is_dir():
            candidates = sorted(p for p in path.iterdir() if FILE_RE.fullmatch(p.name))
        else:
            candidates = [path]
        for candidate in candidates:
            if FILE_RE.fullmatch(candidate.name) is None:
                raise AuditError(f"{candidate.name} is not an audit file name")
            if candidate.name in seen:
                raise AuditError(f"{candidate.name} was given twice")
            seen.add(candidate.name)
            files.append((candidate.name, _read_regular(candidate, MAX_MAX_FILE_BYTES + MAX_LINE * 2)))
    return files


def read_public_key(path) -> str:
    return public_key_line(_read_regular(Path(path), 16384).decode("ascii", "replace"))


def verify_command(public_key_file, paths, out=sys.stdout) -> int:
    try:
        key = read_public_key(public_key_file)
        files = collect_paths(paths)
    except (OSError, AuditError) as error:
        message = str(error) if isinstance(error, AuditError) else type(error).__name__
        print("secret-proxy audit verify failed: " + message, file=sys.stderr)
        return 1
    result = verify_files(files, key)
    for line in result.lines():
        print(line, file=out)
    return result.exit_code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="secret-proxy audit log tools")
    commands = parser.add_subparsers(dest="command", required=True)
    exporter = commands.add_parser("export", help="(container) write the audit files to stdout")
    exporter.add_argument("--dir", default="/data/audit")
    checker = commands.add_parser("verify", help="check the chain and seals against a pinned key")
    checker.add_argument("--public-key", required=True)
    checker.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    if args.command == "export":
        try:
            export(args.dir, sys.stdout.buffer)
        except (OSError, AuditError) as error:
            print("audit export failed: " + (str(error) if isinstance(error, AuditError)
                                              else type(error).__name__), file=sys.stderr)
            return 1
        return 0
    return verify_command(args.public_key, args.paths)


if __name__ == "__main__":
    sys.exit(main())
