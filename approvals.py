"""Approval rules: hold a sensitive request until a person answers.

Pure module (no mitmproxy, no secrets, no network). The addon decides that a
request needs approval and describes it with :func:`placement_request`,
:func:`aws_request` or :func:`egress_request`. The runtime adapter in
``entry.py`` submits it to the :class:`Broker`, holds the request without
blocking the event loop, and answers the approver's control endpoint.

Safety rules enforced here:

* Nobody listening, a full queue, the prompt rate limit or the timeout all deny.
* One prompt is shown at a time; the next is delivered only after an answer.
* An answer that arrives sooner than ``min_answer_delay`` after the prompt was
  first delivered is treated as type-ahead and denies.
* Session decisions are held in memory only (cleared on restart) and cover the
  exact key: secret, host, method and matched rule; or AWS account, role,
  service, operation and rule; or the egress host. Each key also names the
  requesting client (once named clients exist), so one client's "allow for
  session" never covers another.

A description never contains a secret value, header, body or query string.

Python 3.9 compatible: nothing here needs the container's Python.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

DENY_ONCE = "deny-once"
ALLOW_ONCE = "allow-once"
ALLOW_SESSION = "allow-session"
DENY_SESSION = "deny-session"
CHOICES = (DENY_ONCE, ALLOW_ONCE, ALLOW_SESSION, DENY_SESSION)

# Refusal rules returned to the requester and written to the proxy log.
RULE_DENIED = "approval-denied"
RULE_TIMEOUT = "approval-timeout"
RULE_NO_LISTENER = "approval-no-listener"
RULE_RATE_LIMITED = "approval-rate-limited"
RULE_QUEUE_FULL = "approval-queue-full"
RULE_TOO_FAST = "approval-answered-too-fast"
RULE_MALFORMED = "approval-malformed-answer"
RULE_WITHDRAWN = "approval-withdrawn"
RULE_REQUIRED = "approval-required"

DEFAULT_TIMEOUT = 120.0
DEFAULT_PROMPTS_PER_MINUTE = 10
MIN_TIMEOUT, MAX_TIMEOUT = 10, 600
MAX_PROMPTS_PER_MINUTE = 60
MIN_ANSWER_DELAY = 1.0
LISTENER_GRACE = 10.0
MAX_PENDING = 16
MAX_SESSION_DECISIONS = 1024
MAX_FIELD = 200

# Description fields, in display order. Only these may appear in a request.
FIELDS = ("client", "kind", "method", "host", "path", "secret", "placement",
          "account", "role", "service", "operation", "rule")


def clean(value: object, limit: int = MAX_FIELD) -> Optional[str]:
    """Printable ASCII only, so a description cannot drive the approver's terminal."""
    if value is None:
        return None
    text = str(value)
    out = "".join(c if 32 <= ord(c) < 127 else "?" for c in text)
    if len(out) > limit:
        out = out[: limit - 3] + "..."
    return out


def _path_only(path: object) -> str:
    text = str(path or "/")
    for mark in ("?", "#"):
        text = text.split(mark, 1)[0]
    return text or "/"


@dataclass(frozen=True)
class ApprovalRequest:
    """What is asked about. ``key`` selects the session decision."""

    key: Tuple[str, ...]
    fields: Tuple[Tuple[str, str], ...]

    def describe(self) -> Dict[str, str]:
        return dict(self.fields)

    def summary(self) -> str:
        """One line for the proxy log: never values, bodies or query strings."""
        info = self.describe()
        parts = [info.get("kind", "?")]
        for name in ("client", "method", "host", "secret", "placement", "account", "role",
                     "service", "operation", "rule"):
            if name in info:
                parts.append(f"{name}={info[name]}")
        return " ".join(parts)


def _make(key: Tuple[str, ...], **values: object) -> ApprovalRequest:
    fields = []
    for name in FIELDS:
        value = values.get(name)
        if value is not None and value != "":
            fields.append((name, clean(value)))
    return ApprovalRequest(tuple(clean(part, 512) for part in key), tuple(fields))


def placement_request(*, secret: str, kind: str, name: Optional[str], host: str, method: str,
                      path: str, rule: str, client: Optional[str] = None) -> ApprovalRequest:
    host = (host or "").lower()
    method = (method or "").upper()
    if kind == "header" and name:
        name = name.lower()  # header names are case-insensitive
    placement = kind if not name else f"{kind} {name}"
    return _make(("placement", client or "-", secret, host, method, rule), kind="secret", client=client,
                 method=method, host=host, path=_path_only(path), secret=secret,
                 placement=placement, rule=rule)


def aws_request(*, account: Optional[str], role: Optional[str], service: str, operation: str,
                rule: str, host: str, method: str, path: str,
                client: Optional[str] = None) -> ApprovalRequest:
    return _make(("aws", client or "-", account or "-", role or "-", service, operation, rule), kind="aws",
                 client=client, method=(method or "").upper(), host=(host or "").lower(),
                 path=_path_only(path), account=account or "-", role=role or "-",
                 service=service, operation=operation, rule=rule)


def egress_request(*, host: str, port: int, rule: str, client: Optional[str] = None) -> ApprovalRequest:
    host = (host or "").lower()
    return _make(("egress", client or "-", host), kind="egress", client=client, host=f"{host}:{port}", rule=rule)


@dataclass(frozen=True)
class Outcome:
    allowed: bool
    rule: str              # "" when allowed
    choice: str = ""       # the approver's choice, if one was made


ALLOWED_ONCE = Outcome(True, "", ALLOW_ONCE)


@dataclass
class Pending:
    id: str
    request: ApprovalRequest
    created: float
    deadline: float
    delivered: Optional[float] = None
    outcome: Optional[Outcome] = None
    callbacks: List[Callable[[Outcome], None]] = field(default_factory=list)


class Broker:
    """In-memory approval queue and session decisions (thread-safe)."""

    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT,
                 prompts_per_minute: int = DEFAULT_PROMPTS_PER_MINUTE,
                 clock: Callable[[], float] = time.monotonic,
                 min_answer_delay: float = MIN_ANSWER_DELAY,
                 listener_grace: float = LISTENER_GRACE, max_pending: int = MAX_PENDING,
                 enabled: bool = True,
                 new_id: Callable[[], str] = lambda: secrets.token_hex(16)):
        self.timeout = float(timeout)
        self.prompts_per_minute = int(prompts_per_minute)
        self.clock = clock
        self.min_answer_delay = float(min_answer_delay)
        self.listener_grace = float(listener_grace)
        self.max_pending = int(max_pending)
        # Disabled when no approver capability exists: nobody can ever listen.
        self.enabled = enabled
        self._new_id = new_id
        self._lock = threading.Lock()
        self._queue: "deque[Pending]" = deque()
        self._shown: Optional[Pending] = None
        self._items: Dict[str, Pending] = {}
        self._session: "Dict[Tuple[str, ...], str]" = {}
        self._prompts: "deque[float]" = deque()
        self._pollers = 0
        self._last_activity: Optional[float] = None

    # -- session decisions (read from executor threads) ------------------
    def session_decision(self, key: Tuple[str, ...]) -> Optional[str]:
        """"allow", "deny" or None for an exact request key."""
        with self._lock:
            return self._session.get(tuple(key))

    # -- listener presence --------------------------------------------------
    def poller_started(self) -> None:
        with self._lock:
            self._pollers += 1
            self._last_activity = self.clock()

    def poller_finished(self) -> None:
        with self._lock:
            self._pollers = max(0, self._pollers - 1)
            self._last_activity = self.clock()

    def _listening_locked(self, now: float) -> bool:
        if not self.enabled:
            return False
        if self._pollers > 0 or self._shown is not None:
            return True
        return self._last_activity is not None and now - self._last_activity <= self.listener_grace

    # -- requests -------------------------------------------------------------
    def submit(self, request: ApprovalRequest):
        """Queue *request*; return an :class:`Outcome` now, or a :class:`Pending`."""
        callbacks = []
        with self._lock:
            now = self.clock()
            remembered = self._session.get(request.key)
            if remembered == "allow":
                return Outcome(True, "", ALLOW_SESSION)
            if remembered == "deny":
                return Outcome(False, RULE_DENIED, DENY_SESSION)
            self._expire_locked(now, callbacks)
            if not self._listening_locked(now):
                outcome = Outcome(False, RULE_NO_LISTENER)
            elif len(self._queue) + (self._shown is not None) >= self.max_pending:
                outcome = Outcome(False, RULE_QUEUE_FULL)
            else:
                while self._prompts and now - self._prompts[0] >= 60.0:
                    self._prompts.popleft()
                if len(self._prompts) >= self.prompts_per_minute:
                    outcome = Outcome(False, RULE_RATE_LIMITED)
                else:
                    self._prompts.append(now)
                    item = Pending(self._new_id(), request, now, now + self.timeout)
                    self._items[item.id] = item
                    self._queue.append(item)
                    outcome = None
        self._run(callbacks)
        return item if outcome is None else outcome

    def add_callback(self, item: Pending, callback: Callable[[Outcome], None]) -> None:
        with self._lock:
            if item.outcome is None:
                item.callbacks.append(callback)
                return
            outcome = item.outcome
        callback(outcome)

    def next_item(self) -> Optional[Pending]:
        """The prompt to show now: the one already shown, else the oldest pending."""
        callbacks = []
        with self._lock:
            now = self.clock()
            self._last_activity = now
            self._expire_locked(now, callbacks)
            if self._shown is None and self._queue:
                self._shown = self._queue.popleft()
                self._shown.delivered = now
            shown = self._shown
        self._run(callbacks)
        return shown

    def answer(self, item_id: str, choice: object) -> Optional[Outcome]:
        """Apply the approver's answer to the shown prompt.

        Returns None when *item_id* is not the prompt being shown (unknown,
        already answered or not yet delivered). A malformed or too-early answer
        denies that prompt.
        """
        callbacks = []
        with self._lock:
            now = self.clock()
            self._last_activity = now
            item = self._shown
            if item is None or item.id != item_id:
                return None
            if choice not in CHOICES:
                outcome = Outcome(False, RULE_MALFORMED)
            elif item.delivered is None or now - item.delivered < self.min_answer_delay:
                outcome = Outcome(False, RULE_TOO_FAST)
            elif choice in (ALLOW_ONCE, ALLOW_SESSION):
                outcome = Outcome(True, "", choice)
            else:
                outcome = Outcome(False, RULE_DENIED, choice)
            self._resolve_locked(item, outcome, callbacks)
            if outcome.choice in (ALLOW_SESSION, DENY_SESSION):
                if len(self._session) >= MAX_SESSION_DECISIONS:
                    # Bounded memory: forget the oldest decision.
                    self._session.pop(next(iter(self._session)))
                verdict = "allow" if outcome.choice == ALLOW_SESSION else "deny"
                self._session[item.request.key] = verdict
                # Waiting requests with the same key get the same answer.
                for other in list(self._queue):
                    if other.request.key == item.request.key:
                        self._queue.remove(other)
                        self._resolve_locked(other, Outcome(verdict == "allow",
                                                            "" if verdict == "allow" else RULE_DENIED,
                                                            outcome.choice), callbacks)
        self._run(callbacks)
        return outcome

    def withdraw(self, item_id: str) -> None:
        """The requester went away: drop its prompt (counts as a denial)."""
        callbacks = []
        with self._lock:
            item = self._items.get(item_id)
            if item is not None and item.outcome is None:
                if item in self._queue:
                    self._queue.remove(item)
                self._resolve_locked(item, Outcome(False, RULE_WITHDRAWN), callbacks)
        self._run(callbacks)

    def expire(self) -> List[Pending]:
        """Deny every prompt past its deadline; return them."""
        callbacks = []
        with self._lock:
            expired = self._expire_locked(self.clock(), callbacks)
        self._run(callbacks)
        return expired

    def deadline(self, item: Pending) -> float:
        return item.deadline

    def remaining(self, item: Pending) -> float:
        return max(0.0, item.deadline - self.clock())

    def pending_count(self) -> int:
        with self._lock:
            return len(self._queue) + (self._shown is not None)

    def clear(self) -> None:
        """Forget everything (tests; a restart does this implicitly)."""
        with self._lock:
            self._queue.clear()
            self._shown = None
            self._items.clear()
            self._session.clear()
            self._prompts.clear()
            self._pollers = 0
            self._last_activity = None

    # -- internals ------------------------------------------------------------
    def _expire_locked(self, now: float, callbacks) -> List[Pending]:
        expired = []
        for item in list(self._queue):
            if now >= item.deadline:
                self._queue.remove(item)
                expired.append(item)
        if self._shown is not None and now >= self._shown.deadline:
            expired.append(self._shown)
        for item in expired:
            self._resolve_locked(item, Outcome(False, RULE_TIMEOUT), callbacks)
        return expired

    def _resolve_locked(self, item: Pending, outcome: Outcome, callbacks) -> None:
        if item.outcome is not None:
            return
        item.outcome = outcome
        if self._shown is item:
            self._shown = None
        self._items.pop(item.id, None)
        callbacks.extend((callback, outcome) for callback in item.callbacks)
        item.callbacks = []

    @staticmethod
    def _run(callbacks) -> None:
        for callback, outcome in callbacks:
            callback(outcome)


def validate_settings(value: object) -> Dict[str, float]:
    """Validate the optional manifest ``approvals`` section (fixed messages)."""
    if value is None:
        return {"timeout": DEFAULT_TIMEOUT, "prompts_per_minute": DEFAULT_PROMPTS_PER_MINUTE}
    if not isinstance(value, dict):
        raise ValueError("approvals must be a JSON object")
    unknown = set(value) - {"timeoutSeconds", "maxPromptsPerMinute"}
    if unknown:
        raise ValueError("approvals has unknown fields: " + ", ".join(sorted(map(str, unknown))))
    timeout = value.get("timeoutSeconds", int(DEFAULT_TIMEOUT))
    if type(timeout) is not int or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"approvals.timeoutSeconds must be an integer from {MIN_TIMEOUT} to {MAX_TIMEOUT}")
    rate = value.get("maxPromptsPerMinute", DEFAULT_PROMPTS_PER_MINUTE)
    if type(rate) is not int or not 1 <= rate <= MAX_PROMPTS_PER_MINUTE:
        raise ValueError(f"approvals.maxPromptsPerMinute must be an integer from 1 to {MAX_PROMPTS_PER_MINUTE}")
    return {"timeout": float(timeout), "prompts_per_minute": rate}


def public_item(item: Pending, instance: str, now: float, min_delay: float = MIN_ANSWER_DELAY) -> dict:
    """The JSON the approver receives: the description and timing only."""
    delivered = item.delivered if item.delivered is not None else now
    return {
        "instance": instance,
        "id": item.id,
        "request": item.request.describe(),
        "expiresIn": max(0, int(item.deadline - now)),
        "answerAfter": max(0.0, round(min_delay - (now - delivered), 3)),
    }


# A process-wide broker. entry.load() reconfigures it; a restart clears it.
_default = Broker(enabled=False)


def default_broker() -> Broker:
    return _default


def configure(broker: Broker) -> Broker:
    global _default
    _default = broker
    return broker
