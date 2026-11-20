"""secret-proxy — mitmproxy addon for provider-neutral secret injection.

The client (container) sends a canonical placeholder of the form
`secretref:CANONICAL_NAME` wherever a secret would go, e.g.:

    Authorization: Bearer secretref:GOOGLE_ACCESS_TOKEN
    x-api-key: secretref:API_KEY

This addon detects canonical `secretref:` references in explicitly permitted
request headers, query parameters, HTTP Basic passwords, form fields, and URL
rewrites. It validates the complete manifest placement before resolving through
the selected provider and substituting the real value upstream. Arbitrary
JSON/text body substitution is deliberately unsupported.

Design (see secret-proxy/README.md):
  * The selected provider is accessed only by the secret-proxy process; provider
    credentials and resolved secrets stay outside the container.
  * Canonical-name lookup via the manifest avoids provider-specific aliases and
    host-based collisions.
  * The manifest's host and exact request-placement policy is enforced before
    any provider lookup or upstream mutation.
  * Requests WITHOUT a `secretref:` sentinel pass through
    untouched -> no provider lookup for npm/github/web/etc.
  * Responses are streamed so Bedrock eventstream / SSE flow through unbuffered.
"""

import base64
import json
import logging
import os
import re
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import flow as mitmflow, http

import approvals
import audit
import awsops
import clientgrants
import sigv4
from awscreds import AwsCredsProvider
from googlecreds import GoogleTokenProvider
from auth0creds import Auth0ManagementTokenProvider
from chatgptcreds import ChatGPTCredentials, ChatGPTAuthError
import copilotcreds
import ghclicreds
import githubdevice
from oauthcreds import FormTokenProvider, FormTokenSpec, OAuthTokenError
import gitsign
import sealedjwt
from secretstore import SecretManifest, SecretResolver

CANONICAL_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]+")
UUID_RE = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
# Canonical sentinel host for URL-rewrite injection: when the whole destination
# URL is the secret (e.g. a Slack webhook), the container requests
# https://secretref.invalid/<CANONICAL_NAME> and this addon resolves it through
# the selected provider before rewriting the upstream destination.
SENTINEL_HOST = "secretref.invalid"
CONFIG_DIR = Path(os.environ.get("SECRET_PROXY_CONFIG_DIR", Path.home() / ".config" / "secret-proxy"))
# The manifest is normally supplied as an explicit read-only runtime mount. Keep
# the config-dir path as a local/dev fallback for direct addon use and tests.
SECRETS_FILE = Path(os.environ.get("SECRET_PROXY_SECRETS_FILE", CONFIG_DIR / "secrets.json"))
AWS_OKTA_FILE = CONFIG_DIR / "aws-okta.json"
# Optional operator rules on top of the built-in AWS operation deny list.
AWS_POLICY_FILE = CONFIG_DIR / "aws-policy.json"

log = logging.getLogger("secret_proxy")
# Emit only the purpose-built sanitised messages to the attached proxy terminal.
# Raw mitmproxy flow rendering remains disabled, and no operational log persists
# on disk. Avoid root propagation so mitmproxy cannot duplicate these messages.
_stream = logging.StreamHandler(sys.stderr)
_stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_stream)
log.setLevel(logging.INFO)
log.propagate = False

_manifest = None
_resolver = None
_manifest_mtime = -1.0
_test_store_injected = False
_store_lock = threading.RLock()
_store_generation = None
_generation_local = threading.local()


class _ProviderState:
    """Per-generation cache for providers derived from a secret resolver."""

    def __init__(self, google=None, aws=None, aws_tried=False):
        self.lock = threading.RLock()
        self.google = google
        self.auth0 = None
        self.form_tokens = {}
        self.chatgpt = ChatGPTCredentials()
        # Proxy-owned GitHub logins, created on first use from the manifest.
        self.github = {}
        self.aws = aws
        self.aws_tried = aws_tried


@dataclass(frozen=True)
class _StoreGeneration:
    """Immutable manifest/resolver snapshot plus its derived-provider state."""

    manifest: object
    resolver: object
    providers: _ProviderState


@contextmanager
def _bind_generation(generation):
    """Bind one store generation to the current hook/thread."""
    previous = getattr(_generation_local, "value", _UNBOUND)
    _generation_local.value = generation
    try:
        yield
    finally:
        if previous is _UNBOUND:
            try:
                del _generation_local.value
            except AttributeError:
                pass
        else:
            _generation_local.value = previous


_UNBOUND = object()


def _bound_generation():
    """Return the hook-bound generation, or ``_UNBOUND`` outside a hook."""
    return getattr(_generation_local, "value", _UNBOUND)


def _generation_from_globals_locked():
    """Return a snapshot for direct/test callers that set legacy globals."""
    global _store_generation
    if _manifest is None or _resolver is None:
        return None
    if (
        _store_generation is None
        or _store_generation.manifest is not _manifest
        or _store_generation.resolver is not _resolver
    ):
        _store_generation = _StoreGeneration(
            _manifest,
            _resolver,
            _ProviderState(
                google=_google_provider_singleton,
                aws=_aws_provider,
                aws_tried=_aws_provider_tried,
            ),
        )
    return _store_generation


def _capture_generation():
    """Load, then atomically capture the currently published generation."""
    _load_secret_store()
    with _store_lock:
        return _generation_from_globals_locked()


def _load_secret_store() -> None:
    """Load and publish the manifest/resolver as one single-flight operation."""
    global _manifest, _resolver, _manifest_mtime, _google_provider_singleton
    global _aws_provider, _aws_provider_tried
    global _store_generation

    with _store_lock:
        if _test_store_injected:
            return
        if _manifest is not None and _resolver is not None and _manifest_mtime == -1:
            return

        try:
            mtime = SECRETS_FILE.stat().st_mtime
        except OSError as e:
            _manifest = None
            _resolver = None
            _store_generation = None
            _google_provider_singleton = None
            _aws_provider = None
            _aws_provider_tried = False
            _manifest_mtime = 0.0
            log.error(f"secret_proxy: failed to stat {SECRETS_FILE}: {e}")
            raise

        if mtime == _manifest_mtime and _manifest is not None and _resolver is not None:
            return

        try:
            manifest_env = dict(os.environ)
            manifest = SecretManifest.load(SECRETS_FILE, env=manifest_env)
            resolver = SecretResolver.from_environment(manifest, env=os.environ)
        except Exception as e:  # noqa: BLE001 - fail closed rather than retain stale policy
            _manifest = None
            _resolver = None
            _store_generation = None
            _google_provider_singleton = None
            _aws_provider = None
            _aws_provider_tried = False
            _manifest_mtime = mtime
            log.error(f"secret_proxy: failed to load secret store {SECRETS_FILE}: {e}")
            raise

        # Publish one complete generation only after both objects are ready.
        _manifest = manifest
        _resolver = resolver
        _store_generation = _StoreGeneration(manifest, resolver, _ProviderState())
        # Legacy mirrors remain for direct callers and existing tests.
        _google_provider_singleton = None
        _aws_provider = None
        _aws_provider_tried = False
        _manifest_mtime = mtime
        log.info(f"secret_proxy: loaded secret store from {SECRETS_FILE}")


class SecretReferenceError(Exception):
    """A secret reference is invalid or is not present in the manifest.

    This is deliberately distinct from :class:`PolicyViolation`: malformed or
    unknown references are injection failures (502), not destination-policy
    violations (403).
    """


class PolicyViolation(Exception):
    """A secret reference did not match an exact request placement.

    The request is blocked with 403 before forwarding. ``host`` records the
    attempted or resolved destination for sanitized diagnostics.
    """

    def __init__(self, name: str, host: str):
        self.name = name
        self.host = host
        super().__init__(
            f"secret reference '{name}' not allowed in placement for host '{host}'"
        )


# --- Approval rules (issue #3) ---------------------------------------------
# A placement with "approval": "prompt", an AWS "approve" rule or an egress
# allowlist miss with "allowlistMiss": "approve" holds the request. The checks
# below only *collect* what needs approval; an approval gate placed before any
# secret is resolved (and before any AWS credential is minted) then stops the
# hook with ApprovalRequired. entry.py holds the flow, asks the approver and
# re-runs the hook with the granted keys. Nothing is forwarded meanwhile.
APPROVAL_PENDING = "secret_proxy_approval_pending"
APPROVAL_GRANTS = "secret_proxy_approval_grants"
APPROVAL_HANDLER = "secret_proxy_approval_handler"


class ApprovalRequired(BaseException):
    """A gate found requests that need a person's answer.

    Deliberately a BaseException: the hooks below turn every ordinary Exception
    into a response, and this one must reach _run_hook untouched. It is raised
    only before any secret is resolved, so nothing needs undoing but metadata.
    """


class ApprovalRefused(Exception):
    """A session decision (or the approver) refused this request."""

    def __init__(self, rule: str):
        super().__init__(rule)
        self.rule = rule


def _requester(flow: http.HTTPFlow):
    """The authenticated client name (flow_client), for prompts and session keys.

    Part of every approval key, so one client's "allow for session" never
    covers another client.
    """
    try:
        return flow_client(flow)
    except Exception:  # noqa: BLE001 - a description must never fail a request
        return None


def _approval_needed(flow: http.HTTPFlow, request) -> None:
    """Record that *request* needs approval unless already decided."""
    if request.key in flow.metadata.get(APPROVAL_GRANTS, ()):
        return
    remembered = approvals.default_broker().session_decision(request.key)
    if remembered == "allow":
        log.info("secret_proxy: APPROVAL allow (session) %s", request.summary())
        audit_approval(request, True, choice="session")
        return
    if remembered == "deny":
        log.warning("secret_proxy: APPROVAL deny (session) %s", request.summary())
        audit_approval(request, False, approvals.RULE_DENIED, choice="session")
        raise ApprovalRefused(approvals.RULE_DENIED)
    pending = flow.metadata.setdefault(APPROVAL_PENDING, [])
    if all(item.key != request.key for item in pending):
        pending.append(request)


def _approval_gate(flow: http.HTTPFlow) -> None:
    """Stop before any secret is resolved while an approval is outstanding."""
    if flow.metadata.get(APPROVAL_PENDING):
        raise ApprovalRequired()


def approval_pending(flow: http.HTTPFlow) -> list:
    """Requests the last hook pass is waiting on (entry.py), and clear them."""
    return list(flow.metadata.pop(APPROVAL_PENDING, None) or ())


def approval_grant(flow: http.HTTPFlow, keys) -> None:
    """Allow these exact keys for the rest of this flow only (allow once)."""
    granted = set(flow.metadata.get(APPROVAL_GRANTS, ()))
    granted.update(keys)
    flow.metadata[APPROVAL_GRANTS] = frozenset(granted)


def _approval_refused_body(rule: str) -> bytes:
    return json.dumps({
        "error": "secret_proxy_approval_denied",
        "rule": rule,
        "detail": f"secret-proxy refused this request ({rule})",
    }).encode()


def approval_refusal(flow: http.HTTPFlow, request, rule: str) -> None:
    """The requester's error: only the rule, never the prompt details."""
    info = request.describe() if request is not None else {}
    if info.get("kind") == "aws" and _is_aws_sigv4(flow):
        op = awsops.AwsOperation(info.get("service", awsops.UNKNOWN),
                                 info.get("operation", awsops.UNKNOWN), _aws_protocol(flow))
        decision = awsops.Decision(awsops.DENY, f"approval refused ({rule})", rule)
        _aws_denied_response(flow, AwsOperationDenied(op, decision, None, None))
        return
    flow.response = http.Response.make(
        403, _approval_refused_body(rule),
        {"content-type": "application/json", "cache-control": "no-store"},
    )


def _canonical_ref(ref: str) -> str:
    """Return the manifest's canonical name for *ref*, failing closed.

    UUIDs are deliberately rejected before consulting the manifest: accepting
    an item id here would turn the resolver into an unbounded secret lookup.
    """
    if not isinstance(ref, str):
        raise SecretReferenceError("invalid secret reference")
    if UUID_RE.fullmatch(ref):
        raise SecretReferenceError("UUID secret references are not supported")
    if not CANONICAL_NAME_RE.fullmatch(ref):
        raise SecretReferenceError("invalid canonical secret reference")

    bound = _bound_generation()
    manifest = _manifest if bound is _UNBOUND else (bound.manifest if bound else None)
    if manifest is None:
        raise SecretReferenceError("secret manifest unavailable")

    try:
        canonical = manifest.canonical_name(ref)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise SecretReferenceError("unknown secret reference") from None

    if not isinstance(canonical, str) or not canonical:
        raise SecretReferenceError("invalid secret reference")
    return canonical


def _current_manifest():
    bound = _bound_generation()
    return _manifest if bound is _UNBOUND else (bound.manifest if bound else None)


# --- Scoped clients (clientgrants.py) ---------------------------------------
# The proxy-auth user name identifies the client. mitmproxy's proxyauth addon
# validates it against the htpasswd file and records (user, password) in
# flow.metadata["proxyauth"]: per request for plain HTTP, and from the CONNECT
# for every request in that tunnel (HTTP/1.1 and HTTP/2 alike). A client header
# is never trusted for identity.


def flow_client(flow: http.HTTPFlow) -> str | None:
    """The authenticated client name for *flow*, or None when unauthenticated.

    The default client authenticates as ``secret-proxy``. Shared helper for
    audit logging and approvals.
    """
    auth = getattr(flow, "metadata", {}).get("proxyauth")
    if not isinstance(auth, tuple) or len(auth) != 2:
        return None
    return clientgrants.client_for_username(auth[0])


def _client_grant(flow: http.HTTPFlow):
    """The flow's grant, or None when no ``clients`` section exists (unscoped)."""
    policy = getattr(_current_manifest(), "clients", None)
    if policy is None:
        return None
    return policy.get(flow_client(flow))


def _client_label(flow: http.HTTPFlow) -> str:
    return flow_client(flow) or "unauthenticated"


def _client_may_use(flow: http.HTTPFlow, canonical: str) -> bool:
    """Whether the flow's client may use *canonical* in at least one placement."""
    grant = _client_grant(flow)
    return grant is None or grant.may_use_secret(canonical)


def _client_may_login(flow: http.HTTPFlow, kind: str) -> bool:
    grant = _client_grant(flow)
    return grant is None or grant.may_login(kind)


def _client_denied(flow: http.HTTPFlow, what: str) -> None:
    flow.metadata[_AUDIT_REASON] = "client-not-granted"
    log.warning("secret_proxy: BLOCKED %s %s - client '%s' is not granted %s",
                flow.request.method, flow.request.host, _client_label(flow), what)


def _client_refusal(flow: http.HTTPFlow, what: str) -> bool:
    """403 for a proxy route or answer the client is not granted."""
    _client_denied(flow, what)
    flow.metadata.pop(_AUDIT_REASON, None)
    _audit(flow, "grant", "refused", reason="client-not-granted", secret=_known_secret(what))
    flow.response = http.Response.make(
        403, json.dumps({"error": "secret_proxy_client_not_granted"}).encode(),
        {"content-type": "application/json", "cache-control": "no-store"},
    )
    return True


# --- Audit log (audit.py, issue #6) ------------------------------------------
# Off by default: _audit_log stays None unless the manifest enables it, and then
# every helper below is a no-op. Callers pass only fixed codes, names and
# request metadata; audit.sanitize drops anything else and strips query
# strings. A decision that grants something (an injection, an AWS signature,
# a signature, a login) must be recorded first: when it cannot be, the request
# is refused (AuditUnavailable) rather than performed unrecorded.
_audit_log = None
AUDIT_DIR = os.environ.get("SECRET_PROXY_AUDIT_DIR", "")
_AUDIT_ORIGIN = "secret_proxy_audit_origin"
_AUDIT_REASON = "secret_proxy_audit_reason"
_AUDIT_USES = "secret_proxy_audit_uses"


class AuditUnavailable(Exception):
    """The audit log could not record a decision that grants access."""

    def __init__(self):
        super().__init__("the audit log could not record this decision")


def _audit_signing_key(name: str):
    def provide() -> str:
        generation = _capture_generation()
        with _bind_generation(generation):
            return _resolve(name)
    return provide


def configure_audit(manifest, directory=None, instance=None, signer=None) -> None:
    """Open the audit log when (and only when) the manifest enables it.

    Raises when it is enabled but cannot be opened: the proxy must not run
    with an audit log it was told to keep but cannot write.
    """
    global _audit_log
    close_audit()
    settings = getattr(manifest, "audit", None)
    if settings is None:
        return
    directory = directory or AUDIT_DIR
    if not directory:
        raise audit.AuditError("audit is enabled but no audit directory is configured")
    instance = instance or os.environ.get("SECRET_PROXY_INSTANCE_ID", "")
    if signer is None and settings.get("signingKey"):
        signer = audit.SshSigner(_audit_signing_key(settings["signingKey"]))
    writer = audit.AuditLog(directory, settings, instance, signer=signer)
    writer.open()
    _audit_log = writer
    if writer.key_status == "signed":
        log.info("secret_proxy: audit log enabled (signing key %s)", writer.key_fingerprint)
    else:
        log.warning("secret_proxy: audit log enabled WITHOUT a usable signing key (%s); seals are unsigned",
                    writer.key_status)


def close_audit(reason: str = "stop") -> None:
    """Seal and close the audit log on a clean stop (mitmproxy ``done``)."""
    global _audit_log
    writer, _audit_log = _audit_log, None
    if writer is not None:
        writer.close(reason)


def _audit_origin(flow: http.HTTPFlow):
    """Host, port and path as the client sent them (before any URL rewrite)."""
    origin = flow.metadata.get(_AUDIT_ORIGIN)
    if origin is not None:
        return origin
    return flow.request.host, flow.request.port, flow.request.path


def _audit(flow, event: str, decision: str, **fields) -> bool:
    """Record one decision; True when written (or when auditing is off)."""
    writer = _audit_log
    if writer is None:
        return True
    try:
        values = {}
        if flow is not None:
            host, port, path = _audit_origin(flow)
            values = {"client": _client_label(flow), "host": host, "port": port,
                      "method": flow.request.method, "path": path}
        values.update(fields)
        if not writer.record(event, decision, values):
            log.error("secret_proxy: audit log write failed; refusing what it cannot record")
            return False
        return True
    except Exception:  # noqa: BLE001 - never let auditing break a hook
        log.error("secret_proxy: audit log write failed; refusing what it cannot record")
        return False


def _audit_grant(flow, event: str, decision: str, **fields) -> None:
    """Record a decision that grants something, or refuse it."""
    if not _audit(flow, event, decision, **fields):
        raise AuditUnavailable()


def _audit_unavailable_response(flow: http.HTTPFlow) -> bool:
    flow.response = http.Response.make(
        503, json.dumps({"error": "secret_proxy_audit_unavailable"}).encode(),
        {"content-type": "application/json", "cache-control": "no-store"},
    )
    return True


def _known_secret(name) -> str | None:
    """*name* when it is a manifest secret, so client-typed text is never logged."""
    try:
        _current_manifest().secret(name)
    except Exception:  # noqa: BLE001
        return None
    return name


def _use_fields(entry: str) -> dict:
    """Audit fields for one ``<sink><-<CANONICAL>`` injection log item."""
    sink, _, canonical = entry.rpartition("<-")
    if sink == "Basic":
        kind, name = "basic-password", None
    elif sink.startswith("?"):
        kind, name = "query", sink[1:]
    elif sink.startswith("body:"):
        kind, name = "form", sink[5:]
    else:
        kind, name = "header", sink
    return {"secret": canonical, "placement": kind, "field": name}


def _audit_attempt(flow: http.HTTPFlow, entry: str) -> None:
    """Note a use about to be resolved; recorded once the request is decided."""
    if _audit_log is not None:
        flow.metadata.setdefault(_AUDIT_USES, []).append(entry)


def _audit_commit_uses(flow: http.HTTPFlow) -> None:
    """Record injections that are about to go upstream (raises AuditUnavailable)."""
    for entry in dict.fromkeys(flow.metadata.pop(_AUDIT_USES, None) or ()):
        _audit_grant(flow, "inject", "injected", **_use_fields(entry))


def _audit_injection_failure(flow: http.HTTPFlow, injected, error: Exception) -> None:
    if _audit_log is None:
        return
    attempted = flow.metadata.pop(_AUDIT_USES, None) or ()
    reason = flow.metadata.pop(_AUDIT_REASON, None)
    rule = None
    secret = None
    if isinstance(error, ApprovalRefused):
        reason, rule = "approval-refused", error.rule
    elif isinstance(error, PolicyViolation):
        reason = reason or "placement-not-allowed"
        secret = _known_secret(error.name)
    elif isinstance(error, AuditUnavailable):
        reason = "audit-unavailable"
    elif isinstance(error, SecretReferenceError):
        reason = "invalid-reference"
    elif isinstance(error, OAuthTokenError):
        reason = "token-unavailable"
    else:
        reason = "injection-failed"
    # A policy decision is "refused"; a lookup or internal error is "failed".
    decision = "refused" if reason in (
        "approval-refused", "placement-not-allowed", "client-not-granted", "invalid-reference") else "failed"
    uses = [] if secret else [_use_fields(entry) for entry in dict.fromkeys(list(injected) + list(attempted))]
    for fields in uses or [{"secret": secret}]:
        _audit(flow, "inject", decision, reason=reason, rule=rule, error=type(error).__name__, **fields)


def audit_connect_refusal(host, port, rule) -> None:
    """An upstream connection refused in server_connect (no flow there)."""
    _audit(None, "egress", "refused", host=host, port=port, rule=rule)


def audit_approval(request, allowed: bool, rule: str = "", choice: str = "") -> None:
    """An approval outcome; *request* is an approvals.ApprovalRequest."""
    if _audit_log is None:
        return
    info = request.describe() if request is not None else {}
    host, port = info.get("host"), None
    if info.get("kind") == "egress" and host and host.rpartition(":")[2].isdigit():
        host, _, number = host.rpartition(":")
        port = int(number)
    placement, field = info.get("placement"), None
    if placement and " " in placement:
        placement, field = placement.split(" ", 1)
    _audit(None, "approval", "allowed" if allowed else "denied",
           kind=info.get("kind"), client=info.get("client"), method=info.get("method"),
           host=host, port=port, path=info.get("path"), secret=info.get("secret"),
           placement=placement, field=field, account=info.get("account"),
           role=info.get("role"), service=info.get("service"), operation=info.get("operation"),
           rule=info.get("rule"), reason=rule or None, choice=choice or None)


def _placement_allowed(
    canonical: str,
    flow: http.HTTPFlow,
    *,
    kind: str,
    name: str | None = None,
    template: str | None = None,
    username: str | None = None,
    host: str | None = None,
    path: str | None = None,
    approval: bool = True,
) -> bool:
    """Return whether one complete use matches a manifest placement.

    When the matching placement asks for approval, the use is recorded as
    pending (or refused by a session decision); the caller's gate stops before
    the secret is resolved.
    """
    manifest = _current_manifest()
    if manifest is None:
        return False
    target = host if host is not None else (flow.request.host or "")
    context = dict(
        kind=kind,
        host=target,
        method=flow.request.method or "",
        path=path if path is not None else (flow.request.path or "/"),
        name=name,
        template=template,
        username=username,
    )
    try:
        grant = _client_grant(flow)
        if grant is not None and not grant.may_use_secret(canonical):
            _client_denied(flow, canonical)
            return False
        if not _pinned_host_allows(canonical, target):
            return False
        # The client grant is checked before approval: a request outside the
        # client's grants is refused, never offered for approval.
        granted = None if grant is None else grant.granted_placements(canonical)
        matcher = getattr(manifest, "match_placement", None)
        if matcher is None:  # a manifest without approval support (test fakes)
            if granted is None:
                return bool(manifest.placement_allowed(canonical, **context))
            if not granted.intersection(manifest.placement_indices(canonical, **context)):
                _client_denied(flow, canonical + " in this placement")
                return False
            return True
        match = matcher(canonical, allowed=granted, **context)
        if match is None and granted is not None and manifest.placement_allowed(canonical, **context):
            # The client may use only some placements: one of those must match.
            _client_denied(flow, canonical + " in this placement")
    except Exception:  # noqa: BLE001 - policy failures must fail closed
        return False
    if match is None:
        return False
    if approval and match.approval is not None:
        _approval_needed(flow, approvals.placement_request(
            secret=canonical, kind=kind, name=name, host=target,
            method=context["method"], path=context["path"],
            rule=match.rule(canonical), client=_requester(flow),
        ))
    return True


def _sentinel_resolve(ref: str, flow: http.HTTPFlow) -> tuple[str, str, int, str]:
    """Resolve an explicitly URL-rewrite-only reference and validate its target."""
    canonical = _canonical_ref(ref)
    manifest = _current_manifest()

    # Kind and caller-controlled method are checked before resolution so
    # internal/header-only entries and wrong-method requests never reach a
    # provider backend. Resolved host/path are checked immediately afterward.
    try:
        info = manifest.secret(canonical) if manifest is not None else None
        method = (flow.request.method or "").upper()
        grant = _client_grant(flow)
        granted = None
        if grant is not None:
            if not grant.may_use_secret(canonical):
                _client_denied(flow, canonical)
                raise PolicyViolation(canonical, SENTINEL_HOST)
            granted = grant.granted_placements(canonical)
        candidates = [
            (index, placement)
            for index, placement in enumerate(info.placements if info else ())
            if placement.kind == "url-rewrite"
            and (not placement.methods or method in placement.methods)
            and (granted is None or index in granted)
        ]
        eligible = bool(candidates)
        needs_approval = next(
            (index for index, placement in candidates
             if getattr(placement, "approval", None) is not None), None)
    except PolicyViolation:
        raise
    except Exception:  # noqa: BLE001 - policy failures must fail closed
        eligible = False
    if not eligible:
        raise PolicyViolation(canonical, SENTINEL_HOST)
    if needs_approval is not None:
        # The destination is itself the secret, so the approval is asked
        # before it is resolved: the prompt names the sentinel, not the URL.
        _approval_needed(flow, approvals.placement_request(
            secret=canonical, kind="url-rewrite", name=None, host=SENTINEL_HOST,
            method=method, path=flow.request.path, client=_requester(flow),
            rule=f"{canonical}.placements[{needs_approval}]",
        ))
    _approval_gate(flow)

    url = _resolve(canonical)
    try:
        target = urlsplit(url)
        if target.scheme.lower() != "https":
            raise PolicyViolation(canonical, "")
        resolved_host = target.hostname or ""
        port = target.port or 443
    except (TypeError, ValueError):
        raise PolicyViolation(canonical, "") from None

    target_path = target.path or "/"
    if not resolved_host or not _placement_allowed(
        canonical,
        flow,
        kind="url-rewrite",
        host=resolved_host,
        path=target_path,
        approval=False,  # already approved above, before resolution
    ):
        raise PolicyViolation(canonical, resolved_host)

    path_with_query = target_path
    if target.query:
        path_with_query += "?" + target.query
    return (target.scheme, resolved_host, port, path_with_query)


GOOGLE_ACCESS_TOKEN = "GOOGLE_ACCESS_TOKEN"
_google_provider_singleton = None


def _mirror_provider(generation, kind: str, provider) -> None:
    global _google_provider_singleton, _aws_provider, _aws_provider_tried
    with _store_lock:
        if generation.manifest is not _manifest or generation.resolver is not _resolver:
            return
        if kind == "google":
            _google_provider_singleton = provider
        else:
            _aws_provider = provider
            _aws_provider_tried = True


def _google_provider() -> GoogleTokenProvider:
    global _google_provider_singleton
    bound = _bound_generation()
    if bound is _UNBOUND:
        if _google_provider_singleton is not None:
            return _google_provider_singleton
        resolver = _resolver
        if resolver is None:
            raise RuntimeError("secret resolver unavailable")
        provider = GoogleTokenProvider(resolver.get)
        _google_provider_singleton = provider
        return provider

    if bound is None:
        raise RuntimeError("secret resolver unavailable")
    state = bound.providers
    with state.lock:
        if state.google is None:
            state.google = GoogleTokenProvider(bound.resolver.get)
            _mirror_provider(bound, "google", state.google)
        return state.google


AUTH0_MANAGEMENT_TOKEN = "AUTH0_MANAGEMENT_TOKEN"


def _auth0_tenant(manifest) -> str:
    """The tenant is the one exact host the derived token may be sent to.

    Taking it from the manifest keeps a single source of truth: the host the
    client secret is exchanged at is always the host the minted token is pinned
    to, and a wildcard or second host fails closed.
    """
    info = manifest.secret(AUTH0_MANAGEMENT_TOKEN)
    hosts = {host for placement in info.placements for host in placement.hosts}
    if len(hosts) != 1 or "*" in next(iter(hosts)):
        raise RuntimeError("the Auth0 management token must be pinned to exactly one tenant host")
    return next(iter(hosts))


def _auth0_provider() -> Auth0ManagementTokenProvider:
    bound = _bound_generation()
    if bound is _UNBOUND:
        with _store_lock:
            bound = _generation_from_globals_locked()
    if bound is None:
        raise RuntimeError("secret resolver unavailable")
    state = bound.providers
    with state.lock:
        if state.auth0 is None:
            state.auth0 = Auth0ManagementTokenProvider(
                bound.resolver.get, domain=_auth0_tenant(bound.manifest),
            )
        return state.auth0


# --- Access tokens minted inside the proxy ---------------------------------
# Each derived entry below names a short-lived access token that the proxy mints
# from internalOnly credentials. The container only ever sends a reference to
# the access token; the token exchange itself, and its response, never pass
# through the container. See oauthcreds.py.
WIZ_ACCESS_TOKEN = "WIZ_ACCESS_TOKEN"
CHECKMARX_API_KEY = "CHECKMARX_API_KEY"
CHECKMARX_ACCESS_TOKEN = "CHECKMARX_ACCESS_TOKEN"
CHECKMARX_CLIENT_ID = "ast-app"

_STATIC_FORM_TOKEN_SPECS = {
    WIZ_ACCESS_TOKEN: FormTokenSpec(
        token_url="https://auth.app.wiz.io/oauth/token",
        fields=(("grant_type", "client_credentials"), ("audience", "wiz-api")),
        secret_fields=(("client_id", "WIZ_CLIENT_ID"), ("client_secret", "WIZ_CLIENT_SECRET")),
        default_ttl=86400,
        skew=300,
        label="Wiz",
    ),
}
FORM_TOKEN_NAMES = frozenset(_STATIC_FORM_TOKEN_SPECS) | {CHECKMARX_ACCESS_TOKEN}


def _single_exact_host(manifest, canonical: str) -> str:
    """Return the one exact host a derived token is pinned to, or fail closed."""
    info = manifest.secret(canonical)
    hosts = {host.lower() for placement in info.placements for host in placement.hosts}
    if len(hosts) != 1 or "*" in next(iter(hosts)):
        raise RuntimeError(f"{canonical} must be pinned to exactly one exact host")
    return next(iter(hosts))


def _checkmarx_token_path() -> str:
    realm = getattr(_current_manifest(), "checkmarx_realm", None)
    if not realm:
        raise RuntimeError("Checkmarx realm is not configured")
    return f"/auth/realms/{realm}/protocol/openid-connect/token"


def _form_token_spec(name: str, manifest) -> FormTokenSpec:
    if name == CHECKMARX_ACCESS_TOKEN:
        # The API key is exchanged at the same tenant host the access token is
        # pinned to, so the manifest stays the single source of truth for it.
        host = _single_exact_host(manifest, CHECKMARX_ACCESS_TOKEN)
        return FormTokenSpec(
            token_url=f"https://{host}{_checkmarx_token_path()}",
            fields=(("grant_type", "refresh_token"), ("client_id", CHECKMARX_CLIENT_ID)),
            secret_fields=(("refresh_token", CHECKMARX_API_KEY),),
            default_ttl=300,
            skew=60,
            label="Checkmarx",
        )
    return _STATIC_FORM_TOKEN_SPECS[name]


def _form_token_provider(name: str) -> FormTokenProvider:
    bound = _bound_generation()
    if bound is _UNBOUND:
        with _store_lock:
            bound = _generation_from_globals_locked()
    if bound is None:
        raise RuntimeError("secret resolver unavailable")
    state = bound.providers
    with state.lock:
        provider = state.form_tokens.get(name)
        if provider is None:
            provider = FormTokenProvider(bound.resolver.get, _form_token_spec(name, bound.manifest))
            state.form_tokens[name] = provider
        return provider


# --- Proxy-owned GitHub logins (copilotcreds.py, githubdevice.py) ----------
# Each entry: manifest login kind, runtimeOnly canonical, sentinel path prefix,
# client-facing error, and a factory taking the login's manifest settings.
@dataclass(frozen=True)
class _GitHubLogin:
    kind: str
    canonical: str
    prefix: str
    error: bytes
    client_id: str
    factory: object
    cli_name: str  # the daily CLI's provider name, also the clients login grant


_GITHUB_LOGINS = (
    _GitHubLogin("copilot", copilotcreds.CANONICAL, "/github-copilot",
                 b'{"error":"use_github_copilot_login"}', copilotcreds.CLIENT_ID,
                 lambda settings: copilotcreds.CopilotCredentials(domain=settings["domain"]),
                 "github-copilot"),
    _GitHubLogin("cli", ghclicreds.CANONICAL, "/github",
                 b'{"error":"use_gh_login"}', ghclicreds.CLIENT_ID,
                 lambda settings: ghclicreds.GhCliCredentials(domain=settings["domain"], scopes=settings["scopes"]),
                 "github"),
)


def _bound_or_global():
    bound = _bound_generation()
    if bound is _UNBOUND:
        with _store_lock:
            bound = _generation_from_globals_locked()
    return bound


def _github_settings(login: _GitHubLogin, manifest=None) -> dict | None:
    manifest = manifest if manifest is not None else _current_manifest()
    try:
        return manifest.github_login(login.kind)
    except AttributeError:
        return None


def _github_provider(login: _GitHubLogin):
    """The login's provider for the bound generation, or None when it is off."""
    bound = _bound_or_global()
    if bound is None:
        return None
    settings = _github_settings(login, bound.manifest)
    if settings is None:
        return None
    state = bound.providers
    with state.lock:
        provider = state.github.get(login.kind)
        if provider is None:
            provider = state.github[login.kind] = login.factory(settings)
        return provider


def _github_login_for(canonical: str):
    for login in _GITHUB_LOGINS:
        if login.canonical == canonical and _github_settings(login) is not None:
            return login
    return None


def _pinned_host_allows(canonical: str, host: str) -> bool:
    """A Copilot token may go only to the API host named by its own proxy-ep."""
    login = _github_login_for(canonical)
    if login is None or login.kind != "copilot":
        return True
    provider = _github_provider(login)
    pinned = provider.api_host() if provider is not None else None
    # Logged out: there is no host to pin to, and resolution fails closed.
    return pinned is None or (host or "").lower() == pinned


def _resolve(ref: str) -> str:
    login = _github_login_for(ref)
    if login is not None:
        provider = _github_provider(login)
        if provider is None:
            raise RuntimeError("secret resolver unavailable")
        return provider.get_token()
    if ref == "CHATGPT_ACCESS_TOKEN":
        bound = _bound_generation()
        if bound is _UNBOUND:
            with _store_lock:
                bound = _generation_from_globals_locked()
        if bound is None:
            raise RuntimeError("secret resolver unavailable")
        return bound.providers.chatgpt.get_token()
    if ref in FORM_TOKEN_NAMES:
        return _form_token_provider(ref).get_token()
    if ref == GOOGLE_ACCESS_TOKEN:
        return _google_provider().get_token()
    if ref == AUTH0_MANAGEMENT_TOKEN:
        return _auth0_provider().get_token()

    bound = _bound_generation()
    resolver = _resolver if bound is _UNBOUND else (bound.resolver if bound else None)
    if resolver is None:
        raise RuntimeError("secret resolver unavailable")
    return resolver.get(ref)


_SECRET_REF_VALUE_RE = re.compile(r"secretref:(?P<canonical>[A-Za-z0-9._-]+)")
_MALFORMED_SECRET_REF_RE = re.compile(r"secretref:(?![A-Za-z0-9._-])")


def _reference_shape(value: str) -> tuple[str, str, "_ReferenceSpan"]:
    """Return canonical name, placement template, and sole reference match."""
    matches = list(_SECRET_REF_VALUE_RE.finditer(value))
    if _MALFORMED_SECRET_REF_RE.search(value) or ("secretref:" in value and not matches):
        raise SecretReferenceError("invalid secret reference")
    if len(matches) != 1:
        if matches:
            canonical = _canonical_ref(matches[0].group("canonical"))
            raise PolicyViolation(canonical, "")
        raise SecretReferenceError("invalid secret reference")
    match = matches[0]
    canonical = _canonical_ref(match.group("canonical"))
    start, end = match.start(), match.end()
    prefix = _reference_prefix(canonical)
    if prefix and value[:start].endswith(prefix):
        start -= len(prefix)
    template = value[:start] + "{secret}" + value[end:]
    return canonical, template, _ReferenceSpan(start, end)


class _ReferenceSpan:
    """The characters a resolved secret replaces: the reference plus any
    manifest-declared prefix written directly before it."""

    __slots__ = ("_start", "_end")

    def __init__(self, start: int, end: int):
        self._start, self._end = start, end

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end


def _reference_prefix(canonical: str) -> str | None:
    """Return the manifest-declared literal prefix for *canonical*, if any.

    Some clients check a key's shape before sending it; the Stripe CLI, for
    example, accepts only values that start "sk_test_" or similar. A secret
    whose manifest entry declares that prefix can be referenced as
    "<prefix>" + reference, and the prefix is replaced along with it so the
    real key is not sent with its prefix doubled.
    """
    manifest = _current_manifest()
    try:
        prefix = manifest.secret(canonical).reference_prefix
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    return prefix if isinstance(prefix, str) and prefix else None


def _validate_use(
    value: str,
    flow: http.HTTPFlow,
    *,
    kind: str,
    name: str | None = None,
    username: str | None = None,
) -> tuple[str, str, _ReferenceSpan]:
    canonical, template, match = _reference_shape(value)
    if not _placement_allowed(
        canonical,
        flow,
        kind=kind,
        name=name,
        template=template,
        username=username,
    ):
        raise PolicyViolation(canonical, flow.request.host)
    return canonical, template, match


def _apply_use(
    value: str,
    flow: http.HTTPFlow,
    *,
    kind: str,
    name: str | None,
    username: str | None,
    log_sink: str,
    injected: list[str],
) -> str:
    canonical, _template, match = _validate_use(
        value, flow, kind=kind, name=name, username=username,
    )
    _approval_gate(flow)  # never resolve a secret that still needs approval
    injected.append(f"{log_sink}<-{canonical}")
    _audit_attempt(flow, injected[-1])
    resolved_value = _resolve(canonical)
    return value[:match.start()] + resolved_value + value[match.end():]


def _decode_basic_reference(flow: http.HTTPFlow) -> tuple[str, str] | None:
    auth = flow.request.headers.get("Authorization", "")
    if auth[:6].lower() != "basic ":
        return None
    try:
        decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
    except Exception:
        if "secretref" in auth:
            raise SecretReferenceError("invalid Basic secret reference") from None
        return None
    if "secretref" not in decoded:
        return None
    if ":" not in decoded:
        raise SecretReferenceError("invalid Basic secret reference")
    delimiter_index = decoded.find(":")
    marker_index = decoded.find("secretref:")
    if 0 <= marker_index <= delimiter_index:
        canonical, _template, _match = _reference_shape(decoded)
        raise PolicyViolation(canonical, flow.request.host)
    username, password = decoded.split(":", 1)
    if "secretref" in username:
        canonical, _template, _match = _reference_shape(username)
        raise PolicyViolation(canonical, flow.request.host)
    canonical, template, _match = _reference_shape(password)
    if template != "{secret}" or not _placement_allowed(
        canonical,
        flow,
        kind="basic-password",
        username=username,
    ):
        raise PolicyViolation(canonical, flow.request.host)
    return username, password


def _preflight_request(flow: http.HTTPFlow, *, include_body: bool) -> None:
    """Validate every reference in a request before any provider lookup."""
    for header_name in list(flow.request.headers.keys()):
        value = flow.request.headers[header_name]
        if "secretref:" in value:
            _validate_use(value, flow, kind="header", name=header_name)
    for query_name in list(flow.request.query.keys()):
        value = flow.request.query[query_name]
        if "secretref:" in value:
            _validate_use(value, flow, kind="query", name=query_name)
    _decode_basic_reference(flow)

    if not include_body:
        return
    body = flow.request.content
    if not body or b"secretref" not in body:
        return
    ctype = flow.request.headers.get("Content-Type", "").lower()
    if "application/x-www-form-urlencoded" not in ctype:
        # A non-form body is opaque and is NOT an injection sink (arbitrary
        # JSON/text body substitution is unsupported). The dev container holds
        # only secretref: placeholders (never real secret values) and has no
        # direct egress -- real values are injected only for the exact declared
        # host+sink -- so a literal "secretref:" appearing as ordinary body text
        # (e.g. an LLM prompt/context/memory that discusses secretref: names) is
        # not a secret leak. Pass it through unchanged rather than blocking
        # legitimate opaque traffic such as Bedrock converse bodies.
        return
    if len(body) > 65536:
        raise SecretReferenceError(
            "buffered request body with secret reference exceeds 65536 bytes"
        )
    found = False
    for field_name, value in flow.request.urlencoded_form.items(multi=True):
        if "secretref" in value:
            found = True
            if "secretref:" not in value:
                raise SecretReferenceError("invalid form secret reference")
            _validate_use(value, flow, kind="form", name=field_name)
    if not found:
        raise SecretReferenceError("invalid form secret reference")
    return


def _plan_request_metadata(flow: http.HTTPFlow) -> dict:
    """Resolve previously preflighted metadata without mutating the request."""
    planned: list[str] = []
    header_updates: list[tuple[str, str]] = []
    query_updates: list[tuple[str, str]] = []

    for header_name in list(flow.request.headers.keys()):
        value = flow.request.headers[header_name]
        if "secretref:" in value:
            header_updates.append((header_name, _apply_use(
                value,
                flow,
                kind="header",
                name=header_name,
                username=None,
                log_sink=header_name,
                injected=planned,
            )))

    for query_name in list(flow.request.query.keys()):
        value = flow.request.query[query_name]
        if "secretref:" in value:
            query_updates.append((query_name, _apply_use(
                value,
                flow,
                kind="query",
                name=query_name,
                username=None,
                log_sink=f"?{query_name}",
                injected=planned,
            )))

    basic = _decode_basic_reference(flow)
    if basic is not None:
        username, password = basic
        canonical, _template, match = _validate_use(
            password, flow, kind="basic-password", username=username,
        )
        _approval_gate(flow)
        planned.append(f"Basic<-{canonical}")
        _audit_attempt(flow, planned[-1])
        resolved_password = (
            password[:match.start()] + _resolve(canonical) + password[match.end():]
        )
        encoded = base64.b64encode(
            f"{username}:{resolved_password}".encode("utf-8")
        ).decode("ascii")
        header_updates.append(("Authorization", "Basic " + encoded))

    return {"headers": header_updates, "query": query_updates, "logs": planned}

def _commit_request_metadata(flow: http.HTTPFlow, plan: dict) -> None:
    """Apply a previously validated metadata plan to *flow*."""
    for name, value in plan["headers"]:
        flow.request.headers[name] = value
    for key, value in plan["query"]:
        flow.request.query[key] = value


def _plan_request_body(flow: http.HTTPFlow, metadata_plan: dict | None = None) -> dict | None:
    """Plan explicitly permitted form-field rewrites without live mutation."""
    body = flow.request.content
    if not body or b"secretref" not in body:
        return None
    if "application/x-www-form-urlencoded" not in flow.request.headers.get(
        "Content-Type", ""
    ).lower():
        # Opaque (non-form) body: not an injection sink, so pass it through
        # unchanged (see _preflight_request). Only form fields are injected.
        return None
    if len(body) > 65536:
        raise SecretReferenceError(
            "buffered request body with secret reference exceeds 65536 bytes"
        )

    request_copy = flow.request.copy()
    if metadata_plan is not None:
        for header_name, value in metadata_plan["headers"]:
            request_copy.headers[header_name] = value
        for query_name, value in metadata_plan["query"]:
            request_copy.query[query_name] = value

    planned: list[str] = []
    new_items = []
    for field_name, value in request_copy.urlencoded_form.items(multi=True):
        if "secretref:" in value:
            value = _apply_use(
                value,
                flow,
                kind="form",
                name=field_name,
                username=None,
                log_sink=f"body:{field_name}",
                injected=planned,
            )
        new_items.append((field_name, value))
    request_copy.urlencoded_form = new_items

    body_headers = [
        (header_name, value)
        for header_name, value in request_copy.headers.items(multi=True)
        if header_name.lower() in {
            "content-type", "content-length", "transfer-encoding", "content-encoding",
        }
    ]
    if any(header_name.lower() == "transfer-encoding" for header_name, _ in body_headers):
        body_headers = [
            (header_name, value)
            for header_name, value in body_headers
            if header_name.lower() != "content-length"
        ]
    return {
        "content": request_copy.raw_content,
        "headers": body_headers,
        "logs": planned,
    }

def _commit_request_body(flow: http.HTTPFlow, plan: dict | None) -> None:
    if plan is None:
        return

    # The body and all body/framing headers come from the same mutated copy.
    # Remove every original occurrence first so absent headers and duplicate
    # headers are represented exactly as they were in the plan.
    body_header_names = {
        "content-type",
        "content-length",
        "transfer-encoding",
        "content-encoding",
    }
    for name in list(flow.request.headers.keys()):
        if name.lower() in body_header_names:
            del flow.request.headers[name]
    flow.request.raw_content = plan["content"]
    for name, value in plan["headers"]:
        flow.request.headers.add(name, value)


def _metadata_has_secret_reference(flow: http.HTTPFlow) -> bool:
    """Return whether request metadata contains a secret reference marker.

    Metadata is safe to inspect even when mitmproxy has already switched the
    request body to streaming mode. Opaque streamed bodies are intentionally
    not examined here.
    """
    for value in flow.request.headers.values():
        if "secretref:" in value:
            return True

    for value in flow.request.query.values():
        if "secretref:" in value:
            return True

    auth = flow.request.headers.get("Authorization", "")
    if auth[:6].lower() != "basic ":
        return False
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8")
    except Exception:
        return False
    return "secretref:" in decoded


def _metadata_snapshot(flow: http.HTTPFlow) -> dict:
    """Capture request state needed to undo a prior metadata commit."""
    return {
        "path": flow.request.path,
        "headers": list(flow.request.headers.items(multi=True)),
        "content": flow.request.raw_content,
    }


def _restore_metadata_snapshot(flow: http.HTTPFlow) -> None:
    snapshot = flow.metadata.pop("secret_proxy_metadata_original", None)
    if snapshot is None:
        return
    flow.request.path = snapshot["path"]
    flow.request.headers.clear()
    for name, value in snapshot["headers"]:
        flow.request.headers.add(name, value)
    flow.request.raw_content = snapshot["content"]


def _inject_request_metadata(flow: http.HTTPFlow, injected: list[str]) -> dict:
    """Preflight, plan, and atomically substitute metadata references."""
    _preflight_request(flow, include_body=False)
    _approval_gate(flow)
    plan = _plan_request_metadata(flow)
    if plan["headers"] or plan["query"]:
        flow.metadata.setdefault("secret_proxy_metadata_original", _metadata_snapshot(flow))
        try:
            _commit_request_metadata(flow, plan)
        except Exception:
            # A commit implementation may have partially mutated the request
            # before failing. Restore the pre-commit snapshot so the caller can
            # safely turn the failure into a 502 without forwarding a secret.
            _restore_metadata_snapshot(flow)
            raise
    injected.extend(plan["logs"])
    return plan


def _set_injection_error(flow: http.HTTPFlow, injected: list[str], error: Exception) -> None:
    """Set the safe response used when metadata injection fails."""
    host = flow.request.host
    _audit_injection_failure(flow, injected, error)
    if isinstance(error, AuditUnavailable):
        _audit_unavailable_response(flow)
        return
    if isinstance(error, ApprovalRefused):
        log.warning("secret_proxy: BLOCKED %s %s - %s", flow.request.method, host, error.rule)
        flow.response = http.Response.make(
            403, _approval_refused_body(error.rule),
            {"content-type": "application/json", "cache-control": "no-store"},
        )
        return
    if isinstance(error, PolicyViolation):
        log.warning(
            f"secret_proxy: BLOCKED {flow.request.method} {host} - name '{error.name}' "
            f"not allowed in this request placement (possible exfil attempt)"
        )
        flow.response = http.Response.make(
            403,
            json.dumps({
                "error": "secret_proxy_placement_not_allowed",
                "name": error.name,
                "host": host,
            }).encode(),
            {"content-type": "application/json"},
        )
        return

    log.warning(
        "secret_proxy: inject failed for %s %s (exception=%s, attempted_count=%s)",
        flow.request.method,
        host,
        type(error).__name__,
        len(injected),
    )
    detail = (
        str(error) if isinstance(error, (SecretReferenceError, OAuthTokenError))
        else "secret injection failed"
    )
    flow.response = http.Response.make(
        502,
        json.dumps({"error": "secret_proxy_injection_failed", "detail": detail}).encode(),
        {"content-type": "application/json"},
    )


def _unseal_request(flow: http.HTTPFlow, *, include_body: bool) -> None:
    """Turn sealed JWT references back into plain references (sealedjwt.py).

    Runs before any policy check, so a sealed token is validated exactly like
    the plain reference it encodes and can never bypass a placement rule.
    """
    headers = flow.request.headers
    for header_name in list(headers.keys()):
        values = headers.get_all(header_name)
        unsealed = [copilotcreds.unseal(sealedjwt.unseal(value)) for value in values]
        if unsealed != values:
            headers.set_all(header_name, unsealed)
    if not include_body:
        return
    body = flow.request.content
    marker = ("." + sealedjwt.SEALED_SEGMENT_PREFIX).encode("ascii")
    if not body or marker not in body:
        return
    if "application/x-www-form-urlencoded" not in flow.request.headers.get(
        "Content-Type", ""
    ).lower():
        return
    if len(body) > 65536:
        raise SecretReferenceError(
            "buffered request body with secret reference exceeds 65536 bytes"
        )
    items = list(flow.request.urlencoded_form.items(multi=True))
    unsealed_items = [(name, sealedjwt.unseal(value)) for name, value in items]
    if unsealed_items != items:
        flow.request.urlencoded_form = unsealed_items


def _checkmarx_exchange_response(flow: http.HTTPFlow) -> bool:
    """Answer the cx CLI's own API-key exchange inside the proxy.

    cx reads claims from its API key and its access token, so it cannot work
    with a bare reference, and forwarding its exchange would hand Keycloak's
    reply (a real access token and a reusable refresh token) to the container.
    The proxy therefore answers the exchange itself: it mints the access token
    from the internalOnly API key and returns *sealed* copies of both tokens,
    which keep their claims but carry a reference where the signature was.
    Returns True when it set the response.
    """
    if (flow.request.method or "").upper() != "POST":
        return False
    manifest = _current_manifest()
    if not getattr(manifest, "checkmarx_realm", None):
        return False
    if (flow.request.path or "").split("?", 1)[0] != _checkmarx_token_path():
        return False
    try:
        manifest.canonical_name(CHECKMARX_ACCESS_TOKEN)
        host = _single_exact_host(manifest, CHECKMARX_ACCESS_TOKEN)
    except Exception:  # noqa: BLE001 - not configured for this profile
        return False
    if (flow.request.host or "").lower() != host:
        return False
    if "application/x-www-form-urlencoded" not in flow.request.headers.get(
        "Content-Type", ""
    ).lower():
        return False
    items = list(flow.request.urlencoded_form.items(multi=True))
    refresh = [value for name, value in items if name == "refresh_token"]
    grant = [value for name, value in items if name == "grant_type"]
    others = [value for name, value in items if name not in ("refresh_token", "grant_type")]
    if refresh != [sealedjwt.MARKER + CHECKMARX_API_KEY] or grant != ["refresh_token"]:
        return False
    if any(sealedjwt.MARKER in value for value in others):
        return False
    # The answer resolves the API key and mints an access token: both need the grant.
    if not _client_may_use(flow, CHECKMARX_ACCESS_TOKEN):
        return _client_refusal(flow, CHECKMARX_ACCESS_TOKEN)

    provider = _form_token_provider(CHECKMARX_ACCESS_TOKEN)
    access_token = provider.get_token()
    body = {
        "access_token": sealedjwt.seal(access_token, CHECKMARX_ACCESS_TOKEN),
        "expires_in": provider.remaining_seconds(),
        "refresh_expires_in": 0,
        "refresh_token": sealedjwt.seal(_resolve(CHECKMARX_API_KEY), CHECKMARX_API_KEY),
        "token_type": "Bearer",
        "not-before-policy": 0,
    }
    _audit_grant(flow, "exchange", "answered", provider="checkmarx", secret=CHECKMARX_ACCESS_TOKEN)
    flow.response = http.Response.make(
        200,
        json.dumps(body).encode("utf-8"),
        {"content-type": "application/json", "cache-control": "no-store"},
    )
    log.info(
        "secret_proxy: POST %s - answered the Checkmarx token exchange with sealed tokens",
        host,
    )
    return True


def _chatgpt_status_route(flow: http.HTTPFlow) -> bool:
    """Proxy-auth protected, credential-free evidence of expiry-triggered refresh."""
    if flow.request.host != SENTINEL_HOST or flow.request.path != '/chatgpt/status':
        return False
    if not _client_may_login(flow, "chatgpt"):
        return _client_refusal(flow, "the chatgpt login")
    if flow.request.method != 'GET':
        flow.response = http.Response.make(405, b'{"error":"method_not_allowed"}')
        return True
    instance = os.environ.get('SECRET_PROXY_INSTANCE_ID', '')
    if re.fullmatch(r'[0-9a-f]{32}', instance) is None:
        flow.response = http.Response.make(503, b'{"error":"unavailable"}')
        return True
    try:
        _current_manifest().canonical_name('CHATGPT_ACCESS_TOKEN')
    except (AttributeError, KeyError):
        flow.response = http.Response.make(403, b'{"error":"not_available"}')
        return True
    value = {'instance': instance, **_bound_generation().providers.chatgpt.status()}
    flow.response = http.Response.make(200, json.dumps(value).encode(),
        {'content-type': 'application/json', 'cache-control': 'no-store'})
    return True


def _chatgpt_login_route(flow: http.HTTPFlow) -> bool:
    """Return only a URL or an unusable sealed JWT, never OAuth credentials."""
    if (flow.request.host or "").lower() != SENTINEL_HOST:
        return False
    path = (flow.request.path or "").split("?", 1)[0]
    if path not in ("/chatgpt/start", "/chatgpt/finish"):
        return False
    if not _client_may_login(flow, "chatgpt"):
        return _client_refusal(flow, "the chatgpt login")
    manifest = _current_manifest()
    try:
        manifest.canonical_name("CHATGPT_ACCESS_TOKEN")
    except (AttributeError, KeyError):
        flow.response = http.Response.make(403, b'{"error":"not_available"}')
        return True
    if (path, flow.request.method) not in (("/chatgpt/start", "GET"), ("/chatgpt/finish", "POST")):
        flow.response = http.Response.make(405, b'{"error":"method_not_allowed"}')
        return True
    bound = _bound_generation()
    provider = bound.providers.chatgpt
    if path.endswith("/start"):
        value = {"url": provider.start()}
        _audit(flow, "login", "started", provider="chatgpt")
    else:
        body = flow.request.content or b""
        if len(body) > 8192:
            flow.response = http.Response.make(413, b'{"error":"callback_too_large"}')
            return True
        try:
            value = provider.finish(body.decode("utf-8"))
        except (UnicodeDecodeError, ChatGPTAuthError) as error:
            _audit(flow, "login", "failed", provider="chatgpt", reason="login-failed",
                   error=type(error).__name__)
            value = {"error": "login_failed"}
            flow.response = http.Response.make(400, json.dumps(value).encode(),
                                               {"content-type": "application/json", "cache-control": "no-store"})
            return True
        _audit_grant(flow, "login", "completed", provider="chatgpt")
    flow.response = http.Response.make(200, json.dumps(value).encode(),
                                       {"content-type": "application/json", "cache-control": "no-store"})
    return True


def _json_response(flow: http.HTTPFlow, status: int, value) -> bool:
    body = value if isinstance(value, bytes) else json.dumps(value).encode()
    flow.response = http.Response.make(
        status, body, {"content-type": "application/json", "cache-control": "no-store"})
    return True


_DEVICE_FLOW_PATHS = ("/login/device/code", "/login/oauth/access_token")


def _github_client_login_blocked(flow: http.HTTPFlow) -> bool:
    """Refuse a client's own device/OAuth flow for a proxy-owned client ID.

    Its reply would hand the client a real GitHub token. Only the proxy's own
    login, which never runs through this hook, may use that client ID.
    """
    host = (flow.request.host or "").lower()
    path = (flow.request.path or "").split("?", 1)[0]
    if path not in _DEVICE_FLOW_PATHS:
        return False
    for login in _GITHUB_LOGINS:
        settings = _github_settings(login)
        if settings is None or host != settings["domain"]:
            continue
        if githubdevice.form_or_query_mentions(flow.request, login.client_id):
            log.warning("secret_proxy: BLOCKED %s %s%s - client-side %s login", flow.request.method, host, path, login.kind)
            _audit(flow, "login", "refused", provider=login.cli_name, reason="client-side-login")
            return _json_response(flow, 403, login.error)
    return False


def _copilot_exchange_response(flow: http.HTTPFlow) -> bool:
    """Answer a client's Copilot token exchange with a sealed token.

    Pi's refresh path calls the exchange with its reference bearer. Forwarding
    it would require the real GitHub token and return a live Copilot token, so
    the proxy answers itself. Any other exchange (a real bearer, another
    method, an unknown reference) is refused, never forwarded.
    """
    login = next(item for item in _GITHUB_LOGINS if item.kind == "copilot")
    settings = _github_settings(login)
    if settings is None:
        return False
    if (flow.request.host or "").lower() != "api." + settings["domain"]:
        return False
    if (flow.request.path or "").split("?", 1)[0] != copilotcreds.EXCHANGE_PATH:
        return False
    if not _client_may_use(flow, copilotcreds.CANONICAL):
        return _client_refusal(flow, copilotcreds.CANONICAL)
    reference = sealedjwt.MARKER + copilotcreds.CANONICAL
    auth = flow.request.headers.get_all("authorization")
    if (flow.request.method or "").upper() != "GET" or len(auth) != 1 or auth[0] not in (
        "Bearer " + reference, "token " + reference,
    ):
        log.warning("secret_proxy: BLOCKED %s %s - Copilot exchange without the login reference",
                    flow.request.method, flow.request.host)
        _audit(flow, "exchange", "refused", provider="github-copilot", reason="not-the-login-reference")
        return _json_response(flow, 403, login.error)
    provider = _github_provider(login)
    try:
        value = provider.exchange_answer()
    except (copilotcreds.CopilotAuthError, githubdevice.GitHubDeviceError):
        log.warning("secret_proxy: GET %s - Copilot exchange refused: login required", flow.request.host)
        _audit(flow, "exchange", "refused", provider="github-copilot", reason="login-required")
        return _json_response(flow, 403, login.error)
    _audit_grant(flow, "exchange", "answered", provider="github-copilot", secret=copilotcreds.CANONICAL)
    log.info("secret_proxy: GET %s - answered the Copilot token exchange with a sealed token", flow.request.host)
    return _json_response(flow, 200, value)


def _github_login_route(flow: http.HTTPFlow) -> bool:
    """Start, poll and report proxy-owned GitHub device logins.

    Responses carry only a user code and verification URL, a sealed client
    credential, or credential-free status. GitHub tokens never leave the proxy.
    """
    if (flow.request.host or "").lower() != SENTINEL_HOST:
        return False
    raw_path = flow.request.path or ""
    for login in _GITHUB_LOGINS:
        if raw_path.split("?", 1)[0] not in (login.prefix + "/start", login.prefix + "/poll", login.prefix + "/status"):
            continue
        action = raw_path.split("?", 1)[0].rsplit("/", 1)[1]
        if raw_path != login.prefix + "/" + action:
            return _json_response(flow, 400, {"error": "bad_request"})
        if not _client_may_login(flow, login.cli_name):
            return _client_refusal(flow, "the " + login.cli_name + " login")
        provider = _github_provider(login)
        if provider is None:
            return _json_response(flow, 403, {"error": "not_available"})
        method = (flow.request.method or "").upper()
        if method != {"start": "GET", "poll": "POST", "status": "GET"}[action]:
            return _json_response(flow, 405, {"error": "method_not_allowed"})
        if action == "status":
            instance = os.environ.get("SECRET_PROXY_INSTANCE_ID", "")
            if re.fullmatch(r"[0-9a-f]{32}", instance) is None:
                return _json_response(flow, 503, {"error": "unavailable"})
            return _json_response(flow, 200, {"instance": instance, **provider.status()})
        try:
            if action == "start":
                value = provider.start()
                log.info("secret_proxy: started proxy-owned GitHub %s login", login.kind)
                _audit(flow, "login", "started", provider=login.cli_name)
                return _json_response(flow, 200, value)
            result = provider.poll()
        except githubdevice.GitHubDeviceError as error:
            log.warning("secret_proxy: GitHub %s login failed (%s)", login.kind, error.reason)
            _audit(flow, "login", "failed", provider=login.cli_name, reason=error.reason)
            return _json_response(flow, 200, {"status": "failed", "reason": error.reason})
        if result is None:
            return _json_response(flow, 200, {"status": "pending", "retryAfter": provider.device.retry_after()})
        _audit_grant(flow, "login", "completed", provider=login.cli_name)
        log.info("secret_proxy: completed proxy-owned GitHub %s login", login.kind)
        payload = {"credential": result} if login.kind == "copilot" else result
        return _json_response(flow, 200, {"status": "complete", **payload})
    return False


GIT_SIGNING_SSH_KEY = "GIT_SIGNING_SSH_KEY"
GIT_SIGNING_PATH = "/git/sign"
GIT_SIGNING_KEY_HEADER = "x-git-signing-key"


def _git_signing_response(flow: http.HTTPFlow, status: int, error: str) -> bool:
    flow.response = http.Response.make(
        status,
        json.dumps({"error": error}).encode("utf-8"),
        {"content-type": "application/json", "cache-control": "no-store"},
    )
    return True


def _git_signing_route(flow: http.HTTPFlow) -> bool:
    """Sign a git commit or tag with the proxy-held SSH signing key.

    The container's gpg.ssh.program POSTs the object git wants signed. The
    proxy returns only the armored signature; the private key never leaves
    it. gitsign refuses anything that is not a git commit or tag object.
    """
    if (flow.request.host or "").lower() != SENTINEL_HOST:
        return False
    if (flow.request.path or "").split("?", 1)[0] != GIT_SIGNING_PATH:
        return False
    if (flow.request.method or "").upper() != "POST":
        return _git_signing_response(flow, 405, "method_not_allowed")
    try:
        _current_manifest().canonical_name(GIT_SIGNING_SSH_KEY)
    except (AttributeError, KeyError, ValueError):
        _audit(flow, "sign", "refused", reason="not-configured")
        return _git_signing_response(flow, 403, "git_signing_not_configured")
    grant = _client_grant(flow)
    if grant is not None and not grant.may_sign():
        _client_denied(flow, "git signing")
        flow.metadata.pop(_AUDIT_REASON, None)
        _audit(flow, "sign", "refused", reason="client-not-granted")
        return _git_signing_response(flow, 403, "secret_proxy_client_not_granted")
    payload = flow.request.content or b""
    if len(payload) > gitsign.MAX_PAYLOAD_BYTES:
        _audit(flow, "sign", "refused", reason="object-too-large")
        return _git_signing_response(flow, 413, "object_too_large")
    expected = flow.request.headers.get(GIT_SIGNING_KEY_HEADER) or None
    try:
        kind = gitsign.object_kind(payload)
    except gitsign.GitSignError as error:
        log.warning("secret_proxy: POST %s%s - refused: %s", SENTINEL_HOST, GIT_SIGNING_PATH, error)
        _audit(flow, "sign", "refused", reason="not-a-git-object")
        return _git_signing_response(flow, 400, str(error))
    try:
        private_key = _resolve(GIT_SIGNING_SSH_KEY)
    except Exception as error:  # noqa: BLE001 - provider errors never reach the client
        log.warning(
            "secret_proxy: POST %s%s - signing key unavailable (%s)",
            SENTINEL_HOST, GIT_SIGNING_PATH, type(error).__name__,
        )
        _audit(flow, "sign", "failed", reason="signing-key-unavailable", error=type(error).__name__)
        return _git_signing_response(flow, 502, "signing_key_unavailable")
    try:
        signature = gitsign.sign(private_key, payload, expected)
    except gitsign.GitSignError as error:
        log.warning("secret_proxy: POST %s%s - refused: %s", SENTINEL_HOST, GIT_SIGNING_PATH, error)
        _audit(flow, "sign", "refused", reason="signing-refused", object=kind)
        return _git_signing_response(flow, 400, str(error))
    if not _audit(flow, "sign", "signed", object=kind, secret=GIT_SIGNING_SSH_KEY):
        return _audit_unavailable_response(flow)
    flow.response = http.Response.make(
        200,
        signature.encode("ascii"),
        {"content-type": "text/plain; charset=utf-8", "cache-control": "no-store"},
    )
    log.info("secret_proxy: POST %s%s - signed a git %s", SENTINEL_HOST, GIT_SIGNING_PATH, kind)
    return True


def _health_route(flow: http.HTTPFlow) -> bool:
    """Authenticated liveness only: never resolve or return credentials."""
    if flow.request.host != SENTINEL_HOST or flow.request.path != "/health":
        return False
    instance = os.environ.get("SECRET_PROXY_INSTANCE_ID", "")
    if flow.request.method != "GET" or re.fullmatch(r"[0-9a-f]{32}", instance) is None:
        flow.response = http.Response.make(503, b"unavailable")
    else:
        flow.response = http.Response.make(
            200, json.dumps({"status": "ready", "instance": instance}).encode(),
            {"content-type": "application/json", "cache-control": "no-store"},
        )
    return True


def _request_locked(flow: http.HTTPFlow) -> None:
    host = flow.request.host
    injected: list[str] = list(flow.metadata.pop("secret_proxy_metadata_injected", ()))
    metadata_logged = bool(flow.metadata.pop("secret_proxy_metadata_logged", False))

    try:
        if flow.response is not None:
            flow.metadata.pop(_AUDIT_USES, None)
            return  # a hook (e.g. requestheaders re-sign error) already responded
        if flow.request.stream:
            flow.metadata.pop("secret_proxy_metadata_original", None)
            return  # already re-signed + streamed in requestheaders (S3 / presigned)

        # Prevent Pi's ordinary login from handing a real OAuth reply to the
        # container. Only the proxy-owned browser flow may exchange codes.
        if (host or "").lower() == "auth.openai.com" and (flow.request.path or "").split("?", 1)[0] in (
            "/oauth/token", "/api/accounts/deviceauth/token",
        ):
            try:
                codex_proxy_enabled = _current_manifest().secret("CHATGPT_ACCESS_TOKEN").runtime_only
            except (AttributeError, KeyError):
                codex_proxy_enabled = False
            if codex_proxy_enabled:
                _audit(flow, "login", "refused", provider="chatgpt", reason="client-side-login")
                flow.response = http.Response.make(403, b'{"error":"use_chatgpt_login"}',
                                                   {"content-type": "application/json"})
                return
        if _github_client_login_blocked(flow):
            return
        if _health_route(flow):
            return
        if _github_login_route(flow):
            return
        if _copilot_exchange_response(flow):
            return
        if _chatgpt_status_route(flow):
            return
        if _chatgpt_login_route(flow):
            return
        if _git_signing_route(flow):
            return

        # Do not let a second, ordinary Pi /login leave a real Codex bearer
        # token in auth.json undetected. Only a sealed runtime reference works.
        if (host or "").lower() == "chatgpt.com" and (flow.request.path or "").split("?", 1)[0] == "/backend-api/codex/responses":
            try:
                configured = _current_manifest().secret("CHATGPT_ACCESS_TOKEN").runtime_only
            except (AttributeError, KeyError):
                configured = False
            if configured:
                auth = sealedjwt.unseal(flow.request.headers.get("authorization", ""))
                if auth != "Bearer " + sealedjwt.MARKER + "CHATGPT_ACCESS_TOKEN":
                    _audit(flow, "login", "refused", provider="chatgpt", reason="not-the-login-reference")
                    flow.response = http.Response.make(403, b'{"error":"use_chatgpt_login"}',
                                                       {"content-type": "application/json"})
                    return

        # URL-rewrite is deliberately resolved and validated before any other
        # request mutation. Its existing all-or-nothing behavior is preserved.
        if host == SENTINEL_HOST:
            name = flow.request.path_components[0] if flow.request.path_components else ""
            canonical = _canonical_ref(name)
            scheme, target_host, port, path_with_query = _sentinel_resolve(canonical, flow)
            # The destination URL is the secret: audit the sentinel request only.
            flow.metadata[_AUDIT_ORIGIN] = (flow.request.host, flow.request.port, flow.request.path)
            _audit_grant(flow, "inject", "injected", secret=canonical, placement="url-rewrite")
            flow.request.scheme = scheme
            flow.request.host = target_host
            flow.request.port = port
            flow.request.path = path_with_query
            flow.request.headers["Host"] = target_host + (f":{port}" if port not in (80, 443) else "")
            log.info(f"secret_proxy: {flow.request.method} {SENTINEL_HOST}/{canonical} - rewrote to {target_host}")
            return

        # Validate every reference before any provider lookup. Only after the
        # whole request passes do the existing transactional planners resolve
        # values and build mutations.
        _unseal_request(flow, include_body=True)
        if _checkmarx_exchange_response(flow):
            flow.metadata.pop("secret_proxy_metadata_original", None)
            return
        _preflight_request(flow, include_body=True)
        if _is_aws_sigv4_ours(flow):
            _aws_approval_precheck(flow, flow.request.raw_content)
        _approval_gate(flow)
        metadata_plan = _plan_request_metadata(flow)
        body_plan = _plan_request_body(flow, metadata_plan)

        if metadata_plan["headers"] or metadata_plan["query"] or body_plan is not None:
            flow.metadata.setdefault("secret_proxy_metadata_original", _metadata_snapshot(flow))
        _commit_request_metadata(flow, metadata_plan)
        _commit_request_body(flow, body_plan)
        injected.extend(metadata_plan["logs"])
        if body_plan is not None:
            injected.extend(body_plan["logs"])

        # AWS SigV4 re-signing (only *.amazonaws.com): swap the container's dummy
        # creds for real STS creds and re-sign on the wire. S3 + streaming uploads
        # + our presigned URLs are handled in requestheaders (flow.request.stream
        # set) so only the buffered non-S3 path runs here. Requests signed with a
        # real credential are not ours to re-sign and pass through untouched.
        if _is_aws_sigv4_ours(flow):
            _resign_aws(flow)
            if flow.response is not None:
                flow.metadata.pop(_AUDIT_USES, None)
                _restore_metadata_snapshot(flow)
            else:
                _audit_commit_uses(flow)
                flow.metadata.pop("secret_proxy_metadata_original", None)
            return

        _audit_commit_uses(flow)
        flow.metadata.pop("secret_proxy_metadata_original", None)
    except ApprovalRequired:
        # Held for approval; the re-run must see the same hook state.
        if injected:
            flow.metadata["secret_proxy_metadata_injected"] = tuple(injected)
        if metadata_logged:
            flow.metadata["secret_proxy_metadata_logged"] = True
        raise
    except PolicyViolation as e:
        _restore_metadata_snapshot(flow)
        _set_injection_error(flow, injected, e)
        return
    except Exception as e:  # noqa: BLE001 - fail loudly rather than leak the placeholder
        _restore_metadata_snapshot(flow)
        _set_injection_error(flow, injected, e)
        return

    if injected:
        if not metadata_logged:
            log.info(f"secret_proxy: {flow.request.method} {host} - injected {', '.join(injected)}")
    else:
        log.info(f"secret_proxy: {flow.request.method} {host} - passthrough")


def _require_https(flow: http.HTTPFlow) -> bool:
    """Reject plaintext proxy traffic before resolving or minting credentials."""
    if flow.response is not None:
        return False
    if (flow.request.scheme or "").lower() == "https":
        return True
    log.warning(
        "secret_proxy: BLOCKED %s %s - HTTPS required",
        flow.request.method,
        flow.request.host,
    )
    _audit(flow, "transport", "refused", reason="https-required")
    flow.response = http.Response.make(
        403,
        b'{"error":"secret_proxy_https_required"}',
        {"content-type": "application/json"},
    )
    return False


def _plaintext_request_needs_credentials(flow: http.HTTPFlow) -> bool:
    if flow.request.host == SENTINEL_HOST:
        return True
    if _metadata_has_secret_reference(flow):
        return True
    if b"secretref" in (flow.request.content or b""):
        return True
    if _is_aws_sigv4(flow) or _is_aws_presigned_ours(flow):
        return True
    return bool(
        flow.request.stream
        and flow.request.method.upper() not in ("GET", "HEAD")
    )


def _run_hook(flow: http.HTTPFlow, handler) -> None:
    """Validate transport, capture one generation, then run without the store lock."""
    if flow.response is not None:
        return
    if (flow.request.scheme or "").lower() != "https":
        if _plaintext_request_needs_credentials(flow):
            _require_https(flow)
        elif handler is _request_locked:
            log.info(
                "secret_proxy: %s %s - plaintext passthrough (no credential operation)",
                flow.request.method,
                flow.request.host,
            )
        return
    try:
        generation = _capture_generation()
    except Exception as e:  # noqa: BLE001 - fail closed before any mutation
        _restore_metadata_snapshot(flow)
        _set_injection_error(flow, [], e)
        return
    with _bind_generation(generation):
        try:
            handler(flow)
        except ApprovalRequired:
            # Nothing was resolved; undo any metadata change and hold the flow.
            _restore_metadata_snapshot(flow)
            if not flow.metadata.get(APPROVAL_HANDLER):
                # No runtime adapter will ask anyone: refuse, never forward.
                pending = approval_pending(flow)
                approval_refusal(flow, pending[0] if pending else None, approvals.RULE_REQUIRED)


def request(flow: http.HTTPFlow) -> None:
    _run_hook(flow, _request_locked)


AWS_RESPONSE_CHECK = "secret_proxy_aws_response_check"


def responseheaders(flow: http.HTTPFlow) -> None:
    if flow.metadata.get(AWS_RESPONSE_CHECK) is not None:
        # A response that may hold a decrypted SSM SecureString is buffered and
        # checked in response(). A stated length over the limit is killed now;
        # HTTP/2 may omit the length, so its size is checked after buffering.
        length = (flow.response.headers.get("content-length") or "").strip()
        if length and (not length.isdigit() or int(length) > awsops.RESPONSE_LIMIT):
            check = flow.metadata[AWS_RESPONSE_CHECK]
            log.warning("secret_proxy: AWS DENY %s %s (response too large to check)",
                        check["who"], check["label"])
            _audit(flow, "aws", "denied", account=check["account"], role=check["role"],
                   service=check["service"], operation=check["operation"], rule=check["rule"])
            if flow.killable:
                flow.kill()
            else:
                flow.error = mitmflow.Error(mitmflow.Error.KILLED_MESSAGE)
            return
        flow.response.stream = False
        return
    # Stream the response body straight through (don't buffer) so streaming
    # APIs like Bedrock converse-stream (eventstream) work.
    flow.response.stream = True


def response(flow: http.HTTPFlow) -> None:
    """Refuse a checked SSM response that holds a decrypted SecureString."""
    check = flow.metadata.get(AWS_RESPONSE_CHECK)
    if check is None or flow.response is None:
        return
    if not 200 <= flow.response.status_code < 300:
        return  # errors carry no parameter values
    try:
        body = flow.response.get_content(strict=True) or b""
        if len(body) > awsops.RESPONSE_LIMIT:
            raise ValueError("response too large to check")
        secret = awsops.response_has_secure_string(body)
        reason = "the response contains a SecureString value"
    except (ValueError, UnicodeDecodeError):
        secret, reason = True, "the response could not be checked"
    if not secret:
        return
    op = awsops.AwsOperation(check["service"], check["operation"], awsops.PROTOCOL_JSON)
    decision = awsops.Decision(awsops.DENY, reason, check["rule"])
    log.warning("secret_proxy: AWS DENY %s %s (%s; rule=%s)", check["who"], op.label, reason, check["rule"])
    _aws_error(flow, AwsOperationDenied(op, decision, check["account"], check["role"]))


# --- AWS SigV4 re-signing ---------------------------------------------------
# secret_proxy also folds in what the standalone aws-auth container used to do: it
# mints short-lived STS creds from Okta (awscreds.AwsCredsProvider) and re-signs
# AWS SigV4 requests on the wire. The devenv container holds only DUMMY AWS
# creds; the real STS creds never enter it. The desired (account, role) rides in
# the dummy session token as "secretrole:<account>/<role>" (rewritten by `awsrole`);
# absent that, the provider's default target is used.
_aws_provider = None
_aws_provider_tried = False


def _get_aws_provider():
    """Return the AWS provider for the bound generation, if any.

    Direct unit helpers retain the historical global-cache behavior. Hook
    callers instead use the resolver/provider state attached to their captured
    generation, so a reload cannot change an in-flight request's callback.
    """
    bound = _bound_generation()
    if bound is _UNBOUND:
        return _get_aws_provider_global()
    if bound is None:
        return None

    state = bound.providers
    with state.lock:
        if state.aws is not None or state.aws_tried:
            return state.aws
        state.aws_tried = True
        resolver = bound.resolver
        try:
            if AWS_OKTA_FILE.exists():
                state.aws = AwsCredsProvider.from_config_file(
                    str(AWS_OKTA_FILE), resolver.get
                )
                _mirror_provider(bound, "aws", state.aws)
                log.info(f"secret_proxy: AWS creds provider loaded from {AWS_OKTA_FILE}")
        except Exception as e:  # noqa: BLE001
            log.warning(f"secret_proxy: AWS creds provider unavailable: {e}")
        _mirror_provider(bound, "aws", state.aws)
        return state.aws


def _get_aws_provider_global():
    """Legacy AWS provider cache for direct calls outside a hook."""
    global _aws_provider, _aws_provider_tried
    if _aws_provider is not None or _aws_provider_tried:
        return _aws_provider
    _aws_provider_tried = True
    resolver = _resolver
    if resolver is None:
        log.warning("secret_proxy: AWS creds provider unavailable: secret resolver unavailable")
        return None
    try:
        if AWS_OKTA_FILE.exists():
            _aws_provider = AwsCredsProvider.from_config_file(str(AWS_OKTA_FILE), resolver.get)
            log.info(f"secret_proxy: AWS creds provider loaded from {AWS_OKTA_FILE}")
    except Exception as e:  # noqa: BLE001
        log.warning(f"secret_proxy: AWS creds provider unavailable: {e}")
    return _aws_provider


def _is_aws_sigv4(flow: http.HTTPFlow) -> bool:
    host = (flow.request.host or "").lower()
    if not host.endswith(".amazonaws.com"):
        return False
    return flow.request.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256")


# The dummy access key id dev.sh gives the container. A request signed with it is
# ours even when the caller dropped the session token (an explicit profile, a tool
# that omits it), so both markers are checked.
_AWS_DUMMY_AKID_MARKER = "secret-proxy-dummy-akid"


def _is_aws_sigv4_ours(flow: http.HTTPFlow) -> bool:
    """A SigV4 header-auth request signed with the container's DUMMY credentials,
    which is what re-signing is for. A REAL credential pasted into the container
    (verifying a leaked key, calling an account this role cannot assume) is not
    matched, so it reaches AWS signed exactly as the caller signed it instead of
    being silently re-signed as this container's role. Mirrors the check
    _is_aws_presigned_ours already applies to query-auth URLs."""
    if not _is_aws_sigv4(flow):
        return False
    if flow.request.headers.get("x-amz-security-token", "").startswith("secretrole:"):
        return True
    return _AWS_DUMMY_AKID_MARKER in flow.request.headers.get("Authorization", "")


def _aws_target(flow: http.HTTPFlow, provider) -> tuple[str, str]:
    tok = flow.request.headers.get("x-amz-security-token", "")
    if tok.startswith("secretrole:") and "/" in tok:
        acct, role = tok[len("secretrole:"):].split("/", 1)
        if acct and role:
            return acct, role
    return provider.default_target()


def _is_aws_presigned_ours(flow: http.HTTPFlow) -> bool:
    """A SigV4 PRESIGNED (query-auth) request that WE generated — identified by the
    dummy secretrole: selector in X-Amz-Security-Token. Externally-signed presigned
    URLs (real token, already-valid signature) are NOT matched, so they pass
    through untouched."""
    host = (flow.request.host or "").lower()
    if not host.endswith(".amazonaws.com"):
        return False
    q = flow.request.query
    if not q.get("X-Amz-Algorithm", "").startswith("AWS4-HMAC-SHA256") or "X-Amz-Signature" not in q:
        return False
    return q.get("X-Amz-Security-Token", "").startswith("secretrole:")


def _resign_presigned(flow: http.HTTPFlow) -> None:
    """Re-sign one of our dummy-signed presigned URLs (query-auth) with real STS
    creds so an in-container fetch of a self-generated presigned URL works."""
    if not _require_https(flow):
        return
    checked = None
    if _client_grant(flow) is not None:
        # Before the provider is touched: a scoped client needs an AWS grant
        # without an operations restriction (presigned URLs are not classified).
        try:
            _policy, default_target = _load_aws_policy()
        except Exception:  # noqa: BLE001 - unreadable configuration denies
            default_target = (None, None)
        tok = flow.request.query.get("X-Amz-Security-Token", "")
        checked = tuple(default_target)
        if tok.startswith("secretrole:") and "/" in tok:
            a, r = tok[len("secretrole:"):].split("/", 1)
            if a and r:
                checked = (a, r)
        account, role = checked
        if not (isinstance(account, str) and re.fullmatch(r"[0-9]{12}", account)
                and isinstance(role, str) and re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role)):
            account = role = None
        checked = (account, role)
        denied = _aws_client_denial(flow, account, role, None)
        if denied is not None:
            credential = flow.request.query.get("X-Amz-Credential", "").split("/")
            service = credential[3] if len(credential) == 5 and credential[3] else awsops.UNKNOWN
            op = awsops.AwsOperation(service, awsops.UNKNOWN, awsops.PROTOCOL_REST, "presigned URL")
            log.warning("secret_proxy: AWS DENY %s/%s presigned (%s)", account or "-", role or "-", denied.reason)
            raise AwsOperationDenied(op, denied, account, role)
    provider = _get_aws_provider()
    if provider is None:
        log.warning(f"secret_proxy: {flow.request.host} presigned but no creds provider - passthrough")
        return
    q = flow.request.query
    tok = q.get("X-Amz-Security-Token", "")
    account, role = provider.default_target()
    if tok.startswith("secretrole:") and "/" in tok:
        a, r = tok[len("secretrole:"):].split("/", 1)
        if a and r:
            account, role = a, r
    if checked is not None and (account, role) != checked:
        op = awsops.AwsOperation(awsops.UNKNOWN, awsops.UNKNOWN, awsops.PROTOCOL_REST, "presigned URL")
        denied = awsops.Decision(awsops.DENY, "the signing target differs from the checked target", "clients")
        raise AwsOperationDenied(op, denied, checked[0], checked[1])
    creds = provider.get_creds(account, role)
    params = {k: q[k] for k in q}
    headers_lower = {k.lower(): v for k, v in flow.request.headers.items()}
    _kw = {"akid": creds["AccessKeyId"]}
    _kw["secret"] = creds["SecretAccessKey"]
    _kw["token"] = creds["SessionToken"]
    new = sigv4.resign_query(
        method=flow.request.method,
        path=urlsplit(flow.request.url).path,
        query_params=params,
        headers_lower=headers_lower,
        host=flow.request.host,
        **_kw,
    )
    credential = q.get("X-Amz-Credential", "").split("/")
    _audit_grant(flow, "aws", "allowed", account=account, role=role,
                 service=credential[3] if len(credential) == 5 else None, reason="presigned-url")
    for k, v in new.items():
        flow.request.query[k] = v
    flow.request.stream = True  # body (if any) is UNSIGNED-PAYLOAD; stream unchanged
    log.info(f"secret_proxy: {flow.request.method} {flow.request.host} - AWS presigned re-signed as {account}/{role}")


# --- AWS operation policy --------------------------------------------------
# Some AWS operations return a credential or secret value (GetSecretValue,
# AssumeRole, CreateAccessKey...). Every dummy-signed request is identified and
# checked against awsops' policy BEFORE the creds provider is touched, so a
# denied call never causes an STS mint or a re-signature. Presigned (query-auth)
# URLs are out of scope: they fetch objects and keep their existing behaviour.


class AwsOperationDenied(Exception):
    """A re-sign refused by the AWS operation policy (fixed, secret-free text)."""

    def __init__(self, op, decision, account, role):
        super().__init__(decision.reason)
        self.op = op
        self.decision = decision
        self.account = account
        self.role = role


_aws_policy_lock = threading.Lock()
_aws_policy_cache = None  # (signature, (policy, default_target))


def _file_signature(path: Path):
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    return (info.st_mtime_ns, info.st_size, info.st_ino)


def _read_json_object(path: Path) -> dict:
    with open(path, "rb") as stream:
        data = stream.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise awsops.AwsPolicyError(f"{path.name}: file too large")
    try:
        document = json.loads(data)
    except ValueError:
        raise awsops.AwsPolicyError(f"{path.name}: invalid JSON") from None
    if not isinstance(document, dict):
        raise awsops.AwsPolicyError(f"{path.name}: expected an object")
    return document


def _load_aws_policy():
    """Return (AwsOperationPolicy, (default_account, default_role)).

    Reads only configuration (never a secret). Reloads when either file changes.
    Raises awsops.AwsPolicyError for an invalid policy: callers fail closed.
    """
    global _aws_policy_cache
    signature = (_file_signature(AWS_POLICY_FILE), _file_signature(AWS_OKTA_FILE),
                 str(AWS_POLICY_FILE), str(AWS_OKTA_FILE))
    with _aws_policy_lock:
        if _aws_policy_cache is not None and _aws_policy_cache[0] == signature:
            return _aws_policy_cache[1]
        rules = ()
        if signature[0] is not None:
            with open(AWS_POLICY_FILE, "rb") as stream:
                data = stream.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise awsops.AwsPolicyError("aws-policy.json: file too large")
            rules = awsops.load_policy_bytes(data)
        overrides = ()
        default_target = (None, None)
        if signature[1] is not None:
            config = _read_json_object(AWS_OKTA_FILE)
            if "operation_overrides" in config:
                overrides = awsops.parse_overrides(config["operation_overrides"])
            default_target = (config.get("default_account"), config.get("default_role"))
        result = (awsops.AwsOperationPolicy(rules, overrides), default_target)
        _aws_policy_cache = (signature, result)
        return result


def aws_policy_startup_summary() -> list[str]:
    """Load and validate the AWS operation policy; return log lines (no secrets)."""
    policy, _default = _load_aws_policy()
    builtin = len(awsops.DEFAULT_DENY_RULES)
    count = len(policy.rules) - builtin
    lines = [
        f"secret_proxy: AWS operation policy: {count} rules from {AWS_POLICY_FILE.name}"
        + ("" if AWS_POLICY_FILE.is_file() else " (no file: nothing is blocked)")
        + f", {len(policy.overrides)} role overrides"
    ]
    for override in policy.overrides:
        lines.append(
            "secret_proxy: AWS operation OVERRIDE enabled: "
            f"{override.describe()} (bypasses deny rules for that role only)"
        )
    return lines


def _aws_request_view(flow: http.HTTPFlow, body) -> "awsops.AwsRequest":
    raw_path = flow.request.path or "/"
    path, _, query = raw_path.partition("?")
    headers = tuple((str(k), str(v)) for k, v in flow.request.headers.items(multi=True))
    return awsops.AwsRequest(
        method=flow.request.method or "",
        host=flow.request.host or "",  # the authority: HTTP/2 has no Host header
        path=path or "/",
        query=query,
        headers=headers,
        body=body,
    )


def _aws_selected_target(flow: http.HTTPFlow, default_target) -> tuple:
    """(account, role) for policy and logs; the provider still validates them."""
    account, role = default_target
    tok = flow.request.headers.get("x-amz-security-token", "")
    if tok.startswith("secretrole:") and "/" in tok:
        acct, selected = tok[len("secretrole:"):].split("/", 1)
        if acct and selected:
            account, role = acct, selected
    if not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None:
        account = None
    if not isinstance(role, str) or re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role) is None:
        role = None
    return account, role


def _aws_protocol(flow: http.HTTPFlow) -> str:
    try:
        return awsops.classify(_aws_request_view(flow, None)).protocol
    except Exception:  # noqa: BLE001
        return awsops.PROTOCOL_UNKNOWN


def _aws_approval_precheck(flow: http.HTTPFlow, body) -> None:
    """Collect an AWS approval before any other secret is resolved.

    A denial is left for the real check, which reports it in the usual way.
    """
    try:
        _aws_policy_check(flow, body, quiet=True)
    except AwsOperationDenied:
        pass


def _aws_policy_check(flow: http.HTTPFlow, body, quiet: bool = False):
    """Identify the AWS operation and enforce the policy, before any creds work.

    Returns (operation, decision, account, role) when allowed or awaiting
    approval (the caller's gate stops before minting); raises
    AwsOperationDenied when denied. *body* is None when unavailable.
    """
    try:
        policy, default_target = _load_aws_policy()
    except Exception as e:  # noqa: BLE001 - an unreadable policy denies everything
        log.error("secret_proxy: AWS operation policy unavailable (%s); denying", type(e).__name__)
        op = awsops.AwsOperation(awsops.UNKNOWN, awsops.UNKNOWN, awsops.PROTOCOL_UNKNOWN,
                                 "policy unavailable")
        decision = awsops.Decision(awsops.DENY, "the AWS operation policy could not be loaded",
                                   "policy unavailable")
        raise AwsOperationDenied(op, decision, None, None) from None
    account, role = _aws_selected_target(flow, default_target)
    try:
        op = awsops.classify(_aws_request_view(flow, body))
    except Exception as e:  # noqa: BLE001 - never forward what we cannot identify
        log.error("secret_proxy: AWS operation classification failed (%s)", type(e).__name__)
        op = awsops.AwsOperation(awsops.UNKNOWN, awsops.UNKNOWN, awsops.PROTOCOL_UNKNOWN,
                                 "classification failed",
                                 conditions=frozenset({awsops.CONDITION_UNVERIFIED_SERVICE}))
    # Defence in depth: the re-signer must sign for the same service. A
    # mismatch is an unverifiable target, denied whatever the service.
    try:
        signing = sigv4.parse_authorization(flow.request.headers.get("Authorization", ""))["service"]
    except Exception:  # noqa: BLE001
        signing = None
    if signing != op.service and awsops.CONDITION_UNVERIFIED_SERVICE not in op.conditions:
        op = awsops.AwsOperation(op.service, awsops.UNKNOWN, op.protocol,
                                 "signing scope differs from the inspected scope",
                                 conditions=frozenset({awsops.CONDITION_UNVERIFIED_SERVICE}))
    who = f"{account or '-'}/{role or '-'}"
    flow.metadata["secret_proxy_aws_operation"] = op.label
    # A scoped client's grant is checked first: no override can widen it.
    denied = _aws_client_denial(flow, account, role, op)
    if denied is not None:
        if not quiet:
            log.warning("secret_proxy: AWS DENY %s %s (%s)", who, op.label, denied.reason)
        raise AwsOperationDenied(op, denied, account, role)
    decision = policy.evaluate(op, account, role)
    if decision.needs_approval:
        try:
            _approval_needed(flow, approvals.aws_request(
                account=account, role=role, service=op.service, operation=op.operation,
                rule=decision.rule, host=flow.request.host or "", method=flow.request.method or "",
                path=flow.request.path or "/", client=_requester(flow),
            ))
        except ApprovalRefused as refused:
            denied = awsops.Decision(awsops.DENY, f"approval refused ({refused.rule})", refused.rule)
            raise AwsOperationDenied(op, denied, account, role) from None
        return op, decision, account, role
    if not decision.allowed:
        if not quiet:
            log.warning(
                "secret_proxy: AWS DENY %s %s (%s; rule=%s)", who, op.label, decision.reason, decision.rule,
            )
        raise AwsOperationDenied(op, decision, account, role)
    if decision.overridden:
        log.warning("secret_proxy: AWS ALLOW (override) %s %s", who, op.label)
    return op, decision, account, role


def _aws_client_denial(flow: http.HTTPFlow, account, role, op) -> "awsops.Decision | None":
    """A deny Decision when the flow's client may not use this target/operation."""
    grant = _client_grant(flow)
    if grant is None:
        return None
    grants = grant.aws_grants_for(account, role)
    if not grants:
        return awsops.Decision(
            awsops.DENY, f"client '{_client_label(flow)}' is not granted this AWS account and role",
            "clients")
    if op is None:
        # Presigned URLs are not classified: only an unrestricted grant covers them.
        if not any(not g.operations for g in grants):
            return awsops.Decision(
                awsops.DENY, f"client '{_client_label(flow)}' may use this role only for listed operations",
                "clients")
        return None
    if not any(g.allows_operation(op.service, op.operation) for g in grants):
        return awsops.Decision(
            awsops.DENY, f"client '{_client_label(flow)}' is not granted {op.label}", "clients")
    return None


def _cbor_text(value: str) -> bytes:
    data = value.encode("utf-8")
    n = len(data)
    if n < 24:
        head = bytes([0x60 | n])
    elif n < 256:
        head = bytes([0x78, n])
    else:
        head = bytes([0x79]) + n.to_bytes(2, "big")
    return head + data


def _aws_denied_response(flow: http.HTTPFlow, e: AwsOperationDenied) -> None:
    """403 AccessDeniedException in the request's own protocol."""
    op = e.op
    message = f"secret-proxy blocked {op.label}: {e.decision.reason}"
    code = "AccessDeniedException"
    headers = {"x-amzn-ErrorType": code, "cache-control": "no-store"}
    protocol = op.protocol
    smithy = flow.request.headers.get("smithy-protocol", "").strip().lower()
    if protocol == awsops.PROTOCOL_QUERY or (protocol == awsops.PROTOCOL_REST and op.service == "s3"):
        from xml.sax.saxutils import escape
        if protocol == awsops.PROTOCOL_QUERY:
            body = (
                "<ErrorResponse><Error><Type>Sender</Type>"
                f"<Code>{code}</Code><Message>{escape(message)}</Message>"
                "</Error><RequestId>secret-proxy</RequestId></ErrorResponse>"
            )
        else:
            body = f"<Error><Code>{code}</Code><Message>{escape(message)}</Message></Error>"
        headers["content-type"] = "text/xml"
        payload = body.encode()
    elif protocol == awsops.PROTOCOL_RPCV2 and smithy == "rpc-v2-cbor":
        payload = b"\xa2" + _cbor_text("__type") + _cbor_text(code) + _cbor_text("message") + _cbor_text(message)
        headers["content-type"] = "application/cbor"
        headers["smithy-protocol"] = "rpc-v2-cbor"
    else:
        content_type = "application/json"
        if protocol == awsops.PROTOCOL_JSON:
            requested = flow.request.headers.get("content-type", "").split(";")[0].strip().lower()
            content_type = requested if requested.startswith("application/x-amz-json-") else "application/x-amz-json-1.1"
        elif protocol == awsops.PROTOCOL_RPCV2:
            headers["smithy-protocol"] = "rpc-v2-json"
        headers["content-type"] = content_type
        payload = json.dumps({"__type": code, "message": message}).encode()
    flow.response = http.Response.make(403, payload, headers)


def _aws_resign_apply(flow: http.HTTPFlow, body):
    """Mint STS creds for the request's target and re-sign it. *body* is the
    payload bytes to hash when x-amz-content-sha256 is absent (non-S3); pass None
    to sign over the client's x-amz-content-sha256 header (S3 / streaming). Sets
    the new Authorization + X-Amz-Security-Token headers and returns the
    sigv4.resign() result (incl. a reframer for aws-chunked uploads), or None if
    no creds provider is configured."""
    if not _require_https(flow):
        return None
    # The operation decision precedes the provider, any STS mint and re-signing.
    op, decision, policy_account, policy_role = _aws_policy_check(flow, body)
    _approval_gate(flow)  # an "approve" rule: nothing is minted until answered
    provider = _get_aws_provider()
    if provider is None:
        log.warning(f"secret_proxy: {flow.request.host} AWS SigV4 but no creds provider (aws-okta.json missing) - passthrough")
        return None
    account, role = _aws_target(flow, provider)
    if _client_grant(flow) is not None and (account, role) != (policy_account, policy_role):
        # The client grant was checked for the policy target; never mint for another.
        denied = awsops.Decision(awsops.DENY, "the signing target differs from the checked target", "clients")
        log.warning("secret_proxy: AWS DENY %s/%s %s (%s)", policy_account or "-", policy_role or "-",
                    op.label, denied.reason)
        raise AwsOperationDenied(op, denied, policy_account, policy_role)
    if decision.overridden and (account, role) != (policy_account, policy_role):
        # An override is for one exact role; never mint for any other target.
        denied = awsops.Decision(awsops.DENY, "the role override does not match the signing target",
                                 "operation_overrides")
        log.warning("secret_proxy: AWS DENY %s/%s %s (%s)", policy_account or "-", policy_role or "-",
                    op.label, denied.reason)
        raise AwsOperationDenied(op, denied, policy_account, policy_role)
    creds = provider.get_creds(account, role)
    parts = urlsplit(flow.request.url)
    headers_lower = {k.lower(): v for k, v in flow.request.headers.items()}
    _kw = {"akid": creds["AccessKeyId"]}
    _kw["secret"] = creds["SecretAccessKey"]
    _kw["token"] = creds["SessionToken"]
    _kw["host"] = flow.request.host  # HTTP/2: authority isn't in .headers
    res = sigv4.resign(
        method=flow.request.method,
        path=parts.path,
        query=parts.query,
        headers_lower=headers_lower,
        body=body,
        **_kw,
    )
    _audit_grant(flow, "aws", "allowed", account=account, role=role, service=op.service,
                 operation=op.operation, rule=decision.rule, overridden=decision.overridden or None)
    flow.request.headers["Authorization"] = res["authorization"]
    flow.request.headers["x-amz-security-token"] = res["x-amz-security-token"]
    flow.metadata["secret_proxy_aws"] = f"{account}/{role}"
    if decision.inspect_response:
        flow.metadata[AWS_RESPONSE_CHECK] = {
            "who": f"{account}/{role}", "label": op.label, "account": account, "role": role,
            "service": op.service, "operation": op.operation, "rule": decision.inspect_response}
    return res


def _aws_error(flow: http.HTTPFlow, e: Exception) -> None:
    if isinstance(e, AwsOperationDenied):
        _audit(flow, "aws", "denied", account=e.account, role=e.role, service=e.op.service,
               operation=e.op.operation, rule=e.decision.rule)
        _aws_denied_response(flow, e)
        return
    if isinstance(e, AuditUnavailable):
        _audit_unavailable_response(flow)
        return
    # AwsCredsError carries a fixed, secret-free reason. Credential-vending
    # failures answer 403 rather than 502: AWS SDKs retry 5xx, and each retry
    # used to be another Okta login attempt towards a lockout.
    reason = getattr(e, "reason", None) if type(e).__name__ == "AwsCredsError" else None
    _audit(flow, "aws", "failed", reason=reason, error=type(e).__name__)
    log.error(
        "secret_proxy: AWS re-sign failed for %s %s (exception=%s%s)",
        flow.request.method,
        flow.request.host,
        type(e).__name__,
        f", reason={reason}: {e}" if reason else "",
    )
    flow.response = http.Response.make(
        403 if reason else 502,
        json.dumps({
            "error": "secret_proxy_aws_resign_failed",
            "detail": f"AWS credentials unavailable: {e}" if reason else "AWS request signing failed",
        }).encode(),
        {"content-type": "application/json"},
    )


def _requestheaders_locked(flow: http.HTTPFlow) -> None:
    _requestheaders_inner(flow)
    if flow.response is not None:
        flow.metadata.pop(_AUDIT_USES, None)
    elif flow.request.stream and flow.metadata.get(_AUDIT_USES):
        # Streamed now: request() will not see this flow again.
        try:
            _audit_commit_uses(flow)
        except AuditUnavailable as error:
            _restore_metadata_snapshot(flow)
            _set_injection_error(flow, [], error)


def _requestheaders_inner(flow: http.HTTPFlow) -> None:
    """Re-sign AWS SigV4 requests that carry x-amz-content-sha256 (all S3) BEFORE
    the body is read, then STREAM the body — so multi-GB uploads never buffer in
    the proxy. A signed aws-chunked upload is re-framed on the fly
    (ChunkedResigner); otherwise the body streams through unmodified (the seed is
    already re-signed from the header's payload hash). Non-S3 requests (no
    content-sha256) fall through to the buffered path in request(). Our own
    presigned (query-auth) URLs are re-signed here too."""
    if flow.response is not None:
        return

    injected: list[str] = []
    try:
        _unseal_request(flow, include_body=False)
    except Exception as e:  # noqa: BLE001 - fail closed before forwarding
        _set_injection_error(flow, injected, e)
        return
    # Classify the request before touching metadata. Buffered requests must stay
    # untouched until request(), where body + metadata injection and buffered
    # AWS re-signing happen transactionally in the buffered hook.
    is_aws_presigned = _is_aws_presigned_ours(flow)
    # Broad classification keeps the streaming and transport rules below applying to
    # every AWS SigV4 request, including one signed with a real pasted credential.
    # Only the re-signing decision itself is narrowed to requests that are ours.
    is_aws_sigv4 = _is_aws_sigv4(flow)
    is_aws_ours = _is_aws_sigv4_ours(flow)
    incoming_stream = bool(flow.request.stream)
    # We cannot inspect an arbitrary streamed body for unresolved references.
    # AWS streams are re-signed deliberately below; body-bearing non-AWS streams
    # fail closed instead of forwarding an uninspected marker upstream.
    if (
        incoming_stream
        and not is_aws_presigned
        and not is_aws_sigv4
        and flow.request.method.upper() not in ("GET", "HEAD")
    ):
        _audit(flow, "inject", "refused", reason="streamed-body-unsupported")
        flow.response = http.Response.make(
            502,
            json.dumps({
                "error": "secret_proxy_streamed_body_unsupported",
                "detail": "streamed request body cannot be inspected safely",
            }).encode(),
            {"content-type": "application/json"},
        )
        return
    must_finish_now = bool(incoming_stream or is_aws_presigned)
    payload_hash = flow.request.headers.get("x-amz-content-sha256")
    # Operations named in the body (awsQuery Action, SSM WithDecryption) need a
    # bounded look at it before the policy can allow them. A small, non-chunked
    # request is left to the buffered hook, which re-signs over the same
    # x-amz-content-sha256. Signed aws-chunked uploads are REST and decided on
    # method, path and headers alone; they are never buffered here.
    defer_for_body = False
    if (
        is_aws_ours
        and payload_hash is not None
        and not incoming_stream
        and not payload_hash.upper().startswith("STREAMING-")
    ):
        try:
            defer_for_body = awsops.classify(_aws_request_view(flow, None)).needs_body
        except Exception:  # noqa: BLE001 - the policy check below denies it
            defer_for_body = False
    if is_aws_sigv4 and payload_hash is not None and not defer_for_body:
        must_finish_now = True

    if must_finish_now:
        # Approvals are collected before any reference is resolved or any AWS
        # credential minted, and before a streaming body starts to flow.
        _collect_streaming_approvals(
            flow, aws=is_aws_ours and payload_hash is not None and not defer_for_body,
        )

    if must_finish_now and _metadata_has_secret_reference(flow):
        try:
            _inject_request_metadata(flow, injected)
        except PolicyViolation as e:
            _set_injection_error(flow, injected, e)
            return
        except Exception as e:  # noqa: BLE001 - fail loudly rather than leak the placeholder
            _set_injection_error(flow, injected, e)
            return
        if injected:
            flow.metadata["secret_proxy_metadata_injected"] = tuple(injected)
            flow.metadata["secret_proxy_metadata_logged"] = True
            log.info(f"secret_proxy: {flow.request.method} {flow.request.host} - injected {', '.join(injected)}")

    if is_aws_presigned:
        try:
            _resign_presigned(flow)
        except Exception as e:  # noqa: BLE001
            _restore_metadata_snapshot(flow)
            _aws_error(flow, e)
        return
    if not is_aws_ours:
        return
    if payload_hash is None or defer_for_body:
        return  # need the body (hash or operation) -> buffered resign in request()
    try:
        res = _aws_resign_apply(flow, None)
    except Exception as e:  # noqa: BLE001
        _restore_metadata_snapshot(flow)
        return _aws_error(flow, e)
    if res is None:
        return
    rf = res["reframer"]
    if rf is not None:
        # mitmproxy calls this with each body chunk, then b"" at end (flush).
        def _modify(data: bytes) -> bytes:
            return rf.feed(data) if data else rf.done()
        flow.request.stream = _modify
    else:
        flow.request.stream = True  # seed already re-signed; stream body unchanged
    log.info(f"secret_proxy: {flow.request.method} {flow.request.host} - AWS re-signed (streaming) as {flow.metadata.get('secret_proxy_aws')} {flow.metadata.get('secret_proxy_aws_operation', '')}")


def _collect_streaming_approvals(flow: http.HTTPFlow, *, aws: bool) -> None:
    """Gate a request that is finished in requestheaders (body not read yet).

    A preflight error is not reported here: the real pass below raises it
    again, so nobody is asked to approve a request that would be refused.
    """
    if _metadata_has_secret_reference(flow):
        try:
            _preflight_request(flow, include_body=False)
        except ApprovalRequired:
            raise
        except Exception:  # noqa: BLE001 - reported by the injection pass
            flow.metadata.pop(APPROVAL_PENDING, None)
            return
    if aws:
        _aws_approval_precheck(flow, None)
    _approval_gate(flow)


def requestheaders(flow: http.HTTPFlow) -> None:
    _run_hook(flow, _requestheaders_locked)


def _resign_aws(flow: http.HTTPFlow) -> None:
    """Buffered AWS re-sign for non-S3 requests (no x-amz-content-sha256; small
    bodies like STS/EC2). S3 + streaming uploads are handled in requestheaders."""
    body = flow.request.raw_content
    try:
        res = _aws_resign_apply(flow, body)
    except Exception as e:  # noqa: BLE001
        return _aws_error(flow, e)
    if res is None:
        return
    if res["reframer"] is not None and body:
        rf = res["reframer"]
        flow.request.raw_content = rf.feed(body) + rf.done()
    log.info(f"secret_proxy: {flow.request.method} {flow.request.host} - AWS re-signed (buffered) as {flow.metadata.get('secret_proxy_aws')} {flow.metadata.get('secret_proxy_aws_operation', '')}")
