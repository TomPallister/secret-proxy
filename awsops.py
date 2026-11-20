"""AWS operation identification and operation policy for re-signed requests.

secret-proxy re-signs AWS requests that carry its dummy credentials with real STS
credentials. Some AWS operations return a credential or secret value in their
response (Secrets Manager GetSecretValue, STS AssumeRole, IAM CreateAccessKey...).
This module decides, from the request alone and BEFORE any credential is minted,
which service and operation a request is, and what the policy says about it.

It is pure: no network, no secrets, no mitmproxy. The addon builds an
``AwsRequest`` from a flow and asks ``classify`` and ``AwsOperationPolicy``.
Other features (scoped clients, approvals) can reuse both questions.

Python 3.9 compatible: the macOS installer imports it to validate configuration.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, unquote_to_bytes

# Decision actions. "approve" holds the request until a person answers; a deny
# rule always wins over it and can never be approved.
ALLOW = "allow"
DENY = "deny"
APPROVE = "approve"
ACTIONS = (ALLOW, DENY, APPROVE)

UNKNOWN = "Unknown"            # missing, malformed, ambiguous or unverifiable
UNCLASSIFIED = "Unclassified"  # well-formed REST request with no named operation

PROTOCOL_JSON = "json"
PROTOCOL_QUERY = "query"
PROTOCOL_RPCV2 = "rpcv2"
PROTOCOL_REST = "rest"
PROTOCOL_UNKNOWN = "unknown"

# Bodies are inspected only up to this size. A larger body that is needed to
# identify the operation makes the operation Unknown.
BODY_LIMIT = 16 * 1024 * 1024  # e.g. SES SendRawEmail (10 MB) uses awsQuery

POLICY_VERSION = 1
CONDITION_WITH_DECRYPTION = "with-decryption"
# The request's target service could not be verified (unreadable credential
# scope, or a scope that does not match the host). Denied for every service.
CONDITION_UNVERIFIED_SERVICE = "unverified-service"
# A rule with this "when" lets the request through and checks the response:
# a decrypted SSM SecureString value in it is refused.
WHEN_SECURE_STRING = "secureStringReturned"
WHENS = (WHEN_SECURE_STRING,)

_SERVICE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_OPERATION_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,127}\Z")
_SERVICE_GLOB_RE = re.compile(r"[a-z0-9*?-]{1,63}\Z")
_OPERATION_GLOB_RE = re.compile(r"[A-Za-z0-9_*?]{1,128}\Z")
_ACCOUNT_RE = re.compile(r"[0-9]{12}\Z")
_ROLE_RE = re.compile(r"[A-Za-z0-9+=,.@_-]{1,64}\Z")
_TARGET_PREFIX_RE = re.compile(r"[A-Za-z0-9_.-]{1,255}\Z")
_DATE_RE = re.compile(r"[0-9]{8}\Z")
_RPCV2_PATH_RE = re.compile(r"(?:^|/)service/([^/]+)/operation/([^/]+)$")
_API_VERSION_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")

# A host label that names the signing service differently.
_HOST_ALIASES = {
    "email": {"ses"},
    "pinpoint": {"mobiletargeting"},
    "queue": {"sqs"},
    "iot": {"iotdata"},
    "marketplace": {"aws-marketplace"},
}

# Services whose dangerous operations are named by an RPC protocol. A request to
# them without an identifiable operation is Unknown, never Unclassified REST.
_OPERATION_REQUIRED = frozenset({
    "sts", "iam", "secretsmanager", "ssm", "kms", "ecr", "ecr-public",
})

_SSM_DECRYPTING = frozenset({
    "getparameter", "getparameters", "getparametersbypath", "getparameterhistory",
})


class AwsPolicyError(ValueError):
    """Invalid AWS operation policy or override configuration (fixed text)."""


@dataclass(frozen=True)
class AwsRequest:
    """The parts of a request needed to identify the AWS operation.

    ``headers`` is every (name, value) pair in wire order, duplicates kept.
    ``body`` is None when the body is not available (streaming).
    ``host`` is the request authority (HTTP/2 has no Host header).
    """

    method: str
    host: str
    path: str
    query: str
    headers: Tuple[Tuple[str, str], ...]
    body: Optional[bytes] = None

    def header_values(self, name: str) -> list:
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]


@dataclass(frozen=True)
class AwsOperation:
    service: str
    operation: str
    protocol: str
    reason: str = ""                 # why Unknown; fixed, secret-free text
    needs_body: bool = False         # identification needed a body it did not have
    conditions: frozenset = field(default_factory=frozenset)

    @property
    def label(self) -> str:
        return f"{self.service}:{self.operation}"


@dataclass(frozen=True)
class Decision:
    action: str            # "allow" | "deny" | "approve"
    reason: str            # fixed text, safe to log and to return
    rule: str = ""         # which rule decided, for logs
    overridden: bool = False
    # Source of a "secureStringReturned" rule: the response must be checked.
    inspect_response: str = ""

    @property
    def allowed(self) -> bool:
        return self.action == ALLOW

    @property
    def needs_approval(self) -> bool:
        return self.action == APPROVE


# --- identification ---------------------------------------------------------


def _unknown(service: str, reason: str, protocol: str = PROTOCOL_UNKNOWN,
             needs_body: bool = False) -> AwsOperation:
    return AwsOperation(service or UNKNOWN, UNKNOWN, protocol, reason, needs_body)


def credential_scope(request: AwsRequest) -> Optional[Tuple[str, str]]:
    """Return (region, service) from the single SigV4 Authorization header.

    Mirrors ``sigv4.parse_authorization`` (which the re-signer uses) so the
    policy and the signature always see the same service, then validates it.
    """
    values = request.header_values("authorization")
    if len(values) != 1:
        return None
    value = values[0]
    if not value.startswith("AWS4-HMAC-SHA256 ") or value.count("Credential=") != 1:
        return None
    try:
        after = value.split(" ", 1)[1]
        parts = {p.split("=", 1)[0].strip(): p.split("=", 1)[1] for p in after.split(", ")}
        _akid, date_stamp, region, service, term = parts["Credential"].split("/")
    except (IndexError, KeyError, ValueError):
        return None
    if (term != "aws4_request" or _DATE_RE.fullmatch(date_stamp) is None
            or _SERVICE_RE.fullmatch(region) is None or _SERVICE_RE.fullmatch(service) is None):
        return None
    return region, service


def _host_labels(host: str) -> Optional[list]:
    host = (host or "").lower().rstrip(".")
    if ":" in host:
        host = host.rsplit(":", 1)[0]
    suffix = ".amazonaws.com"
    if not host.endswith(suffix) or len(host) == len(suffix):
        return None
    labels = host[: -len(suffix)].split(".")
    if any(not label for label in labels):
        return None
    return labels


def service_matches_host(service: str, host: str) -> bool:
    """Check the credential-scope service against the endpoint host."""
    labels = _host_labels(host)
    if labels is None:
        return False
    for label in labels:
        if label == service or label.startswith(service + "-") or label.endswith("-" + service):
            return True
        if service in _HOST_ALIASES.get(label, ()):
            return True
    return False


def _media_type(value: str) -> Tuple[str, dict]:
    parts = value.split(";")
    params = {}
    for part in parts[1:]:
        if "=" in part:
            key, _, val = part.partition("=")
            params[key.strip().lower()] = val.strip().strip('"').lower()
    return parts[0].strip().lower(), params


def _encoded(request: AwsRequest) -> bool:
    values = request.header_values("content-encoding")
    return any(v.strip().lower() not in ("", "identity") for v in values)


def _parse_form(text: str) -> Optional[list]:
    try:
        return parse_qsl(text, keep_blank_values=True, strict_parsing=False,
                         encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None


class _Body:
    """Bounded access to the request body for identification."""

    def __init__(self, request: AwsRequest):
        self.request = request

    def text(self) -> Tuple[Optional[str], str]:
        """Return (text, problem). problem is '' or a fixed reason."""
        body = self.request.body
        if body is None:
            return None, "body unavailable"
        if len(body) > BODY_LIMIT:
            return None, "body over the inspection limit"
        if _encoded(self.request):
            return None, "encoded body"
        try:
            return body.decode("utf-8"), ""
        except UnicodeDecodeError:
            return None, "body is not UTF-8"


def _form_body(request: AwsRequest) -> Tuple[Optional[list], str, bool]:
    """Parse an awsQuery form body. Returns (pairs, problem, needs_body)."""
    types = request.header_values("content-type")
    if len(types) != 1:
        return None, "ambiguous Content-Type", False
    _media, params = _media_type(types[0])
    charset = params.get("charset")
    if charset is not None and charset not in ("utf-8", "utf8"):
        return None, "non-UTF-8 query body", False
    text, problem = _Body(request).text()
    if text is None:
        return None, problem, request.body is None
    pairs = _parse_form(text)
    if pairs is None:
        return None, "malformed query body", False
    return pairs, "", False


def _is_form(request: AwsRequest) -> bool:
    return any(_media_type(v)[0] == "application/x-www-form-urlencoded"
               for v in request.header_values("content-type"))


def _is_amz_json(request: AwsRequest) -> bool:
    return any(_media_type(v)[0] in ("application/x-amz-json-1.0", "application/x-amz-json-1.1")
               for v in request.header_values("content-type"))


def _query_pairs(request: AwsRequest) -> Optional[list]:
    return _parse_form(request.query or "")


def _decoded_segments(path: str) -> Optional[list]:
    """Strictly decode a REST path; None when it is ambiguous."""
    if not path.startswith("/"):
        return None
    raw = path[1:].split("/")
    if raw and raw[-1] == "":
        raw = raw[:-1]  # one trailing slash
    segments = []
    for segment in raw:
        try:
            decoded = unquote_to_bytes(segment).decode("utf-8")
        except UnicodeDecodeError:
            return None
        if decoded in ("", ".", "..") or "/" in decoded or "\\" in decoded:
            return None
        if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
            return None
        segments.append(decoded)
    return segments


def _rest_lambda(method: str, segments: list) -> str:
    if method != "GET" or len(segments) < 2:
        return UNCLASSIFIED
    if _API_VERSION_RE.fullmatch(segments[0]) is None or segments[1].lower() != "functions":
        return UNCLASSIFIED
    rest = [s.lower() for s in segments[2:]]
    if not rest:
        return "ListFunctions"
    if len(rest) == 1:
        return "GetFunction"
    if len(rest) == 2 and rest[1] == "configuration":
        return "GetFunctionConfiguration"
    if len(rest) == 2 and rest[1] == "versions":
        return "ListVersionsByFunction"
    return UNCLASSIFIED


def _rest_codeartifact(method: str, segments: list) -> str:
    lowered = [s.lower() for s in segments]
    if method == "POST" and lowered == ["v1", "authorization-token"]:
        return "GetAuthorizationToken"
    return UNCLASSIFIED


_REST_TABLES = {
    "lambda": _rest_lambda,
    "codeartifact": _rest_codeartifact,
}


def _ssm_with_decryption(protocol: str, request: AwsRequest, params: list) -> bool:
    """True unless the request provably does not ask for decryption."""
    if protocol == PROTOCOL_QUERY:
        values = [v for k, v in params if k.lower() == "withdecryption"]
        return any(v.strip().lower() != "false" for v in values)
    if protocol != PROTOCOL_JSON:
        return True
    text, _problem = _Body(request).text()
    if text is None:
        return True

    def unique(pairs):
        seen = set()
        for key, _value in pairs:
            if key in seen:
                raise ValueError("duplicate key")
            seen.add(key)
        return dict(pairs)

    try:
        document = json.loads(text, object_pairs_hook=unique)
    except ValueError:
        return True
    if not isinstance(document, dict):
        return True
    values = [v for k, v in document.items() if k.lower() == "withdecryption"]
    if not values:
        return False
    return len(values) != 1 or values[0] is not False


def _unverified(service: str, reason: str) -> AwsOperation:
    op = _unknown(service, reason)
    return AwsOperation(op.service, op.operation, op.protocol, op.reason, op.needs_body,
                        frozenset({CONDITION_UNVERIFIED_SERVICE}))


def classify(request: AwsRequest) -> AwsOperation:
    """Identify the service and operation of a dummy-signed AWS request."""
    method = (request.method or "").upper()
    scope = credential_scope(request)
    if scope is None:
        return _unverified(UNKNOWN, "unreadable SigV4 credential scope")
    _region, service = scope
    if not service_matches_host(service, request.host):
        return _unverified(service, "credential scope service does not match the host")

    signals = []  # (protocol, operation or None, reason)
    needs_body = False
    query_params: list = []

    # awsJson: X-Amz-Target.
    targets = request.header_values("x-amz-target")
    if targets:
        if len(targets) != 1:
            signals.append((PROTOCOL_JSON, None, "duplicate X-Amz-Target"))
        else:
            prefix, dot, name = targets[0].strip().rpartition(".")
            if (not dot or _TARGET_PREFIX_RE.fullmatch(prefix) is None
                    or _OPERATION_RE.fullmatch(name) is None):
                signals.append((PROTOCOL_JSON, None, "malformed X-Amz-Target"))
            else:
                signals.append((PROTOCOL_JSON, name, ""))
    elif _is_amz_json(request):
        signals.append((PROTOCOL_JSON, None, "awsJson request without X-Amz-Target"))

    # awsQuery: Action in the URL query and/or a form body.
    url_pairs = _query_pairs(request)
    if url_pairs is None:
        signals.append((PROTOCOL_QUERY, None, "malformed query string"))
        url_pairs = []
    query_params.extend(url_pairs)
    is_form_post = method == "POST" and _is_form(request)
    if is_form_post:
        pairs, problem, missing = _form_body(request)
        if pairs is None:
            needs_body = needs_body or missing
            signals.append((PROTOCOL_QUERY, None, problem))
        else:
            query_params.extend(pairs)
    actions = [v for k, v in query_params if k.lower() == "action"]
    if actions:
        distinct = set(actions)
        if len(distinct) != 1:
            signals.append((PROTOCOL_QUERY, None, "conflicting Action values"))
        elif _OPERATION_RE.fullmatch(actions[0]) is None:
            signals.append((PROTOCOL_QUERY, None, "malformed Action"))
        else:
            signals.append((PROTOCOL_QUERY, actions[0], ""))
    elif (is_form_post and service in _OPERATION_REQUIRED
          and not any(s[0] == PROTOCOL_QUERY for s in signals)):
        signals.append((PROTOCOL_QUERY, None, "awsQuery request without Action"))

    # rpcv2 (Smithy RPC v2 CBOR/JSON).
    smithy = request.header_values("smithy-protocol")
    path_match = None
    try:
        decoded_path = unquote_to_bytes(request.path or "").decode("utf-8")
    except UnicodeDecodeError:
        decoded_path = None
    if decoded_path is not None and "%2f" not in (request.path or "").lower():
        path_match = _RPCV2_PATH_RE.search(decoded_path)
    if smithy or path_match:
        if len(smithy) > 1:
            signals.append((PROTOCOL_RPCV2, None, "duplicate Smithy-Protocol"))
        elif smithy and smithy[0].strip().lower() not in ("rpc-v2-cbor", "rpc-v2-json"):
            signals.append((PROTOCOL_RPCV2, None, "unsupported Smithy-Protocol"))
        elif path_match is None or _OPERATION_RE.fullmatch(path_match.group(2)) is None:
            signals.append((PROTOCOL_RPCV2, None, "malformed rpcv2 operation path"))
        else:
            signals.append((PROTOCOL_RPCV2, path_match.group(2), ""))

    # REST: method + path rules for services where an operation matters.
    table = _REST_TABLES.get(service)
    if table is not None:
        segments = _decoded_segments((request.path or "/"))
        if segments is None:
            signals.append((PROTOCOL_REST, None, "ambiguous REST path"))
        else:
            rest_name = table(method, segments)
            if rest_name != UNCLASSIFIED:
                signals.append((PROTOCOL_REST, rest_name, ""))

    protocols = {s[0] for s in signals}
    if len(protocols) > 1:
        return _unknown(service, "operation fields of more than one protocol",
                        needs_body=needs_body)
    if len(signals) > 1:
        return _unknown(service, "conflicting operation fields", needs_body=needs_body)
    if not signals:
        if service in _OPERATION_REQUIRED:
            return _unknown(service, "no operation identified", PROTOCOL_REST)
        return AwsOperation(service, UNCLASSIFIED, PROTOCOL_REST)

    protocol, name, reason = signals[0]
    if name is None:
        return _unknown(service, reason, protocol, needs_body)
    conditions = set()
    if service == "ssm" and name.lower() in _SSM_DECRYPTING:
        if _ssm_with_decryption(protocol, request, query_params):
            conditions.add(CONDITION_WITH_DECRYPTION)
            if protocol == PROTOCOL_JSON and request.body is None:
                needs_body = True
    return AwsOperation(service, name, protocol, needs_body=needs_body,
                        conditions=frozenset(conditions))


# --- policy -----------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    action: str
    service: str
    operations: Tuple[str, ...]
    condition: Optional[str] = None
    source: str = "built-in"
    when: Optional[str] = None

    def matches(self, op: AwsOperation) -> bool:
        if not fnmatch.fnmatchcase(op.service.lower(), self.service.lower()):
            return False
        if not any(fnmatch.fnmatchcase(op.operation.lower(), p.lower()) for p in self.operations):
            return False
        if self.when == WHEN_SECURE_STRING:
            # Only a decrypting read (or one we could not identify) can return
            # a SecureString in plaintext; otherwise the value is ciphertext.
            return op.operation == UNKNOWN or CONDITION_WITH_DECRYPTION in op.conditions
        return self.condition is None or self.condition in op.conditions


@dataclass(frozen=True)
class Override:
    account: str
    role: str
    service: str
    operations: Tuple[str, ...]

    def matches(self, op: AwsOperation, account: Optional[str], role: Optional[str]) -> bool:
        return (
            account == self.account
            and role == self.role
            and op.service.lower() == self.service
            and any(fnmatch.fnmatchcase(op.operation.lower(), p.lower()) for p in self.operations)
        )

    def describe(self) -> str:
        return f"{self.account}/{self.role} may call {self.service}:{','.join(self.operations)}"


def _builtin(service: str, *operations: str, condition: Optional[str] = None) -> Rule:
    return Rule(DENY, service, tuple(operations), condition, "built-in deny list")


# Built in: only a safety check, not policy. A request whose target service
# can't be verified (its signature's service doesn't match the host) is denied,
# so the proxy never signs for a service other than the one it checked. What to
# block is configured in aws-policy.json; see STARTER_POLICY.
DEFAULT_DENY_RULES: Tuple[Rule, ...] = (
    _builtin("*", UNKNOWN, condition=CONDITION_UNVERIFIED_SERVICE),
)

_SSM_READS = ["GetParameter", "GetParameters", "GetParametersByPath", "GetParameterHistory", UNKNOWN]

# Written by `setup.sh init` and shipped as examples/aws-policy.json.
STARTER_POLICY = {
    "version": 1,
    "rules": [
        {"action": "deny", "service": "secretsmanager",
         "operations": ["GetSecretValue", "BatchGetSecretValue", UNKNOWN],
         "comment": "Secrets Manager values. Unknown: a request whose operation can't be identified."},
        {"action": "deny", "service": "ssm", "operations": _SSM_READS, "when": WHEN_SECURE_STRING,
         "comment": "Parameter Store: the call goes through; a response holding a decrypted "
                    "SecureString is refused. Plain String parameters are unaffected."},
    ],
}


RESPONSE_LIMIT = 4 * 1024 * 1024


def response_has_secure_string(body: bytes) -> bool:
    """True when an SSM JSON response holds a SecureString value.

    Raises ValueError when the body can't be read as JSON: the caller refuses.
    Walks the whole document, so every response shape (Parameter, Parameters,
    history entries) is covered.
    """
    document = json.loads(body.decode("utf-8"))
    stack = [document]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            kind = item.get("Type")
            if isinstance(kind, str) and kind.lower() == "securestring" and "Value" in item:
                return True
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _check_keys(obj: dict, allowed: Iterable[str], where: str) -> None:
    extra = set(obj) - set(allowed)
    if extra:
        raise AwsPolicyError(f"{where}: unsupported field")


def _operation_list(value: object, where: str) -> Tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 256:
        raise AwsPolicyError(f"{where}: operations must be a non-empty list")
    out = []
    for item in value:
        if not isinstance(item, str) or _OPERATION_GLOB_RE.fullmatch(item) is None:
            raise AwsPolicyError(f"{where}: operations entries must be globs over [A-Za-z0-9_*?]")
        out.append(item)
    return tuple(out)


def parse_policy(document: object) -> Tuple[Rule, ...]:
    """Validate an aws-policy.json document and return its rules."""
    if not isinstance(document, dict):
        raise AwsPolicyError("aws-policy.json: expected an object")
    _check_keys(document, ("version", "rules"), "aws-policy.json")
    if document.get("version") != POLICY_VERSION or isinstance(document.get("version"), bool):
        raise AwsPolicyError(f"aws-policy.json: version must be {POLICY_VERSION}")
    rules = document.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 1000:
        raise AwsPolicyError("aws-policy.json: rules must be a list")
    out = []
    for index, rule in enumerate(rules):
        where = f"aws-policy.json rule {index + 1}"
        if not isinstance(rule, dict):
            raise AwsPolicyError(f"{where}: expected an object")
        _check_keys(rule, ("action", "service", "operations", "comment", "when"), where)
        if set(rule) - {"comment", "when"} != {"action", "service", "operations"}:
            raise AwsPolicyError(f"{where}: action, service and operations are required")
        action = rule["action"]
        if action not in ACTIONS:
            raise AwsPolicyError(f"{where}: action must be allow, deny or approve")
        service = rule["service"]
        if not isinstance(service, str) or _SERVICE_GLOB_RE.fullmatch(service) is None:
            raise AwsPolicyError(f"{where}: service must be a glob over [a-z0-9-*?]")
        if "comment" in rule and not isinstance(rule["comment"], str):
            raise AwsPolicyError(f"{where}: comment must be a string")
        when = rule.get("when")
        if when is not None:
            if when not in WHENS:
                raise AwsPolicyError(f"{where}: when must be {WHEN_SECURE_STRING}")
            if action != DENY or service != "ssm":
                raise AwsPolicyError(f"{where}: when {WHEN_SECURE_STRING} needs action deny and service ssm")
        out.append(Rule(action, service, _operation_list(rule["operations"], where), None, where, when))
    return tuple(out)


def parse_overrides(value: object) -> Tuple[Override, ...]:
    """Validate aws-okta.json ``operation_overrides``."""
    if not isinstance(value, list) or len(value) > 256:
        raise AwsPolicyError("operation_overrides: expected a list")
    out = []
    for index, item in enumerate(value):
        where = f"operation_overrides entry {index + 1}"
        if not isinstance(item, dict):
            raise AwsPolicyError(f"{where}: expected an object")
        _check_keys(item, ("account", "role", "service", "operations", "comment"), where)
        if set(item) - {"comment"} != {"account", "role", "service", "operations"}:
            raise AwsPolicyError(f"{where}: account, role, service and operations are required")
        account, role, service = item["account"], item["role"], item["service"]
        if not isinstance(account, str) or _ACCOUNT_RE.fullmatch(account) is None:
            raise AwsPolicyError(f"{where}: account must be a 12-digit AWS account id")
        if not isinstance(role, str) or _ROLE_RE.fullmatch(role) is None:
            raise AwsPolicyError(f"{where}: role must be an exact IAM role name")
        if not isinstance(service, str) or _SERVICE_RE.fullmatch(service) is None:
            raise AwsPolicyError(f"{where}: service must be an exact AWS signing service name")
        if "comment" in item and not isinstance(item["comment"], str):
            raise AwsPolicyError(f"{where}: comment must be a string")
        out.append(Override(account, role, service, _operation_list(item["operations"], where)))
    return tuple(out)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AwsPolicyError("aws-policy.json: duplicate key")
        result[key] = value
    return result


def load_policy_bytes(data: bytes) -> Tuple[Rule, ...]:
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except AwsPolicyError:
        raise
    except (UnicodeDecodeError, ValueError):
        raise AwsPolicyError("aws-policy.json: invalid JSON") from None
    return parse_policy(document)


class AwsOperationPolicy:
    """Built-in safety rule + aws-policy.json rules + per-role overrides.

    Order: a matching deny rule denies (the built-in unverified-service rule
    always applies); a matching override for the exact account and role then
    allows it. A matching approve rule then asks a person, so a deny rule
    can never be approved but an overridden operation can still require
    approval. Otherwise, when allow rules exist for the service, the operation
    must match one of them. Everything else is allowed. A matching
    "secureStringReturned" rule does not deny the request: it marks the
    decision so the response is checked (skipped for an exact role override).
    """

    def __init__(self, rules: Sequence[Rule] = (), overrides: Sequence[Override] = ()):
        self.rules = tuple(DEFAULT_DENY_RULES) + tuple(rules)
        self.overrides = tuple(overrides)

    def evaluate(self, op: AwsOperation, account: Optional[str] = None,
                 role: Optional[str] = None) -> Decision:
        decision = self._evaluate_request(op, account, role)
        if decision.action == DENY or decision.overridden:
            return decision
        if any(o.matches(op, account, role) for o in self.overrides):
            return decision  # an exact role override also skips the response check
        check = next((r for r in self.rules if r.when == WHEN_SECURE_STRING and r.matches(op)), None)
        if check is None:
            return decision
        return Decision(decision.action, decision.reason, decision.rule, False, check.source)

    def _evaluate_request(self, op: AwsOperation, account: Optional[str],
                          role: Optional[str]) -> Decision:
        override = next((o for o in self.overrides if o.matches(op, account, role)), None)
        deny = next((r for r in self.rules if r.action == DENY and r.when is None and r.matches(op)), None)
        approve = next((r for r in self.rules if r.action == APPROVE and r.matches(op)), None)
        if deny is not None:
            if override is not None:
                if approve is not None:
                    return Decision(APPROVE, "the operation requires approval", approve.source, True)
                return Decision(ALLOW, "explicit role override", "operation_overrides", True)
            if op.operation == UNKNOWN:
                reason = f"the operation could not be identified safely ({op.reason or 'unknown'})"
            else:
                reason = f"the operation is denied by {deny.source}"
            return Decision(DENY, reason, deny.source)
        if approve is not None:
            return Decision(APPROVE, "the operation requires approval", approve.source)
        allows = [r for r in self.rules if r.action == ALLOW
                  and fnmatch.fnmatchcase(op.service.lower(), r.service.lower())]
        if allows:
            match = next((r for r in allows if r.matches(op)), None)
            if match is not None:
                return Decision(ALLOW, "allowed by policy", match.source)
            if override is not None:
                return Decision(ALLOW, "explicit role override", "operation_overrides", True)
            return Decision(DENY, "the operation is not in the service's allow list in aws-policy.json",
                            "aws-policy.json allow list")
        return Decision(ALLOW, "not denied", "default")
