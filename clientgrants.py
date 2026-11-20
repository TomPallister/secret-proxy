"""Scoped proxy clients: names, tokens' user names and grants (issue #2).

An optional manifest ``clients`` section names the processes that may use the
proxy. Each client authenticates with its own token (its name is the proxy-auth
user name) and may use only what it is granted. Without the section there is a
single ``default`` client, user name ``secret-proxy``, with every grant: exactly
the behaviour before clients existed.

Pure and Python 3.9 compatible: the macOS controller imports it (through
secretstore) to read client names before the runtime starts.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Mapping, Optional, Tuple

DEFAULT_CLIENT = "default"
# The default client keeps the historical proxy-auth user name, so existing
# client settings, health checks and published token files are unchanged.
DEFAULT_USERNAME = "secret-proxy"
NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
# The bootstrap bundle is bounded (runtime.MAX_BOOTSTRAP); so is the client list.
MAX_CLIENTS = 16
MAX_AWS_GRANTS = 64

# Proxy-owned login routes a client may drive, by the daily CLI's provider name.
LOGIN_KINDS = ("chatgpt", "github-copilot", "github")

_ACCOUNT_RE = re.compile(r"[0-9]{12}\Z")
_ROLE_RE = re.compile(r"[A-Za-z0-9+=,.@_-]{1,64}\Z")
_SERVICE_GLOB_RE = re.compile(r"[a-z0-9*?-]{1,63}\Z")
_OPERATION_GLOB_RE = re.compile(r"[A-Za-z0-9_*?]{1,128}\Z")


class ClientConfigError(ValueError):
    """Invalid ``clients`` section. Messages contain configuration text only."""


def username(client: str) -> str:
    """The proxy-auth user name a client authenticates with."""
    return DEFAULT_USERNAME if client == DEFAULT_CLIENT else client


def client_for_username(user: object) -> Optional[str]:
    """The client name for an authenticated proxy-auth user name, or None."""
    if user == DEFAULT_USERNAME:
        return DEFAULT_CLIENT
    if isinstance(user, str) and user != DEFAULT_CLIENT and valid_name(user):
        return user
    return None


def valid_name(name: object) -> bool:
    return isinstance(name, str) and NAME_RE.fullmatch(name) is not None and name != DEFAULT_USERNAME


def token_file_name(client: str) -> str:
    """Published token file name: ``proxy-token`` (default) or ``proxy-token.<name>``."""
    if client == DEFAULT_CLIENT:
        return "proxy-token"
    if not valid_name(client):
        raise ClientConfigError("invalid client name")
    return "proxy-token." + client


@dataclass(frozen=True)
class AwsGrant:
    account: str          # 12 digits, or "*"
    role: str             # exact IAM role name, or "*"
    # (service glob, operation glob) pairs; empty means any operation the AWS
    # operation policy allows.
    operations: Tuple[Tuple[str, str], ...] = ()

    def matches_target(self, account: Optional[str], role: Optional[str]) -> bool:
        if account is None or role is None:
            return False
        return (self.account in ("*", account)) and (self.role in ("*", role))

    def allows_operation(self, service: str, operation: str) -> bool:
        if not self.operations:
            return True
        return any(
            fnmatch.fnmatchcase(service.lower(), svc.lower())
            and fnmatch.fnmatchcase(operation.lower(), op.lower())
            for svc, op in self.operations
        )


@dataclass(frozen=True)
class ClientGrant:
    """What one client may do. ``everything`` short-circuits every check."""

    name: str
    everything: bool = False
    # canonical secret -> None (every placement) or a frozenset of placement indices
    secrets: Mapping[str, Optional[FrozenSet[int]]] = field(default_factory=dict)
    aws: Tuple[AwsGrant, ...] = ()
    signing: bool = False
    logins: FrozenSet[str] = frozenset()

    def may_use_secret(self, canonical: str) -> bool:
        return self.everything or canonical in self.secrets

    def granted_placements(self, canonical: str) -> Optional[FrozenSet[int]]:
        """None means every placement; a set restricts to those indices.

        Callers must check :meth:`may_use_secret` first.
        """
        if self.everything:
            return None
        return self.secrets.get(canonical)

    def may_login(self, kind: str) -> bool:
        return self.everything or kind in self.logins

    def may_sign(self) -> bool:
        return self.everything or self.signing

    def aws_grants_for(self, account: Optional[str], role: Optional[str]) -> Tuple[AwsGrant, ...]:
        if self.everything:
            return (AwsGrant("*", "*"),)
        return tuple(g for g in self.aws if g.matches_target(account, role))


# A grant for an unauthenticated or unknown identity: nothing at all.
NO_GRANT = ClientGrant(name="")


class ClientPolicy:
    """The parsed ``clients`` section."""

    def __init__(self, grants: Dict[str, ClientGrant]):
        self._grants = dict(grants)

    def names(self) -> Tuple[str, ...]:
        return tuple(sorted(self._grants))

    def named(self) -> Tuple[str, ...]:
        """Clients other than default, each with its own token."""
        return tuple(name for name in self.names() if name != DEFAULT_CLIENT)

    def get(self, name: Optional[str]) -> ClientGrant:
        if name is None:
            return NO_GRANT
        return self._grants.get(name, NO_GRANT)


def _keys(obj: dict, allowed, where: str) -> None:
    extra = set(obj) - set(allowed)
    if extra:
        raise ClientConfigError(f"{where}.{sorted(extra)[0]} is not supported")


def _secret_grants(raw: object, where: str, secrets: Mapping) -> Dict[str, Optional[FrozenSet[int]]]:
    if not isinstance(raw, dict):
        raise ClientConfigError(f"{where} must be an object of canonical secret names")
    out: Dict[str, Optional[FrozenSet[int]]] = {}
    for name, value in raw.items():
        item = f"{where}.{name}"
        info = secrets.get(name) if isinstance(name, str) else None
        if info is None:
            raise ClientConfigError(f"{item} names an unknown secret")
        if getattr(info, "internal_only", False):
            # Never placed in a request by a client: grant the derived secret instead.
            raise ClientConfigError(f"{item} is internalOnly; grant the secret derived from it")
        if value is True:
            out[name] = None
            continue
        if not isinstance(value, dict) or set(value) != {"placements"}:
            raise ClientConfigError(f"{item} must be true or {{\"placements\": [indices]}}")
        indices = value["placements"]
        count = len(getattr(info, "placements", []) or [])
        if (not isinstance(indices, list) or not indices
                or any(type(index) is not int or not 0 <= index < count for index in indices)
                or len(set(indices)) != len(indices)):
            raise ClientConfigError(
                f"{item}.placements must list unique indices into secrets.{name}.placements"
            )
        out[name] = frozenset(indices)
    return out


def _aws_grants(raw: object, where: str) -> Tuple[AwsGrant, ...]:
    if not isinstance(raw, list) or len(raw) > MAX_AWS_GRANTS:
        raise ClientConfigError(f"{where} must be a list of at most {MAX_AWS_GRANTS} grants")
    out = []
    for index, item in enumerate(raw):
        at = f"{where}[{index}]"
        if not isinstance(item, dict):
            raise ClientConfigError(f"{at} must be an object")
        _keys(item, ("account", "role", "operations", "comment"), at)
        if not {"account", "role"} <= set(item):
            raise ClientConfigError(f"{at} requires account and role")
        account, role = item["account"], item["role"]
        if not isinstance(account, str) or (account != "*" and _ACCOUNT_RE.fullmatch(account) is None):
            raise ClientConfigError(f"{at}.account must be a 12-digit AWS account id or *")
        if not isinstance(role, str) or (role != "*" and _ROLE_RE.fullmatch(role) is None):
            raise ClientConfigError(f"{at}.role must be an exact IAM role name or *")
        if "comment" in item and not isinstance(item["comment"], str):
            raise ClientConfigError(f"{at}.comment must be a string")
        operations = []
        if "operations" in item:
            value = item["operations"]
            if not isinstance(value, list) or not value or len(value) > 256:
                raise ClientConfigError(f"{at}.operations must be a non-empty list")
            for entry in value:
                service, sep, operation = entry.partition(":") if isinstance(entry, str) else ("", "", "")
                if (not sep or _SERVICE_GLOB_RE.fullmatch(service) is None
                        or _OPERATION_GLOB_RE.fullmatch(operation) is None):
                    raise ClientConfigError(f"{at}.operations entries must be service:Operation globs")
                operations.append((service, operation))
        out.append(AwsGrant(account, role, tuple(operations)))
    return tuple(out)


def parse_clients(raw: object, secrets: Mapping, enabled_logins) -> Optional[ClientPolicy]:
    """Validate a manifest ``clients`` section; None when it is absent.

    *secrets* maps canonical names to parsed secret metadata, and
    *enabled_logins* lists the proxy-owned logins this manifest turns on.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict) or not raw:
        raise ClientConfigError("clients must be a non-empty object")
    if DEFAULT_CLIENT not in raw:
        # Explicit, reviewable: the operator decides what the default token may do.
        raise ClientConfigError("clients must declare default (use {\"all\": true} to keep every grant)")
    if len(raw) > MAX_CLIENTS:
        raise ClientConfigError(f"clients supports at most {MAX_CLIENTS} entries")
    enabled = set(enabled_logins)
    grants: Dict[str, ClientGrant] = {}
    for name, spec in raw.items():
        if name != DEFAULT_CLIENT and not valid_name(name):
            raise ClientConfigError(
                "client names must match [a-z][a-z0-9-]{0,31} and must not be secret-proxy"
            )
        where = f"clients.{name}"
        if not isinstance(spec, dict):
            raise ClientConfigError(f"{where} must be an object")
        _keys(spec, ("all", "secrets", "aws", "signing", "logins", "comment"), where)
        if "comment" in spec and not isinstance(spec["comment"], str):
            raise ClientConfigError(f"{where}.comment must be a string")
        if "all" in spec:
            if spec["all"] is not True or set(spec) - {"all", "comment"}:
                raise ClientConfigError(f"{where}.all must be exactly true and used alone")
            grants[name] = ClientGrant(name=name, everything=True)
            continue
        secret_grants = _secret_grants(spec.get("secrets", {}), f"{where}.secrets", secrets)
        aws = _aws_grants(spec.get("aws", []), f"{where}.aws")
        signing = spec.get("signing", False)
        if type(signing) is not bool:
            raise ClientConfigError(f"{where}.signing must be true or false")
        logins = spec.get("logins", [])
        if (not isinstance(logins, list) or len(set(map(str, logins))) != len(logins)
                or any(kind not in LOGIN_KINDS for kind in logins)):
            raise ClientConfigError(f"{where}.logins must list unique values from: " + ", ".join(LOGIN_KINDS))
        for kind in logins:
            if kind not in enabled:
                raise ClientConfigError(f"{where}.logins names {kind}, which this manifest does not enable")
        grants[name] = ClientGrant(
            name=name,
            secrets=secret_grants,
            aws=aws,
            signing=signing,
            logins=frozenset(logins),
        )
    return ClientPolicy(grants)
