"""Strict standalone manifest, 1Password backend and in-memory resolver."""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit
from pathlib import Path
from typing import Mapping, Protocol

import approvals
import audit
from egress import EgressPolicy
import clientgrants


# Validation patterns
CANONICAL_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")
# Lowercase/digit words, each followed by "_" (for example "sk_test_").
REFERENCE_PREFIX_RE = re.compile(r"(?:[a-z0-9]{1,16}_){1,4}")
DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

VALID_VALUE_FIELDS = ("password", "sshPrivateKey")
# Values the proxy itself obtains through a login it owns. They are never read
# from the runtime vault. By default they are held in RAM only and a restart
# requires a new login; an opt-in loginStore (loginstore.py) persists the
# long-lived login tokens in a separate read/write vault.
RUNTIME_ONLY_NAMES = frozenset({"CHATGPT_ACCESS_TOKEN", "GITHUB_COPILOT_SESSION_TOKEN", "GH_CLI_OAUTH_TOKEN"})
# Proxy-owned GitHub logins: the manifest key, its runtimeOnly secret and the
# fields each one accepts.
GITHUB_LOGINS = {
    "copilot": ("GITHUB_COPILOT_SESSION_TOKEN", frozenset({"domain"})),
    "cli": ("GH_CLI_OAUTH_TOKEN", frozenset({"domain", "scopes"})),
}
# The GitHub CLI's own minimum scopes for `gh auth login`.
GH_CLI_DEFAULT_SCOPES = ("repo", "read:org", "gist")
_GITHUB_SCOPE_RE = re.compile(r"[a-z0-9:_-]{1,64}")
_GITHUB_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
ACCOUNT_NAMES = ("runtime",)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


@dataclass
class SecretPlacement:
    """One exact request context in which a secret may be injected."""

    kind: str
    hosts: list[str]
    name: str | None = None
    template: str | None = None
    username: str | None = None
    methods: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    # "prompt": a matching request is held until a person approves it.
    approval: str | None = None


@dataclass(frozen=True)
class PlacementMatch:
    """The placement that decided a request, and whether it needs approval."""

    index: int
    approval: str | None
    # The placement whose approval rule applies, when it isn't *index* (a
    # scoped client granted only a broader placement).
    approval_index: int | None = None

    def rule(self, secret_name: str) -> str:
        index = self.index if self.approval_index is None else self.approval_index
        return f"{secret_name}.placements[{index}]"


@dataclass
class SecretInfo:
    """Metadata about a secret from the manifest."""

    name: str
    account: str
    placements: list[SecretPlacement] = field(default_factory=list)
    internal_only: bool = False
    derived_from: list[str] | None = None
    runtime_only: bool = False
    profiles: list[str] = field(default_factory=list)
    # Literal text a client may write directly before the reference because it
    # validates the key's shape locally (for example "sk_test_" for the Stripe
    # CLI). The proxy replaces the prefix together with the reference.
    reference_prefix: str | None = None
    value_field: str = "password"


class SecretManifest:
    """Loads and validates the canonical secret manifest.

    Usage:
        manifest = SecretManifest.load("secrets.json", env=os.environ)
        manifest.canonical_name("MY_SECRET")
        manifest.placement_allowed(
            "MY_SECRET", kind="header", host="api.example.com", method="GET",
            path="/", name="x-api-key", template="{secret}",
        )
        secret = manifest.secret("MY_SECRET")
    """

    def __init__(
        self,
        provider: str,
        accounts: dict,
        secrets: dict[str, SecretInfo],
    ):
        self._provider = provider
        self._accounts = accounts
        self._secrets = secrets

    @property
    def provider(self) -> str:
        """Return the selected secret provider."""
        return self._provider

    @classmethod
    def load(cls, path: str | Path, env: dict | None = None) -> SecretManifest:
        """Load and validate manifest from path.

        Args:
            path: Path to secrets.json
            env: Environment dict (defaults to empty, requires SECRET_PROVIDER)

        Raises:
            ValueError: On validation errors
            FileNotFoundError: If manifest doesn't exist
        """
        if env is None:
            env = {}

        # No profile/provider selection: the explicit file is the entire policy.
        provider = "1password"
        with open(path) as f:
            data = json.load(f, object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or set(data) - {"schemaVersion", "account", "secrets", "checkmarxRealm", "egress", "githubLogins", "clients", "approvals", "audit", "loginStore"}:
            raise ValueError("invalid manifest root")
        if type(data.get("schemaVersion")) is not int or data["schemaVersion"] != 3:
            raise ValueError("schemaVersion must be exactly integer 3")
        account = data.get("account")
        if not isinstance(account, dict) or set(account) != {"vault"}:
            raise ValueError("account must contain only vault")
        vault = account["vault"]
        if not isinstance(vault, str) or not vault.strip() or any(ord(c) < 32 for c in vault):
            raise ValueError("account.vault must be a nonempty string")
        accounts = {"runtime": {"onepasswordVault": vault}}
        raw_secrets = data.get("secrets")
        if not isinstance(raw_secrets, dict):
            raise ValueError("secrets must be a JSON object")
        realm = data.get("checkmarxRealm")
        if realm is not None and (not isinstance(realm, str) or re.fullmatch(r"[A-Za-z0-9_-]+", realm) is None):
            raise ValueError("invalid checkmarxRealm")
        if "CHECKMARX_ACCESS_TOKEN" in raw_secrets and not realm:
            raise ValueError("checkmarxRealm is required for Checkmarx")
        # Optional; absent means open egress (address checks still apply).
        # Raises EgressConfigError.
        egress = EgressPolicy.from_config(data.get("egress"))
        # Optional approval timing; the default is a 120 s timeout.
        approval_settings = approvals.validate_settings(data.get("approvals"))

        def validate_string_list(
            name: str, field_name: str, value: object, *, nonempty: bool = False
        ) -> list[str]:
            if not isinstance(value, list):
                raise ValueError(
                    f"secrets.{name}.{field_name} must be a list"
                )
            if nonempty and not value:
                raise ValueError(
                    f"secrets.{name}.{field_name} must be a nonempty list"
                )
            if any(not isinstance(item, str) or not item for item in value):
                raise ValueError(
                    f"secrets.{name}.{field_name} must contain nonempty strings"
                )
            return value

        def valid_host_pattern(pattern: str) -> bool:
            # A wildcard is permitted only as an entire DNS label.  In
            # particular, a bare '*' would allow forwarding any destination.
            labels = pattern.split(".")
            if not pattern or pattern == "*" or len(pattern) > 253:
                return False
            if all(label == "*" for label in labels):
                return False
            return all(
                label == "*" or DNS_LABEL_RE.fullmatch(label) is not None
                for label in labels
            )

        # First pass: validate names and build secrets.
        secrets: dict[str, SecretInfo] = {}

        for name, spec in raw_secrets.items():
            if not isinstance(name, str):
                raise ValueError("secrets keys must be canonical name strings")

            # Reject UUID-shaped names first (more specific error).
            if UUID_RE.fullmatch(name):
                raise ValueError(
                    f"UUID-shaped secret name rejected: '{name}'. "
                    "Use a descriptive canonical name instead."
                )

            if CANONICAL_NAME_RE.fullmatch(name) is None:
                raise ValueError(
                    f"Invalid canonical secret name '{name}': "
                    f"must match ^[A-Z][A-Z0-9_]+$"
                )

            if not isinstance(spec, dict):
                raise ValueError(f"secrets.{name} must be an object")

            unknown_fields = set(spec) - {
                "placements", "internalOnly", "derivedFrom",
                "referencePrefix", "runtimeOnly", "valueField",
            }
            if unknown_fields:
                field_name = sorted(unknown_fields)[0]
                raise ValueError(f"secrets.{name}.{field_name} is not supported")

            account = "runtime"
            profiles = []

            has_internal = "internalOnly" in spec
            has_placements = "placements" in spec
            if has_internal == has_placements:
                raise ValueError(
                    f"secrets.{name} must declare exactly one of internalOnly or placements"
                )

            runtime_only = spec.get("runtimeOnly", False)
            if type(runtime_only) is not bool or (runtime_only and name not in RUNTIME_ONLY_NAMES):
                raise ValueError(f"secrets.{name}.runtimeOnly is invalid")
            placements: list[SecretPlacement] = []
            internal_only = False
            if has_internal:
                if spec["internalOnly"] is not True:
                    raise ValueError(f"secrets.{name}.internalOnly must be exactly true")
                internal_only = True
            else:
                raw_placements = spec["placements"]
                if not isinstance(raw_placements, list) or not raw_placements:
                    raise ValueError(f"secrets.{name}.placements must be a nonempty list")

                for index, placement_spec in enumerate(raw_placements):
                    prefix = f"secrets.{name}.placements[{index}]"
                    if not isinstance(placement_spec, dict):
                        raise ValueError(f"{prefix} must be an object")

                    kind = placement_spec.get("kind")
                    if kind not in {
                        "header", "basic-password", "query", "form", "url-rewrite"
                    }:
                        raise ValueError(f"{prefix}.kind is not supported")

                    common_fields = {"kind", "hosts", "methods", "paths", "approval"}
                    kind_fields = {
                        "header": {"name", "template"},
                        "basic-password": {"username"},
                        "query": {"name", "template"},
                        "form": {"name", "template"},
                        "url-rewrite": set(),
                    }[kind]
                    extra_fields = set(placement_spec) - common_fields - kind_fields
                    if extra_fields:
                        field_name = sorted(extra_fields)[0]
                        raise ValueError(f"{prefix}.{field_name} is not supported")

                    hosts = validate_string_list(
                        name, f"placements[{index}].hosts",
                        placement_spec.get("hosts"), nonempty=True,
                    )
                    if len({host.lower() for host in hosts}) != len(hosts):
                        raise ValueError(f"{prefix}.hosts must not contain duplicates")
                    for host_pattern in hosts:
                        if not valid_host_pattern(host_pattern):
                            raise ValueError(f"{prefix}.hosts contains an invalid DNS pattern")

                    methods = validate_string_list(
                        name, f"placements[{index}].methods",
                        placement_spec.get("methods", []),
                    )
                    if len(set(methods)) != len(methods) or any(
                        method != method.upper() or re.fullmatch(r"[A-Z]+", method) is None
                        for method in methods
                    ):
                        raise ValueError(f"{prefix}.methods contains an invalid HTTP method")

                    paths = validate_string_list(
                        name, f"placements[{index}].paths",
                        placement_spec.get("paths", []),
                    )
                    if len(set(paths)) != len(paths):
                        raise ValueError(f"{prefix}.paths must not contain duplicates")
                    for path_pattern in paths:
                        if (
                            not path_pattern.startswith("/")
                            or "?" in path_pattern
                            or "#" in path_pattern
                            or "\\" in path_pattern
                            or path_pattern.count("*") > 1
                            or ("*" in path_pattern and not path_pattern.endswith("*"))
                            or any(part == ".." for part in path_pattern.split("/"))
                        ):
                            raise ValueError(f"{prefix}.paths contains an invalid path pattern")

                    approval = placement_spec.get("approval")
                    if "approval" in placement_spec and approval != "prompt":
                        raise ValueError(f'{prefix}.approval must be "prompt"')

                    placement_name = placement_spec.get("name")
                    template = placement_spec.get("template")
                    username = placement_spec.get("username")

                    if kind in {"header", "query", "form"}:
                        if not isinstance(placement_name, str) or not placement_name:
                            raise ValueError(f"{prefix}.name must be a nonempty string")
                        if kind == "header":
                            if re.fullmatch(r"[A-Za-z0-9-]+", placement_name) is None:
                                raise ValueError(f"{prefix}.name is not a valid header name")
                            placement_name = placement_name.lower()
                        elif re.fullmatch(r"[A-Za-z0-9_.-]+", placement_name) is None:
                            raise ValueError(f"{prefix}.name is not a valid parameter name")

                        if (
                            not isinstance(template, str)
                            or template.count("{secret}") != 1
                            or "{" in template.replace("{secret}", "")
                            or "}" in template.replace("{secret}", "")
                        ):
                            raise ValueError(
                                f"{prefix}.template must contain exactly one {{secret}} placeholder"
                            )
                    else:
                        placement_name = None
                        template = None

                    if kind == "basic-password":
                        if username is not None and (
                            not isinstance(username, str) or not username or ":" in username
                        ):
                            raise ValueError(f"{prefix}.username is invalid")
                    else:
                        username = None

                    placements.append(SecretPlacement(
                        kind=kind,
                        hosts=list(hosts),
                        name=placement_name,
                        template=template,
                        username=username,
                        methods=list(methods),
                        paths=list(paths),
                        approval=approval,
                    ))

            if "derivedFrom" in spec:
                derived_from = validate_string_list(
                    name, "derivedFrom", spec["derivedFrom"], nonempty=True
                )
                for source in derived_from:
                    if CANONICAL_NAME_RE.fullmatch(source) is None:
                        raise ValueError(
                            f"secrets.{name}.derivedFrom must contain canonical names"
                        )
            else:
                derived_from = None

            reference_prefix = spec.get("referencePrefix")
            if reference_prefix is not None:
                if (
                    not isinstance(reference_prefix, str)
                    or REFERENCE_PREFIX_RE.fullmatch(reference_prefix) is None
                ):
                    raise ValueError(
                        f"secrets.{name}.referencePrefix must match "
                        f"{REFERENCE_PREFIX_RE.pattern}"
                    )
                if internal_only:
                    raise ValueError(
                        f"secrets.{name}.referencePrefix requires an injectable secret"
                    )

            value_field = spec.get("valueField", "password")
            if value_field not in VALID_VALUE_FIELDS:
                raise ValueError(
                    f"secrets.{name}.valueField must be one of "
                    f"{', '.join(VALID_VALUE_FIELDS)}"
                )
            if value_field != "password" and (not internal_only or derived_from):
                raise ValueError(
                    f"secrets.{name}.valueField {value_field} requires a stored "
                    "internalOnly secret"
                )

            secrets[name] = SecretInfo(
                name=name,
                account=account,
                placements=placements,
                internal_only=internal_only,
                derived_from=derived_from,
                runtime_only=runtime_only,
                profiles=list(profiles),
                reference_prefix=reference_prefix,
                value_field=value_field,
            )

        # Resolve references only after every canonical name has been checked.
        for name, secret in secrets.items():
            if secret.derived_from is not None:
                for source in secret.derived_from:
                    if source not in secrets:
                        raise ValueError(
                            f"Secret '{name}' derives from unknown secret '{source}'"
                        )

        # Reject cycles before any credential access.
        active, complete = set(), set()
        def visit(name):
            if name in active:
                raise ValueError("cyclic derivedFrom dependency")
            if name in complete:
                return
            active.add(name)
            for source in secrets[name].derived_from or []:
                visit(source)
            active.remove(name)
            complete.add(name)
        for name in secrets:
            visit(name)

        manifest = cls(provider, accounts, secrets)
        manifest.checkmarx_realm = realm
        manifest._egress = egress
        manifest._approval_settings = approval_settings
        manifest.github_logins = _github_logins(data.get("githubLogins"), secrets)
        enabled_logins = [kind for kind, on in (
            ("chatgpt", "CHATGPT_ACCESS_TOKEN" in secrets and secrets["CHATGPT_ACCESS_TOKEN"].runtime_only),
            ("github-copilot", "copilot" in manifest.github_logins),
            ("github", "cli" in manifest.github_logins),
        ) if on]
        # Optional and off by default: None keeps proxy-owned logins in RAM only.
        manifest.login_store = _login_store(data.get("loginStore"), vault, enabled_logins)
        # Optional; absent means one default client with every grant (today's
        # behaviour). Raises ClientConfigError, a ValueError.
        manifest.clients = clientgrants.parse_clients(data.get("clients"), secrets, enabled_logins)
        # Optional and off by default: None means nothing is ever written.
        # Raises AuditConfigError, a ValueError.
        manifest.audit = audit.parse_settings(data.get("audit"), secrets)
        return manifest

    def egress_policy(self) -> EgressPolicy:
        """Return the egress policy; manifest interception hosts are allowed."""
        policy = getattr(self, "_egress", None) or EgressPolicy()
        return policy.with_interception_hosts(self.interception_hosts())

    def approval_settings(self) -> dict:
        """Approval timeout and prompt rate (defaults when the section is absent)."""
        value = getattr(self, "_approval_settings", None)
        return dict(value) if value is not None else approvals.validate_settings(None)

    def uses_approval(self) -> bool:
        """Whether any placement asks for approval (for startup diagnostics)."""
        return any(
            placement.approval is not None
            for secret in self._secrets.values()
            for placement in secret.placements
        )

    def github_login(self, kind: str) -> dict | None:
        """Settings for an enabled proxy-owned GitHub login, or None when off."""
        value = getattr(self, "github_logins", {}).get(kind)
        return dict(value) if value is not None else None

    def login_vault(self) -> str | None:
        """The read/write vault for proxy-owned logins, or None (RAM only)."""
        store = getattr(self, "login_store", None)
        return store["vault"] if store is not None else None

    def canonical_name(self, name: str) -> str:
        """Validate and return a canonical secret name.

        Raises:
            KeyError: If the canonical name is not present.
        """
        if name in self._secrets:
            return name
        raise KeyError(f"Unknown secret: '{name}'")

    @staticmethod
    def _host_matches(pattern: str, host: str) -> bool:
        pattern_parts = pattern.lower().split(".")
        host_parts = host.lower().split(".")
        return len(pattern_parts) == len(host_parts) and all(
            expected == "*" or expected == actual
            for expected, actual in zip(pattern_parts, host_parts)
        )

    @staticmethod
    def _path_matches(patterns: list[str], path: str) -> bool:
        if not patterns:
            return True
        path_only = path.split("?", 1)[0]
        if (
            not path_only.startswith("/")
            or "\\" in path_only
            or "\x00" in path_only
        ):
            return False
        # Reject percent-encodings that could alter path STRUCTURE (an encoded
        # separator, backslash, or NUL) before decoding; then decode the rest so
        # legitimately-encoded segment characters match — e.g. a Bedrock model
        # id's ':' arrives as %3A in /model/<id>/converse-stream. Matching then
        # happens on the decoded path, which is re-validated for traversal.
        lowered = path_only.lower()
        if "%2f" in lowered or "%5c" in lowered or "%00" in lowered:
            return False
        try:
            decoded = unquote(path_only, errors="strict")
        except (UnicodeDecodeError, ValueError):
            return False
        if (
            "\\" in decoded
            or "\x00" in decoded
            or any(part == ".." for part in decoded.split("/"))
        ):
            return False
        return any(
            decoded.startswith(pattern[:-1])
            if pattern.endswith("*")
            else decoded == pattern
            for pattern in patterns
        )

    def interception_hosts(self) -> tuple[str, ...]:
        """Return host patterns that require HTTPS interception.

        Only active, non-internal manifest placements are included. The
        runtime proxy adds its own sentinel and AWS signing hosts separately.
        """
        return tuple(sorted({
            host
            for secret in self._secrets.values()
            if not secret.internal_only
            for placement in secret.placements
            for host in placement.hosts
        }))

    def placement_allowed(
        self,
        secret_name: str,
        *,
        kind: str,
        host: str,
        method: str,
        path: str,
        name: str | None = None,
        template: str | None = None,
        username: str | None = None,
    ) -> bool:
        """Return whether a complete request context matches one placement."""
        return self.match_placement(
            secret_name, kind=kind, host=host, method=method, path=path,
            name=name, template=template, username=username,
        ) is not None

    def match_placement(
        self,
        secret_name: str,
        *,
        kind: str,
        host: str,
        method: str,
        path: str,
        name: str | None = None,
        template: str | None = None,
        username: str | None = None,
        allowed: frozenset | set | None = None,
    ) -> PlacementMatch | None:
        """Return the placement that matches a complete request context.

        *allowed* restricts the candidates to placement indices a scoped
        client is granted. When several placements match, one that requires
        approval wins, so a broader placement without approval cannot bypass
        an approval rule. That holds for scoped clients too: a request that
        matches any approval placement needs approval, even when the client
        is granted only a broader placement without one.
        """
        indices = self.placement_indices(
            secret_name, kind=kind, host=host, method=method, path=path,
            name=name, template=template, username=username,
        )
        placements = self._secrets[secret_name].placements
        approval = next((index for index in indices if placements[index].approval is not None), None)
        if allowed is not None:
            indices = tuple(index for index in indices if index in allowed)
        if not indices:
            return None
        for index in indices:
            if placements[index].approval is not None:
                return PlacementMatch(index, placements[index].approval)
        if approval is not None:
            return PlacementMatch(indices[0], placements[approval].approval, approval)
        return PlacementMatch(indices[0], None)

    def _placement_matches(
        self,
        secret: SecretInfo,
        placement: SecretPlacement,
        *,
        kind: str,
        host: str,
        method: str,
        path: str,
        name: str | None,
        template: str | None,
        username: str | None,
    ) -> bool:
        if secret.internal_only or not isinstance(host, str):
            return False
        method_upper = method.upper() if isinstance(method, str) else ""
        if placement.kind != kind:
            return False
        if not any(self._host_matches(pattern, host) for pattern in placement.hosts):
            return False
        if placement.methods and method_upper not in placement.methods:
            return False
        if not self._path_matches(placement.paths, path):
            return False
        if kind == "header":
            if not isinstance(name, str) or placement.name != name.lower():
                return False
            if placement.template != template:
                return False
        elif kind in {"query", "form"}:
            if placement.name != name or placement.template != template:
                return False
        elif kind == "basic-password":
            if placement.username is not None and placement.username != username:
                return False
        return True

    def placement_indices(
        self,
        secret_name: str,
        *,
        kind: str,
        host: str,
        method: str,
        path: str,
        name: str | None = None,
        template: str | None = None,
        username: str | None = None,
    ) -> tuple[int, ...]:
        """Indices of every placement a complete request context matches.

        Scoped clients may be granted individual placements by index.
        """
        secret = self._secrets.get(secret_name)
        if secret is None:
            raise KeyError(f"Unknown secret: '{secret_name}'")
        return tuple(
            index for index, placement in enumerate(secret.placements)
            if self._placement_matches(
                secret, placement, kind=kind, host=host, method=method, path=path,
                name=name, template=template, username=username,
            )
        )

    def has_placement_kind(self, secret_name: str, kind: str) -> bool:
        """Return whether a non-internal secret declares *kind* at all."""
        secret = self._secrets.get(secret_name)
        if secret is None:
            raise KeyError(f"Unknown secret: '{secret_name}'")
        return not secret.internal_only and any(
            placement.kind == kind for placement in secret.placements
        )

    @staticmethod
    def _copy_placement(placement: SecretPlacement) -> SecretPlacement:
        return SecretPlacement(
            kind=placement.kind,
            hosts=list(placement.hosts),
            name=placement.name,
            template=placement.template,
            username=placement.username,
            methods=list(placement.methods),
            paths=list(placement.paths),
            approval=placement.approval,
        )

    def secret(self, name: str) -> SecretInfo:
        """Get a defensive copy of secret metadata by canonical name."""
        secret = self._secrets.get(name)
        if secret is None:
            raise KeyError(f"Unknown secret: '{name}'")
        return SecretInfo(
            name=secret.name,
            account=secret.account,
            placements=[self._copy_placement(item) for item in secret.placements],
            internal_only=secret.internal_only,
            runtime_only=secret.runtime_only,
            derived_from=(
                None if secret.derived_from is None else list(secret.derived_from)
            ),
            profiles=list(secret.profiles),
            reference_prefix=secret.reference_prefix,
            value_field=secret.value_field,
        )

    def secrets_for_account(self, account_name: str) -> tuple[SecretInfo, ...]:
        """Return all secrets for a configured logical account.

        Results include both stored and derived secrets, ordered by canonical
        secret name.  Each returned ``SecretInfo`` and its list-valued fields
        are defensive copies of the manifest's internal metadata.

        Raises:
            KeyError: If *account_name* is not configured.
        """
        if account_name not in ACCOUNT_NAMES or account_name not in self._accounts:
            raise KeyError(f"Unknown account: '{account_name}'")

        return tuple(
            SecretInfo(
                name=secret.name,
                account=secret.account,
                placements=[
                    self._copy_placement(item) for item in secret.placements
                ],
                internal_only=secret.internal_only,
                runtime_only=secret.runtime_only,
            derived_from=(
                    None
                    if secret.derived_from is None
                    else list(secret.derived_from)
                ),
                profiles=list(secret.profiles),
                reference_prefix=secret.reference_prefix,
                value_field=secret.value_field,
            )
            for name in sorted(self._secrets)
            if (secret := self._secrets[name]).account == account_name
        )

    def account(self, name: str) -> dict:
        """Get runtime account configuration.

        Args:
            name: Account name

        Returns:
            Account configuration dict
        """
        return self._accounts.get(name, {})


class LoginStoreConfigError(ValueError):
    """Invalid ``loginStore`` or a bootstrap that does not match it. Fixed text only."""


def _valid_vault_name(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not any(ord(c) < 32 for c in value)


def _login_store(raw: object, runtime_vault: str, enabled_logins) -> dict | None:
    """Validate ``loginStore``: a separate read/write vault for proxy-owned logins."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {"vault"}:
        raise LoginStoreConfigError("loginStore must contain only vault")
    vault = raw["vault"]
    if not _valid_vault_name(vault):
        raise LoginStoreConfigError("loginStore.vault must be a nonempty string")
    if vault == runtime_vault:
        raise LoginStoreConfigError("loginStore.vault must differ from account.vault, which stays read-only")
    if not enabled_logins:
        raise LoginStoreConfigError("loginStore requires a proxy-owned login (ChatGPT, GitHub Copilot or GitHub CLI)")
    return {"vault": vault}


def check_login_vault(manifest: "SecretManifest", declared: object) -> None:
    """The bootstrap item's declared login vault must match the manifest exactly.

    *declared* is the vault named by the bootstrap item's ``login_vault`` field
    (None when it has none). The service account may only be given write access
    to a vault the manifest uses for logins, and vice versa.
    """
    store = getattr(manifest, "login_store", None)
    expected = store["vault"] if store is not None else None
    if declared != expected:
        if expected is None:
            raise LoginStoreConfigError("the bootstrap declares a login vault but the manifest has no loginStore")
        raise LoginStoreConfigError("the bootstrap item does not declare the manifest's loginStore vault")


def _github_logins(raw: object, secrets: dict) -> dict:
    """Validate ``githubLogins``. A login is on only when its runtimeOnly
    secret is declared; the optional section only adjusts its settings."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict) or set(raw) - set(GITHUB_LOGINS):
        raise ValueError("githubLogins supports only: " + ", ".join(sorted(GITHUB_LOGINS)))
    result = {}
    for kind, (canonical, allowed) in GITHUB_LOGINS.items():
        settings = raw.get(kind, {})
        if not isinstance(settings, dict) or set(settings) - allowed:
            raise ValueError(f"githubLogins.{kind} is invalid")
        info = secrets.get(canonical)
        enabled = bool(info is not None and info.runtime_only)
        if kind in raw and not enabled:
            raise ValueError(f"githubLogins.{kind} requires runtimeOnly secret {canonical}")
        if not enabled:
            continue
        domain = settings.get("domain", "github.com")
        labels = domain.split(".") if isinstance(domain, str) else []
        if (len(labels) < 2 or len(domain) > 253
                or not all(_GITHUB_DOMAIN_LABEL_RE.fullmatch(label) for label in labels)):
            raise ValueError(f"githubLogins.{kind}.domain must be a lowercase host name")
        result[kind] = {"domain": domain}
        if "scopes" in allowed:
            scopes = settings.get("scopes", list(GH_CLI_DEFAULT_SCOPES))
            if (not isinstance(scopes, list) or not 0 < len(scopes) <= 20 or len(set(scopes)) != len(scopes)
                    or not all(isinstance(scope, str) and _GITHUB_SCOPE_RE.fullmatch(scope) for scope in scopes)):
                raise ValueError(f"githubLogins.{kind}.scopes must be unique OAuth scope names")
            result[kind]["scopes"] = tuple(scopes)
    return result


# --- Backends ---


DEFAULT_CLI_PATH = "/usr/local/bin:/usr/bin:/bin"
DEFAULT_CLI_HOME = "/home/secretproxy"
OP_CLI_PATH = "/usr/local/bin/op"
OP_CONFIG_DIR = "/tmp/op-config"
APPROVED_CERT_PATHS = {
    "NODE_EXTRA_CA_CERTS": frozenset(
        {
            "/usr/local/share/ca-certificates/corporate-ca.crt",
            "/usr/local/share/ca-certificates/secret-proxy-ca.crt",
        }
    ),
    "SSL_CERT_FILE": frozenset({"/etc/ssl/certs/ca-certificates.crt"}),
    "SSL_CERT_DIR": frozenset({"/etc/ssl/certs"}),
}
PROXY_ENV_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
NO_PROXY_ENV_NAMES = ("NO_PROXY", "no_proxy")
PROXY_SCHEME_NAMES = frozenset({"http", "https"})
NO_PROXY_SAFE_RE = re.compile(r"^[A-Za-z0-9.*,:_\[\]-]+$")


def _valid_proxy_url(value: object) -> bool:
    """Return whether *value* is an HTTP(S) proxy URL with a hostname."""
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
        return (
            parsed.scheme.lower() in PROXY_SCHEME_NAMES
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and (port is None or 0 < port <= 65535)
            and "\x00" not in value
            and not any(char.isspace() for char in value)
        )
    except ValueError:
        return False


def _valid_no_proxy(value: object) -> bool:
    """Return whether *value* is a comma-separated safe host list."""
    if not isinstance(value, str) or not value or any(
        not entry for entry in value.split(",")
    ):
        return False
    return NO_PROXY_SAFE_RE.fullmatch(value) is not None


def build_cli_env(
    runtime_env: Mapping[str, str] | None,
    *,
    credential_name: str,
    credential: str,
) -> dict[str, str]:
    """Build the fixed, validated environment passed to a provider CLI.

    Only values explicitly approved for subprocess use are copied.  In
    particular, this must not grow into a general environment forwarder:
    provider credentials are added by the caller and all other values are
    either fixed or validated here.
    """
    source = os.environ if runtime_env is None else runtime_env
    cli_env = {
        "PATH": DEFAULT_CLI_PATH,
        "HOME": DEFAULT_CLI_HOME,
    }

    for name, approved_paths in APPROVED_CERT_PATHS.items():
        value = source.get(name)
        if isinstance(value, str) and value in approved_paths:
            cli_env[name] = value

    for name in PROXY_ENV_NAMES:
        value = source.get(name)
        if _valid_proxy_url(value):
            cli_env[name] = value

    for name in NO_PROXY_ENV_NAMES:
        value = source.get(name)
        if _valid_no_proxy(value):
            cli_env[name] = value

    # Only the selected backend credential is exposed to the subprocess.
    cli_env[credential_name] = credential
    return cli_env


class CommandRunner(Protocol):
    """Protocol for subprocess execution, enabling test injection."""

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        input: str | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a command and return CompletedProcess."""
        ...


class DefaultCommandRunner:
    """Default implementation using subprocess.run."""

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        input: str | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            env=env,
            input=input,
            timeout=timeout,
        )


class SecretBackendError(Exception):
    """Error from a secret backend. Must not contain secret values."""

    pass


class OnePasswordBackend:
    """1Password CLI backend using service account tokens.

    Uses OP_SERVICE_ACCOUNT_TOKEN for authentication. Selects vault based
    on the manifest\'s single runtime account.
    """

    def __init__(
        self,
        manifest: SecretManifest,
        token: str,
        runner: CommandRunner | None = None,
        runtime_env: Mapping[str, str] | None = None,
    ):
        self._manifest = manifest
        if not token:
            raise SecretBackendError("1Password service account capability is required")
        self._token = token
        self._runtime_env = dict(os.environ if runtime_env is None else runtime_env)
        self._runner = runner or DefaultCommandRunner()

    def get(self, name: str) -> str:
        """Get secret value by exact item title.

        Args:
            name: Exact item title (canonical secret name)

        Returns:
            The password field value

        Raises:
            SecretBackendError: On lookup failure (never contains secret values)
        """
        # Get secret info to determine account
        try:
            secret_info = self._manifest.secret(name)
        except KeyError:
            raise SecretBackendError(f"Unknown secret '{name}' not in manifest")

        if secret_info.runtime_only or secret_info.derived_from:
            raise SecretBackendError("derived/runtime values cannot be read from the vault")
        vault = self._manifest.account("runtime")["onepasswordVault"]
        token = self._token

        cli_env = build_cli_env(
            self._runtime_env,
            credential_name="OP_SERVICE_ACCOUNT_TOKEN",
            credential=token,
        )
        cli_env["OP_CONFIG_DIR"] = OP_CONFIG_DIR

        # List items in vault - expose only OP_SERVICE_ACCOUNT_TOKEN
        try:
            result = self._runner.run(
                [OP_CLI_PATH, "item", "list", "--vault", vault, "--format=json"],
                env=cli_env,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            raise SecretBackendError(
                f"1Password list timed out for '{name}' in vault '{vault}'"
            )

        if result.returncode != 0:
            raise SecretBackendError(
                f"1Password list failed for '{name}' in vault '{vault}': "
                f"exit code {result.returncode}"
            )

        try:
            items = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise SecretBackendError(
                f"1Password returned invalid JSON for vault '{vault}'"
            )

        # Validate response structure: must be a list
        if not isinstance(items, list):
            raise SecretBackendError(
                f"1Password returned unexpected response structure for '{name}' in vault '{vault}'"
            )

        # Validate every returned item before inspecting any fields.  Provider
        # output is untrusted and malformed elements must not escape as a
        # provider-output-dependent exception.
        if any(not isinstance(item, dict) for item in items):
            raise SecretBackendError(
                f"1Password returned a malformed item for '{name}'"
            )

        # Filter for exact title match
        matches = [item for item in items if item.get("title") == name]

        if not matches:
            raise SecretBackendError(
                f"No 1Password item found with exact title '{name}' in vault '{vault}'"
            )
        if len(matches) > 1:
            raise SecretBackendError(
                f"Multiple 1Password items found with title '{name}' in vault '{vault}': "
                "expected exactly one"
            )

        item_id = matches[0].get("id")
        if not isinstance(item_id, str):
            raise SecretBackendError(f"1Password item '{name}' has an invalid ID")
        if not item_id:
            raise SecretBackendError(f"1Password item '{name}' has no ID")

        value_field = _value_field(self._manifest, name)
        field_label = "private key" if value_field == "sshPrivateKey" else "password"

        # Get the value field by ID
        try:
            result = self._runner.run(
                [
                    OP_CLI_PATH, "item", "get", item_id,
                    "--vault", vault,
                    "--fields", f"label={field_label}",
                    "--format=json",
                    "--reveal",
                ],
                env=cli_env,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            raise SecretBackendError(
                f"1Password item retrieval timed out for '{name}'"
            )

        if result.returncode != 0:
            raise SecretBackendError(
                f"1Password item retrieval failed for '{name}': "
                f"exit code {result.returncode}"
            )

        try:
            field_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise SecretBackendError(
                f"1Password returned invalid JSON for item '{name}'"
            )

        # Validate response structure: must be a dict
        if not isinstance(field_data, dict):
            raise SecretBackendError(
                f"1Password returned unexpected response structure for item '{name}'"
            )

        if value_field == "sshPrivateKey":
            return _onepassword_ssh_private_key(name, field_data)

        # Extract value from field
        password = field_data.get("value", "")
        if not isinstance(password, str):
            raise SecretBackendError(
                f"1Password item '{name}' returned a non-string password"
            )
        if not password:
            raise SecretBackendError(f"1Password item '{name}' has empty password field")

        return password


def _value_field(manifest: SecretManifest | None, name: str) -> str:
    if manifest is None:
        return "password"
    try:
        return manifest.secret(name).value_field
    except KeyError:
        raise SecretBackendError(f"Unknown secret '{name}' not in manifest")


def _checked_private_key(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.startswith(
        "-----BEGIN OPENSSH PRIVATE KEY-----"
    ):
        raise SecretBackendError(
            f"Item '{name}' does not hold an OpenSSH private key"
        )
    return value


def _onepassword_ssh_private_key(name: str, field_data: dict) -> str:
    """Return the OpenSSH form of a 1Password SSH Key item's private key."""
    if field_data.get("type") != "SSHKEY":
        raise SecretBackendError(f"1Password item '{name}' is not an SSH Key item")
    formats = field_data.get("ssh_formats")
    openssh = formats.get("openssh") if isinstance(formats, dict) else None
    value = openssh.get("value") if isinstance(openssh, dict) else None
    return _checked_private_key(name, value)


# --- Resolver with caching ---


@dataclass
class _InflightLookup:
    """Bookkeeping for one backend lookup in one cache generation."""

    epoch: int
    event: threading.Event = field(default_factory=threading.Event)
    value: str | None = None
    error: BaseException | None = None


class SecretResolver:
    """Cached resolver that selects the appropriate backend.

    Usage:
        resolver = SecretResolver.from_environment(manifest, env=os.environ)
        value = resolver.get("MY_SECRET")
    """

    # Static values remain in RAM until explicit clear or process exit.

    def __init__(
        self,
        manifest: SecretManifest,
        backend: OnePasswordBackend,
    ):
        self._manifest = manifest
        self._backend = backend
        self._cache: dict[str, tuple[str, float]] = {}
        self._inflight: dict[str, _InflightLookup] = {}
        self._cache_epoch = 0
        self._lock = threading.RLock()

    @classmethod
    def from_environment(
        cls,
        manifest: SecretManifest,
        env: dict[str, str] | None = None,
        runner: CommandRunner | None = None,
    ) -> SecretResolver:
        """Create a resolver with one scoped runtime service-account capability."""
        env = {} if env is None else env
        backend = OnePasswordBackend(
            manifest, token=env.get("OP_SERVICE_ACCOUNT_TOKEN", ""),
            runner=runner, runtime_env=env,
        )
        return cls(manifest, backend)

    def _finish_lookup(self, name: str, lookup: _InflightLookup, value=None, error=None):
        """Publish one backend lookup result and release all waiters."""
        with self._lock:
            lookup.value = value
            lookup.error = error
            # Only a lookup from the current epoch may repopulate the cache.
            if error is None and lookup.epoch == self._cache_epoch:
                self._cache[name] = (value, time.time())
            if self._inflight.get(name) is lookup:
                del self._inflight[name]
            lookup.event.set()

    def get(self, name: str) -> str:
        """Get secret value by canonical name.

        Static secrets remain cached until clear_cache() or process exit.

        Args:
            name: Canonical secret name

        Returns:
            Secret value

        Raises:
            SecretBackendError: On lookup failure
            KeyError: If name not in manifest
        """
        # Manifest validation is local and does not need the bookkeeping lock.
        self._manifest.secret(name)

        with self._lock:
            cached = self._cache.get(name)
            if cached is not None:
                return cached[0]

            # A clear_cache() advances the epoch. Do not join a lookup from an
            # older epoch: it must not make a post-clear call observe stale
            # data, and its result must not be published into the new cache.
            lookup = self._inflight.get(name)
            if lookup is None or lookup.epoch != self._cache_epoch:
                lookup = _InflightLookup(self._cache_epoch)
                self._inflight[name] = lookup
                owner = True
            else:
                owner = False

        if not owner:
            # Backend I/O happens outside the lock. The owner publishes either
            # a value or an exception before setting the event, so every waiter
            # is released on both success and failure.
            lookup.event.wait()
            if lookup.error is not None:
                raise lookup.error
            return lookup.value  # type: ignore[return-value]

        try:
            value = self._backend.get(name)
        except BaseException as error:
            self._finish_lookup(name, lookup, error=error)
            raise

        self._finish_lookup(name, lookup, value=value)
        return value

    def clear_cache(self) -> None:
        """Clear the secret cache and invalidate in-flight cache publications."""
        with self._lock:
            self._cache.clear()
            self._cache_epoch += 1
