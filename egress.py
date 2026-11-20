"""Egress policy: destination address refusal and optional host allow/deny lists.

Pure module (no mitmproxy import) so it can be validated by the macOS installer
on Command Line Tools Python 3.9 and unit-tested with a fake resolver.

Two independent checks decide whether the proxy may open an upstream
connection for a client:

* **Addresses** (always on). Every address a destination resolves to is
  checked. Loopback, link-local, unspecified, multicast, reserved and known
  cloud-metadata addresses are always refused. Private and other
  special-purpose ranges are refused unless an explicit CIDR allows them.
  IPv4-mapped, IPv4-compatible and NAT64 well-known-prefix IPv6 addresses are
  unwrapped and checked as IPv4.
* **Host names** (optional ``egress`` manifest section). ``deny`` patterns are
  checked first in every mode; in ``allowlist`` mode a host must be a manifest
  interception host or match an ``allow`` pattern.

The caller connects only to addresses returned by :meth:`EgressPolicy.check`,
so a second DNS answer (rebinding) can never select an unchecked address.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Sequence, Tuple, Union

SENTINEL_HOST = "secret" + "ref.invalid"

MODES = ("open", "allowlist")
ALLOWLIST_MISS = ("deny", "approve")
# The rule named when an allowlist miss is held for approval (issue #3).
APPROVAL_RULE = "egress-allowlist"
MAX_PATTERNS = 256
MAX_CIDRS = 64
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_HOST_RE = re.compile(r"^[0-9a-fA-FxX.]+$")

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Resolver = Callable[[str, int], Sequence[str]]

# Names that reach instance metadata services without a visible IP literal.
METADATA_HOSTS = frozenset({
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "metadata.azure.internal",
    "metadata.platformequinix.com",
    "metadata.packet.net",
})


def _nets(*cidrs: str) -> Tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(cidr) for cidr in cidrs)


# Checked in this order; the first match names the refusal rule.
_ALWAYS_DENY = (
    # Specific metadata endpoints first so they keep their precise rule name,
    # and so an allowed private CIDR (fc00::/7, 100.64.0.0/10) cannot open them.
    ("metadata-address", _nets("169.254.169.254/32", "169.254.170.2/32",
                               "fd00:ec2::254/128", "100.100.100.200/32")),
    ("unspecified-address", _nets("0.0.0.0/8", "::/128")),
    ("loopback-address", _nets("127.0.0.0/8", "::1/128")),
    ("link-local-address", _nets("169.254.0.0/16", "fe80::/10")),
    ("multicast-address", _nets("224.0.0.0/4", "ff00::/8")),
    ("reserved-address", _nets("240.0.0.0/4")),
)

# Refused unless an explicit allowPrivateCidrs entry contains the address.
_CONFIGURABLE_DENY = (
    ("private-address", _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                              "100.64.0.0/10", "fc00::/7", "fec0::/10")),
    ("special-purpose-address", _nets(
        "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "100::/64", "2001::/32", "2001:db8::/32",
        "2002::/16", "64:ff9b:1::/48",
    )),
)

# IPv6 forms that carry an IPv4 address. They are unwrapped before checking,
# so a CIDR written in these forms would never match anything.
_EMBEDDED_V4 = _nets("::ffff:0:0/96", "::/96", "64:ff9b::/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_COMPAT = ipaddress.ip_network("::/96")


class EgressConfigError(ValueError):
    """Invalid egress configuration. Messages contain only configuration text."""


@dataclass(frozen=True)
class Refusal:
    rule: str
    # 403 for a policy refusal; 502 when the name did not resolve.
    status: int = 403


@dataclass(frozen=True)
class Allowed:
    addresses: Tuple[str, ...]
    # Set when the addresses passed but the host itself needs a person's
    # approval (an allowlist miss with allowlistMiss "approve").
    approval: Optional[str] = None


Decision = Union[Allowed, Refusal]
UNRESOLVED = Refusal("unresolved", 502)


def unwrap(address: IPAddress) -> IPAddress:
    """Return the IPv4 address embedded in an IPv6 address, if any."""
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        packed = int(address)
        if address in _NAT64:
            return ipaddress.IPv4Address(packed & 0xFFFFFFFF)
        # IPv4-compatible (::a.b.c.d, deprecated); :: and ::1 stay IPv6.
        if address in _COMPAT and packed > 1:
            return ipaddress.IPv4Address(packed & 0xFFFFFFFF)
    return address


def parse_address(text: str) -> Optional[IPAddress]:
    """Parse an IP literal (with optional IPv6 zone); None for a host name."""
    candidate = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    if "%" in candidate:
        try:
            return ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError:
            return None
    # Legacy numeric IPv4 forms ("2130706433", "0x7f.1") that resolvers accept.
    if _NUMERIC_HOST_RE.fullmatch(candidate) and any(c.isdigit() for c in candidate):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(candidate))
        except (OSError, ValueError):
            return None
    return None


def normalize_host(host: object) -> Optional[str]:
    """Lower-case a destination host; None when it cannot be a valid host."""
    if not isinstance(host, str):
        return None
    value = host.lower()
    if value.endswith("."):
        value = value[:-1]  # one absolute-name dot; "a.." stays invalid
    if not value or len(value) > 253:
        return None
    if any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in value):
        return None
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    address = parse_address(value)
    if address is not None:
        return str(address)
    if any(not label for label in value.split(".")):
        return None
    return value


def address_refusal(text: str, allowed: Iterable[IPNetwork] = ()) -> Optional[str]:
    """Return the refusal rule for one resolved address, or None if allowed."""
    try:
        address = parse_address(text)
    except ValueError:
        address = None
    if address is None:
        return "invalid-address"
    address = unwrap(address)
    for rule, networks in _ALWAYS_DENY:
        if any(address in network for network in networks if network.version == address.version):
            return rule
    for rule, networks in _CONFIGURABLE_DENY:
        if any(address in network for network in networks if network.version == address.version):
            if any(address in network for network in allowed if network.version == address.version):
                return None
            return rule
    return None


class HostPattern:
    """A host pattern for the egress allow and deny lists.

    ``*.example.com`` matches one or more labels before ``example.com`` (not
    ``example.com`` itself). A ``*`` label anywhere else matches exactly one
    label. IP literals match only the same address. Partial-label wildcards
    such as ``api*.example.com`` are rejected.
    """

    def __init__(self, text: object, *, where: str):
        if not isinstance(text, str) or not text:
            raise EgressConfigError(f"{where} must contain nonempty strings")
        value = text.strip().lower()
        if value != text.lower():
            raise EgressConfigError(f"{where}: pattern {text!r} has surrounding spaces")
        if value.endswith("."):
            value = value[:-1]
        if not value or len(value) > 253:
            raise EgressConfigError(f"{where}: invalid pattern {text!r}")
        self.text = text
        self.address = None
        try:
            literal = ipaddress.ip_address(value)
        except ValueError:
            literal = None
        if literal is not None:
            self.address = str(literal)
            self.labels: Tuple[str, ...] = ()
            return
        labels = tuple(value.split("."))
        for label in labels:
            if "*" in label and label != "*":
                raise EgressConfigError(
                    f"{where}: partial-label wildcard in {text!r}; use a whole '*' label"
                )
            if label != "*" and _LABEL_RE.fullmatch(label) is None:
                raise EgressConfigError(f"{where}: invalid host label in {text!r}")
        if all(label == "*" for label in labels):
            raise EgressConfigError(
                f"{where}: {text!r} would match every host; use mode \"open\" instead"
            )
        self.labels = labels

    def matches(self, host: str) -> bool:
        """Match a host already passed through :func:`normalize_host`."""
        if self.address is not None:
            return host == self.address
        if parse_address(host) is not None:
            return False
        parts = host.split(".")
        if self.labels[0] == "*":
            suffix = self.labels[1:]
            if len(parts) < len(suffix) + 1:
                return False
            tail = parts[len(parts) - len(suffix):] if suffix else []
        else:
            suffix = self.labels
            if len(parts) != len(suffix):
                return False
            tail = parts
        return all(expected == "*" or expected == actual
                   for expected, actual in zip(suffix, tail))

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"HostPattern({self.text!r})"


def _manifest_host_matches(pattern: str, host: str) -> bool:
    """Manifest semantics: every ``*`` is exactly one whole label."""
    expected, actual = pattern.lower().split("."), host.split(".")
    return len(expected) == len(actual) and all(
        left == "*" or left == right for left, right in zip(expected, actual)
    )


def _cidr(text: object, where: str) -> IPNetwork:
    if not isinstance(text, str) or not text:
        raise EgressConfigError(f"{where} must contain CIDR strings")
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise EgressConfigError(f"{where}: {text!r} is not a CIDR without host bits") from None
    if any(network.version == embedded.version and network.overlaps(embedded)
           for embedded in _EMBEDDED_V4):
        raise EgressConfigError(f"{where}: {text!r} uses an IPv4-in-IPv6 form; write the IPv4 CIDR")
    for rule, networks in _ALWAYS_DENY:
        if rule == "metadata-address":
            continue  # still refused inside an allowed CIDR; checked first
        if any(network.version == other.version and network.overlaps(other) for other in networks):
            raise EgressConfigError(f"{where}: {text!r} overlaps {rule} ranges, which cannot be allowed")
    if not any(network.version == other.version and network.overlaps(other)
               for _, networks in _CONFIGURABLE_DENY for other in networks):
        raise EgressConfigError(f"{where}: {text!r} contains no private or special-purpose addresses")
    return network


class EgressPolicy:
    """Validated egress configuration plus the proxy's interception hosts."""

    def __init__(self, mode: str = "open", allow: Sequence[HostPattern] = (),
                 deny: Sequence[HostPattern] = (), allowed_cidrs: Sequence[IPNetwork] = (),
                 interception_hosts: Sequence[str] = (), allowlist_miss: str = "deny"):
        self.mode = mode
        self.allowlist_miss = allowlist_miss
        self.allow = tuple(allow)
        self.deny = tuple(deny)
        self.allowed_cidrs = tuple(allowed_cidrs)
        self.interception_hosts = tuple(interception_hosts)

    @classmethod
    def from_config(cls, value: object) -> "EgressPolicy":
        """Validate the manifest ``egress`` section (None = today's open default)."""
        if value is None:
            return cls()
        if not isinstance(value, dict):
            raise EgressConfigError("egress must be a JSON object")
        unknown = set(value) - {"mode", "allow", "deny", "allowPrivateCidrs", "allowlistMiss"}
        if unknown:
            raise EgressConfigError("egress has unknown fields: " + ", ".join(sorted(map(str, unknown))))
        mode = value.get("mode", "open")
        if mode not in MODES:
            raise EgressConfigError('egress.mode must be "open" or "allowlist"')
        miss = value.get("allowlistMiss", "deny")
        if miss not in ALLOWLIST_MISS:
            raise EgressConfigError('egress.allowlistMiss must be "deny" or "approve"')
        if mode == "open" and "allowlistMiss" in value:
            raise EgressConfigError('egress.allowlistMiss has no effect in mode "open"; set mode "allowlist"')

        def patterns(field: str):
            raw = value.get(field, [])
            if not isinstance(raw, list):
                raise EgressConfigError(f"egress.{field} must be a list")
            if len(raw) > MAX_PATTERNS:
                raise EgressConfigError(f"egress.{field} has more than {MAX_PATTERNS} patterns")
            parsed = [HostPattern(item, where=f"egress.{field}") for item in raw]
            keys = [item.address or ".".join(item.labels) for item in parsed]
            if len(set(keys)) != len(keys):
                raise EgressConfigError(f"egress.{field} contains duplicate patterns")
            return parsed

        allow, deny = patterns("allow"), patterns("deny")
        if mode == "open" and allow:
            raise EgressConfigError('egress.allow has no effect in mode "open"; set mode "allowlist"')
        raw_cidrs = value.get("allowPrivateCidrs", [])
        if not isinstance(raw_cidrs, list):
            raise EgressConfigError("egress.allowPrivateCidrs must be a list")
        if len(raw_cidrs) > MAX_CIDRS:
            raise EgressConfigError(f"egress.allowPrivateCidrs has more than {MAX_CIDRS} entries")
        cidrs = [_cidr(item, "egress.allowPrivateCidrs") for item in raw_cidrs]
        if len(set(cidrs)) != len(cidrs):
            raise EgressConfigError("egress.allowPrivateCidrs contains duplicates")
        return cls(mode, allow, deny, cidrs, allowlist_miss=miss)

    def with_interception_hosts(self, hosts: Iterable[str]) -> "EgressPolicy":
        return EgressPolicy(self.mode, self.allow, self.deny, self.allowed_cidrs, tuple(hosts),
                            self.allowlist_miss)

    # -- host-name decision -------------------------------------------------
    def host_refusal(self, host: str) -> Optional[str]:
        """Return the refusal rule for a normalized host name, or None."""
        if host == SENTINEL_HOST:
            return "sentinel-upstream"
        if host in METADATA_HOSTS:
            return "metadata-host"
        if any(pattern.matches(host) for pattern in self.deny):
            return "egress-deny"
        if self.mode == "open":
            return None
        if any(_manifest_host_matches(pattern, host) for pattern in self.interception_hosts):
            return None
        if any(pattern.matches(host) for pattern in self.allow):
            return None
        return self._allowlist_miss(host)

    def _allowlist_miss(self, host: str) -> Optional[str]:
        # Always a refusal rule: with allowlistMiss "approve", check() turns
        # this one rule into an approval after the addresses have passed.
        return APPROVAL_RULE

    def approval_rule(self, host: str) -> Optional[str]:
        """The rule needing approval for a normalized host, or None."""
        if self.allowlist_miss != "approve":
            return None
        return APPROVAL_RULE if self.host_refusal(host) == APPROVAL_RULE else None

    # -- full decision ------------------------------------------------------
    def check(self, host: object, port: int, resolver: Resolver) -> Decision:
        """Decide one destination, resolving it at most once.

        Returns the checked addresses, in resolver order, that the caller must
        connect to. Any refused address refuses the whole destination.
        """
        normalized = normalize_host(host)
        if normalized is None:
            return Refusal("invalid-host")
        literal = parse_address(normalized) is not None
        if literal:
            # A refused address names its address rule in every mode.
            rule = address_refusal(normalized, self.allowed_cidrs)
            if rule is not None:
                return Refusal(rule)
        rule = self.host_refusal(normalized)
        approval = None
        if rule == APPROVAL_RULE and self.allowlist_miss == "approve":
            # Deny lists, metadata names and address rules were checked first
            # and still refuse; only a plain allowlist miss can be approved.
            approval, rule = rule, None
        if rule is not None:
            return Refusal(rule)
        if literal:
            addresses = [normalized]
        else:
            try:
                addresses = list(resolver(normalized, port))
            except (OSError, UnicodeError, ValueError):
                return UNRESOLVED
        checked = []
        for address in addresses:
            rule = address_refusal(address, self.allowed_cidrs) if isinstance(address, str) else "invalid-address"
            if rule is not None:
                return Refusal(rule)
            if address not in checked:
                checked.append(address)
        if not checked:
            return UNRESOLVED
        return Allowed(tuple(checked), approval)


def system_resolver(host: str, port: int) -> Sequence[str]:
    """Resolve once with the system resolver, preserving its address order."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos if info[0] in (socket.AF_INET, socket.AF_INET6)]
