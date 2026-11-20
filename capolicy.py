"""Name-constrained proxy CA policy, shared by the runtime and the macOS CLI.

Standard library only and Python 3.9 compatible: the daily macOS CLI imports
this module with Command Line Tools Python. The container runtime generates
certificates in ``constrainedca.py``; this module decides WHICH names a
constrained CA may cover and checks a public certificate before trust.

A dNSName name constraint permits a domain and every name below it. Manifest
wildcards may appear in any label, so a constraint can only express the fixed
suffix after the last wildcard label: ``bedrock-runtime.*.amazonaws.com``
needs ``amazonaws.com``. A suffix with fewer than two labels is refused rather
than permitting a whole top-level domain. Every IPv4 and IPv6 address is
excluded: name constraints only restrict name forms that they mention, so
without an explicit exclusion a leaf with an IP address SAN would be valid.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

CONFIG_NAME = 'ca.json'
MODE = 'name-constrained'
LABEL_RE = re.compile(r'[a-z][a-z0-9-]{0,30}')
CN_PREFIX = 'secret-proxy name-constrained CA '
SENTINEL_HOST = 'secret' + 'ref.invalid'
AWS_PATTERN = '*.amazonaws.com'
CHATGPT_AUTH_HOST = 'auth.openai.com'
MAX_CONFIG = 4096
_DNS_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
# iPAddress subtree encodings: address followed by mask (RFC 5280 4.2.1.10).
EXCLUDED_ADDRESS_RANGES = (bytes(8), bytes(32))  # 0.0.0.0/0 and ::/0

_OID_CN = bytes.fromhex('550403')
_OID_BASIC_CONSTRAINTS = bytes.fromhex('551d13')
_OID_NAME_CONSTRAINTS = bytes.fromhex('551d1e')


class CAPolicyError(ValueError):
    """A safe, credential-free message about CA policy."""


def common_name(label: str) -> str:
    if not isinstance(label, str) or LABEL_RE.fullmatch(label) is None:
        raise CAPolicyError('Invalid CA label; expected the instance name')
    return CN_PREFIX + label


def parse_config(data: bytes) -> bool:
    """Return True for an explicit opt-in. Anything unexpected is refused."""
    if len(data) > MAX_CONFIG:
        raise CAPolicyError('ca.json is too large')
    try:
        value = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise CAPolicyError('ca.json is not valid JSON') from None
    if value != {'mode': MODE}:
        raise CAPolicyError('ca.json must be exactly {"mode": "name-constrained"}')
    return True


def interception_patterns(manifest, aws: bool) -> list:
    """Host patterns the proxy intercepts (mirrors entry._allow_hosts)."""
    patterns = list(manifest.interception_hosts())
    patterns.append(SENTINEL_HOST)
    if aws:
        patterns.append(AWS_PATTERN)
    try:
        manifest.secret('CHATGPT_ACCESS_TOKEN')
    except KeyError:
        pass
    else:
        patterns.append(CHATGPT_AUTH_HOST)
    # Proxy-owned GitHub logins intercept the login domain and, for Copilot,
    # the API host serving the token exchange.
    github_login = getattr(manifest, 'github_login', None)
    for kind in ('copilot', 'cli'):
        settings = github_login(kind) if github_login else None
        if settings is not None:
            patterns.append(settings['domain'])
            if kind == 'copilot':
                patterns.append('api.' + settings['domain'])
    return list(dict.fromkeys(patterns))


def permitted_domains(patterns) -> list:
    """Return the minimal sorted dNSName subtrees covering every pattern."""
    domains = set()
    for pattern in patterns:
        if not isinstance(pattern, str):
            raise CAPolicyError('Invalid interception host pattern')
        labels = pattern.lower().split('.')
        wildcards = [index for index, label in enumerate(labels) if label == '*']
        suffix = labels[wildcards[-1] + 1:] if wildcards else labels
        if len(suffix) < 2 or any(_DNS_LABEL.fullmatch(label) is None for label in suffix):
            raise CAPolicyError('Host pattern ' + repr(pattern) + ' has no fixed suffix of at '
                                'least two labels; a name-constrained CA cannot cover it narrowly')
        domains.add('.'.join(suffix))
    if not domains:
        raise CAPolicyError('No interception hosts; nothing to constrain')
    return sorted(domain for domain in domains
                  if not any(domain != other and domain.endswith('.' + other) for other in domains))


def name_permitted(name: str, domains) -> bool:
    name = name.lower().rstrip('.')
    return any(name == domain or name.endswith('.' + domain) for domain in domains)


# --- Minimal DER reader for public certificates (no third-party packages). ---

def _tlv(data: bytes, offset: int):
    if offset + 2 > len(data):
        raise CAPolicyError('Truncated certificate')
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7f
        if count == 0 or count > 4 or offset + count > len(data):
            raise CAPolicyError('Invalid certificate length')
        length = int.from_bytes(data[offset:offset + count], 'big')
        offset += count
    end = offset + length
    if end > len(data):
        raise CAPolicyError('Truncated certificate')
    return tag, data[offset:end], end


def _children(data: bytes) -> list:
    items, offset = [], 0
    while offset < len(data):
        tag, value, offset = _tlv(data, offset)
        items.append((tag, value))
    return items


def pem_certificates(data: bytes) -> list:
    blocks = re.findall(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----', data, re.S)
    try:
        return [base64.b64decode(b''.join(block.split()), validate=True) for block in blocks]
    except ValueError:
        raise CAPolicyError('Invalid PEM certificate') from None


def _common_name(name: bytes):
    for _, rdn in _children(name):
        for _, attribute in _children(rdn):
            parts = _children(attribute)
            if len(parts) == 2 and parts[0] == (0x06, _OID_CN):
                return parts[1][1].decode('utf-8', 'strict')
    return None


def _subtrees(data: bytes) -> list:
    result = []
    for tag, subtree in _children(data):
        fields = _children(subtree) if tag == 0x30 else []
        if len(fields) != 1:  # minimum/maximum are not used by this project
            raise CAPolicyError('Unsupported name constraint subtree')
        result.append(fields[0])
    return result


def certificate_info(der: bytes) -> dict:
    """Parse the fields trust decisions need. Raises CAPolicyError when malformed."""
    tag, certificate, end = _tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise CAPolicyError('Invalid certificate')
    parts = _children(certificate)
    if len(parts) != 3 or parts[0][0] != 0x30:
        raise CAPolicyError('Invalid certificate')
    tbs = _children(parts[0][1])
    if tbs and tbs[0][0] == 0xa0:
        tbs = tbs[1:]
    if len(tbs) < 6:
        raise CAPolicyError('Invalid certificate')
    issuer, subject = tbs[2][1], tbs[4][1]
    info = {'sha1': hashlib.sha1(der).hexdigest().upper(), 'commonName': _common_name(subject),
            'selfIssued': issuer == subject, 'ca': False, 'nameConstraints': None}
    extensions = [value for tag, value in tbs[6:] if tag == 0xa3]
    seen = set()
    for wrapper in extensions:
        for _, extension in _children(_children(wrapper)[0][1]):
            fields = _children(extension)
            if not fields or fields[0][0] != 0x06:
                raise CAPolicyError('Invalid certificate extension')
            oid = fields[0][1]
            if oid in seen:
                raise CAPolicyError('Duplicate certificate extension')
            seen.add(oid)
            if fields[-1][0] != 0x04 or len(fields) not in (2, 3):
                raise CAPolicyError('Invalid certificate extension')
            critical = len(fields) == 3 and fields[1] == (0x01, b'\xff')
            value = fields[-1][1]
            if oid == _OID_BASIC_CONSTRAINTS:
                inner = _children(_children(value)[0][1]) if value else []
                info['ca'] = bool(inner) and inner[0] == (0x01, b'\xff')
            elif oid == _OID_NAME_CONSTRAINTS:
                permitted, excluded = [], []
                for tag, subtrees in _children(_children(value)[0][1]):
                    if tag == 0xa0:
                        permitted = _subtrees(subtrees)
                    elif tag == 0xa1:
                        excluded = _subtrees(subtrees)
                    else:
                        raise CAPolicyError('Invalid name constraints')
                info['nameConstraints'] = {'critical': critical, 'permitted': permitted, 'excluded': excluded}
    return info


def check_trustable(der: bytes, label: str) -> dict:
    """Refuse anything but this instance's self-signed, name-constrained CA."""
    info = certificate_info(der)
    constraints = info['nameConstraints']
    if not info['selfIssued'] or not info['ca'] or info['commonName'] != common_name(label):
        raise CAPolicyError('Not this instance\'s name-constrained proxy CA')
    if constraints is None or not constraints['critical']:
        raise CAPolicyError('Proxy CA has no critical name constraints; refusing to trust it. '
                            'Enable ca.json name-constrained mode for this instance first')
    domains = []
    for tag, value in constraints['permitted']:
        try:
            domain = value.decode('ascii')
        except UnicodeDecodeError:
            domain = ''
        if tag != 0x82 or domain != domain.lower() or permitted_domains([domain]) != [domain]:
            raise CAPolicyError('Proxy CA permits a name form or domain this project never issues')
        domains.append(domain)
    if not domains:
        raise CAPolicyError('Proxy CA permits no names')
    excluded = {value for tag, value in constraints['excluded'] if tag == 0x87}
    if not set(EXCLUDED_ADDRESS_RANGES) <= excluded:
        raise CAPolicyError('Proxy CA does not exclude every IP address')
    return {'sha1': info['sha1'], 'domains': sorted(domains)}
