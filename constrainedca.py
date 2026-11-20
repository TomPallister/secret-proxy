"""Generate and maintain an opt-in name-constrained mitmproxy CA (container side).

Only runs when the private configuration contains ``ca.json`` with
``{"mode": "name-constrained"}``. Without it, mitmproxy keeps creating and
loading its own CA exactly as before. Policy (which names) lives in
``capolicy.py``; this module only writes certificates in mitmproxy's confdir
format. Replaced CA files are moved aside, never deleted.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path
import secrets
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import capolicy
from capolicy import CAPolicyError
from secretstore import SecretManifest

BASENAME = 'mitmproxy'
CA_FILES = ('ca.pem', 'ca-cert.pem', 'ca-cert.cer', 'ca.p12', 'ca-cert.p12')
VALIDITY = datetime.timedelta(days=10 * 365)
RENEW_BEFORE = datetime.timedelta(days=30)
EXCLUDED = (ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0'))
ORGANIZATION = 'secret-proxy'


def path(state: Path, suffix: str) -> Path:
    return state / f'{BASENAME}-{suffix}'


def plan(config: Path, label: str | None):
    """Validate opt-in and compute permitted names before any credential is read.

    Returns None (mitmproxy default CA) or the sorted permitted domains.
    """
    chosen = config / capolicy.CONFIG_NAME
    if not chosen.exists():
        return None
    capolicy.parse_config(chosen.read_bytes())
    capolicy.common_name(label)  # constrained mode needs the instance label
    manifest = SecretManifest.load(config / 'manifest.json')
    patterns = capolicy.interception_patterns(manifest, (config / 'aws-okta.json').is_file())
    return capolicy.permitted_domains(patterns)


def _load(state: Path):
    try:
        raw = path(state, 'ca.pem').read_bytes()
        key = serialization.load_pem_private_key(raw, None)
        cert = x509.load_pem_x509_certificate(raw)
        public = x509.load_pem_x509_certificate(path(state, 'ca-cert.pem').read_bytes())
    except (OSError, ValueError, TypeError):
        return None
    if public != cert or key.public_key() != cert.public_key():
        return None
    return cert


def _ours(cert) -> bool:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return bool(names) and str(names[0].value).startswith(capolicy.CN_PREFIX)


def matches(cert, label: str, domains, now: datetime.datetime) -> bool:
    try:
        constraint = cert.extensions.get_extension_for_class(x509.NameConstraints)
    except x509.ExtensionNotFound:
        return False
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    permitted = constraint.value.permitted_subtrees or []
    excluded = constraint.value.excluded_subtrees or []
    return (constraint.critical and bool(names) and names[0].value == capolicy.common_name(label)
            and all(isinstance(name, x509.DNSName) for name in permitted)
            and sorted(name.value for name in permitted) == list(domains)
            and {name.value for name in excluded if isinstance(name, x509.IPAddress)} == set(EXCLUDED)
            and len(excluded) == len(EXCLUDED)
            and cert.not_valid_after_utc - RENEW_BEFORE > now)


def generate(label: str, domains, now: datetime.datetime):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, capolicy.common_name(label)),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION)])
    builder = (x509.CertificateBuilder()
               .serial_number(x509.random_serial_number())
               .subject_name(name).issuer_name(name)
               .not_valid_before(now - datetime.timedelta(days=2))
               .not_valid_after(now + VALIDITY)
               .public_key(key.public_key())
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=False, content_commitment=False, key_encipherment=False,
                   data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                   encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
               .add_extension(x509.NameConstraints(
                   permitted_subtrees=[x509.DNSName(domain) for domain in domains],
                   excluded_subtrees=[x509.IPAddress(network) for network in EXCLUDED]), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    return key, builder.sign(private_key=key, algorithm=hashes.SHA256())


def _write(target: Path, data: bytes):
    temporary = target.with_name('.' + target.name + '-' + secrets.token_hex(4))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def _retire(state: Path) -> Path | None:
    present = [path(state, suffix) for suffix in CA_FILES if path(state, suffix).exists()]
    if not present:
        return None
    retired = state / 'retired' / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(4))
    retired.mkdir(mode=0o700, parents=True)
    for item in present:
        os.replace(item, retired / item.name)
    return retired


def ensure(state: Path, label: str | None, domains, now: datetime.datetime | None = None) -> str:
    """Return 'default', 'kept', 'created' or 'replaced'."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    current = _load(state)
    if domains is None:
        if current is not None and _ours(current):
            raise CAPolicyError('This instance has a name-constrained CA but no ca.json. Restore '
                                'ca.json, or explicitly retire the CA volume before using a default CA')
        return 'default'
    if current is not None and matches(current, label, domains, now):
        return 'kept'
    replaced = _retire(state) is not None
    key, cert = generate(label, domains, now)
    private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
    public_pem = cert.public_bytes(serialization.Encoding.PEM)
    name = BASENAME.encode()
    _write(path(state, 'ca-cert.pem'), public_pem)
    _write(path(state, 'ca-cert.cer'), public_pem)
    _write(path(state, 'ca-cert.p12'), pkcs12.serialize_key_and_certificates(
        name, None, cert, None, serialization.NoEncryption()))
    _write(path(state, 'ca.p12'), pkcs12.serialize_key_and_certificates(
        name, key, cert, None, serialization.NoEncryption()))
    # mitmproxy loads this file; write it last so a partial write is detected.
    _write(path(state, 'ca.pem'), private_pem + public_pem)
    return 'replaced' if replaced else 'created'
