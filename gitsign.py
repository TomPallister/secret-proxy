"""Sign git commits and tags with an SSH key held only by secret-proxy.

The dev container's git calls ``git-ssh-sign-proxy`` as its
``gpg.ssh.program``. That shim sends the object to be signed to the proxy, and
this module produces the same armored SSHSIG signature that
``ssh-keygen -Y sign -n git`` would (PROTOCOL.sshsig), so GitHub verifies it
against the signing key registered on the account. The private key is read
from the secret store and never leaves the proxy.

Only Ed25519 keys are supported, and only git commit and tag objects are
signed: the payload must look like one, so the container cannot use the proxy
to sign arbitrary data, and the signature's ``git`` namespace stops it being
replayed as anything other than a git signature.

``sign_message`` signs arbitrary bytes in another, explicit namespace for the
proxy's own use (audit log seals); no client route reaches it.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NAMESPACE = b"git"
HASH_ALGORITHM = b"sha512"
MAX_PAYLOAD_BYTES = 1024 * 1024

# A commit object starts with its tree; a tag object starts with its target.
_OBJECT_ID = rb"(?:[0-9a-f]{40}|[0-9a-f]{64})"
_COMMIT_RE = re.compile(rb"tree " + _OBJECT_ID + rb"\n")
_TAG_RE = re.compile(rb"object " + _OBJECT_ID + rb"\ntype [a-z]+\ntag ")


class GitSignError(ValueError):
    """The request cannot be signed. Messages never contain key material."""


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _load_key(private_key_openssh: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_ssh_private_key(
            private_key_openssh.encode("ascii"), password=None
        )
    except (ValueError, TypeError, UnicodeEncodeError) as error:
        raise GitSignError("the signing key is not an unencrypted OpenSSH key") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise GitSignError("the signing key must be an Ed25519 key")
    return key


def public_key_line(private_key_openssh: str) -> str:
    """Return ``ssh-ed25519 <base64>`` for the signing key."""
    key = _load_key(private_key_openssh)
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("ascii")


def normalise_public_key(line: str) -> str:
    """Return the ``<type> <base64>`` part of an OpenSSH public key line."""
    if line.startswith("key::"):
        line = line[len("key::"):]
    parts = line.strip().split()
    if len(parts) < 2:
        raise GitSignError("the requested signing key is not an OpenSSH public key")
    return f"{parts[0]} {parts[1]}"


def object_kind(payload: bytes) -> str:
    """Return ``commit`` or ``tag``, or raise for anything else."""
    if _COMMIT_RE.match(payload):
        return "commit"
    if _TAG_RE.match(payload):
        return "tag"
    raise GitSignError("only git commit and tag objects can be signed")


def sign(private_key_openssh: str, payload: bytes, expected_public_key: str | None = None) -> str:
    """Return an armored SSH signature over a git commit or tag object."""
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise GitSignError("the object to sign is too large")
    object_kind(payload)
    key = _load_key(private_key_openssh)
    if expected_public_key is not None:
        actual = public_key_line(private_key_openssh)
        if normalise_public_key(expected_public_key) != actual:
            raise GitSignError(
                "git's user.signingkey is not the key secret-proxy signs with"
            )

    return _sshsig(key, payload, NAMESPACE)


def sign_message(private_key_openssh: str, message: bytes, namespace: bytes) -> str:
    """Return an armored SSHSIG over arbitrary *message* in *namespace*.

    For proxy-internal use only (the audit log seals its hash chain with
    namespace ``secret-proxy-audit``). Never reachable from a client: the git
    route always signs in the ``git`` namespace, so a signature made here
    cannot be replayed as a git signature, and vice versa.
    """
    if not isinstance(namespace, bytes) or not namespace or namespace == NAMESPACE:
        raise GitSignError("an explicit, non-git namespace is required")
    if len(message) > MAX_PAYLOAD_BYTES:
        raise GitSignError("the message to sign is too large")
    return _sshsig(_load_key(private_key_openssh), message, namespace)


def _sshsig(key: Ed25519PrivateKey, payload: bytes, namespace: bytes) -> str:
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_blob = _ssh_string(b"ssh-ed25519") + _ssh_string(public_raw)
    digest = hashlib.sha512(payload).digest()
    signed_data = (
        b"SSHSIG"
        + _ssh_string(namespace)
        + _ssh_string(b"")
        + _ssh_string(HASH_ALGORITHM)
        + _ssh_string(digest)
    )
    signature_blob = _ssh_string(b"ssh-ed25519") + _ssh_string(key.sign(signed_data))
    blob = (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + _ssh_string(public_blob)
        + _ssh_string(namespace)
        + _ssh_string(b"")
        + _ssh_string(HASH_ALGORITHM)
        + _ssh_string(signature_blob)
    )
    encoded = base64.b64encode(blob).decode("ascii")
    lines = [encoded[i:i + 70] for i in range(0, len(encoded), 70)]
    return "-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n"
