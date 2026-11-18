"""Sealed JWT references for clients that read their token's claims locally.

Some CLIs decode their API key or access token as a JWT before sending it (the
Checkmarx One ``cx`` CLI reads ``aud``, ``azp`` and ``ast-base-url`` from its
tokens). A bare secret reference fails that local decode, so those clients get
a *sealed* JWT instead. It keeps the real token's header and claims, which are
metadata rather than credentials, but its signature segment is replaced with
the base64url encoding of a secret reference. Without the real signature the
token is useless to anyone who copies it.

``unseal`` turns every sealed JWT in a value back into the plain reference it
encodes. addon.py applies it before policy checks, so a sealed token is held to
exactly the same manifest placement rules as the reference written directly.
"""

from __future__ import annotations

import base64
import re

# Assembled from two halves so no invisible character can creep into the marker.
MARKER = "secre" + "tref:"
_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")
# Every sealed signature segment starts with the base64url encoding of the
# first nine marker bytes, which gives a cheap pre-filter.
SEALED_SEGMENT_PREFIX = base64.urlsafe_b64encode(MARKER.encode("ascii")[:9]).decode("ascii")
_SEGMENT = r"[A-Za-z0-9_-]+"
_SEALED_JWT_RE = re.compile(
    rf"(?<![A-Za-z0-9_.-])({_SEGMENT})\.({_SEGMENT})\.({re.escape(SEALED_SEGMENT_PREFIX)}[A-Za-z0-9_-]*)(?![A-Za-z0-9_.-])"
)


class SealedJwtError(ValueError):
    pass


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def seal(real_jwt: str, canonical: str) -> str:
    """Return *real_jwt* with its signature replaced by a reference to *canonical*."""
    if not _NAME_RE.fullmatch(canonical or ""):
        raise SealedJwtError("invalid canonical name")
    parts = real_jwt.split(".") if isinstance(real_jwt, str) else []
    if len(parts) != 3 or not all(re.fullmatch(_SEGMENT, part) for part in parts):
        raise SealedJwtError("value is not a compact JWT")
    return f"{parts[0]}.{parts[1]}.{_b64url_encode((MARKER + canonical).encode('ascii'))}"


def sealed_reference(segment: str) -> str | None:
    """Return the plain reference a sealed signature segment encodes, if any."""
    try:
        decoded = _b64url_decode(segment).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
    if not decoded.startswith(MARKER) or not _NAME_RE.fullmatch(decoded[len(MARKER):]):
        return None
    return decoded


def is_sealed(value: str) -> bool:
    match = _SEALED_JWT_RE.fullmatch(value or "")
    return bool(match and sealed_reference(match.group(3)))


def unseal(value: str) -> str:
    """Replace every sealed JWT in *value* with the reference it encodes."""
    if not isinstance(value, str) or "." + SEALED_SEGMENT_PREFIX not in value:
        return value

    def replace(match: re.Match) -> str:
        reference = sealed_reference(match.group(3))
        return reference if reference is not None else match.group(0)

    return _SEALED_JWT_RE.sub(replace, value)
