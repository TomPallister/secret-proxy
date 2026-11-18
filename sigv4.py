"""SigV4 helpers for secret_proxy AWS request re-signing.

Pure-stdlib (hashlib/hmac) so the mitmproxy addon needs no extra deps for the
chunk-signature chain. The *seed*/normal request signature is done with botocore
at runtime (robust canonicalization across services); this module owns the parts
botocore doesn't expose for RE-signing an existing request:

  * signing-key derivation (AWS4 HMAC ladder)
  * the aws-chunked payload chunk-signature CHAIN
    (STREAMING-AWS4-HMAC-SHA256-PAYLOAD)

Chunk string-to-sign (per AWS S3 "Transferring Payload in Multiple Chunks"):

    AWS4-HMAC-SHA256-PAYLOAD\n
    <amz-date>\n
    <credential-scope>\n
    <previous-signature>\n
    <SHA256 hex of "">\n
    <SHA256 hex of this chunk's data>

The first chunk chains off the request's seed signature; each subsequent chunk
chains off the previous chunk's signature; the final (0-length) chunk hashes "".
"""

from __future__ import annotations

import hashlib
import hmac
from urllib.parse import quote, unquote

EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def _uri_encode(s: str, encode_slash: bool = True) -> str:
    safe = "-_.~"
    if not encode_slash:
        safe += "/"
    return quote(s, safe=safe)


def canonical_uri(path: str, service: str) -> str:
    """SigV4 canonical URI. S3 uses the path encoded once (no normalization);
    other services normalize then URI-encode the (already-encoded) path again
    (double-encoding), matching botocore."""
    if not path:
        return "/"
    # Strip any query (caller passes path only) and work from the decoded key.
    decoded = unquote(path)
    if service == "s3":
        return _uri_encode(decoded, encode_slash=False)
    return _uri_encode(_uri_encode(decoded, encode_slash=False), encode_slash=False)


def canonical_query(raw_query: str) -> str:
    """SigV4 canonical query string for a URL-based query. Matches botocore's
    _canonical_query_string_url: split the raw (already wire-encoded) query into
    key/value pairs, sort, and rejoin — WITHOUT re-encoding (the wire form is
    what was signed). Re-signing must reproduce this exactly."""
    if not raw_query:
        return ""
    pairs = []
    for part in raw_query.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        pairs.append((k, v))
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def derive_signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    """AWS4 signing key: HMAC ladder over date -> region -> service -> aws4_request.
    date_stamp is YYYYMMDD (the date portion of the credential scope)."""
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()


def canonical_request(
    method: str,
    canonical_uri: str,
    canonical_querystring: str,
    headers: list[tuple[str, str]],
    payload_hash: str,
) -> tuple[str, str]:
    """Build the SigV4 canonical request from the headers to be signed. Returns
    (canonical_request, signed_headers_list). Header names are lowercased,
    values trimmed + internal whitespace collapsed, then sorted by name."""
    norm = sorted(
        ((k.lower().strip(), " ".join(v.strip().split())) for k, v in headers),
        key=lambda kv: kv[0],
    )
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in norm)
    signed_headers = ";".join(k for k, _ in norm)
    cr = "\n".join(
        [method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash]
    )
    return cr, signed_headers


def string_to_sign(amz_date: str, scope: str, cr: str) -> str:
    return "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, sha256_hex(cr.encode("utf-8"))])


def seed_signature(signing_key: bytes, amz_date: str, scope: str, cr: str) -> str:
    """The request's main ("seed") SigV4 signature over a canonical request."""
    sts = string_to_sign(amz_date, scope, cr)
    return hmac.new(signing_key, sts.encode("utf-8"), hashlib.sha256).hexdigest()


def authorization_header(akid: str, scope: str, signed_headers: str, signature: str) -> str:
    return (
        f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )


def chunk_string_to_sign(amz_date: str, scope: str, prev_sig: str, chunk_hash_hex: str) -> str:
    return "\n".join(
        [
            "AWS4-HMAC-SHA256-PAYLOAD",
            amz_date,
            scope,
            prev_sig,
            EMPTY_HASH,
            chunk_hash_hex,
        ]
    )


def chunk_signature(signing_key: bytes, amz_date: str, scope: str, prev_sig: str, chunk_hash_hex: str) -> str:
    """Signature for one aws-chunked chunk. chunk_hash_hex = SHA256 hex of the
    chunk's raw data (the final 0-length chunk uses EMPTY_HASH)."""
    sts = chunk_string_to_sign(amz_date, scope, prev_sig, chunk_hash_hex)
    return hmac.new(signing_key, sts.encode("utf-8"), hashlib.sha256).hexdigest()


class ChunkedResigner:
    """Re-sign an aws-chunked (STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]) request
    body on the fly. Feed raw body bytes in any sizes; get back re-framed bytes
    with each chunk signature recomputed against a new signing key, chained from
    the new seed signature. Content-Length is preserved (identical chunk sizes;
    signatures are always 64 hex chars).

    Framing: data chunks are ``<hex-size>;chunk-signature=<64hex>\r\n<data>\r\n``;
    the final chunk is the 0-length ``0;chunk-signature=<64hex>\r\n`` header line,
    followed by an optional trailer:
        ``<trailer-header>:<value>\r\nx-amz-trailer-signature:<64hex>\r\n\r\n``
    The trailer signature (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER) chains off
    the FINAL chunk's signature and is re-signed too; the trailer's checksum
    header (over the unmodified payload) is preserved byte-for-byte. An empty
    trailer (plain ``\r\n``, the non-trailer variant) passes through unchanged.
    """

    def __init__(self, signing_key: bytes, amz_date: str, scope: str, seed_sig: str):
        self._key = signing_key
        self._amz = amz_date
        self._scope = scope
        self._prev = seed_sig
        self._final_sig = None  # signature of the 0-length final chunk
        self._buf = bytearray()
        self._trailing = False  # past the final 0-length chunk -> buffer trailer

    def feed(self, data: bytes) -> bytes:
        self._buf += data
        if self._trailing:
            return b""  # buffer the (small) trailer; re-signed + emitted at done()
        out = bytearray()
        while True:
            i = self._buf.find(b"\r\n")
            if i < 0:
                break  # header line incomplete
            header = bytes(self._buf[:i])
            size_part = header.split(b";", 1)[0]
            try:
                size = int(size_part, 16)
            except ValueError:
                self._trailing = True  # not a chunk header -> trailer region
                break
            if size == 0:
                # Final chunk: header line only (no data). Re-sign over the empty
                # payload, emit, then buffer whatever follows as the trailer.
                sig = chunk_signature(self._key, self._amz, self._scope, self._prev, EMPTY_HASH)
                self._prev = sig
                self._final_sig = sig
                out += f"0;chunk-signature={sig}\r\n".encode()
                del self._buf[: i + 2]
                self._trailing = True
                break
            frame_end = i + 2 + size + 2  # header CRLF + data + trailing CRLF
            if len(self._buf) < frame_end:
                break  # whole frame not buffered yet
            data_start = i + 2
            chunk = bytes(self._buf[data_start : data_start + size])
            sig = chunk_signature(self._key, self._amz, self._scope, self._prev, sha256_hex(chunk))
            self._prev = sig
            out += f"{size:x};chunk-signature={sig}\r\n".encode() + chunk + b"\r\n"
            del self._buf[:frame_end]
        return bytes(out)

    def done(self) -> bytes:
        """Flush the buffered trailer (re-signing its x-amz-trailer-signature if
        present). Call once the upstream body is complete."""
        trailer = bytes(self._buf)
        self._buf.clear()
        if not self._trailing:
            return trailer  # incomplete/malformed body -> emit residual as-is
        return self._resign_trailer(trailer)

    def _resign_trailer(self, trailer: bytes) -> bytes:
        # Empty or unsigned trailer -> nothing to re-sign.
        if b"x-amz-trailer-signature:" not in trailer.lower():
            return trailer
        lines = trailer.split(b"\r\n")
        # Canonical trailing headers = each (non-signature) header as
        # lowercased ``name:value\n``, sorted; hashed for the trailer StringToSign.
        canon_parts = []
        for ln in lines:
            low = ln.lower()
            if not ln.strip() or low.startswith(b"x-amz-trailer-signature:"):
                continue
            name, _, val = ln.partition(b":")
            canon_parts.append(name.strip().lower() + b":" + val.strip() + b"\n")
        canon_parts.sort()
        canon_hash = sha256_hex(b"".join(canon_parts))
        sts = "\n".join(
            [
                "AWS4-HMAC-SHA256-TRAILER",
                self._amz,
                self._scope,
                self._final_sig or self._prev,
                canon_hash,
            ]
        )
        new_sig = hmac.new(self._key, sts.encode("utf-8"), hashlib.sha256).hexdigest()
        # Rebuild byte-for-byte, swapping only the trailer signature value.
        out_lines = []
        for ln in lines:
            if ln.lower().startswith(b"x-amz-trailer-signature:"):
                out_lines.append(b"x-amz-trailer-signature:" + new_sig.encode())
            else:
                out_lines.append(ln)
        return b"\r\n".join(out_lines)


def parse_authorization(auth: str) -> dict:
    """Parse an incoming SigV4 Authorization header into its parts."""
    if not auth.startswith("AWS4-HMAC-SHA256"):
        raise ValueError("not a SigV4 Authorization header")
    after = auth.split(" ", 1)[1]
    parts = {p.split("=", 1)[0].strip(): p.split("=", 1)[1] for p in after.split(", ")}
    cred = parts["Credential"]
    akid, date_stamp, region, service, _term = cred.split("/")
    return {
        "akid": akid,
        "date_stamp": date_stamp,
        "region": region,
        "service": service,
        "signed_headers": parts["SignedHeaders"].split(";"),
        "signature": parts["Signature"],
    }


def resign(
    *,
    method: str,
    path: str,
    query: str,
    headers_lower: dict,
    body: bytes | None,
    akid: str,
    secret: str,
    token: str,
    host: str = "",
) -> dict:
    """Re-sign an AWS SigV4 request with real STS creds. *headers_lower* is a
    case-normalised {lowername: value} map of the incoming (dummy-signed)
    request. *host* is the request authority (``flow.request.host``) used for the
    signed ``host`` header — pass it explicitly because HTTP/2 requests carry the
    authority in the ``:authority`` pseudo-header, NOT a ``host`` entry in
    headers_lower (relying on headers_lower there yields an empty ``host:`` line
    and a SignatureDoesNotMatch). Region/service/date come from the incoming
    Authorization scope; the session token is swapped for the real one and
    included in the signature.

    Returns {authorization, x-amz-security-token, x-amz-date, signed_headers,
    canonical_request, reframer}. *reframer* is a ChunkedResigner when the payload
    is an aws-chunked signed stream (STREAMING-AWS4-HMAC-SHA256-PAYLOAD), else None.
    """
    p = parse_authorization(headers_lower.get("authorization", ""))
    region, service, date_stamp = p["region"], p["service"], p["date_stamp"]
    amz_date = headers_lower.get("x-amz-date", "")
    scope = f"{date_stamp}/{region}/{service}/aws4_request"

    payload_hash = headers_lower.get("x-amz-content-sha256")
    if payload_hash is None:
        payload_hash = sha256_hex(body or b"")

    # Sign exactly the headers the client signed, but swap the security-token
    # value for the real one (and make sure it's in the signed set).
    names = list(p["signed_headers"])
    if "x-amz-security-token" not in names:
        names.append("x-amz-security-token")
    hdrs = []
    for n in names:
        if n == "x-amz-security-token":
            hdrs.append((n, token))
        elif n == "host" and host:
            hdrs.append((n, host))  # HTTP/2: authority not in headers_lower
        else:
            hdrs.append((n, headers_lower.get(n, "")))

    cr, signed_list = canonical_request(method, canonical_uri(path, service), canonical_query(query), hdrs, payload_hash)
    key = derive_signing_key(secret, date_stamp, region, service)
    sig = seed_signature(key, amz_date, scope, cr)

    reframer = None
    if payload_hash.startswith("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"):
        reframer = ChunkedResigner(key, amz_date, scope, sig)

    return {
        "authorization": authorization_header(akid, scope, signed_list, sig),
        "x-amz-security-token": token,
        "x-amz-date": amz_date,
        "signed_headers": signed_list,
        "canonical_request": cr,
        "reframer": reframer,
    }


def resign_query(
    *,
    method: str,
    path: str,
    query_params: dict,
    headers_lower: dict,
    host: str,
    akid: str,
    secret: str,
    token: str,
) -> dict:
    """Re-sign a SigV4 PRESIGNED (query-string auth) request with real STS creds.
    *query_params* is the DECODED query as {name: value} (e.g. mitmproxy's
    flow.request.query). Swaps X-Amz-Credential (real AKID, same scope) +
    X-Amz-Security-Token (real token), recomputes X-Amz-Signature over the
    canonical request (payload hash = UNSIGNED-PAYLOAD, host from the authority),
    and returns the updated {name: value} query to put back on the wire.

    Only OUR presigned URLs (dummy creds) should be passed here — the caller keys
    off X-Amz-Security-Token starting with 'secretrole:' so externally-signed URLs
    (already valid) are left as passthrough.
    """
    cred = query_params.get("X-Amz-Credential", "")
    parts = cred.split("/")
    if len(parts) < 5:
        raise ValueError(f"bad X-Amz-Credential: {cred!r}")
    _akid, date_stamp, region, service = parts[0], parts[1], parts[2], parts[3]
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    amz_date = query_params.get("X-Amz-Date", "")
    signed_headers = query_params.get("X-Amz-SignedHeaders", "host")

    new = dict(query_params)
    new["X-Amz-Credential"] = f"{akid}/{scope}"
    if token:
        new["X-Amz-Security-Token"] = token
    new.pop("X-Amz-Signature", None)

    canonical_qs = "&".join(sorted(f"{_uri_encode(k)}={_uri_encode(v)}" for k, v in new.items()))

    hv = dict(headers_lower)
    hv["host"] = host  # authority (HTTP/2 has no host header)
    canon_headers = "".join(
        f"{n}:{' '.join(hv.get(n, '').strip().split())}\n" for n in signed_headers.split(";")
    )
    cr = "\n".join([method, canonical_uri(path, service), canonical_qs, canon_headers, signed_headers, "UNSIGNED-PAYLOAD"])
    key = derive_signing_key(secret, date_stamp, region, service)
    new["X-Amz-Signature"] = seed_signature(key, amz_date, scope, cr)
    return new
