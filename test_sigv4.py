"""Prove the SigV4 chunk-signature chain against AWS's published example.

Vectors: AWS S3 docs, "Signature Calculations for the Authorization Header:
Transferring Payload in Multiple Chunks (Chunked Upload)".
  AKID   AKIAIOSFODNN7EXAMPLE
  secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region us-east-1   service s3   date 20130524T000000Z
  66560-byte object, 64KiB chunks -> chunks of 65536, 1024, 0 bytes.

Run:  uv run --python 3.12 python dev-env/secret-proxy/test_sigv4.py
"""

import hashlib
import hmac
import sys

from sigv4 import (
    EMPTY_HASH,
    ChunkedResigner,
    authorization_header,
    canonical_request,
    chunk_signature,
    derive_signing_key,
    seed_signature,
    sha256_hex,
)

SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATE_STAMP = "20130524"
REGION = "us-east-1"
SERVICE = "s3"
AMZ_DATE = "20130524T000000Z"
SCOPE = "20130524/us-east-1/s3/aws4_request"

# Seed signature = the request's Authorization signature (from the AWS doc).
SEED_SIG = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"

# Expected per-chunk signatures (from the AWS doc).
EXP_CHUNK1 = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"
EXP_CHUNK2 = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"
EXP_CHUNK3 = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"


def _aws_chunked_body() -> bytes:
    """The AWS-doc example body, framed with the known example chunk signatures
    (i.e. as if signed with the example key). Chunks: 65536'a', 1024'a', 0."""
    return (
        f"10000;chunk-signature={EXP_CHUNK1}\r\n".encode()
        + b"a" * 65536
        + b"\r\n"
        + f"400;chunk-signature={EXP_CHUNK2}\r\n".encode()
        + b"a" * 1024
        + b"\r\n"
        + f"0;chunk-signature={EXP_CHUNK3}\r\n\r\n".encode()
    )


def _test_reframer(key: bytes) -> list[str]:
    fails: list[str] = []
    body = _aws_chunked_body()

    # 1) Re-frame with the SAME key + seed -> byte-for-byte identical output
    #    (proves the parser + re-emitter round-trip and preserve Content-Length).
    r = ChunkedResigner(key, AMZ_DATE, SCOPE, SEED_SIG)
    out = r.feed(body) + r.done()
    if out != body:
        fails.append(f"reframer identity (whole): len {len(out)} vs {len(body)}")

    # 2) Same, but fed in awkward 7-byte slices -> must still reassemble identically
    #    (proves partial-read safety across TCP boundaries).
    r2 = ChunkedResigner(key, AMZ_DATE, SCOPE, SEED_SIG)
    out2 = bytearray()
    for i in range(0, len(body), 7):
        out2 += r2.feed(body[i : i + 7])
    out2 += r2.done()
    if bytes(out2) != body:
        fails.append(f"reframer identity (7-byte splits): len {len(out2)} vs {len(body)}")

    # 3) Re-frame with a DIFFERENT seed -> chunk sigs change but structure/length
    #    hold, and re-parsing yields a valid chain from the new seed.
    new_seed = "00" * 32
    r3 = ChunkedResigner(key, AMZ_DATE, SCOPE, new_seed)
    out3 = r3.feed(body) + r3.done()
    if len(out3) != len(body):
        fails.append(f"reframer new-seed length changed: {len(out3)} vs {len(body)}")
    exp_c1 = chunk_signature(key, AMZ_DATE, SCOPE, new_seed, sha256_hex(b"a" * 65536))
    if f"chunk-signature={exp_c1}".encode() not in out3:
        fails.append("reframer new-seed: chunk1 not re-signed from new seed")
    if EXP_CHUNK1.encode() in out3:
        fails.append("reframer new-seed: old chunk1 signature leaked through")
    return fails


def _test_stream_callback(key: bytes) -> list[str]:
    """The mitmproxy streaming contract: the addon sets
    flow.request.stream = lambda data: rf.feed(data) if data else rf.done().
    Feeding the body in chunks then a final b"" must equal the buffered re-frame."""
    fails: list[str] = []
    body = _aws_chunked_body()
    # Buffered reference.
    rb = ChunkedResigner(key, AMZ_DATE, SCOPE, SEED_SIG)
    buffered = rb.feed(body) + rb.done()
    # Streamed via the addon's callback pattern (arbitrary 1000-byte network reads
    # + the terminating empty chunk mitmproxy sends at end-of-stream).
    rs = ChunkedResigner(key, AMZ_DATE, SCOPE, SEED_SIG)
    modify = lambda data: rs.feed(data) if data else rs.done()  # noqa: E731
    out = bytearray()
    for i in range(0, len(body), 1000):
        out += modify(body[i : i + 1000])
    out += modify(b"")  # EOF flush
    if bytes(out) != buffered:
        fails.append(f"stream callback != buffered (len {len(out)} vs {len(buffered)})")
    return fails


def _trailer_sig(key: bytes, final_sig: str, header_lines: list[bytes]) -> str:
    """Compute an aws-chunked trailer signature (AWS4-HMAC-SHA256-TRAILER),
    mirroring the documented algorithm, to build + verify test bodies."""
    parts = sorted(
        h.split(b":", 1)[0].strip().lower() + b":" + h.split(b":", 1)[1].strip() + b"\n"
        for h in header_lines
    )
    canon_hash = sha256_hex(b"".join(parts))
    sts = "\n".join(["AWS4-HMAC-SHA256-TRAILER", AMZ_DATE, SCOPE, final_sig, canon_hash])
    return hmac.new(key, sts.encode("utf-8"), hashlib.sha256).hexdigest()


def _test_trailer(key: bytes) -> list[str]:
    """Signed-trailer (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER) re-signing:
    same key -> byte-identical (incl. trailer sig); new key -> chunk + trailer
    sigs change, trailer sig chains off the NEW final-chunk sig, no old sig leaks.
    """
    fails: list[str] = []
    checksum = b"x-amz-checksum-crc32:AAAAAA=="

    # Build a body whose chunk + trailer signatures are correct for `key`.
    c1 = chunk_signature(key, AMZ_DATE, SCOPE, SEED_SIG, sha256_hex(b"a" * 65536))
    cf = chunk_signature(key, AMZ_DATE, SCOPE, c1, EMPTY_HASH)
    tsig = _trailer_sig(key, cf, [checksum])
    body = (
        f"10000;chunk-signature={c1}\r\n".encode() + b"a" * 65536 + b"\r\n"
        + f"0;chunk-signature={cf}\r\n".encode()
        + checksum + b"\r\n"
        + b"x-amz-trailer-signature:" + tsig.encode() + b"\r\n\r\n"
    )

    # Same key -> identical output (proves parse + re-emit + trailer re-sign).
    r = ChunkedResigner(key, AMZ_DATE, SCOPE, SEED_SIG)
    out = r.feed(body) + r.done()
    if out != body:
        fails.append(f"trailer identity failed (len {len(out)} vs {len(body)})")

    # New key -> trailer re-signed off the new final-chunk sig; length preserved.
    k2 = derive_signing_key("anothersecretanothersecret000000", DATE_STAMP, REGION, SERVICE)
    r2 = ChunkedResigner(k2, AMZ_DATE, SCOPE, SEED_SIG)
    out2 = r2.feed(body) + r2.done()
    if len(out2) != len(body):
        fails.append(f"trailer new-key length changed: {len(out2)} vs {len(body)}")
    c1b = chunk_signature(k2, AMZ_DATE, SCOPE, SEED_SIG, sha256_hex(b"a" * 65536))
    cfb = chunk_signature(k2, AMZ_DATE, SCOPE, c1b, EMPTY_HASH)
    exp_tsig = _trailer_sig(k2, cfb, [checksum])
    if f"x-amz-trailer-signature:{exp_tsig}".encode() not in out2:
        fails.append("trailer new-key: signature not re-signed off the new final-chunk sig")
    if tsig.encode() in out2:
        fails.append("trailer new-key: old trailer signature leaked through")
    # The checksum header (over unmodified payload) must be preserved verbatim.
    if checksum not in out2:
        fails.append("trailer new-key: checksum header not preserved")
    return fails


def main() -> int:
    failures = []

    key = derive_signing_key(SECRET, DATE_STAMP, REGION, SERVICE)

    # --- Seed / normal re-sign: reproduce the AWS doc's Authorization signature
    # from the chunked-upload example's canonical request (payload hash = the
    # streaming literal). This exercises canonical_request + string_to_sign.
    seed_headers = [
        ("host", "s3.amazonaws.com"),
        ("x-amz-date", AMZ_DATE),
        ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", "66560"),
        ("content-length", "66824"),
    ]
    cr, signed = canonical_request(
        "PUT", "/examplebucket/chunkObject.txt", "", seed_headers, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    )
    seed = seed_signature(key, AMZ_DATE, SCOPE, cr)
    if seed != SEED_SIG:
        failures.append(f"seed signature: got {seed} want {SEED_SIG}")
    exp_signed = "content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class"
    if signed != exp_signed:
        failures.append(f"signed headers: got {signed} want {exp_signed}")
    # Authorization header shape (uses the doc's seed sig).
    auth = authorization_header("AKIAIOSFODNN7EXAMPLE", SCOPE, exp_signed, SEED_SIG)
    if not auth.startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"):
        failures.append(f"authorization header malformed: {auth}")

    # Chunk 1: 65536 bytes of 'a', chains off the seed signature.
    c1_hash = sha256_hex(b"a" * 65536)
    c1 = chunk_signature(key, AMZ_DATE, SCOPE, SEED_SIG, c1_hash)
    if c1 != EXP_CHUNK1:
        failures.append(f"chunk1: got {c1} want {EXP_CHUNK1}")

    # Chunk 2: 1024 bytes of 'a', chains off chunk 1.
    c2_hash = sha256_hex(b"a" * 1024)
    c2 = chunk_signature(key, AMZ_DATE, SCOPE, c1, c2_hash)
    if c2 != EXP_CHUNK2:
        failures.append(f"chunk2: got {c2} want {EXP_CHUNK2}")

    # Final chunk: 0 bytes, hashes "", chains off chunk 2.
    c3 = chunk_signature(key, AMZ_DATE, SCOPE, c2, EMPTY_HASH)
    if c3 != EXP_CHUNK3:
        failures.append(f"final chunk: got {c3} want {EXP_CHUNK3}")

    failures += _test_reframer(key)
    failures += _test_stream_callback(key)
    failures += _test_trailer(key)

    # Sanity: the empty hash constant is the well-known SHA256("").
    if EMPTY_HASH != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        failures.append(f"EMPTY_HASH wrong: {EMPTY_HASH}")

    if failures:
        print("FAIL:")
        for f in failures:
            print("  -", f)
        return 1
    print("PASS: seed + chunk-chain vectors match AWS docs; aws-chunked re-framer round-trips + re-signs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
