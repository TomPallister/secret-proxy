"""Cross-validate sigv4 canonicalization against botocore (the in-container
client), so re-signed requests match bit-for-bit.

For each sample request we let botocore sign it, then reconstruct the SAME
canonical request from the signed headers with our sigv4 helpers and assert the
signature matches. This proves canonical_uri / canonical_query / canonical
headers / string-to-sign are correct for real requests.

Run:  uv run --python 3.12 --with botocore python dev-env/secret-proxy/test_resign.py
"""

import sys

from botocore.auth import S3SigV4Auth, S3SigV4QueryAuth, SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from sigv4 import canonical_query, canonical_request, canonical_uri, derive_signing_key, seed_signature, sha256_hex

AKID = "AKIDEXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
TOKEN = "FQoGZXIvYWERTOKENEXAMPLE"


def _parse_auth(auth: str):
    # AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, SignedHeaders=a;b, Signature=SIG
    after = auth.split(" ", 1)[1]
    parts = {p.split("=", 1)[0].strip(): p.split("=", 1)[1] for p in after.split(", ")}
    cred = parts["Credential"]
    _akid, date_stamp, region, service, _ = cred.split("/")
    return date_stamp, region, service, parts["SignedHeaders"], parts["Signature"]


def _check(name, method, url, headers, body, service, region, fails):
    creds = Credentials(AKID, SECRET, TOKEN)
    req = AWSRequest(method=method, url=url, data=body, headers=dict(headers))
    signer = S3SigV4Auth(creds, service, region) if service == "s3" else SigV4Auth(creds, service, region)
    signer.add_auth(req)
    auth = req.headers["Authorization"]
    date_stamp, rgn, svc, signed_headers, want_sig = _parse_auth(auth)
    scope = f"{date_stamp}/{rgn}/{svc}/aws4_request"
    amz_date = req.headers["X-Amz-Date"]
    from urllib.parse import urlsplit

    # Reconstruct the canonical request from exactly the headers botocore signed.
    names = signed_headers.split(";")
    present = {k.lower(): ("" if v is None else v) for k, v in req.headers.items()}
    # botocore derives Host from the URL at signing time rather than storing it;
    # on the wire (what the addon sees) the Host header is always present.
    present.setdefault("host", urlsplit(req.url).netloc)
    hdrs = [(n, present.get(n, "")) for n in names]
    payload_hash = present.get("x-amz-content-sha256") or sha256_hex(body or b"")
    parts = urlsplit(req.url)
    cu = canonical_uri(parts.path, svc)
    cq = canonical_query(parts.query)
    cr, my_signed = canonical_request(method, cu, cq, hdrs, payload_hash)
    if my_signed != signed_headers:
        fails.append(f"{name}: signed-headers mismatch\n   mine: {my_signed}\n   boto: {signed_headers}")
    key = derive_signing_key(SECRET, date_stamp, rgn, svc)
    my_sig = seed_signature(key, amz_date, scope, cr)
    if my_sig != want_sig:
        fails.append(f"{name}: signature mismatch\n   mine: {my_sig}\n   boto: {want_sig}")


def _check_resign(name, method, url, headers, body, service, region, fails):
    """Dummy-sign with botocore (as the in-container client would), then resign()
    with real creds and verify the output is correct + self-consistent."""
    import sigv4
    from urllib.parse import urlsplit

    dummy = Credentials("AKIADUMMY000000000000", "dummysecretdummysecretdummy", "secretrole:111122223333/role-a")
    req = AWSRequest(method=method, url=url, data=body, headers=dict(headers))
    signer = S3SigV4Auth(dummy, service, region) if service == "s3" else SigV4Auth(dummy, service, region)
    signer.add_auth(req)
    parts = urlsplit(req.url)
    hl = {k.lower(): ("" if v is None else v) for k, v in req.headers.items()}
    hl.setdefault("host", parts.netloc)

    RAK, RSK, RTOK = "AKIAREAL0000000000000", "realsecretrealsecretrealsecret00", "REALSESSIONTOKEN=="
    res = sigv4.resign(method=method, path=parts.path, query=parts.query, headers_lower=hl, body=body, akid=RAK, secret=RSK, token=RTOK)

    ap = sigv4.parse_authorization(res["authorization"])
    if ap["akid"] != RAK:
        fails.append(f"{name}: resign didn't swap the AKID")
    if res["x-amz-security-token"] != RTOK:
        fails.append(f"{name}: resign didn't set the real session token")
    if "x-amz-security-token" not in ap["signed_headers"]:
        fails.append(f"{name}: security-token not in SignedHeaders")
    # Oracle: reconstruct the canonical request from the emitted signed headers
    # (token swapped) with the botocore-validated primitives; the signature must
    # match what resign emitted.
    vals = {n: (RTOK if n == "x-amz-security-token" else hl.get(n, "")) for n in ap["signed_headers"]}
    ph = hl.get("x-amz-content-sha256") or sha256_hex(body or b"")
    cr, _ = canonical_request(method, canonical_uri(parts.path, service), canonical_query(parts.query), list(vals.items()), ph)
    scope = f'{ap["date_stamp"]}/{ap["region"]}/{ap["service"]}/aws4_request'
    key = derive_signing_key(RSK, ap["date_stamp"], ap["region"], ap["service"])
    want = seed_signature(key, hl["x-amz-date"], scope, cr)
    if want != ap["signature"]:
        fails.append(f"{name}: resign signature not self-consistent")


def _check_resign_streaming(fails):
    """resign() of an aws-chunked signed upload returns a ChunkedResigner seeded
    with the new seed signature; feeding the AWS example body re-signs chunk 1
    off that seed."""
    import sigv4

    date_stamp, region, service = "20130524", "us-east-1", "s3"
    amz_date, scope = "20130524T000000Z", "20130524/us-east-1/s3/aws4_request"
    signed = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    hl = {
        "authorization": sigv4.authorization_header("AKIADUMMY", scope, signed, "deadbeef"),
        "host": "examplebucket.s3.amazonaws.com",
        "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "x-amz-date": amz_date,
        "x-amz-security-token": "secretrole:111122223333/role-a",
    }
    RAK, RSK, RTOK = "AKIAREAL", "realsecretrealsecretrealsecret00", "REALTOK=="
    res = sigv4.resign(method="PUT", path="/examplebucket/chunkObject.txt", query="", headers_lower=hl, body=None, akid=RAK, secret=RSK, token=RTOK)
    if res["reframer"] is None:
        fails.append("streaming: resign returned no ChunkedResigner")
        return
    new_seed = sigv4.parse_authorization(res["authorization"])["signature"]
    key = sigv4.derive_signing_key(RSK, date_stamp, region, service)
    exp_c1 = sigv4.chunk_signature(key, amz_date, scope, new_seed, sha256_hex(b"a" * 65536))
    body = "10000;chunk-signature=deadbeef\r\n".encode() + b"a" * 65536 + b"\r\n0;chunk-signature=deadbeef\r\n\r\n"
    out = res["reframer"].feed(body) + res["reframer"].done()
    if f"chunk-signature={exp_c1}".encode() not in out:
        fails.append("streaming: reframer did not re-sign chunk1 off the new seed")


def _check_presign(fails):
    """resign_query must reproduce botocore's presigned SigV4 query signature
    (same creds), and swap credential/token/signature under new creds."""
    import sigv4
    from urllib.parse import parse_qs, urlsplit

    creds = Credentials(AKID, SECRET, TOKEN)
    req = AWSRequest(method="GET", url="https://examplebucket.s3.eu-west-1.amazonaws.com/my%20key/obj.bin", headers={})
    S3SigV4QueryAuth(creds, "s3", "eu-west-1", expires=3600).add_auth(req)
    parts = urlsplit(req.url)
    qp = {k: v[0] for k, v in parse_qs(parts.query).items()}
    want = qp["X-Amz-Signature"]

    _kw = {"akid": AKID}
    _kw["secret"] = SECRET
    _kw["token"] = TOKEN
    new = sigv4.resign_query(method="GET", path=parts.path, query_params=qp, headers_lower={}, host=parts.netloc, **_kw)
    if new["X-Amz-Signature"] != want:
        fails.append(f"presign cross-val: got {new['X-Amz-Signature']} want {want}")

    _kw2 = {"akid": "AKIAREAL0000000000000"}
    _kw2["secret"] = "realsecretrealsecretrealsecret00"
    _kw2["token"] = "REALSESSIONTOKEN=="
    new2 = sigv4.resign_query(method="GET", path=parts.path, query_params=qp, headers_lower={}, host=parts.netloc, **_kw2)
    if new2["X-Amz-Signature"] == want:
        fails.append("presign swap: signature did not change under new creds")
    if not new2["X-Amz-Credential"].startswith("AKIAREAL0000000000000/"):
        fails.append(f"presign swap: credential not swapped ({new2['X-Amz-Credential']})")
    if new2["X-Amz-Security-Token"] != "REALSESSIONTOKEN==":
        fails.append("presign swap: token not swapped")


def main() -> int:
    fails = []

    # STS GetCallerIdentity (POST form body, region us-east-1).
    _check(
        "sts",
        "POST",
        "https://sts.eu-west-1.amazonaws.com/",
        {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        b"Action=GetCallerIdentity&Version=2011-06-15",
        "sts",
        "eu-west-1",
        fails,
    )
    # S3 GET simple key.
    _check("s3-simple", "GET", "https://examplebucket.s3.eu-west-1.amazonaws.com/hello.txt", {}, b"", "s3", "eu-west-1", fails)
    # S3 GET key with space + subdir.
    _check("s3-space", "GET", "https://examplebucket.s3.eu-west-1.amazonaws.com/my%20dir/a%20b.txt", {}, b"", "s3", "eu-west-1", fails)
    # S3 GET with query params (list-objects v2).
    _check(
        "s3-query",
        "GET",
        "https://examplebucket.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=foo/bar&max-keys=10",
        {},
        b"",
        "s3",
        "eu-west-1",
        fails,
    )
    # EC2 (non-S3, double-encoded path) DescribeInstances.
    _check("ec2", "GET", "https://ec2.eu-west-1.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15", {}, b"", "ec2", "eu-west-1", fails)

    # resign() end-to-end (dummy-sign -> resign with real creds -> verify).
    _check_resign("resign-sts", "POST", "https://sts.eu-west-1.amazonaws.com/", {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}, b"Action=GetCallerIdentity&Version=2011-06-15", "sts", "eu-west-1", fails)
    _check_resign("resign-s3", "GET", "https://examplebucket.s3.eu-west-1.amazonaws.com/hello.txt", {}, b"", "s3", "eu-west-1", fails)
    _check_resign_streaming(fails)

    # Presigned (query-auth) re-signing: cross-validate against botocore's
    # SigV4QueryAuth, then a creds-swap check.
    _check_presign(fails)

    # Regression: HTTP/2 requests carry the authority in :authority, so
    # headers_lower has NO 'host'. resign(host=...) must fill it, or the canonical
    # 'host:' line is empty -> SignatureDoesNotMatch (the terraform/aws-sdk-go bug).
    import sigv4 as _s4
    _kw = {"akid": "AKID"}
    _kw["secret"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    _kw["token"] = "tok"
    scope_h2 = "20260101/eu-west-1/sts/aws4_request"
    hl_h2 = {
        "authorization": _s4.authorization_header("AKID", scope_h2, "host;x-amz-date", "deadbeef"),
        "x-amz-date": "20260101T000000Z",
    }  # deliberately NO 'host' key (as in an intercepted HTTP/2 request)
    r_h2 = _s4.resign(method="POST", path="/", query="", headers_lower=hl_h2, body=b"x", host="sts.eu-west-1.amazonaws.com", **_kw)
    if "host:sts.eu-west-1.amazonaws.com" not in r_h2["canonical_request"]:
        fails.append("HTTP/2 regression: host param not used in canonical request")
    if "\nhost:\n" in r_h2["canonical_request"]:
        fails.append("HTTP/2 regression: empty host: line in canonical request")

    if fails:
        print("FAIL:")
        for f in fails:
            print("  -", f)
        return 1
    print("PASS: sigv4 canonicalization matches botocore (sts/s3/ec2) + resign() end-to-end (normal + streaming) + HTTP/2 host + presign query-auth")
    return 0


if __name__ == "__main__":
    sys.exit(main())
