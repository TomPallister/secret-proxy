"""Unit tests for GoogleTokenProvider (mint + cache; HTTP is stubbed).

Run:  uv run --python 3.12 python dev-env/secret-proxy/test_googlecreds.py
"""

import sys

from googlecreds import GoogleTokenError, GoogleTokenProvider


def main() -> int:
    fails = []

    # get_secret resolves the three OAuth secret names; record what was asked for.
    asked = []

    def get_secret(name):
        asked.append(name)
        return {
            "GOOGLE_CLIENT_ID": "CID",
            "GOOGLE_CLIENT_SECRET": "CSECRET",
            "GOOGLE_REFRESH_TOKEN": "RTOKEN",
        }[name]

    p = GoogleTokenProvider(get_secret)

    # Stub the token endpoint; count calls.
    calls = {"n": 0}

    def fake_fetch(form):
        calls["n"] += 1
        # sanity: the form carries the refresh-token grant with resolved secrets
        if form.get("grant_type") != "refresh_token":
            fails.append(f"grant_type wrong: {form.get('grant_type')}")
        if form.get("client_id") != "CID" or form.get("refresh_token") != "RTOKEN":
            fails.append("form did not carry resolved secrets")
        return {"access_token": f"ya29.token{calls['n']}", "expires_in": 3600}

    p._fetch = fake_fetch  # type: ignore[assignment]

    # 1) First call mints; second call is served from cache (no 2nd fetch).
    t1 = p.get_token()
    t2 = p.get_token()
    if calls["n"] != 1:
        fails.append(f"expected 1 mint, got {calls['n']}")
    if t1 != t2 or not t1.startswith("ya29.token"):
        fails.append(f"token inconsistent: {t1!r} {t2!r}")
    if set(asked) != {"GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REFRESH_TOKEN"}:
        fails.append(f"unexpected secret lookups: {asked}")

    # 2) Expired token refreshes.
    p._exp = 0.0  # force expiry
    t3 = p.get_token()
    if calls["n"] != 2 or t3 == t1:
        fails.append(f"expected refresh on expiry (n={calls['n']}, t3={t3!r})")

    # 3) A short-TTL token respects the skew (expires early).
    p2 = GoogleTokenProvider(get_secret, skew=120)
    p2._fetch = lambda form: {"access_token": "short", "expires_in": 60}  # type: ignore[assignment]
    p2.get_token()
    if p2._exp > __import__("time").time() + 1:
        fails.append("skew not applied: 60s TTL with 120s skew should already be expired")

    # 4) Missing access_token -> GoogleTokenError.
    p3 = GoogleTokenProvider(get_secret)
    p3._fetch = lambda form: {"error": "invalid_grant", "error_description": "bad refresh"}  # type: ignore[assignment]
    try:
        p3.get_token()
        fails.append("expected GoogleTokenError on missing access_token")
    except GoogleTokenError as e:
        if "bad refresh" not in str(e):
            fails.append(f"error missing detail: {e}")

    if fails:
        print("FAIL:")
        for f in fails:
            print("  -", f)
        return 1
    print("PASS: GoogleTokenProvider mint + cache + skew + refresh + error handling")
    return 0


if __name__ == "__main__":
    sys.exit(main())
