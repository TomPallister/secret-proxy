"""Unit tests for sealedjwt.py (sealed JWT references)."""
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sealedjwt  # noqa: E402

MARKER = "secret" + "ref:"


def _enc(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


REAL = f"{_enc({'alg': 'RS256'})}.{_enc({'aud': 'https://x.example'})}.cmVhbC1zaWduYXR1cmU"


class TestSealedJwt(unittest.TestCase):
    def test_seal_keeps_header_and_claims_and_drops_the_signature(self):
        sealed = sealedjwt.seal(REAL, "CHECKMARX_ACCESS_TOKEN")
        self.assertEqual(REAL.rsplit(".", 1)[0], sealed.rsplit(".", 1)[0])
        self.assertNotIn("cmVhbC1zaWduYXR1cmU", sealed)
        self.assertTrue(sealedjwt.is_sealed(sealed))
        self.assertFalse(sealedjwt.is_sealed(REAL))

    def test_unseal_restores_the_plain_reference_in_context(self):
        sealed = sealedjwt.seal(REAL, "CHECKMARX_ACCESS_TOKEN")
        self.assertEqual(f"Bearer {MARKER}CHECKMARX_ACCESS_TOKEN", sealedjwt.unseal(f"Bearer {sealed}"))
        self.assertEqual(
            f"a={MARKER}CHECKMARX_ACCESS_TOKEN&b=1",
            sealedjwt.unseal(f"a={sealed}&b=1"),
        )

    def test_unseal_leaves_everything_else_alone(self):
        for value in (
            REAL,
            "Bearer plain-token",
            "dummy.dummy.dummy",
            # Starts like a sealed segment but does not decode to a reference.
            f"{_enc({})}.{_enc({})}.{sealedjwt.SEALED_SEGMENT_PREFIX}AAAA",
            # Embedded inside a longer dotted value: not a standalone token.
            "x." + sealedjwt.seal(REAL, "NAME") + ".y",
        ):
            with self.subTest(value=value):
                self.assertEqual(value, sealedjwt.unseal(value))

    def test_seal_refuses_values_that_are_not_compact_jwts(self):
        for value in ("not-a-jwt", "a.b", "a.b.c.d", "a.b.c d", ""):
            with self.subTest(value=value):
                with self.assertRaises(sealedjwt.SealedJwtError):
                    sealedjwt.seal(value, "NAME")
        with self.assertRaises(sealedjwt.SealedJwtError):
            sealedjwt.seal(REAL, "bad name")

    def test_marker_is_plain_ascii(self):
        self.assertEqual(b"secre" + b"tref:", sealedjwt.MARKER.encode("ascii"))


if __name__ == "__main__":
    unittest.main()
