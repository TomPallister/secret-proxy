"""Tests for race-safe proxy authentication token file handling."""

import importlib
import os
import stat
import tempfile
import unittest
from pathlib import Path

try:
    proxy_token = importlib.import_module("proxy_token")
except ModuleNotFoundError:
    proxy_token = None


VALID = ("a" * 48).encode()


class ProxyTokenTestCase(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(proxy_token, "proxy_token module must exist")
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_validate_accepts_exact_token_with_optional_final_newline(self):
        self.assertEqual(proxy_token.validate_token(VALID), VALID.decode())
        self.assertEqual(proxy_token.validate_token(VALID + b"\n"), VALID.decode())

    def test_validate_rejects_every_other_shape(self):
        invalid = (
            b"",
            b" " * 48,
            b"A" * 48,
            b"a" * 47,
            b"a" * 49,
            VALID + b"\n\n",
            VALID + b" ",
            b"g" * 48,
        )
        for value in invalid:
            with self.subTest(value=value[:8]):
                with self.assertRaises(proxy_token.ProxyTokenError):
                    proxy_token.validate_token(value)

    def test_secure_private_reads_and_repairs_same_regular_file(self):
        path = self.root / "proxy-token"
        path.write_bytes(VALID + b"\n")
        path.chmod(0o644)

        actual = proxy_token.secure_private(path, self.uid, self.gid)

        self.assertEqual(actual, VALID.decode())
        metadata = path.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual((metadata.st_uid, metadata.st_gid), (self.uid, self.gid))

    def test_private_path_rejects_symlink_fifo_and_symlinked_ancestor(self):
        target = self.root / "target"
        target.write_bytes(VALID + b"\n")
        symlink = self.root / "proxy-token"
        symlink.symlink_to(target)
        with self.assertRaises(proxy_token.ProxyTokenError):
            proxy_token.secure_private(symlink, self.uid, self.gid)
        symlink.unlink()

        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(proxy_token.ProxyTokenError):
            proxy_token.secure_private(fifo, self.uid, self.gid)
        fifo.unlink()

        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        (real_parent / "proxy-token").write_bytes(VALID + b"\n")
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(proxy_token.ProxyTokenError):
            proxy_token.secure_private(
                linked_parent / "proxy-token", self.uid, self.gid
            )

    def test_ensure_directory_creates_private_path_without_following_symlinks(self):
        self.assertTrue(
            hasattr(proxy_token, "ensure_directory"),
            "proxy_token.ensure_directory must exist",
        )
        nested = self.root / "config" / "secret-proxy"
        proxy_token.ensure_directory(nested, self.uid, self.gid)
        self.assertTrue(nested.is_dir())
        self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o700)

        real_parent = self.root / "real-config"
        real_parent.mkdir()
        linked_parent = self.root / "linked-config"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(proxy_token.ProxyTokenError):
            proxy_token.ensure_directory(
                linked_parent / "secret-proxy", self.uid, self.gid
            )

    def test_create_is_exclusive_and_does_not_follow_existing_path(self):
        path = self.root / "proxy-token"
        proxy_token.create_private(path, VALID + b"\n", self.uid, self.gid)
        self.assertEqual(path.read_bytes(), VALID + b"\n")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        with self.assertRaises(proxy_token.ProxyTokenError):
            proxy_token.create_private(path, b"b" * 48 + b"\n", self.uid, self.gid)
        self.assertEqual(path.read_bytes(), VALID + b"\n")

    def test_publish_is_atomic_group_readable_and_rejects_nonregular_destination(self):
        source = self.root / "private-token"
        proxy_token.create_private(source, VALID + b"\n", self.uid, self.gid)
        shared = self.root / "shared"
        shared.mkdir()
        destination = shared / "proxy-token"

        proxy_token.publish(source, destination, self.uid, self.gid)

        self.assertEqual(destination.read_bytes(), VALID + b"\n")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)
        self.assertEqual(
            (destination.stat().st_uid, destination.stat().st_gid),
            (self.uid, self.gid),
        )
        self.assertEqual(list(shared.glob(".proxy-token.tmp.*")), [])

        destination.unlink()
        destination.mkdir()
        with self.assertRaises(proxy_token.ProxyTokenError):
            proxy_token.publish(source, destination, self.uid, self.gid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
