import fcntl
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import host


class InstanceLockTests(unittest.TestCase):
    def test_lock_serializes_serve_and_install(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(host, 'SA_HOME', Path(tmp)):
            dep = host.Deployment('fixture', 'secagent', 10260)
            dep.private.mkdir(parents=True)
            first = host.open_instance_lock(dep)
            second = host.open_instance_lock(dep, installer=True)
            try:
                fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError): fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(first); os.close(second)

    def test_privileged_update_refuses_links_nonempty_and_public_lock(self):
        for kind in ('hardlink', 'symlink', 'nonempty', 'public'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp, patch.object(host, 'SA_HOME', Path(tmp)):
                dep = host.Deployment('fixture', 'secagent', 10260)
                dep.private.mkdir(parents=True)
                target = Path(tmp) / 'victim'; target.touch(mode=0o600)
                lock = dep.private / 'serve.lock'
                if kind == 'hardlink': os.link(target, lock)
                elif kind == 'symlink': lock.symlink_to(target)
                elif kind == 'nonempty': lock.write_text('must not become a lock'); lock.chmod(0o600)
                else: lock.touch(mode=0o644)
                with patch.object(host.os, 'fchown') as change:
                    with self.assertRaises((OSError, host.HostError)): host.open_instance_lock(dep, installer=True)
                    change.assert_not_called()
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                self.assertEqual(target.read_bytes(), b'')

    def test_symlinked_private_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(host, 'SA_HOME', Path(tmp)):
            base = Path(tmp); (base / 'outside').mkdir()
            (base / '.config').symlink_to(base / 'outside')
            dep = host.Deployment('fixture', 'secagent', 10260)
            dep.private.mkdir(parents=True)
            with self.assertRaises(host.HostError): host.open_instance_lock(dep, installer=True)
            self.assertFalse((dep.private / 'serve.lock').exists())
