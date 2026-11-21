import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import host
import macos_install as installer


class InstallTests(unittest.TestCase):
    def test_snapshot_has_public_code_modes_even_with_private_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / 'release'
            def git(args, **kwargs):
                data = b'tree fixture\ngpgsig fixture\n\nfixture' if 'cat-file' in args else b'fixture'
                return subprocess.CompletedProcess(args, 0, data, b'')
            previous = os.umask(0o077)
            try:
                with patch.object(installer.subprocess, 'run', side_effect=git):
                    installer.snapshot(Path(tmp), 'a' * 40, destination)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
                for name in (*installer.FILES, 'source.json'):
                    expected = 0o755 if name == 'secret-proxy' else 0o644
                    self.assertEqual((destination / name).stat().st_mode & 0o777, expected)
            finally:
                os.umask(previous)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforces symlink modes')
    def test_activation_symlink_is_traversable_under_private_umask(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(installer, 'ROOT', Path(tmp)):
            release = Path(tmp) / 'release'
            release.mkdir()
            previous = os.umask(0o077)
            try:
                installer.activate(release)
                self.assertEqual((Path(tmp) / 'current').lstat().st_mode & 0o777, 0o755)
                self.assertEqual((Path(tmp) / 'current').resolve(), release.resolve())
            finally:
                os.umask(previous)

    def test_stages_only_committed_files_and_is_idempotent_without_service_changes(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp).resolve()
            prefix = root / 'install'
            shared = root / 'shared'
            private = root / 'secagent'
            (private / '.config').mkdir(parents=True)
            source = root / 'source'
            source.mkdir()
            (source / 'manifest.json').write_text(json.dumps({'schemaVersion': 3, 'account': {'vault': 'Fixture'}, 'secrets': {}}))
            user = pwd.getpwuid(os.getuid())
            stack.enter_context(patch.dict(os.environ, {'SUDO_USER': user.pw_name}))
            stack.enter_context(patch('macos_install.sys.platform', 'darwin'))
            stack.enter_context(patch('macos_install.os.getuid', return_value=0))
            stack.enter_context(patch('macos_install.os.chown'))
            stack.enter_context(patch('macos_install.root_owned'))
            commands = stack.enter_context(patch('macos_install.run'))
            stopped = stack.enter_context(patch('macos_install.require_stopped_resources'))
            account = SimpleNamespace(pw_uid=user.pw_uid, pw_gid=user.pw_gid)
            stack.enter_context(patch('macos_install.ensure_account', return_value=account))
            for module in (host, installer):
                stack.enter_context(patch.object(module, 'ROOT', prefix))
                stack.enter_context(patch.object(module, 'SHARED_ROOT', shared))
                stack.enter_context(patch.object(module, 'SA_HOME', private))
            def snapshot(repo, commit, destination):
                destination.mkdir()
                for name in installer.FILES:
                    (destination / name).write_text('committed fixture')
                (destination / 'source.json').write_text(json.dumps({'commit': commit}))
            stack.enter_context(patch('macos_install.snapshot', side_effect=snapshot))
            args = argparse.Namespace(instance='candidate', machine='secagent', port=10260,
                                      repo=root, commit='a' * 40, config=source, agent_dir=None)
            previous = os.umask(0o077)
            stack.callback(os.umask, previous)
            installer.install(args)
            deployment = host.Deployment('candidate', 'secagent', 10260)
            config = deployment.private / 'config/manifest.json'
            before = config.stat().st_mtime_ns
            release = prefix / 'releases' / ('a' * 40)
            for directory in (prefix, prefix / 'releases', prefix / 'instances', shared,
                              release, deployment.private / 'config'):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
            self.assertEqual(deployment.private.stat().st_mode & 0o777, 0o700)
            self.assertEqual(deployment.shared.stat().st_mode & 0o777, 0o750)
            release.chmod(0o700)  # Repair an already-staged v0.1.0 release, not only fresh installs.
            installer.install(args)
            self.assertEqual(release.stat().st_mode & 0o777, 0o755)
            self.assertEqual(config.stat().st_mtime_ns, before)
            self.assertEqual((prefix / 'current').resolve(), prefix / 'releases' / ('a' * 40))
            self.assertFalse(any('podman' in str(c) for c in commands.call_args_list))
            from test_vpn_selection import external
            catalog = {'version': 1, 'networks': {'corp-vpn': external()}}
            (source / 'networks.json').write_text(json.dumps(catalog))
            with self.assertRaises(host.HostError):
                installer.install(args)  # No implicit private-policy overwrite.
            args.update_networks = True
            (deployment.shared / 'ready.json').write_text('{}')
            with self.assertRaisesRegex(host.HostError, 'Stop'):
                installer.install(args)
            (deployment.shared / 'ready.json').unlink()
            installer.install(args)
            stopped.assert_called_once()
            registered = json.loads((prefix / 'instances/candidate.json').read_text())
            self.assertEqual(registered['networks'], catalog['networks'])
            self.assertEqual(config.stat().st_mtime_ns, before)
            self.assertEqual((deployment.private / 'config/networks.json').read_text(), json.dumps(catalog))
            # Network updates cannot override manifest/CA/AWS/client policy.
            (source / 'manifest.json').write_text((source / 'manifest.json').read_text() + '\n')
            with self.assertRaisesRegex(host.HostError, 'private policy'):
                installer.install(args)
            args.port += 1
            with self.assertRaises(host.HostError):
                installer.install(args)

    def test_network_update_requires_all_owned_resources_absent_and_engine_available(self):
        deployment = host.Deployment('candidate', 'secagent', 10260)
        for result in (0, 125):
            with patch.object(installer.subprocess, 'run', return_value=subprocess.CompletedProcess([], result)) as run:
                with self.assertRaises(host.HostError): installer.require_stopped_resources(deployment)
                self.assertIn('exists', run.call_args.args[0])
        with patch.object(installer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)) as run:
            installer.require_stopped_resources(deployment)
            self.assertEqual([c.args[0][-1] for c in run.call_args_list], ['sp-candidate', 'sp-candidate-relay', 'sp-candidate-vpn'])
            self.assertTrue(all(c.args[0][:4] == ['/usr/bin/sudo', '-n', '-u', 'secagent'] for c in run.call_args_list))

    def test_name_constrained_ca_opt_in_is_validated_and_copied_as_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'config'
            config.mkdir()
            def write(hosts, ca):
                (config / 'manifest.json').write_text(json.dumps({'schemaVersion': 3, 'account': {'vault': 'Fixture'},
                    'secrets': {'EXAMPLE_TOKEN': {'placements': [{'kind': 'header', 'hosts': hosts,
                    'name': 'authorization', 'template': 'Bearer {secret}'}]}}}))
                (config / 'ca.json').write_text(ca)
            write(['api.example.com', '*.example.org'], '{"mode": "name-constrained"}')
            self.assertIn('ca.json', installer.validate_source_config(config))
            self.assertIn('ca.json', installer.POLICY_FILES)
            for hosts, ca in ((['*.com'], '{"mode": "name-constrained"}'),
                              (['api.example.com'], '{"mode": "anything"}')):
                write(hosts, ca)
                with self.subTest(hosts=hosts, ca=ca), self.assertRaises(host.HostError):
                    installer.validate_source_config(config)
            (config / 'ca.json').unlink()
            write(['*.com'], '{}')
            (config / 'ca.json').unlink()
            installer.validate_source_config(config)  # wildcards stay valid without the opt-in

    def test_private_config_symlinks_and_unrecognised_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config'
            config.mkdir()
            target = root / 'external'
            target.write_text('{}')
            (config / 'manifest.json').symlink_to(target)
            with self.assertRaises(host.HostError):
                installer.validate_source_config(config)
            (config / 'manifest.json').unlink()
            (config / 'manifest.json').write_text(json.dumps({'schemaVersion': 3, 'account': {'vault': 'Fixture'}, 'secrets': {}, 'credential': 'must-not-be-copied'}))
            with self.assertRaises(ValueError):
                installer.validate_source_config(config)
