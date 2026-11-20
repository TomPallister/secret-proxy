import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import setup
from secretstore import SecretManifest


class SetupTests(unittest.TestCase):
    def create(self, path, answers=None):
        with patch('builtins.input', side_effect=answers or [
                'example.1password.com', '', '', '', '', 'y', '']):
            setup.initialise(path)

    def test_init_generates_valid_private_metadata_not_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / 'settings'
            self.create(base)
            self.assertEqual(base.stat().st_mode & 0o777, 0o700)
            config = base / 'config'
            self.assertEqual(set(p.name for p in config.iterdir()),
                             {'manifest.json', 'bootstrap.json', 'client-environment.json', 'ca.json', 'aws-policy.json'})
            self.assertEqual(config.stat().st_mode & 0o777, 0o700)
            for p in config.iterdir():
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            manifest = SecretManifest.load(config / 'manifest.json')
            self.assertEqual(set(json.loads((config / 'manifest.json').read_text())['secrets']),
                             {'GITHUB_TOKEN', 'CHATGPT_ACCESS_TOKEN'})
            manifest.secret('GITHUB_TOKEN'); manifest.secret('CHATGPT_ACCESS_TOKEN')
            self.assertEqual(json.loads((config / 'client-environment.json').read_text())['GITHUB_TOKEN'],
                             'secret' + 'ref:GITHUB_TOKEN')
            bootstrap = json.loads((config / 'bootstrap.json').read_text())
            self.assertEqual(bootstrap, {'account': 'example.1password.com', 'vault': 'Private',
                'item': 'Secret Proxy Bootstrap', 'runtimeVault': 'DevEnv'})
            self.assertNotIn('cli.json', [p.name for p in base.iterdir()])
            self.assertEqual(json.loads((config / 'ca.json').read_text()), {'mode': 'name-constrained'})
            setup.validate_source_config(config)

    def test_name_constrained_ca_is_the_new_install_default_and_can_be_declined(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / 'settings'
            self.create(base, ['example.1password.com', '', '', '', '', 'n', 'n'])
            self.assertFalse((base / 'config/ca.json').exists())
            with self.assertRaises(setup.SetupError):
                self.create(Path(tmp) / 'other', ['example.1password.com', '', '', '', '', 'n', 'maybe'])
            self.assertFalse((Path(tmp) / 'other').exists())

    def test_existing_paths_symlinks_and_repository_locations_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for path in (base, base / 'link'):
                if path != base: path.symlink_to(base / 'missing')
                with patch('builtins.input') as ask, self.assertRaises(setup.SetupError):
                    setup.initialise(path)
                ask.assert_not_called()
            with patch.object(setup, 'REPO', base), self.assertRaises(setup.SetupError):
                setup.initialise(base / 'private-config')

    def test_invalid_answers_leave_no_files_or_side_effects(self):
        for answers in ([ 'not-an-account', '', '', '', '', ''],
                        ['example.1password.com', 'Private', 'Private', '', '', ''],
                        ['example.1password.com', '', '', '', 'n', 'n']):
            with tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp) / 'settings'
                with self.assertRaises(setup.SetupError): self.create(base, answers)
                self.assertFalse(base.exists())

    def test_github_demo_is_read_only_and_codex_is_optional(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / 'settings'
            self.create(base, ['example.1password.com', '', '', '', '', 'n', ''])
            manifest = json.loads((base / 'config/manifest.json').read_text())
            self.assertEqual(set(manifest['secrets']), {'GITHUB_TOKEN'})
            placement = manifest['secrets']['GITHUB_TOKEN']['placements'][0]
            self.assertEqual(placement['methods'], ['GET', 'HEAD'])
            self.assertEqual(placement['hosts'], ['api.github.com'])

    def fixture_install(self, tmp, stack):
        base = tmp / 'settings'; self.create(base)
        install_root = tmp / 'installed'
        repo = tmp / 'repo'; repo.mkdir()
        executable = tmp / 'op'; executable.write_text('fixture'); executable.chmod(0o755)
        stack.enter_context(patch.object(setup, 'REPO', repo))
        stack.enter_context(patch.object(setup, 'ROOT', install_root))
        stack.enter_context(patch.object(setup, 'LINK', tmp / 'bin/secret-proxy'))
        stack.enter_context(patch.object(setup.sys, 'platform', 'darwin'))
        stack.enter_context(patch.object(setup.os, 'getuid', return_value=501))
        stack.enter_context(patch.object(setup, 'source_revision', return_value='a' * 40))
        stack.enter_context(patch.object(setup.shutil, 'which', return_value=str(executable)))
        def installed(command, **kwargs):
            release = install_root / 'releases' / ('a' * 40)
            release.mkdir(parents=True)
            (release / 'secret-proxy').write_text('fixture')
            return subprocess.CompletedProcess(command, 0)
        call = stack.enter_context(patch.object(setup.subprocess, 'run', side_effect=installed))
        return base, call

    def test_install_registers_only_then_wires_private_cli_and_pinned_link(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            base, call = self.fixture_install(Path(tmp), stack)
            setup.install(base, 'local', 10260, Path(tmp) / 'agent')
            command = call.call_args.args[0]
            self.assertEqual(command[:2], ['/usr/bin/sudo', setup.PYTHON])
            self.assertIn('macos_install.py', command[2])
            self.assertNotIn('up', command)
            self.assertEqual(call.call_count, 1)
            metadata = base / 'cli.json'
            self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(metadata.read_text())['instance'], 'local')
            self.assertEqual(setup.LINK.readlink(), setup.ROOT / 'releases' / ('a' * 40) / 'secret-proxy')

    def test_install_refuses_existing_deployment_cli_or_command_before_sudo(self):
        for collision in ('deployment', 'metadata', 'command'):
            with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                base, call = self.fixture_install(Path(tmp), stack)
                if collision == 'deployment':
                    setup.ROOT.mkdir()
                elif collision == 'metadata':
                    (base / 'cli.json').write_text('{}')
                else:
                    setup.LINK.parent.mkdir(); setup.LINK.symlink_to('/missing')
                with self.assertRaises(setup.SetupError): setup.install(base, 'local', 10260, None)
                call.assert_not_called()

    def test_vault_mismatch_stops_before_sudo(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            base, call = self.fixture_install(Path(tmp), stack)
            path = base / 'config/bootstrap.json'
            value = json.loads(path.read_text()); value['runtimeVault'] = 'AnotherVault'
            path.write_text(json.dumps(value))
            with self.assertRaises(setup.SetupError): setup.install(base, 'local', 10260, None)
            call.assert_not_called()

    def test_failed_sudo_does_not_create_cli_or_link(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            base, call = self.fixture_install(Path(tmp), stack)
            call.side_effect = subprocess.CalledProcessError(1, ['sudo'])
            with self.assertRaises(subprocess.CalledProcessError): setup.install(base, 'local', 10260, None)
            self.assertFalse((base / 'cli.json').exists())
            self.assertFalse(setup.LINK.is_symlink())

    def test_dirty_unsigned_or_untrusted_source_is_rejected(self):
        for mode in ('dirty', 'unsigned'):
            def git(command, **kwargs):
                if 'status' in command: return subprocess.CompletedProcess(command, 0, 'dirty' if mode == 'dirty' else '')
                if 'rev-parse' in command: return subprocess.CompletedProcess(command, 0, 'a' * 40)
                raise subprocess.CalledProcessError(1, command)
            with patch.object(setup.subprocess, 'run', side_effect=git), self.assertRaises(setup.SetupError):
                setup.source_revision()

    def test_help_does_not_need_privileges_or_configuration(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            setup.main(['--help'])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn('init', output.getvalue())


if __name__ == '__main__':
    unittest.main()
