import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import host
import macos_install as installer


class InstallTests(unittest.TestCase):
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
            installer.install(args)
            config = host.Deployment('candidate', 'secagent', 10260).private / 'config/manifest.json'
            before = config.stat().st_mtime_ns
            installer.install(args)
            self.assertEqual(config.stat().st_mtime_ns, before)
            self.assertEqual((prefix / 'current').resolve(), prefix / 'releases' / ('a' * 40))
            self.assertFalse(any('podman' in str(c) for c in commands.call_args_list))
            args.port += 1
            with self.assertRaises(host.HostError):
                installer.install(args)

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
