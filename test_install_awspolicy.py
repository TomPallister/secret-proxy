"""Explicit AWS-policy installation, using disposable files and mocked OS administration."""
import argparse
from contextlib import contextmanager, ExitStack
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


@contextmanager
def installation():
    with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
        root = Path(temporary).resolve()
        source = root / 'source'
        source.mkdir()
        (source / 'manifest.json').write_text(json.dumps({'schemaVersion': 3, 'account': {'vault': 'Fixture'}, 'secrets': {}}))
        (source / 'aws-policy.json').write_text('{"version":1,"rules":[]}')
        user = pwd.getpwuid(os.getuid())
        stack.enter_context(patch.dict(os.environ, {'SUDO_USER': user.pw_name}))
        stack.enter_context(patch('macos_install.sys.platform', 'darwin'))
        stack.enter_context(patch('macos_install.os.getuid', return_value=0))
        stack.enter_context(patch('macos_install.os.chown'))
        stack.enter_context(patch('macos_install.root_owned'))
        stack.enter_context(patch('macos_install.run'))
        stack.enter_context(patch('macos_install.ensure_account', return_value=SimpleNamespace(pw_uid=user.pw_uid, pw_gid=user.pw_gid)))
        for module in (host, installer):
            for name, value in (('ROOT', root / 'install'), ('SHARED_ROOT', root / 'shared'), ('SA_HOME', root / 'secagent')):
                stack.enter_context(patch.object(module, name, value))
        (host.SA_HOME / '.config').mkdir(parents=True)
        def snapshot(repo, commit, destination):
            destination.mkdir()
            for name in installer.FILES:
                (destination / name).write_text('committed fixture')
            (destination / 'source.json').write_text(json.dumps({'commit': commit}))
        stack.enter_context(patch('macos_install.snapshot', side_effect=snapshot))
        args = argparse.Namespace(instance='candidate', machine='secagent', port=10260, repo=root,
                                  commit='a' * 40, config=source, agent_dir=None,
                                  update_networks=False, update_aws_policy=False)
        old_umask = os.umask(0o077)
        stack.callback(os.umask, old_umask)
        installer.install(args)
        deployment = host.Deployment('candidate', 'secagent', 10260)
        yield source, args, deployment


def replacement(source):
    data = b'{"version":1,"rules":[{"action":"deny","service":"sts","operations":["AssumeRole*"]}]}'
    (source / 'aws-policy.json').write_bytes(data)
    return data


class AwsPolicyInstallTests(unittest.TestCase):
    def test_update_is_explicit_stopped_and_changes_only_aws_file(self):
        with installation() as (source, args, deployment):
            destination = deployment.private / 'config'
            before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in destination.iterdir()}
            registration = (host.ROOT / 'instances/candidate.json').read_bytes()
            client = (deployment.shared / 'client.json').read_bytes()
            data = replacement(source)
            with self.assertRaisesRegex(host.HostError, 'private policy'):
                installer.install(args)
            args.update_aws_policy = True
            (deployment.shared / 'ready.json').write_text('{}')
            with patch.object(installer, 'require_stopped_resources') as stopped:
                with self.assertRaisesRegex(host.HostError, 'Stop'):
                    installer.install(args)
                stopped.assert_not_called()
            (deployment.shared / 'ready.json').unlink()
            with patch.object(installer, 'require_stopped_resources') as stopped:
                installer.install(args)
                stopped.assert_called_once_with(deployment)
            self.assertEqual((destination / 'aws-policy.json').read_bytes(), data)
            self.assertEqual((destination / 'aws-policy.json').stat().st_mode & 0o777, 0o644)
            for name, value in before.items():
                if name != 'aws-policy.json':
                    self.assertEqual(((destination / name).read_bytes(), (destination / name).stat().st_mtime_ns), value)
            self.assertEqual((host.ROOT / 'instances/candidate.json').read_bytes(), registration)
            self.assertEqual((deployment.shared / 'client.json').read_bytes(), client)

    def test_unrelated_changes_and_missing_or_invalid_aws_policy_refused(self):
        with installation() as (source, args, deployment):
            args.update_aws_policy = True
            destination = deployment.private / 'config/aws-policy.json'
            old = destination.read_bytes()
            replacement(source)
            manifest = (source / 'manifest.json').read_bytes()
            with patch.object(installer, 'require_stopped_resources'):
                (source / 'manifest.json').write_bytes(manifest + b'\n')
                with self.assertRaisesRegex(host.HostError, 'private policy'):
                    installer.install(args)
                (source / 'manifest.json').write_bytes(manifest)
                args.port += 1
                with self.assertRaises(host.HostError): installer.install(args)
                args.port -= 1
                for data in (b'not-json', b'{"version":1,"rules":[{"action":"invalid"}]}', None):
                    if data is None: (source / 'aws-policy.json').unlink()
                    else: (source / 'aws-policy.json').write_bytes(data)
                    with self.assertRaises(host.HostError): installer.install(args)
                    self.assertEqual(destination.read_bytes(), old)

    def test_running_resource_or_failed_inspection_refuses_before_write(self):
        with installation() as (source, args, deployment):
            args.update_aws_policy = True
            replacement(source)
            destination = deployment.private / 'config/aws-policy.json'
            before = destination.read_bytes()
            with patch.object(installer, 'require_stopped_resources', side_effect=host.HostError('resource exists or inspection failed')):
                with self.assertRaises(host.HostError): installer.install(args)
            self.assertEqual(destination.read_bytes(), before)

    def test_only_one_update_family_and_existing_installation_required(self):
        with installation() as (source, args, deployment):
            replacement(source)
            args.update_aws_policy = args.update_networks = True
            with patch.object(installer, 'install_snapshot') as snapshot:
                with self.assertRaises(host.HostError): installer.install(args)
                snapshot.assert_not_called()
            args.update_networks = False
            args.instance = 'not-installed'
            with self.assertRaises(host.HostError): installer.install(args)

    def test_serve_lock_prevents_policy_update(self):
        import fcntl
        with installation() as (source, args, deployment):
            args.update_aws_policy = True
            replacement(source)
            fd = host.open_instance_lock(deployment, installer=True)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(installer, 'require_stopped_resources') as stopped:
                    with self.assertRaisesRegex(host.HostError, 'Stop'):
                        installer.install(args)
                    stopped.assert_not_called()
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
