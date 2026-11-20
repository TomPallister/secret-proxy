import json
import contextlib
import io
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

import host

from host import Deployment, HostError, bootstrap_env, container_command, validate_bootstrap_item
from migrate_config import MigrationError, convert, export


class HostTests(unittest.TestCase):
    def deployment(self, **kwargs):
        return Deployment.from_dict({'instance': 'candidate', 'machine': 'secagent', 'port': 10260, **kwargs})

    def test_fixed_loopback_readonly_capability_dropped_contract(self):
        cmd = container_command(self.deployment(), 'sha256:' + 'a' * 64)
        self.assertIn('127.0.0.1:10260:10256', cmd)
        self.assertIn('--read-only', cmd)
        self.assertIn('--cap-drop=ALL', cmd)
        self.assertIn('--security-opt=no-new-privileges', cmd)
        self.assertIn('--log-driver=none', cmd)
        self.assertIn('--userns=keep-id:uid=1000,gid=1000', cmd)
        self.assertIn('--init', cmd)
        self.assertNotIn('--privileged', cmd)
        self.assertFalse(any('op_token' in arg or 'OP_SERVICE' in arg for arg in cmd))
        self.assertEqual(cmd[-1], 'sha256:' + 'a' * 64)
        self.assertFalse(any('/Users/example' in arg for arg in cmd))
        # The instance label for an opt-in constrained CA is set before the image.
        self.assertEqual(cmd[cmd.index('SECRET_PROXY_CA_LABEL=candidate') - 1], '--env')
        self.assertLess(cmd.index('SECRET_PROXY_CA_LABEL=candidate'), cmd.index('sha256:' + 'a' * 64))
        self.assertTrue({'capolicy.py', 'constrainedca.py'} <= set(host.BUILD_FILES))

    def test_invalid_deployment_cannot_choose_paths_or_executables(self):
        for change in ({'instance': '../live'}, {'instance': 'secret-proxy'},
                       {'machine': '--bad'}, {'port': True}, {'port': 80},
                       {'engine': '/tmp/evil'}, {'sharedDir': '/etc/live'}, {'image': 'latest'}):
            with self.subTest(change=change), self.assertRaises(HostError):
                self.deployment(**change)

    def test_host_bootstrap_drops_inherited_capabilities_and_proxy(self):
        env = bootstrap_env('/Users/example', {'PATH': '/tmp', 'OP_SERVICE_ACCOUNT_TOKEN': 'bad',
                                              'OP_SESSION_example': 'bad', 'HTTPS_PROXY': 'bad',
                                              'GITHUB_TOKEN': 'bad', 'NODE_OPTIONS': 'bad'})
        self.assertEqual(env, {'HOME': '/Users/example', 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})

    def test_relay_exec_replaces_process_and_does_not_inherit_sensitive_environment(self):
        script = """import os, sys
from host import relay_exec
os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = 'must-not-cross'
child = "import json,os,sys; x=json.load(sys.stdin); assert x['op_token']=='fixture'; assert 'OP_SERVICE_ACCOUNT_TOKEN' not in os.environ; print('relayed')"
relay_exec([sys.executable, '-c', child], {'op_token': 'fixture', 'proxy_token': 'a'*48})
raise AssertionError('exec returned')
"""
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'relayed')

    def test_build_uses_disposable_allowlisted_context_not_installed_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'release'
            source.mkdir()
            for name in host.BUILD_FILES:
                (source / name).write_text('fixture ' + name)
            (source / 'unrelated.json').write_text('must-not-be-copied')
            work = root / 'private'
            work.mkdir()
            deployment = self.deployment()
            contexts = []
            def build(_deployment, *args, **kwargs):
                context = Path(args[-1])
                contexts.append(context)
                self.assertNotEqual(context, source)
                self.assertEqual(context.parent, work)
                self.assertEqual(context.stat().st_mode & 0o777, 0o700)
                self.assertEqual({p.name for p in context.iterdir()}, set(host.BUILD_FILES))
                # Reproduce the write performed by Podman's remote --secret path.
                (context / 'podman-build-secret-fixture').write_text('public-ca-fixture')
                self.assertEqual((context / 'Dockerfile').read_bytes(), (source / 'Dockerfile').read_bytes())
                return subprocess.CompletedProcess(args, 0, b'', b'')
            with patch.object(host, 'engine', side_effect=build):
                host.build_image(deployment, source, work, root / 'ca.pem', root / 'image-id')
            self.assertFalse(contexts[0].exists())
            self.assertFalse((source / 'podman-build-secret-fixture').exists())

    def test_failed_build_shows_bounded_diagnostics_and_cleans_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'release'
            source.mkdir()
            for name in host.BUILD_FILES:
                (source / name).write_text('fixture')
            output = io.StringIO()
            failure = subprocess.CompletedProcess([], 125, b'old output\n' * 1000,
                                                  b'Error: creating temp file: permission denied\n')
            with patch.object(host, 'engine', return_value=failure), contextlib.redirect_stderr(output):
                with self.assertRaisesRegex(HostError, 'before credential bootstrap'):
                    host.build_image(self.deployment(), source, root, root / 'absent-ca.pem', root / 'image-id')
            self.assertIn('permission denied', output.getvalue())
            self.assertLess(len(output.getvalue()), 10000)
            self.assertFalse(list(root.glob('build-*')))
            # Credential-bearing operations must retain their existing suppression.
            with self.assertRaises(HostError) as error:
                host.checked(failure, 'desktop bootstrap')
            self.assertNotIn('permission denied', str(error.exception))

    def test_bootstrap_exact_identity_and_provenance(self):
        config = {'account': 'example.1password.com', 'vault': 'Private', 'item': 'Runtime capability', 'runtimeVault': 'DevEnv'}
        item = {'title': config['item'], 'id': 'a' * 26, 'category': 'LOGIN', 'vault': {'name': 'Private'},
                'fields': [{'id': 'password', 'type': 'CONCEALED', 'purpose': 'PASSWORD', 'value': 'fixture-capability'},
                           {'label': 'account_url', 'value': config['account']},
                           {'label': 'destination_vault', 'value': 'DevEnv'},
                           {'label': 'permissions', 'value': 'read_items'}]}
        self.assertEqual(validate_bootstrap_item(config, item), 'fixture-capability')
        for change in ({'title': 'different'}, {'category': 'SSH_KEY'}, {'state': 'ARCHIVED'}, {'vault': {'name': 'DevEnv'}}, {'fields': []}):
            with self.subTest(change=change), self.assertRaises(HostError):
                validate_bootstrap_item(config, {**item, **change})


class MigrationTests(unittest.TestCase):
    def source(self):
        return {'schemaVersion': 2, 'accounts': {
            'alpha': {'onepasswordAccount': 'example.1password.com', 'onepasswordVault': 'DevEnv',
                      'onepasswordBootstrapVault': 'Private', 'serviceAccountTokenItem': 'Runtime capability'},
            'beta': {'onepasswordAccount': 'different.1password.com', 'onepasswordVault': 'Elsewhere',
                     'onepasswordBootstrapVault': 'Private', 'serviceAccountTokenItem': 'Different capability'}},
            'secrets': {'EXAMPLE': {'account': 'alpha', 'profiles': ['selected'], 'internalOnly': True},
                        'UNRELATED': {'account': 'beta', 'profiles': ['excluded'], 'internalOnly': True}}}

    def test_filters_unselected_and_removes_routing_metadata(self):
        manifest, bootstrap = convert(self.source(), 'selected')
        self.assertEqual(manifest, {'schemaVersion': 3, 'account': {'vault': 'DevEnv'},
                                   'secrets': {'EXAMPLE': {'internalOnly': True}}})
        self.assertEqual(bootstrap['account'], 'example.1password.com')

    def test_mixed_vaults_and_empty_selection_fail_closed(self):
        source = self.source()
        source['secrets']['UNRELATED']['profiles'] = ['selected']
        for data, profile in ((source, 'selected'), (self.source(), 'missing')):
            with self.assertRaises(MigrationError):
                convert(data, profile)

    def test_export_private_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'legacy.json'
            source.write_text(json.dumps(self.source()))
            target = root / 'out'
            export(source, target, 'selected')
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            self.assertEqual((target / 'manifest.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                export(source, target, 'selected')


if __name__ == '__main__':
    unittest.main()
