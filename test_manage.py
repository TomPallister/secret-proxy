import contextlib
import io
import json
import plistlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import manage
import capolicy


class ManageTests(unittest.TestCase):
    def settings(self):
        return {'instance': 'candidate', 'bootstrap': '/private/example/bootstrap.json', 'op': '/opt/example/op'}

    def test_config_accepts_metadata_only_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cli.json'
            path.write_text(json.dumps(self.settings())); path.chmod(0o600)
            self.assertEqual(manage.load_settings(path), self.settings())
            alias = Path(tmp) / 'alias'; alias.symlink_to(path)
            with self.assertRaises(OSError): manage.load_settings(alias)
            for change in ({'instance': '../legacy'}, {'instance': 'secret-proxy'},
                           {'op': 'op'}, {'bootstrap': '/path\nextra'},
                           {'op_token': 'must-not-be-accepted'}, {'engine': '/tmp/evil'}):
                path.write_text(json.dumps({**self.settings(), **change}))
                with self.subTest(change=change), self.assertRaises(manage.ClientError):
                    manage.load_settings(path)

    def test_login_run_and_start_use_installed_code_and_do_not_install(self):
        settings = self.settings()
        with patch.object(manage.os, 'execv') as execute:
            manage.execute(settings, 'login')
            self.assertEqual(execute.call_args.args[0], manage.PYTHON)
            self.assertEqual(execute.call_args.args[1], [manage.PYTHON, str(manage.ROOT / 'current/client.py'),
                '--config', str(manage.SHARED_ROOT / 'candidate/client.json'), 'login'])
            manage.execute(settings, 'run', ['--', '/usr/bin/true'])
            self.assertEqual(execute.call_args.args[1][-3:], ['run', '--', '/usr/bin/true'])
            client = Mock(); client.check_ready.side_effect = OSError('not ready')
            with patch.object(manage, 'selected_client', return_value=client), patch.object(manage.os, 'isatty', return_value=True):
                manage.execute(settings, 'start')
            self.assertEqual(execute.call_args.args[1], [manage.PYTHON, str(manage.ROOT / 'current/host.py'),
                'up', 'candidate', '--bootstrap', settings['bootstrap'], '--op', settings['op']])

    def test_start_is_idempotent_and_never_restarts_a_ready_proxy(self):
        with patch.object(manage, 'selected_client', return_value=Mock()), patch.object(manage.os, 'execv') as execute, patch.object(manage.os, 'isatty', return_value=True), contextlib.redirect_stdout(io.StringIO()):
            manage.execute(self.settings(), 'start')
            execute.assert_not_called()

    def test_unavailable_start_needs_a_terminal_and_run_needs_a_command(self):
        client = Mock(); client.check_ready.side_effect = OSError('not ready')
        with patch.object(manage, 'selected_client', return_value=client), patch.object(manage.os, 'isatty', return_value=False), patch.object(manage.os, 'execv') as execute:
            with self.assertRaises(manage.ClientError): manage.execute(self.settings(), 'start')
            with self.assertRaises(manage.ClientError): manage.execute(self.settings(), 'run')
            execute.assert_not_called()

    def test_stop_is_instance_scoped_and_waits_before_returning(self):
        with patch.object(manage, 'controller_pids', return_value=[123]) as ids, patch.object(manage.subprocess, 'run') as run, patch.object(manage, 'wait_controllers') as wait:
            manage.execute(self.settings(), 'stop')
            ids.assert_called_once_with('candidate')
            self.assertEqual(run.call_args.args[0], [manage.PYTHON, str(manage.ROOT / 'current/host.py'), 'stop', 'candidate'])
            wait.assert_called_once_with([123])

    def test_pid_selection_matches_exact_installed_controller_and_instance(self):
        fixture = '10 /usr/bin/python3 /opt/secret-proxy/current/host.py serve candidate\n11 /usr/bin/python3 /tmp/host.py serve candidate\n12 /usr/bin/python3 /opt/secret-proxy/current/host.py serve candidate-other\n13 /usr/bin/python3 /opt/secret-proxy/current/host.py up candidate\n'
        with patch.object(manage.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, fixture)):
            self.assertEqual(manage.controller_pids('candidate'), [10])

    def test_controller_wait_is_bounded(self):
        with patch.object(manage.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), patch.object(manage.time, 'monotonic', side_effect=[0, 31]), patch.object(manage.time, 'sleep'):
            with self.assertRaises(manage.ClientError): manage.wait_controllers([123])

    def test_auth_status_validates_allowlisted_fields_and_nonce_without_refresh(self):
        status = {'instance': 'a' * 32, 'loggedIn': True, 'expiresAt': 2000, 'refreshCount': 1,
                  'lastRefreshAt': 1000, 'lastRefreshDueAt': 990}
        client = Mock(); client.call.return_value = status
        with patch.object(manage, 'selected_client', return_value=client), patch.object(manage, 'private_read', return_value=json.dumps({'status': 'ready', 'instance': 'a' * 32}).encode()), contextlib.redirect_stdout(io.StringIO()) as output:
            manage.execute(self.settings(), 'auth-status')
            self.assertEqual(json.loads(output.getvalue()), status)
            client.call.assert_called_once_with('/chatgpt/status')
            for change in ({'instance': 'b' * 32}, {'refreshCount': 'credential-shaped-value'}, {'access': 'must-not-print'}, {'expiresAt': True}):
                client.call.return_value = {**status, **change}
                output.truncate(0); output.seek(0)
                with self.subTest(change=change), self.assertRaises(manage.ClientError):
                    manage.execute(self.settings(), 'auth-status')
                self.assertEqual(output.getvalue(), '')

    def test_login_provider_selects_the_proxy_owned_login(self):
        with patch.object(manage.os, 'execv') as execute:
            manage.execute(self.settings(), 'login', provider='chatgpt')
            self.assertEqual(execute.call_args.args[1][-1], 'login')
            manage.execute(self.settings(), 'login', provider='github-copilot')
            self.assertEqual(execute.call_args.args[1][-3:], ['login', '--provider', 'github-copilot'])
        with patch.object(manage, 'execute') as run, patch.object(manage, 'load_settings', return_value=self.settings()):
            manage.main(['login', 'github-copilot'])
            self.assertEqual(run.call_args.args[3], 'github-copilot')
            manage.main(['login'])
            self.assertIsNone(run.call_args.args[3])
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                manage.main(['login', 'unknown'])

    def test_copilot_auth_status_has_its_own_credential_free_fields(self):
        status = {'instance': 'a' * 32, 'loggedIn': True, 'expiresAt': 2000, 'refreshCount': 1, 'lastRefreshAt': 1000}
        client = Mock(); client.call.return_value = status
        with patch.object(manage, 'selected_client', return_value=client), patch.object(manage, 'private_read', return_value=json.dumps({'status': 'ready', 'instance': 'a' * 32}).encode()), contextlib.redirect_stdout(io.StringIO()) as output:
            manage.execute(self.settings(), 'auth-status', provider='github-copilot')
            self.assertEqual(json.loads(output.getvalue()), status)
            client.call.assert_called_once_with('/github-copilot/status')
            for change in ({'lastRefreshDueAt': 1}, {'token': 'must-not-print'}, {'expiresAt': 'x'}):
                client.call.return_value = {**status, **change}
                with self.subTest(change=change), self.assertRaises(manage.ClientError):
                    manage.execute(self.settings(), 'auth-status', provider='github-copilot')

    def test_source_launcher_refuses_uninstalled_execution(self):
        result = subprocess.run([manage.sys.executable, str(Path(__file__).with_name('secret-proxy')), '--help'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('installed root-owned launcher', result.stderr)

    def test_help_does_not_need_installed_policy_or_config(self):
        result = subprocess.run([manage.sys.executable, str(Path(__file__).with_name('manage.py')), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('auth-status', result.stdout)


class FakeSecurity:
    """In-memory stand-in for /usr/bin/security; nothing real is changed."""
    KEYCHAIN = '/Users/example/Library/Keychains/login.keychain-db'

    def __init__(self):
        self.keychain, self.trust, self.calls = {}, set(), []

    @staticmethod
    def der(path):
        return capolicy.pem_certificates(Path(path).read_bytes())[0]

    def __call__(self, args):
        self.calls.append(list(args))
        ok = lambda out=b'': subprocess.CompletedProcess(args, 0, out, b'')
        fail = lambda err: subprocess.CompletedProcess(args, 1, b'', err)
        command = args[0]
        if command == 'login-keychain':
            return ok(b'    "' + self.KEYCHAIN.encode() + b'"\n')
        if command == 'find-certificate':
            assert args[-1] == self.KEYCHAIN and args[1:3] == ['-a', '-c']
            pems = [manage.pem_file(Path(tempfile.mkdtemp()), der).read_bytes() for der in self.keychain.values()
                    if args[3] in (capolicy.certificate_info(der)['commonName'] or '')]
            return ok(b''.join(pems))
        if command == 'trust-settings-export':
            if not self.trust:
                return fail(b'SecTrustSettingsCreateExternalRepresentation: No Trust Settings were found.')
            Path(args[1]).write_bytes(plistlib.dumps({'trustList': {h: {} for h in self.trust}, 'trustVersion': 1}))
            return ok()
        if command == 'add-trusted-cert':
            assert args[1:5] == ['-r', 'trustRoot', '-p', 'ssl']
            der = self.der(args[-1])
            sha1 = capolicy.certificate_info(der)['sha1']
            if '-k' in args:
                if sha1 in self.keychain:
                    return fail(b'already in keychain')
                self.keychain[sha1] = der
            self.trust.add(sha1)
            return ok()
        if command == 'remove-trusted-cert':
            sha1 = capolicy.certificate_info(self.der(args[1]))['sha1']
            if sha1 not in self.trust:
                return fail(b'not trusted')
            self.trust.discard(sha1)
            return ok()
        if command == 'delete-certificate':
            if args[1] != '-Z' or args[2] not in self.keychain:
                return fail(b'could not be found')
            del self.keychain[args[2]]
            return ok()
        raise AssertionError(args)


def constrained_ca(label='candidate', domains=('example.com',)):
    import datetime
    from cryptography.hazmat.primitives import serialization
    import constrainedca
    _, cert = constrainedca.generate(label, list(domains), datetime.datetime.now(datetime.timezone.utc))
    return cert.public_bytes(serialization.Encoding.DER)


class TrustCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.shared = Path(self.tmp.name)
        (self.shared / 'candidate').mkdir()
        patcher = patch.object(manage, 'SHARED_ROOT', self.shared)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.security = FakeSecurity()
        self.keychain = manage.Keychain(self.security)
        self.client = Mock(env={'SSL_CERT_FILE': '/bundle.pem'})

    def publish(self, der):
        path = self.shared / 'candidate/ca.pem'
        path.write_bytes(manage.pem_file(Path(self.tmp.name), der).read_bytes())
        path.chmod(0o640)
        return capolicy.certificate_info(der)['sha1']

    def run_quiet(self, function, *args):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            function(*args)
        return output.getvalue()

    def trust(self):
        return self.run_quiet(manage.trust_ca, self.client, ManageTests.settings(None), self.keychain)

    def untrust(self):
        return self.run_quiet(manage.untrust_ca, ManageTests.settings(None), self.keychain)

    def test_trust_is_idempotent_and_proves_the_published_ca_serves_tls(self):
        sha1 = self.publish(constrained_ca())
        self.assertIn('limited to: example.com', self.trust())
        self.assertEqual(set(self.security.keychain), {sha1})
        self.assertEqual(self.security.trust, {sha1})
        self.assertEqual(self.client.env['SSL_CERT_FILE'], str(self.shared / 'candidate/ca.pem'))
        self.assertEqual(self.client.check_ready.call_count, 2)
        writes = [c for c in self.security.calls if c[0] in ('add-trusted-cert', 'remove-trusted-cert', 'delete-certificate')]
        self.assertEqual(len(writes), 1)
        self.assertIn('-k', writes[0])
        self.security.calls.clear()
        self.assertIn('already trusted', self.trust())
        self.assertFalse([c for c in self.security.calls if c[0] in ('add-trusted-cert', 'remove-trusted-cert', 'delete-certificate')])

    def test_trust_replaces_an_older_ca_of_the_same_instance_only(self):
        old = self.publish(constrained_ca())
        self.trust()
        other = constrained_ca('candidate-other')
        self.security.keychain['OTHER'] = other
        self.security.trust.add('OTHER')
        new = self.publish(constrained_ca(domains=('example.com', 'example.org')))
        self.trust()
        self.assertEqual(set(self.security.keychain), {new, 'OTHER'})
        self.assertEqual(self.security.trust, {new, 'OTHER'})
        self.assertNotEqual(old, new)

    def test_existing_untrusted_keychain_item_gets_trust_without_duplicate_add(self):
        der = constrained_ca()
        sha1 = self.publish(der)
        self.security.keychain[sha1] = der
        self.trust()
        self.assertEqual(self.security.trust, {sha1})

    def test_unconstrained_wrong_instance_or_unready_ca_is_never_trusted(self):
        from mitmproxy import certs
        from cryptography.hazmat.primitives import serialization
        _, plain = certs.create_ca('mitmproxy', 'mitmproxy', 2048)
        for der in (plain.public_bytes(serialization.Encoding.DER), constrained_ca('other')):
            self.publish(der)
            with self.subTest(), self.assertRaises(manage.ClientError):
                self.trust()
            self.assertEqual(self.security.calls, [])
        self.publish(constrained_ca())
        self.client.check_ready.side_effect = manage.ClientError('not ready')
        with self.assertRaises(manage.ClientError):
            self.trust()
        self.assertEqual(self.security.calls, [])

    def test_untrust_removes_entries_and_is_idempotent_without_a_running_proxy(self):
        sha1 = self.publish(constrained_ca())
        self.trust()
        self.assertIn('Removed', self.untrust())
        self.assertEqual((self.security.keychain, self.security.trust), ({}, set()))
        self.assertIn('nothing changed', self.untrust())
        # A trust setting orphaned by a manually deleted keychain item is removed.
        self.trust()
        del self.security.keychain[sha1]
        self.untrust()
        self.assertEqual(self.security.trust, set())

    def test_untrust_leaves_other_instances_alone(self):
        other = constrained_ca('candidate2')
        sha1 = capolicy.certificate_info(other)['sha1']
        self.security.keychain[sha1] = other
        self.security.trust.add(sha1)
        self.assertIn('nothing changed', self.untrust())
        self.assertEqual(set(self.security.keychain), {sha1})

    def test_failed_security_call_reports_without_further_changes(self):
        self.publish(constrained_ca())
        def refuse(args):
            if args[0] == 'add-trusted-cert':
                return subprocess.CompletedProcess(args, 1, b'', b'User canceled the operation.')
            return self.security(args)
        with self.assertRaisesRegex(manage.ClientError, 'canceled'):
            manage.trust_ca(self.client, ManageTests.settings(None), manage.Keychain(refuse))
        self.assertEqual(self.security.trust, set())

    def test_trust_commands_dispatch_with_the_real_security_binary_injected(self):
        with patch.object(manage, 'trust_ca') as trust, patch.object(manage, 'untrust_ca') as untrust, \
                patch.object(manage, 'selected_client', return_value='client'):
            manage.execute(ManageTests.settings(None), 'trust-ca')
            manage.execute(ManageTests.settings(None), 'untrust-ca')
        self.assertIs(trust.call_args.args[2].run, manage.run_security)
        self.assertIs(untrust.call_args.args[1].run, manage.run_security)
        self.assertEqual(manage.SECURITY, '/usr/bin/security')
