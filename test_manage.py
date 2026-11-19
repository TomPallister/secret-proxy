import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import manage


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
