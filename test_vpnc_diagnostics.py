import contextlib
import json
import os
import tempfile
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import vpnc_runtime as vpn
from vpn_status import ClientErrors, STAGES, encode_stage


class ClientErrorTests(unittest.TestCase):
    def test_only_known_client_errors_become_fixed_codes(self):
        cases = (
            (b'no response from target', 'client-peer-no-response'),
            (b'authentication unsuccessful', 'client-auth-rejected'),
            (b'hash comparison failed: HASH_MISMATCH(23)', 'client-group-auth-failed'),
            (b"Error binding to source port. Try '--local-port 0'", 'client-bind-failed'),
            (b"can't initialise tunnel interface: Permission denied", 'client-tunnel-open-failed'),
            (b"can't send packet: Operation not permitted", 'client-send-failed'),
            (b'making socket: Permission denied', 'client-socket-failed'),
            (b'connecting to port 500: Network is unreachable', 'client-socket-failed'),
            (b'unable to get password', 'client-helper-failed'),
            (b'authentication failed (requires interactive mode)', 'client-interactive-required'),
            (b'response was invalid [1]: INVALID_PAYLOAD_TYPE(1)', 'client-negotiation-rejected'),
            (b'quick mode response rejected: NO_PROPOSAL_CHOSEN(14)', 'client-negotiation-rejected'),
            (b'Peer has selected DES as encryption method.', 'client-weak-algorithm'),
        )
        for prefix in (b'vpnc: ', b'/usr/sbin/vpnc: '):
            for message, expected in cases:
                with self.subTest(prefix=prefix, message=message):
                    errors = ClientErrors()
                    errors.feed(prefix + message + b'\n')
                    self.assertEqual(errors.stage, expected)
                    self.assertIn(errors.stage, STAGES)
                    self.assertEqual(encode_stage(errors.stage), b'SP-VPN/1 ' + expected.encode() + b'\n')
                    self.assertEqual(errors.pending, b'')

    def test_unknown_unframed_and_incomplete_text_is_not_reported(self):
        for data in (b'private fixture diagnostic\n', b'vpnc: private fixture diagnostic\n',
                     b'SP-VPN/1 ready\n', b'prefix vpnc: authentication unsuccessful\n',
                     b'vpnc: authentication unsuccessful', b'vpnc: authentication unsuccessful extra\n',
                     b'\xffvpnc: authentication unsuccessful\n'):
            with self.subTest(data=data):
                errors = ClientErrors(); errors.feed(data)
                self.assertEqual(errors.stage, 'client-exited')

    def test_first_recognised_error_wins_and_later_private_text_is_discarded(self):
        errors = ClientErrors()
        errors.feed(b'vpnc: no response from target\nvpnc: authentication unsuccessful\nprivate fixture')
        self.assertEqual(errors.stage, 'client-peer-no-response')
        self.assertEqual(errors.pending, b'')
        errors.feed(b'another private fixture' * 1000)
        self.assertEqual(errors.pending, b'')

    def test_overflow_cannot_smuggle_error_suffix(self):
        for length in (513, 1026, 100000):
            errors = ClientErrors()
            errors.feed(b'x' * length + b'vpnc: authentication unsuccessful\n')
            self.assertEqual(errors.stage, 'client-exited')
            self.assertLessEqual(len(errors.pending), 512)
            errors.feed(b'vpnc: authentication unsuccessful\n')
            self.assertEqual(errors.stage, 'client-auth-rejected')

    def test_chunk_boundaries_and_private_suffix_never_escape_fixed_output(self):
        data = b'/usr/sbin/vpnc: hash comparison failed: private fixture material\n'
        for size in range(1, len(data) + 1):
            errors = ClientErrors()
            for offset in range(0, len(data), size): errors.feed(data[offset:offset+size])
            self.assertEqual(errors.stage, 'client-group-auth-failed')
            self.assertNotIn(b'private fixture', encode_stage(errors.stage))

    def test_pipe_drain_is_bounded_and_handles_eof_or_not_ready(self):
        child = SimpleNamespace(stderr=SimpleNamespace(fileno=lambda: 123))
        errors = ClientErrors()
        with patch.object(vpn.os, 'read', return_value=b'x'*4096) as read:
            vpn.drain_client(child, errors)
            self.assertEqual(read.call_count, 16)
            self.assertLessEqual(len(errors.pending), 512)
        for value in (b'', BlockingIOError()):
            with patch.object(vpn.os, 'read', side_effect=[value]) as read:
                vpn.drain_client(child, errors)
                self.assertEqual(read.call_count, 1)

    def test_connect_reads_exit_tail_without_logging_and_cleans_up(self):
        profile = {'type': 'vpnc', 'gateway': '192.0.2.8', 'group': 'Fixture', 'dhGroup': 'dh5',
                   'usernameSecret': 'USER', 'passwordSecret': 'PASS', 'groupSecret': 'GROUP'}
        child = Mock(); child.poll.return_value = 2; child.stderr.fileno.return_value = 123
        resolver = Mock(); resolver.get.side_effect = lambda name: 'fixture-' + name.lower()
        manifest = SimpleNamespace(load=lambda path: object())
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            ready = Path(tmp) / 'ready'
            stack.enter_context(patch.dict(sys.modules, {
                'runtime': SimpleNamespace(read_bootstrap=lambda fd: {'op_token': 'fixture-only'}),
                'secretstore': SimpleNamespace(SecretManifest=manifest,
                    SecretResolver=SimpleNamespace(from_environment=lambda *a, **k: resolver))}))
            patches = (
                ('READY', ready), ('Path', lambda path: SimpleNamespace(read_bytes=lambda: b'{}')),
                ('load_networks', lambda data: {'fixture': profile}), ('validate_secrets', lambda *a: None),
                ('hook_stage', lambda: None), ('clear_challenge', Mock()),
                ('publish', Mock()),
            )
            for name, value in patches: stack.enter_context(patch.object(vpn, name, value))
            stack.enter_context(patch.object(vpn.socket, 'getaddrinfo', return_value=[
                (2, 2, 0, '', ('192.0.2.8', 500))]))
            stack.enter_context(patch.object(vpn.subprocess, 'check_output', return_value=json.dumps([
                {'addr_info': [{'scope': 'global', 'local': '10.89.0.2', 'prefixlen': 24}]}]).encode()))
            stack.enter_context(patch.object(vpn.subprocess, 'run'))
            popen = stack.enter_context(patch.object(vpn.subprocess, 'Popen', return_value=child))
            blocking = stack.enter_context(patch.object(vpn.os, 'set_blocking'))
            stack.enter_context(patch.object(vpn.os, 'read', side_effect=[BlockingIOError(),
                b'/usr/sbin/vpnc: authentication unsuccessful\n', b'']))
            stack.enter_context(patch.object(vpn.signal, 'signal'))
            stack.enter_context(patch.object(vpn.os, 'umask'))
            stack.enter_context(patch.object(vpn.sys, 'stdin', SimpleNamespace(fileno=lambda: 0)))
            with self.assertRaisesRegex(ValueError, 'client exited'):
                vpn.connect('fixture')
            vpn.publish.assert_called_with('client-auth-rejected')
            blocking.assert_called_once_with(123, False)
            self.assertIs(popen.call_args.kwargs['stderr'], subprocess.PIPE)
            self.assertIs(popen.call_args.kwargs['stdout'], subprocess.DEVNULL)
            self.assertIs(popen.call_args.kwargs['stdin'], subprocess.DEVNULL)
            self.assertNotIn('OP_SERVICE_ACCOUNT_TOKEN', popen.call_args.kwargs['env'])
            self.assertEqual(popen.call_args.kwargs['env'].get('VPNPID'), str(os.getpid()))
            child.stderr.close.assert_called_once()
            vpn.clear_challenge.assert_called_once()
            self.assertFalse(ready.exists())
            self.assertFalse((ready.parent / 'vpnc.conf').exists())

    def test_wait_keeps_draining_after_readiness_without_retaining_output(self):
        child = subprocess.Popen([sys.executable, '-c',
            "import os; os.write(2, b'private fixture\\n' * 100000)"],
            env={'PATH': os.defpath}, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        os.set_blocking(child.stderr.fileno(), False)
        result = []
        worker = threading.Thread(target=lambda: result.append(vpn.wait_client(child)), daemon=True)
        worker.start()
        try:
            worker.join(8)
            self.assertFalse(worker.is_alive(), 'Client stderr must drain after readiness too')
            self.assertEqual(result, [0])
        finally:
            if child.poll() is None: child.kill()
            child.wait(timeout=5); worker.join(5); child.stderr.close()


if __name__ == '__main__':
    unittest.main()
