import base64
import json
import os
from pathlib import Path
import pty
import select
import signal
import tempfile
import termios
import threading
import time
import unittest
from unittest.mock import patch

from client import ClientError, client_env, read_hidden, save_credential, validate_credential


def credential():
    marker = 'secret' + 'ref:CHATGPT_ACCESS_TOKEN'
    sig = base64.urlsafe_b64encode(marker.encode()).decode().rstrip('=')
    claims = base64.urlsafe_b64encode(json.dumps({'https://api.openai.com/auth': {'chatgpt_account_id': 'example'}}).encode()).decode().rstrip('=')
    return {'type': 'oauth', 'access': 'e30.' + claims + '.' + sig,
            'refresh': marker, 'expires': 4102444800000, 'accountId': 'example'}


class ClientTests(unittest.TestCase):
    def test_only_sealed_matching_credentials_accepted(self):
        valid = credential()
        self.assertEqual(validate_credential(valid), valid)
        for change in ({'access': 'real-token'}, {'refresh': 'real-refresh'},
                       {'type': 'api_key'}, {'expires': True}, {'expires': 0},
                       {'accountId': 'different'}, {'extra': 'value'}):
            with self.subTest(change=change), self.assertRaises(ClientError):
                validate_credential({**valid, **change})

    def test_atomic_private_write_preserves_other_providers(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'auth.json'
            target.write_text(json.dumps({'example': {'type': 'api_key', 'key': 'fixture'}}))
            save_credential(Path(tmp), credential())
            self.assertEqual(json.loads(target.read_text())['example']['key'], 'fixture')
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(tmp).glob('.auth-*')), [])

    def test_symlink_and_unsealed_reply_do_not_modify_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            original = folder / 'original'
            original.write_text('{}')
            (folder / 'auth.json').symlink_to(original)
            with self.assertRaises(ClientError):
                save_credential(folder, credential())
            self.assertEqual(original.read_text(), '{}')
            (folder / 'auth.json').unlink()
            with self.assertRaises(ClientError):
                save_credential(folder, {**credential(), 'access': 'real'})
            self.assertFalse((folder / 'auth.json').exists())

    def test_long_terminal_callback_is_not_truncated_and_modes_restored(self):
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        value = 'http://localhost:1455/auth/callback?code=' + 'x' * 12000 + '&state=example'
        result = []
        def receive():
            result.append(read_hidden(slave, timeout=3))
        worker = threading.Thread(target=receive)
        try:
            worker.start()
            for _ in range(100):
                if not termios.tcgetattr(slave)[3] & termios.ICANON:
                    break
                time.sleep(.01)
            data = (value + '\n').encode()
            while data:
                sent = os.write(master, data[:1000])
                data = data[sent:]
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, [value])
            after = termios.tcgetattr(slave)
            # Darwin sets the transient PENDIN flag when canonical mode returns.
            after[3] &= ~getattr(termios, 'PENDIN', 0)
            before[3] &= ~getattr(termios, 'PENDIN', 0)
            self.assertEqual(after, before)
        finally:
            os.close(master)
            os.close(slave)

    def test_long_callback_through_controlling_dev_tty(self):
        value = 'http://localhost:1455/auth/callback?code=' + 'x' * 12000 + '&state=example'
        pid, master = pty.fork()
        if pid == 0:
            try:
                # The actual CLI opens /dev/tty, not the PTY slave descriptor.
                # macOS kqueue accepts the latter but rejects the former.
                with open('/dev/tty', 'rb', buffering=0) as tty:
                    before = termios.tcgetattr(tty.fileno())
                    actual = read_hidden(tty.fileno(), timeout=3)
                    after = termios.tcgetattr(tty.fileno())
                    before[3] &= ~getattr(termios, 'PENDIN', 0)
                    after[3] &= ~getattr(termios, 'PENDIN', 0)
                    assert actual == value and before == after
                os.write(1, b'INPUT_OK\n')
                os._exit(0)
            except BaseException:
                os.write(1, b'INPUT_FAILED\n')
                os._exit(1)
        data = (value + '\n').encode()
        output = bytearray()
        status = None
        deadline = time.monotonic() + 5
        try:
            while time.monotonic() < deadline:
                writable = [master] if data and not termios.tcgetattr(master)[3] & termios.ICANON else []
                readable, writable, _ = select.select([master], writable, [], .05)
                if readable:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        chunk = b''
                    output.extend(chunk)
                if writable:
                    sent = os.write(master, data[:1000])
                    data = data[sent:]
                waited, result = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = result
                    break
            self.assertEqual(status, 0, bytes(output))
            self.assertEqual(data, b'')
            self.assertNotIn(b'x' * 100, output, 'Callback was echoed')
        finally:
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(master)

    def test_callback_stdin_file_and_limit(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"http://localhost:1455/auth/callback?code=fixture&state=example\n")
            stream.seek(0)
            self.assertTrue(read_hidden(stream.fileno()).endswith("state=example"))
            stream.seek(0)
            stream.write(b"x" * 32769)
            stream.seek(0)
            with self.assertRaises(ClientError):
                read_hidden(stream.fileno())

    def test_environment_is_command_scoped_and_bypasses_cannot_leak_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'proxy-token').write_text('a' * 48 + '\n')
            (root / 'proxy-token').chmod(0o600)
            (root / 'ca.pem').write_text('fixture certificate')
            config = {'sharedDir': tmp, 'port': 10260, 'agentDir': '/tmp/example-agent',
                      'environment': {'AWS_REGION': 'eu-west-1', 'AWS_BEARER_TOKEN_BEDROCK': 'secret' + 'ref:BEDROCK'}}
            ambient = {'PATH': '/bin', 'NO_PROXY': '*', 'no_proxy': '*', 'HTTPS_PROXY': 'old', 'ALL_PROXY': 'old'}
            with patch.dict(os.environ, ambient, clear=True):
                result = client_env(config)
                self.assertEqual(os.environ, ambient)
            self.assertNotIn('ALL_PROXY', result)
            self.assertEqual(result['NO_PROXY'], 'localhost,127.0.0.1,::1')
            self.assertEqual(result['no_proxy'], result['NO_PROXY'])
            self.assertEqual(result['PI_CODING_AGENT_DIR'], '/tmp/example-agent')
            self.assertEqual(result['NODE_USE_ENV_PROXY'], '1')
            self.assertTrue(result['HTTPS_PROXY'].endswith('@127.0.0.1:10260'))

    def test_environment_rejects_injection_and_bad_ports(self):
        for env in ({'LD_PRELOAD': 'bad'}, {'NODE_OPTIONS': 'bad'}, {'GOOD': 'a\nb'}):
            with self.assertRaises(ClientError):
                client_env({'sharedDir': '/unused', 'port': 10260, 'environment': env})
        for port in (True, -1, 65536, '10260'):
            with self.assertRaises(ClientError):
                client_env({'sharedDir': '/unused', 'port': port})


if __name__ == '__main__':
    unittest.main()
