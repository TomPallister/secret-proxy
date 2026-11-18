"""Command-scoped host client and sealed ChatGPT login. No vault capability here."""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import ssl
import stat
import sys
import tempfile
import termios
import time
import urllib.parse

MARKER = 'secret' + 'ref:'
HOST = 'secret' + 'ref.invalid'
MAX_CALLBACK = 32768


class ClientError(Exception):
    pass


def private_read(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > limit:
            raise ClientError('Unsafe client state file')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ClientError('Client state file too large')
        return data
    finally:
        os.close(fd)


def validate_config(config: dict) -> dict:
    if not isinstance(config, dict) or set(config) - {'sharedDir', 'port', 'agentDir', 'environment'}:
        raise ClientError('Invalid client configuration')
    port = config.get('port')
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ClientError('Invalid proxy port')
    for name in ('sharedDir', 'agentDir'):
        value = config.get(name)
        if name == 'agentDir' and value is None:
            continue
        if not isinstance(value, str) or not value.startswith('/') or '\x00' in value or '\n' in value:
            raise ClientError('Client paths must be absolute')
    env = config.get('environment', {})
    if not isinstance(env, dict):
        raise ClientError('Invalid client environment')
    # Configuration contains references and non-secret tool settings only. Never
    # accept loader/interpreter knobs that turn launching a client into code exec.
    for key, value in env.items():
        if (not re.fullmatch(r'[A-Z][A-Z0-9_]*', key)
                or key in {'PATH', 'HOME', 'ENV', 'BASH_ENV', 'ZDOTDIR', 'SHELLOPTS', 'NODE_OPTIONS', 'PYTHONPATH', 'PYTHONHOME', 'SSLKEYLOGFILE'}
                or key.startswith(('LD_', 'DYLD_', 'OP_', 'PI_', 'GIT_CONFIG', 'BASH_FUNC'))
                or key.lower().endswith('proxy')
                or not isinstance(value, str) or any(ord(c) < 32 for c in value)):
            raise ClientError('Unsafe client environment setting')
    return config


def client_env(config: dict) -> dict:
    validate_config(config)
    shared = Path(config['sharedDir'])
    token = private_read(shared / 'proxy-token', 49).decode('ascii').strip()
    if not re.fullmatch(r'[0-9a-f]{48}', token):
        raise ClientError('Invalid proxy capability')
    private_read(shared / 'ca.pem', 131072)
    ca = str(shared / 'ca.pem')
    # bundle.pem contains public platform/corporate roots AND this proxy's root.
    bundle = shared / 'bundle.pem'
    if bundle.exists():
        private_read(bundle, 2 * 1024 * 1024)
        ca = str(bundle)
    env = {key: value for key, value in os.environ.items()
           if not key.lower().endswith('_proxy') and key != 'OP_SERVICE_ACCOUNT_TOKEN' and not key.startswith('OP_SESSION_')}
    env.update(config.get('environment', {}))
    proxy = f'http://secret-proxy:{token}@127.0.0.1:{config["port"]}'
    env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, http_proxy=proxy, https_proxy=proxy,
               NO_PROXY='localhost,127.0.0.1,::1', no_proxy='localhost,127.0.0.1,::1',
               NODE_USE_ENV_PROXY='1', NODE_EXTRA_CA_CERTS=ca, SSL_CERT_FILE=ca,
               REQUESTS_CA_BUNDLE=ca, CURL_CA_BUNDLE=ca, AWS_CA_BUNDLE=ca, GIT_SSL_CAINFO=ca)
    if config.get('agentDir'):
        env['PI_CODING_AGENT_DIR'] = config['agentDir']
    return env


class ProxyClient:
    def __init__(self, config: dict):
        self.config = validate_config(config)
        self.env = client_env(config)

    def call(self, path: str, body: bytes | None = None, *, tls: bool = True) -> dict:
        # Explicit CONNECT; never honour ambient proxy/no_proxy or redirects.
        parsed = urllib.parse.urlsplit(self.env['HTTPS_PROXY'])
        auth = base64.b64encode(f'{parsed.username}:{parsed.password}'.encode()).decode()
        if tls:
            context = ssl.create_default_context()
            context.load_verify_locations(self.env['SSL_CERT_FILE'])
            connection = http.client.HTTPSConnection('127.0.0.1', self.config['port'], context=context, timeout=45)
            connection.set_tunnel(HOST, 443, headers={'Proxy-Authorization': 'Basic ' + auth})
            target = path
            headers = {'Content-Type': 'text/plain'}
        else:
            connection = http.client.HTTPConnection('127.0.0.1', self.config['port'], timeout=5)
            target = 'http://' + HOST + path
            headers = {'Proxy-Authorization': 'Basic ' + auth, 'Content-Type': 'text/plain'}
        try:
            connection.request('POST' if body is not None else 'GET', target, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(65537)
            if response.status != 200 or len(data) > 65536:
                raise ClientError('Proxy request failed; check readiness or login state')
            result = json.loads(data)
            if not isinstance(result, dict):
                raise ClientError('Invalid proxy response')
            return result
        finally:
            connection.close()

    def check_ready(self):
        expected = json.loads(private_read(Path(self.config['sharedDir']) / 'ready.json', 4096))
        actual = self.call('/health')
        if actual != expected or set(actual) != {'status', 'instance'} or actual['status'] != 'ready':
            raise ClientError('Stale or invalid proxy readiness')


def read_hidden(fd: int, timeout: float = 600) -> str:
    """Disable canonical TTY buffering: long OAuth callbacks must not truncate."""
    if stat.S_ISREG(os.fstat(fd).st_mode):
        data = os.read(fd, MAX_CALLBACK + 1)
        if len(data) > MAX_CALLBACK:
            raise ClientError('Callback exceeds size limit')
        value = data.decode('utf-8').strip()
        if any(ord(char) < 32 for char in value):
            raise ClientError('Invalid callback input')
        return value
    previous = termios.tcgetattr(fd) if os.isatty(fd) else None
    try:
        if previous is not None:
            current = termios.tcgetattr(fd)
            current[3] &= ~(termios.ECHO | termios.ICANON)
            current[6][termios.VMIN] = 1
            current[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW, current)
        result = bytearray()
        deadline = time.monotonic() + timeout
        # macOS kqueue rejects /dev/tty with EINVAL even though it accepts
        # a PTY slave fd. select() supports both; we watch only one descriptor.
        with selectors.SelectSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ClientError('Callback input timed out')
                data = os.read(fd, 1024)
                if not data:
                    break
                finished = False
                for char in data:
                    if char in (10, 13):
                        finished = True
                        break
                    if char in (8, 127):
                        result = result[:-1]
                    elif char == 4:
                        raise ClientError('Login cancelled')
                    elif char < 32:
                        raise ClientError('Invalid callback input')
                    else:
                        result.append(char)
                    if len(result) > MAX_CALLBACK:
                        raise ClientError('Callback exceeds size limit')
                if finished:
                    break
        return result.decode('utf-8').strip()
    finally:
        if previous is not None:
            termios.tcsetattr(fd, termios.TCSANOW, previous)


def validate_credential(value: object) -> dict:
    try:
        if not isinstance(value, dict) or set(value) != {'type', 'access', 'refresh', 'expires', 'accountId'}:
            raise ValueError()
        if value['type'] != 'oauth' or type(value['expires']) is not int or value['expires'] <= int(time.time() * 1000):
            raise ValueError()
        if not isinstance(value['accountId'], str) or not value['accountId']:
            raise ValueError()
        parts = value['access'].split('.')
        if len(parts) != 3:
            raise ValueError()
        def decode(part):
            return base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True)
        signature = decode(parts[2]).decode('ascii')
        if signature != MARKER + 'CHATGPT_ACCESS_TOKEN' or value['refresh'] != signature:
            raise ValueError()
        claims = json.loads(decode(parts[1]))
        if claims['https://api.openai.com/auth']['chatgpt_account_id'] != value['accountId']:
            raise ValueError()
        return value
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
        raise ClientError('Proxy returned an invalid or unsealed credential') from None


def save_credential(agent_dir: Path, value: dict):
    validate_credential(value)
    agent_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = agent_dir / 'auth.json'
    if target.is_symlink():
        raise ClientError('Refusing a symlinked auth.json')
    original = private_read(target, 2 * 1024 * 1024) if target.exists() else None
    old = json.loads(original) if original is not None else {}
    if not isinstance(old, dict):
        raise ClientError('Invalid Pi auth file')
    old['openai-codex'] = value
    fd, temporary = tempfile.mkstemp(prefix='.auth-', dir=agent_dir)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(old, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        # Refuse detected concurrent changes. Do not run Pi login/logout in parallel.
        current = private_read(target, 2 * 1024 * 1024) if target.exists() else None
        if target.is_symlink() or current != original:
            raise ClientError('Pi auth changed during login; retry')
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path, help='Non-secret client JSON')
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run', help='Run one command with scoped proxy/trust environment')
    run.add_argument('argv', nargs=argparse.REMAINDER)
    login = commands.add_parser('login', help='Proxy-owned ChatGPT login for Pi')
    login.add_argument('--agent-dir', type=Path)
    login.add_argument('--callback-stdin', action='store_true')
    commands.add_parser('status')
    args = parser.parse_args()
    config = json.loads(private_read(args.config, 65536))
    client = ProxyClient(config)
    client.check_ready()
    if args.command == 'status':
        print('Proxy ready (authenticated instance check; vault/upstreams not tested)')
    elif args.command == 'run':
        argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
        if not argv:
            raise ClientError('A command is required')
        os.execvpe(argv[0], argv, client.env)
    else:
        agent = args.agent_dir or Path(client.env.get('PI_CODING_AGENT_DIR', str(Path.home() / '.pi/agent')))
        url = client.call('/chatgpt/start').get('url')
        parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
        if parsed is None or (parsed.scheme, parsed.netloc, parsed.path) != ('https', 'auth.openai.com', '/oauth/authorize'):
            raise ClientError('Invalid authorisation URL')
        print('Open in your browser:\n' + url, file=sys.stderr)
        print('The localhost callback may show a connection error. Paste the FULL address-bar URL.', file=sys.stderr)
        print('Callback (hidden): ', end='', flush=True, file=sys.stderr)
        if args.callback_stdin:
            callback = read_hidden(sys.stdin.fileno())
        else:
            with open('/dev/tty', 'rb', buffering=0) as tty:
                callback = read_hidden(tty.fileno())
        print(file=sys.stderr)
        value = client.call('/chatgpt/finish', callback.encode())
        save_credential(agent, value)
        print(f'Sealed reference saved to {agent / "auth.json"}; no usable OAuth token stored.')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        # Never echo request URLs, provider bodies, callback codes or capabilities.
        detail = str(error) if isinstance(error, ClientError) else type(error).__name__
        print('secret-proxy client failed: ' + detail, file=sys.stderr)
        sys.exit(1)
