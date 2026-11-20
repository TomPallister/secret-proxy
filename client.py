"""Command-scoped host client and sealed proxy-owned logins. No vault capability here."""
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

import clientgrants

MARKER = 'secret' + 'ref:'
HOST = 'secret' + 'ref.invalid'
MAX_CALLBACK = 32768
GH_TOKEN_VARIABLES = ('GH_TOKEN', 'GH_ENTERPRISE_TOKEN')


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
        # gh reads these; they may only ever carry a reference, never a token.
        if key in GH_TOKEN_VARIABLES and re.fullmatch(re.escape(MARKER) + r'[A-Z][A-Z0-9_]+', value) is None:
            raise ClientError(key + ' must be a secret reference, not a token')
    return config


def check_client_name(client: str) -> str:
    if client != clientgrants.DEFAULT_CLIENT and not clientgrants.valid_name(client):
        raise ClientError('Invalid client name')
    return client


def client_env(config: dict, client: str = clientgrants.DEFAULT_CLIENT) -> dict:
    """Proxy/trust environment for one client, using only that client's token."""
    validate_config(config)
    check_client_name(client)
    shared = Path(config['sharedDir'])
    token = private_read(shared / clientgrants.token_file_name(client), 49).decode('ascii').strip()
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
    proxy = f'http://{clientgrants.username(client)}:{token}@127.0.0.1:{config["port"]}'
    env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, http_proxy=proxy, https_proxy=proxy,
               NO_PROXY='localhost,127.0.0.1,::1', no_proxy='localhost,127.0.0.1,::1',
               NODE_USE_ENV_PROXY='1', NODE_EXTRA_CA_CERTS=ca, SSL_CERT_FILE=ca,
               REQUESTS_CA_BUNDLE=ca, CURL_CA_BUNDLE=ca, AWS_CA_BUNDLE=ca, GIT_SSL_CAINFO=ca)
    if config.get('agentDir'):
        env['PI_CODING_AGENT_DIR'] = config['agentDir']
    return env


class ProxyClient:
    def __init__(self, config: dict, client: str = clientgrants.DEFAULT_CLIENT):
        self.config = validate_config(config)
        self.client = check_client_name(client)
        self.env = client_env(config, client)

    def request(self, path: str, body: bytes | None = None, *, tls: bool = True,
                headers: dict | None = None, timeout: float = 45) -> tuple:
        """One sentinel request; returns (status, body). Never follows redirects."""
        # Explicit CONNECT; never honour ambient proxy/no_proxy or redirects.
        parsed = urllib.parse.urlsplit(self.env['HTTPS_PROXY'])
        auth = base64.b64encode(f'{parsed.username}:{parsed.password}'.encode()).decode()
        if tls:
            context = ssl.create_default_context()
            context.load_verify_locations(self.env['SSL_CERT_FILE'])
            connection = http.client.HTTPSConnection('127.0.0.1', self.config['port'], context=context, timeout=timeout)
            connection.set_tunnel(HOST, 443, headers={'Proxy-Authorization': 'Basic ' + auth})
            target = path
            sent = {'Content-Type': 'text/plain'}
        else:
            connection = http.client.HTTPConnection('127.0.0.1', self.config['port'], timeout=5)
            target = 'http://' + HOST + path
            sent = {'Proxy-Authorization': 'Basic ' + auth, 'Content-Type': 'text/plain'}
        sent.update(headers or {})
        try:
            connection.request('POST' if body is not None else 'GET', target, body=body, headers=sent)
            response = connection.getresponse()
            # Callers refuse a body over 65536 bytes.
            return response.status, response.read(65537)
        finally:
            connection.close()

    def call(self, path: str, body: bytes | None = None, *, tls: bool = True) -> dict:
        status, data = self.request(path, body, tls=tls)
        if status != 200 or len(data) > 65536:
            raise ClientError('Proxy request failed; check readiness or login state')
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ClientError('Invalid proxy response')
        return result

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


COPILOT_REFERENCE = MARKER + 'GITHUB_COPILOT_SESSION_TOKEN'
_HOST_RE = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+'
LOGIN_FAILURES = {'expired_token': 'the code expired before it was entered',
                  'access_denied': 'access was denied in the browser',
                  'login_failed': 'GitHub refused the login',
                  'no_login': 'the login was replaced or cancelled',
                  'unavailable': 'GitHub or the Copilot service was unavailable'}


def validate_copilot_credential(value: object) -> dict:
    """Accept only a sealed Copilot entry: references, real expiry, no token."""
    try:
        if not isinstance(value, dict) or not {'type', 'access', 'refresh', 'expires'} <= set(value) \
                or set(value) - {'type', 'access', 'refresh', 'expires', 'enterpriseUrl', 'availableModelIds'}:
            raise ValueError()
        if value['type'] != 'oauth' or value['refresh'] != COPILOT_REFERENCE:
            raise ValueError()
        if type(value['expires']) is not int or value['expires'] <= 0:
            raise ValueError()
        pattern = ('tid=' + re.escape(COPILOT_REFERENCE) + r';exp=[0-9]{1,12}(?:;proxy-ep=' + _HOST_RE + ')?')
        if not isinstance(value['access'], str) or re.fullmatch(pattern, value['access']) is None:
            raise ValueError()
        if 'enterpriseUrl' in value and (not isinstance(value['enterpriseUrl'], str)
                                         or re.fullmatch(_HOST_RE, value['enterpriseUrl']) is None):
            raise ValueError()
        models = value.get('availableModelIds', [])
        if not isinstance(models, list) or not all(isinstance(item, str) and re.fullmatch(r'[A-Za-z0-9._:/-]{1,128}', item) for item in models):
            raise ValueError()
        return value
    except (ValueError, KeyError, TypeError):
        raise ClientError('Proxy returned an invalid or unsealed credential') from None


def save_credential(agent_dir: Path, value: dict, provider: str = 'openai-codex'):
    {'openai-codex': validate_credential, 'github-copilot': validate_copilot_credential}[provider](value)
    agent_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = agent_dir / 'auth.json'
    if target.is_symlink():
        raise ClientError('Refusing a symlinked auth.json')
    original = private_read(target, 2 * 1024 * 1024) if target.exists() else None
    old = json.loads(original) if original is not None else {}
    if not isinstance(old, dict):
        raise ClientError('Invalid Pi auth file')
    old[provider] = value
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


def device_login(client: ProxyClient, prefix: str) -> dict:
    """Show the user code, then let the proxy poll GitHub until the login ends."""
    start = client.call(prefix + '/start')
    code, uri, expires = start.get('userCode'), start.get('verificationUri'), start.get('expiresIn')
    parsed = urllib.parse.urlsplit(uri) if isinstance(uri, str) else None
    if (not isinstance(code, str) or re.fullmatch(r'[A-Za-z0-9-]{4,32}', code) is None or parsed is None
            or parsed.scheme != 'https' or not parsed.hostname or any(ord(c) < 33 for c in uri)
            or type(expires) is not int or not 0 < expires <= 3600):
        raise ClientError('Invalid device login response')
    print(f'Open {uri} and enter the code: {code}', file=sys.stderr)
    print('Waiting for you to approve the login in the browser...', file=sys.stderr)
    deadline = time.monotonic() + expires + 30
    while time.monotonic() < deadline:
        result = client.call(prefix + '/poll', b'')
        status = result.get('status')
        if status == 'complete':
            return result
        if status == 'failed':
            reason = result.get('reason')
            raise ClientError('Login failed: ' + LOGIN_FAILURES.get(reason, 'unknown error'))
        retry = result.get('retryAfter')
        if status != 'pending' or type(retry) is not int or retry < 0:
            raise ClientError('Invalid device login response')
        # The proxy itself waits up to 10 seconds for GitHub's poll interval.
        time.sleep(min(max(retry - 10, 0), 60))
    raise ClientError('Login timed out')


# --- Approval prompts (issue #3) ---------------------------------------------
APPROVER_HEADER = 'X-Secret-Proxy-Approver'
INSTANCE_HEADER = 'X-Secret-Proxy-Instance'
APPROVAL_CHOICES = {'1': 'deny-once', '2': 'allow-once', '3': 'allow-session', '4': 'deny-session'}
APPROVAL_FIELDS = ('client', 'kind', 'method', 'host', 'path', 'secret', 'placement',
                   'account', 'role', 'service', 'operation', 'rule')
APPROVAL_KINDS = ('secret', 'aws', 'egress')
MIN_ANSWER_DELAY = 1.0


def printable(value: object) -> str:
    """Never let a description move the cursor or change the terminal."""
    return ''.join(c if 32 <= ord(c) < 127 else '?' for c in str(value))[:200]


def validate_prompt(value: object, instance: str) -> dict:
    try:
        if not isinstance(value, dict) or set(value) != {'instance', 'id', 'request', 'expiresIn', 'answerAfter'}:
            raise ValueError()
        if value['instance'] != instance or re.fullmatch(r'[0-9a-f]{32}', value['id']) is None:
            raise ValueError()
        request = value['request']
        if (not isinstance(request, dict) or set(request) - set(APPROVAL_FIELDS)
                or request.get('kind') not in APPROVAL_KINDS
                or not all(isinstance(item, str) and len(item) <= 512 for item in request.values())):
            raise ValueError()
        if type(value['expiresIn']) is not int or not 0 <= value['expiresIn'] <= 3600:
            raise ValueError()
        if type(value['answerAfter']) not in (int, float) or not 0 <= value['answerAfter'] <= 60:
            raise ValueError()
        return value
    except (ValueError, TypeError):
        raise ClientError('Invalid approval prompt from the proxy') from None


def describe_prompt(prompt: dict) -> str:
    request = prompt['request']
    titles = {'secret': 'A request wants to use a secret', 'aws': 'An AWS operation needs approval',
              'egress': 'A connection to an unlisted host needs approval'}
    lines = ['', titles[request['kind']] + ':']
    for name in APPROVAL_FIELDS:
        if name != 'kind' and name in request:
            lines.append(f'  {name:<10} {printable(request[name])}')
    lines.append(f'Expires in {prompt["expiresIn"]} s. Choose:')
    lines.append('  1 deny once   2 allow once   3 allow for this proxy session   4 deny for this proxy session')
    return '\n'.join(lines)


def read_choice(fd: int, delay: float, timeout: float, sleep=time.sleep) -> str | None:
    """Wait *delay*, discard anything typed ahead, then read one line."""
    sleep(max(delay, MIN_ANSWER_DELAY))
    if os.isatty(fd):
        termios.tcflush(fd, termios.TCIFLUSH)
    deadline = time.monotonic() + max(timeout - delay, 0)
    data = bytearray()
    with selectors.SelectSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                return None
            chunk = os.read(fd, 64)
            if not chunk:
                return data.decode('ascii', 'replace').strip() if data else None
            data.extend(chunk)
            if b'\n' in data or b'\r' in data or len(data) > 64:
                return data.splitlines()[0].decode('ascii', 'replace').strip() if data.strip() else ''


def approvals_loop(client: ProxyClient, approver: str, *, fd: int = 0, out=None,
                   reader=read_choice, rounds: int | None = None) -> None:
    """Long-poll the proxy and answer one prompt at a time."""
    out = out or sys.stderr
    if re.fullmatch(r'[0-9a-f]{48}', approver) is None:
        raise ClientError('Invalid approver capability')
    client.check_ready()
    instance = json.loads(private_read(Path(client.config['sharedDir']) / 'ready.json', 4096))['instance']
    headers = {APPROVER_HEADER: approver, INSTANCE_HEADER: instance}
    print('Waiting for approval requests. Ctrl-C to stop; with nobody listening, requests are denied.',
          file=out, flush=True)
    while rounds is None or rounds > 0:
        if rounds is not None:
            rounds -= 1
        status, data = client.request('/approvals/next', headers=headers, timeout=40)
        if status == 204:
            continue
        if status == 409:
            raise ClientError('The proxy restarted; run approvals again')
        if status != 200 or len(data) > 65536:
            raise ClientError('The approval endpoint refused this approver')
        prompt = validate_prompt(json.loads(data), instance)
        # The terminal bell: terminals flag or sound it when this tab isn't in front.
        print('\a' + time.strftime('[%H:%M:%S]') + describe_prompt(prompt), file=out, flush=True)
        print('Choice: ', end='', file=out, flush=True)
        try:
            answer = reader(fd, float(prompt['answerAfter']), float(prompt['expiresIn']))
        except KeyboardInterrupt:
            client.request('/approvals/' + prompt['id'], json.dumps({'choice': 'deny-once'}).encode(),
                           headers=headers, timeout=10)
            print('\nDenied; stopped.', file=out, flush=True)
            raise
        if answer is None:
            print('\nNo answer in time; the proxy denies it.', file=out, flush=True)
            continue
        choice = APPROVAL_CHOICES.get(answer)
        if choice is None:
            # A typo is not a yes: deny this request.
            print('Not one of 1-4; denying once.', file=out, flush=True)
            choice = 'deny-once'
        status, data = client.request('/approvals/' + prompt['id'], json.dumps({'choice': choice}).encode(),
                                      headers=headers, timeout=10)
        try:
            result = json.loads(data) if status == 200 and len(data) <= 65536 else {}
        except ValueError:
            result = {}
        if result.get('instance') != instance or result.get('id') != prompt['id']:
            print('The proxy did not accept that answer (expired or replaced); it is denied.', file=out, flush=True)
        elif result.get('result') == 'allowed':
            print('Allowed (' + choice + ').', file=out, flush=True)
        else:
            print('Denied (' + printable(result.get('rule') or choice) + ').', file=out, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path, help='Non-secret client JSON')
    parser.add_argument('--client', default=clientgrants.DEFAULT_CLIENT,
                        help='Scoped client whose token to use (default: default)')
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run', help='Run one command with scoped proxy/trust environment')
    run.add_argument('argv', nargs=argparse.REMAINDER)
    login = commands.add_parser('login', help='Proxy-owned login (ChatGPT for Pi by default)')
    login.add_argument('--provider', choices=('chatgpt', 'github-copilot', 'github'), default='chatgpt')
    login.add_argument('--agent-dir', type=Path)
    login.add_argument('--callback-stdin', action='store_true')
    commands.add_parser('status')
    args = parser.parse_args()
    config = json.loads(private_read(args.config, 65536))
    client = ProxyClient(config, args.client)
    client.check_ready()
    if args.command == 'status':
        print('Proxy ready (authenticated instance check; vault/upstreams not tested)')
    elif args.command == 'run':
        argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
        if not argv:
            raise ClientError('A command is required')
        os.execvpe(argv[0], argv, client.env)
    elif args.provider == 'github':
        scopes = device_login(client, '/github').get('scopes')
        if not isinstance(scopes, list) or not all(isinstance(s, str) and re.fullmatch(r'[a-z0-9:_-]{1,64}', s) for s in scopes):
            raise ClientError('Invalid device login response')
        print('GitHub CLI login held by the proxy (scopes: ' + (', '.join(scopes) or 'none reported') + ').')
        print('Run gh through `secret-proxy run`; it receives only a reference in GH_TOKEN.')
    elif args.provider == 'github-copilot':
        agent = args.agent_dir or Path(client.env.get('PI_CODING_AGENT_DIR', str(Path.home() / '.pi/agent')))
        value = device_login(client, '/github-copilot').get('credential')
        save_credential(agent, value, 'github-copilot')
        print(f'Sealed GitHub Copilot reference saved to {agent / "auth.json"}; no usable token stored.')
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
