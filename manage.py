"""Daily macOS commands using an installed, root-owned release and private metadata.

No installation, implicit restart, token export or background daemon. Stop/start
are explicit; start remains attached and uses the existing desktop bootstrap.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

from client import ClientError, ProxyClient, private_read
from host import Deployment, HostError, PYTHON, ROOT, SHARED_ROOT


def load_settings(path: Path) -> dict:
    value = json.loads(private_read(path, 16384))
    if not isinstance(value, dict) or set(value) != {'instance', 'bootstrap', 'op'}:
        raise ClientError('CLI settings must contain only instance, bootstrap and op metadata')
    try:
        Deployment.from_dict({'instance': value['instance'], 'machine': 'unused', 'port': 10260})
    except (HostError, TypeError):
        raise ClientError('Invalid instance name') from None
    for key in ('bootstrap', 'op'):
        path = value[key]
        if not isinstance(path, str) or not path.startswith('/') or any(ord(c) < 32 for c in path):
            raise ClientError('Bootstrap and op paths must be absolute, with no control characters')
    return value


def selected_client(settings: dict) -> ProxyClient:
    config = SHARED_ROOT / settings['instance'] / 'client.json'
    return ProxyClient(json.loads(private_read(config, 65536)))


def controller_pids(instance: str) -> list[int]:
    # Keep unrelated process command lines in local memory only. Never print them.
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,command='], capture_output=True,
                            text=True, check=True, timeout=10)
    found = set()
    for row in result.stdout.splitlines():
        try:
            pid, command = row.strip().split(None, 1)
            pid = int(pid)
            args = shlex.split(command)
        except ValueError:
            continue
        if pid <= 0:
            continue
        for i, word in enumerate(args):
            if word == str(ROOT / 'current/host.py') and args[i + 1:i + 3] == ['serve', instance]:
                found.add(pid)
                break
    return sorted(found)


def wait_controllers(pids: list[int]):
    deadline = time.monotonic() + 30
    while pids:
        pids = [pid for pid in pids if subprocess.run(
            ['/bin/ps', '-p', str(pid), '-o', 'pid='], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=5).returncode == 0]
        if pids and time.monotonic() >= deadline:
            raise ClientError('Old controller has not finished cleanup; wait before starting again')
        if pids:
            time.sleep(.2)


# Proxy-owned logins: status route and the exact credential-free fields it returns.
LOGINS = {
    'chatgpt': ('/chatgpt/status', {'instance', 'loggedIn', 'expiresAt', 'refreshCount', 'lastRefreshAt', 'lastRefreshDueAt'}),
    'github-copilot': ('/github-copilot/status', {'instance', 'loggedIn', 'expiresAt', 'refreshCount', 'lastRefreshAt'}),
    'github': ('/github/status', {'instance', 'loggedIn', 'scopes'}),
}


def auth_status(client: ProxyClient, settings: dict, provider: str = 'chatgpt') -> dict:
    client.check_ready()
    route, fields = LOGINS[provider]
    result = client.call(route)
    expected = json.loads(private_read(SHARED_ROOT / settings['instance'] / 'ready.json', 4096))
    if (not isinstance(result, dict) or set(result) != fields
            or not isinstance(result['instance'], str) or re.fullmatch(r'[0-9a-f]{32}', result['instance']) is None
            or result['instance'] != expected['instance'] or type(result['loggedIn']) is not bool
            or ('refreshCount' in fields and (type(result['refreshCount']) is not int or result['refreshCount'] < 0))
            or ('scopes' in fields and (not isinstance(result['scopes'], list) or not all(
                isinstance(scope, str) and re.fullmatch(r'[a-z0-9:_-]{1,64}', scope) for scope in result['scopes'])))):
        raise ClientError('Invalid or stale authentication status')
    for name in sorted(fields & {'expiresAt', 'lastRefreshAt', 'lastRefreshDueAt'}):
        if result[name] is not None and (type(result[name]) is not int or result[name] < 0):
            raise ClientError('Invalid authentication status timestamp')
    return result


def execute(settings: dict, command: str, argv=(), provider: str | None = None):
    instance = settings['instance']
    config = str(SHARED_ROOT / instance / 'client.json')
    host = str(ROOT / 'current/host.py')
    client = str(ROOT / 'current/client.py')
    if command == 'start':
        try:
            selected_client(settings).check_ready()
        except (OSError, ClientError):
            pass
        else:
            print('Proxy already ready; left running unchanged. Use stop, then start for an explicit restart.')
            return
        if not os.isatty(0) or not os.isatty(1):
            raise ClientError('Start needs an attached terminal for sudo and desktop approval')
        os.execv(PYTHON, [PYTHON, host, 'up', instance, '--bootstrap', settings['bootstrap'], '--op', settings['op']])
    elif command == 'stop':
        pids = controller_pids(instance)
        subprocess.run([PYTHON, host, 'stop', instance], check=True)
        wait_controllers(pids)
        print('Selected proxy stopped; CA, capability, policy and workspace retained. Start needs browser login again.')
    elif command == 'status':
        selected_client(settings).check_ready()
        print('Proxy ready (authenticated instance check; vault/upstreams not tested)')
    elif command == 'auth-status':
        print(json.dumps(auth_status(selected_client(settings), settings, provider or 'chatgpt'), indent=2))
    elif command == 'login':
        extra = [] if provider in (None, 'chatgpt') else ['--provider', provider]
        os.execv(PYTHON, [PYTHON, client, '--config', config, 'login', *extra])
    elif command == 'run':
        argv = list(argv)
        if argv[:1] == ['--']:
            argv = argv[1:]
        if not argv:
            raise ClientError('A command is required')
        os.execv(PYTHON, [PYTHON, client, '--config', config, 'run', '--', *argv])
    else:
        raise ClientError('Unknown command')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path.home() / '.config/secret-proxy/cli.json',
                        help='Private metadata file, never a token file')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('start', 'stop', 'status'):
        commands.add_parser(name)
    for name in ('login', 'auth-status'):
        commands.add_parser(name).add_argument('provider', nargs='?', choices=sorted(LOGINS),
                                               help='Proxy-owned login (default: chatgpt)')
    commands.add_parser('run').add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    execute(load_settings(args.config), args.command, getattr(args, 'argv', ()), getattr(args, 'provider', None))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        detail = str(error) if isinstance(error, ClientError) else type(error).__name__
        print('secret-proxy command failed: ' + detail, file=sys.stderr)
        sys.exit(1)
