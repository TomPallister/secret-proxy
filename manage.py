"""Daily macOS commands using an installed, root-owned release and private metadata.

No installation, implicit restart, token export or background daemon. Stop/start
are explicit; start remains attached and uses the existing desktop bootstrap.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import sys
import tempfile
import time

import audit
import capolicy
from client import ClientError, ProxyClient, check_client_name, private_read
from clientgrants import DEFAULT_CLIENT
from host import Deployment, HostError, PYTHON, ROOT, SHARED_ROOT

SECURITY = '/usr/bin/security'


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


def selected_client(settings: dict, client: str = DEFAULT_CLIENT) -> ProxyClient:
    config = SHARED_ROOT / settings['instance'] / 'client.json'
    return ProxyClient(json.loads(private_read(config, 65536)), client)


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


# Added together, and only, when the manifest has a loginStore.
STORE_FIELDS = frozenset({'stored', 'restoredFromStore'})


def auth_status(client: ProxyClient, settings: dict, provider: str = 'chatgpt') -> dict:
    client.check_ready()
    route, fields = LOGINS[provider]
    result = client.call(route)
    expected = json.loads(private_read(SHARED_ROOT / settings['instance'] / 'ready.json', 4096))
    if isinstance(result, dict) and STORE_FIELDS <= set(result):
        if any(type(result[name]) is not bool for name in STORE_FIELDS):
            raise ClientError('Invalid or stale authentication status')
        fields = fields | STORE_FIELDS
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


def run_security(args: list) -> subprocess.CompletedProcess:
    # Inherit stdin/terminal: macOS shows its own password/Touch ID dialog for
    # user trust changes. Output contains certificate names, never secrets.
    return subprocess.run([SECURITY, *args], capture_output=True, timeout=300,
                          env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(Path.home())})


class Keychain:
    """User-domain trust settings and the login keychain via /usr/bin/security."""

    def __init__(self, run=run_security):
        self.run = run

    def call(self, *args, allow=()):
        result = self.run(list(args))
        if result.returncode and not any(text in (result.stdout or b'') + (result.stderr or b'') for text in allow):
            detail = (result.stderr or b'').decode('utf-8', 'replace').strip()[-300:]
            raise ClientError('security ' + args[0] + ' failed' + (': ' + detail if detail else ''))
        return result

    def login_keychain(self) -> str:
        output = self.call('login-keychain').stdout.decode('utf-8', 'replace').strip().strip('"')
        if not output.startswith('/') or not output.endswith(('.keychain', '.keychain-db')) or '\n' in output:
            raise ClientError('Could not identify the login keychain')
        return output

    def find(self, name: str, keychain: str) -> list:
        output = self.call('find-certificate', '-a', '-c', name, '-p', keychain,
                           allow=(b'could not be found',)).stdout or b''
        found = []
        for der in capolicy.pem_certificates(output):
            info = capolicy.certificate_info(der)
            if info['commonName'] == name:  # -c is a substring match
                found.append((info['sha1'], der))
        return found

    def trusted(self) -> set:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trust.plist'
            result = self.call('trust-settings-export', str(target), allow=(b'No Trust Settings',))
            if result.returncode or not target.exists():
                return set()
            data = plistlib.loads(target.read_bytes())
        return {key.upper() for key in data.get('trustList', {})}

    def add_trust(self, pem: Path, keychain: str | None):
        args = ['add-trusted-cert', '-r', 'trustRoot', '-p', 'ssl']
        if keychain:
            args += ['-k', keychain]
        self.call(*args, str(pem))

    def remove_trust(self, pem: Path):
        self.call('remove-trusted-cert', str(pem))

    def delete(self, sha1: str, keychain: str):
        self.call('delete-certificate', '-Z', sha1, keychain)


def pem_file(directory: Path, der: bytes) -> Path:
    target = directory / (hashlib.sha1(der).hexdigest() + '.pem')
    body = base64.encodebytes(der).replace(b'\n', b'')
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    target.write_bytes(b'-----BEGIN CERTIFICATE-----\n' + b'\n'.join(lines) + b'\n-----END CERTIFICATE-----\n')
    return target


def current_ca(client: ProxyClient, settings: dict) -> bytes:
    """The CA serving the authenticated instance now, refused unless constrained."""
    client.check_ready()
    path = SHARED_ROOT / settings['instance'] / 'ca.pem'
    certificates = capolicy.pem_certificates(private_read(path, 131072))
    if len(certificates) != 1:
        raise ClientError('Expected exactly one public proxy CA')
    try:
        capolicy.check_trustable(certificates[0], settings['instance'])
    except capolicy.CAPolicyError as error:
        raise ClientError(str(error)) from None
    # Prove that this exact file (with the platform default roots, which cannot
    # issue the private sentinel name) verifies the proxy's own TLS identity.
    client.env = dict(client.env, SSL_CERT_FILE=str(path))
    client.check_ready()
    return certificates[0]


def remove_entries(keychain: Keychain, login: str, entries, directory: Path, trusted: set) -> int:
    for sha1, der in entries:
        if sha1 in trusted:
            keychain.remove_trust(pem_file(directory, der))
        keychain.delete(sha1, login)
    return len(entries)


def trust_ca(client: ProxyClient, settings: dict, keychain: Keychain):
    der = current_ca(client, settings)
    info = capolicy.check_trustable(der, settings['instance'])
    login = keychain.login_keychain()
    entries = keychain.find(capolicy.common_name(settings['instance']), login)
    trusted = keychain.trusted()
    with tempfile.TemporaryDirectory() as tmp:
        stale = [entry for entry in entries if entry[0] != info['sha1']]
        removed = remove_entries(keychain, login, stale, Path(tmp), trusted)
        present = any(sha1 == info['sha1'] for sha1, _ in entries)
        if present and info['sha1'] in trusted:
            print('Proxy CA already trusted for SSL' + (f'; removed {removed} older entr' + ('y' if removed == 1 else 'ies') if removed else ''))
            return
        keychain.add_trust(pem_file(Path(tmp), der), None if present else login)
    if info['sha1'] not in keychain.trusted():
        raise ClientError('Trust setting was not recorded; nothing else changed')
    print('Trusted the name-constrained proxy CA for SSL in your login keychain, limited to: '
          + ', '.join(info['domains']) + '. Undo with: secret-proxy untrust-ca')


def untrust_ca(settings: dict, keychain: Keychain):
    """Remove every trust entry and certificate this instance added. Needs no running proxy."""
    name = capolicy.common_name(settings['instance'])
    login = keychain.login_keychain()
    entries = keychain.find(name, login)
    trusted = keychain.trusted()
    with tempfile.TemporaryDirectory() as tmp:
        removed = remove_entries(keychain, login, entries, Path(tmp), trusted)
        # A trust setting can outlive a manually deleted keychain item.
        try:
            shared = capolicy.pem_certificates(private_read(SHARED_ROOT / settings['instance'] / 'ca.pem', 131072))
        except (OSError, ClientError, capolicy.CAPolicyError):
            shared = []
        for der in shared:
            info = capolicy.certificate_info(der)
            if info['commonName'] == name and info['sha1'] in trusted and info['sha1'] not in {s for s, _ in entries}:
                keychain.remove_trust(pem_file(Path(tmp), der))
                removed += 1
    print('Removed the proxy CA trust entry' if removed else 'No proxy CA trust entry found; nothing changed')


def export_audit_files(settings: dict, run=subprocess.run) -> list:
    """Copy the audit files out of the proxy's private volume (read-only).

    host.py asks for sudo and reads them as the proxy account, through a
    throwaway offline container. Only validated audit files come back.
    """
    result = run([PYTHON, str(ROOT / 'current/host.py'), 'audit-export', settings['instance']],
                 stdout=subprocess.PIPE, timeout=900)
    if result.returncode:
        raise ClientError('Audit export failed; nothing was written')
    try:
        return audit.parse_export(result.stdout)
    except audit.AuditError as error:
        raise ClientError('Invalid audit export: ' + str(error)) from None


def audit_command(settings: dict, action: str, public_key=None, paths=(), destination=None,
                  run=subprocess.run) -> int:
    if action == 'export':
        files = export_audit_files(settings, run)
        if not files:
            print('No audit files: the audit log is off, or nothing has been recorded yet')
            return 0
        try:
            target = audit.write_export(files, destination)
        except FileExistsError:
            raise ClientError('The destination already exists; choose a new directory') from None
        print(f'Exported {len(files)} audit file(s) to {target}. '
              'Check them with: secret-proxy audit verify --public-key <file> ' + str(target))
        return 0
    if not paths:
        files = export_audit_files(settings, run)
        if not files:
            print('No audit files: the audit log is off, or nothing has been recorded yet')
            return 1
        with tempfile.TemporaryDirectory(prefix='secret-proxy-audit-') as tmp:
            target = audit.write_export(files, Path(tmp) / 'audit')
            return audit.verify_command(public_key, [str(target)])
    return audit.verify_command(public_key, list(paths))


def execute(settings: dict, command: str, argv=(), provider: str | None = None,
            client_name: str = DEFAULT_CLIENT):
    instance = settings['instance']
    check_client_name(client_name)
    # Only commands acting as a client take --client; lifecycle and CA trust
    # always use the default client (the operator's own token).
    scoped = [] if client_name == DEFAULT_CLIENT else ['--client', client_name]
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
        print('Selected proxy stopped; CA, capability, policy and workspace retained. Start needs login again '
              'unless the manifest has a loginStore.')
    elif command == 'status':
        selected_client(settings, client_name).check_ready()
        print('Proxy ready (authenticated instance check; vault/upstreams not tested)')
    elif command == 'auth-status':
        print(json.dumps(auth_status(selected_client(settings, client_name), settings, provider or 'chatgpt'), indent=2))
    elif command == 'login':
        extra = [] if provider in (None, 'chatgpt') else ['--provider', provider]
        os.execv(PYTHON, [PYTHON, client, '--config', config, *scoped, 'login', *extra])
    elif command == 'logout':
        if provider not in LOGINS:
            raise ClientError('Name the login to sign out of')
        os.execv(PYTHON, [PYTHON, client, '--config', config, *scoped, 'logout', '--provider', provider])
    elif command == 'approvals':
        if not os.isatty(0) or not os.isatty(1):
            raise ClientError('Approvals need an attached terminal')
        # host.py asks for sudo, then answers prompts as secagent: the
        # approver capability is never readable by this user or its clients.
        os.execv(PYTHON, [PYTHON, host, 'approvals', instance])
    elif command == 'trust-ca':
        trust_ca(selected_client(settings), settings, Keychain())
    elif command == 'untrust-ca':
        untrust_ca(settings, Keychain())
    elif command == 'run':
        argv = list(argv)
        if argv[:1] == ['--']:
            argv = argv[1:]
        if not argv:
            raise ClientError('A command is required')
        os.execv(PYTHON, [PYTHON, client, '--config', config, *scoped, 'run', '--', *argv])
    else:
        raise ClientError('Unknown command')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path.home() / '.config/secret-proxy/cli.json',
                        help='Private metadata file, never a token file')
    commands = parser.add_subparsers(dest='command', required=True)
    client_help = 'Scoped client whose token to use (default: default)'
    for name in ('start', 'stop', 'trust-ca', 'untrust-ca', 'approvals'):
        commands.add_parser(name)
    commands.add_parser('status').add_argument('--client', default=DEFAULT_CLIENT, help=client_help)
    for name in ('login', 'logout', 'auth-status'):
        sub = commands.add_parser(name)
        sub.add_argument('provider', choices=sorted(LOGINS), help='Proxy-owned login')
        sub.add_argument('--client', default=DEFAULT_CLIENT, help=client_help)
    run = commands.add_parser('run')
    run.add_argument('--client', default=DEFAULT_CLIENT, help=client_help)
    run.add_argument('argv', nargs=argparse.REMAINDER)
    audit_parser = commands.add_parser('audit', help='Export or verify the opt-in audit log')
    audit_actions = audit_parser.add_subparsers(dest='action', required=True)
    exporter = audit_actions.add_parser('export', help='Copy the audit files into a new directory')
    exporter.add_argument('destination', type=Path)
    verifier = audit_actions.add_parser('verify', help='Check the hash chain and seals against a pinned key')
    verifier.add_argument('--public-key', required=True, type=Path,
                          help='The signing key\'s OpenSSH public key, obtained independently')
    verifier.add_argument('paths', nargs='*', help='Exported files or directories (default: export now)')
    args = parser.parse_args(argv)
    if args.command == 'audit':
        # Verifying copies needs no installed instance; exporting does.
        if args.action == 'verify' and args.paths:
            sys.exit(audit_command({}, 'verify', args.public_key, args.paths))
        sys.exit(audit_command(load_settings(args.config), args.action, getattr(args, 'public_key', None),
                               getattr(args, 'paths', ()), getattr(args, 'destination', None)))
    execute(load_settings(args.config), args.command, getattr(args, 'argv', ()), getattr(args, 'provider', None),
            getattr(args, 'client', DEFAULT_CLIENT))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        detail = str(error) if isinstance(error, ClientError) else type(error).__name__
        print('secret-proxy command failed: ' + detail, file=sys.stderr)
        sys.exit(1)
