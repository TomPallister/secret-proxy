"""First-time macOS setup. Generates metadata; never asks for or reads a token.

Does not start services, change existing installations or configure global trust.
Use the operations guide, not this helper, for upgrades and additional instances.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from egress import EgressConfigError
from host import Deployment, HostError, PYTHON, ROOT, validate_bootstrap_config
from macos_install import validate_source_config
from client import validate_config

REPO = Path(__file__).resolve().parent
LINK = Path.home() / '.local/bin/secret-proxy'


class SetupError(Exception):
    pass


def exists(path):
    return path.exists() or path.is_symlink()


def outside_repo(path):
    path = path.absolute()
    if any(ord(c) < 32 for c in str(path)):
        raise SetupError('Use a configuration path without control characters.')
    if path.resolve().is_relative_to(REPO.resolve()):
        raise SetupError('Keep private configuration outside the source checkout.')
    return path


def save(path, data):
    # Exclusive creation: never overwrite an existing file or follow a symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def ask(label, default=''):
    answer = input(label + (f' [{default}]' if default else '') + ': ').strip()
    return answer or default


def yes(label, default):
    value = ask(label + ' (y/n)', 'y' if default else 'n').lower()
    if value not in ('y', 'n'):
        raise SetupError('Answer y or n; no files were created.')
    return value == 'y'


def initialise(base):
    base = outside_repo(base)
    if exists(base):
        raise SetupError('Settings directory already exists; nothing changed. Use --directory for a new location.')
    print('Enter names only, never API keys or service-account tokens.')
    bootstrap = {
        'account': ask('1Password account hostname (for example example.1password.com)'),
        'runtimeVault': ask('Vault the proxy may read', 'DevEnv'),
        'vault': ask('Different vault holding the bootstrap Login item', 'Private'),
        'item': ask('Bootstrap Login item title', 'Secret Proxy Bootstrap'),
    }
    try:
        validate_bootstrap_config(bootstrap)
    except HostError:
        raise SetupError('Invalid account/vault metadata; the bootstrap vault must differ from the runtime vault.') from None
    github = yes('Enable the read-only GitHub example', True)
    codex = yes('Enable ChatGPT/Codex for Pi', False)
    if not github and not codex:
        raise SetupError('Choose at least one starter integration. Advanced policy can be added later.')
    secrets, environment = {}, {}
    if github:
        secrets['GITHUB_TOKEN'] = {'placements': [{
            'kind': 'header', 'hosts': ['api.github.com'], 'name': 'authorization',
            'template': 'Bearer {secret}', 'methods': ['GET', 'HEAD']}]}
        environment['GITHUB_TOKEN'] = 'secret' + 'ref:GITHUB_TOKEN'
    if codex:
        secrets['CHATGPT_ACCESS_TOKEN'] = {'runtimeOnly': True, 'placements': [{
            'kind': 'header', 'hosts': ['chatgpt.com'], 'name': 'authorization',
            'template': 'Bearer {secret}', 'methods': ['POST'],
            'paths': ['/backend-api/codex/responses']}]}
    base.mkdir(mode=0o700, parents=True)
    config = base / 'config'; config.mkdir(mode=0o700)
    save(config / 'bootstrap.json', bootstrap)
    save(config / 'manifest.json', {'schemaVersion': 3,
         'account': {'vault': bootstrap['runtimeVault']}, 'secrets': secrets})
    save(config / 'client-environment.json', environment)
    print('Created metadata in ' + str(config))
    print('Next: complete the 1Password steps in docs/setup.md, then run:')
    extra = '' if base == Path.home() / '.config/secret-proxy' else ' --directory ' + shlex.quote(str(base))
    print('  ./setup.sh install' + extra)
    if codex:
        print('For Pi, add --agent-dir /absolute/path/to/your/pi-agent-directory.')
    print('Nothing was installed, started or read from 1Password.')


def source_revision():
    def git(*args):
        return subprocess.run(['git', '-c', 'core.fsmonitor=false', '-C', str(REPO), *args],
                              capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    try:
        if git('status', '--porcelain', '--untracked-files=all'):
            raise SetupError('Source checkout has uncommitted changes. Install a reviewed clean commit.')
        revision = git('rev-parse', 'HEAD')
        if re.fullmatch(r'[0-9a-f]{40}', revision) is None:
            raise SetupError('Could not identify the source revision.')
        git('-c', 'gpg.ssh.allowedSignersFile=' + str(REPO / 'release-signers'),
            'verify-commit', revision)
        return revision
    except subprocess.CalledProcessError:
        raise SetupError('Source signature could not be verified. See docs/setup.md; do not bypass this check.') from None


def install(base, instance, port, agent_dir):
    if sys.platform != 'darwin' or os.getuid() == 0:
        raise SetupError('Run setup as your normal macOS user, not with sudo.')
    base = outside_repo(base)
    # This helper is intentionally not an upgrade or takeover tool.
    for path in (ROOT, base / 'cli.json', LINK):
        if exists(path):
            raise SetupError('Existing installation, CLI settings or command found. Nothing changed; see docs/operations.md.')
    if base.is_symlink():
        raise SetupError('Refusing a symlinked settings directory.')
    try:
        contents = validate_source_config(base / 'config')
    except HostError as error:  # fixed text, e.g. an invalid aws-policy.json rule
        raise SetupError(str(error)) from None
    bootstrap = json.loads(contents['bootstrap.json'])
    validate_bootstrap_config(bootstrap)
    if json.loads(contents['manifest.json'])['account']['vault'] != bootstrap['runtimeVault']:
        raise SetupError('Manifest and bootstrap must select the same runtime vault.')
    policy = Deployment.from_dict({'instance': instance, 'machine': 'secagent', 'port': port})
    client = {'sharedDir': str(policy.shared), 'port': port,
              'environment': json.loads(contents.get('client-environment.json', b'{}'))}
    if agent_dir:
        client['agentDir'] = str(agent_dir)
    validate_config(client)
    op = shutil.which('op')
    if not op or not Path(op).is_absolute():
        raise SetupError('Install the 1Password CLI and enable its desktop integration first.')
    revision = source_revision()
    print('Installing reviewed source ' + revision)
    print('This registers a separate secagent installation; it does not start a proxy or read a vault.')
    command = ['/usr/bin/sudo', PYTHON, str(REPO / 'macos_install.py'),
               '--repo', str(REPO), '--commit', revision, '--config', str(base / 'config'),
               '--instance', instance, '--machine', 'secagent', '--port', str(port)]
    if agent_dir:
        command += ['--agent-dir', str(agent_dir)]
    subprocess.run(command, check=True)
    launcher = ROOT / 'releases' / revision / 'secret-proxy'
    if not launcher.is_file():
        raise SetupError('Installed launcher is missing; CLI settings were not created.')
    LINK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    # Both writes are exclusive, so a concurrently created command is not replaced.
    LINK.symlink_to(launcher)
    save(base / 'cli.json', {'instance': instance,
         'bootstrap': str(base / 'config/bootstrap.json'), 'op': op})
    print('Installed ' + str(LINK))
    print('Add ~/.local/bin to PATH if needed. Then, in a terminal:')
    if base == Path.home() / '.config/secret-proxy':
        print('  secret-proxy start')
    else:
        print('  secret-proxy --config ' + shlex.quote(str(base / 'cli.json')) + ' start')
    print('Keep it attached. Use another terminal for clients; see docs/setup.md.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('init', 'install'):
        child = commands.add_parser(name)
        child.add_argument('--directory', type=Path, default=Path.home() / '.config/secret-proxy',
                           help='Private settings parent; policy lives in its config/ child')
        if name == 'install':
            child.add_argument('--instance', default='local')
            child.add_argument('--port', type=int, default=10260)
            child.add_argument('--agent-dir', type=Path, help='Pi agent directory, if enabling ChatGPT/Codex')
    args = parser.parse_args(argv)
    if args.command == 'init':
        initialise(args.directory)
    else:
        install(args.directory, args.instance, args.port, args.agent_dir)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        detail = str(error) if isinstance(error, (SetupError, EgressConfigError)) else type(error).__name__
        print('Setup stopped: ' + detail, file=sys.stderr)
        sys.exit(1)
