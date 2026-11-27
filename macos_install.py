"""Stage an exact committed release and register an isolated Mac candidate.

Run through sudo, explicitly. This never starts/stops/recreates a machine or a
container, never rewrites the legacy deployment, and never reads a vault.
"""
from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile

from awscreds import AwsCredsProvider
from awsops import AwsPolicyError, load_policy_bytes
import capolicy
from clientgrants import ClientConfigError
from client import private_read, validate_config
from host import Deployment, HostError, PODMAN, PYTHON, ROOT, SA_HOME, SHARED_ROOT
from egress import EgressConfigError
from secretstore import LoginStoreConfigError, SecretManifest, check_login_vault
import vpn_profiles

GIT = '/Library/Developer/CommandLineTools/usr/bin/git'
FILES = ('Dockerfile', '.dockerignore', 'pyproject.toml', 'uv.lock',
         'addon.py', 'entry.py', 'sigv4.py', 'awscreds.py', 'awsops.py', 'githubguard.py', 'googlecreds.py',
         'auth0creds.py', 'oauthcreds.py', 'chatgptcreds.py', 'githubdevice.py',
         'copilotcreds.py', 'ghclicreds.py', 'loginstore.py', 'sealedjwt.py',
         'gitsign.py', 'egress.py', 'secretstore.py', 'clientgrants.py', 'runtime.py', 'client.py', 'host.py', 'networking.py',
         'manage.py', 'secret-proxy', 'vpn_profiles.py', 'vpn_status.py', 'vpn_gateway.py', 'vpnc_runtime.py', 'vpnc_password_helper.py', 'capolicy.py', 'constrainedca.py', 'approvals.py', 'audit.py')
# Private policy copied into the instance's read-only /config (bootstrap metadata
# stays desktop-side). ca.json opts into a name-constrained CA.
POLICY_FILES = ('manifest.json', 'aws-okta.json', 'aws-policy.json', 'upstream-ca.pem', 'ca.json', 'networks.json')


def root_owned(path: Path):
    """Check the real executable AND every ancestor; no writable code roots."""
    real = path.resolve(strict=True)
    for part in (real, *real.parents):
        info = part.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise HostError('A required executable or ancestor is not root-owned/private')
    return real


def run(*args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/root'}, timeout=30)
    if result.returncode:
        raise HostError('Installation command failed: ' + Path(args[0]).name)
    return result.stdout.decode().strip()


def ensure_account():
    try:
        record = pwd.getpwnam('secagent')
    except KeyError:
        used_uids = {p.pw_uid for p in pwd.getpwall()}
        used_gids = {g.gr_gid for g in grp.getgrall()}
        try:
            gid = grp.getgrnam('secagent').gr_gid
        except KeyError:
            gid = next(i for i in range(480, 500) if i not in used_gids)
            for key, value in [('PrimaryGroupID', str(gid)), ('Password', '*')]:
                run('/usr/bin/dscl', '.', '-create', '/Groups/secagent', key, value)
        uid = next(i for i in range(480, 500) if i not in used_uids)
        for key, value in [('UniqueID', str(uid)), ('PrimaryGroupID', str(gid)),
                           ('NFSHomeDirectory', str(SA_HOME)), ('UserShell', '/usr/bin/false'),
                           ('Password', '*'), ('IsHidden', '1')]:
            run('/usr/bin/dscl', '.', '-create', '/Users/secagent', key, value)
        record = pwd.getpwnam('secagent')
    if record.pw_dir != str(SA_HOME) or record.pw_shell != '/usr/bin/false' or not 0 < record.pw_uid < 500:
        raise HostError('Existing secagent account does not meet the isolation contract')
    result = subprocess.run(['/usr/sbin/dseditgroup', '-o', 'checkmember', '-m', 'secagent', 'admin'], capture_output=True)
    if result.returncode == 0:
        raise HostError('secagent must not be an administrator')
    for path in (SA_HOME, SA_HOME / '.tmp', SA_HOME / '.config'):
        if path.is_symlink():
            raise HostError('Refusing a symlinked private directory')
        path.mkdir(mode=0o700, exist_ok=True)
        os.chown(path, record.pw_uid, record.pw_gid)
        path.chmod(0o700)
    return record


def snapshot(repo: Path, commit: str, destination: Path):
    if re.fullmatch(r'[0-9a-f]{40}', commit) is None:
        raise HostError('Specify an exact 40-character commit SHA')
    base = [GIT, '-c', 'safe.directory=' + str(repo), '-c', 'core.fsmonitor=false', '-C', str(repo)]
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/var/empty', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_NO_REPLACE_OBJECTS': '1'}
    def git(*args):
        result = subprocess.run(base + list(args), env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        if result.returncode:
            raise HostError('Could not read the specified source commit')
        return result.stdout
    raw = git('cat-file', 'commit', commit)
    if b'\ngpgsig ' not in raw.split(b'\n\n', 1)[0]:
        raise HostError('The source commit must carry a signature (verify it as your own user first)')
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)  # mkdir modes are filtered by the caller's umask.
    for name in FILES:
        data = git('show', commit + ':' + name)
        (destination / name).write_bytes(data)
        (destination / name).chmod(0o755 if name == 'secret-proxy' else 0o644)
    (destination / 'source.json').write_text(json.dumps({'commit': commit}) + '\n')
    (destination / 'source.json').chmod(0o644)


def validate_source_config(source: Path):
    if source.is_symlink():
        raise HostError('Refusing a symlinked configuration directory')
    for path in source.iterdir():
        if path.name not in {'manifest.json', 'aws-okta.json', 'aws-policy.json', 'upstream-ca.pem', 'bootstrap.json', 'client-environment.json', 'network.json', 'networks.json', 'ca.json'}:
            raise HostError('Unexpected private configuration file')
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            raise HostError('Invalid private configuration file')
    contents = {p.name: private_read(p, 2 * 1024 * 1024) for p in source.iterdir()}
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / 'manifest.json'
        manifest.write_bytes(contents['manifest.json'])
        try:
            loaded = SecretManifest.load(manifest)
        except ClientConfigError as error:
            raise HostError('Invalid clients section: ' + str(error)) from None
        except LoginStoreConfigError as error:
            raise HostError('Invalid loginStore section: ' + str(error)) from None
    if 'networks.json' in contents:
        if 'network.json' in contents:
            raise HostError('Use networks.json or legacy network.json, not both')
        vpn_profiles.validate_secrets(vpn_profiles.load_networks(contents['networks.json']), loaded)
    if 'bootstrap.json' in contents:
        # The bootstrap item must declare exactly the manifest's login vault.
        try:
            check_login_vault(loaded, json.loads(contents['bootstrap.json']).get('loginVault'))
        except (LoginStoreConfigError, AttributeError) as error:
            raise HostError('Invalid bootstrap login vault: ' + str(error)) from None
    if 'aws-okta.json' in contents:
        AwsCredsProvider._validate_config(json.loads(contents['aws-okta.json']))
    if 'aws-policy.json' in contents:
        try:
            load_policy_bytes(contents['aws-policy.json'])
        except AwsPolicyError as error:
            raise HostError('Invalid AWS operation policy: ' + str(error)) from None
    if 'ca.json' in contents:
        # Refuse at install time a host set that cannot be constrained narrowly.
        try:
            capolicy.parse_config(contents['ca.json'])
            capolicy.permitted_domains(capolicy.interception_patterns(loaded, 'aws-okta.json' in contents))
        except capolicy.CAPolicyError as error:
            raise HostError(str(error)) from None
    return contents


def activate(release: Path):
    link = ROOT / '.current-new'
    if link.exists() or link.is_symlink():
        raise HostError('Unexpected staging symlink')
    link.symlink_to(release)
    if hasattr(os, 'lchmod'):  # macOS enforces the symlink's own permissions.
        os.lchmod(link, 0o755)
    os.replace(link, ROOT / 'current')


def require_stopped_resources(deployment):
    from host import engine_env
    env = engine_env()
    prefix = ['/usr/bin/sudo', '-n', '-u', 'secagent', '/usr/bin/env', '-i',
              *[key + '=' + value for key, value in env.items()], PODMAN,
              '--connection', deployment.machine, 'container', 'exists']
    for suffix in ('', '-relay', '-vpn'):
        result = subprocess.run(prefix + [deployment.name + suffix], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=15)
        if result.returncode != 1:
            raise HostError('Stop all instance resources before updating networks; engine inspection must succeed')


def install(args):
    if not getattr(args, 'update_networks', False):
        return install_snapshot(args)
    if sys.platform != 'darwin' or os.getuid() != 0 or os.environ.get('SUDO_USER') in (None, '', 'root'):
        raise HostError('Run with sudo from your own macOS account')
    deployment = Deployment.from_dict({'instance': args.instance, 'machine': args.machine, 'port': args.port})
    if deployment.private.is_symlink() or not deployment.private.is_dir():
        raise HostError('Network updates require an existing installation')
    # Metadata-only change, but require an explicitly stopped instance and hold
    # the same lock as serve throughout validation/staging/publication.
    import fcntl
    from host import open_instance_lock
    fd = open_instance_lock(deployment, installer=True)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostError('Stop the instance before updating networks') from None
        if (deployment.shared / 'ready.json').exists():
            raise HostError('Stop the instance before updating networks')
        require_stopped_resources(deployment)
        return install_snapshot(args)
    finally:
        os.close(fd)


def install_snapshot(args):
    if sys.platform != 'darwin' or os.getuid() != 0 or os.environ.get('SUDO_USER') in (None, '', 'root'):
        raise HostError('Run with sudo from your own macOS account')
    caller = pwd.getpwnam(os.environ['SUDO_USER'])
    if not re.fullmatch(r'[A-Za-z0-9._-]+', caller.pw_name):
        raise HostError('Unsupported local account name')
    source = args.config.resolve(strict=True)
    contents = validate_source_config(source)
    policy = {'instance': args.instance, 'machine': args.machine, 'port': args.port}
    if 'network.json' in contents:
        policy['network'] = json.loads(contents['network.json'])
    if 'networks.json' in contents:
        policy['networks'] = vpn_profiles.load_networks(contents['networks.json'])
    deployment = Deployment.from_dict(policy)
    environment = json.loads(contents.get('client-environment.json', b'{}'))
    client = {'sharedDir': str(deployment.shared), 'port': args.port, 'environment': environment}
    if args.agent_dir:
        client['agentDir'] = str(args.agent_dir)
    validate_config(client)
    for executable in (PODMAN, '/opt/podman/bin/krunkit', '/opt/podman/bin/gvproxy', PYTHON, GIT):
        root_owned(Path(executable))
    # Refuse pre-existing symlinks/writable roots instead of taking them over.
    root_owned(Path('/opt'))
    for path in (ROOT, ROOT / 'releases', ROOT / 'instances', SHARED_ROOT):
        if path.is_symlink():
            raise HostError('Refusing a symlinked install root')
        path.mkdir(mode=0o755, exist_ok=True)
        root_owned(path)
        path.chmod(0o755)  # Only these validated, public install roots.
    registration = ROOT / 'instances' / (args.instance + '.json')
    existing = registration.exists() or deployment.private.exists() or deployment.shared.exists()
    if existing:
        expected_registration = deployment.to_dict()
        existing_registration = json.loads(private_read(registration, 32768))
        old_registration, new_registration = dict(existing_registration), dict(expected_registration)
        if getattr(args, 'update_networks', False):
            for value in (old_registration, new_registration):
                value.pop('networks', None)
                value.pop('network', None)
        if (not registration.is_file() or not deployment.private.is_dir() or not deployment.shared.is_dir()
                or old_registration != new_registration
                or json.loads(private_read(deployment.shared / 'client.json', 65536)) != client):
            raise HostError('Existing instance differs; choose a new candidate name (no implicit overwrite)')
        actual = {p.name: private_read(p, 2 * 1024 * 1024) for p in (deployment.private / 'config').iterdir()}
        expected = {name: value for name, value in contents.items() if name in POLICY_FILES}
        if getattr(args, 'update_networks', False):
            actual.pop('networks.json', None)
            expected.pop('networks.json', None)
        if actual != expected:
            raise HostError('Existing private policy differs; no implicit overwrite')
    release = ROOT / 'releases' / args.commit
    # An already-staged release is reusable only if every byte matches Git.
    # Immutable content from Git, never an uncommitted working-tree copy.
    with tempfile.TemporaryDirectory(prefix='.stage-', dir=ROOT) as tmp:
        staged = Path(tmp) / 'release'
        snapshot(args.repo.resolve(), args.commit, staged)
        if release.exists():
            root_owned(release)
            for name in (*FILES, 'source.json'):
                root_owned(release / name)
                if (release / name).read_bytes() != (staged / name).read_bytes():
                    raise HostError('Staged release differs from its committed content')
        else:
            staged.rename(release)
    release.chmod(0o755)  # Also repair byte-verified releases staged with umask 077.
    if existing:
        if getattr(args, 'update_networks', False):
            from host import atomic
            path = deployment.private / 'config/networks.json'
            if 'networks.json' in contents:
                atomic(path, contents['networks.json'], 0o644)
            else:
                path.unlink(missing_ok=True)
            atomic(registration, json.dumps(deployment.to_dict()).encode() + b'\n', 0o644)
            print('Explicit network catalog update applied to stopped instance; other policy and client settings retained.')
        activate(release)
        print('Committed release staged. No running service changed.')
        return
    account = ensure_account()
    for path in (deployment.private.parent, deployment.private):
        if path.is_symlink():
            raise HostError('Refusing a symlinked instance directory')
        path.mkdir(mode=0o700, exist_ok=True)
        os.chown(path, account.pw_uid, account.pw_gid)
        path.chmod(0o700)
    config = deployment.private / 'config'
    config.mkdir(mode=0o755, exist_ok=True)
    os.chown(config, 0, account.pw_gid)
    config.chmod(0o755)  # The private parent remains 0700.
    for name in POLICY_FILES:
        if name in contents:
            (config / name).write_bytes(contents[name])
            os.chown(config / name, 0, account.pw_gid)
            (config / name).chmod(0o644)
    deployment.shared.mkdir(mode=0o750, exist_ok=True)
    deployment.shared.chmod(0o750)
    os.chown(deployment.shared, account.pw_uid, account.pw_gid)
    # Reset only our own candidate directory ACL, never a legacy shared directory.
    run('/bin/chmod', '-N', str(deployment.shared))
    # Explicit caller ACL works immediately, without requiring a new group login.
    for entry in (f'user:{caller.pw_name} allow list,search,readattr,readextattr,readsecurity',
                  f'user:{caller.pw_name} allow read,readattr,readextattr,readsecurity,file_inherit,only_inherit'):
        run('/bin/chmod', '+a', entry, str(deployment.shared))
    (deployment.shared / 'client.json').write_text(json.dumps(client, indent=2) + '\n')
    (deployment.shared / 'client.json').chmod(0o640)
    os.chown(deployment.shared / 'client.json', account.pw_uid, account.pw_gid)
    registration.write_text(json.dumps(deployment.to_dict()) + '\n')
    registration.chmod(0o644)
    activate(release)
    print('Registered isolated candidate: ' + args.instance)
    print('No machine/container was started or stopped. No credentials were read.')
    print('Client settings: ' + str(deployment.shared / 'client.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--instance', default='candidate')
    parser.add_argument('--machine', default='secagent')
    parser.add_argument('--port', type=int, default=10260)
    parser.add_argument('--agent-dir', type=Path)
    parser.add_argument('--update-networks', action='store_true',
                        help='Explicitly update only network profiles on a stopped existing instance')
    install(parser.parse_args())


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = str(error) if isinstance(error, (HostError, EgressConfigError)) else type(error).__name__
        print('secret-proxy installation failed: ' + detail, file=sys.stderr)
        sys.exit(1)
