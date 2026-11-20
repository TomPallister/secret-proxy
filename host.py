"""macOS secagent controller. Installed code and instance policy are root-owned.

Prepare/build runs before any service-account capability is read. Serve receives
one bounded capability bundle on stdin. No live legacy container is ever retired.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time

from client import private_read, ProxyClient
from networking import NetworkPolicy, NetworkError, resolve_gateway, check_gateway, relay_command
from runtime import read_bootstrap
import clientgrants
from secretstore import SecretManifest

ROOT = Path('/opt/secret-proxy')
SHARED_ROOT = Path('/private/etc/secret-proxy')
PYTHON = '/Library/Developer/CommandLineTools/usr/bin/python3'
PODMAN = '/opt/podman/bin/podman'
SA_HOME = Path('/Users/secagent')
BUILD_FILES = ('Dockerfile', '.dockerignore', 'pyproject.toml', 'uv.lock',
               'addon.py', 'entry.py', 'sigv4.py', 'awscreds.py', 'awsops.py', 'googlecreds.py',
               'auth0creds.py', 'oauthcreds.py', 'chatgptcreds.py', 'githubdevice.py',
               'copilotcreds.py', 'ghclicreds.py', 'sealedjwt.py',
               'gitsign.py', 'egress.py', 'secretstore.py', 'clientgrants.py', 'runtime.py', 'capolicy.py', 'constrainedca.py',
               'approvals.py')


class HostError(Exception):
    pass


@dataclass(frozen=True)
class Deployment:
    instance: str
    machine: str
    port: int
    network: NetworkPolicy | None = None

    def to_dict(self):
        result = {'instance': self.instance, 'machine': self.machine, 'port': self.port}
        if self.network:
            result['network'] = self.network.to_dict()
        return result

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or set(data) - {'instance', 'machine', 'port', 'network'} or not {'instance', 'machine', 'port'} <= set(data):
            raise HostError('Invalid deployment settings')
        if (not isinstance(data['instance'], str) or re.fullmatch(r'[a-z][a-z0-9-]{0,30}', data['instance']) is None
                or data['instance'] in {'secret-proxy', 'work-vpn'}):
            raise HostError('Invalid instance name')
        if not isinstance(data['machine'], str) or re.fullmatch(r'[a-z][a-z0-9-]{0,40}', data['machine']) is None:
            raise HostError('Invalid machine name')
        if type(data['port']) is not int or not 1024 <= data['port'] <= 65535:
            raise HostError('Invalid listen port')
        network = NetworkPolicy.from_dict(data['network']) if 'network' in data else None
        return cls(data['instance'], data['machine'], data['port'], network)

    @property
    def name(self):
        return 'sp-' + self.instance

    @property
    def private(self):
        return SA_HOME / '.config/standalone-secret-proxy' / self.instance

    @property
    def shared(self):
        return SHARED_ROOT / self.instance


def bootstrap_env(home: str, ambient=None) -> dict:
    return {'HOME': home, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}


def engine_env() -> dict:
    return {**bootstrap_env(str(SA_HOME)), 'PATH': '/opt/podman/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'USER': 'secagent', 'LOGNAME': 'secagent',
            'TMPDIR': str(SA_HOME / '.tmp'), 'CONTAINERS_MACHINE_PROVIDER': 'libkrun'}


def engine(deployment: Deployment, *args, **kwargs):
    return subprocess.run([PODMAN, '--connection', deployment.machine, *args],
                          env=engine_env(), stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=kwargs.pop('timeout', 60), **kwargs)


def checked(result, operation: str):
    if result.returncode:
        # Podman/provider diagnostics may contain URLs or capability bytes.
        raise HostError(operation + ' failed; no provider output was forwarded')
    return result.stdout


def atomic(path: Path, data: bytes, mode=0o640):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def container_command(deployment: Deployment, image: str, gateway=None) -> list:
    if re.fullmatch(r'sha256:[0-9a-f]{64}', image) is None:
        raise HostError('An exact local image ID is required')
    if bool(deployment.network) != bool(gateway):
        raise HostError('VPN mode requires a checked, pinned gateway; no direct fallback')
    args = [PODMAN, '--connection', deployment.machine, 'run', '--rm', '-i', '--init',
            '--name', deployment.name, '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--log-driver=none', '--pids-limit=256',
            '--userns=keep-id:uid=1000,gid=1000',
            # Non-secret instance name; used only for an opt-in name-constrained CA.
            '--env', 'SECRET_PROXY_CA_LABEL=' + deployment.instance,
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m',
            '--volume', f'{deployment.name}-ca:/data',
            '--volume', f'{deployment.private}/config:/config:ro',
            '--volume', f'{deployment.private}/runtime-ca.pem:/etc/ssl/certs/ca-certificates.crt:ro']
    if deployment.network:
        args += ['--network', 'container:' + gateway.container_id,
                 '--volume', f'{deployment.private}/resolv.conf:/etc/resolv.conf:ro', image,
                 '--port', str(deployment.network.port), '--required-interface', deployment.network.interface]
    else:
        args += ['--publish', f'127.0.0.1:{deployment.port}:10256', image]
    return args


def ensure_machine(deployment: Deployment):
    result = subprocess.run([PODMAN, 'machine', 'inspect', deployment.machine], env=engine_env(),
                            capture_output=True, timeout=30)
    if result.returncode:
        # No automatic recreate: existing machines may contain a live service.
        result = subprocess.run([PODMAN, 'machine', 'init', '--cpus', '2', '--memory', '2048',
                                 '--disk-size', '20', '--volume', f'{SA_HOME}/.config:{SA_HOME}/.config',
                                 deployment.machine], env=engine_env(), capture_output=True, timeout=600)
        checked(result, 'machine init')
        result = subprocess.run([PODMAN, 'machine', 'inspect', deployment.machine], env=engine_env(),
                                capture_output=True, timeout=30)
    info = json.loads(checked(result, 'machine inspect'))[0]
    # Podman inspect omits mounts; read the private machine configuration.
    machine_config = SA_HOME / '.config/containers/podman/machine/libkrun' / (deployment.machine + '.json')
    mounts = json.loads(machine_config.read_text()).get('Mounts', [])
    if not any(m.get('Source') == str(SA_HOME / '.config') and m.get('Target') == str(SA_HOME / '.config') for m in mounts):
        raise HostError('Existing machine lacks the private config mount; refusing to recreate it')
    if info.get('State') != 'running':
        checked(subprocess.run([PODMAN, 'machine', 'start', deployment.machine], env=engine_env(),
                               capture_output=True, timeout=180), 'machine start')


def build_image(deployment: Deployment, source: Path, work: Path, ca: Path, iid: Path):
    # Remote Podman stages --secret files INSIDE its context. Never grant write
    # access to the installed release: copy only build inputs into private,
    # disposable secagent-owned storage. No vault capability exists at this stage.
    with tempfile.TemporaryDirectory(prefix='build-', dir=work) as temporary:
        context = Path(temporary)
        for name in BUILD_FILES:
            (context / name).write_bytes((source / name).read_bytes())
            (context / name).chmod(0o644)
        args = ['build', '--iidfile', str(iid)]
        if ca.exists():
            args += ['--secret', 'id=upstream_ca,src=' + str(ca)]
        args += [str(context)]
        result = engine(deployment, *args, timeout=900)
        if result.returncode:
            # Only this credential-free build phase may expose diagnostics;
            # checked() continues suppressing credential-bearing provider output.
            tail = ((result.stdout or b'') + b'\n' + (result.stderr or b''))[-8192:]
            print('Image build diagnostics (before credential bootstrap):', file=sys.stderr)
            print(tail.decode('utf-8', errors='replace'), file=sys.stderr)
            raise HostError('image build failed before credential bootstrap')


def prepare(deployment: Deployment):
    ensure_machine(deployment)
    deployment.private.mkdir(mode=0o700, parents=True, exist_ok=True)
    if deployment.network:
        resolve_gateway(deployment.network, lambda *args: engine(deployment, *args))
        atomic(deployment.private / 'resolv.conf', ''.join('nameserver ' + ip + '\n' for ip in deployment.network.dns).encode(), 0o644)
    source = ROOT / 'current'
    source_id = json.loads((source / 'source.json').read_text())['commit']
    ca = deployment.private / 'config/upstream-ca.pem'
    fingerprint = hashlib.sha256((source_id + ':').encode() + (ca.read_bytes() if ca.exists() else b'')).hexdigest()
    cache = deployment.private / 'image.json'
    image = None
    if cache.exists():
        record = json.loads(private_read(cache, 4096))
        if record.get('fingerprint') == fingerprint:
            candidate = record.get('image', '')
            if re.fullmatch(r'sha256:[0-9a-f]{64}', candidate) and engine(deployment, 'image', 'exists', candidate).returncode == 0:
                image = candidate
    if image is None:
        iid = deployment.private / 'image-id'
        build_image(deployment, source, deployment.private, ca, iid)
        image = iid.read_text().strip()
        if re.fullmatch(r'sha256:[0-9a-f]{64}', image) is None:
            raise HostError('Invalid image ID')
        atomic(cache, json.dumps({'fingerprint': fingerprint, 'image': image}).encode(), 0o600)
    roots = checked(engine(deployment, 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
                           '--entrypoint=/bin/cat', image, '/etc/ssl/certs/ca-certificates.crt'), 'public CA extraction')
    atomic(deployment.private / 'runtime-ca.pem', roots + b'\n' + (ca.read_bytes() if ca.exists() else b''), 0o600)
    print('Candidate image prepared; no credentials consumed and no existing container changed.', flush=True)


def client_tokens(deployment: Deployment, default_token: str) -> dict:
    """One persistent private token per named manifest client (issue #2).

    Tokens survive restarts, like the default capability, so a client keeps its
    published file. With no ``clients`` section this returns {} and nothing
    changes. Values never appear in argv or output.
    """
    manifest = SecretManifest.load(deployment.private / 'config/manifest.json')
    names = manifest.clients.named() if manifest.clients is not None else ()
    if not names:
        return {}
    directory = deployment.private / 'client-tokens'
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise HostError('Unsafe client token directory')
    directory.chmod(0o700)
    tokens = {}
    for name in names:
        path = directory / name
        if not path.exists():
            atomic(path, (secrets.token_hex(24) + '\n').encode(), 0o600)
        token = private_read(path, 49).decode().strip()
        if re.fullmatch(r'[0-9a-f]{48}', token) is None or token == default_token or token in tokens.values():
            raise HostError('Invalid client proxy capability: ' + name)
        tokens[name] = token
    return tokens


def publish_client_tokens(deployment: Deployment, tokens: dict):
    """Publish each named client's token as its own owner-only file.

    A token is only a boundary if a less-trusted process can read just its own
    file: hand that one file (not the shared directory) to the client's
    container, VM or user. Files of clients no longer in the manifest go.
    """
    for path in deployment.shared.iterdir():
        name = path.name[len('proxy-token.'):] if path.name.startswith('proxy-token.') else None
        if name is not None and name not in tokens and clientgrants.valid_name(name):
            path.unlink()
    for name, token in tokens.items():
        atomic(deployment.shared / clientgrants.token_file_name(name), (token + '\n').encode(), 0o600)


def serve(deployment: Deployment):
    if engine(deployment, 'container', 'exists', deployment.name).returncode == 0:
        raise HostError('Instance already exists; stop it explicitly before starting')
    gateway = None
    relay_id = None
    if deployment.network:
        gateway = resolve_gateway(deployment.network, lambda *args: engine(deployment, *args))
        if engine(deployment, 'container', 'exists', deployment.name + '-relay').returncode == 0:
            raise HostError('Candidate relay already exists; refusing to replace it')
    record = json.loads(private_read(deployment.private / 'image.json', 4096))
    image = record['image']
    bundle = read_bootstrap(sys.stdin.fileno())
    proxy_file = deployment.private / 'proxy-token'
    if not proxy_file.exists():
        atomic(proxy_file, (secrets.token_hex(24) + '\n').encode(), 0o600)
    capability = private_read(proxy_file, 49).decode().strip()
    if re.fullmatch(r'[0-9a-f]{48}', capability) is None:
        raise HostError('Invalid instance proxy capability')
    bundle['proxy_token'] = capability
    clients = client_tokens(deployment, capability)
    if clients:
        bundle['client_tokens'] = clients
    # A fresh approver-only capability every boot (issue #3). It stays in
    # secagent's private directory: no client token is ever an approver, so a
    # requesting client cannot answer its own approval prompt.
    approver_file = deployment.private / 'approver-token'
    approver = secrets.token_hex(24)
    if approver == capability or approver in clients.values():
        raise HostError('Approver capability collided with a client capability')
    atomic(approver_file, (approver + '\n').encode(), 0o600)
    bundle['approver_token'] = approver
    approver = ''
    ready = deployment.shared / 'ready.json'
    ready.unlink(missing_ok=True)
    child = subprocess.Popen(container_command(deployment, image, gateway), env=engine_env(), stdin=subprocess.PIPE)
    def stop(_signum, _frame):
        engine(deployment, 'stop', '--time=10', deployment.name, timeout=30)
    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        child.stdin.write(json.dumps(bundle).encode())
        child.stdin.close()
        bundle.clear()
        deadline = time.monotonic() + 60
        while child.poll() is None and time.monotonic() < deadline:
            result = engine(deployment, 'exec', deployment.name, '/bin/cat', '/tmp/secret-proxy/ready.json', timeout=5)
            if result.returncode == 0:
                status = json.loads(result.stdout)
                if set(status) != {'status', 'instance'} or status['status'] != 'ready' or not re.fullmatch(r'[0-9a-f]{32}', status['instance']):
                    raise HostError('Invalid runtime readiness')
                ca = checked(engine(deployment, 'exec', deployment.name, '/bin/cat', '/data/mitmproxy/mitmproxy-ca-cert.pem'), 'public CA export')
                atomic(deployment.shared / 'proxy-token', (capability + '\n').encode())
                publish_client_tokens(deployment, clients)
                atomic(deployment.shared / 'ca.pem', ca)
                roots = (deployment.private / 'runtime-ca.pem').read_bytes()
                atomic(deployment.shared / 'bundle.pem', roots + b'\n' + ca)
                if gateway:
                    check_gateway(deployment.network, gateway, lambda *args: engine(deployment, *args))
                    reply = checked(engine(deployment, *relay_command(deployment.network, gateway,
                                    deployment.name + '-relay', deployment.port, image)), 'candidate relay start')
                    relay_id = reply.decode().strip()
                    if re.fullmatch(r'[0-9a-f]{64}', relay_id) is None:
                        raise HostError('Invalid candidate relay identity')
                    client = ProxyClient({'sharedDir': str(deployment.shared), 'port': deployment.port})
                    if client.call('/health') != status:
                        raise HostError('Candidate relay did not reach the expected proxy')
                atomic(ready, result.stdout)  # publish readiness LAST
                print('Candidate ready. Keep this command attached; use stop for explicit shutdown.', flush=True)
                if gateway:
                    while child.poll() is None:
                        check_gateway(deployment.network, gateway, lambda *args: engine(deployment, *args))
                        try:
                            return child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pass
                    return child.returncode
                return child.wait()
            time.sleep(.2)
        raise HostError('Candidate failed readiness')
    finally:
        ready.unlink(missing_ok=True)
        approver_file.unlink(missing_ok=True)
        if relay_id:
            try:
                checked(engine(deployment, 'rm', '-f', relay_id), 'candidate relay cleanup')
            except (HostError, OSError, subprocess.TimeoutExpired):
                print('Candidate relay cleanup failed; run the explicit stop command when the engine is reachable.', file=sys.stderr)
        if child.poll() is None:
            stop(signal.SIGTERM, None)
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def stop_instance(deployment):
    """Idempotently stop only this instance, never its externally owned gateway."""
    (deployment.shared / 'ready.json').unlink(missing_ok=True)
    names = [deployment.name]
    if deployment.network:
        names.append(deployment.name + '-relay')
    for name in names:
        exists = engine(deployment, 'container', 'exists', name)
        if exists.returncode == 1:
            continue
        checked(exists, 'candidate inspection')
        identifier = checked(engine(deployment, 'container', 'inspect', name, '--format', '{{.Id}}'), 'candidate identity').decode().strip()
        if re.fullmatch(r'[0-9a-f]{64}', identifier) is None:
            raise HostError('Invalid candidate identity')
        # Pin the exact instance before stopping; never act on the VPN name/ID.
        checked(engine(deployment, 'rm', '-f', identifier, timeout=30), 'candidate stop')


def approvals_session(deployment: Deployment):
    """Answer approval prompts as secagent; the approver capability stays here."""
    import client as client_module
    if not os.isatty(0):
        raise HostError('Approvals need an attached terminal')
    try:
        approver = private_read(deployment.private / 'approver-token', 49).decode('ascii').strip()
    except FileNotFoundError:
        raise HostError('The proxy is not running, or predates approvals; start it first') from None
    client = ProxyClient({'sharedDir': str(deployment.shared), 'port': deployment.port})
    client_module.approvals_loop(client, approver)


def validate_bootstrap_config(config: dict):
    if not isinstance(config, dict) or set(config) != {'account', 'vault', 'item', 'runtimeVault'}:
        raise HostError('Invalid bootstrap configuration')
    if any(not isinstance(v, str) or not v or v.startswith('-') or any(ord(c) < 32 for c in v) for v in config.values()):
        raise HostError('Invalid bootstrap metadata')
    if re.fullmatch(r'[a-z0-9-]+\.1password\.(?:com|eu|ca)', config['account']) is None or config['vault'] == config['runtimeVault']:
        raise HostError('Invalid bootstrap account/vault boundary')


def validate_bootstrap_item(config: dict, item: dict) -> str:
    validate_bootstrap_config(config)
    if (not isinstance(item, dict) or item.get('title') != config['item'] or item.get('category') != 'LOGIN'
            or item.get('vault', {}).get('name') != config['vault']
            or item.get('state', '').upper() == 'ARCHIVED'
            or re.fullmatch(r'[a-z0-9]{26}', item.get('id', '')) is None):
        raise HostError('Bootstrap item identity mismatch')
    fields = item.get('fields', [])
    if not isinstance(fields, list) or any(not isinstance(f, dict) for f in fields):
        raise HostError('Invalid bootstrap fields')
    for label, expected in {'account_url': config['account'], 'destination_vault': config['runtimeVault'], 'permissions': 'read_items'}.items():
        matches = [f for f in fields if f.get('label') == label]
        if len(matches) != 1 or matches[0].get('value') != expected:
            raise HostError('Bootstrap provenance mismatch')
    values = [f for f in fields if f.get('id') == 'password' and f.get('purpose') == 'PASSWORD' and f.get('type') == 'CONCEALED']
    if len(values) != 1:
        raise HostError('Missing bootstrap capability')
    value = values[0].get('value')
    if not isinstance(value, str) or not value or not value.isascii() or len(value) > 12000 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise HostError('Invalid bootstrap capability')
    return value


def load_deployment(instance: str) -> Deployment:
    # Validate before constructing the privileged path.
    Deployment.from_dict({'instance': instance, 'machine': 'secagent', 'port': 10260})
    path = ROOT / 'instances' / (instance + '.json')
    if path.stat().st_uid != 0:
        raise HostError('Instance policy must be root-owned')
    deployment = Deployment.from_dict(json.loads(private_read(path, 4096)))
    if deployment.instance != instance:
        raise HostError('Instance policy identity mismatch')
    return deployment


def as_secagent(command: str, instance: str) -> list:
    env = engine_env()
    return ['/usr/bin/sudo', '-n', '-u', 'secagent', '/usr/bin/env', '-i',
            *[k + '=' + v for k, v in env.items()], PYTHON, str(ROOT / 'current/host.py'), command, instance]


def relay_exec(argv: list, bundle: dict):
    """Replace the desktop bootstrap process so its capability cannot linger.

    Only a short-lived pipe writer retains the original address space. The
    foreground process becomes sudo, with a clean environment and no token argv.
    """
    payload = json.dumps(bundle).encode()
    if len(payload) > 16384:
        raise HostError('Bootstrap bundle too large')
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            # Orphan only the bounded pipe writer; launchd reaps it, rather than
            # leaving an unknown zombie child under the long-running sudo.
            if os.fork() != 0:
                os._exit(0)
            os.close(reader)
            view = memoryview(payload)
            while view:
                sent = os.write(writer, view)
                view = view[sent:]
            os.close(writer)
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(writer)
    os.waitpid(child, 0)
    os.dup2(reader, 0)
    os.close(reader)
    os.execvpe(argv[0], argv, bootstrap_env(str(Path.home())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['up', 'prepare', 'serve', 'stop', 'approvals'])
    parser.add_argument('instance')
    parser.add_argument('--bootstrap', type=Path)
    parser.add_argument('--op', type=Path, help='Absolute desktop-integrated op executable (up only)')
    args = parser.parse_args()
    deployment = load_deployment(args.instance)
    if args.bootstrap:
        args.bootstrap = args.bootstrap.resolve(strict=True)
    os.chdir('/')
    if args.command == 'up':
        if not args.bootstrap or not args.op or not args.op.is_absolute() or not args.op.is_file():
            raise HostError('up requires --bootstrap and an absolute --op path')
        checked(subprocess.run(['/usr/bin/sudo', '-v'], timeout=120), 'sudo authentication')
        checked(subprocess.run(as_secagent('prepare', args.instance), timeout=1200), 'candidate preparation')
        checked(subprocess.run(['/usr/bin/sudo', '-v'], timeout=120), 'sudo refresh')
        config = json.loads(private_read(args.bootstrap, 16384))
        validate_bootstrap_config(config)
        # Desktop integration may prompt for Touch ID. Never use ambient OP_SESSION
        # or OP_SERVICE_ACCOUNT_TOKEN, and never log provider output on error.
        result = subprocess.run([str(args.op), 'item', 'get', config['item'], '--vault', config['vault'],
                                 '--account', config['account'], '--format=json', '--reveal'],
                                env=bootstrap_env(str(Path.home())), capture_output=True, timeout=180)
        capability = validate_bootstrap_item(config, json.loads(checked(result, 'desktop bootstrap')))
        bundle = {'op_token': capability, 'proxy_token': '0' * 48}
        relay_exec(as_secagent('serve', args.instance), bundle)
        raise AssertionError('exec unexpectedly returned')
    if os.getuid() != pwd.getpwnam('secagent').pw_uid:
        if args.command not in ('stop', 'approvals'):
            raise HostError('This operation must run as secagent')
        checked(subprocess.run(['/usr/bin/sudo', '-v'], timeout=120), 'sudo authentication')
        if args.command == 'approvals':
            # Ctrl-C also reaches the secagent child, which denies the prompt
            # on screen before it exits; give it time instead of killing it.
            child = subprocess.Popen(as_secagent(args.command, args.instance))
            try:
                return child.wait()
            except KeyboardInterrupt:
                try:
                    return child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    return child.wait()
        return subprocess.run(as_secagent(args.command, args.instance)).returncode
    if args.command == 'prepare':
        prepare(deployment)
    elif args.command == 'serve':
        return serve(deployment)
    elif args.command == 'approvals':
        try:
            approvals_session(deployment)
        except KeyboardInterrupt:
            return 130
    else:
        stop_instance(deployment)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        detail = str(error) if isinstance(error, (HostError, NetworkError)) else type(error).__name__
        print('secret-proxy host failed: ' + detail, file=sys.stderr)
        sys.exit(1)
