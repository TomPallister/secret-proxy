"""Opt-in, credential-free external-VPN contract smoke on an explicit test engine.

Creates an internal network and a disposable namespace donor with a dummy
interface, NOT a real VPN. Exercises host.serve, its relay and interface-loss
cleanup. Never touches an existing gateway, live proxy or credential volume.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host
from client import ProxyClient
from networking import NetworkError

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--connection', required=True)
parser.add_argument('--image', required=True)
parser.add_argument('--failure', choices=['interface', 'gateway'], default='interface')
args = parser.parse_args()
env = {'HOME': str(Path.home()), 'PATH': '/opt/podman/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'CONTAINERS_MACHINE_PROVIDER': 'libkrun'}
base = [host.PODMAN, '--connection', args.connection]
def run(*argv, **kwargs):
    result = subprocess.run(base + list(argv), env=env, capture_output=True, timeout=60, **kwargs)
    if result.returncode:
        raise RuntimeError('Fixture command failed: ' + result.stderr.decode())
    return result.stdout
image = run('image', 'inspect', '--format', '{{.Id}}', args.image).decode().strip()
if not image.startswith('sha256:'):
    image = 'sha256:' + image
name = 'vpn-smoke-' + secrets.token_hex(4)
network = name + '-net'
donor = name + '-gateway'
remote = run('machine', 'ssh', args.connection, 'mktemp', '-d', '/tmp/sp-vpn-smoke.XXXXXX').decode().strip()
assert remote.startswith('/tmp/sp-vpn-smoke.') and '\n' not in remote
# Match the remote fixture path locally, so the real host controller can read
# its cache/state while Podman sees the independently staged VM files.
local = Path(remote)
local.mkdir(mode=0o700, exist_ok=False)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
policy = {'container': donor, 'network': network, 'interface': 'tunfixture', 'port': 10257,
          'readyFile': '/run/vpn/ready', 'dns': ['127.0.0.1']}
deployment = host.Deployment.from_dict({'instance': name, 'machine': args.connection, 'port': port, 'network': policy})
results = queue.Queue()
worker = None
try:
    run('network', 'create', '--internal', network)
    run('run', '-d', '--name', donor, '--network', network, '--read-only', '--user=0',
        '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--tmpfs', '/run:rw,size=8m',
        '--entrypoint=/bin/sh', image, '-ec',
        'ip link add tunfixture type dummy; ip link set tunfixture up; mkdir -p /run/vpn; touch /run/vpn/ready; exec sleep infinity')
    setup = '''import json, pathlib, shutil
root = pathlib.Path('/fixture/.config/standalone-secret-proxy/INSTANCE')
(root / 'config').mkdir(parents=True)
(root / 'config/manifest.json').write_text(json.dumps({'schemaVersion':3,'account':{'vault':'Fixture'},'secrets':{}}))
shutil.copyfile('/etc/ssl/certs/ca-certificates.crt', root / 'runtime-ca.pem')
(root / 'resolv.conf').write_text('nameserver 127.0.0.1\\n')
'''.replace('INSTANCE', name)
    run('run', '--rm', '-i', '--network=none', '--user=0', '--volume', remote + ':/fixture:z',
        '--entrypoint=/opt/secret-proxy/.venv/bin/python', image, '-', input=setup.encode())
    with patch.object(host, 'SA_HOME', local), patch.object(host, 'SHARED_ROOT', local / 'shared'), patch.object(host, 'engine_env', return_value=env):
        deployment.private.mkdir(parents=True, mode=0o700)
        deployment.shared.mkdir(parents=True, mode=0o700)
        (deployment.private / 'image.json').write_text(json.dumps({'image': image}))
        (deployment.private / 'proxy-token').write_text('a' * 48 + '\n')
        roots = run('run', '--rm', '--network=none', '--entrypoint=/bin/cat', image, '/etc/ssl/certs/ca-certificates.crt')
        (deployment.private / 'runtime-ca.pem').write_bytes(roots)
        def exercise():
            try:
                deadline = time.monotonic() + 55
                while not (deployment.shared / 'ready.json').exists():
                    assert time.monotonic() < deadline, 'No candidate readiness'
                    time.sleep(.1)
                ProxyClient({'sharedDir': str(deployment.shared), 'port': port}).check_ready()
                expected = run('exec', donor, 'readlink', '/proc/self/ns/net')
                actual = run('exec', deployment.name, 'readlink', '/proc/self/ns/net')
                assert expected == actual, 'Proxy did not join the donor namespace'
                if args.failure == 'interface':
                    run('exec', donor, 'ip', 'link', 'set', 'tunfixture', 'down')
                else:
                    run('stop', '--time=1', donor)
                results.put(None)
            except BaseException as error:
                results.put(error)
        worker = threading.Thread(target=exercise, daemon=True)
        worker.start()
        reader, writer = os.pipe()
        os.write(writer, json.dumps({'op_token':'offline-fixture-only','proxy_token':'0'*48}).encode())
        os.close(writer)
        with os.fdopen(reader, 'rb') as input_stream, patch.object(sys, 'stdin', input_stream):
            try:
                result = host.serve(deployment)
                assert result != 0, 'Interface-loss shutdown must be nonzero'
            except NetworkError:
                pass  # Host detected loss before the runtime guard did.
            except host.HostError:
                gateway = host.resolve_gateway(deployment.network, lambda *a: host.engine(deployment, *a))
                cmd = host.container_command(deployment, image, gateway)
                index = cmd.index(image)
                cmd = cmd[:index] + ['--entrypoint=/opt/secret-proxy/.venv/bin/python', image, '-c',
                    'import os,socket,subprocess; print(os.listdir("/sys/class/net")); print(socket.if_nameindex()); subprocess.run(["ip","link","show"]); from runtime import require_interface; require_interface("tunfixture")']
                debug = subprocess.run(cmd, env=env, capture_output=True, timeout=15)
                print(debug.stdout.decode(), debug.stderr.decode(), file=sys.stderr)
                raise
        worker.join(60)
        assert not worker.is_alive()
        error = results.get_nowait()
        if error:
            raise error
        assert not (deployment.shared / 'ready.json').exists()
        for target in (deployment.name, deployment.name + '-relay'):
            assert subprocess.run(base + ['container', 'exists', target], env=env, capture_output=True).returncode != 0
        expected_running = b'true' if args.failure == 'interface' else b'false'
        assert run('container', 'inspect', donor, '--format', '{{.State.Running}}').strip() == expected_running
        print('PASS: real host lifecycle, shared namespace, opaque loopback relay, authenticated TLS, ' + args.failure + '-loss shutdown; controller leaves external gateway intact; no credentials or upstream calls')
finally:
    for target in (deployment.name + '-relay', deployment.name, donor):
        subprocess.run(base + ['rm', '-f', target], env=env, capture_output=True, timeout=30)
    subprocess.run(base + ['volume', 'rm', deployment.name + '-ca'], env=env, capture_output=True, timeout=30)
    subprocess.run(base + ['network', 'rm', network], env=env, capture_output=True, timeout=30)
    run('machine', 'ssh', args.connection, 'rm', '-rf', '--', remote)
    import shutil
    shutil.rmtree(local)
