"""Explicit Mac/Podman integration test; fake capabilities, no vault/upstream calls.

Runs the real controller's container contract on a user-selected test connection.
Uses only a new sp-smoke-* container/volume and a VM /tmp directory, then cleans up.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host
from client import ProxyClient

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--connection', required=True)
parser.add_argument('--image', required=True)
args = parser.parse_args()
env = {'HOME': str(Path.home()), 'PATH': '/opt/podman/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'CONTAINERS_MACHINE_PROVIDER': 'libkrun'}
podman = [host.PODMAN, '--connection', args.connection]
def run(*argv, **kw):
    result = subprocess.run(podman + list(argv), env=env, capture_output=True, timeout=60, **kw)
    if result.returncode:
        # This test uses synthetic fixtures only, never a real capability.
        if argv[:1] != ('exec',):
            print(result.stderr.decode(), file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, argv)
    return result.stdout
image = run('image', 'inspect', '--format', '{{.Id}}', args.image).decode().strip()
if not image.startswith('sha256:'):
    image = 'sha256:' + image
name = 'smoke-' + secrets.token_hex(4)
remote = run('machine', 'ssh', args.connection, 'mktemp', '-d', '/tmp/sp-smoke.XXXXXX').decode().strip()
assert remote.startswith('/tmp/sp-smoke.') and '\n' not in remote
host.SA_HOME = Path(remote)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
deployment = host.Deployment.from_dict({'instance': name, 'machine': args.connection, 'port': port})
# No Mac home bind mounts are required. Stage fixture metadata inside the VM.
setup = '''import json, pathlib, shutil
root = pathlib.Path('/fixture/.config/standalone-secret-proxy/INSTANCE')
(root / 'config').mkdir(parents=True)
(root / 'config/manifest.json').write_text(json.dumps({'schemaVersion': 3, 'account': {'vault':'Fixture'}, 'secrets':{}}))
shutil.copyfile('/etc/ssl/certs/ca-certificates.crt', root / 'runtime-ca.pem')
'''.replace('INSTANCE', name)
run('run', '--rm', '-i', '--network=none', '--user=0', '--volume', remote + ':/fixture:z',
    '--entrypoint=/opt/secret-proxy/.venv/bin/python', image, '-', input=setup.encode())
child = None
try:
    with tempfile.TemporaryDirectory() as tmp:
        shared = Path(tmp)
        config = {'sharedDir': tmp, 'port': port}
        with open(shared / 'runtime.log', 'wb') as log:
            child = subprocess.Popen(host.container_command(deployment, image), env=env,
                                     stdin=subprocess.PIPE, stdout=log, stderr=log)
            child.stdin.write(json.dumps({'op_token': 'offline-fixture-only', 'proxy_token': 'a' * 48}).encode())
            child.stdin.close()
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and child.poll() is None:
                try:
                    ready = run('exec', deployment.name, '/bin/cat', '/tmp/secret-proxy/ready.json')
                    break
                except subprocess.CalledProcessError:
                    time.sleep(.2)
            else:
                print((shared / 'runtime.log').read_text(), file=sys.stderr)
                debug = host.container_command(deployment, image)
                debug[debug.index(deployment.name)] += '-diagnostic'
                debug = debug[:-1] + ['--entrypoint=/opt/secret-proxy/.venv/bin/python', image, '-c',
                    'import os; from pathlib import Path; print(os.getuid()); '\
                    '[print(str(p), p.stat().st_uid, oct(p.stat().st_mode), os.access(p, os.W_OK), os.access(p, os.R_OK)) '\
                    'for p in map(Path, ["/config/manifest.json", "/data/mitmproxy", "/tmp", "/tmp", "/etc/ssl/certs/ca-certificates.crt"])]']
                diagnostic = subprocess.run(debug, env=env, capture_output=True, timeout=30)
                print(diagnostic.stdout.decode(), diagnostic.stderr.decode(), file=sys.stderr)
                raise AssertionError('Runtime readiness failed')
            ca = run('exec', deployment.name, '/bin/cat', '/data/mitmproxy/mitmproxy-ca-cert.pem')
            (shared / 'ca.pem').write_bytes(ca)
            (shared / 'proxy-token').write_text('a' * 48 + '\n')
            (shared / 'proxy-token').chmod(0o600)
            (shared / 'ready.json').write_bytes(ready)
            client = ProxyClient(config)
            client.check_ready()  # real TLS CONNECT, Basic proxy auth and CA validation
            expected = json.loads(ready)
            (shared / 'ready.json').write_text(json.dumps({**expected, 'instance': '0' * 32}))
            try:
                client.check_ready()
                raise AssertionError('Stale readiness accepted')
            except host.HostError:
                raise
            except Exception as error:
                from client import ClientError
                assert isinstance(error, ClientError), type(error)
            (shared / 'ready.json').write_bytes(ready)
            (shared / 'proxy-token').write_text('b' * 48 + '\n')
            try:
                ProxyClient(config).check_ready()
                raise AssertionError('Wrong proxy capability accepted')
            except OSError:
                pass  # HTTPS CONNECT is rejected with 407
            (shared / 'proxy-token').write_text('a' * 48 + '\n')
            client_config = shared / 'client.json'
            client_config.write_text(json.dumps(config))
            result = subprocess.run([sys.executable, str(Path(host.__file__).parent / 'client.py'),
                                     '--config', str(client_config), 'status'], capture_output=True, timeout=15)
            assert result.returncode == 0, result.stderr
            before = dict(os.environ)
            scoped = client.env
            assert scoped['HTTPS_PROXY'].endswith(':' + str(port))
            assert os.environ == before
            run('stop', '--time=10', deployment.name)
            child.wait(timeout=15)
            output = (shared / 'runtime.log').read_bytes()
            assert b'offline-fixture-only' not in output and b'a' * 48 not in output
            print('PASS: exact launch flags, non-root tmpfs/CA volume, loopback publish, TLS host client, wrong-auth and stale-readiness rejection, clean stop; no vault or external API calls')
finally:
    if child and child.poll() is None:
        subprocess.run(podman + ['rm', '-f', deployment.name], env=env, capture_output=True, timeout=30)
        child.wait(timeout=15)
    subprocess.run(podman + ['volume', 'rm', deployment.name + '-ca'], env=env, capture_output=True, timeout=30)
    run('machine', 'ssh', args.connection, 'rm', '-rf', '--', remote)
