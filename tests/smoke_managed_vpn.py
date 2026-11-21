"""Real controller/namespace/relay lifecycle with synthetic op/vpnc executables.

No real VPN, credential lookup or upstream call. The mounted fixture executables
replace only authentication/transport, not profile selection, firewall, standard
vpnc route script, publication, namespace/relay contracts or lifecycle cleanup.
"""
import argparse
import hashlib
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
import vpn_gateway
from client import ProxyClient
from networking import NetworkError

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--connection', required=True)
parser.add_argument('--image', required=True)
parser.add_argument('--failure', choices=['auth'])
args = parser.parse_args()
env = {'HOME': str(Path.home()), 'PATH': '/opt/podman/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'CONTAINERS_MACHINE_PROVIDER': 'libkrun'}
base = [host.PODMAN, '--connection', args.connection]

def run(*argv, **kwargs):
    result = subprocess.run(base + list(argv), env=env, capture_output=True, timeout=60, **kwargs)
    if result.returncode:
        raise RuntimeError('Synthetic fixture command failed: ' + result.stderr.decode() + result.stdout.decode())
    return result.stdout

image = run('image', 'inspect', '--format', '{{.Id}}', args.image).decode().strip()
if not image.startswith('sha256:'): image = 'sha256:' + image
name = 'mg-smoke-' + secrets.token_hex(4)
remote = run('machine', 'ssh', args.connection, 'mktemp', '-d', '/tmp/sp-mg-smoke.XXXXXX').decode().strip()
assert remote.startswith('/tmp/sp-mg-smoke.') and '\n' not in remote
local = Path(remote); local.mkdir(mode=0o700, exist_ok=False)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
profile = {'type': 'vpnc', 'gateway': '192.0.2.8', 'group': 'Fixture', 'dhGroup': 'dh14',
    'dns': ['10.20.0.53'], 'usernameSecret': 'VPN_USER', 'passwordSecret': 'VPN_PASSWORD', 'groupSecret': 'VPN_GROUP'}
catalog = {'version': 1, 'networks': {'fixture': profile}}
manifest = {'schemaVersion': 3, 'account': {'vault': 'Fixture'}, 'secrets':
            {profile[key]: {'internalOnly': True} for key in ('usernameSecret', 'passwordSecret', 'groupSecret')}}
registration = {'instance': name, 'machine': args.connection, 'port': port, 'networks': catalog['networks']}
deployment = host.Deployment.from_dict(registration).select_network('fixture')
fake_op = '''#!/opt/secret-proxy/.venv/bin/python
import json,os,sys
assert os.environ.get('OP_SERVICE_ACCOUNT_TOKEN')=='offline-fixture-only'
values={'VPN_USER':'fixture-user','VPN_PASSWORD':'fixture-pass','VPN_GROUP':'fixture-group'}
if sys.argv[1:3]==['item','list']: print(json.dumps([{'id':n,'title':n} for n in values]))
elif sys.argv[1:3]==['item','get']: print(json.dumps({'value':values[sys.argv[3]]}))
else: sys.exit(1)
'''
fake_vpnc = '''#!/opt/secret-proxy/.venv/bin/python
import os,pathlib,signal,socket,subprocess,sys,time
sys.path.insert(0,'/opt/secret-proxy')
from vpnc_runtime import hook
assert 'OP_SERVICE_ACCOUNT_TOKEN' not in os.environ
assert '--non-inter' in sys.argv and '--no-detach' in sys.argv
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as ike: ike.bind(('0.0.0.0',500))
text=pathlib.Path(sys.argv[-1]).read_text()
assert 'Xauth password fixture-pass\\n' in text
assert 'IPSec secret fixture-group\\n' in text
assert 'policy drop' in subprocess.check_output(['nft','list','ruleset']).decode()
subprocess.run(['ip','link','add','tun0','type','dummy'],check=True)
env={**os.environ,'reason':'pre-init','TUNDEV':'tun0','VPNGATEWAY':'192.0.2.8','VPNPID':str(os.getpid()),
     'INTERNAL_IP4_ADDRESS':'10.222.0.2','INTERNAL_IP4_NETMASK':'255.255.255.255','INTERNAL_IP4_MTU':'1390'}
hook(env)
env['reason']='connect'; hook(env)
def stop(*args):
 env['reason']='disconnect'; hook(env); sys.exit(0)
signal.signal(signal.SIGTERM,stop)
while True: time.sleep(.2)
'''
if args.failure == 'auth':
    fake_op = fake_op.replace("values={'VPN_USER'", "sys.exit(2)\nvalues={'VPN_USER'")

# All fixture bytes are synthetic and staged only in a new VM temporary dir.
setup = '''import json,pathlib,shutil,sys
value=json.load(sys.stdin); root=pathlib.Path('/fixture/.config/standalone-secret-proxy')/value['name']
(root/'config').mkdir(parents=True)
for name in ('manifest','networks'): (root/'config'/ (name+'.json')).write_text(json.dumps(value[name]))
shutil.copyfile('/etc/ssl/certs/ca-certificates.crt',root/'runtime-ca.pem')
(root/'resolv.conf').write_text('nameserver 10.20.0.53\\n')
for name in ('op','vpnc'):
 path=pathlib.Path('/fixture')/name; path.write_text(value[name]); path.chmod(0o755)
'''
original_command = vpn_gateway.command

def fixture_command(*a):
    command = original_command(*a)
    index = command.index('--entrypoint=/opt/secret-proxy/.venv/bin/python')
    command[index:index] = ['--volume', remote + '/op:/usr/local/bin/op:ro',
                            '--volume', remote + '/vpnc:/usr/sbin/vpnc:ro']
    return command

worker = None
try:
    run('run', '--rm', '-i', '--network=none', '--user=0', '--volume', remote + ':/fixture:z',
        '--entrypoint=/opt/secret-proxy/.venv/bin/python', image, '-c', setup,
        input=json.dumps({'name': name, 'manifest': manifest, 'networks': catalog, 'op': fake_op, 'vpnc': fake_vpnc}).encode())
    with patch.object(host, 'SA_HOME', local), patch.object(host, 'SHARED_ROOT', local / 'shared'), \
         patch.object(host, 'engine_env', return_value=env), patch.object(vpn_gateway, 'command', side_effect=fixture_command):
        deployment.private.mkdir(parents=True, mode=0o700); deployment.shared.mkdir(parents=True, mode=0o700)
        (deployment.private / 'config').mkdir()
        for filename, value in [('manifest.json', manifest), ('networks.json', catalog)]:
            (deployment.private / 'config' / filename).write_text(json.dumps(value))
        (deployment.private / 'image.json').write_text(json.dumps({'image': image}))
        (deployment.private / 'proxy-token').write_text('a' * 48 + '\n')
        (deployment.private / 'runtime-ca.pem').write_bytes(run('run', '--rm', '--network=none', '--entrypoint=/bin/cat', image, '/etc/ssl/certs/ca-certificates.crt'))
        def invoke(selected):
            reader, writer = os.pipe()
            os.write(writer, json.dumps({'op_token': 'offline-fixture-only', 'proxy_token': '0'*48}).encode()); os.close(writer)
            with os.fdopen(reader, 'rb') as input_stream, patch.object(sys, 'stdin', input_stream):
                return host.serve(selected)
        previous = None
        for mode in ('direct', 'fixture', 'direct'):
            selected = host.Deployment.from_dict(registration).select_network(mode)
            if mode == 'fixture' and args.failure == 'auth':
                try:
                    invoke(selected)
                except NetworkError:
                    pass
                else:
                    raise AssertionError('Failed VPN login was accepted')
                for target in (deployment.name, deployment.name + '-relay', deployment.network.container):
                    assert host.engine(deployment, 'container', 'exists', target).returncode == 1
                assert not (deployment.shared / 'ready.json').exists()
                assert not (deployment.shared / 'network-state.json').exists()
                continue
            results = queue.Queue()
            def exercise():
                try:
                    deadline = time.monotonic() + 60
                    while not (deployment.shared / 'ready.json').exists():
                        assert time.monotonic() < deadline, 'No readiness'
                        time.sleep(.1)
                    ProxyClient({'sharedDir': str(deployment.shared), 'port': port}).check_ready()
                    metadata = json.loads((deployment.shared / 'network-state.json').read_bytes())
                    ready = json.loads((deployment.shared / 'ready.json').read_bytes())
                    assert metadata == {'network': mode, 'instance': ready['instance']}
                    state = {f: hashlib.sha256((deployment.shared / f).read_bytes()).hexdigest() for f in ('ca.pem', 'proxy-token')}
                    if mode == 'fixture':
                        run('exec', deployment.network.container, 'test', '!', '-e', '/run/vpn/vpnc.conf')
                        assert run('exec', deployment.network.container, 'readlink', '/proc/self/ns/net') == run('exec', deployment.name, 'readlink', '/proc/self/ns/net')
                        run('exec', deployment.network.container, 'ip', 'link', 'set', 'tun0', 'down')
                    else:
                        if previous is not None: assert state == previous, 'Network selection changed CA/capability'
                        assert host.engine(deployment, 'container', 'exists', deployment.network.container).returncode == 1
                        host.stop_instance(selected)
                    results.put(state)
                except BaseException as error:
                    results.put(error)
                    host.stop_instance(selected)
            worker = threading.Thread(target=exercise, daemon=True); worker.start()
            try:
                invoke(selected)
            except NetworkError:
                assert mode == 'fixture'
            worker.join(65)
            assert not worker.is_alive()
            result = results.get_nowait()
            if isinstance(result, BaseException): raise result
            previous = result
            for target in (deployment.name, deployment.name + '-relay', deployment.network.container):
                assert host.engine(deployment, 'container', 'exists', target).returncode == 1, target
            assert not (deployment.shared / 'ready.json').exists()
            assert not (deployment.shared / 'network-state.json').exists()
        if args.failure:
            print('PASS: failed VPN credential bootstrap never serves clients or falls back; later explicit direct start preserves endpoint/CA/capability')
        else:
            print('PASS: direct/managed/direct startup, standard route hook, firewall-before-login, shared namespace/TLS, tunnel-loss cleanup; endpoint/CA/capability retained')
finally:
    for target in (deployment.name + '-relay', deployment.name, deployment.network.container):
        subprocess.run(base + ['rm', '-f', target], env=env, capture_output=True, timeout=30)
    if worker is not None: worker.join(65)
    subprocess.run(base + ['volume', 'rm', deployment.name + '-ca'], env=env, capture_output=True, timeout=30)
    subprocess.run(base + ['network', 'rm', deployment.network.network], env=env, capture_output=True, timeout=30)
    run('machine', 'ssh', args.connection, 'rm', '-rf', '--', remote)
    import shutil
    shutil.rmtree(local)
