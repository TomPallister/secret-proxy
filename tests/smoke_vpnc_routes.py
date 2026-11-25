"""Actual packaged route hooks in an isolated no-network container.

No IKE authentication, vault, external interface, host mount or proxy start.
Uses a real persistent TUN and synthetic addresses to exercise connect/restore.
The --mutation variant must fail its route-restoration assertion.
"""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host

PROBE = r'''
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import vpnc_runtime as vpn

os.umask(0o077)
vpn.READY.parent.mkdir(mode=0o700)
mutation = os.environ.get('ROUTE_TEST_MUTATION', '')
def run(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=10)
def defaults():
    return [{k: row[k] for k in ('dst','gateway','dev','metric') if k in row}
            for row in json.loads(run('ip','-j','-4','route','show','default'))]
def rules():
    return json.loads(run('nft','-j','list','table','inet','secret_proxy_vpn'))
for argv in (('ip','link','add','eth0','type','dummy'),
             ('ip','addr','add','10.89.0.2/24','dev','eth0'),
             ('ip','link','set','eth0','up'),
             ('ip','route','add','default','via','10.89.0.1','dev','eth0')):
    run(*argv)
before = defaults()
assert before == [{'dst':'default','gateway':'10.89.0.1','dev':'eth0'}]
resolv = hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest()
subprocess.run(['nft','-f','-'], input=vpn.firewall('192.0.2.8','10.89.0.0/24').encode(), check=True)
firewall = rules()
env = vpn.client_environment()
assert env['VPNPID'] == str(os.getpid())
backup = Path('/run/vpnc') / ('defaultroute.' + env['VPNPID'])
common = {**env, 'VPNGATEWAY':'192.0.2.8', 'INTERNAL_IP4_ADDRESS':'198.51.100.2',
          'INTERNAL_IP4_DNS':'192.0.2.53', 'INTERNAL_IP6_DNS':'2001:db8::53'}

def hook(reason):
    event = {**common, 'reason':reason}
    if reason != 'pre-init': event['TUNDEV'] = 'tun0'
    if mutation == 'unstable-pid' and reason == 'disconnect':
        event['VPNPID'] = str(int(env['VPNPID']) + 1000)
    # Fresh real Python process on every event, as spawned by packaged vpnc.
    result = subprocess.run([sys.executable, '/opt/secret-proxy/vpnc_runtime.py', 'hook'],
        env=event, stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
    assert result.returncode == 0, 'Packaged route hook rejected: ' + reason
    assert hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest() == resolv
    assert rules() == firewall, 'Hook changed the packet kill switch'

hook('pre-init')
assert not vpn.READY.exists() and vpn.hook_stage() == 'negotiating'
run('ip','tuntap','add','dev','tun0','mode','tun')
for cycle in range(2):
    hook('connect')
    assert vpn.READY.exists() and vpn.hook_stage() == 'ready'
    assert defaults() == [{'dst':'default','dev':'tun0'}]
    assert json.loads(run('ip','-j','-4','route','get','1.1.1.1'))[0]['dev'] == 'tun0'
    peer = json.loads(run('ip','-j','-4','route','get','192.0.2.8'))[0]
    assert peer['dev'] == 'eth0' and peer['gateway'] == '10.89.0.1'
    assert list(Path('/run/vpnc').glob('defaultroute.*')) == [backup]
    # The distro script serialises route tokens on separate lines.
    assert backup.read_text().split() == ['default','via','10.89.0.1','dev','eth0']
    saved = backup.read_bytes()
    hook('reconnect')
    assert vpn.READY.exists() and backup.read_bytes() == saved
    hook('disconnect')
    assert not vpn.READY.exists() and vpn.hook_stage() == 'disconnected'
    assert defaults() == before, 'Original default route was not restored'
    assert not list(Path('/run/vpnc').glob('defaultroute.*')), 'Route backup was not consumed'
    assert 'UP' not in json.loads(run('ip','-j','link','show','tun0'))[0]['flags']
print('PASS: packaged pre-init/connect/reconnect/disconnect twice; stable route backup consumed; original route restored; DNS and kill switch unchanged; no external network or login')
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--connection', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--mutation', choices=('unstable-pid',), default='')
    args = parser.parse_args()
    env = {'HOME': str(Path.home()), 'PATH': '/opt/podman/bin:/usr/bin:/bin:/usr/sbin:/sbin',
           'CONTAINERS_MACHINE_PROVIDER': 'libkrun'}
    base = [host.PODMAN, '--connection', args.connection]
    row, = json.loads(subprocess.check_output(base + ['image', 'inspect', args.image], env=env))
    identifier = row.get('Id') or row['ID']
    name = 'vpnc-routes-' + secrets.token_hex(6)
    command = base + ['run', '--rm', '--init', '-i', '--name', name, '--network=none',
        '--read-only', '--user=0', '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW',
        '--cap-add=NET_BIND_SERVICE', '--device=/dev/net/tun', '--security-opt=no-new-privileges',
        '--security-opt=label=disable', '--pids-limit=64', '--log-driver=none',
        '--tmpfs', '/run:rw,nodev,nosuid,noexec,size=16m,mode=0755',
        '--tmpfs', '/tmp:rw,nodev,nosuid,noexec,size=16m,mode=1777',
        '--env', 'ROUTE_TEST_MUTATION=' + args.mutation,
        '--entrypoint=/opt/secret-proxy/.venv/bin/python', identifier, '-B', '-']
    try:
        subprocess.run(command, env=env, input=PROBE.encode(), check=True, timeout=120)
    finally:
        subprocess.run(base + ['rm', '-f', name], env=env, capture_output=True, timeout=15)


if __name__ == '__main__':
    main()
