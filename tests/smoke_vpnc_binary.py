"""Packaged vpnc startup contract, synthetic credentials, no external network.

This checks ephemeral source binding with UDP500 occupied, pre-init ordering,
classified bind/no-response errors and rejection of an unexpected helper prompt.
It cannot establish an authenticated IKE/XAUTH tunnel. --mutation must fail.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host

PROBE = r'''
import os
from pathlib import Path
import socket
import subprocess
import time
import vpnc_runtime as vpn

os.umask(0o077)
vpn.READY.parent.mkdir(mode=0o700)
for command in (['ip', 'link', 'add', 'eth0', 'type', 'dummy'],
                ['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'eth0'],
                ['ip', 'link', 'set', 'eth0', 'up']):
    subprocess.run(command, check=True)
# The peer is unreachable on a dummy interface in --network=none. There is no
# gateway, host interface, NAT, port publish or real authentication attempt.
profile = {'group': 'Fixture', 'dhGroup': 'dh5', 'totpMode': 'challenge', 'totpSecret': 'FIXTURE'}
values = {'usernameSecret': 'fixture-user', 'passwordSecret': 'fixture-pass',
          'groupSecret': 'fixture-group', 'totpSecret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'}
config = vpn.READY.parent / 'vpnc.conf'
config.write_text(vpn.configuration(profile, values, '192.0.2.8', 59))
if os.environ.get('PORT_TEST_MUTATION') == 'fixed-port':
    config.write_text(config.read_text().replace('Local Port 0\n', 'Local Port 500\n'))
vpn.write_challenge(values, '192.0.2.8')
env = vpn.client_environment()

def classified_run(argv, expected):
    child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    os.set_blocking(child.stderr.fileno(), False)
    errors = vpn.ClientErrors()
    try:
        deadline = time.monotonic() + 40
        while child.poll() is None:
            vpn.drain_client(child, errors)
            assert time.monotonic() < deadline, 'Synthetic client did not exit'
            time.sleep(.05)
        vpn.drain_client(child, errors)
        assert child.returncode != 0
        assert errors.stage == expected, 'Real client error was not classified: ' + errors.stage
        assert not vpn.READY.exists()
    finally:
        if child.poll() is None: child.terminate()
        try: child.wait(timeout=3)
        except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
        child.stderr.close()

# The peer address is local to this --network=none namespace. Occupy UDP500:
# production config must still emit IKE from an ephemeral source, without an
# argv override. Only the explicit negative classifier test forces source500.
subprocess.run(['ip', 'addr', 'add', '192.0.2.8/32', 'dev', 'eth0'], check=True)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
    occupied.bind(('0.0.0.0', 500)); occupied.settimeout(4)
    collision = vpn.vpnc_command(profile, config)
    collision[-1:-1] = ['--local-port', '500']
    classified_run(collision, 'client-bind-failed')
    child = subprocess.Popen(vpn.vpnc_command(profile, config), env=env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            packet, address = occupied.recvfrom(65536)
        except socket.timeout:
            raise AssertionError('Production client failed to negotiate with UDP500 occupied') from None
        assert packet and address[1] > 1023 and address[1] not in (500, 4500)
        assert child.poll() is None
        assert vpn.hook_stage() == 'negotiating', 'Real pre-init hook was rejected'
        assert not vpn.READY.exists(), 'No authenticated tunnel exists'
        assert subprocess.run(['ip', 'link', 'show', 'tun0'], capture_output=True).returncode == 0
    finally:
        if child.poll() is None: child.terminate()
        try: child.communicate(timeout=3)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(timeout=3)

# A local UDP sink accepts but never answers. This is the unmodified production
# command/config: the source port must be ephemeral without any test override.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
    peer.bind(('192.0.2.8', 500))
    classified_run(vpn.vpnc_command(profile, config), 'client-peer-no-response')

# Removing the canned password triggers the binary's configuration-time prompt,
# not the allowlisted second XAUTH challenge. The real execl(helper, prompt)
# path must refuse it and never print an OTP to the caller.
vpn.clear_challenge()
vpn.write_challenge(values, '192.0.2.8')
config.write_text(vpn.configuration(profile, values, '192.0.2.8', 59).replace('Xauth password fixture-pass\n', ''))
result = subprocess.run(vpn.vpnc_command(profile, config), env=env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
assert result.returncode != 0
assert vpn.hook_stage() == 'challenge-refused'
assert not vpn.CHALLENGE.exists()
assert not vpn.READY.exists()
print('PASS: packaged vpnc ephemeral binding with UDP500 occupied; pre-init/TUN contract; real bind/no-response errors classified; unexpected helper prompt refused; no false readiness or external network')
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--connection', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--mutation', choices=('fixed-port',), default='')
    args = parser.parse_args()
    env = {'HOME': str(Path.home()), 'PATH': '/opt/podman/bin:/usr/bin:/bin:/usr/sbin:/sbin',
           'CONTAINERS_MACHINE_PROVIDER': 'libkrun'}
    base = [host.PODMAN, '--connection', args.connection]
    image, = json.loads(subprocess.check_output(base + ['image', 'inspect', args.image], env=env))
    identifier = image.get('Id') or image['ID']
    name = 'vpnc-binary-' + secrets.token_hex(6)
    command = base + ['run', '--rm', '--init', '-i', '--name', name, '--network=none',
        '--read-only', '--user=0', '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW',
        '--cap-add=NET_BIND_SERVICE', '--device=/dev/net/tun', '--security-opt=no-new-privileges',
        '--security-opt=label=disable', '--pids-limit=64', '--log-driver=none',
        '--tmpfs', '/run:rw,nodev,nosuid,noexec,size=16m,mode=0755',
        '--tmpfs', '/tmp:rw,nodev,nosuid,noexec,size=16m,mode=1777',
        '--env', 'PORT_TEST_MUTATION=' + args.mutation,
        '--entrypoint=/opt/secret-proxy/.venv/bin/python', identifier, '-B', '-']
    try:
        subprocess.run(command, env=env, input=PROBE.encode(), check=True, timeout=75)
    finally:
        # Only this uniquely named, synthetic no-network fixture.
        subprocess.run(base + ['rm', '-f', name], env=env, capture_output=True, timeout=15)


if __name__ == '__main__':
    main()
