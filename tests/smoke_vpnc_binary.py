"""Packaged vpnc startup contract, synthetic credentials, no external network.

This checks its real pre-init ordering and rejection of an unexpected password
helper prompt. It cannot establish an authenticated IKE/XAUTH tunnel.
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
import subprocess
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
vpn.write_challenge(values, '192.0.2.8')
env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(vpn.READY.parent)}
child = subprocess.Popen(vpn.vpnc_command(profile, config), env=env,
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    try:
        child.communicate(timeout=3)
        raise AssertionError('Packaged vpnc exited before synthetic negotiation')
    except subprocess.TimeoutExpired:
        assert vpn.hook_stage() == 'negotiating', 'Real pre-init hook was rejected'
        assert not vpn.READY.exists(), 'No authenticated tunnel exists'
        assert subprocess.run(['ip', 'link', 'show', 'tun0'], capture_output=True).returncode == 0
finally:
    if child.poll() is None:
        child.terminate()
    try:
        child.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill(); child.communicate(timeout=3)

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
print('PASS: packaged vpnc pre-init without TUNDEV, real TUN creation, no false readiness; unexpected real helper prompt refused')
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--connection', required=True)
    parser.add_argument('--image', required=True)
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
        '--entrypoint=/opt/secret-proxy/.venv/bin/python', identifier, '-']
    try:
        subprocess.run(command, env=env, input=PROBE.encode(), check=True, timeout=30)
    finally:
        # Only this uniquely named, synthetic no-network fixture.
        subprocess.run(base + ['rm', '-f', name], env=env, capture_output=True, timeout=15)


if __name__ == '__main__':
    main()
