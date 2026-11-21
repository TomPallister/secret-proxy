"""Trusted, managed IKEv1/XAUTH gateway. Never serves credentials to clients.

Only full-tunnel IPv4 is supported. An inet output kill switch remains installed
through disconnect/route restoration; IPv6 outside the tunnel is also dropped.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from networking import NetworkError
from vpn_profiles import checked_address, load_networks, validate_secrets

READY = Path('/run/vpn/ready')
ROOT = Path('/opt/secret-proxy')


def totp(seed, now):
    text = seed.strip().replace(' ', '').upper().rstrip('=')
    raw = base64.b32decode(text + '=' * (-len(text) % 8), casefold=True)
    if not 10 <= len(raw) <= 128:
        raise ValueError('Invalid TOTP seed')
    digest = hmac.new(raw, struct.pack('>Q', int(now) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return '%06d' % ((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000)


def configuration(profile, values, gateway, now):
    for value in values.values():
        if not isinstance(value, str) or not value or len(value) > 4096 or any(not 32 <= ord(c) < 127 for c in value):
            raise ValueError('Invalid VPN credential field')
    gateway = str(ipaddress.IPv4Address(gateway))
    password = values['passwordSecret']
    if 'totpSecret' in profile:
        password += totp(values['totpSecret'], now)
    fields = [('IPSec gateway', gateway), ('IPSec ID', profile['group']),
              ('IPSec secret', values['groupSecret']), ('IKE DH Group', profile['dhGroup']),
              ('Xauth username', values['usernameSecret']), ('Xauth password', password),
              ('Interface name', 'tun0'), ('NAT Traversal Mode', 'natt'),
              ('Script', str(ROOT / '.venv/bin/python') + ' ' + str(ROOT / 'vpnc_runtime.py') + ' hook')]
    return ''.join(key + ' ' + value + '\n' for key, value in fields)


def firewall(gateway, relay_cidr):
    gateway = checked_address(ipaddress.IPv4Address(gateway))
    subnet = ipaddress.IPv4Network(relay_cidr)
    if subnet.prefixlen < 16 or not subnet.is_private:
        raise ValueError('Unsafe relay subnet')
    # No blanket established-connection allowance: when tun0 disappears an
    # established connection must not leak through the restored eth0 default.
    return '''table inet secret_proxy_vpn {
 chain output {
  type filter hook output priority 0; policy drop;
  oifname "lo" accept
  oifname "tun0" accept
  ip daddr %s udp dport { 500, 4500 } accept
  ip daddr %s ip protocol esp accept
  ip daddr %s tcp sport 10257 ct state established accept
 }
}
''' % (gateway, gateway, subnet)


def hook(environment=None):
    env = dict(environment if environment is not None else os.environ)
    reason = env.get('reason')
    if reason not in ('pre-init', 'connect', 'disconnect', 'reconnect', 'attempt-reconnect') or env.get('TUNDEV') != 'tun0':
        raise ValueError('Unexpected VPN script event')
    READY.unlink(missing_ok=True)
    # Proxy DNS is explicit in the installed profile, not a rewritten guest file.
    env.pop('INTERNAL_IP4_DNS', None)
    env.pop('INTERNAL_IP6_DNS', None)
    env['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    subprocess.run(['/usr/share/vpnc-scripts/vpnc-script'], env=env,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True, timeout=30)
    if reason in ('connect', 'reconnect'):
        table = subprocess.run(['/usr/sbin/ip', '-j', '-4', 'route', 'show'],
                               capture_output=True, check=True, timeout=5)
        prefixes = {row.get('dst') for row in json.loads(table.stdout) if row.get('dev') == 'tun0'}
        if 'default' not in prefixes and not {'0.0.0.0/1', '128.0.0.0/1'} <= prefixes:
            raise ValueError('Managed VPN requires a full-tunnel IPv4 route')
        route = subprocess.run(['/usr/sbin/ip', '-j', '-4', 'route', 'get', '1.1.1.1'],
                               capture_output=True, check=True, timeout=5)
        routes = json.loads(route.stdout)
        if len(routes) != 1 or routes[0].get('dev') != 'tun0':
            raise ValueError('Managed VPN requires a full-tunnel IPv4 route')
        READY.write_text('ready\n')


def connect(profile_name):
    # Imports stay out of the vpnc hook, which runs several times per connection.
    from runtime import read_bootstrap
    from secretstore import SecretManifest, SecretResolver
    profiles = load_networks(Path('/config/networks.json').read_bytes())
    profile = profiles[profile_name]
    if profile['type'] != 'vpnc':
        raise ValueError('Not a managed VPN profile')
    manifest = SecretManifest.load('/config/manifest.json')
    validate_secrets({profile_name: profile}, manifest)
    os.umask(0o077)
    READY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    READY.unlink(missing_ok=True)
    bundle = read_bootstrap(sys.stdin.fileno())
    # The service-account capability exists only during this trusted bootstrap.
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(READY.parent),
           'OP_CONFIG_DIR': '/tmp/op-config', 'OP_CLI_PATH': '/usr/local/bin/op',
           'OP_SERVICE_ACCOUNT_TOKEN': bundle['op_token'],
           'SSL_CERT_FILE': '/etc/ssl/certs/ca-certificates.crt'}
    resolver = SecretResolver.from_environment(manifest, env=env)
    values = {key: resolver.get(profile[key]) for key in
              ('usernameSecret', 'passwordSecret', 'groupSecret', 'totpSecret') if key in profile}
    resolver.clear_cache()
    del resolver
    env.clear(); bundle.clear()
    # Resolve before installing the firewall; the IKE peer is pinned to this IP.
    answers = socket.getaddrinfo(profile['gateway'], 500, socket.AF_INET, socket.SOCK_DGRAM)
    gateway = checked_address(ipaddress.IPv4Address(answers[0][4][0]))
    addresses = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', 'eth0']))
    local = [a for row in addresses for a in row['addr_info'] if a.get('scope') == 'global']
    if len(local) != 1:
        raise ValueError('Unexpected gateway interface addresses')
    relay_cidr = str(ipaddress.IPv4Interface(str(local[0]['local']) + '/' + str(local[0]['prefixlen'])).network)
    subprocess.run(['/usr/sbin/nft', '-f', '-'], input=firewall(gateway, relay_cidr).encode(), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if 'totpSecret' in profile and time.time() % 30 > 20:
        time.sleep(30 - time.time() % 30 + .1)
    config = READY.parent / 'vpnc.conf'
    config.write_text(configuration(profile, values, gateway, time.time()))
    config.chmod(0o600)
    values.clear()
    child = subprocess.Popen(['/usr/sbin/vpnc', '--no-detach', '--non-inter',
                              '--pid-file', '/run/vpn/vpnc.pid', str(config)],
                             env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(READY.parent)},
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def stop(_signal, _frame):
        if child.poll() is None:
            child.terminate()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    try:
        deadline = time.monotonic() + 90
        while not READY.exists():
            if child.poll() is not None or time.monotonic() >= deadline:
                raise ValueError('VPN did not become ready')
            time.sleep(.2)
        config.unlink()  # no password or OTP remains in the config after login
        return child.wait()
    finally:
        READY.unlink(missing_ok=True)
        config.unlink(missing_ok=True)
        # Never remove the firewall, even while vpnc restores routes.
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['hook']:
            hook()
        elif len(sys.argv) == 2:
            sys.exit(connect(sys.argv[1]))
        else:
            raise ValueError('Expected an installed VPN profile')
    except Exception as exc:
        # vpnc/provider diagnostics can contain credentials; never forward them.
        print('Managed VPN failed: ' + type(exc).__name__, file=sys.stderr)
        sys.exit(1)
