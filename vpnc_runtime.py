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
import tempfile
import time

from networking import NetworkError
from vpn_profiles import checked_address, load_networks, validate_secrets
from vpn_status import FAILURES, STAGES, encode_stage, publish

READY = Path('/run/vpn/ready')
ROOT = Path('/opt/secret-proxy')
CHALLENGE = Path('/run/vpn/totp-challenge.json')


def totp(seed, now):
    text = seed.strip().replace(' ', '').upper().rstrip('=')
    raw = base64.b32decode(text + '=' * (-len(text) % 8), casefold=True)
    if not 10 <= len(raw) <= 128:
        raise ValueError('Invalid TOTP seed')
    digest = hmac.new(raw, struct.pack('>Q', int(now) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return '%06d' % ((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000)


def write_challenge(values, gateway, state=CHALLENGE):
    # Validate before writing; seed is confined to the gateway's private tmpfs.
    totp(values['totpSecret'], time.time())
    peer = str(ipaddress.IPv4Address(gateway))
    prompts = [kind + ' for VPN ' + values['usernameSecret'] + '@' + peer + ': '
               for kind in ('Password', 'Passcode', 'Answer')]
    data = {'seed': values['totpSecret'], 'prompts': prompts, 'deadline': time.monotonic() + 90}
    fd = os.open(state, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)


def answer_challenge(prompt, state=CHALLENGE):
    # Claim before reading: even simultaneous/repeated helper calls cannot issue
    # another OTP. Unexpected or expired challenges consume the single attempt.
    used = state.with_suffix('.used')
    fd = os.open(used, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    try:
        data = json.loads(state.read_text())
        if prompt not in data['prompts'] or time.monotonic() >= data['deadline']:
            raise ValueError('Unexpected or expired VPN challenge')
        return totp(data['seed'], time.time())
    finally:
        state.unlink(missing_ok=True)


def clear_challenge(state=CHALLENGE):
    state.unlink(missing_ok=True)
    state.with_suffix('.used').unlink(missing_ok=True)


def vpnc_command(profile, config):
    # vpnc refuses a second XAUTH challenge with --non-inter, even when a
    # Password helper is configured. Our helper is one-shot and stdin stays EOF.
    flags = [] if profile.get('totpMode') == 'challenge' else ['--non-inter']
    return ['/usr/sbin/vpnc', '--no-detach', *flags, '--pid-file', '/run/vpn/vpnc.pid', str(config)]


def configuration(profile, values, gateway, now):
    for value in values.values():
        if not isinstance(value, str) or not value or len(value) > 4096 or any(not 32 <= ord(c) < 127 for c in value):
            raise ValueError('Invalid VPN credential field')
    gateway = str(ipaddress.IPv4Address(gateway))
    password = values['passwordSecret']
    if 'totpSecret' in profile and profile.get('totpMode', 'append') == 'append':
        password += totp(values['totpSecret'], now)
    fields = [('IPSec gateway', gateway), ('IPSec ID', profile['group']),
              ('IPSec secret', values['groupSecret']), ('IKE DH Group', profile['dhGroup']),
              ('Xauth username', values['usernameSecret']), ('Xauth password', password),
              ('Interface name', 'tun0'), ('NAT Traversal Mode', 'natt'),
              ('Script', str(ROOT / '.venv/bin/python') + ' ' + str(ROOT / 'vpnc_runtime.py') + ' hook')]
    if profile.get('totpMode') == 'challenge':
        fields.append(('Password helper', str(ROOT / 'vpnc_password_helper.py')))
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


def hook_stage():
    try:
        with (READY.parent / 'hook-status').open(encoding='ascii') as stream:
            value = stream.read(65).strip()
    except FileNotFoundError:
        return None
    except UnicodeError:
        return 'hook-rejected'
    return value if value in STAGES else 'hook-rejected'


def record_hook_stage(stage):
    encode_stage(stage)
    # Keep the first failure: vpnc may run disconnect after a rejected hook.
    if hook_stage() not in FAILURES:
        fd, temporary = tempfile.mkstemp(prefix='.hook-', dir=READY.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(stage + '\n')
            os.replace(temporary, READY.parent / 'hook-status')
        finally:
            Path(temporary).unlink(missing_ok=True)


def hook(environment=None):
    env = dict(environment if environment is not None else os.environ)
    reason = env.get('reason')
    READY.unlink(missing_ok=True)
    failure = 'hook-rejected'
    try:
        # Packaged vpnc calls pre-init BEFORE tun_open() sets TUNDEV. Later
        # events must still name exactly the managed interface, never eth0.
        valid_interface = env.get('TUNDEV') in (None, 'tun0') if reason == 'pre-init' else env.get('TUNDEV') == 'tun0'
        if reason not in ('pre-init', 'connect', 'disconnect', 'reconnect', 'attempt-reconnect') or not valid_interface:
            raise ValueError('Unexpected VPN script event')
        if hook_stage() in FAILURES:
            raise ValueError('VPN hook previously failed')
        # Proxy DNS is explicit in the installed profile, not a rewritten guest file.
        env.pop('INTERNAL_IP4_DNS', None)
        env.pop('INTERNAL_IP6_DNS', None)
        env['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
        failure = 'route-script-failed'
        record_hook_stage('route-script')
        subprocess.run(['/usr/share/vpnc-scripts/vpnc-script'], env=env,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True, timeout=30)
        if reason in ('connect', 'reconnect'):
            failure = 'full-tunnel-required'
            record_hook_stage('full-tunnel-check')
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
            record_hook_stage('ready')
            READY.write_text('ready\n')
        else:
            record_hook_stage('negotiating' if reason == 'pre-init' else 'disconnected')
    except Exception:
        record_hook_stage(failure)
        raise


def connect(profile_name):
    # Imports stay out of the vpnc hook, which runs several times per connection.
    from runtime import read_bootstrap
    from secretstore import SecretManifest, SecretResolver
    publish('profile')
    profiles = load_networks(Path('/config/networks.json').read_bytes())
    profile = profiles[profile_name]
    if profile['type'] != 'vpnc':
        raise ValueError('Not a managed VPN profile')
    manifest = SecretManifest.load('/config/manifest.json')
    validate_secrets({profile_name: profile}, manifest)
    os.umask(0o077)
    READY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    READY.unlink(missing_ok=True)
    (READY.parent / 'hook-status').unlink(missing_ok=True)
    publish('bootstrap')
    bundle = read_bootstrap(sys.stdin.fileno())
    # The service-account capability exists only during this trusted bootstrap.
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(READY.parent),
           'OP_CONFIG_DIR': '/tmp/op-config', 'OP_CLI_PATH': '/usr/local/bin/op',
           'OP_SERVICE_ACCOUNT_TOKEN': bundle['op_token'],
           'SSL_CERT_FILE': '/etc/ssl/certs/ca-certificates.crt'}
    publish('vault')
    resolver = SecretResolver.from_environment(manifest, env=env)
    values = {key: resolver.get(profile[key]) for key in
              ('usernameSecret', 'passwordSecret', 'groupSecret', 'totpSecret') if key in profile}
    resolver.clear_cache()
    del resolver
    env.clear(); bundle.clear()
    # Resolve before installing the firewall; the IKE peer is pinned to this IP.
    publish('peer-resolution')
    answers = socket.getaddrinfo(profile['gateway'], 500, socket.AF_INET, socket.SOCK_DGRAM)
    gateway = checked_address(ipaddress.IPv4Address(answers[0][4][0]))
    addresses = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', 'eth0']))
    local = [a for row in addresses for a in row['addr_info'] if a.get('scope') == 'global']
    if len(local) != 1:
        raise ValueError('Unexpected gateway interface addresses')
    relay_cidr = str(ipaddress.IPv4Interface(str(local[0]['local']) + '/' + str(local[0]['prefixlen'])).network)
    publish('firewall')
    subprocess.run(['/usr/sbin/nft', '-f', '-'], input=firewall(gateway, relay_cidr).encode(), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if 'totpSecret' in profile and profile.get('totpMode', 'append') == 'append' and time.time() % 30 > 20:
        time.sleep(30 - time.time() % 30 + .1)
    publish('configuration')
    config = READY.parent / 'vpnc.conf'
    config.write_text(configuration(profile, values, gateway, time.time()))
    config.chmod(0o600)
    if profile.get('totpMode') == 'challenge':
        write_challenge(values, gateway)
    values.clear()
    child = subprocess.Popen(vpnc_command(profile, config),
                             env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(READY.parent)},
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def stop(_signal, _frame):
        if child.poll() is None:
            child.terminate()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    try:
        deadline = time.monotonic() + 90
        last = 'negotiating'
        publish(last)
        while True:
            stage = hook_stage()
            if stage and stage != last:
                publish(stage)
                last = stage
            if stage in FAILURES:
                raise ValueError('VPN startup hook refused')
            if READY.exists():
                break
            if child.poll() is not None:
                publish('client-exited')
                raise ValueError('VPN client exited before readiness')
            if time.monotonic() >= deadline:
                publish('startup-timeout')
                raise ValueError('VPN did not become ready')
            time.sleep(.2)
        config.unlink()  # no password or OTP remains in the config after login
        clear_challenge()
        publish('ready')
        return child.wait()
    finally:
        READY.unlink(missing_ok=True)
        config.unlink(missing_ok=True)
        clear_challenge()
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
