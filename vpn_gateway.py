"""Bounded lifecycle for gateway containers created by this proxy instance only."""
from __future__ import annotations

import json
import re
import secrets
import subprocess
import time

from networking import NetworkError, resolve_gateway

OWNER = 'io.secret-proxy.vpn-owner'
LAUNCH = 'io.secret-proxy.vpn-launch'


def inspect_owned(engine, kind, name, instance, nonce=None):
    result = engine(kind, 'inspect', name)
    if result.returncode:
        raise NetworkError('Managed VPN inspection failed')
    try:
        row, = json.loads(result.stdout)
        labels = row.get('Labels') or row.get('labels') or row.get('Config', {}).get('Labels') or {}
        if labels.get(OWNER) != instance or (nonce and labels.get(LAUNCH) != nonce):
            raise ValueError()
    except (TypeError, KeyError, ValueError):
        raise NetworkError('VPN resource is not owned by this startup; refusing to change it') from None
    return row


def command(deployment, image, nonce):
    if re.fullmatch(r'sha256:[0-9a-f]{64}', image) is None:
        raise NetworkError('Managed VPN requires an exact image ID')
    policy = deployment.network
    return ['run', '--rm', '-i', '--init', '--name', policy.container,
            '--label', OWNER + '=' + deployment.instance, '--label', LAUNCH + '=' + nonce,
            '--network', policy.network, '--read-only', '--user', '0:0',
            '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--cap-add=NET_BIND_SERVICE',
            '--device=/dev/net/tun', '--security-opt=no-new-privileges', '--security-opt=label=disable',
            '--pids-limit=128', '--log-driver=none',
            '--tmpfs', '/run:rw,nodev,nosuid,noexec,size=16m,mode=0755',
            '--tmpfs', '/tmp:rw,nodev,nosuid,noexec,size=16m,mode=1777',
            '--volume', str(deployment.private / 'config') + ':/config:ro',
            '--volume', str(deployment.private / 'runtime-ca.pem') + ':/etc/ssl/certs/ca-certificates.crt:ro',
            '--entrypoint=/opt/secret-proxy/.venv/bin/python', image,
            '/opt/secret-proxy/vpnc_runtime.py', deployment.network_name]


class ManagedGateway:
    def __init__(self, deployment, image, bundle, engine, engine_command, environment):
        self.deployment, self.image, self.bundle = deployment, image, bundle
        self.engine, self.engine_command, self.environment = engine, engine_command, environment
        self.nonce = secrets.token_hex(16)
        self.child = None
        self.identifier = None

    def __enter__(self):
        dep = self.deployment
        exists = self.engine('container', 'exists', dep.network.container)
        if exists.returncode != 1:
            raise NetworkError('Managed VPN container already exists or cannot be inspected; use explicit stop')
        exists = self.engine('network', 'exists', dep.network.network)
        if exists.returncode == 1:
            result = self.engine('network', 'create', '--label', OWNER + '=' + dep.instance, dep.network.network)
            if result.returncode:
                raise NetworkError('Managed VPN network creation failed')
        elif exists.returncode != 0:
            raise NetworkError('Managed VPN network inspection failed')
        network = inspect_owned(self.engine, 'network', dep.network.network, dep.instance)
        if network.get('internal', False) or network.get('driver', 'bridge') != 'bridge':
            raise NetworkError('Managed VPN needs its owned bridge network')
        # No proxy capability or login-vault metadata is needed by the gateway.
        payload = json.dumps({'op_token': self.bundle['op_token'], 'proxy_token': '0' * 48}).encode()
        try:
            self.child = subprocess.Popen(self.engine_command(command(dep, self.image, self.nonce)),
                                          env=self.environment, stdin=subprocess.PIPE,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.child.stdin.write(payload); self.child.stdin.close()
            payload = b''
            deadline = time.monotonic() + 240
            while self.child.poll() is None and time.monotonic() < deadline:
                exists = self.engine('container', 'exists', dep.network.container)
                if exists.returncode == 0:
                    row = inspect_owned(self.engine, 'container', dep.network.container, dep.instance, self.nonce)
                    identifier = row.get('Id') or row.get('ID')
                    if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{64}', identifier):
                        raise NetworkError('Invalid managed VPN identity')
                    self.identifier = identifier
                    ready = self.engine('exec', identifier, 'test', '-r', dep.network.ready_file)
                    if ready.returncode == 0:
                        gateway = resolve_gateway(dep.network, self.engine)
                        if gateway.container_id != identifier:
                            raise NetworkError('VPN identity changed during startup')
                        return self
                elif exists.returncode != 1:
                    raise NetworkError('Managed VPN startup inspection failed')
                time.sleep(.2)
            raise NetworkError('Managed VPN failed readiness; no direct fallback')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.child is None:
            return
        # If interrupted before the first inspection, discover only the exact
        # launch-labelled resource. Never clean up by name without proof.
        try:
            target = self.identifier or self.deployment.network.container
            exists = self.engine('container', 'exists', target)
            if exists.returncode == 0:
                row = inspect_owned(self.engine, 'container', target, self.deployment.instance, self.nonce)
                identifier = row.get('Id') or row.get('ID')
                if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{64}', identifier):
                    raise NetworkError('Invalid managed VPN cleanup identity')
                result = self.engine('rm', '-f', identifier)
                if result.returncode and self.engine('container', 'exists', identifier).returncode != 1:
                    raise NetworkError('Managed VPN cleanup failed; use explicit stop')
            elif exists.returncode != 1:
                raise NetworkError('Managed VPN cleanup inspection failed')
        finally:
            # Even when inspection fails, reap only the client process we
            # launched. Never issue a name-based rm against an unproven resource.
            if self.child.poll() is None:
                self.child.terminate()
                try:
                    self.child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.child.kill(); self.child.wait()

    def __exit__(self, *exc):
        self.close()
