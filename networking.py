"""Attach to an externally owned VPN namespace without managing its lifecycle.

The external owner is responsible for authenticated tunnel setup and fail-closed
routing. This controller never starts, removes, restarts or reconfigures it.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re


class NetworkError(Exception):
    pass


@dataclass(frozen=True)
class NetworkPolicy:
    container: str
    network: str
    interface: str
    port: int
    ready_file: str
    dns: tuple[str, ...]

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != {'container', 'network', 'interface', 'port', 'readyFile', 'dns'}:
            raise NetworkError('Invalid external VPN policy')
        for key in ('container', 'network'):
            if not isinstance(value[key], str) or re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}', value[key]) is None:
                raise NetworkError('Invalid VPN container/network name')
        if not isinstance(value['interface'], str) or re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,14}', value['interface']) is None:
            raise NetworkError('Invalid required VPN interface')
        path = value['readyFile']
        if (not isinstance(path, str) or not path.startswith('/run/') or len(path) > 256
                or any(part in ('', '.', '..') for part in path.split('/')[1:])
                or re.fullmatch(r'/[a-zA-Z0-9/_.-]+', path) is None):
            raise NetworkError('Invalid VPN readiness path')
        if type(value['port']) is not int or not 1024 <= value['port'] <= 65535 or value['port'] == 10256:
            raise NetworkError('Choose a distinct unprivileged proxy port for the shared namespace')
        if not isinstance(value['dns'], list) or not 1 <= len(value['dns']) <= 3:
            raise NetworkError('Explicit IPv4 DNS servers required')
        try:
            dns = tuple(str(ipaddress.IPv4Address(v)) for v in value['dns'] if isinstance(v, str))
            if len(dns) != len(value['dns']):
                raise ValueError()
        except ValueError:
            raise NetworkError('Explicit IPv4 DNS servers required') from None
        return cls(value['container'], value['network'], value['interface'], value['port'], path, dns)

    def to_dict(self):
        return {'container': self.container, 'network': self.network, 'interface': self.interface,
                'port': self.port, 'readyFile': self.ready_file, 'dns': list(self.dns)}


@dataclass(frozen=True)
class Gateway:
    container_id: str
    address: str


def check_gateway(policy, gateway, engine):
    status = engine('container', 'inspect', gateway.container_id, '--format', '{{.State.Running}}')
    if status.returncode or status.stdout.strip() != b'true':
        raise NetworkError('Pinned VPN gateway is not running; no direct fallback')
    ready = engine('exec', gateway.container_id, 'test', '-r', policy.ready_file)
    flags = engine('exec', gateway.container_id, 'ip', '-j', 'link', 'show', 'dev', policy.interface)
    try:
        links = json.loads(flags.stdout)
        up = flags.returncode == 0 and len(links) == 1 and 'UP' in links[0]['flags']
    except (ValueError, KeyError, TypeError):
        up = False
    if ready.returncode or not up:
        raise NetworkError('VPN readiness/interface is down; no direct fallback')


def resolve_gateway(policy, engine):
    result = engine('container', 'inspect', policy.container, '--format', '{{.Id}}')
    identifier = result.stdout.decode().strip() if result.returncode == 0 else ''
    if re.fullmatch(r'[a-f0-9]{64}', identifier) is None:
        raise NetworkError('VPN gateway unavailable; it must be started by its owner')
    result = engine('container', 'inspect', identifier, '--format', '{{json .NetworkSettings.Networks}}')
    try:
        if result.returncode:
            raise ValueError()
        address = str(ipaddress.IPv4Address(json.loads(result.stdout)[policy.network]['IPAddress']))
        ip = ipaddress.IPv4Address(address)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise NetworkError('VPN gateway lacks an address on the explicit relay network') from None
    gateway = Gateway(identifier, address)
    check_gateway(policy, gateway, engine)
    return gateway


def relay_command(policy, gateway, name, port, image):
    # Returns only arguments for an existing, pinned engine. No vault state,
    # auth capability or config volume enters this opaque TCP relay.
    return ['run', '--detach', '--rm', '--init', '--name', name, '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--log-driver=none',
            '--pids-limit=128', '--network', policy.network,
            '--publish', f'127.0.0.1:{port}:10256', '--entrypoint=/usr/bin/socat', image,
            'TCP-LISTEN:10256,fork,reuseaddr', f'TCP:{gateway.address}:{policy.port}']
