"""Strict, non-secret named network configuration; direct is never configurable."""
from __future__ import annotations

import ipaddress
import json
import re

from networking import NetworkError, NetworkPolicy

NAME = re.compile(r'[a-z][a-z0-9-]{0,31}')
SECRET_NAME = re.compile(r'[A-Z][A-Z0-9_]{1,127}')


def network_name(value):
    if not isinstance(value, str) or NAME.fullmatch(value) is None:
        raise NetworkError('Invalid network selection')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise NetworkError('Duplicate network configuration field')
        result[key] = value
    return result


def load_networks(data):
    if len(data) > 32768:
        raise NetworkError('Network configuration too large')
    value = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != {'version', 'networks'} or type(value['version']) is not int or value['version'] != 1:
        raise NetworkError('networks.json requires version 1 and networks; no default is allowed')
    return validate_networks(value['networks'])


def validate_networks(value):
    if not isinstance(value, dict) or len(value) > 8:
        raise NetworkError('At most eight named networks are supported')
    result = {}
    for name, profile in value.items():
        network_name(name)
        if name in ('direct', 'legacy') or not isinstance(profile, dict):
            raise NetworkError('Reserved network name or invalid profile')
        kind = profile.get('type')
        if kind == 'external':
            policy = NetworkPolicy.from_dict({k: v for k, v in profile.items() if k != 'type'})
            result[name] = {'type': 'external', **policy.to_dict()}
        elif kind == 'vpnc':
            required = {'type', 'gateway', 'group', 'dhGroup', 'dns', 'usernameSecret', 'passwordSecret', 'groupSecret'}
            if not required <= set(profile) or set(profile) - required - {'totpSecret'}:
                raise NetworkError('Invalid vpnc profile; use secret names, never credentials or commands')
            gateway = profile['gateway']
            if not isinstance(gateway, str) or len(gateway) > 253 or not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', gateway):
                raise NetworkError('Invalid VPN gateway')
            try:
                address = ipaddress.IPv4Address(gateway)
            except ValueError:
                labels = gateway.split('.')
                if len(labels) < 2 or any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in labels):
                    raise NetworkError('Invalid VPN gateway hostname') from None
            else:
                checked_address(address)
            group = profile['group']
            if not isinstance(group, str) or not group or len(group) > 128 or any(not 32 <= ord(c) < 127 for c in group):
                raise NetworkError('Invalid VPN group')
            if profile['dhGroup'] not in ('dh2', 'dh5', 'dh14'):
                raise NetworkError('Unsupported IKE DH group')
            dns = profile['dns']
            if not isinstance(dns, list) or not 1 <= len(dns) <= 3:
                raise NetworkError('Explicit IPv4 DNS servers required')
            try:
                for address in dns:
                    if not isinstance(address, str):
                        raise ValueError()
                    checked_address(ipaddress.IPv4Address(address))
            except ValueError:
                raise NetworkError('Invalid VPN DNS address') from None
            for key in ('usernameSecret', 'passwordSecret', 'groupSecret', 'totpSecret'):
                if key in profile and (not isinstance(profile[key], str) or not SECRET_NAME.fullmatch(profile[key])):
                    raise NetworkError('VPN credentials must be canonical secret names')
            result[name] = dict(profile)
        else:
            raise NetworkError('Network type must be external or vpnc')
    return result


def checked_address(address):
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local or address.is_reserved:
        raise NetworkError('Unsafe VPN endpoint or DNS address')
    return str(address)


def validate_secrets(networks, manifest):
    for profile in networks.values():
        if profile['type'] != 'vpnc':
            continue
        for key in ('usernameSecret', 'passwordSecret', 'groupSecret', 'totpSecret'):
            if key not in profile:
                continue
            try:
                info = manifest.secret(profile[key])
            except (ValueError, KeyError):
                raise NetworkError('VPN credential is missing from the manifest') from None
            if not info.internal_only or info.value_field != 'password' or info.runtime_only or info.derived_from:
                raise NetworkError('VPN credentials must be internal-only stored password fields')


def gateway_policy(instance, profile):
    if profile['type'] == 'external':
        return NetworkPolicy.from_dict({k: v for k, v in profile.items() if k != 'type'})
    return NetworkPolicy('sp-' + instance + '-vpn', 'sp-' + instance + '-vpn-net',
                         'tun0', 10257, '/run/vpn/ready', tuple(profile['dns']))
