"""Offline AWS policy export: make legacy implicit defaults explicit.

Never imports/executes the legacy module or contacts Okta/AWS/a vault. Supply
that deployment's module and actual config; repository seed config is NOT proof
of active policy. An explicit approved-host list remains required.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import sys

from awscreds import AwsCredsProvider
from secretstore import _unique_object

NAMES = {'DEFAULT_ACCOUNT_APP_URLS', 'DEFAULT_ALLOWED_ROLES', 'DEFAULT_ACCOUNT_ROLE_OVERRIDES'}
FIELDS = {'schemaVersion', 'region', 'session_duration', 'default_account', 'default_role',
          'OKTA_USERNAME', 'OKTA_PASSWORD', 'OKTA_SECRET', 'default_app_url',
          'account_app_urls', 'allowed_roles', 'account_role_overrides', 'okta_hosts'}


def literal_defaults(text: str) -> dict:
    values = {}
    for node in ast.parse(text).body:
        target = node.target if isinstance(node, ast.AnnAssign) else (
            node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else None)
        if isinstance(target, ast.Name) and target.id in NAMES:
            if target.id in values:
                raise ValueError('Repeated legacy policy declaration')
            values[target.id] = ast.literal_eval(node.value)
    if set(values) != NAMES:
        raise ValueError('Explicit legacy policy declarations required')
    return values


def convert_aws(config: dict, defaults: dict, hosts: list[str]) -> dict:
    if not isinstance(config, dict) or set(config) - FIELDS or set(defaults) != NAMES:
        raise ValueError('Unsupported AWS policy fields; review the source manually')
    if 'schemaVersion' in config and config['schemaVersion'] != 2:
        raise ValueError('Unsupported legacy AWS policy version')
    # Mirror the legacy provider's precedence, including per-account built-ins
    # which outrank a file's GLOBAL role list. Never infer or widen entitlement.
    result = {k: v for k, v in config.items() if k != 'schemaVersion'}
    result['okta_hosts'] = hosts
    result['allowed_roles'] = config.get('allowed_roles', defaults['DEFAULT_ALLOWED_ROLES'])
    result['account_app_urls'] = {**defaults['DEFAULT_ACCOUNT_APP_URLS'], **config.get('account_app_urls', {})}
    result['account_role_overrides'] = {**defaults['DEFAULT_ACCOUNT_ROLE_OVERRIDES'], **config.get('account_role_overrides', {})}
    AwsCredsProvider._validate_config(result)
    return result


def export_aws(config: dict, defaults: dict, hosts: list[str], output: Path):
    result = convert_aws(config, defaults, hosts)
    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with open(output, 'x', opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, help='Actual legacy config, or - for bounded stdin')
    parser.add_argument('--legacy-module', required=True, type=Path)
    parser.add_argument('--okta-host', required=True, action='append')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.source == '-':
        data = sys.stdin.buffer.read(65537)
    else:
        with open(args.source, 'rb') as stream:
            data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('AWS policy exceeds limit')
    with args.legacy_module.open('rb') as stream:
        module = stream.read(262145)
    if len(module) > 262144:
        raise ValueError('Legacy module exceeds limit')
    export_aws(json.loads(data, object_pairs_hook=_unique_object), literal_defaults(module.decode()),
               args.okta_host, args.output)
    print('Private AWS policy exported without resolving credentials or contacting any provider.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('AWS export refused; verify source policy, approved hosts and output path. No provider was contacted.', file=sys.stderr)
        sys.exit(1)
