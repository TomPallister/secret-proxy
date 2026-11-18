"""Offline conversion of an existing schema-2 policy into external schema 3.

Reads configuration metadata only. Does not call a vault, copy any secret value,
change an existing deployment or provision a service account. Output stays private.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile

from secretstore import SecretManifest, _unique_object


class MigrationError(Exception):
    pass


def convert(source: dict, profile: str, realm: str | None = None) -> tuple[dict, dict]:
    if source.get('schemaVersion') != 2 or not isinstance(source.get('accounts'), dict):
        raise MigrationError('Expected a schema-2 source manifest')
    selected = {}
    bindings = []
    for name, spec in source['secrets'].items():
        if profile not in spec.get('profiles', []):
            continue
        account = source['accounts'][spec['account']]
        runtime_name = account.get('onepasswordRuntimeAccount', spec['account'])
        runtime = source['accounts'][runtime_name]
        vault = account.get('onepasswordRuntimeVault', runtime['onepasswordVault'])
        if vault != runtime['onepasswordVault']:
            raise MigrationError('Runtime vault override needs manual bootstrap mapping')
        bindings.append((runtime['onepasswordAccount'], vault, runtime['onepasswordBootstrapVault'], runtime['serviceAccountTokenItem']))
        selected[name] = {key: value for key, value in spec.items() if key not in ('account', 'profiles')}
    if not selected or len(set(bindings)) != 1:
        raise MigrationError('The selected policy must resolve to one account/vault/bootstrap binding')
    account, vault, bootstrap_vault, item = bindings[0]
    manifest = {'schemaVersion': 3, 'account': {'vault': vault}, 'secrets': selected}
    if 'CHECKMARX_ACCESS_TOKEN' in selected:
        if not realm:
            raise MigrationError('An explicit Checkmarx realm is required')
        manifest['checkmarxRealm'] = realm
    bootstrap = {'account': account, 'vault': bootstrap_vault, 'item': item, 'runtimeVault': vault}
    return manifest, bootstrap


def export(source: Path, destination: Path, profile: str, realm: str | None = None):
    manifest, bootstrap = convert(json.loads(source.read_text(), object_pairs_hook=_unique_object), profile, realm)
    # Validate in a private temporary directory before publishing any output.
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / 'manifest.json'
        staged.write_text(json.dumps(manifest))
        SecretManifest.load(staged)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(destination, 0o700)
    for name, data in (('manifest.json', manifest), ('bootstrap.json', bootstrap)):
        with open(destination / name, 'x', opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--checkmarx-realm')
    args = parser.parse_args()
    export(args.source, args.output, args.profile, args.checkmarx_realm)
    print('Private configuration exported. No credentials read, moved or provisioned.')


if __name__ == '__main__':
    main()
