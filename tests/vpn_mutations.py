"""Bounded VPN regression mutations; run in an isolated worktree, never installed source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ('direct-default', 'host.py', "return replace(self, network=None, vpn=None, network_name='direct')",
     'return self.select_network(next(iter(self.networks)))',
     'test_vpn_selection.SelectionTests.test_catalog_has_no_default_and_direct_never_uses_a_vpn'),
    ('mode-mismatch', 'manage.py', 'if active != network_name:', 'if False:',
     'test_vpn_selection.SelectionTests.test_ready_other_mode_is_not_silently_kept_or_restarted'),
    ('boot-bound-mode', 'manage.py', "or state['instance'] != ready.get('instance')", 'or False',
     'test_vpn_selection.SelectionTests.test_mode_metadata_must_match_authenticated_boot'),
    ('drop-policy', 'vpnc_runtime.py', 'type filter hook output priority 0; policy drop;',
     'type filter hook output priority 0; policy accept;',
     'test_vpnc_runtime.VpncTests.test_kill_switch_allows_tunnel_and_ike_not_direct_tcp_or_ipv6'),
    ('full-tunnel', 'vpnc_runtime.py', "if 'default' not in prefixes and not {'0.0.0.0/1', '128.0.0.0/1'} <= prefixes:",
     'if False:', 'test_vpnc_runtime.VpncTests.test_connect_requires_full_tunnel_route_before_readiness'),
    ('withdraw-readiness', 'vpnc_runtime.py', '    READY.unlink(missing_ok=True)\n    # Proxy DNS',
     '    pass\n    # Proxy DNS',
     'test_vpnc_runtime.VpncTests.test_disconnect_removes_readiness_before_standard_script_and_never_removes_firewall'),
    ('resource-ownership', 'vpn_gateway.py', "if labels.get(OWNER) != instance or (nonce and labels.get(LAUNCH) != nonce):",
     'if False:', 'test_vpn_gateway.GatewayTests.test_cleanup_refuses_replaced_resource_identity'),
    ('ike-capability', 'vpn_gateway.py', "'--cap-add=NET_BIND_SERVICE'", "'--cap-add=NET_RAW'",
     'test_vpn_gateway.GatewayTests.test_production_command_is_bounded_and_capability_free'),
    ('internal-only', 'vpn_profiles.py', "if not info.internal_only or info.value_field != 'password' or info.runtime_only or info.derived_from:",
     'if False:', 'test_vpn_gateway.GatewayTests.test_all_credentials_must_be_internal_stored_password_fields'),
    ('no-default-setting', 'vpn_profiles.py', "or set(value) != {'version', 'networks'}", 'or False',
     'test_vpn_gateway.GatewayTests.test_config_rejects_duplicates_defaults_and_oversize'),
    ('stopped-resource-inspection', 'macos_install.py',
     "if result.returncode != 1:\n            raise HostError('Stop all instance resources before updating networks; engine inspection must succeed')",
     "if False:\n            raise HostError('Stop all instance resources before updating networks; engine inspection must succeed')",
     'test_install.InstallTests.test_network_update_requires_all_owned_resources_absent_and_engine_available'),
    ('lock-hardlink', 'host.py', 'or metadata.st_nlink != 1', 'or False',
     'test_instance_lock.InstanceLockTests.test_privileged_update_refuses_links_nonempty_and_public_lock'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Private evidence directory outside the checkout')
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error('Put evidence outside the source checkout')
    os.umask(0o077)
    output.mkdir(parents=True, exist_ok=True)
    originals = {name: (ROOT / name).read_bytes() for _, name, *_ in CASES}
    for key, name, old, _, _ in CASES:
        if originals[name].count(old.encode()) != 1:
            raise AssertionError('Mutation anchor mismatch: ' + key)
    results = []
    with tempfile.TemporaryDirectory(prefix='vpn-mutation-cache-') as cache:
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPYCACHEPREFIX': cache}
        for key, name, old, new, test in CASES:
            path = ROOT / name
            before = originals[name]
            if path.read_bytes() != before or before.count(old.encode()) != 1:
                raise AssertionError('Mutation anchor/source mismatch: ' + key)
            changed = before.replace(old.encode(), new.encode())
            try:
                path.write_bytes(changed)
                result = subprocess.run([sys.executable, '-B', '-m', 'unittest', test], cwd=ROOT,
                                        env=env, capture_output=True, timeout=60)
                log = result.stdout + result.stderr
                (output / (key + '.log')).write_bytes(log)
                caught = result.returncode != 0 and b'FAIL:' in log and b'ERROR:' not in log
                results.append({'mutation': key, 'caughtByAssertion': caught, 'exitCode': result.returncode})
                if not caught:
                    raise AssertionError('Mutation not caught cleanly: ' + key)
            finally:
                if path.read_bytes() != changed:
                    raise RuntimeError('Source changed during mutation; inspect before restoring: ' + name)
                path.write_bytes(before)
                assert path.read_bytes() == before
                (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    assert all((ROOT / name).read_bytes() == value for name, value in originals.items())
    (output / 'restored.json').write_text(json.dumps({name: hashlib.sha256(value).hexdigest()
                                                   for name, value in originals.items()}, indent=2) + '\n')
    print('PASS: %d mutations caught by assertions; source bytes restored' % len(results))


if __name__ == '__main__':
    main()
