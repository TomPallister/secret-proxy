"""Compatibility contracts for the packaged client and its route-script ABI."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import vpnc_runtime as vpn
from test_vpn_selection import managed


class CompatibilityTests(unittest.TestCase):
    def test_client_uses_ephemeral_source_port_in_every_auth_mode(self):
        values = {'usernameSecret': 'fixture-user', 'passwordSecret': 'fixture-pass',
                  'groupSecret': 'fixture-group', 'totpSecret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'}
        for mode in (None, 'append', 'challenge'):
            profile = managed()
            if mode is not None:
                profile.update(totpMode=mode, totpSecret='FIXTURE_TOTP')
            with self.subTest(mode=mode):
                text = vpn.configuration(profile, values, '192.0.2.8', 59)
                self.assertEqual([line for line in text.splitlines() if line.startswith('Local Port')],
                                 ['Local Port 0'])
                self.assertIn('NAT Traversal Mode natt\n', text)
                self.assertNotIn('--local-port', vpn.vpnc_command(profile, Path('/run/vpn/vpnc.conf')))

    def test_client_environment_uses_controller_identity_and_excludes_ambient_secrets(self):
        environment = getattr(vpn, 'client_environment', None)
        self.assertTrue(callable(environment), 'The controller must supply an explicit stable hook identity')
        with patch.object(vpn.os, 'getpid', return_value=2468), patch.dict(os.environ, {
                'VPNPID': '9999', 'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-not-a-capability',
                'HTTPS_PROXY': 'https://fixture.invalid'}):
            self.assertEqual(environment(), {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                             'HOME': str(vpn.READY.parent), 'VPNPID': '2468'})
            self.assertEqual(environment()['VPNPID'], environment()['VPNPID'])

    def test_hook_rejects_missing_or_unsafe_identity_without_running_route_script(self):
        for identity in (None, '', '0', '-1', '01', '12\n', ' 12', '１２', '../route',
                         '2147483648', '1'*10000, 42):
            with self.subTest(identity=repr(identity)[:40]), tempfile.TemporaryDirectory() as tmp:
                ready = Path(tmp) / 'ready'; ready.touch()
                env = {'reason': 'pre-init'}
                if identity is not None: env['VPNPID'] = identity
                with patch.object(vpn, 'READY', ready), patch.object(vpn.subprocess, 'run') as run:
                    with self.assertRaises(ValueError): vpn.hook(env)
                    run.assert_not_called()
                    self.assertFalse(ready.exists())
                    self.assertEqual(vpn.hook_stage(), 'hook-rejected')

    def test_every_hook_forwards_same_identity_despite_different_python_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / 'ready'
            observed = []
            def run(argv, **kwargs):
                if argv == ['/usr/share/vpnc-scripts/vpnc-script']:
                    observed.append(kwargs['env']['VPNPID'])
                    self.assertNotIn('INTERNAL_IP4_DNS', kwargs['env'])
                    self.assertNotIn('INTERNAL_IP6_DNS', kwargs['env'])
                    self.assertFalse(ready.exists(), 'Readiness must be withdrawn before each hook')
                data = [{'dst': 'default', 'dev': 'tun0'}]
                return subprocess.CompletedProcess(argv, 0, json.dumps(data).encode(), b'')
            with patch.object(vpn, 'READY', ready), patch.object(vpn.subprocess, 'run', side_effect=run):
                for index, reason in enumerate(('pre-init', 'connect', 'attempt-reconnect', 'reconnect', 'disconnect')):
                    env = {'reason': reason, 'VPNPID': '2468', 'INTERNAL_IP4_DNS': '192.0.2.53',
                           'INTERNAL_IP6_DNS': '2001:db8::53'}
                    if reason != 'pre-init': env['TUNDEV'] = 'tun0'
                    original = dict(env)
                    with patch.object(vpn.os, 'getpid', return_value=9000+index):
                        vpn.hook(env)
                    self.assertEqual(env, original, 'Hook must not mutate its caller environment')
                    self.assertEqual(ready.exists(), reason in ('connect', 'reconnect'))
            self.assertEqual(observed, ['2468']*5)
