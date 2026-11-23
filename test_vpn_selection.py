import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import host
import manage
from networking import NetworkError


def external():
    return {'type': 'external', 'container': 'vpn-example', 'network': 'vpn-net',
            'interface': 'tun0', 'port': 10257, 'readyFile': '/run/vpn/ready', 'dns': ['10.20.0.53']}


def managed():
    return {'type': 'vpnc', 'gateway': 'vpn.example.org', 'group': 'Example', 'dhGroup': 'dh5',
            'dns': ['10.20.0.53'], 'usernameSecret': 'VPN_USERNAME', 'passwordSecret': 'VPN_PASSWORD',
            'groupSecret': 'VPN_GROUP_SECRET', 'totpSecret': 'VPN_TOTP'}


def registration():
    return {'instance': 'example', 'machine': 'secagent', 'port': 10260,
            'networks': {'corp-vpn': external(), 'managed-vpn': managed()}}


class SelectionTests(unittest.TestCase):
    def test_catalog_has_no_default_and_direct_never_uses_a_vpn(self):
        deployment = host.Deployment.from_dict(registration())
        self.assertEqual(deployment.to_dict(), registration())
        direct = deployment.select_network('direct')
        self.assertIsNone(direct.network)
        self.assertIsNone(direct.vpn)
        selected = deployment.select_network('corp-vpn')
        self.assertEqual(selected.network.container, 'vpn-example')
        self.assertEqual(selected.network_name, 'corp-vpn')
        # A selection is per invocation, not remembered by the registration.
        self.assertIsNone(host.Deployment.from_dict(deployment.to_dict()).select_network('direct').network)
        managed_dep = deployment.select_network('managed-vpn')
        self.assertEqual(managed_dep.network.container, 'sp-example-vpn')
        self.assertEqual(managed_dep.vpn['gateway'], 'vpn.example.org')

    def test_serve_requires_explicit_selection_before_side_effects(self):
        data = registration(); data.pop('networks')
        data['network'] = {k: v for k, v in external().items() if k != 'type'}
        with patch.object(host, 'open_instance_lock') as lock:
            with self.assertRaises(host.HostError): host.serve(host.Deployment.from_dict(data))
            lock.assert_not_called()

    def test_unknown_and_unsafe_profiles_refused(self):
        for profile in ({'direct': external()}, {'../oops': external()}, {'bad': {**managed(), 'password': 'literal'}},
                        {'bad': {**managed(), 'group': 'Example\nScript /tmp/evil'}},
                        {'bad': {**managed(), 'dns': ['127.0.0.1']}},
                        {'bad': {**managed(), 'gateway': '-evil'}}, {'bad': {'type': 'unknown'}}):
            with self.subTest(profile=profile), self.assertRaises((host.HostError, NetworkError)):
                host.Deployment.from_dict({**registration(), 'networks': profile})
        deployment = host.Deployment.from_dict(registration())
        for name in ('missing', '', '../bad'):
            with self.subTest(name=name), self.assertRaises((host.HostError, NetworkError)):
                deployment.select_network(name)
        with self.assertRaises(host.HostError):
            host.Deployment.from_dict({**registration(), 'defaultNetwork': 'corp-vpn'})

    def test_totp_mode_requires_seed_and_supported_explicit_value(self):
        for mode in ('append', 'challenge'):
            profile = {**managed(), 'totpMode': mode}
            selected = host.Deployment.from_dict({**registration(), 'networks': {'vpn': profile}}).select_network('vpn')
            self.assertEqual(selected.vpn['totpMode'], mode)
        for mode in ('automatic', None, True, [], 'challenge\nScript /bad'):
            with self.subTest(mode=mode), self.assertRaises(NetworkError):
                host.Deployment.from_dict({**registration(), 'networks': {'vpn': {**managed(), 'totpMode': mode}}})
        profile = {**managed(), 'totpMode': 'challenge'}; del profile['totpSecret']
        with self.assertRaises(NetworkError):
            host.Deployment.from_dict({**registration(), 'networks': {'vpn': profile}})

    def test_external_gateway_cannot_alias_resources_that_stop_owns(self):
        for suffix in ('', '-relay', '-vpn'):
            profile = {**external(), 'container': 'sp-example' + suffix}
            with self.assertRaisesRegex(host.HostError, 'conflicts'):
                host.Deployment.from_dict({**registration(), 'networks': {'bad': profile}})

    def test_legacy_external_registration_requires_explicit_selection(self):
        policy = external(); policy.pop('type')
        dep = host.Deployment.from_dict({'instance': 'example', 'machine': 'secagent', 'port': 10260, 'network': policy})
        self.assertIsNone(dep.select_network('direct').network)
        self.assertEqual(dep.select_network('legacy').network.to_dict(), policy)

    def test_cli_selects_direct_unless_operator_passes_network(self):
        settings = {'instance': 'example', 'bootstrap': '/private/bootstrap.json', 'op': '/opt/op'}
        with patch.object(manage, 'execute') as execute, patch.object(manage, 'load_settings', return_value=settings):
            manage.main(['start'])
            self.assertEqual(execute.call_args.kwargs['network_name'], 'direct')
            manage.main(['start', '--network', 'corp-vpn'])
            self.assertEqual(execute.call_args.kwargs['network_name'], 'corp-vpn')
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                manage.main(['stop', '--network', 'corp-vpn'])

    def test_ready_other_mode_is_not_silently_kept_or_restarted(self):
        settings = {'instance': 'example', 'bootstrap': '/private/bootstrap.json', 'op': '/opt/op'}
        with patch.object(manage, 'selected_client', return_value=Mock()), \
             patch.object(manage, 'current_network', return_value='corp-vpn'), patch.object(manage.os, 'execv') as execute:
            with self.assertRaisesRegex(manage.ClientError, 'stop'):
                manage.execute(settings, 'start')
            with contextlib.redirect_stdout(io.StringIO()):
                manage.execute(settings, 'start', network_name='corp-vpn')
            execute.assert_not_called()

    def test_mode_metadata_must_match_authenticated_boot(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(manage, 'SHARED_ROOT', Path(tmp)):
            shared = Path(tmp) / 'example'; shared.mkdir()
            for filename, value in [('ready.json', {'status': 'ready', 'instance': 'a' * 32}),
                                    ('network-state.json', {'instance': 'b' * 32, 'network': 'corp-vpn'})]:
                path = shared / filename; path.write_text(json.dumps(value)); path.chmod(0o600)
            with self.assertRaises(manage.ClientError):
                manage.current_network({'instance': 'example'})
            (shared / 'network-state.json').write_text(json.dumps({'instance': 'a' * 32, 'network': 'corp-vpn'}))
            self.assertEqual(manage.current_network({'instance': 'example'}), 'corp-vpn')
