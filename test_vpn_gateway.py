import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import host
from networking import NetworkError
from test_vpn_selection import registration, managed
import vpn_gateway as vpn
import vpn_profiles
from secretstore import SecretManifest


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.dep = host.Deployment.from_dict(registration()).select_network('managed-vpn')
        self.calls = []
        self.container = False
        self.owner = self.dep.instance
        self.identifier = 'b' * 64
        self.ready = True

    def engine(self, *args, **kwargs):
        self.calls.append(args)
        status, data = 0, b''
        if args[:2] == ('container', 'exists'):
            status = 0 if self.container else 1
        elif args[:2] == ('network', 'exists'):
            status = 1
        elif args[:2] == ('network', 'inspect'):
            data = json.dumps([{'labels': {vpn.OWNER: self.owner}, 'internal': False, 'driver': 'bridge'}]).encode()
        elif args[:2] == ('container', 'inspect'):
            if '--format' not in args:
                data = json.dumps([{'Id': self.identifier, 'Config': {'Labels': {vpn.OWNER: self.owner, vpn.LAUNCH: 'a' * 32}}}]).encode()
            elif args[-1] == '{{.Id}}': data = self.identifier.encode()
            elif args[-1] == '{{.State.Running}}': data = b'true'
            elif args[-1] == '{{json .NetworkSettings.Networks}}':
                data = json.dumps({self.dep.network.network: {'IPAddress': '10.89.0.2'}}).encode()
            else: raise AssertionError(args)
        elif args[:2] == ('rm', '-f'):
            self.assertEqual(args[2], self.identifier)
            self.container = False
        elif args[0] == 'exec' and 'ip' in args: data = b'[{"flags":["UP"]}]'
        elif args[0] == 'exec': status = 0 if self.ready else 1
        elif args[:2] != ('network', 'create'): raise AssertionError(args)
        return subprocess.CompletedProcess(args, status, data, b'')

    def launch(self, *a, **kw):
        self.container = True
        self.child = Mock()
        self.child.poll.return_value = None
        return self.child

    def gateway(self):
        return vpn.ManagedGateway(self.dep, 'sha256:' + 'd' * 64,
            {'op_token': 'synthetic-service-capability', 'proxy_token': 'f'*48, 'login_vault': 'NotNeeded'},
            self.engine, lambda args: ['fixture-podman', *args], {'HOME': '/fixture'})

    def test_production_command_is_bounded_and_capability_free(self):
        command = vpn.command(self.dep, 'sha256:' + 'd' * 64, 'a' * 32)
        for value in ('--read-only', '--security-opt=no-new-privileges', '--cap-drop=ALL',
                      '--cap-add=NET_BIND_SERVICE', '--device=/dev/net/tun'):
            self.assertIn(value, command)
        for value in ('--privileged', '--publish', '--env', '--pid=host', '--network=host'):
            self.assertNotIn(value, command)
        self.assertEqual(command[-1], 'managed-vpn')
        with self.assertRaises(NetworkError): vpn.command(self.dep, 'latest', 'a'*32)

    def test_launch_checks_owned_identity_and_cleans_only_that_id(self):
        with patch.object(vpn.secrets, 'token_hex', return_value='a'*32), patch.object(vpn.subprocess, 'Popen', side_effect=self.launch) as launch:
            with self.gateway() as gateway:
                self.assertEqual(gateway.identifier, self.identifier)
                payload = json.loads(self.child.stdin.write.call_args.args[0])
                self.assertEqual(payload, {'op_token': 'synthetic-service-capability', 'proxy_token': '0'*48})
                self.assertNotIn('synthetic-service-capability', repr(launch.call_args.args))
            self.child.terminate.assert_called_once()
            self.assertIn(('rm', '-f', self.identifier), self.calls)
            self.assertFalse(any('direct' in call for call in self.calls))

    def test_existing_or_unowned_resources_are_never_taken_over(self):
        for container, owner in ((True, self.dep.instance), (False, 'other-instance')):
            self.container, self.owner = container, owner
            with self.subTest(container=container), patch.object(vpn.subprocess, 'Popen') as launch:
                with self.assertRaises(NetworkError):
                    with self.gateway(): pass
                launch.assert_not_called()
                self.assertFalse(any(call[:2] == ('rm', '-f') for call in self.calls))

    def test_failed_readiness_never_returns_gateway_or_falls_back(self):
        self.ready = False
        with patch.object(vpn.secrets, 'token_hex', return_value='a'*32), patch.object(vpn.subprocess, 'Popen', side_effect=self.launch), \
             patch.object(vpn.time, 'monotonic', side_effect=[0, 1, 241]), patch.object(vpn.time, 'sleep'):
            with self.assertRaisesRegex(NetworkError, 'no direct fallback'):
                with self.gateway(): self.fail('Not ready')
        self.assertIn(('rm', '-f', self.identifier), self.calls)

    def test_cleanup_refuses_replaced_resource_identity(self):
        with patch.object(vpn.secrets, 'token_hex', return_value='a'*32), patch.object(vpn.subprocess, 'Popen', side_effect=self.launch):
            gateway = self.gateway(); gateway.__enter__()
            self.owner = 'other-instance'
            with self.assertRaises(NetworkError): gateway.close()
            self.assertFalse(any(call[:2] == ('rm', '-f') for call in self.calls))
            self.child.terminate.assert_called_once()

    def test_all_credentials_must_be_internal_stored_password_fields(self):
        profile = managed()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'manifest.json'
            names = [profile[key] for key in ('usernameSecret', 'passwordSecret', 'groupSecret', 'totpSecret')]
            value = {'schemaVersion': 3, 'account': {'vault': 'Fixture'},
                     'secrets': {name: {'internalOnly': True} for name in names}}
            path.write_text(json.dumps(value))
            vpn_profiles.validate_secrets({'fixture': profile}, SecretManifest.load(path))
            value['secrets'].pop(names[0]); path.write_text(json.dumps(value))
            with self.assertRaises(NetworkError): vpn_profiles.validate_secrets({'fixture': profile}, SecretManifest.load(path))
            value['secrets'][names[0]] = {'placements': [{'kind': 'header', 'hosts': ['api.example.org'], 'name': 'x-test', 'template': '{secret}'}]}
            path.write_text(json.dumps(value))
            with self.assertRaises(NetworkError): vpn_profiles.validate_secrets({'fixture': profile}, SecretManifest.load(path))

    def test_config_rejects_duplicates_defaults_and_oversize(self):
        valid = json.dumps({'version': 1, 'networks': {'fixture': managed()}})
        self.assertIn('fixture', vpn_profiles.load_networks(valid))
        for raw in ('{"version":1,"version":1,"networks":{}}',
                    '{"version":1,"networks":{},"default":"fixture"}',
                    '{"version":true,"networks":{}}', ' '*32769):
            with self.subTest(raw=raw[:80]), self.assertRaises(NetworkError): vpn_profiles.load_networks(raw)
