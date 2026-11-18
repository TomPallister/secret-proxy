import json
import subprocess
import struct
import unittest
from unittest.mock import Mock, patch
from pathlib import Path
import tempfile

from host import Deployment, HostError, container_command, stop_instance
from runtime import require_interface, wait_serving

from networking import NetworkPolicy, NetworkError, resolve_gateway, check_gateway, relay_command


class NetworkTests(unittest.TestCase):
    def policy(self, **changes):
        return NetworkPolicy.from_dict({'container': 'vpn-gateway', 'network': 'vpn-egress',
            'interface': 'tun0', 'port': 10257, 'readyFile': '/run/vpn/ready', 'dns': ['127.0.0.53'], **changes})

    def engine(self, *args, **kwargs):
        if args[:2] == ('container', 'inspect'):
            field = args[args.index('--format') + 1]
            value = {'{{.Id}}': 'a' * 64, '{{.State.Running}}': 'true',
                     '{{json .NetworkSettings.Networks}}': json.dumps({'vpn-egress': {'IPAddress': '10.89.0.2'}})}[field]
            return subprocess.CompletedProcess(args, 0, value.encode(), b'')
        if 'ip' in args:
            return subprocess.CompletedProcess(args, 0, b'[{"flags":["UP"]}]', b'')
        return subprocess.CompletedProcess(args, 0, b'', b'')

    def test_validation_and_round_trip(self):
        policy = self.policy()
        self.assertEqual(NetworkPolicy.from_dict(policy.to_dict()), policy)
        for change in ({'container': '--bad'}, {'network': '../bad'}, {'interface': '../lo'},
                       {'readyFile': '/run/../etc/secret'}, {'dns': ['example.com']}, {'port': True},
                       {'port': 10256}, {'extra': 'bad'}, {'dns': []}):
            with self.subTest(change=change), self.assertRaises(NetworkError):
                self.policy(**change)

    def test_pin_identity_and_address_without_mutating_gateway(self):
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            return self.engine(*args, **kwargs)
        gateway = resolve_gateway(self.policy(), run)
        self.assertEqual(gateway.container_id, 'a' * 64)
        self.assertEqual(gateway.address, '10.89.0.2')
        self.assertTrue(all(c[0] in ('container', 'exec') for c in calls))
        self.assertTrue(all('rm' not in c and 'stop' not in c and 'connect' not in c for c in calls))
        check_gateway(self.policy(), gateway, run)

    def test_down_gateway_or_interface_fails_closed(self):
        for failure in ('inspect', 'ready', 'interface'):
            def run(*args, **kwargs):
                if (failure == 'inspect' and args[0] == 'container'
                    or failure == 'ready' and 'test' in args
                    or failure == 'interface' and 'ip' in args):
                    return subprocess.CompletedProcess(args, 1, b'', b'')
                return self.engine(*args, **kwargs)
            with self.subTest(failure=failure), self.assertRaises(NetworkError):
                resolve_gateway(self.policy(), run)

    def test_namespace_join_cannot_publish_or_fall_back_to_direct(self):
        policy = self.policy()
        deployment = Deployment.from_dict({'instance': 'example', 'machine': 'secagent', 'port': 10260,
                                          'network': policy.to_dict()})
        self.assertEqual(Deployment.from_dict(deployment.to_dict()), deployment)
        with self.assertRaises(HostError):
            container_command(deployment, 'sha256:' + 'b' * 64)
        gateway = resolve_gateway(policy, self.engine)
        cmd = container_command(deployment, 'sha256:' + 'b' * 64, gateway)
        self.assertNotIn('--publish', cmd)
        self.assertIn('container:' + 'a' * 64, cmd)
        self.assertEqual(cmd[-4:], ['--port', '10257', '--required-interface', 'tun0'])
        self.assertTrue(any(arg.endswith('/resolv.conf:/etc/resolv.conf:ro') for arg in cmd))

    def test_runtime_refuses_down_interface_and_stops_after_loss(self):
        with patch('runtime.fcntl.ioctl', return_value=struct.pack('16sH', b'tun0', 0x1003)):
            require_interface('tun0')
        with patch('runtime.fcntl.ioctl', return_value=struct.pack('16sH', b'tun0', 0x1002)), self.assertRaises(ValueError):
            require_interface('tun0')
        with patch('runtime.fcntl.ioctl', side_effect=OSError('missing')), self.assertRaises(ValueError):
            require_interface('tun0')
        with self.assertRaises(ValueError):
            require_interface('../lo')
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired('fixture', 1)
        with patch('runtime.require_interface', side_effect=[None, ValueError('down')]), self.assertRaises(ValueError):
            wait_serving(child, 'tun0')
        child.wait.assert_called_once_with(timeout=1)

    def test_explicit_stop_never_stops_external_gateway(self):
        deployment = Deployment.from_dict({'instance': 'example', 'machine': 'secagent', 'port': 10260,
                                          'network': self.policy().to_dict()})
        calls = []
        def engine(_deployment, *args, **kwargs):
            calls.append(args)
            output = b'b' * 64 if args[:2] == ('container', 'inspect') else b''
            return subprocess.CompletedProcess(args, 0, output, b'')
        with tempfile.TemporaryDirectory() as tmp, patch('host.SHARED_ROOT', Path(tmp)), patch('host.engine', side_effect=engine):
            deployment.shared.mkdir()
            (deployment.shared / 'ready.json').touch()
            stop_instance(deployment)
            self.assertFalse((deployment.shared / 'ready.json').exists())
        self.assertNotIn(self.policy().container, [arg for call in calls for arg in call])
        self.assertEqual([call[2] for call in calls if call[:2] == ('container', 'exists')],
                         ['sp-example', 'sp-example-relay'])
        self.assertEqual([call for call in calls if call[:2] == ('rm', '-f')],
                         [('rm', '-f', 'b' * 64)] * 2)

    def test_relay_has_no_capability_or_private_mount_and_uses_pinned_ip(self):
        gateway = resolve_gateway(self.policy(), self.engine)
        args = relay_command(self.policy(), gateway, 'sp-example-relay', 10260, 'sha256:' + 'b' * 64)
        self.assertIn('127.0.0.1:10260:10256', args)
        self.assertIn('TCP:10.89.0.2:10257', args)
        self.assertIn('--cap-drop=ALL', args)
        self.assertNotIn('--volume', args)
        self.assertNotIn('--env', args)
        self.assertNotIn('vpn-gateway', args)
