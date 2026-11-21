import unittest
from unittest.mock import patch

import vpnc_runtime as vpn
from test_vpn_selection import managed


class VpncTests(unittest.TestCase):
    def test_totp_rfc_vector_and_config_never_exposes_seed(self):
        seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        self.assertEqual(vpn.totp(seed, 59), '287082')
        import base64
        unpadded = base64.b32encode(b'1234567890123').decode()
        self.assertEqual(vpn.totp(unpadded.rstrip('='), 59), vpn.totp(unpadded, 59))
        values = {'usernameSecret': 'fixture-user', 'passwordSecret': 'fixture-password',
                  'groupSecret': 'fixture-group-key', 'totpSecret': seed}
        text = vpn.configuration(managed(), values, '192.0.2.8', now=59)
        self.assertIn('Xauth password fixture-password287082\n', text)
        self.assertIn('IPSec gateway 192.0.2.8\n', text)
        self.assertNotIn(seed, text)
        self.assertIn('Interface name tun0\n', text)
        for bad in ('bad\nScript /tmp/evil', 'bad\r', 'bad\x00', ''):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                vpn.configuration(managed(), {**values, 'passwordSecret': bad}, '192.0.2.8', now=59)

    def test_kill_switch_allows_tunnel_and_ike_not_direct_tcp_or_ipv6(self):
        rules = vpn.firewall('192.0.2.8', '10.89.0.0/24')
        self.assertIn('policy drop', rules)
        self.assertIn('oifname "tun0" accept', rules)
        self.assertIn('udp dport { 500, 4500 }', rules)
        self.assertIn('ip daddr 192.0.2.8', rules)
        self.assertIn('tcp sport 10257 ct state established', rules)
        self.assertNotIn('ct state established,related accept', rules)
        self.assertNotIn('tcp dport 443', rules)
        self.assertNotIn('ip6', rules)
        for bad in ('192.0.2.8; accept', '::1', '127.0.0.1'):
            with self.assertRaises((ValueError, vpn.NetworkError)):
                vpn.firewall(bad, '10.89.0.0/24')

    def test_disconnect_removes_readiness_before_standard_script_and_never_removes_firewall(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / 'ready'; ready.touch()
            def run(args, **kwargs):
                self.assertFalse(ready.exists())
                self.assertEqual(args, ['/usr/share/vpnc-scripts/vpnc-script'])
                self.assertNotIn('INTERNAL_IP4_DNS', kwargs['env'])
            with patch.object(vpn, 'READY', ready), patch.object(vpn.subprocess, 'run', side_effect=run):
                vpn.hook({'reason': 'disconnect', 'TUNDEV': 'tun0', 'INTERNAL_IP4_DNS': '10.20.0.53'})
            self.assertFalse(ready.exists())

    def test_connect_requires_full_tunnel_route_before_readiness(self):
        import subprocess
        import tempfile
        from pathlib import Path
        import json
        for dev, prefixes, permitted in (('eth0', ['default'], False), ('tun0', ['default'], True),
                                         ('tun0', ['0.0.0.0/1', '128.0.0.0/1'], True),
                                         ('tun0', ['1.1.1.1/32'], False)):
            with self.subTest(dev=dev, prefixes=prefixes), tempfile.TemporaryDirectory() as tmp:
                ready = Path(tmp) / 'ready'
                def run(args, **kwargs):
                    data = [{'dev': dev, 'dst': prefix} for prefix in prefixes] if args[-1] == 'show' else [{'dev': dev}]
                    return subprocess.CompletedProcess(args, 0, json.dumps(data).encode(), b'')
                with patch.object(vpn, 'READY', ready), patch.object(vpn.subprocess, 'run', side_effect=run):
                    if permitted:
                        vpn.hook({'reason': 'connect', 'TUNDEV': 'tun0'})
                    else:
                        with self.assertRaises(ValueError): vpn.hook({'reason': 'connect', 'TUNDEV': 'tun0'})
                self.assertEqual(ready.exists(), permitted)
