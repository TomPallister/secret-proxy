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

    def test_separate_challenge_keeps_password_and_uses_fixed_helper(self):
        values = {'usernameSecret': 'fixture-user', 'passwordSecret': 'fixture-password',
                  'groupSecret': 'fixture-group', 'totpSecret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'}
        text = vpn.configuration({**managed(), 'totpMode': 'challenge'}, values, '192.0.2.8', now=59)
        self.assertIn('Xauth password fixture-password\n', text)
        self.assertNotIn('fixture-password287082', text)
        self.assertIn('Password helper /opt/secret-proxy/vpnc_password_helper.py\n', text)
        self.assertNotIn(values['totpSecret'], text)

    def test_challenge_cli_allows_helper_but_not_stdin_or_arbitrary_commands(self):
        from pathlib import Path
        config = Path('/run/vpn/vpnc.conf')
        self.assertIn('--non-inter', vpn.vpnc_command(managed(), config))
        argv = vpn.vpnc_command({**managed(), 'totpMode': 'challenge'}, config)
        self.assertNotIn('--non-inter', argv)
        self.assertEqual(argv, ['/usr/sbin/vpnc', '--no-detach', '--pid-file', '/run/vpn/vpnc.pid', str(config)])

    def test_challenge_is_private_prompt_bound_and_single_use(self):
        import tempfile
        from pathlib import Path
        values = {'usernameSecret': 'fixture-user', 'totpSecret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'}
        for kind in ('Password', 'Passcode', 'Answer'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / 'challenge.json'
                with patch.object(vpn.time, 'monotonic', return_value=100), patch.object(vpn.time, 'time', return_value=59):
                    vpn.write_challenge(values, '192.0.2.8', state)
                    self.assertEqual(state.stat().st_mode & 0o777, 0o600)
                    result = vpn.answer_challenge(kind + ' for VPN fixture-user@192.0.2.8: ', state)
                    self.assertEqual(result, '287082')
                    self.assertFalse(state.exists())
                    with self.assertRaises((OSError, ValueError)):
                        vpn.answer_challenge(kind + ' for VPN fixture-user@192.0.2.8: ', state)

    def test_challenge_rejects_unexpected_identity_prompt_and_expiry(self):
        import tempfile
        from pathlib import Path
        values = {'usernameSecret': 'fixture-user', 'totpSecret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'}
        for prompt, clock in [('Password for VPN other@192.0.2.8: ', 101),
                              ('Password for VPN fixture-user@192.0.2.9: ', 101),
                              ('Unexpected challenge', 101),
                              ('Password for VPN fixture-user@192.0.2.8: \n', 101),
                              ('Password for VPN fixture-user@192.0.2.8: ', 190)]:
            with self.subTest(prompt=prompt, clock=clock), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / 'challenge.json'
                with patch.object(vpn.time, 'monotonic', return_value=100):
                    vpn.write_challenge(values, '192.0.2.8', state)
                with patch.object(vpn.time, 'monotonic', return_value=clock), self.assertRaises(ValueError):
                    vpn.answer_challenge(prompt, state)
                self.assertFalse(state.exists())
                vpn.clear_challenge(state)
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_concurrent_challenges_issue_only_one_code(self):
        import concurrent.futures
        import tempfile
        import threading
        from pathlib import Path
        values = {'usernameSecret': 'fixture-user', 'totpSecret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'}
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'challenge.json'
            vpn.write_challenge(values, '192.0.2.8', state)
            entered, release = threading.Event(), threading.Event()
            def held_totp(*args):
                if not entered.is_set():
                    entered.set()
                    if not release.wait(5): raise AssertionError('Test synchronization timed out')
                return '287082'
            with patch.object(vpn, 'totp', side_effect=held_totp), concurrent.futures.ThreadPoolExecutor(2) as pool:
                first = pool.submit(vpn.answer_challenge, 'Password for VPN fixture-user@192.0.2.8: ', state)
                self.assertTrue(entered.wait(2))
                try:
                    second = pool.submit(vpn.answer_challenge, 'Password for VPN fixture-user@192.0.2.8: ', state)
                    with self.assertRaises(OSError): second.result(timeout=2)
                finally:
                    release.set()
                self.assertEqual(first.result(timeout=2), '287082')
            vpn.clear_challenge(state)

    def test_challenge_state_cannot_overwrite_existing_file_or_symlink(self):
        import tempfile
        from pathlib import Path
        values = {'usernameSecret': 'fixture-user', 'totpSecret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'}
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / 'victim'; victim.write_text('unchanged')
            state = Path(tmp) / 'challenge.json'; state.symlink_to(victim)
            with self.assertRaises(OSError): vpn.write_challenge(values, '192.0.2.8', state)
            self.assertEqual(victim.read_text(), 'unchanged')

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
