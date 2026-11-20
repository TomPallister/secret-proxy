"""Opt-in name-constrained CA: policy, generation, mitmproxy leaves and verifiers.

Everything is offline: temporary directories, loopback TLS and file-based roots.
Platform checks (macOS security, curl backends, Command Line Tools Python) skip
when the tool is absent. Nothing touches a keychain or the trust settings.
"""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import verification
from mitmproxy import certs

import capolicy
import constrainedca
import entry
from secretstore import SecretManifest

ROOT = Path(__file__).parent
SENTINEL = 'secret' + 'ref.invalid'
CLT_PYTHON = '/Library/Developer/CommandLineTools/usr/bin/python3'


def manifest(hosts, chatgpt=False):
    secrets = {'EXAMPLE_TOKEN': {'placements': [{'kind': 'header', 'hosts': hosts, 'name': 'authorization',
                                                  'template': 'Bearer {secret}'}]}}
    if chatgpt:
        secrets['CHATGPT_ACCESS_TOKEN'] = {'runtimeOnly': True, 'placements': [{
            'kind': 'header', 'hosts': ['chatgpt.com'], 'name': 'authorization', 'template': 'Bearer {secret}'}]}
    return {'schemaVersion': 3, 'account': {'vault': 'Example'}, 'secrets': secrets}


def config_dir(tmp, hosts, ca=True, aws=False, chatgpt=False):
    config = Path(tmp) / 'config'
    config.mkdir()
    (config / 'manifest.json').write_text(json.dumps(manifest(hosts, chatgpt)))
    if ca:
        (config / 'ca.json').write_text(json.dumps({'mode': 'name-constrained'}))
    if aws:
        (config / 'aws-okta.json').write_text('{}')  # existence is what selects AWS interception
    return config


def leaf(store, *names):
    sans = [x509.IPAddress(ipaddress.ip_address(n)) if re.fullmatch(r'[0-9.:]+', n) else x509.DNSName(n)
            for n in names]
    return store.get_cert(names[0], sans)


def write_pem(path, *items):
    path.write_bytes(b''.join(item.public_bytes(serialization.Encoding.PEM) for item in items))
    return path


class PolicyTests(unittest.TestCase):
    def test_permitted_domains_cover_exact_and_wildcard_hosts_narrowly(self):
        self.assertEqual(capolicy.permitted_domains(['API.Example.com', '*.example.org', 'svc.*.example.net',
                                                     'a.example.org', SENTINEL]),
                         ['api.example.com', 'example.net', 'example.org', SENTINEL])
        for pattern in ('*.com', 'example.*', 'svc.*.com', 'localhost', 'bad_label.example.com', 'x.*'):
            with self.subTest(pattern=pattern), self.assertRaises(capolicy.CAPolicyError):
                capolicy.permitted_domains([pattern])
        with self.assertRaises(capolicy.CAPolicyError):
            capolicy.permitted_domains([])

    def test_patterns_mirror_every_runtime_interception_host(self):
        # If entry.py starts intercepting a host the constraint omits, leaves
        # for it would be rejected; this guard keeps the two derivations equal.
        cases = [(ROOT / 'examples/manifest.json', False), (ROOT / 'examples/derived-manifest.json', True),
                 (ROOT / 'examples/github-manifest.json', False), (ROOT / 'examples/egress-manifest.json', False)]
        with tempfile.TemporaryDirectory() as tmp:
            wildcard = Path(tmp) / 'manifest.json'
            wildcard.write_text(json.dumps(manifest(['*.example.com', 'svc.*.example.net'], chatgpt=True)))
            cases.append((wildcard, True))
            for path, aws in cases:
                aws_file = Path(tmp) / ('aws.json' if aws else 'missing.json')
                if aws:
                    aws_file.write_text('{}')
                with self.subTest(path=path.name, aws=aws), patch.object(entry.addon, 'SECRETS_FILE', path), \
                        patch.object(entry.addon, 'AWS_OKTA_FILE', aws_file):
                    expected = set(entry._allow_hosts())
                    patterns = capolicy.interception_patterns(SecretManifest.load(path), aws)
                    converted = {entry._AWS_RE if p == capolicy.AWS_PATTERN else entry._host_pattern(p) for p in patterns}
                    self.assertEqual(converted, expected)
                    domains = capolicy.permitted_domains(patterns)
                    for pattern in patterns:
                        self.assertTrue(capolicy.name_permitted(pattern.replace('*', 'x1'), domains), pattern)

    def test_config_is_an_exact_opt_in(self):
        self.assertTrue(capolicy.parse_config(b'{"mode": "name-constrained"}'))
        for bad in (b'', b'{}', b'{"mode": "default"}', b'{"mode": "name-constrained", "x": 1}', b'[1]', b'x' * 5000):
            with self.subTest(bad=bad[:20]), self.assertRaises(capolicy.CAPolicyError):
                capolicy.parse_config(bad)

    def test_plan_is_none_without_opt_in_and_validates_before_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = config_dir(tmp, ['api.example.com'], ca=False)
            self.assertIsNone(constrainedca.plan(config, 'local'))
            (config / 'ca.json').write_text('{"mode": "name-constrained"}')
            self.assertEqual(constrainedca.plan(config, 'local'), ['api.example.com', SENTINEL])
            with self.assertRaises(capolicy.CAPolicyError):
                constrainedca.plan(config, None)
            with self.assertRaises(capolicy.CAPolicyError):
                constrainedca.plan(config, '../other')
            (config / 'aws-okta.json').write_text('{}')
            self.assertIn('amazonaws.com', constrainedca.plan(config, 'local'))

    def test_runtime_refuses_bad_ca_policy_before_reading_the_bootstrap(self):
        import runtime
        with tempfile.TemporaryDirectory() as tmp:
            config = config_dir(tmp, ['*.com'])
            argv = ['runtime.py', '--config-dir', str(config), '--state-dir', str(Path(tmp) / 'state'),
                    '--runtime-dir', str(Path(tmp) / 'run'), '--ca-label', 'local']
            with patch.object(sys, 'argv', argv), patch.object(runtime, 'read_bootstrap',
                                                                side_effect=AssertionError('read credentials')):
                with self.assertRaisesRegex(capolicy.CAPolicyError, 'fixed suffix'):
                    runtime.main()
            self.assertFalse((Path(tmp) / 'state').exists())


class GenerationTests(unittest.TestCase):
    now = datetime.datetime.now(datetime.timezone.utc)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / 'state'
        self.state.mkdir()
        self.domains = capolicy.permitted_domains(['api.example.com', '*.example.org', 'svc.*.example.net', SENTINEL])

    def tearDown(self):
        self.tmp.cleanup()

    def files(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir() if p.is_file()}

    def test_default_mode_leaves_mitmproxy_ca_untouched(self):
        self.assertEqual(constrainedca.ensure(self.state, None, None), 'default')
        self.assertEqual(list(self.state.iterdir()), [])
        certs.CertStore.create_store(self.state, 'mitmproxy', 2048)
        before = self.files()
        self.assertEqual(constrainedca.ensure(self.state, 'local', None), 'default')
        self.assertEqual(self.files(), before)

    def test_default_mode_refuses_a_leftover_constrained_ca(self):
        constrainedca.ensure(self.state, 'local', self.domains)
        with self.assertRaisesRegex(capolicy.CAPolicyError, 'ca.json'):
            constrainedca.ensure(self.state, 'local', None)

    def test_generated_ca_is_critical_constrained_and_mitmproxy_loads_it(self):
        self.assertEqual(constrainedca.ensure(self.state, 'local', self.domains, self.now), 'created')
        for name in self.state.iterdir():
            self.assertEqual(name.stat().st_mode & 0o077, 0, name.name)
        ca = x509.load_pem_x509_certificate((self.state / 'mitmproxy-ca-cert.pem').read_bytes())
        constraint = ca.extensions.get_extension_for_class(x509.NameConstraints)
        self.assertTrue(constraint.critical)
        self.assertEqual(sorted(n.value for n in constraint.value.permitted_subtrees), self.domains)
        self.assertEqual({n.value for n in constraint.value.excluded_subtrees},
                         {ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')})
        self.assertEqual(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
        store = certs.CertStore.from_store(self.state, 'mitmproxy', 2048)
        self.assertEqual(store.default_ca.to_cryptography(), ca)
        der = ca.public_bytes(serialization.Encoding.DER)
        trusted = capolicy.check_trustable(der, 'local')
        self.assertEqual(trusted['domains'], self.domains)
        self.assertEqual(trusted['sha1'], ca.fingerprint(hashes.SHA1()).hex().upper())

    def test_leaves_verify_inside_constraints_and_fail_outside(self):
        constrainedca.ensure(self.state, 'local', self.domains, self.now)
        store = certs.CertStore.from_store(self.state, 'mitmproxy', 2048)
        root = store.default_ca.to_cryptography()
        verifier = verification.PolicyBuilder().store(verification.Store([root])).time(self.now)
        inside = ('api.example.com', 'deep.www.example.org', 'svc.eu-west-1.example.net', SENTINEL)
        outside = ('example.com', 'evil.example', 'api.example.com.evil.example', 'notexample.org')
        for name in inside:
            cert = leaf(store, name).cert.to_cryptography()
            verifier.build_server_verifier(x509.DNSName(name)).verify(cert, [])
        for name in outside:
            cert = leaf(store, name).cert.to_cryptography()
            with self.subTest(name=name), self.assertRaises(verification.VerificationError):
                verifier.build_server_verifier(x509.DNSName(name)).verify(cert, [])
        # An address SAN alongside a permitted name is still refused.
        cert = leaf(store, 'api.example.com', '127.0.0.1').cert.to_cryptography()
        with self.assertRaises(verification.VerificationError):
            verifier.build_server_verifier(x509.DNSName('api.example.com')).verify(cert, [])

    def test_kept_when_unchanged_replaced_when_hosts_change_or_unconstrained(self):
        constrainedca.ensure(self.state, 'local', self.domains, self.now)
        first = self.files()
        self.assertEqual(constrainedca.ensure(self.state, 'local', self.domains, self.now), 'kept')
        self.assertEqual(self.files(), first)
        self.assertEqual(constrainedca.ensure(self.state, 'local', self.domains + ['new.example.com'], self.now), 'replaced')
        self.assertNotEqual(self.files()['mitmproxy-ca.pem'], first['mitmproxy-ca.pem'])
        retired = list((self.state / 'retired').iterdir())
        self.assertEqual(len(retired), 1)
        self.assertEqual((retired[0] / 'mitmproxy-ca.pem').read_bytes(), first['mitmproxy-ca.pem'])
        self.assertEqual(retired[0].stat().st_mode & 0o777, 0o700)
        # A different instance label or an expiring CA is regenerated too.
        self.assertEqual(constrainedca.ensure(self.state, 'other', self.domains, self.now), 'replaced')
        later = self.now + constrainedca.VALIDITY - datetime.timedelta(days=1)
        self.assertEqual(constrainedca.ensure(self.state, 'other', self.domains, later), 'replaced')

    def test_explicit_opt_in_retires_a_default_mitmproxy_ca(self):
        certs.CertStore.create_store(self.state, 'mitmproxy', 2048)
        old = self.files()
        self.assertEqual(constrainedca.ensure(self.state, 'local', self.domains, self.now), 'replaced')
        retired = next((self.state / 'retired').iterdir())
        self.assertEqual((retired / 'mitmproxy-ca.pem').read_bytes(), old['mitmproxy-ca.pem'])
        self.assertEqual(self.files()['mitmproxy-dhparam.pem'], old['mitmproxy-dhparam.pem'])

    def test_partial_or_mismatched_files_are_regenerated(self):
        constrainedca.ensure(self.state, 'local', self.domains, self.now)
        (self.state / 'mitmproxy-ca-cert.pem').unlink()
        self.assertEqual(constrainedca.ensure(self.state, 'local', self.domains, self.now), 'replaced')
        ca = (self.state / 'mitmproxy-ca.pem').read_bytes()
        self.assertTrue(ca.endswith((self.state / 'mitmproxy-ca-cert.pem').read_bytes()))


def variant(**changes):
    """A CA like ours with one property changed, for trust refusal tests."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cn = changes.get('cn', capolicy.common_name('local'))
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().serial_number(1).subject_name(name).issuer_name(name)
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).public_key(key.public_key())
               .add_extension(x509.BasicConstraints(ca=changes.get('ca', True), path_length=None), critical=True))
    permitted = changes.get('permitted', [x509.DNSName('example.com')])
    excluded = changes.get('excluded', [x509.IPAddress(n) for n in constrainedca.EXCLUDED])
    if changes.get('constraints', True):
        builder = builder.add_extension(x509.NameConstraints(permitted_subtrees=permitted or None,
                                                             excluded_subtrees=excluded or None),
                                        critical=changes.get('critical', True))
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


class TrustableTests(unittest.TestCase):
    def test_refuses_anything_but_this_instances_constrained_ca(self):
        capolicy.check_trustable(variant(), 'local')
        for changes in ({'constraints': False}, {'critical': False}, {'cn': 'mitmproxy'}, {'ca': False},
                        {'permitted': [x509.DNSName('com')]}, {'permitted': None, 'excluded': [x509.IPAddress(n) for n in constrainedca.EXCLUDED]},
                        {'permitted': [x509.IPAddress(ipaddress.ip_network('10.0.0.0/8'))]},
                        {'excluded': [x509.IPAddress(ipaddress.ip_network('0.0.0.0/0'))]}, {'excluded': None}):
            with self.subTest(changes=changes), self.assertRaises(capolicy.CAPolicyError):
                capolicy.check_trustable(variant(**changes), 'local')
        with self.assertRaises(capolicy.CAPolicyError):
            capolicy.check_trustable(variant(), 'other')
        with self.assertRaises(capolicy.CAPolicyError):
            capolicy.check_trustable(b'\x30\x03\x02\x01\x01', 'local')

    def test_default_mitmproxy_ca_is_refused(self):
        _, ca = certs.create_ca('mitmproxy', 'mitmproxy', 2048)
        with self.assertRaisesRegex(capolicy.CAPolicyError, 'name constraints|instance'):
            capolicy.check_trustable(ca.public_bytes(serialization.Encoding.DER), 'local')

    @unittest.skipUnless(os.path.exists(CLT_PYTHON), 'Command Line Tools Python is not installed')
    def test_macos_cli_modules_run_on_command_line_tools_python(self):
        der = variant()
        code = ('import sys; sys.path.insert(0, sys.argv[1]); import capolicy, manage, host, client, '
                'macos_install, setup; print(capolicy.check_trustable(bytes.fromhex(sys.argv[2]), "local")["domains"])')
        result = subprocess.run([CLT_PYTHON, '-c', code, str(ROOT), der.hex()], capture_output=True, text=True,
                                timeout=60, env={'PATH': '/usr/bin:/bin', 'HOME': tempfile.gettempdir()})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "['example.com']")


class PlatformVerifierTests(unittest.TestCase):
    """Real platform verifiers with file-based anchors; no keychain changes.

    Each check runs against the constrained CA and, as a positive control, an
    ordinary mitmproxy CA that must accept the very name the constraint rejects.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.stores = {}
        for kind in ('constrained', 'control'):
            state = cls.dir / kind
            state.mkdir()
            if kind == 'constrained':
                constrainedca.ensure(state, 'local', capolicy.permitted_domains(['api.example.com', '*.example.org', SENTINEL]))
            else:
                certs.CertStore.create_store(state, 'mitmproxy', 2048)
            store = certs.CertStore.from_store(state, 'mitmproxy', 2048)
            cls.stores[kind] = (store, write_pem(cls.dir / (kind + '-root.pem'), store.default_ca.to_cryptography()))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def cases(self, names):
        for kind, (store, root) in self.stores.items():
            for name, inside in names:
                yield kind, store, root, name, inside or kind == 'control'

    def leaf_files(self, store, kind, name):
        entry_ = leaf(store, name)
        cert = write_pem(self.dir / (kind + name + '.pem'), entry_.cert.to_cryptography())
        key = self.dir / (kind + name + '.key')
        key.write_bytes(entry_.privatekey.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert, key

    def serve(self, store, kind, name):
        cert, key = self.leaf_files(store, kind, name)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        listener = socket.create_server(('127.0.0.1', 0))
        stop = threading.Event()

        def loop():
            listener.settimeout(0.2)
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except OSError:
                    continue
                try:
                    with context.wrap_socket(connection, server_side=True) as tls:
                        tls.recv(4096)
                        tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                except (OSError, ssl.SSLError):
                    pass
        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        self.addCleanup(lambda: (stop.set(), thread.join(2), listener.close()))
        return listener.getsockname()[1]

    def test_python_openssl_handshake(self):
        for kind, store, root, name, ok in self.cases((('api.example.com', True), ('a.example.org', True),
                                                       ('evil.example', False))):
            port = self.serve(store, kind, name)
            context = ssl.create_default_context(cafile=str(root))
            with self.subTest(kind=kind, name=name):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw, \
                            context.wrap_socket(raw, server_hostname=name):
                        result = True
                except ssl.SSLCertVerificationError:
                    result = False
                self.assertEqual(result, ok)

    @unittest.skipUnless(sys.platform == 'darwin' and os.path.exists('/usr/bin/security'), 'macOS only')
    def test_macos_trust_evaluation_with_a_file_anchor(self):
        for kind, store, root, name, ok in self.cases((('api.example.com', True), ('deep.www.example.org', True),
                                                       (SENTINEL, True), ('evil.example', False),
                                                       ('example.com', False))):
            cert, _ = self.leaf_files(store, kind, name)
            # -N: no keychain search list; -L: no network; -r: anchor from a file.
            result = subprocess.run(['/usr/bin/security', 'verify-cert', '-N', '-L', '-q', '-p', 'ssl', '-n', name,
                                     '-c', str(cert), '-r', str(root)], capture_output=True, timeout=30)
            with self.subTest(kind=kind, name=name):
                self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin' and shutil.which('curl', path='/usr/bin'), 'macOS curl only')
    def test_macos_curl_secure_transport_and_libressl(self):
        for backend in ('secure-transport', 'openssl'):
            for kind, store, root, name, ok in self.cases((('api.example.com', True), ('evil.example', False))):
                port = self.serve(store, kind, name)
                result = subprocess.run(['/usr/bin/curl', '--silent', '--max-time', '10', '--noproxy', '*',
                                         '--cacert', str(root), '--resolve', f'{name}:{port}:127.0.0.1',
                                         f'https://{name}:{port}/'], capture_output=True, timeout=30,
                                        env={'PATH': '/usr/bin:/bin', 'CURL_SSL_BACKEND': backend,
                                             'HOME': self.tmp.name})
                with self.subTest(backend=backend, kind=kind, name=name):
                    self.assertEqual(result.returncode == 0, ok, result.returncode)
                    if ok:
                        self.assertEqual(result.stdout, b'ok')


if __name__ == '__main__':
    unittest.main()
