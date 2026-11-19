"""Real mitmdump wiring for egress enforcement (#4, #5).

Starts the actual proxy entrypoint against a local fixture upstream. Only the
resolver is faked (scripted, with a rebinding answer) and the fixture upstream's
exact loopback address is permitted; everything else is the shipped hook code.
Offline: no vault, vendor or external network is contacted.
"""
import datetime
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent

FIXTURE = '''
import json
from pathlib import Path
import egress
import entry

STATE = Path(__file__).parent
_real = egress.address_refusal

def address_refusal(text, allowed=()):
    # Permit only the fixture upstream's exact address; all other rules stay.
    return None if text == "127.0.0.1" else _real(text, allowed)

egress.address_refusal = address_refusal
ANSWERS = {
    "intercepted.example.test": [["127.0.0.1"]],
    "allowed.example.test": [["127.0.0.1"]],
    "rebind.example.test": [["127.0.0.1"], ["169.254.169.254"]],
    "private.example.test": [["10.9.8.7"]],
}

def resolver(host, port):
    calls = STATE / "calls.json"
    log = json.loads(calls.read_text()) if calls.exists() else []
    log.append(host)
    calls.write_text(json.dumps(log))
    queue = ANSWERS.get(host)
    if not queue:
        raise OSError("no such host")
    return queue.pop(0) if len(queue) > 1 else queue[0]

entry._resolver = resolver
from entry import (load, http_connect, requestheaders, request, responseheaders,
                   server_connect, server_connected, server_connect_error,
                   server_disconnected, client_disconnected)
'''


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    peers = set()
    requests = []

    def do_GET(self):
        type(self).peers.add(self.client_address)
        type(self).requests.append(self.path)
        body = b"upstream-ok"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def read_response(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(rest) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        rest += chunk
    return status, rest[:length]


class WireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.root = root
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.upstream_port = cls.upstream.server_address[1]
        cls.tls_upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*cls.leaf(root))
        cls.tls_upstream.socket = context.wrap_socket(cls.tls_upstream.socket, server_side=True)
        threading.Thread(target=cls.tls_upstream.serve_forever, daemon=True).start()
        cls.tls_port = cls.tls_upstream.server_address[1]
        (root / "manifest.json").write_text(json.dumps({
            "schemaVersion": 3, "account": {"vault": "Fixture"},
            "egress": {"mode": "allowlist", "deny": ["denied.example.test"],
                       "allow": ["allowed.example.test", "rebind.example.test",
                                 "private.example.test"]},
            "secrets": {"API_KEY": {"placements": [{
                "kind": "header", "hosts": ["intercepted.example.test"], "name": "x-api-key",
                "template": "{secret}"}]}},
        }))
        (root / "fixture_entry.py").write_text(FIXTURE)
        cls.port = free_port()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root),
            "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1",
            "SECRET_PROXY_CONFIG_DIR": str(root),
            "SECRET_PROXY_SECRETS_FILE": str(root / "manifest.json"),
            "OP_SERVICE_ACCOUNT_TOKEN": "offline-fixture-only",
        }
        command = [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()",
                   "--listen-host", "127.0.0.1", "--listen-port", str(cls.port),
                   "--set", f"confdir={root / 'ca'}", "--set", "flow_detail=0",
                   "--set", "termlog_verbosity=error", "--set", "connection_strategy=lazy",
                   "--set", "upstream_cert=false",
                   "--set", f"ssl_verify_upstream_trusted_ca={root / 'upstream.pem'}",
                   "-s", str(root / "fixture_entry.py")]
        cls.log = (root / "proxy.log").open("wb")
        cls.child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                     stdout=cls.log, stderr=cls.log)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if cls.child.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        cls.tearDownClass()
        raise AssertionError("proxy did not start: " + (root / "proxy.log").read_text())

    @staticmethod
    def leaf(root):
        """Self-signed upstream certificate for the host NAME only (no IP SAN)."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intercepted.example.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("intercepted.example.test")]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(key, hashes.SHA256()))
        (root / "upstream.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / "upstream.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return str(root / "upstream.pem"), str(root / "upstream.key")

    @classmethod
    def tearDownClass(cls):
        if cls.child.poll() is None:
            cls.child.terminate()
            try:
                cls.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.child.kill()
                cls.child.wait()
        cls.log.close()
        for server in (cls.upstream, cls.tls_upstream):
            server.shutdown()
            server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        Upstream.peers.clear()
        Upstream.requests.clear()

    def calls(self):
        path = self.root / "calls.json"
        return json.loads(path.read_text()) if path.exists() else []

    def proxy(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=10)

    def connect(self, host, port=None):
        sock = self.proxy()
        target = f"{host}:{port or self.upstream_port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        return sock, read_response(sock)

    def test_connect_refusals_name_the_rule_and_reach_nothing(self):
        for host, rule in [("169.254.169.254", "metadata-address"), ("metadata.google.internal", "metadata-host"),
                           ("127.0.0.2", "loopback-address"), ("denied.example.test", "egress-deny"),
                           ("unlisted.example.test", "egress-allowlist"), ("private.example.test", "private-address")]:
            with self.subTest(host=host):
                sock, (status, body) = self.connect(host)
                sock.close()
                self.assertEqual(status, 403)
                self.assertEqual(json.loads(body), {"error": "secret_proxy_egress_refused", "rule": rule})
        self.assertEqual(Upstream.requests, [])
        self.assertNotIn("unlisted.example.test", self.calls())
        self.assertNotIn("denied.example.test", self.calls())

    def test_rebinding_after_connect_uses_the_checked_address(self):
        before = self.calls().count("rebind.example.test")
        sock, (status, _) = self.connect("rebind.example.test")
        with sock:
            self.assertEqual(status, 200)
            # Passthrough tunnel: the upstream connection opens now (lazy). The
            # fake DNS would answer metadata if the proxy resolved again.
            sock.sendall(b"GET /tunnel HTTP/1.1\r\nHost: rebind.example.test\r\n\r\n")
            self.assertEqual(read_response(sock), (200, b"upstream-ok"))
        self.assertEqual(self.calls().count("rebind.example.test"), before + 1)
        self.assertEqual(Upstream.requests, ["/tunnel"])
        # A fresh CONNECT resolves again and now sees the rebound answer.
        sock, (status, body) = self.connect("rebind.example.test")
        sock.close()
        self.assertEqual((status, json.loads(body)["rule"]), (403, "metadata-address"))

    def test_plain_http_is_checked_and_reuses_the_upstream_connection(self):
        with self.proxy() as sock:
            for path in ("/one", "/two"):
                sock.sendall(f"GET http://allowed.example.test:{self.upstream_port}{path} HTTP/1.1\r\n"
                             f"Host: allowed.example.test:{self.upstream_port}\r\n\r\n".encode())
                self.assertEqual(read_response(sock), (200, b"upstream-ok"))
            sock.sendall(b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
            status, body = read_response(sock)
        self.assertEqual((status, json.loads(body)["rule"]), (403, "metadata-address"))
        self.assertEqual(Upstream.requests, ["/one", "/two"])
        # The host name was restored after connecting, so mitmproxy reused it.
        self.assertEqual(len(Upstream.peers), 1)
        with self.proxy() as sock:
            sock.sendall(b"GET http://unlisted.example.test/ HTTP/1.1\r\nHost: unlisted.example.test\r\n\r\n")
            status, body = read_response(sock)
        self.assertEqual((status, json.loads(body)["rule"]), (403, "egress-allowlist"))

    def test_intercepted_tls_verifies_the_name_and_reuses_the_pinned_connection(self):
        sock, (status, _) = self.connect("intercepted.example.test", self.tls_port)
        self.assertEqual(status, 200)
        context = ssl.create_default_context(cafile=str(self.root / "ca/mitmproxy-ca-cert.pem"))
        with context.wrap_socket(sock, server_hostname="intercepted.example.test") as stream:
            for path in ("/tls-one", "/tls-two"):
                stream.sendall(f"GET {path} HTTP/1.1\r\nHost: intercepted.example.test\r\n\r\n".encode())
                self.assertEqual(read_response(stream), (200, b"upstream-ok"))
        # Upstream TLS was verified against the NAME (the leaf has no IP SAN)
        # although the socket went to the pinned address; and it was reused.
        self.assertEqual(Upstream.requests, ["/tls-one", "/tls-two"])
        self.assertEqual(len(Upstream.peers), 1)


if __name__ == "__main__":
    unittest.main()
