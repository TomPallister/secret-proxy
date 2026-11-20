"""Real mitmdump wiring for scoped client identity (issue #2).

Starts the shipped entrypoint with a multi-user htpasswd file and confirms that
the authenticated client name reaches the addon for every request inside a
CONNECT tunnel, over HTTP/1.1 and HTTP/2, and that grants are enforced on the
wire. Only DNS and secret resolution are faked; offline throughout.
"""
import base64
import datetime
import hashlib
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
SENTINEL = "secret" + "ref.invalid"
REF = "secre" + "tref:"
TOKENS = {"secret-proxy": "a" * 48, "reader": "b" * 48, "nothing": "c" * 48}

FIXTURE = '''
import json
from pathlib import Path
from mitmproxy import http
import addon
import egress
import entry

STATE = Path(__file__).parent
_real = egress.address_refusal
egress.address_refusal = lambda text, allowed=(): None if text == "127.0.0.1" else _real(text, allowed)

def resolver(host, port):
    if host == "api.example.test":
        return ["127.0.0.1"]
    raise OSError("no such host")

entry._resolver = resolver

def fake_resolve(ref):
    calls = STATE / "resolved.json"
    log = json.loads(calls.read_text()) if calls.exists() else []
    log.append(ref)
    calls.write_text(json.dumps(log))
    return "real-" + ref

addon._resolve = fake_resolve
_health = addon._health_route

def whoami(flow):
    if flow.request.path == "/whoami":
        flow.response = http.Response.make(200, json.dumps({
            "client": addon.flow_client(flow), "http": flow.request.http_version}).encode())
        return True
    return _health(flow)

addon._health_route = whoami
from entry import (load, http_connect, requestheaders, request, responseheaders,
                   server_connect, server_connected, server_connect_error,
                   server_disconnected, client_disconnected)
'''


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def do_GET(self):
        type(self).seen.append(self.headers.get("x-api-key"))
        body = b"upstream-ok"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


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


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class ClientWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = cls.root = Path(cls.tmp.name)
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*cls.leaf(root))
        cls.upstream.socket = context.wrap_socket(cls.upstream.socket, server_side=True)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.upstream_port = cls.upstream.server_address[1]
        (root / "manifest.json").write_text(json.dumps({
            "schemaVersion": 3, "account": {"vault": "Fixture"},
            "secrets": {"API_KEY": {"placements": [{
                "kind": "header", "hosts": ["api.example.test"], "name": "x-api-key", "template": "{secret}"}]}},
            "clients": {"default": {"all": True}, "reader": {"secrets": {"API_KEY": True}}, "nothing": {}},
        }))
        (root / "htpasswd").write_text("".join(
            user + ":{SHA}" + base64.b64encode(hashlib.sha1(token.encode()).digest()).decode() + "\n"
            for user, token in TOKENS.items()))
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
                   "--set", f"confdir={root / 'ca'}", "--set", f"proxyauth=@{root / 'htpasswd'}",
                   "--set", "flow_detail=0", "--set", "termlog_verbosity=error",
                   "--set", "connection_strategy=lazy", "--set", "upstream_cert=false",
                   "--set", f"ssl_verify_upstream_trusted_ca={root / 'upstream.pem'}",
                   "-s", str(root / "fixture_entry.py")]
        cls.log = (root / "proxy.log").open("wb")
        cls.child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=cls.log,
                                     stderr=cls.log, start_new_session=True)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and cls.child.poll() is None:
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        cls.tearDownClass()
        raise AssertionError("proxy did not start: " + (root / "proxy.log").read_text())

    @staticmethod
    def leaf(root):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.example.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.example.test")]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(key, hashes.SHA256()))
        (root / "upstream.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / "upstream.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return str(root / "upstream.pem"), str(root / "upstream.key")

    @classmethod
    def tearDownClass(cls):
        if cls.child.poll() is None:
            try:
                os.killpg(cls.child.pid, 15)
                cls.child.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                os.killpg(cls.child.pid, 9)
                cls.child.wait()
        cls.log.close()
        cls.upstream.shutdown()
        cls.upstream.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        Upstream.seen.clear()
        (self.root / "resolved.json").unlink(missing_ok=True)

    def resolved(self):
        path = self.root / "resolved.json"
        return json.loads(path.read_text()) if path.exists() else []

    def tunnel(self, user, host, port=443, token=None, alpn=("http/1.1",)):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        auth = base64.b64encode(f"{user}:{token or TOKENS[user]}".encode()).decode()
        target = f"{host}:{port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                     f"Proxy-Authorization: Basic {auth}\r\n\r\n".encode())
        status, _ = read_response(sock)
        if status != 200:
            sock.close()
            return status, None
        context = ssl.create_default_context(cafile=str(self.root / "ca/mitmproxy-ca-cert.pem"))
        context.set_alpn_protocols(list(alpn))
        return status, context.wrap_socket(sock, server_hostname=host)

    def get(self, stream, path, host=SENTINEL, headers=""):
        stream.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n".encode())
        return read_response(stream)

    def test_every_request_in_a_tunnel_carries_its_clients_name(self):
        for user, client in (("reader", "reader"), ("secret-proxy", "default"), ("nothing", "nothing")):
            with self.subTest(user):
                status, stream = self.tunnel(user, SENTINEL)
                self.assertEqual(status, 200)
                with stream:
                    for _ in range(2):
                        status, body = self.get(stream, "/whoami")
                        self.assertEqual((status, json.loads(body)), (200, {"client": client, "http": "HTTP/1.1"}))

    def test_http2_requests_carry_the_tunnels_client(self):
        import h2.connection
        import h2.events
        status, stream = self.tunnel("reader", SENTINEL, alpn=("h2",))
        self.assertEqual(status, 200)
        with stream:
            self.assertEqual(stream.selected_alpn_protocol(), "h2")
            conn = h2.connection.H2Connection()
            conn.initiate_connection()
            for stream_id in (1, 3):
                conn.send_headers(stream_id, [(":method", "GET"), (":path", "/whoami"),
                                              (":authority", SENTINEL), (":scheme", "https")], end_stream=True)
            stream.sendall(conn.data_to_send())
            bodies = {}
            done = set()
            while len(done) < 2:
                data = stream.recv(65536)
                self.assertTrue(data, "connection closed early")
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.DataReceived):
                        bodies[event.stream_id] = bodies.get(event.stream_id, b"") + event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        done.add(event.stream_id)
                stream.sendall(conn.data_to_send())
        for stream_id in (1, 3):
            self.assertEqual(json.loads(bodies[stream_id]), {"client": "reader", "http": "HTTP/2.0"})

    def test_a_token_authenticates_only_its_own_user_name(self):
        for user, token in (("reader", TOKENS["secret-proxy"]), ("secret-proxy", TOKENS["reader"]),
                            ("default", TOKENS["secret-proxy"]), ("ghost", TOKENS["reader"])):
            with self.subTest(user):
                status, _ = self.tunnel(user, SENTINEL, token=token)
                self.assertEqual(status, 407)

    def test_grants_are_enforced_on_the_wire(self):
        status, stream = self.tunnel("nothing", "api.example.test", self.upstream_port)
        self.assertEqual(status, 200)
        with stream:
            status, body = self.get(stream, "/data", "api.example.test", "x-api-key: " + REF + "API_KEY\r\n")
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"], "secret_proxy_placement_not_allowed")
        self.assertEqual((self.resolved(), Upstream.seen), ([], []))
        status, stream = self.tunnel("reader", "api.example.test", self.upstream_port)
        with stream:
            self.assertEqual(self.get(stream, "/data", "api.example.test", "x-api-key: " + REF + "API_KEY\r\n"),
                             (200, b"upstream-ok"))
        self.assertEqual((self.resolved(), Upstream.seen), (["API_KEY"], ["real-API_KEY"]))


if __name__ == "__main__":
    unittest.main()
