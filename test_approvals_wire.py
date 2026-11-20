"""Real mitmdump wiring for approval rules (#3).

Starts the actual proxy entrypoint against local fixture upstreams. Only the
resolver, the vault backend and the fixture upstream's loopback address are
faked; the hooks, the control endpoint and the approver CLI loop are the
shipped code. Offline: no vault, vendor or external network is contacted.

No-hang rules: the proxy runs in its own session with output to a file and is
killed by process group; every socket has a timeout; every thread is joined
with a deadline.
"""
import hashlib
import io
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

import client
import test_egress_wire as egress_wire
from test_egress_wire import Upstream, free_port, read_response

ROOT = Path(__file__).parent
INSTANCE = "ab" * 16
APPROVER = "c" * 48
REF = "secre" + "tref:"

FIXTURE = '''
import json
from pathlib import Path
import egress
import entry
import secretstore

STATE = Path(__file__).parent
_real = egress.address_refusal

def address_refusal(text, allowed=()):
    return None if text == "127.0.0.1" else _real(text, allowed)

egress.address_refusal = address_refusal

def resolver(host, port):
    if host in ("intercepted.example.test", "unlisted.example.test"):
        return ["127.0.0.1"]
    raise OSError("no such host")

entry._resolver = resolver

def backend_get(self, name):
    path = STATE / "resolved.json"
    seen = json.loads(path.read_text()) if path.exists() else []
    seen.append(name)
    path.write_text(json.dumps(seen))
    return "fixture-secret-value"

secretstore.OnePasswordBackend.get = backend_get
from entry import (load, http_connect, requestheaders, request, responseheaders,
                   server_connect, server_connected, server_connect_error,
                   server_disconnected, client_disconnected)
'''


class Recorder(Upstream):
    headers = []

    def do_GET(self):
        type(self).headers.append(self.headers.get("x-api-key"))
        super().do_GET()


class ApprovalWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.root = root
        cls.upstream = None
        cls.child = None
        cls.log = None
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*egress_wire.WireTests.leaf(root))
        cls.upstream.socket = context.wrap_socket(cls.upstream.socket, server_side=True)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.tls_port = cls.upstream.server_address[1]
        (root / "manifest.json").write_text(json.dumps({
            "schemaVersion": 3, "account": {"vault": "Fixture"},
            "egress": {"mode": "allowlist", "allowlistMiss": "approve"},
            "approvals": {"timeoutSeconds": 10},
            "secrets": {"API_KEY": {"placements": [{
                "kind": "header", "hosts": ["intercepted.example.test"], "name": "x-api-key",
                "template": "{secret}", "approval": "prompt"}]}},
        }))
        (root / "fixture_entry.py").write_text(FIXTURE)
        shared = root / "shared"
        shared.mkdir()
        (shared / "proxy-token").write_text("e" * 48 + "\n")
        (shared / "ready.json").write_text(json.dumps({"status": "ready", "instance": INSTANCE}))
        cls.port = free_port()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root),
            "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1",
            "SECRET_PROXY_CONFIG_DIR": str(root),
            "SECRET_PROXY_SECRETS_FILE": str(root / "manifest.json"),
            "OP_SERVICE_ACCOUNT_TOKEN": "offline-fixture-only",
            "SECRET_PROXY_INSTANCE_ID": INSTANCE,
            "SECRET_PROXY_APPROVER_DIGEST": hashlib.sha256(APPROVER.encode()).hexdigest(),
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
                                     stdout=cls.log, stderr=cls.log, start_new_session=True)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and cls.child.poll() is None:
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                ca = root / "ca/mitmproxy-ca-cert.pem"
                if ca.exists():
                    (shared / "ca.pem").write_bytes(ca.read_bytes())
                    cls.approver_client = client.ProxyClient({"sharedDir": str(shared), "port": cls.port})
                    return
            except OSError:
                pass
            time.sleep(0.1)
        cls.tearDownClass()
        raise AssertionError("proxy did not start")

    @classmethod
    def tearDownClass(cls):
        if cls.child is not None and cls.child.poll() is None:
            try:
                os.killpg(cls.child.pid, signal.SIGTERM)
                cls.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(cls.child.pid, signal.SIGKILL)
                cls.child.wait(timeout=10)
            except ProcessLookupError:
                pass
        if cls.log is not None:
            cls.log.close()
        if cls.upstream is not None:
            cls.upstream.shutdown()
            cls.upstream.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        Recorder.requests.clear()
        Recorder.headers.clear()
        resolved = self.root / "resolved.json"
        if resolved.exists():
            resolved.unlink()

    def resolved(self):
        path = self.root / "resolved.json"
        return json.loads(path.read_text()) if path.exists() else []

    def tunnel(self, host, port, alpn=("http/1.1",)):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=15)
        target = f"{host}:{port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        status, body = read_response(sock)
        if status != 200:
            sock.close()
            return None, (status, body)
        context = ssl.create_default_context(cafile=str(self.root / "ca/mitmproxy-ca-cert.pem"))
        context.set_alpn_protocols(list(alpn))
        return context.wrap_socket(sock, server_hostname=host), (status, body)

    def h1_request(self, results):
        stream, _ = self.tunnel("intercepted.example.test", self.tls_port)
        with stream:
            stream.sendall(b"GET /held?q=1 HTTP/1.1\r\nHost: intercepted.example.test\r\n"
                           b"x-api-key: " + (REF + "API_KEY").encode() + b"\r\n\r\n")
            results.append(read_response(stream))

    def h2_request(self, results):
        import h2.connection
        import h2.events
        stream, _ = self.tunnel("intercepted.example.test", self.tls_port, alpn=("h2",))
        with stream:
            results.append(("alpn", stream.selected_alpn_protocol()))
            conn = h2.connection.H2Connection()
            conn.initiate_connection()
            conn.send_headers(1, [(":method", "GET"), (":path", "/held-h2"), (":scheme", "https"),
                                  (":authority", "intercepted.example.test"),
                                  ("x-api-key", REF + "API_KEY")], end_stream=True)
            stream.sendall(conn.data_to_send())
            status, body = None, b""
            while True:
                data = stream.recv(65535)
                if not data:
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        status = int(dict(event.headers)[b":status"])
                    elif isinstance(event, h2.events.DataReceived):
                        body += event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        results.append((status, body))
                        return
                stream.sendall(conn.data_to_send())

    def answered(self, worker, choice, check_held=None):
        results = []
        prompts = []
        errors = []

        def reader(_fd, delay, _timeout):
            # The request is held while the prompt is on screen.
            time.sleep(delay)  # as read_choice does; earlier answers are refused
            if check_held is not None:
                check_held()
            prompts.append(True)
            return choice

        output = io.StringIO()

        def approve():
            try:
                client.approvals_loop(self.approver_client, APPROVER, out=output, reader=reader, rounds=1)
            except Exception as error:  # noqa: BLE001 - reported below
                errors.append(error)

        # The approver is polling before the request arrives.
        approver = threading.Thread(target=approve, daemon=True)
        approver.start()
        time.sleep(0.5)
        requester = threading.Thread(target=worker, args=(results,), daemon=True)
        requester.start()
        for thread in (requester, approver):
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive(), "a held request or the approver did not finish")
        self.assertEqual(errors, [])
        self.assertEqual(prompts, [True], output.getvalue())
        return results, output.getvalue()

    def assert_nothing_happened_yet(self):
        self.assertEqual(Recorder.requests, [], "forwarded before approval")
        self.assertEqual(self.resolved(), [], "resolved before approval")

    def test_1_no_listener_denies_immediately(self):
        started = time.monotonic()
        results = []
        self.h1_request(results)
        self.assertLess(time.monotonic() - started, 5)
        status, body = results[0]
        self.assertEqual((status, json.loads(body)["rule"]), (403, "approval-no-listener"))
        self.assert_nothing_happened_yet()

    def test_2_http1_allow_once(self):
        results, output = self.answered(self.h1_request, "2", self.assert_nothing_happened_yet)
        self.assertEqual(results, [(200, b"upstream-ok")])
        self.assertEqual(Recorder.requests, ["/held?q=1"])
        self.assertEqual(Recorder.headers, ["fixture-secret-value"])
        self.assertEqual(self.resolved(), ["API_KEY"])
        self.assertIn("secret     API_KEY", output)
        self.assertIn("path       /held", output)
        self.assertNotIn("q=1", output)
        self.assertNotIn("fixture-secret-value", output)

    def test_3_http2_deny_once(self):
        results, _ = self.answered(self.h2_request, "1", self.assert_nothing_happened_yet)
        self.assertEqual(results[0], ("alpn", "h2"))
        status, body = results[1]
        self.assertEqual((status, json.loads(body)["rule"]), (403, "approval-denied"))
        self.assert_nothing_happened_yet()

    def test_4_http2_allow_once(self):
        results, _ = self.answered(self.h2_request, "2", self.assert_nothing_happened_yet)
        self.assertEqual(results, [("alpn", "h2"), (200, b"upstream-ok")])
        self.assertEqual(Recorder.headers, ["fixture-secret-value"])

    def test_5_egress_allowlist_miss_held_in_connect(self):
        def connect(results):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=15)
            with sock:
                target = f"unlisted.example.test:{self.tls_port}"
                sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                results.append(read_response(sock))

        results, output = self.answered(connect, "1")
        self.assertIn("unlisted.example.test", output)
        self.assertEqual((results[0][0], json.loads(results[0][1])["rule"]), (403, "approval-denied"))
        results, _ = self.answered(connect, "2")
        self.assertEqual(results[0][0], 200)

    def test_6_log_has_decisions_but_no_values_or_queries(self):
        self.log.flush()
        text = (self.root / "proxy.log").read_text()
        self.assertNotIn("Traceback", text)
        self.assertIn("APPROVAL allow (allow-once) secret method=GET host=intercepted.example.test", text)
        self.assertIn("APPROVAL deny (approval-denied)", text)
        self.assertIn("APPROVAL deny (approval-no-listener)", text)
        self.assertNotIn("fixture-secret-value", text)
        self.assertNotIn("q=1", text)


if __name__ == "__main__":
    unittest.main()
