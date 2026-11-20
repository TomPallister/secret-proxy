"""Real mitmdump wiring for the audit log (#6).

Starts the actual proxy entrypoint with the audit log enabled, makes one
injected request and one refused CONNECT, stops the proxy with SIGTERM as
``podman stop`` does, and verifies the sealed log with ``ssh-keygen`` and a
throwaway key. Only the vault backend, DNS and the fixture upstream's loopback
address are faked. Offline: nothing external is contacted.

No-hang rules: the proxy runs in its own session with output to a file and is
killed by process group; every socket has a timeout.
"""
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

import audit
import test_egress_wire as egress_wire
from test_audit import SSH_KEYGEN, make_key
from test_egress_wire import Upstream, free_port, read_response

ROOT = Path(__file__).parent
INSTANCE = "ab" * 16
REF = "secre" + "tref:"
SECRET_VALUE = "fixture-secret-value-3b9e"

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
    if host == "intercepted.example.test":
        return ["127.0.0.1"]
    raise OSError("no such host")

entry._resolver = resolver

def backend_get(self, name):
    if name == "AUDIT_SIGNING_SSH_KEY":
        return (STATE / "key").read_text()
    return "%s"

secretstore.OnePasswordBackend.get = backend_get
from entry import (load, done, http_connect, requestheaders, request, responseheaders,
                   server_connect, server_connected, server_connect_error,
                   server_disconnected, client_disconnected)
''' % SECRET_VALUE


class Recorder(Upstream):
    headers = []

    def do_GET(self):
        type(self).headers.append(self.headers.get("x-api-key"))
        super().do_GET()


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen not installed")
class AuditWireTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = root = Path(self.tmp.name)
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*egress_wire.WireTests.leaf(root))
        self.upstream.socket = context.wrap_socket(self.upstream.socket, server_side=True)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        self.tls_port = self.upstream.server_address[1]
        _private, self.public = make_key(root)
        (root / "manifest.json").write_text(json.dumps({
            "schemaVersion": 3, "account": {"vault": "Fixture"},
            "audit": {"enabled": True, "signingKey": "AUDIT_SIGNING_SSH_KEY"},
            "secrets": {
                "API_KEY": {"placements": [{"kind": "header", "hosts": ["intercepted.example.test"],
                                            "name": "x-api-key", "template": "{secret}"}]},
                "AUDIT_SIGNING_SSH_KEY": {"internalOnly": True, "valueField": "sshPrivateKey"},
            },
        }))
        (root / "fixture_entry.py").write_text(FIXTURE)
        self.audit_dir = root / "data" / "audit"
        self.port = free_port()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root),
            "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1",
            "SECRET_PROXY_CONFIG_DIR": str(root),
            "SECRET_PROXY_SECRETS_FILE": str(root / "manifest.json"),
            "OP_SERVICE_ACCOUNT_TOKEN": "offline-fixture-only",
            "SECRET_PROXY_INSTANCE_ID": INSTANCE,
            "SECRET_PROXY_AUDIT_DIR": str(self.audit_dir),
        }
        command = [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()",
                   "--listen-host", "127.0.0.1", "--listen-port", str(self.port),
                   "--set", f"confdir={root / 'ca'}", "--set", "flow_detail=0",
                   "--set", "termlog_verbosity=error", "--set", "connection_strategy=lazy",
                   "--set", "upstream_cert=false",
                   "--set", f"ssl_verify_upstream_trusted_ca={root / 'upstream.pem'}",
                   "-s", str(root / "fixture_entry.py")]
        self.log = (root / "proxy.log").open("wb")
        self.addCleanup(self.log.close)
        self.child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                      stdout=self.log, stderr=self.log, start_new_session=True)
        self.addCleanup(self.kill)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and self.child.poll() is None:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                if (root / "ca/mitmproxy-ca-cert.pem").exists():
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise AssertionError("proxy did not start: " + (root / "proxy.log").read_text())

    def kill(self):
        if self.child.poll() is None:
            try:
                os.killpg(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.child.wait(timeout=10)

    def connect(self, host, port):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        target = f"{host}:{port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        return sock, read_response(sock)

    def test_injection_is_audited_and_a_clean_stop_seals_and_signs(self):
        sock, (status, _) = self.connect("intercepted.example.test", self.tls_port)
        self.assertEqual(status, 200)
        context = ssl.create_default_context(cafile=str(self.root / "ca/mitmproxy-ca-cert.pem"))
        with context.wrap_socket(sock, server_hostname="intercepted.example.test") as stream:
            stream.sendall(("GET /v1/items?page=query-only-77 HTTP/1.1\r\nHost: intercepted.example.test\r\n"
                            "x-api-key: " + REF + "API_KEY\r\n\r\n").encode())
            self.assertEqual(read_response(stream), (200, b"upstream-ok"))
        self.assertEqual(Recorder.headers[-1], SECRET_VALUE)
        sock, (status, _) = self.connect("169.254.169.254", 80)
        sock.close()
        self.assertEqual(status, 403)
        os.killpg(self.child.pid, signal.SIGTERM)  # what podman stop sends
        self.child.wait(timeout=20)
        files = [(p.name, p.read_bytes()) for p in sorted(self.audit_dir.glob("audit-*.jsonl"))]
        result = audit.verify_files(files, self.public)
        self.assertEqual(result.status, "sealed", result.lines() + [(self.root / "proxy.log").read_text()])
        recorded = [json.loads(line) for _name, data in files for line in data.splitlines()]
        events = [(e["event"], e["decision"], e.get("secret"), e.get("path"), e.get("rule"))
                  for e in recorded if e["type"] == "event"]
        self.assertIn(("inject", "injected", "API_KEY", "/v1/items", None), events)
        self.assertIn(("egress", "refused", None, None, "metadata-address"), events)
        data = b"".join(content for _name, content in files)
        for leaked in (SECRET_VALUE, "query-only-77", REF, "PRIVATE KEY"):
            self.assertNotIn(leaked.encode(), data)
        self.assertEqual(oct(self.audit_dir.stat().st_mode & 0o777), "0o700")


if __name__ == "__main__":
    unittest.main()
