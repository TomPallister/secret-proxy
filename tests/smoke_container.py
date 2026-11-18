"""Run via image's Python on stdin. No network or real vault access required."""
import base64
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *args):
        pass

assert not Path("/usr/local/bin/bw").exists()
assert not Path("/usr/local/bin/node").exists()
assert not Path("/tmp/build-ca.pem").exists()
assert not Path("/usr/local/share/ca-certificates/corporate-ca.crt").exists()
server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
with tempfile.TemporaryDirectory() as tmp:
    config = Path(tmp) / "config"
    config.mkdir()
    (config / "manifest.json").write_text(json.dumps({"schemaVersion": 3, "account": {"vault": "Fixture"}, "secrets": {}}))
    (config / "aws-okta.json").write_text(json.dumps({
        "okta_hosts": ["example.okta.com"],
        "default_app_url": "https://example.okta.com/home/amazon_aws/example/1",
        "default_account": "123456789012", "default_role": "ReadOnly",
        "allowed_roles": ["ReadOnly"], "OKTA_USERNAME": "OKTA_USERNAME",
        "OKTA_PASSWORD": "OKTA_PASSWORD", "OKTA_SECRET": "OKTA_SECRET",
    }))
    child = subprocess.Popen(["/opt/secret-proxy/.venv/bin/python", "/opt/secret-proxy/runtime.py",
        "--config-dir", str(config), "--port", "19080",
        "--state-dir", str(Path(tmp) / "state"), "--runtime-dir", str(Path(tmp) / "runtime")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        child.stdin.write(json.dumps({"op_token": "not-a-real-capability", "proxy_token": "a" * 48}).encode())
        child.stdin.close()
        deadline = time.monotonic() + 20
        def request(auth):
            conn = http.client.HTTPConnection("127.0.0.1", 19080, timeout=2)
            try:
                headers = {"Proxy-Authorization": "Basic " + base64.b64encode(auth.encode()).decode()}
                conn.request("GET", f"http://127.0.0.1:{server.server_port}/", headers=headers)
                response = conn.getresponse()
                return response.status, response.read()
            finally:
                conn.close()
        while True:
            try:
                status, _ = request("secret-proxy:wrong")
                break
            except (OSError, http.client.HTTPException):
                if child.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("proxy did not become ready")
                time.sleep(0.1)
        assert status == 407, status
        assert request("secret-proxy:" + "a" * 48) == (200, b"ok")
        while not (Path(tmp) / 'runtime/ready.json').exists():
            assert child.poll() is None and time.monotonic() < deadline, 'authenticated readiness missing'
            time.sleep(.1)
        assert child.poll() is None
        assert len(list((Path(tmp) / "runtime").glob("proxy-*/saml2aws.ini"))) == 1
        child.terminate()
        child.wait(timeout=10)
        assert not list((Path(tmp) / "runtime").glob("proxy-*")), "temporary auth file not cleaned"
        print("PASS: read-only, capability-dropped container; 407/200 authentication; clean shutdown; no Node, bw or baked corporate CA")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        output = child.stdout.read()
        assert b"not-a-real-capability" not in output and b"a" * 48 not in output
        server.shutdown()
