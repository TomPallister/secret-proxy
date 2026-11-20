"""Container runtime: credentials arrive on stdin, never argv or a config file.

This is an internal secagent entrypoint, not an installer or host launcher.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import fcntl
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import signal
import ssl
import socket
import struct
import subprocess
import sys
import tempfile
import time

from secretstore import LoginStoreConfigError, SecretManifest, check_login_vault
import clientgrants
from awscreds import AwsCredsProvider
from awsops import AwsPolicyError, load_policy_bytes
from egress import EgressConfigError
from capolicy import CAPolicyError
from audit import AuditConfigError

MAX_BOOTSTRAP = 16384


def read_bootstrap(fd: int, timeout: float = 30) -> dict:
    """Read a bounded EOF-terminated capability bundle under one deadline."""
    deadline = time.monotonic() + timeout
    data = bytearray()
    with selectors.DefaultSelector() as poll:
        poll.register(fd, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not poll.select(remaining):
                raise ValueError("bootstrap timed out")
            chunk = os.read(fd, min(4096, MAX_BOOTSTRAP + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_BOOTSTRAP:
                raise ValueError("bootstrap exceeds size limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate bootstrap key")
            result[key] = value
        return result
    obj = json.loads(data, object_pairs_hook=unique)
    if not isinstance(obj, dict) or not {"op_token", "proxy_token"} <= set(obj) \
            or set(obj) - {"op_token", "proxy_token", "client_tokens", "approver_token", "login_vault"}:
        raise ValueError("invalid bootstrap fields")
    op = obj["op_token"]
    if not isinstance(op, str) or not op or not op.isascii() or any(c.isspace() or ord(c) < 33 for c in op):
        raise ValueError("invalid service-account capability")
    proxy = obj["proxy_token"]
    if not isinstance(proxy, str) or re.fullmatch(r"[0-9a-f]{48}", proxy) is None:
        raise ValueError("invalid proxy capability")
    # Optional: one token per named client (the default client uses proxy_token).
    clients = obj.get("client_tokens", {})
    if not isinstance(clients, dict) or len(clients) > clientgrants.MAX_CLIENTS:
        raise ValueError("invalid client capabilities")
    seen = {proxy}
    for name, token in clients.items():
        if (not clientgrants.valid_name(name) or name == clientgrants.DEFAULT_CLIENT
                or not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{48}", token) is None
                or token in seen):
            raise ValueError("invalid client capabilities")
        seen.add(token)
    # Optional: the approver-only capability for approval prompts (issue #3).
    # It must differ from every client token: no client may approve itself.
    approver = obj.get("approver_token")
    if approver is not None and (not isinstance(approver, str)
                                 or re.fullmatch(r"[0-9a-f]{48}", approver) is None
                                 or approver in seen):
        raise ValueError("invalid approver capability")
    # Optional: the login vault the bootstrap item declares (loginStore).
    login_vault = obj.get("login_vault")
    if login_vault is not None and (not isinstance(login_vault, str) or not login_vault.strip()
                                    or any(ord(c) < 32 for c in login_vault)):
        raise ValueError("invalid login vault")
    return obj


def htpasswd(capabilities: dict, named_clients) -> str:
    """One {SHA} line per client; with no clients section, exactly today's file.

    *named_clients* are the manifest's non-default clients; each needs exactly
    its own token in the bundle, and the bundle may carry nothing else.
    """
    tokens = capabilities.get("client_tokens", {})
    if set(tokens) != set(named_clients):
        raise clientgrants.ClientConfigError("client tokens do not match the manifest clients; restart through the controller")
    lines = [(clientgrants.DEFAULT_USERNAME, capabilities["proxy_token"])]
    lines += [(name, tokens[name]) for name in sorted(named_clients)]
    return "".join(user + ":{SHA}" + base64.b64encode(hashlib.sha1(token.encode()).digest()).decode() + "\n"
                   for user, token in lines)


def command(config: Path, state: Path, auth: Path, port: int, capabilities: dict,
            audit_dir: Path = Path("/data/audit")):
    """Build a fixed launch contract; secrets are confined to the child env."""
    root = Path(__file__).resolve().parent
    mitmdump = root / ".venv/bin/mitmdump"
    args = [str(mitmdump), "--listen-host", "0.0.0.0", "--listen-port", str(port),
            "--set", f"confdir={state}", "--set", f"proxyauth=@{auth}",
            "--set", "flow_detail=0", "--set", "termlog_verbosity=error",
            "--set", "connection_strategy=lazy", "--set", "upstream_cert=false",
            "--set", "ssl_verify_upstream_trusted_ca=/etc/ssl/certs/ca-certificates.crt",
            "-s", str(root / "entry.py")]
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/secretproxy",
        "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1",
        "SECRET_PROXY_CONFIG_DIR": str(config),
        "SECRET_PROXY_SECRETS_FILE": str(config / "manifest.json"),
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
        "OP_SERVICE_ACCOUNT_TOKEN": capabilities["op_token"],
        "SECRET_PROXY_INSTANCE_ID": secrets.token_hex(16),
        # Used only when the manifest enables the audit log: the proxy's own
        # persistent volume, never /config and never a client-shared directory.
        "SECRET_PROXY_AUDIT_DIR": str(audit_dir),
    }
    if capabilities.get("approver_token"):
        # Only a digest: the proxy can check an answer but not make one.
        env["SECRET_PROXY_APPROVER_DIGEST"] = hashlib.sha256(
            capabilities["approver_token"].encode("ascii")).hexdigest()
    return args, env


def configure_aws(config: Path, target: Path) -> None:
    """Create only non-secret saml2aws settings inside private tmpfs state."""
    cfg = json.loads(config.read_text())
    AwsCredsProvider._validate_config(cfg)
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/secretproxy",
        "SAML2AWS_CONFIGFILE": str(target),
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    }
    args = ["/usr/local/bin/saml2aws", "configure", "--skip-prompt",
            "--idp-account", "default", "--idp-provider", "Okta", "--mfa", "Auto",
            "--url", cfg["default_app_url"], "--aws-urn", "urn:amazon:webservices",
            "--region", cfg.get("region", "eu-west-1"), "--profile", "saml",
            "--session-duration", cfg.get("session_duration", "3600")]
    result = subprocess.run(args, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError("saml2aws configuration failed")


def validate_aws_policy(config: Path) -> None:
    """Refuse to start with an invalid optional aws-policy.json."""
    path = config / "aws-policy.json"
    if path.exists():
        data = path.read_bytes()
        if len(data) > 2 * 1024 * 1024:
            raise AwsPolicyError("aws-policy.json: file too large")
        load_policy_bytes(data)


def wait_ready(child, port: int, capability: str, instance: str, ca: Path, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    expected = {"status": "ready", "instance": instance}
    auth = base64.b64encode(("secret-proxy:" + capability).encode()).decode()
    while child.poll() is None and time.monotonic() < deadline:
        conn = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(str(ca))
            conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=1, context=context)
            conn.set_tunnel("secret" + "ref.invalid", 443,
                            headers={"Proxy-Authorization": "Basic " + auth})
            conn.request("GET", "/health")
            response = conn.getresponse()
            if response.status == 200 and json.loads(response.read(4097)) == expected:
                return expected
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            if conn is not None:
                conn.close()
        time.sleep(0.1)
    raise ValueError("proxy did not become ready")


def require_interface(name: str | None):
    if name is None:
        return
    if re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,14}', name) is None:
        raise ValueError('invalid required interface')
    try:
        # A container joining another user namespace's netns can see a stale
        # /sys mount. Query the current kernel network namespace, not sysfs.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            result = fcntl.ioctl(probe.fileno(), 0x8913, struct.pack('256s', name.encode('ascii')))
        up = struct.unpack_from('H', result, 16)[0] & 1
    except (OSError, ValueError):
        up = False
    if not up:
        raise ValueError('required VPN interface is down')


def wait_serving(child, required_interface):
    if required_interface is None:
        return child.wait()
    while child.poll() is None:
        require_interface(required_interface)
        try:
            return child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    return child.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, default=Path("/config"))
    parser.add_argument("--state-dir", type=Path, default=Path("/data/mitmproxy"))
    parser.add_argument("--runtime-dir", type=Path, default=Path("/tmp/secret-proxy"))
    parser.add_argument("--audit-dir", type=Path, default=Path("/data/audit"))
    parser.add_argument("--port", type=int, default=10256)
    parser.add_argument("--required-interface")
    parser.add_argument("--ca-label", default=os.environ.get("SECRET_PROXY_CA_LABEL"),
                        help="Instance name, used only for a name-constrained CA")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        raise ValueError("invalid port")
    require_interface(args.required_interface)
    config = args.config_dir.resolve(strict=True)
    manifest = SecretManifest.load(config / "manifest.json")
    named_clients = manifest.clients.named() if manifest.clients is not None else ()
    aws = config / "aws-okta.json"
    if aws.exists():
        # Validate before credentials are consumed; never mint during validation.
        AwsCredsProvider.from_config_file(str(aws), lambda _: (_ for _ in ()).throw(AssertionError()))
    validate_aws_policy(config)
    # Opt-in CA policy is validated before credentials are consumed. Imported
    # here: host.py imports this module on macOS Python without cryptography.
    import constrainedca
    ca_domains = constrainedca.plan(config, args.ca_label)
    capabilities = read_bootstrap(sys.stdin.fileno())
    # The service account may write only the login vault the manifest uses.
    check_login_vault(manifest, capabilities.get("login_vault"))
    os.umask(0o077)
    args.state_dir.mkdir(parents=True, exist_ok=True)
    args.runtime_dir.mkdir(parents=True, exist_ok=True)
    ca_state = constrainedca.ensure(args.state_dir, args.ca_label, ca_domains)
    if ca_state in ("created", "replaced"):
        print("secret-proxy runtime: " + ca_state + " a name-constrained CA for "
              + ", ".join(ca_domains) + ". Consumers need the new public CA; run "
              "`secret-proxy trust-ca` again if you trust it on macOS.", file=sys.stderr, flush=True)
    with tempfile.TemporaryDirectory(prefix="proxy-", dir=args.runtime_dir) as tmp:
        auth = Path(tmp) / "htpasswd"
        auth.write_text(htpasswd(capabilities, named_clients))
        auth.chmod(0o600)
        argv, env = command(config, args.state_dir.resolve(), auth, args.port, capabilities,
                            args.audit_dir)
        if aws.exists():
            saml_config = Path(tmp) / "saml2aws.ini"
            configure_aws(aws, saml_config)
            env["SECRET_PROXY_SAML_CONFIG"] = str(saml_config)
        proxy_capability = capabilities["proxy_token"]
        capabilities.clear()
        child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, start_new_session=True)
        def stop(signum, _frame):
            if child.poll() is None:
                child.send_signal(signum)
        handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        ready = args.runtime_dir / "ready.json"
        try:
            status = wait_ready(child, args.port, proxy_capability, env["SECRET_PROXY_INSTANCE_ID"],
                                args.state_dir / "mitmproxy-ca-cert.pem")
            proxy_capability = ""
            pending = args.runtime_dir / ".ready.json"
            pending.write_text(json.dumps(status) + "\n")
            os.replace(pending, ready)
            return wait_serving(child, args.required_interface)
        finally:
            ready.unlink(missing_ok=True)
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            for sig, handler in handlers.items():
                signal.signal(sig, handler)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        # Provider/JSON errors must not echo any capability or callback content.
        # AWS policy, egress, CA policy and client errors contain only policy text, so show them.
        detail = (str(error) if isinstance(error, (AwsPolicyError, EgressConfigError, CAPolicyError,
                                                   clientgrants.ClientConfigError, AuditConfigError,
                                                   LoginStoreConfigError))
                  else type(error).__name__)
        print("secret-proxy runtime failed: " + detail, file=sys.stderr)
        sys.exit(1)
