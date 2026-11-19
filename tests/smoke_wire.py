"""Offline wire smoke: real TLS/H1/H2/addon, synthetic provider, generated keys.

Run on stdin with the candidate image's Python and --network=none. This does
not contact a vault, vendor, live proxy or use host credentials. Only the CLI
runner is replaced; manifest validation, resolution, cache, policy, injection,
streaming, TLS and signing use the actual installed implementation.
"""
import base64
import datetime
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
import h2.config
import h2.connection
import h2.events

sys.path.insert(0, str(Path.cwd() if __file__ == '<stdin>' else Path(__file__).resolve().parents[1]))
import runtime
import gitsign

REF = 'secret' + 'ref:'
SENTINEL = 'secret' + 'ref.invalid'


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        values = {'API_KEY': secrets.token_hex(24)}
        signing = Ed25519PrivateKey.generate()
        values['GIT_SIGNING_SSH_KEY'] = signing.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption()).decode()
        (root / 'values.json').write_text(json.dumps(values))
        (root / 'values.json').chmod(0o600)
        # Self-signed fixture leaf is trusted only by this proxy subprocess.
        key = Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
                .sign(key, None))
        (root / 'server.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / 'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (root / 'server.key').chmod(0o600)
        observed = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                query = parse_qs(urlsplit(self.path).query)
                observed.append(self.headers.get('X-Api-Key') == values['API_KEY'] and
                                query.get('key', [values['API_KEY']]) == [values['API_KEY']])
                self.answer()

            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                auth = base64.b64decode(self.headers['Authorization'].split()[1]).decode()
                observed.append(parse_qs(body.decode()).get('key') == [values['API_KEY']] and
                                auth == 'fixture:' + values['API_KEY'])
                self.answer()

            def answer(self):
                self.send_response(200 if observed[-1] else 400)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')  # Never echo the synthetic credential.

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / 'server.pem', root / 'server.key')
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        placements = [dict(kind=kind, hosts=['127.0.0.1'], methods=['GET', 'POST'], paths=['/check'],
                           **fields) for kind, fields in [
            ('header', {'name': 'x-api-key', 'template': '{secret}'}),
            ('query', {'name': 'key', 'template': '{secret}'}),
            ('form', {'name': 'key', 'template': '{secret}'}),
            ('basic-password', {'username': 'fixture'})]]
        (root / 'manifest.json').write_text(json.dumps({'schemaVersion': 3, 'account': {'vault': 'Fixture'},
            'secrets': {'API_KEY': {'placements': placements},
                        'CHATGPT_ACCESS_TOKEN': {'runtimeOnly': True, 'placements': [
                            {'kind': 'header', 'hosts': ['chatgpt.com'], 'name': 'authorization',
                             'template': 'Bearer {secret}', 'methods': ['POST'],
                             'paths': ['/backend-api/codex/responses']}]},
                        'GIT_SIGNING_SSH_KEY': {'internalOnly': True, 'valueField': 'sshPrivateKey'}}}))
        # Synthetic AWS configuration: makes the proxy intercept AWS hosts. No
        # Okta values exist, so an allowed call fails at credential vending.
        (root / 'aws-okta.json').write_text(json.dumps({
            'okta_hosts': ['example.okta.com'],
            'default_app_url': 'https://example.okta.com/home/amazon_aws/example/1',
            'default_account': '123456789012', 'default_role': 'ReadOnly', 'allowed_roles': ['ReadOnly'],
            'OKTA_USERNAME': 'OKTA_USERNAME', 'OKTA_PASSWORD': 'OKTA_PASSWORD', 'OKTA_SECRET': 'OKTA_SECRET'}))
        fixture = root / 'fixture_entry.py'
        fixture.write_text('''import json
from pathlib import Path
import subprocess
import secretstore
class FixtureRunner:
    def run(self, args, *, env, timeout):
        values = json.loads((Path(__file__).parent / 'values.json').read_text())
        assert args[:2] == ['/usr/local/bin/op', 'item']
        if args[2] == 'list':
            result = [{'id': name, 'title': name} for name in values]
        elif args[2] == 'get':
            name = args[3]
            result = ({'type': 'SSHKEY', 'ssh_formats': {'openssh': {'value': values[name]}}}
                      if name == 'GIT_SIGNING_SSH_KEY' else {'value': values[name]})
        else:
            raise AssertionError('Unexpected provider operation')
        return subprocess.CompletedProcess(args, 0, json.dumps(result), '')
secretstore.DefaultCommandRunner = FixtureRunner
from entry import load, requestheaders, request, responseheaders
''')
        capability = secrets.token_hex(24)
        auth = root / 'auth'
        auth.write_text('secret-proxy:{SHA}' + base64.b64encode(hashlib.sha1(capability.encode()).digest()).decode())
        auth.chmod(0o600)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        state = root / 'ca'
        command, env = runtime.command(root, state, auth, port,
            {'op_token': 'offline-fixture-only', 'proxy_token': capability})
        command[-1] = str(fixture)
        command = [f'ssl_verify_upstream_trusted_ca={root / "server.pem"}'
                   if arg.startswith('ssl_verify_upstream_trusted_ca=') else arg for arg in command]
        proxy_auth = 'Basic ' + base64.b64encode(('secret-proxy:' + capability).encode()).decode()
        with (root / 'runtime.log').open('wb') as log:
            child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            try:
                runtime.wait_ready(child, port, capability, env['SECRET_PROXY_INSTANCE_ID'], state / 'mitmproxy-ca-cert.pem')
                context = ssl.create_default_context(cafile=str(state / 'mitmproxy-ca-cert.pem'))

                def request(method, path, headers=None, body=None, host='127.0.0.1', target_port=None):
                    connection = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=5)
                    connection.set_tunnel(host, target_port or server.server_port,
                                          {'Proxy-Authorization': proxy_auth})
                    try:
                        connection.request(method, path, body=body, headers=headers or {})
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()

                sentinel = 'secret' + 'ref.invalid'
                code, body = request('GET', '/chatgpt/status', host=sentinel, target_port=443)
                assert code == 200
                assert json.loads(body) == {'instance': env['SECRET_PROXY_INSTANCE_ID'], 'loggedIn': False,
                    'expiresAt': None, 'refreshCount': 0, 'lastRefreshAt': None, 'lastRefreshDueAt': None}
                unauthenticated = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                try:
                    unauthenticated.request('GET', 'http://' + sentinel + '/chatgpt/status')
                    assert unauthenticated.getresponse().status == 407
                finally:
                    unauthenticated.close()
                assert not observed  # Neither status request contacted an upstream.
                assert request('GET', '/check?key=' + REF + 'API_KEY', {'X-Api-Key': REF + 'API_KEY'}) == (200, b'ok')
                basic = 'Basic ' + base64.b64encode(('fixture:' + REF + 'API_KEY').encode()).decode()
                assert request('POST', '/check', {'Authorization': basic,
                    'Content-Type': 'application/x-www-form-urlencoded'}, urlencode({'key': REF + 'API_KEY'})) == (200, b'ok')
                before = len(observed)
                assert request('GET', '/denied', {'X-Api-Key': REF + 'API_KEY'})[0] == 403
                assert len(observed) == before  # Refused before any upstream call.

                # Negotiate HTTP/2 to the proxy, which downgrades to fixture H1.
                tunnel = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                tunnel.set_tunnel('127.0.0.1', server.server_port, {'Proxy-Authorization': proxy_auth})
                tunnel.connect()
                context.set_alpn_protocols(['h2'])
                with context.wrap_socket(tunnel.sock, server_hostname='127.0.0.1') as stream:
                    assert stream.selected_alpn_protocol() == 'h2'
                    protocol = h2.connection.H2Connection(config=h2.config.H2Configuration(header_encoding='utf-8'))
                    protocol.initiate_connection()
                    protocol.send_headers(1, [(':method', 'GET'), (':scheme', 'https'),
                        (':authority', f'127.0.0.1:{server.server_port}'), (':path', '/check'),
                        ('x-api-key', REF + 'API_KEY')], end_stream=True)
                    stream.sendall(protocol.data_to_send())
                    finished, body, status = False, b'', None
                    while not finished:
                        packet = stream.recv(65536)
                        assert packet, 'HTTP/2 closed early'
                        for event in protocol.receive_data(packet):
                            if isinstance(event, h2.events.ResponseReceived):
                                status = dict(event.headers)[':status']
                            elif isinstance(event, h2.events.DataReceived):
                                body += event.data
                            elif isinstance(event, h2.events.StreamEnded):
                                finished = True
                        pending = protocol.data_to_send()
                        if pending:
                            stream.sendall(pending)
                    assert status == '200' and body == b'ok'
                context.set_alpn_protocols(['http/1.1'])
                aws_checks(request, port, proxy_auth, context)
                payload = (b'tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n'
                    b'author Developer <developer@example.com> 1700000000 +0000\n'
                    b'committer Developer <developer@example.com> 1700000000 +0000\n\nfeat: fixture\n')
                status, signature = request('POST', '/git/sign', body=payload, host=SENTINEL, target_port=443)
                assert status == 200 and signature.decode() == gitsign.sign(values['GIT_SIGNING_SSH_KEY'], payload)
                assert b'PRIVATE KEY' not in signature
                assert observed == [True, True, True]
            finally:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                server.shutdown()
                server.server_close()
        output = (root / 'runtime.log').read_text()
        assert values['API_KEY'] not in output and values['GIT_SIGNING_SSH_KEY'] not in output
        assert 'AWS DENY 123456789012/ReadOnly secretsmanager:GetSecretValue' in output
        assert 'AWS DENY 123456789012/ReadOnly sts:AssumeRole' in output
        assert 'BODY-MARKER' not in output
        print('PASS: real TLS/H1/H2; authenticated credential-free status; header/query/form/basic injection; path refusal before upstream; AWS operation denial before minting (H1+H2); generated-key signing; no vault or external network')


def aws_auth(service):
    return ('AWS4-HMAC-SHA256 Credential=secret-proxy-dummy-akid-resigned-on-wire/20260101/'
            f'eu-west-1/{service}/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef')


def aws_headers(service, extra):
    return {'Authorization': aws_auth(service), 'x-amz-date': '20260101T000000Z',
            'x-amz-security-token': 'secretrole:123456789012/ReadOnly', **extra}


def h2_request(port, proxy_auth, context, host, headers, body):
    tunnel = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    tunnel.set_tunnel(host, 443, {'Proxy-Authorization': proxy_auth})
    tunnel.connect()
    context.set_alpn_protocols(['h2'])
    try:
        with context.wrap_socket(tunnel.sock, server_hostname=host) as stream:
            assert stream.selected_alpn_protocol() == 'h2'
            protocol = h2.connection.H2Connection(config=h2.config.H2Configuration(header_encoding='utf-8'))
            protocol.initiate_connection()
            protocol.send_headers(1, [(':method', 'POST'), (':scheme', 'https'), (':authority', host),
                                      (':path', '/')] + [(k.lower(), v) for k, v in headers.items()]
                                  + [('content-length', str(len(body)))])
            protocol.send_data(1, body, end_stream=True)
            stream.sendall(protocol.data_to_send())
            finished, data, status, response_headers = False, b'', None, {}
            while not finished:
                packet = stream.recv(65536)
                assert packet, 'HTTP/2 closed early'
                for event in protocol.receive_data(packet):
                    if isinstance(event, h2.events.ResponseReceived):
                        response_headers = dict(event.headers)
                        status = response_headers[':status']
                    elif isinstance(event, h2.events.DataReceived):
                        data += event.data
                    elif isinstance(event, h2.events.StreamEnded):
                        finished = True
                pending = protocol.data_to_send()
                if pending:
                    stream.sendall(pending)
            return status, response_headers, data
    finally:
        context.set_alpn_protocols(['http/1.1'])


def aws_checks(request, port, proxy_auth, context):
    """Denied AWS operations get 403 from the proxy over H1 and H2; nothing upstream."""
    status, body = request('POST', '/', aws_headers('secretsmanager', {
        'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': 'secretsmanager.GetSecretValue'}),
        b'{"SecretId":"BODY-MARKER"}', host='secretsmanager.eu-west-1.amazonaws.com', target_port=443)
    assert status == 403 and json.loads(body)['__type'] == 'AccessDeniedException', (status, body)
    assert b'BODY-MARKER' not in body
    status, headers, body = h2_request(port, proxy_auth, context, 'sts.amazonaws.com', aws_headers('sts', {
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'}),
        b'Action=AssumeRole&RoleSessionName=BODY-MARKER')
    assert status == '403' and b'<Code>AccessDeniedException</Code>' in body, (status, body)
    assert headers.get('x-amzn-errortype') == 'AccessDeniedException'
    # An allowed operation passes the policy and only then reaches credential
    # vending, which fails here because no Okta values exist.
    status, headers, body = h2_request(port, proxy_auth, context, 'sts.amazonaws.com', aws_headers('sts', {
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'}), b'Action=GetCallerIdentity')
    assert status in ('403', '502') and json.loads(body)['error'] == 'secret_proxy_aws_resign_failed', (status, body)


if __name__ == '__main__':
    main()
