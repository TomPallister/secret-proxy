"""Addon-level AWS operation policy tests — issue #1.

A denied AWS operation must get a 403 from the proxy, on both the buffered
(``request``) and streaming (``requestheaders``) paths and over HTTP/1.1 and
HTTP/2, without the creds provider being touched (so no STS credentials are
fetched or used). Allowed operations are still re-signed.
"""
import io
import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sigv4
from test_injection import AddonTestCase, FakeManifest, FakeResolver, make_flow

ACCOUNT = "123456789012"
AMZ_DATE = "20260101T000000Z"


def dummy_auth(service, region="eu-west-1", signed="host;x-amz-date"):
    scope = f"20260101/{region}/{service}/aws4_request"
    return sigv4.authorization_header("secret-proxy-dummy-akid-resigned-on-wire", scope, signed, "deadbeef")


class FakeProvider:
    """Records every interaction: a denied call must leave this empty."""

    def __init__(self):
        self.calls = []

    def default_target(self):
        self.calls.append(("default_target",))
        return ACCOUNT, "ReadOnly"

    def get_creds(self, account, role):
        self.calls.append(("get_creds", account, role))
        creds = {"AccessKeyId": "ASIAEXAMPLEFIXTURE00", "Expiration": ""}
        creds["SecretAccessKey"] = "fixture-signing-material-not-real"
        creds["SessionToken"] = "fixture-session-token"
        return creds


class AwsPolicyAddonTestCase(AddonTestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.policy_file = root / "aws-policy.json"
        self.okta_file = root / "aws-okta.json"
        for name, value in (("AWS_POLICY_FILE", self.policy_file), ("AWS_OKTA_FILE", self.okta_file)):
            patcher = patch.object(self.addon, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        cache = patch.object(self.addon, "_aws_policy_cache", None)
        cache.start()
        self.addCleanup(cache.stop)
        self.addon._manifest = FakeManifest({})
        self.addon._resolver = FakeResolver({})
        self.addon._manifest_mtime = -1
        self.provider = FakeProvider()
        self.provider_lookups = 0

        def get_provider():
            self.provider_lookups += 1
            return self.provider

        patcher = patch.object(self.addon, "_get_aws_provider", side_effect=get_provider)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.log = io.StringIO()
        handler = logging.StreamHandler(self.log)
        self.addon.log.addHandler(handler)
        self.addCleanup(self.addon.log.removeHandler, handler)

    # -- helpers -------------------------------------------------------------
    def aws_flow(self, host, service, *, path="/", method="POST", headers=None, content=b"",
                 role="ReadOnly", http2=False, sha256=None):
        all_headers = {
            "Authorization": dummy_auth(service),
            "x-amz-date": AMZ_DATE,
            "x-amz-security-token": f"secretrole:{ACCOUNT}/{role}",
        }
        if sha256 is not None:
            all_headers["x-amz-content-sha256"] = sha256
        all_headers.update(headers or {})
        flow = make_flow(host, path, method, headers=all_headers)
        flow.request.content = content
        if http2:
            flow.request.http_version = "HTTP/2.0"
            del flow.request.headers["Host"]  # the authority is :authority, not a header
        return flow

    def json_flow(self, service, target, body=b"{}", host=None, **kw):
        return self.aws_flow(host or f"{service}.eu-west-1.amazonaws.com", service,
                             headers={"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": target},
                             content=body, **kw)

    def query_flow(self, service, body, host=None, **kw):
        return self.aws_flow(host or f"{service}.amazonaws.com", service,
                             headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
                             content=body, **kw)

    def run_hooks(self, flow):
        self.addon.requestheaders(flow)
        if flow.response is None and not flow.request.stream:
            self.addon.request(flow)
        return flow

    def assertDenied(self, flow, label):
        self.assertIsNotNone(flow.response, label)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.response.headers.get("x-amzn-ErrorType"), "AccessDeniedException")
        self.assertIn(b"AccessDeniedException", flow.response.content)
        self.assertIn(b"secret-proxy blocked " + label.encode(), flow.response.content)
        self.assertEqual(self.provider.calls, [], "no STS credentials may be fetched")
        self.assertEqual(self.provider_lookups, 0, "the creds provider must not be consulted")
        self.assertTrue(flow.request.headers["Authorization"].startswith(
            "AWS4-HMAC-SHA256 Credential=secret-proxy-dummy-akid"))
        self.assertTrue(flow.request.headers["x-amz-security-token"].startswith("secretrole:"))

    def assertResigned(self, flow, label=None):
        self.assertIsNone(flow.response, flow.response and flow.response.content)
        self.assertIn(("get_creds", ACCOUNT, "ReadOnly"), self.provider.calls)
        self.assertIn("Credential=ASIAEXAMPLEFIXTURE00/", flow.request.headers["Authorization"])
        self.assertEqual(flow.request.headers["x-amz-security-token"], "fixture-session-token")
        if label:
            self.assertIn(label, self.log.getvalue())


class BufferedPathTests(AwsPolicyAddonTestCase):
    def deny_in_file(self, *rules):
        with open(self.policy_file, "w") as stream:
            json.dump({"version": 1, "rules": [
                {"action": "deny", "service": service, "operations": list(ops)} for service, *ops in rules]}, stream)

    def test_denied_operations_return_403_without_minting(self):
        cases = [
            (self.json_flow("secretsmanager", "secretsmanager.GetSecretValue"), "secretsmanager:GetSecretValue"),
            (self.json_flow("secretsmanager", "secretsmanager.BatchGetSecretValue"),
             "secretsmanager:BatchGetSecretValue"),
            (self.query_flow("secretsmanager", b"Action=GetSecretValue&SecretId=x"),
             "secretsmanager:GetSecretValue"),
        ]
        for flow, label in cases:
            with self.subTest(label=label):
                self.provider.calls.clear()
                self.provider_lookups = 0
                self.run_hooks(flow)
                self.assertDenied(flow, label)

    def test_operator_denies_from_the_policy_file_return_403_without_minting(self):
        self.deny_in_file(("sts", "Assume*"), ("lambda", "GetFunction*"), ("kms", "Decrypt"))
        cases = [
            (self.query_flow("sts", b"Action=AssumeRole&RoleArn=x&RoleSessionName=y"), "sts:AssumeRole"),
            (self.aws_flow("lambda.eu-west-1.amazonaws.com", "lambda", method="GET",
                           path="/2015-03-31/functions/fn/configuration"), "lambda:GetFunctionConfiguration"),
            (self.json_flow("kms", "TrentService.Decrypt"), "kms:Decrypt"),
        ]
        for flow, label in cases:
            with self.subTest(label=label):
                self.provider.calls.clear()
                self.provider_lookups = 0
                self.run_hooks(flow)
                self.assertDenied(flow, label)

    def test_former_defaults_are_now_allowed(self):
        for flow, label in (
            (self.query_flow("sts", b"Action=AssumeRole&RoleArn=x&RoleSessionName=y"), "sts:AssumeRole"),
            (self.aws_flow("lambda.eu-west-1.amazonaws.com", "lambda", method="GET",
                           path="/2015-03-31/functions/fn/configuration"), "lambda:GetFunctionConfiguration"),
            (self.json_flow("ssm", "AmazonSSM.GetParameter", b'{"Name":"p","WithDecryption":true}'),
             "ssm:GetParameter"),
        ):
            with self.subTest(label=label):
                self.provider.calls.clear()
                self.assertResigned(self.run_hooks(flow), label)

    def test_allowed_calls_are_resigned(self):
        flow = self.run_hooks(self.query_flow("sts", b"Action=GetCallerIdentity&Version=2011-06-15"))
        self.assertResigned(flow, "sts:GetCallerIdentity")
        self.provider.calls.clear()
        flow = self.run_hooks(self.json_flow("ssm", "AmazonSSM.GetParameter", b'{"Name":"p"}'))
        self.assertResigned(flow, "ssm:GetParameter")
        self.provider.calls.clear()
        flow = self.run_hooks(self.aws_flow("ec2.eu-west-1.amazonaws.com", "ec2", method="GET",
                                            path="/?Action=DescribeInstances&Version=2016-11-15"))
        self.assertResigned(flow, "ec2:DescribeInstances")

    def test_unknown_operation_is_denied(self):
        flow = self.json_flow("secretsmanager", "secretsmanager.GetSecretValue")
        flow.request.headers.add("X-Amz-Target", "secretsmanager.ListSecrets")
        self.run_hooks(flow)
        self.assertDenied(flow, "secretsmanager:Unknown")

    def test_oversized_query_body_is_unknown(self):
        import awsops
        body = b"Action=ListSecrets&pad=" + b"a" * (awsops.BODY_LIMIT + 1)
        flow = self.run_hooks(self.query_flow("secretsmanager", body))
        self.assertDenied(flow, "secretsmanager:Unknown")

    def test_query_error_is_xml_and_log_has_no_body(self):
        marker = "BODY-MARKER-MUST-NOT-BE-LOGGED"
        flow = self.run_hooks(self.query_flow("secretsmanager", f"Action=GetSecretValue&SecretId={marker}".encode()))
        self.assertDenied(flow, "secretsmanager:GetSecretValue")
        self.assertTrue(flow.response.content.startswith(b"<ErrorResponse>"))
        self.assertIn(b"<Code>AccessDeniedException</Code>", flow.response.content)
        log = self.log.getvalue()
        self.assertIn(f"AWS DENY {ACCOUNT}/ReadOnly secretsmanager:GetSecretValue", log)
        self.assertNotIn(marker, log)
        self.assertNotIn(marker.encode(), flow.response.content)

    def test_json_error_shape(self):
        flow = self.run_hooks(self.json_flow("secretsmanager", "secretsmanager.GetSecretValue"))
        body = json.loads(flow.response.content)
        self.assertEqual(body["__type"], "AccessDeniedException")
        self.assertIn("built-in deny list", body["message"])
        self.assertEqual(flow.response.headers["content-type"], "application/x-amz-json-1.1")

    def test_rpcv2_cbor_error_shape(self):
        with open(self.policy_file, "w") as stream:
            json.dump({"version": 1, "rules": [
                {"action": "deny", "service": "monitoring", "operations": ["GetMetricData"]}]}, stream)
        flow = self.aws_flow("monitoring.eu-west-1.amazonaws.com", "monitoring",
                             path="/service/GraniteServiceVersion20100801/operation/GetMetricData",
                             headers={"Smithy-Protocol": "rpc-v2-cbor", "Content-Type": "application/cbor"})
        self.run_hooks(flow)
        self.assertDenied(flow, "monitoring:GetMetricData")
        self.assertEqual(flow.response.content[0], 0xA2)
        self.assertEqual(flow.response.headers["smithy-protocol"], "rpc-v2-cbor")

    def test_signing_scope_must_match_the_inspected_scope(self):
        # Defence in depth: if the re-signer ever parsed a different service
        # than the policy inspected, the request is Unknown and denied.
        real = sigv4.parse_authorization
        def other_service(value):
            parsed = dict(real(value))
            parsed["service"] = "s3"
            return parsed
        flow = self.query_flow("sts", b"Action=GetCallerIdentity")
        with patch.object(sigv4, "parse_authorization", side_effect=other_service):
            self.run_hooks(flow)
        self.assertDenied(flow, "sts:Unknown")

    def test_scope_host_mismatch_is_denied(self):
        flow = self.aws_flow("secretsmanager.eu-west-1.amazonaws.com", "s3",
                             headers={"Content-Type": "application/x-amz-json-1.1",
                                      "X-Amz-Target": "secretsmanager.GetSecretValue"},
                             content=b"{}")
        self.run_hooks(flow)
        self.assertDenied(flow, "s3:Unknown")


class StreamingPathTests(AwsPolicyAddonTestCase):
    def test_s3_upload_streams_and_is_resigned(self):
        flow = self.aws_flow("bucket.s3.eu-west-1.amazonaws.com", "s3", method="PUT", path="/key",
                             sha256="UNSIGNED-PAYLOAD", headers={"Content-Type": "application/octet-stream"})
        flow.request.content = None
        self.addon.requestheaders(flow)
        self.assertTrue(flow.request.stream)
        self.assertResigned(flow, "s3:Unclassified")

    def test_chunked_upload_is_never_buffered(self):
        flow = self.aws_flow("bucket.s3.eu-west-1.amazonaws.com", "s3", method="PUT", path="/key",
                             sha256="STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
        flow.request.content = None
        self.addon.requestheaders(flow)
        self.assertTrue(callable(flow.request.stream))
        self.assertResigned(flow)

    def test_streaming_rest_denial_happens_before_minting(self):
        with open(self.policy_file, "w") as stream:
            json.dump({"version": 1, "rules": [
                {"action": "deny", "service": "lambda", "operations": ["GetFunction"]}]}, stream)
        flow = self.aws_flow("lambda.eu-west-1.amazonaws.com", "lambda", method="GET",
                             path="/2015-03-31/functions/fn", sha256="UNSIGNED-PAYLOAD")
        self.addon.requestheaders(flow)
        self.assertDenied(flow, "lambda:GetFunction")
        self.assertFalse(flow.request.stream)

    def test_body_dependent_operation_is_deferred_then_decided(self):
        # A content-sha256 header normally selects streaming; a body-named
        # operation is instead deferred to the buffered hook's bounded look.
        body = b"Action=GetSecretValue&SecretId=x"
        flow = self.query_flow("secretsmanager", body, sha256=sigv4.sha256_hex(body))
        self.addon.requestheaders(flow)
        self.assertIsNone(flow.response)
        self.assertFalse(flow.request.stream)
        self.assertEqual(self.provider_lookups, 0)
        self.addon.request(flow)
        self.assertDenied(flow, "secretsmanager:GetSecretValue")

        body = b"Action=ListSecrets"
        flow = self.query_flow("secretsmanager", body, sha256=sigv4.sha256_hex(body))
        self.run_hooks(flow)
        self.assertResigned(flow, "secretsmanager:ListSecrets")

    def test_already_streaming_body_cannot_be_inspected(self):
        flow = self.query_flow("secretsmanager", b"", sha256="UNSIGNED-PAYLOAD")
        flow.request.stream = True  # mitmproxy already streams it: body unavailable
        self.addon.requestheaders(flow)
        self.assertDenied(flow, "secretsmanager:Unknown")


class Http2Tests(AwsPolicyAddonTestCase):
    def test_http2_denied_and_allowed(self):
        flow = self.run_hooks(self.json_flow("secretsmanager", "secretsmanager.GetSecretValue", http2=True))
        self.assertDenied(flow, "secretsmanager:GetSecretValue")
        self.provider.calls.clear()
        flow = self.run_hooks(self.query_flow("sts", b"Action=GetCallerIdentity", host="sts.eu-west-1.amazonaws.com",
                                              http2=True))
        self.assertResigned(flow, "sts:GetCallerIdentity")
        self.assertIsNone(flow.request.headers.get("Host"))

    def test_http2_streaming_denial(self):
        with open(self.policy_file, "w") as stream:
            json.dump({"version": 1, "rules": [
                {"action": "deny", "service": "lambda", "operations": ["GetFunctionConfiguration"]}]}, stream)
        flow = self.aws_flow("lambda.eu-west-1.amazonaws.com", "lambda", method="GET",
                             path="/2015-03-31/functions/fn/configuration", sha256="UNSIGNED-PAYLOAD", http2=True)
        self.addon.requestheaders(flow)
        self.assertDenied(flow, "lambda:GetFunctionConfiguration")

    def test_service_is_checked_against_the_authority_not_the_host_header(self):
        flow = self.aws_flow("secretsmanager.eu-west-1.amazonaws.com", "sts",
                             headers={"Host": "sts.eu-west-1.amazonaws.com",
                                      "Content-Type": "application/x-www-form-urlencoded"},
                             content=b"Action=GetCallerIdentity")
        self.run_hooks(flow)
        self.assertDenied(flow, "sts:Unknown")


class OverrideAndPolicyFileTests(AwsPolicyAddonTestCase):
    def write_okta(self, overrides):
        config = {"default_account": ACCOUNT, "default_role": "ReadOnly", "operation_overrides": overrides}
        self.okta_file.write_text(json.dumps(config))

    def test_role_override_allows_only_the_named_role(self):
        self.write_okta([{"account": ACCOUNT, "role": "ReadOnly", "service": "secretsmanager",
                          "operations": ["GetSecretValue"]}])
        flow = self.run_hooks(self.json_flow("secretsmanager", "secretsmanager.GetSecretValue"))
        self.assertResigned(flow)
        self.assertIn("AWS ALLOW (override)", self.log.getvalue())
        self.provider.calls.clear()
        self.provider_lookups = 0
        flow = self.run_hooks(self.json_flow("secretsmanager", "secretsmanager.GetSecretValue", role="Admin"))
        self.assertDenied(flow, "secretsmanager:GetSecretValue")

    def test_override_never_mints_for_a_different_target(self):
        # The policy and the provider must agree on the target, or deny.
        self.write_okta([{"account": ACCOUNT, "role": "ReadOnly", "service": "secretsmanager",
                          "operations": ["GetSecretValue"]}])
        self.provider.default_target = lambda: (ACCOUNT, "Admin")
        flow = self.json_flow("secretsmanager", "secretsmanager.GetSecretValue")
        del flow.request.headers["x-amz-security-token"]
        self.run_hooks(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertNotIn("get_creds", [call[0] for call in self.provider.calls])

    def test_default_role_from_config_is_used_without_a_selector(self):
        self.write_okta([{"account": ACCOUNT, "role": "ReadOnly", "service": "secretsmanager",
                          "operations": ["GetSecretValue"]}])
        flow = self.json_flow("secretsmanager", "secretsmanager.GetSecretValue")
        del flow.request.headers["x-amz-security-token"]
        self.run_hooks(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(self.provider.calls[-1], ("get_creds", ACCOUNT, "ReadOnly"))

    def test_policy_file_rules_apply(self):
        self.policy_file.write_text(json.dumps({"version": 1, "rules": [
            {"action": "allow", "service": "ec2", "operations": ["Describe*"]}]}))
        flow = self.run_hooks(self.aws_flow("ec2.eu-west-1.amazonaws.com", "ec2", method="GET",
                                            path="/?Action=TerminateInstances&InstanceId.1=i-1"))
        self.assertDenied(flow, "ec2:TerminateInstances")

    def test_invalid_policy_at_runtime_denies_everything(self):
        self.policy_file.write_text('{"version": 1, "rules": [{"action": "approve"}]}')
        flow = self.run_hooks(self.query_flow("sts", b"Action=GetCallerIdentity"))
        self.assertDenied(flow, "Unknown:Unknown")
        self.assertIn("policy unavailable", self.log.getvalue())

    def test_startup_summary_lists_overrides(self):
        self.write_okta([{"account": ACCOUNT, "role": "Deployer", "service": "sts", "operations": ["AssumeRole"]}])
        lines = self.addon.aws_policy_startup_summary()
        self.assertTrue(any("OVERRIDE" in line and f"{ACCOUNT}/Deployer may call sts:AssumeRole" in line
                            for line in lines))

    def test_entry_load_refuses_invalid_policy(self):
        import entry
        from mitmproxy.exceptions import OptionsError
        self.policy_file.write_text('{"version": 1, "rules": [{"action": "deny", "service": "s3", '
                                    '"operations": ["Get[x]"]}]}')
        root = Path(__file__).parent
        with patch.object(self.addon, "SECRETS_FILE", root / "examples/manifest.json"):
            with self.assertRaises(OptionsError):
                entry.load(None)
        self.assertIn("aws-policy.json rule 1", self.log.getvalue())


class PresignedUnchangedTests(AwsPolicyAddonTestCase):
    def test_presigned_urls_keep_existing_behaviour(self):
        flow = make_flow("bucket.s3.eu-west-1.amazonaws.com", "/key", query={
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": "secret-proxy-dummy-akid/20260101/eu-west-1/s3/aws4_request",
            "X-Amz-Date": AMZ_DATE, "X-Amz-Expires": "60", "X-Amz-SignedHeaders": "host",
            "X-Amz-Signature": "deadbeef", "X-Amz-Security-Token": f"secretrole:{ACCOUNT}/ReadOnly",
        })
        self.addon.requestheaders(flow)
        self.assertIsNone(flow.response)
        self.assertIn(("get_creds", ACCOUNT, "ReadOnly"), self.provider.calls)


if __name__ == "__main__":
    unittest.main()
