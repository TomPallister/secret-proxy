"""AWS operation identification and policy (awsops.py) — issue #1.

Pure unit tests: no network, no credentials. Every protocol style, the default
deny list, ambiguous requests that must become Unknown, policy-file validation
and per-role overrides.
"""
import ast
import json
from pathlib import Path
import shutil
import subprocess
import unittest

import awsops
from awsops import AwsOperationPolicy, AwsPolicyError, AwsRequest, classify

ACCOUNT = "123456789012"
ROLE = "ReadOnly"


def auth(service, region="eu-west-1"):
    return ("Authorization",
            "AWS4-HMAC-SHA256 Credential=secret-proxy-dummy-akid/20260101/"
            f"{region}/{service}/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef")


def req(method, host, path="/", query="", headers=(), body=b"", service=None):
    service = service or host.split(".")[0]
    return AwsRequest(method, host, path, query, (auth(service),) + tuple(headers), body)


def json_req(service, target, body=b"{}", host=None, version="1.1", extra=()):
    host = host or f"{service}.eu-west-1.amazonaws.com"
    return req("POST", host, headers=(("Content-Type", f"application/x-amz-json-{version}"),
                                      ("X-Amz-Target", target)) + tuple(extra),
               body=body, service=service)


FORM = ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")


def query_req(service, body, host=None, extra=(), query=""):
    host = host or f"{service}.amazonaws.com"
    return req("POST", host, query=query, headers=(FORM,) + tuple(extra), body=body, service=service)


POLICY = AwsOperationPolicy()
# An operator who wants every unidentifiable request denied adds this rule.
STRICT = AwsOperationPolicy(awsops.parse_policy({"version": 1, "rules": [
    {"action": "deny", "service": "*", "operations": ["Unknown"]}]}))


def decide(request, account=ACCOUNT, role=ROLE, policy=POLICY):
    op = classify(request)
    return op, policy.evaluate(op, account, role)


class ProtocolDetectionTests(unittest.TestCase):
    def test_json_target(self):
        op = classify(json_req("secretsmanager", "secretsmanager.GetSecretValue"))
        self.assertEqual((op.service, op.operation, op.protocol), ("secretsmanager", "GetSecretValue", "json"))
        op = classify(json_req("kms", "TrentService.Decrypt", version="1.1"))
        self.assertEqual(op.label, "kms:Decrypt")
        op = classify(json_req("ecr", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken",
                               host="api.ecr.eu-west-1.amazonaws.com"))
        self.assertEqual(op.label, "ecr:GetAuthorizationToken")
        op = classify(json_req("dynamodb", "DynamoDB_20120810.GetItem", version="1.0"))
        self.assertEqual(op.label, "dynamodb:GetItem")

    def test_query_form_action(self):
        op = classify(query_req("sts", b"Action=AssumeRole&Version=2011-06-15&RoleArn=x"))
        self.assertEqual((op.label, op.protocol), ("sts:AssumeRole", "query"))
        op = classify(query_req("iam", b"Action=CreateAccessKey&Version=2010-05-08"))
        self.assertEqual(op.label, "iam:CreateAccessKey")

    def test_query_get_action(self):
        op = classify(req("GET", "ec2.eu-west-1.amazonaws.com",
                          query="Action=DescribeInstances&Version=2016-11-15", body=b""))
        self.assertEqual((op.label, op.protocol), ("ec2:DescribeInstances", "query"))
        op = classify(req("GET", "iam.amazonaws.com", query="Action=CreateAccessKey&Version=2010-05-08"))
        self.assertEqual(op.label, "iam:CreateAccessKey")

    def test_query_action_in_url_and_body_must_agree(self):
        op = classify(query_req("sts", b"Action=GetCallerIdentity", query="Action=GetCallerIdentity"))
        self.assertEqual(op.label, "sts:GetCallerIdentity")
        op = classify(query_req("sts", b"Action=GetCallerIdentity", query="Action=AssumeRole"))
        self.assertEqual(op.operation, "Unknown")

    def test_rpcv2_path(self):
        for proto in ("rpc-v2-cbor", "rpc-v2-json"):
            op = classify(req("POST", "monitoring.eu-west-1.amazonaws.com",
                              "/service/GraniteServiceVersion20100801/operation/GetMetricData",
                              headers=(("Smithy-Protocol", proto),)))
            self.assertEqual((op.label, op.protocol), ("monitoring:GetMetricData", "rpcv2"))
        op = classify(req("POST", "example-svc.eu-west-1.amazonaws.com",
                          "/prefix/service/Svc/operation/GetSecret", headers=(("Smithy-Protocol", "rpc-v2-cbor"),),
                          service="example-svc"))
        self.assertEqual(op.operation, "GetSecret")

    def test_rest_lambda_paths(self):
        cases = {
            "/2015-03-31/functions/my-fn": "GetFunction",
            "/2015-03-31/functions/my-fn/": "GetFunction",
            "/2015-03-31/functions/arn%3Aaws%3Alambda%3Aeu-west-1%3A123456789012%3Afunction%3Amy-fn": "GetFunction",
            "/2015-03-31/functions/my-fn/configuration": "GetFunctionConfiguration",
            "/2015-03-31/Functions/my-fn/Configuration": "GetFunctionConfiguration",
            "/2015-03-31/functions/": "ListFunctions",
            "/2015-03-31/functions/my-fn/versions": "ListVersionsByFunction",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                op = classify(req("GET", "lambda.eu-west-1.amazonaws.com", path))
                self.assertEqual((op.operation, op.protocol), (expected, "rest"))
        op = classify(req("POST", "lambda.eu-west-1.amazonaws.com", "/2015-03-31/functions/my-fn/invocations"))
        self.assertEqual(op.operation, "Unclassified")

    def test_rest_codeartifact_and_s3(self):
        op = classify(req("POST", "codeartifact.eu-west-1.amazonaws.com", "/v1/authorization-token",
                          query="domain=example&domain-owner=123456789012"))
        self.assertEqual(op.label, "codeartifact:GetAuthorizationToken")
        op = classify(req("GET", "bucket.s3.eu-west-1.amazonaws.com", "/a//b/../c", body=None, service="s3"))
        self.assertEqual(op.label, "s3:Unclassified")
        op = classify(req("PUT", "bucket.s3.eu-west-1.amazonaws.com", "/key",
                          headers=(("Content-Type", "application/x-www-form-urlencoded"),), body=None, service="s3"))
        self.assertEqual(op.label, "s3:Unclassified")
        self.assertFalse(op.needs_body)


class UnknownTests(unittest.TestCase):
    def assertUnknown(self, request, service=None):
        op = classify(request)
        self.assertEqual(op.operation, "Unknown", op)
        if service:
            self.assertEqual(op.service, service)
        self.assertEqual(STRICT.evaluate(op, ACCOUNT, ROLE).action, "deny")
        expected = "deny" if op.service == "secretsmanager" or "unverified-service" in op.conditions else "allow"
        self.assertEqual(POLICY.evaluate(op, ACCOUNT, ROLE).action, expected, op)
        return op

    def test_duplicate_and_malformed_target(self):
        base = json_req("secretsmanager", "secretsmanager.ListSecrets")
        self.assertUnknown(AwsRequest(base.method, base.host, base.path, base.query,
                                      base.headers + (("X-Amz-Target", "secretsmanager.ListSecrets"),), base.body))
        for target in ("GetSecretValue", "secretsmanager.", "a.b c", "secretsmanager.Get-Secret", "x.y,z.w"):
            with self.subTest(target=target):
                self.assertUnknown(json_req("secretsmanager", target))

    def test_json_without_target(self):
        self.assertUnknown(req("POST", "secretsmanager.eu-west-1.amazonaws.com",
                               headers=(("Content-Type", "application/x-amz-json-1.1"),), body=b"{}"))

    def test_conflicting_actions_and_bad_actions(self):
        self.assertUnknown(query_req("sts", b"Action=GetCallerIdentity&Action=AssumeRole"))
        self.assertUnknown(query_req("sts", b"Action=GetCallerIdentity&action=AssumeRole"))
        self.assertUnknown(query_req("sts", b"Action=GetCallerIdentity;Action=AssumeRole"))
        self.assertUnknown(query_req("sts", b"Version=2011-06-15"))  # no Action
        self.assertUnknown(query_req("sts", b"Action="))

    def test_more_than_one_protocol(self):
        self.assertUnknown(AwsRequest(
            "POST", "sts.amazonaws.com", "/", "Action=AssumeRole",
            (auth("sts"), ("Content-Type", "application/x-amz-json-1.1"),
             ("X-Amz-Target", "AWSSecurityTokenServiceV20110615.GetCallerIdentity")), b"{}"))
        self.assertUnknown(AwsRequest(
            "POST", "sts.amazonaws.com", "/", "",
            (auth("sts"), FORM, ("X-Amz-Target", "AWSSecurityTokenServiceV20110615.GetCallerIdentity")),
            b"Action=AssumeRole"))
        op = self.assertUnknown(req("GET", "lambda.eu-west-1.amazonaws.com", "/2015-03-31/functions/fn",
                                    headers=(("X-Amz-Target", "lambda.ListLayers"),)))
        self.assertEqual(op.reason, "operation fields of more than one protocol")
        self.assertUnknown(req("GET", "lambda.eu-west-1.amazonaws.com", "/2015-03-31/functions/fn",
                               query="Action=ListLayers"))
        self.assertUnknown(req("POST", "monitoring.eu-west-1.amazonaws.com",
                               "/service/S/operation/GetMetricData", query="Action=ListMetrics",
                               headers=(("Smithy-Protocol", "rpc-v2-cbor"),)))

    def test_query_body_encoding_charset_size_and_availability(self):
        self.assertUnknown(query_req("sts", b"Action=GetCallerIdentity", extra=(("Content-Encoding", "gzip"),)))
        latin = req("POST", "sts.amazonaws.com",
                    headers=(("Content-Type", "application/x-www-form-urlencoded; charset=iso-8859-1"),),
                    body=b"Action=GetCallerIdentity")
        self.assertUnknown(latin)
        self.assertUnknown(query_req("sts", b"Action=GetCallerIdentity&x=\xff"))
        self.assertUnknown(query_req("sts", b"Action=GetCallerIdentity&x=%FF"))
        big = b"Action=GetCallerIdentity&pad=" + b"a" * awsops.BODY_LIMIT
        self.assertUnknown(query_req("sts", big))
        missing = self.assertUnknown(query_req("sts", None))
        self.assertTrue(missing.needs_body)

    def test_rpcv2_header_without_valid_path_and_bad_headers(self):
        host = "monitoring.eu-west-1.amazonaws.com"
        self.assertUnknown(req("POST", host, "/", headers=(("Smithy-Protocol", "rpc-v2-cbor"),)))
        self.assertUnknown(req("POST", host, "/service/S/operation/GetMetricData",
                               headers=(("Smithy-Protocol", "rpc-v2-cbor"), ("Smithy-Protocol", "rpc-v2-cbor"))))
        self.assertUnknown(req("POST", host, "/service/S/operation/GetMetricData",
                               headers=(("Smithy-Protocol", "rpc-v3"),)))
        self.assertUnknown(req("POST", host, "/service/S/operation/Get%2FMetricData",
                               headers=(("Smithy-Protocol", "rpc-v2-cbor"),)))

    def test_ambiguous_rest_paths_for_operation_tables(self):
        for path in ("/2015-03-31//functions/fn", "/2015-03-31/functions/fn%2Fconfiguration",
                     "/2015-03-31/functions/../functions/fn", "/2015-03-31/functions/%ff",
                     "/2015-03-31/functions/./fn"):
            with self.subTest(path=path):
                self.assertUnknown(req("GET", "lambda.eu-west-1.amazonaws.com", path))

    def test_operation_required_services_without_operation(self):
        self.assertUnknown(req("GET", "sts.amazonaws.com", "/"), "sts")
        self.assertUnknown(req("POST", "secretsmanager.eu-west-1.amazonaws.com", body=b"{}"), "secretsmanager")
        self.assertUnknown(req("POST", "iam.amazonaws.com", headers=(("Content-Type", "text/plain"),),
                               body=b"Action=CreateAccessKey"), "iam")

    def test_scope_and_host(self):
        # Scope says s3, host is Secrets Manager: never evaluated as s3.
        self.assertUnknown(req("POST", "secretsmanager.eu-west-1.amazonaws.com",
                               headers=(("X-Amz-Target", "secretsmanager.GetSecretValue"),), service="s3"), "s3")
        bad_auth = (
            "AWS4-HMAC-SHA256 dummy",
            "AWS4-HMAC-SHA256 Credential=a/20260101/eu-west-1/sts/aws4_request, SignedHeaders=host, "
            "Signature=x, Credential=a/20260101/eu-west-1/s3/aws4_request",
            "AWS4-HMAC-SHA256 Credential=a/20260101/eu-west-1/sts/other, SignedHeaders=host, Signature=x",
            "AWS4-HMAC-SHA256 Credential=a/2026/eu-west-1/sts/aws4_request, SignedHeaders=host, Signature=x",
            "AWS4-HMAC-SHA256 Credential=a/20260101/eu-west-1/STS/aws4_request, SignedHeaders=host, Signature=x",
        )
        for value in bad_auth:
            with self.subTest(value=value):
                self.assertUnknown(AwsRequest("POST", "sts.amazonaws.com", "/", "",
                                              (("Authorization", value), FORM), b"Action=GetCallerIdentity"))
        twice = AwsRequest("POST", "sts.amazonaws.com", "/", "", (auth("sts"), auth("sts"), FORM),
                           b"Action=GetCallerIdentity")
        self.assertUnknown(twice)
        self.assertUnknown(AwsRequest("POST", "sts.amazonaws.com", "/", "", (FORM,), b"Action=GetCallerIdentity"))

    def test_service_host_consistency(self):
        good = [("bedrock", "bedrock-runtime.eu-west-1.amazonaws.com"), ("ses", "email.eu-west-1.amazonaws.com"),
                ("sts", "sts-fips.us-east-1.amazonaws.com"), ("s3", "bucket.s3.amazonaws.com"),
                ("s3", "123456789012.s3-control.eu-west-1.amazonaws.com"), ("execute-api", "x.execute-api.eu-west-1.amazonaws.com"),
                ("lex", "runtime-v2-lex.eu-west-1.amazonaws.com"), ("sqs", "queue.amazonaws.com"),
                ("secretsmanager", "vpce-1.secretsmanager.eu-west-1.vpce.amazonaws.com"),
                ("sts", "sts.amazonaws.com.")]
        for service, host in good:
            with self.subTest(host=host):
                self.assertTrue(awsops.service_matches_host(service, host))
        bad = [("s3", "secretsmanager.eu-west-1.amazonaws.com"), ("sts", "sts.amazonaws.com.example.com"),
               ("sts", "amazonaws.com"), ("eu", "sts.eu-west-1.example.com"), ("secrets", "secretsmanager.amazonaws.com")]
        for service, host in bad:
            with self.subTest(host=host):
                self.assertFalse(awsops.service_matches_host(service, host))


class DefaultDenyListTests(unittest.TestCase):
    """Only Secrets Manager reads of stored values are denied by default."""

    def test_secrets_manager_reads_are_denied(self):
        cases = [
            json_req("secretsmanager", "secretsmanager.GetSecretValue"),
            json_req("secretsmanager", "secretsmanager.BatchGetSecretValue"),
            json_req("secretsmanager", "secretsmanager.getsecretvalue"),  # case-insensitive
            json_req("secretsmanager", "secretsmanager.GetSecretValue",
                     host="secretsmanager-fips.us-east-1.amazonaws.com"),
            query_req("secretsmanager", b"Action=GetSecretValue&SecretId=x"),
            req("POST", "secretsmanager.eu-west-1.amazonaws.com", "/service/secretsmanager/operation/GetSecretValue",
                headers=(("Smithy-Protocol", "rpc-v2-cbor"),)),
        ]
        for request in cases:
            with self.subTest(request=request.headers[-1:], host=request.host, path=request.path):
                op, decision = decide(request)
                self.assertEqual(decision.action, "deny", op)
                self.assertIn("credentials or secret values", decision.reason)

    def test_unidentifiable_secrets_manager_requests_are_denied(self):
        cases = [
            json_req("secretsmanager", "secretsmanager.GetSecretValue",
                     extra=(("X-Amz-Target", "secretsmanager.ListSecrets"),)),  # duplicate target
            req("POST", "secretsmanager.eu-west-1.amazonaws.com", "/", body=b"{}",
                headers=(("Content-Type", "application/x-amz-json-1.1"),)),  # no target
            query_req("secretsmanager", b"Action=ListSecrets&Action=GetSecretValue"),
        ]
        for request in cases:
            with self.subTest(request=request.headers[-2:]):
                op, decision = decide(request)
                self.assertEqual((op.operation, decision.action), ("Unknown", "deny"), op)

    def test_unverifiable_target_service_is_denied_for_every_service(self):
        # A credential scope that does not match the host could aim the proxy's
        # signature at another service, so it stays denied whatever the service.
        for service, host in (("sts", "secretsmanager.eu-west-1.amazonaws.com"),
                              ("s3", "ec2.eu-west-1.amazonaws.com")):
            with self.subTest(service=service):
                op, decision = decide(req("POST", host, "/", service=service))
                self.assertEqual((op.operation, decision.action), ("Unknown", "deny"), op)

    def test_everything_else_is_allowed(self):
        cases = [
            query_req("sts", b"Action=GetCallerIdentity&Version=2011-06-15"),
            query_req("sts", b"Action=GetAccessKeyInfo&AccessKeyId=x"),
            query_req("sts", b"Action=AssumeRole&RoleArn=x&RoleSessionName=y"),
            query_req("sts", b"Action=GetSessionToken"),
            req("GET", "bucket.s3.eu-west-1.amazonaws.com", "/", query="list-type=2", service="s3"),
            req("PUT", "bucket.s3.eu-west-1.amazonaws.com", "/key", body=None, service="s3"),
            json_req("ssm", "AmazonSSM.GetParameter", b'{"Name":"x"}'),
            json_req("ssm", "AmazonSSM.GetParameter", b'{"Name":"x","WithDecryption":true}'),
            json_req("secretsmanager", "secretsmanager.ListSecrets"),
            json_req("secretsmanager", "secretsmanager.DescribeSecret"),
            query_req("iam", b"Action=CreateAccessKey&Version=2010-05-08"),
            json_req("ecr", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken",
                     host="api.ecr.eu-west-1.amazonaws.com"),
            req("GET", "ec2.eu-west-1.amazonaws.com", query="Action=DescribeInstances"),
            json_req("dynamodb", "DynamoDB_20120810.DescribeTable", version="1.0"),
            json_req("kms", "TrentService.Decrypt"),
            req("GET", "lambda.eu-west-1.amazonaws.com", "/2015-03-31/functions/fn"),
            req("GET", "lambda.eu-west-1.amazonaws.com", "/2015-03-31/functions/fn/configuration"),
            req("GET", "lambda.eu-west-1.amazonaws.com", "/2015-03-31/functions/"),
            req("POST", "lambda.eu-west-1.amazonaws.com", "/2015-03-31/functions/fn/invocations"),
        ]
        for request in cases:
            with self.subTest(path=request.path, headers=request.headers[-1:]):
                op, decision = decide(request)
                self.assertEqual(decision.action, "allow", (op, decision))

    def test_operators_can_add_their_own_denies(self):
        policy = AwsOperationPolicy(awsops.parse_policy({"version": 1, "rules": [
            {"action": "deny", "service": "sts", "operations": ["Assume*", "Get*Token", "Unknown"]},
            {"action": "deny", "service": "lambda", "operations": ["GetFunction*"]}]}))
        for request, action in ((query_req("sts", b"Action=AssumeRole"), "deny"),
                                (query_req("sts", b"Action=GetCallerIdentity"), "allow"),
                                (req("GET", "lambda.eu-west-1.amazonaws.com", "/2015-03-31/functions/fn"), "deny")):
            with self.subTest(path=request.path, body=request.body):
                self.assertEqual(policy.evaluate(classify(request), ACCOUNT, ROLE).action, action)


class SsmDecryptionTests(unittest.TestCase):
    def assertDecrypting(self, body, expected, protocol="json"):
        if protocol == "json":
            request = json_req("ssm", "AmazonSSM.GetParameter", body)
        else:
            request = query_req("ssm", body, host="ssm.eu-west-1.amazonaws.com")
        op = classify(request)
        self.assertEqual("with-decryption" in op.conditions, expected, (body, op))

    def test_with_decryption_values(self):
        self.assertDecrypting(b'{"Name":"x"}', False)
        self.assertDecrypting(b'{"Name":"x","WithDecryption":false}', False)
        self.assertDecrypting(b'{"Name":"x","WithDecryption":true}', True)
        self.assertDecrypting(b'{"Name":"x","WithDecryption":"true"}', True)
        self.assertDecrypting(b'{"Name":"x","WithDecryption":"false"}', True)  # not a boolean
        self.assertDecrypting(b'{"Name":"x","WithDecryption":null}', True)
        self.assertDecrypting(b'{"Name":"x","withdecryption":true}', True)
        self.assertDecrypting(b'{"WithDecryption":false,"WithDecryption":true}', True)
        self.assertDecrypting(b'{"WithDecryption":false,"withDecryption":true}', True)
        self.assertDecrypting(b'{"Name":"x"', True)
        self.assertDecrypting(b'[]', True)
        self.assertDecrypting(b'\xff', True)
        self.assertDecrypting(b'{"Name":"' + b"a" * awsops.BODY_LIMIT + b'"}', True)

    def test_unavailable_or_encoded_body_is_decrypting(self):
        op = classify(json_req("ssm", "AmazonSSM.GetParameters", None))
        self.assertIn("with-decryption", op.conditions)
        self.assertTrue(op.needs_body)
        op = classify(json_req("ssm", "AmazonSSM.GetParameters", b'{"Names":["x"]}',
                               extra=(("Content-Encoding", "gzip"),)))
        self.assertIn("with-decryption", op.conditions)

    def test_query_protocol_flag(self):
        self.assertDecrypting(b"Action=GetParameter&Name=x", False, "query")
        self.assertDecrypting(b"Action=GetParameter&Name=x&WithDecryption=false", False, "query")
        self.assertDecrypting(b"Action=GetParameter&Name=x&WithDecryption=true", True, "query")
        self.assertDecrypting(b"Action=GetParameter&WithDecryption=false&withdecryption=1", True, "query")

    def test_other_ssm_operations_have_no_condition(self):
        op = classify(json_req("ssm", "AmazonSSM.DescribeParameters", None))
        self.assertEqual(op.conditions, frozenset())
        self.assertFalse(op.needs_body)


class PolicyFileTests(unittest.TestCase):
    def policy(self, rules, overrides=()):
        document = json.dumps({"version": 1, "rules": rules}).encode()
        return AwsOperationPolicy(awsops.load_policy_bytes(document), awsops.parse_overrides(list(overrides)))

    def test_file_deny_and_allow_list(self):
        policy = self.policy([
            {"action": "deny", "service": "dynamodb", "operations": ["Scan", "Batch*"], "comment": "no bulk reads"},
            {"action": "allow", "service": "ec2", "operations": ["Describe*"]},
        ])
        _op, decision = decide(json_req("dynamodb", "DynamoDB_20120810.Scan", version="1.0"), policy=policy)
        self.assertEqual(decision.action, "deny")
        self.assertIn("aws-policy.json rule 1", decision.reason)
        _op, decision = decide(req("GET", "ec2.eu-west-1.amazonaws.com", query="Action=DescribeVpcs"), policy=policy)
        self.assertEqual(decision.action, "allow")
        _op, decision = decide(req("GET", "ec2.eu-west-1.amazonaws.com", query="Action=TerminateInstances"),
                               policy=policy)
        self.assertEqual(decision.action, "deny")
        self.assertIn("allow list", decision.reason)
        _op, decision = decide(query_req("sts", b"Action=GetCallerIdentity"), policy=policy)
        self.assertEqual(decision.action, "allow")

    def test_file_cannot_remove_or_allow_the_built_in_deny_list(self):
        policy = self.policy([{"action": "allow", "service": "secretsmanager", "operations": ["*"]}])
        _op, decision = decide(json_req("secretsmanager", "secretsmanager.GetSecretValue"), policy=policy)
        self.assertEqual(decision.action, "deny")
        _op, decision = decide(json_req("secretsmanager", "secretsmanager.ListSecrets"), policy=policy)
        self.assertEqual(decision.action, "allow")

    def test_invalid_documents_fail(self):
        good_rule = {"action": "deny", "service": "s3", "operations": ["DeleteBucket"]}
        bad = [
            b"[]", b"{", b"\xff", b'{"version": 2, "rules": []}', b'{"version": true, "rules": []}',
            b'{"rules": []}', b'{"version": 1, "rules": {}}', b'{"version": 1, "rules": [], "extra": 1}',
            b'{"version": 1, "version": 1, "rules": []}',
        ]
        rule_mutations = [
            {**good_rule, "action": "approved"}, {**good_rule, "action": "Allow"},
            {**good_rule, "service": "S3"}, {**good_rule, "service": "s3.x"}, {**good_rule, "service": ""},
            {**good_rule, "operations": []}, {**good_rule, "operations": "DeleteBucket"},
            {**good_rule, "operations": ["Delete[Bucket]"]}, {**good_rule, "operations": ["a.b"]},
            {**good_rule, "operations": [""]}, {**good_rule, "operations": [1]},
            {**good_rule, "extra": True}, {**good_rule, "comment": 1},
            {"action": "deny", "service": "s3"}, "deny s3:*",
        ]
        for rule in rule_mutations:
            bad.append(json.dumps({"version": 1, "rules": [rule]}).encode())
        for document in bad:
            with self.subTest(document=document[:80]), self.assertRaises(AwsPolicyError):
                awsops.load_policy_bytes(document)
        self.assertEqual(len(awsops.load_policy_bytes(b'{"version": 1}')), 0)

    def test_example_policy_is_valid(self):
        path = Path(__file__).parent / "examples" / "aws-policy.json"
        rules = awsops.load_policy_bytes(path.read_bytes())
        self.assertTrue(rules)


class OverrideTests(unittest.TestCase):
    OVERRIDE = {"account": ACCOUNT, "role": "Deployer", "service": "secretsmanager",
                "operations": ["GetSecretValue"], "comment": "deploy tooling"}

    def test_exact_role_override_allows_only_that_role(self):
        policy = AwsOperationPolicy((), awsops.parse_overrides([self.OVERRIDE]))
        request = json_req("secretsmanager", "secretsmanager.GetSecretValue")
        decision = policy.evaluate(classify(request), ACCOUNT, "Deployer")
        self.assertEqual((decision.action, decision.overridden), ("allow", True))
        for account, role in ((ACCOUNT, "ReadOnly"), ("111122223333", "Deployer"), (None, None), (ACCOUNT, None)):
            with self.subTest(account=account, role=role):
                self.assertEqual(policy.evaluate(classify(request), account, role).action, "deny")
        other = json_req("secretsmanager", "secretsmanager.BatchGetSecretValue")
        self.assertEqual(policy.evaluate(classify(other), ACCOUNT, "Deployer").action, "deny")

    def test_override_also_covers_allow_lists_and_unknown(self):
        rules = awsops.load_policy_bytes(json.dumps({"version": 1, "rules": [
            {"action": "allow", "service": "ec2", "operations": ["Describe*"]}]}).encode())
        overrides = awsops.parse_overrides([
            {"account": ACCOUNT, "role": "Ops", "service": "ec2", "operations": ["StopInstances"]},
            {"account": ACCOUNT, "role": "Ops", "service": "iot-jobs-data", "operations": ["Unknown"]},
        ])
        policy = AwsOperationPolicy(rules, overrides)
        stop = classify(req("GET", "ec2.eu-west-1.amazonaws.com", query="Action=StopInstances"))
        self.assertEqual(policy.evaluate(stop, ACCOUNT, "Ops").action, "allow")
        self.assertEqual(policy.evaluate(stop, ACCOUNT, "Other").action, "deny")
        unknown = awsops.AwsOperation("iot-jobs-data", "Unknown", "unknown", "x")
        self.assertEqual(policy.evaluate(unknown, ACCOUNT, "Ops").action, "allow")

    def test_invalid_overrides(self):
        bad = [
            {}, {**self.OVERRIDE, "account": "1234"}, {**self.OVERRIDE, "account": "*"},
            {**self.OVERRIDE, "role": "a/b"}, {**self.OVERRIDE, "role": "*"},
            {**self.OVERRIDE, "service": "*"}, {**self.OVERRIDE, "service": "Secrets"},
            {**self.OVERRIDE, "operations": []}, {**self.OVERRIDE, "operations": ["Get[x]"]},
            {**self.OVERRIDE, "extra": 1}, {**self.OVERRIDE, "comment": []}, "x",
        ]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(AwsPolicyError):
                awsops.parse_overrides([item])
        with self.assertRaises(AwsPolicyError):
            awsops.parse_overrides({"x": 1})


class CompatibilityTests(unittest.TestCase):
    def test_source_parses_as_python_3_9(self):
        source = (Path(__file__).parent / "awsops.py").read_text()
        ast.parse(source, feature_version=(3, 9))

    def test_runs_under_command_line_tools_python_when_present(self):
        python = "/Library/Developer/CommandLineTools/usr/bin/python3"
        if not Path(python).exists() or shutil.which(python) is None:
            self.skipTest("macOS Command Line Tools Python not installed")
        script = (
            "import awsops\n"
            "r=awsops.AwsRequest('POST','secretsmanager.us-east-1.amazonaws.com','/','',(('Authorization',"
            "'AWS4-HMAC-SHA256 Credential=a/20260101/us-east-1/secretsmanager/aws4_request, SignedHeaders=host, Signature=x'),"
            "('X-Amz-Target','secretsmanager.GetSecretValue')),b'{}')\n"
            "print(awsops.AwsOperationPolicy().evaluate(awsops.classify(r)).action)\n"
        )
        result = subprocess.run([python, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); exec(sys.argv[2])",
                                 str(Path(__file__).parent), script],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "deny")



class ConfigurationValidationTests(unittest.TestCase):
    """aws-policy.json and operation_overrides are validated wherever config is accepted."""

    OKTA = dict(okta_hosts=["example.okta.com"], default_app_url="https://example.okta.com/home/amazon_aws/example/1",
                default_account=ACCOUNT, default_role="ReadOnly", allowed_roles=["ReadOnly"],
                OKTA_USERNAME="OKTA_USERNAME", OKTA_PASSWORD="OKTA_PASSWORD", OKTA_SECRET="OKTA_SECRET")

    def test_aws_okta_operation_overrides_are_strict(self):
        from awscreds import AwsCredsError, AwsCredsProvider
        AwsCredsProvider._validate_config(self.OKTA)  # absent: unchanged behaviour
        good = {"account": ACCOUNT, "role": "ReadOnly", "service": "sts", "operations": ["AssumeRole"]}
        AwsCredsProvider._validate_config({**self.OKTA, "operation_overrides": [good]})
        for bad in ([{**good, "role": "*"}], {"x": 1}, [good, {**good, "operations": ["a b"]}]):
            with self.subTest(bad=bad), self.assertRaises(AwsCredsError):
                AwsCredsProvider._validate_config({**self.OKTA, "operation_overrides": bad})

    def test_runtime_rejects_invalid_policy_file(self):
        import tempfile
        import runtime
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp)
            runtime.validate_aws_policy(config)  # absent file: fine
            (config / "aws-policy.json").write_text('{"version": 1, "rules": []}')
            runtime.validate_aws_policy(config)
            (config / "aws-policy.json").write_text('{"version": 1, "rules": [{"action": "allow"}]}')
            with self.assertRaises(AwsPolicyError):
                runtime.validate_aws_policy(config)

    def test_installer_accepts_and_validates_policy_file(self):
        import tempfile
        import macos_install
        from host import HostError
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            (source / "manifest.json").write_text(json.dumps(
                {"schemaVersion": 3, "account": {"vault": "Fixture"}, "secrets": {}}))
            self.assertNotIn("aws-policy.json", macos_install.validate_source_config(source))
            policy = (Path(__file__).parent / "examples" / "aws-policy.json").read_bytes()
            (source / "aws-policy.json").write_bytes(policy)
            self.assertEqual(macos_install.validate_source_config(source)["aws-policy.json"], policy)
            self.assertIn("aws-policy.json", macos_install.POLICY_FILES)
            (source / "aws-policy.json").write_text('{"version": 1, "rules": [], "extra": true}')
            with self.assertRaisesRegex(HostError, "Invalid AWS operation policy"):
                macos_install.validate_source_config(source)
            (source / "aws-policy.json").unlink()
            (source / "aws-policy.txt").write_text("{}")
            with self.assertRaisesRegex(HostError, "Unexpected"):
                macos_install.validate_source_config(source)

    def test_module_ships_in_every_file_list(self):
        import host
        import macos_install
        root = Path(__file__).parent
        self.assertIn("awsops.py", host.BUILD_FILES)
        self.assertIn("awsops.py", macos_install.FILES)
        copy = next(line for line in (root / "Dockerfile").read_text().splitlines()
                    if line.startswith("COPY addon.py"))
        self.assertIn(" awsops.py ", copy)


if __name__ == "__main__":
    unittest.main()
