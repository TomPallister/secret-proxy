"""Credential-minting regressions: synthetic requests only, no provider access."""
import unittest
from urllib.parse import urlencode

from test_awsops_addon import AwsPolicyAddonTestCase, ACCOUNT, AMZ_DATE

# Explicit expectations, not derived from the implementation's deny list.
MINTS = {
    "sts": ("AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
            "GetSessionToken", "GetFederationToken", "GetServiceBearerToken"),
    "iam": ("CreateAccessKey", "CreateServiceSpecificCredential", "ResetServiceSpecificCredential"),
    "ecr": ("GetAuthorizationToken",),
    "ecr-public": ("GetAuthorizationToken",),
    "cognito-identity": ("GetCredentialsForIdentity", "GetOpenIdToken", "GetOpenIdTokenForDeveloperIdentity"),
}


class CredentialMintTests(AwsPolicyAddonTestCase):
    def test_mints_denied_in_both_hooks_and_protocol_versions(self):
        for http2 in (False, True):
            for service, operations in MINTS.items():
                for operation in operations:
                    for streaming in (False, True):
                        with self.subTest(service=service, operation=operation, http2=http2, streaming=streaming):
                            self.provider.calls.clear()
                            self.provider_lookups = 0
                            if service in ("sts", "iam"):
                                flow = self.query_flow(service, ("Action=" + operation).encode(), http2=http2)
                            else:
                                flow = self.json_flow(service, "Fixture." + operation, http2=http2)
                            if streaming:
                                flow.request.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
                            self.assertDenied(self.run_hooks(flow), service + ":" + operation)

    def test_query_get_and_ambiguous_operations_fail_closed(self):
        for service in MINTS:
            with self.subTest(service=service):
                self.assertDenied(self.run_hooks(self.aws_flow(
                    service + ".amazonaws.com", service, method="GET",
                    path="/?Action=" + MINTS[service][0])), service + ":" + MINTS[service][0])
                self.assertDenied(self.run_hooks(self.query_flow(
                    service, b"Action=GetCallerIdentity&Action=AssumeRole")), service + ":Unknown")
                self.assertDenied(self.run_hooks(self.aws_flow(
                    service + ".amazonaws.com", service)), service + ":Unknown")

    def test_codeartifact_authorization_token_is_denied(self):
        flow = self.aws_flow("codeartifact.eu-west-1.amazonaws.com", "codeartifact",
                             path="/v1/authorization-token")
        self.assertDenied(self.run_hooks(flow), "codeartifact:GetAuthorizationToken")

    def test_presigned_query_cannot_bypass_mint_policy(self):
        for service, host in (("sts", "sts.amazonaws.com"), ("s3", "sts.amazonaws.com"),
                              ("s3", "sts.s3.amazonaws.com")):
            with self.subTest(service=service, host=host):
                query = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                         "X-Amz-Credential": f"dummy/20260101/eu-west-1/{service}/aws4_request",
                         "X-Amz-Date": AMZ_DATE, "X-Amz-Expires": "60", "X-Amz-SignedHeaders": "host",
                         "X-Amz-Signature": "deadbeef", "X-Amz-Security-Token": f"secretrole:{ACCOUNT}/ReadOnly",
                         "Action": "AssumeRole"}
                flow = self.aws_flow(host, service, method="GET", path="/?" + urlencode(query))
                # Query auth alone (no Authorization header).
                del flow.request.headers["Authorization"]
                self.run_hooks(flow)
                self.assertIsNotNone(flow.response)
                self.assertEqual(flow.response.status_code, 403)
                self.assertEqual(self.provider_lookups, 0)
                self.assertEqual(self.provider.calls, [])

    def test_normal_development_calls_still_work(self):
        for flow in (self.query_flow("sts", b"Action=GetCallerIdentity"),
                     self.query_flow("iam", b"Action=GetRole"),
                     self.json_flow("ecr", "Fixture.DescribeRepositories"),
                     self.json_flow("cognito-identity", "Fixture.ListIdentityPools")):
            self.assertResigned(self.run_hooks(flow))


if __name__ == "__main__":
    unittest.main()
