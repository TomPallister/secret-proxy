"""GitHub guard unit and addon tests. Never contact GitHub or resolve a real secret."""
import base64
import gzip
import json
import unittest
from urllib.parse import urlencode
from unittest.mock import patch

from test_injection import AddonTestCase, FakeManifest, FakeResolver, make_flow

REF = "secret" + "ref:FIXTURE_TOKEN"
VALUE = "fixture-github-credential"
ADMIN = (
    ("POST", "/user/keys"), ("POST", "/user/gpg_keys"), ("POST", "/user/ssh_signing_keys"),
    ("PATCH", "/user"), ("DELETE", "/repos/acme/app"), ("PATCH", "/repos/acme/app"),
    ("POST", "/repos/acme/app/transfer"), ("PUT", "/repos/acme/app/collaborators/someone"),
    ("POST", "/repos/acme/app/hooks"), ("POST", "/repos/acme/app/keys"),
    ("PUT", "/repos/acme/app/actions/secrets/KEY"), ("POST", "/repos/acme/app/actions/runners/registration-token"),
    ("PUT", "/repos/acme/app/branches/main/protection"), ("POST", "/repos/acme/app/rulesets"),
    ("PUT", "/repos/acme/app/environments/prod"), ("POST", "/orgs/acme/invitations"),
    ("PATCH", "/orgs/acme"), ("POST", "/orgs/acme/hooks"), ("PUT", "/teams/1/memberships/someone"),
    ("POST", "/app/installations/1/access_tokens"), ("POST", "/applications/client/token"),
    ("POST", "/authorizations"), ("POST", "/gists"), ("POST", "/user/repos"),
    ("POST", "/repos/acme/app/future-admin-api"),
)
NORMAL = (
    ("GET", "/user"), ("HEAD", "/repos/acme/app"), ("GET", "/repos/acme/app/issues?page=2"),
    ("POST", "/repos/acme/app/pulls"), ("PATCH", "/repos/acme/app/pulls/1"),
    ("POST", "/repos/acme/app/pulls/1/reviews"), ("POST", "/repos/acme/app/issues/1/comments"),
    ("PUT", "/repos/acme/app/pulls/1/merge"), ("PUT", "/repos/acme/app/pulls/1/update-branch"),
    ("PUT", "/repos/acme/app/contents/src/file.py"), ("DELETE", "/repos/acme/app/contents/old.py"),
    ("POST", "/repos/acme/app/git/refs"), ("PATCH", "/repos/acme/app/git/refs/heads/topic"),
    ("POST", "/repos/acme/app/releases"), ("DELETE", "/repos/acme/app/releases/assets/123"),
    ("POST", "/repos/acme/app/check-runs"), ("POST", "/repos/acme/app/statuses/abcdef"),
    ("POST", "/repos/acme/app/actions/workflows/build.yml/dispatches"),
)


def gql(query, **extra):
    return json.dumps({"query": query, **extra}).encode()


class GithubAddonTests(AddonTestCase):
    def setUp(self):
        super().setUp()
        self.addon._manifest = FakeManifest({"FIXTURE_TOKEN": {"hosts": [
            "api.github.com", "uploads.github.com", "github.com", "git.example.com", "api.git.example.com", "api.example.com"]}})
        self.addon._resolver = FakeResolver({"FIXTURE_TOKEN": VALUE})
        self.addon._manifest_mtime = -1

    def flow(self, method, path, body=None, host="api.github.com", sink="header"):
        headers = {"Authorization": "Bearer " + REF}
        query = None
        if sink == "basic":
            headers["Authorization"] = "Basic " + base64.b64encode(("x-access-token:" + REF).encode()).decode()
        elif sink == "query":
            headers = {}
            query = {"access_token": REF}
        return make_flow(host, path, method, headers=headers, query=query, content=body,
                         content_type="application/json" if body is not None else None)

    def run_hooks(self, flow):
        self.addon.requestheaders(flow)
        if flow.response is None:
            self.addon.request(flow)
        return flow

    def denied(self, flow):
        self.addon._resolver.get_calls.clear()
        self.run_hooks(flow)
        self.assertIsNotNone(flow.response, flow.request.path)
        self.assertEqual(flow.response.status_code, 403, flow.response.content)
        self.assertEqual(json.loads(flow.response.content)["error"], "secret_proxy_github_denied")
        self.assertEqual(self.addon._resolver.get_calls, [], "must refuse before any credential lookup")
        self.assertNotIn(VALUE, str(flow.request.headers))
        self.assertNotIn(VALUE.encode(), flow.response.content)

    def allowed(self, flow):
        self.addon._resolver.get_calls.clear()
        self.run_hooks(flow)
        self.assertIsNone(flow.response, flow.response and flow.response.content)
        self.assertEqual(self.addon._resolver.get_calls, ["FIXTURE_TOKEN"])
        authorization = flow.request.headers.get("Authorization", "")
        if authorization.startswith("Basic "):
            authorization = base64.b64decode(authorization[6:]).decode()
        self.assertIn(VALUE, authorization)

    def test_rest_admin_denied_for_both_http_versions_and_auth_styles(self):
        for http2 in (False, True):
            for sink in ("header", "basic", "query"):
                for method, path in ADMIN:
                    with self.subTest(http2=http2, sink=sink, method=method, path=path):
                        flow = self.flow(method, path, sink=sink)
                        if http2:
                            flow.request.http_version = "HTTP/2.0"
                            del flow.request.headers["Host"]
                        self.denied(flow)

    def test_normal_repo_work_unchanged(self):
        for method, path in NORMAL:
            with self.subTest(method=method, path=path):
                self.allowed(self.flow(method, path))
        self.allowed(self.flow("POST", "/repos/acme/app/releases/1/assets?name=file", b"fixture", "uploads.github.com"))
        for path, method in (("/acme/app.git/info/refs?service=git-upload-pack", "GET"),
                             ("/acme/app.git/git-receive-pack", "POST"),
                             ("/acme/app/git-upload-pack", "POST")):
            self.allowed(self.flow(method, path, host="github.com", sink="basic"))

    def test_normal_graphql_operations(self):
        for query in ('query { viewer { login } }',
                      'mutation { createPullRequest(input:{repositoryId:"x",headRefName:"fix",baseRefName:"main",title:"x"}) { clientMutationId } }',
                      'mutation ($input: AddCommentInput!) { alias: addComment(input:$input) { clientMutationId } }',
                      'mutation { ...Allowed } fragment Allowed on Mutation { mergePullRequest(input:{pullRequestId:"x"}) { clientMutationId } }'):
            with self.subTest(query=query):
                self.allowed(self.flow("POST", "/graphql", gql(query, variables={"input": {"subjectId": "x", "body": "fixture"}})))

    def test_graphql_admin_aliases_fragments_mixed_unknown_mutations(self):
        for query in (
            'mutation { addComment: addSshKey(input:{key:"fixture"}) { clientMutationId } }',
            'mutation { addSshKey(input:{key:"fixture"}) @skip(if:true) { clientMutationId } }',
            'mutation { ...Blocked } fragment Blocked on Mutation { deleteRepository(input:{repositoryId:"x"}) { clientMutationId } }',
            'mutation { ... on Mutation { updateRepository(input:{repositoryId:"x",visibility:PUBLIC}) { clientMutationId } } }',
            'mutation { addComment(input:{subjectId:"x",body:"ok"}){clientMutationId} createGist(input:{description:"x"}){clientMutationId} }',
            'mutation { futureAdminAction { clientMutationId } }',
            'mutation { ...A } fragment A on Mutation { ...B } fragment B on Mutation { ...A }',
            'mutation { ...Missing }',
            'query Safe { viewer{login} } mutation Unsafe { addSshKey(input:{key:"x"}){clientMutationId} }',
        ):
            with self.subTest(query=query):
                self.denied(self.flow("POST", "/graphql", gql(query)))

    def test_graphql_malformed_transport_denied(self):
        for body in (b'not json', b'[]', b'{"query":"{viewer{login}}","query":"mutation{deleteRepository{id}}"}',
                     gql('{viewer{login}}', extensions={"persistedQuery": {"sha256Hash": "x"}}),
                     gql('mutation { broken'), gql('query A{viewer{login}} query B{viewer{login}}'),
                     gql('query A{viewer{login}}', operationName="Missing"),
                     gql('{viewer{login}}') + b' ' * (2 * 1024 * 1024)):
            with self.subTest(body=body[:70]):
                self.denied(self.flow("POST", "/graphql", body))
        self.denied(self.flow("GET", "/graphql?query=mutation%7BdeleteRepository%7Bid%7D%7D"))
        for header, value in (("content-type", "application/graphql"), ("content-encoding", "gzip")):
            flow = self.flow("POST", "/graphql", gql('{viewer{login}}'))
            flow.request.headers[header] = value
            if header == "content-encoding":
                flow.request.raw_content = gzip.compress(gql("{viewer{login}}"))
            self.denied(flow)

    def test_path_and_method_ambiguity_denied(self):
        for path in ("/user/%6beys", "/repos/acme/app/contents/../keys", "/repos/acme/app/contents/%2e%2e/keys",
                     "/repos/acme/app/contents/%252e%252e/keys", "/repos/acme/app%2fkeys", "//user/keys",
                     "/repos/acme/app/contents/a%5cb", "/repos/acme/app/contents/a%00b"):
            self.denied(self.flow("PUT" if "/contents/" in path else "POST", path))
        for header in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
            flow = self.flow("GET", "/repos/acme/app")
            flow.request.headers[header] = "DELETE"
            self.denied(flow)
        self.denied(self.flow("GET", "/repos/acme/app?_method=DELETE"))
        flow = self.flow("POST", "/user/keys")
        flow.request.headers["Host"] = "not-github.example"  # authority wins
        self.denied(flow)

    def test_guard_does_not_grant_placements_or_intercept_others(self):
        self.allowed(self.flow("POST", "/user/keys", host="api.example.com"))
        flow = self.flow("POST", "/user/keys")
        del flow.request.headers["Authorization"]
        self.run_hooks(flow)
        self.assertIsNone(flow.response)  # not our credential
        self.addon._resolver.get_calls.clear()
        self.addon._manifest = FakeManifest({"FIXTURE_TOKEN": {"hosts": ["github.com"]}})
        flow = self.run_hooks(self.flow("GET", "/user"))
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(self.addon._resolver.get_calls, [])

    def test_enterprise_and_github_web_do_not_offer_an_unguarded_route(self):
        with patch.object(self.addon._manifest, "github_login", create=True,
                          return_value={"domain": "git.example.com"}):
            self.denied(self.flow("POST", "/api/v3/user/keys", host="git.example.com"))
            self.denied(self.flow("POST", "/user/keys", host="api.git.example.com"))
            self.denied(self.flow("POST", "/api/graphql", gql('mutation { addSshKey(input:{key:"x"}) { clientMutationId } }'), "git.example.com"))
            self.allowed(self.flow("POST", "/api/v3/repos/acme/app/pulls", host="git.example.com"))
        self.denied(self.flow("POST", "/settings/keys", host="github.com", sink="basic"))

    def test_form_reference_and_encoded_basic_are_guarded(self):
        flow = self.flow("POST", "/user/keys", urlencode({"access_token": REF}).encode())
        del flow.request.headers["Authorization"]
        flow.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.denied(flow)
        flow = self.flow("POST", "/user/keys", sink="basic")
        self.denied(flow)
        self.assertIn(REF, base64.b64decode(flow.request.headers["Authorization"][6:]).decode())

    def test_url_rewrite_cannot_bypass_api_guard(self):
        for method, path in (("POST", "/user/keys"), ("GET", "/repos/acme/app?_method=DELETE")):
            self.addon._manifest = FakeManifest({"FIXTURE_URL": {"placements": [
                {"kind": "url-rewrite", "hosts": ["api.github.com"]}]}})
            self.addon._resolver = FakeResolver({"FIXTURE_URL": "https://api.github.com" + path})
            flow = make_flow(self.addon.SENTINEL_HOST, "/FIXTURE_URL", method)
            self.run_hooks(flow)
            self.assertIsNotNone(flow.response)
            self.assertEqual(flow.response.status_code, 403)
            self.assertEqual(json.loads(flow.response.content)["error"], "secret_proxy_github_denied")
            # A URL must be resolved to learn its destination, but not forwarded.
            self.assertEqual(self.addon._resolver.get_calls, ["FIXTURE_URL"])
            self.assertEqual(flow.request.host, self.addon.SENTINEL_HOST)

    def test_audit_and_errors_do_not_contain_graphql_values(self):
        flow = self.flow("POST", "/graphql", gql('mutation { addSshKey(input:{key:"PRIVATE-INPUT"}){clientMutationId} }'))
        with patch.object(self.addon, "_audit_log") as writer:
            writer.record.return_value = True
            self.denied(flow)
        self.assertIn("github-api-denied", str(writer.record.call_args_list))
        self.assertNotIn("PRIVATE-INPUT", str(writer.record.call_args_list))
        self.assertNotIn("PRIVATE-INPUT", flow.response.text)

    def test_parser_limits_and_duplicate_definitions(self):
        queries = [
            'query{viewer{login}} mutation{addSshKey(input:{key:"x"}){clientMutationId}}',
            'query Same{viewer{login}} query Same{viewer{login}}',
            'mutation{...F} fragment F on Mutation{addComment{clientMutationId}} fragment F on Mutation{addSshKey{clientMutationId}}',
            '{viewer{' + 'x{' * 80 + 'login' + '}' * 80 + '}}',
            '{viewer{' + 'login ' * 11000 + '}}',
            '{viewer{' + 'alias: login ' * 4000 + '}}',
        ]
        for query in queries:
            self.denied(self.flow("POST", "/graphql", gql(query)))

    def test_streamed_get_and_signing_spoof_cannot_skip_guard(self):
        for method, path in (("GET", "/graphql"), ("POST", "/user/keys")):
            flow = self.flow(method, path)
            flow.request.stream = method == "GET"
            if method == "POST":
                # Force the AWS streaming path alongside a different reference header.
                flow.request.headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=dummy/20260101/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=x"
                flow.request.headers["X-Api-Key"] = REF
                flow.request.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
            self.denied(flow)


if __name__ == "__main__":
    unittest.main()
