"""Approval rules (issue #3): hold a request until a person answers.

Covers the broker's safety rules with an injected clock (no real waiting), the
manifest/AWS/egress configuration, the addon's gates (nothing resolved and
nothing forwarded until approved, on the buffered and streaming paths and over
HTTP/2), the runtime adapter's control endpoint, and the CLI loop.
"""
import asyncio
import io
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import approvals
import awsops
import egress
from secretstore import SecretManifest
from test_awsops_addon import ACCOUNT, AwsPolicyAddonTestCase
from test_injection import AddonTestCase, FakeResolver, make_flow

REF = "secre" + "tref:"
INSTANCE = "ab" * 16
APPROVER = "c" * 48
PROXY = "d" * 48


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def request(n="A", method="POST"):
    return approvals.placement_request(secret=f"EXAMPLE_{n}", kind="header", name="authorization",
                                       host="api.example.com", method=method, path="/v1?q=1",
                                       rule=f"EXAMPLE_{n}.placements[0]")


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.broker = approvals.Broker(clock=self.clock, timeout=120, prompts_per_minute=3,
                                       max_pending=4)
        self.broker.poller_started()

    def deliver(self):
        item = self.broker.next_item()
        self.clock.advance(1.0)
        return item

    def test_no_listener_denies_immediately(self):
        broker = approvals.Broker(clock=self.clock)
        self.assertEqual(broker.submit(request()), approvals.Outcome(False, approvals.RULE_NO_LISTENER))
        disabled = approvals.Broker(clock=self.clock, enabled=False)
        disabled.poller_started()
        self.assertEqual(disabled.submit(request()).rule, approvals.RULE_NO_LISTENER)

    def test_listener_grace_after_a_poll(self):
        broker = approvals.Broker(clock=self.clock, listener_grace=10)
        broker.poller_started()
        broker.poller_finished()
        self.clock.advance(9)
        self.assertIsInstance(broker.submit(request("A")), approvals.Pending)
        self.clock.advance(200)  # also expires A
        broker.next_item()
        broker._last_activity = self.clock() - 11
        self.assertEqual(broker.submit(request("B")).rule, approvals.RULE_NO_LISTENER)

    def test_allow_once_and_one_prompt_at_a_time(self):
        first = self.broker.submit(request("A"))
        second = self.broker.submit(request("B"))
        self.assertIs(self.deliver(), first)
        self.assertIs(self.broker.next_item(), first, "the shown prompt is repeated, not the next")
        outcomes = []
        self.broker.add_callback(first, outcomes.append)
        self.assertEqual(self.broker.answer(first.id, approvals.ALLOW_ONCE).allowed, True)
        self.assertEqual(outcomes, [approvals.Outcome(True, "", approvals.ALLOW_ONCE)])
        self.assertIsNone(self.broker.session_decision(first.request.key), "once is not remembered")
        self.assertIs(self.broker.next_item(), second)
        self.assertIsNone(self.broker.answer(first.id, approvals.ALLOW_ONCE), "already answered")

    def test_deny_once(self):
        item = self.broker.submit(request())
        self.deliver()
        outcome = self.broker.answer(item.id, approvals.DENY_ONCE)
        self.assertEqual(outcome, approvals.Outcome(False, approvals.RULE_DENIED, approvals.DENY_ONCE))
        self.assertIsInstance(self.broker.submit(request()), approvals.Pending, "deny once is not remembered")

    def test_allow_session_covers_exact_key_only(self):
        item = self.broker.submit(request("A"))
        queued_same = self.broker.submit(request("A"))
        self.deliver()
        self.broker.answer(item.id, approvals.ALLOW_SESSION)
        self.assertEqual(queued_same.outcome, approvals.Outcome(True, "", approvals.ALLOW_SESSION))
        self.assertEqual(self.broker.session_decision(request("A").key), "allow")
        self.assertEqual(self.broker.submit(request("A")), approvals.Outcome(True, "", approvals.ALLOW_SESSION))
        # Same secret and host, other method: a different key, asked again.
        self.assertIsInstance(self.broker.submit(request("A", method="GET")), approvals.Pending)

    def test_deny_session(self):
        item = self.broker.submit(request())
        self.deliver()
        self.broker.answer(item.id, approvals.DENY_SESSION)
        self.assertEqual(self.broker.session_decision(request().key), "deny")
        self.assertEqual(self.broker.submit(request()).rule, approvals.RULE_DENIED)

    def test_timeout_denies_queued_and_shown(self):
        shown = self.broker.submit(request("A"))
        queued = self.broker.submit(request("B"))
        self.broker.next_item()
        self.clock.advance(119)
        self.assertEqual(self.broker.expire(), [])
        self.clock.advance(1)
        self.assertEqual(set(i.id for i in self.broker.expire()), {shown.id, queued.id})
        self.assertEqual(shown.outcome.rule, approvals.RULE_TIMEOUT)
        self.assertEqual(queued.outcome.rule, approvals.RULE_TIMEOUT)
        self.assertIsNone(self.broker.answer(shown.id, approvals.ALLOW_ONCE), "a late answer changes nothing")

    def test_rate_limit_and_queue_limit(self):
        items = [self.broker.submit(request(str(i))) for i in range(3)]
        self.assertTrue(all(isinstance(i, approvals.Pending) for i in items))
        self.assertEqual(self.broker.submit(request("X")).rule, approvals.RULE_RATE_LIMITED)
        self.clock.advance(60)  # window passes; the three time out too
        self.broker.expire()
        self.assertIsInstance(self.broker.submit(request("Y")), approvals.Pending)
        broker = approvals.Broker(clock=self.clock, max_pending=2, prompts_per_minute=60)
        broker.poller_started()
        broker.submit(request("1"))
        broker.submit(request("2"))
        self.assertEqual(broker.submit(request("3")).rule, approvals.RULE_QUEUE_FULL)

    def test_malformed_and_too_fast_answers_deny(self):
        self.broker = approvals.Broker(clock=self.clock, prompts_per_minute=60)
        self.broker.poller_started()
        for bad in (None, "", "ALLOW-ONCE", "yes", 2, {"choice": "allow-once"}):
            with self.subTest(bad=bad):
                item = self.broker.submit(request(f"M{len(str(bad))}{type(bad).__name__}"))
                self.deliver()
                self.assertEqual(self.broker.answer(item.id, bad).rule, approvals.RULE_MALFORMED)
        item = self.broker.submit(request("F"))
        self.broker.next_item()
        self.clock.advance(0.5)
        self.assertEqual(self.broker.answer(item.id, approvals.ALLOW_ONCE).rule, approvals.RULE_TOO_FAST)

    def test_answer_only_applies_to_the_shown_prompt(self):
        item = self.broker.submit(request())
        self.assertIsNone(self.broker.answer(item.id, approvals.ALLOW_ONCE), "not delivered yet")
        self.assertIsNone(self.broker.answer("0" * 32, approvals.ALLOW_ONCE))
        self.assertIsNone(item.outcome)

    def test_withdraw(self):
        item = self.broker.submit(request())
        self.broker.withdraw(item.id)
        self.assertEqual(item.outcome.rule, approvals.RULE_WITHDRAWN)
        self.assertIsNone(self.broker.next_item())

    def test_descriptions_carry_no_query_values_or_terminal_controls(self):
        ask = approvals.placement_request(secret="EXAMPLE_A", kind="query", name="key",
                                          host="API.Example.com", method="post",
                                          path="/v1/\x1b[2Jitems?key=" + REF + "EXAMPLE_A&x=1#frag",
                                          rule="EXAMPLE_A.placements[2]", client="ci\nbot")
        info = ask.describe()
        self.assertEqual(info["path"], "/v1/?[2Jitems")
        self.assertEqual(info["host"], "api.example.com")
        self.assertEqual(info["method"], "POST")
        self.assertEqual(info["client"], "ci?bot")
        self.assertEqual(ask.key, ("placement", "ci?bot", "EXAMPLE_A", "api.example.com", "POST",
                                   "EXAMPLE_A.placements[2]"))
        aws = approvals.aws_request(account=ACCOUNT, role="Admin", service="iam", operation="CreateRole",
                                    rule="aws-policy.json rule 1", host="iam.amazonaws.com", method="POST",
                                    path="/")
        self.assertEqual(aws.key, ("aws", "-", ACCOUNT, "Admin", "iam", "CreateRole", "aws-policy.json rule 1"))
        self.assertEqual(approvals.egress_request(host="New.Example.com", port=443, rule="egress-allowlist").key,
                         ("egress", "-", "new.example.com"))
        other_client = approvals.egress_request(host="new.example.com", port=443, rule="egress-allowlist",
                                                client="other")
        self.assertNotEqual(other_client.key[1], "-", "a session decision is per client")
        public = approvals.public_item(approvals.Pending("e" * 32, ask, 0, 120, delivered=0.25), INSTANCE, 0.5)
        self.assertEqual(set(public), {"instance", "id", "request", "expiresIn", "answerAfter"})
        self.assertNotIn(REF, json.dumps(public))

    def test_settings(self):
        self.assertEqual(approvals.validate_settings(None), {"timeout": 120.0, "prompts_per_minute": 10})
        self.assertEqual(approvals.validate_settings({"timeoutSeconds": 30, "maxPromptsPerMinute": 2}),
                         {"timeout": 30.0, "prompts_per_minute": 2})
        for bad in ([], {"timeoutSeconds": 5}, {"timeoutSeconds": 601}, {"timeoutSeconds": 30.5},
                    {"timeoutSeconds": True}, {"maxPromptsPerMinute": 0}, {"other": 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                approvals.validate_settings(bad)


# --- configuration ------------------------------------------------------------

def manifest_file(directory, secrets, **extra):
    path = Path(directory) / "manifest.json"
    path.write_text(json.dumps({"schemaVersion": 3, "account": {"vault": "Example"},
                                "secrets": secrets, **extra}))
    return path


HEADER = {"kind": "header", "hosts": ["api.example.com"], "name": "Authorization",
          "template": "Bearer {secret}"}
SECRETS = {
    "EXAMPLE_TOKEN": {"placements": [
        {**HEADER, "methods": ["POST"], "approval": "prompt"},
        {**HEADER, "methods": ["GET"]},
    ]},
    "EXAMPLE_QUERY_KEY": {"placements": [
        {"kind": "query", "hosts": ["api.example.com"], "name": "key", "template": "{secret}",
         "approval": "prompt"}]},
    "EXAMPLE_FORM_SECRET": {"placements": [
        {"kind": "form", "hosts": ["auth.example.com"], "name": "client_secret", "template": "{secret}",
         "approval": "prompt"}]},
    "EXAMPLE_PASSWORD": {"placements": [
        {"kind": "basic-password", "hosts": ["git.example.com"], "username": "bot", "approval": "prompt"}]},
    "EXAMPLE_WEBHOOK_URL": {"placements": [
        {"kind": "url-rewrite", "hosts": ["hooks.example.com"], "methods": ["POST"], "approval": "prompt"}]},
    "EXAMPLE_PLAIN": {"placements": [{**HEADER, "name": "x-api-key", "template": "{secret}"}]},
}


class ConfigurationTests(unittest.TestCase):
    def test_manifest_approval_field_and_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = SecretManifest.load(manifest_file(tmp, SECRETS, approvals={"timeoutSeconds": 60}))
        self.assertTrue(manifest.uses_approval())
        self.assertEqual(manifest.approval_settings()["timeout"], 60.0)
        context = dict(kind="header", host="api.example.com", path="/", name="authorization",
                       template="Bearer {secret}")
        post = manifest.match_placement("EXAMPLE_TOKEN", method="POST", **context)
        get = manifest.match_placement("EXAMPLE_TOKEN", method="GET", **context)
        self.assertEqual((post.index, post.approval), (0, "prompt"))
        self.assertEqual((get.index, get.approval), (1, None))
        self.assertIsNone(manifest.match_placement("EXAMPLE_TOKEN", method="PUT", **context))
        self.assertEqual(manifest.secret("EXAMPLE_TOKEN").placements[0].approval, "prompt")

    def test_approval_placement_wins_over_a_broader_one(self):
        secrets = {"EXAMPLE_TOKEN": {"placements": [
            {**HEADER},  # any method, no approval
            {**HEADER, "methods": ["DELETE"], "approval": "prompt"},
        ]}}
        with tempfile.TemporaryDirectory() as tmp:
            manifest = SecretManifest.load(manifest_file(tmp, secrets))
        match = manifest.match_placement("EXAMPLE_TOKEN", kind="header", host="api.example.com",
                                         method="DELETE", path="/", name="authorization",
                                         template="Bearer {secret}")
        self.assertEqual((match.index, match.approval), (1, "prompt"))

    def test_default_manifest_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = SecretManifest.load(manifest_file(tmp, {"EXAMPLE_PLAIN": SECRETS["EXAMPLE_PLAIN"]}))
        self.assertFalse(manifest.uses_approval())
        self.assertEqual(manifest.approval_settings(), {"timeout": 120.0, "prompts_per_minute": 10})
        for example in Path(__file__).resolve().parent.glob("examples/*manifest.json"):
            with self.subTest(example=example.name):
                SecretManifest.load(example)

    def test_invalid_approval_configuration_fails(self):
        for change in ({"approval": "yes"}, {"approval": True}, {"approval": None}):
            secrets = {"EXAMPLE_PLAIN": {"placements": [{**HEADER, **change}]}}
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp, \
                    self.assertRaisesRegex(ValueError, "approval must be"):
                SecretManifest.load(manifest_file(tmp, secrets))
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError, "timeoutSeconds"):
            SecretManifest.load(manifest_file(tmp, SECRETS, approvals={"timeoutSeconds": 1}))

    def test_aws_approve_action_and_deny_precedence(self):
        rules = awsops.load_policy_bytes(json.dumps({"version": 1, "rules": [
            {"action": "approve", "service": "iam", "operations": ["Create*"]},
            {"action": "deny", "service": "iam", "operations": ["CreateUser"]},
            {"action": "approve", "service": "secretsmanager", "operations": ["GetSecretValue"]},
            {"action": "approve", "service": "ec2", "operations": ["Run*"]},
            {"action": "allow", "service": "ec2", "operations": ["Describe*"]},
        ]}).encode())
        overrides = awsops.parse_overrides([{"account": ACCOUNT, "role": "Admin",
                                             "service": "secretsmanager", "operations": ["GetSecretValue"]}])
        policy = awsops.AwsOperationPolicy(rules, overrides)

        def decide(service, operation, role="ReadOnly"):
            return policy.evaluate(awsops.AwsOperation(service, operation, "json"), ACCOUNT, role)

        self.assertEqual(decide("iam", "CreateRole").action, awsops.APPROVE)
        self.assertEqual(decide("iam", "CreateRole").rule, "aws-policy.json rule 1")
        self.assertEqual(decide("iam", "CreateUser").action, awsops.DENY, "deny beats approve")
        self.assertEqual(decide("secretsmanager", "GetSecretValue").action, awsops.DENY,
                         "an approve rule cannot open a built-in deny")
        overridden = decide("secretsmanager", "GetSecretValue", role="Admin")
        self.assertEqual((overridden.action, overridden.overridden), (awsops.APPROVE, True))
        self.assertEqual(decide("ec2", "RunInstances").action, awsops.APPROVE)
        self.assertEqual(decide("ec2", "DescribeInstances").action, awsops.ALLOW)
        self.assertEqual(decide("ec2", "TerminateInstances").action, awsops.DENY)
        self.assertEqual(decide("s3", "Unclassified").action, awsops.ALLOW)

    def test_egress_allowlist_miss_approve(self):
        resolve = {"new.example.net": ["203.0.114.7"], "inside.example.net": ["10.1.2.3"]}.get

        def resolver(host, _port):
            return resolve(host) or []

        policy = egress.EgressPolicy.from_config({
            "mode": "allowlist", "allow": ["*.example.com"], "deny": ["bad.example.net"],
            "allowlistMiss": "approve"})
        decision = policy.check("new.example.net", 443, resolver)
        self.assertEqual(decision, egress.Allowed(("203.0.114.7",), "egress-allowlist"))
        self.assertEqual(policy.check("bad.example.net", 443, resolver), egress.Refusal("egress-deny"))
        self.assertEqual(policy.check("inside.example.net", 443, resolver), egress.Refusal("private-address"))
        self.assertEqual(policy.check("metadata.google.internal", 443, resolver), egress.Refusal("metadata-host"))
        listed = egress.EgressPolicy.from_config({"mode": "allowlist", "allow": ["*.example.net"],
                                                  "allowlistMiss": "approve"})
        self.assertIsNone(listed.check("new.example.net", 443, resolver).approval)
        default = egress.EgressPolicy.from_config({"mode": "allowlist"})
        self.assertEqual(default.check("new.example.net", 443, resolver), egress.Refusal("egress-allowlist"))
        for bad in ({"mode": "allowlist", "allowlistMiss": "allow"},
                    {"mode": "open", "allowlistMiss": "approve"}):
            with self.subTest(bad=bad), self.assertRaises(egress.EgressConfigError):
                egress.EgressPolicy.from_config(bad)


# --- addon gates ----------------------------------------------------------------

class GateTestCase(AddonTestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addon._manifest = SecretManifest.load(manifest_file(self.tmp.name, SECRETS))
        self.resolver = FakeResolver({
            "EXAMPLE_TOKEN": "real-token-value", "EXAMPLE_QUERY_KEY": "real-query-value",
            "EXAMPLE_FORM_SECRET": "real-form-value", "EXAMPLE_PASSWORD": "real-password-value",
            "EXAMPLE_WEBHOOK_URL": "https://hooks.example.com/services/T000/B000/xyz",
            "EXAMPLE_PLAIN": "real-plain-value",
        })
        self.addon._resolver = self.resolver
        self.addon._manifest_mtime = -1
        self.broker = approvals.configure(approvals.Broker(enabled=True))
        self.addCleanup(approvals.configure, approvals.Broker(enabled=False))

    def held(self, flow):
        """Run the buffered hook as the runtime adapter would (handler present)."""
        flow.metadata[self.addon.APPROVAL_HANDLER] = True
        self.addon.request(flow)
        return self.addon.approval_pending(flow)

    def token_flow(self, method="POST", http2=False):
        flow = make_flow("api.example.com", "/v1/items?page=2", method,
                         headers={"Authorization": "Bearer " + REF + "EXAMPLE_TOKEN"})
        if http2:
            flow.request.http_version = "HTTP/2.0"
            del flow.request.headers["Host"]
        return flow


class AddonGateTests(GateTestCase):
    def test_held_request_resolves_nothing_and_is_not_forwarded(self):
        for http2 in (False, True):
            with self.subTest(http2=http2):
                self.resolver.get_calls.clear()
                flow = self.token_flow(http2=http2)
                pending = self.held(flow)
                self.assertEqual(self.resolver.get_calls, [], "no secret may be resolved")
                self.assertIsNone(flow.response)
                self.assertEqual(flow.request.headers["Authorization"], "Bearer " + REF + "EXAMPLE_TOKEN")
                self.assertEqual(len(pending), 1)
                info = pending[0].describe()
                self.assertEqual(info, {
                    "kind": "secret", "method": "POST", "host": "api.example.com", "path": "/v1/items",
                    "secret": "EXAMPLE_TOKEN", "placement": "header authorization",
                    "rule": "EXAMPLE_TOKEN.placements[0]"})
                self.assertNotIn("real-token-value", json.dumps(info))

    def test_without_the_runtime_adapter_a_held_request_is_refused(self):
        flow = self.token_flow()
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(json.loads(flow.response.content)["rule"], approvals.RULE_REQUIRED)
        self.assertEqual(self.resolver.get_calls, [])

    def test_granted_once_injects_for_that_flow_only(self):
        flow = self.token_flow()
        pending = self.held(flow)
        self.addon.approval_grant(flow, [pending[0].key])
        self.assertEqual(self.held(flow), [])
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer real-token-value")
        self.assertEqual(len(self.held(self.token_flow())), 1, "a new request asks again")

    def test_session_decisions(self):
        key = approvals.placement_request(secret="EXAMPLE_TOKEN", kind="header", name="authorization",
                                          host="api.example.com", method="POST", path="/",
                                          rule="EXAMPLE_TOKEN.placements[0]").key
        self.broker._session[key] = "allow"
        flow = self.token_flow()
        self.assertEqual(self.held(flow), [])
        self.assertEqual(flow.request.headers["Authorization"], "Bearer real-token-value")
        self.broker._session[key] = "deny"
        self.resolver.get_calls.clear()
        flow = self.token_flow()
        self.assertEqual(self.held(flow), [])
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(json.loads(flow.response.content),
                         {"error": "secret_proxy_approval_denied", "rule": approvals.RULE_DENIED,
                          "detail": "secret-proxy refused this request (approval-denied)"})
        self.assertEqual(self.resolver.get_calls, [])

    def test_placements_without_approval_are_unchanged(self):
        flow = self.token_flow(method="GET")
        self.assertEqual(self.held(flow), [])
        self.assertEqual(flow.request.headers["Authorization"], "Bearer real-token-value")
        flow = make_flow("api.example.com", "/", "GET", headers={"x-api-key": REF + "EXAMPLE_PLAIN"})
        self.assertEqual(self.held(flow), [])
        self.assertEqual(flow.request.headers["x-api-key"], "real-plain-value")

    def test_policy_violation_is_refused_without_a_prompt(self):
        flow = make_flow("evil.example.net", "/", "POST",
                         headers={"Authorization": "Bearer " + REF + "EXAMPLE_TOKEN"})
        self.assertEqual(self.held(flow), [])
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(self.resolver.get_calls, [])

    def test_query_form_basic_and_url_rewrite_are_held_before_resolution(self):
        import base64
        flows = {
            "EXAMPLE_QUERY_KEY": make_flow("api.example.com", "/", "GET", query={"key": REF + "EXAMPLE_QUERY_KEY"}),
            "EXAMPLE_FORM_SECRET": make_flow(
                "auth.example.com", "/token", "POST",
                content=("grant_type=client_credentials&client_secret=" + REF + "EXAMPLE_FORM_SECRET").encode(),
                content_type="application/x-www-form-urlencoded"),
            "EXAMPLE_PASSWORD": make_flow("git.example.com", "/repo.git", "GET", headers={
                "Authorization": "Basic " + base64.b64encode(("bot:" + REF + "EXAMPLE_PASSWORD").encode()).decode()}),
            "EXAMPLE_WEBHOOK_URL": make_flow(self.addon.SENTINEL_HOST, "/EXAMPLE_WEBHOOK_URL", "POST",
                                             content=b"{}"),
        }
        for name, flow in flows.items():
            with self.subTest(name=name):
                self.resolver.get_calls.clear()
                pending = self.held(flow)
                self.assertEqual(self.resolver.get_calls, [])
                self.assertIsNone(flow.response)
                self.assertEqual([p.describe()["secret"] for p in pending], [name])
                self.addon.approval_grant(flow, [pending[0].key])
                self.assertEqual(self.held(flow), [])
                self.assertIsNone(flow.response, flow.response and flow.response.content)
                self.assertEqual(self.resolver.get_calls, [name])
        rewrite = flows["EXAMPLE_WEBHOOK_URL"]
        self.assertEqual(rewrite.request.host, "hooks.example.com")
        self.assertEqual(self.addon.approval_pending(rewrite), [])

    def test_url_rewrite_prompt_names_the_sentinel_not_the_url(self):
        flow = make_flow(self.addon.SENTINEL_HOST, "/EXAMPLE_WEBHOOK_URL", "POST", content=b"{}")
        info = self.held(flow)[0].describe()
        self.assertEqual(info["host"], self.addon.SENTINEL_HOST)
        self.assertNotIn("hooks.example.com", json.dumps(info))

    def test_streamed_metadata_is_held_in_requestheaders(self):
        flow = make_flow("api.example.com", "/upload", "GET",
                         headers={"Authorization": "Bearer " + REF + "EXAMPLE_TOKEN"})
        flow.request.method = "POST"
        flow.request.stream = True
        flow.request.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
        flow.metadata[self.addon.APPROVAL_HANDLER] = True
        self.addon.requestheaders(flow)
        # A streamed non-AWS body is refused as before; no prompt for it.
        self.assertEqual(flow.response.status_code, 502)
        self.assertEqual(self.resolver.get_calls, [])


class ScopedClientApprovalTests(GateTestCase):
    """Client grants come first; prompts and session keys name the client."""

    def setUp(self):
        super().setUp()
        clients = {
            "default": {"all": True},
            "reader": {"secrets": {"EXAMPLE_TOKEN": {"placements": [1]}}},
            "writer": {"secrets": {"EXAMPLE_TOKEN": True}},
            "other-writer": {"secrets": {"EXAMPLE_TOKEN": True}},
        }
        self.addon._manifest = SecretManifest.load(manifest_file(self.tmp.name, SECRETS, clients=clients))

    def as_client(self, flow, client):
        import clientgrants
        flow.metadata["proxyauth"] = (clientgrants.username(client), "f" * 48)
        return flow

    def test_request_outside_the_grant_is_refused_not_offered(self):
        flow = self.as_client(self.token_flow(), "reader")  # reader has only the GET placement
        self.assertEqual(self.held(flow), [])
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(json.loads(flow.response.content)["error"], "secret_proxy_placement_not_allowed")
        self.assertEqual(self.resolver.get_calls, [])
        flow = self.as_client(self.token_flow(method="GET"), "reader")
        self.assertEqual(self.held(flow), [])
        self.assertEqual(flow.request.headers["Authorization"], "Bearer real-token-value")

    def test_prompt_and_session_key_name_the_client(self):
        pending = self.held(self.as_client(self.token_flow(), "writer"))
        self.assertEqual(pending[0].describe()["client"], "writer")
        self.assertEqual(pending[0].key[1], "writer")
        self.broker._session[pending[0].key] = "allow"
        flow = self.as_client(self.token_flow(), "writer")
        self.assertEqual(self.held(flow), [])
        self.assertEqual(flow.request.headers["Authorization"], "Bearer real-token-value")
        other = self.held(self.as_client(self.token_flow(), "other-writer"))
        self.assertEqual(len(other), 1, "one client's session decision never covers another")
        self.assertEqual(other[0].describe()["client"], "other-writer")


class AwsGateTests(AwsPolicyAddonTestCase):
    def setUp(self):
        super().setUp()
        self.policy_file.write_text(json.dumps({"version": 1, "rules": [
            {"action": "approve", "service": "iam", "operations": ["CreateRole"]},
            {"action": "approve", "service": "s3", "operations": ["*"]},
            {"action": "deny", "service": "s3", "operations": ["DeleteBucket"]},
        ]}))
        self.broker = approvals.configure(approvals.Broker(enabled=True))
        self.addCleanup(approvals.configure, approvals.Broker(enabled=False))

    def hold(self, flow, hook):
        flow.metadata[self.addon.APPROVAL_HANDLER] = True
        hook(flow)
        return self.addon.approval_pending(flow)

    def test_buffered_operation_is_held_without_minting(self):
        for http2 in (False, True):
            with self.subTest(http2=http2):
                self.provider.calls.clear()
                self.provider_lookups = 0
                flow = self.query_flow("iam", b"Action=CreateRole&RoleName=x", http2=http2)
                self.addon.requestheaders(flow)
                pending = self.hold(flow, self.addon.request)
                self.assertIsNone(flow.response)
                self.assertEqual(self.provider_lookups, 0, "no credentials before approval")
                info = pending[0].describe()
                self.assertEqual((info["kind"], info["service"], info["operation"], info["account"], info["role"]),
                                 ("aws", "iam", "CreateRole", ACCOUNT, "ReadOnly"))
                self.assertNotIn("RoleName", json.dumps(info))
                self.addon.approval_grant(flow, [pending[0].key])
                self.assertEqual(self.hold(flow, self.addon.request), [])
                self.assertResigned(flow)

    def test_streaming_upload_is_held_before_the_body_streams(self):
        for http2 in (False, True):
            with self.subTest(http2=http2):
                self.provider.calls.clear()
                self.provider_lookups = 0
                flow = self.aws_flow("example-bucket.s3.eu-west-1.amazonaws.com", "s3", path="/key?x=1",
                                     method="PUT", sha256="UNSIGNED-PAYLOAD", http2=http2)
                pending = self.hold(flow, self.addon.requestheaders)
                self.assertIsNone(flow.response)
                self.assertFalse(flow.request.stream, "the body must not start streaming")
                self.assertEqual(self.provider_lookups, 0)
                self.assertEqual(pending[0].describe()["path"], "/key")
                self.addon.approval_grant(flow, [pending[0].key])
                self.assertEqual(self.hold(flow, self.addon.requestheaders), [])
                self.assertTrue(flow.request.stream)
                self.assertResigned(flow)

    def test_streaming_upload_resolves_no_header_secret_before_aws_approval(self):
        from test_injection import FakeManifest
        self.addon._manifest = FakeManifest({"EXAMPLE_TRACE": {"placements": [{
            "kind": "header", "hosts": ["example-bucket.s3.eu-west-1.amazonaws.com"],
            "name": "x-example-trace", "template": "{secret}"}]}})
        resolver = FakeResolver({"EXAMPLE_TRACE": "real-trace-value"})
        self.addon._resolver = resolver
        flow = self.aws_flow("example-bucket.s3.eu-west-1.amazonaws.com", "s3", path="/key", method="PUT",
                             sha256="UNSIGNED-PAYLOAD", headers={"x-example-trace": REF + "EXAMPLE_TRACE"})
        pending = self.hold(flow, self.addon.requestheaders)
        self.assertEqual([p.describe()["kind"] for p in pending], ["aws"])
        self.assertEqual(resolver.get_calls, [], "no secret before the AWS approval")
        self.assertEqual(flow.request.headers["x-example-trace"], REF + "EXAMPLE_TRACE")
        self.addon.approval_grant(flow, [pending[0].key])
        self.assertEqual(self.hold(flow, self.addon.requestheaders), [])
        self.assertEqual(resolver.get_calls, ["EXAMPLE_TRACE"])
        self.assertResigned(flow)

    def test_client_without_the_aws_grant_is_refused_not_offered(self):
        import clientgrants
        self.addon._manifest.clients = clientgrants.parse_clients({
            "default": {"all": True},
            "limited": {"aws": [{"account": ACCOUNT, "role": "ReadOnly", "operations": ["iam:List*"]}]},
        }, {}, [])
        flow = self.query_flow("iam", b"Action=CreateRole")
        flow.metadata["proxyauth"] = ("limited", "f" * 48)
        self.addon.requestheaders(flow)
        self.assertEqual(self.hold(flow, self.addon.request), [])
        self.assertDenied(flow, "iam:CreateRole")
        self.assertIn(b"not granted", flow.response.content)

    def test_deny_rule_beats_approve_rule(self):
        flow = self.aws_flow("example-bucket.s3.eu-west-1.amazonaws.com", "s3", path="/",
                             method="DELETE", sha256="UNSIGNED-PAYLOAD")
        # DeleteBucket is REST-Unclassified for s3, so make the deny match it.
        self.policy_file.write_text(json.dumps({"version": 1, "rules": [
            {"action": "approve", "service": "s3", "operations": ["*"]},
            {"action": "deny", "service": "s3", "operations": ["Unclassified"]},
        ]}))
        self.assertEqual(self.hold(flow, self.addon.requestheaders), [])
        self.assertDenied(flow, "s3:Unclassified")

    def test_session_deny_is_an_aws_error_and_refusal_shape(self):
        flow = self.query_flow("iam", b"Action=CreateRole")
        pending = self.hold(flow, self.addon.request)
        self.broker._session[pending[0].key] = "deny"
        flow = self.query_flow("iam", b"Action=CreateRole")
        self.assertEqual(self.hold(flow, self.addon.request), [])
        self.assertDenied(flow, "iam:CreateRole")
        self.assertIn(b"approval-denied", flow.response.content)
        flow = self.query_flow("iam", b"Action=CreateRole")
        self.addon.approval_refusal(flow, pending[0], approvals.RULE_TIMEOUT)
        self.assertDenied(flow, "iam:CreateRole")
        self.assertIn(b"approval-timeout", flow.response.content)


# --- runtime adapter (entry.py) ------------------------------------------------

def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=20))


class EntryTests(GateTestCase):
    def setUp(self):
        super().setUp()
        import entry
        self.entry = entry
        self.broker = approvals.configure(approvals.Broker(enabled=True, min_answer_delay=0.0, timeout=5))
        import hashlib
        patches = [
            patch.object(entry, "_approver_digest", hashlib.sha256(APPROVER.encode()).hexdigest()),
            patch.dict(os.environ, {"SECRET_PROXY_INSTANCE_ID": INSTANCE}),
            patch.object(entry, "_wakeups", set()),
            patch.object(entry, "_held_by_client", {}),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def control(self, path, method="GET", body=None, approver=APPROVER, instance=INSTANCE):
        headers = {}
        if approver is not None:
            headers[self.entry.APPROVER_HEADER] = approver
        if instance is not None:
            headers[self.entry.INSTANCE_HEADER] = instance
        return make_flow(self.addon.SENTINEL_HOST, path, method, headers=headers,
                         content=None if body is None else json.dumps(body).encode())

    async def approver(self, choice, answers=1):
        seen = []
        for _ in range(answers):
            flow = self.control("/approvals/next")
            await self.entry._approval_route(flow, poll_seconds=5)
            prompt = json.loads(flow.response.content)
            seen.append(prompt)
            answer = self.control("/approvals/" + prompt["id"], "POST", {"choice": choice})
            await self.entry._approval_route(answer)
            seen.append(json.loads(answer.response.content))
        return seen

    async def with_listener(self, flow, hook, choice, answers=1):
        self.broker.poller_started()  # the CLI is polling
        approver = asyncio.ensure_future(self.approver(choice, answers))
        await asyncio.sleep(0)
        await self.entry._run_with_approvals(flow, hook)
        self.broker.poller_finished()
        return await approver

    def test_allow_once_forwards_after_approval(self):
        flow = self.token_flow()
        seen = run(self.with_listener(flow, self.addon.request, "allow-once"))
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer real-token-value")
        self.assertEqual(seen[0]["request"]["secret"], "EXAMPLE_TOKEN")
        self.assertEqual(seen[0]["instance"], INSTANCE)
        self.assertEqual(seen[1], {"instance": INSTANCE, "id": seen[0]["id"], "result": "allowed", "rule": ""})
        self.assertNotIn("real-token-value", json.dumps(seen))

    def test_deny_once_is_a_403_with_only_the_rule(self):
        flow = self.token_flow()
        run(self.with_listener(flow, self.addon.request, "deny-once"))
        self.assertEqual(flow.response.status_code, 403)
        body = json.loads(flow.response.content)
        self.assertEqual(body["rule"], approvals.RULE_DENIED)
        self.assertNotIn("EXAMPLE_TOKEN.placements", json.dumps(body))
        self.assertEqual(self.resolver.get_calls, [])

    def test_allow_session_then_no_prompt(self):
        run(self.with_listener(self.token_flow(), self.addon.request, "allow-session"))
        flow = self.token_flow()
        run(self.entry._run_with_approvals(flow, self.addon.request))  # nobody listening now
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer real-token-value")

    def test_malformed_answer_denies(self):
        flow = self.token_flow()
        run(self.with_listener(flow, self.addon.request, "allow-twice"))
        self.assertEqual(json.loads(flow.response.content)["rule"], approvals.RULE_MALFORMED)
        self.assertEqual(self.resolver.get_calls, [])

    def test_no_listener_denies_without_waiting(self):
        flow = self.token_flow()
        started = time.monotonic()
        run(self.entry._run_with_approvals(flow, self.addon.request))
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(json.loads(flow.response.content)["rule"], approvals.RULE_NO_LISTENER)
        self.assertEqual(self.resolver.get_calls, [])

    def test_timeout_denies(self):
        approvals.configure(approvals.Broker(enabled=True, timeout=0.05))

        async def scenario():
            approvals.default_broker().poller_started()
            flow = self.token_flow()
            await self.entry._run_with_approvals(flow, self.addon.request)
            return flow

        flow = run(scenario())
        self.assertEqual(json.loads(flow.response.content)["rule"], approvals.RULE_TIMEOUT)
        self.assertEqual(self.resolver.get_calls, [])

    def test_two_secrets_ask_one_prompt_at_a_time(self):
        flow = make_flow("api.example.com", "/", "POST", headers={
            "Authorization": "Bearer " + REF + "EXAMPLE_TOKEN"}, query={"key": REF + "EXAMPLE_QUERY_KEY"})
        seen = run(self.with_listener(flow, self.addon.request, "allow-once", answers=2))
        self.assertEqual([seen[0]["request"]["secret"], seen[2]["request"]["secret"]],
                         ["EXAMPLE_TOKEN", "EXAMPLE_QUERY_KEY"])
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.query["key"], "real-query-value")

    def test_control_endpoint_authentication(self):
        async def call(flow):
            handled = await self.entry._approval_route(flow, poll_seconds=0.01)
            return handled, flow.response.status_code

        self.assertEqual(run(call(self.control("/approvals/next", approver=None))), (True, 403))
        self.assertEqual(run(call(self.control("/approvals/next", approver=PROXY))), (True, 403),
                         "the requester's proxy capability cannot approve")
        self.assertEqual(run(call(self.control("/approvals/next", instance="ef" * 16))), (True, 409))
        self.assertEqual(run(call(self.control("/approvals/next", instance=None))), (True, 409))
        self.assertEqual(run(call(self.control("/approvals/next"))), (True, 204))
        self.assertEqual(run(call(self.control("/approvals/next", "POST"))), (True, 405))
        self.assertEqual(run(call(self.control("/approvals/" + "0" * 32, "POST", {"choice": "allow-once"}))),
                         (True, 404))
        plain = self.control("/approvals/next")
        plain.request.scheme = "http"
        self.assertEqual(run(call(plain)), (True, 403))
        with patch.object(self.entry, "_approver_digest", None):
            self.assertEqual(run(call(self.control("/approvals/next"))), (True, 503))
        other = make_flow("api.example.com", "/approvals/next")
        self.assertFalse(run(self.entry._approval_route(other)))

    def test_disabled_broker_denies_everything(self):
        approvals.configure(approvals.Broker(enabled=False))
        approvals.default_broker().poller_started()
        flow = self.token_flow()
        run(self.entry._run_with_approvals(flow, self.addon.request))
        self.assertEqual(json.loads(flow.response.content)["rule"], approvals.RULE_NO_LISTENER)

    def test_client_disconnect_withdraws_its_prompt(self):
        async def scenario():
            self.broker.poller_started()
            flow = self.token_flow()
            task = asyncio.ensure_future(self.entry._run_with_approvals(flow, self.addon.request))
            for _ in range(200):
                if self.entry._held_by_client:
                    break
                await asyncio.sleep(0.01)
            self.entry.client_disconnected(flow.client_conn)
            await task
            return flow

        flow = run(scenario())
        self.assertEqual(json.loads(flow.response.content)["rule"], approvals.RULE_WITHDRAWN)
        self.assertEqual(self.broker.pending_count(), 0)

    def test_hook_executor_is_not_occupied_while_held(self):
        async def scenario():
            self.broker.poller_started()
            held = [self.token_flow() for _ in range(40)]  # more than the executor's threads
            tasks = [asyncio.ensure_future(self.entry._run_with_approvals(f, self.addon.request)) for f in held]
            for _ in range(200):
                if self.broker.pending_count() >= 16:
                    break
                await asyncio.sleep(0.01)
            plain = make_flow("api.example.com", "/", "GET", headers={"x-api-key": REF + "EXAMPLE_PLAIN"})
            await asyncio.wait_for(self.entry._run_with_approvals(plain, self.addon.request), timeout=5)
            for item in list(self.broker._queue):
                self.broker.withdraw(item.id)
            await asyncio.gather(*tasks)
            return plain

        plain = run(scenario())
        self.assertEqual(plain.request.headers["x-api-key"], "real-plain-value")


class EgressApprovalTests(unittest.TestCase):
    def setUp(self):
        import entry
        self.entry = entry
        self.broker = approvals.configure(approvals.Broker(enabled=True, min_answer_delay=0.0, timeout=5))
        self.addCleanup(approvals.configure, approvals.Broker(enabled=False))
        policy = egress.EgressPolicy.from_config({"mode": "allowlist", "allow": ["*.example.com"],
                                                  "allowlistMiss": "approve"})
        self.resolutions = []

        def resolver(host, port):
            self.resolutions.append(host)
            return ["203.0.114.9"]

        for item in (patch.object(entry, "_egress_policy", policy), patch.object(entry, "_resolver", resolver),
                     patch.dict(entry._pins, clear=True), patch.dict(entry._connecting, clear=True),
                     patch.object(entry, "_wakeups", set()), patch.object(entry, "_held_by_client", {})):
            item.start()
            self.addCleanup(item.stop)

    def connect(self, host="new.example.net"):
        from mitmproxy.test import tflow, tutils
        return tflow.tflow(req=tutils.treq(method=b"CONNECT", host=host, port=443, path=b"",
                                           authority=f"{host}:443".encode()))

    def answer_with(self, choice):
        async def answer():
            for _ in range(500):
                item = self.broker.next_item()
                if item is not None:
                    self.broker.answer(item.id, choice)
                    self.entry._wake_approvers()
                    return item.request.describe()
                await asyncio.sleep(0.01)
        return answer()

    def test_allowlist_miss_is_held_in_connect(self):
        async def scenario(choice):
            self.broker.poller_started()
            flow = self.connect()
            answer = asyncio.ensure_future(self.answer_with(choice))
            await self.entry.http_connect(flow)
            return flow, await answer

        flow, info = asyncio.run(scenario("deny-once"))
        self.assertEqual(json.loads(flow.response.content)["rule"], approvals.RULE_DENIED)
        self.assertEqual(info, {"kind": "egress", "host": "new.example.net:443", "rule": "egress-allowlist"})
        self.assertEqual(self.entry._pins, {}, "no connection may be pinned")
        flow, _ = asyncio.run(scenario("allow-session"))
        self.assertIsNone(flow.response)
        self.assertEqual(self.entry._pinned(flow.client_conn.id, "new.example.net", 443), ("203.0.114.9",))
        again = self.connect()
        self.broker.poller_finished()
        asyncio.run(self.entry.http_connect(again))
        self.assertIsNone(again.response, "the session decision covers the host")

    def test_listed_hosts_and_no_listener(self):
        flow = self.connect("api.example.com")
        asyncio.run(self.entry.http_connect(flow))
        self.assertIsNone(flow.response)
        flow = self.connect()
        asyncio.run(self.entry.http_connect(flow))
        self.assertEqual(json.loads(flow.response.content)["rule"], approvals.RULE_NO_LISTENER)

    def test_server_connect_never_asks(self):
        from mitmproxy import connection
        from mitmproxy.proxy.server_hooks import ServerConnectionHookData
        flow = self.connect()
        server = connection.Server(address=("new.example.net", 443))
        asyncio.run(self.entry.server_connect(ServerConnectionHookData(server=server, client=flow.client_conn)))
        self.assertEqual(server.error, "secret-proxy egress refused (approval-required)")


# --- CLI ------------------------------------------------------------------------

class ClientTests(unittest.TestCase):
    def prompt(self, **change):
        value = {"instance": INSTANCE, "id": "e" * 32, "expiresIn": 100, "answerAfter": 1.0,
                 "request": {"kind": "aws", "host": "iam.amazonaws.com", "method": "POST", "path": "/",
                             "account": ACCOUNT, "role": "Admin", "service": "iam",
                             "operation": "CreateRole", "rule": "aws-policy.json rule 1"}}
        value.update(change)
        return value

    def test_prompt_validation(self):
        import client
        self.assertEqual(client.validate_prompt(self.prompt(), INSTANCE)["id"], "e" * 32)
        for change in ({"instance": "ef" * 16}, {"id": "x"}, {"expiresIn": -1}, {"answerAfter": "1"},
                       {"request": {"kind": "other"}}, {"request": {"kind": "aws", "value": "x"}},
                       {"extra": 1}):
            with self.subTest(change=change), self.assertRaises(client.ClientError):
                client.validate_prompt(self.prompt(**change), INSTANCE)

    def test_description_is_sanitised(self):
        import client
        text = client.describe_prompt(self.prompt(request={"kind": "secret", "host": "a\x1b]0;x\x07b",
                                                           "secret": "EXAMPLE_TOKEN"}))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertIn("a?]0;x?b", text)
        self.assertIn("1 deny once", text)

    def run_loop(self, answers):
        import client
        fake = Mock()
        fake.config = {"sharedDir": "/unused"}
        posted = []
        replies = []
        for answer in answers:
            replies.append((200, json.dumps(self.prompt()).encode()))

        def request(path, body=None, **kwargs):
            if body is not None:
                choice = json.loads(body)["choice"]
                posted.append((path, choice, kwargs["headers"]))
                return 200, json.dumps({"instance": INSTANCE, "id": "e" * 32,
                                        "result": "allowed" if "allow" in choice else "denied",
                                        "rule": ""}).encode()
            return replies.pop(0)

        fake.request.side_effect = lambda path, body=None, **kw: request(path, body, **kw)
        iterator = iter(answers)

        def reader(fd, delay, timeout):
            value = next(iterator)
            if isinstance(value, BaseException):
                raise value
            return value

        out = io.StringIO()
        with patch.object(client, "private_read", return_value=json.dumps({"instance": INSTANCE}).encode()):
            try:
                client.approvals_loop(fake, APPROVER, out=out, reader=reader, rounds=len(answers))
            except KeyboardInterrupt:
                pass
        return posted, out.getvalue()

    def test_choices_and_malformed_input(self):
        posted, output = self.run_loop(["2", "3", "4", "1", "yes", ""])
        self.assertEqual([choice for _path, choice, _h in posted],
                         ["allow-once", "allow-session", "deny-session", "deny-once", "deny-once", "deny-once"])
        self.assertEqual(posted[0][0], "/approvals/" + "e" * 32)
        self.assertEqual(posted[0][2], {"X-Secret-Proxy-Approver": APPROVER, "X-Secret-Proxy-Instance": INSTANCE})
        self.assertNotIn(APPROVER, output)

    def test_timeout_posts_nothing_and_interrupt_denies(self):
        posted, _ = self.run_loop([None])
        self.assertEqual(posted, [])
        posted, _ = self.run_loop([KeyboardInterrupt()])
        self.assertEqual([choice for _path, choice, _h in posted], ["deny-once"])

    def test_read_choice_discards_type_ahead(self):
        import client
        master, slave = os.openpty()
        try:
            def typing_during_delay(_seconds):
                os.write(master, b"2\n")  # typed before the prompt accepted input
                time.sleep(0.05)
            later = threading.Timer(0.2, lambda: os.write(master, b"4\n"))
            later.start()
            try:
                self.assertEqual(client.read_choice(slave, 0.0, 5.0, sleep=typing_during_delay), "4")
            finally:
                later.cancel()
            self.assertIsNone(client.read_choice(slave, 0.0, 1.2, sleep=lambda _s: None))
        finally:
            os.close(master)
            os.close(slave)


class LaunchTests(unittest.TestCase):
    def test_runtime_passes_only_a_digest(self):
        import hashlib
        from runtime import command
        argv, env = command(Path("/config"), Path("/state"), Path("/tmp/auth"), 10256,
                            {"op_token": "fixture", "proxy_token": PROXY, "approver_token": APPROVER})
        self.assertEqual(env["SECRET_PROXY_APPROVER_DIGEST"], hashlib.sha256(APPROVER.encode()).hexdigest())
        self.assertNotIn(APPROVER, json.dumps([argv, env]))
        _argv, env = command(Path("/config"), Path("/state"), Path("/tmp/auth"), 10256,
                             {"op_token": "fixture", "proxy_token": PROXY})
        self.assertNotIn("SECRET_PROXY_APPROVER_DIGEST", env)

    def test_bootstrap_approver_field(self):
        from test_runtime import RuntimeTests
        reader = RuntimeTests("test_bootstrap_exact_fields_and_types")
        good = {"op_token": "fixture", "proxy_token": PROXY, "approver_token": APPROVER}
        self.assertEqual(reader.read(json.dumps(good).encode()), good)
        for bad in ({**good, "approver_token": PROXY}, {**good, "approver_token": "short"},
                    {**good, "approver_token": 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                reader.read(json.dumps(bad).encode())

    def test_manage_approvals_runs_as_secagent_through_host(self):
        import manage
        settings = {"instance": "candidate", "bootstrap": "/private/example/bootstrap.json", "op": "/opt/example/op"}
        with patch.object(manage.os, "execv") as execute, patch.object(manage.os, "isatty", return_value=True):
            manage.execute(settings, "approvals")
        self.assertEqual(execute.call_args.args[1], [manage.PYTHON, str(manage.ROOT / "current/host.py"),
                                                     "approvals", "candidate"])
        with patch.object(manage.os, "execv") as execute, patch.object(manage.os, "isatty", return_value=False), \
                self.assertRaises(manage.ClientError):
            manage.execute(settings, "approvals")
        execute.assert_not_called()



class HostApproverTests(unittest.TestCase):
    """host.serve: a fresh private approver capability, never any client token."""

    def setUp(self):
        from test_clients import HostTokenTests, SCOPED
        self.helper = HostTokenTests("test_serve_without_clients_sends_todays_bundle")
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)
        self.scoped = SCOPED

    def test_approver_is_private_fresh_and_distinct(self):
        helper = self.helper
        helper.write_manifest(self.scoped)
        first = helper.run_serve()
        second = helper.run_serve()
        approver = first["approver_token"]
        self.assertRegex(approver, r"^[0-9a-f]{48}$")
        self.assertNotEqual(approver, second["approver_token"], "a new capability every boot")
        tokens = {first["proxy_token"], *first["client_tokens"].values()}
        self.assertNotIn(approver, tokens, "no client token is an approver")
        for path in helper.deployment.shared.iterdir():
            self.assertNotIn(approver, path.read_text(), path.name)
        self.assertFalse((helper.deployment.private / "approver-token").exists(), "removed on exit")

    def test_runtime_refuses_an_approver_equal_to_a_client_token(self):
        from test_runtime import RuntimeTests
        reader = RuntimeTests("test_bootstrap_exact_fields_and_types")
        bundle = {"op_token": "fixture", "proxy_token": PROXY, "client_tokens": {"reader": "f" * 48}}
        self.assertEqual(reader.read(json.dumps({**bundle, "approver_token": APPROVER}).encode())["approver_token"],
                         APPROVER)
        with self.assertRaises(ValueError):
            reader.read(json.dumps({**bundle, "approver_token": "f" * 48}).encode())


if __name__ == "__main__":
    unittest.main()
