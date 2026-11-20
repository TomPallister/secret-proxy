"""Opt-in login store: proxy-owned logins persisted in a read/write vault.

Offline only: a fake op runner holds the "vault" in memory and records every
argv, environment and stdin. No real op, vault, OpenAI or GitHub call.
"""
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mitmproxy import http

import addon
import chatgptcreds
import client
import copilotcreds
import ghclicreds
import host
import loginstore
import macos_install
import manage
import runtime
from chatgptcreds import ChatGPTAuthError, ChatGPTCredentials
from copilotcreds import CopilotCredentials
from ghclicreds import GhCliCredentials
from host import HostError, validate_bootstrap_config, validate_bootstrap_item
from loginstore import LoginStore, LoginStoreError, Persistence
from secretstore import LoginStoreConfigError, SecretManifest, check_login_vault
from test_chatgptcreds import jwt
from test_copilotcreds import GITHUB_TOKEN, Clock, FakeGitHub
from test_ghclicreds import FakeGitHub as FakeGhGitHub, GH_TOKEN

ROOT = Path(__file__).resolve().parent
OP_TOKEN = "ops_" + "fixturecapability" * 3
REFRESH = "refresh-" + "rotating" * 4
INSTANCE = "c" * 32


class FakeOp:
    """An in-memory login vault behind the op CLI's argv contract."""

    def __init__(self):
        self.calls = []
        self.items = {}  # id -> item
        self.fail = set()  # operations to fail: list, get, create, edit, delete
        self.next_id = 0

    def add(self, title, value, metadata=None, item_id=None):
        item_id = item_id or self._new_id()
        fields = [{"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": value}]
        fields += [{"id": k, "type": "STRING", "label": k, "value": v} for k, v in (metadata or {}).items()]
        self.items[item_id] = {"id": item_id, "title": title, "category": "LOGIN", "fields": fields}
        return item_id

    def _new_id(self):
        self.next_id += 1
        return ("item%022d" % self.next_id)[:26]

    def value(self, title):
        found = [item for item in self.items.values() if item["title"] == title]
        if not found:
            return None
        assert len(found) == 1
        return next(f["value"] for f in found[0]["fields"] if f["id"] == "password")

    def run(self, args, *, env=None, input=None, timeout=None):
        self.calls.append({"args": list(args), "env": dict(env or {}), "input": input, "timeout": timeout})
        assert args[0] == "/usr/local/bin/op" and timeout is not None
        assert args[args.index("--vault") + 1] == "Logins"
        operation = args[2]
        if operation in self.fail:
            return subprocess.CompletedProcess(args, 1, "", "op failed for " + (input or ""))
        if operation == "list":
            out = [{"id": item["id"], "title": item["title"]} for item in self.items.values()]
            return subprocess.CompletedProcess(args, 0, json.dumps(out), "")
        if operation == "get":
            return subprocess.CompletedProcess(args, 0, json.dumps(self.items[args[3]]), "")
        if operation == "create":
            assert args[-1] == "-"
            template = json.loads(input)
            item_id = self._new_id()
            self.items[item_id] = {"id": item_id, **template}
            return subprocess.CompletedProcess(args, 0, "{}", "")
        if operation == "edit":
            template = json.loads(input)
            self.items[args[3]] = {"id": args[3], **template}
            return subprocess.CompletedProcess(args, 0, "{}", "")
        if operation == "delete":
            del self.items[args[3]]
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError("unexpected op command")


def store(op=None):
    op = op or FakeOp()
    return LoginStore("Logins", OP_TOKEN, runner=op, runtime_env={}), op


def all_text(op):
    """Everything op ever saw except stdin: argv and environment."""
    return json.dumps([[call["args"], {k: v for k, v in call["env"].items() if k != "OP_SERVICE_ACCOUNT_TOKEN"}]
                       for call in op.calls])


def manifest_data(**extra):
    data = json.loads((ROOT / "examples" / "manifest.json").read_text())
    data.update(extra)
    return data


def load(data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "manifest.json"
        path.write_text(json.dumps(data))
        return SecretManifest.load(path)


class LoginStoreTests(unittest.TestCase):
    def test_create_then_edit_and_values_only_on_stdin(self):
        login, op = store()
        login.save("github", GH_TOKEN, {"domain": "github.com", "scopes": "repo", "requested_scopes": "repo"})
        self.assertEqual([c["args"][2] for c in op.calls], ["list", "create"])
        self.assertEqual(op.value("SECRET_PROXY_LOGIN_GITHUB"), GH_TOKEN)
        login.save("github", GH_TOKEN + "2", {"domain": "github.com"})
        self.assertEqual([c["args"][2] for c in op.calls], ["list", "create", "list", "edit"])
        self.assertEqual(len(op.items), 1)
        self.assertEqual(op.value("SECRET_PROXY_LOGIN_GITHUB"), GH_TOKEN + "2")
        self.assertNotIn(GH_TOKEN, all_text(op))
        self.assertIn(GH_TOKEN, op.calls[1]["input"])
        template = json.loads(op.calls[1]["input"])
        self.assertEqual(template["title"], "SECRET_PROXY_LOGIN_GITHUB")
        self.assertEqual(template["category"], "LOGIN")
        password = [f for f in template["fields"] if f["id"] == "password"]
        self.assertEqual(password[0]["type"], "CONCEALED")
        # Only the selected capability, a fixed PATH/HOME and op's config dir.
        env = op.calls[0]["env"]
        self.assertEqual(env["OP_SERVICE_ACCOUNT_TOKEN"], OP_TOKEN)
        self.assertEqual(set(env), {"PATH", "HOME", "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONFIG_DIR"})

    def test_read_and_delete(self):
        login, op = store()
        self.assertIsNone(login.read("chatgpt"))
        op.add("SECRET_PROXY_LOGIN_CHATGPT", REFRESH, {"account_id": "account-1", "ignored": "x"})
        found = login.read("chatgpt")
        self.assertEqual((found.value, found.metadata), (REFRESH, {"account_id": "account-1"}))
        self.assertNotIn(REFRESH, repr(found))
        self.assertTrue(login.delete("chatgpt"))
        self.assertFalse(login.delete("chatgpt"))
        self.assertEqual(op.items, {})

    def test_duplicates_are_refused_without_writing(self):
        login, op = store()
        op.add("SECRET_PROXY_LOGIN_GITHUB", "one-token-value")
        op.add("SECRET_PROXY_LOGIN_GITHUB", "two-token-value")
        for action in (lambda: login.read("github"), lambda: login.delete("github"),
                       lambda: login.save("github", GH_TOKEN, {})):
            with self.subTest(action=action), self.assertRaisesRegex(LoginStoreError, "more than one"):
                action()
        self.assertEqual({c["args"][2] for c in op.calls}, {"list"})

    def test_failures_never_carry_values_or_op_output(self):
        login, op = store()
        op.fail.add("create")
        with self.assertRaises(LoginStoreError) as error:
            login.save("github", GH_TOKEN, {})
        self.assertNotIn(GH_TOKEN, str(error.exception))
        self.assertNotIn("op failed", str(error.exception))
        timeout = Mock(side_effect=subprocess.TimeoutExpired(["op"], 20))
        with self.assertRaisesRegex(LoginStoreError, "timed out"):
            LoginStore("Logins", OP_TOKEN, runner=Mock(run=timeout)).read("github")

    def test_invalid_values_and_items_are_refused(self):
        login, op = store()
        for value in ("", "has space", "line\nbreak", "x" * 20000):
            with self.subTest(value=value[:10]), self.assertRaises(LoginStoreError):
                login.save("github", value, {})
        with self.assertRaises(LoginStoreError):
            login.save("github", GH_TOKEN, {"unknown": "x"})
        self.assertEqual(op.calls, [])
        item_id = op.add("SECRET_PROXY_LOGIN_GITHUB", GH_TOKEN)
        op.items[item_id]["category"] = "PASSWORD"
        with self.assertRaisesRegex(LoginStoreError, "not the expected Login item"):
            login.read("github")


class PersistenceTests(unittest.TestCase):
    def test_write_failure_keeps_pending_and_retries_with_backoff(self):
        clock = Clock()
        login, op = store()
        persist = Persistence(login, "github", clock)
        op.fail.add("create")
        with self.assertLogs("secret_proxy", "WARNING") as logs:
            self.assertFalse(persist.save(GH_TOKEN, {}))
        self.assertNotIn(GH_TOKEN, "\n".join(logs.output))
        self.assertFalse(persist.stored)
        calls = len(op.calls)
        self.assertFalse(persist.flush())  # not yet due: no vault request
        self.assertEqual(len(op.calls), calls)
        op.fail.clear()
        clock.now += loginstore.FIRST_RETRY
        self.assertTrue(persist.flush())
        self.assertTrue(persist.stored)
        self.assertEqual(op.value("SECRET_PROXY_LOGIN_GITHUB"), GH_TOKEN)
        self.assertTrue(persist.flush())  # nothing pending: no request
        self.assertEqual(len(op.calls), calls + 2)

    def test_backoff_is_bounded(self):
        clock = Clock()
        login, op = store()
        op.fail.add("list")
        persist = Persistence(login, "github", clock)
        with self.assertLogs("secret_proxy", "WARNING"):
            persist.save(GH_TOKEN, {})
            for _ in range(20):
                clock.now += loginstore.MAX_RETRY
                persist.flush()
        self.assertEqual(persist._backoff, loginstore.MAX_RETRY)

    def test_unreadable_vault_restores_later_not_on_every_use(self):
        clock = Clock()
        login, op = store()
        op.fail.add("list")
        persist = Persistence(login, "github", clock)
        with self.assertLogs("secret_proxy", "WARNING"):
            self.assertIsNone(persist.take_restore())
        self.assertIsNone(persist.take_restore())
        self.assertEqual(len(op.calls), 1)
        op.fail.clear()
        op.add("SECRET_PROXY_LOGIN_GITHUB", GH_TOKEN)
        clock.now += loginstore.FIRST_RETRY
        self.assertEqual(persist.take_restore().value, GH_TOKEN)
        self.assertIsNone(persist.take_restore())  # once per start


def chatgpt(op, clock, responses, calls=None):
    calls = [] if calls is None else calls

    def request(fields):
        calls.append(dict(fields))
        answer = responses.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer
    login, _ = store(op)
    return ChatGPTCredentials(request=request, clock=clock, store=login), calls


def chatgpt_login(provider):
    from urllib.parse import parse_qs, urlsplit
    state = parse_qs(urlsplit(provider.start()).query)["state"][0]
    return provider.finish("http://localhost:1455/auth/callback?code=one-time-code&state=" + state)


def pair(n, account="account-1"):
    return {"access_token": jwt(account, "signature%d" % n), "refresh_token": "refresh-%d-%s" % (n, "r" * 20),
            "expires_in": 3600}


class ChatGPTStoreTests(unittest.TestCase):
    TITLE = "SECRET_PROXY_LOGIN_CHATGPT"

    def test_login_rotation_and_restart_restore(self):
        clock, op = Clock(), FakeOp()
        provider, calls = chatgpt(op, clock, [pair(1), pair(2)])
        chatgpt_login(provider)
        self.assertEqual(op.value(self.TITLE), pair(1)["refresh_token"])
        clock.now += 3500
        provider.get_token()
        self.assertEqual(op.value(self.TITLE), pair(2)["refresh_token"])  # rotation written back
        # A restarted proxy: a new provider over the same vault, no login.
        restarted, calls = chatgpt(op, clock, [pair(3)])
        self.assertEqual(restarted.get_token(), pair(3)["access_token"])
        self.assertEqual(calls, [{"grant_type": "refresh_token", "client_id": chatgptcreds.CLIENT_ID,
                                  "refresh_token": pair(2)["refresh_token"]}])
        self.assertEqual(op.value(self.TITLE), pair(3)["refresh_token"])
        status = restarted.status()
        self.assertEqual((status["loggedIn"], status["stored"], status["restoredFromStore"]), (True, True, True))
        self.assertEqual(len(calls), 1)  # restored once only
        self.assertNotIn(pair(3)["refresh_token"], all_text(op) + json.dumps(status))

    def test_rejected_stored_token_logs_out_with_fixed_message(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, REFRESH, {"account_id": "account-1"})
        provider, calls = chatgpt(op, clock, [ChatGPTAuthError("x", "rejected")])
        with self.assertLogs("secret_proxy", "WARNING") as logs:
            with self.assertRaisesRegex(ChatGPTAuthError, "login required"):
                provider.get_token()
        self.assertIn("stored ChatGPT login is no longer valid; run secret-proxy login chatgpt", logs.output[0])
        self.assertNotIn(REFRESH, "\n".join(logs.output))
        self.assertEqual(op.value(self.TITLE), REFRESH)  # not deleted automatically
        with self.assertRaisesRegex(ChatGPTAuthError, "login required"):
            provider.get_token()
        self.assertEqual(len(calls), 1)  # never offered again
        self.assertEqual(provider.status()["loggedIn"], False)

    def test_unreachable_upstream_keeps_the_stored_token_for_later(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, REFRESH, {"account_id": "account-1"})
        provider, calls = chatgpt(op, clock, [ChatGPTAuthError("x", "unreachable"), pair(1)])
        with self.assertLogs("secret_proxy", "WARNING"):
            with self.assertRaises(ChatGPTAuthError):
                provider.get_token()
        with self.assertRaises(ChatGPTAuthError):
            provider.get_token()  # backoff: not retried immediately
        self.assertEqual(len(calls), 1)
        clock.now += loginstore.FIRST_RETRY
        self.assertEqual(provider.get_token(), pair(1)["access_token"])
        self.assertEqual([c["refresh_token"] for c in calls], [REFRESH, REFRESH])

    def test_ambiguous_failure_does_not_reuse_the_token(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, REFRESH, {"account_id": "account-1"})
        provider, calls = chatgpt(op, clock, [ChatGPTAuthError("x"), pair(1)])
        with self.assertLogs("secret_proxy", "WARNING") as logs:
            with self.assertRaises(ChatGPTAuthError):
                provider.get_token()
        self.assertIn("could not restore the stored ChatGPT login", logs.output[0])
        clock.now += loginstore.MAX_RETRY
        with self.assertRaises(ChatGPTAuthError):
            provider.get_token()
        self.assertEqual(len(calls), 1)

    def test_restore_refuses_another_account_or_missing_account(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, REFRESH, {"account_id": "account-1"})
        provider, _ = chatgpt(op, clock, [pair(1, "account-2")])
        with self.assertLogs("secret_proxy", "WARNING"), self.assertRaises(ChatGPTAuthError):
            provider.get_token()
        op2 = FakeOp()
        op2.add(self.TITLE, REFRESH)
        provider, calls = chatgpt(op2, clock, [pair(1)])
        with self.assertLogs("secret_proxy", "WARNING"), self.assertRaises(ChatGPTAuthError):
            provider.get_token()
        self.assertEqual(calls, [])

    def test_unreadable_vault_behaves_as_logged_out(self):
        clock, op = Clock(), FakeOp()
        op.fail.add("list")
        provider, calls = chatgpt(op, clock, [])
        with self.assertLogs("secret_proxy", "WARNING") as logs:
            status = provider.status()
        self.assertEqual((status["loggedIn"], status["stored"]), (False, False))
        self.assertIn("could not read the stored ChatGPT login", logs.output[0])

    def test_failed_write_still_logs_in_and_retries_on_next_use(self):
        clock, op = Clock(), FakeOp()
        op.fail.add("create")
        provider, _ = chatgpt(op, clock, [pair(1)])
        with self.assertLogs("secret_proxy", "WARNING"):
            credential = chatgpt_login(provider)
        self.assertEqual(credential["accountId"], "account-1")
        self.assertIsNone(op.value(self.TITLE))
        op.fail.clear()
        clock.now += loginstore.FIRST_RETRY
        provider.get_token()
        self.assertEqual(op.value(self.TITLE), pair(1)["refresh_token"])

    def test_logout_clears_ram_and_deletes(self):
        clock, op = Clock(), FakeOp()
        provider, _ = chatgpt(op, clock, [pair(1)])
        chatgpt_login(provider)
        self.assertEqual(provider.logout(), {"stored": False})
        self.assertIsNone(op.value(self.TITLE))
        with self.assertRaisesRegex(ChatGPTAuthError, "login required"):
            provider.get_token()
        op.add(self.TITLE, REFRESH, {"account_id": "account-1"})
        with self.assertRaises(ChatGPTAuthError):
            provider.get_token()  # a logout is not undone by a later restore

    def test_failed_delete_on_logout_is_never_restored(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, REFRESH, {"account_id": "account-1"})
        provider, calls = chatgpt(op, clock, [pair(1)])
        op.fail.add("delete")
        with self.assertLogs("secret_proxy", "WARNING"):
            self.assertEqual(provider.logout(), {"stored": True})
        op.fail.add("delete")
        with self.assertLogs("secret_proxy", "WARNING"), self.assertRaisesRegex(ChatGPTAuthError, "login required"):
            clock.now += loginstore.FIRST_RETRY
            provider.get_token()
        self.assertEqual(calls, [])  # the stored token was not used after logout

    def test_pre_send_errors_are_classified(self):
        import socket
        import urllib.error
        cases = [(urllib.error.URLError(socket.gaierror()), "unreachable"),
                 (urllib.error.URLError(ConnectionRefusedError()), "unreachable"),
                 (urllib.error.URLError(TimeoutError()), None),
                 (urllib.error.HTTPError("u", 400, "x", {}, None), "rejected"),
                 (urllib.error.HTTPError("u", 429, "x", {}, None), "unreachable"),
                 (urllib.error.HTTPError("u", 503, "x", {}, None), None)]
        for error, reason in cases:
            with self.subTest(error=error), patch("urllib.request.urlopen", side_effect=error):
                with self.assertRaises(ChatGPTAuthError) as caught:
                    ChatGPTCredentials._post({"grant_type": "refresh_token"})
                self.assertEqual(caught.exception.reason, reason)


def copilot(op, clock, fake):
    login, _ = store(op)
    return CopilotCredentials(request=fake, clock=clock, sleep=clock.sleep, store=login)


class CopilotStoreTests(unittest.TestCase):
    TITLE = "SECRET_PROXY_LOGIN_GITHUB_COPILOT"

    def test_login_stores_only_the_github_token_and_restart_mints_again(self):
        clock, op = Clock(), FakeOp()
        fake = FakeGitHub(clock)
        provider = copilot(op, clock, fake)
        provider.start()
        fake.polls.append({"access_token": GITHUB_TOKEN})
        provider.poll()
        self.assertEqual(op.value(self.TITLE), GITHUB_TOKEN)
        self.assertEqual(len(op.items), 1)
        restarted = copilot(op, clock, fake)
        before = fake.exchanges
        self.assertIn("proxy-ep=", restarted.get_token())
        self.assertEqual(fake.exchanges, before + 1)
        status = restarted.status()
        self.assertEqual((status["loggedIn"], status["stored"], status["restoredFromStore"]), (True, True, True))
        self.assertNotIn(GITHUB_TOKEN, all_text(op))

    def test_rejected_token_logs_out(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, GITHUB_TOKEN, {"domain": "github.com"})
        fake = FakeGitHub(clock)
        fake.exchange_status = 401
        provider = copilot(op, clock, fake)
        with self.assertLogs("secret_proxy", "WARNING") as logs:
            with self.assertRaisesRegex(copilotcreds.CopilotAuthError, "login required"):
                provider.get_token()
        self.assertIn("no longer valid", logs.output[0])
        self.assertEqual(provider.status()["restoredFromStore"], False)

    def test_transient_exchange_failure_retries(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, GITHUB_TOKEN, {"domain": "github.com"})
        fake = FakeGitHub(clock)
        fake.exchange_status = 500
        provider = copilot(op, clock, fake)
        with self.assertLogs("secret_proxy", "WARNING"):
            with self.assertRaisesRegex(copilotcreds.CopilotAuthError, "retry shortly"):
                provider.get_token()
        fake.exchange_status = 200
        clock.now += copilotcreds.RETRY_DELAY
        self.assertIn("proxy-ep=", provider.get_token())

    def test_other_domain_is_not_restored(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, GITHUB_TOKEN, {"domain": "github.example.com"})
        fake = FakeGitHub(clock)
        provider = copilot(op, clock, fake)
        with self.assertLogs("secret_proxy", "WARNING"):
            self.assertIsNone(provider.api_host())
        self.assertEqual(fake.exchanges, 0)

    def test_logout(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, GITHUB_TOKEN, {"domain": "github.com"})
        provider = copilot(op, clock, FakeGitHub(clock))
        provider.get_token()
        self.assertEqual(provider.logout(), {"stored": False})
        self.assertEqual(op.items, {})
        with self.assertRaisesRegex(copilotcreds.CopilotAuthError, "login required"):
            provider.get_token()


def ghcli(op, clock, fake, scopes=ghclicreds.DEFAULT_SCOPES):
    login, _ = store(op)
    return GhCliCredentials(scopes=scopes, request=fake, clock=clock, sleep=clock.sleep, store=login)


class GhCliStoreTests(unittest.TestCase):
    TITLE = "SECRET_PROXY_LOGIN_GITHUB"

    def test_login_and_restore(self):
        clock, op = Clock(), FakeOp()
        provider = ghcli(op, clock, FakeGhGitHub())
        provider.start()
        provider.poll()
        item = next(iter(op.items.values()))
        self.assertEqual({f["label"]: f["value"] for f in item["fields"] if f["type"] == "STRING"},
                         {"domain": "github.com", "scopes": "gist read:org repo",
                          "requested_scopes": "repo read:org gist"})
        restarted = ghcli(op, clock, FakeGhGitHub())
        self.assertEqual(restarted.get_token(), GH_TOKEN)
        self.assertEqual(restarted.status(), {"loggedIn": True, "scopes": ["gist", "read:org", "repo"],
                                              "stored": True, "restoredFromStore": True})

    def test_other_settings_are_not_restored(self):
        clock, op = Clock(), FakeOp()
        op.add(self.TITLE, GH_TOKEN, {"domain": "github.com", "scopes": "repo", "requested_scopes": "repo read:org gist"})
        provider = ghcli(op, clock, FakeGhGitHub(), scopes=("repo", "workflow"))
        with self.assertLogs("secret_proxy", "WARNING"), self.assertRaises(ghclicreds.GhCliAuthError):
            provider.get_token()

    def test_without_a_store_status_and_behaviour_are_unchanged(self):
        provider = GhCliCredentials()
        self.assertEqual(provider.status(), {"loggedIn": False, "scopes": []})
        self.assertEqual(provider.logout(), {"stored": False})
        self.assertEqual(ChatGPTCredentials().status(), {'loggedIn': False, 'expiresAt': None, 'refreshCount': 0,
                                                         'lastRefreshAt': None, 'lastRefreshDueAt': None})
        self.assertEqual(set(CopilotCredentials().status()), {"loggedIn", "expiresAt", "refreshCount", "lastRefreshAt"})


class ManifestTests(unittest.TestCase):
    def test_absent_means_off(self):
        manifest = load(manifest_data())
        self.assertIsNone(manifest.login_vault())
        self.assertIsNone(addon._login_store_for(manifest))
        check_login_vault(manifest, None)
        with self.assertRaises(LoginStoreConfigError):
            check_login_vault(manifest, "Logins")

    def test_valid_and_invalid(self):
        self.assertEqual(load(manifest_data(loginStore={"vault": "Logins"})).login_vault(), "Logins")
        for value in ({"vault": "Automation"}, {"vault": ""}, {"vault": " "}, {"vault": "a\nb"}, {"vault": 1},
                      {}, {"vault": "Logins", "extra": 1}, "Logins", []):
            with self.subTest(value=value), self.assertRaises(ValueError):
                load(manifest_data(loginStore=value))
        data = manifest_data(loginStore={"vault": "Logins"})
        del data["secrets"]["CHATGPT_ACCESS_TOKEN"]
        with self.assertRaisesRegex(LoginStoreConfigError, "requires a proxy-owned login"):
            load(data)
        manifest = load(manifest_data(loginStore={"vault": "Logins"}))
        check_login_vault(manifest, "Logins")
        for declared in (None, "Other"):
            with self.subTest(declared=declared), self.assertRaises(LoginStoreConfigError):
                check_login_vault(manifest, declared)

    def test_example_manifest_is_valid(self):
        manifest = SecretManifest.load(ROOT / "examples" / "login-store-manifest.json")
        self.assertEqual(manifest.login_vault(), "Logins")

    def test_addon_store_uses_the_runtime_capability(self):
        manifest = load(manifest_data(loginStore={"vault": "Logins"}))
        with patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": OP_TOKEN}):
            created = addon._login_store_for(manifest)
        self.assertEqual(created.vault, "Logins")
        with patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": ""}), self.assertRaises(LoginStoreError):
            addon._login_store_for(manifest)


class AddonTests(unittest.TestCase):
    @staticmethod
    def flow(host, method, path, auth=None, body=b"", headers=None):
        request = http.Request.make(method, "https://" + host + path, content=body, headers=headers or {})
        if auth:
            request.headers["Authorization"] = auth
        flow = http.HTTPFlow(None, None)
        flow.request = request
        return flow

    def use(self, data, op):
        class Resolver:
            def get(self, name):
                raise AssertionError("must not read the runtime vault: " + name)
        self.clock = Clock()
        login, _ = store(op)
        self.generation = addon._StoreGeneration(load(data), Resolver(), addon._ProviderState(login_store=login))
        patcher = patch.object(addon, "_capture_generation", return_value=self.generation)
        patcher.start()
        self.addCleanup(patcher.stop)
        env = patch.dict(os.environ, {"SECRET_PROXY_INSTANCE_ID": INSTANCE})
        env.start()
        self.addCleanup(env.stop)

    def send(self, flow):
        addon.requestheaders(flow)
        addon.request(flow)
        return flow

    def logout(self, path, headers=None, method="POST"):
        return self.send(self.flow(addon.SENTINEL_HOST, method, path,
                                   headers={"X-Secret-Proxy-Instance": INSTANCE} if headers is None else headers))

    def github_data(self, **extra):
        data = json.loads((ROOT / "examples" / "github-manifest.json").read_text())
        data["loginStore"] = {"vault": "Logins"}
        data.update(extra)
        return data

    def test_copilot_exchange_works_after_restart_without_login(self):
        op = FakeOp()
        op.add(CopilotStoreTests.TITLE, GITHUB_TOKEN, {"domain": "github.com"})
        self.use(self.github_data(), op)
        fake = FakeGitHub(self.clock)
        self.generation.providers.github["copilot"] = copilot(op, self.clock, fake)
        if True:
            reference = "Bearer " + "secre" + "tref:" + copilotcreds.CANONICAL
            answer = self.send(self.flow("api.github.com", "GET", copilotcreds.EXCHANGE_PATH, reference))
            self.assertEqual(answer.response.status_code, 200)
            body = json.loads(answer.response.content)
            self.assertTrue(copilotcreds.is_sealed(body["token"]))
            self.assertNotIn(GITHUB_TOKEN.encode(), answer.response.content)
            # The restored token is pinned to its own proxy-ep host.
            wrong = self.send(self.flow("api.business.githubcopilot.com", "POST", "/chat/completions",
                                        reference, b"{}"))
            self.assertEqual(wrong.response.status_code, 403)
            self.assertNotIn(GITHUB_TOKEN, json.dumps(dict(wrong.request.headers)))
            right = self.send(self.flow("api.individual.githubcopilot.com", "POST", "/chat/completions",
                                        reference, b"{}"))
            self.assertIsNone(right.response)
            self.assertTrue(right.request.headers["authorization"].startswith("Bearer tid=fixture-tid"))

    def test_restored_copilot_token_is_pinned_on_the_first_request(self):
        op = FakeOp()
        op.add(CopilotStoreTests.TITLE, GITHUB_TOKEN, {"domain": "github.com"})
        self.use(self.github_data(), op)
        fake = FakeGitHub(self.clock)
        self.generation.providers.github["copilot"] = copilot(op, self.clock, fake)
        reference = "Bearer " + "secre" + "tref:" + copilotcreds.CANONICAL
        wrong = self.send(self.flow("api.business.githubcopilot.com", "POST", "/chat/completions", reference, b"{}"))
        self.assertEqual(wrong.response.status_code, 403)
        self.assertFalse(wrong.request.headers["authorization"].startswith("Bearer tid="))

    def test_gh_injection_after_restart(self):
        op = FakeOp()
        op.add(GhCliStoreTests.TITLE, GH_TOKEN, {"domain": "github.com", "scopes": "repo",
                                                 "requested_scopes": "repo read:org gist"})
        self.use(self.github_data(), op)
        flow = self.send(self.flow("api.github.com", "GET", "/user", "token " + "secre" + "tref:" + ghclicreds.CANONICAL))
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers["authorization"], "token " + GH_TOKEN)

    def test_logout_route(self):
        op = FakeOp()
        op.add(GhCliStoreTests.TITLE, GH_TOKEN, {"domain": "github.com", "scopes": "repo",
                                                 "requested_scopes": "repo read:org gist"})
        self.use(self.github_data(), op)
        with addon._bind_generation(self.generation):
            provider = addon._github_provider(addon._GITHUB_LOGINS[1])
        self.assertIsNotNone(provider._store)  # the factory passes the generation's store
        self.assertEqual(provider.get_token(), GH_TOKEN)
        for headers, status in (({}, 409), ({"X-Secret-Proxy-Instance": "d" * 32}, 409)):
            with self.subTest(headers=headers):
                self.assertEqual(self.logout("/github/logout", headers).response.status_code, status)
        self.assertEqual(self.logout("/github/logout", method="GET").response.status_code, 405)
        self.assertEqual(self.logout("/github/logout?x=1").response.status_code, 400)
        self.assertEqual(provider.get_token(), GH_TOKEN)  # refused attempts change nothing
        done = self.logout("/github/logout")
        self.assertEqual(json.loads(done.response.content), {"instance": INSTANCE, "loggedOut": True, "stored": False})
        self.assertEqual(op.items, {})
        with self.assertRaises(ghclicreds.GhCliAuthError):
            provider.get_token()
        self.assertEqual(self.logout("/chatgpt/logout").response.status_code, 403)  # not enabled here

    def test_logout_failure_is_reported_and_retried(self):
        op = FakeOp()
        op.add(ChatGPTStoreTests.TITLE, REFRESH, {"account_id": "account-1"})
        self.use(manifest_data(loginStore={"vault": "Logins"}), op)
        op.fail.add("delete")
        with self.assertLogs("secret_proxy", "WARNING"):
            done = self.logout("/chatgpt/logout")
        self.assertEqual(json.loads(done.response.content)["stored"], True)
        self.assertNotIn(REFRESH.encode(), done.response.content)
        op.fail.clear()
        self.clock.now += loginstore.FIRST_RETRY
        provider = self.generation.providers.chatgpt
        provider._clock = provider._store._clock = lambda: 2e9
        status = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/chatgpt/status"))
        self.assertEqual(json.loads(status.response.content)["stored"], False)
        self.assertEqual(op.items, {})

    def test_logout_needs_the_login_grant(self):
        data = manifest_data(loginStore={"vault": "Logins"},
                             clients={"default": {"all": True}, "reader": {"secrets": {"GITHUB_TOKEN": True}}})
        self.use(data, FakeOp())
        flow = self.flow(addon.SENTINEL_HOST, "POST", "/chatgpt/logout",
                         headers={"X-Secret-Proxy-Instance": INSTANCE})
        flow.metadata["proxyauth"] = ("reader", "")
        addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertIn(b"client_not_granted", flow.response.content)

    def test_status_route_adds_store_fields(self):
        op = FakeOp()
        self.use(manifest_data(loginStore={"vault": "Logins"}), op)
        flow = self.send(self.flow(addon.SENTINEL_HOST, "GET", "/chatgpt/status"))
        self.assertEqual(json.loads(flow.response.content), {
            "instance": INSTANCE, "loggedIn": False, "expiresAt": None, "refreshCount": 0,
            "lastRefreshAt": None, "lastRefreshDueAt": None, "stored": False, "restoredFromStore": False})

    def test_without_a_login_store_nothing_touches_op(self):
        runner = Mock()
        with patch.object(loginstore, "DefaultCommandRunner", return_value=runner):
            manifest = load(manifest_data())
            self.assertIsNone(addon._login_store_for(manifest))
            state = addon._ProviderState()
            state.chatgpt.status()
            state.chatgpt.logout()
            self.assertIsNone(state.chatgpt._store)
        runner.run.assert_not_called()


class BootstrapTests(unittest.TestCase):
    CONFIG = {'account': 'example.1password.com', 'vault': 'Private', 'item': 'Runtime capability',
              'runtimeVault': 'DevEnv'}

    def item(self, *extra):
        return {'title': self.CONFIG['item'], 'id': 'a' * 26, 'category': 'LOGIN', 'vault': {'name': 'Private'},
                'fields': [{'id': 'password', 'type': 'CONCEALED', 'purpose': 'PASSWORD', 'value': 'fixture-capability'},
                           {'label': 'account_url', 'value': self.CONFIG['account']},
                           {'label': 'destination_vault', 'value': 'DevEnv'},
                           {'label': 'permissions', 'value': 'read_items'}, *extra]}

    def test_config_login_vault(self):
        validate_bootstrap_config({**self.CONFIG, 'loginVault': 'Logins'})
        for vault in ('Private', 'DevEnv', '', '-x'):
            with self.subTest(vault=vault), self.assertRaises(HostError):
                validate_bootstrap_config({**self.CONFIG, 'loginVault': vault})
        with self.assertRaises(HostError):
            validate_bootstrap_config({**self.CONFIG, 'other': 'x'})

    def test_item_provenance(self):
        login_field = {'label': 'login_vault', 'value': 'Logins'}
        config = {**self.CONFIG, 'loginVault': 'Logins'}
        self.assertEqual(validate_bootstrap_item(self.CONFIG, self.item()), 'fixture-capability')
        self.assertEqual(validate_bootstrap_item(config, self.item(login_field)), 'fixture-capability')
        for cfg, item in ((config, self.item()), (config, self.item({'label': 'login_vault', 'value': 'Other'})),
                          (config, self.item(login_field, login_field)), (self.CONFIG, self.item(login_field))):
            with self.subTest(cfg=cfg, item=item['fields'][4:]), self.assertRaisesRegex(HostError, 'provenance'):
                validate_bootstrap_item(cfg, item)

    def test_runtime_bundle(self):
        def read(bundle):
            reader, writer = os.pipe()
            os.write(writer, json.dumps(bundle).encode())
            os.close(writer)
            try:
                return runtime.read_bootstrap(reader, timeout=5)
            finally:
                os.close(reader)
        base = {"op_token": OP_TOKEN, "proxy_token": "a" * 48}
        self.assertEqual(read({**base, "login_vault": "Logins"})["login_vault"], "Logins")
        for value in ("", 1, "a\nb"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                read({**base, "login_vault": value})

    def test_serve_refuses_a_mismatched_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            deployment = Mock(private=Path(tmp))
            (Path(tmp) / "config").mkdir()
            (Path(tmp) / "config/manifest.json").write_text(json.dumps(manifest_data(loginStore={"vault": "Logins"})))
            host.check_login_vault(deployment, "Logins")
            for declared in (None, "Other"):
                with self.subTest(declared=declared), self.assertRaisesRegex(HostError, "login"):
                    host.check_login_vault(deployment, declared)

    def test_install_cross_checks_bootstrap_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            (source / "manifest.json").write_text(json.dumps(manifest_data(loginStore={"vault": "Logins"})))
            for path in source.iterdir():
                path.chmod(0o600)
            bootstrap = source / "bootstrap.json"
            bootstrap.write_text(json.dumps({**self.CONFIG, "runtimeVault": "Automation", "loginVault": "Logins"}))
            bootstrap.chmod(0o600)
            macos_install.validate_source_config(source)
            bootstrap.write_text(json.dumps({**self.CONFIG, "runtimeVault": "Automation"}))
            with self.assertRaisesRegex(HostError, "login vault"):
                macos_install.validate_source_config(source)
            (source / "manifest.json").write_text(json.dumps(manifest_data(loginStore={"vault": "Automation"})))
            with self.assertRaisesRegex(HostError, "loginStore"):
                macos_install.validate_source_config(source)


class CliTests(unittest.TestCase):
    SETTINGS = {"instance": "candidate", "bootstrap": "/private/example/bootstrap.json", "op": "/opt/example/op"}

    def test_auth_status_accepts_both_store_fields_or_neither(self):
        status = {"instance": "a" * 32, "loggedIn": True, "scopes": ["repo"]}
        proxy = Mock()
        ready = json.dumps({"status": "ready", "instance": "a" * 32}).encode()
        with patch.object(manage, "private_read", return_value=ready):
            for value in (status, {**status, "stored": True, "restoredFromStore": False}):
                proxy.call.return_value = value
                self.assertEqual(manage.auth_status(proxy, self.SETTINGS, "github"), value)
            for change in ({"stored": True}, {"stored": "yes", "restoredFromStore": False},
                           {"stored": True, "restoredFromStore": None}):
                proxy.call.return_value = {**status, **change}
                with self.subTest(change=change), self.assertRaises(manage.ClientError):
                    manage.auth_status(proxy, self.SETTINGS, "github")

    def test_manage_logout_requires_a_provider_and_execs_the_client(self):
        with patch.object(manage.os, "execv", side_effect=SystemExit) as execv, self.assertRaises(SystemExit):
            manage.execute(self.SETTINGS, "logout", provider="github-copilot", client_name="reader")
        argv = execv.call_args[0][1]
        self.assertEqual(argv[-5:], ["--client", "reader", "logout", "--provider", "github-copilot"])
        with self.assertRaises(manage.ClientError):
            manage.execute(self.SETTINGS, "logout")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            manage.main(["logout"])

    def test_client_logout_sends_the_instance_and_checks_the_reply(self):
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / "ready.json"
            ready.write_text(json.dumps({"status": "ready", "instance": INSTANCE}))
            ready.chmod(0o600)
            proxy = Mock(config={"sharedDir": tmp})
            reply = {"instance": INSTANCE, "loggedOut": True, "stored": False}
            proxy.request.return_value = (200, json.dumps(reply).encode())
            self.assertEqual(client.logout(proxy, "chatgpt"), reply)
            proxy.request.assert_called_once_with("/chatgpt/logout", b"", headers={"X-Secret-Proxy-Instance": INSTANCE})
            for answer in ((409, b"{}"), (403, b"{}"), (200, b"[]"), (200, json.dumps({**reply, "instance": "d" * 32}).encode()),
                           (200, json.dumps({**reply, "token": "x"}).encode()),
                           (200, json.dumps({**reply, "stored": 0}).encode())):
                proxy.request.return_value = answer
                with self.subTest(answer=answer), self.assertRaises(client.ClientError):
                    client.logout(proxy, "chatgpt")


class MacPythonTests(unittest.TestCase):
    CLT = "/Library/Developer/CommandLineTools/usr/bin/python3"

    @unittest.skipUnless(os.path.exists(CLT), "Command Line Tools Python is not installed")
    def test_host_side_modules_import_on_python_3_9(self):
        code = ("import sys; sys.path.insert(0, sys.argv[1])\n"
                "import host, manage, client, setup, macos_install, secretstore\n"
                "print('ok')\n")
        with tempfile.TemporaryDirectory() as cwd:
            result = subprocess.run([self.CLT, "-I", "-c", code, str(ROOT)], cwd=cwd, capture_output=True,
                                    text=True, timeout=120, stdin=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        self.assertEqual(result.stdout.strip(), "ok")


if __name__ == "__main__":
    unittest.main()
