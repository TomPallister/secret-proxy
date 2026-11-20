"""Opt-in tamper-evident audit log (issue #6).

Covers: off by default (nothing constructed or written), the field allow-list
(no secret values, query strings, bodies or headers, also on error paths),
the hash chain and seals, rotation and retention, ``verify`` against tamper
cases and a wrong key, export, and Python 3.9 compatibility of the verifier.
Offline: synthetic fixtures and throwaway ssh-keygen keys only.
"""
import ast
import asyncio
import base64
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import approvals
import audit
from secretstore import SecretBackendError, SecretManifest
from test_awsops_addon import ACCOUNT, AwsPolicyAddonTestCase
from test_injection import AddonTestCase, FakeResolver, make_flow

ROOT = Path(__file__).resolve().parent
REF = "secre" + "tref:"
INSTANCE = "ab" * 16
SSH_KEYGEN = shutil.which("ssh-keygen", path=audit.SSH_KEYGEN_PATH)
CLT_PYTHON = "/Library/Developer/CommandLineTools/usr/bin/python3"

# Synthetic values: none of these may ever appear in an audit file.
VALUES = {
    "API_KEY": "real-api-key-0f3e9c",
    "BASIC_PW": "real-basic-pw-7d21aa",
    "FORM_SECRET": "real-form-secret-55b1",
    "HOOK_URL": "https://hooks.example.com/services/T000/B000/real-hook-path-8c4d",
}
QUERY_VALUE = "query-only-value-6e0b"
BODY_VALUE = "body-only-value-a17c"


def make_key(directory, name="key"):
    path = Path(directory) / name
    subprocess.run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "fixture", "-f", str(path)],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=30, check=True, start_new_session=True)
    return path.read_text(), (Path(str(path) + ".pub")).read_text()


def needs_ssh_keygen(test):
    return unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen not installed")(test)


SETTINGS = {"maxFileBytes": audit.DEFAULT_MAX_FILE_BYTES, "maxTotalBytes": audit.DEFAULT_MAX_TOTAL_BYTES,
            "maxAgeDays": audit.DEFAULT_MAX_AGE_DAYS, "signingKey": None}


def manifest_document(audit_section=None, **extra):
    document = {
        "schemaVersion": 3,
        "account": {"vault": "Fixture"},
        "secrets": {
            "API_KEY": {"placements": [
                {"kind": "header", "hosts": ["api.example.com"], "name": "x-api-key", "template": "{secret}"},
                {"kind": "query", "hosts": ["api.example.com"], "name": "key", "template": "{secret}"},
            ]},
            "BASIC_PW": {"placements": [
                {"kind": "basic-password", "hosts": ["git.example.com"], "username": "x-access-token"}]},
            "FORM_SECRET": {"placements": [
                {"kind": "form", "hosts": ["auth.example.com"], "name": "client_secret",
                 "template": "{secret}", "methods": ["POST"]}]},
            "HOOK_URL": {"placements": [{"kind": "url-rewrite", "hosts": ["hooks.example.com"],
                                         "methods": ["POST"]}]},
            "GIT_SIGNING_SSH_KEY": {"internalOnly": True, "valueField": "sshPrivateKey"},
            "AUDIT_SIGNING_SSH_KEY": {"internalOnly": True, "valueField": "sshPrivateKey"},
        },
    }
    if audit_section is not None:
        document["audit"] = audit_section
    document.update(extra)
    return document


def load_manifest(document):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "manifest.json"
        path.write_text(json.dumps(document))
        return SecretManifest.load(path)


def read_files(directory):
    return [(p.name, p.read_bytes()) for p in sorted(Path(directory).glob("audit-*.jsonl"))]


def all_bytes(directory):
    return b"".join(data for _name, data in read_files(directory))


def entries(directory):
    return [json.loads(line) for _name, data in read_files(directory) for line in data.splitlines()]


def events(directory):
    return [entry for entry in entries(directory) if entry["type"] == "event"]


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


# --- configuration -----------------------------------------------------------

class SettingsTests(unittest.TestCase):
    def test_absent_or_disabled_means_off(self):
        self.assertIsNone(audit.parse_settings(None))
        self.assertIsNone(audit.parse_settings({"enabled": False}))
        self.assertIsNone(load_manifest(manifest_document()).audit)
        self.assertIsNone(load_manifest(manifest_document({"enabled": False})).audit)

    def test_defaults_and_bounds(self):
        settings = load_manifest(manifest_document({"enabled": True})).audit
        self.assertEqual(settings, SETTINGS)
        settings = audit.parse_settings({"enabled": True, "maxFileBytes": 65536, "maxTotalBytes": 131072,
                                         "maxAgeDays": 7})
        self.assertEqual((settings["maxFileBytes"], settings["maxTotalBytes"], settings["maxAgeDays"]),
                         (65536, 131072, 7))

    def test_invalid_sections_are_refused(self):
        bad = [[], {}, {"enabled": "yes"}, {"enabled": True, "extra": 1},
               {"enabled": True, "maxFileBytes": 10}, {"enabled": True, "maxFileBytes": True},
               {"enabled": True, "maxFileBytes": 1 << 20, "maxTotalBytes": 1 << 19},
               {"enabled": True, "maxAgeDays": 0}, {"enabled": True, "signingKey": "lower"},
               {"enabled": False, "maxAgeDays": -1}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(audit.AuditConfigError):
                audit.parse_settings(value)

    def test_signing_key_must_be_an_internal_ssh_key(self):
        settings = load_manifest(manifest_document({"enabled": True, "signingKey": "AUDIT_SIGNING_SSH_KEY"})).audit
        self.assertEqual(settings["signingKey"], "AUDIT_SIGNING_SSH_KEY")
        for name in ("API_KEY", "MISSING_KEY"):
            with self.subTest(name), self.assertRaisesRegex(ValueError, "internalOnly"):
                load_manifest(manifest_document({"enabled": True, "signingKey": name}))

    def test_example_manifest_loads(self):
        manifest = SecretManifest.load(ROOT / "examples/audit-manifest.json")
        self.assertEqual(manifest.audit["signingKey"], "AUDIT_SIGNING_SSH_KEY")


# --- the field allow-list ------------------------------------------------------

class SanitizeTests(unittest.TestCase):
    def test_unknown_and_malformed_fields_are_dropped_and_counted(self):
        kept, dropped = audit.sanitize({
            "secret": "API_KEY", "value": "real", "headers": {"a": "b"}, "body": b"x",
            "secretValue": "x", "client": "Not A Client", "port": "443", "account": "12",
            "method": "get", "host": "API.Example.COM", "overridden": 1, "missing": None,
        })
        self.assertEqual(kept, {"secret": "API_KEY", "method": "GET", "host": "api.example.com"})
        self.assertEqual(dropped, 8)

    def test_free_text_is_never_accepted(self):
        kept, dropped = audit.sanitize({"reason": "token abc123 was rejected", "error": "No key: abc",
                                        "rule": "x\ny", "secret": "API_KEY value"})
        self.assertEqual((kept, dropped), ({}, 4))

    def test_paths_lose_query_strings_and_fragments_and_are_capped(self):
        self.assertEqual(audit.clean_path("/v1/items?key=" + QUERY_VALUE + "#frag"), "/v1/items")
        self.assertEqual(audit.clean_path("/a#b?c"), "/a")
        self.assertEqual(audit.clean_path("/caf\u00e9\n x"), "/caf???x")
        long = audit.clean_path("/" + "x" * 1000)
        self.assertEqual(len(long), audit.MAX_PATH)
        self.assertTrue(long.endswith("..."))
        self.assertIsNone(audit.clean_path("?only=query"))


# --- writer --------------------------------------------------------------------

class WriterTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "audit"
        self.clock = Clock()

    def writer(self, settings=None, signer=None, instance=INSTANCE):
        log = audit.AuditLog(self.dir, dict(SETTINGS, **(settings or {})), instance, signer=signer,
                             clock=self.clock)
        log.open()
        return log


class WriterTests(WriterTestCase):
    def test_private_modes_and_header(self):
        log = self.writer()
        self.assertTrue(log.record("inject", "injected", {"secret": "API_KEY", "placement": "header"}))
        log.close()
        self.assertEqual(stat.S_IMODE(self.dir.stat().st_mode), 0o700)
        files = list(self.dir.iterdir())
        self.assertEqual([p.name for p in files], ["audit-00000001.jsonl"])
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        header, event, seal = entries(self.dir)
        self.assertEqual((header["type"], header["n"], header["instance"], header["prev"]),
                         ("header", 1, INSTANCE, None))
        self.assertEqual(header["keyStatus"], "no-signing-key")
        self.assertEqual(event["prev"], audit.line_hash(read_files(self.dir)[0][1].splitlines()[0]))
        self.assertEqual((seal["type"], seal["signature"], seal["keyStatus"], seal["entries"]),
                         ("seal", None, "no-signing-key", 1))

    def test_reopen_chains_to_the_previous_file(self):
        first = self.writer()
        first.record("egress", "refused", {"rule": "metadata"})
        # An unclean stop: no seal. The next boot still chains to the last line.
        first._close_file()
        second = self.writer(instance="cd" * 16)
        second.close()
        (_n1, data1), (_n2, data2) = read_files(self.dir)
        header2 = json.loads(data2.splitlines()[0])
        self.assertEqual(header2["n"], 2)
        self.assertEqual(header2["prev"], audit.line_hash(data1.splitlines()[-1]))

    def test_failed_write_leaves_no_torn_line_and_reports_failure(self):
        log = self.writer()
        self.assertTrue(log.record("egress", "refused", {"rule": "one"}))
        before = (self.dir / "audit-00000001.jsonl").read_bytes()
        real_write = os.write

        def half_then_fail(fd, data):
            real_write(fd, bytes(data[: len(data) // 2]))
            raise OSError(28, "No space left on device")

        with patch.object(audit.os, "write", side_effect=half_then_fail):
            self.assertFalse(log.record("egress", "refused", {"rule": "two"}))
        self.assertFalse(log.healthy)
        self.assertEqual((self.dir / "audit-00000001.jsonl").read_bytes(), before)
        self.assertTrue(log.record("egress", "refused", {"rule": "three"}))
        self.assertTrue(log.healthy)
        log.close()
        self.assertEqual([e["rule"] for e in events(self.dir)], ["one", "three"])

    def test_record_after_close_fails(self):
        log = self.writer()
        log.close()
        log.close()  # idempotent
        self.assertFalse(log.record("egress", "refused", {}))

    def test_rotation_by_size_and_age(self):
        log = self.writer({"maxFileBytes": 65536, "maxTotalBytes": 1 << 20})
        for index in range(400):
            log.record("inject", "injected", {"secret": "API_KEY", "path": "/" + "p" * 200, "port": 443})
        self.clock.now += audit.ROTATE_AGE_SECONDS
        log.record("egress", "refused", {"rule": "late"})
        log.close()
        files = read_files(self.dir)
        self.assertGreaterEqual(len(files), 3)
        for _name, data in files[:-1]:
            self.assertEqual(json.loads(data.splitlines()[-1])["reason"], "rotate")
        self.assertEqual(json.loads(files[-1][1].splitlines()[1])["rule"], "late")

    def test_retention_prunes_only_the_oldest_files(self):
        log = self.writer({"maxFileBytes": 65536, "maxTotalBytes": 200000})
        for index in range(1200):
            log.record("inject", "injected", {"secret": "API_KEY", "path": "/" + "p" * 200})
        log.close()
        names = [name for name, _ in read_files(self.dir)]
        numbers = [int(name[6:14]) for name in names]
        self.assertGreater(numbers[0], 1, "old files were pruned")
        self.assertEqual(numbers, list(range(numbers[0], numbers[0] + len(numbers))), "contiguous")
        self.assertLessEqual(sum(p.stat().st_size for p in self.dir.iterdir()), 200000 + 65536 + 8192)

    def test_retention_by_age_happens_at_start(self):
        log = self.writer()
        log.record("egress", "refused", {"rule": "old"})
        log.close()
        old = self.dir / "audit-00000001.jsonl"
        os.utime(old, (self.clock.now - 10 * 86400, self.clock.now - 10 * 86400))
        self.writer({"maxAgeDays": 7}).close()
        self.assertEqual([name for name, _ in read_files(self.dir)], ["audit-00000002.jsonl"])

    def test_retention_never_leaves_a_gap(self):
        for _ in range(3):
            log = self.writer()
            log.record("egress", "refused", {"rule": "x"})
            log.close()
        old = self.clock.now - 10 * 86400
        for name in ("audit-00000001.jsonl", "audit-00000003.jsonl"):
            os.utime(self.dir / name, (old, old))  # 3 looks old, but 2 is young
        os.utime(self.dir / "audit-00000002.jsonl", (self.clock.now, self.clock.now))
        self.writer({"maxAgeDays": 7}).close()
        self.assertEqual([name for name, _ in read_files(self.dir)],
                         ["audit-00000002.jsonl", "audit-00000003.jsonl", "audit-00000004.jsonl"])

    def test_refuses_a_symlinked_or_foreign_directory(self):
        target = Path(self.tmp.name) / "elsewhere"
        target.mkdir()
        os.symlink(target, self.dir)
        with self.assertRaises(audit.AuditError):
            self.writer()


# --- verify -------------------------------------------------------------------

@needs_ssh_keygen
class VerifyTests(WriterTestCase):
    def setUp(self):
        super().setUp()
        self.private, self.public = make_key(self.tmp.name)
        self.signer = audit.SshSigner(lambda: self.private)

    def signed_log(self, files=1, per_file=5, unclean=False):
        log = self.writer({"maxFileBytes": 65536} if files > 1 else None, signer=self.signer)
        if files > 1:
            while len(read_files(self.dir)) < files:
                log.record("inject", "injected", {"secret": "API_KEY", "path": "/" + "p" * 200})
        for index in range(per_file):
            log.record("aws", "denied", {"account": ACCOUNT, "role": "ReadOnly", "service": "sts",
                                         "operation": "AssumeRole", "rule": "built-in", "seq": index})
        if unclean:
            log._close_file()
        else:
            log.close()
        return read_files(self.dir)

    def verify(self, files, key=None):
        return audit.verify_files(files, key or self.public)

    @staticmethod
    def rehash(files, change):
        """Apply *change* to entry dicts, then rebuild every hash consistently."""
        name, data = files[0]
        lines = [json.loads(line) for line in data.splitlines()]
        change(lines)
        out = []
        for index, entry in enumerate(lines):
            if index:
                entry["prev"] = audit.line_hash(out[-1])
            out.append(audit.canonical(entry))
        return [(name, b"\n".join(out) + b"\n")] + list(files[1:])

    def rewrite(self, files, index, line_number, change):
        name, data = files[index]
        lines = data.split(b"\n")
        lines[line_number] = change(lines[line_number])
        files = list(files)
        files[index] = (name, b"\n".join(lines))
        return files

    def test_clean_stop_is_valid_and_sealed(self):
        result = self.verify(self.signed_log())
        self.assertEqual(result.status, "sealed", result.lines())
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.entries, 5)
        header = entries(self.dir)[0]
        self.assertEqual(header["keyFingerprint"], audit.fingerprint(self.public))

    def test_multi_file_chain_is_valid(self):
        files = self.signed_log(files=3)
        self.assertGreaterEqual(len(files), 3)
        self.assertEqual(self.verify(files).status, "sealed")

    def test_unclean_stop_reports_an_unsigned_tail(self):
        result = self.verify(self.signed_log(unclean=True))
        self.assertEqual(result.status, "unsigned-tail", result.lines())
        self.assertEqual(result.exit_code, 3)
        self.assertEqual(result.tail, 5)

    def test_truncated_seal_is_an_unsigned_tail(self):
        name, data = self.signed_log()[0]
        result = self.verify([(name, data[: data.rstrip(b"\n").rfind(b"\n") + 1])])
        self.assertEqual(result.status, "unsigned-tail")

    def test_torn_final_line_is_noted(self):
        name, data = self.signed_log(unclean=True)[0]
        result = self.verify([(name, data + b'{"type":"ev')])
        self.assertEqual(result.status, "unsigned-tail")
        self.assertTrue(any("incomplete final line" in note for note in result.notes))

    def assertInvalid(self, files, text, key=None):
        result = self.verify(files, key)
        self.assertEqual(result.status, "invalid", result.lines())
        self.assertEqual(result.exit_code, 1)
        self.assertTrue(any(text in error for error in result.errors), result.errors)

    def test_edited_entry_is_detected(self):
        files = self.signed_log()

        def edit(line):
            entry = json.loads(line)
            entry["operation"] = "GetCallerIdentity"
            return audit.canonical(entry)

        self.assertInvalid(self.rewrite(files, 0, 2, edit), "does not follow")
        self.assertInvalid(self.rewrite(files, 0, 2, lambda line: line.replace(b":", b": ", 1)),
                           "canonical")

    def test_edited_last_event_of_a_sealed_file_is_detected(self):
        files = self.signed_log()

        def edit(line):
            entry = json.loads(line)
            entry["role"] = "Admin"
            return audit.canonical(entry)

        self.assertInvalid(self.rewrite(files, 0, 5, edit), "does not follow")

    def test_deleted_inserted_and_reordered_entries_are_detected(self):
        name, data = self.signed_log()[0]
        lines = data.split(b"\n")
        deleted = b"\n".join(lines[:2] + lines[3:])
        inserted = b"\n".join(lines[:3] + [lines[2]] + lines[3:])
        reordered = b"\n".join(lines[:2] + [lines[3], lines[2]] + lines[4:])
        for label, content in (("deleted", deleted), ("inserted", inserted), ("reordered", reordered)):
            with self.subTest(label):
                self.assertInvalid([(name, content)], "sequence")

    def test_consistently_rewritten_chain_fails_the_signature(self):
        # Re-hash every line after an edit: the chain looks fine, the seal does not.
        files = self.rehash(self.signed_log(), lambda lines: lines[2].update(operation="GetCallerIdentity"))
        self.assertInvalid(files, "does not verify")

    def test_wrong_key_is_detected(self):
        _private, other_public = make_key(self.tmp.name, "other")
        files = self.signed_log()
        self.assertInvalid(files, "different signing key", key=other_public)
        # Without a key fingerprint in the header the signature itself fails.
        files = self.rehash(files, lambda lines: lines[0].update(keyFingerprint=None))
        self.assertInvalid(files, "does not verify", key=other_public)

    def test_seal_signed_by_another_key_is_detected(self):
        other_private, _other_public = make_key(self.tmp.name, "other")
        self.signer = audit.SshSigner(lambda: other_private)
        files = self.signed_log()
        self.assertInvalid(files, "different signing key")
        files = self.rehash(files, lambda lines: lines[0].update(keyFingerprint=None))
        self.assertInvalid(files, "does not verify")

    def test_removed_signature_is_only_an_unsigned_tail(self):
        files = self.signed_log()
        files = self.rewrite(files, 0, 6, lambda line: audit.canonical(
            dict(json.loads(line), signature=None, keyStatus="signing-key-unavailable")))
        self.assertEqual(self.verify(files).status, "unsigned-tail")

    def test_missing_middle_file_is_detected(self):
        files = self.signed_log(files=3)
        self.assertInvalid(files[:1] + files[2:], "missing")

    def test_missing_oldest_files_are_noted_not_hidden(self):
        files = self.signed_log(files=3)
        result = self.verify(files[1:])
        self.assertEqual(result.status, "sealed")
        self.assertTrue(any("earlier file" in note for note in result.notes))

    def test_reordered_files_and_a_truncated_middle_file_are_detected(self):
        files = self.signed_log(files=3)
        name, data = files[0]
        self.assertInvalid([(name, data[: data.rstrip(b"\n").rfind(b"\n") + 1])] + files[1:], "does not follow")

    def test_seal_signatures_cannot_use_the_git_namespace(self):
        import gitsign
        with self.assertRaises(gitsign.GitSignError):
            gitsign.sign_message(self.private, b"message", b"git")
        with self.assertRaises(gitsign.GitSignError):
            gitsign.sign_message(self.private, b"message", b"")
        with self.assertRaises(gitsign.GitSignError):
            gitsign.sign(self.private, b"secret-proxy-audit seal v1\n")  # git route: commits/tags only

    def test_signing_key_unavailable_writes_an_unsigned_seal(self):
        def unavailable():
            raise SecretBackendError("vault unreachable " + VALUES["API_KEY"])

        log = self.writer(signer=audit.SshSigner(unavailable))
        log.record("egress", "refused", {"rule": "metadata"})
        log.close()
        header, _event, seal = entries(self.dir)
        self.assertEqual(header["keyStatus"], "signing-key-unavailable")
        self.assertEqual((seal["signature"], seal["keyStatus"]), (None, "signing-key-unavailable"))
        self.assertNotIn(VALUES["API_KEY"].encode(), all_bytes(self.dir))
        self.assertEqual(self.verify(read_files(self.dir)).status, "unsigned-tail")

    def test_verify_command_and_exit_codes(self):
        self.signed_log()
        key = Path(self.tmp.name) / "pinned.pub"
        key.write_text(self.public)
        out = io.StringIO()
        self.assertEqual(audit.verify_command(key, [str(self.dir)], out), 0)
        self.assertIn("VALID, SEALED", out.getvalue())
        (self.dir / "audit-00000001.jsonl").write_bytes(b"garbage\n")
        out = io.StringIO()
        self.assertEqual(audit.verify_command(key, [str(self.dir)], out), 1)
        self.assertIn("INVALID", out.getvalue())

    def test_verify_runs_under_python_3_9(self):
        ast.parse((ROOT / "audit.py").read_text(), feature_version=(3, 9))
        if not Path(CLT_PYTHON).exists():
            self.skipTest("macOS Command Line Tools Python not installed")
        self.signed_log()
        key = Path(self.tmp.name) / "pinned.pub"
        key.write_text(self.public)
        result = subprocess.run([CLT_PYTHON, "-I", str(ROOT / "audit.py"), "verify", "--public-key", str(key),
                                 str(self.dir)], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                timeout=60, start_new_session=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("VALID, SEALED", result.stdout)


class ExportTests(WriterTestCase):
    def test_export_round_trip_and_validation(self):
        log = self.writer()
        log.record("egress", "refused", {"rule": "metadata"})
        log.close()
        (self.dir / "unrelated.txt").write_text("ignored")
        out = io.BytesIO()
        self.assertEqual(audit.export(self.dir, out), 1)
        files = audit.parse_export(out.getvalue())
        self.assertEqual(files, read_files(self.dir))
        target = audit.write_export(files, Path(self.tmp.name) / "copy")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((target / files[0][0]).stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            audit.write_export(files, target)
        for bad in (b'{"name":"../x","data":""}', b'{"name":"audit-00000001.jsonl","data":"!!"}',
                    b'{"name":"audit-00000001.jsonl","data":"","extra":1}', b"not json"):
            with self.subTest(bad=bad), self.assertRaises(audit.AuditError):
                audit.parse_export(bad)
        self.assertEqual(audit.export(Path(self.tmp.name) / "absent", io.BytesIO()), 0)


# --- the proxy ------------------------------------------------------------------

def as_client(flow, client="default"):
    flow.metadata["proxyauth"] = ("secret-proxy" if client == "default" else client, "a" * 48)
    return flow


class AddonAuditCase(AddonTestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "audit"
        self.addCleanup(self.addon.close_audit)
        self.resolver = FakeResolver(dict(VALUES))

    def use(self, audit_section={"enabled": True}, signer=None, **extra):
        manifest = load_manifest(manifest_document(audit_section, **extra))
        self.addon._manifest = manifest
        self.addon._resolver = self.resolver
        self.addon._manifest_mtime = -1
        self.addon.configure_audit(manifest, directory=self.dir, instance=INSTANCE, signer=signer)
        return manifest

    def assertNoLeak(self, *extra):
        data = all_bytes(self.dir)
        for value in list(VALUES.values()) + [QUERY_VALUE, BODY_VALUE, "x-api-key: ", *extra]:
            self.assertNotIn(value.encode(), data, value)
        self.assertNotIn(REF.encode(), data)
        self.assertNotIn(b"?", data.replace(b'"t":', b""), "no query strings")


class OffByDefaultTests(AddonAuditCase):
    def test_nothing_is_constructed_or_written(self):
        with patch.object(audit, "AuditLog", side_effect=AssertionError("audit writer constructed")):
            for section in (None, {"enabled": False}):
                with self.subTest(section=section):
                    self.use(section)
                    self.assertIsNone(self.addon._audit_log)
                    flow = make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"})
                    self.addon.request(flow)
                    self.assertEqual(flow.request.headers["x-api-key"], VALUES["API_KEY"])
                    bad = make_flow("evil.example.net", headers={"x-api-key": REF + "API_KEY"})
                    self.addon.request(bad)
                    self.assertEqual(bad.response.status_code, 403)
        self.assertFalse(self.dir.exists())
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])

    def test_entry_load_without_audit_writes_nothing(self):
        import entry
        from mitmproxy.test import taddons
        manifest = Path(self.tmp.name) / "manifest.json"
        manifest.write_text(json.dumps(manifest_document()))
        with patch.object(audit, "AuditLog", side_effect=AssertionError("audit writer constructed")), \
                patch.object(self.addon, "SECRETS_FILE", manifest), \
                patch.object(self.addon, "AUDIT_DIR", str(self.dir)), \
                patch.object(self.addon, "AWS_OKTA_FILE", Path(self.tmp.name) / "absent.json"), \
                taddons.context():
            entry.load(None)
            entry.done()
        self.assertFalse(self.dir.exists())

    def test_entry_load_opens_and_done_seals(self):
        import entry
        from mitmproxy.test import taddons
        manifest = Path(self.tmp.name) / "manifest.json"
        manifest.write_text(json.dumps(manifest_document({"enabled": True})))
        with patch.object(self.addon, "SECRETS_FILE", manifest), \
                patch.object(self.addon, "AUDIT_DIR", str(self.dir)), \
                patch.object(self.addon, "AWS_OKTA_FILE", Path(self.tmp.name) / "absent.json"), \
                patch.dict(os.environ, {"SECRET_PROXY_INSTANCE_ID": INSTANCE}), \
                taddons.context():
            entry.load(None)
            self.assertIsNotNone(self.addon._audit_log)
            entry.done()
        self.assertIsNone(self.addon._audit_log)
        self.assertEqual([e["type"] for e in entries(self.dir)], ["header", "seal"])

    def test_enabled_without_a_directory_refuses_to_start(self):
        import entry
        from mitmproxy.exceptions import OptionsError
        from mitmproxy.test import taddons
        manifest = Path(self.tmp.name) / "manifest.json"
        manifest.write_text(json.dumps(manifest_document({"enabled": True})))
        with patch.object(self.addon, "SECRETS_FILE", manifest), patch.object(self.addon, "AUDIT_DIR", ""), \
                patch.dict(os.environ, {"SECRET_PROXY_INSTANCE_ID": INSTANCE}), taddons.context():
            with self.assertRaisesRegex(OptionsError, "audit log"):
                entry.load(None)


class InjectionAuditTests(AddonAuditCase):
    def flows(self):
        basic = base64.b64encode(("x-access-token:" + REF + "BASIC_PW").encode()).decode()
        return {
            "header": make_flow("api.example.com", "/v1/items?page=" + QUERY_VALUE, "GET",
                                headers={"x-api-key": REF + "API_KEY"}),
            "query": make_flow("api.example.com", "/v1/search", "GET", query={"key": REF + "API_KEY"}),
            "basic-password": make_flow("git.example.com", "/repo.git/info/refs", "GET",
                                        headers={"Authorization": "Basic " + basic}),
            "form": make_flow("auth.example.com", "/token", "POST",
                              content=("client_secret=" + REF + "FORM_SECRET&note=" + BODY_VALUE).encode(),
                              content_type="application/x-www-form-urlencoded"),
            "url-rewrite": make_flow(self.addon.SENTINEL_HOST, "/HOOK_URL", "POST",
                                     content=BODY_VALUE.encode()),
        }

    def test_successful_injections_are_recorded_without_values(self):
        self.use()
        for placement, flow in self.flows().items():
            with self.subTest(placement):
                self.addon.request(as_client(flow))
                self.assertIsNone(flow.response, flow.response and flow.response.content)
        self.addon.close_audit()
        recorded = events(self.dir)
        self.assertEqual([(e["placement"], e["secret"], e["decision"]) for e in recorded], [
            ("header", "API_KEY", "injected"), ("query", "API_KEY", "injected"),
            ("basic-password", "BASIC_PW", "injected"), ("form", "FORM_SECRET", "injected"),
            ("url-rewrite", "HOOK_URL", "injected")])
        self.assertEqual(recorded[0]["path"], "/v1/items")
        self.assertEqual(recorded[0]["field"], "x-api-key")
        self.assertEqual(recorded[0]["client"], "default")
        # The rewritten destination (the secret) is never recorded.
        self.assertEqual((recorded[4]["host"], recorded[4]["path"]), (self.addon.SENTINEL_HOST, "/HOOK_URL"))
        self.assertNoLeak("hooks.example.com", "page=")

    def test_later_refusal_of_a_rewritten_request_names_only_the_sentinel(self):
        import egress
        import entry
        self.use()
        flow = as_client(self.flows()["url-rewrite"])
        self.addon.request(flow)
        self.assertEqual(flow.request.host, "hooks.example.com")
        entry._refusal_response(flow, egress.Refusal("egress-allowlist"))
        self.addon.close_audit()
        refused = events(self.dir)[-1]
        self.assertEqual((refused["event"], refused["host"], refused["path"]),
                         ("egress", self.addon.SENTINEL_HOST, "/HOOK_URL"))
        self.assertNoLeak("hooks.example.com", "real-hook-path")

    def test_streaming_injection_is_recorded_once(self):
        self.use()
        flow = as_client(make_flow("api.example.com", "/upload", "GET", headers={"x-api-key": REF + "API_KEY"}))
        flow.request.stream = True
        self.addon.requestheaders(flow)
        self.addon.request(flow)
        self.assertEqual(flow.request.headers["x-api-key"], VALUES["API_KEY"])
        self.assertEqual([(e["event"], e["decision"]) for e in events(self.dir)], [("inject", "injected")])
        self.assertNoLeak()

    def test_error_paths_record_refusals_without_values(self):
        self.use()

        class Failing(FakeResolver):
            def __init__(self, error):
                super().__init__(dict(VALUES))
                self.error = error

            def get(self, name):
                self.get_calls.append(name)
                raise self.error

        cases = {
            "placement-not-allowed": (None, make_flow("evil.example.net", "/x?k=" + QUERY_VALUE,
                                                      headers={"x-api-key": REF + "API_KEY"})),
            "injection-failed": (SecretBackendError("1Password said " + VALUES["API_KEY"]),
                                 make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"})),
            "runtime": (RuntimeError("boom " + VALUES["BASIC_PW"]),
                        make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"})),
            "invalid-reference": (None, make_flow("api.example.com",
                                                  headers={"x-api-key": REF + "NOT_A_SECRET_" + QUERY_VALUE})),
        }
        for label, (error, flow) in cases.items():
            with self.subTest(label):
                self.addon._resolver = Failing(error) if error else FakeResolver(dict(VALUES))
                self.addon.request(as_client(flow))
                self.assertIn(flow.response.status_code, (403, 502))
        self.addon.close_audit()
        recorded = events(self.dir)
        self.assertEqual([e["reason"] for e in recorded],
                         ["placement-not-allowed", "injection-failed", "injection-failed", "invalid-reference"])
        self.assertEqual([e.get("error") for e in recorded[1:3]], ["SecretBackendError", "RuntimeError"])
        self.assertEqual([e.get("secret") for e in recorded], ["API_KEY", "API_KEY", "API_KEY", None])
        self.assertEqual([e["decision"] for e in recorded], ["refused", "failed", "failed", "refused"])
        self.assertEqual(recorded[0]["host"], "evil.example.net")
        self.assertNoLeak("1Password said", "boom", "NOT_A_SECRET")

    def test_client_not_granted_is_the_recorded_reason(self):
        self.use(clients={"default": {"all": True}, "reader": {}})
        flow = as_client(make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"}), "reader")
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.addon.close_audit()
        [event] = events(self.dir)
        self.assertEqual((event["client"], event["reason"], event["secret"]),
                         ("reader", "client-not-granted", "API_KEY"))

    def test_a_failed_audit_write_refuses_the_request(self):
        self.use()
        self.addon._audit_log._close_file()  # every later write fails
        for flow in self.flows().values():
            with self.subTest(flow.request.path):
                self.addon.request(as_client(flow))
                self.assertEqual(flow.response.status_code, 503, flow.response.content)
                self.assertEqual(json.loads(flow.response.content)["error"], "secret_proxy_audit_unavailable")
                for value in flow.request.headers.values():
                    self.assertNotIn("real-", value)
                self.assertNotIn(b"real-", flow.request.content or b"")
                self.assertNotEqual(flow.request.host, "hooks.example.com")
        stream = as_client(make_flow("api.example.com", "/upload", "GET", headers={"x-api-key": REF + "API_KEY"}))
        stream.request.stream = True
        self.addon.requestheaders(stream)
        self.assertEqual(stream.response.status_code, 503)
        self.assertEqual(stream.request.headers["x-api-key"], REF + "API_KEY")

    def test_approval_timeout_and_session_decisions_are_recorded(self):
        import entry
        secrets = manifest_document()["secrets"]
        secrets["API_KEY"]["placements"][0]["approval"] = "prompt"
        document = manifest_document({"enabled": True})
        document["secrets"] = secrets
        manifest = load_manifest(document)
        self.addon._manifest, self.addon._resolver, self.addon._manifest_mtime = manifest, self.resolver, -1
        self.addon.configure_audit(manifest, directory=self.dir, instance=INSTANCE)
        broker = approvals.configure(approvals.Broker(enabled=True, timeout=0.05))
        self.addCleanup(approvals.configure, approvals.Broker(enabled=False))

        async def scenario():
            broker.poller_started()
            flow = as_client(make_flow("api.example.com", "/v1?x=" + QUERY_VALUE,
                                       headers={"x-api-key": REF + "API_KEY"}))
            await entry._run_with_approvals(flow, self.addon.request)
            return flow

        with patch.object(entry, "_wakeups", set()), patch.object(entry, "_held_by_client", {}):
            flow = asyncio.run(asyncio.wait_for(scenario(), timeout=20))
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(self.resolver.get_calls, [])
        key = approvals.placement_request(secret="API_KEY", kind="header", name="x-api-key",
                                          host="api.example.com", method="GET", path="/",
                                          rule="API_KEY.placements[0]", client="default").key
        broker._session[key] = "allow"
        allowed = as_client(make_flow("api.example.com", headers={"x-api-key": REF + "API_KEY"}))
        self.addon.request(allowed)
        self.assertIsNone(allowed.response)
        self.addon.close_audit()
        recorded = events(self.dir)
        timeout = recorded[0]
        self.assertEqual((timeout["event"], timeout["decision"], timeout["reason"], timeout["secret"],
                          timeout["placement"], timeout["field"], timeout["path"]),
                         ("approval", "denied", approvals.RULE_TIMEOUT, "API_KEY", "header", "x-api-key", "/v1"))
        self.assertEqual([(e["event"], e["decision"], e.get("choice")) for e in recorded[-2:]],
                         [("approval", "allowed", "session"), ("inject", "injected", None)])
        self.assertNoLeak()


class RouteAuditTests(AddonAuditCase):
    @needs_ssh_keygen
    def test_git_signing_and_seal_signature(self):
        private, public = make_key(self.tmp.name)
        self.resolver.values["GIT_SIGNING_SSH_KEY"] = private
        self.resolver.values["AUDIT_SIGNING_SSH_KEY"] = private
        self.use({"enabled": True, "signingKey": "AUDIT_SIGNING_SSH_KEY"})
        commit = b"tree " + b"0" * 40 + b"\nauthor x <x@example.com> 0 +0000\n\nmsg\n"
        flow = as_client(make_flow(self.addon.SENTINEL_HOST, "/git/sign", "POST", content=commit))
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 200)
        refused = as_client(make_flow(self.addon.SENTINEL_HOST, "/git/sign", "POST", content=b"not a commit"))
        self.addon.request(refused)
        self.addon.close_audit()
        signed, other = events(self.dir)
        self.assertEqual((signed["event"], signed["decision"], signed["object"], signed["secret"]),
                         ("sign", "signed", "commit", "GIT_SIGNING_SSH_KEY"))
        self.assertEqual((other["decision"], other["reason"]), ("refused", "not-a-git-object"))
        data = all_bytes(self.dir)
        self.assertNotIn(private.split("\n")[1].encode(), data)
        self.assertNotIn(b"author x", data)
        self.assertEqual(audit.verify_files(read_files(self.dir), public).status, "sealed")

    def test_egress_refusal_is_recorded(self):
        import egress
        import entry
        self.use()
        flow = as_client(make_flow("169.254.169.254", "/latest/meta-data?token=" + QUERY_VALUE))
        entry._refusal_response(flow, egress.Refusal("metadata"))
        self.addon.audit_connect_refusal("10.0.0.1", 443, "private-address")
        self.addon.close_audit()
        first, second = events(self.dir)
        self.assertEqual((first["event"], first["decision"], first["rule"], first["path"]),
                         ("egress", "refused", "metadata", "/latest/meta-data"))
        self.assertEqual((second["host"], second["port"], second["rule"]), ("10.0.0.1", 443, "private-address"))
        self.assertNoLeak()


class AwsAuditTests(AwsPolicyAddonTestCase):
    def setUp(self):
        super().setUp()
        self.tmp2 = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp2.cleanup)
        self.dir = Path(self.tmp2.name) / "audit"
        self.addCleanup(self.addon.close_audit)
        self.addon.configure_audit(type("M", (), {"audit": dict(SETTINGS)})(), directory=self.dir,
                                   instance=INSTANCE)
        self.okta_file.write_text(json.dumps({"default_account": ACCOUNT, "default_role": "ReadOnly"}))

    def test_denied_and_allowed_aws_calls_are_recorded_without_credentials(self):
        denied = self.query_flow("secretsmanager", b"Action=GetSecretValue&SecretId=" + BODY_VALUE.encode())
        self.addon.request(denied)
        self.assertEqual(denied.response.status_code, 403)
        allowed = self.query_flow("sts", b"Action=GetCallerIdentity&Version=2011-06-15")
        self.addon.request(allowed)
        self.assertIsNone(allowed.response)
        self.addon.close_audit()
        first, second = events(self.dir)
        self.assertEqual((first["event"], first["decision"], first["account"], first["role"],
                          first["service"], first["operation"], first["rule"]),
                         ("aws", "denied", ACCOUNT, "ReadOnly", "secretsmanager", "GetSecretValue",
                          "aws-policy.json rule 1"))
        self.assertEqual((second["decision"], second["operation"]), ("allowed", "GetCallerIdentity"))
        data = all_bytes(self.dir)
        for value in ("fixture-signing-material-not-real", "fixture-session-token", BODY_VALUE, "SecretId"):
            self.assertNotIn(value.encode(), data)

    def test_audit_failure_refuses_the_aws_call_before_it_is_sent(self):
        self.addon._audit_log._close_file()
        flow = self.query_flow("sts", b"Action=GetCallerIdentity&Version=2011-06-15")
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 503)
        self.assertNotIn("fixture-session-token", flow.request.headers.get("x-amz-security-token", ""))


# --- runtime, controller and daily CLI ---------------------------------------------

class RuntimeAndHostTests(unittest.TestCase):
    def test_runtime_passes_the_private_audit_directory(self):
        from runtime import command
        _argv, env = command(Path("/config"), Path("/data/mitmproxy"), Path("/tmp/auth"), 10256,
                             {"op_token": "x", "proxy_token": "0" * 48})
        self.assertEqual(env["SECRET_PROXY_AUDIT_DIR"], "/data/audit")

    def test_export_container_is_offline_and_read_only(self):
        import host
        deployment = host.Deployment("candidate", "machine", 10260)
        args = host.audit_export_command(deployment, "sha256:" + "a" * 64)
        self.assertIn("--network=none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("sp-candidate-ca:/data:ro", args)
        self.assertFalse(any("/config" in arg or "proxy-token" in arg for arg in args))
        with self.assertRaises(host.HostError):
            host.audit_export_command(deployment, "latest")

    def test_build_lists_ship_audit(self):
        import host
        import macos_install
        self.assertIn("audit.py", host.BUILD_FILES)
        self.assertIn("audit.py", macos_install.FILES)


class ManageAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def exported(self):
        directory = Path(self.tmp.name) / "source"
        log = audit.AuditLog(directory, SETTINGS, INSTANCE)
        log.open()
        log.record("egress", "refused", {"rule": "metadata"})
        log.close()
        out = io.BytesIO()
        audit.export(directory, out)
        return out.getvalue()

    def test_export_writes_a_new_private_directory(self):
        import manage
        data = self.exported()
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, data, None)

        target = Path(self.tmp.name) / "copy"
        with patch("sys.stdout", io.StringIO()):
            self.assertEqual(manage.audit_command({"instance": "candidate"}, "export", destination=target,
                                                  run=run), 0)
        self.assertEqual(calls[0][-2:], ["audit-export", "candidate"])
        self.assertEqual([p.name for p in target.iterdir()], ["audit-00000001.jsonl"])
        with self.assertRaises(manage.ClientError):
            manage.audit_command({"instance": "candidate"}, "export", destination=target, run=run)

    def test_failed_export_writes_nothing(self):
        import manage

        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, b"", None)

        target = Path(self.tmp.name) / "copy"
        with self.assertRaises(manage.ClientError):
            manage.audit_command({"instance": "candidate"}, "export", destination=target, run=run)
        self.assertFalse(target.exists())

    def test_manage_parses_audit_commands(self):
        import manage
        with patch.object(manage, "audit_command", return_value=3) as command, \
                self.assertRaises(SystemExit) as exit_info:
            manage.main(["audit", "verify", "--public-key", "/tmp/k.pub", "/tmp/a"])
        self.assertEqual(exit_info.exception.code, 3)
        self.assertEqual(command.call_args[0][:2], ({}, "verify"))


if __name__ == "__main__":
    unittest.main()
