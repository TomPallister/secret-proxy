"""Egress policy: address refusal and DNS pinning (#4)."""
import asyncio
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import egress
from egress import Allowed, EgressConfigError, EgressPolicy, Refusal

ROOT = Path(__file__).parent
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


class FakeResolver:
    """Answers from a script; each call pops the next answer for a name."""

    def __init__(self, answers):
        self.answers = {name: list(values) for name, values in answers.items()}
        self.calls = []

    def __call__(self, host, port):
        self.calls.append((host, port))
        queue = self.answers.get(host)
        if not queue:
            raise OSError("no such host")
        return queue.pop(0) if len(queue) > 1 else queue[0]


def policy(config=None):
    return EgressPolicy.from_config(config)


class AddressTests(unittest.TestCase):
    def assertRule(self, address, rule, allowed=()):
        cidrs = [ipaddress.ip_network(c) for c in allowed]
        self.assertEqual(egress.address_refusal(address, cidrs), rule, address)

    def test_always_denied_ipv4(self):
        for address, rule in [
            ("169.254.169.254", "metadata-address"), ("169.254.170.2", "metadata-address"),
            ("100.100.100.200", "metadata-address"), ("169.254.1.1", "link-local-address"),
            ("127.0.0.1", "loopback-address"), ("127.8.9.10", "loopback-address"),
            ("0.0.0.0", "unspecified-address"), ("0.1.2.3", "unspecified-address"),
            ("224.0.0.1", "multicast-address"), ("239.1.1.1", "multicast-address"),
            ("255.255.255.255", "reserved-address"), ("240.0.0.1", "reserved-address"),
        ]:
            with self.subTest(address=address):
                self.assertRule(address, rule)

    def test_always_denied_ipv6(self):
        for address, rule in [
            ("fd00:ec2::254", "metadata-address"), ("fe80::1", "link-local-address"),
            ("fe80::1%eth0", "link-local-address"), ("::1", "loopback-address"),
            ("::", "unspecified-address"), ("ff02::1", "multicast-address"),
        ]:
            with self.subTest(address=address):
                self.assertRule(address, rule)

    def test_ipv4_embedded_in_ipv6_is_unwrapped(self):
        for address, rule in [
            ("::ffff:169.254.169.254", "metadata-address"),
            ("::ffff:127.0.0.1", "loopback-address"),
            ("::ffff:10.1.2.3", "private-address"),
            ("::a9fe:a9fe", "metadata-address"),          # IPv4-compatible
            ("64:ff9b::a9fe:a9fe", "metadata-address"),   # NAT64 well-known prefix
            ("64:ff9b::7f00:1", "loopback-address"),
            ("::ffff:" + PUBLIC_V4, None),
            ("64:ff9b::5db8:d822", None),
        ]:
            with self.subTest(address=address):
                self.assertRule(address, rule)

    def test_private_ranges_denied_unless_allowed(self):
        for address in ("10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1",
                        "100.64.0.1", "fc00::1", "fd12:3456::1"):
            with self.subTest(address=address):
                self.assertRule(address, "private-address")
        self.assertRule("192.0.2.1", "special-purpose-address")
        self.assertRule("2001:db8::1", "special-purpose-address")
        self.assertRule("10.20.30.40", None, allowed=["10.20.0.0/16"])
        self.assertRule("10.21.0.1", "private-address", allowed=["10.20.0.0/16"])
        self.assertRule("::ffff:10.20.30.40", None, allowed=["10.20.0.0/16"])
        self.assertRule("fd12:3456::1", None, allowed=["fd12:3456::/32"])
        # Metadata endpoints stay refused inside an allowed private CIDR.
        self.assertRule("fd00:ec2::254", "metadata-address", allowed=["fd00::/8"])
        self.assertRule("100.100.100.200", "metadata-address", allowed=["100.64.0.0/10"])

    def test_public_addresses_allowed(self):
        for address in (PUBLIC_V4, PUBLIC_V6, "172.32.0.1", "11.0.0.1"):
            with self.subTest(address=address):
                self.assertRule(address, None)

    def test_garbage_address_is_refused(self):
        self.assertRule("not-an-address", "invalid-address")


class CheckTests(unittest.TestCase):
    def test_literal_ips_are_checked_without_resolution(self):
        resolver = FakeResolver({})
        p = policy()
        for host in ("169.254.169.254", "[fd00:ec2::254]", "::ffff:169.254.169.254",
                     "2852039166", "0xa9.0xfe.0xa9.0xfe", "127.1"):
            with self.subTest(host=host):
                self.assertIsInstance(p.check(host, 80, resolver), Refusal)
        self.assertEqual(p.check(PUBLIC_V4, 443, resolver), Allowed((PUBLIC_V4,)))
        self.assertEqual(resolver.calls, [])

    def test_hostnames_resolving_to_metadata_or_link_local_are_refused(self):
        resolver = FakeResolver({
            "meta.example.com": [["169.254.169.254"]],
            "ll.example.com": [["fe80::1"]],
            "mapped.example.com": [["::ffff:169.254.169.254"]],
        })
        p = policy()
        self.assertEqual(p.check("meta.example.com", 80, resolver), Refusal("metadata-address"))
        self.assertEqual(p.check("ll.example.com", 80, resolver), Refusal("link-local-address"))
        self.assertEqual(p.check("mapped.example.com", 80, resolver), Refusal("metadata-address"))

    def test_metadata_names_refused_before_resolution(self):
        resolver = FakeResolver({"metadata.google.internal": [[PUBLIC_V4]]})
        p = policy()
        for host in ("metadata.google.internal", "METADATA.google.internal.", "metadata", "instance-data"):
            with self.subTest(host=host):
                self.assertEqual(p.check(host, 80, resolver), Refusal("metadata-host"))
        self.assertEqual(resolver.calls, [])

    def test_every_address_of_a_multi_address_answer_is_checked(self):
        resolver = FakeResolver({
            "mixed.example.com": [[PUBLIC_V4, PUBLIC_V6, "10.0.0.5"]],
            "dual.example.com": [[PUBLIC_V6, PUBLIC_V4, PUBLIC_V4]],
        })
        p = policy()
        self.assertEqual(p.check("mixed.example.com", 443, resolver), Refusal("private-address"))
        self.assertEqual(p.check("dual.example.com", 443, resolver), Allowed((PUBLIC_V6, PUBLIC_V4)))

    def test_unresolved_and_invalid_hosts(self):
        resolver = FakeResolver({"empty.example.com": [[]]})
        p = policy()
        self.assertEqual(p.check("missing.example.com", 443, resolver), egress.UNRESOLVED)
        self.assertEqual(p.check("empty.example.com", 443, resolver), egress.UNRESOLVED)
        for host in ("", "a..example.com", "bad host.example.com", None, "x" * 300):
            with self.subTest(host=host):
                self.assertEqual(p.check(host, 443, resolver), Refusal("invalid-host"))

    def test_sentinel_is_never_an_upstream_destination(self):
        self.assertEqual(policy().check(egress.SENTINEL_HOST, 443, FakeResolver({})),
                         Refusal("sentinel-upstream"))

    def test_allowed_private_cidrs_work_for_hostnames(self):
        resolver = FakeResolver({"intranet.example.com": [["10.20.1.2"]]})
        allowed = policy({"allowPrivateCidrs": ["10.20.0.0/16"]})
        self.assertEqual(allowed.check("intranet.example.com", 443, resolver), Allowed(("10.20.1.2",)))
        self.assertEqual(policy().check("intranet.example.com", 443, resolver), Refusal("private-address"))


class ConfigTests(unittest.TestCase):
    def test_absent_section_allows_public_hosts_only(self):
        p = EgressPolicy.from_config(None)
        self.assertEqual(p.allowed_cidrs, ())
        resolver = FakeResolver({"anything.example.net": [[PUBLIC_V4]]})
        self.assertEqual(p.check("anything.example.net", 443, resolver), Allowed((PUBLIC_V4,)))

    def test_invalid_configs_have_clear_errors(self):
        for config, message in [
            ([], "JSON object"),
            ({"extra": 1}, "unknown fields: extra"),
            ({"allowPrivateCidrs": ["10.0.0.1/8"]}, "host bits"),
            ({"allowPrivateCidrs": ["127.0.0.0/8"]}, "loopback"),
            ({"allowPrivateCidrs": ["0.0.0.0/0"]}, "cannot be allowed"),
            ({"allowPrivateCidrs": ["169.254.0.0/16"]}, "link-local"),
            ({"allowPrivateCidrs": ["::ffff:10.0.0.0/104"]}, "IPv4-in-IPv6"),
            ({"allowPrivateCidrs": ["198.51.100.0/24", "198.51.100.0/24"]}, "duplicates"),
            ({"allowPrivateCidrs": ["8.8.8.0/24"]}, "no private"),
            ({"allowPrivateCidrs": "10.0.0.0/8"}, "must be a list"),
        ]:
            with self.subTest(config=config):
                with self.assertRaisesRegex(EgressConfigError, message):
                    EgressPolicy.from_config(config)

    def test_manifest_section_is_validated(self):
        from secretstore import SecretManifest
        self.assertEqual(SecretManifest.load(ROOT / "examples/manifest.json").egress_policy().allowed_cidrs, ())
        data = json.loads((ROOT / "examples/manifest.json").read_text())
        data["egress"] = {"allowPrivateCidrs": ["10.20.0.0/16"]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(data))
            self.assertEqual(len(SecretManifest.load(path).egress_policy().allowed_cidrs), 1)
            data["egress"]["allowPrivateCidrs"] = ["127.0.0.0/8"]
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(EgressConfigError, "loopback"):
                SecretManifest.load(path)


class StartupTests(unittest.TestCase):
    def bad_manifest(self, directory):
        data = json.loads((ROOT / "examples/manifest.json").read_text())
        data["egress"] = {"allowPrivateCidrs": ["127.0.0.0/8"]}
        path = Path(directory) / "manifest.json"
        path.write_text(json.dumps(data))
        return path

    def test_entry_load_refuses_to_start(self):
        import entry
        from mitmproxy.exceptions import OptionsError
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(entry.addon, "SECRETS_FILE", self.bad_manifest(directory)):
                with self.assertRaisesRegex(OptionsError, "invalid egress configuration: .*loopback"):
                    entry.load(None)

    def test_runtime_prints_a_clear_error_before_reading_capabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            self.bad_manifest(directory)
            result = subprocess.run(
                [sys.executable, str(ROOT / "runtime.py"), "--config-dir", directory],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                env={**os.environ, "PYTHONPATH": str(ROOT)},
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("secret-proxy runtime failed: egress.allowPrivateCidrs: '127.0.0.0/8' overlaps loopback", result.stderr)


# --- mitmproxy hook wiring --------------------------------------------------

def run(coro):
    return asyncio.run(coro)


class HookTests(unittest.TestCase):
    def setUp(self):
        import entry
        self.entry = entry
        self.resolver = FakeResolver({
            "api.example.com": [[PUBLIC_V4]],
            # Rebinding: first answer public, later answers point at metadata.
            "rebind.example.com": [[PUBLIC_V4], ["169.254.169.254"]],
            "intranet.example.com": [["10.20.0.9"]],
        })
        patches = [
            patch.object(entry, "_egress_policy", policy()),
            patch.object(entry, "_resolver", self.resolver),
            patch.dict(entry._pins, clear=True),
            patch.dict(entry._connecting, clear=True),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def connect_flow(self, host, port=443):
        from mitmproxy.test import tflow, tutils
        flow = tflow.tflow(req=tutils.treq(method=b"CONNECT", host=host, port=port,
                                           path=b"", authority=f"{host}:{port}".encode()))
        return flow

    def plain_flow(self, host, port=80):
        from mitmproxy.test import tflow, tutils
        return tflow.tflow(req=tutils.treq(scheme=b"http", host=host, port=port))

    def server(self, flow, host, port=443):
        from mitmproxy import connection
        from mitmproxy.proxy.server_hooks import ServerConnectionHookData
        server = connection.Server(address=(host, port))
        return ServerConnectionHookData(server=server, client=flow.client_conn)

    def body(self, flow):
        return json.loads(flow.response.content)

    def test_connect_refusals_are_403_naming_the_rule_without_upstream(self):
        for host, rule in [("169.254.169.254", "metadata-address"), ("metadata.google.internal", "metadata-host"),
                           ("intranet.example.com", "private-address"), ("127.0.0.1", "loopback-address")]:
            with self.subTest(host=host):
                flow = self.connect_flow(host)
                run(self.entry.http_connect(flow))
                self.assertEqual(flow.response.status_code, 403)
                self.assertEqual(self.body(flow), {"error": "secret_proxy_egress_refused", "rule": rule})
                self.assertEqual(self.entry._pins, {})
        # Name-based refusals never resolved the name.
        self.assertEqual(self.resolver.calls, [("intranet.example.com", 443)])

    def test_unresolvable_connect_is_502(self):
        flow = self.connect_flow("missing.example.com")
        run(self.entry.http_connect(flow))
        self.assertEqual(flow.response.status_code, 502)

    def test_allowed_connect_pins_checked_address_and_server_connect_uses_it(self):
        flow = self.connect_flow("rebind.example.com")
        run(self.entry.http_connect(flow))
        self.assertIsNone(flow.response)
        data = self.server(flow, "rebind.example.com")
        run(self.entry.server_connect(data))
        self.assertIsNone(data.server.error)
        # The resolver now answers metadata, but it was asked only once and the
        # connection goes to the address that was checked.
        self.assertEqual(data.server.address, (PUBLIC_V4, 443))
        self.assertEqual(self.resolver.calls, [("rebind.example.com", 443)])

    def test_server_connect_restores_name_for_connection_reuse(self):
        from mitmproxy.connection import ConnectionState
        from mitmproxy.proxy.layers.http import GetHttpConnection
        flow = self.connect_flow("api.example.com")
        run(self.entry.http_connect(flow))
        data = self.server(flow, "api.example.com")
        run(self.entry.server_connect(data))
        data.server.state = ConnectionState.OPEN  # mitmproxy opened the socket
        data.server.peername = (PUBLIC_V4, 443)
        self.entry.server_connected(data)
        self.assertEqual(data.server.address, ("api.example.com", 443))
        self.assertEqual(self.entry._connecting, {})
        spec = GetHttpConnection(("api.example.com", 443), tls=False, via=None)
        self.assertTrue(spec.connection_spec_matches(data.server))

    def test_server_connect_without_a_pin_resolves_once_and_checks(self):
        flow = self.connect_flow("x")
        data = self.server(flow, "rebind.example.com")
        run(self.entry.server_connect(data))
        self.assertEqual(data.server.address, (PUBLIC_V4, 443))
        # A later connection to the same name (rebound answer) is refused.
        other = self.server(self.connect_flow("y"), "rebind.example.com")
        run(self.entry.server_connect(other))
        self.assertEqual(other.server.error, "secret-proxy egress refused (metadata-address)")
        for host in ("169.254.169.254", egress.SENTINEL_HOST, "intranet.example.com"):
            with self.subTest(host=host):
                refused = self.server(self.connect_flow("z"), host)
                run(self.entry.server_connect(refused))
                self.assertIn("secret-proxy egress refused", refused.server.error)

    def test_server_connect_refuses_without_a_loaded_policy(self):
        with patch.object(self.entry, "_egress_policy", None):
            data = self.server(self.connect_flow("x"), "api.example.com")
            run(self.entry.server_connect(data))
            self.assertIn("policy-unavailable", data.server.error)

    def test_plain_http_refused_before_addon_runs(self):
        for host, rule in [("169.254.169.254", "metadata-address"), ("intranet.example.com", "private-address")]:
            with self.subTest(host=host), patch.object(self.entry.addon, "requestheaders") as addon_hook:
                flow = self.plain_flow(host)
                run(self.entry.requestheaders(flow))
                self.assertEqual(flow.response.status_code, 403)
                self.assertEqual(self.body(flow)["rule"], rule)
                addon_hook.assert_not_called()

    def test_plain_http_allowed_host_pins_and_reaches_addon(self):
        with patch.object(self.entry.addon, "requestheaders") as addon_hook:
            flow = self.plain_flow("api.example.com")
            run(self.entry.requestheaders(flow))
            self.assertIsNone(flow.response)
            addon_hook.assert_called_once()
        data = self.server(flow, "api.example.com", 80)
        run(self.entry.server_connect(data))
        self.assertEqual(data.server.address, (PUBLIC_V4, 80))
        self.assertEqual(self.resolver.calls, [("api.example.com", 80)])

    def test_sentinel_connect_and_requests_are_local(self):
        flow = self.connect_flow(egress.SENTINEL_HOST)
        run(self.entry.http_connect(flow))
        self.assertIsNone(flow.response)
        self.assertEqual(self.resolver.calls, [])

    def test_url_rewrite_destination_is_checked_after_the_addon(self):
        def rewrite(flow):
            flow.request.host = "169.254.169.254"
        flow = self.plain_flow(egress.SENTINEL_HOST, 443)
        flow.request.scheme = "https"
        with patch.object(self.entry.addon, "request", side_effect=rewrite):
            run(self.entry.request(flow))
        self.assertEqual(self.body(flow)["rule"], "metadata-address")

    def test_client_disconnect_drops_pins(self):
        flow = self.connect_flow("api.example.com")
        run(self.entry.http_connect(flow))
        self.assertIn(flow.client_conn.id, self.entry._pins)
        self.entry.client_disconnected(flow.client_conn)
        self.assertNotIn(flow.client_conn.id, self.entry._pins)

    def test_pins_per_client_are_bounded(self):
        for index in range(self.entry.MAX_PINS_PER_CLIENT + 5):
            self.entry._pin("client", f"h{index}.example.com", 443, (PUBLIC_V4,))
        self.assertEqual(len(self.entry._pins["client"]), self.entry.MAX_PINS_PER_CLIENT)


if __name__ == "__main__":
    unittest.main()
