"""Concurrent mitmproxy entrypoint for the secret-proxy addon.

The implementation in ``addon.py`` remains synchronously callable for unit
 tests and direct diagnostics. This module is the runtime adapter: mitmproxy
runs its blocking provider lookups and AWS credential work in its executor so
one slow secret refresh cannot stop unrelated proxy connections.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

import addon
import egress
from mitmproxy import ctx, http
from mitmproxy.exceptions import OptionsError
from secretstore import SecretManifest

_AWS_RE = r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.amazonaws\.com(?::\d+)?$"
_HOOK_EXECUTOR = ThreadPoolExecutor(
    max_workers=max(8, min(32, (os.cpu_count() or 1) * 4)),
    thread_name_prefix="secret-proxy-hook",
)


def _host_pattern(pattern: str) -> str:
    """Convert a manifest's exact-label wildcard to an anchored regex."""
    labels = []
    for label in pattern.split("."):
        if label == "*":
            labels.append(r"[A-Za-z0-9-]+")
        else:
            labels.append(re.escape(label))
    return r"^" + r"\.".join(labels) + r"(?::\d+)?$"


def _allow_hosts(manifest=None) -> list[str]:
    """Build the minimal set of hosts that need TLS interception."""
    if manifest is None:
        manifest = SecretManifest.load(addon.SECRETS_FILE)
    patterns = [_host_pattern(host) for host in manifest.interception_hosts()]
    patterns.append(_host_pattern(addon.SENTINEL_HOST))
    # AWS signing is intentionally broader than the manifest: the client may
    # sign any AWS service endpoint, while the addon itself still requires our
    # dummy credential marker before minting or re-signing credentials.
    if addon.AWS_OKTA_FILE.is_file():
        patterns.append(_AWS_RE)
    try:
        manifest.secret("CHATGPT_ACCESS_TOKEN")
    except KeyError:
        pass
    else:
        patterns.append(_host_pattern("auth.openai.com"))
    # Proxy-owned GitHub logins: intercept the login host (to refuse a client's
    # own device flow) and, for Copilot, the API host serving the exchange.
    for kind in ("copilot", "cli"):
        settings = manifest.github_login(kind)
        if settings is not None:
            patterns.append(_host_pattern(settings["domain"]))
            if kind == "copilot":
                patterns.append(_host_pattern("api." + settings["domain"]))
    return list(dict.fromkeys(patterns))


def load(loader) -> None:
    """Restrict MITM processing to manifest and AWS signing destinations."""
    global _egress_policy
    try:
        manifest = SecretManifest.load(addon.SECRETS_FILE)
        patterns = _allow_hosts(manifest)
        policy = manifest.egress_policy()
    except Exception as error:
        message = (
            "secret_proxy: could not build allow_hosts; refusing to start with "
            "unrestricted interception"
        )
        if isinstance(error, egress.EgressConfigError):
            # Configuration text only; never secret values.
            message = "secret_proxy: invalid egress configuration: " + str(error)
        addon.log.error("%s (%s)", message, type(error).__name__)
        # AddonManager deliberately propagates OptionsError from load hooks;
        # a normal Exception would only be logged and startup would continue.
        raise OptionsError(message) from error
    try:
        # Built-in AWS deny list + optional aws-policy.json + role overrides.
        # Overrides are logged here so they are visible at every start.
        policy_lines = addon.aws_policy_startup_summary()
    except Exception as error:
        message = "secret_proxy: invalid AWS operation policy; refusing to start"
        detail = str(error) if isinstance(error, addon.awsops.AwsPolicyError) else type(error).__name__
        addon.log.error("%s (%s)", message, detail)
        raise OptionsError(message) from error
    _egress_policy = policy
    _pins.clear()
    ctx.options.update(allow_hosts=patterns)
    addon.log.info("secret_proxy: intercepting %d configured host patterns", len(patterns))
    addon.log.info(
        "secret_proxy: egress mode %s (%d allow, %d deny, %d private CIDRs)",
        policy.mode, len(policy.allow), len(policy.deny), len(policy.allowed_cidrs),
    )
    for line in policy_lines:
        addon.log.info("%s", line)


# --- Egress enforcement -----------------------------------------------------
# Every upstream connection passes server_connect, which connects only to an
# address that was checked (pinned at CONNECT/request time, or resolved and
# checked there). http_connect and the request hooks refuse early with a 403
# naming the rule; server_connect is the final gate for any other path.
# The policy is fixed at startup, like the interception host list.
_egress_policy = None
_resolver = egress.system_resolver
# client connection id -> OrderedDict((host, port) -> checked addresses)
_pins: dict = {}
# server connection id -> original (host, port) address while connecting
_connecting: dict = {}
MAX_PINS_PER_CLIENT = 64


def _policy():
    if _egress_policy is None:
        # load() never succeeded: refuse rather than run without a policy.
        raise RuntimeError("egress policy unavailable")
    return _egress_policy


def _pin(client_id, host, port, addresses) -> None:
    pins = _pins.setdefault(client_id, OrderedDict())
    pins[(host, port)] = addresses
    pins.move_to_end((host, port))
    while len(pins) > MAX_PINS_PER_CLIENT:
        pins.popitem(last=False)


def _pinned(client_id, host, port):
    return _pins.get(client_id, {}).get((host, port))


async def _decide(host, port):
    """Resolve once (off the event loop) and check every address."""
    try:
        policy = _policy()
    except RuntimeError:
        return egress.Refusal("policy-unavailable", 503)
    # The default executor is where asyncio itself runs getaddrinfo, so DNS
    # waits do not occupy the credential-hook pool.
    return await asyncio.get_running_loop().run_in_executor(
        None, policy.check, host, port, _resolver,
    )


def _refusal_response(flow, refusal) -> None:
    if refusal.status == 403:
        body = {"error": "secret_proxy_egress_refused", "rule": refusal.rule}
    else:
        body = {"error": "secret_proxy_egress_unavailable", "rule": refusal.rule}
    addon.log.warning(
        "secret_proxy: BLOCKED %s %s:%s - egress %s",
        flow.request.method, flow.request.host, flow.request.port, refusal.rule,
    )
    flow.response = http.Response.make(
        refusal.status, json.dumps(body).encode(),
        {"content-type": "application/json", "cache-control": "no-store"},
    )


async def _check_destination(flow) -> bool:
    """Decide the flow's destination before any upstream connection."""
    if flow.response is not None:
        return False
    host = egress.normalize_host(flow.request.host)
    port = flow.request.port
    if host == egress.SENTINEL_HOST:
        return True  # answered or rewritten locally, never connected upstream
    client_id = flow.client_conn.id
    if host is not None and _pinned(client_id, host, port) is not None:
        return True
    decision = await _decide(flow.request.host, port)
    if isinstance(decision, egress.Refusal):
        _refusal_response(flow, decision)
        return False
    _pin(client_id, host, port, decision.addresses)
    return True


async def http_connect(flow) -> None:
    """Refuse a CONNECT before mitmproxy answers it or opens any connection."""
    await _check_destination(flow)


async def server_connect(data) -> None:
    """Final gate: connect only to a checked address, never re-resolving."""
    server = data.server
    if server.via is not None:
        server.error = "secret-proxy egress refused (upstream-proxy)"
        return
    host, port = server.address
    normalized = egress.normalize_host(host)
    addresses = None if normalized is None else _pinned(data.client.id, normalized, port)
    if addresses is None:
        decision = await _decide(host, port)
        if isinstance(decision, egress.Refusal):
            addon.log.warning(
                "secret_proxy: BLOCKED connect %s:%s - egress %s", host, port, decision.rule,
            )
            server.error = f"secret-proxy egress refused ({decision.rule})"
            return
        addresses = decision.addresses
        _pin(data.client.id, normalized, port, addresses)
    # Connect to the checked address. The TLS server name was already chosen
    # from the host name; the name is restored once the socket is open so
    # mitmproxy can keep reusing the connection for the same destination.
    _connecting[server.id] = server.address
    server.address = (addresses[0], port)


def _restore_address(server) -> None:
    original = _connecting.pop(server.id, None)
    if original is not None and server.address != original:
        # Server.__setattr__ forbids changing the address of an open
        # connection; this only restores the name we temporarily replaced.
        object.__setattr__(server, "address", original)


def server_connected(data) -> None:
    _restore_address(data.server)


def server_connect_error(data) -> None:
    _connecting.pop(data.server.id, None)


def server_disconnected(data) -> None:
    _connecting.pop(data.server.id, None)


def client_disconnected(client) -> None:
    _pins.pop(client.id, None)


async def request(flow) -> None:
    """Run the blocking request hook away from mitmproxy's event loop."""
    await asyncio.get_running_loop().run_in_executor(
        _HOOK_EXECUTOR, addon.request, flow,
    )
    # A URL rewrite may have changed the destination; check it before the
    # upstream connection (normally a cached decision from requestheaders).
    await _check_destination(flow)


def responseheaders(flow) -> None:
    """Keep streaming response behavior in the normal hook path."""
    addon.responseheaders(flow)


async def requestheaders(flow) -> None:
    """Run streaming AWS re-signing away from mitmproxy's event loop."""
    # Plain HTTP has no CONNECT; refuse before any credential work.
    if not await _check_destination(flow):
        return
    await asyncio.get_running_loop().run_in_executor(
        _HOOK_EXECUTOR, addon.requestheaders, flow,
    )
