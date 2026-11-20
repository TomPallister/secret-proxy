"""Concurrent mitmproxy entrypoint for the secret-proxy addon.

The implementation in ``addon.py`` remains synchronously callable for unit
 tests and direct diagnostics. This module is the runtime adapter: mitmproxy
runs its blocking provider lookups and AWS credential work in its executor so
one slow secret refresh cannot stop unrelated proxy connections.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

import addon
import approvals
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
    _configure_approvals(manifest, policy)
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
    if decision.approval is not None:
        # The addresses passed; the host is an allowlist miss configured to
        # ask. Hold the CONNECT (or plain request) until a person answers.
        ask = approvals.egress_request(host=host or "", port=port, rule=decision.approval,
                                       client=addon._requester(flow))
        outcome = await _await_outcome(ask, flow.client_conn.id)
        if not outcome.allowed:
            _refusal_response(flow, egress.Refusal(outcome.rule))
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
        if isinstance(decision, egress.Allowed) and decision.approval is not None:
            # Approval is asked at CONNECT/request time; never here.
            decision = egress.Refusal(approvals.RULE_REQUIRED)
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
    # A held request whose client went away no longer needs an answer.
    for item_id in _held_by_client.pop(client.id, set()):
        approvals.default_broker().withdraw(item_id)


async def request(flow) -> None:
    """Run the blocking request hook away from mitmproxy's event loop."""
    if await _approval_route(flow):
        return
    await _run_with_approvals(flow, addon.request)
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
    # Streaming requests are approved here, before the body starts to flow.
    await _run_with_approvals(flow, addon.requestheaders)


# --- Approval rules (issue #3) ---------------------------------------------
# A held request waits here, in the event loop, never in the hook executor, so
# it cannot starve credential lookups. The addon has resolved nothing for it.
# The approver uses an authenticated control endpoint on the sentinel host:
# proxy authentication plus an approver-only capability that ordinary clients
# do not receive, bound to this boot's instance nonce.
APPROVER_HEADER = "x-secret-proxy-approver"
INSTANCE_HEADER = "x-secret-proxy-instance"
POLL_SECONDS = 25.0
MAX_APPROVAL_ROUNDS = 4
_APPROVAL_ID_RE = re.compile(r"/approvals/([0-9a-f]{32})")
_approver_digest = None
_wakeups: set = set()
# client connection id -> ids of its held prompts
_held_by_client: dict = {}


def _configure_approvals(manifest, policy) -> None:
    global _approver_digest
    digest = os.environ.get("SECRET_PROXY_APPROVER_DIGEST", "")
    _approver_digest = digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None
    settings = manifest.approval_settings()
    approvals.configure(approvals.Broker(
        timeout=settings["timeout"], prompts_per_minute=settings["prompts_per_minute"],
        enabled=_approver_digest is not None,
    ))
    configured = manifest.uses_approval() or policy.allowlist_miss == "approve"
    try:
        aws_policy, _target = addon._load_aws_policy()
        configured = configured or any(rule.action == addon.awsops.APPROVE for rule in aws_policy.rules)
    except Exception:  # noqa: BLE001 - load() already validated the AWS policy
        pass
    if _approver_digest is None:
        if configured:
            addon.log.warning(
                "secret_proxy: approval rules are configured but no approver capability "
                "exists; every request needing approval is denied",
            )
    else:
        addon.log.info(
            "secret_proxy: approvals available (timeout %ds, at most %d prompts a minute)",
            int(settings["timeout"]), settings["prompts_per_minute"],
        )


def _wake_approvers() -> None:
    for event in list(_wakeups):
        event.set()


def _log_outcome(request, outcome) -> None:
    if outcome.allowed:
        addon.log.info("secret_proxy: APPROVAL allow (%s) %s", outcome.choice or "-", request.summary())
    else:
        addon.log.warning("secret_proxy: APPROVAL deny (%s) %s", outcome.rule, request.summary())


async def _await_outcome(request, client_id=None):
    """Ask once and wait, without blocking the loop; every failure denies."""
    broker = approvals.default_broker()
    result = broker.submit(request)
    if isinstance(result, approvals.Outcome):
        _log_outcome(request, result)
        return result
    item = result
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def done(outcome):
        def settle():
            if not future.done():
                future.set_result(outcome)
        try:
            same_loop = asyncio.get_running_loop() is loop
        except RuntimeError:
            same_loop = False
        if same_loop:
            settle()
        else:
            loop.call_soon_threadsafe(settle)

    broker.add_callback(item, done)
    if client_id is not None:
        _held_by_client.setdefault(client_id, set()).add(item.id)
    addon.log.info("secret_proxy: APPROVAL waiting %s", request.summary())
    _wake_approvers()
    try:
        while not future.done():
            remaining = broker.remaining(item)
            if remaining <= 0:
                broker.expire()
                await asyncio.sleep(0)
                continue
            try:
                await asyncio.wait_for(asyncio.shield(future), timeout=remaining)
            except asyncio.TimeoutError:
                broker.expire()
        outcome = future.result()
    except asyncio.CancelledError:
        broker.withdraw(item.id)
        raise
    except Exception:  # noqa: BLE001 - any failure while waiting denies
        broker.withdraw(item.id)
        outcome = approvals.Outcome(False, approvals.RULE_REQUIRED)
    finally:
        held = _held_by_client.get(client_id)
        if held is not None:
            held.discard(item.id)
            if not held:
                _held_by_client.pop(client_id, None)
    _log_outcome(request, outcome)
    _wake_approvers()  # the next prompt can be shown now
    return outcome


async def _run_with_approvals(flow, hook) -> None:
    """Run *hook*; while it is waiting on approvals, ask, then run it again."""
    flow.metadata[addon.APPROVAL_HANDLER] = True
    loop = asyncio.get_running_loop()
    for _round in range(MAX_APPROVAL_ROUNDS):
        await loop.run_in_executor(_HOOK_EXECUTOR, hook, flow)
        pending = addon.approval_pending(flow)
        if not pending or flow.response is not None:
            return
        for ask in pending:
            outcome = await _await_outcome(ask, flow.client_conn.id)
            if not outcome.allowed:
                addon.approval_refusal(flow, ask, outcome.rule)
                return
            addon.approval_grant(flow, [ask.key])
    # Still asking after every round: refuse rather than loop or forward.
    await loop.run_in_executor(_HOOK_EXECUTOR, hook, flow)
    pending = addon.approval_pending(flow)
    if pending and flow.response is None:
        addon.approval_refusal(flow, pending[0], approvals.RULE_REQUIRED)


def _control_response(flow, status: int, value=None) -> bool:
    body = b"" if value is None else json.dumps(value).encode()
    headers = {"cache-control": "no-store"}
    if value is not None:
        headers["content-type"] = "application/json"
    flow.response = http.Response.make(status, body, headers)
    return True


async def _next_prompt(timeout: float):
    broker = approvals.default_broker()
    loop = asyncio.get_running_loop()
    event = asyncio.Event()
    _wakeups.add(event)
    broker.poller_started()
    try:
        deadline = loop.time() + timeout
        while True:
            event.clear()
            item = broker.next_item()
            if item is not None:
                return item
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                await asyncio.wait_for(event.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                return broker.next_item()
    finally:
        _wakeups.discard(event)
        broker.poller_finished()


async def _approval_route(flow, poll_seconds: float = None) -> bool:
    """GET /approvals/next (long-poll) and POST /approvals/<id> on the sentinel."""
    if egress.normalize_host(flow.request.host) != egress.SENTINEL_HOST:
        return False
    path = (flow.request.path or "").split("?", 1)[0]
    if path != "/approvals" and not path.startswith("/approvals/"):
        return False
    if (flow.request.scheme or "").lower() != "https":
        return _control_response(flow, 403, {"error": "secret_proxy_https_required"})
    if _approver_digest is None:
        return _control_response(flow, 503, {"error": "approvals_unavailable"})
    presented = flow.request.headers.get(APPROVER_HEADER, "")
    digest = hashlib.sha256(presented.encode("utf-8", "replace")).hexdigest()
    if not presented or not hmac.compare_digest(digest, _approver_digest):
        addon.log.warning("secret_proxy: BLOCKED %s %s%s - approver capability required",
                          flow.request.method, egress.SENTINEL_HOST, path)
        return _control_response(flow, 403, {"error": "approver_required"})
    instance = os.environ.get("SECRET_PROXY_INSTANCE_ID", "")
    if re.fullmatch(r"[0-9a-f]{32}", instance) is None:
        return _control_response(flow, 503, {"error": "unavailable"})
    if not hmac.compare_digest(flow.request.headers.get(INSTANCE_HEADER, ""), instance):
        return _control_response(flow, 409, {"error": "stale_instance"})
    broker = approvals.default_broker()
    if path == "/approvals/next":
        if flow.request.method != "GET":
            return _control_response(flow, 405, {"error": "method_not_allowed"})
        item = await _next_prompt(POLL_SECONDS if poll_seconds is None else poll_seconds)
        if item is None:
            return _control_response(flow, 204)
        return _control_response(flow, 200, approvals.public_item(
            item, instance, broker.clock(), broker.min_answer_delay))
    match = _APPROVAL_ID_RE.fullmatch(path)
    if match is None:
        return _control_response(flow, 404, {"error": "not_found"})
    if flow.request.method != "POST":
        return _control_response(flow, 405, {"error": "method_not_allowed"})
    choice = None
    body = flow.request.content or b""
    if len(body) <= 1024:
        try:
            value = json.loads(body)
        except ValueError:
            value = None
        if isinstance(value, dict) and set(value) == {"choice"} and isinstance(value["choice"], str):
            choice = value["choice"]
    # A malformed answer still counts: it denies the prompt being shown.
    outcome = broker.answer(match.group(1), choice)
    if outcome is None:
        return _control_response(flow, 404, {"error": "no_such_prompt"})
    _wake_approvers()
    return _control_response(flow, 200, {
        "instance": instance, "id": match.group(1),
        "result": "allowed" if outcome.allowed else "denied", "rule": outcome.rule,
    })
