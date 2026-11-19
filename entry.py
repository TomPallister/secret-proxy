"""Concurrent mitmproxy entrypoint for the secret-proxy addon.

The implementation in ``addon.py`` remains synchronously callable for unit
 tests and direct diagnostics. This module is the runtime adapter: mitmproxy
runs its blocking provider lookups and AWS credential work in its executor so
one slow secret refresh cannot stop unrelated proxy connections.
"""

from __future__ import annotations

import asyncio
import os
import re
from concurrent.futures import ThreadPoolExecutor

import addon
from mitmproxy import ctx
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


def _allow_hosts() -> list[str]:
    """Build the minimal set of hosts that need TLS interception."""
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
    return list(dict.fromkeys(patterns))


def load(loader) -> None:
    """Restrict MITM processing to manifest and AWS signing destinations."""
    try:
        patterns = _allow_hosts()
    except Exception as error:
        message = (
            "secret_proxy: could not build allow_hosts; refusing to start with "
            "unrestricted interception"
        )
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
    ctx.options.update(allow_hosts=patterns)
    addon.log.info("secret_proxy: intercepting %d configured host patterns", len(patterns))
    for line in policy_lines:
        addon.log.info("%s", line)


async def request(flow) -> None:
    """Run the blocking request hook away from mitmproxy's event loop."""
    await asyncio.get_running_loop().run_in_executor(
        _HOOK_EXECUTOR, addon.request, flow,
    )


def responseheaders(flow) -> None:
    """Keep streaming response behavior in the normal hook path."""
    addon.responseheaders(flow)


async def requestheaders(flow) -> None:
    """Run streaming AWS re-signing away from mitmproxy's event loop."""
    await asyncio.get_running_loop().run_in_executor(
        _HOOK_EXECUTOR, addon.requestheaders, flow,
    )
