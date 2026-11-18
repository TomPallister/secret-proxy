# Operating a testing deployment

Use the installed daily CLI described in the README. The proxy is foreground,
not a persistent service. Closing a terminal is not a reliable stop command.
Do not put tokens in shell profiles, shell history, command arguments or a
launcher configuration. Bootstrap metadata is not a service-account token.

## Start, login and stop

1. `secret-proxy start` prepares the image before desktop approval. Keep its
   terminal attached. A ready instance is left alone.
2. In another terminal, `secret-proxy login` starts proxy-owned PKCE. Paste the
   full callback only into its hidden prompt. No usable OAuth token is saved.
3. `secret-proxy status` checks authenticated TLS and the current boot nonce.
   This is liveness, not proof that every upstream integration works.
4. Use clients through their existing, explicitly selected adapters, or
   `secret-proxy run -- /absolute/path/to/client`. Host programs must support
   the supplied proxy and trust settings; see the README's Go/macOS caveat.
5. `secret-proxy stop` stops only the selected instance and waits for the old
   foreground controllers to finish. It preserves volumes, trust, capability,
   policy and client auth. A new start requires browser login again.

## Evidence of real OAuth refresh

`secret-proxy auth-status` reads `/chatgpt/status` over authenticated TLS and
checks the response against the current boot nonce. The output contains only:

- `instance`: boot nonce, not a credential;
- `loggedIn`: whether an access/refresh pair is held in memory;
- `expiresAt`: Unix seconds for the provider response's actual expiry deadline;
- `refreshCount`: successful expiry-triggered refreshes since the last login;
- `lastRefreshAt` and `lastRefreshDueAt`: Unix seconds for the last successful
  refresh and the expiry-minus-120-seconds threshold that triggered it.

No tokens, account IDs, identity claims or upstream error bodies are returned.
Status does not fetch a secret, perform a token exchange, move the clock, force
refresh or keep an idle login alive. Login resets these counters; a process
restart resets all in-memory state. `loggedIn` is not an upstream liveness probe.

To accept natural refresh, record a status baseline, allow the real deadline to
arrive, make a normal model call and read status again. Require the same boot
nonce, an increased `refreshCount`, and `lastRefreshAt >= lastRefreshDueAt`, plus
a successful model response and unchanged sealed client auth. Check that no
intervening browser login occurred. Repeat after the next deadline to observe
another rotating refresh token. A login, synthetic-clock test or new process is
**not** proof of automatic refresh. Do not expose or dump process memory to
inspect tokens. Some providers issue long-lived access tokens; report the test
as pending rather than simulating time passage.

## Upgrade without changing the trust boundary

- Verify the exact new signed source and its audit before installing. The
  installer accepts restrictive umasks, explicitly normalising only public code
  and required directory modes; private state stays private.
- Record current source revision, instance identity, public CA/capability hashes,
  consumer bindings and sealed-auth hashes privately. Never print capabilities.
- Stage the new release with the **same** private policy and instance. Configuration
  mismatches are refused; no implicit policy migration or vault change occurs.
- Prepare the new image before interrupting the working service. Installation
  and image preparation alone do not replace a running container.
- At a coordinated checkpoint, stop the selected proxy, wait for controller
  cleanup, start it from the newly selected release and perform browser login.
- Verify both normal host and container consumers: authenticated nonce, expected
  network isolation, read-only upstream access, signing and real model calls.
  Preserve workspaces and existing same-account sealed client auth. A system-root
  bundle may change with the base image; the proxy CA/capability must not churn.
- Update the user-level CLI symlink only to a reviewed, root-owned installed
  release. The version-pinned CLI can operate an older engine during rollback.

An engine rollback is a **coordinated restart**, not a silent fallback. Keep the
previous exact source/release, image or reproducible build inputs, instance
policy, CA volume, capability, bootstrap metadata and a tested restart command.
An older installer may need its documented permissions workaround. Never change
`current` to an unchecked source tree or overwrite a policy to make it fit.

## Retiring a predecessor

Do this only after normal consumers are accepted and the operator authorises it:

1. Inventory exact container IDs, network/port ownership and process dependencies.
   Do not dump container environments or provider output. Do not infer that a
   VPN or another consumer is absent from a service's display name.
2. Keep the selected replacement running. Stop **only** verified predecessor IDs;
   do not remove machines, shared networks, volumes, CA material or private policy.
3. Recheck replacement host/container consumers and closed predecessor ports.
4. Move obsolete user-side migration helpers into a private, dated archive after
   verifying no active launcher references them. Keep an index and an explicit
   rollback entry point. Do not delete the sole copy of private policy, auth
   backups or history needed for recovery.
5. Keep the retired services stopped rather than irreversibly deleting rollback
   material while natural-refresh or other acceptance remains pending.

Archiving is not proof of deletion or proof of natural refresh. Machine removal,
volume deletion and wider host cleanup are separate, destructive operations.
