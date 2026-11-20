# Daily operations and recovery

For the first installation, follow [setup](setup.md). After that, use the installed CLI. The proxy is foreground,
not a persistent service. Closing a terminal is not a reliable stop command.
Do not put tokens in shell profiles, shell history, command arguments or a
launcher configuration. Bootstrap metadata is not a service-account token.

## Start, login and stop

1. `secret-proxy start` prepares the image before desktop approval. Keep its
   terminal attached. A ready instance is left alone.
2. In another terminal, `secret-proxy login` starts proxy-owned PKCE. Paste the
   full callback only into its hidden prompt. No usable OAuth token is saved.
   For GitHub Copilot, run `secret-proxy login github-copilot`: open the URL it
   prints and enter the code. The proxy waits for GitHub, so leave it running.
   `secret-proxy login github` works the same way for the GitHub CLI.
3. `secret-proxy status` checks authenticated TLS and the current boot nonce.
   This is liveness, not proof that every upstream integration works.
4. Use clients through their existing, explicitly selected adapters, or
   `secret-proxy run -- /absolute/path/to/client`. Host programs must support
   the supplied proxy and trust settings; see [client compatibility](clients.md).
5. `secret-proxy stop` stops only the selected instance and waits for the old
   foreground controllers to finish. It preserves volumes, trust, capability,
   policy and client auth. A new start requires browser login again.

## Scoped client tokens

With a manifest [`clients` section](advanced-setup.md#scoped-clients), each start
publishes `proxy-token.<name>` (owner-only) beside the default `proxy-token` in
the instance's shared directory. Tokens persist across restarts. To rotate one,
stop the proxy, delete
`/Users/secagent/.config/standalone-secret-proxy/<instance>/client-tokens/<name>`
as root, and start again; hand the new file to that client. Removing a client
from the manifest deletes its published file at the next start. Any client can
use `secret-proxy status --client <name>`; logins need that client's `logins`
grant. A refused use logs `client '<name>' is not granted ...` without values.

## Name-constrained CA and macOS trust

With `ca.json` (see [advanced configuration](advanced-setup.md)) the proxy owns
its CA. At each start it keeps the CA when its constraints still match the
configured hosts; otherwise it moves the old CA files to `retired/` in the CA
volume and creates a new one, printing the permitted names. Consumers then need
the new public CA: restart container consumers and rerun `secret-proxy trust-ca`.
The proxy also renews the CA 30 days before it expires.

- `secret-proxy trust-ca`: trust this instance's constrained CA for SSL in your
  login keychain (user trust settings, one authentication prompt).
- `secret-proxy untrust-ca`: remove that trust entry and certificate. Run it
  before deleting an instance.

Neither command restarts the proxy or changes its CA. Inspect what is trusted with
`security dump-trust-settings` (user domain). See [clients](clients.md).

## Optional authentication diagnostics

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

`secret-proxy auth-status github-copilot` reads `/github-copilot/status` the same
way. It returns `instance`, `loggedIn`, `expiresAt` (the Copilot token's expiry),
`refreshCount` (refreshes since the last login, done by the proxy before
`refresh_in`) and `lastRefreshAt`. It never refreshes or returns a token.
`secret-proxy auth-status github` returns only `instance`, `loggedIn` and the
`scopes` GitHub granted to the gh login.

You do not need to wait for token expiry or run a refresh acceptance exercise to
use this development tool. If authentication breaks during normal use, check
`auth-status` and retry a deliberate browser login. The fields above are useful
for diagnosis, not a release checklist. Never dump tokens or process memory to
investigate a failure.

## AWS operation policy

Some AWS calls send a credential or a secret value back to the caller. The proxy
checks every AWS request that carries its dummy credentials **before** it mints
or uses STS credentials, and refuses these by default:

| Service | Denied operations |
|---|---|
| `secretsmanager` | `GetSecretValue`, `BatchGetSecretValue` |
| `ssm` | `GetParameter`, `GetParameters`, `GetParametersByPath`, `GetParameterHistory`, only when `WithDecryption` is true |
| `iam` | `CreateAccessKey`, `CreateServiceSpecificCredential`, `ResetServiceSpecificCredential` |
| `sts` | `Assume*` and `Get*Token` (for example `AssumeRole`, `GetSessionToken`, `GetFederationToken`) |
| `ecr`, `ecr-public`, `codeartifact` | `GetAuthorizationToken` |
| `lambda` | `GetFunction`, `GetFunctionConfiguration`, `ListFunctions`, `ListVersionsByFunction` (they return environment variables) |
| `kms` | `Decrypt`, `DeriveSharedSecret` |
| any | `Unknown` |

`sts get-caller-identity`, S3, `ssm get-parameter` without decryption and other
calls are unaffected. This is a **new default**: it applies even with no policy
file. Terraform plans that read Lambda functions now need an override.

The operation comes from the request itself: `X-Amz-Target` (JSON protocols), the
`Action` form or query value (Query protocols), the `/service/…/operation/…` path
(RPC v2) or the method and path (REST, Lambda and CodeArtifact only; other REST
requests are `Unclassified`). The service comes from the signature's credential
scope and must match the host. Anything missing, duplicated, conflicting,
encoded, non-UTF-8, over 16 MiB when the body is needed, or carrying more than one
protocol's operation field is `Unknown`, and is denied.

A denied call gets HTTP 403 with code `AccessDeniedException` and a message such
as `secret-proxy blocked sts:AssumeRole: …`, in the protocol's own JSON, XML or
CBOR shape. The proxy terminal shows one line with the account, role, service,
operation and decision. Bodies and responses are never logged. Presigned URLs are
out of scope and behave as before.

### Optional `aws-policy.json`

Add rules next to the manifest. The built-in deny list always applies; the file can
add deny rules and per-service allow lists, never remove a built-in rule:

```json
{
  "version": 1,
  "rules": [
    {"action": "deny", "service": "dynamodb", "operations": ["Scan"]},
    {"action": "allow", "service": "ec2", "operations": ["Describe*"]}
  ]
}
```

`service` is a lower-case glob over `[a-z0-9-*?]`; `operations` are globs over
`[A-Za-z0-9_*?]`, matched without regard to case. Once a service has an allow
rule, its other operations (including `Unknown` and `Unclassified`) are denied.
An invalid file stops the proxy from starting and names the bad rule. See
`examples/aws-policy.json`.

### Overrides for one role

For a genuine need, allow specific operations for **one exact account and role**
in `aws-okta.json`:

```json
"operation_overrides": [
  {"account": "123456789012", "role": "Deployer", "service": "secretsmanager",
   "operations": ["GetSecretValue"], "comment": "release tooling"}
]
```

There are none by default. Each override is printed at start-up and each use logs
`AWS ALLOW (override)`. Any client that can select that role can use it, so give
the exception its own role with narrow upstream permissions. Adding or changing
either file is a private policy change: the installer refuses to overwrite an
existing instance's policy, as for any other policy file.

## Approval prompts

With [approval rules](advanced-setup.md#approval-rules) configured, keep a
terminal running:

```bash
secret-proxy approvals
```

It asks for sudo, then runs as the proxy account: the approver capability is a
per-boot file in that account's private directory, so ordinary clients (which
hold only the proxy capability) can never answer their own prompt. It
long-polls the proxy over authenticated TLS, bound to the current boot nonce,
and shows one request at a time:

```
An AWS operation needs approval:
  method     POST
  host       iam.amazonaws.com
  path       /
  account    123456789012
  role       Admin
  service    iam
  operation  CreateRole
  rule       aws-policy.json rule 3
Expires in 119 s. Choose:
  1 deny once   2 allow once   3 allow for this proxy session   4 deny for this proxy session
```

- Input is accepted only after a one-second pause; anything typed earlier is
  discarded, and the proxy refuses an answer that arrives sooner.
- Anything other than `1`–`4` denies once. No answer before the timeout denies.
  Ctrl-C denies the request on screen and stops.
- "For this proxy session" covers the same client, secret, host, method and
  matched rule (AWS: account, role, service, operation and rule; egress: the
  host), not the whole host. Session decisions are in memory only; `stop`
  clears them.
- With nobody listening (no `approvals` terminal for about 10 seconds), every
  request that needs approval is denied at once.

The proxy terminal logs each decision with the rule and request summary, never
a secret value, body or query string, for example
`APPROVAL deny (approval-timeout) aws method=POST host=iam.amazonaws.com ...`.

## Refused destinations

The proxy refuses connections to loopback, link-local, metadata, multicast and
reserved addresses, by default to private ranges, and to any host the optional
`egress` allow/deny list refuses. A client sees a `403` with
`secret_proxy_egress_refused` and the rule name; the proxy terminal logs
`BLOCKED ... egress <rule>` with the host and port only. If a legitimate
internal destination is refused with `private-address`, add its network to
`egress.allowPrivateCidrs` in a new candidate registration; for
`egress-allowlist`, add the host to `egress.allow`. See
[egress controls](advanced-setup.md#egress-controls).

**Upgrading from a release without egress checks:** private destinations that
used to work, for example internal hosts through a VPN, are now refused until
you list them. Check the networks you need before switching over.

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
   material while you are still validating normal use.

Archiving keeps a recovery copy; it does not delete the underlying data. Machine removal,
volume deletion and wider host cleanup are separate, destructive operations.
