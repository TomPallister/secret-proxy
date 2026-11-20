# Daily operations and recovery

For the first installation, follow [setup](setup.md). After that, use the installed CLI. The proxy is foreground,
not a persistent service. Closing a terminal is not a reliable stop command.
Do not put tokens in shell profiles, shell history, command arguments or a
launcher configuration. Bootstrap metadata is not a service-account token.

## Start, login and stop

1. `secret-proxy start` prepares the image before desktop approval. Keep its
   terminal attached. A ready instance is left alone.
2. In another terminal, `secret-proxy login chatgpt` starts proxy-owned PKCE. Paste the
   full callback only into its hidden prompt. The client saves only a sealed
   record; optional proxy-side persistence is described below.
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
   policy and client auth. A new start requires browser login again, unless the
   manifest has a [login store](#stored-logins). With the
   [audit log](#audit-log) on, a stop seals and signs it.

## Stored logins

With `loginStore` in the manifest ([setup](advanced-setup.md#login-store)), each
completed login is also written to the login vault: the ChatGPT refresh token,
or the GitHub token for Copilot and gh. After a restart nothing needs to be
done. The first use of a login, or the first `auth-status` for it, restores it:

- ChatGPT: one refresh with the stored refresh token. OpenAI rotates it on every
  refresh, so the new one is written back each time.
- GitHub Copilot: a new Copilot token is minted from the stored GitHub token.
- gh: the stored token is used as it is.

Restore runs once per start, and the proxy never polls the vault: it reads the
vault on restore and writes it on login, logout and each ChatGPT rotation.
Those operations consume the service account's request quota; configure limits
for your usage rather than assuming the vault is never rate-limited. If something
fails, the proxy logs a fixed message (never a value) and carries on:

| Message | What it means |
| --- | --- |
| `stored ChatGPT login is no longer valid; run secret-proxy login chatgpt` | OpenAI refused the stored token. The proxy is logged out; log in again (this replaces the item). |
| `could not restore the stored ChatGPT login; run secret-proxy login chatgpt` | The refresh failed in a way that may have used the token. It is not retried. |
| `could not reach OpenAI to restore ...; will retry` | Nothing reached OpenAI. The next use after a back-off tries again. |
| `stored GitHub Copilot login is no longer valid` | GitHub refused the stored token; log in again. |
| `stored GitHub CLI login was made with other settings` | The gh domain or requested scopes changed; log in again. |
| `could not read the stored ... login (...)` | The vault could not be read. The login counts as logged out; the next use after a back-off tries again. |
| `could not save the stored ... login (...)` | The write failed. The login keeps working in memory and the write is retried on later use, with back-off. |

A rejected stored login is not deleted automatically, so you can inspect it; the
next login replaces it. Several items with the same title are refused; delete
the extras in 1Password.

`secret-proxy logout chatgpt|github-copilot|github` signs out of that login on
the running proxy and deletes its stored item. It needs the login's grant and the
current boot nonce, so it never acts on a restarted proxy. If the delete fails,
it says so; the proxy stays signed out and retries the delete on later use. Sealed
references saved by clients stay in their files but stop working until the next
login. Logout does not revoke tokens at OpenAI/GitHub; revoke upstream access
separately if that is your intent. 1Password keeps deleted items in Recently
Deleted for 30 days. If a delete remains pending when the proxy stops, its next
start can still find the old item; confirm the delete succeeded before relying
on logout to persist across restarts.

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

`secret-proxy auth-status chatgpt` reads `/chatgpt/status` over authenticated TLS and
checks the response against the current boot nonce. The output contains only:

- `instance`: boot nonce, not a credential;
- `loggedIn`: whether an access/refresh pair is held in memory;
- `expiresAt`: Unix seconds for the provider response's actual expiry deadline;
- `refreshCount`: successful expiry-triggered refreshes since the last login;
- `lastRefreshAt` and `lastRefreshDueAt`: Unix seconds for the last successful
  refresh and the expiry-minus-120-seconds threshold that triggered it.

No tokens, account IDs, identity claims or upstream error bodies are returned.
Without a login store, status does not fetch a secret, perform a token exchange,
move the clock, force refresh or keep an idle login alive. Login resets these
counters; a process restart resets all in-memory state. `loggedIn` is not an
upstream liveness probe.

With a [login store](#stored-logins), every login's status also has `stored`
(the login vault holds this login, as of the last read or write) and
`restoredFromStore` (this login came from the vault, not a login since start).
The first status after a start may then restore the login, which for ChatGPT
and Copilot is one token request.

`secret-proxy auth-status github-copilot` reads `/github-copilot/status` the same
way. It returns `instance`, `loggedIn`, `expiresAt` (the Copilot token's expiry),
`refreshCount` (refreshes since the last login, done by the proxy before
`refresh_in`) and `lastRefreshAt`. It never returns a usable token; with a login
store it can mint the initial Copilot session as part of restoration.
`secret-proxy auth-status github` returns only `instance`, `loggedIn` and the
`scopes` GitHub granted to the gh login.

You do not need to wait for token expiry or run a refresh acceptance exercise to
use this development tool. If authentication breaks during normal use, check
`auth-status` and retry a deliberate browser login. The fields above are useful
for diagnosis, not a release checklist. Never dump tokens or process memory to
investigate a failure.

## AWS operation policy

The proxy checks every AWS request that carries its dummy credentials **before**
it mints or uses STS credentials. What to block is configured in one file,
`aws-policy.json`, next to the manifest. `./setup.sh init` writes this starter
file (also `examples/aws-policy.json`):

```json
{
  "version": 1,
  "rules": [
    {"action": "deny", "service": "secretsmanager",
     "operations": ["GetSecretValue", "BatchGetSecretValue", "Unknown"]},
    {"action": "deny", "service": "ssm",
     "operations": ["GetParameter", "GetParameters", "GetParametersByPath", "GetParameterHistory", "Unknown"],
     "when": "secureStringReturned"}
  ]
}
```

- **Secrets Manager:** reading a stored value is refused before anything is
  sent. `ListSecrets`, `DescribeSecret` and the rest are allowed.
- **Parameter Store:** reads go through as normal. If the response holds a
  decrypted `SecureString`, the proxy replaces it with a 403, so the value never
  reaches the client. Plain `String` parameters are unaffected, including
  Terraform's default decrypting reads of them. A read without decryption is not
  checked: a `SecureString` then comes back still encrypted.

Edit or delete the rules as you like. **With no file, nothing is blocked.** The
only built-in rule is a safety check: a request whose signature's service doesn't
match its host is refused, so the proxy never signs for a service it didn't check.

### Writing rules

```json
{"action": "deny", "service": "sts", "operations": ["Assume*", "Get*Token"]}
{"action": "approve", "service": "iam", "operations": ["Create*", "Attach*"]}
{"action": "allow", "service": "ec2", "operations": ["Describe*"]}
```

- `deny` refuses the call. `approve` holds it until a person answers
  `secret-proxy approvals`. Once a service has an `allow` rule, only the listed
  operations are allowed for it. A deny always beats approve and allow.
- `service` is the AWS signing name (`sts`, `kms`, `lambda`…), a lower-case glob
  over `[a-z0-9-*?]`. `operations` are globs over `[A-Za-z0-9_*?]`, matched
  without regard to case.
- `"when": "secureStringReturned"` is only valid with `deny` and service `ssm`.
  It lets the call through and checks the response instead.
- An invalid file stops the proxy from starting and names the bad rule.
- The file is copied into the proxy at install time, so a change takes effect at
  the next install and restart, like any other policy change.

The operation comes from the request itself: `X-Amz-Target` (JSON protocols), the
`Action` form or query value (Query protocols), the `/service/…/operation/…` path
(RPC v2) or the method and path (REST, Lambda and CodeArtifact only; other REST
requests, such as S3, are `Unclassified`, so they can only be ruled on as a whole
service). Anything missing, duplicated, conflicting, encoded, non-UTF-8, over
16 MiB when the body is needed, or carrying more than one protocol's operation
field is `Unknown`. List `Unknown` in a rule to cover those requests, as the
starter file does, so a muddled request can't slip past.

A refused call gets HTTP 403 with code `AccessDeniedException` and a message such
as `secret-proxy blocked secretsmanager:GetSecretValue: …`, in the protocol's own
JSON, XML or CBOR shape. A checked Parameter Store response that can't be read
or is over 4 MiB is refused too. The proxy terminal shows one line
with the account, role, service, operation and decision. Values, bodies and
responses are never logged. Presigned URLs are not checked.

### Overrides for one role

To exempt **one exact account and role** from a deny rule or a Parameter Store
check, add an override in `aws-okta.json`:

```json
"operation_overrides": [
  {"account": "123456789012", "role": "Deployer", "service": "secretsmanager",
   "operations": ["GetSecretValue"], "comment": "release tooling"}
]
```

There are none by default. Each override is printed at start-up and each use logs
`AWS ALLOW (override)`. Any client that can select that role can use it, so give
the exception its own role with narrow upstream permissions. An override never
waives the built-in signing-service/host verification, even for `Unknown` or
wildcard operations. Adding or changing
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

## Audit log

Only with an enabled manifest [`audit` section](advanced-setup.md#audit-log).
The files live in the proxy account's volume; copy them out to read them:

```bash
secret-proxy audit export ~/audit-2026-11-20
secret-proxy audit verify --public-key ~/audit-signing.pub ~/audit-2026-11-20
secret-proxy audit verify --public-key ~/audit-signing.pub   # export to a temporary directory, then verify
```

`export` asks for sudo, then reads the files as the proxy account through a
throwaway container with no network and the volume mounted read-only. It works
while the proxy runs and after it stops, and refuses to overwrite an existing
directory. The copy is 0700/0600.

`verify` needs no sudo and no running proxy. Get the public key independently
(for example the public key of the SSH Key item in 1Password), not from the
log or the proxy: pinning it is what makes the check meaningful. It uses
`ssh-keygen -Y verify`. Results:

- `VALID, SEALED` (exit 0): every entry is in an unbroken chain up to a seal
  signed by the pinned key. Expect this after a clean stop.
- `VALID CHAIN, UNSIGNED TAIL` (exit 3): the chain is intact, but the last
  entries come after the last valid signature (the proxy is still running, it
  stopped uncleanly, or no signing key was available). Those entries are not
  authenticated. After a clean stop with a key, treat this as suspicious.
- `INVALID` (exit 1): an entry was edited, deleted, inserted or reordered, a
  file in the middle is missing or truncated, or a seal does not verify with
  the pinned key (a wrong or replaced key). The message names the first file
  and line that fails.

A signature also covers every earlier file, because each file's header is
chained to the previous one. Retention removes files from the oldest end;
`verify` then notes how many earlier files are missing, and cannot tell
retention from someone deleting the oldest files.

What `verify` cannot detect:

- Removal of the newest whole files, or of the unsigned tail of the newest file:
  the log just looks shorter. Compare the end time with when you expect.
- Changes to the unsigned tail by someone who rewrites its hashes consistently.
- Anything by someone who can read the proxy's state **and** holds the signing
  key: they can rewrite the history and sign it again. So can anyone if you
  verify without pinning the key yourself.

To turn the log off, remove the section (or set `"enabled": false`) and
restart. Old files stay in the volume until you delete them as the proxy account.

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
