# Advanced installation and configuration

For a first installation, use [the setup guide](setup.md). This page covers
manual registration, existing installations, migration and optional networking.
Nothing here is required for the read-only GitHub quickstart.

## Private configuration

Supply a private directory containing:

- `manifest.json`: schema 3, one explicit `account.vault`, enabled entries and
  exact placement policies. Examples are under `examples/` and contain only
  fictional/public example identities.
- Optional `aws-okta.json`: explicit approved `okta_hosts`, SAML app URLs,
  default account/role and role allowlists. No organisational defaults exist.
  Optional `operation_overrides` allow named AWS operations for one exact role.
- Optional `aws-policy.json`: which AWS calls are refused, held for approval or
  allowed. `./setup.sh init` writes a starter file; without one nothing is refused. See [AWS operation policy](operations.md#aws-operation-policy)
  and `examples/aws-policy.json`.
- `checkmarxRealm` in the manifest when enabling Checkmarx.
- Optional `clients` in the manifest: named clients, each with its own token and
  grants. See [scoped clients](#scoped-clients).
- Optional `upstream-ca.pem`: corporate trust roots. Used as a build secret and
  as an external runtime trust input, never baked into the image.
- Optional `client-environment.json`: tool variables containing canonical
  references and non-secret settings. No real credentials. Loader/interpreter
  environment overrides are refused.
- Optional `ca.json`: exactly `{"mode": "name-constrained"}`. The proxy then
  generates its own CA with critical name constraints covering only its
  interception hosts (exact names, the fixed suffix after a wildcard's last `*`,
  the internal sentinel, `amazonaws.com` with AWS, `auth.openai.com` with
  ChatGPT), excluding every IPv4/IPv6 address. Installation refuses a host
  pattern without a fixed suffix of at least two labels (e.g. `*.com`). New
  setups enable this by default; without the file mitmproxy's own unconstrained
  CA is used exactly as before. Existing instances keep their CA: opting in is a
  policy change (a new candidate, or an operator-placed root-owned file), and the
  first constrained start retires the old CA into `retired/` in its volume.
  Removing `ca.json` later is refused at start while a constrained CA is present.
  A client that CONNECTs to an IP address instead of a name gets a certificate
  with an IP address, which constrained verifiers reject.
- `bootstrap.json` (desktop-side only): account/vault/item metadata for the
  Login item holding the scoped service-account token. This file contains
  **no token** and is not copied into the proxy configuration.

Example bootstrap metadata:

```json
{
  "account": "example.1password.com",
  "vault": "Private",
  "item": "DevEnv Runtime capability",
  "runtimeVault": "DevEnv"
}
```

Use a read-only service account scoped to the runtime vault. Store its token in
the bootstrap Login item's password field, with these text fields:
`account_url` matching the configured account, `destination_vault` matching
`runtimeVault`, and `permissions` equal to `read_items`. The launcher verifies
that provenance, but item metadata alone does **not** independently prove the
service account's actual privileges. Review those in 1Password.

`migrate_config.py` converts an existing schema-2 policy offline, selecting one
profile and requiring all selected entries to resolve to a single runtime
account/vault. It refuses overwriting output or collapsing multiple vaults. It
never reads or moves credentials. An export preserves existing vault bindings;
it is **not proof of a newly isolated work-only vault**.

`migrate_aws.py` separately exports the **actual active** legacy AWS config. It
parses literal defaults from the corresponding legacy module without executing
it, preserving per-account precedence and requiring an explicit approved Okta
host list. It never contacts a provider, fetches credentials or overwrites output:

```sh
uv run --locked python migrate_aws.py --source /private/path/aws-okta.json \
  --legacy-module /private/path/awscreds.py --okta-host example.okta.com \
  --output /private/new-candidate/aws-okta.json
```

Use the active protected configuration, not a repository seed. Review the
result outside this repository before installing it as a new candidate.

## Egress controls

The proxy decides every upstream connection before opening it, for CONNECT
tunnels (intercepted or not) and plain HTTP. It resolves the name **once**,
checks **every** address in the answer, then connects to a checked address.
A second DNS answer (rebinding) cannot change where that connection goes.

Always refused, and not configurable:

- loopback, link-local (`169.254.0.0/16`, `fe80::/10`), unspecified,
  multicast and reserved (`240.0.0.0/4`) addresses;
- cloud metadata addresses (`169.254.169.254`, `169.254.170.2`,
  `fd00:ec2::254`, `100.100.100.200`), even inside an allowed private range;
- metadata names such as `metadata.google.internal`, `metadata` and
  `instance-data`.

IPv4-mapped, IPv4-compatible and NAT64 (`64:ff9b::/96`) IPv6 addresses are
checked as the IPv4 address they carry. Numeric forms such as `2852039166` are
read as the address they encode.

Refused by default, allowed by explicit CIDR: private ranges (`10/8`,
`172.16/12`, `192.168/16`, CGNAT `100.64/10`, `fc00::/7`, `fec0::/10`) and
other special-purpose ranges (documentation, benchmarking, 6to4, Teredo).

An optional `egress` section in `manifest.json` configures the rest. Every
field is optional; without the section, egress is open as before apart from the
address checks above. See `examples/egress-manifest.json`:

```json
"egress": {
  "mode": "allowlist",
  "allow": ["*.example.com", "registry.example.org", "api.*.example.net"],
  "deny": ["paste.example.com"],
  "allowPrivateCidrs": ["10.20.0.0/16", "fd12:3456::/32"]
}
```

- `mode`: `open` (default) or `allowlist`. In `allowlist` mode a host must
  match `allow` or be a manifest placement host. `allow` is refused in `open`
  mode so a mistaken mode does not silently ignore it.
- `deny` is checked first in both modes, including for manifest hosts.
- Patterns: an exact host; `*.example.com` matches one or more labels before
  `example.com` (not `example.com` itself); a `*` label elsewhere matches
  exactly one label. IP literals match only that address. Partial-label
  wildcards (`api*.example.com`), a bare `*` and duplicates are rejected at
  startup. Ports are not part of a pattern.
- AWS endpoints, `auth.openai.com` and the GitHub login domains (`<domain>`,
  `api.<domain>`) are not implicitly allowed. In
  `allowlist` mode with AWS signing, list the endpoints you use, for example
  `*.amazonaws.com` or `sts.amazonaws.com`.
- `allowPrivateCidrs`: networks without host bits. Entries overlapping
  loopback, link-local or other always-refused ranges, IPv4-in-IPv6 forms and
  entirely public networks are rejected.

Refusals are a `403` naming the rule, sent before any upstream connection:
`{"error":"secret_proxy_egress_refused","rule":"private-address"}`. Rules
are `metadata-host`, `metadata-address`, `loopback-address`,
`link-local-address`, `unspecified-address`, `multicast-address`,
`reserved-address`, `private-address`, `special-purpose-address`,
`egress-deny`, `egress-allowlist` and `invalid-host`. A name that does not
resolve gets `502` with rule `unresolved`.

The policy is read at startup and invalid configuration stops startup with a
message naming the problem. The installer validates it too. Change it with a
new candidate registration, like any other policy change.

Limits:

- It covers only traffic that comes through the proxy. To stop clients going
  direct, route them through it, for example with an internal network that has
  no other way out.
- Host patterns match the requested name. The addresses that name resolves to
  are checked separately.
- The proxy's own connections (1Password, Okta/AWS credential minting, the
  ChatGPT login exchange) do not go through these lists.
- The proxy connects to the first checked address, so it does not fall back to
  later addresses when the first one fails to connect.

## Approval rules

Some uses are legitimate but rare and sensitive, such as a write to a
production API or `iam:CreateRole`. An approval rule holds a matching request
until a person answers it. All of them are off by default:

- a placement field `"approval": "prompt"`;
- an AWS rule `{"action": "approve", ...}` in `aws-policy.json`;
- `"allowlistMiss": "approve"` in an `allowlist` egress section, for hosts
  that are not listed.

See `examples/approval-manifest.json` and `examples/aws-policy.json`. Precedence:

- A [scoped client](#scoped-clients)'s grants are checked first: a request
  outside them is refused, never offered for approval.
- A deny rule always wins. A built-in AWS deny, a file deny rule, an egress
  `deny` pattern, a metadata name and every refused address can never be
  approved. A request that breaks a placement rule is refused without a prompt.
- When several placements match, one with `"approval"` wins, so a broader
  placement cannot bypass it. An AWS role override that allows a denied
  operation still asks when an approve rule also matches.

A held request is not forwarded, no secret is resolved for it and no AWS
credential is minted until it is approved. Streaming uploads are held before
their body starts to flow. Egress approvals hold the CONNECT (or plain HTTP
request). Answer with `secret-proxy approvals`; see
[operations](operations.md#approval-prompts).

Optional timing, in `manifest.json`:

```json
"approvals": {"timeoutSeconds": 120, "maxPromptsPerMinute": 10}
```

`timeoutSeconds` (10 to 600, default 120) denies an unanswered request.
`maxPromptsPerMinute` (1 to 60, default 10) denies new prompts above the rate.
At most 16 requests wait at once.

The requester only receives an error: HTTP 403 with
`{"error":"secret_proxy_approval_denied","rule":"approval-denied"}` (or the
AWS `AccessDeniedException` shape for AWS requests, or the egress refusal
shape). Rules: `approval-denied`, `approval-timeout`, `approval-no-listener`,
`approval-rate-limited`, `approval-queue-full`, `approval-malformed-answer`,
`approval-answered-too-fast`, `approval-withdrawn` (the client went away) and
`approval-required` (no runtime adapter could ask).

The prompt names the authenticated client, method, host, path
without the query string, the secret's canonical name and placement, or the AWS
account, role, service and operation, and the matched rule. It never contains
a secret value, header value, body or query string. For a URL-rewrite secret
the destination is itself the secret, so the prompt names the sentinel host.

A launcher that starts `runtime.py` directly enables approvals by adding an
`approver_token` (48 lowercase hex characters, different from `proxy_token` and
every client token) to
the bootstrap bundle. Without it, every request that needs approval is denied.

## Audit log

Off by default. The proxy then writes nothing about requests anywhere: its
activity goes only to the attached terminal. To keep a tamper-evident record of
security decisions, add to `manifest.json` (see `examples/audit-manifest.json`):

```json
"audit": {"enabled": true, "signingKey": "AUDIT_SIGNING_SSH_KEY"}
```

and an Ed25519 SSH Key item for it:

```json
"AUDIT_SIGNING_SSH_KEY": {"internalOnly": true, "valueField": "sshPrivateKey"}
```

Use a dedicated key rather than your Git signing key; reuse works (audit seals
use their own SSH signature namespace) but a separate key keeps the two apart.
Without `signingKey` the files are still hash-chained, but nothing is signed.

| Field | Default | Range |
|---|---|---|
| `maxFileBytes` | 4 MiB | 64 KiB to 64 MiB; a new file starts after this size, and at least daily |
| `maxTotalBytes` | 64 MiB | `maxFileBytes` to 256 MiB; oldest files are deleted above it |
| `maxAgeDays` | 90 | 1 to 3650; files whose last change is older are deleted |

Files are `audit-NNNNNNNN.jsonl` in the proxy's own volume (`/data/audit` in
the container): directory 0700, files 0600, readable only through the proxy
account. Nothing goes to `/config` or the shared client directory. A file is
deleted only from the oldest end, never the one in use. A client that makes
many refused requests can push older entries out through retention, so size
`maxTotalBytes` for how far back you need to look and export regularly. An invalid `audit`
section, or an audit directory that cannot be opened, stops the proxy from
starting.

**What is recorded.** One JSON line per decision: time, client, host, port,
method and path without the query string or fragment, and as relevant the
secret's canonical name, placement kind and field name, the decision
(`injected`, `refused`, `allowed`, `denied`, `failed`, `signed`, `answered`,
`started`, `completed`), a fixed reason code or rule, an exception class name,
AWS account, role, service and operation, and the approval choice. Events cover
injections, AWS decisions, egress refusals, approvals, proxy-owned logins, the
Copilot and Checkmarx exchange answers and Git signing. Requests without a
reference (plain passthrough) are not recorded.

**Never recorded:** secret values, headers, request or response bodies, query
strings, OAuth tokens, callbacks or error message text. Every field is checked
against a fixed allow-list and shape when it is written; anything else is
dropped and counted in the entry's `dropped` field. For a URL-rewrite secret the
destination is itself the secret, so only the sentinel host and the reference
name are recorded.

**Each entry is on disk before the request proceeds.** Every line is written
and `fsync`ed before the decision takes effect. If an entry that grants
something (an injection, an AWS signature, a Git signature, a login or an
exchange answer) cannot be written, the request is refused with
`503 {"error":"secret_proxy_audit_unavailable"}` and nothing is sent upstream.
A failed write is cut back so no partial line stays in the chain.

**Chain and seal.** Each line carries a sequence number and the SHA-256 of the
previous line. Each file starts with a header (format version, file number,
boot nonce, start time, signing-key fingerprint) chained to the previous
file's last line. A clean stop (`secret-proxy stop`, Ctrl-C) and each rotation
end the file with a `seal`: an SSH signature (namespace `secret-proxy-audit`)
over the file's header hash, the seal's position and the last hash. If the key
cannot be read, the seal says why and has no signature. A crash, `kill -9` or
VM failure leaves the last file without a seal. To export and check the log,
see [operations](operations.md#audit-log).

## GitHub logins

The proxy can own a GitHub Copilot login (for Pi) and a GitHub CLI login (for
`gh`). Each is off unless the manifest declares its runtime-only entry. Copilot
example (`examples/github-manifest.json` has both):

```json
{
  "githubLogins": {"copilot": {"domain": "github.com"}},
  "secrets": {
    "GITHUB_COPILOT_SESSION_TOKEN": {
      "runtimeOnly": true,
      "placements": [{"kind": "header", "hosts": ["api.githubcopilot.com", "api.*.githubcopilot.com"],
                      "name": "authorization", "template": "Bearer {secret}", "methods": ["GET", "POST"]}]
    }
  }
}
```

- `githubLogins` is optional. `domain` defaults to `github.com`. For GitHub
  Enterprise Cloud with data residency, set your own domain (for example
  `github.example.com`); the device flow then uses that domain and the exchange
  uses `api.<domain>`.
- Do not create a vault item for `GITHUB_COPILOT_SESSION_TOKEN`. With
  `runtimeOnly`, the value only ever comes from the login. Without it, the name
  is an ordinary vault secret and the login stays off.
- Enabling the login adds `<domain>` and `api.<domain>` to the intercepted hosts,
  so the proxy can refuse a client's own device flow and answer its token
  exchange. The placements decide where the Copilot token may go; the token's own
  `proxy-ep` narrows that to one host.

For gh, declare `GH_CLI_OAUTH_TOKEN`. The example in `examples/` is read-only:
it allows `GET`/`HEAD` on `api.github.com` with gh's `token` header. That covers
`gh api` reads, but most other gh commands use GraphQL, which is a `POST`. A
full-access policy, including uploads and Git over HTTPS, looks like this:

```json
{
  "githubLogins": {"cli": {"domain": "github.com", "scopes": ["repo", "read:org", "gist"]}},
  "secrets": {
    "GH_CLI_OAUTH_TOKEN": {
      "runtimeOnly": true,
      "placements": [
        {"kind": "header", "hosts": ["api.github.com", "uploads.github.com"],
         "name": "authorization", "template": "token {secret}"},
        {"kind": "basic-password", "hosts": ["github.com"], "username": "x-access-token"}
      ]
    }
  }
}
```

- `scopes` defaults to gh's own minimum (`repo`, `read:org`, `gist`). Fewer
  scopes limit what the token can do on GitHub, whatever the placements allow.
- Path rules can't tell a Git fetch from a push, so Git placements grant both.
  Use GitHub permissions and scopes to limit writes.
- Enabling the login adds `<domain>` to the intercepted hosts so the proxy can
  refuse gh's own device flow.

## Scoped clients

By default there is one proxy token, and whoever holds it can use every
placement, login, Git signing and every allowed AWS role. An optional `clients`
section in the manifest gives each named client its own token and its own
grants (`examples/clients-manifest.json`):

```json
{
  "clients": {
    "default": {"all": true},
    "issue-reader": {"secrets": {"GITHUB_TOKEN": {"placements": [0]}}},
    "notifier": {
      "secrets": {"EXAMPLE_WEBHOOK_URL": true},
      "aws": [{"account": "123456789012", "role": "ExampleReadOnly",
               "operations": ["sts:GetCallerIdentity", "s3:*"]}],
      "signing": false,
      "logins": []
    }
  }
}
```

- Without a `clients` section nothing changes: one `default` client with every
  grant, proxy-auth user name `secret-proxy`, token file `proxy-token`.
- With the section, `default` must be declared. `{"all": true}` keeps every
  grant (used alone). The default client keeps the user name `secret-proxy` and
  the `proxy-token` file, so existing settings, health checks and the daily CLI
  keep working. Other names are `[a-z][a-z0-9-]{0,31}`, at most 16 clients; the
  name is the client's proxy-auth user name.
- Everything not granted is refused. A grant lists:
  - `secrets`: canonical names. `true` allows every placement of that secret;
    `{"placements": [0, 2]}` allows only those entries (by index) of its
    `placements` list. Grant a derived entry (for example `WIZ_ACCESS_TOKEN`),
    never the internal-only secret it comes from.
  - `aws`: `account` (12 digits or `*`) and `role` (exact name or `*`) a client
    may select, optionally narrowed by `operations`, as `service:Operation`
    globs matched against the operation the proxy identifies (REST services
    without named operations, such as S3, identify as `s3:Unclassified`; use
    `s3:*`). The rules in `aws-policy.json` still apply, and a role
    override cannot widen a client's grant. Presigned URLs are not classified,
    so only an `aws` grant without `operations` covers them.
  - `signing`: `true` to use proxy Git signing.
  - `logins`: proxy-owned login routes the client may drive (`chatgpt`,
    `github-copilot`, `github`). Using the resulting token is a separate secret
    grant, for example `CHATGPT_ACCESS_TOKEN`.
- Refusals happen before any secret is resolved or any AWS credential minted:
  `403` with `secret_proxy_placement_not_allowed` for placements,
  `secret_proxy_client_not_granted` for logins, signing and the Copilot and
  Checkmarx token-exchange answers, and an AWS `AccessDeniedException` for AWS.
  `/health` stays open to every authenticated client. Egress rules apply to all
  clients unchanged. Requests with no reference pass through for any client.
- A URL-rewrite secret granted by placement index is resolved before its
  destination is known, then refused if the destination matches an ungranted
  placement. Grant the whole secret, or keep one URL-rewrite placement per secret.

The controller creates one random token per named client, keeps it in the
instance's private directory (so it survives restarts, like the default token)
and passes it to the runtime on stdin with the service-account capability. The
runtime writes one `{SHA}` line per client into its private htpasswd file. Each
token is published as its own owner-only file, `proxy-token.<name>`, next to
`proxy-token`; files of clients removed from the manifest are deleted at the
next start. Tokens are never in argv or logs. Use one with `--client`:

```sh
secret-proxy run --client issue-reader -- gh api repos/example/project/issues
```

**Scoping is only a boundary when the less-trusted process cannot read the
other tokens.** On a single-user Mac you can read every published token,
including the unrestricted `proxy-token`, so any process running as you can
too: there, scoping organises access but does not contain a hostile process.
It contains one when the narrow token is the only one the process can reach,
for example a container that gets just its own file:

```sh
podman run --rm \
  -v /private/etc/secret-proxy/<instance>/proxy-token.issue-reader:/run/proxy-token:ro \
  -v /private/etc/secret-proxy/<instance>/bundle.pem:/run/ca.pem:ro \
  example/tool sh -c 'export HTTPS_PROXY="http://issue-reader:$(cat /run/proxy-token)@host.containers.internal:10260"; exec tool'
```

Adjust the proxy address to however your container reaches the proxy port.
Mount the single file, never the shared directory. A shim run as another
local user, given only its own token file, works the same way.

Changing the `clients` section is a policy change, like any manifest change:
register it as a new candidate or replace the root-owned policy deliberately,
then restart.

## Candidate installation on macOS

Prerequisites: Apple silicon macOS supporting libkrun, the root-owned Podman
installer tools under `/opt/podman/bin`, Command Line Tools Python/Git, and a
working desktop-integrated `op`. Review the committed source before using sudo.

For an isolated rehearsal, the operator helper checks clean/signed source and
then runs the install/start sequence below (sudo and Touch ID remain interactive):

```sh
./candidate.sh "$HOME/.config/secret-proxy-candidate-source" \
  "$HOME/.pi/agent-secret-proxy-candidate"
```

Use a separate Pi agent directory to leave the live auth file unchanged. Keep
the helper attached; run status/login from another terminal using the client
commands below. Alternatively, run the steps explicitly from a clean checkout,
after verifying the signed commit as your own user:

```sh
REV=$(git rev-parse HEAD)
git verify-commit "$REV"
sudo /Library/Developer/CommandLineTools/usr/bin/python3 macos_install.py \
  --repo "$PWD" --commit "$REV" \
  --config "$HOME/.config/secret-proxy-candidate-source" \
  --instance candidate --machine secagent --port 10260 \
  --agent-dir "$HOME/.pi/agent"
```

Select the **correct** Pi agent directory for your installation; there is no
hardcoded work/personal profile. `PI_CODING_AGENT_DIR` is also honoured by the
client when no configured/explicit agent directory overrides it.

The installer copies an allowlisted tree from the exact signed commit to a
root-owned `/opt/secret-proxy/releases/<commit>`, never from an uncommitted
working tree. It registers root-owned instance policy, private secagent config
and an explicit read-only client ACL under `/private/etc/secret-proxy/candidate`.
Repeat installation is idempotent for identical configuration; policy changes
require a new candidate name rather than implicitly changing a running service.
It does not install a global CA, fetch credentials or start any service.

Start the candidate (sudo and desktop Touch ID may prompt):

```sh
/Library/Developer/CommandLineTools/usr/bin/python3 /opt/secret-proxy/current/host.py \
  up candidate --bootstrap "$HOME/.config/secret-proxy-candidate-source/bootstrap.json" \
  --op "$(command -v op)"
```

Image preparation happens **before** the capability is fetched. Podman's
remote client needs a writable context to stage build-secret files, so the
controller copies only allowlisted build inputs from the immutable release to
a temporary secagent-private directory and removes it afterwards. Build failures
show a bounded diagnostic tail; credential-bearing provider errors stay hidden.
The bounded bootstrap travels only over stdin. Proxy authentication is never placed in
argv. The image is read-only, non-root, capability-dropped, without persistent
container logs, with private runtime files under tmpfs and a private CA volume.
Keep the command attached. Explicit shutdown is:

```sh
/Library/Developer/CommandLineTools/usr/bin/python3 /opt/secret-proxy/current/host.py stop candidate
```

Never assume closing a terminal stopped a container. Use `stop`. No volumes are
deleted; the candidate CA/client capability persist across restarts.

An existing machine must already share secagent's private `.config` directory.
The controller refuses to recreate a machine if that mount is missing. For a
fresh machine it creates only the required private config mount.


## Optional externally managed VPN

Without `network.json` the candidate uses direct egress. Internal hosts
reached through a VPN usually resolve to private addresses, which are refused
unless listed in `egress.allowPrivateCidrs` (see [egress controls](#egress-controls)). To attach to an already
running VPN container on the **same secagent engine**, add external private
`network.json` before registering a **new** candidate instance:

```json
{
  "container": "vpn-gateway",
  "network": "vpn-client-network",
  "interface": "tun0",
  "port": 10257,
  "readyFile": "/run/vpn/ready",
  "dns": ["127.0.0.53"]
}
```

Names are examples; use the external owner's actual readiness/interface/network
contract. The shared-namespace port must be unused, unprivileged and distinct
from 10256, so the legacy proxy can continue listening unchanged. The controller
pins the gateway's container ID and network IP, joins that namespace, and starts
an opaque, credential-free relay for the new host loopback port. It never starts,
stops, removes, connects networks to or reconfigures the gateway. The gateway
must provide `test` and `ip -j link` for health inspection.

Interface loss stops the proxy; gateway loss withdraws readiness and removes the
candidate relay. Neither causes a direct-egress fallback. The external owner
must itself enforce **fail-closed routing**: periodic watchdogs are secondary
checks, not atomic routing enforcement or proof of an authenticated tunnel.
A gateway restart needs an explicit candidate restart (and ChatGPT login).

Do not alter the existing direct candidate's policy in place or start a duplicate
VPN login. A live VPN rehearsal still requires operator coordination.
