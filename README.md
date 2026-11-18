# secret-proxy

Standalone, organisation-neutral secret injection for host applications or
containers. Private policies, tenant identities, vault metadata and corporate
certificates stay outside this repository and its images. 1Password only.

**Development candidate, not a general production release.** A direct-egress
macOS deployment has passed host Pi and development-container cutover checks:
authenticated routing, preserved sealed login and workspace, read-only AWS/GitHub,
Git signing, Bedrock and Codex model calls, compaction, and restart/relogin.
Host routing rollback was also exercised. Consumer adapters live outside this
engine. VPN attachment is tested with disposable namespaces, not a live tunnel.
[v0.1.0](https://github.com/TomPallister/secret-proxy/releases/tag/v0.1.0) is a
published **source-only testing preview**, licensed under Apache-2.0. Its upgraded
runtime has also passed the host and development-container checks above.
Prebuilt image redistribution is not cleared, particularly for the bundled
1Password CLI; see [the licensing review](docs/licensing-review.md).

**Known dependency findings remain.** The reviewed Python lock had zero known
advisory matches, with a documented/tested Tornado compatibility override. Debian
and bundled-tool findings are documented and accepted for this preview's testing
scope, not generally production-cleared. The official saml2aws binary is retained.
See [the audit](docs/dependency-audit.md). New source changes still require review,
scanning and explicit release/deployment approval.

## Licence

Copyright 2026 secret-proxy contributors. First-party source is licensed under
the [Apache License, Version 2.0](LICENSE). Dependencies retain their own licences
and terms; this does not grant permission to redistribute the bundled tools.

## Security contract

Clients send canonical references instead of stored credentials. Injection is
checked against destination, method, path and header/query/form/Basic placement.
OAuth exchanges happen inside the proxy; ChatGPT and Checkmarx clients receive
sealed references rather than reusable OAuth tokens. Git signing returns only
a signature. Static values are cached in RAM until invalidation/restart;
derived credentials follow expiry. ChatGPT access and rotating refresh tokens
remain memory-only: restart means browser login again.

See [the security boundaries](SECURITY.md) and the
[source-only release procedure](docs/source-release.md).

This isolates proxy-held credentials, **not every credential that an allowed
upstream API might return or create**. An authenticated client can use allowed
access. Root/sudo, trusted bootstrap and private policy are trusted boundaries.
Selective TLS interception does not narrow an installed root CA's authority.

The recommended Mac boundary is a separate, non-admin `secagent` OS account
with its own libkrun Podman machine. A container owned by the desktop user is
not equivalent isolation. The installer never retires/recreates existing
machines or legacy services. Candidate mode uses its own container, CA volume,
client capability, readiness files and loopback port.

## Private configuration

Supply a private directory containing:

- `manifest.json`: schema 3, one explicit `account.vault`, enabled entries and
  exact placement policies. Examples are under `examples/` and contain only
  fictional/public example identities.
- Optional `aws-okta.json`: explicit approved `okta_hosts`, SAML app URLs,
  default account/role and role allowlists. No organisational defaults exist.
- `checkmarxRealm` in the manifest when enabling Checkmarx.
- Optional `upstream-ca.pem`: corporate trust roots. Used as a build secret and
  as an external runtime trust input, never baked into the image.
- Optional `client-environment.json`: tool variables containing canonical
  references and non-secret settings. No real credentials. Loader/interpreter
  environment overrides are refused.
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

## Daily commands

After installing a release that contains the daily CLI, create a **private**
`~/.config/secret-proxy/cli.json` from [`examples/cli.json`](examples/cli.json).
Choose the instance already registered by the installer, the desktop-side
bootstrap metadata file, and the absolute path to desktop-integrated `op`.
Use mode 0600. Never put a service-account token in this file. Keep `cli.json`,
launchers and operation history **outside** the installer's private policy
directory: that directory accepts only its explicitly allowlisted policy files.
The example uses a separate `config/` subdirectory for bootstrap/policy metadata.

Link the installed launcher as your own user (do not overwrite an unrelated
existing command). Use the exact verified release revision you installed:

```sh
mkdir -p "$HOME/.local/bin"
ln -s "/opt/secret-proxy/releases/$REV/secret-proxy" "$HOME/.local/bin/secret-proxy"
secret-proxy status
secret-proxy start       # foreground; sudo / Touch ID; no implicit restart
# In another terminal after readiness:
secret-proxy login       # hidden browser callback; sealed auth only
secret-proxy auth-status # credential-free, read-only refresh evidence
secret-proxy run -- /absolute/path/to/client
secret-proxy stop        # only this instance; waits for controller cleanup
```

The launcher is pinned to an immutable installed **CLI** revision, while the
selected engine remains `/opt/secret-proxy/current`. It therefore remains usable
if the engine is rolled back to an older version without the CLI. `auth-status`
requires a runtime that supports it; older runtimes fail that command rather than
fabricating evidence. `status`, `start`, `stop`, `login` and `run` use the existing
host/client contract. `--config /absolute/path/to/cli.json` selects another
explicit metadata file. Neither status command starts a service or resolves a
vault secret. `start` leaves an authenticated, ready instance unchanged.

Keep the start terminal attached. To restart explicitly, use `stop`, then
`start`, and repeat browser `login`: real access/refresh tokens never persist.
Starting an unhealthy instance does **not** implicitly remove it. Stop it
explicitly first. No command silently downloads, installs or selects an upgrade.
Normal clients retain their existing bindings; a new login uses the agent
directory in the installed client configuration, not an implicit global profile.

See [operations, refresh evidence and reversible retirement](docs/operations.md)
for upgrade/rollback and cleanup ordering.

## Optional externally managed VPN

Without `network.json` the candidate uses direct egress. To attach to an already
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

## Host clients and ChatGPT login

```sh
CLIENT=/opt/secret-proxy/current/client.py
CONFIG=/private/etc/secret-proxy/candidate/client.json
python3 "$CLIENT" --config "$CONFIG" status
python3 "$CLIENT" --config "$CONFIG" login
python3 "$CLIENT" --config "$CONFIG" run -- /absolute/path/to/real-pi
```

`run` changes only the launched process and its children. It replaces inherited
proxy bypasses, supplies the public trust bundle and configured references, and
does not print an export script containing the client capability. It does not
change other host applications or configure the OS-wide proxy. Start the real
Pi executable, not an existing wrapper that overrides proxy settings. Clients
must honour these proxy and CA variables: macOS Go programs such as `gh` do not
honour `SSL_CERT_FILE`, so they are not yet accepted without a separate host
trust decision. Arbitrary editors/clients are not claimed to work.

`status` verifies authenticated TLS and the current boot-instance nonce. It
proves the runtime is serving the selected policy, **not that vault access or
all upstream integrations work**.

`login` prints the OpenAI authorisation URL. After browser sign-in, paste the
full localhost callback into the hidden prompt. Noncanonical terminal input
supports long callbacks (tested with 12 KB); `--callback-stdin` is available for
pipes/files. The proxy validates OAuth state and exchanges the code. The client
rejects unsealed replies and account-claim mismatches, then atomically updates
only Pi's `openai-codex` entry with mode 0600. Do not run Pi `/login` or `/logout`
concurrently with this helper. Existing provider entries are preserved.

## Development and verification

```sh
./test.sh
uv run --locked ruff check --isolated --select E9,F63,F7,F82 .
podman build -t localhost/secret-proxy-candidate:phase2 .
```

For inspected build networks, add
`--secret id=upstream_ca,src=/absolute/path/to/corporate-ca.pem`.
The certificate is used in a temporary bundle and removed in the same layer.
The base, Python dependencies and downloaded tools are pinned/checksummed;
Debian apt repository contents are still mutable, so this is not yet a
bit-for-bit reproducible image.

Credential-free, external-network-free runtime smoke:

```sh
podman run --rm -i --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  --entrypoint /opt/secret-proxy/.venv/bin/python \
  localhost/secret-proxy-candidate:phase2 - < tests/smoke_container.py
```

For actual TLS/H1/H2 injection and signing against a generated local upstream,
run the same network-disabled container command with `tests/smoke_wire.py` as
stdin instead. All credentials and signing keys in that test are synthetic.

Real Mac host/Podman contract test, against an explicit test connection:

```sh
uv run --locked python tests/smoke_host.py --connection devenv \
  --image localhost/secret-proxy-candidate:phase2
```

This creates/removes only new `sp-smoke-*` containers/volumes and a VM temporary
directory. It tests the actual launch flags, loopback publishing, non-root state,
TLS CONNECT, CA handoff, wrong-auth and stale-readiness rejection, and stop.
It uses synthetic capabilities and makes no vault or external API calls.

A full controller/relay smoke with an internal network, dummy tunnel interface
and fake capabilities is also available. It touches only disposable fixtures:

```sh
uv run --locked python tests/smoke_vpn.py --connection devenv \
  --image localhost/secret-proxy-candidate:integration
uv run --locked python tests/smoke_vpn.py --connection devenv \
  --image localhost/secret-proxy-candidate:integration --failure gateway
```

Optional **live, billable** Pi prompt/compaction/recall acceptance uses an already
logged-in candidate and temporary sealed-only auth/settings. It never changes the
original agent directory, enables tools/extensions or saves a session:

```sh
uv run --locked python tests/smoke_pi.py --help
```

## Remaining acceptance gates

- Private vault-scope review (the working deployment retains its existing binding).
- Actual expiry-driven OAuth refresh: unit coverage exists; live expiry remains
  unverified. Successful restart/relogin is not evidence of automatic refresh.
- Live externally owned VPN attachment, if that deployment mode is wanted.
  The accepted deployment uses direct egress; no VPN was silently started.
- Container rollback remains documented rather than live-rehearsed. Keep the
  old engine, configuration, CA and token available during normal-use validation.
- Known native/OS findings remain documented testing-preview risks. Re-audit
  dependencies and coordinate acceptance before each subsequent upgrade.
- Retain the selected Apache-2.0 licence, scan each exact release history and obtain
  explicit publication approval for new releases. Source-only publication does not clear images
  for redistribution; see the separate licensing gates.

Personal-machine migration is separate, not a prerequisite.
