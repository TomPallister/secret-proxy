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
