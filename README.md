# secret-proxy

**Let tools use your API keys without giving them the keys.**

Your app sends a credential reference. The proxy reads the real value from
1Password and adds it on the way to the allowed API. The app never needs the token.

```text
Your app → reference → secret-proxy → real credential → allowed API
```

Works with host applications and containers, including AI coding agents.

## Get started

The supported installer is for **Apple silicon macOS**, using Podman and
**1Password with service-account support**. This is a personal-development
and early testing release, not a production service.

**[Follow the setup guide →](docs/setup.md)**

1. Create a small 1Password vault and a read-only service account.
2. Run `./setup.sh init` to generate configuration, then `./setup.sh install`.
3. Run `secret-proxy start` and try the read-only GitHub example.

Setup asks for **names, not tokens**. It does not start anything automatically
or replace an existing installation.

## Everyday use

```sh
secret-proxy start                 # terminal 1: direct; keep attached
secret-proxy status                # terminal 2: authenticated readiness
secret-proxy run -- your-command
secret-proxy login chatgpt         # optional: first Codex login or recovery
secret-proxy auth-status chatgpt
secret-proxy stop                  # deliberate stop, not closing a terminal
```

`login`, `auth-status` and `logout` require a provider: `chatgpt`,
`github-copilot` or `github`. For ChatGPT/Codex, paste the browser callback only
into the hidden terminal prompt. GitHub logins use a device code. Pi receives
sealed records; gh receives a reference in `GH_TOKEN`, never the real token.
Each integration must be enabled in your policy. API reads, GraphQL and Git
clone/push require their own placements; login does not grant them automatically.

By default, proxy-owned logins are memory-only and need login after restart.
The optional [login vault](docs/advanced-setup.md#login-store) is **separate and
read/write**; the secrets vault stays read-only. It holds ChatGPT's rotating
refresh token and the GitHub tokens for Copilot/gh, not short-lived access/session
tokens. First use (including `auth-status`) can restore a saved login.

`secret-proxy logout github` clears that proxy login and deletes its saved item,
if configured; it does not revoke upstream access. Check reported save/delete
failures before stopping; see [stored logins](docs/operations.md#stored-logins).
The proxy is foreground, not a background service; use `stop` explicitly.

VPN is opt-in on **each start**: `secret-proxy start --network office-vpn` selects
an installed [network profile](docs/networks.md). Plain `start` is direct, never
remembers a VPN, and refuses to switch a running instance silently.

macOS Go tools such as gh ignore `SSL_CERT_FILE`. With a name-constrained CA
(the setup default), `secret-proxy trust-ca` adds it to your login keychain;
`secret-proxy untrust-ca` undoes that. Review the permitted DNS subtrees first:
wildcard rules can broaden constraints beyond individual request placements.
See [client compatibility](docs/clients.md); never disable TLS verification.

## Features and policy

| Feature | Configuration and limits |
| --- | --- |
| API-key injection | Headers, queries, forms, Basic auth and URL rewrites; exact placement rules |
| Proxy-owned OAuth | Supported derived-token services, ChatGPT/Codex, GitHub Copilot and gh |
| Login persistence | Optional separate [read/write login vault](docs/advanced-setup.md#login-store) |
| AWS signing and filtering | Okta/SAML; [aws-policy.json](docs/operations.md#aws-operation-policy) starter blocks secret reads and client-side credential/token minting |
| GitHub API guard | [Normal repo writes, no administration](docs/github-policy.md); parsed GraphQL, unknown writes refused |
| Git signing | Commit/tag signatures without handing clients a private key |
| Scoped clients | Separate tokens and [grants](docs/advanced-setup.md#scoped-clients) for secrets, AWS roles, signing and logins |
| Egress checks | Metadata/private-address refusal; optional [host allow/deny lists](docs/advanced-setup.md#egress-controls) |
| Operator approvals | [Once/session decisions](docs/advanced-setup.md#approval-rules); deny without a listener or on timeout, never widen client grants |
| Audit log | Optional [hash-chained decisions](docs/advanced-setup.md#audit-log), retention and signed seals with a configured key; active tail remains unsigned until sealed |
| macOS CA trust | Explicit trust/untrust for the name-constrained CA, not unrestricted host trust |

The starter enables read-only GitHub and optional ChatGPT/Codex, not every
integration. Configuration changes require deliberate installation/restart;
editing a source manifest is not deployment. No automatic lifecycle changes.

## Security boundaries

A client can still **use the access you grant it**. The AWS and GitHub guards
reduce dangerous API paths; other APIs may still return credentials. This is not
a malicious-software sandbox, and the audit log is not a complete traffic log.

The Mac installer uses a separate non-admin account and VM. Root/admin access
and private policy remain trusted. Applications must honour proxy/trust settings;
not every application does. Read [SECURITY.md](SECURITY.md) and the known
[dependency issues](docs/dependency-audit.md) before deciding whether it fits.

## Guides

- [Setup and first request](docs/setup.md)
- [Connecting Pi and other applications](docs/clients.md)
- [Daily operations, upgrades and recovery](docs/operations.md)
- [Custom policy, migration and VPN configuration](docs/advanced-setup.md)
- [Development and tests](docs/development.md)

## Licence

[Apache-2.0](LICENSE) for first-party source. Releases are source-only;
[third-party licences](docs/licensing-review.md) still apply to built images.
