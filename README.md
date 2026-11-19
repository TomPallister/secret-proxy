# secret-proxy

**Let tools use your API keys without giving them the keys.**

Your app sends a placeholder such as `secretref:GITHUB_TOKEN`. The proxy reads
the real value from 1Password and adds it to the request on its way to GitHub.
The app never needs the stored token.

```text
Your app → placeholder → secret-proxy → real credential → allowed API
```

Useful for AI coding agents and development tools. It works with host applications
as well as containers; you do not need a containerised development environment.

## Get started

The supported installer is for **Apple silicon macOS**, using Podman and
**1Password with service-account support**. This is a personal-development
tool and an early testing release, not a production service.

**[Follow the setup guide →](docs/setup.md)**

The first-time setup has three parts:

1. Create a small 1Password vault and a read-only service account.
2. Run `./setup.sh init` to generate configuration, then `./setup.sh install`.
3. Run `secret-proxy start` and try the read-only GitHub example.

Setup asks for **names, not tokens**. Real credentials stay in 1Password.
It does not start anything automatically or replace an existing installation.

## Everyday use

```sh
# Terminal 1 — keep this open
secret-proxy start

# Terminal 2
secret-proxy status
secret-proxy run -- your-command

# When finished
secret-proxy stop
```

For **ChatGPT/Codex in Pi**, run `secret-proxy login` after starting the proxy.
Follow the browser instructions and paste the callback into the terminal's
hidden prompt. You must log in again after a restart: those OAuth tokens are
kept in memory, not saved to disk. Other integrations do not require this login.

The proxy does not run as a background service. Use `stop` explicitly rather
than assuming that closing its terminal stopped it.

## What it supports

- API keys in headers, query parameters, forms and HTTP Basic authentication.
- Proxy-managed OAuth for supported services, including ChatGPT/Codex.
- AWS request signing using Okta/SAML credentials. Calls that return
  credentials or secrets (`GetSecretValue`, `AssumeRole`, `CreateAccessKey`…)
  are refused by default; see the [AWS operation policy](docs/operations.md#aws-operation-policy).
- Git commit/tag signing without handing the client a private key.

Each integration needs an explicit policy defining **where** its credential may
be used. The starter setup includes read-only GitHub and optional ChatGPT/Codex;
it does not enable every integration automatically.

## What it does not promise

A client can still **use the access you grant it**. This protects proxy-held
credentials; apart from the AWS deny list, it does not prevent allowed APIs from
returning or creating other credentials. It is not a sandbox for arbitrary malicious software.

The Mac installer puts the proxy in a separate non-admin account and VM.
Root/admin access and your private policy remain trusted. Applications must
honour the proxy and certificate settings; not every application does.

Known dependency issues remain documented for this testing release.
Read [security boundaries](SECURITY.md) and [dependency notes](docs/dependency-audit.md)
before deciding whether it fits your needs.

## More detail

- [Setup and first request](docs/setup.md)
- [Connecting Pi and other applications](docs/clients.md)
- [Daily operations, upgrades and recovery](docs/operations.md)
- [Custom policy, migration and VPN configuration](docs/advanced-setup.md)
- [Development and tests](docs/development.md)

## Licence

[Apache-2.0](LICENSE) for this project's source. Third-party tools retain their
own licences. Releases are source-only; see [third-party licensing](docs/licensing-review.md)
before redistributing built images.
