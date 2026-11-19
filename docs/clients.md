# Connecting applications

Run a command through the proxy:

```sh
secret-proxy run -- your-command
```

Only that process and its children receive the proxy address, public certificate
bundle and configured placeholder variables. Other host applications are not
changed. The command does not change the OS-wide proxy or trust store.

## Start with curl

With the GitHub starter configuration:

```sh
secret-proxy run -- sh -c 'curl --fail --silent --show-error -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'
```

The inner shell expands the placeholder set by `run`. GitHub GET/HEAD requests
are allowed; write requests are deliberately not in the starter policy.

## Pi with ChatGPT/Codex

Enable the integration during setup and install with the Pi agent directory you
want to use. Then:

```sh
secret-proxy login
secret-proxy run -- /absolute/path/to/your/pi
```

Use the actual Pi executable, not a dotfiles or other wrapper that replaces
network settings. Choose an OpenAI Codex model in Pi.

Login prints a browser URL. Sign in, then paste the full localhost callback into
the hidden terminal prompt. Do not put it in chat, a shell command or Git. Long
callbacks are supported; the localhost page need not load successfully for its
URL to contain the code.

The proxy performs the OAuth exchange and keeps the real access/refresh tokens
in RAM. The client saves only sealed references in the selected Pi auth file
(mode 0600), preserving other providers. Do not run Pi's own `/login` or
`/logout` concurrently. Restarting the proxy requires `secret-proxy login`
again; your existing same-account client references can stay in place.

## Pi with GitHub Copilot

Add the Copilot entry to your manifest (see
[advanced configuration](advanced-setup.md#github-logins)) and install with the
Pi agent directory you want to use. Then, with the proxy running:

```sh
secret-proxy login github-copilot
secret-proxy run -- /absolute/path/to/your/pi
```

Login prints a GitHub URL and a short code. Open the URL, enter the code and
approve the request. The proxy polls GitHub itself, so leave the command running
until it reports that the reference was saved. Choose a GitHub Copilot model in
Pi. Do not use Pi's own `/login` for Copilot: the proxy refuses it.

What happens:

- The proxy keeps the GitHub token and the short-lived Copilot token in RAM and
  refreshes the Copilot token before it expires. Nothing is stored in the vault.
- The `github-copilot` entry in Pi's auth file (mode 0600, other providers left
  alone) holds only references. `refresh` is `secretref:GITHUB_COPILOT_SESSION_TOKEN`.
  `access` keeps the Copilot token's real `exp=` and `proxy-ep=` fields, which
  Pi uses for its API address, with a reference instead of the token's
  identifier and signature. `expires` is the real expiry minus Pi's five-minute
  margin.
- When Pi refreshes, its call to `api.github.com/copilot_internal/v2/token` is
  answered by the proxy with a new sealed value. It never reaches GitHub.
- The real Copilot token is added only for the API host named by its own
  `proxy-ep` (`proxy.` becomes `api.`), and only where the manifest allows it.

After a proxy restart the old entry stops working (the proxy answers with an
injection error) until you run `secret-proxy login github-copilot` again.
Models that GitHub requires you to enable first must be enabled in your GitHub
Copilot settings; the proxy-owned login does not change model policy.

Only Pi's Copilot provider is supported. VS Code, the Copilot CLI and other
editors use their own sign-in and are not supported through this login; if one
of them uses the same OAuth client ID as Pi, the proxy refuses its sign-in.
Copilot telemetry hosts are not intercepted: they never receive either token.

## GitHub CLI (gh)

Add the gh entry to your manifest (see
[advanced configuration](advanced-setup.md#github-logins)) and give gh a reference
in `client-environment.json`, before installation:

```json
{"GH_TOKEN": "secretref:GH_CLI_OAUTH_TOKEN"}
```

Then, with the proxy running:

```sh
secret-proxy login github
secret-proxy run -- gh api user
```

Login works like the Copilot one: open the URL, enter the code, and leave the
command running. The proxy uses the GitHub CLI's own OAuth app and scopes
(`repo`, `read:org`, `gist` unless the manifest says otherwise) and keeps the
token in RAM. gh sees only the reference, so `gh auth status` reports that
`GH_TOKEN` is in use, and `gh auth login` is refused (by gh itself, and by the
proxy for gh's OAuth app). `GH_TOKEN` and `GH_ENTERPRISE_TOKEN` in the client
configuration must be references; anything else is refused.

For Git over HTTPS, run `gh auth setup-git` once so Git asks gh for credentials.
gh then hands Git the reference with the user name `x-access-token`, and the
proxy adds the real token as the Basic password where the manifest allows it.

After a proxy restart, run `secret-proxy login github` again. The existing
vault-stored `GITHUB_TOKEN` integration is separate and unchanged.

On macOS, gh is a Go program and ignores `SSL_CERT_FILE`, so it cannot trust the
proxy certificate yet. It works in Linux containers that trust the proxy CA. On
macOS it needs the planned `secret-proxy trust-ca` command (a separate change);
do not disable TLS verification instead.

## Compatibility limits

Applications must honour the supplied proxy and CA settings. Curl and accepted
Node/Pi paths do. **Arbitrary applications are not automatically supported.**

In particular, macOS Go programs such as `gh` may not use `SSL_CERT_FILE`.
Do not disable TLS verification to make them work. They need an explicit trust
integration that is outside this quickstart.

Containers need a route to the host proxy and the public CA in their own trust
store; `secret-proxy run` does not create or secure a container network. Existing
dotfiles adapters are separate consumer implementations, not a requirement for
using this project.

Other OAuth services, AWS and Git signing also need their matching private policy
and client configuration. See [advanced configuration](advanced-setup.md).
AWS calls that return credentials or secrets, such as `secretsmanager
get-secret-value`, are refused with `AccessDeniedException` from secret-proxy;
see the [AWS operation policy](operations.md#aws-operation-policy).

## Refused destinations

Requests to metadata, loopback, link-local and (by default) private addresses
get `403` with `{"error":"secret_proxy_egress_refused","rule":"..."}`, and an
optional allow-list can refuse other hosts the same way. The rule name says
why; see [egress controls](advanced-setup.md#egress-controls).

## Low-level client interface

The daily CLI delegates to the installed client. For an explicitly registered
instance, the equivalent interface is:

```sh
python3 /opt/secret-proxy/current/client.py \
  --config /private/etc/secret-proxy/local/client.json status
```

Replace `status` with `login` or `run -- <command>` as needed.
A configuration can set `agentDir`; otherwise the client honours its explicit
agent-directory option or Pi's environment/default. A configured directory takes
precedence over `PI_CODING_AGENT_DIR`.

`status` checks authenticated TLS and the current boot nonce. It does not fetch
a secret or prove every configured API works. Test the particular read-only
request you intend to use.
