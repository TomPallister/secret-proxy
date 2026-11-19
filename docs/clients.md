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
