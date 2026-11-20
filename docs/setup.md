# Set up secret-proxy on a Mac

This guide gets you from a fresh installation to one read-only GitHub request.
It does not require dotfiles, Pi, Docker Desktop or a development container.
Allow time for the first image build and keep a terminal available for prompts.

Already running secret-proxy? **Do not use the first-install helper.** Use the
[operations guide](operations.md). Setup refuses existing installations rather
than guessing what it may replace.

## 1. Install the prerequisites

- An **Apple silicon Mac** supported by Podman's libkrun provider.
- Apple's Command Line Tools: `xcode-select --install`.
- The official **Podman macOS installer**, including krunkit. The installer needs
  root-owned tools under `/opt/podman/bin`; a user-owned Homebrew Podman binary
  is not a substitute. See [Podman installation](https://podman.io/docs/installation).
- **1Password desktop and CLI**, with desktop app integration enabled for the CLI.
  You should be able to approve an `op` request through the desktop app.
- A 1Password account that lets you create a **read-only service account**.
  If your organisation disables this feature, resolve that first; do not use a
  broader account or work around its policy. See
  [1Password service accounts](https://developer.1password.com/docs/service-accounts/).

No global HTTP proxy or system-wide certificate installation is needed.

## 2. Get the code and generate your configuration

```sh
git clone https://github.com/TomPallister/secret-proxy.git
cd secret-proxy
./setup.sh init
```

Review the code before installing it. The helper asks for your account hostname,
two vault names and a Login item title. Defaults are:

| Name | Purpose |
| --- | --- |
| `DevEnv` vault | Only credentials that the proxy may use |
| `Private` vault | Holds the service-account token; the proxy cannot read this vault |
| `Secret Proxy Bootstrap` Login item | Stores that token for desktop-approved startup |

Choose the read-only GitHub example for the first test. ChatGPT/Codex is optional.
Keep the default **name-constrained CA** unless you have a reason not to: it lets
`secret-proxy trust-ca` make macOS Go tools such as `gh` work later.
**Do not enter credentials into these prompts.** They only ask for names.

The helper creates three or four private files, without reading 1Password:

```text
~/.config/secret-proxy/
  config/
    manifest.json            # which credentials may go to which requests
    bootstrap.json           # where desktop startup finds its service-account token
    client-environment.json  # placeholders for client programs, not real secrets
    ca.json                  # optional: name-constrained proxy CA
    aws-policy.json          # which AWS calls are refused (used only with AWS signing)
```

Nothing is installed or started. Files are mode 0600; directories are 0700.
An existing directory is never overwritten. To prepare an isolated configuration,
use `./setup.sh init --directory /absolute/path/to/new-settings` and pass the same
`--directory` to install. Keep it outside this repository.

## 3. Prepare 1Password

Use the names you entered above. These steps are manual so you can review the
permissions before allowing the proxy to use anything.

1. Create the **DevEnv** vault.
2. For the GitHub example, create a GitHub token with only the repository/account
   read access you want. In DevEnv, create a **Login** item titled exactly
   **`GITHUB_TOKEN`**, with the token in its **password** field. Use a unique title.
3. Create a **service account** with **Read Items** access to **DevEnv only**.
   It needs no write permissions and no access to Private or other vaults.
4. In **Private**, create a **Login** item titled **Secret Proxy Bootstrap**:
   - **password:** the service-account token from step 3;
   - add a text field **`account_url`**: your bare account hostname, e.g. `example.1password.com`;
   - add a text field **`destination_vault`**: `DevEnv`;
   - add a text field **`permissions`**: `read_items`.

Those three text fields let startup check that it found the intended item. They
are not a replacement for checking the actual service-account permissions in
1Password. Never put the token into a JSON file, command argument or shell profile.

If you enabled only ChatGPT/Codex, omit the GitHub item. ChatGPT credentials come
from browser login; do not create a `CHATGPT_ACCESS_TOKEN` vault item.

**On a corporate TLS-inspection network:** before installation, place the approved
public CA certificate in `config/upstream-ca.pem`, mode 0600. Use a PEM certificate
bundle from your organisation, not a private key. It is supplied externally to
builds and the running proxy, not embedded in the image.

## 4. Install

```sh
./setup.sh install
```

For ChatGPT/Codex in Pi, choose the directory that contains your Pi configuration:

```sh
./setup.sh install --agent-dir "$HOME/.pi/agent"
```

Use one command or the other, **not both**. The helper:

- verifies the clean source commit against the included release signing key;
- asks for sudo to install immutable code and a separate non-admin `secagent` account;
- registers instance `local` on host loopback port `10260`;
- creates private CLI metadata at `~/.config/secret-proxy/cli.json`;
- links the installed, version-pinned CLI at `~/.local/bin/secret-proxy`.

It does **not** start a service, fetch a credential, replace an existing command,
configure a system proxy, or install a global CA. Its `config/` directory remains
policy-only; CLI metadata lives alongside it, not inside it.

If `secret-proxy` is not on PATH, use `~/.local/bin/secret-proxy` below, or add
`$HOME/.local/bin` to your shell's PATH. With a custom settings directory, pass
`secret-proxy --config /absolute/path/to/new-settings/cli.json ...` each time.

### Source verification

The included `release-signers` file contains the project's **public** SSH signing
key. Its fingerprint is `SHA256:HgPiKNUiD0aSy1y/QHptxXGA8oM+iv05iw1XZlMkZAY`.
Obtain code from the project repository and review the release/commit you intend
to install. A key downloaded alongside code is not an independent proof of its
origin. Setup uses a command-scoped Git setting and does not change your Git config.

Dirty checkouts, unsigned commits or signatures from another key are refused.
For your own fork, establish and review your own signing policy; do not disable
verification to make an error disappear.

## 5. Start and make your first request

Terminal 1:

```sh
secret-proxy start
```

The first run creates the separate proxy VM and builds its image. Sudo and
1Password approval may prompt. Wait for readiness and **keep the terminal open**.

Terminal 2:

```sh
secret-proxy status
secret-proxy run -- sh -c 'curl --fail --silent --show-error -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'
```

You should get your GitHub user JSON. The shell receives a placeholder in
`GITHUB_TOKEN`; the proxy inserts the real token only on the upstream request.
The starter policy allows **GET and HEAD to api.github.com only**. It does not
allow pushes, repository writes or Git-over-HTTPS. Add only the policies you need
later; see [custom configuration](advanced-setup.md).

`status` proves the proxy is reachable and authenticated. The GitHub request is
the separate check that the configured credential and upstream connection work.

## Optional: ChatGPT/Codex in Pi

Install Pi separately and enable ChatGPT/Codex during `init`. Then:

```sh
secret-proxy login chatgpt
secret-proxy run -- /absolute/path/to/your/pi
```

Use the real Pi executable, not a wrapper that replaces proxy settings. Choose
an OpenAI Codex model in Pi. Login prints a browser URL; after sign-in, paste the
full localhost callback into the **hidden terminal prompt**, never into chat.
The client saves a sealed reference in Pi's `openai-codex` auth entry, not the
real access/refresh tokens. Other provider entries are preserved. Avoid running
Pi `/login` or `/logout` at the same time.

After every proxy restart, run `secret-proxy login chatgpt` again. GitHub and other
vault-backed services do not need this browser login.

## If something goes wrong

| Symptom | Next step |
| --- | --- |
| `Existing installation ... found` | Setup deliberately will not take over. Use the operations guide; don't delete `/opt/secret-proxy` to bypass the check. |
| Source signature failure | Use a clean, reviewed signed commit and check `release-signers`; do not bypass verification. |
| Startup fails to read the bootstrap item | Check the exact title, Login/password field, three text fields and desktop CLI integration. |
| Vault lookup fails | Check item title, runtime vault and service-account read permission. |
| GitHub returns 401/403 | Check the token's validity, scopes and organisation approval. The proxy cannot grant access your token lacks. |
| TLS issuer error | Check your organisation's CA bundle; do not disable certificate verification. |
| ChatGPT stops working after restart | Run `secret-proxy login chatgpt` again. |
| CLI/link setup fails after sudo | Installation may have partially completed. Keep the files and inspect them using the advanced guide; the first-install helper will not overwrite them on retry. |

Use `secret-proxy stop` explicitly when finished. It retains the CA, configuration
and saved client references. More detail: [operations](operations.md) and
[client compatibility](clients.md).
