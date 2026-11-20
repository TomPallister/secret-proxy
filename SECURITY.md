# Security boundaries

This is a development candidate. The tests and one accepted deployment are
engineering evidence, not a penetration test or a security certification.

## What is protected

- A separately owned proxy holds its 1Password service-account capability,
  resolved values, private signing key, and real derived tokens. Clients send
  references; the proxy's own OAuth/login routes return sealed references.
- Injection checks the configured destination and placement, including applicable
  methods, paths and field names. An internal-only value cannot be obtained by
  presenting its name to the URL-rewrite sentinel.
- AWS credentials are minted and requests re-signed inside the proxy, constrained
  by explicit account/role policy. Before minting, each request's operation is
  identified and checked against `aws-policy.json`. The starter file refuses
  Secrets Manager reads and Parameter Store responses holding a decrypted
  `SecureString`. Without the file nothing is refused, apart from a request whose
  signature's service doesn't match its host.
  Git signing returns a signature, not the key.
- Client readiness uses authenticated TLS and an exact per-boot nonce. A stale
  readiness file must not silently select an old or unauthenticated service.
- Bootstrap capabilities use bounded stdin rather than command arguments. Provider
  failures are sanitised; there is no persistent request log in the host launch
  contract unless the opt-in audit log is enabled. Browser callbacks belong in
  the hidden terminal prompt, not chat/logs.
- Optional audit log (off by default): one hash-chained JSON line per security
  decision in the proxy account's own volume (0700/0600), sealed with an SSH
  signature from an internalOnly store key at each clean stop and rotation.
  Fields pass a fixed allow-list: never secret values, headers, bodies, query
  strings or error text. A decision that grants something is refused when its
  entry cannot be written. `secret-proxy audit verify` checks the chain and
  seals against a public key you pin.
- Proxied connections to loopback, link-local, cloud-metadata, multicast and
  reserved addresses are refused, and private ranges unless explicitly allowed.
  The proxy resolves a name once, checks every address and connects only to a
  checked one, so DNS rebinding cannot redirect that connection. An optional
  host allow/deny list limits where proxied traffic may go.
- Optional scoped clients: each named client has its own proxy token (its
  proxy-auth user name is the client name) and may use only its granted
  secrets, placements, AWS accounts/roles/operations, logins and Git signing.
  Identity comes from proxy authentication only, never a request header; a
  refusal happens before any secret is resolved or AWS credential minted.
  Without a `clients` section there is one unrestricted token, as before.
- Optional approval rules hold a matching request before any secret is
  resolved, any AWS credential minted or anything forwarded. Deny rules always
  win; no listener, a timeout, the rate limit and malformed or too-early answers
  deny. A client's grants are checked first, so a request outside them is
  refused, never offered. Only the proxy account's per-boot approver
  capability (never a client token) can answer,
  through `secret-proxy approvals`; clients receive only the denial rule.
- ChatGPT access and rotating refresh tokens are memory-only. Restart requires
  browser sign-in again. Static secrets remain cached until invalidation/restart.
- GitHub Copilot: the proxy runs the device flow and the Copilot token exchange.
  The GitHub token and Copilot token are memory-only. The client's own exchange
  call is answered by the proxy with a sealed token and never forwarded. The real
  Copilot token is sent only to the API host named by its own `proxy-ep` field,
  within the manifest placement. A client-side device flow using the Copilot
  OAuth client ID, or an exchange with any other bearer, is refused.
- GitHub CLI: the proxy runs gh's device flow and keeps the OAuth token in RAM.
  gh receives only a reference in `GH_TOKEN`; the client refuses a configured
  `GH_TOKEN` that is not a reference. gh's own device flow is refused. The
  token can only be added where the manifest places `GH_CLI_OAUTH_TOKEN`.

## What is not protected

- **Use of access.** An authorised or compromised client can perform operations
  that its configured credentials and upstream account permit. This is not a
  per-human authorisation system or a general read-only API gateway.
- **Credentials returned by upstream APIs.** The starter AWS policy covers only
  Secrets Manager and Parameter Store `SecureString` values. Other AWS calls can
  return credentials or secrets and are allowed unless you add rules: for example
  STS `AssumeRole`, IAM `CreateAccessKey`, registry tokens, KMS `Decrypt`, and
  environment variables in Lambda or ECS configuration. Presigned URLs are not
  checked. A role override
  applies to any client that can select that role. Non-AWS vendor APIs that
  return or create keys are not blocked. Narrow upstream permissions and external
  policy accordingly; this is not response-data loss prevention.
- **Scoped tokens a process can read.** Scoping limits a process only if it
  cannot read another, broader token. On a single-user host every published
  token, including the unrestricted default one, is readable by that user and
  so by any process running as them. Hand a narrow token to a separate
  container, VM or user, giving it only that one file. Upstream permissions of
  the granted secrets still apply in full.
- **All host traffic.** The host client supplies command-scoped proxy variables;
  a program can ignore them. Egress checks and the optional allow-list apply only
  to traffic that goes through the proxy; they are not an egress firewall for the
  machine. A development container's no-direct-egress network is an external
  consumer control, not a property of every proxy client.
- **Data sent to allowed hosts.** An allowed or manifest host can still receive
  anything a client sends it. In `open` egress mode any public host can.
- **Root, sudo or trusted bootstrap.** Administrators can read process memory,
  change the installation or act as the proxy owner. Review source and signing-key
  trust before authorising installation. A desktop-user-owned container alone is
  not equivalent to the separate-account boundary.
- **Approval as authentication.** An approval prompt describes the request;
  it cannot show what a body will do, so approve only what you expected. Allow
  for session lets matching requests from the same client through until restart.
  Someone who can run sudo (or act as the proxy account) can answer prompts.
  The prompt shows the client name the proxy authenticated, not who started it.
- **Independent proof of vault scope.** Bootstrap checks declared item metadata;
  only provider-side configuration determines actual service-account permissions.
  Use a read-only capability scoped to the intended runtime vault.
- **Other GitHub OAuth apps.** Blocking a client's own device flow covers only
  the OAuth client IDs of the proxy-owned logins that are enabled. A client with
  network access to GitHub can still sign in with a different app.
- **Narrow CA authority by default.** Intercepting only configured hosts does not
  constrain the authority of a trusted root CA. The launcher never installs global
  trust. An opt-in `ca.json` makes the proxy CA name-constrained (critical, DNS
  names only, every IP address excluded); `trust-ca` refuses any other CA. Its
  authority still covers whole subtrees: `api.github.com` permits names below it,
  and a wildcard permits its whole fixed suffix (`*.amazonaws.com` permits all of
  `amazonaws.com`), and enabling a GitHub login permits all of its domain
  (`github.com`). Whoever can read the CA key (secagent, root) can impersonate
  those names to every application trusting it. Name constraints are enforced by
  macOS, Go, OpenSSL/LibreSSL and curl; an application with its own verifier might not.
- **A tamper-proof audit log.** The audit log is tamper evidence on the local
  machine only. Someone who can read the proxy's state and also holds the
  signing key can rewrite history consistently and sign it again, and a
  verifier that does not pin the public key independently proves nothing. After
  an unclean stop (crash, `kill -9`, VM failure) the entries since the last
  seal are unsigned. Deleting the newest files or the unsigned tail, or the
  oldest files (indistinguishable from retention), is not detected. The log
  records request metadata such as hosts, paths and client names: treat it as
  sensitive, and note that root can read or delete it.
- **An atomic VPN kill switch.** Interface/container watchdogs are secondary.
  The external VPN owner must enforce fail-closed routes; no live VPN acceptance
  is claimed merely because the disposable namespace tests pass.

## Operator guidance

Keep private manifests, upstream CA files, capability files and account metadata
outside the checkout. Do not allow a credential to be injected into an echo or
reflection endpoint. Prefer exact destinations and narrowly scoped upstream
roles. Do not interpret successful readiness as proof of every upstream login.

Only import source from a reviewed, signed commit whose signer you trust through
an independent channel. A signature proves control of a key, not code safety.
Keep rollback state until a replacement has passed normal-use checks; a test
result does not grant permission to stop an unrelated service.

Do not attach real credentials, callbacks, full private manifests or raw request
captures to public issues. Contact the maintainer privately to arrange a safe
reporting channel before sharing sensitive evidence.
