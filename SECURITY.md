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
  by explicit account/role policy. Git signing returns a signature, not the key.
- Client readiness uses authenticated TLS and an exact per-boot nonce. A stale
  readiness file must not silently select an old or unauthenticated service.
- Bootstrap capabilities use bounded stdin rather than command arguments. Provider
  failures are sanitised; there is no persistent request log in the host launch
  contract. Browser callbacks belong in the hidden terminal prompt, not chat/logs.
- ChatGPT access and rotating refresh tokens are memory-only. Restart requires
  browser sign-in again. Static secrets remain cached until invalidation/restart.

## What is not protected

- **Use of access.** An authorised or compromised client can perform operations
  that its configured credentials and upstream account permit. This is not a
  per-human authorisation system or a general read-only API gateway.
- **Credentials returned by upstream APIs.** For example, AWS credential/key
  creation or secret-reading operations can return sensitive values. AWS signing
  has an account/role guard, not an AWS-action filter. Secret/key-creating vendor
  APIs are not comprehensively blocked. Narrow upstream permissions and external
  policy accordingly; injection-only does not imply response-data loss prevention.
- **All host traffic.** The host client supplies command-scoped proxy variables;
  a program can ignore them. Selective TLS interception is not an egress firewall.
  A development container's no-direct-egress network is an external consumer
  control, not a property of every proxy client.
- **Root, sudo or trusted bootstrap.** Administrators can read process memory,
  change the installation or act as the proxy owner. Review source and signing-key
  trust before authorising installation. A desktop-user-owned container alone is
  not equivalent to the separate-account boundary.
- **Independent proof of vault scope.** Bootstrap checks declared item metadata;
  only provider-side configuration determines actual service-account permissions.
  Use a read-only capability scoped to the intended runtime vault.
- **Narrow CA authority.** Intercepting only configured hosts does not constrain
  the authority of a trusted root CA. The launcher does not install global trust.
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
