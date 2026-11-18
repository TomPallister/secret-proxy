# Standalone secret-proxy

- Work in isolated Git worktrees. Conventional, signed commits; never bypass signing.
- No private manifests, tenant IDs, credentials, real user identities or corporate certificates in this repository or its image layers.
- 1Password only. Client processes receive references, never stored/derived OAuth credentials.
- Use `uv run --locked`; do not install with pip. Run `./test.sh` before committing.
- No GitHub Actions. Do not publish until the operator approves a reviewed, scanned release.
- Do not restart the live proxy, replace CAs/tokens, or alter vaults without coordinating with the operator.
- One direct-egress macOS deployment has passed operator-approved host Pi and dev-container cutover checks. Passing tests does not authorize another deployment, restart, VPN change, rollback retirement or publication.
- Publication uses a clean, source-only history prepared separately from local operational history. Never push all refs, mirror a development repository, or publish an unreviewed bundle.
