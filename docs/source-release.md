# Source-only release procedure

Nothing in this procedure authorises a deployment, service restart, vault change
or publication. Obtain explicit operator approval before creating/pushing a
public repository or release. A first-party licence must be chosen first.

## Publication boundary

Publish only reviewed source, tests, examples, documentation and dependency/build
recipes. Do not publish images, downloaded tools, wheel caches, virtual
environments, private policy, CA certificates, capability files or auth state.
Build recipes do not imply permission to redistribute their downloaded binaries.
See [the dependency licensing review](licensing-review.md).

Operational development history is not a publication artifact. A fixture can
retain private metadata even when it is not a working credential. Prepare a
separate clean publication history containing only the sanitised tree. Retain
operational commit IDs privately while installed releases or restart helpers
still depend on them; do not rewrite those dependencies during a source review.

Never use `git push --all` or `--mirror` from the operational repository. Review a
fresh clone of the exact publication bundle/ref and push only that clone's
approved branch. Its complete reachable history must pass the same checks as
its current tree. Git author and signing metadata remain part of the artifact
and must also be reviewed; do not confuse a public signature with a secret key.

## Local gates

1. Review every tracked path and all reachable blobs/commit messages. Check for
   private domains, account IDs, item UUIDs, personal paths and configuration.
   Keep any organisation-specific search terms and scan reports **outside** the
   public tree; a private-name denylist would itself leak those names.
2. Run an independent secret scanner with network verification disabled. For
   example, use pinned `detect-secrets==1.5.0` with `scan --no-verify` from the
   directory being scanned. Include a temporary, unregistered token-shaped
   positive control and require detection; do not assume empty output proves
   that the intended directory was scanned. Remove the control before packaging.
3. Review every result. Record exact finding hashes and reasons privately; do not
   blanket-exclude all tests. Published AWS example credentials, signatures,
   download checksums, canonical reference names, format markers and deliberately
   fake test inputs can be legitimate findings, but new results need review.
4. Run `./test.sh`, fatal Python lint and compilation from the exact candidate.
   Mutation-test the boundary assertions. The default unit suites use fixtures;
   live smoke scripts require separate operator coordination.
5. Build a source archive/bundle from committed content, enumerate its members,
   clone it into a fresh directory, verify the commit signature and rerun gates.
   Record the commit/tree ID and archive digest in the external release ledger.
6. Add the chosen licence and any required attribution. Rescan and reverify the
   final commit after that change; approval of an earlier tree is not approval
   of a different artifact. Publish no image attachments.

## Source provenance and fixture attribution

The engine and adapters were extracted/refactored from the operator-maintained
predecessor. Its private configuration and history are not part of the public
source artifact. Third-party packages are installed from the lockfile and
pinned tool downloads, not vendored into the source tree. Source-header and
history inspection alone cannot establish ownership of every line; the licence
choice remains the operator's decision, not legal clearance by this document.

- `sigv4.py` implements the documented AWS signing protocol; `test_sigv4.py`
  uses published S3 chunk-signature **example data**, not live credentials:
  [AWS S3 streaming signature calculations](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html).
- `test_resign.py` imports installed botocore to independently compare results;
  it does not vendor botocore implementation files.
- `gitsign.py` implements the SSHSIG format using installed cryptography:
  [OpenSSH PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig).
  Tests generate their own keys; a literal private-key header used by a format
  validator is not a bundled private key.
- UUID-rejection fixtures use only the explicit synthetic value
  `00000000-0000-4000-8000-000000000000`. Never paste an actual vault item ID into
  a test just because that test is supposed to reject it.

These protocol references attribute the examples/specifications; they are not
licence grants for separately redistributed libraries or executables. Required
image notices, corresponding source and proprietary redistribution permission
remain separate from a source-only release.
