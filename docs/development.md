# Development and testing

## Development and verification

```sh
./test.sh
uv run --locked ruff check --isolated --select E9,F63,F7,F82 .
podman build -t localhost/secret-proxy-candidate:phase2 .
```

For inspected build networks, add
`--secret id=upstream_ca,src=/absolute/path/to/corporate-ca.pem`.
The certificate is used in a temporary bundle and removed in the same layer.
The base, Python dependencies and downloaded tools are pinned/checksummed;
Debian apt repository contents are still mutable, so this is not yet a
bit-for-bit reproducible image.

Credential-free, external-network-free runtime smoke:

```sh
podman run --rm -i --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  --entrypoint /opt/secret-proxy/.venv/bin/python \
  localhost/secret-proxy-candidate:phase2 - < tests/smoke_container.py
```

For actual TLS/H1/H2 injection and signing against a generated local upstream,
run the same network-disabled container command with `tests/smoke_wire.py` as
stdin instead. All credentials and signing keys in that test are synthetic.

Real Mac host/Podman contract test, against an explicit test connection:

```sh
uv run --locked python tests/smoke_host.py --connection devenv \
  --image localhost/secret-proxy-candidate:phase2
```

This creates/removes only new `sp-smoke-*` containers/volumes and a VM temporary
directory. It tests the actual launch flags, loopback publishing, non-root state,
TLS CONNECT, CA handoff, wrong-auth and stale-readiness rejection, and stop.
It uses synthetic capabilities and makes no vault or external API calls.

A full controller/relay smoke with an internal network, dummy tunnel interface
and fake capabilities is also available. It touches only disposable fixtures:

```sh
uv run --locked python tests/smoke_vpn.py --connection devenv \
  --image localhost/secret-proxy-candidate:integration
uv run --locked python tests/smoke_vpn.py --connection devenv \
  --image localhost/secret-proxy-candidate:integration --failure gateway
```

Optional **live, billable** Pi prompt/compaction/recall acceptance uses an already
logged-in candidate and temporary sealed-only auth/settings. It never changes the
original agent directory, enables tools/extensions or saves a session:

```sh
uv run --locked python tests/smoke_pi.py --help
```

The audit-log tests (`test_audit.py`, `test_audit_wire.py`) create throwaway
Ed25519 keys with `ssh-keygen` and verify seals with `ssh-keygen -Y verify`;
they skip those cases when `ssh-keygen` is not installed. `test_audit_wire.py`
starts a real `mitmdump`, stops it with SIGTERM and checks the signed seal.
