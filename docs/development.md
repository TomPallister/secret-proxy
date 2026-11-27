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

Managed VPN tests use only synthetic provider/client executables and disposable
resources on the selected engine (no company VPN or vault calls):

```sh
uv run --locked python tests/smoke_managed_vpn.py --connection devenv \
  --image localhost/secret-proxy-candidate:phase2
uv run --locked python tests/smoke_managed_vpn.py --connection devenv \
  --image localhost/secret-proxy-candidate:phase2 --failure auth
uv run --locked python tests/smoke_managed_vpn.py --connection devenv \
  --image localhost/secret-proxy-candidate:phase2 --challenge
uv run --locked python tests/smoke_vpn_firewall.py --connection devenv \
  --image localhost/secret-proxy-candidate:phase2
```

The latter uses two **internal** networks for kernel packet tests. Its
`--mutation open`, `--mutation established` and `--mutation dns` variants must
fail: they deliberately weaken
only the disposable fixture's firewall and demonstrate the negative assertions
are effective. The managed lifecycle test replaces authentication/transport with
fixtures, but executes the real controller, route script, firewall, relay and
cleanup. It is not live VPN acceptance. `tests/vpn_mutations.py` checks the unit
regressions against temporary source mutations and restores every byte.

Packaged client/config and route-script compatibility checks (no external network,
vault or real authentication):

```sh
uv run --locked python tests/smoke_vpnc_binary.py --connection devenv \
  --image localhost/secret-proxy-candidate:phase2
uv run --locked python tests/smoke_vpnc_routes.py --connection devenv \
  --image localhost/secret-proxy-candidate:phase2
```

The binary test observes ephemeral-source IKE with UDP500 occupied, without an
argv override. The route test invokes fresh production hook processes and the
actual distro script against a real TUN, checking saved-route identity and
restoration while retaining the packet kill switch. `--mutation fixed-port` on
the binary test and `--mutation unstable-pid` on the route test must fail their
specific assertions. Run the unmodified positive controls first.

Optional **live, billable** Pi prompt/compaction/recall acceptance uses an already
logged-in candidate and temporary sealed-only auth/settings. It never changes the
original agent directory, enables tools/extensions or saves a session:

```sh
uv run --locked python tests/smoke_pi.py --help
```

Credential/API guards have focused regressions and baseline-checked mutation
controls (the latter run in disposable source copies, never installed files):

```sh
uv run --locked python -m unittest test_credential_guards test_githubguard test_ghclicreds
uv run --locked python tests/credential_guard_mutations.py
```

`tests/smoke_wire.py` also sends allowed and refused GitHub REST/GraphQL requests
and AWS credential-minting requests through real TLS over HTTP/1.1 and HTTP/2,
using only a local upstream and fake provider. It verifies denied requests never
reach that upstream. No real GitHub/AWS writes are part of these tests.

The audit-log tests (`test_audit.py`, `test_audit_wire.py`) create throwaway
Ed25519 keys with `ssh-keygen` and verify seals with `ssh-keygen -Y verify`;
they skip those cases when `ssh-keygen` is not installed. `test_audit_wire.py`
starts a real `mitmdump`, stops it with SIGTERM and checks the signed seal.
