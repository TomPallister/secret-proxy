# Explicit network selection

```sh
secret-proxy start                         # direct, on every invocation
secret-proxy start --network office-vpn    # explicitly selected installed profile
secret-proxy status                        # authenticated readiness and active network
secret-proxy stop
```

Configuration lists **available** networks. There is no default-VPN setting and
no remembered selection. A running instance on a different network is refused:
stop it, then start with the intended selection. Unknown profiles, failed VPN
login, missing readiness and tunnel loss never cause a direct-egress fallback.

The proxy instance, host loopback port, CA, client capability and optional login
store stay the same. Host/container clients keep their bindings. This routes
**proxy traffic**, not all applications on the Mac. Switching still interrupts
requests, so coordinate the stop/start with people and long-running consumers.

## Private configuration

Put `networks.json` beside the private `manifest.json`, outside this repository.
The root installer validates and copies it; editing the source file is not a
live configuration change. Names are lowercase letters, digits and hyphens,
starting with a letter (at most 32 characters). `direct` and `legacy` are reserved.
At most eight profiles are allowed. Duplicate JSON fields and unknown settings
(including a default or plaintext password) are refused.

There are two profile types:

- `vpnc`: the proxy manages its own Cisco-compatible IKEv1/IPsec XAUTH gateway.
- `external`: attach to an already running gateway; its owner manages the VPN
  and must provide a genuine packet-level kill switch.

### Managed IPsec/XAUTH

Example only: substitute your approved gateway, group, DNS and canonical secret
names. The gateway must support a **full-tunnel IPv4** connection. This is not an
AnyConnect/SAML/browser-MFA, WireGuard, arbitrary-command or split-tunnel driver.

```json
{
  "version": 1,
  "networks": {
    "office-vpn": {
      "type": "vpnc",
      "gateway": "vpn.example.org",
      "group": "Example",
      "dhGroup": "dh14",
      "dns": ["10.20.0.53"],
      "usernameSecret": "VPN_USERNAME",
      "passwordSecret": "VPN_PASSWORD",
      "groupSecret": "VPN_GROUP_SECRET",
      "totpSecret": "VPN_TOTP_SEED"
    }
  }
}
```

The three username/password/group references are required; `totpSecret` is
optional. Each names an existing manifest secret with `internalOnly: true`, a
stored `password` field and no derived/runtime-only value. The matching Login
item's password field in the selected 1Password runtime vault holds the value.
For example, this is the shape of the manifest's `secrets` entries:

```json
{
  "VPN_USERNAME": {"internalOnly": true},
  "VPN_PASSWORD": {"internalOnly": true},
  "VPN_GROUP_SECRET": {"internalOnly": true},
  "VPN_TOTP_SEED": {"internalOnly": true}
}
```

With `totpSecret`, the stored value is a base32 seed. A six-digit, 30-second
SHA-1 TOTP is appended to the password for XAUTH. Other challenge-response flows
are not supported. Values must be nonempty printable ASCII without newlines;
there are no secret-value arguments or shell interpolation. Without TOTP, the
password is sent as stored. Login is noninteractive and bounded; there is no
automatic reconnect or repeated MFA loop.

`dh14` is preferred where the server supports it. Legacy `dh2`/`dh5` are explicit
compatibility options, not a recommendation: IKEv1/XAUTH and older DH groups have
security limitations. Obtain gateway/group/DH/MFA requirements from its owner.
Do not downgrade them just to make a connection work.

DNS must be one to three explicit IPv4 servers reachable through the VPN. No
fallback resolver is used for proxy traffic. Private API destinations also need
narrow `egress.allowPrivateCidrs` in the manifest; a VPN profile **does not widen
secret placements, client grants, AWS policies or egress policy**. Existing
name-constrained CA coverage must also permit the intended API hosts.

### Externally owned gateway

```json
{
  "version": 1,
  "networks": {
    "office-vpn": {
      "type": "external",
      "container": "vpn-gateway",
      "network": "vpn-client-network",
      "interface": "tun0",
      "port": 10257,
      "readyFile": "/run/vpn/ready",
      "dns": ["127.0.0.53"]
    }
  }
}
```

The external owner starts it on the same `secagent` engine and defines readiness,
DNS and fail-closed routing. The container must provide `test` and `ip -j link`.
The controller pins its ID/address and never starts, stops, removes or changes
it. Its name cannot collide with this instance's proxy, relay or managed gateway.
The shared proxy port must be unprivileged, unused and different from 10256.

Old registrations using `network.json` remain readable, but no longer imply a
VPN on startup: explicitly use `secret-proxy start --network legacy`. Do not
combine `network.json` with `networks.json`. Migrate the old attachment into an
`external` profile during a coordinated configuration update.

## Installation and updates

For a new instance, include `networks.json` in the private source configuration
before following [advanced installation](advanced-setup.md).

For an existing instance, first install the reviewed code release using the
normal [upgrade procedure](operations.md#upgrade-without-changing-the-trust-boundary). Then
stop it and repeat the **same** `macos_install.py` invocation (same instance,
machine, port, agent directory and reviewed commit) with `--update-networks`.
This explicit option changes only the network catalog/registration. It requires
a stopped instance, successful engine inspection and the controller lock;
all other installed policy and client settings must remain byte-identical.
It never starts a service, reads a vault, changes a capability or installs a
VPN default. Ordinary installation still refuses policy differences.

If new manifest secrets, private CIDRs or CA coverage are needed, those are
separate reviewed policy changes: `--update-networks` intentionally cannot
apply them. Do not bypass an installer refusal by copying over installed
policy. Coordinate the existing installation's policy update first.

Afterward, use `start --network office-vpn` in an attached operator terminal.
The first attempt with a real gateway requires attended VPN acceptance; the
synthetic test suite is not evidence of company VPN authentication.

## Runtime boundary and failure behaviour

1. Preparation builds the exact reviewed image before consuming credentials.
2. The selected profile starts an instance-owned, labelled gateway in the
   `secagent` VM. Existing containers and foreign-labelled networks are refused.
3. The trusted gateway reads only the selected internal credential names using
   the bootstrap service account. Bootstrap vault lookup and gateway DNS happen
   before the tunnel; no client proxy is serving yet. The peer is pinned to the
   resolved IPv4 address for this connection.
4. Before launching `vpnc`, an `nftables` **inet output drop policy** permits only
   loopback, `tun0`, IKE/ESP to that peer and established proxy replies to the
   relay subnet. It does not permit arbitrary established outbound connections.
5. The distro `vpnc-script` configures the tunnel's routes. Readiness requires a
   full-tunnel IPv4 route; the proxy never forces a default route onto a split
   tunnel. Its configured DNS is used in the joined namespace.
6. The proxy joins the pinned namespace. An opaque, credential-free relay keeps
   the existing host loopback endpoint. Readiness and network metadata are
   published only after authenticated TLS reaches the correct proxy boot.
7. Tunnel loss stops the proxy and removes its relay and managed gateway.
   The firewall remains while `vpnc` restores routes: it blocks direct fallback
   immediately, independently of the secondary interface/liveness watchdogs.

The gateway uses the existing proxy image and service-account boundary, not a
new host-wide VPN. It has `NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE`, `/dev/net/tun`
and device-label exemption in its own namespace; no host network/PID namespace,
engine socket, credential volume or host home. Its filesystem is read-only with
RAM-backed temporary files. Credentials are never returned to the dev container.
The bootstrap capability is not inherited by `vpnc`; its temporary password
configuration is removed after connection. Provider/client error output is not
forwarded. The shared service account retains its existing authority; Python
memory clearing is not a secure-erasure guarantee.

Explicit stop also cleans an instance-owned gateway left by an interrupted
startup. It does not delete the owned network, other gateways, ciphertext,
policy, CA or login store. After an engine outage or failed cleanup, inspect the
instance and use explicit stop; never delete a whole machine to recover.

## Verification scope

Unit/mutation tests cover strict configuration, selection, ownership, startup
failure and cleanup. Disposable real-engine tests use synthetic `op`/`vpnc`
executables to exercise the production controller, standard route hook, kernel
firewall, namespace, TLS relay, tunnel loss and a later direct start preserving
endpoint/trust/capability. Separate packet tests prove direct IPv4, IPv6,
established TCP and restored-route traffic are blocked, with positive controls.
Off-tunnel UDP DNS is also blocked, with a permitted tunnel-path control.
These tests do not prove a real gateway login, MFA policy, company DNS or API access.
