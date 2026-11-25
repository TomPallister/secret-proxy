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
      "totpSecret": "VPN_TOTP_SEED",
      "totpMode": "append"
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
SHA-1 TOTP is appended to the password for XAUTH by default (`totpMode: "append"`).
For gateways that first accept the password and then request a separate code,
select `totpMode: "challenge"`. This uses a fixed helper that answers **one**
Password/Passcode/Answer prompt matching the configured username and pinned peer,
within 90 seconds. Unknown, expired or repeated challenges fail closed. The seed
exists only in the gateway's private tmpfs until consumed or startup ends; it is
never an argument, environment variable or log entry. No arbitrary helper command
or other challenge-response/MFA flow is supported.

Values must be nonempty printable ASCII without newlines; there are no secret-value
arguments or shell interpolation. Without TOTP, the password is sent as stored.
Login is automated and bounded, with stdin closed. Challenge mode omits vpnc's
`--non-inter` (which prevents its helper from answering a second XAUTH challenge),
not our timeout, one-shot limit or closed stdin. There is no automatic reconnect
or repeated MFA loop. The client uses `Local Port 0` (an ephemeral source port),
not a fixed local UDP500/4500 bind. Peer destination ports remain IKE500/NAT-T4500.
This matters behind container/VM NAT; it does not broaden the packet filter.

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

## Diagnosing a failed start

Managed startup reports only a fixed stage code, for example
`Managed VPN failed readiness (stage: vault); no direct fallback`.
Raw provider/client output, prompts, usernames, host addresses, credentials and
exception messages are not forwarded. The stage describes the last operation,
not necessarily its underlying cause:

- `launch`, `profile`, `bootstrap`: engine/image launch, installed configuration,
  or capability-bundle intake.
- `vault`, `peer-resolution`, `firewall`, `configuration`: selected credential
  lookup, peer/interface discovery, kill-switch installation, or private client
  configuration.
- `negotiating`, `client-exited`, `startup-timeout`: the VPN client started but
  never completed readiness. These codes alone do not prove incorrect credentials.
- `client-peer-no-response`: the client exhausted its peer-response retries;
  this does not distinguish a dropped packet from a silently refusing gateway.
- `client-auth-rejected`, `client-group-auth-failed`: the client reported XAUTH
  rejection or failed group-authentication hash verification. Neither identifies
  which stored value or server policy needs changing; do not guess or loop logins.
- `client-bind-failed`, `client-tunnel-open-failed`, `client-send-failed`,
  `client-socket-failed`: a local socket, tunnel or packet operation failed.
- `client-helper-failed`, `client-interactive-required`: the client could not
  obtain a challenge answer or required interactive handling.
- `client-negotiation-rejected`, `client-weak-algorithm`: the client rejected
  protocol negotiation or an offered weak algorithm. No algorithm downgrade or
  peer/firewall expansion is performed automatically.
- `challenge-refused`: the one-shot helper rejected a prompt, identity, deadline
  or repeated invocation. Do not retry authentication in a loop.
- `route-script-failed`, `full-tunnel-required`, `hook-rejected`: the distro hook
  failed, full-tunnel routes were absent, or the event/interface/connection identity
  was missing or invalid. The proxy does not force routes or relax these checks.

Only recognised fatal stderr lines from the packaged client are translated into
these fixed codes. Input is processed in bounded chunks/lines in the trusted
gateway and discarded, never printed, written to a log, or passed to the host.
Debug output remains disabled and client stdout is discarded. Unknown or
oversized diagnostics still yield `client-exited`. A pipe continues draining
after readiness to prevent output backpressure from blocking disconnect.
A rejected hook/helper takes precedence over a client error. Diagnostics never
authorise readiness, retries, a policy change or weaker transport.

The packaged client calls `pre-init` before it defines `TUNDEV`; this event alone
may omit it. Connect/disconnect events still require exactly `tun0`. Every hook
also requires the explicit positive `VPNPID` supplied by the controlling gateway
runtime. This stable identity names the distro script's saved route files across
fresh Python hook processes; it avoids its `ps`/parent-process fallback entirely.
Missing or invalid identity fails closed rather than guessing a different file.
A failed hook withdraws readiness and its first failure is retained through cleanup.
The controller, rather than Podman's auto-removal, removes the exact owned
container ID, so a fast startup failure cannot race away its final status.
Status frames cannot establish readiness or authorize traffic.

Inspect the stage and installed profile before a coordinated retry. If restoring
direct service is desired, explicitly stop and then use plain `start`; it is
never an automatic recovery action. Old versions' generic readiness errors do
not contain enough evidence to identify which stage failed.

## Verification scope

Unit/mutation tests cover strict configuration, selection, ownership, startup
failure and cleanup. Disposable real-engine tests use synthetic `op`/`vpnc`
executables to exercise the production controller, standard route hook, kernel
firewall, namespace, TLS relay, tunnel loss and a later direct start preserving
endpoint/trust/capability. Separate packet tests prove direct IPv4, IPv6,
established TCP and restored-route traffic are blocked, with positive controls.
Off-tunnel UDP DNS is also blocked, with a permitted tunnel-path control.
`tests/smoke_vpnc_binary.py` additionally runs the packaged VPN binary under
`--network=none`, with synthetic credentials and a local unanswered peer. It
observes an actual ephemeral-source IKE packet while local UDP500 is occupied,
using the production config without port overrides. It also checks real pre-init,
TUN creation, classified bind/no-response errors and unexpected-helper refusal.

`tests/smoke_vpnc_routes.py` runs the actual packaged route script through fresh
production hook processes: pre-init, connect, reconnect and disconnect, twice.
A real TUN and synthetic routes live only in a no-network container. It verifies
one stable backup file, original-default restoration, backup cleanup and unchanged
DNS/kill-switch rules. It does not run IKE authentication. Its `--mutation
unstable-pid` variant must fail restoration; the binary smoke's `--mutation
fixed-port` must fail negotiation with local UDP500 occupied.

Neither these tests nor the synthetic lifecycle tests prove a real gateway login,
MFA policy, company DNS or API access.
