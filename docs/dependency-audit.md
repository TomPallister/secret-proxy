# Dependency remediation and remaining release gate

Checked 2026-11-18. These are version/advisory matches, not counts of independently
demonstrated exploits. No live proxy was upgraded or restarted. The release
candidate is tested locally; earlier live acceptance used the previous build.

## Python runtime: remediated

The old mitmproxy 11.1.3 lock had 45 advisory records across 13 packages. The new
lock uses **mitmproxy 12.3.1**, updated transitive dependencies and an explicit
**Tornado 6.6.1 compatibility override**. `pip-audit==2.9.0` reports **zero known
advisories** for the exported runtime graph. This is a point-in-time check, not a
guarantee of absence of vulnerabilities.

Upstream mitmproxy caps Tornado at 6.5.10. That version still matches
GHSA-pcg2-g6cj-q92c, GHSA-r4j5-9xpp-3985, GHSA-pw9p-v7r6-gx4p and
GHSA-5cjw-f85j-cv6r; the last fix requires 6.6.1. The override is declared in
`pyproject.toml` and `uv.lock`, not hidden in an install command. Only the headless
`mitmdump` entrypoint is supported; a regression test rejects any Tornado import
by that entrypoint. Remove the override when upstream admits the patched release.

Compatibility evidence:

- Project unit/provider/signing suites, plus installed-version and lock assertions.
- 422 upstream mitmproxy 12.3.1 tests covering web, CLI, htpasswd, HTTP networking
  and HTTP proxy layers with Tornado 6.6.1. Two ldap3/pyasn1 deprecation warnings.
- Disposable non-root/read-only container, host TLS/readiness and VPN-loss smokes.
- `tests/smoke_wire.py`: real TLS, HTTP/1 and negotiated HTTP/2 through the actual
  addon, header/query/form/Basic injection, refusal before contacting upstream,
  and generated-key signing. Only the provider CLI runner is synthetic. It runs
  with networking disabled and never accesses a real vault or vendor.
- A synthetic-clock regression covers two consecutive OAuth expiries, rotating
  refresh tokens and continued use of the original sealed reference. This is
  **not** proof of natural expiry against the live OAuth provider.

## Image: available official updates applied, residuals not waived

The candidate also updates the multi-architecture Python base digest, applies
available Debian package updates, moves the checksum-pinned 1Password CLI from
2.39.0 to **2.42.0**, and removes download/extraction tools and unused base-image
pip from the final filesystem. Both CLI architecture archives were fetched from
the official vendor endpoint and hashed; executable/image smokes ran on ARM64.

`Trivy 0.76.2` scanned an exported candidate image, including embedded Go build
metadata. Counts below include repeated advisory matches across related Debian
binary packages, not just unique CVEs:

| Component | Earlier image | Updated candidate |
| --- | ---: | ---: |
| Debian packages | 590 | 324 (103 high, 116 medium, 89 low, 16 unknown) |
| Python packages | 1 base-pip finding | 0 |
| 1Password CLI | 67 | 4 (1 high, 2 medium, 1 unknown) |
| Official saml2aws 2.36.19 binary | 123 | 123 (1 critical, 51 high, 65 medium, 4 low, 2 unknown) |

No fixed Debian package versions were available for the remaining 324 matches in
that report. The four 1Password matches concern embedded `x/crypto`, `x/net` and
Go standard-library versions; 2.42.0 was the latest official CLI checked.
Upstream `saml2aws` still publishes 2.36.19, built with Go 1.22.5 and older
libraries. Installing a newer Go toolchain elsewhere does not fix a downloaded
statically linked binary.

**These remaining matches are not suppressed or accepted automatically.** A
licence choice or a clean Python audit does not close the broader release gate.
Review applicability and obtain specific risk acceptance, wait for vendor fixes,
or separately approve and maintain a tested replacement/rebuild before treating
this candidate as cleared for publication or deployment.

### Separate saml2aws rebuild experiment — not selected

A private disposable experiment rebuilt the same upstream source commit with Go
1.27.4 and updated modules. Its final binary scan found zero known advisories
across 43 detected packages. This additionally required mapping the v3 go-jose
module to patched v4.1.6 for its JSON subpackage; it is **not an official upstream
binary or a drop-in vendor-supported update**.

The supported headless/core/Okta and replacement JSON test selection passed
199 cases/subtests across 13 packages without external networking. An attempted
full upstream suite did **not** pass: browser tests require downloaded drivers,
a DNS-error expectation differs offline, and modern vet rejects a legacy
Shibboleth format call. No complete upstream-suite or real Okta acceptance is
claimed. Adopting this experiment would add a maintained third-party compatibility
build; it has deliberately not replaced the official binary in the Dockerfile.

## Reproduce and preserve evidence

```sh
uv export --locked --no-dev --no-emit-project --format requirements-txt \
  > /private/audit/runtime-requirements.txt
uv tool run --from pip-audit==2.9.0 pip-audit --no-deps --disable-pip \
  -r /private/audit/runtime-requirements.txt --format json \
  --output /private/audit/runtime-vulnerabilities.json
```

For an image audit, export the exact local image and run pinned Trivy with
`image --input image.tar --scanners vuln --format json`. Record the image ID,
scanner/database versions, full results and build inputs outside the public tree.
Binary-only investigation needs `trivy rootfs`, not a default `trivy fs` scan;
require a detected `gobinary` result and inspected package inventory. An empty
result from the wrong scanning mode is not a clean audit.

Package auditing sends public names/versions to advisory services, not source or
private configuration. Scanning still does not establish every code path's
reachability or cover every embedded native component. No image is approved for
redistribution; the separate proprietary and copyleft licence gates remain.
