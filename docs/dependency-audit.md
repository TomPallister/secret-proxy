# Dependency audit — publication blocked

Checked 2026-11-18 with `pip-audit==2.9.0` against a fully resolved export of
`uv.lock`, excluding development dependencies. This checks public vulnerability
advisories for the locked Python runtime graph; it does not audit the Debian
base, downloaded executables or every reachable code path.

The existing mitmproxy 11.1.3 lock reports **45 advisory records across 13
packages**. These are version matches, not 45 independently demonstrated exploits
in this deployment. Some affected components may only be used by features that
the headless proxy does not enable. Reachability has not been established for
every advisory, so they are not silently waived.

| Locked component | Version | Advisory records |
| --- | --- | ---: |
| brotli | 1.1.0 | 2 |
| certifi | 2026.7.22 | 1 |
| cryptography | 44.0.3 | 6 |
| flask | 3.1.0 | 2 |
| h11 | 0.14.0 | 1 |
| h2 | 4.1.0 | 2 |
| mitmproxy | 11.1.3 | 2 |
| msgpack | 1.1.0 | 2 |
| pyasn1 | 0.6.4 | 4 |
| pyopenssl | 25.0.0 | 2 |
| tornado | 6.4.2 | 19 |
| urwid | 2.6.16 | 1 |
| werkzeug | 3.1.8 | 1 |

## Upgrade constraint

A separate, disposable resolution of **mitmproxy 12.3.1** reduces the report to
four Tornado advisories, but is not a clean fix. Its published metadata caps
Tornado at **6.5.10**, below the remaining fixed releases:

- GHSA-pcg2-g6cj-q92c: header-parser CPU denial of service; fixed in 6.6.
- GHSA-r4j5-9xpp-3985: small-chunk CPU/memory denial of service; fixed in 6.6.
- GHSA-pw9p-v7r6-gx4p: templated redirect handling; fixed in 6.6.
- GHSA-5cjw-f85j-cv6r: incomplete redirect fix; fixed in 6.6.1.

Do not silently force a transitive version outside the upstream compatibility
range, omit it from the report, or treat a resolver experiment as a deployed
upgrade. The next change needs either a compatible upstream release or an
explicitly documented compatibility override/fix, followed by unit tests and
isolated container/TLS/signing/provider smoke tests. Refresh the licence inventory
for the resulting versions too.

**No live service or runtime dependency was changed by this audit.** Keep this
publication gate closed until remediation or a specific, evidence-backed risk
acceptance is recorded. A licence choice alone does not close it.

## Reproduce

```sh
uv export --locked --no-dev --no-emit-project --format requirements-txt \
  > /private/audit/runtime-requirements.txt
uv tool run --from pip-audit==2.9.0 pip-audit --no-deps --disable-pip \
  -r /private/audit/runtime-requirements.txt --format json \
  --output /private/audit/runtime-vulnerabilities.json
```

The audit sends public package names/versions to the advisory service, not source
or private configuration. Preserve the full machine-readable result and its date
outside the public tree. A later clean result is a point-in-time advisory check,
not a guarantee of absence of vulnerabilities.
