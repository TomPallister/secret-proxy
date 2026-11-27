# Licensing review — release gate

Status: preliminary engineering inventory, not legal clearance. No prebuilt
image is cleared for redistribution. The operator selected Apache-2.0 for
first-party source on 2026-11-18; the exact text is in `LICENSE`.

## Source versus dependencies versus images

The licence of a development tool does not normally dictate the licence of its
output. Incorporated third-party source, linked/imported libraries and bundled
executables must be considered separately. A container is not one uniformly
licensed work just because it is one downloadable artifact.

The first release should be **source only**: first-party Python/shell code,
configuration examples, lockfile and a Dockerfile that the operator builds.
Do not attach binaries, wheel caches, virtual environments, private policy or
container images to that release. This reduces redistribution scope; it does
not exempt the project from provenance review or users from upstream terms.

## Findings from the pinned candidate

| Component | Observed licence | Consequence |
| --- | --- | --- |
| mitmproxy 12.3.1 | MIT | Preserve its notice when redistributing it. |
| graphql-core 3.2.12 | MIT | Pinned parser for the GitHub operation guard; retain its notice when redistributing it. |
| Most Python dependencies | MIT, BSD, Apache-2.0 or PSF | Preserve their respective notices; check bundled native-library notices too. |
| ldap3 2.9.1 | LGPL v3 | Library-specific source, notice and replacement/relinking requirements need a distribution review. |
| urwid 4.0.13 | LGPL-2.1-only | Same: do not call the whole Python dependency tree permissive. |
| certifi 2026.10.23 | MPL-2.0 | Preserve notices and applicable source availability for covered files. |
| publicsuffix2 2.20191221 | MIT and MPL-2.0 | Code and bundled list data have distinct terms. |
| saml2aws 2.36.19 | MIT at project level | Its compiled Go dependency tree still needs a binary-level review before image distribution. |
| oathtool (Debian package) | GPL-3+; package also lists LGPL-2.1+ material | Invoked as a separate program. Distributing the executable needs the relevant notices and corresponding-source compliance. |
| socat (Debian package) | GPL-2 with OpenSSL exception plus other licensed files | Separate executable; retain component-specific notices and comply with source obligations for the actual package version. |
| vpnc and vpnc-scripts (Debian packages) | GPL-2+; vpnc also contains BSD-2-clause material | Managed VPN invokes the unmodified programs as separate processes. Preserve notices and satisfy corresponding-source obligations before image redistribution. |
| nftables (Debian package) | GPL-2 with file-specific GPL-2+ and other notices | Invoked as a separate executable for the managed VPN kill switch; include its libraries and actual package notices in any image review. |
| 1Password CLI 2.42.0 | Proprietary terms | No affirmative permission to redistribute it in a public image has been established. Do not publish an image containing it without permission/clarification. |
| Python/Debian base and uv 0.8.17 | Multiple component licences | A complete image review must include base packages and native/transitive components, not just Python metadata. |

Metadata was refreshed for the dependency remediation on 2026-11-18. In
particular, cryptography 50.0.2 declares Apache-2.0 OR BSD-3-Clause and Tornado
6.6.1 declares Apache-2.0; the LGPL/MPL qualifications above still apply. The
separate experimental saml2aws source rebuild is not selected in this image.

The LGPL libraries and MPL-covered files do not by themselves require all
first-party files to be GPL/MPL. Similarly, invoking an independent GPL utility
through its ordinary CLI does not by itself make the caller GPL. This assessment
must be revisited if GPL code is copied into the engine or the programs are
combined in a materially different way.

The selected Apache-2.0 licence adds an explicit patent grant for first-party
source. It does not replace dependency licences or terms, establish third-party
ownership, clear binary redistribution, or authorise publication.

## Evidence and limits

The review inspected `pyproject.toml`, `uv.lock`, the Dockerfile, installed Python
package licence metadata and Debian copyright files in the candidate image.
It searched source headers for copied/adapted-source notices and inspected the
first-party extraction history. Metadata is a starting point, not proof of a
complete notice inventory or ownership of every line. Test vectors, any copied
snippets, compiled dependency trees and base-image content still require review.
No third-party licence text should be invented from a classifier string.

Python packages and downloaded executables are pinned, but `apt-get` resolves
against mutable Debian repositories. An inventory of today's image cannot be
claimed to describe a future rebuild. Image distribution would require a
versioned SBOM, matching notices and corresponding-source retention tied to the
**actual image digest**.

References:

- [GNU GPL FAQ: mere aggregation](https://www.gnu.org/licenses/gpl-faq.html#MereAggregation)
- [1Password terms](https://1password.com/legal/terms-of-service/) — review the applicable agreement and redistribution restrictions, rather than assuming a free download is freely redistributable.
- [saml2aws pinned licence](https://github.com/Versent/saml2aws/blob/v2.36.19/LICENSE.md)
- [mitmproxy pinned licence](https://github.com/mitmproxy/mitmproxy/blob/v12.3.1/LICENSE)
- [MPL 2.0 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)

## Before source publication

- Confirm first-party provenance and retain any required third-party attribution.
- Retain the operator-selected Apache-2.0 licence and its exact official text.
- Review the final tracked tree and all reachable history for private content.
- Verify that no generated image, downloaded binary, cache or private fixture is
  included in the publication.
- Make the source-only/no-public-images policy explicit in release instructions.

Before any later image publication, additionally resolve 1Password redistribution,
complete the executable/base-image audit, collect notices and satisfy applicable
corresponding-source and library-replacement requirements. A source URL alone is
not a blanket substitute for those obligations.
