# GitHub API operation guard

A manifest placement grants permission to use a credential, not to administer a
GitHub account. The built-in guard checks requests using **any** proxy-injected
reference on `api.github.com`, `uploads.github.com` and GitHub's web/Git host.
For ordinary references it runs before token resolution (including proxy-owned
gh login restoration), approval prompts and forwarding. URL-rewrite secrets must
first be resolved to learn the destination; that destination is then checked
before forwarding. It cannot be bypassed by a broad
placement or an approval. Requests without an injected reference are not guarded.

## Allowed work

Reads (`GET`, `HEAD`, `OPTIONS`, plus parsed GraphQL queries) and enumerated
development writes and the narrow management exceptions below work **without new prompts**:

- Issues, PRs, comments, reviews, labels, milestones and reactions.
- PR merge/update-branch, Git objects and refs, file contents.
- Releases and release assets (REST), checks/statuses, deployments and workflow
  dispatch/rerun/cancel APIs.
- Known GraphQL development mutations, including `createPullRequest`,
  `addComment`, `mergePullRequest`, `createCommitOnBranch` and ref updates.
- Git smart-HTTP fetch/push on `github.com`, governed by the existing placements.
- Repository creation (personal/organisation/template), forking and archiving.
- Repository/organisation webhook creation and Actions-variable management.
- Team reads, including listing teams, members and repository access; no team writes.

This does not grant a placement, client permission or upstream GitHub scope.
Read-only placements stay read-only. Repository/branch restrictions still belong
to placements, scoped clients and GitHub protection rules. It does not gate Git
pushes or approve changes to executable code, hooks or CI files within a repo.

## Management exceptions

These are explicit operation exceptions, not broad account/repository administration:

| Action | Allowed API |
| --- | --- |
| Create a repository | POST `/user/repos`, `/orgs/{org}/repos` or `/repos/{owner}/{template}/generate`; GraphQL `createRepository` / `cloneTemplateRepository` |
| Fork a repository | POST `/repos/{owner}/{repo}/forks` |
| Archive a repository | PATCH `/repos/{owner}/{repo}` with **only** JSON `{"archived":true}`; GraphQL `archiveRepository` |
| Create a webhook | POST `/repos/{owner}/{repo}/hooks` or `/orgs/{org}/hooks` |
| Manage repository/organisation Actions variables | POST the `/actions/variables` collection; PATCH/DELETE `/actions/variables/{name}` |
| Manage environment variables | POST `/repos/{owner}/{repo}/environments/{environment}/variables`; PATCH/DELETE its `/{name}` item. The legacy `/repositories/{id}/environments/...` shape is also permitted. |
| Assign an organisation variable to repositories | PUT its `/repositories` collection, or PUT/DELETE `/repositories/{id}` under `/orgs/{org}/actions/variables/{name}` |

Reads were already permitted. All three variable scopes are supported; variables
are non-secret configuration, **not** GitHub Actions secrets. Environment creation,
protection rules and runner registration/removal remain refused. Existing path
validation still applies (including refusing encoded slashes in environment names).

Archiving does not permit unarchiving, renaming, changing visibility or other
settings on an existing repository. The REST archive body must be bounded,
uncompressed JSON with one boolean `archived: true` field: extra/duplicate fields,
query parameters and type coercions are refused. `updateRepository` and
`unarchiveRepository` remain blocked. New-repository creation accepts GitHub's
creation options; it does not grant management rights over existing repositories.
Webhook editing/deletion/redelivery remains refused; only creation was requested.

GitHub permissions are still required: organisation-variable management and
organisation hooks can need broader token scopes than the starter gh login.
This guard change does not add scopes, change a token or trigger a new login.

## Refused work

Writes outside that explicit list get HTTP 403 with
`{"error":"secret_proxy_github_denied","reason":"<fixed code>"}`. This includes:

- Account SSH/GPG/signing keys, profile/security settings and OAuth/token APIs.
- Repository settings other than the archive-only action, deletion/transfer,
  collaborators, deploy keys, webhook editing/deletion, secrets, runners,
  environment creation/protection, branch protection and rulesets.
- Organisation/team/enterprise administration outside the named exceptions above.
- Gist writes. Perform these deliberately outside the untrusted client's access.
- Unknown REST writes and unknown GraphQL mutation names, including future APIs.

The allowlists are in `githubguard.py`. A new legitimate write requires a reviewed
source change and tests; there is no request-side override or automatic fallback.
Interactive/time-window grants are not implemented by this guard.

## GraphQL and transport

Only POST JSON documents are supported at the GraphQL endpoint. A pinned GraphQL
parser reads the syntax tree; aliases use the actual field name, root fragments
are expanded, cycles/missing fragments are refused, and **all** operations in the
document are checked. Directives such as `@skip` never waive a denial. Query text
inside strings/comments cannot change the classification.

Malformed/duplicate-key JSON, batches, persisted queries/extensions, compressed
bodies, ambiguous operation selection and unparseable documents fail closed.
Inspection is bounded to 2 MiB, 10,000 parser tokens and bounded selection/fragment
traversal. This is a parser bound, not a general ingress-memory/DoS guarantee:
the proxy already buffers ordinary request bodies before inspection.

Authority, not a spoofable HTTP/1 Host header, selects the guard. Ambiguous paths
(encoded separators/dot segments, nested encoding, controls), method-override
headers and query parameters are refused. Streaming metadata injection uses the
same guard; GraphQL cannot be forwarded without an inspectable body.

For configured `githubLogins` domains, `/api/v3` and `/api/graphql`, plus the
corresponding `api.<domain>` / `uploads.<domain>` hosts, are guarded too. A custom
PAT-only enterprise domain **without** a configured GitHub login domain is not
automatically recognised; keep its placements narrow. Normal non-GitHub APIs are
unaffected. URL-rewrite destinations are checked after resolution, before forwarding.

## Limits and deployment

Allowed reads can return private content; allowed writes can exfiltrate it or
publish malicious code, and workflow dispatches may run privileged CI. Creating
repos/forks can copy or publish code, webhooks can send repo/org events to the
supplied URL, and variable edits can alter workflow behaviour. These are deliberate
capabilities, not claims of exfiltration prevention. The guard
is not a complete GitHub authorisation system and cannot stop misuse within
allowed operations. Use least-privilege GitHub tokens and branch/environment
protection. It does not claim that every allowed response is credential-free.

Denials use fixed reason codes. Enabled audit logging records an injection refusal
with `github-api-denied`, never the GraphQL query, variables or returned token.

Installing this code enables the guard; no new manifest key is required. Existing
placements cannot turn it off. Source edits alone do not deploy it: build/install
and restart only with the operator's coordination, preserving policy, trust,
capabilities and stored logins. AWS denials are a **separate private policy change**;
see [AWS operation policy](operations.md#aws-operation-policy).
