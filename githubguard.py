"""Operation guard for requests using a proxy-injected GitHub credential.

Independent of secret names and placements: a placement grants use of a token,
not permission to administer an account. Reads and enumerated development writes
are permitted; unknown writes fail closed. This is NOT repository/branch
protection, a permissions system, or a guarantee that allowed responses contain
no sensitive data. It does not apply to credentials pasted into clients.

GraphQL is parsed as a document, never searched for mutation-looking text.
No caller-supplied text is returned in a denial reason. Python 3.9 compatible.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, unquote_to_bytes

from graphql import GraphQLError, parse
from graphql.language import ast

BODY_LIMIT = 2 * 1024 * 1024
TOKEN_LIMIT = 10000
DEPTH_LIMIT = 64

# Known developer writes only. No catch-all /repos/* or mutation-name patterns:
# new GitHub administration APIs must not silently acquire permission.
_REPO = r"/repos/[^/]+/[^/]+"
_ID = r"[0-9]+"
_REST_WRITES = (
    ("POST", r"/issues"),
    ("PATCH", rf"/issues/{_ID}"),
    ("POST", rf"/issues/{_ID}/comments"),
    ("PATCH|DELETE", rf"/issues/comments/{_ID}"),
    ("POST|DELETE", rf"/issues/{_ID}/assignees"),
    ("POST|PUT|DELETE", rf"/issues/{_ID}/labels(?:/[^/]+)?"),
    ("PUT|DELETE", rf"/issues/{_ID}/lock"),
    ("POST", r"/labels|/milestones"),
    ("PATCH|DELETE", r"/labels/[^/]+|/milestones/[0-9]+"),
    ("POST", r"/pulls"),
    ("PATCH", rf"/pulls/{_ID}"),
    ("PUT", rf"/pulls/{_ID}/(?:merge|update-branch)"),
    ("POST|DELETE", rf"/pulls/{_ID}/requested_reviewers"),
    ("POST", rf"/pulls/{_ID}/(?:reviews|comments)|/pulls/{_ID}/comments/{_ID}/replies"),
    ("POST", rf"/pulls/{_ID}/reviews/{_ID}/events"),
    ("PUT", rf"/pulls/{_ID}/reviews/{_ID}(?:/dismissals)?"),
    ("DELETE", rf"/pulls/{_ID}/reviews/{_ID}"),
    ("PATCH|DELETE", rf"/pulls/comments/{_ID}"),
    ("POST", r"/commits/[^/]+/comments"),
    ("PATCH|DELETE", rf"/comments/{_ID}"),
    ("POST|DELETE", rf"/(?:issues/{_ID}|issues/comments/{_ID}|pulls/comments/{_ID}|comments/{_ID}|releases/{_ID})/reactions(?:/{_ID})?"),
    ("PUT|DELETE", r"/contents/.+"),
    ("POST", r"/git/(?:blobs|trees|commits|tags|refs)"),
    ("PATCH|DELETE", r"/git/refs/.+"),
    ("POST", r"/merges|/merge-upstream"),
    ("POST", r"/branches/[^/]+/rename"),
    ("POST", r"/releases"),
    ("PATCH|DELETE", rf"/releases/{_ID}|/releases/assets/{_ID}"),
    ("POST", r"/releases/generate-notes"),
    ("POST", r"/check-runs|/check-suites|/statuses/[^/]+|/deployments|/dispatches"),
    ("PATCH", rf"/check-runs/{_ID}"),
    ("POST", rf"/check-runs/{_ID}/rerequest|/check-suites/{_ID}/rerequest|/deployments/{_ID}/statuses"),
    ("DELETE", rf"/deployments/{_ID}"),
    ("POST", r"/actions/workflows/[^/]+/dispatches"),
    ("POST", rf"/actions/runs/{_ID}/(?:rerun|rerun-failed-jobs|cancel|force-cancel)|/actions/jobs/{_ID}/rerun"),
    ("DELETE", rf"/actions/artifacts/{_ID}|/actions/runs/{_ID}(?:/logs)?"),
)
_REST_WRITES = tuple((set(methods.split("|")), re.compile(_REPO + "(?:" + path + ")\\Z"))
                     for methods, path in _REST_WRITES)

_MUTATIONS = frozenset("""
addComment updateIssueComment deleteIssueComment
createIssue updateIssue closeIssue reopenIssue deleteIssue
addAssigneesToAssignable removeAssigneesFromAssignable
addLabelsToLabelable removeLabelsFromLabelable clearLabelsFromLabelable
createLabel updateLabel deleteLabel createMilestone updateMilestone deleteMilestone
createPullRequest updatePullRequest closePullRequest reopenPullRequest
markPullRequestReadyForReview convertPullRequestToDraft mergePullRequest
updatePullRequestBranch enablePullRequestAutoMerge disablePullRequestAutoMerge
addPullRequestReview updatePullRequestReview submitPullRequestReview deletePullRequestReview dismissPullRequestReview
addPullRequestReviewComment updatePullRequestReviewComment deletePullRequestReviewComment
addPullRequestReviewThread resolveReviewThread unresolveReviewThread requestReviews
addReaction removeReaction lockLockable unlockLockable
createCommitOnBranch createRef updateRef updateRefs deleteRef mergeBranch
createDiscussion updateDiscussion deleteDiscussion addDiscussionComment updateDiscussionComment deleteDiscussionComment
markDiscussionCommentAsAnswer unmarkDiscussionCommentAsAnswer
""".split())


def _path(raw):
    path, _, query = raw.partition("?")
    if not path.startswith("/") or re.search(r"%(?![0-9a-fA-F]{2})", path):
        raise ValueError()
    segments = path[1:].split("/")
    if segments and segments[-1] == "":
        segments.pop()
    decoded = []
    for part in segments:
        part = unquote_to_bytes(part).decode("utf-8")
        if (not part or part in (".", "..") or any(c in part for c in "/\\%?#")
                or any(ord(c) < 32 or ord(c) == 127 for c in part)):
            raise ValueError()
        decoded.append(part)
    # Method override is not part of the supported GitHub API contract.
    if any(key.lower() in ("_method", "x-http-method-override")
           for key, _ in parse_qsl(query, errors="strict")):
        raise ValueError()
    return "/" + "/".join(decoded), query


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError()
        out[key] = value
    return out


def _graphql(method, query_string, headers, body):
    if method != "POST" or query_string:
        return "graphql-transport"
    types = [v.split(";", 1)[0].strip().lower() for k, v in headers if k.lower() == "content-type"]
    encodings = [v for k, v in headers if k.lower() == "content-encoding"]
    if types != ["application/json"] or encodings not in ([], ["identity"]):
        return "graphql-transport"
    if body is None or len(body) > BODY_LIMIT:
        return "graphql-body-limit"
    try:
        data = json.loads(body.decode("utf-8"), object_pairs_hook=_unique)
        if (not isinstance(data, dict) or not isinstance(data.get("query"), str)
                or set(data) - {"query", "variables", "operationName"}
                or data.get("variables") is not None and not isinstance(data["variables"], dict)):
            return "graphql-document"
        document = parse(data["query"], max_tokens=TOKEN_LIMIT, no_location=True)
        operations, fragments, names = [], {}, set()
        for definition in document.definitions:
            if isinstance(definition, ast.OperationDefinitionNode):
                name = definition.name.value if definition.name else ""
                if name in names:
                    return "graphql-document"
                names.add(name)
                operations.append(definition)
            elif isinstance(definition, ast.FragmentDefinitionNode):
                name = definition.name.value
                if name in fragments:
                    return "graphql-document"
                fragments[name] = definition
            else:
                return "graphql-document"
        selected = data.get("operationName")
        if (not operations or (selected is not None and (not isinstance(selected, str) or selected not in names))
                or len(operations) > 1 and (not selected or "" in names)):
            return "graphql-document"

        # Bound the ENTIRE tree, including nested selections, before walking
        # fragments. Check all operations, not only the selected one. Directives
        # never waive a denial, even when @skip would currently avoid execution.
        budget = TOKEN_LIMIT
        def fields(selection, visiting=frozenset(), depth=0):
            nonlocal budget
            if depth > DEPTH_LIMIT:
                raise ValueError()
            result = []
            for node in selection.selections:
                budget -= 1
                if budget < 0:
                    raise ValueError()
                if isinstance(node, ast.FieldNode):
                    result.append(node.name.value)  # alias is deliberately ignored
                    if node.selection_set:
                        fields(node.selection_set, visiting, depth + 1)
                elif isinstance(node, ast.InlineFragmentNode):
                    result.extend(fields(node.selection_set, visiting, depth + 1))
                elif isinstance(node, ast.FragmentSpreadNode):
                    name = node.name.value
                    if name in visiting or name not in fragments:
                        raise ValueError()
                    result.extend(fields(fragments[name].selection_set, visiting | {name}, depth + 1))
                else:
                    raise ValueError()
            return result

        for operation in operations:
            roots = fields(operation.selection_set)
            if operation.operation.value == "mutation":
                if any(field not in _MUTATIONS for field in roots):
                    return "graphql-mutation-not-allowed"
            elif operation.operation.value != "query":
                return "graphql-operation-not-allowed"
    except (ValueError, UnicodeError, GraphQLError, RecursionError):
        return "graphql-document"
    return None


def check(*, method, host, path, headers=(), body=None, enterprise_domains=()):
    """Return a fixed denial reason, or None. Called BEFORE resolving a token.

    GitHub.com API/upload hosts always guarded. A configured GitHub Enterprise
    login domain gets /api/v3 and /api/graphql protection; token-bearing web
    writes are refused too. Git smart HTTP transport remains placement-gated.
    Custom PAT-only enterprise domains require a configured GitHub login domain.
    """
    host = host.lower().rstrip(".")
    api_hosts = {"api.github.com"} | {"api." + domain for domain in enterprise_domains}
    upload_hosts = {"uploads.github.com"} | {"uploads." + domain for domain in enterprise_domains}
    enterprise = host in enterprise_domains and host != "github.com"
    if host not in api_hosts | upload_hosts | {"github.com"} and not enterprise:
        return None
    if any(k.lower() in ("x-http-method-override", "x-method-override", "x-http-method") for k, _ in headers):
        return "method-override"
    try:
        path, query = _path(path)
    except (ValueError, UnicodeError):
        return "ambiguous-path"
    method = method.upper()
    if enterprise:
        if path == "/api/graphql":
            path = "/graphql"
        elif path == "/api/v3" or path.startswith("/api/v3/"):
            path = path[len("/api/v3"):] or "/"
        else:
            enterprise = False  # Git/web endpoint, not REST
    api = host in api_hosts or enterprise
    if api and path == "/graphql":
        return _graphql(method, query, headers, body)
    if method in ("GET", "HEAD", "OPTIONS"):
        return None
    if host in upload_hosts:
        if method == "POST" and re.fullmatch(_REPO + r"/releases/[0-9]+/assets", path):
            return None
    elif api:
        if any(method in methods and pattern.fullmatch(path) for methods, pattern in _REST_WRITES):
            return None
    elif method == "POST" and re.fullmatch(r"/[^/]+/[^/]+/(?:git-upload-pack|git-receive-pack)", path):
        return None
    return "write-not-allowed"
