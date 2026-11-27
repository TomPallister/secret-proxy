"""Mutation controls in disposable source copies, never installed/live files.

uv run --locked python tests/credential_guard_mutations.py
Every case runs its positive control first and requires an assertion failure,
not an import, syntax or infrastructure error. No vault/network/real credentials.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
AWS = "test_credential_guards.CredentialMintTests."
GH = "test_githubguard.GithubAddonTests."
CASES = [
    ("sts-mint", "awsops.py", '"AssumeRole*", "GetSessionToken"', '"UnusedOperation", "GetSessionToken"',
     AWS + "test_mints_denied_in_both_hooks_and_protocol_versions"),
    ("iam-mint", "awsops.py", '"CreateAccessKey", "CreateServiceSpecificCredential"', '"UnusedOperation", "CreateServiceSpecificCredential"',
     AWS + "test_mints_denied_in_both_hooks_and_protocol_versions"),
    ("ecr-mint", "awsops.py", '"service": "ecr", "operations": ["GetAuthorizationToken", UNKNOWN]',
     '"service": "ecr", "operations": ["UnusedOperation", UNKNOWN]', AWS + "test_mints_denied_in_both_hooks_and_protocol_versions"),
    ("cognito-unknown", "awsops.py", '"ecr-public", "cognito-identity",', '"ecr-public",',
     AWS + "test_query_get_and_ambiguous_operations_fail_closed"),
    ("presigned-bypass", "addon.py", 'if (len(credential) != 5 or credential[3] != "s3"',
     'if False and (len(credential) != 5 or credential[3] != "s3"', AWS + "test_presigned_query_cannot_bypass_mint_policy"),
    ("injection-gate", "addon.py", '    if reason is not None:\n        flow.metadata[_AUDIT_REASON] = "github-api-denied"',
     '    if False:\n        flow.metadata[_AUDIT_REASON] = "github-api-denied"', GH + "test_rest_admin_denied_for_both_http_versions_and_auth_styles"),
    ("rest-default", "githubguard.py", '    return "write-not-allowed"', '    return None',
     GH + "test_rest_admin_denied_for_both_http_versions_and_auth_styles"),
    ("graphql-default", "githubguard.py", 'if any(field not in _MUTATIONS for field in roots):', 'if False:',
     GH + "test_graphql_admin_aliases_fragments_mixed_unknown_mutations"),
    ("graphql-alias", "githubguard.py", 'result.append(node.name.value)',
     'result.append(node.alias.value if node.alias else node.name.value)', GH + "test_graphql_admin_aliases_fragments_mixed_unknown_mutations"),
    ("graphql-fragment", "githubguard.py", 'result.extend(fields(fragments[name].selection_set, visiting | {name}, depth + 1))',
     'pass', GH + "test_graphql_admin_aliases_fragments_mixed_unknown_mutations"),
    ("graphql-depth", "githubguard.py", 'DEPTH_LIMIT = 64', 'DEPTH_LIMIT = 10000', GH + "test_parser_limits_and_duplicate_definitions"),
    ("graphql-tokens", "githubguard.py", 'max_tokens=TOKEN_LIMIT', 'max_tokens=None', GH + "test_parser_limits_and_duplicate_definitions"),
    ("graphql-bytes", "githubguard.py", 'BODY_LIMIT = 2 * 1024 * 1024', 'BODY_LIMIT = 8 * 1024 * 1024',
     GH + "test_graphql_malformed_transport_denied"),
    ("method-override", "githubguard.py", 'if any(k.lower() in ("x-http-method-override", "x-method-override", "x-http-method") for k, _ in headers):',
     'if False:', GH + "test_path_and_method_ambiguity_denied"),
    ("path-traversal", "githubguard.py", 'part in (".", "..")', 'False', GH + "test_path_and_method_ambiguity_denied"),
    ("sentinel-query", "addon.py", 'path=target_path + ("?" + target.query if target.query else ""),',
     'path=target_path,', GH + "test_url_rewrite_cannot_bypass_api_guard"),
    ("archive-gate", "githubguard.py", 'return _archive_only(query, headers, body)', 'return None',
     GH + "test_archive_only_not_general_repository_settings"),
    ("archive-fields", "githubguard.py", ' and set(data) == {"archived"}', '',
     GH + "test_archive_only_not_general_repository_settings"),
    ("archive-boolean", "githubguard.py", 'data["archived"] is True', 'bool(data["archived"])',
     GH + "test_archive_only_not_general_repository_settings"),
    ("archive-query", "githubguard.py", 'if (query_string or types !=', 'if (types !=',
     GH + "test_archive_only_not_general_repository_settings"),
    ("creation-allowed", "githubguard.py", '/user/repos|', '/unused/repos|',
     GH + "test_repo_creation_forking_and_webhook_creation"),
    ("webhook-path", "githubguard.py", '(?:generate|forks|hooks)|', '(?:generate|forks|hooks)(?:/.*)?|',
     GH + "test_requested_exceptions_do_not_open_adjacent_administration"),
    ("variables-not-secrets", "githubguard.py", ')/variables"', ')/(?:variables|secrets)"',
     GH + "test_requested_exceptions_do_not_open_adjacent_administration"),
    ("variable-assignment-method", "githubguard.py", '("PUT", _ORG +', '("PUT|PATCH", _ORG +',
     GH + "test_requested_exceptions_do_not_open_adjacent_administration"),
    ("unarchive-refused", "githubguard.py", 'createRepository cloneTemplateRepository archiveRepository',
     'createRepository cloneTemplateRepository archiveRepository unarchiveRepository', GH + "test_lifecycle_graphql_and_team_reads"),
]


def main():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    for name in ("SECRET_PROXY_CONFIG_DIR", "SECRET_PROXY_SECRETS_FILE", "OP_SERVICE_ACCOUNT_TOKEN", "PYTHONPATH"):
        env.pop(name, None)
    for label, filename, before, after, test in CASES:
        with tempfile.TemporaryDirectory(prefix="sp-guard-mutation-") as temporary:
            target = Path(temporary) / "source"
            shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pi", ".ruff_cache"))
            path = target / filename
            source = path.read_text()
            assert source.count(before) == 1, (label, "mutation anchor is not unique")
            command = [sys.executable, "-m", "unittest", test]
            baseline = subprocess.run(command, cwd=target, env=env, capture_output=True, text=True, timeout=60)
            assert baseline.returncode == 0, (label, "baseline failed", baseline.stderr[-3000:])
            path.write_text(source.replace(before, after, 1))
            result = subprocess.run(command, cwd=target, env=env, capture_output=True, text=True, timeout=60)
            assert result.returncode != 0 and "AssertionError" in result.stderr and "errors=" not in result.stderr, (
                label, "survived or infrastructure error", result.stderr[-3000:])
            print("CAUGHT:", label, flush=True)
    print(f"PASS: {len(CASES)} mutations, each with a passing positive control")


if __name__ == "__main__":
    main()
