#!/usr/bin/env bash
# Operator-run rehearsal only. Does not replace the live proxy or install trust.
set -euo pipefail
usage() {
	printf 'Usage: %s PRIVATE_CONFIG_DIR ISOLATED_PI_AGENT_DIR\n' "$0"
}
if [ "${1:-}" = --help ]; then usage; exit 0; fi
[ "$#" -eq 2 ] || { usage >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || { echo 'This rehearsal helper is macOS-only.' >&2; exit 2; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PRIVATE=$(CDPATH= cd -- "$1" && pwd -P)
case "$2" in
	/*) AGENT_DIR=$2 ;;
	*) echo 'Use an absolute, isolated Pi agent directory.' >&2; exit 2 ;;
esac
cd "$ROOT"
[ -z "$(git -c core.fsmonitor=false status --porcelain --untracked-files=all)" ] \
	|| { echo 'Commit the source changes before running it as secagent.' >&2; exit 1; }
REV=$(git rev-parse HEAD)
git verify-commit "$REV"
OP=$(command -v op)
case "$OP" in /*) ;; *) echo 'op must resolve to an absolute executable.' >&2; exit 2 ;; esac
PYTHON=/Library/Developer/CommandLineTools/usr/bin/python3
printf '%s\n' 'Installing isolated candidate on port 10260; the legacy deployment is left alone.'
printf '%s\n' 'This reuses the configured vault binding. It does not provision or narrow vault access.'
/usr/bin/sudo "$PYTHON" "$ROOT/macos_install.py" \
	--repo "$ROOT" --commit "$REV" --config "$PRIVATE" \
	--instance candidate --machine secagent --port 10260 --agent-dir "$AGENT_DIR"
exec "$PYTHON" /opt/secret-proxy/current/host.py up candidate \
	--bootstrap "$PRIVATE/bootstrap.json" --op "$OP"
