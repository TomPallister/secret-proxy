#!/bin/sh
# Source-only first-time setup. Never starts the proxy or reads a vault.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
PYTHON=/Library/Developer/CommandLineTools/usr/bin/python3
[ -x "$PYTHON" ] || { printf '%s\n' 'Install Apple Command Line Tools first: xcode-select --install' >&2; exit 1; }
exec "$PYTHON" "$ROOT/setup.py" "$@"
