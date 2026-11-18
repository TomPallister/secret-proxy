#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
uv run --locked python -m unittest discover
uv run --locked python test_googlecreds.py
uv run --locked python test_sigv4.py
uv run --locked python test_resign.py
