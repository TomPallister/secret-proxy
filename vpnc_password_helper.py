#!/opt/secret-proxy/.venv/bin/python
"""One-shot XAUTH TOTP helper, invoked only by vpnc inside its gateway."""
import sys
from vpnc_runtime import answer_challenge, record_hook_stage

try:
    if len(sys.argv) != 2:
        raise ValueError('Expected one VPN challenge')
    print(answer_challenge(sys.argv[1]))
except Exception:
    # Neither prompts, credentials nor provider diagnostics go to logs.
    try:
        record_hook_stage('challenge-refused')
    except OSError:
        pass
    print('VPN challenge refused', file=sys.stderr)
    sys.exit(2)
