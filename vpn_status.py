"""Fixed startup-stage protocol. Never transport provider text or credentials."""
STAGES = frozenset(('launch', 'profile', 'bootstrap', 'vault', 'peer-resolution',
                    'firewall', 'configuration', 'negotiating', 'route-script',
                    'full-tunnel-check', 'ready', 'disconnected', 'hook-rejected',
                    'route-script-failed', 'full-tunnel-required', 'challenge-refused',
                    'client-exited', 'startup-timeout'))
FAILURES = frozenset(('hook-rejected', 'route-script-failed', 'full-tunnel-required',
                      'challenge-refused'))
PREFIX = b'SP-VPN/1 '


def encode_stage(stage):
    if not isinstance(stage, str) or stage not in STAGES:
        raise ValueError('Unknown VPN startup stage')
    return PREFIX + stage.encode('ascii') + b'\n'


def publish(stage):
    # Only callers' hardcoded stage identifiers can reach this stream.
    print(encode_stage(stage).decode('ascii'), end='', flush=True)


class Progress:
    """Bounded parser: invalid/oversized lines are discarded, never displayed."""
    def __init__(self):
        self.stage = 'launch'
        self.pending = bytearray()
        self.discarding = False

    def feed(self, data):
        for byte in data:
            if byte == 10:
                if not self.discarding and self.pending.startswith(PREFIX):
                    stage = bytes(self.pending[len(PREFIX):]).decode('ascii', errors='replace')
                    if stage in STAGES:
                        self.stage = stage
                self.pending.clear()
                self.discarding = False
            elif not self.discarding:
                if len(self.pending) == 64:
                    self.pending.clear()
                    self.discarding = True
                else:
                    self.pending.append(byte)
