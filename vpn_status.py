"""Fixed startup-stage protocol. Never transport provider text or credentials."""
STAGES = frozenset(('launch', 'profile', 'bootstrap', 'vault', 'peer-resolution',
                    'firewall', 'configuration', 'negotiating', 'route-script',
                    'full-tunnel-check', 'ready', 'disconnected', 'hook-rejected',
                    'route-script-failed', 'full-tunnel-required', 'challenge-refused',
                    'client-exited', 'startup-timeout', 'client-peer-no-response',
                    'client-auth-rejected', 'client-group-auth-failed', 'client-bind-failed',
                    'client-tunnel-open-failed', 'client-send-failed', 'client-socket-failed',
                    'client-helper-failed', 'client-interactive-required',
                    'client-negotiation-rejected', 'client-weak-algorithm'))
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


class ClientErrors:
    """Translate known vpnc stderr into enums; never forward or persist text.

    Unknown, incomplete and overlong lines are discarded. The first recognised
    fatal error wins. This is diagnostic evidence only, never a readiness signal.
    vpnc debug output remains disabled and its stdout remains /dev/null.
    """
    EXACT = {
        b'no response from target': 'client-peer-no-response',
        b'authentication unsuccessful': 'client-auth-rejected',
        b'unable to get password': 'client-helper-failed',
        b'authentication failed (requires interactive mode)': 'client-interactive-required',
    }
    STARTS = (
        (b'hash comparison failed: ', 'client-group-auth-failed'),
        (b'Error binding to source port.', 'client-bind-failed'),
        (b"can't initialise tunnel interface: ", 'client-tunnel-open-failed'),
        (b"can't send packet: ", 'client-send-failed'),
        (b'making socket: ', 'client-socket-failed'),
        (b'receiving packet: ', 'client-socket-failed'),
        (b"can't poll socket: ", 'client-socket-failed'),
        (b'connecting to port ', 'client-socket-failed'),
        (b'response was invalid [', 'client-negotiation-rejected'),
        (b'configuration response rejected: ', 'client-negotiation-rejected'),
        (b'xauth SET message rejected: ', 'client-negotiation-rejected'),
        (b'xauth packet unsupported: ', 'client-negotiation-rejected'),
        (b'quick mode response rejected', 'client-negotiation-rejected'),
    )

    def __init__(self):
        self.stage = 'client-exited'
        self.pending = bytearray()
        self.discarding = False

    def line(self, data):
        for prefix in (b'/usr/sbin/vpnc: ', b'vpnc: '):
            if data.startswith(prefix):
                message = data[len(prefix):]
                code = self.EXACT.get(message)
                for stem, candidate in self.STARTS:
                    if message.startswith(stem):
                        code = candidate
                        break
                if message.startswith(b'Peer has selected ') and message.endswith(
                        (b' as encryption method.', b' as authentication method.')):
                    code = 'client-weak-algorithm'
                if code:
                    self.stage = code
                return

    def feed(self, data):
        for byte in data:
            if self.stage != 'client-exited':
                return  # Retain only the fixed code, not later private output.
            if byte == 10:
                if not self.discarding:
                    self.line(bytes(self.pending))
                self.pending.clear()
                self.discarding = False
            elif not self.discarding:
                if len(self.pending) == 512:
                    self.pending.clear()
                    self.discarding = True
                else:
                    self.pending.append(byte)


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
