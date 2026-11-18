"""Opt-in live Pi acceptance: streaming, manual compaction, post-compaction use.

Uses an ephemeral agent directory containing only validated sealed auth. No
plugins/tools/context discovery, saved sessions, or live Pi settings changes.
Costs three small model calls. Never prints auth, response bodies or diagnostics.
"""
import argparse
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from client import ProxyClient, private_read, validate_credential


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--node', required=True)
    parser.add_argument('--pi-cli', required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--confirm-live', required=True, action='store_true')
    args = parser.parse_args()
    config = json.loads(private_read(args.config, 65536))
    source = Path(config['agentDir']) / 'auth.json'
    original = private_read(source, 2 * 1024 * 1024)
    auth = validate_credential(json.loads(original)['openai-codex'])
    with tempfile.TemporaryDirectory(prefix='sp-pi-acceptance-') as temporary:
        root = Path(temporary)
        target = root / 'auth.json'
        target.write_text(json.dumps({'openai-codex': auth}))
        target.chmod(0o600)
        (root / 'settings.json').write_text(json.dumps({'compaction': {
            'enabled': False, 'keepRecentTokens': 0, 'reserveTokens': 2048}}))
        client = ProxyClient({**config, 'agentDir': str(root)})
        client.check_ready()
        command = [args.node, args.pi_cli, '--mode', 'rpc', '--no-session',
                   '--provider', 'openai-codex', '--model', args.model, '--thinking', 'minimal',
                   '-ne', '-ns', '-np', '-nc', '-nt', '--no-themes',
                   '--system-prompt', 'You are a connectivity-test assistant. Follow the prompt exactly.']
        child = subprocess.Popen(command, cwd=root, env=client.env, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        records = queue.Queue()
        def drain():
            try:
                for line in child.stdout:
                    records.put(json.loads(line))
            except Exception:
                records.put({'type': 'reader_error'})
            finally:
                records.put({'type': 'eof'})
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        deadline = time.monotonic() + 180
        def send(kind, **fields):
            child.stdin.write(json.dumps({'id': kind, 'type': kind, **fields}).encode() + b'\n')
            child.stdin.flush()
        def wait(kind, identifier=None):
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Pi acceptance timed out')
                item = records.get(timeout=max(.01, deadline - time.monotonic()))
                assert item.get('type') not in ('eof', 'reader_error'), 'Pi terminated unexpectedly'
                if item.get('type') == 'response':
                    assert item.get('success'), 'Pi rejected an acceptance command (details suppressed)'
                if item.get('type') == 'message_end' and item.get('message', {}).get('role') == 'assistant':
                    assert item['message'].get('stopReason') not in ('error', 'aborted'), 'Provider call failed (details suppressed)'
                if item.get('type') == kind and (identifier is None or item.get('id') == identifier):
                    return item
        try:
            send('set_auto_retry', enabled=False)
            wait('response', 'set_auto_retry')
            send('prompt', message='Remember the acceptance marker ORBIT_BLUE_42. Reply with ACK only.')
            wait('agent_settled')
            send('compact', customInstructions='Preserve the exact acceptance marker. Keep the summary short.')
            result = wait('response', 'compact')['data']
            assert 'ORBIT_BLUE_42' in result['summary'], 'Compaction lost the marker'
            assert result.get('usage', {}).get('totalTokens', 0) > 0, 'No model compaction usage recorded'
            send('prompt', message='Reply only with the acceptance marker from the earlier conversation.')
            wait('agent_settled')
            send('get_last_assistant_text')
            assert wait('response', 'get_last_assistant_text')['data']['text'].strip() == 'ORBIT_BLUE_42'
            validate_credential(json.loads(private_read(target, 2 * 1024 * 1024))['openai-codex'])
            assert private_read(source, 2 * 1024 * 1024) == original, 'Source auth changed'
            print('PASS: live Pi prompt, model-backed compaction and post-compaction recall; auth stays sealed; original auth/settings untouched')
        finally:
            child.stdin.close()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            reader.join(5)


if __name__ == '__main__':
    main()
