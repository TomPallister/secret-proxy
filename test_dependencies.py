"""Security pins and the supported headless entrypoint (no web/console UI)."""
import hashlib
import importlib.metadata
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest


class DependencyTests(unittest.TestCase):
    def test_selected_apache_licence_is_complete_and_declared(self):
        root = Path(__file__).parent
        self.assertEqual(hashlib.sha256((root / 'LICENSE').read_bytes()).hexdigest(),
                         'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30')
        self.assertEqual(tomllib.loads((root / 'pyproject.toml').read_text())['project']['license'],
                         'Apache-2.0')

    def test_security_pins_are_explicit_in_project_and_lock(self):
        root = Path(__file__).parent
        project = tomllib.loads((root / 'pyproject.toml').read_text())
        lock = tomllib.loads((root / 'uv.lock').read_text())
        self.assertIn('mitmproxy==12.3.1', project['project']['dependencies'])
        self.assertEqual(project['tool']['uv']['override-dependencies'], ['tornado==6.6.1'])
        versions = {pkg['name']: pkg['version'] for pkg in lock['package']}
        self.assertEqual(versions['mitmproxy'], '12.3.1')
        self.assertEqual(versions['tornado'], '6.6.1')
        self.assertEqual(lock['manifest']['overrides'], [{'name': 'tornado', 'specifier': '==6.6.1'}])

    def test_installed_runtime_matches_reviewed_pair(self):
        self.assertEqual(importlib.metadata.version('mitmproxy'), '12.3.1')
        self.assertEqual(importlib.metadata.version('tornado'), '6.6.1')

    def test_headless_entrypoint_does_not_import_tornado(self):
        # This is the real installed entrypoint, not a fake DumpMaster. Running
        # --version exercises its import graph without sockets or real state.
        script = '''
import importlib.abc
import sys
class DenyTornado(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'tornado' or fullname.startswith('tornado.'):
            raise AssertionError('Headless entrypoint imported the web dependency')
sys.meta_path.insert(0, DenyTornado())
from mitmproxy.tools.main import mitmdump
mitmdump(['--version'])
'''
        result = subprocess.run([sys.executable, '-c', script], capture_output=True,
                                text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('12.3.1', result.stdout)
