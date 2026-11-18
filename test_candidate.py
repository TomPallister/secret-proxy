import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'macOS operator helper')
class CandidateTests(unittest.TestCase):
    def test_help_needs_no_privileges(self):
        result = subprocess.run(['bash', str(Path(__file__).parent / 'candidate.sh'), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('ISOLATED_PI_AGENT_DIR', result.stdout)

    def test_dirty_or_unsigned_source_stops_before_sudo(self):
        script = Path(__file__).parent / 'candidate.sh'
        for mode in ('dirty', 'unsigned'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                git = root / 'git'
                git.write_text('#!/bin/bash\ncase "$*" in\n*status*) ' +
                               ('echo dirty' if mode == 'dirty' else ':') +
                               ';;\n*rev-parse*) printf "%040d\\n" 0;;\n*verify-commit*) exit 1;;\nesac\n')
                git.chmod(0o755)
                result = subprocess.run(['bash', str(script), str(root), str(root / 'isolated-agent')],
                                        env={**os.environ, 'PATH': str(root) + ':/usr/bin:/bin'},
                                        capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Installing isolated candidate', result.stdout)
