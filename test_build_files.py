"""The image's runtime files must agree across every list that names them."""
import re
import unittest
from pathlib import Path

import host
import macos_install

ROOT = Path(__file__).resolve().parent


def dockerfile_runtime_files():
    lines = [line for line in (ROOT / 'Dockerfile').read_text().splitlines()
             if line.startswith('COPY ') and line.rstrip().endswith('/opt/secret-proxy/')]
    assert len(lines) == 1, lines
    return set(lines[0].split()[1:-1])


def dockerignore_allowed():
    allowed = set()
    for line in (ROOT / '.dockerignore').read_text().splitlines():
        if line.startswith('!'):
            allowed.add(line[1:])
    return allowed


class BuildFileListTests(unittest.TestCase):
    def test_every_runtime_file_is_copied_allowed_staged_and_installed(self):
        runtime = dockerfile_runtime_files()
        self.assertTrue(runtime)
        for name in runtime:
            self.assertTrue((ROOT / name).is_file(), name)
        build = set(host.BUILD_FILES)
        self.assertLessEqual(runtime, dockerignore_allowed(), 'missing from .dockerignore allowlist')
        self.assertEqual(runtime, {n for n in build if n.endswith('.py')}, 'host.BUILD_FILES differs')
        self.assertLessEqual(build, set(macos_install.FILES), 'not installed by macos_install')
        self.assertLessEqual(dockerignore_allowed(), build, '.dockerignore allows unstaged files')

    def test_runtime_imports_are_shipped(self):
        runtime = dockerfile_runtime_files()
        local = {p.stem for p in ROOT.glob('*.py')}
        for name in runtime:
            source = (ROOT / name).read_text()
            for module in re.findall(r'^(?:from|import) ([A-Za-z_][A-Za-z0-9_]*)', source, re.M):
                if module in local:
                    self.assertIn(module + '.py', runtime, f'{name} imports {module}')


if __name__ == '__main__':
    unittest.main()
