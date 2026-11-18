"""Public-source boundaries. Only fictional/documented example identities allowed.

Private organisation denylists belong in the external pre-publication scan, not
in this repository (a denylist would itself publish those identities).
"""
from pathlib import Path
import re
import unittest


def public_text_files():
    root = Path(__file__).parent
    patterns = ('*.py', '*.md', '*.sh', 'release-signers', 'secret-proxy', 'examples/**/*.json', 'tests/**/*.py', 'docs/**/*.md')
    return sorted({path for pattern in patterns for path in root.glob(pattern)})


class BoundaryTests(unittest.TestCase):
    def test_no_non_example_aws_accounts(self):
        allowed = {'000000000000', '111122223333', '123456789012', '999999999999'}
        for path in public_text_files():
            unexpected = set(re.findall(r'(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])', path.read_text())) - allowed
            self.assertFalse(unexpected, f'{path.name}: non-example AWS account identifier')

    def test_uuid_fixtures_use_only_the_documented_example(self):
        allowed = {'00000000-0000-4000-8000-000000000000'}
        for path in public_text_files():
            values = set(re.findall(r'\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b', path.read_text(), re.I))
            self.assertFalse({value.lower() for value in values} - allowed,
                             f'{path.name}: replace UUID metadata with the documented fixture')

    def test_no_private_runtime_configuration_at_repository_root(self):
        root = Path(__file__).parent
        for name in ('manifest.json', 'aws-okta.json', 'bootstrap.json', 'client.json', 'proxy-token', 'auth.json', 'cli.json', 'corporate-ca.pem'):
            self.assertFalse((root / name).exists(), f'{name} belongs outside this repository')

    def test_image_does_not_copy_host_configuration_or_host_launchers(self):
        root = Path(__file__).parent
        dockerfile = (root / 'Dockerfile').read_text()
        copies = [line for line in dockerfile.splitlines() if line.startswith('COPY ')]
        self.assertEqual(len(copies), 2)
        for line in copies:
            self.assertNotIn(' . ', line)
            self.assertNotIn('*.py', line)
            self.assertNotIn('host.py', line)
            self.assertNotIn('client.py', line)
            self.assertNotIn('examples/', line)
        self.assertEqual((root / '.dockerignore').read_text().splitlines()[0], '*')

    def test_no_zero_width_characters_in_source(self):
        for path in public_text_files():
            self.assertNotIn(bytes.fromhex('e2808b'), path.read_bytes(), path.name)
