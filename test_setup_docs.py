"""Keep the quickstart small, linked, and consistent with the first-install helper."""
import base64
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).parent


class SetupDocsTests(unittest.TestCase):
    def test_readme_is_a_short_entrypoint_not_an_acceptance_log(self):
        text = (ROOT / 'README.md').read_text()
        self.assertLessEqual(len(text.splitlines()), 110)
        for unwanted in ('Remaining acceptance gates', 'refresh acceptance',
                         'candidate-aws', 'cutover checks', 'compaction'):
            self.assertNotIn(unwanted, text)
        self.assertIn('docs/setup.md', text)
        self.assertIn('1Password', text)
        self.assertIn('secret-proxy stop', text)

    def test_local_links_in_onboarding_docs_resolve(self):
        for name in ('README.md', 'docs/setup.md', 'docs/operations.md',
                     'docs/clients.md', 'docs/advanced-setup.md', 'docs/development.md'):
            path = ROOT / name
            for link in re.findall(r'\]\(([^)]+)\)', path.read_text()):
                if '://' in link or link.startswith('#'):
                    continue
                self.assertTrue((path.parent / link.split('#')[0]).exists(), (name, link))

    def test_setup_guide_separates_tokens_from_metadata_and_covers_no_takeover(self):
        text = (ROOT / 'docs/setup.md').read_text()
        for required in ('./setup.sh init', './setup.sh install', 'read_items',
                         'destination_vault', 'account_url', 'password',
                         'GET and HEAD', 'not a replacement', 'existing installations',
                         'secret-proxy run -- sh -c', 'public', 'signature'):
            self.assertIn(required, text)
        self.assertIn('secret-proxy start', text)
        self.assertIn('secret-proxy login', text)

    def test_release_signer_is_public_and_not_in_the_runtime_image(self):
        lines = (ROOT / 'release-signers').read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r'^release namespaces="git" ssh-ed25519 [A-Za-z0-9+/=]+$')
        self.assertNotIn('PRIVATE KEY', lines[0])
        key = base64.b64decode(lines[0].split()[-1], validate=True)
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
        self.assertIn(fingerprint, (ROOT / 'docs/setup.md').read_text())
        for line in (ROOT / 'Dockerfile').read_text().splitlines():
            if line.startswith('COPY '):
                self.assertNotIn('setup', line)
                self.assertNotIn('release-signers', line)


if __name__ == '__main__':
    unittest.main()
