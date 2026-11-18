import json
from pathlib import Path
import tempfile
import unittest

from awscreds import AwsCredsError, AwsCredsProvider
from migrate_aws import convert_aws, export_aws, literal_defaults


class AwsMigrationTests(unittest.TestCase):
    def fixtures(self):
        config = {'schemaVersion': 2, 'default_account': '111122223333', 'default_role': 'Reader',
                  'default_app_url': 'https://example.okta.com/home/amazon_aws/default/123',
                  **{k: k for k in ('OKTA_USERNAME', 'OKTA_PASSWORD', 'OKTA_SECRET')}}
        defaults = {'DEFAULT_ALLOWED_ROLES': ['Reader', 'Writer'],
                    'DEFAULT_ACCOUNT_APP_URLS': {'999999999999': 'https://example.okta.com/home/amazon_aws/other/123'},
                    'DEFAULT_ACCOUNT_ROLE_OVERRIDES': {'999999999999': ['Billing']}}
        return config, defaults

    def test_literal_extraction_does_not_execute_module(self):
        text = "raise AssertionError('must never execute')\nDEFAULT_ALLOWED_ROLES: list[str] = ['Reader']\nDEFAULT_ACCOUNT_APP_URLS = {}\nDEFAULT_ACCOUNT_ROLE_OVERRIDES = {}"
        self.assertEqual(literal_defaults(text)['DEFAULT_ALLOWED_ROLES'], ['Reader'])
        for bad in (text.replace("['Reader']", "make_roles()"), text + '\nDEFAULT_ALLOWED_ROLES = []', ''):
            with self.assertRaises((ValueError, SyntaxError)):
                literal_defaults(bad)

    def test_all_implicit_policy_is_explicit_and_precedence_retained(self):
        config, defaults = self.fixtures()
        config['allowed_roles'] = ['Reader']
        result = convert_aws(config, defaults, ['example.okta.com'])
        provider = AwsCredsProvider(result, lambda _: self.fail('Must never fetch a credential'))
        self.assertEqual(provider._resolve_app_url('999999999999'), defaults['DEFAULT_ACCOUNT_APP_URLS']['999999999999'])
        provider._check_role_allowed('999999999999', 'Billing')
        provider._check_role_allowed('111122223333', 'Reader')
        for account, role in [('999999999999', 'Reader'), ('111122223333', 'Billing'), ('111122223333', 'Writer')]:
            with self.assertRaises(AwsCredsError):
                provider._check_role_allowed(account, role)
        config['account_role_overrides'] = {'999999999999': ['Reader']}
        config['account_app_urls'] = {'999999999999': config['default_app_url']}
        result = convert_aws(config, defaults, ['example.okta.com'])
        self.assertEqual(result['account_role_overrides']['999999999999'], ['Reader'])
        self.assertEqual(result['account_app_urls']['999999999999'], config['default_app_url'])

    def test_refuses_values_unknown_fields_and_unapproved_hosts(self):
        config, defaults = self.fixtures()
        for change, hosts in [({'OKTA_PASSWORD': 'plaintext-not-a-reference'}, ['example.okta.com']),
                              ({'password': 'unexpected'}, ['example.okta.com']), ({}, ['different.okta.com'])]:
            with self.assertRaises((ValueError, AwsCredsError)):
                convert_aws({**config, **change}, defaults, hosts)

    def test_private_file_and_no_overwrite(self):
        config, defaults = self.fixtures()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'new/aws-okta.json'
            export_aws(config, defaults, ['example.okta.com'], path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text())['allowed_roles'], ['Reader', 'Writer'])
            with self.assertRaises(FileExistsError):
                export_aws(config, defaults, ['example.okta.com'], path)
