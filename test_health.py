import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import addon


class HealthTests(unittest.TestCase):
    def test_health_has_no_credential_resolution_and_only_nonce_status(self):
        flow = SimpleNamespace(request=SimpleNamespace(host=addon.SENTINEL_HOST, path='/health', method='GET'), response=None)
        with patch.dict(os.environ, {'SECRET_PROXY_INSTANCE_ID': 'a' * 32}), patch.object(addon, '_current_manifest', side_effect=AssertionError('No vault/manifest access')):
            self.assertTrue(addon._health_route(flow))
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(json.loads(flow.response.content), {'status': 'ready', 'instance': 'a' * 32})

    def test_missing_nonce_or_wrong_method_is_not_ready(self):
        for method, nonce in [('POST', 'a' * 32), ('GET', 'bad')]:
            flow = SimpleNamespace(request=SimpleNamespace(host=addon.SENTINEL_HOST, path='/health', method=method), response=None)
            with patch.dict(os.environ, {'SECRET_PROXY_INSTANCE_ID': nonce}):
                self.assertTrue(addon._health_route(flow))
            self.assertEqual(flow.response.status_code, 503)

    def test_route_does_not_match_upstream_or_query_parameters(self):
        for host, path in [('example.com', '/health'), (addon.SENTINEL_HOST, '/health?foo=bar')]:
            flow = SimpleNamespace(request=SimpleNamespace(host=host, path=path, method='GET'), response=None)
            self.assertFalse(addon._health_route(flow))
