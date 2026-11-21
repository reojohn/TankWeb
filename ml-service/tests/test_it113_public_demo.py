"""Regression checks for the login-free, synthetic-only IT113 research dashboard."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]

class PublicDemoContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.endpoint = (ROOT/'public/it113_demo_infer.php').read_text(encoding='utf-8')
        cls.html = (ROOT/'public/assessment/index.html').read_text(encoding='utf-8')
        cls.js = (ROOT/'public/assessment/it113-live.js').read_text(encoding='utf-8')
        cls.catalog = json.loads((ROOT/'public/assessment/evidence.json').read_text(encoding='utf-8'))

    def test_nine_login_free_navigation_views(self):
        views = re.findall(r'data-view="([a-z]+)"', self.html)
        self.assertEqual(len(views), 9)
        self.assertEqual(len(set(views)), 9)
        self.assertTrue(all(f'id="view-{name}"' in self.html for name in views))
        self.assertNotIn('href="/login.php"', self.html)

    def test_preserved_wolf_and_animations(self):
        self.assertIn('/images/wolf1.png', self.html)
        self.assertTrue((ROOT/'public/images/wolf1.png').is_file())
        css = (ROOT/'public/assessment/site.css').read_text(encoding='utf-8')
        self.assertIn('@keyframes logoFloat', css)
        self.assertIn('animation:logoFloat', css)

    def test_public_gateway_uses_curated_or_bounded_numeric_only_and_explicit_opt_in(self):
        self.assertIn("array_keys($request) === ['sample_id']", self.endpoint)
        self.assertIn("$request['source'] === 'numeric_csv'", self.endpoint)
        self.assertIn("count($features) !== 20", self.endpoint)
        self.assertIn("count($request) === 3", self.endpoint)
        self.assertIn('IT113_PUBLIC_DEMO_ENABLED', self.endpoint)
        self.assertIn("'false'", self.endpoint)
        self.assertIn("/assessment/evidence.json", self.endpoint)
        self.assertNotIn('fortress_ml_persist_prediction(', self.endpoint)
        self.assertNotIn('new PDO(', self.endpoint)
        self.assertIn('fortress_ml_post(', self.endpoint)

    def test_public_gateway_rate_limits_and_checks_origin(self):
        for word in ('it113_demo_rate_limit', 'Retry-After', 'HTTP_ORIGIN', 'HTTP_SEC_FETCH_SITE',
                     'IT113_DEMO_ALLOWED_ORIGINS', 'random_bytes(16)'):
            self.assertIn(word, self.endpoint)

    def test_client_sends_only_bounded_numeric_vectors_and_no_private_tokens(self):
        self.assertIn('postInference({sample_id:sampleId})', self.js)
        self.assertIn("source:'numeric_csv'", self.js)
        self.assertIn('queuedCsv.length', self.js)
        self.assertNotIn('ML_SERVICE_TOKEN', self.js)
        self.assertNotIn('DB_PASS', self.js)
        self.assertIn("$record['database_written'] = $written", self.endpoint)

    def test_synthetic_catalog_only(self):
        self.assertIs(self.catalog['not_live_inference'], True)
        self.assertIs(self.catalog['contains_real_personal_data'], False)
        self.assertGreaterEqual(len(self.catalog['examples']), 7)
        ids = [item['id'] for item in self.catalog['examples']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(len(item['features']) == 20 for item in self.catalog['examples']))

if __name__ == '__main__':
    unittest.main()
