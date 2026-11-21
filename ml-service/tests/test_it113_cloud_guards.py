"""Contracts for fail-closed cloud-side rate limiting and Free Render wakeups."""
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]

class CloudPublicGuards(unittest.TestCase):
    def test_cloud_never_falls_back_to_files(self):
        limit = (ROOT/'src/it113_shared_limiter.php').read_text(encoding='utf-8')
        self.assertIn('it113_limit_is_loopback()', limit)
        self.assertIn("IT113_RATE_LIMIT_MODE", limit)
        self.assertIn("IT113_RATE_LIMIT_SECRET", limit)
        self.assertIn("return 'unavailable';", limit)
        self.assertIn('hash_hmac(', limit)
        self.assertIn('REMOTE_ADDR', limit)
        self.assertNotIn('HTTP_X_FORWARDED_FOR', limit)
    def test_atomic_shared_limit_all_scopes(self):
        limit = (ROOT/'src/it113_shared_limiter.php').read_text(encoding='utf-8')
        for text in ['ON CONFLICT (bucket_key) DO UPDATE', 'WHERE bucket.hits < :cap',
                     '$pdo->beginTransaction()', '$pdo->rollBack()', '$pdo->commit()',
                     "'infer'", "'read'", "'write'", "'global'", "'peer'"]:
            self.assertIn(text,limit)
    def test_migration_only_new_rate_table_and_no_anon_access(self):
        sql=(ROOT/'sql/it113_shared_rate_limits.sql').read_text(encoding='utf-8')
        self.assertIn('CREATE TABLE IF NOT EXISTS public.it113_demo_rate_buckets',sql)
        self.assertIn('ENABLE ROW LEVEL SECURITY',sql)
        self.assertIn('FROM anon',sql)
        self.assertIn('FROM authenticated',sql)
        self.assertNotIn('DROP TABLE',sql)
    def test_api_fails_closed_if_counter_unavailable(self):
        infer=(ROOT/'public/it113_demo_infer.php').read_text(encoding='utf-8')
        hist=(ROOT/'public/it113_demo_history.php').read_text(encoding='utf-8')
        for text in [infer,hist]:
            self.assertIn("SAFETY_GATE_UNAVAILABLE",text)
            self.assertIn("DEMO_LIMIT_REACHED",text)
            self.assertIn("Retry-After",text)
        self.assertIn("it113_demo_limit('infer')",infer)
        self.assertIn("'read' : 'write'",hist)
    def test_sleep_error_does_not_fabricate_prediction(self):
        infer=(ROOT/'public/it113_demo_infer.php').read_text(encoding='utf-8')
        js=(ROOT/'public/assessment/it113-live.js').read_text(encoding='utf-8')
        self.assertIn("'ML_STARTING'", infer)
        self.assertIn('No simulated result was substituted',infer)
        self.assertIn("data.code==='ML_STARTING'",js)
        self.assertIn('ctrl.abort(),25000',js)
        self.assertNotIn('ML_SERVICE_TOKEN',js)
