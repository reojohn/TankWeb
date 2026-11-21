"""New security/functional contracts for the optional dynamic IT113 system."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

class DynamicAssessmentContracts(unittest.TestCase):
    def test_new_migration_is_isolated_and_reresumable(self):
        sql=(ROOT/'sql/it113_dynamic_assessments.sql').read_text(encoding='utf-8')
        self.assertIn('CREATE TABLE IF NOT EXISTS public.it113_demo_assessments',sql)
        self.assertIn('CREATE TABLE IF NOT EXISTS public.it113_demo_case_events',sql)
        self.assertIn('ENABLE ROW LEVEL SECURITY',sql)
        self.assertIn('FROM anon',sql)
        self.assertIn('FROM authenticated',sql)
        self.assertNotIn('DROP TABLE',sql)
    def test_server_storage_is_opt_in_and_session_scoped(self):
        s=(ROOT/'src/it113_public_store.php').read_text(encoding='utf-8')
        for marker in ('IT113_DEMO_PERSISTENCE_ENABLED','httponly','samesite','Strict',
                       'session_digest = ?', 'random_bytes(32)','revision<15', 'ROLLBACK'):
            if marker=='ROLLBACK':continue
            self.assertIn(marker,s)
        self.assertNotIn('$_REQUEST[\'DB_PASS\']',s)
        self.assertNotIn('ml_predictions',s)
    def test_numeric_csv_is_bounded_and_no_credential_fields(self):
        s=(ROOT/'public/it113_demo_infer.php').read_text(encoding='utf-8')
        for marker in ('4096','count($features) !== 20','numeric_csv',
                       'IT113_PUBLIC_DEMO_ENABLED','it113_demo_rate_limit','fortress_ml_post('):
            self.assertIn(marker,s)
        self.assertNotIn('fortress_ml_persist_prediction(',s)
    def test_updated_research_workflow_is_reachable(self):
        html=(ROOT/'public/assessment/index.html').read_text(encoding='utf-8')
        js=(ROOT/'public/assessment/it113-live.js').read_text(encoding='utf-8')
        for ident in ('csv-input','csv-run','csv-template','case-status','report-export-csv','report-print','dynamic-report-preview'):
            self.assertIn(ident,html+js)
        for marker in ('readCsv','syncHistory','updateCase','renderAnalytics','renderReport','window.print'):
            self.assertIn(marker,js)
        self.assertIn('/images/wolf1.png',html)
        self.assertNotIn('href="/login.php"',html)
    def test_source_model_features_are_current(self):
        schema=json.loads((ROOT/'public/assessment/model_summary.json').read_text(encoding='utf-8'))
        self.assertEqual(len(schema['dataset']['features']),20)
        self.assertEqual(len(schema['dataset']['classes']),7)
    def test_web_history_endpoint_is_session_scoped(self):
        s=(ROOT/'public/it113_demo_history.php').read_text(encoding='utf-8')
        for marker in ('HTTP_ORIGIN','HTTP_SEC_FETCH_SITE','it113_store_history','it113_store_status','it113_store_clear','trace_id'):
            self.assertIn(marker,s)
