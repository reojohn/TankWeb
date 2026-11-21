"""Offline Phase 3 regression tests: no live DB or private service required."""
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
PUBLIC=ROOT/'public'/'assessment'


class Phase3StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m=json.loads((PUBLIC/'model_summary.json').read_text(encoding="utf-8"))
        cls.ev=json.loads((PUBLIC/'evidence.json').read_text(encoding="utf-8"))
        cls.manifest=json.loads((PUBLIC/'phase3_manifest.json').read_text(encoding="utf-8"))
        cls.html=(PUBLIC/'index.html').read_text(encoding="utf-8")
        cls.js=(PUBLIC/'phase3.js').read_text(encoding="utf-8")

    def test_public_snapshot_contains_only_synthetic_evidence(self):
        self.assertTrue(self.ev['not_live_inference'])
        self.assertFalse(self.ev['contains_real_personal_data'])
        self.assertFalse(self.manifest['live_inference'])
        self.assertFalse(self.manifest['contains_private_data'])
        self.assertNotIn('ML_SERVICE_TOKEN',self.js)
        self.assertNotIn('POST /predict',self.js)
        self.assertNotIn('DB_PASSWORD',self.html)

    def test_phase3_manifest_identifies_actual_saved_models(self):
        raw=(ROOT/'ml-service/models/xgboost_threat_classifier.json').read_bytes()+(ROOT/'ml-service/models/autoencoder.joblib').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest()[:16],self.manifest['classifier_autoencoder_version'])
        for attr,file in [('metadata_sha256','model_summary.json'),('evidence_sha256','evidence.json')]:
            self.assertEqual(hashlib.sha256((PUBLIC/file).read_bytes()).hexdigest(),self.manifest[attr])

    def test_seven_views_are_distinct_and_reachable(self):
        source=(PUBLIC/'site.js').read_text(encoding="utf-8")
        for page in ('overview','dataset','evaluation','defense','examples','mitigations','reports'):
            self.assertIn(f'id="view-{page}"',self.html)
            self.assertIn(f'data-view="{page}"',self.html)
            self.assertIn(f"'{page}'",source)
        self.assertIn('/images/wolf1.png',self.html)
        self.assertIn('@keyframes logoFloat',(PUBLIC/'site.css').read_text(encoding="utf-8"))

    def test_confusion_matrix_reconciles_with_accuracy(self):
        m=self.m['xgboost']['confusion_matrix']
        rows=self.m['dataset']['test_rows']
        self.assertEqual(sum(map(sum,m)),rows)
        self.assertAlmostEqual(sum(row[i] for i,row in enumerate(m))/rows,self.m['xgboost']['accuracy'],places=10)

    def test_phase3_pdf_present_and_not_final_phase5_report(self):
        pdf=(PUBLIC/'it113_model_evaluation.pdf').read_bytes()
        self.assertTrue(pdf.startswith(b'%PDF-'))
        self.assertGreater(len(pdf),10000)
        self.assertIn('PHASE 3',self.html)
        self.assertIn('Phase 5',self.html)
        self.assertIn('/assessment/it113_model_evaluation.pdf',self.html)

    def test_privileged_ai_view_and_reports_remain_authenticated(self):
        ai=(ROOT/'public/ai_threat_intelligence.php').read_text(encoding="utf-8")
        report=(ROOT/'public/report_export.php').read_text(encoding="utf-8")
        for text in (ai,report):
            self.assertIn('require_admin_auth();',text)
        self.assertIn('verify_csrf_token',report)
        self.assertIn('phase3-trace-panel',ai)
        self.assertIn('indicator_evidence',ai)
        self.assertIn('model_evaluation_snapshot.json',(ROOT/'src/report_exporter.php').read_text(encoding="utf-8"))

    def test_report_includes_threat_specific_mitigations(self):
        report=(ROOT/'src/report_exporter.php').read_text(encoding="utf-8")
        self.assertIn('mitigation_matrix',report)
        for name in ['Brute Force','Credential Stuffing','Reconnaissance','Web Attack','MFA Abuse','Session Abuse','Normal']:
            self.assertIn("'Behavior Class'=>'"+name,report)
        self.assertIn("'Mitigation Matrix'",report)


if __name__=='__main__':unittest.main()
