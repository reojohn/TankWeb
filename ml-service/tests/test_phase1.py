"""Reproducibility tests for the IT113 phase-1 synthetic assessment.

Run from ml-service: python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "training"))
from train_models import CLASSES, FEATURES, make_dataset, validate_features  # noqa: E402


class Phase1ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.metadata = json.loads((ROOT / "models" / "model_metadata.json").read_text(encoding="utf-8"))

    def test_independent_split_sizes_and_all_labels(self):
        for per_class, seed, shifted in ((5000, 113, False), (1000, 2113, False), (1500, 9113, True)):
            x, y = make_dataset(per_class, seed, shifted)
            self.assertEqual(x.shape, (7 * per_class, len(FEATURES)))
            np.testing.assert_array_equal(np.bincount(y), [per_class] * len(CLASSES))

    def test_nested_window_and_count_invariants(self):
        for per_class, seed, shifted in ((5000, 113, False), (1000, 2113, False), (1500, 9113, True)):
            x, _ = make_dataset(per_class, seed, shifted)
            self.assertFalse(any(validate_features(x).values()))

    def test_replay_produces_same_first_25_records(self):
        a, ya = make_dataset(100, 9113, True)
        b, yb = make_dataset(100, 9113, True)
        np.testing.assert_array_equal(a[:25], b[:25])
        np.testing.assert_array_equal(ya[:25], yb[:25])

    def test_classifier_test_scores_match_saved_report(self):
        model = XGBClassifier()
        model.load_model(ROOT / "models" / "xgboost_threat_classifier.json")
        x, y = make_dataset(1500, 9113, True)
        pred = model.predict(x)
        self.assertAlmostEqual(accuracy_score(y, pred), self.metadata["xgboost"]["accuracy"], places=9)
        self.assertAlmostEqual(f1_score(y, pred, average="macro"), self.metadata["xgboost"]["macro_f1"], places=9)
        self.assertEqual(confusion_matrix(y, pred).tolist(), self.metadata["xgboost"]["confusion_matrix"])

    def test_anomaly_threshold_recomputed_using_validation_only(self):
        x, y = make_dataset(1000, 2113, False)
        normal = x[y == 0]
        scaler = joblib.load(ROOT / "models" / "autoencoder_scaler.joblib")
        model = joblib.load(ROOT / "models" / "autoencoder.joblib")
        scaled = scaler.transform(normal)
        errors = np.mean(np.square(scaled - model.predict(scaled)), axis=1)
        threshold = float(np.quantile(errors, .99))
        self.assertAlmostEqual(threshold, self.metadata["autoencoder"]["threshold_p99"], places=8)
        self.assertEqual(self.metadata["autoencoder"]["threshold_calibrated_from"], "validation_normal_only")

    def test_public_dashboard_has_no_private_data(self):
        public = ROOT.parent / "public" / "assessment"
        evidence = json.loads((public / "evidence.json").read_text(encoding="utf-8"))
        summary = json.loads((public / "model_summary.json").read_text(encoding="utf-8"))
        self.assertFalse(evidence["contains_real_personal_data"])
        self.assertTrue(evidence["not_live_inference"])
        self.assertEqual(summary, self.metadata)
        self.assertGreaterEqual(len(evidence["examples"]), 7)
        for case in evidence["examples"]:
            self.assertEqual(set(case["features"]), set(FEATURES))
            self.assertEqual(case["correct"], case["true_label"] == case["predicted_label"])
            self.assertNotIn("ip", case)
            self.assertNotIn("username", case)


if __name__ == '__main__':
    unittest.main()
