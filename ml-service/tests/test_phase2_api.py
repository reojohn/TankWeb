"""Phase-2 API contract, authentication, input integrity and evidence checks."""
import importlib
import os
import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["ML_SERVICE_TOKEN"] = "0123456789abcdef" * 4
api = importlib.import_module("app")
TOKEN = os.environ["ML_SERVICE_TOKEN"]


class Phase2ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(api.app)
        cls.header = {"Authorization": f"Bearer {TOKEN}"}
        cls.features = {name: 0.0 for name in api.FEATURES}
        cls.features.update({
            "requests_1m": 5, "requests_5m": 12, "unique_paths_5m": 4,
            "auth_endpoint_requests_5m": 7, "post_ratio_5m": 0.75,
            "failed_logins_5m": 4, "failed_logins_15m": 6,
            "avg_request_interval_5m": 5, "off_hours": 1,
        })
        cls.valid = {"features": cls.features, "rule_score": 35.0, "trace_id": "c1a2b3c4d5e6"}

    def test_health_minimal(self):
        self.assertEqual(self.client.get("/health").json(), {"status": "ok"})

    def test_predict_denies_missing_and_invalid_token(self):
        for headers in ({}, {"Authorization": "Bearer bad"}):
            self.assertEqual(self.client.post("/predict", json=self.valid, headers=headers).status_code, 401)

    def test_model_info_denies_anonymous(self):
        self.assertEqual(self.client.get("/model-info").status_code, 401)
        data = self.client.get("/model-info", headers=self.header)
        self.assertEqual(data.status_code, 200)
        self.assertEqual(data.json()["model_version"], api.MODEL_VERSION)

    def test_prediction_trace_and_numeric_evidence(self):
        r = self.client.post("/predict", json=self.valid, headers=self.header)
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        self.assertEqual(data["trace_id"], self.valid["trace_id"])
        self.assertEqual(len(data["model_version"]), 16)
        self.assertTrue(0 <= data["risk_score"] <= 100)
        self.assertEqual(data["explanation_type"], "threshold_indicator_not_causal_attribution")
        self.assertTrue(any(item["feature"] == "failed_logins_5m" and item["observed"] == 4
                            for item in data["indicator_evidence"]))
        self.assertEqual(set(data["probabilities"]), set(api.CLASSES))
        self.assertNotIn("source_ip", data)
        self.assertNotIn("username", data)

    def test_rejects_invalid_values_and_extra_fields(self):
        bad_cases = [
            {"features": {**self.features, "failed_logins_5m": -1}},
            {"features": {**self.features, "post_ratio_5m": 1.2}},
            {"features": {**self.features, "off_hours": 2}},
            {"features": {**self.features, "requests_1m": 13}},
            {"features": {**self.features, "failed_logins_5m": 7}},
            {"features": {**self.features, "unique_paths_5m": 13}},
            {"features": {**self.features, "requests_1m": True}},
            {"features": {**self.features, "unrecognized": 1}},
            {"features": {k:v for k,v in self.features.items() if k != "off_hours"}},
            {"features": self.features, "rule_score": 101},
            {"features": self.features, "trace_id": "../../bad"},
            {"features": self.features, "unauthorized_extra": "x"},
        ]
        for bad in bad_cases:
            with self.subTest(bad=bad):
                self.assertEqual(self.client.post("/predict", json=bad, headers=self.header).status_code, 422)


if __name__ == "__main__":
    unittest.main()
