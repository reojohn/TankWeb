"""Export PUBLIC, SYNTHETIC-ONLY assessment evidence for the no-login dashboard.

Never export real audit logs, model tokens, IP addresses, user records, or environment data.
Run after train_models.py to regenerate precomputed model test examples.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from xgboost import XGBClassifier

from train_models import CLASSES, FEATURES, make_dataset

ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / "models" / "model_metadata.json"
OUT = ROOT.parent / "public" / "assessment"


def export() -> None:
    metadata = json.loads(METADATA.read_text(encoding="utf-8"))
    classifier = XGBClassifier()
    classifier.load_model(ROOT / "models" / "xgboost_threat_classifier.json")
    scaler = joblib.load(ROOT / "models" / "autoencoder_scaler.joblib")
    autoencoder = joblib.load(ROOT / "models" / "autoencoder.joblib")
    x, labels = make_dataset(per_class=1500, seed=9113, shifted=True)
    probabilities = classifier.predict_proba(x)
    predicted = probabilities.argmax(axis=1)
    errors = np.mean(np.square(scaler.transform(x) - autoencoder.predict(scaler.transform(x))), axis=1)
    threshold = float(metadata["autoencoder"]["threshold_p99"])
    examples = []
    for label_id, true_class in enumerate(CLASSES):
        for outcome in ("correct", "incorrect"):
            candidates = np.flatnonzero((labels == label_id) & ((predicted == labels) if outcome == "correct" else (predicted != labels)))
            if not len(candidates):
                continue
            i = int(candidates[0])
            scores = probabilities[i]
            examples.append({
                "id": f"{true_class.lower()}_{outcome}",
                "true_label": true_class,
                "predicted_label": CLASSES[int(predicted[i])],
                "correct": outcome == "correct",
                "confidence": round(float(scores[predicted[i]]), 6),
                "anomaly": bool(errors[i] > threshold),
                "reconstruction_error": round(float(errors[i]), 6),
                "features": {f: round(float(x[i, j]), 4) for j, f in enumerate(FEATURES)},
            })
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "model_summary.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (OUT / "evidence.json").write_text(json.dumps({
        "source": "Precomputed XGBoost/autoencoder inference on independent synthetic held-out TEST samples",
        "not_live_inference": True,
        "contains_real_personal_data": False,
        "examples": examples,
    }, indent=2), encoding="utf-8")
    print(f"Exported {len(examples)} synthetic test examples to {OUT}")


if __name__ == "__main__":
    export()
