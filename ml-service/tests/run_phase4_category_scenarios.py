"""IT113 Phase 4, Step 3: local-only seven-category prediction validation.

Use ONLY the bundled held-out SYNTHETIC dataset and an in-process FastAPI
TestClient. Nothing is sent to the internet, Supabase, or a running ML service.

Run from the project root:
    python ml-service/tests/run_phase4_category_scenarios.py
or from ml-service:
    python tests/run_phase4_category_scenarios.py
"""
from __future__ import annotations

import csv
import hashlib
import importlib
import json
import os
import secrets
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from fastapi.testclient import TestClient
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

SERVICE_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = SERVICE_ROOT / "models"
DATASET = SERVICE_ROOT / "data" / "synthetic_test_dataset.csv"
OUTPUT_DIR = SERVICE_ROOT / "phase4-results"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    # Isolate this in-process test from production credentials. The new token
    # exists in THIS Python process only; never display, save, or transmit it.
    os.environ["ML_SERVICE_TOKEN"] = secrets.token_hex(32)
    sys.path.insert(0, str(SERVICE_ROOT))
    api = importlib.import_module("app")

    metadata = json.loads((MODEL_DIR / "model_metadata.json").read_text(encoding="utf-8"))
    labels = list(metadata["dataset"]["classes"])
    features = list(metadata["dataset"]["features"])
    check(len(labels) == 7, "Expected exactly seven threat categories")
    check(DATASET.exists(), f"Missing held-out test data: {DATASET}")

    rows: list[dict[str, str]] = []
    with DATASET.open("r", encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        check(reader.fieldnames == features + ["label"], "Unexpected held-out CSV columns")
        for row in reader:
            check(row["label"] in labels, "Unknown expected class in held-out test set")
            rows.append(row)

    check(len(rows) == int(metadata["dataset"]["test_rows"]), "Held-out row count changed")
    X = np.array([[float(row[name]) for name in features] for row in rows], dtype=np.float32)
    expected = [row["label"] for row in rows]
    probs = api.classifier.predict_proba(X)
    predicted = [labels[int(idx)] for idx in np.argmax(probs, axis=1)]
    cm = confusion_matrix(expected, predicted, labels=labels).tolist()
    accuracy = float(accuracy_score(expected, predicted))
    correct_count = sum(a == b for a, b in zip(expected, predicted))
    wrong_count = len(rows) - correct_count

    # Guard against using the wrong model, modified test file, or mismatched saved report.
    check(cm == metadata["xgboost"]["confusion_matrix"],
          "Confusion matrix differs from the saved Phase 1 evaluation metadata")
    check(abs(accuracy - float(metadata["xgboost"]["accuracy"])) < 1e-10,
          "Accuracy differs from saved evaluation metadata")

    success_by_class = {}
    failure_by_class = {}
    per_class = {}
    for label in labels:
        idx = [i for i, value in enumerate(expected) if value == label]
        correct = [i for i in idx if predicted[i] == label]
        incorrect = [i for i in idx if predicted[i] != label]
        check(correct, f"No correct sample for {label}")
        success_by_class[label] = correct[0]
        if incorrect:
            failure_by_class[label] = incorrect[0]
        per_class[label] = {
            "total": len(idx), "correct": len(correct), "incorrect": len(incorrect),
            "recall": round(len(correct) / len(idx), 6),
        }

    # Real inference requests through the same FastAPI endpoint as the PHP bridge.
    # TestClient runs in this process, requiring no exposed listening port.
    client = TestClient(api.app)
    header = {"Authorization": f"Bearer {os.environ['ML_SERVICE_TOKEN']}"}
    check(client.get("/health").status_code == 200, "Health endpoint failed")
    probe = {"features": {feature: float(rows[0][feature]) for feature in features}, "rule_score": 0.0}
    check(client.post("/predict", json=probe, headers={}).status_code == 401,
          "ML API accepted an anonymous inference request")

    selected = [(name, "correct", success_by_class[name]) for name in labels]
    selected += [(name, "incorrect", failure_by_class[name]) for name in labels if name in failure_by_class]
    evidence_rows = []

    for name, kind, index in selected:
        feature_map = {feature: float(rows[index][feature]) for feature in features}
        trace = hashlib.sha256(f"fortress-phase4-synthetic-{index}".encode()).hexdigest()[:24]
        response = client.post("/predict", headers=header, json={
            "features": feature_map,
            "rule_score": 0.0,
            "trace_id": trace,
        })
        check(response.status_code == 200,
              f"Inference returned {response.status_code} for test row {index}: {response.text[:500]}")
        result = response.json()
        check(result["classification"] == predicted[index],
              f"API prediction disagrees with batch model at row {index}")
        check(result["trace_id"] == trace, "Inference trace ID not preserved")
        check(result["model_version"] == api.MODEL_VERSION, "Model version mismatch")
        check(result["explanation_type"] == "threshold_indicator_not_causal_attribution",
              "Explanation type unexpected")
        check(0 <= result["risk_score"] <= 100, "Risk score out of bounds")
        check(0 <= result["anomaly_score"] <= 1, "Anomaly score out of bounds")
        check(0 <= result["confidence"] <= 1, "Confidence out of bounds")
        check("source_ip" not in result and "username" not in result,
              "Unexpected personally identifying information returned")
        evidence_rows.append({
            "source": "held-out-synthetic-test",
            "test_row_1_based": index + 2,  # +1 for zero index, +1 for CSV header
            "scenario": kind,
            "expected_label": expected[index],
            "predicted_label": result["classification"],
            "match": "PASS" if expected[index] == result["classification"] else "MISCLASSIFIED",
            "confidence": result["confidence"],
            "anomaly_score": result["anomaly_score"],
            "risk_score": result["risk_score"],
            "severity": result["severity"],
            "model_version": result["model_version"],
            "trace_id": result["trace_id"],
            "feature_digest": result["feature_digest"],
            "indicators": "; ".join(result.get("indicators", [])),
        })

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUTPUT_DIR / "phase4_scenario_evidence.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(evidence_rows[0]))
        writer.writeheader()
        writer.writerows(evidence_rows)

    summary = {
        "description": "Local-only held-out synthetic evidence, not live intrusion testing",
        "dataset": "ml-service/data/synthetic_test_dataset.csv",
        "model_version": api.MODEL_VERSION,
        "row_count": len(rows),
        "total_correct": correct_count,
        "total_misclassified": wrong_count,
        "accuracy": accuracy,
        "per_class": per_class,
        "class_order": labels,
        "confusion_matrix": cm,
        "classification_report": classification_report(expected, predicted, labels=labels, output_dict=True, zero_division=0),
        "sample_evidence_file": csv_path.name,
        "sample_evidence_cases": len(evidence_rows),
        "limitations": [
            "All observations are simulated; estimates do not establish performance on real traffic.",
            "One example per class was selected to illustrate a correct prediction, not to estimate success rates.",
            "A misclassification example is included when the held-out set has one for that class.",
            "Risk scores include rule_score=0 for repeatable examples and do not represent live security decisions.",
            "The in-process HTTP API test does not validate PostgreSQL or cloud deployment.",
        ],
    }
    summary_path = OUTPUT_DIR / "phase4_category_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    print("\nIT113 PHASE 4 / STEP 3 - SEVEN-CATEGORY VALIDATION")
    print("Data source: held-out SYNTHETIC TEST SET; Supabase / network: NOT USED")
    print("Model version:", api.MODEL_VERSION)
    print("-" * 77)
    print(f"{'Category':<23}{'Correct':>9}{'Wrong':>9}{'Total':>9}{'Recall':>12}")
    for name in labels:
        item = per_class[name]
        print(f"{name:<23}{item['correct']:>9}{item['incorrect']:>9}{item['total']:>9}{item['recall'] * 100:>11.2f}%")
    print("-" * 77)
    print(f"TOTAL: {correct_count}/{len(rows)} correct, {wrong_count} misclassified; accuracy {accuracy * 100:.4f}%")
    print(f"API: {len(evidence_rows)} authenticated example requests PASSED consistency checks")
    print("Examples: one correct per category, plus one incorrect if available")
    if set(failure_by_class) != set(labels):
        print("No incorrect held-out example for:", ", ".join(name for name in labels if name not in failure_by_class))
    print("PASS: held-out metrics agree with the saved model evaluation metadata")
    print("PASS: anonymous /predict denied; all sample trace IDs and versions validated")
    print("Evidence CSV:", csv_path)
    print("Metrics JSON:", summary_path)
    print("IMPORTANT: Synthetic results are not evidence of real-world detection accuracy.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("\nPHASE 4 STEP 3 FAILED:", str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
