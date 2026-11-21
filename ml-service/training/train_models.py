from __future__ import annotations

import csv
import json
import hashlib
import platform
from pathlib import Path

import joblib
import numpy as np
import sklearn
import xgboost
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, average_precision_score)
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"
DATA_DIR = ROOT / "data"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

FEATURES = [
    "requests_1m",
    "requests_5m",
    "unique_paths_5m",
    "post_ratio_5m",
    "auth_endpoint_requests_5m",
    "failed_logins_5m",
    "failed_logins_15m",
    "unique_usernames_15m",
    "successful_logins_15m",
    "qr_failures_15m",
    "sensitive_path_probes_15m",
    "suspicious_requests_15m",
    "scanner_events_15m",
    "csrf_failures_15m",
    "method_anomalies_15m",
    "auth_rejections_15m",
    "ban_events_15m",
    "avg_request_interval_5m",
    "ua_changes_15m",
    "off_hours",
]

CLASSES = [
    "NORMAL",
    "BRUTE_FORCE",
    "CREDENTIAL_STUFFING",
    "RECONNAISSANCE",
    "WEB_ATTACK",
    "MFA_ABUSE",
    "SESSION_ABUSE",
]

CLASS_TO_ID = {name: idx for idx, name in enumerate(CLASSES)}

COUNT_FEATURES = {
    "requests_1m", "requests_5m", "unique_paths_5m", "auth_endpoint_requests_5m",
    "failed_logins_5m", "failed_logins_15m", "unique_usernames_15m",
    "successful_logins_15m", "qr_failures_15m", "sensitive_path_probes_15m",
    "suspicious_requests_15m", "scanner_events_15m", "csrf_failures_15m",
    "method_anomalies_15m", "auth_rejections_15m", "ban_events_15m", "ua_changes_15m",
}


def validate_features(x: np.ndarray) -> dict[str, int]:
    """Report impossible count/window relationships. Zero violations are required."""
    index = {name: i for i, name in enumerate(FEATURES)}
    get = lambda name: x[:, index[name]]
    checks = {
        "requests_1m_gt_requests_5m": get("requests_1m") > get("requests_5m"),
        "unique_paths_gt_requests_5m": get("unique_paths_5m") > get("requests_5m"),
        "auth_requests_gt_requests_5m": get("auth_endpoint_requests_5m") > get("requests_5m"),
        "failed_logins_5m_gt_auth_requests_5m": get("failed_logins_5m") > get("auth_endpoint_requests_5m"),
        "failed_logins_5m_gt_failed_logins_15m": get("failed_logins_5m") > get("failed_logins_15m"),
        "post_ratio_outside_zero_one": (get("post_ratio_5m") < 0) | (get("post_ratio_5m") > 1),
        "non_finite_values": ~np.isfinite(x).all(axis=1),
    }
    for name in COUNT_FEATURES:
        vals = get(name)
        checks["negative_or_fractional_" + name] = (vals < 0) | (np.abs(vals - np.round(vals)) > 1e-6)
    return {name: int(np.sum(mask)) for name, mask in checks.items()}


def _clip_round(values: dict[str, float]) -> np.ndarray:
    row = []
    for feature in FEATURES:
        value = float(values[feature])
        if feature in COUNT_FEATURES:
            value = max(0.0, round(value))
        elif feature == "post_ratio_5m":
            value = min(1.0, max(0.0, value))
        elif feature == "avg_request_interval_5m":
            value = min(300.0, max(0.05, value))
        elif feature == "off_hours":
            value = 1.0 if value >= 0.5 else 0.0
        row.append(value)
    cleaned = dict(zip(FEATURES, row, strict=True))
    # Generate physically possible nested time-window counts without altering
    # the discriminative attack signals (failed attempts / auth attempts).
    cleaned["failed_logins_15m"] = max(cleaned["failed_logins_15m"], cleaned["failed_logins_5m"])
    cleaned["auth_endpoint_requests_5m"] = max(cleaned["auth_endpoint_requests_5m"], cleaned["failed_logins_5m"])
    cleaned["requests_5m"] = max(cleaned["requests_5m"], cleaned["auth_endpoint_requests_5m"], cleaned["requests_1m"])
    cleaned["unique_paths_5m"] = min(cleaned["unique_paths_5m"], cleaned["requests_5m"])
    return np.asarray([cleaned[f] for f in FEATURES], dtype=np.float32)


def _normal(rng: np.random.Generator, shift: float = 1.0) -> np.ndarray:
    req5 = max(1, rng.poisson(9 * shift))
    req1 = min(req5, max(0, rng.poisson(2.0 * shift)))
    vals = {
        "requests_1m": req1,
        "requests_5m": req5,
        "unique_paths_5m": min(req5, max(1, rng.poisson(4.0))),
        "post_ratio_5m": rng.beta(2, 7),
        "auth_endpoint_requests_5m": rng.poisson(0.8),
        "failed_logins_5m": rng.binomial(2, 0.08),
        "failed_logins_15m": rng.binomial(3, 0.10),
        "unique_usernames_15m": 1 + rng.binomial(1, 0.02),
        "successful_logins_15m": rng.binomial(2, 0.45),
        "qr_failures_15m": rng.binomial(2, 0.05),
        "sensitive_path_probes_15m": 0,
        "suspicious_requests_15m": rng.binomial(1, 0.01),
        "scanner_events_15m": 0,
        "csrf_failures_15m": rng.binomial(1, 0.01),
        "method_anomalies_15m": 0,
        "auth_rejections_15m": rng.binomial(1, 0.03),
        "ban_events_15m": 0,
        "avg_request_interval_5m": rng.uniform(12, 75),
        "ua_changes_15m": rng.binomial(1, 0.03),
        "off_hours": rng.binomial(1, 0.18),
    }
    return _clip_round(vals)


def _brute_force(rng: np.random.Generator, shifted: bool) -> np.ndarray:
    low = 4 if shifted else 7
    vals = {
        "requests_1m": rng.integers(low, 22),
        "requests_5m": rng.integers(20, 75),
        "unique_paths_5m": rng.integers(1, 5),
        "post_ratio_5m": rng.uniform(0.65, 1.0),
        "auth_endpoint_requests_5m": rng.integers(12, 55),
        "failed_logins_5m": rng.integers(low, 22),
        "failed_logins_15m": rng.integers(12, 55),
        "unique_usernames_15m": rng.integers(1, 4),
        "successful_logins_15m": rng.binomial(2, 0.06),
        "qr_failures_15m": rng.binomial(2, 0.08),
        "sensitive_path_probes_15m": rng.binomial(2, 0.04),
        "suspicious_requests_15m": rng.binomial(2, 0.08),
        "scanner_events_15m": rng.binomial(1, 0.05),
        "csrf_failures_15m": rng.binomial(2, 0.08),
        "method_anomalies_15m": rng.binomial(1, 0.05),
        "auth_rejections_15m": rng.integers(3, 18),
        "ban_events_15m": rng.binomial(2, 0.35),
        "avg_request_interval_5m": rng.uniform(1.5 if shifted else 0.4, 10.0),
        "ua_changes_15m": rng.binomial(2, 0.1),
        "off_hours": rng.binomial(1, 0.45),
    }
    return _clip_round(vals)


def _credential_stuffing(rng: np.random.Generator, shifted: bool) -> np.ndarray:
    vals = {
        "requests_1m": rng.integers(3 if shifted else 6, 20),
        "requests_5m": rng.integers(18, 65),
        "unique_paths_5m": rng.integers(2, 7),
        "post_ratio_5m": rng.uniform(0.55, 0.95),
        "auth_endpoint_requests_5m": rng.integers(10, 45),
        "failed_logins_5m": rng.integers(3, 15),
        "failed_logins_15m": rng.integers(9, 38),
        "unique_usernames_15m": rng.integers(5 if shifted else 8, 28),
        "successful_logins_15m": rng.binomial(3, 0.12),
        "qr_failures_15m": rng.binomial(3, 0.12),
        "sensitive_path_probes_15m": rng.binomial(1, 0.06),
        "suspicious_requests_15m": rng.binomial(2, 0.08),
        "scanner_events_15m": rng.binomial(1, 0.03),
        "csrf_failures_15m": rng.binomial(2, 0.08),
        "method_anomalies_15m": rng.binomial(1, 0.03),
        "auth_rejections_15m": rng.integers(3, 16),
        "ban_events_15m": rng.binomial(1, 0.2),
        "avg_request_interval_5m": rng.uniform(2.0, 14.0),
        "ua_changes_15m": rng.integers(0, 5),
        "off_hours": rng.binomial(1, 0.38),
    }
    return _clip_round(vals)


def _recon(rng: np.random.Generator, shifted: bool) -> np.ndarray:
    vals = {
        "requests_1m": rng.integers(3, 18),
        "requests_5m": rng.integers(18, 80),
        "unique_paths_5m": rng.integers(10 if shifted else 16, 58),
        "post_ratio_5m": rng.uniform(0.0, 0.25),
        "auth_endpoint_requests_5m": rng.integers(0, 6),
        "failed_logins_5m": rng.binomial(3, 0.08),
        "failed_logins_15m": rng.binomial(5, 0.1),
        "unique_usernames_15m": 1 + rng.binomial(2, 0.05),
        "successful_logins_15m": 0,
        "qr_failures_15m": 0,
        "sensitive_path_probes_15m": rng.integers(2 if shifted else 4, 18),
        "suspicious_requests_15m": rng.integers(1, 10),
        "scanner_events_15m": rng.binomial(3, 0.6),
        "csrf_failures_15m": rng.binomial(2, 0.04),
        "method_anomalies_15m": rng.binomial(3, 0.18),
        "auth_rejections_15m": rng.binomial(4, 0.15),
        "ban_events_15m": rng.binomial(1, 0.15),
        "avg_request_interval_5m": rng.uniform(1.2 if shifted else 0.3, 9.0),
        "ua_changes_15m": rng.integers(0, 4),
        "off_hours": rng.binomial(1, 0.42),
    }
    return _clip_round(vals)


def _web_attack(rng: np.random.Generator, shifted: bool) -> np.ndarray:
    vals = {
        "requests_1m": rng.integers(2, 15),
        "requests_5m": rng.integers(8, 45),
        "unique_paths_5m": rng.integers(3, 18),
        "post_ratio_5m": rng.uniform(0.25, 0.85),
        "auth_endpoint_requests_5m": rng.integers(0, 10),
        "failed_logins_5m": rng.binomial(4, 0.15),
        "failed_logins_15m": rng.binomial(8, 0.18),
        "unique_usernames_15m": rng.integers(1, 5),
        "successful_logins_15m": rng.binomial(2, 0.1),
        "qr_failures_15m": rng.binomial(2, 0.05),
        "sensitive_path_probes_15m": rng.integers(0, 5),
        "suspicious_requests_15m": rng.integers(2 if shifted else 4, 16),
        "scanner_events_15m": rng.binomial(2, 0.35),
        "csrf_failures_15m": rng.binomial(3, 0.18),
        "method_anomalies_15m": rng.binomial(3, 0.18),
        "auth_rejections_15m": rng.integers(1, 9),
        "ban_events_15m": rng.binomial(1, 0.2),
        "avg_request_interval_5m": rng.uniform(1.0, 15.0),
        "ua_changes_15m": rng.integers(0, 4),
        "off_hours": rng.binomial(1, 0.35),
    }
    return _clip_round(vals)


def _mfa_abuse(rng: np.random.Generator, shifted: bool) -> np.ndarray:
    vals = {
        "requests_1m": rng.integers(2, 12),
        "requests_5m": rng.integers(8, 38),
        "unique_paths_5m": rng.integers(2, 8),
        "post_ratio_5m": rng.uniform(0.45, 0.9),
        "auth_endpoint_requests_5m": rng.integers(6, 25),
        "failed_logins_5m": rng.binomial(4, 0.15),
        "failed_logins_15m": rng.binomial(7, 0.18),
        "unique_usernames_15m": rng.integers(1, 4),
        "successful_logins_15m": rng.integers(1, 4),
        "qr_failures_15m": rng.integers(3 if shifted else 5, 18),
        "sensitive_path_probes_15m": 0,
        "suspicious_requests_15m": rng.binomial(2, 0.08),
        "scanner_events_15m": 0,
        "csrf_failures_15m": rng.binomial(2, 0.05),
        "method_anomalies_15m": 0,
        "auth_rejections_15m": rng.integers(2, 12),
        "ban_events_15m": rng.binomial(1, 0.18),
        "avg_request_interval_5m": rng.uniform(2.0, 18.0),
        "ua_changes_15m": rng.binomial(2, 0.08),
        "off_hours": rng.binomial(1, 0.32),
    }
    return _clip_round(vals)


def _session_abuse(rng: np.random.Generator, shifted: bool) -> np.ndarray:
    vals = {
        "requests_1m": rng.integers(3, 20),
        "requests_5m": rng.integers(15, 70),
        "unique_paths_5m": rng.integers(6, 28),
        "post_ratio_5m": rng.uniform(0.15, 0.55),
        "auth_endpoint_requests_5m": rng.integers(0, 8),
        "failed_logins_5m": rng.binomial(3, 0.08),
        "failed_logins_15m": rng.binomial(5, 0.1),
        "unique_usernames_15m": rng.integers(1, 4),
        "successful_logins_15m": rng.binomial(2, 0.2),
        "qr_failures_15m": rng.binomial(2, 0.08),
        "sensitive_path_probes_15m": rng.binomial(3, 0.18),
        "suspicious_requests_15m": rng.integers(1, 8),
        "scanner_events_15m": rng.binomial(2, 0.15),
        "csrf_failures_15m": rng.integers(1 if shifted else 2, 9),
        "method_anomalies_15m": rng.integers(0, 5),
        "auth_rejections_15m": rng.integers(4, 16),
        "ban_events_15m": rng.binomial(1, 0.12),
        "avg_request_interval_5m": rng.uniform(1.0, 12.0),
        "ua_changes_15m": rng.integers(1 if shifted else 2, 8),
        "off_hours": rng.binomial(1, 0.45),
    }
    return _clip_round(vals)


GENERATORS = {
    "NORMAL": lambda r, s: _normal(r, 1.15 if s else 1.0),
    "BRUTE_FORCE": _brute_force,
    "CREDENTIAL_STUFFING": _credential_stuffing,
    "RECONNAISSANCE": _recon,
    "WEB_ATTACK": _web_attack,
    "MFA_ABUSE": _mfa_abuse,
    "SESSION_ABUSE": _session_abuse,
}


def make_dataset(per_class: int, seed: int, shifted: bool) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    rows: list[np.ndarray] = []
    labels: list[int] = []
    for class_name in CLASSES:
        generator = GENERATORS[class_name]
        for _ in range(per_class):
            rows.append(generator(rng, shifted))
            labels.append(CLASS_TO_ID[class_name])
    x = np.vstack(rows)
    y = np.asarray(labels, dtype=np.int64)
    order = rng.permutation(len(y))
    return x[order], y[order]


def save_csv(path: Path, x: np.ndarray, y: np.ndarray) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(FEATURES + ["label"])
        for row, label in zip(x, y, strict=True):
            writer.writerow([f"{float(v):.6g}" for v in row] + [CLASSES[int(label)]])


def train() -> None:
    # Three *independently seeded* simulated sets. Test data are never used
    # for threshold calibration, model selection, or training.
    x_train, y_train = make_dataset(per_class=5000, seed=113, shifted=False)
    x_validation, y_validation = make_dataset(per_class=1000, seed=2113, shifted=False)
    x_test, y_test = make_dataset(per_class=1500, seed=9113, shifted=True)
    splits = {"train": (x_train, y_train), "validation": (x_validation, y_validation), "test": (x_test, y_test)}
    data_quality = {key: validate_features(x) for key, (x, _) in splits.items()}
    if any(any(count for count in findings.values()) for findings in data_quality.values()):
        raise AssertionError(f"Synthetic dataset violates nested-counter constraints: {data_quality}")
    save_csv(DATA_DIR / "synthetic_security_dataset.csv", x_train, y_train)
    save_csv(DATA_DIR / "synthetic_validation_dataset.csv", x_validation, y_validation)
    save_csv(DATA_DIR / "synthetic_test_dataset.csv", x_test, y_test)

    classifier = XGBClassifier(
        n_estimators=320,
        max_depth=5,
        learning_rate=0.055,
        subsample=0.88,
        colsample_bytree=0.9,
        min_child_weight=2,
        reg_lambda=1.2,
        objective="multi:softprob",
        eval_metric="mlogloss",
        tree_method="hist",
        random_state=113,
        n_jobs=4,
    )
    classifier.fit(x_train, y_train)
    classifier.save_model(MODEL_DIR / "xgboost_threat_classifier.json")

    pred = classifier.predict(x_test)
    report = classification_report(y_test, pred, target_names=CLASSES, output_dict=True, zero_division=0)

    normal_train = x_train[y_train == CLASS_TO_ID["NORMAL"]]
    normal_validation = x_validation[y_validation == CLASS_TO_ID["NORMAL"]]
    normal_test = x_test[y_test == CLASS_TO_ID["NORMAL"]]
    scaler = StandardScaler()
    normal_train_scaled = scaler.fit_transform(normal_train)
    normal_validation_scaled = scaler.transform(normal_validation)
    normal_test_scaled = scaler.transform(normal_test)

    autoencoder = MLPRegressor(
        hidden_layer_sizes=(16, 8, 4, 8, 16),
        activation="relu",
        solver="adam",
        alpha=0.0005,
        batch_size=128,
        learning_rate_init=0.001,
        max_iter=500,
        tol=0.001,
        early_stopping=True,
        validation_fraction=0.15,
        n_iter_no_change=25,
        random_state=113,
    )
    autoencoder.fit(normal_train_scaled, normal_train_scaled)
    # Calibrate the 99th percentile on VALIDATION normal samples only.
    validation_recon = autoencoder.predict(normal_validation_scaled)
    validation_errors = np.mean(np.square(normal_validation_scaled - validation_recon), axis=1)
    threshold = float(np.quantile(validation_errors, 0.99))

    # All evaluation metrics below use the untouched TEST set.
    normal_recon = autoencoder.predict(normal_test_scaled)
    normal_errors = np.mean(np.square(normal_test_scaled - normal_recon), axis=1)
    p95 = float(np.quantile(normal_errors, 0.95))
    p50 = float(np.quantile(normal_errors, 0.50))

    all_scaled = scaler.transform(x_test)
    all_recon = autoencoder.predict(all_scaled)
    all_errors = np.mean(np.square(all_scaled - all_recon), axis=1)
    anomaly_scores = np.clip(all_errors / max(threshold, 1e-9), 0.0, 3.0) / 3.0
    anomaly_binary = (all_errors > threshold).astype(int)
    true_anomaly = (y_test != CLASS_TO_ID["NORMAL"]).astype(int)
    ae_cm = confusion_matrix(true_anomaly, anomaly_binary, labels=[0, 1])

    joblib.dump(autoencoder, MODEL_DIR / "autoencoder.joblib", compress=3)
    joblib.dump(scaler, MODEL_DIR / "autoencoder_scaler.joblib", compress=3)

    feature_importance = sorted(
        zip(FEATURES, classifier.feature_importances_.tolist(), strict=True),
        key=lambda item: item[1],
        reverse=True,
    )

    metadata = {
        "project": "FortressAuth Hybrid Intelligent Threat Detection",
        "dataset": {
            "type": "synthetic/simulated course-project security telemetry",
            "training_rows": int(len(y_train)),
            "validation_rows": int(len(y_validation)),
            "holdout_rows": int(len(y_test)),
            "test_rows": int(len(y_test)),
            "split_seeds": {"train": 113, "validation": 2113, "test": 9113},
            "split_role": "Independent synthetic training, normal-threshold calibration, and distribution-shifted final test sets",
            "class_counts": {key: {CLASSES[i]: int(np.sum(y == i)) for i in range(len(CLASSES))} for key, (_, y) in splits.items()},
            "data_quality_invariant_violations": data_quality,
            "data_quality_checks_passed": True,
            "classes": CLASSES,
            "features": FEATURES,
            "note": "Class-balanced, artificially generated security activity. The test set introduces a limited synthetic shift, not real traffic or field validation. Performance cannot establish production detection rates.",
        },
        "xgboost": {
            "accuracy": float(accuracy_score(y_test, pred)),
            "macro_f1": float(f1_score(y_test, pred, average="macro")),
            "weighted_f1": float(f1_score(y_test, pred, average="weighted")),
            "macro_precision": float(precision_score(y_test, pred, average="macro", zero_division=0)),
            "macro_recall": float(recall_score(y_test, pred, average="macro", zero_division=0)),
            "classification_report": report,
            "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
            "top_feature_importance": feature_importance[:10],
        },
        "autoencoder": {
            "implementation": "scikit-learn MLPRegressor trained X->X as a compact feed-forward autoencoder",
            "normal_error_p50": p50,
            "normal_error_p95": p95,
            "threshold_p99": threshold,
            "threshold_calibrated_from": "validation_normal_only",
            "validation_normal_rows": int(len(normal_validation)),
            "validation_normal_error_p99": threshold,
            "test_confusion_matrix_binary_normal_then_anomaly": ae_cm.tolist(),
            "test_anomaly_precision": float(precision_score(true_anomaly, anomaly_binary, zero_division=0)),
            "test_anomaly_f1": float(f1_score(true_anomaly, anomaly_binary, zero_division=0)),
            "test_anomaly_roc_auc": float(roc_auc_score(true_anomaly, all_errors)),
            "test_anomaly_average_precision": float(average_precision_score(true_anomaly, all_errors)),
            "holdout_anomaly_recall": float(np.sum((anomaly_binary == 1) & (true_anomaly == 1)) / max(1, np.sum(true_anomaly == 1))),
            "holdout_normal_false_positive_rate": float(np.sum((anomaly_binary == 1) & (true_anomaly == 0)) / max(1, np.sum(true_anomaly == 0))),
            "mean_normalized_anomaly_score": float(np.mean(anomaly_scores)),
        },
        "reproducibility": {
            "training_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "python": platform.python_version(), "numpy": np.__version__,
            "scikit_learn": sklearn.__version__, "xgboost": xgboost.__version__,
            "random_state": 113,
            "algorithm_notes": "XGBoost 320 trees / max depth 5. MLPRegressor encoder-decoder 16-8-4-8-16 trained on normal-only behavior.",
            "limitation": "Rule weights are illustrative; measured classifier accuracy is not an end-to-end threat-prevention success rate. No real-world external validation has been performed.",
        },
        "risk_fusion": {
            "rule_weight": 0.35,
            "xgboost_weight": 0.40,
            "autoencoder_weight": 0.25,
            "bands": {"NORMAL": "0-29", "WATCH": "30-49", "SUSPICIOUS": "50-69", "HIGH": "70-84", "CRITICAL": "85-100"},
        },
    }
    # Both endpoints and the public academic dashboard use this SAME evaluated
    # metadata. The dashboard shows metrics, never private telemetry or secrets.
    (MODEL_DIR / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (DATA_DIR / "training_report.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(json.dumps({
        "training_rows": len(y_train),
        "validation_rows": len(y_validation),
        "holdout_rows": len(y_test),
        "xgboost_accuracy": metadata["xgboost"]["accuracy"],
        "xgboost_macro_f1": metadata["xgboost"]["macro_f1"],
        "autoencoder_threshold": threshold,
        "autoencoder_anomaly_recall": metadata["autoencoder"]["holdout_anomaly_recall"],
        "autoencoder_normal_false_positive_rate": metadata["autoencoder"]["holdout_normal_false_positive_rate"],
    }, indent=2))


if __name__ == "__main__":
    train()
