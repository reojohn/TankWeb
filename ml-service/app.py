from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
import joblib
import numpy as np
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "models"
METADATA = json.loads((MODEL_DIR / "model_metadata.json").read_text(encoding="utf-8"))
FEATURES = METADATA["dataset"]["features"]
CLASSES = METADATA["dataset"]["classes"]
AE_THRESHOLD = float(METADATA["autoencoder"]["threshold_p99"])

classifier = XGBClassifier()
classifier.load_model(MODEL_DIR / "xgboost_threat_classifier.json")
autoencoder = joblib.load(MODEL_DIR / "autoencoder.joblib")
scaler = joblib.load(MODEL_DIR / "autoencoder_scaler.joblib")

CLASS_BASE_RISK = {
    "NORMAL": 8.0,
    "BRUTE_FORCE": 86.0,
    "CREDENTIAL_STUFFING": 92.0,
    "RECONNAISSANCE": 72.0,
    "WEB_ATTACK": 91.0,
    "MFA_ABUSE": 87.0,
    "SESSION_ABUSE": 90.0,
}

app = FastAPI(title="FortressAuth ML Threat Engine", version="1.0.0")
SERVICE_TOKEN = os.getenv("ML_SERVICE_TOKEN", "").strip()

def require_service_token(authorization: str | None) -> None:
    if not SERVICE_TOKEN:
        return
    expected = f"Bearer {SERVICE_TOKEN}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


class PredictionRequest(BaseModel):
    features: dict[str, float] = Field(default_factory=dict)
    rule_score: float = Field(default=0.0, ge=0.0, le=100.0)


def band(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "SUSPICIOUS"
    if score >= 30:
        return "WATCH"
    return "NORMAL"


def explain(feature_map: dict[str, float], prediction: str) -> list[str]:
    candidates: list[tuple[float, str]] = []
    rules = [
        ("failed_logins_5m", 4, "Elevated failed-password frequency"),
        ("failed_logins_15m", 8, "Repeated authentication failures over time"),
        ("unique_usernames_15m", 4, "Multiple usernames attempted from one source"),
        ("qr_failures_15m", 3, "Repeated Personal ID verification failures"),
        ("sensitive_path_probes_15m", 1, "Sensitive-resource probing"),
        ("suspicious_requests_15m", 2, "Suspicious request-pattern activity"),
        ("scanner_events_15m", 1, "Scanner/reconnaissance indicators"),
        ("csrf_failures_15m", 1, "CSRF validation failures"),
        ("auth_rejections_15m", 3, "Repeated protected-resource rejection"),
        ("ua_changes_15m", 2, "Unusual user-agent changes"),
        ("unique_paths_5m", 12, "Broad endpoint enumeration"),
        ("requests_1m", 12, "High short-window request rate"),
    ]
    for name, threshold, text in rules:
        value = float(feature_map.get(name, 0.0))
        if value >= threshold:
            candidates.append((value / max(float(threshold), 1.0), text))
    candidates.sort(reverse=True)
    items = [text for _, text in candidates[:5]]
    if not items and prediction == "NORMAL":
        items.append("Behavior remains close to the learned normal baseline")
    return items


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "classifier": "xgboost",
        "anomaly_detector": "autoencoder",
        "features": len(FEATURES),
    }


@app.get("/model-info")
def model_info() -> dict:
    return METADATA


@app.post("/predict")
def predict(payload: PredictionRequest, authorization: str | None = Header(default=None)) -> dict:
    require_service_token(authorization)
    missing = [feature for feature in FEATURES if feature not in payload.features]
    if missing:
        raise HTTPException(status_code=422, detail={"missing_features": missing})

    try:
        row = np.asarray([[float(payload.features[name]) for name in FEATURES]], dtype=np.float32)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="All ML feature values must be numeric") from exc

    probabilities = classifier.predict_proba(row)[0]
    class_idx = int(np.argmax(probabilities))
    predicted_class = CLASSES[class_idx]
    confidence = float(probabilities[class_idx])

    scaled = scaler.transform(row)
    reconstructed = autoencoder.predict(scaled)
    reconstruction_error = float(np.mean(np.square(scaled - reconstructed)))
    # Score grows beyond threshold but is capped. 1.0 means strongly outside the learned normal region.
    anomaly_score = min(1.0, reconstruction_error / max(AE_THRESHOLD * 2.5, 1e-9))

    base_risk = CLASS_BASE_RISK[predicted_class]
    xgb_risk = base_risk * (0.55 + 0.45 * confidence)
    rule_score = float(payload.rule_score)
    final_risk = float(np.clip(0.35 * rule_score + 0.40 * xgb_risk + 0.25 * (anomaly_score * 100.0), 0.0, 100.0))

    probability_map = {CLASSES[i]: round(float(probabilities[i]), 6) for i in range(len(CLASSES))}
    return {
        "model": "FortressAuth Hybrid ML v1",
        "classification": predicted_class,
        "confidence": round(confidence, 6),
        "probabilities": probability_map,
        "reconstruction_error": round(reconstruction_error, 6),
        "anomaly_score": round(anomaly_score, 6),
        "rule_score": round(rule_score, 2),
        "xgboost_risk": round(xgb_risk, 2),
        "risk_score": round(final_risk, 2),
        "severity": band(final_risk),
        "indicators": explain(payload.features, predicted_class),
        "automatic_block": False,
    }
