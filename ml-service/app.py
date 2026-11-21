"""FortressAuth authenticated, numeric-only ML inference service.

No credentials, usernames, paths or raw security logs are accepted by /predict.
The public /health endpoint intentionally discloses minimal information.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
from pathlib import Path

import joblib
import numpy as np
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "models"
METADATA = json.loads((MODEL_DIR / "model_metadata.json").read_text(encoding="utf-8"))
FEATURES = list(METADATA["dataset"]["features"])
CLASSES = list(METADATA["dataset"]["classes"])
AE_THRESHOLD = float(METADATA["autoencoder"]["threshold_p99"])

# Refuse to operate in an unauthenticated state, including with a placeholder.
SERVICE_TOKEN = os.getenv("ML_SERVICE_TOKEN", "").strip()
if (len(SERVICE_TOKEN) < 24 or len(SERVICE_TOKEN) > 256 or SERVICE_TOKEN.lower() in {
    "replace-with-a-random-private-token", "choose-a-private-token", "changeme"
} or SERVICE_TOKEN.lower().startswith(("replace_", "replace-", "choose-"))
    or not re.fullmatch(r"[A-Za-z0-9._~+/=\-]{24,256}", SERVICE_TOKEN)):
    raise RuntimeError("ML_SERVICE_TOKEN must be a private random value of at least 24 characters")

classifier = XGBClassifier()
classifier.load_model(MODEL_DIR / "xgboost_threat_classifier.json")
autoencoder = joblib.load(MODEL_DIR / "autoencoder.joblib")
scaler = joblib.load(MODEL_DIR / "autoencoder_scaler.joblib")
MODEL_VERSION = hashlib.sha256(
    (MODEL_DIR / "xgboost_threat_classifier.json").read_bytes()
    + (MODEL_DIR / "autoencoder.joblib").read_bytes()
).hexdigest()[:16]

CLASS_BASE_RISK = {
    "NORMAL": 8.0, "BRUTE_FORCE": 86.0, "CREDENTIAL_STUFFING": 92.0,
    "RECONNAISSANCE": 72.0, "WEB_ATTACK": 91.0, "MFA_ABUSE": 87.0,
    "SESSION_ABUSE": 90.0,
}

app = FastAPI(title="FortressAuth ML Threat Engine", version="2.0.0", docs_url=None, redoc_url=None)


def require_service_token(authorization: str | None) -> None:
    expected = f"Bearer {SERVICE_TOKEN}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


class PredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    features: dict[str, StrictFloat | StrictInt]
    rule_score: float = Field(default=0.0, ge=0.0, le=100.0, allow_inf_nan=False)
    trace_id: str | None = Field(default=None, min_length=12, max_length=64, pattern=r"^[a-fA-F0-9-]+$")


def validated_features(payload: PredictionRequest) -> dict[str, float]:
    missing = sorted(set(FEATURES) - set(payload.features))
    unknown = sorted(set(payload.features) - set(FEATURES))
    if missing or unknown:
        raise HTTPException(status_code=422, detail={"missing_features": missing, "unknown_features": unknown})
    values = {name: float(payload.features[name]) for name in FEATURES}
    if any(not math.isfinite(value) or value < 0.0 or value > 1_000_000 for value in values.values()):
        raise HTTPException(status_code=422, detail="Features must be finite, nonnegative and bounded")
    if not 0.0 <= values["post_ratio_5m"] <= 1.0:
        raise HTTPException(status_code=422, detail="post_ratio_5m must be between 0 and 1")
    if values["off_hours"] not in (0.0, 1.0):
        raise HTTPException(status_code=422, detail="off_hours must be 0 or 1")
    # Reject impossible relationships, not just malformed numeric types.
    if (values["requests_1m"] > values["requests_5m"]
        or values["unique_paths_5m"] > values["requests_5m"]
        or values["auth_endpoint_requests_5m"] > values["requests_5m"]
        or values["failed_logins_5m"] > values["failed_logins_15m"]):
        raise HTTPException(status_code=422, detail="Inconsistent rolling-window feature counts")
    return values


def band(score: float) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 50: return "SUSPICIOUS"
    if score >= 30: return "WATCH"
    return "NORMAL"


EVIDENCE_RULES = [
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


def explanation_evidence(feature_map: dict[str, float], prediction: str) -> list[dict]:
    candidates = []
    for name, threshold, description in EVIDENCE_RULES:
        value = feature_map[name]
        if value >= threshold:
            candidates.append((value / threshold, {
                "feature": name, "observed": round(value, 3),
                "threshold": threshold, "description": description,
            }))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return [item for _, item in candidates[:5]]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/model-info")
def model_info(authorization: str | None = Header(default=None)) -> dict:
    require_service_token(authorization)
    return {"model_version": MODEL_VERSION, "metadata": METADATA}


@app.post("/predict")
def predict(payload: PredictionRequest, authorization: str | None = Header(default=None)) -> dict:
    require_service_token(authorization)
    feature_map = validated_features(payload)
    row = np.asarray([[feature_map[name] for name in FEATURES]], dtype=np.float32)
    probabilities = classifier.predict_proba(row)[0]
    class_idx = int(np.argmax(probabilities))
    predicted_class = CLASSES[class_idx]
    confidence = float(probabilities[class_idx])

    scaled = scaler.transform(row)
    reconstructed = autoencoder.predict(scaled)
    reconstruction_error = float(np.mean(np.square(scaled - reconstructed)))
    anomaly_score = min(1.0, reconstruction_error / max(AE_THRESHOLD * 2.5, 1e-9))

    base_risk = CLASS_BASE_RISK[predicted_class]
    xgb_risk = base_risk * (0.55 + 0.45 * confidence)
    rule_score = float(payload.rule_score)
    final_risk = float(np.clip(0.35 * rule_score + 0.40 * xgb_risk + 0.25 * (anomaly_score * 100.0), 0.0, 100.0))

    evidence = explanation_evidence(feature_map, predicted_class)
    indicators = [item["description"] for item in evidence]
    if not indicators and predicted_class == "NORMAL":
        indicators = ["Behavior remains close to the learned normal baseline"]
    feature_digest = hashlib.sha256(json.dumps(feature_map, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "model": "FortressAuth Hybrid ML v2",
        "model_version": MODEL_VERSION,
        "trace_id": payload.trace_id or secrets.token_hex(12),
        "feature_digest": feature_digest,
        "classification": predicted_class,
        "confidence": round(confidence, 6),
        "probabilities": {CLASSES[i]: round(float(probabilities[i]), 6) for i in range(len(CLASSES))},
        "reconstruction_error": round(reconstruction_error, 6),
        "anomaly_score": round(anomaly_score, 6),
        "rule_score": round(rule_score, 2),
        "xgboost_risk": round(xgb_risk, 2),
        "risk_score": round(final_risk, 2),
        "severity": band(final_risk),
        "indicators": indicators,
        "indicator_evidence": evidence,
        "explanation_type": "threshold_indicator_not_causal_attribution",
        "automatic_block": False,
    }
