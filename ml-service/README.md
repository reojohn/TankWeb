# FortressAuth ML Threat Engine

This optional service adds two ML signals without becoming an authentication dependency:

1. **XGBoost** classifies behavioral telemetry into NORMAL, BRUTE_FORCE, CREDENTIAL_STUFFING, RECONNAISSANCE, WEB_ATTACK, MFA_ABUSE, or SESSION_ABUSE.
2. A compact **feed-forward autoencoder** learns the normal behavioral baseline and returns an anomaly score.
3. FortressAuth combines ML results with its existing deterministic security-rule score.

The service receives numeric metadata only. It never needs passwords, Personal ID QR values, CSRF tokens, cookies, authorization headers, or session IDs.

## Training data

`training/train_models.py` generates 35,000 training observations, 7,000 independent validation observations, and 10,500 distribution-shifted hold-out test observations. The generated attack examples are explicitly synthetic and are intended for course-project demonstration, not production incident prevalence claims.

Run training from this directory with:

```bash
python training/train_models.py
python training/export_evidence.py
python -m unittest discover -s tests -v
```

The committed model artifacts are already produced in `models/`.

## Phase 2 live inference security and telemetry (November 2026)

The FastAPI process now **requires** a private 24+ character `ML_SERVICE_TOKEN`; `/predict` and `/model-info` always require its bearer header. The loopback-only Windows launcher starts `start_local.py`, which reads the root `.env` first. Run `python -c "import secrets; print(secrets.token_hex(32))"` to generate a token. The inference request validates the exact 20 numeric features, their ranges and nested time-window counts. Predictions include a model version, trace ID, feature digest and observed threshold indicators; those indicators are **not causal feature attribution**. `sql/ml_request_telemetry.sql` adds the optional durable security telemetry table. See `IT113_PHASE2_IMPLEMENTATION.md` for setup and tested limitations.

## Run locally

```bash
pip install -r requirements.txt
python start_local.py
```

Then configure FortressAuth:

```env
ML_SERVICE_ENABLED=true
ML_SERVICE_URL=http://127.0.0.1:8001
ML_SERVICE_TOKEN=use-the-same-private-token-on-both-services
```

If the service is unavailable, FortressAuth continues using all existing password, Personal ID, session, CSRF, rate-limit, ban, request-signature, and audit controls.

## Phase 1 evaluation methodology

- Each of the seven behavior classes has 5,000 training, 1,000 validation, and 1,500 test observations.
- The synthetic generator enforces basic count/time-window invariants; every split is checked before fitting.
- XGBoost fits **training data only**; per-class precision, recall and F1 are computed on the untouched test set.
- Autoencoder fits **normal training data only**. Its anomaly cutoff is the 99th percentile of reconstruction errors on **normal validation data only**. Test set records have no role in setting the cutoff.
- `data/training_report.json` and `models/model_metadata.json` contain the reported metrics. `public/assessment/` contains an intentionally public, read-only copy of those metrics and **synthetic test examples only**. This public output contains no user records, logs, or security tokens.
- The synthetic train/test class balance and limited artificially introduced distribution shift make measured performance **not representative of real-world deployment accuracy**. Validate real-world performance only on suitably authorized, labeled telemetry.
