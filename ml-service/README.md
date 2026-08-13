# FortressAuth ML Threat Engine

This optional service adds two ML signals without becoming an authentication dependency:

1. **XGBoost** classifies behavioral telemetry into NORMAL, BRUTE_FORCE, CREDENTIAL_STUFFING, RECONNAISSANCE, WEB_ATTACK, MFA_ABUSE, or SESSION_ABUSE.
2. A compact **feed-forward autoencoder** learns the normal behavioral baseline and returns an anomaly score.
3. FortressAuth combines ML results with its existing deterministic security-rule score.

The service receives numeric metadata only. It never needs passwords, Personal ID QR values, CSRF tokens, cookies, authorization headers, or session IDs.

## Training data

`training/train_models.py` generates 35,000 synthetic training observations and a separate 10,500-row shifted hold-out set. The generated attack examples are explicitly synthetic and are intended for course-project demonstration, not production incident prevalence claims.

Run training from this directory with:

```bash
python training/train_models.py
```

The committed model artifacts are already produced in `models/`.

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8001
```

Then configure FortressAuth:

```env
ML_SERVICE_ENABLED=true
ML_SERVICE_URL=http://127.0.0.1:8001
ML_SERVICE_TOKEN=use-the-same-private-token-on-both-services
```

If the service is unavailable, FortressAuth continues using all existing password, Personal ID, session, CSRF, rate-limit, ban, request-signature, and audit controls.
