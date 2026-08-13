# FortressAuth Hybrid ML Integration

## What was added

The existing FortressAuth security controls remain authoritative. A separate optional ML service now adds behavioral intelligence through three signals:

1. **Deterministic rule score** from existing FortressAuth authentication/request telemetry.
2. **XGBoost classifier** for known behavioral patterns: NORMAL, BRUTE_FORCE, CREDENTIAL_STUFFING, RECONNAISSANCE, WEB_ATTACK, MFA_ABUSE, and SESSION_ABUSE.
3. **Autoencoder anomaly score** for behavior that differs from the learned normal baseline.

The final advisory risk score uses the project configuration:

- 35% deterministic rule signal
- 40% XGBoost risk signal
- 25% autoencoder anomaly signal

Risk bands are NORMAL (0–29), WATCH (30–49), SUSPICIOUS (50–69), HIGH (70–84), and CRITICAL (85–100).

## Security boundary

The ML engine is **not an authentication factor** and is **not allowed to automatically ban users/IPs**. Password → Personal ID QR remains unchanged. If the ML service fails, FortressAuth keeps enforcing its original CSRF, rate-limit, IP-ban, session, request-signature, account, and audit controls.

No password value, QR value, CSRF token, cookie, authorization header, session ID, API key, or secret is sent to ML. Only numeric behavior metadata is used.

## Synthetic training dataset

`ml-service/training/train_models.py` generates 35,000 labeled synthetic training rows and a separate 10,500-row shifted hold-out set. The hold-out profiles deliberately use changed ranges so the evaluation is not a simple copy of the training generator ranges.

The bundled training run produced approximately:

- XGBoost accuracy: 96.8%
- XGBoost macro F1: 96.8%
- Autoencoder normal false-positive rate: 1.0%
- Autoencoder anomaly recall on the synthetic shifted hold-out: 100%

These metrics describe the generated course-project dataset only. They are not claims of real-world production detection performance.

## Files

- `src/ml_threat.php` — PHP telemetry aggregation, rule score, fail-safe ML client, latest prediction storage
- `ml-service/app.py` — FastAPI inference service
- `ml-service/models/` — trained XGBoost and autoencoder artifacts
- `ml-service/training/train_models.py` — reproducible synthetic dataset generator/trainer
- `ml-service/data/synthetic_security_dataset.csv` — generated labeled training dataset
- `ml-service/data/training_report.json` — evaluation report
- `docker-compose.yml` — local two-service startup
- `public/threats.php` — Hybrid Machine Learning threat panel
- `public/security_controls.php` — ML architecture/runtime status

## Local setup without Docker

Start FortressAuth as usual after configuring the database in `.env`.

Start the ML service in another terminal:

```bash
cd ml-service
pip install -r requirements.txt
ML_SERVICE_TOKEN=choose-a-private-token uvicorn app:app --host 127.0.0.1 --port 8001
```

Add matching settings to the root `.env`:

```env
ML_SERVICE_ENABLED=true
ML_SERVICE_URL=http://127.0.0.1:8001
ML_SERVICE_TOKEN=choose-a-private-token
ML_TIMEOUT_MS=400
ML_MIN_LOG_RISK=30
```

Then browse FortressAuth. `Threat Center` will display the latest hybrid ML result.

## Docker Compose

With database variables and `ML_SERVICE_TOKEN` in the root `.env`:

```bash
docker compose up --build
```

The root PHP image deliberately excludes `ml-service/`; the ML engine has its own image and process.

## Separate hosting/deployment

Deploy the PHP application exactly as before. Deploy `ml-service/` as a second small Python web service. Set the PHP environment to the private/internal ML URL whenever the hosting platform supports private networking. Use the same strong `ML_SERVICE_TOKEN` on both services.

Do not expose the model endpoint without a token on a public deployment. If the service cannot be reached, FortressAuth fails open **only for ML enrichment**, never for authentication/security enforcement.

## Demonstration ideas

Normal browsing should normally produce a low score and NORMAL classification. Controlled test traffic can demonstrate patterns such as repeated password failures, many usernames from one source, sensitive path probing, repeated Personal ID failures, abnormal CSRF/session rejection, and unusually broad path enumeration.

For defense wording, describe the training data as **synthetic/simulated security telemetry created for a controlled project demonstration**.
