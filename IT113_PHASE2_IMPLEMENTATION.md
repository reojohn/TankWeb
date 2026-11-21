# FortressAuth IT113 — Phase 2 Implementation and Verification

**Status:** source-level implementation completed and tested locally on 2026-11-20. Applying the PostgreSQL migration and testing the actual cloud deployment still require the project's private database credentials and deployed services. Phase 3 interface/report upgrades are not included.

## Changes implemented

1. **Fail-closed ML authorization.** The FastAPI process refuses to start without a strong non-placeholder `ML_SERVICE_TOKEN` (24–256 allowed ASCII characters). Its `/predict` and `/model-info` routes require the bearer token. Anonymous `/health` returns only `{ "status": "ok" }`. The public `/assessment/` pages remain static and login-free. The original privileged PHP administration routes still require their existing controls.
2. **Client/service token synchronization.** `ml-service/start_local.py` reads the private root `.env` before starting Uvicorn, so the Windows launcher and PHP use the same token. Docker Compose requires the token rather than silently passing an empty string. PHP fails without transmitting telemetry when the token is absent or invalid, and requires HTTPS for remote ML URLs (local loopback / Docker service HTTP is allowed).
3. **Validated inference features.** FastAPI accepts only the 20 configured numeric features and a 0–100 `rule_score`. It rejects unknown/missing keys, booleans, invalid ranges, NaN/Infinity, inconsistent rolling-window counts and invalid trace IDs with HTTP 422.
4. **Durable minimized request telemetry.** `sql/ml_request_telemetry.sql` creates a 24-hour rolling source for request method, path-without-query, IP, timestamp, random request ID and hashed user agent. `src/ml_threat.php` writes both PostgreSQL and local backup, preferring DB time windows when present. No request bodies, cookies, credentials, raw user-agent strings or QR values are stored in this new table. Existing `security_events` is preferred for audit features, with a bounded local audit fallback.
5. **Traceable assessment.** Each real or queued prediction stores an opaque request trace ID, stable model-file version fingerprint, feature digest, numeric threshold-trigger explanations and feature-source provenance (UTC observation window, DB/local source, counts, capped request/event IDs). Explanations are **threshold indicators**, not proof that a feature causally produced an XGBoost prediction.
6. **Safe error/queue handling.** The ML client verifies the returned trace ID, numeric risk and confidence, category and model version before accepting a response. If inference is unavailable, a timestamped numeric snapshot is queued for retrospective analysis; queue replay is never itself used for live enforcement.
7. **Conservative defaults.** The academic build defaults `ML_ASSISTED_ENFORCEMENT=false` for new configurations. Existing deterministic IP-ban, CSRF, rate-limit and authentication controls are untouched. If a source window is truncated, PHP also forces the ML result to advisory-only regardless of the enforcement setting.

## Installation over the Phase 1 + Wolf-logo build

1. Extract the changed-files ZIP. Copy the **contents of `TankWeb-v3/`** onto the same folder in which you installed Phase 1 and the Wolf Logo Premium UI update. Confirm file replacement. The ZIP does not contain your `.env`, any database password, model artifacts, or any image assets.
2. **Keep your actual root `.env` private.** Set the existing database connection values and:

   ```env
   ML_SERVICE_ENABLED=true
   ML_SERVICE_URL=http://127.0.0.1:8001
   ML_SERVICE_TOKEN=<paste your own random token here>
   ML_ASSISTED_ENFORCEMENT=false
   ML_QUEUE_ENABLED=true
   ```

   Generate a random token locally using `python -c "import secrets; print(secrets.token_hex(32))"`. Copy the result **without angle brackets** into the root `.env`. Never share that token, commit it, or put it in a browser-side JavaScript variable. On separate hosting, place the same value in both the PHP and ML service environment settings; use an HTTPS ML URL.
3. Run `sql/ml_request_telemetry.sql` **once in the Supabase PostgreSQL SQL Editor** using a migration/owner account. Also confirm prior `sql/persistent_security_history.sql` and `sql/ml_analysis_queue.sql` have been applied. Do not run SQL migrations as the low-privilege runtime user. Grant that runtime DB role SELECT, INSERT, DELETE for the new table and USAGE/SELECT on its sequence as needed; the migration file contains illustrative comments.
4. If dependencies are not installed, run `cd ml-service` and `python -m pip install -r requirements.txt`. Then from the project root launch `Start FortressAuth.bat`. The private ML API binds to `127.0.0.1:8001`, and the login-free assessment remains `http://127.0.0.1:8082/assessment/`.
5. In Docker Compose, define the same private token in root `.env` and use `docker compose up --build`. A missing token correctly prevents startup rather than allowing unauthenticated prediction requests.

### Expected behavior and limitations

- **Public assessment** continues showing **Phase 1 synthetic model metrics and examples**. Phase 2 does not make this public dashboard show private live security events; that belongs to the access-controlled Phase 3 integration.
- **Real telemetry** is collected for PHP-handled application requests where `ML_SERVICE_ENABLED=true`, including existing protected routes. Loading static assessment HTML/CSS/JS alone does not generate login telemetry. The original privileged login is preserved as a data source, but is not required to view the public assessment.
- Before the database migration, the system remains operational with bounded **local-file fallback**, but local files can be lost on ephemeral hosting and cannot be called durable.
- If database writes fail, the file backup remains, but the PostgreSQL query for that window may temporarily be incomplete; the source label records which was used. Existing logs are not automatically backfilled.
- We did **not** run against your live Supabase/Render/Vercel deployment or generate real attack traffic. Actual production accuracy, availability, and false-positive rate are not established by the synthetic 96.76% Phase 1 accuracy.
- IP addresses and event IDs are used privately for authorized security monitoring; restrict access, apply retention, and never expose the admin prediction history as a public endpoint.
- The ML service will refuse an unprotected remote `http://` URL to avoid leaking bearer tokens on a public network. Use `https://` for a hosted ML API, or the allowed local Docker/loopback HTTP addresses.

## Verification performed

- **13/13 tests passed**: 6 Phase 1 split/data/model reproducibility tests, 5 Phase 2 FastAPI contract/auth/input/evidence tests, and 2 isolated PHP telemetry/log-bounding tests.
- **Local cross-process smoke test passed**: PHP securely called a real Uvicorn FastAPI instance with an ephemeral test token, receiving a valid XGBoost + autoencoder prediction and matching trace/model fields.
- PHP `ml_threat.php` syntax validation passed. No PHP database migration was attempted on a real cloud database.

Run Python tests with `cd ml-service && python -m unittest discover -s tests -v`. The PHP fallback tests auto-skip if PHP CLI is absent.

## Next: Phase 3

Add authenticated live assessment and model evaluation views, connect event provenance and model-version summaries to the existing premium dashboard, update report exports, and keep the synthetic public demo clearly separated from private live data.
