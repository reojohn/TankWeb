# FortressAuth IT113 — Dynamic Assessment Upgrade

**Patch base:** `TankWeb-v3(1).zip` plus `FortressAuth_IT113_Premium_LoginFree_ChangedFiles.zip` (the latest approved login-free academic UI).  
**Delivery:** changed files only, with their exact `TankWeb-v3/` paths.  
**Status:** local model + PHP inference and desktop/mobile preview tested; Supabase migration/live persistence and hosted deployment still require verification on your account.

## New dynamic capabilities

- Choose any curated held-out synthetic example and run the **real** authenticated XGBoost/autoencoder model.
- Download a **20-column numeric CSV template**, load 1–8 simulated rows (16 KB maximum), validate relationships and numeric bounds, then run fresh model inference one row at a time. Free-form text, file uploads to the backend, usernames, passwords, raw network logs, IP addresses, and arbitrary attack traffic are not accepted. CSV rows are never uploaded as files; the browser sends only bounded numeric feature objects.
- Review recent synthetic assessments, classification, confidence, risk, anomaly score, supporting thresholds, evidence trace ID, and model version in Threat Findings.
- Track academic mitigation statuses `OPEN → INVESTIGATING → MITIGATED → RESOLVED` (plus reopen / add a note), with revision protection and event history **when database persistence is enabled**. No automatic blocks or security actions.
- Dynamically recalculate classification distributions, labeled-example match counts, and follow-up statuses from actual inference results. Saved *held-out* model evaluation remains a separate, clearly labeled metric.
- Export the current findings as JSON or CSV, and use the Reports page's **Print current report / PDF** action. The older static model-evaluation PDF remains available for comparison.
- Preserve the original wolf-and-dagger artwork, its animations, nine navigation sections, and the login-free academic dashboard; **legacy privileged admin routes are unchanged**.

## 1. Install changed files

1. Make a private backup of your latest cumulative `TankWeb-v3` folder.
2. Extract the patch ZIP and copy the contents of its `TankWeb-v3/` folder into your own `TankWeb-v3/`, keeping relative paths. Replace matching files. **Do not replace the whole project.**
3. Preserve your root `.env` and existing trained models. This patch deliberately contains no `.env` file, credentials, runtime logs, or database dumps.
4. Run the model and PHP service as before using `Start FortressAuth.bat`.

## 2. Apply the new SQL schema for private academic history

Use the **healthy replacement Supabase project** `FortressAuth-IT113` under `codeauth Org`, not the original failed project. The Phase 1–4 core migrations are already installed on your new project. This upgrade adds **two independent tables** and does not delete or change any legacy data.

1. Open Supabase → **SQL Editor** in `FortressAuth-IT113`.
2. Paste the entire `TankWeb-v3/sql/it113_dynamic_assessments.sql` and run it once.
3. The script creates `public.it113_demo_assessments` and `public.it113_demo_case_events`; it enables RLS and revokes direct API roles (`anon` and `authenticated`).
4. Verify using this **read-only query**:

```sql
SELECT c.relname AS table_name, c.relrowsecurity AS rls_enabled,
       has_table_privilege('anon', c.oid, 'SELECT') AS anon_select,
       has_table_privilege('authenticated', c.oid, 'SELECT') AS authenticated_select
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname IN
  ('it113_demo_assessments','it113_demo_case_events');
```

Expected: both tables present, RLS true, both SELECT privileges false.

## 3. Configure only the private backend environment

In your existing private root `.env`, **update** the existing keys if present; do not add duplicates:

```dotenv
ML_SERVICE_ENABLED=true
ML_SERVICE_URL=http://127.0.0.1:8001
ML_SERVICE_TOKEN=YOUR_EXISTING_PRIVATE_ML_TOKEN
IT113_PUBLIC_DEMO_ENABLED=true
IT113_DEMO_PERSISTENCE_ENABLED=true
ML_ASSISTED_ENFORCEMENT=false
```

`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS`, and `DB_SSLMODE` should stay set to your working **new Supabase Session Pooler** configuration. Use your actual secret password. **Never send or publish it.** Local `ML_SERVICE_URL` works only when PHP and ML run on the same computer; for separate cloud services use HTTPS and private token authentication.

**Keep `IT113_DEMO_PERSISTENCE_ENABLED=false` until the SQL script succeeds.** With persistence disabled or Supabase unavailable, inference continues normally but history stays in the browser only; this behavior is labeled in the UI.

The demo is login-free, but persistence uses a random 256-bit HttpOnly, SameSite=Strict cookie; the database stores only a one-way digest and sanitized prediction metadata. This is **not an authentication system** or a substitute for protecting real security records. Server-side DB secrets and ML tokens are never delivered to the browser.

### Windows environment override reminder

Your Windows PowerShell session previously had old `DB_*` variables overriding `.env`. If that happens again, **close the old server windows and restart the launcher**; if needed clear only the current shell's old environment variables, without deleting `.env`:

```powershell
'DB_HOST','DB_PORT','DB_NAME','DB_USER','DB_PASS','DB_SSLMODE' | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
```

## 4. Verify without leaving test rows behind

Open PowerShell in your `TankWeb-v3` root:

```powershell
php scripts/verify_it113_dynamic_db.php
python -m unittest discover -s ml-service/tests -v
php tests/test_it113_phase3_completion.php
php tests/test_it113_mitigation_workflow.php
```

The PHP database self-check performs an INSERT, a status update, a linked history INSERT/SELECT and a **ROLLBACK** on only the new academic tables. It does not affect production security history.

Then open `http://127.0.0.1:8082/assessment/` in your browser:

1. **AI Defense:** select a curated example and click Run model analysis; check the dynamic classification, trace ID, and whether the badge reads `PRIVATE DATABASE` or `BROWSER ONLY`.
2. **Dataset CSV:** download the template, load a 1–8-row synthetic CSV, click Analyze CSV rows, and confirm the number of successful analyses. The per-IP demo limit is **10 per minute, 100 per day** on the local instance; wait instead of retrying if the limit is reached.
3. **Threat Findings:** click Refresh saved history. With persistence enabled, reload the page and confirm your synthetic record remains present. Select a flagged finding, change `OPEN → INVESTIGATING`, add a synthetic analyst note and save. Refresh again to see it and its event history.
4. **Security Analytics:** confirm that class counts and mitigation counts change after new runs/status updates. The large held-out model evaluation figure must **not** change.
5. **Research Reports:** download updated JSON and CSV, then open Print current report / PDF and save as a PDF through the browser.
6. **Clear my demo history** removes only records for the current browser's demo session (when persistence is enabled). It never removes users, live security events, existing ML predictions, or protected mitigation cases.

## 5. Hosting and security requirements

- Vercel hosts static UI; `/it113_demo_infer.php` and `/it113_demo_history.php` must execute on your PHP backend (existing Render rewrite). Confirm the **deployed** routes work after deployment; local results do **not** prove cloud success.
- Turn on public inference and persistence on the PHP backend **only after** verifying cloud throttling. The existing local `flock` file limiter is per-instance and does **not** provide a global guarantee across scaled/ephemeral cloud instances. Configure a real provider/edge limit, monitoring, and a resource budget before exposing anonymous ML inference publicly. If that is not configured, keep `IT113_PUBLIC_DEMO_ENABLED=false` in production and demonstrate locally.
- If the origin seen by Render differs from the browser's host, set `IT113_DEMO_ALLOWED_ORIGINS=https://YOUR-EXACT-DOMAIN` on the PHP backend. Do not use a wildcard. Existing privileged admin URLs are still private.
- Prefer a narrowly privileged server-side PostgreSQL role for the two new academic tables in production, instead of broad `postgres` owner credentials; do not grant public Data API roles access.
- Academic data may be removed after submission using the optional 30-day retention command commented in the migration. No personal-identifying source data should be uploaded.

## Honest scope and limitations

This is a **dynamic interactive AI/ML assessment application**, not an autonomous real-time scanner of arbitrary network traffic. Users can analyze their own **simulated numeric security behavior** or the vetted held-out examples. Continuous real-world monitoring would require a separately authorized telemetry source, consent, retention and privacy protections, and further validation on real-world data.

The trained models, held-out evaluation metrics, and limitations remain unchanged. Newly uploaded unlabeled CSV rows do **not** receive invented true labels or get counted as a new accuracy benchmark. Existing model classification accuracy remains a finding on synthetic data only.

## Checks performed on this patch

- All **32 Python regression tests** passed (prior 26 plus six new dynamic-contract tests).
- Existing 14-assertion protected Threat Findings and 27-assertion mitigation workflow PHP suites passed.
- All changed PHP scripts passed `php -l`; new browser JavaScript passed `node --check`.
- Local **real PHP → trained XGBoost/autoencoder** tested for curated and numeric-only input with expected output and trace; invalid input and unauthorized Origin were rejected; history API properly reported optional persistence disabled.
- Browser UI preview (mock HTTP responses) passed on **1440 px desktop and 390 px mobile** with CSV input, new inference results, case-status interface, no JavaScript errors and no horizontal overflow.
- `node scripts/build-vercel.mjs` passed; static Vercel output contains no PHP source.

**Not verified here:** your private Supabase migration and its durable read/write behavior, hosted public deployment, global edge rate limiting, or production login-free access. Verify these on your own environment before describing them as completed.
