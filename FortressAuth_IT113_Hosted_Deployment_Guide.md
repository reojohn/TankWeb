# FortressAuth IT113 — Hosted Deployment Verification (2026-11-21)

## Status

**Local implementation:** verified from user-provided browser screenshots and JSON/CSV/PDF evidence. **Online implementation:** not yet verified live. Attempts to access the historical Vercel and Render URLs from the assistant's web source were inconclusive (not accessible to that source); this is *not* proof that either site is offline.

## Verified code configuration

The latest uploaded project ZIP `TankWeb-v3(2).zip` contains:

- `vercel.json`: static Vercel build with a catch-all external rewrite to `https://tankweb-v3.onrender.com/:path*`.
- `scripts/build-vercel.mjs`: produces the static Vercel output in `vercel-dist/`.
- `Dockerfile`: PHP 8.4/Apache, PostgreSQL PDO, document root `public/`.
- `ml-service/Dockerfile`: Python 3.12, FastAPI/Uvicorn, port 8000, trained XGBoost and autoencoder model files.
- `public/it113_demo_infer.php` and `public/it113_demo_history.php`: dynamic PHP endpoints, *not* part of the Vercel static bundle.
- `.dockerignore` and `.gitignore`: exclude `.env` and other private data. Confirm those exclusions remain intact before deploying.

### Static build verification performed

`node scripts/build-vercel.mjs` completed successfully in an isolated copy of browser-safe files. The generated static bundle contains the assessment dashboard, `it113-live.js`, model metadata, evaluation PDF, and wolf logo. **No `.php` or `.env` files were present in the generated Vercel output.** This validates static packaging only; it does not validate online routing or live API deployment.

## Step 1: Verify deployment URLs

In Vercel, find **Project -> Deployments -> Visit** and copy the current Production URL. In Render, find the deployed **PHP Web Service URL**. The versions in the ZIP and script are historical defaults; use your real current URLs if different.

Run the included read-only Windows PowerShell script after inspecting it:

```powershell
.\FortressAuth_IT113_Hosted_Readonly_Check.ps1 -VercelUrl 'https://YOUR-VERCEL-URL' -PhpRenderUrl 'https://YOUR-PHP-RENDER-URL'
```

The script sends only HTTP GET requests. It does not call model prediction or update the database. In particular, GET `/it113_demo_infer.php` is **expected to return HTTP 405**. This is a useful routing check: static Vercel alone cannot execute PHP.

If PowerShell prevents running downloaded scripts, leave your system's security policy in place and use the equivalent individual `Invoke-WebRequest` calls instead. Do not disable Avast or browser protections for these checks.

## Step 2: If the backend is not deployed or is outdated

1. Commit **source code only** to the private Git repository. Do not include `.env`, DB passwords, token values, local databases, logs, or exported user data. Check the repo's history for older secrets. If a secret was ever committed, rotate it.
2. Create or update a **Render PHP Web Service** based on the **root Dockerfile**. Render's `PORT` routing must reach Apache's HTTP port; check the service logs and health/start status. Use server environment variables for all private settings.
3. Create or update the separate **Render ML Web Service** based on `ml-service/Dockerfile` with root directory `ml-service`. Set a strong `ML_SERVICE_TOKEN` only through Render's private environment settings. Do not publish the token or put it in Vercel frontend variables.
4. Configure the PHP Render service with the **same** `ML_SERVICE_TOKEN`, `ML_SERVICE_ENABLED=true`, and an `ML_SERVICE_URL` that resolves to the deployed ML service **from the Render PHP container**, not `127.0.0.1:8001`. Ideally, use secure private networking when supported by the service plan and region.
5. Configure database `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS`, and `DB_SSLMODE=require` **only on the PHP backend**. The healthy Supabase session pooler you tested locally can be used if the deployed PHP service can reach it; never expose credentials to Vercel JavaScript.
6. Configure `IT113_DEMO_ALLOWED_ORIGINS` with the **exact production Vercel origin** if browser requests sent via Vercel rewrites reach PHP with a different Host header and are being rejected. Confirm Origin and `Sec-Fetch-Site` behavior from actual safe logs before changing these checks. Do not use a wildcard.
7. Deploy the Vercel static frontend with `node scripts/build-vercel.mjs` and output directory `vercel-dist`. Keep PHP routes handled by the backend rewrite.

## Safety requirement before enabling public dynamic inference

The supplied PHP inference endpoint is limited to curated synthetic examples and bounded numeric feature vectors, but its **per-IP rate limiter is file-based and local to an instance**. Behind a proxy, users may share an apparent IP address, and across multiple instances these limits are not globally enforced. Therefore do **not** enable `IT113_PUBLIC_DEMO_ENABLED=true` and `IT113_DEMO_PERSISTENCE_ENABLED=true` on an openly accessible production service until a reliable shared/edge rate limit, request controls, and appropriate resource/billing limits are in place. Local testing can keep its existing settings. If necessary, leave the hosted AI demo unavailable and present the fully dynamic workflow locally for the course evaluation.

The academic dashboard does **not** require login; older administrative and operational routes must remain access controlled. Do not expose real operational logs or automatic blocking controls through the demo.

## Step 3: Live verification checklist

- [ ] Vercel `/assessment/` loads with the premium theme and wolf assets.
- [ ] Vercel `/assessment/it113-live.js` loads with HTTP 200 (latest version).
- [ ] Vercel `/it113_demo_infer.php` returns **HTTP 405 for GET**, indicating the PHP route is being proxied (do not POST until hardened).
- [ ] Render's PHP `/it113_demo_infer.php` returns **HTTP 405 for GET**.
- [ ] `it113_demo_history.php` responds with expected enabled/disabled status and no secrets.
- [ ] The deployed ML service's `/health` returns `{"status":"ok"}` when intentionally accessible. Do not expose `/predict` unauthenticated.
- [ ] PHP/ML backend URLs and shared token are configured privately; root `.env` is not committed.
- [ ] Full hosted inference and persistence tested only after security controls are verified; capture evidence for the final report.

## Next action

Run the read-only probe with the current public Vercel and Render PHP URLs and share only the resulting status table (not your environment settings). This tells us whether the next change belongs to **Vercel routing**, **PHP deployment**, **ML connectivity**, or **production security controls**.
