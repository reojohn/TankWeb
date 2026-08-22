# FortressAuth v3: Vercel Frontend + Render PHP Backend

## Target architecture

- **Vercel:** public origin and static frontend CDN
- **Render:** PHP security backend, sessions, APIs, reconnaissance handling, report generation
- **Supabase:** PostgreSQL storage
- **ML service:** separate service, unchanged

The browser uses the Vercel domain. `scripts/build-vercel.mjs` copies only browser-safe static assets into `vercel-dist`. Requests not satisfied by that static output are rewritten by `vercel.json` to the Render PHP backend.

This keeps `/login.php`, `/api/v3.php`, `/api/v3_fragment.php`, security feeds, report exports, `/app/index.php`, and intentionally nonexistent reconnaissance paths under PHP enforcement.

## 1. Deploy the v3 backend on Render first

Create a Render Web Service for v3.

Recommended settings:

- Runtime / Language: **Docker**
- Dockerfile path: `./Dockerfile`
- Health check path: `/healthz.php`
- Branch: the v3 deployment branch
- Copy the required production environment variables from the working backend.

Important backend values include:

```env
APP_ENV=production
TRUST_PROXY_HEADERS=true
COOKIE_SECURE=true
SESSION_IDLE_TIMEOUT=900
SESSION_ABSOLUTE_TIMEOUT=28800
SESSION_BIND_USER_AGENT=true
```

Also configure the required DB/Supabase, ML, queue, reconnaissance-defense, and `FORTRESS_VAULT_FLAG` values on Render. Do not place backend secrets in Vercel.

## 2. Point Vercel at the correct Render origin

The repository uses `vercel.json`, not `vercel.ts`.

Before deploying a different backend hostname, update the rewrite destination in `vercel.json`:

```json
{
  "source": "/:path*",
  "destination": "https://YOUR-V3-BACKEND.onrender.com/:path*"
}
```

The current repository does not read a `FORTRESS_BACKEND_ORIGIN` environment variable, so setting that variable alone will not change the proxy destination.

Keep the Vercel Root Directory at the repository root. Its build command runs:

```text
node scripts/build-vercel.mjs
```

The generated `vercel-dist` contains browser-safe static files only. PHP source, `.env` files, logs, and backend secrets remain on Render.

## 3. Why PHP sessions still work

The frontend calls same-origin paths such as `/api/v3.php`, `/api/v3_fragment.php`, and `/login.php`. The browser talks to the Vercel hostname and Vercel reverse-proxies dynamic requests to Render. Keep `TRUST_PROXY_HEADERS=true` and `COOKIE_SECURE=true` on Render.

## 4. Recon and SQLi testing

Test only against your own FortressAuth deployment.

Harmless nonexistent-path examples:

```text
https://YOUR-VERCEL-DOMAIN/dashboad.php
https://YOUR-VERCEL-DOMAIN/randomtest
```

Because those paths are absent from `vercel-dist`, the request reaches the Render backend and FortressAuth reconnaissance handling.

For SQLi testing, submit controlled test input through FortressAuth's own endpoints. If an edge firewall is enabled, remember that a deny rule can block the request before PHP can record it.

Do not perform denial-of-service or high-volume testing against hosting infrastructure.

## 5. Verify after deployment

1. Open `https://YOUR-VERCEL-DOMAIN/login.php`.
2. Log in normally.
3. Confirm the URL becomes `/app/#/overview`.
4. Navigate between pages and confirm the persistent React shell remains responsive.
5. Keep `/app/#/threats` open and test a harmless nonexistent path such as `/dashboad.php` in another tab.
6. Confirm the branded reconnaissance/404 response appears.
7. Confirm Threats, Security Logs, and notifications update as expected.
8. Test logout and logged-out direct access to `/app/#/threats`.
9. Test report export and Current Operator actions.
10. Test Crown Jewel only when you intentionally want to record reaching the pentest objective.

## Local development

```bat
php -S localhost:8082 -t public
```

Vercel-specific output does not alter the local PHP workflow.

## Updating the UI

The live/deployed parity runtime is the committed content under `public/app/`. `BUILD_REACT_V3.bat` now performs a safe source-validation build into `react-build/` and intentionally does not empty `public/app/`, because that directory also contains the PHP auth gate and vendored runtime files.

When changing the current production UI, keep the relevant `frontend/src` source and the tested `public/app` parity runtime in sync until the migration is completed and a single generated build pipeline replaces the parity bundle.
