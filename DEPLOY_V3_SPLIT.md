# FortressAuth v3: Vercel Frontend + Render PHP Backend

## Target architecture

- **Vercel:** public origin and static frontend CDN
- **Render:** PHP security backend, sessions, APIs, reconnaissance handling, report generation
- **Supabase:** PostgreSQL storage
- **ML service:** unchanged

The browser should use the Vercel domain. Vercel serves only static files that exist in `vercel-dist`. Every other request is transparently rewritten to Render.

This means requests such as `/login.php`, `/api/v3.php`, `/security_alert_feed.php`, `/report_export.php`, `/app/`, and intentionally nonexistent recon paths are processed by the same PHP backend that already protects FortressAuth.

## 1. Deploy the v3 backend on Render first

Create a **new Web Service** for v3. Do not replace the stable v2 service yet.

Recommended settings:

- Runtime / Language: **Docker**
- Dockerfile path: `./Dockerfile`
- Health check path: `/healthz.php`
- Branch: your v3 deployment branch
- Copy your existing v2 production environment variables to the new service.

Important backend environment values:

```env
APP_ENV=production
TRUST_PROXY_HEADERS=true
COOKIE_SECURE=true
SESSION_IDLE_TIMEOUT=900
SESSION_ABSOLUTE_TIMEOUT=28800
SESSION_BIND_USER_AGENT=true
```

Also copy the existing DB, Supabase, ML, queue, recon-defense, and `FORTRESS_VAULT_FLAG` values. Do not put backend secrets in Vercel.

After Render is healthy, copy its HTTPS origin, for example:

```text
https://fortressauth-v3-backend.onrender.com
```

## 2. Deploy the same repository as a Vercel project

Keep the **Root Directory at the repository root**.

The repository contains `vercel.ts`, which configures:

- frontend dependency install
- safe static-only extraction from the already-tested React bundle
- reverse proxy to Render

Add this Vercel environment variable for Production (and Preview if you want previews):

```env
FORTRESS_BACKEND_ORIGIN=https://YOUR-V3-BACKEND.onrender.com
```

Do not add database passwords, Supabase service-role keys, ML tokens, or the vault flag to Vercel.

Deploy.

## 3. Why PHP sessions still work

React uses same-origin URLs such as `/api/v3.php` and `/login.php`. The browser talks only to the Vercel hostname. Vercel reverse-proxies those requests to Render, so the application does not need browser-side CORS or cross-site authentication changes.

Keep `TRUST_PROXY_HEADERS=true` and `COOKIE_SECURE=true` on Render.

## 4. Recon and SQLi testing

Test only against your own FortressAuth deployment.

Examples:

```text
https://YOUR-VERCEL-DOMAIN/dashboad.php
https://YOUR-VERCEL-DOMAIN/randomtest
```

These paths do not exist in the Vercel static output, so they are proxied to Render and handled by FortressAuth `security_probe.php` / request monitoring.

For SQLi testing, submit the test input through FortressAuth's own form/endpoints. If you enable Vercel's OWASP managed rules, use **Log** rather than **Deny** for the SQLi rule during the controlled classroom test, otherwise the edge firewall can stop the request before PHP can record it.

Do not perform denial-of-service or high-volume testing against hosting infrastructure.

## 5. Verify after deployment

1. Open `https://YOUR-VERCEL-DOMAIN/login.php`.
2. Log in normally.
3. Confirm the URL becomes `/app/#/overview`.
4. Navigate between pages and confirm React speed is retained.
5. Keep `/app/#/threats` open and test a harmless nonexistent path such as `/dashboad.php` in another tab.
6. Confirm the branded 404/recon response appears.
7. Confirm Threats / Security Logs / notifications update without manual refresh.
8. Test logout and logged-out direct access to `/app/#/threats`.
9. Test report export and Current Operator actions.
10. Test Crown Jewel only when you intentionally want to record reaching the pentest objective.

## Local development remains unchanged

```bat
php -S localhost:8082 -t public
```

Vercel-specific files do not alter the local PHP workflow.

## Updating React later

When you change files under `frontend/src`, run `BUILD_REACT_V3.bat` locally first so `public/app/` contains the tested compiled bundle, then commit both the source changes and the updated `public/app/` files. The split deployment intentionally uses that tested bundle on both Render and Vercel to prevent frontend asset-version mismatches.
