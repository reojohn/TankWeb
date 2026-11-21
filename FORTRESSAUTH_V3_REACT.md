# FortressAuth v3 - React Shell + PHP Security Backend

FortressAuth v3 keeps the security engine in PHP while React owns the persistent command-center shell and route switching.

## Security boundary

The existing `src/` directory remains authoritative for authentication, sessions, authorization, CSRF, brute-force protection, request monitoring, reconnaissance defense, logging, security policy, ML-assisted enforcement, user accounts, metrics, report generation, and Crown Jewel authorization. Supabase/PostgreSQL and the separate ML service remain server-side.

React never makes allow/block decisions and must not contain secrets.

## Current UI architecture

React source lives in `frontend/src/`. The persistent React shell provides the sidebar, mobile command bar, route transitions, prefetching, and navigation for:

- Overview
- Access Activity
- Security Analytics
- Threats
- AI Defense
- Security Logs
- Blocked IPs
- Security Controls
- Current Operator
- Crown Jewel

Most command-center page bodies currently use a protected parity bridge: React fetches server-rendered page fragments from `public/api/v3_fragment.php` and places them inside the persistent shell. This preserves the already-tested PHP page logic while keeping SPA-style navigation. Current Operator and Crown Jewel also use protected bridge flows with their own authorization checks.

`public/api/v3.php` remains the structured JSON bridge for bootstrap/live data and supported actions. PHP sessions and CSRF validation remain authoritative.

## Fast navigation design

Navigation uses hash routes such as:

`/app/#/overview`

`/app/#/threats`

Hash routing avoids colliding with `.htaccess` reconnaissance handling. The shell caches recent fragments briefly and prefetches safe routes. Crown Jewel is intentionally excluded from ordinary prefetching because opening it is the pentest objective.

## Local development

Run the PHP application as before:

```bat
php -S localhost:8082 -t public
```

The protected `/app/` entry is gated by `public/app/index.php`, which verifies the server-side session before the React runtime is allowed to load.

## React source validation build

From the project root, run:

```bat
BUILD_REACT_V3.bat
```

or:

```bat
cd frontend
npm install
npm run build
```

The Vite validation output is written to `react-build/`, not `public/app/`. This is intentional. A previous configuration used `emptyOutDir: true` on `public/app/`, which could delete the PHP auth gate and vendored runtime files.

The currently deployed application uses the tested committed runtime under `public/app/`, including `public/app/assets/v3-fast-navigation-skeleton-20260820.js`.

## Render deployment

The current `Dockerfile` is PHP/Apache only. It copies the committed tested frontend runtime together with the PHP backend, enables Apache rewrite/headers support, and serves `public/` as the document root. It does not run a Node build stage.

## Important rules while continuing the migration

1. Never move passwords, database credentials, ban logic, authorization decisions, ML enforcement thresholds, or Crown Jewel secrets into React.
2. State-changing React actions must continue to send the server-issued CSRF token to PHP.
3. React should call the PHP backend, not Supabase or the ML service directly.
4. Keep the PHP parity pages until a native React replacement is implemented and regression-tested.
5. Do not point a Vite `emptyOutDir` build at `public/app/`; that directory contains security-critical deployment files in the current architecture.
