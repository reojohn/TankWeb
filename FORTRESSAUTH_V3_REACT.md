# FortressAuth v3 - React UI + PHP Security Backend

This copy keeps the working FortressAuth v2 security engine in PHP and moves the command-center interface toward a React single-page application.

## What stays PHP

The existing `src/` directory remains authoritative for authentication, sessions, authorization, CSRF, brute-force protection, request monitoring, reconnaissance defense, logging, security policy, ML-assisted enforcement, user accounts, metrics, and report generation. Supabase/PostgreSQL and the separate ML service are unchanged.

React does not make allow/block decisions. It requests protected JSON from PHP and renders the result.

## React application

React source lives in `frontend/src/`.

Native React routes currently include:

- Overview
- Access Activity
- Security Analytics
- Threats
- AI Defense
- Security Logs
- Blocked IPs
- Security Controls
- Crown Jewel

Current Operator is intentionally migrated through a progressive React bridge in this first v3 pass. React owns the persistent application shell, while the already-working PHP account, Personal ID, and report-management content is loaded inside it so those complex workflows are not broken during the migration.

## PHP JSON API

`public/api/v3.php` is the React data bridge. It reuses the existing PHP security functions and server-side session. It exposes protected views such as:

`/api/v3.php?view=overview`

`/api/v3.php?view=threats`

`/api/v3.php?view=ai`

The Blocked IP page also uses this API for CSRF-protected unblock actions.

## Fast navigation design

The React shell stays mounted while routes change. Navigation uses hash routes such as:

`/app/#/overview`

`/app/#/threats`

Hash routing avoids interfering with the existing FortressAuth `.htaccess` security-probe behavior. API responses have a short in-memory frontend cache and route data is prefetched when a navigation item is hovered or focused.

## Build locally on Windows

From the project root, run:

```bat
BUILD_REACT_V3.bat
```

Or manually:

```bat
cd frontend
npm install
npm run build
```

The compiled application is written to:

`public/app/`

Then run FortressAuth the same way as before, for example:

```bat
php -S localhost:8082 -t public
```

Open the normal login page. When `public/app/index.html` exists, successful login automatically enters the React application. If the React build is absent, login safely falls back to the original PHP dashboard.

## Render deployment

The v3 `Dockerfile` now uses a Node build stage followed by the existing PHP/Apache stage. Render installs the pinned React/Vite packages, builds `public/app/`, then serves the finished bundle from Apache together with the PHP backend.

No new React environment variables are required for the PHP API because the browser uses the same-origin PHP session cookie.

## Important security boundary

Keep these rules while continuing the migration:

1. Never move passwords, database credentials, ban logic, authorization decisions, ML enforcement thresholds, or Crown Jewel secrets into React.
2. State-changing React actions must continue to send the server-issued CSRF token to PHP.
3. React should call the PHP API, not Supabase or the ML service directly.
4. Keep the original PHP pages until each remaining workflow has a native React replacement and has been regression-tested.
