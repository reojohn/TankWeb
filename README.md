# FortressAuth

FortressAuth is a hardened PHP/PostgreSQL authentication lab designed for a defensive penetration-testing exercise.

## Authentication policy

**Password → Registered Personal/School ID QR → Protected Dashboard**

The QR factor is enforced by the backend authorization guard. Legacy TOTP and WebAuthn authentication paths have been removed from the hardened build.

## Security controls

- PDO prepared statements with emulated prepares disabled
- Argon2id password hashing when supported, secure fallback otherwise
- Password + account/IP throttling
- Personal ID account/IP throttling
- CSRF protection on state-changing requests
- Secure, HttpOnly, SameSite=Strict session cookies
- Session ID rotation after authentication
- 15-minute idle timeout and configurable absolute session lifetime
- Optional user-agent session binding
- Server-side session revocation with `session_version`
- Account-disable checks on protected requests
- CSP, frame protection, HSTS on HTTPS, no-store caching, and related headers
- Audit logging with credential/token redaction
- Database secrets loaded only from environment variables or a private `.env`
- Runtime database role no longer performs schema changes
- Synthetic crown-jewel flag page for the pentest exercise

## Setup

1. **Rotate the database password used by any older FortressAuth ZIP.** It appeared in previous source/Git history and must be considered exposed.
2. Copy `.env.example` to `.env` for local development and fill in the new database credentials. `.env` is gitignored.
3. Run `sql/hardening.sql` once using the PostgreSQL owner/migration account.
4. Use a separate least-privilege PostgreSQL runtime user for the web application.
5. Start locally from the project root:

```bash
php -S localhost:8082 -t public
```

For plain HTTP localhost only, set `COOKIE_SECURE=false` in the private `.env`. Keep it `true` in production.

See `HARDENING_NOTES.md` for deployment and security details.


## Hybrid ML threat detection

FortressAuth now includes an optional, separate `ml-service/` that combines:

- **XGBoost** behavioral attack classification
- **Feed-forward autoencoder** anomaly detection
- The existing **deterministic FortressAuth rule score**

The ML layer now supports guarded AI-assisted network enforcement. Authentication does not depend on it, and no model can ban a source by itself. A temporary ban requires a malicious model result plus deterministic FortressAuth evidence, with either repeated qualified strikes or a high-risk multi-signal threshold. The PHP application continues to operate normally if the ML service is disabled or unavailable. The model receives numeric behavioral metadata only and does not receive passwords, Personal ID QR contents, CSRF tokens, cookies, authorization headers, or session IDs.

For the project demonstration, the bundled model was trained on **35,000 synthetic labeled training observations** and evaluated on a separate **10,500-row shifted synthetic hold-out set**. These are simulated project results, not production incident claims.

For local two-service Docker startup, configure `.env`, set a private `ML_SERVICE_TOKEN`, then run:

```bash
docker compose up --build
```

The web app is exposed on `http://localhost:8080` in the included Compose configuration. See `ML_INTEGRATION.md` for model, test, and deployment details.


### Deterministic automated reconnaissance defense

FortressAuth includes a rule-based fuzzer/scanner defense that works independently of the ML service. It tracks compact per-IP rolling request/probe counters, recognizes high-signal scanner User-Agents such as FFUF, Gobuster, Feroxbuster, Dirsearch, Wfuzz, Nuclei, Nikto, sqlmap, and Acunetix, and temporarily bans sources that cross corroborated reconnaissance thresholds. Ordinary browser request bursts alone do not trigger a ban. Configure the optional `RECON_*` variables in `.env.example` or the deployment environment.

