# FortressAuth Hardened Build

This build enforces the intended authentication policy:

**Password → Registered Personal/School ID QR → Protected Dashboard**

## Required deployment steps

1. **Rotate the old PostgreSQL password.** The previous ZIP contained a real-looking password in source and Git history. Treat it as compromised even if it still works.
2. Copy `.env.example` to a private `.env` for local development, or configure the same values as deployment environment variables. Never commit `.env`.
3. Run `sql/hardening.sql` once with the database owner/migration account.
4. Run the web application with a **least-privilege database user** that cannot `ALTER`, `DROP`, or otherwise change schema.
5. For production HTTPS, keep `COOKIE_SECURE=true`. On plain `http://localhost` only, set it to `false` in the private local `.env`.
6. Set `TRUST_PROXY_HEADERS=true` only behind a trusted proxy such as Render. Otherwise keep it false.

## Security changes in this build

- Removed hardcoded database credential fallbacks.
- Production errors are no longer displayed to clients.
- Removed legacy TOTP and WebAuthn public authentication routes and source modules.
- Removed public `phpinfo`, session-dump, and test endpoints.
- Central authorization requires both password and Personal ID QR state.
- Added secure session rotation, idle timeout, absolute timeout, user-agent binding, and cookie hardening.
- Added `session_version` revocation so password changes, account disablement, and Personal ID reset invalidate old sessions.
- Added IP + account password throttling and IP + account Personal ID throttling.
- Removed duplicate login-attempt recording that previously caused accelerated lockouts.
- Login security logs never serialize raw POST data; log redaction also protects common secret fields.
- Proxy IP headers are trusted only when explicitly enabled.
- Added HSTS on HTTPS, stronger response headers, same-origin restrictions, and no-store caching.
- The runtime application no longer performs `ALTER TABLE` operations.
- Password creation/rehashing prefers Argon2id when the PHP build supports it, with a secure fallback.
- Removed old Git metadata from the distributable hardened ZIP so leaked credentials are not carried in history.

## Important limitation of a static ID QR

A printed static QR is a possession factor, but a copied photograph of that QR can potentially be replayed. FortressAuth protects the stored credential by keeping only a password-style hash, but a static printed QR cannot provide cryptographic challenge-response or liveness by itself. Do not describe it as unclonable.
