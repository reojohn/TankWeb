<?php

declare(strict_types=1);

/*
 * Logout is deliberately kept off the full security middleware pipeline.
 *
 * The authenticated application pages still use middleware.php normally, but a
 * logout request must never wait for remote ML inference, reconnaissance
 * analysis, database-backed ban checks, or a PostgreSQL connection before the
 * browser can terminate its session. Keeping this endpoint lightweight also
 * ensures a banned/flagged source can always close an existing session.
 */
require_once __DIR__ . '/../src/session.php';
require_once __DIR__ . '/../src/logger.php';
require_once __DIR__ . '/../src/logout_audit_token.php';

$userId = (int)($_SESSION['uid'] ?? 0);
$logoutAuditToken = null;

// Record a compact local audit event before the session data is erased. Because
// this endpoint intentionally does not bootstrap config.php, no remote database
// connection is opened on the critical logout path.
if ($userId > 0) {
    audit_log('logout uid=' . $userId);
    // Issue a short-lived signed token before the session disappears. The
    // browser uses it to persist the Supabase audit row in a fire-and-forget
    // request after logout, so database latency never blocks session revocation.
    $logoutAuditToken = fortress_issue_logout_audit_token($userId);
}

// Revoke the authenticated session and expire the session cookie immediately.
fortress_destroy_session();

http_response_code(200);
header_remove('X-Powered-By');
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Permitted-Cross-Domain-Policies: none');
header(
    "Content-Security-Policy: " .
    "default-src 'self'; " .
    "base-uri 'self'; " .
    "form-action 'self'; " .
    "frame-ancestors 'none'; " .
    "script-src 'self'; " .
    "style-src 'self'; " .
    "img-src 'self' data:; " .
    "font-src 'self' data:; " .
    "connect-src 'self'; " .
    "object-src 'none';"
);

if (fortress_request_is_https()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#0b0610">
    <meta name="robots" content="noindex,nofollow">
    <meta http-equiv="refresh" content="1;url=/login.php">
    <title>FortressAuth — Securing Session</title>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="stylesheet" href="/css/all.min.css">
    <link rel="stylesheet" href="/css/logout_transition.css">
    <script src="/js/logout_transition.js" defer></script>
</head>
<body class="fortress-logout-page"<?= is_string($logoutAuditToken) && $logoutAuditToken !== '' ? ' data-logout-audit-token="' . htmlspecialchars($logoutAuditToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"' : '' ?>>
    <div class="logout-grid" aria-hidden="true"></div>
    <div class="logout-ambient logout-ambient-one" aria-hidden="true"></div>
    <div class="logout-ambient logout-ambient-two" aria-hidden="true"></div>
    <div class="logout-scanline" aria-hidden="true"></div>

    <main class="logout-shell">
        <section class="logout-card" role="status" aria-live="polite">
            <div class="logout-brand">
                <span class="logout-brand-mark"><img src="/images/wolf1.png" alt=""></span>
                <span>
                    <small>SECURE ACCESS</small>
                    <strong>FortressAuth</strong>
                </span>
            </div>

            <div class="logout-orbital" aria-hidden="true">
                <span class="logout-ring ring-a"></span>
                <span class="logout-ring ring-b"></span>
                <span class="logout-ring ring-c"></span>
                <span class="logout-core"><i class="fa-solid fa-shield-halved"></i></span>
                <span class="logout-spark spark-a"></span>
                <span class="logout-spark spark-b"></span>
            </div>

            <div class="logout-kicker">SESSION TERMINATION PROTOCOL</div>
            <h1>Securing your workspace</h1>
            <p>FortressAuth is closing the authenticated command session and returning this browser to the secure gateway.</p>

            <div class="logout-steps" aria-hidden="true">
                <span class="done"><i class="fa-solid fa-check"></i><em>Session revoked</em></span>
                <span class="active"><i class="fa-solid fa-lock"></i><em>Clearing workspace</em></span>
                <span><i class="fa-solid fa-arrow-right-to-bracket"></i><em>Secure gateway</em></span>
            </div>

            <div class="logout-progress" aria-hidden="true">
                <span></span>
            </div>

            <div class="logout-footer">
                <span><i class="fa-solid fa-shield-check"></i> Protection remains enforced</span>
                <a href="/login.php">Return now <i class="fa-solid fa-arrow-right"></i></a>
            </div>
        </section>
    </main>
</body>
</html>
