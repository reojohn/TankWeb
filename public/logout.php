<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/logger.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$userId = (int)($_SESSION['uid'] ?? 0);
if ($userId > 0) {
    audit_log('logout uid=' . $userId);
}

fortress_destroy_session();

http_response_code(200);
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#0b0610">
    <meta name="robots" content="noindex,nofollow">
    <meta http-equiv="refresh" content="2;url=/login.php">
    <title>FortressAuth — Securing Session</title>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="stylesheet" href="/css/all.min.css">
    <link rel="stylesheet" href="/css/logout_transition.css">
</head>
<body class="fortress-logout-page">
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
