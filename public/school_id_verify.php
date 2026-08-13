<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

if (
    empty($_SESSION['pending_user_id']) ||
    empty($_SESSION['pending_school_id_verification'])
) {
    header('Location: /login.php');
    exit;
}

$userId = (int) $_SESSION['pending_user_id'];

$stmt = $pdo->prepare(
    'SELECT username,
            school_id_qr_enabled,
            school_id_qr_hash
     FROM public.users
     WHERE id = ?
     LIMIT 1'
);

$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    header('Location: /login.php');
    exit;
}

if (
    !(bool) $user['school_id_qr_enabled'] ||
    empty($user['school_id_qr_hash'])
) {
    header('Location: /personal_id_register.php');
    exit;
}

if (empty($_SESSION['school_id_verify_started_at'])) {
    $_SESSION['school_id_verify_started_at'] = time();
}

$csrfToken = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#10071f">
    <meta name="csrf-token" content="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
    <title>FortressAuth — Verify Personal ID</title>
    <link rel="stylesheet" href="/css/login.css">
</head>

<body class="auth-page auth-qr-page">
<main class="verify-shell" id="verification-card">
    <section class="verify-side">
        <div class="verify-brand">
            <img src="/images/wolf.png" alt="FortressAuth">
            <div>
                <span class="eyebrow">IDENTITY CHECKPOINT</span>
                <h1>FortressAuth</h1>
            </div>
        </div>

        <div class="verify-copy">
            <span class="step-pill">STEP 2 OF 2</span>
            <h2>Verify your Personal ID</h2>
            <p>Complete the second authentication step by scanning the QR code on your registered physical Personal ID.</p>
        </div>

        <div class="auth-progress" aria-label="Authentication progress">
            <div class="progress-item complete">
                <span class="progress-number" aria-hidden="true">1</span>
                <div class="progress-copy">
                    <strong>Password</strong>
                    <span>Verified</span>
                </div>
                <span class="progress-check" aria-hidden="true">✓</span>
            </div>
            <div class="progress-line"></div>
            <div class="progress-item active">
                <span class="progress-number" aria-hidden="true">2</span>
                <div class="progress-copy">
                    <strong>Personal ID</strong>
                    <span>Awaiting scan</span>
                </div>
            </div>
        </div>

        <div class="verify-security-note">
            <span class="security-icon small" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.8-2.8 8.2-7 10-4.2-1.8-7-5.2-7-10V6l7-3z"/><path d="M9.2 12.1l1.8 1.8 3.9-4"/></svg>
            </span>
            <p>The scanned value is verified against the protected credential registered to this account.</p>
        </div>
    </section>

    <section class="scanner-panel">
        <div class="scanner-panel-head">
            <div>
                <span class="panel-kicker">LIVE VERIFICATION</span>
                <h3>Personal ID scanner</h3>
            </div>
            <span class="camera-state" id="camera-state"><i></i> Camera off</span>
        </div>

        <div class="scanner-stage" id="scanner-stage">
            <div id="reader" class="qr-reader" aria-label="Personal ID QR camera preview"></div>
            <div class="scanner-placeholder" id="scanner-placeholder" aria-hidden="true">
                <div class="qr-symbol">
                    <span></span><span></span><span></span><span></span>
                </div>
                <strong>Camera ready</strong>
                <span>Start the scanner to begin verification</span>
            </div>
            <div class="scan-overlay" aria-hidden="true">
                <i class="corner tl"></i>
                <i class="corner tr"></i>
                <i class="corner bl"></i>
                <i class="corner br"></i>
                <i class="scan-line"></i>
                <span class="scan-center-dot"></span>
            </div>
        </div>

        <div class="scanner-status-card neutral" id="scanner-status-card" role="status" aria-live="polite">
            <span class="status-orb" aria-hidden="true"></span>
            <div>
                <strong id="scanner-status-title">Ready for verification</strong>
                <span id="scanner-status">Camera is currently off.</span>
            </div>
        </div>

        <button type="button" id="start-scanner" class="primary-action scanner-action">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 8V5a1 1 0 011-1h3"/><path d="M16 4h3a1 1 0 011 1v3"/><path d="M20 16v3a1 1 0 01-1 1h-3"/><path d="M8 20H5a1 1 0 01-1-1v-3"/><rect x="8" y="8" width="8" height="8" rx="1"/></svg>
            <span>Start Personal ID scanner</span>
        </button>

        <p class="scanner-help">Hold the QR code inside the frame and keep the card steady until verification completes.</p>
    </section>
</main>

<script src="/js/auth_motion.js"></script>
<script src="/js/html5-qrcode.min.js"></script>
<script src="/js/school_id_verify.js"></script>
</body>
</html>
