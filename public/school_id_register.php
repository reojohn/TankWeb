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

$factorTypeField = fortress_second_factor_type_available($pdo)
    ? "COALESCE(second_factor_type, 'personal_id') AS second_factor_type"
    : "'personal_id' AS second_factor_type";

$stmt = $pdo->prepare(
    'SELECT username, ' . $factorTypeField . ', school_id_qr_enabled
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

if (fortress_second_factor_type_value($user) === 'generated_qr') {
    audit_log('issued_qr_self_enrollment_blocked uid=' . $userId);
    header('Location: /login.php?issued_qr_required=1');
    exit;
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
    <title>FortressAuth — Register Personal ID</title>
    <link rel="stylesheet" href="/css/login.css">
</head>

<body class="auth-page auth-qr-page">
<main class="verify-shell" id="verification-card">
    <section class="verify-side">
        <div class="verify-brand">
            <img src="/images/wolf.png" alt="FortressAuth">
            <div>
                <span class="eyebrow">SECURITY ENROLLMENT</span>
                <h1>FortressAuth</h1>
            </div>
        </div>

        <div class="verify-copy">
            <span class="step-pill">ONE-TIME SETUP</span>
            <h2>Register your Personal ID</h2>
            <p>Link the QR code printed on your physical Personal ID to this account as the required second authentication factor.</p>
        </div>

        <div class="enrollment-points">
            <div><span>01</span><p><strong>Scan once</strong>Your Personal ID is enrolled to this account.</p></div>
            <div><span>02</span><p><strong>Protected storage</strong>The raw QR value is not stored directly.</p></div>
            <div><span>03</span><p><strong>Verify on login</strong>Future sign-ins require the registered physical ID.</p></div>
        </div>

        <div class="verify-security-note">
            <span class="security-icon small" aria-hidden="true">
                <svg viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></svg>
            </span>
            <p>Only enroll a Personal ID that belongs to the account owner.</p>
        </div>
    </section>

    <section class="scanner-panel">
        <div class="scanner-panel-head">
            <div>
                <span class="panel-kicker">ID ENROLLMENT</span>
                <h3>Personal ID scanner</h3>
            </div>
            <span class="camera-state" id="camera-state"><i></i> Camera off</span>
        </div>

        <?php if ((bool) $user['school_id_qr_enabled']): ?>
            <div class="enrolled-state">
                <div class="success-ring">✓</div>
                <h3>Personal ID already registered</h3>
                <p>This account already has an active Personal ID credential.</p>
                <a class="primary-action link-action" href="/personal_id_verify.php">Continue to verification</a>
            </div>
        <?php else: ?>
            <div class="scanner-stage" id="scanner-stage">
                <div id="reader" class="qr-reader" aria-label="Personal ID QR camera preview"></div>
                <div class="scanner-placeholder" id="scanner-placeholder" aria-hidden="true">
                    <div class="qr-symbol">
                        <span></span><span></span><span></span><span></span>
                    </div>
                    <strong>Ready to enroll</strong>
                    <span>Start the scanner and present your Personal ID</span>
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
                    <strong id="scanner-status-title">Enrollment ready</strong>
                    <span id="scanner-status">Camera is currently off.</span>
                </div>
            </div>

            <button type="button" id="start-scanner" class="primary-action scanner-action">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 8V5a1 1 0 011-1h3"/><path d="M16 4h3a1 1 0 011 1v3"/><path d="M20 16v3a1 1 0 01-1 1h-3"/><path d="M8 20H5a1 1 0 01-1-1v-3"/><rect x="8" y="8" width="8" height="8" rx="1"/></svg>
                <span>Start Personal ID scanner</span>
            </button>

            <p class="scanner-help">Keep the Personal ID steady and make sure the full QR code is visible inside the frame.</p>
        <?php endif; ?>
    </section>
</main>

<script src="/js/auth_motion.js"></script>
<script src="/js/html5-qrcode.min.js"></script>
<script src="/js/school_id_register.js"></script>
</body>
</html>
