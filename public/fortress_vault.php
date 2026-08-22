<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';
require_once __DIR__ . '/../src/fortress_metrics.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// The vault is a deliberate penetration-test crown jewel. It is intentionally
// absent from the normal navigation and requires the same fully verified admin
// session as the rest of the protected command center.
require_admin_auth();

$userId = (int)($_SESSION['uid'] ?? 0);
$ctx = fortress_build_security_context($pdo, $userId, ['minimal' => true]);
$usernameRaw = trim((string)($ctx['usernameRaw'] ?? 'admin')) ?: 'admin';

if (empty($_SESSION['fortress_vault_breach_id'])) {
    $_SESSION['fortress_vault_breach_id'] = 'FRT-' . strtoupper(bin2hex(random_bytes(5)));
}

$breachId = (string)$_SESSION['fortress_vault_breach_id'];
$captureTime = new DateTimeImmutable('now');
$captureTimeDisplay = $captureTime->format('Y-m-d H:i:s T');
$sourceIp = getRealIP();
$personalIdRequired = (bool)($ctx['schoolIdRequired'] ?? true);
$personalIdVerified = !empty($_SESSION['school_id_verified']);

// The reward is intentionally synthetic. In a hosted exercise the flag can be
// replaced without code changes by defining FORTRESS_VAULT_FLAG server-side.
$flag = trim((string)(getenv('FORTRESS_VAULT_FLAG') ?: ''));
if ($flag === '') {
    $flag = 'FORTRESS{FLAG_NOT_CONFIGURED}';
}

// Record the objective as security evidence. Log only once per fully verified
// session so refreshing the animation does not flood the audit trail.
if (empty($_SESSION['fortress_vault_logged'])) {
    audit_log(
        'vault_flag_viewed uid=' . $userId .
        ' username=' . $usernameRaw .
        ' breach_id=' . $breachId .
        ' objective=crown_jewel'
    );
    $_SESSION['fortress_vault_logged'] = true;
}
?>
<!doctype html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#090511">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <title>FortressAuth — Fortress Vault</title>
    <link rel="stylesheet" href="/css/all.min.css">
    <link rel="stylesheet" href="/css/vault.css?v=20260822-mobile-2x2">
<link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head>
<body class="vault-page" data-vault-stage="boot">
    <div class="vault-ambient vault-ambient-one" aria-hidden="true"></div>
    <div class="vault-ambient vault-ambient-two" aria-hidden="true"></div>
    <div class="vault-grid" aria-hidden="true"></div>

    <main class="vault-shell">
        <header class="vault-topbar">
            <a class="vault-brand" href="/dashboard.php" aria-label="Return to FortressAuth overview">
                <span class="vault-brand-mark"><i class="fa-solid fa-shield-halved"></i></span>
                <span>
                    <small>FORTRESSAUTH</small>
                    <strong>Fortress Vault</strong>
                </span>
            </a>

            <div class="vault-topbar-status">
                <span class="vault-live-dot"></span>
                <span>PROTECTED OBJECTIVE REACHED</span>
            </div>
        </header>

        <section class="vault-stage-card" aria-labelledby="vault-title">
            <div class="vault-copy">
                <span class="vault-eyebrow"><i class="fa-solid fa-crosshairs"></i> PENETRATION TEST OBJECTIVE</span>
                <h1 id="vault-title">The Crown Jewel</h1>
                <p>This page represents the protected asset at the center of the FortressAuth exercise. Reaching it with a fully verified administrator session means the penetration-test objective has been captured.</p>

                <div class="vault-sequence" aria-live="polite">
                    <div class="vault-sequence-head">
                        <span id="vault-stage-label">Initializing vault verification</span>
                        <strong id="vault-progress-value">0%</strong>
                    </div>
                    <div class="vault-progress-track"><span id="vault-progress-bar"></span></div>
                    <div class="vault-stage-list">
                        <span data-step="1"><i class="fa-solid fa-circle"></i> Perimeter</span>
                        <span data-step="2"><i class="fa-solid fa-circle"></i> Session</span>
                        <span data-step="3"><i class="fa-solid fa-circle"></i> Locks</span>
                        <span data-step="4"><i class="fa-solid fa-circle"></i> Crown Jewel</span>
                    </div>
                </div>
            </div>

            <div class="vault-visual" aria-label="Animated Fortress Vault opening sequence">
                <div class="vault-frame">
                    <div class="vault-core">
                        <div class="treasure-rays" aria-hidden="true"></div>
                        <div class="treasure-orbit treasure-orbit-one" aria-hidden="true"></div>
                        <div class="treasure-orbit treasure-orbit-two" aria-hidden="true"></div>
                        <div class="treasure-gem"><i class="fa-solid fa-gem"></i></div>
                        <span>CROWN JEWEL</span>
                    </div>

                    <div class="vault-door" aria-hidden="true">
                        <div class="vault-door-ring ring-one"></div>
                        <div class="vault-door-ring ring-two"></div>
                        <div class="vault-spokes">
                            <span></span><span></span><span></span><span></span><span></span><span></span>
                        </div>
                        <div class="vault-lock-hub">
                            <i class="fa-solid fa-lock"></i>
                        </div>
                        <div class="vault-scan-line"></div>
                    </div>
                </div>

                <div class="vault-door-caption">
                    <span class="vault-caption-dot"></span>
                    <span id="vault-visual-status">Vault sealed</span>
                </div>
            </div>
        </section>

        <section class="vault-reward" id="vault-reward" aria-live="polite">
            <div class="reward-burst" aria-hidden="true">
                <span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span>
            </div>
            <div class="reward-icon"><i class="fa-solid fa-trophy"></i></div>
            <span class="reward-kicker">OBJECTIVE COMPLETED</span>
            <h2>FORTRESS BREACHED</h2>
            <p>The protected crown-jewel resource was reached through a fully verified administrator context.</p>

            <div class="flag-card">
                <span>CAPTURED FLAG</span>
                <code id="vault-flag"><?= e($flag) ?></code>
            </div>

            <div class="vault-evidence-grid">
                <article>
                    <i class="fa-solid fa-fingerprint"></i>
                    <span>Breach ID</span>
                    <strong><?= e($breachId) ?></strong>
                </article>
                <article>
                    <i class="fa-solid fa-user-shield"></i>
                    <span>Operator</span>
                    <strong><?= e($usernameRaw) ?></strong>
                </article>
                <article>
                    <i class="fa-solid fa-network-wired"></i>
                    <span>Source IP</span>
                    <strong><?= e($sourceIp) ?></strong>
                </article>
                <article>
                    <i class="fa-solid fa-clock"></i>
                    <span>Captured</span>
                    <strong><?= e($captureTimeDisplay) ?></strong>
                </article>
            </div>

            <div class="vault-verification-note">
                <i class="fa-solid fa-circle-check"></i>
                <div>
                    <strong>Full protected session state confirmed</strong>
                    <span><?= $personalIdRequired ? ($personalIdVerified ? 'Password + registered Personal ID verification are present for this session.' : 'The required Personal ID verification state is missing.') : 'This account is configured for password-only authentication; Personal ID 2FA is disabled by policy.' ?></span>
                </div>
            </div>

            <div class="vault-reward-actions">
                <button type="button" class="vault-copy-flag" id="vault-copy-flag">
                    <i class="fa-regular fa-copy"></i><span>Copy flag</span>
                </button>
                <a href="/dashboard.php"><i class="fa-solid fa-arrow-left"></i> Return to command center</a>
            </div>
        </section>

        <footer class="vault-footer">
            <span><i class="fa-solid fa-flask"></i> Synthetic penetration-test reward</span>
            <span>No real credentials, API keys, or production secrets are stored in this objective.</span>
        </footer>
    </main>

    <script src="/js/vault.js"></script>
    <script src="/js/auto_logout.js"></script>
</body>
</html>
