<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/fortress_metrics.php';
require_once __DIR__ . '/../src/security_policy.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_admin_auth();

// React v3 fragment/live-refresh requests only read session state after auth.
// Release PHP's per-session lock before the heavier metrics/database work so
// /logout.php can revoke the session immediately instead of queuing behind it.
if (defined('FORTRESS_BACKGROUND_REQUEST') && FORTRESS_BACKGROUND_REQUEST === true) {
    fortress_release_session_read_lock();
}
$userId = (int)($_SESSION['uid'] ?? 0);
$ctx = fortress_build_security_context($pdo, $userId, ['minimal' => true]);
extract($ctx, EXTR_SKIP);

// Security Controls renders aggregate evidence, not raw audit history. Pull the
// compact counters directly from PostgreSQL and only fall back to the legacy
// context builder if structured history is temporarily unavailable.
$metricState = fortress_security_metrics_24h_db($pdo);
if (is_array($metricState)) {
    $failedAttempts24h = (int)($metricState['failed_passwords'] ?? 0);
    $successfulPassword24h = (int)($metricState['successful_passwords'] ?? 0);
    $schoolIdSuccess24h = (int)($metricState['school_id_success'] ?? 0);
    $schoolIdFailures24h = (int)($metricState['school_id_failures'] ?? 0);
    $suspiciousRequests24h = (int)($metricState['suspicious_requests'] ?? 0);
    $bruteforce24h = (int)($metricState['brute_force'] ?? 0);
    $totalAuditEvents = max(0, (int)($metricState['total_audit_events'] ?? 0));
    try {
        $activeBans = (int)$pdo->query("SELECT COUNT(*) FROM banned_ips WHERE banned_until > NOW()")->fetchColumn();
    } catch (Throwable $e) {
        $activeBans = 0;
    }
    $threatPoints = $failedAttempts24h + ($suspiciousRequests24h * 2) + ($activeBans * 3) + ($schoolIdFailures24h * 2);
    $threatLevel = $threatPoints >= 8 ? 'ELEVATED' : ($threatPoints >= 3 ? 'WATCH' : 'LOW');
} else {
    $ctx = fortress_build_security_context($pdo, $userId);
    extract($ctx, EXTR_SKIP);
}

$activeNav = 'controls';
$policy = fortress_security_policy();
$reconDefenseEnabled = fortress_recon_enabled();

$aiAssistedEnabled = fortress_ml_assisted_enforcement_enabled();
$aiConfig = fortress_ml_enforcement_config();
$aiStrikeRisk = (float)$aiConfig['strike_risk'];
$aiImmediateRisk = (float)$aiConfig['block_risk'];
$aiRequiredStrikes = (int)$aiConfig['required_strikes'];
$aiStrikeWindow = (int)$aiConfig['window_seconds'];
$aiBanSeconds = (int)$aiConfig['ban_seconds'];
$runtimeDefenseMode = fortress_security_profile_mode();
$runtimeDefenseDefinition = fortress_security_profile_definition($runtimeDefenseMode);

$secondFactorControlName = (string)($defenseLayers[1][0] ?? 'Personal ID 2FA');

$controlDetails = [
    'Password authentication' => ['Credential hashing', 'Operational', $successfulPassword24h . ' accepted / ' . $failedAttempts24h . ' rejected in 24h'],
    $secondFactorControlName => [
        $schoolIdFactorType === 'generated_qr' ? 'Administrator-issued QR possession factor' : 'Personal ID QR possession factor',
        $schoolIdRequired ? ($schoolIdEnabled ? 'Operational' : 'Attention') : 'Disabled',
        $schoolIdRequired
            ? ($schoolIdSuccess24h . ' passed / ' . $schoolIdFailures24h . ' failed in 24h')
            : 'Password-only account policy'
    ],
    'CSRF protection' => ['Session-bound security token', 'Operational', 'State-changing protected actions require the session token'],
    'Brute-force defense' => ['Attempt threshold + temporary ban', 'Operational', $bruteforce24h . ' threshold triggers in 24h'],
    'Suspicious input detection' => ['SQLi, XSS, traversal, shell patterns', 'Operational', $suspiciousRequests24h . ' suspicious detections in 24h'],
    'IP ban enforcement' => ['Database + middleware network restriction', 'Operational', $activeBans . ' active database-backed bans'],
    'Session protection' => ['Strict cookie + regeneration + idle timeout', 'Operational', fortress_policy_minutes((int)$policy['session_idle_seconds']) . ' inactivity policy enforced'],
    'Audit logging' => ['Append-only application security evidence', 'Operational', $totalAuditEvents . ' audit events retained in the current log'],
];

audit_log('security_controls_viewed uid=' . $userId);
?>
<!doctype html><html lang="en"><head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#10071f"><title>FortressAuth — Security Controls</title><link rel="stylesheet" href="/css/all.min.css"><link rel="stylesheet" href="/css/dashboard.css"><link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head><body class="command-page"><div class="ambient ambient-one" aria-hidden="true"></div><div class="ambient ambient-two" aria-hidden="true"></div><main class="command-shell">
<?php require __DIR__ . '/partials/command_header.php'; ?>
<section class="page-hero compact-page-hero"><div><span class="eyebrow">FORTRESS WALLS</span><h1>Security Controls</h1><p>Inspect the operational state, purpose, and current evidence behind every defense layer protecting privileged administrator access.</p></div><div class="page-hero-icon"><i class="fa-solid fa-sliders"></i></div></section>
<section class="posture-summary-strip"><div><span>Protection score</span><strong><?= $protectionScore ?>/100</strong></div><div><span>Defense integrity</span><strong><?= $activeDefenseCount ?>/<?= count($defenseLayers) ?> active</strong></div><div><span>Threat level</span><strong><?= e($threatLevel) ?></strong></div><div><span>Defense profile</span><strong><?= e((string)($runtimeDefenseDefinition['label'] ?? 'BALANCED')) ?></strong></div></section>
<section class="control-grid">
<?php foreach($defenseLayers as $index=>$layer):
    $detail = $controlDetails[$layer[0]] ?? [
        'Configured security control',
        $layer[1] ? 'Operational' : 'Attention',
        $layer[2],
    ];
?>
<article class="panel control-card <?= $layer[1]?'active':'warning' ?>">
    <div class="control-card-top"><span class="control-number"><?= str_pad((string)($index+1),2,'0',STR_PAD_LEFT) ?></span><span class="control-icon"><i class="fa-solid <?= e($layer[4]) ?>"></i></span><span class="status-pill <?= $layer[1]?'status-passed':'status-rejected' ?>"><?= $layer[1]?'ACTIVE':'ATTENTION' ?></span></div>
    <h2><?= e($layer[0]) ?></h2><p><?= e($layer[2]) ?></p>
    <dl class="control-details"><div><dt>Mechanism</dt><dd><?= e($detail[0]) ?></dd></div><div><dt>Runtime state</dt><dd><?= e($detail[1]) ?></dd></div><div><dt>Current evidence</dt><dd><?= e($detail[2]) ?></dd></div><div><dt>Score weight</dt><dd><?= (int)$layer[3] ?> points</dd></div></dl>
</article>
<?php endforeach; ?>
</section>
<article class="panel configuration-panel"><div class="panel-heading compact"><div><span class="eyebrow">PROTECTION POLICY</span><h2>Current Security Configuration</h2></div><i class="fa-solid fa-shield-halved panel-symbol"></i></div><div class="configuration-grid">
<div><i class="fa-solid fa-bolt"></i><span>Runtime defense profile</span><strong><?= e((string)($runtimeDefenseDefinition['label'] ?? 'BALANCED')) ?></strong></div>
<div><i class="fa-solid fa-clock"></i><span>Session inactivity timeout</span><strong><?= e(fortress_policy_minutes((int)$policy['session_idle_seconds'])) ?></strong></div>
<div><i class="fa-solid fa-qrcode"></i><span>QR verification window</span><strong><?= e(fortress_policy_minutes((int)$policy['school_id_verification_window_seconds'])) ?></strong></div>
<div><i class="fa-solid fa-list-ol"></i><span>QR failed-scan limit</span><strong><?= (int)$policy['school_id_session_attempt_limit'] ?> attempts</strong></div>
<div><i class="fa-solid fa-gauge-high"></i><span>Password brute-force threshold</span><strong><?= (int)$policy['password_ip_failure_limit'] ?> IP / <?= (int)$policy['password_account_failure_limit'] ?> account failures · <?= e(fortress_policy_minutes((int)$policy['password_failure_window_seconds'])) ?></strong></div>
<div><i class="fa-solid fa-ban"></i><span>Temporary IP ban duration</span><strong><?= e(fortress_policy_minutes((int)$policy['ip_ban_seconds'])) ?></strong></div>
<div><i class="fa-solid fa-id-card"></i><span>QR verification rate limit</span><strong><?= (int)$policy['school_id_account_attempt_limit'] ?> account / <?= (int)$policy['school_id_ip_attempt_limit'] ?> IP · <?= e(fortress_policy_minutes((int)$policy['school_id_rate_window_seconds'])) ?></strong></div>
<div><i class="fa-solid fa-radar"></i><span>Automated recon / fuzzer defense</span><strong><?= $reconDefenseEnabled ? 'ENFORCED' : 'OFF' ?></strong></div>
<div><i class="fa-solid fa-route"></i><span>Recon probe threshold</span><strong><?= (int)$policy['recon_probe_limit'] ?> probes / 1 minute · <?= (int)$policy['recon_sensitive_probe_limit'] ?> sensitive / 5 minutes</strong></div>
<div><i class="fa-solid fa-network-wired"></i><span>Fuzzer sweep threshold</span><strong><?= (int)$policy['recon_request_limit'] ?> requests / 1 minute · <?= (int)$policy['recon_unique_path_limit'] ?> unique paths / 5 minutes</strong></div>
<div><i class="fa-solid fa-ban"></i><span>Recon temporary ban</span><strong><?= e(fortress_policy_minutes((int)$policy['recon_ban_seconds'])) ?></strong></div>
<div><i class="fa-solid fa-brain"></i><span>AI-assisted enforcement</span><strong><?= $aiAssistedEnabled ? 'GUARDED ON' : 'OFF' ?></strong></div>
<div><i class="fa-solid fa-bolt"></i><span>AI strike threshold</span><strong><?= number_format($aiStrikeRisk, 0) ?>/100 · <?= (int)$aiRequiredStrikes ?> strikes / <?= e(fortress_policy_minutes($aiStrikeWindow)) ?></strong></div>
<div><i class="fa-solid fa-shield-virus"></i><span>Immediate AI block threshold</span><strong><?= number_format($aiImmediateRisk, 0) ?>/100 + corroborating evidence</strong></div>
<div><i class="fa-solid fa-hourglass-half"></i><span>AI-assisted ban duration</span><strong><?= e(fortress_policy_minutes($aiBanSeconds)) ?></strong></div>
<div><i class="fa-solid fa-cookie-bite"></i><span>Session cookie mode</span><strong>HttpOnly + SameSite Strict</strong></div></div></article>
<footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> FortressAuth defense integrity</span><span><?= e($protectionLabel) ?></span></footer>

</div><!-- /.fortress-main-column -->
</main><script src="/js/dashboard.js"></script><script src="/js/auto_logout.js"></script></body></html>
