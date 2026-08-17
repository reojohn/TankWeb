<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';
require_once __DIR__ . '/../src/fortress_metrics.php';
require_once __DIR__ . '/../src/security_policy.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_admin_auth();

$userId = (int)($_SESSION['uid'] ?? 0);
$ctx = fortress_build_security_context($pdo, $userId);
extract($ctx, EXTR_SKIP);

$username = e($usernameRaw);
$clientIpEscaped = e($clientIp);
$schoolUpdatedDisplay = fortress_format_date_value($schoolIdUpdatedAt, 'Not registered');
$verifiedAt = (int)($_SESSION['school_id_verified_at'] ?? 0);
$verifiedDisplay = $schoolIdRequired
    ? ($verifiedAt > 0 ? date('Y-m-d H:i:s', $verifiedAt) : 'Not verified in this session')
    : 'Not required by account policy';
$accessChainComplete = !$schoolIdRequired || $schoolIdVerified;
$secondFactorIsIssued = $schoolIdRequired && ($schoolIdFactorType ?? 'personal_id') === 'generated_qr';
$secondFactorLabel = !$schoolIdRequired
    ? 'Password only'
    : ($secondFactorIsIssued ? 'Issued QR' : 'Personal ID');
$secondFactorFlowTitle = !$schoolIdRequired
    ? 'Second factor'
    : ($secondFactorIsIssued ? 'Issued QR' : 'Personal ID 2FA');
$secondFactorIcon = $secondFactorIsIssued ? 'fa-qrcode' : 'fa-id-card';

$scoreClass = $protectionScore >= 90 ? 'score-strong' : ($protectionScore >= 70 ? 'score-good' : 'score-warning');
$integrityPercent = (int)round(($activeDefenseCount / max(1, count($defenseLayers))) * 100);

$attackSurface = [
    ['fa-database', 'SQL injection patterns', $sqlAttack24h, 'Detected and blocked / 24h'],
    ['fa-code', 'XSS / suspicious input', $xssAttack24h + $pathAttack24h, 'Input defense events / 24h'],
    ['fa-terminal', 'Shell-style payloads', $shellAttack24h, 'Command-pattern detections / 24h'],
    ['fa-spider', 'Honeypot triggers', $honeypot24h, 'Honeypot events / 24h'],
    ['fa-gauge-high', 'Rate-limit pressure', $bruteforce24h, 'Brute-force triggers / 24h'],
    ['fa-shield-halved', 'Blocked requests', $blockedRequests24h, 'Defense rejections / 24h'],
];

$activeNav = 'overview';
audit_log('dashboard_access uid=' . $userId);
?>
<!doctype html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <meta charset="utf-8">
    <title>FortressAuth — Command Center</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#10071f">
    <link rel="stylesheet" href="/css/all.min.css">
    <link rel="stylesheet" href="/css/dashboard.css">
<link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head>
<body class="command-page">
    <div class="ambient ambient-one" aria-hidden="true"></div>
    <div class="ambient ambient-two" aria-hidden="true"></div>

    <main class="command-shell">
        <?php require __DIR__ . '/partials/command_header.php'; ?>

        <section class="command-hero">
            <div class="hero-copy">
                <span class="eyebrow">FORTRESS STATUS / ONLINE</span>
                <h1>FortressAuth <span>Command Center</span></h1>
                <p>
                    FortressAuth protects privileged administrator access using password authentication,
                    optional per-account Personal ID 2FA, CSRF protection, brute-force defense,
                    IP enforcement, suspicious-input detection, protected sessions, and auditable security evidence.
                </p>
                <div class="hero-badges">
                    <span><i class="fa-solid fa-key"></i> Password verified</span>
                    <span class="<?= $schoolIdRequired ? ($schoolIdVerified ? 'verified' : 'warning') : 'verified' ?>">
                        <i class="fa-solid <?= $schoolIdRequired ? e($secondFactorIcon) : 'fa-key' ?>"></i>
                        <?= $schoolIdRequired
                            ? (e($secondFactorLabel) . ' ' . ($schoolIdVerified ? 'verified' : 'not verified'))
                            : 'Second factor not required · password only' ?>
                    </span>
                    <span><i class="fa-solid fa-shield-halved"></i> <?= $activeDefenseCount ?>/<?= count($defenseLayers) ?> defenses holding</span>
                </div>
            </div>

            <div class="fortress-core" aria-label="FortressAuth protection core">
                <div class="core-ring ring-one"></div>
                <div class="core-ring ring-two"></div>
                <div class="core-ring ring-three"></div>
                <div class="core-center"><img src="/images/wolf1.png" alt="FortressAuth shield"></div>
                <div class="core-label core-label-top">IDENTITY</div>
                <div class="core-label core-label-right">SESSION</div>
                <div class="core-label core-label-bottom">AUDIT</div>
                <div class="core-label core-label-left">ACCESS</div>
            </div>
        </section>

        <section class="metric-grid" aria-label="Security summary">
            <article class="metric-card">
                <div class="metric-icon success"><i class="fa-solid fa-user-shield"></i></div>
                <div><span>Current operator</span><strong><?= $username ?></strong><small>Authenticated administrator</small></div>
            </article>
            <article class="metric-card">
                <div class="metric-icon"><i class="fa-solid fa-key"></i></div>
                <div><span>Failed attempts / 24h</span><strong class="metric-number" data-count="<?= $failedAttempts24h ?>"><?= $failedAttempts24h ?></strong><small>Password factor rejections</small></div>
            </article>
            <article class="metric-card">
                <div class="metric-icon danger"><i class="fa-solid fa-triangle-exclamation"></i></div>
                <div><span>Suspicious requests / 24h</span><strong class="metric-number" data-count="<?= $suspiciousRequests24h ?>"><?= $suspiciousRequests24h ?></strong><small>Attack-pattern detections</small></div>
            </article>
            <article class="metric-card">
                <div class="metric-icon danger"><i class="fa-solid fa-ban"></i></div>
                <div><span>Active blocked IPs</span><strong class="metric-number" data-count="<?= $activeBans ?>"><?= $activeBans ?></strong><small>Database-backed network bans</small></div>
            </article>
        </section>

        <!-- 03 Security posture + 04 verification chain -->
        <section class="overview-dual">
            <article class="panel posture-panel">
                <div class="panel-heading compact">
                    <div><span class="eyebrow">SECURITY POSTURE</span><h2>Current Protection Score</h2></div>
                    <span class="panel-status"><i class="fa-solid fa-shield"></i> Live state</span>
                </div>
                <div class="posture-content">
                    <div class="score-orbit <?= e($scoreClass) ?>">
                        <div><strong><?= $protectionScore ?></strong><span>/ 100</span></div>
                    </div>
                    <div class="posture-copy">
                        <span class="posture-label"><?= e($protectionLabel) ?></span>
                        <p>Live composite score derived from the operational state of the active FortressAuth defense layers.</p>
                        <div class="posture-factors">
                            <?php foreach ($defenseLayers as $layer): ?>
                                <span class="<?= $layer[1] ? 'on' : 'off' ?>"><i class="fa-solid <?= $layer[1] ? 'fa-circle-check' : 'fa-circle-exclamation' ?>"></i> <?= e($layer[0]) ?> +<?= (int)$layer[3] ?></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </article>

            <article class="panel verification-panel">
                <div class="panel-heading compact verification-heading">
                    <div><span class="eyebrow">ACCESS VERIFICATION CHAIN</span><h2>Layered Authentication Flow</h2></div>
                    <span class="flow-processing" aria-label="Verification telemetry processing">
                        <span class="flow-processing-dots" aria-hidden="true"><i></i><i></i><i></i></span>
                        <span>PROCESSING</span>
                    </span>
                </div>
                <div class="verification-chain" aria-label="Live authentication verification flow">
                    <div class="chain-node complete"><span>01</span><i class="fa-solid fa-user-shield"></i><strong>Operator</strong><small><?= $username ?></small></div>
                    <div class="chain-connector complete"><i class="fa-solid fa-chevron-right"></i></div>
                    <div class="chain-node complete"><span>02</span><i class="fa-solid fa-key"></i><strong>Password</strong><small>Verified</small></div>
                    <div class="chain-connector complete"><i class="fa-solid fa-chevron-right"></i></div>
                    <div class="chain-node <?= $accessChainComplete ? 'complete' : 'pending' ?>"><span>03</span><i class="fa-solid <?= e($secondFactorIcon) ?>"></i><strong><?= e($secondFactorFlowTitle) ?></strong><small><?= $schoolIdRequired ? ($schoolIdVerified ? 'Verified' : 'Pending') : 'Not required' ?></small></div>
                    <div class="chain-connector <?= $accessChainComplete ? 'complete' : '' ?>"><i class="fa-solid fa-chevron-right"></i></div>
                    <div class="chain-node <?= $accessChainComplete ? 'complete' : 'pending' ?>"><span>04</span><i class="fa-solid fa-lock-open"></i><strong>Session</strong><small><?= $accessChainComplete ? 'Active' : 'Waiting' ?></small></div>
                    <div class="chain-connector <?= $accessChainComplete ? 'complete' : '' ?>"><i class="fa-solid fa-chevron-right"></i></div>
                    <div class="chain-node <?= $accessChainComplete ? 'complete protected' : 'pending' ?>"><span>05</span><i class="fa-solid fa-vault"></i><strong>Protected</strong><small><?= $accessChainComplete ? 'Granted' : 'Locked' ?></small></div>
                </div>
            </article>
        </section>

        <!-- 05 Authentication analytics + 10 explained threat monitor -->
        <section class="analytics-layout">
            <article class="panel chart-panel">
                <div class="panel-heading">
                    <div><span class="eyebrow">AUTHENTICATION ACTIVITY</span><h2>Last 24 Hours</h2><p>Successful password checks, failed passwords, successful Personal ID checks, and blocked security activity.</p></div>
                    <a class="text-link" href="/access_activity.php">Open Access Activity <i class="fa-solid fa-arrow-right"></i></a>
                </div>
                <div class="chart-wrap">
                    <canvas
                        id="authActivityChart"
                        aria-label="Authentication activity chart"
                        data-labels='<?= e(json_encode($chartLabels)) ?>'
                        data-success='<?= e(json_encode($chartSuccess)) ?>'
                        data-failed='<?= e(json_encode($chartFailed)) ?>'
                        data-school='<?= e(json_encode($chartSchool)) ?>'
                        data-blocked='<?= e(json_encode($chartBlocked)) ?>'></canvas>
                </div>
                <div class="chart-legend">
                    <span><i class="legend-dot legend-success"></i><?= $successfulPassword24h ?> password passed</span>
                    <span><i class="legend-dot legend-failed"></i><?= $failedAttempts24h ?> password rejected</span>
                    <span><i class="legend-dot legend-school"></i><?= $schoolIdSuccess24h ?> Personal ID passed</span>
                    <span><i class="legend-dot legend-blocked"></i><?= $blockedRequests24h ?> defense rejections</span>
                </div>
            </article>

            <article class="panel threat-panel explained-threat">
                <div class="panel-heading compact">
                    <div><span class="eyebrow">INTRUSION MONITOR</span><h2>Threat Monitor</h2></div>
                    <i class="fa-solid fa-satellite-dish panel-symbol"></i>
                </div>
                <div class="threat-gauge"><div class="gauge-ring <?= e($threatClass) ?>"><div><strong><?= e($threatLevel) ?></strong><span>Current threat pressure</span></div></div></div>
                <div class="threat-equation">
                    <div><span>Failed passwords</span><strong><?= $failedAttempts24h ?></strong></div>
                    <div><span>Suspicious requests ×2</span><strong><?= $suspiciousRequests24h ?></strong></div>
                    <div><span>Active bans ×3</span><strong><?= $activeBans ?></strong></div>
                    <div><span>Personal ID failures ×2</span><strong><?= $schoolIdFailures24h ?></strong></div>
                    <div class="threat-total"><span>Threat pressure points</span><strong><?= $threatPoints ?></strong></div>
                </div>
                <div class="threat-details">
                    <div><span>Last threat detected</span><strong><?= e($lastThreatRelative) ?></strong></div>
                    <div><span>Last successful login</span><strong><?= e($lastSuccessfulLoginRelative) ?></strong></div>
                </div>
            </article>
        </section>

        <!-- 08 session security + 07 Personal ID status + 11 fortress integrity -->
        <section class="security-state-grid">
            <article class="panel operator-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">PROTECTED SESSION</span><h2>Session Security</h2></div><span class="session-orb"></span></div>
                <div class="operator-identity"><div class="operator-avatar"><i class="fa-solid fa-user-shield"></i></div><div><strong><?= $username ?></strong><span>Current operator · Administrator</span></div></div>
                <dl class="session-details">
                    <div><dt>Session status</dt><dd>ACTIVE</dd></div>
                    <div><dt>Authentication</dt><dd><?= $schoolIdRequired ? ('PASSWORD + ' . strtoupper(e($secondFactorLabel))) : 'PASSWORD ONLY' ?></dd></div>
                    <div><dt>Session started</dt><dd><?= e($sessionStartDisplay) ?></dd></div>
                    <div><dt>Session duration</dt><dd class="session-duration" data-start="<?= $sessionStart ?>">00:00:00</dd></div>
                    <div><dt>Current IP</dt><dd><?= $clientIpEscaped ?></dd></div>
                    <div><dt>Session regeneration</dt><dd>ACTIVE</dd></div>
                    <div><dt>Idle protection</dt><dd>15 MIN</dd></div>
                    <div><dt>CSRF protection</dt><dd>ACTIVE</dd></div>
                </dl>
            </article>

            <article class="panel school-status-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">REGISTERED IDENTITY TOKEN</span><h2>Personal ID Security</h2></div><i class="fa-solid fa-id-card panel-symbol"></i></div>
                <div class="credential-hero <?= $schoolIdRequired && $schoolIdEnabled ? 'active' : 'warning' ?>">
                    <span class="credential-icon"><i class="fa-solid <?= $schoolIdRequired ? 'fa-qrcode' : 'fa-key' ?>"></i></span>
                    <div>
                        <strong><?= !$schoolIdRequired ? '2FA DISABLED' : ($schoolIdEnabled ? 'REGISTERED & ACTIVE' : 'ENROLLMENT REQUIRED') ?></strong>
                        <small><?= $schoolIdRequired ? ($secondFactorIsIssued ? 'Administrator-issued QR possession verification' : 'Personal ID QR possession verification') : 'This account uses password-only authentication' ?></small>
                    </div>
                </div>
                <dl class="session-details school-details">
                    <div><dt>2FA policy</dt><dd><?= $schoolIdRequired ? 'REQUIRED' : 'DISABLED' ?></dd></div>
                    <div><dt>Verification method</dt><dd><?= $schoolIdRequired ? 'QR SCAN' : 'PASSWORD ONLY' ?></dd></div>
                    <div><dt>Current session</dt><dd><?= $schoolIdRequired ? ($schoolIdVerified ? 'PASSED' : 'PENDING') : 'NOT REQUIRED' ?></dd></div>
                    <div><dt>Last verified</dt><dd><?= e($lastSchoolIdRelative) ?></dd></div>
                    <div><dt>Failures / 24h</dt><dd><?= $schoolIdFailures24h ?></dd></div>
                    <div><dt>Credential updated</dt><dd><?= e($schoolUpdatedDisplay) ?></dd></div>
                    <div><dt>Replacement state</dt><dd>NOT REQUESTED</dd></div>
                </dl>
                <a class="panel-action" href="/user_management.php#personal-id">Manage Personal ID <i class="fa-solid fa-arrow-right"></i></a>
            </article>

            <article class="panel integrity-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">DEFENSE INTEGRITY</span><h2>Fortress Integrity</h2></div><i class="fa-solid fa-shield-halved panel-symbol"></i></div>
                <div class="integrity-body">
                    <div class="integrity-number"><strong><?= $integrityPercent ?>%</strong><span><?= $activeDefenseCount ?> / <?= count($defenseLayers) ?> DEFENSE SYSTEMS OPERATIONAL</span></div>
                    <div class="integrity-track"><span data-integrity="<?= $integrityPercent ?>"></span></div>
                    <div class="integrity-list">
                        <?php foreach ($defenseLayers as $layer): ?>
                            <span class="<?= $layer[1] ? 'active' : 'warning' ?>"><i class="fa-solid <?= $layer[1] ? 'fa-check' : 'fa-exclamation' ?>"></i><?= e($layer[0]) ?></span>
                        <?php endforeach; ?>
                    </div>
                    <a class="panel-action" href="/security_controls.php">Inspect all controls <i class="fa-solid fa-arrow-right"></i></a>
                </div>
            </article>
        </section>

        <!-- 09 Attack surface / request security -->
        <article class="panel request-defense-panel">
            <div class="panel-heading">
                <div><span class="eyebrow">ATTACK SURFACE / REQUEST SECURITY</span><h2>Request Defense</h2><p>Only events actually recorded by the existing security controls are counted here.</p></div>
                <a class="text-link" href="/threats.php">Open Threat Center <i class="fa-solid fa-arrow-right"></i></a>
            </div>
            <div class="attack-grid">
                <?php foreach ($attackSurface as $item): ?>
                    <div class="attack-card"><span class="attack-icon"><i class="fa-solid <?= e($item[0]) ?>"></i></span><div><strong class="metric-number" data-count="<?= (int)$item[2] ?>"><?= (int)$item[2] ?></strong><span><?= e($item[1]) ?></span><small><?= e($item[3]) ?></small></div></div>
                <?php endforeach; ?>
            </div>
        </article>

        <!-- Defense layers now full-width so the right side never leaves a large blank column. -->
        <article class="panel defense-panel wide-panel">
            <div class="panel-heading">
                <div><span class="eyebrow">FORTRESS WALLS</span><h2>Defense Layers</h2><p>Eight independent controls form the walls around privileged administrator access.</p></div>
                <span class="panel-status"><i class="fa-solid fa-shield"></i> <?= $activeDefenseCount ?>/<?= count($defenseLayers) ?> active</span>
            </div>
            <div class="defense-list defense-grid-list">
                <?php foreach ($defenseLayers as $index => $layer): ?>
                    <div class="defense-row <?= $layer[1] ? 'active' : 'warning' ?>">
                        <span class="defense-index"><?= str_pad((string)($index + 1), 2, '0', STR_PAD_LEFT) ?></span>
                        <div class="defense-copy"><strong><?= e($layer[0]) ?></strong><small><?= e($layer[2]) ?></small></div>
                        <span class="defense-state"><i class="fa-solid <?= $layer[1] ? 'fa-circle-check' : 'fa-circle-exclamation' ?>"></i><?= $layer[1] ? 'ACTIVE' : 'ATTENTION' ?></span>
                    </div>
                <?php endforeach; ?>
            </div>
        </article>

        <!-- 06 Recent authentication attempts -->
        <article class="panel attempts-panel">
            <div class="panel-heading">
                <div><span class="eyebrow">RECENT ACCESS ATTEMPTS</span><h2>Authentication Attempts</h2><p>Factor-level authentication history reconstructed from FortressAuth audit evidence.</p></div>
                <a class="text-link" href="/access_activity.php">View complete activity <i class="fa-solid fa-arrow-right"></i></a>
            </div>
            <div class="responsive-table-wrap">
                <table class="security-table compact-table">
                    <thead><tr><th>Time</th><th>Operator</th><th>IP</th><th>Factor / Event</th><th>Result</th></tr></thead>
                    <tbody>
                    <?php if (!$recentAuthLines): ?>
                        <tr><td colspan="5" class="table-empty">No authentication activity recorded yet.</td></tr>
                    <?php else: ?>
                        <?php foreach (array_slice($recentAuthLines, 0, 8) as $line): $outcome = fortress_event_outcome($line); ?>
                            <tr>
                                <td><?= e(fortress_event_time($line, 'M d H:i:s')) ?></td>
                                <td><?= e(fortress_log_user($line, $usernameRaw)) ?></td>
                                <td><?= e(fortress_log_ip($line)) ?></td>
                                <td><?= e(fortress_event_title($line)) ?></td>
                                <td><span class="status-pill status-<?= strtolower($outcome) ?>"><?= e($outcome) ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </article>

        <!-- 19 Fortress timeline + security feed -->
        <section class="activity-balance-grid">
            <article class="panel event-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">FORTRESS ACTIVITY</span><h2>Security Event Feed</h2></div><a class="text-link" href="/admin_logs.php">Full audit trail <i class="fa-solid fa-arrow-right"></i></a></div>
                <div class="event-feed">
                    <?php if (!$recentLines): ?><div class="empty-state">No meaningful security activity has been recorded yet.</div>
                    <?php else: foreach ($recentLines as $line): $type = fortress_event_type($line); ?>
                        <div class="event-row <?= e($type) ?>"><span class="event-marker"><i class="fa-solid <?= $type === 'alert' ? 'fa-triangle-exclamation' : ($type === 'success' ? 'fa-check' : 'fa-circle-info') ?>"></i></span><div class="event-copy"><strong><?= e(fortress_event_title($line)) ?></strong><small><?= e(fortress_event_description($line)) ?></small></div><time><?= e(fortress_event_time($line)) ?></time></div>
                    <?php endforeach; endif; ?>
                </div>
            </article>

            <article class="panel timeline-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">SECURITY TIMELINE</span><h2>Current Fortress Timeline</h2></div><i class="fa-solid fa-timeline panel-symbol"></i></div>
                <div class="fortress-timeline">
                    <?php if (!$timeline): ?><div class="empty-state">This session has no additional timeline events yet.</div>
                    <?php else: foreach ($timeline as $index => $line): ?>
                        <div class="timeline-item <?= e(fortress_event_type($line)) ?>"><time><?= e(fortress_event_time($line)) ?></time><span class="timeline-dot"></span><div><strong><?= e(fortress_event_title($line)) ?></strong><small><?= e(fortress_event_description($line)) ?></small></div></div>
                    <?php endforeach; endif; ?>
                </div>
            </article>
        </section>

        <!-- 12 Protected resources + existing protected assets/evidence/actions -->
        <section class="resource-layout">
            <article class="panel assets-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">WHAT THE FORTRESS PROTECTS</span><h2>Protected Assets</h2></div></div>
                <div class="asset-grid">
                    <?php foreach ($protectedAssets as $asset): ?><div class="asset-card"><span class="asset-icon"><i class="fa-solid <?= e($asset[0]) ?>"></i></span><div><strong><?= e($asset[1]) ?></strong><small><?= e($asset[2]) ?></small></div></div><?php endforeach; ?>
                </div>
            </article>

            <article class="panel protected-resources-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">PROTECTED ADMINISTRATOR RESOURCES</span><h2>Access Gateway Coverage</h2></div><i class="fa-solid fa-vault panel-symbol"></i></div>
                <div class="protected-resource-list">
                    <?php foreach ($protectedResources as $resource): ?>
                        <a href="<?= e($resource[1]) ?>"><span><i class="fa-solid <?= e($resource[2]) ?>"></i><strong><?= e($resource[0]) ?></strong></span><em><i class="fa-solid fa-lock"></i> Protected</em></a>
                    <?php endforeach; ?>
                </div>
            </article>
        </section>

        <section class="lower-grid">
            <article class="panel logs-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">SECURITY EVIDENCE</span><h2>Security Logs Overview</h2></div></div>
                <div class="log-summary">
                    <div><i class="fa-solid fa-clipboard-list"></i><span>Audit events</span><strong><?= $totalAuditEvents ?></strong></div>
                    <div><i class="fa-solid fa-spider"></i><span>Honeypot hits</span><strong><?= $totalHoneypotEvents ?></strong></div>
                    <div><i class="fa-solid fa-ban"></i><span>Active bans</span><strong><?= $activeBans ?></strong></div>
                    <div><i class="fa-solid fa-clock"></i><span>Last security event</span><strong class="relative-value"><?= e($lastEventRelative) ?></strong></div>
                </div>
                <a class="primary-action" href="/admin_logs.php"><span>Open Security Logs</span><i class="fa-solid fa-arrow-up-right-from-square"></i></a>
            </article>

            <article class="panel actions-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">OPERATOR CONTROLS</span><h2>Quick Actions</h2></div></div>
                <div class="quick-actions">
                    <a href="/access_activity.php"><span><i class="fa-solid fa-wave-square"></i> View access activity</span><i class="fa-solid fa-chevron-right"></i></a>
                    <a href="/threats.php"><span><i class="fa-solid fa-shield-virus"></i> Open threat center</span><i class="fa-solid fa-chevron-right"></i></a>
                    <a href="/user_management.php#personal-id"><span><i class="fa-solid fa-id-card"></i> Manage Personal ID</span><i class="fa-solid fa-chevron-right"></i></a>
                    <a href="/blocked_ips.php"><span><i class="fa-solid fa-ban"></i> Review blocked IPs</span><i class="fa-solid fa-chevron-right"></i></a>
                    <a href="/security_controls.php"><span><i class="fa-solid fa-sliders"></i> Inspect security controls</span><i class="fa-solid fa-chevron-right"></i></a>
                    <a class="danger-action" href="/logout.php"><span><i class="fa-solid fa-power-off"></i> End protected session</span><i class="fa-solid fa-chevron-right"></i></a>
                </div>
            </article>
        </section>

        <footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> FortressAuth layered identity and access defense</span><span>Session timeout: <?= e(fortress_policy_minutes((int)fortress_security_policy()['session_idle_seconds'])) ?> · Client: <?= $clientIpEscaped ?></span></footer>
    
</div><!-- /.fortress-main-column -->
</main>

    <script src="/js/dashboard.js"></script>
    <script src="/js/auto_logout.js"></script>
</body>
</html>
