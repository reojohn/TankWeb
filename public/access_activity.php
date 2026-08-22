<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/fortress_metrics.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_admin_auth();

$userId = (int)($_SESSION['uid'] ?? 0);
$ctx = fortress_build_security_context($pdo, $userId, ['minimal' => true]);
extract($ctx, EXTR_SKIP);
$activeNav = 'activity';

$metricState = fortress_security_metrics_24h_db($pdo);
$chartState = fortress_security_hourly_chart_db($pdo);
if (is_array($metricState) && is_array($chartState)) {
    $failedAttempts24h = (int)($metricState['failed_passwords'] ?? 0);
    $successfulPassword24h = (int)($metricState['successful_passwords'] ?? 0);
    $schoolIdSuccess24h = (int)($metricState['school_id_success'] ?? 0);
    $schoolIdFailures24h = (int)($metricState['school_id_failures'] ?? 0);
    $totalLoginAttempts24h = $failedAttempts24h + $successfulPassword24h;
    $clientIp = getRealIP();

    $hourNow = new DateTimeImmutable('now');
    $hourKeys = [];
    $chartSuccessMap = $chartFailedMap = $chartSchoolMap = $chartBlockedMap = [];
    for ($i = 23; $i >= 0; $i--) {
        $key = $hourNow->modify('-' . $i . ' hours')->format('Y-m-d H');
        $hourKeys[] = $key;
        $chartSuccessMap[$key] = 0;
        $chartFailedMap[$key] = 0;
        $chartSchoolMap[$key] = 0;
        $chartBlockedMap[$key] = 0;
    }
    foreach ($chartState as $row) {
        $key = (string)($row['hour_key'] ?? '');
        if (!array_key_exists($key, $chartSuccessMap)) continue;
        $chartSuccessMap[$key] = (int)($row['password_success'] ?? 0);
        $chartFailedMap[$key] = (int)($row['password_failed'] ?? 0);
        $chartSchoolMap[$key] = (int)($row['school_success'] ?? 0);
        $chartBlockedMap[$key] = (int)($row['blocked'] ?? 0);
    }
    $chartLabels = array_map(static fn(string $key): string => substr($key, 11, 2) . ':00', $hourKeys);
    $chartSuccess = array_values($chartSuccessMap);
    $chartFailed = array_values($chartFailedMap);
    $chartSchool = array_values($chartSchoolMap);
    $chartBlocked = array_values($chartBlockedMap);
    $auditLines = [];
} else {
    $ctx = fortress_build_security_context($pdo, $userId, ['include_charts' => true]);
    extract($ctx, EXTR_SKIP);
}

$authEventKeys = [
    'password_factor_success', 'password_factor_failed', 'school_id_qr_success',
    'school_id_qr_failed', 'school_id_qr_locked', 'school_id_2fa_not_required', 'login_success', 'logout',
];
$dbAuthHistory = fortress_recent_security_event_lines($pdo, $authEventKeys, 160);
if (is_array($dbAuthHistory)) {
    $authHistory = $dbAuthHistory;
} else {
    $authHistory = array_values(array_filter($auditLines, 'fortress_is_auth_event'));
    $authHistory = array_slice(array_reverse($authHistory), 0, 160);
}
$successful24h = $successfulPassword24h;
$rejected24h = $failedAttempts24h + $schoolIdFailures24h;

audit_log('access_activity_viewed uid=' . $userId);
?>
<!doctype html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#10071f">
    <title>FortressAuth — Access Activity</title>
    <link rel="stylesheet" href="/css/all.min.css"><link rel="stylesheet" href="/css/dashboard.css">
<link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head>
<body class="command-page">
<div class="ambient ambient-one" aria-hidden="true"></div><div class="ambient ambient-two" aria-hidden="true"></div>
<main class="command-shell">
    <?php require __DIR__ . '/partials/command_header.php'; ?>

    <section class="page-hero compact-page-hero">
        <div><span class="eyebrow">AUTHENTICATION OPERATIONS</span><h1>Access Activity</h1><p>Review successful and rejected authentication factors, Personal ID checks, session openings, and access history recorded by FortressAuth.</p></div>
        <div class="page-hero-icon"><i class="fa-solid fa-wave-square"></i></div>
    </section>

    <section class="metric-grid">
        <article class="metric-card"><div class="metric-icon success"><i class="fa-solid fa-circle-check"></i></div><div><span>Password passed / 24h</span><strong class="metric-number" data-count="<?= $successful24h ?>"><?= $successful24h ?></strong><small>Accepted first-factor checks</small></div></article>
        <article class="metric-card"><div class="metric-icon danger"><i class="fa-solid fa-circle-xmark"></i></div><div><span>Rejected factors / 24h</span><strong class="metric-number" data-count="<?= $rejected24h ?>"><?= $rejected24h ?></strong><small>Password + Personal ID rejections</small></div></article>
        <article class="metric-card"><div class="metric-icon success"><i class="fa-solid fa-id-card"></i></div><div><span>Personal ID passed / 24h</span><strong class="metric-number" data-count="<?= $schoolIdSuccess24h ?>"><?= $schoolIdSuccess24h ?></strong><small>Possession checks completed</small></div></article>
        <article class="metric-card"><div class="metric-icon"><i class="fa-solid fa-door-open"></i></div><div><span>Total password attempts</span><strong class="metric-number" data-count="<?= $totalLoginAttempts24h ?>"><?= $totalLoginAttempts24h ?></strong><small>Recorded in the last 24 hours</small></div></article>
    </section>

    <article class="panel chart-panel page-chart">
        <div class="panel-heading"><div><span class="eyebrow">ACCESS ANALYTICS</span><h2>Authentication Activity / 24 Hours</h2><p>Hourly factor activity from the audit trail.</p></div></div>
        <div class="chart-wrap tall-chart"><canvas id="authActivityChart" data-labels='<?= e(json_encode($chartLabels)) ?>' data-success='<?= e(json_encode($chartSuccess)) ?>' data-failed='<?= e(json_encode($chartFailed)) ?>' data-school='<?= e(json_encode($chartSchool)) ?>' data-blocked='<?= e(json_encode($chartBlocked)) ?>'></canvas></div>
        <div class="chart-legend"><span><i class="legend-dot legend-success"></i>Password passed</span><span><i class="legend-dot legend-failed"></i>Password rejected</span><span><i class="legend-dot legend-school"></i>Personal ID passed</span><span><i class="legend-dot legend-blocked"></i>Defense rejection</span></div>
    </article>

    <article class="panel data-panel">
        <div class="panel-heading filter-heading">
            <div><span class="eyebrow">AUTHENTICATION HISTORY</span><h2>Detailed Access Records</h2><p>Filter the most recent factor and session events without exposing any password or QR credential values.</p></div>
            <div class="table-tools">
                <label class="search-control"><i class="fa-solid fa-magnifying-glass"></i><input type="search" data-table-search="accessHistory" placeholder="Search activity..."></label>
                <select data-table-category="accessHistory" aria-label="Filter access activity"><option value="all">All results</option><option value="passed">Passed</option><option value="rejected">Rejected</option><option value="closed">Closed</option></select>
            </div>
        </div>
        <div class="responsive-table-wrap mobile-bounded-table access-history-table-wrap">
            <table class="security-table" data-table="accessHistory">
                <thead><tr><th>Timestamp</th><th>Operator</th><th>Source IP</th><th>Authentication event</th><th>Factor</th><th>Result</th></tr></thead>
                <tbody>
                <?php if (!$authHistory): ?><tr><td colspan="6" class="table-empty">No authentication records available.</td></tr>
                <?php else: foreach ($authHistory as $line):
                    $outcome = fortress_event_outcome($line);
                    $factor = str_contains($line, 'school_id') ? 'Personal ID' : (str_contains($line, 'password') ? 'Password' : 'Session');
                ?>
                    <tr data-search="<?= e(strtolower(fortress_event_title($line) . ' ' . fortress_log_ip($line) . ' ' . fortress_log_user($line, $usernameRaw))) ?>" data-category="<?= e(strtolower($outcome)) ?>">
                        <td><?= e(fortress_event_time($line, 'Y-m-d H:i:s')) ?></td><td><?= e(fortress_log_user($line, $usernameRaw)) ?></td><td><?= e(fortress_log_ip($line)) ?></td><td><?= e(fortress_event_title($line)) ?></td><td><?= e($factor) ?></td><td><span class="status-pill status-<?= strtolower($outcome) ?>"><?= e($outcome) ?></span></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </article>

    <footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> FortressAuth access evidence</span><span>Current operator: <?= e($usernameRaw) ?> · Client: <?= e($clientIp) ?></span></footer>

</div><!-- /.fortress-main-column -->
</main>
<script src="/js/dashboard.js"></script><script src="/js/auto_logout.js"></script>
</body>
</html>
