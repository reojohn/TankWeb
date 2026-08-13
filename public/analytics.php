<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';
require_once __DIR__ . '/../src/fortress_metrics.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_admin_auth();

$userId = (int)($_SESSION['uid'] ?? 0);
$ctx = fortress_build_security_context($pdo, $userId);
extract($ctx, EXTR_SKIP);
$activeNav = 'analytics';

// Seven-day daily trend, reconstructed only from recorded audit evidence.
$today = new DateTimeImmutable('today');
$dayKeys = [];
$dailyPassed = [];
$dailyRejected = [];
$dailyBlocked = [];
for ($i = 6; $i >= 0; $i--) {
    $day = $today->modify('-' . $i . ' days');
    $key = $day->format('Y-m-d');
    $dayKeys[] = $key;
    $dailyPassed[$key] = 0;
    $dailyRejected[$key] = 0;
    $dailyBlocked[$key] = 0;
}

$categoryCounts = ['Authentication'=>0,'Identity'=>0,'Network'=>0,'Threat'=>0,'Session'=>0,'System'=>0];
$outcomeCounts = ['PASSED'=>0,'REJECTED'=>0,'BLOCKED'=>0,'RECORDED'=>0,'CLOSED'=>0];
$cutoff30d = new DateTimeImmutable('-30 days');

foreach ($auditLines as $line) {
    $dt = fortress_event_datetime($line);
    if (!$dt) continue;

    $dayKey = $dt->setTimezone(new DateTimeZone(date_default_timezone_get()))->format('Y-m-d');
    if (array_key_exists($dayKey, $dailyPassed)) {
        $outcome = fortress_event_outcome($line);
        if ($outcome === 'PASSED') $dailyPassed[$dayKey]++;
        elseif ($outcome === 'BLOCKED') $dailyBlocked[$dayKey]++;
        elseif ($outcome === 'REJECTED') $dailyRejected[$dayKey]++;
    }

    if ($dt >= $cutoff30d) {
        $category = fortress_event_category($line);
        if (!isset($categoryCounts[$category])) $categoryCounts[$category] = 0;
        $categoryCounts[$category]++;

        $outcome = fortress_event_outcome($line);
        if (!isset($outcomeCounts[$outcome])) $outcomeCounts[$outcome] = 0;
        $outcomeCounts[$outcome]++;
    }
}

$sevenDayLabels = array_map(static function (string $key): string {
    try { return (new DateTimeImmutable($key))->format('D'); } catch (Throwable $e) { return $key; }
}, $dayKeys);

$categoryLabels = array_keys($categoryCounts);
$categoryValues = array_values($categoryCounts);
$outcomeLabels = array_keys($outcomeCounts);
$outcomeValues = array_values($outcomeCounts);

$totalOutcomes = array_sum($outcomeValues);
$successfulOutcomes = (int)($outcomeCounts['PASSED'] ?? 0);
$rejectedOutcomes = (int)($outcomeCounts['REJECTED'] ?? 0) + (int)($outcomeCounts['BLOCKED'] ?? 0);
$successRate = ($successfulOutcomes + $rejectedOutcomes) > 0
    ? (int)round(($successfulOutcomes / ($successfulOutcomes + $rejectedOutcomes)) * 100)
    : 0;

// Radar values are a relative current-pressure profile. The busiest recorded
// 24-hour category is scaled to 100 so the chart does not invent a risk score.
$pressureRaw = [
    $failedAttempts24h,
    $schoolIdFailures24h,
    $suspiciousRequests24h,
    $bruteforce24h,
    $honeypot24h,
    $activeBans,
];
$pressureMax = max(1, ...$pressureRaw);
$pressureValues = array_map(static fn(int $value): int => (int)round(($value / $pressureMax) * 100), $pressureRaw);

$hourSeries = [
    ['label'=>'Password passed','values'=>$chartSuccess,'color'=>'#61f7bd'],
    ['label'=>'Password rejected','values'=>$chartFailed,'color'=>'#ff6c93'],
    ['label'=>'Personal ID passed','values'=>$chartSchool,'color'=>'#d497ff'],
    ['label'=>'Defense rejection','values'=>$chartBlocked,'color'=>'#ffc86a'],
];
$weekSeries = [
    ['label'=>'Passed','values'=>array_values($dailyPassed),'color'=>'#61f7bd'],
    ['label'=>'Rejected','values'=>array_values($dailyRejected),'color'=>'#ff6c93'],
    ['label'=>'Blocked','values'=>array_values($dailyBlocked),'color'=>'#ffc86a'],
];
$categorySeries = [['label'=>'Events','values'=>$categoryValues,'color'=>'#b45cff']];
$pressureSeries = [['label'=>'Relative pressure','values'=>$pressureValues,'color'=>'#d497ff']];

$pieColors = ['#61f7bd','#77c9ff','#ffc86a','#ff6c93','#d497ff','#7f89ff'];
$spiralColors = ['#56d8ff','#a78bfa','#4ade80','#ff637d','#fbbf24','#60a5fa'];
$outcomeColors = ['#52e6a5','#ff6b8a','#ffb84d','#5cc8ff','#b983ff'];

$mostActiveCategory = 'No recorded category';
if (array_sum($categoryValues) > 0) {
    $mostActiveCategory = array_keys($categoryCounts, max($categoryCounts), true)[0] ?? 'No recorded category';
}

$recentSecurityEvents = array_slice(array_reverse(array_values(array_filter($auditLines, 'fortress_is_meaningful_event'))), 0, 8);
audit_log('security_analytics_viewed uid=' . $userId);
?>
<!doctype html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#10071f">
    <title>FortressAuth — Security Analytics</title>
    <link rel="stylesheet" href="/css/all.min.css">
    <link rel="stylesheet" href="/css/dashboard.css">
<link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head>
<body class="command-page analytics-page">
<div class="ambient ambient-one" aria-hidden="true"></div><div class="ambient ambient-two" aria-hidden="true"></div>
<main class="command-shell">
<?php require __DIR__ . '/partials/command_header.php'; ?>

<section class="page-hero compact-page-hero">
    <div>
        <span class="eyebrow">SECURITY INTELLIGENCE</span>
        <h1>Security Analytics</h1>
        <p>Explore authentication, identity, network, and threat telemetry as visual trends. Every chart below is calculated from FortressAuth audit evidence, current session state, honeypot activity, and database-backed ban records.</p>
        <div class="analytics-interaction-hint"><i class="fa-solid fa-arrow-pointer"></i><span>Interactive analytics</span><small>Hover over bars, rings, slices, lines, and radar nodes for exact values.</small></div>
    </div>
    <div class="page-hero-icon"><i class="fa-solid fa-chart-pie"></i></div>
</section>

<section class="analytics-summary-grid">
    <article class="metric-card"><div class="metric-icon success"><i class="fa-solid fa-percent"></i></div><div><span>30-day factor success</span><strong><?= $successRate ?>%</strong><small>Passed vs rejected/blocked factor outcomes</small></div></article>
    <article class="metric-card"><div class="metric-icon"><i class="fa-solid fa-chart-line"></i></div><div><span>Audit events retained</span><strong class="metric-number" data-count="<?= $totalAuditEvents ?>"><?= $totalAuditEvents ?></strong><small>Current audit evidence volume</small></div></article>
    <article class="metric-card"><div class="metric-icon danger"><i class="fa-solid fa-shield-virus"></i></div><div><span>Threat pressure</span><strong><?= e($threatLevel) ?></strong><small><?= $threatPoints ?> current pressure points</small></div></article>
    <article class="metric-card"><div class="metric-icon success"><i class="fa-solid fa-shield-halved"></i></div><div><span>Defense integrity</span><strong><?= $activeDefenseCount ?>/<?= count($defenseLayers) ?></strong><small><?= e($protectionLabel) ?></small></div></article>
</section>

<section class="analytics-dashboard-grid reference-analytics-layout">
    <article class="panel analytics-card span-6 analytics-card-compact">
        <div class="panel-heading compact"><div><span class="eyebrow">OUTCOME DISTRIBUTION</span><h2>Security Outcomes / 30 Days</h2><p>Recorded factor and defense outcomes shown as a segmented interactive donut inspired by the dashboard reference.</p></div><i class="fa-solid fa-chart-pie panel-symbol"></i></div>
        <div class="analytics-chart-wrap small"><canvas data-security-chart="donut" data-chart-title="Security Outcomes Distribution" role="img" aria-label="Interactive 30-day security outcomes donut chart" data-labels='<?= e(json_encode($outcomeLabels)) ?>' data-values='<?= e(json_encode($outcomeValues)) ?>' data-colors='<?= e(json_encode($outcomeColors)) ?>' data-center-value="<?= $totalOutcomes ?>" data-center-label="Recorded outcomes"></canvas></div>
        <div class="analytics-legend donut-purple-legend"><span><i style="background:#52e6a5"></i>Passed</span><span><i style="background:#ff6b8a"></i>Rejected</span><span><i style="background:#ffb84d"></i>Blocked</span><span><i style="background:#5cc8ff"></i>Recorded</span><span><i style="background:#b983ff"></i>Closed</span></div>
    </article>

    <article class="panel analytics-card span-6 analytics-card-compact">
        <div class="panel-heading compact"><div><span class="eyebrow">CATEGORY DISTRIBUTION</span><h2>Security Category Spiral</h2><p>Concentric activity rings compare authentication, identity, network, threat, session, and system event volume.</p></div><i class="fa-solid fa-circle-notch panel-symbol"></i></div>
        <div class="analytics-chart-wrap small spiral-chart-wrap"><canvas data-security-chart="spiral" data-chart-title="Security Category Spiral" role="img" aria-label="Interactive concentric security category activity rings" data-labels='<?= e(json_encode($categoryLabels)) ?>' data-values='<?= e(json_encode($categoryValues)) ?>' data-colors='<?= e(json_encode($spiralColors)) ?>'></canvas></div>
        <div class="analytics-insight-strip"><div><span>Most active</span><strong><?= e($mostActiveCategory) ?></strong></div><div><span>Total categorized</span><strong><?= array_sum($categoryValues) ?></strong></div><div><span>Window</span><strong>30 days</strong></div></div>
    </article>

    <article class="panel analytics-card span-4">
        <div class="panel-heading compact"><div><span class="eyebrow">SEVEN-DAY TREND</span><h2>Daily Security Outcomes</h2><p>Passed, rejected, and blocked events across the last seven calendar days.</p></div></div>
        <div class="analytics-chart-wrap"><canvas data-security-chart="bar" data-chart-title="Daily Security Outcomes" role="img" aria-label="Interactive seven-day security outcomes bar chart" data-labels='<?= e(json_encode($sevenDayLabels)) ?>' data-series='<?= e(json_encode($weekSeries)) ?>'></canvas></div>
        <div class="analytics-legend"><span><i class="c1"></i>Passed</span><span><i class="c2"></i>Rejected</span><span><i class="c5"></i>Blocked</span></div>
    </article>

    <article class="panel analytics-card span-4">
        <div class="panel-heading compact"><div><span class="eyebrow">CATEGORY VOLUME</span><h2>Security Event Volume</h2><p>Thirty-day volume across the six FortressAuth security event categories.</p></div></div>
        <div class="analytics-chart-wrap"><canvas data-security-chart="bar" data-chart-title="Security Event Volume" role="img" aria-label="Interactive security event volume bar chart" data-labels='<?= e(json_encode($categoryLabels)) ?>' data-series='<?= e(json_encode($categorySeries)) ?>' data-colors='<?= e(json_encode($spiralColors)) ?>'></canvas></div>
    </article>

    <article class="panel analytics-card span-4">
        <div class="panel-heading compact"><div><span class="eyebrow">PRESSURE PROFILE</span><h2>Current Security Radar</h2><p>Relative 24-hour activity intensity, normalized against the busiest recorded pressure category.</p></div></div>
        <div class="analytics-chart-wrap"><canvas data-security-chart="radar" data-chart-title="Current Security Pressure Radar" role="img" aria-label="Interactive 24-hour security pressure radar chart" data-labels='<?= e(json_encode(['Password','Personal ID','Suspicious','Brute force','Honeypot','Active bans'])) ?>' data-series='<?= e(json_encode($pressureSeries)) ?>'></canvas></div>
    </article>

    <article class="panel analytics-card span-12 analytics-timeline-card">
        <div class="panel-heading"><div><span class="eyebrow">24-HOUR TELEMETRY</span><h2>Authentication Activity Timeline</h2><p>Hourly password, Personal ID, and defense outcomes reconstructed directly from the audit trail.</p></div><span class="panel-status"><i class="fa-solid fa-wave-square"></i> Live evidence</span></div>
        <div class="analytics-chart-wrap timeline-chart-wrap"><canvas data-security-chart="line" data-chart-title="Authentication Activity Timeline" role="img" aria-label="Interactive 24-hour authentication activity timeline" data-labels='<?= e(json_encode($chartLabels)) ?>' data-series='<?= e(json_encode($hourSeries)) ?>'></canvas></div>
        <div class="analytics-legend"><span><i class="c1"></i>Password passed</span><span><i class="c2"></i>Password rejected</span><span><i class="c4"></i>Personal ID passed</span><span><i class="c5"></i>Defense rejection</span></div>
    </article>
</section>

<article class="panel data-panel">
    <div class="panel-heading compact"><div><span class="eyebrow">ANALYTICS EVIDENCE</span><h2>Recent Events Behind the Visuals</h2><p>Charts summarize the same meaningful events retained in the security log.</p></div><a class="text-link" href="/admin_logs.php">Open full logs <i class="fa-solid fa-arrow-right"></i></a></div>
    <div class="responsive-table-wrap"><table class="security-table compact-table"><thead><tr><th>Time</th><th>Category</th><th>Event</th><th>Source IP</th><th>Outcome</th></tr></thead><tbody>
    <?php if (!$recentSecurityEvents): ?><tr><td colspan="5" class="table-empty">No security events recorded yet.</td></tr>
    <?php else: foreach ($recentSecurityEvents as $line): $outcome = fortress_event_outcome($line); ?><tr><td><?= e(fortress_event_time($line,'Y-m-d H:i:s')) ?></td><td><?= e(fortress_event_category($line)) ?></td><td><?= e(fortress_event_title($line)) ?></td><td><?= e(fortress_log_ip($line)) ?></td><td><span class="status-pill status-<?= strtolower($outcome) ?>"><?= e($outcome) ?></span></td></tr><?php endforeach; endif; ?>
    </tbody></table></div>
</article>

<footer class="command-footer"><span><i class="fa-solid fa-chart-line"></i> FortressAuth security analytics</span><span>Charts use recorded audit and runtime security data</span></footer>

</div><!-- /.fortress-main-column -->
</main>
<script src="/js/dashboard.js"></script><script src="/js/auto_logout.js"></script>
</body></html>
