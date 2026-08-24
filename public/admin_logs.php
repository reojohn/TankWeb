<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/fortress_metrics.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_admin_auth();

// React v3 fragment/live-refresh requests only read session state after auth.
// Release PHP's per-session lock before the heavier metrics/database work so
// /logout.php can revoke the session immediately instead of queuing behind it.
if (defined('FORTRESS_BACKGROUND_REQUEST') && FORTRESS_BACKGROUND_REQUEST === true) {
    fortress_release_session_read_lock();
}
$userId = (int)($_SESSION['uid'] ?? 0);
$ctx = fortress_build_security_context($pdo, $userId, ['audit_limit' => 500]);
extract($ctx, EXTR_SKIP);
$activeNav = 'logs';
$logRows = array_slice(array_reverse($auditLines), 0, 500);
$honeypotRows = array_slice(array_reverse($honeypotLines), 0, 80);
$auditCategoryCounts = fortress_audit_category_counts_db($pdo);
audit_log('security_logs_viewed uid=' . $userId);
?>
<!doctype html><html lang="en"><head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#10071f"><title>FortressAuth — Security Logs</title><link rel="stylesheet" href="/css/all.min.css"><link rel="stylesheet" href="/css/dashboard.css?v=20260824-0845"><link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head><body class="command-page"><div class="ambient ambient-one" aria-hidden="true"></div><div class="ambient ambient-two" aria-hidden="true"></div><main class="command-shell">
<?php require __DIR__ . '/partials/command_header.php'; ?>
<section class="page-hero compact-page-hero"><div><span class="eyebrow">SECURITY EVIDENCE</span><h1>Security Logs</h1><p>Search structured authentication, identity, network, request-threat, reconnaissance, CSRF, and session evidence. Passwords, QR values, cookies, authorization data, and security tokens are never rendered here.</p></div><div class="page-hero-icon"><i class="fa-solid fa-clipboard-list"></i></div></section>
<section class="metric-grid"><article class="metric-card"><div class="metric-icon"><i class="fa-solid fa-clipboard-list"></i></div><div><span>Audit events</span><strong><?= $totalAuditEvents ?></strong><small>Current audit log entries</small></div></article><article class="metric-card"><div class="metric-icon danger"><i class="fa-solid fa-spider"></i></div><div><span>Honeypot events</span><strong><?= $totalHoneypotEvents ?></strong><small>Decoy interaction evidence</small></div></article><article class="metric-card"><div class="metric-icon danger"><i class="fa-solid fa-ban"></i></div><div><span>Active bans</span><strong><?= $activeBans ?></strong><small>Network restrictions</small></div></article><article class="metric-card"><div class="metric-icon success"><i class="fa-solid fa-clock"></i></div><div><span>Last meaningful event</span><strong class="small-metric-value"><?= e($lastEventRelative) ?></strong><small>Excludes passive page views</small></div></article></section>
<article class="panel data-panel" id="audit-logs"><div class="panel-heading filter-heading"><div><span class="eyebrow">AUDIT TRAIL</span><h2>Structured Security Evidence</h2><p>Up to the 500 most recent audit entries are available in this view.</p></div><div class="table-tools"><label class="search-control"><i class="fa-solid fa-magnifying-glass"></i><input type="search" data-table-search="auditTable" placeholder="Search logs..."></label><select data-table-category="auditTable"><option value="all">All categories</option><option value="authentication">Authentication</option><option value="identity">Identity</option><option value="network">Network</option><option value="threat">Threat</option><option value="session">Session</option><option value="system">System</option><option value="accounts">Accounts</option><option value="configuration">Configuration</option><option value="documentation">Documentation</option></select></div></div><div class="responsive-table-wrap log-table-wrap"><table class="security-table" data-table="auditTable"><thead><tr><th>Timestamp</th><th>Category</th><th>Event</th><th>Operator</th><th>Source IP</th><th>Outcome</th><th>Details</th></tr></thead><tbody><?php if(!$logRows): ?><tr><td colspan="7" class="table-empty">No audit evidence is available.</td></tr><?php else: foreach($logRows as $line): $category=fortress_event_category($line); $outcome=fortress_event_outcome($line); ?><tr data-search="<?= e(strtolower($category.' '.fortress_event_title($line).' '.fortress_log_user($line,$usernameRaw).' '.fortress_log_ip($line))) ?>" data-category="<?= e(strtolower($category)) ?>"><td><?= e(fortress_event_time($line,'Y-m-d H:i:s')) ?></td><td><?= e($category) ?></td><td><?= e(fortress_event_title($line)) ?></td><td><?= e(fortress_log_user($line,$usernameRaw)) ?></td><td><?= e(fortress_log_ip($line)) ?></td><td><span class="status-pill status-<?= strtolower($outcome) ?>"><?= e($outcome) ?></span></td><td><?= e(fortress_event_description($line)) ?></td></tr><?php endforeach; endif; ?></tbody></table></div></article>
<section class="logs-secondary-grid"><article class="panel" id="honeypot-logs"><div class="panel-heading compact"><div><span class="eyebrow">DECOY DEFENSE</span><h2>Honeypot Evidence</h2></div><span class="panel-status"><i class="fa-solid fa-spider"></i><?= $totalHoneypotEvents ?> total</span></div><div class="honeypot-list"><?php if(!$honeypotRows): ?><div class="empty-state">No honeypot activity recorded.</div><?php else: foreach($honeypotRows as $line): ?><div><i class="fa-solid fa-bug"></i><span><strong><?= e(fortress_event_time($line,'Y-m-d H:i:s')) ?></strong><small><?= e(preg_replace('/^\[[^\]]+\]\s*/','',$line)) ?></small></span></div><?php endforeach; endif; ?></div></article><article class="panel"><div class="panel-heading compact"><div><span class="eyebrow">EVIDENCE COVERAGE</span><h2>Log Categories</h2></div></div><div class="category-summary"><?php $cats=['Authentication'=>0,'Identity'=>0,'Network'=>0,'Threat'=>0,'Session'=>0,'System'=>0,'Accounts'=>0,'Configuration'=>0,'Documentation'=>0]; if (is_array($auditCategoryCounts)) { foreach ($auditCategoryCounts as $cat=>$count) { $cats[$cat]=(int)$count; } } else { foreach($auditLines as $line){$cat=fortress_event_category($line);$cats[$cat]=($cats[$cat]??0)+1;} } foreach($cats as $cat=>$count): ?><div><span><?= e($cat) ?></span><strong><?= (int)$count ?></strong></div><?php endforeach; ?></div></article></section>
<footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> FortressAuth audit evidence</span><span>Current log size: <?= $totalAuditEvents ?> events</span></footer>

</div><!-- /.fortress-main-column -->
</main><script src="/js/dashboard.js?v=20260824-0845"></script><script src="/js/auto_logout.js"></script></body></html>
