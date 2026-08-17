<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/fortress_metrics.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_admin_auth();
$userId = (int)($_SESSION['uid'] ?? 0);
$ctx = fortress_build_security_context($pdo, $userId, ['include_all_time_threats' => true, 'include_top_threat_sources' => true]);
extract($ctx, EXTR_SKIP);
$activeNav = 'threats';


$threatNeedles = ['ml_assisted_block','ml_assisted_strike','ml_threat_prediction','malicious_input_detected','shell_attack_detected','request_threat_detected','csp_violation_reported','scanner_user_agent_detected','sensitive_path_probe','reconnaissance_probe','csrf_validation_failed','http_method_blocked','http_method_anomaly','endpoint_method_rejected','oversized_request_detected','oversized_uri_detected','banned_ip_attempt','banned_ip_middleware_block','bruteforce_detected','ip_banned','school_id_qr_failed','school_id_qr_locked','school_id_qr_rate_limited','password_factor_failed','auth_rejected','honeypot_triggered'];
$dbThreatHistory = fortress_recent_security_event_lines($pdo, $threatNeedles, 120);
if (is_array($dbThreatHistory)) {
    $threatHistory = $dbThreatHistory;
} else {
    $threatHistory = array_values(array_filter($auditLines, static fn(string $line): bool => fortress_line_has_any($line, $threatNeedles)));
    $threatHistory = array_slice(array_reverse($threatHistory), 0, 120);
}

$allTime = is_array($threatCategoryAllTime ?? null) ? $threatCategoryAllTime : [];
$threatCategories = [
    ['fa-key', 'Password rejection', (int)($allTime['passwordRejection'] ?? 0), 'All-time first-factor failures'],
    ['fa-id-card', 'Personal ID rejection', (int)($allTime['personalIdRejection'] ?? 0), 'All-time possession-factor failures'],
    ['fa-database', 'SQL injection', (int)($allTime['sqlInjection'] ?? 0), 'Persistent SQL-pattern detections'],
    ['fa-code', 'XSS / traversal', (int)($allTime['xssTraversal'] ?? 0), 'Persistent input-pattern detections'],
    ['fa-terminal', 'Shell payload', (int)($allTime['shellPayload'] ?? 0), 'Persistent command-pattern detections'],
    ['fa-shield-halved', 'CSRF rejection', (int)($allTime['csrfRejection'] ?? 0), 'Persistent anti-CSRF rejections'],
    ['fa-shield', 'CSP violations', (int)($allTime['cspViolations'] ?? 0), 'Persistent browser CSP reports'],
    ['fa-magnifying-glass', 'Recon / 404 probes', (int)($allTime['reconProbes'] ?? 0), 'Persistent path-probe detections'],
    ['fa-robot', 'Scanner fingerprints', (int)($allTime['scannerFingerprints'] ?? 0), 'Persistent scanner-style user agents'],
    ['fa-code-branch', 'HTTP method abuse', (int)($allTime['httpMethodAbuse'] ?? 0), 'Persistent blocked/anomalous methods'],
    ['fa-file-circle-exclamation', 'Oversized requests', (int)($allTime['oversizedRequests'] ?? 0), 'Persistent abnormal request sizes'],
    ['fa-gauge-high', 'Brute force', (int)($allTime['bruteForce'] ?? 0), 'Persistent rate-limit triggers'],
    ['fa-spider', 'Honeypot', (int)($allTime['honeypot'] ?? 0), 'Persistent honeypot events'],
    ['fa-ban', 'Banned-source hits', (int)($allTime['bannedSourceHits'] ?? 0), 'Persistent blocked banned clients'],
    ['fa-door-open', 'Forced Browsing', (int)($allTime['forcedBrowsing'] ?? 0), 'Persistent unauthorized page access'],
];

audit_log('threat_center_viewed uid=' . $userId);
?>
<!doctype html><html lang="en"><head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#10071f"><title>FortressAuth — Threat Center</title><link rel="stylesheet" href="/css/all.min.css"><link rel="stylesheet" href="/css/dashboard.css"><link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head>
<body class="command-page"><div class="ambient ambient-one" aria-hidden="true"></div><div class="ambient ambient-two" aria-hidden="true"></div><main class="command-shell">
<?php require __DIR__ . '/partials/command_header.php'; ?>
<section class="page-hero compact-page-hero threat-page-hero"><div><span class="eyebrow">INTRUSION MONITORING</span><h1>Threat Center</h1><p>Inspect attack pressure, suspicious request patterns, brute-force activity, identity-factor failures, and the network sources producing security events.</p></div><div class="page-hero-icon"><i class="fa-solid fa-shield-virus"></i></div></section>

<section class="threat-overview-grid">
    <article class="panel threat-panel threat-center-gauge"><div class="panel-heading compact"><div><span class="eyebrow">CURRENT THREAT LEVEL</span><h2>Threat Pressure</h2></div><span class="panel-status"><i class="fa-solid fa-satellite-dish"></i> Live</span></div><div class="threat-gauge"><div class="gauge-ring <?= e($threatClass) ?> large-gauge"><div><strong><?= e($threatLevel) ?></strong><span><?= $threatPoints ?> pressure points</span></div></div></div><div class="threat-equation"><div><span>Failed passwords</span><strong><?= $failedAttempts24h ?></strong></div><div><span>Suspicious requests ×2</span><strong><?= $suspiciousRequests24h ?></strong></div><div><span>Active bans ×3</span><strong><?= $activeBans ?></strong></div><div><span>Personal ID failures ×2</span><strong><?= $schoolIdFailures24h ?></strong></div></div></article>
    <article class="panel"><div class="panel-heading compact"><div><span class="eyebrow">SOURCE INTELLIGENCE</span><h2>Top Threat Sources / 24h</h2></div><i class="fa-solid fa-network-wired panel-symbol"></i></div><div class="source-list"><?php if (!$topThreatSources): ?><div class="empty-state">No threat-producing source IPs were recorded in the last 24 hours.</div><?php else: $rank=0; foreach ($topThreatSources as $ip=>$count): $rank++; ?><div><span class="source-rank"><?= str_pad((string)$rank,2,'0',STR_PAD_LEFT) ?></span><code><?= e($ip) ?></code><strong><?= (int)$count ?> events</strong></div><?php endforeach; endif; ?></div><div class="panel-note"><i class="fa-solid fa-circle-info"></i> Localhost and trusted development addresses may appear while testing the project locally.</div></article>
</section>


<article class="panel request-defense-panel"><div class="panel-heading"><div><span class="eyebrow">THREAT CATEGORIES</span><h2>Detected Security Pressure</h2><p>All-time category totals are read from persistent Supabase security evidence, while the live threat pressure and source intelligence above remain rolling 24-hour metrics.</p></div></div><div class="attack-grid threat-category-grid"><?php foreach($threatCategories as $item): ?><div class="attack-card"><span class="attack-icon"><i class="fa-solid <?= e($item[0]) ?>"></i></span><div><strong class="metric-number" data-count="<?= (int)$item[2] ?>"><?= (int)$item[2] ?></strong><span><?= e($item[1]) ?></span><small><?= e($item[3]) ?></small></div></div><?php endforeach; ?></div></article>

<article class="panel data-panel"><div class="panel-heading filter-heading"><div><span class="eyebrow">THREAT TIMELINE</span><h2>Detected Threat Events</h2><p>Security events that contributed to monitoring or blocking decisions.</p></div><div class="table-tools"><label class="search-control"><i class="fa-solid fa-magnifying-glass"></i><input type="search" data-table-search="threatHistory" placeholder="Search threats..."></label><select data-table-category="threatHistory"><option value="all">All categories</option><option value="authentication">Authentication</option><option value="identity">Identity</option><option value="network">Network</option><option value="threat">Threat</option></select></div></div><div class="responsive-table-wrap"><table class="security-table" data-table="threatHistory"><thead><tr><th>Timestamp</th><th>Source IP</th><th>Category</th><th>Detection</th><th>Outcome</th><th>Explanation</th></tr></thead><tbody><?php if(!$threatHistory): ?><tr><td colspan="6" class="table-empty">No threat events have been recorded.</td></tr><?php else: foreach($threatHistory as $line): $category=fortress_event_category($line); $outcome=fortress_event_outcome($line); ?><tr data-search="<?= e(strtolower(fortress_event_title($line).' '.fortress_log_ip($line).' '.$category)) ?>" data-category="<?= e(strtolower($category)) ?>"><td><?= e(fortress_event_time($line,'Y-m-d H:i:s')) ?></td><td><?= e(fortress_log_ip($line)) ?></td><td><?= e($category) ?></td><td><?= e(fortress_event_title($line)) ?></td><td><span class="status-pill status-<?= strtolower($outcome) ?>"><?= e($outcome) ?></span></td><td><?= e(fortress_event_description($line)) ?></td></tr><?php endforeach; endif; ?></tbody></table></div></article>
<footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> FortressAuth intrusion monitoring</span><span>Last threat: <?= e($lastThreatRelative) ?></span></footer>

</div><!-- /.fortress-main-column -->
</main><script src="/js/dashboard.js"></script><script src="/js/auto_logout.js"></script></body></html>
