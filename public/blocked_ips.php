<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/fortress_metrics.php';
require_once __DIR__ . '/../src/logger.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_admin_auth();
$userId = (int)($_SESSION['uid'] ?? 0);
$message = '';
$messageType = 'success';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = (string)($_POST['csrf_token'] ?? '');
    $action = (string)($_POST['action'] ?? '');
    $ipToUnblock = trim((string)($_POST['ip'] ?? ''));

    if (!verify_csrf_token($token)) {
        $message = 'The unblock request was rejected because the security token was invalid.';
        $messageType = 'error';
    } elseif ($action !== 'unblock' || filter_var($ipToUnblock, FILTER_VALIDATE_IP) === false) {
        $message = 'The requested IP address was invalid.';
        $messageType = 'error';
    } else {
        $stmt = $pdo->prepare('DELETE FROM banned_ips WHERE ip = ?');
        $stmt->execute([$ipToUnblock]);
        audit_log('ip_unblocked uid=' . $userId . ' ip=' . $ipToUnblock);
        $message = $stmt->rowCount() > 0 ? 'The selected IP address was removed from the database-backed ban list.' : 'That IP address was not present in the active ban table.';
    }
}

$ctx = fortress_build_security_context($pdo, $userId, ['minimal' => true]);
extract($ctx, EXTR_SKIP);
$activeNav = 'blocked';
$csrfToken = generate_csrf_token();
$banReasons = [];
$allBans = [];
$bannedRequest24h = 0;
$clientIp = getRealIP();
try {
    // Read the ban rows and each ban's latest originating defense in one query.
    // The lateral lookup uses the existing source_ip/time index and avoids a
    // DISTINCT scan across every historical source in security_events.
    $banStmt = $pdo->query(
        "SELECT b.ip, b.banned_until, latest.event_key AS latest_event_key
         FROM banned_ips b
         LEFT JOIN LATERAL (
             SELECT se.event_key
             FROM public.security_events se
             WHERE se.source_ip = b.ip
               AND se.event_key IN ('automated_recon_block','ml_assisted_block','bruteforce_detected','honeypot_triggered')
             ORDER BY se.occurred_at DESC, se.id DESC
             LIMIT 1
         ) latest ON TRUE
         ORDER BY b.banned_until DESC
         LIMIT 500"
    );
    $allBans = $banStmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    foreach ($allBans as $banRow) {
        $reasonIp = (string)($banRow['ip'] ?? '');
        $reasonKey = (string)($banRow['latest_event_key'] ?? '');
        if ($reasonIp === '') continue;
        $banReasons[$reasonIp] = match ($reasonKey) {
            'automated_recon_block' => 'Automated reconnaissance defense',
            'ml_assisted_block' => 'AI-assisted threat defense',
            'bruteforce_detected' => 'Brute-force defense',
            'honeypot_triggered' => 'Honeypot defense',
            default => 'Security policy',
        };
    }

    $bannedRequest24h = (int)$pdo->query(
        "SELECT COUNT(*)
         FROM public.security_events
         WHERE occurred_at >= NOW() - INTERVAL '24 hours'
           AND event_key IN ('banned_ip_attempt','banned_ip_middleware_block')"
    )->fetchColumn();
} catch (Throwable $e) {
    error_log('FortressAuth ban workspace lookup failed: ' . $e->getMessage());
    try {
        $allBans = $pdo->query('SELECT ip, banned_until FROM banned_ips ORDER BY banned_until DESC LIMIT 500')->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $ignored) {
        $allBans = [];
    }
}
$activeRows = [];
$expiredRows = [];
foreach ($allBans as $ban) {
    $until = strtotime((string)($ban['banned_until'] ?? ''));
    if ($until !== false && $until > time()) $activeRows[] = $ban; else $expiredRows[] = $ban;
}
audit_log('blocked_ips_viewed uid=' . $userId);
?>
<!doctype html><html lang="en"><head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#10071f"><title>FortressAuth — Blocked IPs</title><link rel="stylesheet" href="/css/all.min.css"><link rel="stylesheet" href="/css/dashboard.css"><link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head><body class="command-page"><div class="ambient ambient-one" aria-hidden="true"></div><div class="ambient ambient-two" aria-hidden="true"></div><main class="command-shell">
<?php require __DIR__ . '/partials/command_header.php'; ?>
<section class="page-hero compact-page-hero"><div><span class="eyebrow">NETWORK ENFORCEMENT</span><h1>Blocked IPs</h1><p>Review persistent temporary network bans created by brute-force, automated reconnaissance, honeypot, and guarded AI-assisted defenses, then remove a ban when an administrator has verified the source is safe.</p></div><div class="page-hero-icon danger"><i class="fa-solid fa-ban"></i></div></section>
<?php if($message): ?><div class="system-message <?= e($messageType) ?>"><i class="fa-solid <?= $messageType==='error'?'fa-triangle-exclamation':'fa-circle-check' ?>"></i><?= e($message) ?></div><?php endif; ?>
<section class="metric-grid"><article class="metric-card"><div class="metric-icon danger"><i class="fa-solid fa-ban"></i></div><div><span>Active bans</span><strong><?= count($activeRows) ?></strong><small>Currently enforced</small></div></article><article class="metric-card"><div class="metric-icon"><i class="fa-solid fa-clock-rotate-left"></i></div><div><span>Expired records</span><strong><?= count($expiredRows) ?></strong><small>Returned by ban storage</small></div></article><article class="metric-card"><div class="metric-icon danger"><i class="fa-solid fa-shield-halved"></i></div><div><span>Banned-source hits / 24h</span><strong><?= $bannedRequest24h ?></strong><small>Blocked request attempts</small></div></article><article class="metric-card"><div class="metric-icon success"><i class="fa-solid fa-network-wired"></i></div><div><span>Current client</span><strong class="small-metric-value"><?= e($clientIp) ?></strong><small>Administrator network source</small></div></article></section>
<article class="panel data-panel"><div class="panel-heading filter-heading"><div><span class="eyebrow">ACTIVE NETWORK BANS</span><h2>Enforced IP Restrictions</h2><p>Unblocking is a CSRF-protected administrator action and is recorded in the audit trail.</p></div><label class="search-control"><i class="fa-solid fa-magnifying-glass"></i><input type="search" data-table-search="banTable" placeholder="Search IP..."></label></div><div class="responsive-table-wrap"><table class="security-table" data-table="banTable"><thead><tr><th>IP address</th><th>Defense source</th><th>Ban expires</th><th>Remaining</th><th>Status</th><th>Action</th></tr></thead><tbody><?php if(!$activeRows): ?><tr><td colspan="6" class="table-empty">No active database-backed IP bans.</td></tr><?php else: foreach($activeRows as $ban): $until=strtotime((string)$ban['banned_until']); $remaining=max(0,$until-time()); ?><tr data-search="<?= e(strtolower((string)$ban['ip'])) ?>" data-category="active"><td><code><?= e((string)$ban['ip']) ?></code></td><td><?= e((string)($banReasons[(string)$ban['ip']] ?? 'Security policy')) ?></td><td><?= e((string)$ban['banned_until']) ?></td><td><?= e(gmdate($remaining>=3600?'H:i:s':'i:s',$remaining)) ?></td><td><span class="status-pill status-blocked">ACTIVE</span></td><td><form class="inline-action-form" method="post"><input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>"><input type="hidden" name="action" value="unblock"><input type="hidden" name="ip" value="<?= e((string)$ban['ip']) ?>"><button class="table-action danger" type="submit"><i class="fa-solid fa-unlock"></i> Unblock</button></form></td></tr><?php endforeach; endif; ?></tbody></table></div></article>
<?php if($expiredRows): ?><article class="panel data-panel"><div class="panel-heading compact"><div><span class="eyebrow">RECENT BAN RECORDS</span><h2>Expired Restrictions</h2></div></div><div class="responsive-table-wrap"><table class="security-table"><thead><tr><th>IP address</th><th>Defense source</th><th>Ban expired</th><th>Status</th></tr></thead><tbody><?php foreach(array_slice($expiredRows,0,100) as $ban): ?><tr><td><code><?= e((string)$ban['ip']) ?></code></td><td><?= e((string)($banReasons[(string)$ban['ip']] ?? 'Security policy')) ?></td><td><?= e((string)$ban['banned_until']) ?></td><td><span class="status-pill status-closed">EXPIRED</span></td></tr><?php endforeach; ?></tbody></table></div></article><?php endif; ?>
<footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> FortressAuth network enforcement</span><span><?= count($activeRows) ?> active restrictions</span></footer>

</div><!-- /.fortress-main-column -->
</main><script src="/js/dashboard.js"></script><script src="/js/auto_logout.js"></script></body></html>
