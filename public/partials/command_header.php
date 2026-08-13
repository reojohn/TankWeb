<?php
require_once __DIR__ . '/../../src/security_policy.php';
$activeNav = $activeNav ?? 'overview';
$navItems = [
    'overview' => ['/dashboard.php', 'fa-table-cells-large', 'Overview', 'Security command center'],
    'activity' => ['/access_activity.php', 'fa-wave-square', 'Access Activity', 'Authentication history'],
    'analytics' => ['/analytics.php', 'fa-chart-pie', 'Security Analytics', 'Charts and trends'],
    'threats' => ['/threats.php', 'fa-shield-virus', 'Threats', 'Intrusion monitoring'],
    'ai' => ['/ai_threat_intelligence.php', 'fa-brain', 'AI Defense', 'ML threat intelligence'],
    'logs' => ['/admin_logs.php', 'fa-clipboard-list', 'Security Logs', 'Audit evidence'],
    'blocked' => ['/blocked_ips.php', 'fa-ban', 'Blocked IPs', 'Network enforcement'],
    'controls' => ['/security_controls.php', 'fa-sliders', 'Security Controls', 'Defense configuration'],
    'operator' => ['/user_management.php', 'fa-user-shield', 'Current Operator', 'Users, Personal ID and documentation reports'],
    'vault' => ['/fortress_vault.php', 'fa-gem', 'Crown Jewel', 'Pentest objective'],
];

$currentNav = $navItems[$activeNav] ?? $navItems['overview'];
$pageTitle = $currentNav[2];
$pageSubtitle = $currentNav[3];
$score = isset($protectionScore) ? (int)$protectionScore : 100;
$defenseActive = isset($activeDefenseCount) ? (int)$activeDefenseCount : 8;
$defenseTotal = isset($defenseLayers) && is_array($defenseLayers) ? count($defenseLayers) : 8;
$operatorLabel = isset($usernameRaw) && trim((string)$usernameRaw) !== '' ? (string)$usernameRaw : 'admin';
$currentUri = e($_SERVER['REQUEST_URI'] ?? '/dashboard.php');
$notificationOwner = (int)($_SESSION['uid'] ?? 0);
?>

<div class="fortress-mobile-bar">
    <button class="fortress-mobile-menu" type="button" aria-label="Open navigation" aria-expanded="false" data-sidebar-toggle>
        <i class="fa-solid fa-bars"></i>
    </button>
    <div class="fortress-mobile-title">
        <strong><?= e($pageTitle) ?></strong>
        <span>FortressAuth · Protection enforced</span>
    </div>
    <div class="fortress-mobile-actions" aria-label="Quick actions">
        <button class="fortress-mobile-notifications fortress-notification-toggle" type="button" aria-label="Open notifications" aria-expanded="false" aria-controls="fortress-notification-panel" data-notification-toggle>
            <i class="fa-solid fa-bell"></i>
            <span class="fortress-notification-badge" data-notification-badge hidden>0</span>
        </button>
        <a class="fortress-mobile-refresh" href="<?= $currentUri ?>" aria-label="Refresh security status" title="Refresh security status"><i class="fa-solid fa-arrows-rotate"></i></a>
        <a class="fortress-mobile-logout" href="/logout.php" aria-label="Log out" title="Log out"><i class="fa-solid fa-arrow-right-from-bracket"></i></a>
    </div>
</div>
<div class="fortress-sidebar-overlay" data-sidebar-overlay></div>

<aside class="command-chrome fortress-sidebar" data-fortress-sidebar>
    <div class="sidebar-brand-card">
        <a class="brand-lockup" href="/dashboard.php" aria-label="FortressAuth command center">
            <span class="topbar-logo"><img src="/images/wolf1.png" alt=""></span>
            <span class="brand-copy">
                <small>SECURE ACCESS</small>
                <strong>FortressAuth</strong>
                <em>Command Center</em>
            </span>
        </a>
        <button type="button" class="sidebar-close" data-sidebar-close aria-label="Close navigation"><i class="fa-solid fa-xmark"></i></button>
    </div>

    <div class="sidebar-status-card">
        <div>
            <span>Workspace status</span>
            <strong><i class="live-dot"></i> Enforced</strong>
        </div>
        <div class="sidebar-score">
            <span>Score</span>
            <strong><?= $score ?></strong>
        </div>
    </div>

    <a class="sidebar-operator-card operator-management-link <?= $activeNav === 'operator' ? 'active' : '' ?>" href="/user_management.php" aria-label="Open Current Operator workspace">
        <span class="sidebar-operator-icon"><i class="fa-solid fa-user-shield"></i></span>
        <span class="operator-card-copy">
            <small>Current operator</small>
            <strong><?= e($operatorLabel) ?></strong>
            <em class="operator-manage-hint"><i class="fa-solid fa-users-gear"></i> Users <span>+</span> <i class="fa-solid fa-id-card"></i> ID <span>+</span> <i class="fa-solid fa-file-export"></i> Reports</em>
        </span>
        <span class="sidebar-operator-badge">ADMIN</span>
    </a>

    <nav class="command-nav" aria-label="FortressAuth navigation">
        <p class="sidebar-section-label">Navigation</p>
        <div class="command-nav-links" id="command-nav-links">
            <?php foreach ($navItems as $key => $item): ?>
                <?php if ($key === 'operator') continue; ?>

                <?php if ($key === 'vault'): ?>
                    <a class="nav-crown-jewel <?= $activeNav === 'vault' ? 'active' : '' ?>"
                       href="<?= e($item[0]) ?>"
                       aria-label="Crown Jewel - penetration test objective">
                        <span class="crown-jewel-caption" aria-hidden="true">Pentest objective</span>
                        <span class="crown-jewel-image-frame" aria-hidden="true">
                            <img class="crown-jewel-image" src="/images/jewel.png" alt="">
                            <span class="crown-jewel-sweep"></span>
                            <span class="crown-jewel-flare crown-jewel-flare-one"></span>
                            <span class="crown-jewel-flare crown-jewel-flare-two"></span>
                        </span>
                        <span class="crown-jewel-accessible-text">Crown Jewel - Pentest Objective</span>
                    </a>
                <?php else: ?>
                    <a class="<?= $activeNav === $key ? 'active' : '' ?>" href="<?= e($item[0]) ?>">
                        <span class="nav-icon"><i class="fa-solid <?= e($item[1]) ?>"></i></span>
                        <span class="nav-copy"><strong><?= e($item[2]) ?></strong><small><?= e($item[3]) ?></small></span>
                        <?php if ($activeNav === $key): ?><span class="nav-active-rail" aria-hidden="true"></span><?php endif; ?>
                    </a>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    </nav>

</aside>

<div class="fortress-main-column">
<header class="fortress-page-header">
    <div class="page-heading-left">
        <span class="page-heading-icon"><i class="fa-solid <?= e($currentNav[1]) ?>"></i></span>
        <div>
            <div class="page-heading-chips">
                <span>FORTRESSAUTH</span>
                <span class="status-chip"><i class="live-dot"></i> PROTECTION ENFORCED</span>
            </div>
            <h1><?= e($pageTitle) ?></h1>
            <p><?= e($pageSubtitle) ?> · <?= $defenseActive ?>/<?= $defenseTotal ?> defense layers operational</p>
        </div>
    </div>
    <div class="page-heading-actions">
        <div class="header-score-card"><span>Protection</span><strong><?= $score ?>/100</strong></div>
        <button class="icon-action fortress-notification-toggle" type="button" title="Security notifications" aria-label="Open security notifications" aria-expanded="false" aria-controls="fortress-notification-panel" data-notification-toggle>
            <i class="fa-solid fa-bell"></i>
            <span class="fortress-notification-badge" data-notification-badge hidden>0</span>
        </button>
        <a class="icon-action" href="<?= $currentUri ?>" title="Refresh security status" aria-label="Refresh security status"><i class="fa-solid fa-arrows-rotate"></i></a>
        <a class="logout-mini" href="/logout.php"><i class="fa-solid fa-arrow-right-from-bracket"></i><span>Log out</span></a>
    </div>
</header>

<?php $fortressUiPolicy = fortress_security_policy(); ?>
<div id="fortress-security-runtime"
     hidden
     data-alert-poll-seconds="<?= (int)$fortressUiPolicy['alert_poll_seconds'] ?>"
     data-live-poll-seconds="<?= (int)$fortressUiPolicy['live_state_poll_seconds'] ?>"
     data-session-idle-seconds="<?= (int)$fortressUiPolicy['session_idle_seconds'] ?>"
     data-notification-user="<?= $notificationOwner ?>"></div>

<div id="fortress-notification-backdrop" class="fortress-notification-backdrop" data-notification-close hidden></div>
<section id="fortress-notification-panel" class="fortress-notification-panel" aria-label="Security notifications" aria-hidden="true" hidden>
    <div class="fortress-notification-panel-glow fortress-notification-panel-glow-one" aria-hidden="true"></div>
    <div class="fortress-notification-panel-glow fortress-notification-panel-glow-two" aria-hidden="true"></div>
    <div class="fortress-notification-panel-header">
        <div class="fortress-notification-panel-heading">
            <span class="fortress-notification-panel-icon"><i class="fa-solid fa-bell"></i></span>
            <div>
                <h2>Fortress security notifications</h2>
                <p>Threat detections, blocked attacks, authentication events, account changes, and security reports.</p>
            </div>
        </div>
        <button type="button" class="fortress-notification-close" aria-label="Close notifications" data-notification-close><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div class="fortress-notification-toolbar">
        <button type="button" class="fortress-notification-tool" data-notification-mark-all><i class="fa-solid fa-check-double"></i><span>Mark all read</span></button>
        <button type="button" class="fortress-notification-tool" data-notification-enable-toggle><i class="fa-solid fa-bell"></i><span>Live notifications on</span></button>
    </div>
    <div class="fortress-notification-list" data-notification-list>
        <div class="fortress-notification-empty fortress-notification-clear">
            <span class="fortress-notification-empty-icon"><i class="fa-solid fa-circle-check"></i></span>
            <strong>No notification events yet</strong>
            <span>Saved notifications appear instantly here while FortressAuth syncs newer security events in the background.</span>
        </div>
    </div>
</section>

<div id="fortress-security-alert-host" class="fortress-security-alert-host" aria-live="assertive" aria-atomic="false"></div>
<script src="/js/security_alerts.js" defer></script>
<script src="/js/security_live_refresh.js" defer></script>
