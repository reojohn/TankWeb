<?php

declare(strict_types=1);

// Route-entry heartbeat for the React shell. It updates the authenticated PHP
// session and records the same page-view audit event as v2 without re-running
// the full legacy page just to log navigation.
define('FORTRESS_BACKGROUND_REQUEST', true);

require __DIR__ . '/../../src/middleware.php';
require_once __DIR__ . '/../../src/config.php';
require_once __DIR__ . '/../../src/auth.php';
require_once __DIR__ . '/../../src/logger.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_admin_auth();

if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

$userId = (int)($_SESSION['uid'] ?? 0);
$page = strtolower(trim((string)($_GET['page'] ?? 'dashboard')));
$routes = [
    'dashboard' => ['/dashboard.php', 'dashboard_access uid=' . $userId],
    'access_activity' => ['/access_activity.php', 'access_activity_viewed uid=' . $userId],
    'analytics' => ['/analytics.php', 'security_analytics_viewed uid=' . $userId],
    'threats' => ['/threats.php', 'threat_center_viewed uid=' . $userId],
    'ai_threat_intelligence' => ['/ai_threat_intelligence.php', 'ai_threat_intelligence_viewed uid=' . $userId],
    'admin_logs' => ['/admin_logs.php', 'security_logs_viewed uid=' . $userId],
    'blocked_ips' => ['/blocked_ips.php', 'blocked_ips_viewed uid=' . $userId],
    'security_controls' => ['/security_controls.php', 'security_controls_viewed uid=' . $userId],
];

if (!isset($routes[$page])) {
    http_response_code(404);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'message' => 'Unknown FortressAuth route.']);
    exit;
}

// Background requests intentionally do not advance last_activity in auth.php.
// A real SPA route change is user activity, so advance it explicitly here.
$_SESSION['last_activity'] = time();
$_SERVER['REQUEST_URI'] = $routes[$page][0];
audit_log($routes[$page][1]);

http_response_code(204);
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
