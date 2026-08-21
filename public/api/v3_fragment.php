<?php

declare(strict_types=1);

// React v3 uses this endpoint only to render the already-working v2 page body
// inside the persistent SPA shell. Treat the render as a silent background
// synchronization request so it does not create duplicate audit/security events.
define('FORTRESS_BACKGROUND_REQUEST', true);
define('FORTRESS_LIVE_REFRESH_REQUEST', true);

$allowed = [
    'dashboard' => 'dashboard.php',
    'access_activity' => 'access_activity.php',
    'analytics' => 'analytics.php',
    'threats' => 'threats.php',
    'ai_threat_intelligence' => 'ai_threat_intelligence.php',
    'admin_logs' => 'admin_logs.php',
    'blocked_ips' => 'blocked_ips.php',
    'security_controls' => 'security_controls.php',
    'operator' => 'user_management.php',
];

if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    header('Content-Type: text/plain; charset=utf-8');
    echo 'FortressAuth page fragments are read-only.';
    exit;
}

$page = strtolower(trim((string)($_GET['page'] ?? 'dashboard')));
if (!isset($allowed[$page])) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Unknown FortressAuth page fragment.';
    exit;
}

// Keep the included legacy page's normal GET parameters available, but remove
// the bridge-only selector so filters/conditional rendering see their v2 inputs.
unset($_GET['page']);

ob_start();
require dirname(__DIR__) . '/' . $allowed[$page];
$html = (string)ob_get_clean();

$hostNeedle = 'id="fortress-security-alert-host"';
$hostPos = strpos($html, $hostNeedle);
$endNeedle = '</div><!-- /.fortress-main-column -->';
$endPos = strrpos($html, $endNeedle);

if ($hostPos === false || $endPos === false || $endPos <= $hostPos) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'FortressAuth could not extract the requested page content.';
    exit;
}

$fragmentStart = strpos($html, '</div>', $hostPos);
if ($fragmentStart === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'FortressAuth could not locate the page content boundary.';
    exit;
}
$fragmentStart += strlen('</div>');

$fragment = substr($html, $fragmentStart, $endPos - $fragmentStart);

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Fortress-V3-Fragment: ' . $page);
echo trim($fragment);
