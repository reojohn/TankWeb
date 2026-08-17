<?php

declare(strict_types=1);

// Silent live-page synchronization requests must not generate their own
// request-monitor / ML telemetry. Otherwise a refresh caused by a security
// event would create another security-state change and could refresh forever.
if ((string)($_SERVER['HTTP_X_FORTRESS_LIVE_REFRESH'] ?? '') === '1') {
    if (!defined('FORTRESS_LIVE_REFRESH_REQUEST')) {
        define('FORTRESS_LIVE_REFRESH_REQUEST', true);
    }
    if (!defined('FORTRESS_BACKGROUND_REQUEST')) {
        define('FORTRESS_BACKGROUND_REQUEST', true);
    }
}

// Load environment/application configuration before any security component
// reads environment-backed settings such as ML_SERVICE_ENABLED/URL/TOKEN.
// Pages that later require config.php use require_once, so this is loaded only once.
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/request_monitor.php';
require_once __DIR__ . '/ml_threat.php';
require_once __DIR__ . '/error_pages.php';
require_once __DIR__ . '/bruteforce.php';

header_remove('X-Powered-By');

$ip = getRealIP();
$whitelist = ['127.0.0.1', '::1'];
$banFile = __DIR__ . '/../data/banned_ips.txt';

if (!in_array($ip, $whitelist, true) && is_file($banFile)) {
    $banned = file($banFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    if (in_array($ip, $banned, true)) {
        audit_log('banned_ip_middleware_block source=flat_file');
        fortress_render_security_error(403, 'banned_source');
    }
}

// Database-backed bans are authoritative. This makes brute-force, honeypot,
// manual, and AI-assisted bans survive Render sleeps/redeploys instead of
// depending only on the instance-local fallback file.
if (!in_array($ip, $whitelist, true) && isset($pdo) && $pdo instanceof PDO && is_ip_banned($pdo, $ip)) {
    audit_log('banned_ip_middleware_block source=database');
    fortress_render_security_error(403, 'temporary_ip_ban');
}

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(self)');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Permitted-Cross-Domain-Policies: none');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if (fortress_request_is_https()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

header(
    "Content-Security-Policy: " .
    "default-src 'self'; " .
    "base-uri 'self'; " .
    "form-action 'self'; " .
    "frame-ancestors 'none'; " .
    "script-src 'self'; " .
    "style-src 'self' 'unsafe-inline'; " .
    "img-src 'self' data: blob:; " .
    "font-src 'self' data:; " .
    "connect-src 'self'; " .
    "media-src 'self' blob:; " .
    "worker-src 'self' blob:; " .
    "object-src 'none'; " .
    "report-uri /csp_report.php;"
);

fortress_monitor_run();
fortress_ml_evaluate_request();

function safe_redirect(string $url): never
{
    // Only same-origin absolute paths are accepted. //evil.example is rejected.
    if (
        preg_match('#^/[A-Za-z0-9._~!$&\'()*+,;=:@%/?-]*$#', $url) === 1 &&
        !str_starts_with($url, '//') &&
        !preg_match('/[\r\n]/', $url)
    ) {
        header('Location: ' . $url);
        exit;
    }

    audit_log('unsafe_redirect_blocked target_length=' . strlen($url));
    fortress_render_security_error(400, 'unsafe_redirect_blocked');
}
