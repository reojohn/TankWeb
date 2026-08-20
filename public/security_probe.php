<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/logger.php';
require_once __DIR__ . '/../src/error_pages.php';

$probe = (string)($_GET['probe'] ?? $_SERVER['REDIRECT_URL'] ?? $_SERVER['REQUEST_URI'] ?? '/unknown');
$probePath = parse_url($probe, PHP_URL_PATH);
if (!is_string($probePath) || $probePath === '') {
    $probePath = '/unknown';
}

// Browsers commonly request these automatically. Keep them out of the threat
// timeline so real reconnaissance is not buried in harmless noise.
$lowerProbePath = strtolower($probePath);
$benignMissing = ['/favicon.ico', '/robots.txt', '/apple-touch-icon.png', '/apple-touch-icon-precomposed.png'];

// A missing static subresource requested by the browser from an already loaded
// page is not reconnaissance. Sec-Fetch-Dest distinguishes those requests from
// a user/attacker directly browsing to a path, which normally arrives as
// destination "document". Keep the extension allow-list deliberately narrow
// so random pages and security-sensitive/archive probes are still recorded.
$fetchDest = strtolower(trim((string)($_SERVER['HTTP_SEC_FETCH_DEST'] ?? '')));
$staticSubresourceDests = ['image', 'style', 'script', 'font', 'manifest'];
$staticSubresourceExtensions = [
    'css', 'js', 'mjs', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico',
    'woff', 'woff2', 'ttf', 'otf', 'eot', 'map', 'json', 'webmanifest',
];
$extension = strtolower((string)pathinfo($lowerProbePath, PATHINFO_EXTENSION));
$isBrowserStaticMiss = in_array($fetchDest, $staticSubresourceDests, true)
    && in_array($extension, $staticSubresourceExtensions, true);

$isBenignMissing = in_array($lowerProbePath, $benignMissing, true) || $isBrowserStaticMiss;

if (!$isBenignMissing) {
    audit_log(
        'reconnaissance_probe method=' . fortress_log_safe_value((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) .
        ' path=' . fortress_log_safe_value($probePath) .
        ' uid=' . (int)($_SESSION['uid'] ?? 0)
    );

    // Count the probe in the deterministic fuzzer defense. The request is
    // still returned as a generic 404 until the rolling reconnaissance
    // threshold is crossed; then the source receives a temporary 403 ban.
    $sensitiveProbe = function_exists('fortress_monitor_sensitive_path')
        ? fortress_monitor_sensitive_path($probePath) !== null
        : false;
    fortress_recon_register_probe($probePath, $sensitiveProbe);
}

fortress_render_security_error(404, 'resource_not_disclosed');
