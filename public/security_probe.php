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
$lowerProbePath = strtolower(rawurldecode($probePath));

// Phone browsers request a few discovery/icon resources automatically during
// reloads. These are browser behavior, not user-driven endpoint enumeration.
// Match both root-level and nested variants because iOS/Android browsers can
// derive the request from the current document directory (for example /app/).
$benignBrowserBasenames = [
    'favicon.ico',
    'robots.txt',
    'site.webmanifest',
    'manifest.webmanifest',
    'manifest.json',
    'browserconfig.xml',
];
$probeBasename = strtolower((string)basename($lowerProbePath));
$isAppleTouchIcon = preg_match('/^apple-touch-icon(?:-[0-9]+x[0-9]+)?(?:-precomposed)?\.png$/i', $probeBasename) === 1;
$isKnownBrowserDiscoveryPath = in_array($probeBasename, $benignBrowserBasenames, true)
    || $isAppleTouchIcon
    || str_starts_with($lowerProbePath, '/.well-known/appspecific/')
    || $lowerProbePath === '/.well-known/traffic-advice';

// Missing browser assets are not reconnaissance. In production FortressAuth
// sits behind Vercel/Render, and some proxies/clients do not preserve
// Sec-Fetch-Dest. Requiring that header caused harmless image misses such as
// /fortress.png to be persisted as Recon / 404 probes every time the login
// screen loaded. Treat a narrow set of ordinary web-asset extensions as
// benign, but never suppress a path that the sensitive-path detector marks as
// security relevant (for example config/settings/credential-style names).
$fetchDest = strtolower(trim((string)($_SERVER['HTTP_SEC_FETCH_DEST'] ?? '')));
$staticSubresourceDests = ['image', 'style', 'script', 'font', 'manifest'];
$staticSubresourceExtensions = [
    'css', 'js', 'mjs', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico',
    'woff', 'woff2', 'ttf', 'otf', 'eot', 'map', 'json', 'webmanifest',
];
$extension = strtolower((string)pathinfo($lowerProbePath, PATHINFO_EXTENSION));
$sensitiveProbe = function_exists('fortress_monitor_sensitive_path')
    ? fortress_monitor_sensitive_path($probePath) !== null
    : false;
$isStaticAssetMiss = in_array($extension, $staticSubresourceExtensions, true)
    && !$sensitiveProbe;
$isBrowserStaticMiss = $isStaticAssetMiss
    && ($fetchDest === '' || in_array($fetchDest, $staticSubresourceDests, true));

// A subresource destination is also strong browser evidence even when the
// automatically requested path has no useful extension. Sensitive paths are
// never suppressed, regardless of Sec-Fetch-Dest or filename.
$isBrowserSubresourceMiss = !$sensitiveProbe
    && in_array($fetchDest, $staticSubresourceDests, true);

$isBenignMissing = !$sensitiveProbe && (
    $isKnownBrowserDiscoveryPath
    || $isBrowserStaticMiss
    || $isBrowserSubresourceMiss
);

if (!$isBenignMissing) {
    audit_log(
        'reconnaissance_probe method=' . fortress_log_safe_value((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) .
        ' path=' . fortress_log_safe_value($probePath) .
        ' uid=' . (int)($_SESSION['uid'] ?? 0)
    );

    // Count the probe in the deterministic fuzzer defense. The request is
    // still returned as a generic 404 until the rolling reconnaissance
    // threshold is crossed; then the source receives a temporary 403 ban.
    fortress_recon_register_probe($probePath, $sensitiveProbe);
}

fortress_render_security_error(404, 'resource_not_disclosed');
