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
$benignMissing = ['/favicon.ico', '/robots.txt', '/apple-touch-icon.png', '/apple-touch-icon-precomposed.png'];
if (!in_array(strtolower($probePath), $benignMissing, true)) {
    audit_log(
        'reconnaissance_probe method=' . fortress_log_safe_value((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) .
        ' path=' . fortress_log_safe_value($probePath) .
        ' uid=' . (int)($_SESSION['uid'] ?? 0)
    );
}

fortress_render_security_error(404, 'resource_not_disclosed');
