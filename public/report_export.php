<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';
require_once __DIR__ . '/../src/report_exporter.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
require_admin_auth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method not allowed.');
}

$token = (string)($_POST['csrf_token'] ?? '');
if (!verify_csrf_token($token)) {
    audit_log('csrf_validation_failed endpoint=report_export');
    http_response_code(403);
    exit('Invalid CSRF token.');
}

$userId = (int)($_SESSION['uid'] ?? 0);
$format = strtolower(trim((string)($_POST['format'] ?? '')));
$scope = strtolower(trim((string)($_POST['report_scope'] ?? 'full')));
$eventLimit = (int)($_POST['event_limit'] ?? 50);

$allowedFormats = ['pdf', 'xlsx', 'pptx'];
$allowedScopes = ['full', 'identity', 'security'];
if (!in_array($format, $allowedFormats, true) || !in_array($scope, $allowedScopes, true)) {
    http_response_code(400);
    exit('Invalid report request.');
}
$eventLimit = max(10, min(100, $eventLimit));

try {
    $report = fortress_build_documentation_report($pdo, $userId, $scope, $eventLimit);
    [$payload, $contentType, $filename] = fortress_render_documentation_report($report, $format);

    audit_log(
        'security_report_generated uid=' . $userId .
        ' report_id=' . fortress_log_safe_value((string)($report['meta']['report_id'] ?? 'unknown'), 48) .
        ' format=' . fortress_log_safe_value($format, 12) .
        ' scope=' . fortress_log_safe_value($scope, 20) .
        ' event_limit=' . $eventLimit
    );

    header('Content-Type: ' . $contentType);
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($payload));
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    echo $payload;
    exit;
} catch (Throwable $e) {
    error_log('FortressAuth report generation failed: ' . $e->getMessage());
    $_SESSION['user_management_flash'] = [
        'type' => 'error',
        'message' => 'The documentation report could not be generated. Please try again.',
    ];
    header('Location: /user_management.php#reports');
    exit;
}
