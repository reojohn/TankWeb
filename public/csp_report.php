<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/logger.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    audit_log('endpoint_method_rejected method=' . fortress_log_safe_value((string)($_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN')) . ' path=/csp_report.php allowed=POST uid=' . (int)($_SESSION['uid'] ?? 0));
    http_response_code(405);
    header('Allow: POST');
    exit;
}

$length = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($length > 65536) {
    audit_log('oversized_request_detected method=POST path=/csp_report.php bytes=' . $length . ' uid=' . (int)($_SESSION['uid'] ?? 0));
    http_response_code(413);
    exit;
}

$raw = (string)file_get_contents('php://input');
$data = json_decode($raw, true);
$report = is_array($data) ? ($data['csp-report'] ?? $data['body'] ?? $data) : [];

$directive = is_array($report) ? (string)($report['violated-directive'] ?? $report['effective-directive'] ?? 'unknown') : 'unknown';
$blocked = is_array($report) ? (string)($report['blocked-uri'] ?? $report['blockedURL'] ?? 'unknown') : 'unknown';
$document = is_array($report) ? (string)($report['document-uri'] ?? $report['documentURL'] ?? 'unknown') : 'unknown';

// Keep only scheme/host/path for CSP evidence and discard query/fragment data.
function fortress_csp_safe_uri(string $value): string
{
    if ($value === '' || $value === 'unknown' || $value === 'inline' || $value === 'eval') {
        return fortress_log_safe_value($value);
    }
    $parts = parse_url($value);
    if (!is_array($parts)) {
        return fortress_log_safe_value($value, 120);
    }
    $scheme = isset($parts['scheme']) ? $parts['scheme'] . '://' : '';
    $host = (string)($parts['host'] ?? '');
    $path = (string)($parts['path'] ?? '');
    return fortress_log_safe_value($scheme . $host . $path, 160);
}

audit_log(
    'csp_violation_reported directive=' . fortress_log_safe_value($directive, 100) .
    ' blocked=' . fortress_csp_safe_uri($blocked) .
    ' document=' . fortress_csp_safe_uri($document) .
    ' uid=' . (int)($_SESSION['uid'] ?? 0)
);

http_response_code(204);
