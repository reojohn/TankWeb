<?php

declare(strict_types=1);

define('FORTRESS_BACKGROUND_REQUEST', true);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/fortress_metrics.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
require_admin_auth();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

$path = __DIR__ . '/../data/audit.log';
$currentSize = is_file($path) ? (int)filesize($path) : 0;
$cursorRaw = $_GET['cursor'] ?? null;
$clientStreamId = trim((string)($_GET['stream'] ?? ''));
$historyMode = isset($_GET['history']) && (string)$_GET['history'] === '1';

function fortress_alert_stream_id(string $auditPath): string
{
    $marker = dirname($auditPath) . '/.alert_stream_id';
    $existing = is_file($marker) ? trim((string)@file_get_contents($marker)) : '';
    if (preg_match('/^[a-f0-9]{32}$/', $existing)) return $existing;

    try {
        $generated = bin2hex(random_bytes(16));
    } catch (Throwable $e) {
        $generated = hash('sha256', gethostname() . '|' . microtime(true) . '|' . getmypid());
        $generated = substr($generated, 0, 32);
    }

    $handle = @fopen($marker, 'x');
    if ($handle) {
        @fwrite($handle, $generated);
        @fclose($handle);
        return $generated;
    }

    $existing = is_file($marker) ? trim((string)@file_get_contents($marker)) : '';
    return preg_match('/^[a-f0-9]{32}$/', $existing) ? $existing : $generated;
}

$streamId = fortress_alert_stream_id($path);

$priority = [
    'bruteforce_detected' => 100,
    'honeypot_triggered' => 99,
    'ip_banned' => 98,
    'request_threat_detected' => 95,
    'malicious_input_detected' => 94,
    'shell_attack_detected' => 94,
    'csrf_validation_failed' => 92,
    'scanner_user_agent_detected' => 90,
    'sensitive_path_probe' => 88,
    'http_method_blocked' => 86,
    'banned_ip_middleware_block' => 85,
    'banned_ip_attempt' => 85,
    'school_id_qr_locked' => 84,
    'school_id_qr_rate_limited' => 83,
    'school_id_qr_failed' => 80,
    'password_factor_failed' => 78,
    'login_disabled_account' => 76,
    'reconnaissance_probe' => 70,
    'csp_violation_reported' => 68,
    'http_method_anomaly' => 66,
    'endpoint_method_rejected' => 65,
    'oversized_request_detected' => 64,
    'oversized_uri_detected' => 64,
    'auth_rejected' => 62,
    'user_account_deleted' => 58,
    'user_account_disabled' => 57,
    'user_password_reset' => 56,
    'user_personal_id_reset' => 56,
    'user_2fa_disabled' => 55,
    'user_2fa_enabled' => 55,
    'user_2fa_replaced' => 55,
    'current_user_security_policy_changed' => 55,
    'user_account_created' => 52,
    'user_account_updated' => 51,
    'user_account_enabled' => 50,
    'school_id_qr_reset' => 49,
    'school_id_qr_registered' => 48,
    'school_id_qr_success' => 46,
    'login_success' => 44,
    'security_report_generated' => 42,
    'failed_attempts_cleared' => 40,
];

function fortress_alert_field(string $line, string $name): string
{
    if (preg_match('/(?:^|\s)' . preg_quote($name, '/') . '=([^\s]+)/', $line, $m)) {
        return trim($m[1]);
    }
    return '';
}

function fortress_alert_title(string $line): string
{
    if (str_contains($line, 'bruteforce_detected')) return 'Brute Force Detected';
    if (str_contains($line, 'ip_banned')) return 'Attacking Source Temporarily Banned';
    if (str_contains($line, 'request_threat_detected')) {
        $issues = strtolower(fortress_alert_field($line, 'issues'));
        if (str_contains($issues, 'sqli') || str_contains($issues, 'sql')) return 'SQL Injection Attempt Detected';
        if (str_contains($issues, 'xss')) return 'Cross-Site Scripting Attempt Detected';
        if (str_contains($issues, 'shell')) return 'Command Injection Attempt Detected';
        if (str_contains($issues, 'path')) return 'Path Traversal Attempt Detected';
        return 'Suspicious Request Payload Detected';
    }
    if (str_contains($line, 'malicious_input_detected')) {
        $issues = strtolower(fortress_alert_field($line, 'issues'));
        if (str_contains($issues, 'sqli') || str_contains($issues, 'sql')) return 'SQL Injection Attempt Detected';
        if (str_contains($issues, 'xss')) return 'Cross-Site Scripting Attempt Detected';
        if (str_contains($issues, 'path')) return 'Path Traversal Attempt Detected';
        return 'Malicious Login Input Detected';
    }
    if (str_contains($line, 'shell_attack_detected')) return 'Command Injection Attempt Detected';
    if (str_contains($line, 'csrf_validation_failed')) return 'CSRF Attack Rejected';
    if (str_contains($line, 'scanner_user_agent_detected')) return 'Security Scanner Detected';
    if (str_contains($line, 'sensitive_path_probe')) return 'Sensitive Resource Probe Detected';
    if (str_contains($line, 'reconnaissance_probe')) return 'Reconnaissance Attempt Detected';
    if (str_contains($line, 'http_method_blocked')) return 'Dangerous HTTP Method Blocked';
    if (str_contains($line, 'http_method_anomaly')) return 'Unusual HTTP Method Detected';
    if (str_contains($line, 'endpoint_method_rejected')) return 'Invalid Endpoint Method Rejected';
    if (str_contains($line, 'oversized_request_detected')) return 'Oversized Request Detected';
    if (str_contains($line, 'oversized_uri_detected')) return 'Oversized URI Detected';
    if (str_contains($line, 'banned_ip_')) return 'Banned Source Blocked';
    if (str_contains($line, 'school_id_qr_locked') || str_contains($line, 'school_id_qr_rate_limited')) return 'Personal ID Attack Rate Limited';
    if (str_contains($line, 'school_id_qr_failed')) return 'Invalid Personal ID Attempt Detected';
    if (str_contains($line, 'password_factor_failed')) return 'Password Attack Attempt Detected';
    if (str_contains($line, 'csp_violation_reported')) return 'Browser Security Policy Violation';
    if (str_contains($line, 'honeypot_triggered')) return 'Honeypot Intrusion Detected';
    if (str_contains($line, 'auth_rejected')) {
        $reason = strtolower(fortress_alert_field($line, 'reason'));
        if (str_contains($reason, 'fingerprint')) return 'Suspicious Session Reuse Blocked';
        if (str_contains($reason, 'revoked')) return 'Revoked Session Blocked';
        if (str_contains($reason, 'multifactor')) return 'Protected Page Access Blocked';
        return 'Protected Resource Access Blocked';
    }

    return fortress_event_title($line);
}

function fortress_notification_severity(string $key): string
{
    if (in_array($key, [
        'bruteforce_detected', 'honeypot_triggered', 'ip_banned', 'request_threat_detected',
        'malicious_input_detected', 'shell_attack_detected', 'csrf_validation_failed',
        'scanner_user_agent_detected', 'sensitive_path_probe', 'http_method_blocked',
        'banned_ip_middleware_block', 'banned_ip_attempt', 'school_id_qr_locked',
        'school_id_qr_rate_limited', 'school_id_qr_failed', 'password_factor_failed',
        'login_disabled_account', 'reconnaissance_probe', 'auth_rejected',
    ], true)) {
        return 'danger';
    }

    if (in_array($key, [
        'csp_violation_reported', 'http_method_anomaly', 'endpoint_method_rejected',
        'oversized_request_detected', 'oversized_uri_detected', 'user_account_disabled',
        'user_account_deleted', 'user_password_reset', 'user_personal_id_reset',
        'user_2fa_disabled', 'current_user_security_policy_changed',
    ], true)) {
        return 'warning';
    }

    if (in_array($key, [
        'login_success', 'school_id_qr_success', 'school_id_qr_registered',
        'user_account_created', 'user_account_enabled', 'failed_attempts_cleared',
    ], true)) {
        return 'success';
    }

    return 'activity';
}

function fortress_notification_target(string $key): string
{
    if (in_array($key, ['ip_banned', 'banned_ip_attempt', 'banned_ip_middleware_block'], true)) {
        return '/blocked_ips.php';
    }

    if (in_array($key, [
        'login_success', 'password_factor_failed', 'school_id_qr_failed', 'school_id_qr_success',
        'school_id_qr_locked', 'school_id_qr_rate_limited', 'login_disabled_account',
    ], true)) {
        return '/access_activity.php';
    }

    if (str_starts_with($key, 'user_') || in_array($key, [
        'school_id_qr_registered', 'school_id_qr_reset', 'current_user_security_policy_changed',
    ], true)) {
        return '/user_management.php#user-management';
    }

    if ($key === 'security_report_generated') {
        return '/user_management.php#reports';
    }

    if ($key === 'ml_threat_prediction') {
        return '/ai_threat_intelligence.php';
    }

    if (in_array($key, [
        'bruteforce_detected', 'honeypot_triggered', 'request_threat_detected',
        'malicious_input_detected', 'shell_attack_detected', 'csrf_validation_failed',
        'scanner_user_agent_detected', 'sensitive_path_probe', 'reconnaissance_probe',
        'http_method_blocked', 'http_method_anomaly', 'endpoint_method_rejected',
        'oversized_request_detected', 'oversized_uri_detected', 'auth_rejected',
    ], true)) {
        return '/threats.php';
    }

    return '/admin_logs.php#audit-logs';
}

function fortress_notification_timestamp(string $line): string
{
    $date = fortress_event_datetime($line);
    if (!$date) return gmdate(DATE_ATOM);
    return $date->format(DATE_ATOM);
}

function fortress_tail_audit_lines(string $path, int $maxLines = 260): array
{
    if (!is_file($path) || !is_readable($path)) return [];

    $handle = @fopen($path, 'rb');
    if (!$handle) return [];

    $lines = [];
    $buffer = '';
    $position = (int)filesize($path);
    $chunkSize = 8192;

    while ($position > 0 && count($lines) < $maxLines) {
        $readSize = min($chunkSize, $position);
        $position -= $readSize;
        @fseek($handle, $position);
        $chunk = fread($handle, $readSize);
        if ($chunk === false) break;
        $buffer = $chunk . $buffer;

        $parts = preg_split('/\r?\n/', $buffer) ?: [];
        if ($position > 0) {
            $buffer = array_shift($parts) ?? '';
        } else {
            $buffer = '';
        }

        for ($i = count($parts) - 1; $i >= 0; $i--) {
            $line = trim((string)$parts[$i]);
            if ($line === '') continue;
            $lines[] = $line;
            if (count($lines) >= $maxLines) break 2;
        }
    }

    fclose($handle);

    if ($position === 0 && $buffer !== '' && count($lines) < $maxLines) {
        $lines[] = trim($buffer);
    }

    return array_reverse(array_filter($lines, static fn($line) => $line !== ''));
}

function fortress_build_notifications(array $lines, array $priority, int $limit = 30): array
{
    $grouped = [];

    foreach ($lines as $line) {
        $key = fortress_event_key($line);
        if (!isset($priority[$key])) continue;

        // Background alert/live-state requests are already excluded at the
        // authentication layer, so a remaining auth_rejected event represents
        // an actual protected-resource access attempt and must reach admins.

        $rid = fortress_alert_field($line, 'rid');
        $groupKey = $rid !== '' ? $rid : hash('sha256', $line);
        $candidate = [
            'id' => substr(hash('sha256', $line), 0, 20),
            'rid' => $rid,
            'key' => $key,
            'title' => fortress_alert_title($line),
            'description' => fortress_event_description($line),
            'source_ip' => fortress_log_ip($line),
            'time' => fortress_event_time($line, 'H:i:s'),
            'timestamp' => fortress_notification_timestamp($line),
            'outcome' => fortress_event_outcome($line),
            'category' => fortress_event_category($line),
            'severity' => fortress_notification_severity($key),
            'target' => fortress_notification_target($key),
            'priority' => $priority[$key],
        ];

        if (!isset($grouped[$groupKey]) || $candidate['priority'] > $grouped[$groupKey]['priority']) {
            $grouped[$groupKey] = $candidate;
        }
    }

    $events = array_values($grouped);
    usort($events, static function (array $a, array $b): int {
        $timeCompare = strcmp((string)$b['timestamp'], (string)$a['timestamp']);
        if ($timeCompare !== 0) return $timeCompare;
        return $b['priority'] <=> $a['priority'];
    });

    $events = array_slice($events, 0, $limit);
    foreach ($events as &$event) unset($event['priority']);
    unset($event);

    return $events;
}

if ($historyMode) {
    $historyLines = fortress_tail_audit_lines($path, 320);
    $events = fortress_build_notifications($historyLines, $priority, 24);

    echo json_encode([
        'success' => true,
        'cursor' => $currentSize,
        'stream_id' => $streamId,
        'events' => $events,
        'history' => true,
        'reset' => false,
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// A legacy first request still only establishes the cursor. The upgraded
// notification client uses ?history=1 first, then resumes cursor polling.
if ($cursorRaw === null || !ctype_digit((string)$cursorRaw)) {
    echo json_encode([
        'success' => true,
        'cursor' => $currentSize,
        'stream_id' => $streamId,
        'events' => [],
        'reset' => false,
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

$cursor = max(0, (int)$cursorRaw);
$streamChanged = $clientStreamId !== '' && !hash_equals($streamId, $clientStreamId);
$cursorInvalid = $cursor > $currentSize;

// Render and other container hosts can recreate the writable data directory on
// a deploy/restart. A browser may still hold the cursor from the previous
// container. When the log stream changes (or the cursor is now beyond EOF),
// recover recent security history instead of silently dropping those events.
if ($streamChanged || $cursorInvalid) {
    $historyLines = fortress_tail_audit_lines($path, 320);
    $events = fortress_build_notifications($historyLines, $priority, 24);

    echo json_encode([
        'success' => true,
        'cursor' => $currentSize,
        'stream_id' => $streamId,
        'events' => $events,
        'history' => true,
        'reset' => true,
        'reset_reason' => $streamChanged ? 'stream_changed' : 'cursor_invalid',
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

if (!is_file($path)) {
    echo json_encode([
        'success' => true,
        'cursor' => 0,
        'stream_id' => $streamId,
        'events' => [],
        'reset' => false,
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

$handle = @fopen($path, 'rb');
if (!$handle) {
    echo json_encode([
        'success' => true,
        'cursor' => $currentSize,
        'stream_id' => $streamId,
        'events' => [],
        'reset' => false,
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

@fseek($handle, $cursor);
$lines = [];
while (!feof($handle) && count($lines) < 160) {
    $line = fgets($handle);
    if ($line === false) break;
    $line = trim($line);
    if ($line !== '') $lines[] = $line;
}
$newCursor = (int)ftell($handle);
fclose($handle);

$events = fortress_build_notifications($lines, $priority, 8);

echo json_encode([
    'success' => true,
    'cursor' => max($newCursor, $currentSize),
    'stream_id' => $streamId,
    'events' => $events,
    'history' => false,
    'reset' => false,
], JSON_UNESCAPED_SLASHES);
