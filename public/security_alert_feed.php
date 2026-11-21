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

// Authentication has completed and this endpoint is read-only. Free the PHP
// session lock before file/database polling so an explicit logout is never
// blocked by a telemetry request that happened to start first.
fortress_release_session_read_lock();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

$fallbackPath = __DIR__ . '/../data/audit.log';
$cursorRaw = $_GET['cursor'] ?? null;
$clientStreamId = trim((string)($_GET['stream'] ?? ''));
$historyMode = isset($_GET['history']) && (string)$_GET['history'] === '1';

// Durable notification stream backed by PostgreSQL/Supabase. This stream ID
// intentionally stays stable across Render restarts and deployments.
$dbStreamId = 'security-events-v1';

$priority = [
    'automated_recon_block' => 112,
    'ml_assisted_block' => 110,
    'ml_assisted_strike' => 104,
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
    'automated_recon_detected' => 91,
    'automated_recon_blocked_source_attempt' => 86,
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
    if (str_contains($line, 'automated_recon_blocked_source_attempt')) return 'Reconnaissance Source Blocked Again';
    if (str_contains($line, 'automated_recon_block')) return 'Automated Reconnaissance Source Blocked';
    if (str_contains($line, 'automated_recon_detected')) return 'Automated Reconnaissance Detected';
    if (str_contains($line, 'ml_assisted_block')) return 'AI-Assisted Defense Blocked a Threat';
    if (str_contains($line, 'ml_assisted_strike')) return 'AI-Assisted Threat Strike Recorded';
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
        if (in_array($reason, ['missing_primary_session', 'incomplete_primary_auth'], true)) {
            return 'Forced Browsing Attempt Blocked';
        }
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
        'automated_recon_block', 'automated_recon_blocked_source_attempt',
        'ml_assisted_block', 'bruteforce_detected', 'honeypot_triggered', 'ip_banned', 'request_threat_detected',
        'malicious_input_detected', 'shell_attack_detected', 'csrf_validation_failed',
        'scanner_user_agent_detected', 'sensitive_path_probe', 'http_method_blocked',
        'banned_ip_middleware_block', 'banned_ip_attempt', 'school_id_qr_locked',
        'school_id_qr_rate_limited', 'school_id_qr_failed', 'password_factor_failed',
        'login_disabled_account', 'reconnaissance_probe', 'auth_rejected',
    ], true)) {
        return 'danger';
    }

    if (in_array($key, [
        'automated_recon_detected', 'ml_assisted_strike', 'csp_violation_reported', 'http_method_anomaly', 'endpoint_method_rejected',
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
    if (in_array($key, ['automated_recon_block', 'automated_recon_blocked_source_attempt', 'ml_assisted_block', 'ip_banned', 'banned_ip_attempt', 'banned_ip_middleware_block'], true)) {
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

    if (in_array($key, ['ml_threat_prediction', 'ml_assisted_strike'], true)) {
        return '/ai_threat_intelligence.php';
    }

    if (in_array($key, [
        'automated_recon_detected', 'bruteforce_detected', 'honeypot_triggered', 'request_threat_detected',
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
        if (function_exists('fortress_is_benign_recon_event_line') && fortress_is_benign_recon_event_line($line)) {
            continue;
        }

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


/**
 * Query the durable security-event stream. These helpers intentionally return
 * raw audit lines so the existing alert title/description/category logic stays
 * exactly the same while storage moves from audit.log to PostgreSQL.
 */
function fortress_alert_db_max_id(PDO $pdo): int
{
    try {
        $value = $pdo->query('SELECT COALESCE(MAX(id), 0) FROM public.security_events')->fetchColumn();
        return max(0, (int)$value);
    } catch (Throwable $e) {
        error_log('FortressAuth alert stream max-id read failed: ' . $e->getMessage());
        return -1;
    }
}

function fortress_alert_priority_placeholders(array $priority): array
{
    $keys = array_keys($priority);
    $placeholders = [];
    $params = [];
    foreach ($keys as $index => $key) {
        $name = ':k' . $index;
        $placeholders[] = $name;
        $params[$name] = $key;
    }
    return [$placeholders, $params];
}

function fortress_alert_db_history(PDO $pdo, array $priority, int $limit = 320): array
{
    try {
        [$placeholders, $params] = fortress_alert_priority_placeholders($priority);
        if (!$placeholders) return [];

        $sql = 'SELECT id, raw_line
                FROM public.security_events
                WHERE event_key IN (' . implode(',', $placeholders) . ')
                  AND raw_line IS NOT NULL
                  AND BTRIM(raw_line) <> \'\'
                ORDER BY id DESC
                LIMIT ' . max(1, min(1000, $limit));
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!is_array($rows)) return [];

        $lines = [];
        foreach (array_reverse($rows) as $row) {
            $line = trim((string)($row['raw_line'] ?? ''));
            if ($line !== '') $lines[] = $line;
        }
        return $lines;
    } catch (Throwable $e) {
        error_log('FortressAuth alert history read failed: ' . $e->getMessage());
        return [];
    }
}

function fortress_alert_db_since(PDO $pdo, array $priority, int $cursor, int $limit = 160): array
{
    try {
        [$placeholders, $params] = fortress_alert_priority_placeholders($priority);
        if (!$placeholders) return ['rows' => [], 'max_id' => fortress_alert_db_max_id($pdo), 'limit' => max(1, $limit)];

        $params[':cursor'] = max(0, $cursor);
        $safeLimit = max(1, min(500, $limit));
        $sql = 'WITH max_state AS (
                    SELECT COALESCE(MAX(id), 0)::bigint AS max_id
                    FROM public.security_events
                ), batch AS (
                    SELECT id, raw_line
                    FROM public.security_events
                    WHERE id > :cursor
                      AND event_key IN (' . implode(',', $placeholders) . ')
                      AND raw_line IS NOT NULL
                      AND BTRIM(raw_line) <> \'\'
                    ORDER BY id ASC
                    LIMIT ' . $safeLimit . '
                )
                SELECT batch.id, batch.raw_line, max_state.max_id
                FROM max_state
                LEFT JOIN batch ON TRUE
                ORDER BY batch.id ASC NULLS LAST';
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $resultRows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!is_array($resultRows) || !$resultRows) {
            return ['rows' => [], 'max_id' => 0, 'limit' => $safeLimit];
        }

        $maxId = (int)($resultRows[0]['max_id'] ?? 0);
        $rows = [];
        foreach ($resultRows as $row) {
            if ($row['id'] === null) continue;
            $rows[] = [
                'id' => (int)$row['id'],
                'raw_line' => (string)($row['raw_line'] ?? ''),
            ];
        }

        return [
            'rows' => $rows,
            'max_id' => $maxId,
            'limit' => $safeLimit,
        ];
    } catch (Throwable $e) {
        error_log('FortressAuth alert incremental read failed: ' . $e->getMessage());
        return ['rows' => [], 'max_id' => -1, 'limit' => max(1, $limit)];
    }
}

function fortress_alert_file_fallback_payload(string $path, array $priority, bool $historyMode): array
{
    $currentSize = is_file($path) ? (int)filesize($path) : 0;
    $lines = fortress_tail_audit_lines($path, $historyMode ? 320 : 160);
    return [
        'cursor' => $currentSize,
        'stream_id' => 'audit-file-fallback-v1',
        'events' => fortress_build_notifications($lines, $priority, $historyMode ? 24 : 8),
    ];
}

// History/initialization requests need an explicit stream high-water mark.
// Ordinary incremental polling skips that preliminary query and gets both the
// new alert rows and MAX(id) from fortress_alert_db_since() in one round trip.
if ($historyMode) {
    $currentDbMax = fortress_alert_db_max_id($pdo);
    if ($currentDbMax >= 0) {
        $historyLines = fortress_alert_db_history($pdo, $priority, 320);
        $events = fortress_build_notifications($historyLines, $priority, 24);
        echo json_encode([
            'success' => true,
            'cursor' => $currentDbMax,
            'stream_id' => $dbStreamId,
            'events' => $events,
            'history' => true,
            'reset' => false,
            'source' => 'database',
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $fallback = fortress_alert_file_fallback_payload($fallbackPath, $priority, true);
    echo json_encode([
        'success' => true,
        'cursor' => $fallback['cursor'],
        'stream_id' => $fallback['stream_id'],
        'events' => $fallback['events'],
        'history' => true,
        'reset' => false,
        'source' => 'audit_fallback',
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// The first request establishes a durable database event-id cursor.
if ($cursorRaw === null || !ctype_digit((string)$cursorRaw)) {
    $currentDbMax = fortress_alert_db_max_id($pdo);
    $dbAvailable = $currentDbMax >= 0;
    echo json_encode([
        'success' => true,
        'cursor' => $dbAvailable ? $currentDbMax : (is_file($fallbackPath) ? (int)filesize($fallbackPath) : 0),
        'stream_id' => $dbAvailable ? $dbStreamId : 'audit-file-fallback-v1',
        'events' => [],
        'reset' => false,
        'source' => $dbAvailable ? 'database' : 'audit_fallback',
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

$cursor = max(0, (int)$cursorRaw);
$streamChanged = $clientStreamId !== '' && !hash_equals($dbStreamId, $clientStreamId);
if ($streamChanged) {
    $currentDbMax = fortress_alert_db_max_id($pdo);
    if ($currentDbMax >= 0) {
        $historyLines = fortress_alert_db_history($pdo, $priority, 320);
        $events = fortress_build_notifications($historyLines, $priority, 24);
        echo json_encode([
            'success' => true,
            'cursor' => $currentDbMax,
            'stream_id' => $dbStreamId,
            'events' => $events,
            'history' => true,
            'reset' => true,
            'reset_reason' => 'stream_changed',
            'source' => 'database',
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

$batch = fortress_alert_db_since($pdo, $priority, $cursor, 160);
$currentDbMax = (int)($batch['max_id'] ?? -1);
if ($currentDbMax >= 0) {
    if ($cursor > $currentDbMax) {
        $historyLines = fortress_alert_db_history($pdo, $priority, 320);
        $events = fortress_build_notifications($historyLines, $priority, 24);
        echo json_encode([
            'success' => true,
            'cursor' => $currentDbMax,
            'stream_id' => $dbStreamId,
            'events' => $events,
            'history' => true,
            'reset' => true,
            'reset_reason' => 'cursor_invalid',
            'source' => 'database',
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $rows = (array)($batch['rows'] ?? []);
    $lines = [];
    $lastPriorityId = $cursor;
    foreach ($rows as $row) {
        $id = (int)($row['id'] ?? 0);
        if ($id > $lastPriorityId) $lastPriorityId = $id;
        $line = trim((string)($row['raw_line'] ?? ''));
        if ($line !== '') $lines[] = $line;
    }

    $events = fortress_build_notifications($lines, $priority, 8);
    $newCursor = count($rows) >= (int)($batch['limit'] ?? 160)
        ? $lastPriorityId
        : max($cursor, $currentDbMax);

    echo json_encode([
        'success' => true,
        'cursor' => $newCursor,
        'stream_id' => $dbStreamId,
        'events' => $events,
        'history' => false,
        'reset' => false,
        'source' => 'database',
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// Database read failures fall back to the legacy file stream. This fallback is
// intentionally best-effort; normal deployed operation uses security_events.
$fallback = fortress_alert_file_fallback_payload($fallbackPath, $priority, false);
echo json_encode([
    'success' => true,
    'cursor' => $fallback['cursor'],
    'stream_id' => $fallback['stream_id'],
    'events' => $fallback['events'],
    'history' => false,
    'reset' => $clientStreamId !== '' && $clientStreamId !== $fallback['stream_id'],
    'source' => 'audit_fallback',
], JSON_UNESCAPED_SLASHES);
