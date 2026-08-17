<?php

declare(strict_types=1);

function fortress_logger_env_bool(string $name, bool $default = false): bool
{
    $raw = getenv($name);
    if ($raw === false || trim((string)$raw) === '') {
        return $default;
    }
    return filter_var($raw, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? $default;
}

// Resolve proxy headers only when the deployment explicitly declares them trusted.
function getRealIP(): string
{
    $remote = trim((string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'));

    if (!fortress_logger_env_bool('TRUST_PROXY_HEADERS', false)) {
        return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : 'unknown';
    }

    $candidates = [];
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $candidates[] = trim((string)$_SERVER['HTTP_CF_CONNECTING_IP']);
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        foreach (explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']) as $forwarded) {
            $candidates[] = trim($forwarded);
        }
    }
    $candidates[] = $remote;

    foreach ($candidates as $candidate) {
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }

    return 'unknown';
}

/**
 * Short per-request correlation identifier. It is intentionally random and
 * contains no session identifier or other secret material.
 */
function fortress_request_id(): string
{
    static $requestId = null;
    if (is_string($requestId) && $requestId !== '') {
        return $requestId;
    }

    try {
        $requestId = bin2hex(random_bytes(6));
    } catch (Throwable $e) {
        $requestId = substr(hash('sha256', microtime(true) . '|' . getmypid()), 0, 12);
    }

    return $requestId;
}

function fortress_redact_log_message(string $message): string
{
    // Defense-in-depth: redact common secret-bearing key/value formats if a future
    // caller accidentally passes request data into audit_log().
    $patterns = [
        '/\b(password|passwd|pass|password_hash|db_pass|secret|token|csrf_token|qr_value|session_id|authorization|cookie)\s*[=:]\s*([^\s,&;]+)/i',
        '/("(?:password|passwd|password_hash|db_pass|secret|token|csrf_token|qr_value|session_id|authorization|cookie)"\s*:\s*)"[^"]*"/i',
    ];

    $replacements = [
        '$1=[REDACTED]',
        '$1"[REDACTED]"',
    ];

    return preg_replace($patterns, $replacements, $message) ?? '[REDACTED_LOG_ENTRY]';
}

function fortress_log_safe_value(string $value, int $maxLength = 180): string
{
    $value = str_replace(["\r", "\n", "\t"], [' ', ' ', ' '], $value);
    $value = preg_replace('/\s+/', ' ', trim($value)) ?? '';
    $value = str_replace(['=', '"', "'"], ['-', '', ''], $value);
    if (strlen($value) > $maxLength) {
        $value = substr($value, 0, $maxLength) . '…';
    }
    return $value === '' ? '-' : $value;
}



/**
 * Convert the existing audit message into structured fields for persistent
 * database storage. The original raw audit line is still preserved verbatim.
 */
function fortress_audit_message_fields(string $message): array
{
    $message = trim($message);
    if ($message === '') {
        return ['event_key' => 'unknown_event', 'fields' => []];
    }

    $parts = preg_split('/\s+/', $message) ?: [];
    $eventKey = (string)array_shift($parts);
    $eventKey = preg_replace('/[^A-Za-z0-9_.:-]/', '', $eventKey) ?? '';
    if ($eventKey === '') {
        $eventKey = 'unknown_event';
    }

    $fields = [];
    foreach ($parts as $part) {
        if (!str_contains($part, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $part, 2);
        $key = preg_replace('/[^A-Za-z0-9_.:-]/', '', trim($key)) ?? '';
        if ($key === '') {
            continue;
        }
        $fields[$key] = trim($value);
    }

    return ['event_key' => $eventKey, 'fields' => $fields];
}

function fortress_audit_severity(string $eventKey, array $fields): string
{
    $issues = strtolower((string)($fields['issues'] ?? ''));

    if (
        str_contains($issues, 'sql_attack') ||
        str_contains($issues, 'shell_attack') ||
        str_contains($issues, 'command') ||
        in_array($eventKey, [
            'bruteforce_detected', 'banned_ip_middleware_block', 'ml_assisted_block',
            'honeypot_triggered', 'honeypot_access',
        ], true)
    ) {
        return 'HIGH';
    }

    if (
        str_contains($issues, 'xss') ||
        str_contains($issues, 'path_traversal') ||
        in_array($eventKey, [
            'malicious_input_detected', 'auth_rejected', 'ml_assisted_strike',
            'reconnaissance_probe', 'sensitive_path_probe',
            'scanner_user_agent_detected', 'http_method_abuse',
            'oversized_request', 'csrf_rejected', 'csp_violation',
            'login_locked_out',
        ], true)
    ) {
        return 'WARNING';
    }

    return 'INFO';
}

function fortress_audit_outcome(string $eventKey): string
{
    if (
        str_contains($eventKey, 'blocked') ||
        str_contains($eventKey, 'rejected') ||
        in_array($eventKey, [
            'malicious_input_detected', 'auth_rejected', 'ml_assisted_block', 'bruteforce_detected',
            'banned_ip_middleware_block', 'reconnaissance_probe',
            'sensitive_path_probe', 'scanner_user_agent_detected',
            'http_method_abuse', 'oversized_request', 'csrf_rejected',
            'csp_violation', 'login_locked_out', 'unsafe_redirect_blocked',
        ], true)
    ) {
        return 'BLOCKED';
    }

    if (str_contains($eventKey, 'failed') || str_contains($eventKey, 'failure')) {
        return 'REJECTED';
    }

    if (str_contains($eventKey, 'success') || str_contains($eventKey, 'passed')) {
        return 'PASSED';
    }

    return 'RECORDED';
}

/**
 * Best-effort persistent copy of an audit event in Supabase/PostgreSQL.
 * A database failure must never interrupt authentication or security controls,
 * so failures are sent only to PHP's error log while audit.log remains intact.
 */
function fortress_persist_security_event(string $safeMessage, string $rawEntry, string $time, string $ip, string $ua, string $rid): void
{
    global $pdo;

    if (!isset($pdo) || !($pdo instanceof PDO)) {
        return;
    }

    try {
        $parsed = fortress_audit_message_fields($safeMessage);
        $eventKey = (string)$parsed['event_key'];
        $fields = (array)$parsed['fields'];

        $uid = null;
        foreach (['uid', 'user_id', 'actor_uid'] as $uidKey) {
            if (isset($fields[$uidKey]) && ctype_digit((string)$fields[$uidKey])) {
                $uid = (int)$fields[$uidKey];
                break;
            }
        }
        if ($uid === null && isset($_SESSION['uid']) && is_numeric($_SESSION['uid'])) {
            $uid = (int)$_SESSION['uid'];
        }

        $username = null;
        foreach (['username', 'user', 'target'] as $usernameKey) {
            if (!empty($fields[$usernameKey])) {
                $username = substr((string)$fields[$usernameKey], 0, 160);
                break;
            }
        }

        $requestUri = (string)($_SERVER['REQUEST_URI'] ?? '');
        $requestPath = $requestUri !== '' ? (string)(parse_url($requestUri, PHP_URL_PATH) ?: $requestUri) : null;
        if (is_string($requestPath)) {
            $requestPath = substr($requestPath, 0, 500);
        }
        $method = strtoupper(substr((string)($_SERVER['REQUEST_METHOD'] ?? ''), 0, 16));
        $method = $method !== '' ? $method : null;

        $issues = isset($fields['issues']) ? substr((string)$fields['issues'], 0, 1000) : null;
        $severity = fortress_audit_severity($eventKey, $fields);
        $outcome = fortress_audit_outcome($eventKey);

        $metadata = $fields;
        $metadata['request_id'] = $rid;
        $metadata['user_agent'] = $ua;
        $metadataJson = json_encode($metadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($metadataJson)) {
            $metadataJson = '{}';
        }

        $stmt = $pdo->prepare(
            'INSERT INTO public.security_events (
                occurred_at, event_key, source_ip, user_id, username,
                request_path, http_method, issues, severity, outcome,
                raw_line, metadata
             ) VALUES (
                :occurred_at, :event_key, :source_ip, :user_id, :username,
                :request_path, :http_method, :issues, :severity, :outcome,
                :raw_line, CAST(:metadata AS jsonb)
             )'
        );
        $stmt->execute([
            'occurred_at' => $time,
            'event_key' => substr($eventKey, 0, 190),
            'source_ip' => $ip !== '' ? substr($ip, 0, 64) : null,
            'user_id' => $uid,
            'username' => $username,
            'request_path' => $requestPath,
            'http_method' => $method,
            'issues' => $issues,
            'severity' => $severity,
            'outcome' => $outcome,
            'raw_line' => rtrim($rawEntry),
            'metadata' => $metadataJson,
        ]);
    } catch (Throwable $e) {
        error_log('FortressAuth security_events persistence failed: ' . $e->getMessage());
    }
}

function audit_log(string $message): void
{
    // A live synchronization GET only re-renders already-authorized UI.
    // Suppress its page-view logging so live synchronization never grows
    // audit.log or recursively triggers another UI synchronization.
    if (defined('FORTRESS_LIVE_REFRESH_REQUEST') && FORTRESS_LIVE_REFRESH_REQUEST === true) {
        return;
    }

    $dir = __DIR__ . '/../data';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }

    $file = $dir . '/audit.log';
    $safeMessage = fortress_redact_log_message($message);
    $safeMessage = str_replace(["\n", "\r"], ['\\n', '\\r'], $safeMessage);
    $safeMessage = substr($safeMessage, 0, 2000);

    $time = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:sP');
    $ip = getRealIP();
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
    $ua = str_replace(["\r", "\n"], '', $ua);
    $ua = substr($ua, 0, 200);
    $rid = fortress_request_id();

    // Mark deterministic security evidence for the ML shutdown replay hook.
    // This is request-local only; no secret/request body is copied into memory.
    // ML-generated audit events are excluded to prevent a replay feedback loop.
    $parsedForMl = fortress_audit_message_fields($safeMessage);
    $mlEventKey = (string)($parsedForMl['event_key'] ?? '');
    if ($mlEventKey !== '' && !str_starts_with($mlEventKey, 'ml_')) {
        $mlFields = (array)($parsedForMl['fields'] ?? []);
        $mlSeverity = fortress_audit_severity($mlEventKey, $mlFields);
        $mlOutcome = fortress_audit_outcome($mlEventKey);
        $mlExplicitTriggers = [
            'login_failed', 'password_factor_failed', 'school_id_qr_failed',
            'school_id_qr_locked', 'school_id_qr_rate_limited',
            'request_threat_detected', 'malicious_input_detected',
            'sensitive_path_probe', 'scanner_user_agent_detected',
            'http_method_blocked', 'http_method_anomaly', 'endpoint_method_rejected',
            'csrf_validation_failed', 'csrf_rejected', 'auth_rejected',
            'bruteforce_detected', 'honeypot_triggered', 'honeypot_access',
            'csp_violation', 'ip_banned', 'banned_ip_attempt'
        ];
        if (
            in_array($mlEventKey, $mlExplicitTriggers, true) ||
            $mlSeverity !== 'INFO' ||
            in_array($mlOutcome, ['BLOCKED', 'REJECTED'], true)
        ) {
            $GLOBALS['FORTRESS_ML_SECURITY_EVENT_SEEN'] = [
                'event_key' => $mlEventKey,
                'ts' => time(),
            ];
        }
    }

    $entry = sprintf('[%s] rid=%s ip=%s ua=%s %s%s', $time, $rid, $ip, $ua, $safeMessage, PHP_EOL);
    @file_put_contents($file, $entry, FILE_APPEND | LOCK_EX);

    // Keep the existing flat-file log as a fallback, while also persisting a
    // durable copy in Supabase/PostgreSQL so Render restarts cannot erase it.
    fortress_persist_security_event($safeMessage, $entry, $time, $ip, $ua, $rid);
}
