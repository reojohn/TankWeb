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

    $entry = sprintf('[%s] rid=%s ip=%s ua=%s %s%s', $time, $rid, $ip, $ua, $safeMessage, PHP_EOL);
    @file_put_contents($file, $entry, FILE_APPEND | LOCK_EX);
}
