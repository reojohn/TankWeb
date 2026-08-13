<?php

declare(strict_types=1);

require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/security_policy.php';

/**
 * Request telemetry for the course pentesting environment.
 *
 * This layer is deliberately detection-focused. It records suspicious behavior
 * across PHP endpoints without logging credential/token/QR values and without
 * turning heuristic signatures into a broad application-wide blocking WAF.
 */

function fortress_monitor_secret_key(string $key): bool
{
    return preg_match('/(?:pass(word)?|passwd|secret|token|csrf|qr(?:_|$)|cookie|authorization|session|credential|api[_-]?key)/i', $key) === 1;
}

function fortress_monitor_normalize_text(string $value): string
{
    $value = substr($value, 0, 4096);
    // Decode a few times so common percent/double-encoding reconnaissance is visible.
    for ($i = 0; $i < 2; $i++) {
        $decoded = rawurldecode($value);
        if ($decoded === $value) {
            break;
        }
        $value = $decoded;
    }
    return $value;
}

function fortress_monitor_collect_values(array $input, string $prefix = '', int $depth = 0): array
{
    if ($depth > 2) {
        return [];
    }

    $collected = [];
    foreach ($input as $key => $value) {
        if (count($collected) >= 50) {
            break;
        }

        $keyString = (string)$key;
        $name = $prefix === '' ? $keyString : $prefix . '.' . $keyString;
        if (fortress_monitor_secret_key($name)) {
            continue;
        }

        if (is_array($value)) {
            $collected += fortress_monitor_collect_values($value, $name, $depth + 1);
            continue;
        }

        if (is_scalar($value) || $value === null) {
            $collected[$name] = fortress_monitor_normalize_text((string)$value);
        }
    }
    return $collected;
}

function fortress_monitor_sensitive_path(string $path): ?string
{
    $lower = strtolower(fortress_monitor_normalize_text($path));

    $exactOrPrefix = [
        '/.env' => 'environment_file',
        '/.git' => 'git_metadata',
        '/vendor' => 'dependency_tree',
        '/composer.json' => 'dependency_manifest',
        '/composer.lock' => 'dependency_lockfile',
        '/phpinfo.php' => 'phpinfo_probe',
        '/server-status' => 'server_status',
        '/adminer.php' => 'database_admin_tool',
        '/phpmyadmin' => 'database_admin_tool',
        '/wp-admin' => 'common_cms_probe',
        '/wp-login.php' => 'common_cms_probe',
        '/.well-known/security.txt~' => 'backup_file',
    ];

    foreach ($exactOrPrefix as $needle => $label) {
        if ($lower === $needle || str_starts_with($lower, $needle . '/') || str_starts_with($lower, $needle . '?')) {
            return $label;
        }
    }

    if (preg_match('#(?:^|/)(?:backup|database|dump|config|settings|credentials?)(?:[._-]|$)#i', $lower)) {
        return 'sensitive_filename';
    }

    if (preg_match('/\.(?:bak|old|orig|save|swp|sql|sqlite|zip|tar|tgz|gz|7z)(?:$|\?)/i', $lower)) {
        return 'backup_or_archive';
    }

    if (str_contains($lower, '../') || str_contains($lower, '..\\')) {
        return 'path_traversal_probe';
    }

    return null;
}

function fortress_monitor_request_path(): string
{
    $uri = (string)($_SERVER['REQUEST_URI'] ?? '/');
    $path = parse_url($uri, PHP_URL_PATH);
    return is_string($path) && $path !== '' ? $path : '/';
}

function fortress_monitor_endpoint_method_policy(string $path): ?array
{
    $postOnly = [
        '/school_id_register_finish.php',
        '/school_id_verify_finish.php',
        '/school_id_reset.php',
        '/school_id_reverify.php',
        '/csp_report.php',
        '/report_export.php',
    ];
    if (in_array($path, $postOnly, true)) {
        return ['POST'];
    }
    return null;
}

function fortress_monitor_log_event(string $event, array $fields = []): void
{
    $parts = [$event];
    foreach ($fields as $key => $value) {
        if (fortress_monitor_secret_key((string)$key)) {
            continue;
        }
        $parts[] = preg_replace('/[^a-z0-9_\-]/i', '_', (string)$key) . '=' . fortress_log_safe_value((string)$value);
    }
    audit_log(implode(' ', $parts));
}

function fortress_monitor_run(): void
{
    static $ran = false;
    if ($ran) {
        return;
    }
    $ran = true;

    $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    $path = fortress_monitor_request_path();
    $uri = (string)($_SERVER['REQUEST_URI'] ?? $path);
    $uid = (int)($_SESSION['uid'] ?? $_SESSION['pending_user_id'] ?? 0);

    $policy = fortress_security_policy();
    $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($contentLength > (int)$policy['request_body_monitor_bytes']) {
        fortress_monitor_log_event('oversized_request_detected', [
            'method' => $method,
            'path' => $path,
            'bytes' => $contentLength,
            'uid' => $uid,
        ]);
    }

    if (strlen($uri) > (int)$policy['request_uri_monitor_length']) {
        fortress_monitor_log_event('oversized_uri_detected', [
            'method' => $method,
            'path' => $path,
            'uri_length' => strlen($uri),
            'uid' => $uid,
        ]);
    }

    $probeType = fortress_monitor_sensitive_path($path);
    if ($probeType !== null && $path !== '/security_probe.php') {
        fortress_monitor_log_event('sensitive_path_probe', [
            'method' => $method,
            'path' => $path,
            'probe' => $probeType,
            'uid' => $uid,
        ]);
    }

    $dangerousMethods = ['TRACE', 'TRACK', 'CONNECT'];
    if (in_array($method, $dangerousMethods, true)) {
        fortress_monitor_log_event('http_method_blocked', [
            'method' => $method,
            'path' => $path,
            'uid' => $uid,
        ]);
        http_response_code(405);
        header('Allow: GET, HEAD, POST');
        exit('Method not allowed.');
    }

    if (!in_array($method, ['GET', 'HEAD', 'POST', 'OPTIONS'], true)) {
        fortress_monitor_log_event('http_method_anomaly', [
            'method' => $method,
            'path' => $path,
            'uid' => $uid,
        ]);
    }

    $policy = fortress_monitor_endpoint_method_policy($path);
    if ($policy !== null && !in_array($method, $policy, true)) {
        fortress_monitor_log_event('endpoint_method_rejected', [
            'method' => $method,
            'path' => $path,
            'allowed' => implode(',', $policy),
            'uid' => $uid,
        ]);
    }

    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    if (detect_suspicious_ua($ua)) {
        fortress_monitor_log_event('scanner_user_agent_detected', [
            'method' => $method,
            'path' => $path,
            'uid' => $uid,
        ]);
    }

    // Login has specialized blocking/classification already; skip its form values
    // here to prevent duplicate threat events while retaining method/path/UA telemetry.
    if ($path === '/login.php') {
        return;
    }

    $values = fortress_monitor_collect_values($_GET);
    if ($method === 'POST') {
        $values += fortress_monitor_collect_values($_POST);
    }

    // Inspect the decoded path. Query/form values are collected separately so
    // secret-bearing parameter names can be excluded before signature checks.
    $values['request_path'] = fortress_monitor_normalize_text($path);

    $issues = security_check_inputs($values, '');
    if (!$issues) {
        return;
    }

    $issueTypes = [];
    $fieldNames = [];
    foreach ($issues as $issue) {
        [$type, $field] = array_pad(explode(':', (string)$issue, 2), 2, 'request');
        if ($type === 'suspicious_ua') {
            continue;
        }
        $issueTypes[$type] = true;
        $fieldNames[$field] = true;
    }

    if ($issueTypes) {
        fortress_monitor_log_event('request_threat_detected', [
            'method' => $method,
            'path' => $path,
            'issues' => implode(',', array_keys($issueTypes)),
            'fields' => implode(',', array_slice(array_keys($fieldNames), 0, 8)),
            'uid' => $uid,
        ]);
    }
}
