<?php

declare(strict_types=1);

require_once __DIR__ . '/logger.php';

function fortress_ml_env_bool(string $name, bool $default = false): bool
{
    $raw = getenv($name);
    if ($raw === false || trim((string)$raw) === '') return $default;
    return filter_var($raw, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? $default;
}

function fortress_ml_enabled(): bool
{
    return fortress_ml_env_bool('ML_SERVICE_ENABLED', false);
}

function fortress_ml_data_dir(): string
{
    $dir = __DIR__ . '/../data/ml';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir;
}

function fortress_ml_request_log_path(): string
{
    return fortress_ml_data_dir() . '/request_telemetry.jsonl';
}

function fortress_ml_safe_path(): string
{
    $uri = (string)($_SERVER['REQUEST_URI'] ?? '/');
    $path = parse_url($uri, PHP_URL_PATH);
    return is_string($path) && $path !== '' ? substr($path, 0, 180) : '/';
}

function fortress_ml_record_request(): void
{
    $entry = [
        'ts' => time(),
        'ip' => getRealIP(),
        'uid' => (int)($_SESSION['uid'] ?? $_SESSION['pending_user_id'] ?? 0),
        'method' => strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')),
        'path' => fortress_ml_safe_path(),
        'ua' => substr(hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 16),
    ];
    @file_put_contents(fortress_ml_request_log_path(), json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function fortress_ml_tail_lines(string $path, int $maxLines = 700): array
{
    if (!is_file($path)) return [];
    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) return [];
    return array_slice($lines, -$maxLines);
}

function fortress_ml_audit_ts(string $line): int
{
    if (!preg_match('/^\[([^\]]+)\]/', $line, $m)) return 0;
    $ts = strtotime($m[1]);
    return $ts === false ? 0 : $ts;
}

function fortress_ml_features_for_ip(string $ip): array
{
    $now = time();
    $requests = [];
    foreach (fortress_ml_tail_lines(fortress_ml_request_log_path(), 1200) as $line) {
        $item = json_decode($line, true);
        if (!is_array($item) || (string)($item['ip'] ?? '') !== $ip) continue;
        $ts = (int)($item['ts'] ?? 0);
        if ($ts < $now - 900) continue;
        $requests[] = $item;
    }

    $r1 = array_values(array_filter($requests, static fn(array $r): bool => (int)$r['ts'] >= time() - 60));
    $r5 = array_values(array_filter($requests, static fn(array $r): bool => (int)$r['ts'] >= time() - 300));
    $paths = array_unique(array_map(static fn(array $r): string => (string)$r['path'], $r5));
    $postCount = count(array_filter($r5, static fn(array $r): bool => (string)$r['method'] === 'POST'));
    $authCount = count(array_filter($r5, static function(array $r): bool {
        return preg_match('#/(?:login|school_id|personal_id)#i', (string)$r['path']) === 1;
    }));
    $uaValues = array_unique(array_map(static fn(array $r): string => (string)$r['ua'], $requests));
    $intervals = [];
    $sortedTs = array_map(static fn(array $r): int => (int)$r['ts'], $r5);
    sort($sortedTs);
    for ($i = 1; $i < count($sortedTs); $i++) $intervals[] = max(0, $sortedTs[$i] - $sortedTs[$i - 1]);
    $avgInterval = $intervals ? array_sum($intervals) / count($intervals) : 60.0;

    $counts = [
        'failed5' => 0, 'failed15' => 0, 'success15' => 0, 'qr15' => 0, 'probe15' => 0,
        'suspicious15' => 0, 'scanner15' => 0, 'csrf15' => 0, 'method15' => 0,
        'reject15' => 0, 'ban15' => 0,
    ];
    $usernames = [];
    $auditPath = __DIR__ . '/../data/audit.log';
    foreach (fortress_ml_tail_lines($auditPath, 1800) as $line) {
        if (!str_contains($line, 'ip=' . $ip . ' ') && !str_contains($line, 'ip=' . $ip . PHP_EOL) && !preg_match('/\bip=' . preg_quote($ip, '/') . '(?:\s|$)/', $line)) continue;
        $ts = fortress_ml_audit_ts($line);
        if ($ts <= 0 || $ts < $now - 900) continue;
        $age5 = $ts >= $now - 300;
        if (str_contains($line, 'password_factor_failed')) {
            $counts['failed15']++;
            if ($age5) $counts['failed5']++;
            if (preg_match('/\busername=([^\s]+)/', $line, $m)) $usernames[$m[1]] = true;
        }
        if (str_contains($line, 'password_factor_success') || str_contains($line, 'login_success')) $counts['success15']++;
        if (str_contains($line, 'school_id_qr_failed') || str_contains($line, 'school_id_qr_locked') || str_contains($line, 'school_id_qr_rate_limited')) $counts['qr15']++;
        if (str_contains($line, 'sensitive_path_probe') || str_contains($line, 'reconnaissance_probe')) $counts['probe15']++;
        if (str_contains($line, 'request_threat_detected') || str_contains($line, 'malicious_input_detected') || str_contains($line, 'shell_attack_detected')) $counts['suspicious15']++;
        if (str_contains($line, 'scanner_user_agent_detected')) $counts['scanner15']++;
        if (str_contains($line, 'csrf_validation_failed')) $counts['csrf15']++;
        if (str_contains($line, 'http_method_blocked') || str_contains($line, 'http_method_anomaly') || str_contains($line, 'endpoint_method_rejected')) $counts['method15']++;
        if (str_contains($line, 'auth_rejected')) $counts['reject15']++;
        if (str_contains($line, 'ip_banned') || str_contains($line, 'banned_ip_attempt') || str_contains($line, 'banned_ip_middleware_block')) $counts['ban15']++;
    }

    $hour = (int)date('G');
    return [
        'requests_1m' => count($r1),
        'requests_5m' => count($r5),
        'unique_paths_5m' => count($paths),
        'post_ratio_5m' => count($r5) > 0 ? $postCount / count($r5) : 0.0,
        'auth_endpoint_requests_5m' => $authCount,
        'failed_logins_5m' => $counts['failed5'],
        'failed_logins_15m' => $counts['failed15'],
        'unique_usernames_15m' => max(1, count($usernames)),
        'successful_logins_15m' => $counts['success15'],
        'qr_failures_15m' => $counts['qr15'],
        'sensitive_path_probes_15m' => $counts['probe15'],
        'suspicious_requests_15m' => $counts['suspicious15'],
        'scanner_events_15m' => $counts['scanner15'],
        'csrf_failures_15m' => $counts['csrf15'],
        'method_anomalies_15m' => $counts['method15'],
        'auth_rejections_15m' => $counts['reject15'],
        'ban_events_15m' => $counts['ban15'],
        'avg_request_interval_5m' => round($avgInterval, 3),
        'ua_changes_15m' => max(0, count($uaValues) - 1),
        'off_hours' => ($hour < 6 || $hour >= 22) ? 1 : 0,
    ];
}

function fortress_ml_rule_score(array $f): float
{
    $score =
        min(35, (float)$f['failed_logins_5m'] * 6.0) +
        min(15, (float)$f['qr_failures_15m'] * 5.0) +
        min(20, (float)$f['sensitive_path_probes_15m'] * 8.0) +
        min(20, (float)$f['suspicious_requests_15m'] * 8.0) +
        min(10, (float)$f['scanner_events_15m'] * 5.0) +
        min(10, (float)$f['csrf_failures_15m'] * 4.0) +
        min(10, (float)$f['auth_rejections_15m'] * 2.0) +
        min(15, (float)$f['ban_events_15m'] * 10.0);
    return min(100.0, $score);
}

function fortress_ml_post(array $payload): ?array
{
    $url = trim((string)(getenv('ML_SERVICE_URL') ?: ''));
    if ($url === '' || !preg_match('#^https?://#i', $url)) return null;
    $timeoutMs = (int)(getenv('ML_TIMEOUT_MS') ?: 250);
    // ML is an additional detection layer, so it must never make normal page
    // navigation feel blocked. Keep synchronous inference tightly bounded.
    $timeoutMs = max(75, min(300, $timeoutMs));
    $token = trim((string)(getenv('ML_SERVICE_TOKEN') ?: ''));
    $headers = "Content-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\n";
    if ($token !== '') {
        $headers .= 'Authorization: Bearer ' . str_replace(["\r", "\n"], '', $token) . "\r\n";
    }
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => $headers,
            'content' => json_encode($payload, JSON_UNESCAPED_SLASHES),
            'timeout' => $timeoutMs / 1000,
            'ignore_errors' => true,
        ],
    ]);
    $body = @file_get_contents(rtrim($url, '/') . '/predict', false, $context);
    if (!is_string($body) || $body === '') return null;
    $decoded = json_decode($body, true);
    return is_array($decoded) && isset($decoded['risk_score']) ? $decoded : null;
}

function fortress_ml_evaluate_request(): void
{
    // Live-security/background polling is UI synchronization, not a real
    // protected-page request. Never feed those requests into ML telemetry or
    // inference, otherwise the poller can classify its own traffic and create
    // a feedback loop of new security events.
    if (defined('FORTRESS_BACKGROUND_REQUEST') && FORTRESS_BACKGROUND_REQUEST === true) {
        return;
    }

    if (!fortress_ml_enabled()) return;

    // Telemetry remains complete on every request. Only the expensive model
    // inference is throttled so ordinary admin navigation never waits on the
    // Python service every few seconds.
    fortress_ml_record_request();

    $ip = getRealIP();
    $cachePath = fortress_ml_data_dir() . '/eval_' . sha1($ip) . '.json';
    $cached = [];
    if (is_file($cachePath)) {
        $decoded = json_decode((string)@file_get_contents($cachePath), true);
        if (is_array($decoded)) $cached = $decoded;
    }

    $lastAttempt = (int)($cached['ts'] ?? 0);
    $lastOk = !empty($cached['ok']);
    $successCooldown = max(5, min(60, (int)(getenv('ML_SUCCESS_COOLDOWN_SECONDS') ?: 12)));
    $failureCooldown = max(15, min(300, (int)(getenv('ML_FAILURE_BACKOFF_SECONDS') ?: 60)));
    $cooldown = $lastOk ? $successCooldown : $failureCooldown;

    if ($lastAttempt > 0 && $lastAttempt >= time() - $cooldown) return;

    $features = fortress_ml_features_for_ip($ip);
    $ruleScore = fortress_ml_rule_score($features);
    $result = fortress_ml_post(['features' => $features, 'rule_score' => $ruleScore]);

    @file_put_contents($cachePath, json_encode([
        'ts' => time(),
        'ok' => $result ? 1 : 0,
    ]), LOCK_EX);

    if (!$result) return;

    $record = [
        'ts' => time(),
        'ip' => $ip,
        'features' => $features,
        'result' => $result,
    ];
    @file_put_contents(fortress_ml_data_dir() . '/latest_prediction.json', json_encode($record, JSON_PRETTY_PRINT), LOCK_EX);
    @file_put_contents(fortress_ml_data_dir() . '/predictions.jsonl', json_encode($record, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);

    $minLogRisk = (float)(getenv('ML_MIN_LOG_RISK') ?: 30);
    if ((float)$result['risk_score'] >= $minLogRisk || (string)($result['classification'] ?? 'NORMAL') !== 'NORMAL') {
        audit_log(
            'ml_threat_prediction class=' . fortress_log_safe_value((string)($result['classification'] ?? 'UNKNOWN')) .
            ' confidence=' . number_format((float)($result['confidence'] ?? 0), 3, '.', '') .
            ' anomaly=' . number_format((float)($result['anomaly_score'] ?? 0), 3, '.', '') .
            ' risk=' . number_format((float)($result['risk_score'] ?? 0), 1, '.', '') .
            ' severity=' . fortress_log_safe_value((string)($result['severity'] ?? 'UNKNOWN'))
        );
    }
}

function fortress_ml_latest_prediction(): ?array
{
    $path = fortress_ml_data_dir() . '/latest_prediction.json';
    if (!is_file($path)) return null;
    $decoded = json_decode((string)@file_get_contents($path), true);
    return is_array($decoded) ? $decoded : null;
}
