<?php

declare(strict_types=1);

require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/security_policy.php';
require_once __DIR__ . '/bruteforce.php';
require_once __DIR__ . '/error_pages.php';

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

function fortress_ml_env_float(string $name, float $default, float $minimum = 0.0, float $maximum = 100.0): float
{
    $raw = getenv($name);
    if ($raw === false || trim((string)$raw) === '' || !is_numeric($raw)) return $default;
    return max($minimum, min($maximum, (float)$raw));
}

function fortress_ml_assisted_enforcement_enabled(): bool
{
    // The model never blocks by itself. When enabled, PHP requires model confidence
    // plus deterministic evidence before it can add a strike or temporary ban.
    return fortress_ml_enabled() && fortress_ml_env_bool('ML_ASSISTED_ENFORCEMENT', true);
}

function fortress_ml_enforcement_exempt(string $ip): bool
{
    // Protect loopback development sessions from accidental self-bans. Additional
    // trusted addresses can be supplied as a comma-separated deployment setting.
    $exempt = fortress_ml_env_bool('ML_ENFORCEMENT_EXEMPT_LOOPBACK', true) ? ['127.0.0.1', '::1'] : [];
    $configured = trim((string)(getenv('ML_ENFORCEMENT_EXEMPT_IPS') ?: ''));
    if ($configured !== '') {
        foreach (explode(',', $configured) as $candidate) {
            $candidate = trim($candidate);
            if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_IP)) {
                $exempt[] = $candidate;
            }
        }
    }
    return in_array($ip, array_values(array_unique($exempt)), true);
}

function fortress_ml_evidence_groups(array $f): array
{
    $groups = [];

    if (
        (float)($f['failed_logins_5m'] ?? 0) >= 3 ||
        (float)($f['failed_logins_15m'] ?? 0) >= 5 ||
        (float)($f['qr_failures_15m'] ?? 0) >= 2 ||
        (float)($f['auth_rejections_15m'] ?? 0) >= 3
    ) {
        $groups[] = 'auth_abuse';
    }

    if (
        (float)($f['suspicious_requests_15m'] ?? 0) >= 1 ||
        (float)($f['csrf_failures_15m'] ?? 0) >= 1 ||
        (float)($f['method_anomalies_15m'] ?? 0) >= 1
    ) {
        $groups[] = 'request_attack';
    }

    if (
        (float)($f['sensitive_path_probes_15m'] ?? 0) >= 1 ||
        (float)($f['scanner_events_15m'] ?? 0) >= 1
    ) {
        $groups[] = 'reconnaissance';
    }

    if (
        (float)($f['requests_1m'] ?? 0) >= 20 ||
        (float)($f['unique_paths_5m'] ?? 0) >= 12 ||
        ((float)($f['requests_5m'] ?? 0) >= 12 && (float)($f['avg_request_interval_5m'] ?? 60) <= 1.5) ||
        (float)($f['ua_changes_15m'] ?? 0) >= 2
    ) {
        $groups[] = 'automation_pattern';
    }

    return array_values(array_unique($groups));
}

function fortress_ml_recent_strike_count(string $ip, int $windowSeconds): int
{
    global $pdo;

    $windowSeconds = max(60, min(3600, $windowSeconds));
    $databaseCount = 0;

    if (isset($pdo) && $pdo instanceof PDO) {
        try {
            $stmt = $pdo->prepare(
                "SELECT COUNT(*)
                 FROM public.security_events
                 WHERE event_key = 'ml_assisted_strike'
                   AND source_ip = :ip
                   AND occurred_at > NOW() - make_interval(secs => CAST(:seconds AS integer))"
            );
            $stmt->execute(['ip' => $ip, 'seconds' => $windowSeconds]);
            $databaseCount = (int)$stmt->fetchColumn();
        } catch (Throwable $e) {
            error_log('FortressAuth ML strike lookup failed: ' . $e->getMessage());
        }
    }

    // Flat-file fallback keeps local development functional before/without the
    // persistent security_events table. Use max(), not sum(), because audit_log
    // intentionally writes the same event to both stores.
    $fileCount = 0;
    $cutoff = time() - $windowSeconds;
    $auditPath = __DIR__ . '/../data/audit.log';
    foreach (fortress_ml_tail_lines($auditPath, 2200) as $line) {
        if (!str_contains($line, 'ml_assisted_strike')) continue;
        if (!preg_match('/\bip=' . preg_quote($ip, '/') . '(?:\s|$)/', $line)) continue;
        $ts = fortress_ml_audit_ts($line);
        if ($ts >= $cutoff) $fileCount++;
    }

    return max($databaseCount, $fileCount);
}

function fortress_ml_enforcement_decision(string $ip, array $features, array $result): array
{
    $classification = strtoupper((string)($result['classification'] ?? 'NORMAL'));
    $risk = (float)($result['risk_score'] ?? 0);
    $confidence = (float)($result['confidence'] ?? 0);
    $ruleScore = (float)($result['rule_score'] ?? 0);
    $evidence = fortress_ml_evidence_groups($features);
    $evidenceCount = count($evidence);

    $enabled = fortress_ml_assisted_enforcement_enabled();
    $exempt = fortress_ml_enforcement_exempt($ip);

    $strikeRisk = fortress_ml_env_float('ML_ASSISTED_STRIKE_RISK', 65.0, 30.0, 100.0);
    $repeatRisk = fortress_ml_env_float('ML_ASSISTED_REPEAT_BLOCK_RISK', 72.0, $strikeRisk, 100.0);
    $blockRisk = fortress_ml_env_float('ML_ASSISTED_IMMEDIATE_BLOCK_RISK', 85.0, $repeatRisk, 100.0);
    $minConfidence = fortress_ml_env_float('ML_ASSISTED_MIN_CONFIDENCE', 0.82, 0.50, 1.0);
    $repeatConfidence = fortress_ml_env_float('ML_ASSISTED_REPEAT_CONFIDENCE', 0.85, $minConfidence, 1.0);
    $blockConfidence = fortress_ml_env_float('ML_ASSISTED_BLOCK_CONFIDENCE', 0.90, $repeatConfidence, 1.0);
    $windowSeconds = max(120, min(3600, (int)(getenv('ML_ASSISTED_STRIKE_WINDOW_SECONDS') ?: 600)));
    $requiredStrikes = max(2, min(5, (int)(getenv('ML_ASSISTED_REQUIRED_STRIKES') ?: 2)));

    $maliciousClass = $classification !== '' && $classification !== 'NORMAL';
    $eligibleStrike = $enabled && !$exempt && $maliciousClass
        && $risk >= $strikeRisk
        && $confidence >= $minConfidence
        && $ruleScore >= 20.0
        && $evidenceCount >= 1;

    $priorStrikes = $eligibleStrike ? fortress_ml_recent_strike_count($ip, $windowSeconds) : 0;
    $strikeCount = $priorStrikes + ($eligibleStrike ? 1 : 0);

    $immediateBlock = $eligibleStrike
        && $risk >= $blockRisk
        && $confidence >= $blockConfidence
        && $ruleScore >= 45.0
        && $evidenceCount >= 2;

    $repeatBlock = $eligibleStrike
        && $strikeCount >= $requiredStrikes
        && $risk >= $repeatRisk
        && $confidence >= $repeatConfidence
        && $ruleScore >= 30.0;

    $action = 'OBSERVE';
    if (!$enabled) $action = 'ADVISORY_ONLY';
    elseif ($exempt) $action = 'EXEMPT';
    elseif ($immediateBlock || $repeatBlock) $action = 'TEMPORARY_BAN';
    elseif ($eligibleStrike) $action = 'STRIKE';

    return [
        'enabled' => $enabled,
        'exempt' => $exempt,
        'action' => $action,
        'strike' => $eligibleStrike,
        'strike_count' => $strikeCount,
        'required_strikes' => $requiredStrikes,
        'evidence' => $evidence,
        'immediate_block' => $immediateBlock,
        'repeat_block' => $repeatBlock,
        'block' => $immediateBlock || $repeatBlock,
        'window_seconds' => $windowSeconds,
    ];
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

function fortress_ml_service_status_path(): string
{
    return fortress_ml_data_dir() . '/service_status.json';
}

function fortress_ml_write_service_status(array $status): void
{
    $record = array_merge([
        'ts' => time(),
        'ok' => false,
        'state' => 'UNKNOWN',
        'http_code' => 0,
        'latency_ms' => 0,
    ], $status);

    // Keep diagnostics intentionally non-sensitive: never persist the ML URL,
    // bearer token, request body, response body, or raw transport exception.
    @file_put_contents(
        fortress_ml_service_status_path(),
        json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    );
}

function fortress_ml_service_status(): ?array
{
    $path = fortress_ml_service_status_path();
    if (!is_file($path)) return null;
    $decoded = json_decode((string)@file_get_contents($path), true);
    return is_array($decoded) ? $decoded : null;
}

function fortress_ml_post(array $payload): ?array
{
    $url = trim((string)(getenv('ML_SERVICE_URL') ?: ''));
    if ($url === '' || !preg_match('#^https?://#i', $url)) {
        fortress_ml_write_service_status([
            'ok' => false,
            'state' => 'CONFIG_ERROR',
        ]);
        return null;
    }

    $timeoutMs = (int)(getenv('ML_TIMEOUT_MS') ?: 1500);
    // A separately deployed Render ML service needs enough time for DNS/TLS,
    // routing, and inference. The request remains bounded so the ML layer can
    // never stall normal FortressAuth navigation indefinitely.
    $timeoutMs = max(250, min(5000, $timeoutMs));

    $token = trim((string)(getenv('ML_SERVICE_TOKEN') ?: ''));
    $headers = "Content-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\n";
    if ($token !== '') {
        $headers .= 'Authorization: Bearer ' . str_replace(["\r", "\n"], '', $token) . "\r\n";
    }

    $encodedPayload = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if (!is_string($encodedPayload)) {
        fortress_ml_write_service_status([
            'ok' => false,
            'state' => 'PAYLOAD_ERROR',
        ]);
        return null;
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => $headers,
            'content' => $encodedPayload,
            'timeout' => $timeoutMs / 1000,
            'ignore_errors' => true,
        ],
    ]);

    if (function_exists('error_clear_last')) error_clear_last();
    $startedAt = microtime(true);
    $body = @file_get_contents(rtrim($url, '/') . '/predict', false, $context);
    $latencyMs = (int)round((microtime(true) - $startedAt) * 1000);

    $responseHeaders = $http_response_header ?? [];
    $httpCode = 0;
    if (is_array($responseHeaders) && isset($responseHeaders[0]) && preg_match('/\s(\d{3})\s/', (string)$responseHeaders[0], $match)) {
        $httpCode = (int)$match[1];
    }

    if (!is_string($body) || $body === '') {
        $lastError = error_get_last();
        $message = strtolower((string)($lastError['message'] ?? ''));
        $state = str_contains($message, 'timed out') || $latencyMs >= $timeoutMs
            ? 'TIMEOUT'
            : 'TRANSPORT_ERROR';

        fortress_ml_write_service_status([
            'ok' => false,
            'state' => $state,
            'http_code' => $httpCode,
            'latency_ms' => $latencyMs,
        ]);
        error_log('FortressAuth ML request failed state=' . $state . ' http=' . $httpCode . ' latency_ms=' . $latencyMs);
        return null;
    }

    if ($httpCode < 200 || $httpCode >= 300) {
        $state = match ($httpCode) {
            401, 403 => 'UNAUTHORIZED',
            422 => 'INVALID_PAYLOAD',
            502, 503, 504 => 'SERVICE_UNAVAILABLE',
            default => 'HTTP_ERROR',
        };
        fortress_ml_write_service_status([
            'ok' => false,
            'state' => $state,
            'http_code' => $httpCode,
            'latency_ms' => $latencyMs,
        ]);
        error_log('FortressAuth ML request rejected state=' . $state . ' http=' . $httpCode . ' latency_ms=' . $latencyMs);
        return null;
    }

    $decoded = json_decode($body, true);
    if (!is_array($decoded) || !isset($decoded['risk_score'])) {
        fortress_ml_write_service_status([
            'ok' => false,
            'state' => 'INVALID_RESPONSE',
            'http_code' => $httpCode,
            'latency_ms' => $latencyMs,
        ]);
        error_log('FortressAuth ML request returned an invalid prediction response.');
        return null;
    }

    fortress_ml_write_service_status([
        'ok' => true,
        'state' => 'CONNECTED',
        'http_code' => $httpCode,
        'latency_ms' => $latencyMs,
    ]);
    return $decoded;
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

    $decision = fortress_ml_enforcement_decision($ip, $features, $result);
    $result['automatic_block'] = (bool)$decision['block'];
    $result['enforcement_mode'] = !empty($decision['enabled']) ? 'AI_ASSISTED' : 'ADVISORY';
    $result['enforcement_action'] = (string)$decision['action'];
    $result['enforcement_evidence'] = (array)$decision['evidence'];
    $result['enforcement_strikes'] = (int)$decision['strike_count'];
    $result['enforcement_required_strikes'] = (int)$decision['required_strikes'];

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
            ' severity=' . fortress_log_safe_value((string)($result['severity'] ?? 'UNKNOWN')) .
            ' action=' . fortress_log_safe_value((string)$decision['action']) .
            ' strikes=' . (int)$decision['strike_count']
        );
    }

    if (!empty($decision['strike'])) {
        audit_log(
            'ml_assisted_strike class=' . fortress_log_safe_value((string)($result['classification'] ?? 'UNKNOWN')) .
            ' risk=' . number_format((float)($result['risk_score'] ?? 0), 1, '.', '') .
            ' confidence=' . number_format((float)($result['confidence'] ?? 0), 3, '.', '') .
            ' rule=' . number_format((float)($result['rule_score'] ?? 0), 1, '.', '') .
            ' evidence=' . fortress_log_safe_value(implode(',', (array)$decision['evidence'])) .
            ' strikes=' . (int)$decision['strike_count'] .
            ' required=' . (int)$decision['required_strikes']
        );
    }

    if (!empty($decision['block'])) {
        global $pdo;
        if (isset($pdo) && $pdo instanceof PDO) {
            $banSeconds = max(60, min(86400, (int)(getenv('ML_ASSISTED_BAN_SECONDS') ?: 600)));
            ban_ip($pdo, $ip, $banSeconds);
            audit_log(
                'ml_assisted_block class=' . fortress_log_safe_value((string)($result['classification'] ?? 'UNKNOWN')) .
                ' risk=' . number_format((float)($result['risk_score'] ?? 0), 1, '.', '') .
                ' confidence=' . number_format((float)($result['confidence'] ?? 0), 3, '.', '') .
                ' evidence=' . fortress_log_safe_value(implode(',', (array)$decision['evidence'])) .
                ' strikes=' . (int)$decision['strike_count'] .
                ' ban_seconds=' . $banSeconds
            );
            fortress_render_security_error(403, 'ai_assisted_temporary_ban');
        }

        // Never fail closed solely because the persistence/enforcement backend
        // is unavailable. The deterministic rules continue independently.
        audit_log('ml_assisted_enforcement_deferred reason=ban_backend_unavailable');
    }
}

function fortress_ml_latest_prediction(): ?array
{
    $path = fortress_ml_data_dir() . '/latest_prediction.json';
    if (!is_file($path)) return null;
    $decoded = json_decode((string)@file_get_contents($path), true);
    return is_array($decoded) ? $decoded : null;
}
