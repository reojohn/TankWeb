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

function fortress_ml_enforcement_config(): array
{
    $config = [
        'strike_risk' => fortress_ml_env_float('ML_ASSISTED_STRIKE_RISK', 65.0, 30.0, 100.0),
        'repeat_risk' => fortress_ml_env_float('ML_ASSISTED_REPEAT_BLOCK_RISK', 72.0, 30.0, 100.0),
        'block_risk' => fortress_ml_env_float('ML_ASSISTED_IMMEDIATE_BLOCK_RISK', 85.0, 30.0, 100.0),
        'min_confidence' => fortress_ml_env_float('ML_ASSISTED_MIN_CONFIDENCE', 0.82, 0.50, 1.0),
        'repeat_confidence' => fortress_ml_env_float('ML_ASSISTED_REPEAT_CONFIDENCE', 0.85, 0.50, 1.0),
        'block_confidence' => fortress_ml_env_float('ML_ASSISTED_BLOCK_CONFIDENCE', 0.90, 0.50, 1.0),
        'window_seconds' => max(120, min(3600, (int)(getenv('ML_ASSISTED_STRIKE_WINDOW_SECONDS') ?: 600))),
        'required_strikes' => max(2, min(5, (int)(getenv('ML_ASSISTED_REQUIRED_STRIKES') ?: 2))),
        'ban_seconds' => max(60, min(86400, (int)(getenv('ML_ASSISTED_BAN_SECONDS') ?: 600))),
    ];

    foreach (fortress_security_profile_ml_overrides(fortress_security_profile_mode()) as $key => $value) {
        if (array_key_exists($key, $config)) {
            $config[$key] = $value;
        }
    }

    // Keep the risk/confidence ladder internally consistent even if deployment
    // environment values are unusual.
    $config['strike_risk'] = max(30.0, min(100.0, (float)$config['strike_risk']));
    $config['repeat_risk'] = max($config['strike_risk'], min(100.0, (float)$config['repeat_risk']));
    $config['block_risk'] = max($config['repeat_risk'], min(100.0, (float)$config['block_risk']));
    $config['min_confidence'] = max(0.50, min(1.0, (float)$config['min_confidence']));
    $config['repeat_confidence'] = max($config['min_confidence'], min(1.0, (float)$config['repeat_confidence']));
    $config['block_confidence'] = max($config['repeat_confidence'], min(1.0, (float)$config['block_confidence']));
    $config['window_seconds'] = max(120, min(3600, (int)$config['window_seconds']));
    $config['required_strikes'] = max(2, min(5, (int)$config['required_strikes']));
    $config['ban_seconds'] = max(60, min(86400, (int)$config['ban_seconds']));

    return $config;
}

function fortress_ml_queue_replay_limit(): int
{
    $configured = max(1, min(5, (int)(getenv('ML_QUEUE_REPLAY_LIMIT') ?: 2)));
    $profile = fortress_security_profile_queue_replay_limit(fortress_security_profile_mode());
    return $profile === null ? $configured : $profile;
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

    $mlConfig = fortress_ml_enforcement_config();
    $strikeRisk = (float)$mlConfig['strike_risk'];
    $repeatRisk = (float)$mlConfig['repeat_risk'];
    $blockRisk = (float)$mlConfig['block_risk'];
    $minConfidence = (float)$mlConfig['min_confidence'];
    $repeatConfidence = (float)$mlConfig['repeat_confidence'];
    $blockConfidence = (float)$mlConfig['block_confidence'];
    $windowSeconds = (int)$mlConfig['window_seconds'];
    $requiredStrikes = (int)$mlConfig['required_strikes'];

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

/**
 * Check whether durable ML prediction history is installed in PostgreSQL.
 * The result is cached briefly, but a missing/transient table is rechecked so
 * applying the migration does not require a PHP process restart.
 */
function fortress_ml_predictions_db_available(): bool
{
    static $available = null;
    if (is_bool($available)) return $available;

    $sessionKey = 'fortress_ml_predictions_table_available_v1';
    if (session_status() === PHP_SESSION_ACTIVE) {
        $cached = $_SESSION[$sessionKey] ?? null;
        if (is_array($cached) && (int)($cached['expires_at'] ?? 0) >= time()) {
            return $available = !empty($cached['available']);
        }
    }

    global $pdo;
    if (!isset($pdo) || !($pdo instanceof PDO)) {
        return $available = false;
    }

    try {
        $stmt = $pdo->query("SELECT to_regclass('public.ml_predictions')");
        $available = (string)$stmt->fetchColumn() !== '';
    } catch (Throwable $e) {
        $available = false;
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION[$sessionKey] = ['available' => $available, 'expires_at' => time() + 60];
    }
    return $available;
}

function fortress_ml_prediction_fingerprint(array $record): string
{
    $encoded = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    return hash('sha256', is_string($encoded) ? $encoded : serialize($record));
}

function fortress_ml_decode_json_value(mixed $value): array
{
    if (is_array($value)) return $value;
    if (!is_string($value) || trim($value) === '') return [];
    $decoded = json_decode($value, true);
    return is_array($decoded) ? $decoded : [];
}

/** Persist one complete ML assessment without making enforcement depend on DB. */
function fortress_ml_persist_prediction(array $record): bool
{
    global $pdo;
    if (!fortress_ml_predictions_db_available() || !isset($pdo) || !($pdo instanceof PDO)) return false;

    $result = is_array($record['result'] ?? null) ? $record['result'] : [];
    $features = is_array($record['features'] ?? null) ? $record['features'] : [];
    $queue = is_array($record['queue'] ?? null) ? $record['queue'] : [];
    $ts = max(1, (int)($record['ts'] ?? time()));

    $recordJson = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $featuresJson = json_encode($features, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $resultJson = json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $queueJson = json_encode($queue, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($recordJson) || !is_string($featuresJson) || !is_string($resultJson) || !is_string($queueJson)) return false;

    try {
        $stmt = $pdo->prepare(
            "INSERT INTO public.ml_predictions (
                record_fingerprint, analyzed_at, source_ip, model_name, analysis_mode,
                classification, confidence, anomaly_score, rule_score, xgboost_risk,
                risk_score, severity, enforcement_mode, enforcement_action, automatic_block,
                queue_delay_seconds, features, result, queue_metadata, record
             ) VALUES (
                :fingerprint, :analyzed_at, :source_ip, :model_name, :analysis_mode,
                :classification, :confidence, :anomaly_score, :rule_score, :xgboost_risk,
                :risk_score, :severity, :enforcement_mode, :enforcement_action, :automatic_block,
                :queue_delay_seconds, CAST(:features AS jsonb), CAST(:result AS jsonb),
                CAST(:queue_metadata AS jsonb), CAST(:record AS jsonb)
             )
             ON CONFLICT (record_fingerprint) DO NOTHING"
        );
        $stmt->execute([
            'fingerprint' => fortress_ml_prediction_fingerprint($record),
            'analyzed_at' => gmdate('Y-m-d H:i:s+00:00', $ts),
            'source_ip' => substr((string)($record['ip'] ?? 'unknown'), 0, 64),
            'model_name' => substr((string)($result['model'] ?? 'FortressAuth Hybrid ML'), 0, 120),
            'analysis_mode' => substr(strtoupper((string)($result['analysis_mode'] ?? 'LIVE')), 0, 32),
            'classification' => substr(strtoupper((string)($result['classification'] ?? 'UNKNOWN')), 0, 64),
            'confidence' => is_numeric($result['confidence'] ?? null) ? (float)$result['confidence'] : null,
            'anomaly_score' => is_numeric($result['anomaly_score'] ?? null) ? (float)$result['anomaly_score'] : null,
            'rule_score' => is_numeric($result['rule_score'] ?? null) ? (float)$result['rule_score'] : null,
            'xgboost_risk' => is_numeric($result['xgboost_risk'] ?? null) ? (float)$result['xgboost_risk'] : null,
            'risk_score' => is_numeric($result['risk_score'] ?? null) ? (float)$result['risk_score'] : null,
            'severity' => substr(strtoupper((string)($result['severity'] ?? 'UNKNOWN')), 0, 32),
            'enforcement_mode' => substr(strtoupper((string)($result['enforcement_mode'] ?? 'ADVISORY')), 0, 32),
            'enforcement_action' => substr(strtoupper((string)($result['enforcement_action'] ?? 'OBSERVE')), 0, 32),
            // PDO::Statement::execute(array) binds array values as strings. A PHP
            // false becomes an empty string, which PostgreSQL rejects for a BOOLEAN
            // column (invalid input syntax for type boolean: ""). Send canonical
            // PostgreSQL boolean text instead so NORMAL/EXEMPT analyses persist too.
            'automatic_block' => !empty($result['automatic_block']) ? 'true' : 'false',
            'queue_delay_seconds' => max(0, (int)($result['queue_delay_seconds'] ?? 0)),
            'features' => $featuresJson,
            'result' => $resultJson,
            'queue_metadata' => $queueJson,
            'record' => $recordJson,
        ]);
        return true;
    } catch (Throwable $e) {
        error_log('FortressAuth ml_predictions persistence failed: ' . $e->getMessage());
        return false;
    }
}

/**
 * Dual-write prediction history: PostgreSQL is durable; local JSON remains a
 * bounded compatibility/fallback source for local development and DB outages.
 */
function fortress_ml_store_prediction_record(array $record): void
{
    @file_put_contents(
        fortress_ml_data_dir() . '/latest_prediction.json',
        json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    );
    @file_put_contents(
        fortress_ml_data_dir() . '/predictions.jsonl',
        json_encode($record, JSON_UNESCAPED_SLASHES) . PHP_EOL,
        FILE_APPEND | LOCK_EX
    );
    fortress_ml_persist_prediction($record);
}

/** @return array<int,array<string,mixed>> */
function fortress_ml_prediction_history(int $limit = 25): array
{
    $limit = max(1, min(500, $limit));
    $rows = [];
    $seen = [];

    global $pdo;
    if (fortress_ml_predictions_db_available() && isset($pdo) && $pdo instanceof PDO) {
        try {
            $stmt = $pdo->prepare(
                "SELECT record, record_fingerprint
                 FROM public.ml_predictions
                 ORDER BY analyzed_at DESC, id DESC
                 LIMIT :lim"
            );
            $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
            $stmt->execute();
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) ?: [] as $dbRow) {
                $record = fortress_ml_decode_json_value($dbRow['record'] ?? null);
                if (!$record || !is_array($record['result'] ?? null)) continue;
                $fp = (string)($dbRow['record_fingerprint'] ?? fortress_ml_prediction_fingerprint($record));
                $seen[$fp] = true;
                $rows[] = $record;
            }
        } catch (Throwable $e) {
            error_log('FortressAuth ml_predictions read failed: ' . $e->getMessage());
        }
    }

    // Merge recent local-only records in case the database was unavailable for
    // a prediction. Duplicates are removed by the same record fingerprint.
    $path = fortress_ml_data_dir() . '/predictions.jsonl';
    foreach (array_reverse(fortress_ml_tail_lines($path, min(1500, $limit * 4))) as $line) {
        $record = json_decode($line, true);
        if (!is_array($record) || !is_array($record['result'] ?? null)) continue;
        $fp = fortress_ml_prediction_fingerprint($record);
        if (isset($seen[$fp])) continue;
        $seen[$fp] = true;
        $rows[] = $record;
    }

    usort($rows, static fn(array $a, array $b): int => (int)($b['ts'] ?? 0) <=> (int)($a['ts'] ?? 0));
    return array_slice($rows, 0, $limit);
}

function fortress_ml_safe_path(): string
{
    $uri = (string)($_SERVER['REQUEST_URI'] ?? '/');
    $path = parse_url($uri, PHP_URL_PATH);
    return is_string($path) && $path !== '' ? substr($path, 0, 180) : '/';
}

function fortress_ml_record_request(): void
{
    static $recorded = false;
    if ($recorded) return;
    $recorded = true;

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

/**
 * Durable ML replay queue.
 *
 * Why it exists: a free/idle ML service can be asleep exactly when a security
 * event arrives. FortressAuth still applies its deterministic defenses in real
 * time, then stores the telemetry snapshot so XGBoost/Autoencoder can analyse
 * it after the ML service becomes available again.
 *
 * Preferred persistence is PostgreSQL (sql/ml_analysis_queue.sql). If that
 * table has not been installed yet, a bounded local-file fallback is used so
 * local development continues to work.
 */
function fortress_ml_queue_enabled(): bool
{
    return fortress_ml_env_bool('ML_QUEUE_ENABLED', true);
}

function fortress_ml_queue_dir(): string
{
    $dir = fortress_ml_data_dir() . '/queue';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir;
}

function fortress_ml_queue_max_age(): int
{
    return max(300, min(86400, (int)(getenv('ML_QUEUE_MAX_AGE_SECONDS') ?: 21600)));
}

function fortress_ml_queue_max_pending(): int
{
    return max(10, min(500, (int)(getenv('ML_QUEUE_MAX_PENDING') ?: 100)));
}

function fortress_ml_queue_retry_seconds(): int
{
    return max(10, min(300, (int)(getenv('ML_QUEUE_RETRY_SECONDS') ?: 30)));
}

function fortress_ml_queue_fingerprint(string $ip, array $features, float $ruleScore): string
{
    ksort($features);
    // A one-minute bucket suppresses duplicate snapshots generated by the same
    // request/retry burst while still allowing the behavioral window to evolve.
    $bucket = intdiv(time(), 60);
    $canonical = json_encode([$ip, $features, round($ruleScore, 2), $bucket], JSON_UNESCAPED_SLASHES);
    return hash('sha256', is_string($canonical) ? $canonical : $ip . '|' . $bucket);
}

function fortress_ml_queue_db_available(): bool
{
    static $available = null;
    if (is_bool($available)) return $available;

    $sessionKey = 'fortress_ml_queue_table_available_v1';
    if (session_status() === PHP_SESSION_ACTIVE) {
        $cached = $_SESSION[$sessionKey] ?? null;
        if (is_array($cached) && (int)($cached['expires_at'] ?? 0) >= time()) {
            return $available = !empty($cached['available']);
        }
    }

    global $pdo;
    if (!isset($pdo) || !($pdo instanceof PDO)) {
        return $available = false;
    }

    try {
        $stmt = $pdo->query("SELECT to_regclass('public.ml_analysis_queue')");
        $available = (string)$stmt->fetchColumn() !== '';
    } catch (Throwable $e) {
        $available = false;
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION[$sessionKey] = ['available' => $available, 'expires_at' => time() + 60];
    }
    return $available;
}

function fortress_ml_queue_file_cleanup(): void
{
    $dir = fortress_ml_queue_dir();
    $now = time();
    $cutoff = $now - fortress_ml_queue_max_age();

    // Recover a queue item if a PHP worker stopped after claiming it but before
    // completing the replay. The next request can safely retry it.
    foreach (glob($dir . '/*.processing') ?: [] as $processing) {
        $mtime = (int)(@filemtime($processing) ?: 0);
        if ($mtime > 0 && $mtime < $now - 300) {
            $record = json_decode((string)@file_get_contents($processing), true);
            if (is_array($record)) {
                $record['available_at'] = $now;
                @file_put_contents($processing, json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
            }
            $pending = preg_replace('/\.processing$/', '.json', $processing) ?: ($processing . '.json');
            @rename($processing, $pending);
        }
    }

    $files = glob($dir . '/*.json') ?: [];
    foreach ($files as $file) {
        $decoded = json_decode((string)@file_get_contents($file), true);
        $queuedAt = is_array($decoded) ? (int)($decoded['queued_at'] ?? 0) : 0;
        if ($queuedAt <= 0 || $queuedAt < $cutoff) @unlink($file);
    }

    // Bound the fallback queue even if a test generates a large burst. Prefer
    // keeping higher-rule-score snapshots when the queue is full.
    $files = glob($dir . '/*.json') ?: [];
    if (count($files) <= fortress_ml_queue_max_pending()) return;
    usort($files, static function (string $a, string $b): int {
        $ra = json_decode((string)@file_get_contents($a), true);
        $rb = json_decode((string)@file_get_contents($b), true);
        $sa = is_array($ra) ? (float)($ra['payload']['rule_score'] ?? 0) : 0.0;
        $sb = is_array($rb) ? (float)($rb['payload']['rule_score'] ?? 0) : 0.0;
        if ($sa !== $sb) return $sa <=> $sb;
        return (@filemtime($a) ?: 0) <=> (@filemtime($b) ?: 0);
    });
    $remove = count($files) - fortress_ml_queue_max_pending();
    for ($i = 0; $i < $remove; $i++) @unlink($files[$i]);
}

function fortress_ml_queue_db_cleanup(): void
{
    global $pdo;
    if (!fortress_ml_queue_db_available() || !isset($pdo) || !($pdo instanceof PDO)) return;

    try {
        $maxAge = fortress_ml_queue_max_age();
        $pdo->prepare(
            "UPDATE public.ml_analysis_queue
             SET status = 'discarded', updated_at = NOW()
             WHERE status IN ('pending','processing')
               AND queued_at < NOW() - make_interval(secs => CAST(:max_age AS integer))"
        )->execute(['max_age' => $maxAge]);

        // Keep completed rows only long enough for recent queue metrics/debugging.
        $pdo->exec(
            "DELETE FROM public.ml_analysis_queue
             WHERE status IN ('completed','discarded')
               AND updated_at < NOW() - INTERVAL '24 hours'"
        );

        $maxPending = fortress_ml_queue_max_pending();
        $count = (int)$pdo->query(
            "SELECT COUNT(*) FROM public.ml_analysis_queue WHERE status IN ('pending','processing')"
        )->fetchColumn();
        if ($count >= $maxPending) {
            $remove = ($count - $maxPending) + 1;
            $stmt = $pdo->prepare(
                "WITH victims AS (
                    SELECT id
                    FROM public.ml_analysis_queue
                    WHERE status = 'pending'
                    ORDER BY COALESCE((payload->>'rule_score')::numeric, 0) ASC, queued_at ASC
                    LIMIT :remove
                 )
                 UPDATE public.ml_analysis_queue q
                 SET status = 'discarded', updated_at = NOW()
                 FROM victims v
                 WHERE q.id = v.id"
            );
            $stmt->bindValue(':remove', max(1, $remove), PDO::PARAM_INT);
            $stmt->execute();
        }
    } catch (Throwable $e) {
        error_log('FortressAuth ML queue cleanup failed.');
    }
}

function fortress_ml_queue_enqueue(string $ip, array $features, float $ruleScore, string $reason): bool
{
    if (!fortress_ml_queue_enabled() || !$features) return false;

    $reason = preg_replace('/[^a-z0-9_:-]/i', '_', substr($reason, 0, 80)) ?: 'ml_unavailable';
    $fingerprint = fortress_ml_queue_fingerprint($ip, $features, $ruleScore);
    $queuedAt = time();
    $payload = [
        'features' => $features,
        'rule_score' => round($ruleScore, 2),
        'reason' => $reason,
        'captured_at' => $queuedAt,
    ];

    global $pdo;
    if (fortress_ml_queue_db_available() && isset($pdo) && $pdo instanceof PDO) {
        fortress_ml_queue_db_cleanup();
        try {
            $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
            if (!is_string($encoded)) return false;
            $stmt = $pdo->prepare(
                "INSERT INTO public.ml_analysis_queue
                    (fingerprint, source_ip, payload, status, queued_at, available_at, updated_at)
                 VALUES
                    (:fingerprint, :source_ip, CAST(:payload AS jsonb), 'pending', NOW(), NOW(), NOW())
                 ON CONFLICT (fingerprint) DO NOTHING"
            );
            $stmt->execute([
                'fingerprint' => $fingerprint,
                'source_ip' => substr($ip, 0, 64),
                'payload' => $encoded,
            ]);
            return $stmt->rowCount() > 0;
        } catch (Throwable $e) {
            error_log('FortressAuth ML queue database insert failed; using file fallback.');
        }
    }

    fortress_ml_queue_file_cleanup();
    $path = fortress_ml_queue_dir() . '/' . $fingerprint . '.json';
    if (is_file($path)) return false;
    $record = [
        'fingerprint' => $fingerprint,
        'source_ip' => $ip,
        'queued_at' => $queuedAt,
        'available_at' => $queuedAt,
        'attempts' => 0,
        'payload' => $payload,
    ];
    return @file_put_contents($path, json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) !== false;
}

function fortress_ml_queue_same_as_latest(string $ip, array $features): bool
{
    $latest = fortress_ml_latest_prediction();
    if (!is_array($latest) || (string)($latest['ip'] ?? '') !== $ip) return false;
    $latestFeatures = is_array($latest['features'] ?? null) ? $latest['features'] : [];
    if (!$latestFeatures) return false;
    ksort($latestFeatures);
    ksort($features);
    return $latestFeatures === $features;
}

function fortress_ml_register_shutdown_capture(string $ip): void
{
    static $registered = false;
    if ($registered || !fortress_ml_queue_enabled()) return;
    $registered = true;

    register_shutdown_function(static function () use ($ip): void {
        // logger.php marks this request only when deterministic security evidence
        // was recorded. This captures events that occur after middleware returns,
        // such as failed login or malicious-login handling.
        $securityEvent = $GLOBALS['FORTRESS_ML_SECURITY_EVENT_SEEN'] ?? null;
        if (!is_array($securityEvent) || empty($securityEvent['event_key'])) return;

        $features = fortress_ml_features_for_ip($ip);
        if (!$features || fortress_ml_queue_same_as_latest($ip, $features)) return;
        $ruleScore = fortress_ml_rule_score($features);
        fortress_ml_queue_enqueue(
            $ip,
            $features,
            $ruleScore,
            'security_event:' . (string)$securityEvent['event_key']
        );
    });
}

function fortress_ml_prepare_request_capture(): void
{
    if (defined('FORTRESS_BACKGROUND_REQUEST') && FORTRESS_BACKGROUND_REQUEST === true) return;
    if (!fortress_ml_enabled()) return;

    // Register before the deterministic monitor runs. Even a request that is
    // rejected/terminated by the monitor can therefore be queued at shutdown.
    fortress_ml_record_request();
    fortress_ml_register_shutdown_capture(getRealIP());
}

function fortress_ml_queue_claim_db(int $limit): array
{
    global $pdo;
    if (!fortress_ml_queue_db_available() || !isset($pdo) || !($pdo instanceof PDO)) return [];

    try {
        $pdo->beginTransaction();
        $pdo->exec(
            "UPDATE public.ml_analysis_queue
             SET status = 'pending', available_at = NOW(), updated_at = NOW()
             WHERE status = 'processing' AND updated_at < NOW() - INTERVAL '5 minutes'"
        );
        $stmt = $pdo->prepare(
            "SELECT id, fingerprint, source_ip, payload, queued_at, attempts
             FROM public.ml_analysis_queue
             WHERE status = 'pending'
               AND available_at <= NOW()
               AND queued_at >= NOW() - make_interval(secs => :max_age)
             ORDER BY COALESCE((payload->>'rule_score')::numeric, 0) DESC, queued_at ASC
             FOR UPDATE SKIP LOCKED
             LIMIT :lim"
        );
        $stmt->bindValue(':max_age', fortress_ml_queue_max_age(), PDO::PARAM_INT);
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll() ?: [];
        if ($rows) {
            $ids = array_map(static fn(array $row): int => (int)$row['id'], $rows);
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $update = $pdo->prepare(
                "UPDATE public.ml_analysis_queue
                 SET status = 'processing', attempts = attempts + 1, updated_at = NOW()
                 WHERE id IN ($placeholders)"
            );
            $update->execute($ids);
        }
        $pdo->commit();
        return $rows;
    } catch (Throwable $e) {
        if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
        error_log('FortressAuth ML queue claim failed.');
        return [];
    }
}

function fortress_ml_queue_finish_db(int $id, bool $ok, ?array $result = null): void
{
    global $pdo;
    if (!fortress_ml_queue_db_available() || !isset($pdo) || !($pdo instanceof PDO)) return;
    try {
        if ($ok) {
            $encoded = json_encode($result ?? [], JSON_UNESCAPED_SLASHES);
            $stmt = $pdo->prepare(
                "UPDATE public.ml_analysis_queue
                 SET status = 'completed', completed_at = NOW(), updated_at = NOW(),
                     last_error_state = NULL, result = CAST(:result AS jsonb)
                 WHERE id = :id"
            );
            $stmt->execute(['result' => is_string($encoded) ? $encoded : '{}', 'id' => $id]);
            return;
        }

        $state = (string)(fortress_ml_service_status()['state'] ?? 'UNAVAILABLE');
        $retry = fortress_ml_queue_retry_seconds();
        $stmt = $pdo->prepare(
            "UPDATE public.ml_analysis_queue
             SET status = 'pending', updated_at = NOW(),
                 available_at = NOW() + make_interval(secs => CAST(:retry AS integer)),
                 last_error_state = :state
             WHERE id = :id"
        );
        $stmt->execute(['retry' => $retry, 'state' => substr($state, 0, 64), 'id' => $id]);
    } catch (Throwable $e) {
        error_log('FortressAuth ML queue completion update failed.');
    }
}

function fortress_ml_queue_claim_files(int $limit): array
{
    fortress_ml_queue_file_cleanup();
    $now = time();
    $rows = [];
    foreach (glob(fortress_ml_queue_dir() . '/*.json') ?: [] as $file) {
        if (count($rows) >= $limit) break;
        $record = json_decode((string)@file_get_contents($file), true);
        if (!is_array($record) || (int)($record['available_at'] ?? 0) > $now) continue;
        $processing = substr($file, 0, -5) . '.processing';
        if (!@rename($file, $processing)) continue;
        $record['_file'] = $processing;
        $record['attempts'] = (int)($record['attempts'] ?? 0) + 1;
        $rows[] = $record;
    }
    return $rows;
}

function fortress_ml_queue_finish_file(array $row, bool $ok): void
{
    $processing = (string)($row['_file'] ?? '');
    if ($processing === '' || !is_file($processing)) return;
    if ($ok) {
        @unlink($processing);
        return;
    }

    $row['available_at'] = time() + fortress_ml_queue_retry_seconds();
    unset($row['_file']);
    $pending = preg_replace('/\.processing$/', '.json', $processing) ?: ($processing . '.json');
    @file_put_contents($processing, json_encode($row, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    @rename($processing, $pending);
}

function fortress_ml_store_queued_prediction(string $ip, array $features, array $result, array $queueMeta): array
{
    $queuedAt = (int)($queueMeta['queued_at'] ?? $queueMeta['captured_at'] ?? time());
    $reason = (string)($queueMeta['reason'] ?? 'ml_unavailable');
    $result['automatic_block'] = false;
    $result['enforcement_mode'] = 'RETROSPECTIVE';
    $result['enforcement_action'] = 'RETROSPECTIVE';
    $result['enforcement_evidence'] = fortress_ml_evidence_groups($features);
    $result['enforcement_strikes'] = 0;
    $result['enforcement_required_strikes'] = max(2, (int)(getenv('ML_ASSISTED_REQUIRED_STRIKES') ?: 2));
    $result['analysis_mode'] = 'QUEUED_REPLAY';
    $result['queue_delay_seconds'] = max(0, time() - $queuedAt);
    $result['queue_reason'] = $reason;

    $record = [
        'ts' => time(),
        'ip' => $ip,
        'features' => $features,
        'result' => $result,
        'queue' => [
            'queued_at' => $queuedAt,
            'processed_at' => time(),
            'reason' => $reason,
        ],
    ];
    fortress_ml_store_prediction_record($record);

    audit_log(
        'ml_queue_replayed class=' . fortress_log_safe_value((string)($result['classification'] ?? 'UNKNOWN')) .
        ' risk=' . number_format((float)($result['risk_score'] ?? 0), 1, '.', '') .
        ' confidence=' . number_format((float)($result['confidence'] ?? 0), 3, '.', '') .
        ' queued_seconds=' . (int)$result['queue_delay_seconds'] .
        ' reason=' . fortress_log_safe_value($reason)
    );
    return $record;
}

function fortress_ml_process_queue(int $limit = 1): int
{
    if (!fortress_ml_queue_enabled() || !fortress_ml_enabled()) return 0;
    $limit = max(1, min(5, $limit));
    $processed = 0;

    $dbRows = fortress_ml_queue_claim_db($limit);
    foreach ($dbRows as $row) {
        $payload = is_array($row['payload'] ?? null)
            ? $row['payload']
            : json_decode((string)($row['payload'] ?? ''), true);
        if (!is_array($payload) || !is_array($payload['features'] ?? null)) {
            fortress_ml_queue_finish_db((int)$row['id'], true, ['discarded' => true]);
            continue;
        }
        $result = fortress_ml_post([
            'features' => $payload['features'],
            'rule_score' => (float)($payload['rule_score'] ?? 0),
        ]);
        if (!$result) {
            fortress_ml_queue_finish_db((int)$row['id'], false);
            return $processed;
        }
        fortress_ml_store_queued_prediction(
            (string)$row['source_ip'],
            $payload['features'],
            $result,
            [
                'queued_at' => strtotime((string)$row['queued_at']) ?: (int)($payload['captured_at'] ?? time()),
                'reason' => (string)($payload['reason'] ?? 'ml_unavailable'),
            ]
        );
        fortress_ml_queue_finish_db((int)$row['id'], true, $result);
        $processed++;
        if ($processed >= $limit) return $processed;
    }

    $fileRows = fortress_ml_queue_claim_files($limit - $processed);
    foreach ($fileRows as $row) {
        $payload = is_array($row['payload'] ?? null) ? $row['payload'] : [];
        if (!is_array($payload['features'] ?? null)) {
            fortress_ml_queue_finish_file($row, true);
            continue;
        }
        $result = fortress_ml_post([
            'features' => $payload['features'],
            'rule_score' => (float)($payload['rule_score'] ?? 0),
        ]);
        if (!$result) {
            fortress_ml_queue_finish_file($row, false);
            return $processed;
        }
        fortress_ml_store_queued_prediction(
            (string)($row['source_ip'] ?? 'unknown'),
            $payload['features'],
            $result,
            [
                'queued_at' => (int)($row['queued_at'] ?? $payload['captured_at'] ?? time()),
                'reason' => (string)($payload['reason'] ?? 'ml_unavailable'),
            ]
        );
        fortress_ml_queue_finish_file($row, true);
        $processed++;
        if ($processed >= $limit) break;
    }
    return $processed;
}

function fortress_ml_queue_status(): array
{
    $pending = 0;
    $completed = 0;
    global $pdo;
    if (fortress_ml_queue_db_available() && isset($pdo) && $pdo instanceof PDO) {
        try {
            $stmt = $pdo->query(
                "SELECT
                    COUNT(*) FILTER (WHERE status IN ('pending','processing')) AS pending,
                    COUNT(*) FILTER (WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '24 hours') AS completed_24h
                 FROM public.ml_analysis_queue"
            );
            $row = $stmt->fetch() ?: [];
            $pending += (int)($row['pending'] ?? 0);
            $completed += (int)($row['completed_24h'] ?? 0);
        } catch (Throwable $e) {
            // File fallback status below remains available.
        }
    }
    fortress_ml_queue_file_cleanup();
    $pending += count(glob(fortress_ml_queue_dir() . '/*.json') ?: []);
    $pending += count(glob(fortress_ml_queue_dir() . '/*.processing') ?: []);
    return ['pending' => $pending, 'completed_24h' => $completed];
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

    // Request telemetry/shutdown capture is prepared before the deterministic
    // monitor in middleware.php. Keep this idempotent call for direct includes.
    fortress_ml_prepare_request_capture();

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

    if (!$result) {
        // Preserve this behavioral snapshot instead of losing the ML analysis
        // opportunity while the remote model is sleeping/unavailable.
        fortress_ml_queue_enqueue($ip, $features, $ruleScore, 'prediction_unavailable');
        return;
    }

    $decision = fortress_ml_enforcement_decision($ip, $features, $result);
    $result['automatic_block'] = (bool)$decision['block'];
    $result['enforcement_mode'] = !empty($decision['enabled']) ? 'AI_ASSISTED' : 'ADVISORY';
    $result['enforcement_action'] = (string)$decision['action'];
    $result['enforcement_evidence'] = (array)$decision['evidence'];
    $result['enforcement_strikes'] = (int)$decision['strike_count'];
    $result['enforcement_required_strikes'] = (int)$decision['required_strikes'];
    $result['analysis_mode'] = 'LIVE';

    $record = [
        'ts' => time(),
        'ip' => $ip,
        'features' => $features,
        'result' => $result,
    ];
    fortress_ml_store_prediction_record($record);

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
            $banSeconds = (int)fortress_ml_enforcement_config()['ban_seconds'];
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

    // The successful live call proves the ML service is awake. Replay a small
    // bounded number of saved snapshots without delaying normal navigation.
    $replayLimit = fortress_ml_queue_replay_limit();
    fortress_ml_process_queue($replayLimit);
}

function fortress_ml_latest_prediction(): ?array
{
    $history = fortress_ml_prediction_history(1);
    if (isset($history[0]) && is_array($history[0])) return $history[0];

    // Compatibility fallback for an older/local installation that has only the
    // latest snapshot file and no predictions.jsonl history yet.
    $path = fortress_ml_data_dir() . '/latest_prediction.json';
    if (!is_file($path)) return null;
    $decoded = json_decode((string)@file_get_contents($path), true);
    return is_array($decoded) ? $decoded : null;
}
