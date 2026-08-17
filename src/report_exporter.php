<?php

declare(strict_types=1);

require_once __DIR__ . '/fortress_metrics.php';
require_once __DIR__ . '/user_accounts.php';
require_once __DIR__ . '/ml_threat.php';

function fortress_report_read_json(string $path): array
{
    if (!is_file($path)) return [];
    $raw = @file_get_contents($path);
    if (!is_string($raw) || trim($raw) === '') return [];
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function fortress_report_label(string $value): string
{
    $value = str_replace(['_', '-'], ' ', trim($value));
    $value = preg_replace('/\s+/', ' ', $value) ?? '';
    if ($value === '') return 'Not recorded';
    $label = ucwords(strtolower($value));
    return str_replace(
        ['Mfa', 'Csrf', 'Csp', ' Ip', 'Qr', 'Xgboost', ' Ml', 'Http'],
        ['MFA', 'CSRF', 'CSP', ' IP', 'QR', 'XGBoost', ' ML', 'HTTP'],
        $label
    );
}

function fortress_report_percent(mixed $value, int $digits = 1, bool $fraction = false): string
{
    if (!is_numeric($value)) return 'Not recorded';
    $number = (float)$value;
    if ($fraction) $number *= 100.0;
    return number_format($number, $digits) . '%';
}

function fortress_report_score(mixed $value, int $digits = 1): string
{
    if (!is_numeric($value)) return 'Not recorded';
    return number_format((float)$value, $digits) . '/100';
}

function fortress_report_epoch_time(mixed $value, string $fallback = 'Not recorded'): string
{
    $timestamp = is_numeric($value) ? (int)$value : 0;
    return $timestamp > 0 ? date('Y-m-d H:i:s', $timestamp) : $fallback;
}

/** @return array<int,array<string,mixed>> */
function fortress_report_prediction_history(int $limit = 25): array
{
    $rows = [];
    foreach (fortress_ml_prediction_history(max(1, $limit)) as $decoded) {
        if (!is_array($decoded['result'] ?? null)) continue;
        $result = $decoded['result'];
        $rows[] = [
            'Time' => fortress_report_epoch_time($decoded['ts'] ?? 0),
            'Source IP' => (string)($decoded['ip'] ?? 'unknown'),
            'Classification' => fortress_report_label((string)($result['classification'] ?? 'UNKNOWN')),
            'Confidence' => fortress_report_percent($result['confidence'] ?? null, 1, true),
            'Anomaly' => fortress_report_percent($result['anomaly_score'] ?? null, 1, false),
            'Rule Signal' => fortress_report_score($result['rule_score'] ?? null, 1),
            'XGBoost Risk' => fortress_report_score($result['xgboost_risk'] ?? null, 1),
            'Hybrid Risk' => fortress_report_score($result['risk_score'] ?? null, 1),
            'Severity' => fortress_report_label((string)($result['severity'] ?? 'UNKNOWN')),
            'Enforcement Action' => fortress_report_label((string)($result['enforcement_action'] ?? 'OBSERVE')),
            'Indicators' => implode('; ', array_map('strval', is_array($result['indicators'] ?? null) ? $result['indicators'] : [])),
        ];
    }
    return $rows;
}

function fortress_report_ai_findings(?array $latestPrediction, bool $mlEnabled): array
{
    if (!$mlEnabled && !$latestPrediction) {
        return [
            'The hybrid machine-learning service is currently disabled, so no live behavioral classification is available for this report.',
            'Password authentication, Personal ID verification, rate limits, deterministic request defenses, session controls, IP bans, and audit logging continue to operate without the ML service.',
            'When the ML service is enabled, FortressAuth combines XGBoost known-behavior classification, Autoencoder anomaly detection, and deterministic rule evidence into a hybrid risk assessment that can contribute guarded enforcement strikes.',
        ];
    }

    if (!$latestPrediction || !is_array($latestPrediction['result'] ?? null)) {
        return [
            'The ML service is enabled, but no completed behavioral analysis has been saved yet.',
            'FortressAuth needs a completed telemetry window before XGBoost classification, Autoencoder deviation, and hybrid risk can be documented.',
            'Core deterministic defenses remain active while the AI layer waits for enough behavioral telemetry.',
        ];
    }

    $result = $latestPrediction['result'];
    $classification = fortress_report_label((string)($result['classification'] ?? 'UNKNOWN'));
    $severity = fortress_report_label((string)($result['severity'] ?? 'UNKNOWN'));
    $confidence = is_numeric($result['confidence'] ?? null) ? ((float)$result['confidence'] * 100.0) : 0.0;
    $anomaly = (float)($result['anomaly_score'] ?? 0.0);
    $risk = (float)($result['risk_score'] ?? 0.0);
    $rule = (float)($result['rule_score'] ?? 0.0);
    $xgbRisk = (float)($result['xgboost_risk'] ?? 0.0);
    $source = (string)($latestPrediction['ip'] ?? 'unknown');
    $probabilities = is_array($result['probabilities'] ?? null) ? $result['probabilities'] : [];
    arsort($probabilities);
    $topProbabilityParts = [];
    foreach (array_slice($probabilities, 0, 3, true) as $class => $probability) {
        $topProbabilityParts[] = fortress_report_label((string)$class) . ' ' . fortress_report_percent($probability, 1, true);
    }

    $anomalyMeaning = $anomaly >= 70 ? 'strongly outside the learned normal baseline'
        : ($anomaly >= 50 ? 'a significant deviation from the learned normal baseline'
        : ($anomaly >= 30 ? 'a moderate deviation from the learned normal baseline' : 'near the learned normal baseline'));

    $messages = [
        sprintf('The latest hybrid assessment for source %s is %s with a risk score of %.1f/100 and a %s severity label.', $source, $classification, $risk, strtolower($severity)),
        sprintf('XGBoost classified the activity as %s with %.1f%% model confidence and contributed %.1f/100 to the known-behavior risk signal.', $classification, $confidence, $xgbRisk),
        sprintf('The Autoencoder anomaly score is %.1f%%, which places the observed activity %s. This anomaly percentage measures behavioral deviation and is not an attacker probability.', $anomaly, $anomalyMeaning),
        sprintf('The deterministic FortressAuth rule engine contributed %.1f/100. The hybrid model uses this rule evidence together with XGBoost and Autoencoder output rather than allowing ML to replace authentication or enforcement.', $rule),
    ];

    if ($topProbabilityParts) {
        $messages[] = 'The strongest XGBoost class probabilities are ' . implode(', ', $topProbabilityParts) . '.';
    }
    $indicators = array_values(array_filter(array_map('strval', is_array($result['indicators'] ?? null) ? $result['indicators'] : [])));
    if ($indicators) {
        $messages[] = 'Behavioral indicators recorded by the latest analysis: ' . implode('; ', $indicators) . '.';
    } else {
        $messages[] = 'The latest analysis did not record additional behavioral indicators beyond the model scores.';
    }
    $action = fortress_report_label((string)($result['enforcement_action'] ?? 'OBSERVE'));
    $messages[] = !empty($result['automatic_block'])
        ? 'AI-assisted enforcement issued a temporary network ban after the model result was corroborated by deterministic security evidence. Saved action: ' . $action . '.'
        : 'AI-assisted enforcement did not ban the source for this saved result. Current action: ' . $action . '. Authentication decisions remain independent of ML.';

    return $messages;
}

/**
 * Builds an administrator-safe documentation snapshot. Password hashes,
 * Personal ID QR hashes, session identifiers, cookies and CSRF values are
 * intentionally excluded from every exported format.
 */
function fortress_build_documentation_report(PDO $pdo, int $userId, string $scope = 'full', int $eventLimit = 50): array
{
    $allowedScopes = ['full', 'identity', 'security'];
    if (!in_array($scope, $allowedScopes, true)) $scope = 'full';
    $eventLimit = max(10, min(100, $eventLimit));

    $ctx = fortress_build_security_context($pdo, $userId);
    $users = fortress_fetch_users($pdo);
    $auditLines = is_array($ctx['auditLines'] ?? null) ? $ctx['auditLines'] : fortress_read_lines(__DIR__ . '/../data/audit.log');
    $defenseLayers = is_array($ctx['defenseLayers'] ?? null) ? $ctx['defenseLayers'] : [];

    $totalUsers = count($users);
    $activeUsers = count(array_filter($users, static fn(array $u): bool => (bool)($u['is_active'] ?? false)));
    $personalIdUsers = count(array_filter($users, static fn(array $u): bool => (bool)($u['school_id_2fa_required'] ?? true)));
    $superAdminUsers = count(array_filter($users, static fn(array $u): bool => fortress_normalize_role($u['role'] ?? 'superadmin') === 'superadmin'));
    $adminUsers = $totalUsers - $superAdminUsers;
    $generatedAt = new DateTimeImmutable('now');
    $operator = trim((string)($ctx['usernameRaw'] ?? 'admin')) ?: 'admin';
    $scopeLabels = [
        'full' => 'Full Security Documentation',
        'identity' => 'Access & Identity Documentation',
        'security' => 'Security & Audit Documentation',
    ];

    $latestPrediction = fortress_ml_latest_prediction();
    $mlEnabled = fortress_ml_enabled();
    $mlHistory = fortress_report_prediction_history(min(25, $eventLimit));
    $trainingReport = fortress_report_read_json(__DIR__ . '/../ml-service/data/training_report.json');
    if (!$trainingReport) $trainingReport = fortress_report_read_json(__DIR__ . '/../ml-service/models/model_metadata.json');

    $latestResult = is_array($latestPrediction['result'] ?? null) ? $latestPrediction['result'] : [];
    $latestFeatures = is_array($latestPrediction['features'] ?? null) ? $latestPrediction['features'] : [];
    $probabilities = is_array($latestResult['probabilities'] ?? null) ? $latestResult['probabilities'] : [];
    arsort($probabilities);

    $summary = [
        ['Protection score', (int)($ctx['protectionScore'] ?? 0) . '/100'],
        ['Protection status', (string)($ctx['protectionLabel'] ?? 'Unknown')],
        ['Threat level', (string)($ctx['threatLevel'] ?? 'Unknown')],
        ['Defense layers', (int)($ctx['activeDefenseCount'] ?? 0) . '/' . max(1, count($defenseLayers)) . ' operational'],
        ['Registered operators', (string)$totalUsers],
        ['Super administrators', (string)$superAdminUsers],
        ['Administrators', (string)$adminUsers],
        ['Active administrators', (string)$activeUsers],
        ['Personal ID 2FA accounts', (string)$personalIdUsers],
        ['Active IP bans', (string)(int)($ctx['activeBans'] ?? 0)],
        ['Failed passwords / 24h', (string)(int)($ctx['failedAttempts24h'] ?? 0)],
        ['Successful passwords / 24h', (string)(int)($ctx['successfulPassword24h'] ?? 0)],
        ['Personal ID successes / 24h', (string)(int)($ctx['schoolIdSuccess24h'] ?? 0)],
        ['Personal ID failures / 24h', (string)(int)($ctx['schoolIdFailures24h'] ?? 0)],
        ['Suspicious requests / 24h', (string)(int)($ctx['suspiciousRequests24h'] ?? 0)],
        ['Threat pressure points', (string)(int)($ctx['threatPoints'] ?? 0)],
        ['ML service', $mlEnabled ? 'Enabled' : 'Disabled'],
        ['Latest AI classification', $latestResult ? fortress_report_label((string)($latestResult['classification'] ?? 'Unknown')) : 'No completed analysis'],
        ['Latest hybrid risk', $latestResult ? fortress_report_score($latestResult['risk_score'] ?? null) : 'Not available'],
        ['Latest AI severity', $latestResult ? fortress_report_label((string)($latestResult['severity'] ?? 'Unknown')) : 'Not available'],
    ];

    $administrators = [];
    foreach ($users as $user) {
        $requires2fa = (bool)($user['school_id_2fa_required'] ?? true);
        $personalIdEnrolled = (bool)($user['school_id_qr_enabled'] ?? false);
        $administrators[] = [
            'Display Name' => trim((string)($user['full_name'] ?? '')) ?: (string)($user['username'] ?? 'Unknown'),
            'Username' => (string)($user['username'] ?? 'Unknown'),
            'Role' => fortress_normalize_role($user['role'] ?? 'superadmin') === 'superadmin' ? 'Super Admin' : 'Admin',
            'Account Status' => (bool)($user['is_active'] ?? false) ? 'Active' : 'Inactive',
            'Authentication Policy' => $requires2fa ? 'Password + Personal ID QR' : 'Password only',
            'Personal ID' => $requires2fa ? ($personalIdEnrolled ? 'Enrolled' : 'Enrollment required') : 'Not required',
            'Last Login' => fortress_format_date_value($user['last_login_at'] ?? null, 'Never'),
            'Updated' => fortress_format_date_value($user['updated_at'] ?? null, 'Not recorded'),
        ];
    }

    $defenses = [];
    foreach ($defenseLayers as $layer) {
        $defenses[] = [
            'Defense Layer' => (string)($layer[0] ?? 'Defense'),
            'State' => !empty($layer[1]) ? 'Operational' : 'Attention required',
            'Description' => (string)($layer[2] ?? ''),
            'Weight' => (string)(int)($layer[3] ?? 0) . ' points',
        ];
    }

    $meaningful = array_values(array_filter($auditLines, 'fortress_is_meaningful_event'));
    $meaningful = array_slice(array_reverse($meaningful), 0, $eventLimit);
    $events = [];
    foreach ($meaningful as $line) {
        $events[] = [
            'Time' => fortress_event_time($line, 'Y-m-d H:i:s'),
            'Category' => fortress_event_category($line),
            'Event' => fortress_event_title($line),
            'Source IP' => fortress_log_ip($line),
            'Outcome' => fortress_event_outcome($line),
            'Description' => fortress_event_description($line),
        ];
    }

    $personalIdLines = array_values(array_filter($auditLines, static fn(string $line): bool => fortress_line_has_any($line, [
        'school_id_qr_registered', 'school_id_qr_success', 'school_id_qr_failed', 'school_id_qr_locked',
        'school_id_qr_rate_limited', 'school_id_qr_reset', 'school_id_reverification_started',
        'user_2fa_enabled', 'user_2fa_disabled', 'user_2fa_replaced',
    ])));
    $personalIdLines = array_slice(array_reverse($personalIdLines), 0, min(40, $eventLimit));
    $identityEvents = [];
    foreach ($personalIdLines as $line) {
        $identityEvents[] = [
            'Time' => fortress_event_time($line, 'Y-m-d H:i:s'),
            'Event' => fortress_event_title($line),
            'Source IP' => fortress_log_ip($line),
            'Outcome' => fortress_event_outcome($line),
            'Description' => fortress_event_description($line),
        ];
    }

    $authLines = array_values(array_filter($auditLines, static fn(string $line): bool => fortress_is_auth_event($line) || fortress_line_has_any($line, ['login_failed', 'auth_rejected', 'login_disabled_account'])));
    $authLines = array_slice(array_reverse($authLines), 0, min(60, $eventLimit));
    $authEvents = [];
    foreach ($authLines as $line) {
        $authEvents[] = [
            'Time' => fortress_event_time($line, 'Y-m-d H:i:s'),
            'Category' => fortress_event_category($line),
            'Event' => fortress_event_title($line),
            'User' => fortress_log_user($line, 'not-recorded'),
            'Source IP' => fortress_log_ip($line),
            'Outcome' => fortress_event_outcome($line),
            'Description' => fortress_event_description($line),
        ];
    }

    $managementLines = array_values(array_filter($auditLines, static fn(string $line): bool => fortress_line_has_any($line, [
        'user_account_created', 'user_account_updated', 'user_account_enabled', 'user_account_disabled',
        'user_password_reset', 'user_personal_id_reset', 'user_account_deleted', 'user_2fa_enabled',
        'user_2fa_disabled', 'user_2fa_replaced', 'current_user_security_policy_changed',
    ])));
    $managementLines = array_slice(array_reverse($managementLines), 0, min(40, $eventLimit));
    $managementEvents = [];
    foreach ($managementLines as $line) {
        $managementEvents[] = [
            'Time' => fortress_event_time($line, 'Y-m-d H:i:s'),
            'Event' => fortress_event_title($line),
            'Actor/User' => fortress_log_user($line, 'admin'),
            'Source IP' => fortress_log_ip($line),
            'Outcome' => fortress_event_outcome($line),
            'Description' => fortress_event_description($line),
        ];
    }

    $last24 = [];
    $cutoff = time() - 86400;
    foreach ($auditLines as $line) {
        $dt = fortress_event_datetime($line);
        if ($dt && $dt->getTimestamp() >= $cutoff) $last24[] = $line;
    }

    $threatDefinitions = [
        ['Brute-force detections', ['bruteforce_detected'], 'Repeated password failures that crossed the brute-force detection threshold.'],
        ['Request / web attack detections', ['request_threat_detected', 'malicious_input_detected', 'shell_attack_detected'], 'Suspicious request or input signatures detected by deterministic request defenses.'],
        ['Reconnaissance / scanner activity', ['sensitive_path_probe', 'reconnaissance_probe', 'scanner_user_agent_detected'], 'Scanning or sensitive-path discovery activity recorded by FortressAuth.'],
        ['CSRF / CSP / method violations', ['csrf_validation_failed', 'csp_violation_reported', 'http_method_blocked', 'http_method_anomaly', 'endpoint_method_rejected'], 'Browser or request-policy violations blocked or recorded by platform controls.'],
        ['Network bans / blocked banned sources', ['ip_banned', 'banned_ip_attempt', 'banned_ip_middleware_block'], 'Sources temporarily banned or blocked before protected logic executed.'],
        ['Protected-resource rejections', ['auth_rejected', 'login_disabled_account'], 'Requests rejected because authentication, account state, or session requirements were not satisfied.'],
        ['Personal ID abuse / verification pressure', ['school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited'], 'Failed, locked, or rate-limited possession-factor verification activity.'],
        ['ML threat predictions recorded', ['ml_threat_prediction'], 'Hybrid ML analyses written to the audit trail after model/risk thresholds were met.'],
    ];
    $threatFindings = [];
    foreach ($threatDefinitions as [$label, $needles, $meaning]) {
        $count = count(array_filter($last24, static fn(string $line): bool => fortress_line_has_any($line, $needles)));
        $threatFindings[] = ['Threat Signal' => $label, '24-Hour Count' => (string)$count, 'Interpretation' => $meaning];
    }

    $sourceCounts = [];
    foreach ($last24 as $line) {
        $category = fortress_event_category($line);
        $outcome = fortress_event_outcome($line);
        if ($category !== 'Threat' && !in_array($outcome, ['BLOCKED', 'REJECTED'], true)) continue;
        $ip = fortress_log_ip($line);
        if ($ip === '' || $ip === 'unknown') continue;
        $sourceCounts[$ip] = ($sourceCounts[$ip] ?? 0) + 1;
    }
    arsort($sourceCounts);
    $topSources = [];
    foreach (array_slice($sourceCounts, 0, 10, true) as $ip => $count) {
        $topSources[] = ['Source IP' => (string)$ip, 'Security Events / 24h' => (string)$count, 'Note' => 'Count reflects reportable threat or blocked/rejected audit events, not a determination of attacker identity.'];
    }

    $aiLatest = [
        ['Metric', 'ML service state', 'Value', $mlEnabled ? 'ENABLED' : 'DISABLED'],
        ['Metric', 'Model', 'Value', (string)($latestResult['model'] ?? ($trainingReport['project'] ?? 'FortressAuth Hybrid ML'))],
        ['Metric', 'Latest analysis', 'Value', fortress_report_epoch_time($latestPrediction['ts'] ?? 0)],
        ['Metric', 'Source IP', 'Value', (string)($latestPrediction['ip'] ?? 'Not recorded')],
        ['Metric', 'Classification', 'Value', $latestResult ? fortress_report_label((string)($latestResult['classification'] ?? 'UNKNOWN')) : 'No completed analysis'],
        ['Metric', 'Model confidence', 'Value', $latestResult ? fortress_report_percent($latestResult['confidence'] ?? null, 1, true) : 'Not available'],
        ['Metric', 'Autoencoder anomaly', 'Value', $latestResult ? fortress_report_percent($latestResult['anomaly_score'] ?? null, 1, false) : 'Not available'],
        ['Metric', 'XGBoost risk contribution', 'Value', $latestResult ? fortress_report_score($latestResult['xgboost_risk'] ?? null, 1) : 'Not available'],
        ['Metric', 'Rule-engine signal', 'Value', $latestResult ? fortress_report_score($latestResult['rule_score'] ?? null, 1) : 'Not available'],
        ['Metric', 'Hybrid risk', 'Value', $latestResult ? fortress_report_score($latestResult['risk_score'] ?? null, 1) : 'Not available'],
        ['Metric', 'Severity', 'Value', $latestResult ? fortress_report_label((string)($latestResult['severity'] ?? 'UNKNOWN')) : 'Not available'],
        ['Metric', 'AI-assisted enforcement action', 'Value', $latestResult ? fortress_report_label((string)($latestResult['enforcement_action'] ?? 'OBSERVE')) : 'Not available'],
        ['Metric', 'AI-assisted temporary ban', 'Value', !empty($latestResult['automatic_block']) ? 'ENFORCED' : 'NOT ENFORCED'],
    ];

    $aiProbabilities = [];
    foreach ($probabilities as $class => $probability) {
        $aiProbabilities[] = ['Behavior Class' => fortress_report_label((string)$class), 'Probability' => fortress_report_percent($probability, 1, true)];
    }

    $featureLabels = [
        'requests_1m' => 'Requests / 1 min', 'requests_5m' => 'Requests / 5 min', 'unique_paths_5m' => 'Unique paths / 5 min',
        'post_ratio_5m' => 'POST ratio / 5 min', 'auth_endpoint_requests_5m' => 'Auth endpoint requests / 5 min',
        'failed_logins_5m' => 'Failed logins / 5 min', 'failed_logins_15m' => 'Failed logins / 15 min',
        'unique_usernames_15m' => 'Unique usernames / 15 min', 'successful_logins_15m' => 'Successful logins / 15 min',
        'qr_failures_15m' => 'Personal ID failures / 15 min', 'sensitive_path_probes_15m' => 'Sensitive path probes / 15 min',
        'suspicious_requests_15m' => 'Suspicious requests / 15 min', 'scanner_events_15m' => 'Scanner events / 15 min',
        'csrf_failures_15m' => 'CSRF failures / 15 min', 'method_anomalies_15m' => 'HTTP method anomalies / 15 min',
        'auth_rejections_15m' => 'Auth rejections / 15 min', 'ban_events_15m' => 'Ban events / 15 min',
        'avg_request_interval_5m' => 'Avg request interval / 5 min', 'ua_changes_15m' => 'User-agent changes / 15 min', 'off_hours' => 'Off-hours flag',
    ];
    $aiFeatures = [];
    foreach ($latestFeatures as $key => $value) {
        $display = is_float($value) ? number_format($value, 3) : (string)$value;
        if ($key === 'post_ratio_5m' && is_numeric($value)) $display = fortress_report_percent((float)$value, 1, true);
        $aiFeatures[] = ['Feature' => $featureLabels[$key] ?? fortress_report_label((string)$key), 'Value' => $display, 'Internal Key' => (string)$key];
    }

    $dataset = is_array($trainingReport['dataset'] ?? null) ? $trainingReport['dataset'] : [];
    $xgboost = is_array($trainingReport['xgboost'] ?? null) ? $trainingReport['xgboost'] : [];
    $autoencoder = is_array($trainingReport['autoencoder'] ?? null) ? $trainingReport['autoencoder'] : [];
    $fusion = is_array($trainingReport['risk_fusion'] ?? null) ? $trainingReport['risk_fusion'] : [];
    $classes = is_array($dataset['classes'] ?? null) ? $dataset['classes'] : [];
    $trainingFeatures = is_array($dataset['features'] ?? null) ? $dataset['features'] : [];
    $bands = is_array($fusion['bands'] ?? null) ? $fusion['bands'] : [];

    $modelValidation = [
        ['Field' => 'Project / model family', 'Details' => (string)($trainingReport['project'] ?? 'FortressAuth Hybrid Intelligent Threat Detection')],
        ['Field' => 'Training data type', 'Details' => (string)($dataset['type'] ?? 'Not recorded')],
        ['Field' => 'Training rows', 'Details' => (string)($dataset['training_rows'] ?? 'Not recorded')],
        ['Field' => 'Holdout rows', 'Details' => (string)($dataset['holdout_rows'] ?? 'Not recorded')],
        ['Field' => 'Behavior classes', 'Details' => $classes ? implode(', ', array_map(static fn($v): string => fortress_report_label((string)$v), $classes)) : 'Not recorded'],
        ['Field' => 'Behavioral features', 'Details' => $trainingFeatures ? count($trainingFeatures) . ' non-sensitive numerical features' : 'Not recorded'],
        ['Field' => 'XGBoost holdout accuracy', 'Details' => fortress_report_percent($xgboost['accuracy'] ?? null, 2, true)],
        ['Field' => 'XGBoost macro F1', 'Details' => fortress_report_percent($xgboost['macro_f1'] ?? null, 2, true)],
        ['Field' => 'Autoencoder implementation', 'Details' => (string)($autoencoder['implementation'] ?? 'Not recorded')],
        ['Field' => 'Autoencoder normal error p95', 'Details' => is_numeric($autoencoder['normal_error_p95'] ?? null) ? number_format((float)$autoencoder['normal_error_p95'], 4) : 'Not recorded'],
        ['Field' => 'Autoencoder threshold p99', 'Details' => is_numeric($autoencoder['threshold_p99'] ?? null) ? number_format((float)$autoencoder['threshold_p99'], 4) : 'Not recorded'],
        ['Field' => 'Holdout anomaly recall', 'Details' => fortress_report_percent($autoencoder['holdout_anomaly_recall'] ?? null, 2, true)],
        ['Field' => 'Normal false-positive rate', 'Details' => fortress_report_percent($autoencoder['holdout_normal_false_positive_rate'] ?? null, 2, true)],
        ['Field' => 'Hybrid fusion weights', 'Details' => 'Rules ' . fortress_report_percent($fusion['rule_weight'] ?? null, 0, true) . ' | XGBoost ' . fortress_report_percent($fusion['xgboost_weight'] ?? null, 0, true) . ' | Autoencoder ' . fortress_report_percent($fusion['autoencoder_weight'] ?? null, 0, true)],
        ['Field' => 'Hybrid risk bands', 'Details' => $bands ? implode(' | ', array_map(static fn($k, $v): string => fortress_report_label((string)$k) . ' ' . (string)$v, array_keys($bands), array_values($bands))) : 'Not recorded'],
        ['Field' => 'Training-data note', 'Details' => (string)($dataset['note'] ?? 'Training metadata was not recorded.')],
    ];

    $featureImportance = [];
    foreach (is_array($xgboost['top_feature_importance'] ?? null) ? $xgboost['top_feature_importance'] : [] as $index => $item) {
        if (!is_array($item)) continue;
        $featureImportance[] = [
            'Rank' => (string)($index + 1),
            'Feature' => $featureLabels[(string)($item[0] ?? '')] ?? fortress_report_label((string)($item[0] ?? 'Unknown')),
            'Importance' => fortress_report_percent($item[1] ?? null, 2, true),
        ];
    }

    $classMetrics = [];
    $classificationReport = is_array($xgboost['classification_report'] ?? null) ? $xgboost['classification_report'] : [];
    foreach ($classes as $class) {
        $metrics = is_array($classificationReport[$class] ?? null) ? $classificationReport[$class] : [];
        if (!$metrics) continue;
        $classMetrics[] = [
            'Behavior Class' => fortress_report_label((string)$class),
            'Precision' => fortress_report_percent($metrics['precision'] ?? null, 2, true),
            'Recall' => fortress_report_percent($metrics['recall'] ?? null, 2, true),
            'F1 Score' => fortress_report_percent($metrics['f1-score'] ?? null, 2, true),
            'Support' => (string)(int)($metrics['support'] ?? 0),
        ];
    }

    $provenance = [
        ['Source' => 'Administrator database', 'Purpose' => 'Account status, authentication policy, Personal ID enrollment state, last-login and update timestamps.', 'Privacy Boundary' => 'No password hashes or QR credential hashes are exported.'],
        ['Source' => 'FortressAuth audit log', 'Purpose' => 'Authentication, Personal ID, account-management, network-defense, request-defense, session, and documentation events.', 'Privacy Boundary' => 'Sensitive request values, CSRF tokens, cookies, authorization headers, and session identifiers are excluded.'],
        ['Source' => 'ML latest prediction / history', 'Purpose' => 'XGBoost classification, Autoencoder anomaly score, hybrid risk, safe behavioral feature window, and AI analysis history.', 'Privacy Boundary' => 'Only non-sensitive numerical behavior and source IP evidence are used in the model report.'],
        ['Source' => 'ML training metadata', 'Purpose' => 'Model validation metrics, class performance, feature importance, Autoencoder validation, and fusion weights.', 'Privacy Boundary' => 'Training metadata describes the course-project model and does not contain user credentials.'],
    ];

    $limitations = [
        'This report is a point-in-time administrative snapshot. Counts and findings can change as new authentication and security events are recorded.',
        'XGBoost confidence is model confidence for the selected behavior class. It is not a probability that a person is an attacker.',
        'Autoencoder anomaly percentage represents deviation from the learned normal baseline. It must be interpreted with classifier, rule-engine, and audit evidence.',
        'The current ML training metadata identifies synthetic/simulated course-project security telemetry. Evaluation scores demonstrate model behavior in that controlled dataset and must not be presented as production incident prevalence.',
        'The hybrid ML layer is supplementary and cannot make authentication decisions. Guarded network enforcement requires a malicious model result plus deterministic corroboration, with repeated qualified strikes or a high-risk multi-signal threshold before a temporary ban.',
        'Source IP evidence identifies the network source recorded by the application and does not by itself establish the identity or intent of a person.',
        'Generated documentation intentionally excludes passwords, password hashes, Personal ID QR values/hashes, cookies, session IDs, CSRF tokens, authorization headers, and similar secrets.',
    ];

    $conclusion = [
        sprintf('FortressAuth reports a protection score of %d/100 with a current protection status of %s and threat level of %s.', (int)($ctx['protectionScore'] ?? 0), (string)($ctx['protectionLabel'] ?? 'Unknown'), (string)($ctx['threatLevel'] ?? 'Unknown')),
        $latestResult
            ? sprintf('The latest AI analysis is %s with %s hybrid risk and %s severity; use this together with the threat findings and audit evidence in this report.', fortress_report_label((string)($latestResult['classification'] ?? 'Unknown')), fortress_report_score($latestResult['risk_score'] ?? null), fortress_report_label((string)($latestResult['severity'] ?? 'Unknown')))
            : 'No completed AI prediction is available in the current snapshot, so the report relies on deterministic defenses, authentication records, and audit evidence.',
        'For documentation or presentation, prioritize the executive summary, AI/model findings, threat findings, authentication evidence, defense posture, and the most recent audit events. Keep the limitations slide/page attached when presenting model results.',
    ];

    return [
        'meta' => [
            'title' => 'FortressAuth Security Findings & Documentation Report',
            'subtitle' => 'System Findings, AI Model Analysis, Authentication Records & Audit Evidence',
            'report_id' => 'FAR-' . $generatedAt->format('Ymd-His') . '-U' . max(0, $userId),
            'scope' => $scope,
            'scope_label' => $scopeLabels[$scope],
            'generated_at' => $generatedAt->format('Y-m-d H:i:s T'),
            'generated_by' => $operator,
            'classification' => 'Administrative security documentation',
            'evidence_limit' => $eventLimit,
            'evidence_window' => '24-hour metrics plus up to ' . $eventLimit . ' selected recent evidence events',
            'notice' => 'Safe export boundary: passwords, hashes, QR credential values, session identifiers, cookies, CSRF tokens and authorization secrets are excluded.',
        ],
        'summary' => $summary,
        'ai' => [
            'latest' => $aiLatest,
            'probabilities' => $aiProbabilities,
            'features' => $aiFeatures,
            'indicators' => array_values(array_filter(array_map('strval', is_array($latestResult['indicators'] ?? null) ? $latestResult['indicators'] : []))),
            'analyst_findings' => fortress_report_ai_findings($latestPrediction, $mlEnabled),
            'history' => $mlHistory,
            'model_validation' => $modelValidation,
            'feature_importance' => $featureImportance,
            'class_metrics' => $classMetrics,
        ],
        'threat_findings' => $threatFindings,
        'top_sources' => $topSources,
        'authentication_events' => $authEvents,
        'administrators' => $administrators,
        'identity_events' => $identityEvents,
        'management_events' => $managementEvents,
        'defenses' => $defenses,
        'events' => $events,
        'provenance' => $provenance,
        'limitations' => $limitations,
        'conclusion' => $conclusion,
    ];
}

function fortress_report_ascii(string $value): string
{
    $value = str_replace(["\r", "\n", "\t"], [' ', ' ', ' '], $value);
    $value = preg_replace('/\s+/', ' ', trim($value)) ?? '';
    $replace = [
        '—' => '-', '–' => '-', '’' => "'", '‘' => "'", '“' => '"', '”' => '"',
        '•' => '-', '…' => '...', '→' => '->', '·' => '-', '×' => 'x',
    ];
    return strtr($value, $replace);
}

function fortress_report_xml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
}

function fortress_report_filename(array $report, string $extension): string
{
    $scope = preg_replace('/[^a-z0-9_-]+/i', '-', (string)($report['meta']['scope'] ?? 'full')) ?: 'full';
    return 'FortressAuth-' . $scope . '-report-' . date('Ymd-His') . '.' . $extension;
}

/** @return array<int,string> */
function fortress_report_wrap(string $text, int $width): array
{
    $text = fortress_report_ascii($text);
    if ($text === '') return [''];
    $wrapped = wordwrap($text, max(12, $width), "\n", true);
    return explode("\n", $wrapped);
}

function fortress_pdf_escape(string $text): string
{
    $text = fortress_report_ascii($text);
    $text = str_replace('\\', '\\\\', $text);
    $text = str_replace('(', '\\(', $text);
    return str_replace(')', '\\)', $text);
}

function fortress_report_summary_value(array $summary, string $label, string $fallback = 'Not recorded'): string
{
    foreach ($summary as $row) {
        if ((string)($row[0] ?? '') === $label) return (string)($row[1] ?? $fallback);
    }
    return $fallback;
}

function fortress_report_pdf(array $report): string
{
    $meta = is_array($report['meta'] ?? null) ? $report['meta'] : [];
    $summary = is_array($report['summary'] ?? null) ? $report['summary'] : [];
    $conclusion = is_array($report['conclusion'] ?? null) ? $report['conclusion'] : [];

    $hexToRgb = static function (string $hex): string {
        $hex = strtoupper(trim($hex));
        $hex = ltrim($hex, '#');
        if (strlen($hex) === 3) {
            $hex = $hex[0] . $hex[0] . $hex[1] . $hex[1] . $hex[2] . $hex[2];
        }
        if (!preg_match('/^[0-9A-F]{6}$/', $hex)) $hex = '000000';
        $r = hexdec(substr($hex, 0, 2)) / 255;
        $g = hexdec(substr($hex, 2, 2)) / 255;
        $b = hexdec(substr($hex, 4, 2)) / 255;
        return number_format($r, 3, '.', '') . ' ' . number_format($g, 3, '.', '') . ' ' . number_format($b, 3, '.', '');
    };

    $pages = [];
    $page = ['mode' => 'cover', 'items' => []];
    $y = 0.0;

    $addRect = static function (float $x, float $y0, float $w, float $h, string $fill, ?string $stroke = null, float $lineWidth = 1.0) use (&$page): void {
        $page['items'][] = [
            'type' => 'rect',
            'x' => $x,
            'y' => $y0,
            'w' => $w,
            'h' => $h,
            'fill' => $fill,
            'stroke' => $stroke,
            'line_width' => $lineWidth,
        ];
    };

    $addText = static function (string $text, float $x, float $y0, float $size = 9.5, bool $bold = false, string $color = '24212B') use (&$page): void {
        $page['items'][] = [
            'type' => 'text',
            'text' => fortress_report_ascii($text),
            'x' => $x,
            'y' => $y0,
            'size' => $size,
            'bold' => $bold,
            'color' => $color,
        ];
    };

    $addWrappedAbs = static function (string $text, float $x, float $y0, int $width, float $size = 9.0, bool $bold = false, string $color = '24212B', float $leading = 12.0) use ($addText): float {
        foreach (fortress_report_wrap($text, $width) as $line) {
            $addText($line, $x, $y0, $size, $bold, $color);
            $y0 -= $leading;
        }
        return $y0;
    };

    $newPage = static function (string $mode = 'body') use (&$pages, &$page, &$y): void {
        if (!empty($page['items'])) $pages[] = $page;
        $page = ['mode' => $mode, 'items' => []];
        $y = $mode === 'cover' ? 0.0 : 694.0;
    };

    $title = (string)($meta['title'] ?? 'FortressAuth Security Findings & Documentation Report');
    $subtitle = (string)($meta['subtitle'] ?? 'System findings, AI model analysis, authentication records and audit evidence');
    $scopeLabel = (string)($meta['scope_label'] ?? 'Full Security Documentation');
    $reportId = (string)($meta['report_id'] ?? 'Not assigned');
    $generatedAt = (string)($meta['generated_at'] ?? date('Y-m-d H:i:s'));
    $generatedBy = (string)($meta['generated_by'] ?? 'FortressAuth');
    $notice = (string)($meta['notice'] ?? 'Safe export boundary: passwords, hashes, QR credential values, session identifiers, cookies, CSRF tokens and authorization secrets are excluded.');
    $evidenceWindow = (string)($meta['evidence_window'] ?? 'Administrative report snapshot');

    $addRect(0, 0, 612, 792, 'FAF7FD');
    $addRect(0, 560, 612, 232, '16091F');
    $addRect(0, 548, 612, 12, '7C3AED');
    $addRect(418, 0, 194, 792, 'F4EDFB');
    $addRect(432, 595, 130, 130, '241030');
    $addRect(452, 615, 90, 90, '7C3AED');

    $addText('FORTRESSAUTH SECURITY DOCUMENTATION', 46, 752, 10.5, true, 'CFA9FF');
    $addWrappedAbs($title, 46, 716, 34, 21.0, true, 'FFFFFF', 23.0);
    $addWrappedAbs($subtitle, 46, 659, 58, 10.6, false, 'EADAF8', 12.5);
    $addRect(46, 614, 170, 24, '8B5CF6');
    $addText($scopeLabel, 56, 621, 9.8, true, 'FFFFFF');
    $addText('Report ID: ' . $reportId, 46, 594, 9.1, true, 'F8F2FF');
    $addText('Generated: ' . $generatedAt, 46, 578, 8.9, false, 'EDE3F6');
    $addText('Prepared by: ' . $generatedBy, 46, 564, 8.9, false, 'EDE3F6');
    $addWrappedAbs('Evidence window: ' . $evidenceWindow, 46, 548, 64, 8.7, false, 'EDE3F6', 11.3);

    $addRect(46, 486, 520, 60, 'F6EFFB', 'E6D8F3');
    $addText('SAFE EXPORT BOUNDARY', 58, 528, 9.2, true, '5B21B6');
    $addWrappedAbs($notice, 58, 512, 82, 8.5, false, '4B4453', 10.5);

    $metricCards = [
        ['Protection score', fortress_report_summary_value($summary, 'Protection score')],
        ['Threat level', fortress_report_summary_value($summary, 'Threat level')],
        ['Defense layers', fortress_report_summary_value($summary, 'Defense layers')],
        ['Active administrators', fortress_report_summary_value($summary, 'Active administrators')],
        ['Suspicious requests / 24h', fortress_report_summary_value($summary, 'Suspicious requests / 24h')],
        ['Latest hybrid risk', fortress_report_summary_value($summary, 'Latest hybrid risk')],
    ];
    $cardFill = ['FFFFFF', 'F5EEFF', 'FFFFFF', 'F5EEFF', 'FFFFFF', 'F5EEFF'];
    $cardPositions = [
        [46, 398], [310, 398], [46, 326], [310, 326], [46, 254], [310, 254],
    ];
    foreach ($metricCards as $index => $metric) {
        [$cx, $cy] = $cardPositions[$index];
        $addRect($cx, $cy, 230, 58, $cardFill[$index], 'E6D8F3');
        $addText((string)$metric[0], $cx + 12, $cy + 40, 8.2, true, '6D28D9');
        $addWrappedAbs((string)$metric[1], $cx + 12, $cy + 22, 24, 13.5, true, '20122E', 13.5);
    }

    $addRect(46, 128, 252, 92, 'FFFFFF', 'E6D8F3');
    $addText('DOCUMENTATION PACKAGE', 58, 204, 9.0, true, '5B21B6');
    $packageLines = [
        'Executive security summary and system posture',
        'AI model findings, probabilities and validation',
        'Authentication records, Personal ID evidence and security logs',
        'Defense-layer status, evidence sources and final assessment',
    ];
    $packageY = 188.0;
    foreach ($packageLines as $line) {
        $packageY = $addWrappedAbs(chr(149) . ' ' . $line, 60, $packageY, 34, 8.2, false, '403748', 10.2);
    }

    $addRect(312, 128, 254, 92, 'F4EDFB', 'E6D8F3');
    $addText('PRESENTATION HIGHLIGHTS', 324, 204, 9.0, true, '5B21B6');
    $highlightLines = $conclusion ? array_slice($conclusion, 0, 3) : [
        'Use the executive summary and AI findings as the main briefing points.',
        'Use authentication and audit evidence to support documentation.',
    ];
    $highlightY = 188.0;
    foreach ($highlightLines as $index => $line) {
        $highlightY = $addWrappedAbs(($index + 1) . '. ' . (string)$line, 326, $highlightY, 34, 8.2, false, '403748', 10.2);
    }

    $addText('FortressAuth • Premium security documentation export', 46, 34, 8.4, false, '7B6D88');

    $newPage('body');

    $addLine = static function (
        string $text,
        float $size = 9.5,
        bool $bold = false,
        float $indent = 0.0,
        float $leading = 13.0,
        string $style = 'normal',
        string $color = '24212B'
    ) use (&$y, $newPage, $addText, $addRect): void {
        $required = $style === 'section' ? 34 : ($style === 'callout' ? 22 : 18);
        if ($y < 60 + $required) $newPage('body');
        $x = 52.0 + $indent;
        if ($style === 'section') {
            $addRect(38, $y - 8, 536, 22, 'EFE8F8');
            $addRect(38, $y - 8, 7, 22, '7C3AED');
            $color = '2F1243';
        } elseif ($style === 'callout') {
            $addRect(44, $y - 6, 524, 18, 'F8F3FC');
            $color = '5B21B6';
        }
        $addText($text, $x, $y, $size, $bold, $color);
        $y -= $leading;
    };

    $addWrapped = static function (
        string $text,
        int $width = 94,
        float $size = 9.1,
        bool $bold = false,
        float $indent = 0.0,
        string $style = 'normal',
        string $color = '24212B'
    ) use ($addLine): void {
        $first = true;
        foreach (fortress_report_wrap($text, $width) as $line) {
            $addLine($line, $size, $bold, $indent, 12.25, $first ? $style : 'normal', $color);
            $first = false;
        }
    };

    $section = static function (string $title) use (&$y, $addLine, $newPage): void {
        if ($y < 132) $newPage('body');
        $y -= 5;
        $addLine(strtoupper($title), 11.2, true, 0, 22.5, 'section');
    };

    $keyValueRows = static function (array $rows, int $width = 92) use ($addWrapped): void {
        foreach ($rows as $row) {
            if (isset($row[0], $row[1])) {
                $addWrapped((string)$row[0] . ': ' . (string)$row[1], $width, 8.95, false, 8);
            }
        }
    };

    $metaIntro = [
        'Report ID: ' . $reportId,
        'Generated: ' . $generatedAt,
        'Generated by: ' . $generatedBy,
        'Scope: ' . $scopeLabel,
    ];
    foreach ($metaIntro as $index => $line) {
        $addLine($line, $index === 0 ? 9.4 : 8.8, $index === 0, 0, 12.5, $index === 0 ? 'callout' : 'normal');
    }
    $addWrapped($notice, 94, 8.3, false, 0, 'callout', '5A5365');

    $section('Executive security summary');
    $keyValueRows($report['summary'] ?? []);

    if (in_array((string)($meta['scope'] ?? 'full'), ['full', 'security'], true)) {
        $section('AI & model findings');
        foreach (($report['ai']['latest'] ?? []) as $row) {
            $addWrapped((string)($row[1] ?? 'Metric') . ': ' . (string)($row[3] ?? 'Not recorded'), 92, 8.95, false, 8);
        }

        $addLine('AI analyst interpretation', 9.9, true, 8, 15.5, 'callout');
        foreach (($report['ai']['analyst_findings'] ?? []) as $index => $finding) {
            $addWrapped(($index + 1) . '. ' . (string)$finding, 88, 8.65, false, 13);
        }

        if (!empty($report['ai']['probabilities'])) {
            $addLine('XGBoost behavior probabilities', 9.9, true, 8, 15.5, 'callout');
            foreach ($report['ai']['probabilities'] as $row) {
                $addWrapped((string)$row['Behavior Class'] . ': ' . (string)$row['Probability'], 88, 8.55, false, 13);
            }
        }

        if (!empty($report['ai']['features'])) {
            $addLine('Current non-sensitive behavioral feature window', 9.9, true, 8, 15.5, 'callout');
            foreach (array_slice($report['ai']['features'], 0, 20) as $row) {
                $addWrapped((string)$row['Feature'] . ': ' . (string)$row['Value'], 88, 8.45, false, 13);
            }
        }

        $section('Model validation & training metadata');
        foreach (($report['ai']['model_validation'] ?? []) as $row) {
            $addWrapped((string)$row['Field'] . ': ' . (string)$row['Details'], 91, 8.55, false, 8);
        }
        if (!empty($report['ai']['feature_importance'])) {
            $addLine('Top XGBoost feature importance', 9.9, true, 8, 15.5, 'callout');
            foreach (array_slice($report['ai']['feature_importance'], 0, 10) as $row) {
                $addWrapped('#' . $row['Rank'] . ' ' . $row['Feature'] . ' - ' . $row['Importance'], 88, 8.45, false, 13);
            }
        }
        if (!empty($report['ai']['class_metrics'])) {
            $addLine('XGBoost class-level holdout metrics', 9.9, true, 8, 15.5, 'callout');
            foreach ($report['ai']['class_metrics'] as $row) {
                $addWrapped($row['Behavior Class'] . ' | Precision ' . $row['Precision'] . ' | Recall ' . $row['Recall'] . ' | F1 ' . $row['F1 Score'] . ' | Support ' . $row['Support'], 88, 8.25, false, 13);
            }
        }

        $section('Threat findings - last 24 hours');
        foreach (($report['threat_findings'] ?? []) as $row) {
            $addWrapped($row['Threat Signal'] . ': ' . $row['24-Hour Count'], 90, 8.95, true, 8);
            $addWrapped($row['Interpretation'], 88, 8.25, false, 13);
        }
        if (!empty($report['top_sources'])) {
            $addLine('Top security-event source IPs', 9.9, true, 8, 15.5, 'callout');
            foreach (array_slice($report['top_sources'], 0, 10) as $row) {
                $parts = [];
                foreach (['Source IP', 'Security Events / 24h', 'Note'] as $key) {
                    if (isset($row[$key]) && (string)$row[$key] !== '') $parts[] = $key . ': ' . (string)$row[$key];
                }
                if ($parts) $addWrapped(implode(' | ', $parts), 88, 8.35, false, 13);
            }
        }

        if (!empty($report['ai']['history'])) {
            $section('Recent AI analyses');
            foreach (array_slice($report['ai']['history'], 0, 15) as $row) {
                $addWrapped($row['Time'] . ' | ' . $row['Source IP'] . ' | ' . $row['Classification'] . ' | Confidence ' . $row['Confidence'] . ' | Anomaly ' . $row['Anomaly'] . ' | Risk ' . $row['Hybrid Risk'] . ' | ' . $row['Severity'], 90, 8.2, true, 8);
                if ((string)($row['Indicators'] ?? '') !== '') $addWrapped('Indicators: ' . $row['Indicators'], 87, 7.95, false, 13);
            }
        }
    }

    if (in_array((string)($meta['scope'] ?? 'full'), ['full', 'identity'], true)) {
        $section('Administrator access directory');
        if (empty($report['administrators'])) {
            $addLine('No administrator records are available.');
        } else {
            foreach ($report['administrators'] as $index => $row) {
                $addLine(($index + 1) . '. ' . (string)$row['Display Name'] . ' (' . (string)$row['Username'] . ')', 9.7, true, 7, 14);
                $addWrapped('Role: ' . $row['Role'] . ' | Status: ' . $row['Account Status'] . ' | Policy: ' . $row['Authentication Policy'] . ' | Personal ID: ' . $row['Personal ID'], 88, 8.4, false, 12);
                $addWrapped('Last login: ' . $row['Last Login'] . ' | Updated: ' . $row['Updated'], 88, 8.3, false, 12);
            }
        }

        $section('Authentication records');
        if (empty($report['authentication_events'])) {
            $addLine('No recent authentication evidence is available.');
        } else {
            foreach (array_slice($report['authentication_events'], 0, (int)($meta['evidence_limit'] ?? 50)) as $row) {
                $addWrapped($row['Time'] . ' | ' . $row['Outcome'] . ' | ' . $row['Event'] . ' | User ' . $row['User'] . ' | ' . $row['Source IP'], 90, 8.3, true, 7);
                $addWrapped($row['Description'], 88, 7.95, false, 13);
            }
        }

        $section('Personal ID security evidence');
        if (empty($report['identity_events'])) {
            $addLine('No Personal ID security events are available.');
        } else {
            foreach ($report['identity_events'] as $row) {
                $addWrapped($row['Time'] . ' | ' . $row['Outcome'] . ' | ' . $row['Event'] . ' | ' . $row['Source IP'], 90, 8.3, true, 7);
                $addWrapped($row['Description'], 88, 7.95, false, 13);
            }
        }

        if (!empty($report['management_events'])) {
            $section('Administrator account change evidence');
            foreach ($report['management_events'] as $row) {
                $addWrapped($row['Time'] . ' | ' . $row['Outcome'] . ' | ' . $row['Event'] . ' | ' . $row['Source IP'], 90, 8.3, true, 7);
                $addWrapped($row['Description'], 88, 7.95, false, 13);
            }
        }
    }

    if (in_array((string)($meta['scope'] ?? 'full'), ['full', 'security'], true)) {
        $section('Defense posture');
        foreach (($report['defenses'] ?? []) as $row) {
            $addWrapped($row['Defense Layer'] . ' - ' . $row['State'] . ' (' . $row['Weight'] . ')', 90, 8.85, true, 7);
            $addWrapped($row['Description'], 88, 8.1, false, 13);
        }

        $section('Recent security audit evidence');
        if (empty($report['events'])) {
            $addLine('No meaningful security events are available.');
        } else {
            foreach ($report['events'] as $row) {
                $addWrapped($row['Time'] . ' | ' . $row['Category'] . ' | ' . $row['Outcome'] . ' | ' . $row['Event'] . ' | ' . $row['Source IP'], 90, 8.2, true, 7);
                $addWrapped($row['Description'], 88, 7.9, false, 13);
            }
        }
    }

    $section('Evidence sources & privacy boundaries');
    foreach (($report['provenance'] ?? []) as $row) {
        $addWrapped($row['Source'] . ': ' . $row['Purpose'], 90, 8.55, true, 7);
        $addWrapped('Privacy: ' . $row['Privacy Boundary'], 88, 8.0, false, 13);
    }

    $section('Conclusion / system assessment');
    foreach (($report['conclusion'] ?? []) as $index => $line) {
        $addWrapped(($index + 1) . '. ' . (string)$line, 90, 8.7, false, 7, $index === 0 ? 'callout' : 'normal');
    }

    $section('Limitations and assumptions');
    foreach (($report['limitations'] ?? []) as $index => $line) {
        $addWrapped(($index + 1) . '. ' . (string)$line, 90, 8.25, false, 7);
    }

    if (!empty($page['items'])) $pages[] = $page;
    if (!$pages) $pages = [['mode' => 'body', 'items' => []]];

    $objects = [];
    $objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
    $objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
    $objects[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>';

    $pageRefs = [];
    $objNo = 5;
    $pageCount = count($pages);
    foreach ($pages as $pageIndex => $pageDef) {
        $pageObj = $objNo++;
        $contentObj = $objNo++;
        $pageRefs[] = $pageObj . ' 0 R';

        $mode = (string)($pageDef['mode'] ?? 'body');
        $stream = '';
        if ($mode === 'body') {
            $stream .= "q\n" . $hexToRgb('FFFFFF') . " rg\n0 0 612 792 re f\nQ\n";
            $stream .= "q\n" . $hexToRgb('16091F') . " rg\n0 752 612 40 re f\nQ\n";
            $stream .= "q\n" . $hexToRgb('7C3AED') . " rg\n0 744 612 8 re f\nQ\n";
            $stream .= "BT /F2 8 Tf " . $hexToRgb('D8B4FE') . " rg 42 768 Td (FORTRESSAUTH PREMIUM DOCUMENTATION REPORT) Tj ET\n";
            $stream .= "BT /F1 8 Tf " . $hexToRgb('6C6477') . " rg 42 22 Td (Page " . ($pageIndex + 1) . " of " . $pageCount . "  •  " . fortress_pdf_escape($scopeLabel) . "  •  Report ID " . fortress_pdf_escape($reportId) . ") Tj ET\n";
            $stream .= "q\n" . $hexToRgb('EFE8F8') . " rg\n36 34 540 1 re f\nQ\n";
        }

        foreach (($pageDef['items'] ?? []) as $item) {
            if (($item['type'] ?? '') === 'rect') {
                $stream .= "q\n" . $hexToRgb((string)$item['fill']) . " rg\n";
                $stream .= number_format((float)$item['x'], 2, '.', '') . ' ' . number_format((float)$item['y'], 2, '.', '') . ' ' . number_format((float)$item['w'], 2, '.', '') . ' ' . number_format((float)$item['h'], 2, '.', '') . " re f\n";
                if (!empty($item['stroke'])) {
                    $stream .= $hexToRgb((string)$item['stroke']) . " RG\n" . number_format((float)($item['line_width'] ?? 1.0), 2, '.', '') . " w\n";
                    $stream .= number_format((float)$item['x'], 2, '.', '') . ' ' . number_format((float)$item['y'], 2, '.', '') . ' ' . number_format((float)$item['w'], 2, '.', '') . ' ' . number_format((float)$item['h'], 2, '.', '') . " re S\n";
                }
                $stream .= "Q\n";
            } elseif (($item['type'] ?? '') === 'text') {
                $font = !empty($item['bold']) ? 'F2' : 'F1';
                $size = number_format((float)($item['size'] ?? 9.5), 2, '.', '');
                $x = number_format((float)($item['x'] ?? 44), 2, '.', '');
                $yy = number_format((float)($item['y'] ?? 44), 2, '.', '');
                $color = $hexToRgb((string)($item['color'] ?? '24212B'));
                $stream .= "BT /{$font} {$size} Tf {$color} rg {$x} {$yy} Td (" . fortress_pdf_escape((string)($item['text'] ?? '')) . ") Tj ET\n";
            }
        }

        $objects[$contentObj] = "<< /Length " . strlen($stream) . " >>\nstream\n" . $stream . "endstream";
        $objects[$pageObj] = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ' . $contentObj . ' 0 R >>';
    }

    $objects[2] = '<< /Type /Pages /Count ' . count($pageRefs) . ' /Kids [' . implode(' ', $pageRefs) . '] >>';
    ksort($objects);

    $pdf = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
    $offsets = [0 => 0];
    $maxObject = max(array_keys($objects));
    for ($i = 1; $i <= $maxObject; $i++) {
        $offsets[$i] = strlen($pdf);
        $pdf .= $i . " 0 obj\n" . ($objects[$i] ?? '<<>>') . "\nendobj\n";
    }

    $xref = strlen($pdf);
    $pdf .= "xref\n0 " . ($maxObject + 1) . "\n";
    $pdf .= "0000000000 65535 f \n";
    for ($i = 1; $i <= $maxObject; $i++) $pdf .= sprintf("%010d 00000 n \n", $offsets[$i]);
    $pdf .= "trailer\n<< /Size " . ($maxObject + 1) . " /Root 1 0 R >>\nstartxref\n{$xref}\n%%EOF";
    return $pdf;
}

final class FortressZipBuilder
{
    private array $entries = [];

    public function add(string $name, string $data): void
    {
        $name = ltrim(str_replace('\\', '/', $name), '/');
        if ($name === '' || str_contains($name, '..')) {
            throw new InvalidArgumentException('Invalid archive entry name.');
        }
        $this->entries[$name] = $data;
    }

    public function build(): string
    {
        $local = '';
        $central = '';
        $offset = 0;
        $count = 0;
        [$dosTime, $dosDate] = $this->dosDateTime();

        foreach ($this->entries as $name => $data) {
            $compressed = gzdeflate($data, 9);
            $method = $compressed === false ? 0 : 8;
            if ($compressed === false) $compressed = $data;
            $crc = crc32($data);
            $nameLen = strlen($name);
            $compLen = strlen($compressed);
            $dataLen = strlen($data);

            $localHeader = pack('VvvvvvVVVvv', 0x04034b50, 20, 0, $method, $dosTime, $dosDate, $crc, $compLen, $dataLen, $nameLen, 0);
            $local .= $localHeader . $name . $compressed;

            $centralHeader = pack('VvvvvvvVVVvvvvvVV', 0x02014b50, 20, 20, 0, $method, $dosTime, $dosDate, $crc, $compLen, $dataLen, $nameLen, 0, 0, 0, 0, 0, $offset);
            $central .= $centralHeader . $name;
            $offset += strlen($localHeader) + $nameLen + $compLen;
            $count++;
        }

        $end = pack('VvvvvVVv', 0x06054b50, 0, 0, $count, $count, strlen($central), strlen($local), 0);
        return $local . $central . $end;
    }

    private function dosDateTime(): array
    {
        $year = max(1980, (int)date('Y'));
        $time = ((int)date('H') << 11) | ((int)date('i') << 5) | intdiv((int)date('s'), 2);
        $date = (($year - 1980) << 9) | ((int)date('n') << 5) | (int)date('j');
        return [$time, $date];
    }
}

function fortress_xlsx_column_name(int $index): string
{
    $name = '';
    while ($index > 0) {
        $index--;
        $name = chr(65 + ($index % 26)) . $name;
        $index = intdiv($index, 26);
    }
    return $name;
}

function fortress_xlsx_sheet_xml(array $rows, array $widths = [], array $options = []): string
{
    $maxCols = 1;
    foreach ($rows as $row) $maxCols = max($maxCols, count($row['cells'] ?? []));

    $cols = '';
    for ($i = 1; $i <= $maxCols; $i++) {
        $width = (float)($widths[$i - 1] ?? ($i === 1 ? 24 : 18));
        $cols .= '<col min="' . $i . '" max="' . $i . '" width="' . $width . '" customWidth="1"/>';
    }

    $sheetRows = '';
    $rowNum = 1;
    foreach ($rows as $row) {
        $cells = '';
        $style = (int)($row['style'] ?? 0);
        foreach (($row['cells'] ?? []) as $colIndex => $value) {
            $ref = fortress_xlsx_column_name($colIndex + 1) . $rowNum;
            $cellStyle = isset($row['cell_styles'][$colIndex]) ? (int)$row['cell_styles'][$colIndex] : $style;
            $xmlValue = fortress_report_xml((string)$value);
            $cells .= '<c r="' . $ref . '" t="inlineStr" s="' . $cellStyle . '"><is><t xml:space="preserve">' . $xmlValue . '</t></is></c>';
        }
        $height = isset($row['height']) ? ' ht="' . (float)$row['height'] . '" customHeight="1"' : '';
        $sheetRows .= '<row r="' . $rowNum . '"' . $height . '>' . $cells . '</row>';
        $rowNum++;
    }

    $lastRow = max(1, $rowNum - 1);
    $lastCell = fortress_xlsx_column_name($maxCols) . $lastRow;
    $freezeRow = max(1, min($lastRow, (int)($options['freeze_row'] ?? 1)));
    $topLeft = 'A' . ($freezeRow + 1);
    $tabColor = strtoupper((string)($options['tab_color'] ?? '7C3AED'));
    if (!preg_match('/^[0-9A-F]{6}$/', $tabColor)) $tabColor = '7C3AED';

    $mergeXml = '';
    $mergeRanges = is_array($options['merge_ranges'] ?? null) ? $options['merge_ranges'] : [];
    if ($mergeRanges) {
        $mergeXml = '<mergeCells count="' . count($mergeRanges) . '">';
        foreach ($mergeRanges as $range) {
            $mergeXml .= '<mergeCell ref="' . fortress_report_xml((string)$range) . '"/>';
        }
        $mergeXml .= '</mergeCells>';
    }

    $autoFilterXml = '';
    $filterRow = (int)($options['auto_filter_row'] ?? 0);
    if ($filterRow > 0 && $filterRow <= $lastRow) {
        $autoFilterXml = '<autoFilter ref="A' . $filterRow . ':' . fortress_xlsx_column_name($maxCols) . $lastRow . '"/>';
    }

    $printTitleXml = '';
    if (!empty($options['print_title_rows'])) {
        $printTitleXml = '<printOptions horizontalCentered="0" verticalCentered="0"/>';
    }

    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        . '<sheetPr><tabColor rgb="FF' . $tabColor . '"/><pageSetUpPr fitToPage="1"/></sheetPr>'
        . '<dimension ref="A1:' . $lastCell . '"/>'
        . '<sheetViews><sheetView workbookViewId="0" showGridLines="0" zoomScale="95" zoomScaleNormal="95"><pane ySplit="' . $freezeRow . '" topLeftCell="' . $topLeft . '" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A' . ($freezeRow + 1) . '" sqref="A' . ($freezeRow + 1) . '"/></sheetView></sheetViews>'
        . '<sheetFormatPr defaultRowHeight="18"/>'
        . '<cols>' . $cols . '</cols><sheetData>' . $sheetRows . '</sheetData>'
        . $mergeXml . $autoFilterXml . $printTitleXml
        . '<pageMargins left="0.35" right="0.35" top="0.55" bottom="0.55" header="0.2" footer="0.2"/>'
        . '<pageSetup orientation="landscape" fitToWidth="1" fitToHeight="0" paperSize="9"/>'
        . '</worksheet>';
}

function fortress_report_xlsx(array $report): string
{
    $sheets = [];
    $meta = $report['meta'];
    $reportId = (string)($meta['report_id'] ?? 'Not assigned');
    $scopeLabel = (string)($meta['scope_label'] ?? 'Documentation');

    $summaryRows = [
        ['style' => 2, 'height' => 34, 'cells' => [$meta['title'], '']],
        ['style' => 3, 'height' => 25, 'cells' => ['FORTRESSAUTH PREMIUM SECURITY DOCUMENTATION', $scopeLabel]],
        ['style' => 5, 'cells' => ['Report ID', $reportId]],
        ['style' => 5, 'cells' => ['Generated at', (string)$meta['generated_at']]],
        ['style' => 5, 'cells' => ['Generated by', (string)$meta['generated_by']]],
        ['style' => 5, 'cells' => ['Evidence window', (string)($meta['evidence_window'] ?? '')]],
        ['style' => 8, 'height' => 42, 'cells' => ['Safe export boundary', (string)$meta['notice']]],
        ['style' => 5, 'cells' => ['', '']],
        ['style' => 10, 'height' => 24, 'cells' => ['EXECUTIVE SECURITY SNAPSHOT', 'CURRENT VALUE']],
    ];
    foreach ($report['summary'] as $index => $item) {
        $summaryRows[] = ['style' => $index % 2 === 0 ? 6 : 7, 'height' => 22, 'cells' => [$item[0], $item[1]]];
    }
    $sheets[] = [
        'name' => 'Executive Summary',
        'rows' => $summaryRows,
        'widths' => [38, 78],
        'options' => ['freeze_row' => 9, 'merge_ranges' => ['A1:B1'], 'tab_color' => '7C3AED'],
    ];

    $metadataRows = [
        ['style' => 2, 'height' => 32, 'cells' => ['OFFICIAL REPORT METADATA', '']],
        ['style' => 3, 'height' => 24, 'cells' => ['FortressAuth export profile', $scopeLabel]],
        ['style' => 1, 'cells' => ['Official Report Detail', 'Value']],
        ['style' => 7, 'cells' => ['Report ID', $reportId]],
        ['style' => 0, 'cells' => ['Title', (string)$meta['title']]],
        ['style' => 7, 'cells' => ['Subtitle', (string)($meta['subtitle'] ?? '')]],
        ['style' => 0, 'cells' => ['Scope', $scopeLabel]],
        ['style' => 7, 'cells' => ['Generated at', (string)$meta['generated_at']]],
        ['style' => 0, 'cells' => ['Generated by', (string)$meta['generated_by']]],
        ['style' => 7, 'cells' => ['Classification', (string)$meta['classification']]],
        ['style' => 0, 'cells' => ['Evidence limit', (string)($meta['evidence_limit'] ?? '')]],
        ['style' => 7, 'cells' => ['Evidence window', (string)($meta['evidence_window'] ?? '')]],
        ['style' => 8, 'height' => 40, 'cells' => ['Safe export boundary', (string)$meta['notice']]],
    ];
    $sheets[] = [
        'name' => 'Report Metadata',
        'rows' => $metadataRows,
        'widths' => [34, 100],
        'options' => ['freeze_row' => 3, 'merge_ranges' => ['A1:B1'], 'auto_filter_row' => 3, 'tab_color' => '8B5CF6'],
    ];

    $addAssocSheet = static function (array &$sheets, string $name, array $data, array $headers, array $widths, string $kicker = 'FORTRESSAUTH DOCUMENTATION', string $tabColor = '7C3AED'): void {
        $cols = max(1, count($headers));
        $lastCol = fortress_xlsx_column_name($cols);
        $rows = [
            ['style' => 2, 'height' => 31, 'cells' => array_pad([strtoupper($name)], $cols, '')],
            ['style' => 4, 'height' => 22, 'cells' => array_pad([$kicker], $cols, '')],
            ['style' => 1, 'height' => 24, 'cells' => $headers],
        ];
        if (!$data) {
            $rows[] = ['style' => 8, 'height' => 30, 'cells' => array_pad(['No data available for this report snapshot.'], $cols, '')];
        } else {
            foreach ($data as $index => $row) {
                $rows[] = [
                    'style' => $index % 2 === 0 ? 0 : 7,
                    'height' => 22,
                    'cells' => array_map(static fn(string $key): string => (string)($row[$key] ?? ''), $headers),
                ];
            }
        }
        $sheets[] = [
            'name' => $name,
            'rows' => $rows,
            'widths' => $widths,
            'options' => [
                'freeze_row' => 3,
                'merge_ranges' => ['A1:' . $lastCol . '1', 'A2:' . $lastCol . '2'],
                'auto_filter_row' => 3,
                'tab_color' => $tabColor,
            ],
        ];
    };

    if (in_array($meta['scope'], ['full', 'security'], true)) {
        $aiLatestRows = [
            ['style' => 2, 'height' => 31, 'cells' => ['AI & MODEL LATEST FINDING', '']],
            ['style' => 4, 'height' => 22, 'cells' => ['HYBRID INTELLIGENT THREAT DETECTION', '']],
            ['style' => 1, 'height' => 24, 'cells' => ['AI / Model Metric', 'Current Value']],
        ];
        foreach (($report['ai']['latest'] ?? []) as $index => $row) {
            $aiLatestRows[] = ['style' => $index % 2 === 0 ? 6 : 7, 'height' => 22, 'cells' => [(string)($row[1] ?? 'Metric'), (string)($row[3] ?? 'Not recorded')]];
        }
        $sheets[] = ['name' => 'AI Latest Finding', 'rows' => $aiLatestRows, 'widths' => [40, 78], 'options' => ['freeze_row' => 3, 'merge_ranges' => ['A1:B1', 'A2:B2'], 'auto_filter_row' => 3, 'tab_color' => '6D28D9']];

        $analystRows = [
            ['style' => 2, 'height' => 31, 'cells' => ['FORTRESSAUTH AI ANALYST', '']],
            ['style' => 4, 'height' => 22, 'cells' => ['INTERPRETATION OF CURRENT FINDINGS', '']],
            ['style' => 1, 'height' => 24, 'cells' => ['No.', 'AI Analyst Interpretation']],
        ];
        foreach (($report['ai']['analyst_findings'] ?? []) as $index => $finding) {
            $analystRows[] = ['style' => $index === 0 ? 8 : ($index % 2 === 0 ? 0 : 7), 'height' => 34, 'cells' => [(string)($index + 1), (string)$finding]];
        }
        $sheets[] = ['name' => 'AI Analyst', 'rows' => $analystRows, 'widths' => [8, 118], 'options' => ['freeze_row' => 3, 'merge_ranges' => ['A1:B1', 'A2:B2'], 'auto_filter_row' => 3, 'tab_color' => '7C3AED']];

        $addAssocSheet($sheets, 'AI Probabilities', $report['ai']['probabilities'] ?? [], ['Behavior Class', 'Probability'], [34, 18], 'KNOWN-BEHAVIOR CLASSIFIER', '7C3AED');
        $addAssocSheet($sheets, 'AI Feature Window', $report['ai']['features'] ?? [], ['Feature', 'Value', 'Internal Key'], [38, 20, 34], 'NON-SENSITIVE BEHAVIORAL FEATURE WINDOW', '7C3AED');
        $addAssocSheet($sheets, 'AI Analysis History', $report['ai']['history'] ?? [], ['Time', 'Source IP', 'Classification', 'Confidence', 'Anomaly', 'Rule Signal', 'XGBoost Risk', 'Hybrid Risk', 'Severity', 'Enforcement Action', 'Indicators'], [22, 20, 24, 16, 16, 18, 18, 18, 16, 24, 70], 'RECENT MODEL ANALYSIS EVIDENCE', '6D28D9');
        $addAssocSheet($sheets, 'Model Validation', $report['ai']['model_validation'] ?? [], ['Field', 'Details'], [38, 106], 'MODEL EVALUATION & TRAINING METADATA', '6D28D9');
        $addAssocSheet($sheets, 'Feature Importance', $report['ai']['feature_importance'] ?? [], ['Rank', 'Feature', 'Importance'], [10, 42, 18], 'MODEL EXPLAINABILITY', '8B5CF6');
        $addAssocSheet($sheets, 'Class Metrics', $report['ai']['class_metrics'] ?? [], ['Behavior Class', 'Precision', 'Recall', 'F1 Score', 'Support'], [28, 16, 16, 16, 14], 'XGBOOST HOLDOUT VALIDATION', '8B5CF6');
        $addAssocSheet($sheets, 'Threat Findings', $report['threat_findings'] ?? [], ['Threat Signal', '24-Hour Count', 'Interpretation'], [42, 18, 88], 'RECORDED SECURITY SIGNALS', 'B83280');
        $addAssocSheet($sheets, 'Threat Sources', $report['top_sources'] ?? [], ['Source IP', 'Security Events / 24h', 'Note'], [24, 22, 92], 'NETWORK EVIDENCE', 'B83280');
    }

    if (in_array($meta['scope'], ['full', 'identity'], true)) {
        $addAssocSheet($sheets, 'Administrators', $report['administrators'] ?? [], ['Display Name', 'Username', 'Role', 'Account Status', 'Authentication Policy', 'Personal ID', 'Last Login', 'Updated'], [30, 20, 18, 18, 30, 24, 22, 22], 'ACCESS & IDENTITY DIRECTORY', '5B8C85');
        $addAssocSheet($sheets, 'Authentication Records', $report['authentication_events'] ?? [], ['Time', 'Category', 'Event', 'User', 'Source IP', 'Outcome', 'Description'], [22, 18, 38, 20, 20, 16, 88], 'AUTHENTICATION EVIDENCE', '5B8C85');
        $addAssocSheet($sheets, 'Personal ID Evidence', $report['identity_events'] ?? [], ['Time', 'Event', 'Source IP', 'Outcome', 'Description'], [22, 38, 20, 16, 88], 'POSSESSION-FACTOR EVIDENCE', '5B8C85');
        $addAssocSheet($sheets, 'Account Changes', $report['management_events'] ?? [], ['Time', 'Event', 'Actor/User', 'Source IP', 'Outcome', 'Description'], [22, 40, 20, 20, 16, 88], 'ADMINISTRATOR CHANGE HISTORY', '5B8C85');
    }

    if (in_array($meta['scope'], ['full', 'security'], true)) {
        $addAssocSheet($sheets, 'Defense Layers', $report['defenses'] ?? [], ['Defense Layer', 'State', 'Description', 'Weight'], [30, 20, 80, 16], 'SECURITY CONTROL STATUS', '7C3AED');
        $addAssocSheet($sheets, 'Security Events', $report['events'] ?? [], ['Time', 'Category', 'Event', 'Source IP', 'Outcome', 'Description'], [22, 18, 40, 20, 16, 90], 'AUDIT LOG SNAPSHOT', 'B83280');
    }

    $addAssocSheet($sheets, 'Evidence Sources', $report['provenance'] ?? [], ['Source', 'Purpose', 'Privacy Boundary'], [32, 90, 90], 'SOURCE GOVERNANCE & PRIVACY BOUNDARIES', '7C3AED');

    $conclusionRows = [
        ['style' => 2, 'height' => 31, 'cells' => ['CONCLUSION / SYSTEM ASSESSMENT', '']],
        ['style' => 4, 'height' => 22, 'cells' => ['FINAL ADMINISTRATIVE ASSESSMENT', '']],
        ['style' => 1, 'height' => 24, 'cells' => ['No.', 'System Assessment / Documentation Conclusion']],
    ];
    foreach (($report['conclusion'] ?? []) as $index => $item) {
        $conclusionRows[] = ['style' => $index === 0 ? 8 : ($index % 2 === 0 ? 0 : 7), 'height' => 34, 'cells' => [(string)($index + 1), (string)$item]];
    }
    $sheets[] = ['name' => 'Conclusion', 'rows' => $conclusionRows, 'widths' => [8, 118], 'options' => ['freeze_row' => 3, 'merge_ranges' => ['A1:B1', 'A2:B2'], 'auto_filter_row' => 3, 'tab_color' => '7C3AED']];

    $limitationRows = [
        ['style' => 2, 'height' => 31, 'cells' => ['LIMITATIONS AND ASSUMPTIONS', '']],
        ['style' => 4, 'height' => 22, 'cells' => ['INTERPRETATION BOUNDARIES', '']],
        ['style' => 1, 'height' => 24, 'cells' => ['No.', 'Limitation / Assumption']],
    ];
    foreach (($report['limitations'] ?? []) as $index => $item) {
        $limitationRows[] = ['style' => 9, 'height' => 34, 'cells' => [(string)($index + 1), (string)$item]];
    }
    $sheets[] = ['name' => 'Limitations', 'rows' => $limitationRows, 'widths' => [8, 118], 'options' => ['freeze_row' => 3, 'merge_ranges' => ['A1:B1', 'A2:B2'], 'auto_filter_row' => 3, 'tab_color' => 'B83280']];

    $zip = new FortressZipBuilder();
    $sheetOverrides = '';
    $workbookSheets = '';
    $workbookRels = '';

    foreach ($sheets as $index => $sheet) {
        $n = $index + 1;
        $zip->add('xl/worksheets/sheet' . $n . '.xml', fortress_xlsx_sheet_xml($sheet['rows'], $sheet['widths'], $sheet['options'] ?? []));
        $sheetOverrides .= '<Override PartName="/xl/worksheets/sheet' . $n . '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>';
        $workbookSheets .= '<sheet name="' . fortress_report_xml(substr($sheet['name'], 0, 31)) . '" sheetId="' . $n . '" r:id="rId' . $n . '"/>';
        $workbookRels .= '<Relationship Id="rId' . $n . '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' . $n . '.xml"/>';
    }
    $styleRid = count($sheets) + 1;
    $workbookRels .= '<Relationship Id="rId' . $styleRid . '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>';

    $zip->add('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' . $sheetOverrides . '</Types>');
    $zip->add('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>');
    $zip->add('xl/workbook.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' . $workbookSheets . '</sheets></workbook>');
    $zip->add('xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' . $workbookRels . '</Relationships>');
    $zip->add('xl/styles.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="7"><font><sz val="10"/><color rgb="FF30283A"/><name val="Aptos"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Aptos"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="18"/><name val="Aptos Display"/></font><font><b/><color rgb="FF2B123A"/><sz val="11"/><name val="Aptos"/></font><font><b/><color rgb="FF6D28D9"/><sz val="10"/><name val="Aptos"/></font><font><color rgb="FF655A70"/><sz val="9"/><name val="Aptos"/></font><font><b/><color rgb="FF7A244A"/><sz val="10"/><name val="Aptos"/></font></fonts><fills count="9"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF16091F"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF7C3AED"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFF3E8FF"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFBF8FD"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFF7E8"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFF2F6"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFFFFF"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="3"><border/><border><left style="thin"><color rgb="FFE6D8F3"/></left><right style="thin"><color rgb="FFE6D8F3"/></right><top style="thin"><color rgb="FFE6D8F3"/></top><bottom style="thin"><color rgb="FFE6D8F3"/></bottom></border><border><bottom style="medium"><color rgb="FF7C3AED"/></bottom></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="11"><xf numFmtId="0" fontId="0" fillId="8" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="1" fillId="3" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="2" fillId="2" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="4" fillId="4" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="5" fillId="5" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="3" fillId="8" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="5" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="3" fillId="6" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="6" fillId="7" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="3" fillId="8" borderId="2" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>');

    $created = gmdate('Y-m-d\TH:i:s\Z');
    $zip->add('docProps/core.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>' . fortress_report_xml($meta['title']) . '</dc:title><dc:creator>FortressAuth</dc:creator><cp:lastModifiedBy>FortressAuth</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">' . $created . '</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">' . $created . '</dcterms:modified></cp:coreProperties>');
    $zip->add('docProps/app.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>FortressAuth</Application><DocSecurity>0</DocSecurity><ScaleCrop>false</ScaleCrop><Company>FortressAuth</Company><AppVersion>1.0</AppVersion></Properties>');
    return $zip->build();
}

function fortress_ppt_shape(int $id, string $name, int $x, int $y, int $cx, int $cy, string $text = '', int $fontSize = 2000, string $color = 'F4EAFF', bool $bold = false, ?string $fill = null, ?string $line = null, string $font = 'Aptos', string $anchor = 't'): string
{
    $fillXml = $fill ? '<a:solidFill><a:srgbClr val="' . $fill . '"/></a:solidFill>' : '<a:noFill/>';
    $lineXml = $line ? '<a:ln w="12700"><a:solidFill><a:srgbClr val="' . $line . '"/></a:solidFill></a:ln>' : '<a:ln><a:noFill/></a:ln>';
    $paragraphs = '';
    $lines = $text === '' ? [''] : explode("\n", $text);
    foreach ($lines as $lineText) {
        $paragraphs .= '<a:p><a:r><a:rPr lang="en-US" sz="' . $fontSize . '" b="' . ($bold ? '1' : '0') . '" dirty="0"><a:solidFill><a:srgbClr val="' . $color . '"/></a:solidFill><a:latin typeface="' . fortress_report_xml($font) . '"/></a:rPr><a:t>' . fortress_report_xml($lineText) . '</a:t></a:r><a:endParaRPr lang="en-US" sz="' . $fontSize . '"/></a:p>';
    }
    return '<p:sp><p:nvSpPr><p:cNvPr id="' . $id . '" name="' . fortress_report_xml($name) . '"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="' . $x . '" y="' . $y . '"/><a:ext cx="' . $cx . '" cy="' . $cy . '"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom>' . $fillXml . $lineXml . '</p:spPr><p:txBody><a:bodyPr wrap="square" lIns="127000" rIns="127000" tIns="80000" bIns="80000" anchor="' . $anchor . '"/><a:lstStyle/>' . $paragraphs . '</p:txBody></p:sp>';
}

function fortress_ppt_cover_slide_xml(array $report, int $pageNo, int $totalPages): string
{
    $meta = is_array($report['meta'] ?? null) ? $report['meta'] : [];
    $summary = is_array($report['summary'] ?? null) ? $report['summary'] : [];
    $reportId = (string)($meta['report_id'] ?? 'Not assigned');
    $generatedAt = (string)($meta['generated_at'] ?? date('Y-m-d H:i:s'));

    $metricCards = [
        ['Protection score', fortress_report_summary_value($summary, 'Protection score')],
        ['Threat level', fortress_report_summary_value($summary, 'Threat level')],
        ['Defense layers', fortress_report_summary_value($summary, 'Defense layers')],
        ['Latest hybrid risk', fortress_report_summary_value($summary, 'Latest hybrid risk')],
    ];

    $shapes = '';
    $id = 2;
    $shapes .= fortress_ppt_shape($id++, 'Background', 0, 0, 12192000, 6858000, '', 1000, 'FFFFFF', false, '120718');
    $shapes .= fortress_ppt_shape($id++, 'Right panel', 8570000, 0, 3622000, 6858000, '', 1000, 'FFFFFF', false, 'F5EDFB');
    $shapes .= fortress_ppt_shape($id++, 'Accent bar', 0, 0, 12192000, 220000, '', 1000, 'FFFFFF', false, '7C3AED');
    $shapes .= fortress_ppt_shape($id++, 'Kicker', 640000, 420000, 3400000, 360000, 'FORTRESSAUTH PREMIUM REPORT', 1200, 'D6BCFA', true);
    $shapes .= fortress_ppt_shape($id++, 'Title', 640000, 980000, 7200000, 980000, (string)($meta['title'] ?? 'FortressAuth Security Findings & Documentation Report'), 2800, 'FFFFFF', true, null, null, 'Aptos Display');
    $shapes .= fortress_ppt_shape($id++, 'Subtitle', 640000, 1980000, 6800000, 720000, (string)($meta['subtitle'] ?? ''), 1480, 'EEE6F8', false);
    $shapes .= fortress_ppt_shape($id++, 'Scope card', 640000, 2780000, 2500000, 460000, (string)($meta['scope_label'] ?? 'Documentation'), 1600, '5B21B6', true, 'F5EEFF', 'E7DAF6');
    $shapes .= fortress_ppt_shape($id++, 'Meta', 640000, 3340000, 5200000, 820000, 'Report ID: ' . $reportId . "\nGenerated: " . $generatedAt . "\nPrepared by: " . (string)($meta['generated_by'] ?? 'FortressAuth'), 1100, 'D8D0E2', false);
    $shapes .= fortress_ppt_shape($id++, 'Notice card', 640000, 4320000, 5800000, 900000, (string)($meta['notice'] ?? ''), 1020, '41384A', false, 'F8F3FC', 'E7DAF6');
    $shapes .= fortress_ppt_shape($id++, 'Package title', 8880000, 660000, 2600000, 360000, 'PACKAGE SNAPSHOT', 1200, '5B21B6', true);

    $positions = [
        [8850000, 1180000], [10365000, 1180000], [8850000, 2260000], [10365000, 2260000],
    ];
    foreach ($metricCards as $index => $card) {
        [$x, $y] = $positions[$index];
        $shapes .= fortress_ppt_shape($id++, 'Metric card ' . $index, $x, $y, 1350000, 860000, $card[0] . "\n" . $card[1], 1180, '281538', true, $index % 2 === 0 ? 'FFFFFF' : 'F5EEFF', 'E7DAF6');
    }

    $packageText = "Included in this documentation package:\n• Executive security summary\n• AI findings and model validation\n• Authentication and Personal ID evidence\n• Security logs, defenses and conclusions";
    $shapes .= fortress_ppt_shape($id++, 'Package body', 8850000, 3460000, 2500000, 1600000, $packageText, 1020, '43384A', false, 'FFFFFF', 'E7DAF6');
    $shapes .= fortress_ppt_shape($id++, 'Footer left', 640000, 6310000, 4500000, 240000, 'FortressAuth • Administrative security documentation', 900, 'A696B9', false);
    $shapes .= fortress_ppt_shape($id++, 'Footer right', 9530000, 6310000, 1600000, 240000, 'Slide ' . $pageNo . ' of ' . $totalPages, 900, '7E6C95', false);

    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="120718"/></a:solidFill><a:effectLst/></p:bgPr></p:bg><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>' . $shapes . '</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>';
}

function fortress_ppt_slide_xml(string $title, array $lines, string $kicker = 'FORTRESSAUTH SECURITY DOCUMENTATION', array $meta = []): string
{
    $pageNo = (int)($meta['page_no'] ?? 1);
    $totalPages = (int)($meta['total_pages'] ?? 1);
    $reportId = (string)($meta['report_id'] ?? 'Not assigned');
    $scopeLabel = (string)($meta['scope_label'] ?? 'Documentation');

    $shapes = '';
    $id = 2;
    $shapes .= fortress_ppt_shape($id++, 'Background', 0, 0, 12192000, 6858000, '', 1000, 'FFFFFF', false, 'FBF8FD');
    $shapes .= fortress_ppt_shape($id++, 'Sidebar', 0, 0, 1850000, 6858000, '', 1000, 'FFFFFF', false, '16091F');
    $shapes .= fortress_ppt_shape($id++, 'Top accent', 0, 0, 12192000, 200000, '', 1000, 'FFFFFF', false, '7C3AED');
    $shapes .= fortress_ppt_shape($id++, 'Sidebar brand', 380000, 430000, 1050000, 420000, 'FORTRESSAUTH', 1350, 'D6BCFA', true);
    $shapes .= fortress_ppt_shape($id++, 'Sidebar label', 380000, 1020000, 1050000, 780000, 'PREMIUM\nSECURITY\nREPORT', 1450, 'FFFFFF', true, null, null, 'Aptos Display');
    $shapes .= fortress_ppt_shape($id++, 'Sidebar info', 300000, 5600000, 1250000, 620000, $scopeLabel . "\nReport ID " . $reportId, 950, 'B8ABC9', false);
    $shapes .= fortress_ppt_shape($id++, 'Main card', 2140000, 1180000, 9650000, 4700000, '', 1000, 'FFFFFF', false, 'FFFFFF', 'E7DAF6');
    $shapes .= fortress_ppt_shape($id++, 'Kicker card', 2400000, 410000, 3500000, 340000, $kicker, 1100, '5B21B6', true, 'F5EEFF', 'E7DAF6');
    $shapes .= fortress_ppt_shape($id++, 'Title', 2400000, 820000, 9000000, 520000, $title, 2450, '261534', true, null, null, 'Aptos Display');
    $shapes .= fortress_ppt_shape($id++, 'Footer left', 2380000, 6260000, 4400000, 220000, 'Generated by FortressAuth • Administrative documentation', 860, '7C708C', false);
    $shapes .= fortress_ppt_shape($id++, 'Footer right', 9980000, 6260000, 1300000, 220000, 'Slide ' . $pageNo . ' of ' . $totalPages, 860, '7C708C', false);

    $y = 1520000;
    foreach ($lines as $line) {
        if ($y > 5440000) break;
        $text = (string)($line['text'] ?? '');
        $size = (int)($line['size'] ?? 1500);
        $bold = !empty($line['bold']);
        $color = (string)($line['color'] ?? ($bold ? '3B1558' : '43384A'));
        $height = (int)($line['height'] ?? 360000);
        $fill = $line['fill'] ?? null;
        $boxH = max($height, $fill ? 350000 : 260000);
        if ($fill) {
            $shapes .= fortress_ppt_shape($id++, 'Line card ' . $id, 2440000, $y, 9020000, $boxH, $text, $size, $color, $bold, (string)$fill, 'EDE2F8');
        } else {
            $shapes .= fortress_ppt_shape($id++, 'Line text ' . $id, 2460000, $y, 8960000, $boxH, $text, $size, $color, $bold);
        }
        $y += $boxH + 60000;
    }

    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="FBF8FD"/></a:solidFill><a:effectLst/></p:bgPr></p:bg><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>' . $shapes . '</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>';
}

function fortress_report_pptx(array $report): string
{
    $meta = is_array($report['meta'] ?? null) ? $report['meta'] : [];
    $slideSpecs = [];
    $slideSpecs[] = ['type' => 'cover'];

    $summaryLines = [];
    foreach (array_slice($report['summary'] ?? [], 0, 14) as $item) {
        $summaryLines[] = ['text' => $item[0] . ': ' . $item[1], 'size' => 1260, 'bold' => true, 'height' => 290000, 'fill' => 'FFFFFF'];
    }
    $slideSpecs[] = ['type' => 'content', 'title' => 'Executive Security Overview', 'kicker' => 'CURRENT SYSTEM POSTURE', 'lines' => $summaryLines];

    if (in_array((string)($meta['scope'] ?? 'full'), ['full', 'security'], true)) {
        $aiLatestLines = [];
        foreach (($report['ai']['latest'] ?? []) as $row) {
            $aiLatestLines[] = ['text' => (string)($row[1] ?? 'Metric') . ': ' . (string)($row[3] ?? 'Not recorded'), 'size' => 1320, 'bold' => true, 'height' => 295000, 'fill' => 'F7F1FF'];
        }
        $slideSpecs[] = ['type' => 'content', 'title' => 'AI & Model Findings', 'kicker' => 'HYBRID INTELLIGENT THREAT DETECTION', 'lines' => array_slice($aiLatestLines, 0, 12)];

        $analystChunks = array_chunk($report['ai']['analyst_findings'] ?? [], 5);
        if (!$analystChunks) $analystChunks = [[]];
        foreach ($analystChunks as $index => $chunk) {
            $lines = [];
            if (!$chunk) {
                $lines[] = ['text' => 'No AI analyst interpretation is available for the current snapshot.', 'size' => 1380, 'height' => 500000, 'fill' => 'FFFFFF'];
            } else {
                foreach ($chunk as $i => $finding) {
                    $lines[] = ['text' => ($i + 1 + ($index * 5)) . '. ' . (string)$finding, 'size' => 1120, 'height' => 570000, 'fill' => $i === 0 ? 'F5EEFF' : 'FFFFFF'];
                }
            }
            $slideSpecs[] = ['type' => 'content', 'title' => 'FortressAuth AI Analyst' . (count($analystChunks) > 1 ? ' (' . ($index + 1) . '/' . count($analystChunks) . ')' : ''), 'kicker' => 'INTERPRETATION OF CURRENT FINDINGS', 'lines' => $lines];
        }

        $probabilityLines = [];
        foreach (($report['ai']['probabilities'] ?? []) as $row) {
            $probabilityLines[] = ['text' => $row['Behavior Class'] . ': ' . $row['Probability'], 'size' => 1420, 'bold' => true, 'height' => 330000, 'fill' => 'FFFFFF'];
        }
        if (!$probabilityLines) $probabilityLines[] = ['text' => 'No XGBoost class probabilities are available yet.', 'size' => 1380, 'height' => 480000, 'fill' => 'FFFFFF'];
        $probabilityLines[] = ['text' => 'Model confidence describes confidence in the selected behavior class. It is not a probability that a person is an attacker.', 'size' => 1040, 'color' => '6A5D72', 'height' => 620000, 'fill' => 'FFF7E8'];
        $slideSpecs[] = ['type' => 'content', 'title' => 'XGBoost Behavior Classification', 'kicker' => 'KNOWN-BEHAVIOR CLASSIFIER', 'lines' => $probabilityLines];

        $modelLines = [];
        foreach (($report['ai']['model_validation'] ?? []) as $row) {
            $modelLines[] = ['text' => $row['Field'] . ': ' . $row['Details'], 'size' => 1020, 'height' => 390000, 'fill' => 'FFFFFF'];
        }
        foreach (array_chunk($modelLines, 9) as $index => $chunk) {
            $slideSpecs[] = ['type' => 'content', 'title' => 'Model Validation & Training Metadata' . (count(array_chunk($modelLines, 9)) > 1 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'MODEL EVALUATION', 'lines' => $chunk];
        }

        $importanceLines = [];
        foreach (array_slice($report['ai']['feature_importance'] ?? [], 0, 10) as $row) {
            $importanceLines[] = ['text' => '#' . $row['Rank'] . '  ' . $row['Feature'] . '  -  ' . $row['Importance'], 'size' => 1200, 'bold' => true, 'height' => 320000, 'fill' => 'F7F1FF'];
        }
        if ($importanceLines) $slideSpecs[] = ['type' => 'content', 'title' => 'Top XGBoost Feature Importance', 'kicker' => 'MODEL EXPLAINABILITY', 'lines' => $importanceLines];

        $classMetricLines = [];
        foreach (($report['ai']['class_metrics'] ?? []) as $row) {
            $classMetricLines[] = ['text' => $row['Behavior Class'] . ' | Precision ' . $row['Precision'] . ' | Recall ' . $row['Recall'] . ' | F1 ' . $row['F1 Score'] . ' | Support ' . $row['Support'], 'size' => 1060, 'bold' => true, 'height' => 405000, 'fill' => 'FFFFFF'];
        }
        if ($classMetricLines) $slideSpecs[] = ['type' => 'content', 'title' => 'Class-Level Holdout Metrics', 'kicker' => 'XGBOOST VALIDATION', 'lines' => $classMetricLines];

        $threatLines = [];
        foreach (($report['threat_findings'] ?? []) as $row) {
            $threatLines[] = ['text' => $row['Threat Signal'] . ': ' . $row['24-Hour Count'], 'size' => 1240, 'bold' => true, 'color' => '7A244A', 'height' => 280000, 'fill' => 'FFF2F6'];
            $threatLines[] = ['text' => $row['Interpretation'], 'size' => 980, 'height' => 330000, 'fill' => 'FFFFFF'];
        }
        foreach (array_chunk($threatLines, 10) as $index => $chunk) {
            $slideSpecs[] = ['type' => 'content', 'title' => 'Threat Findings - Last 24 Hours' . ($index > 0 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'RECORDED SECURITY SIGNALS', 'lines' => $chunk];
        }

        if (!empty($report['top_sources'])) {
            $sourceLines = [];
            foreach ($report['top_sources'] as $row) {
                $sourceLines[] = ['text' => $row['Source IP'] . '  |  ' . $row['Security Events / 24h'] . ' reportable event(s)', 'size' => 1260, 'bold' => true, 'height' => 320000, 'fill' => 'FFF7E8'];
            }
            $sourceLines[] = ['text' => 'Source IP evidence identifies the network source recorded by FortressAuth and does not by itself establish a person\'s identity or intent.', 'size' => 1040, 'height' => 560000, 'fill' => 'FFFFFF'];
            $slideSpecs[] = ['type' => 'content', 'title' => 'Top Security-Event Sources', 'kicker' => 'NETWORK EVIDENCE', 'lines' => $sourceLines];
        }

        foreach (array_chunk(array_slice($report['ai']['history'] ?? [], 0, 15), 5) as $index => $chunk) {
            $lines = [];
            foreach ($chunk as $row) {
                $lines[] = ['text' => $row['Time'] . ' | ' . $row['Classification'] . ' | Risk ' . $row['Hybrid Risk'] . ' | ' . $row['Severity'], 'size' => 1080, 'bold' => true, 'color' => '5F249F', 'height' => 290000, 'fill' => 'FFFFFF'];
                $detail = 'Source ' . $row['Source IP'] . ' | Confidence ' . $row['Confidence'] . ' | Anomaly ' . $row['Anomaly'];
                if (!empty($row['Indicators'])) $detail .= ' | ' . $row['Indicators'];
                $lines[] = ['text' => $detail, 'size' => 960, 'height' => 420000, 'fill' => 'F7F1FF'];
            }
            if ($lines) $slideSpecs[] = ['type' => 'content', 'title' => 'Recent AI Analyses' . (count(array_chunk(array_slice($report['ai']['history'] ?? [], 0, 15), 5)) > 1 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'RECENT ANALYSIS HISTORY', 'lines' => $lines];
        }
    }

    if (in_array((string)($meta['scope'] ?? 'full'), ['full', 'identity'], true)) {
        foreach (array_chunk($report['administrators'] ?? [], 4) ?: [[]] as $index => $chunk) {
            $lines = [];
            if (!$chunk) {
                $lines[] = ['text' => 'No administrator records are available.', 'size' => 1380, 'height' => 480000, 'fill' => 'FFFFFF'];
            } else {
                foreach ($chunk as $row) {
                    $lines[] = ['text' => $row['Display Name'] . ' (' . $row['Username'] . ')', 'size' => 1240, 'bold' => true, 'height' => 280000, 'fill' => 'F5EEFF'];
                    $lines[] = ['text' => 'Role: ' . $row['Role'] . ' | Status: ' . $row['Account Status'] . ' | Policy: ' . $row['Authentication Policy'] . ' | Personal ID: ' . $row['Personal ID'], 'size' => 980, 'height' => 320000, 'fill' => 'FFFFFF'];
                    $lines[] = ['text' => 'Last login: ' . $row['Last Login'] . ' | Updated: ' . $row['Updated'], 'size' => 950, 'height' => 320000, 'fill' => 'FFFFFF'];
                }
            }
            $slideSpecs[] = ['type' => 'content', 'title' => 'Administrator Access Directory' . ($index > 0 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'ACCESS & IDENTITY', 'lines' => $lines];
        }

        foreach (array_chunk($report['authentication_events'] ?? [], 4) ?: [[]] as $index => $chunk) {
            $lines = [];
            if (!$chunk) {
                $lines[] = ['text' => 'No recent authentication evidence is available.', 'size' => 1380, 'height' => 480000, 'fill' => 'FFFFFF'];
            } else {
                foreach ($chunk as $row) {
                    $lines[] = ['text' => $row['Time'] . ' | ' . $row['Outcome'] . ' | ' . $row['Event'] . ' | User ' . $row['User'], 'size' => 1040, 'bold' => true, 'height' => 360000, 'fill' => 'FFFFFF'];
                    $lines[] = ['text' => $row['Source IP'] . ' | ' . $row['Description'], 'size' => 940, 'height' => 420000, 'fill' => 'F7F1FF'];
                }
            }
            $slideSpecs[] = ['type' => 'content', 'title' => 'Authentication Records' . ($index > 0 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'AUTHENTICATION EVIDENCE', 'lines' => $lines];
        }

        foreach (array_chunk($report['identity_events'] ?? [], 4) as $index => $chunk) {
            $lines = [];
            foreach ($chunk as $row) {
                $lines[] = ['text' => $row['Time'] . ' | ' . $row['Outcome'] . ' | ' . $row['Event'], 'size' => 1040, 'bold' => true, 'height' => 340000, 'fill' => 'FFF7E8'];
                $lines[] = ['text' => $row['Source IP'] . ' | ' . $row['Description'], 'size' => 940, 'height' => 400000, 'fill' => 'FFFFFF'];
            }
            if ($lines) $slideSpecs[] = ['type' => 'content', 'title' => 'Personal ID Security Evidence' . ($index > 0 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'POSSESSION-FACTOR EVIDENCE', 'lines' => $lines];
        }

        foreach (array_chunk($report['management_events'] ?? [], 4) as $index => $chunk) {
            $lines = [];
            foreach ($chunk as $row) {
                $lines[] = ['text' => $row['Time'] . ' | ' . $row['Outcome'] . ' | ' . $row['Event'], 'size' => 1040, 'bold' => true, 'height' => 340000, 'fill' => 'F5EEFF'];
                $lines[] = ['text' => $row['Source IP'] . ' | ' . $row['Description'], 'size' => 940, 'height' => 400000, 'fill' => 'FFFFFF'];
            }
            if ($lines) $slideSpecs[] = ['type' => 'content', 'title' => 'Administrator Account Change Evidence' . ($index > 0 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'ACCOUNT CHANGE HISTORY', 'lines' => $lines];
        }
    }

    if (in_array((string)($meta['scope'] ?? 'full'), ['full', 'security'], true)) {
        foreach (array_chunk($report['defenses'] ?? [], 5) as $index => $chunk) {
            $lines = [];
            foreach ($chunk as $row) {
                $lines[] = ['text' => $row['Defense Layer'] . ' - ' . $row['State'] . ' (' . $row['Weight'] . ')', 'size' => 1080, 'bold' => true, 'height' => 330000, 'fill' => 'FFFFFF'];
                $lines[] = ['text' => $row['Description'], 'size' => 960, 'height' => 350000, 'fill' => 'F7F1FF'];
            }
            if ($lines) $slideSpecs[] = ['type' => 'content', 'title' => 'Defense Posture' . ($index > 0 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'SECURITY CONTROL STATUS', 'lines' => $lines];
        }

        foreach (array_chunk($report['events'] ?? [], 4) ?: [[]] as $index => $chunk) {
            $lines = [];
            if (!$chunk) {
                $lines[] = ['text' => 'No meaningful security events are available.', 'size' => 1380, 'height' => 480000, 'fill' => 'FFFFFF'];
            } else {
                foreach ($chunk as $row) {
                    $lines[] = ['text' => $row['Time'] . ' | ' . $row['Category'] . ' | ' . $row['Outcome'] . ' | ' . $row['Event'], 'size' => 990, 'bold' => true, 'height' => 360000, 'fill' => 'FFFFFF'];
                    $lines[] = ['text' => $row['Source IP'] . ' | ' . $row['Description'], 'size' => 930, 'height' => 410000, 'fill' => 'F7F1FF'];
                }
            }
            $slideSpecs[] = ['type' => 'content', 'title' => 'Recent Security Audit Evidence' . ($index > 0 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'AUDIT LOG SNAPSHOT', 'lines' => $lines];
        }
    }

    foreach (array_chunk($report['provenance'] ?? [], 4) as $index => $chunk) {
        $lines = [];
        foreach ($chunk as $row) {
            $lines[] = ['text' => $row['Source'] . ': ' . $row['Purpose'], 'size' => 1040, 'bold' => true, 'height' => 340000, 'fill' => 'FFFFFF'];
            $lines[] = ['text' => 'Privacy: ' . $row['Privacy Boundary'], 'size' => 930, 'height' => 390000, 'fill' => 'F7F1FF'];
        }
        if ($lines) $slideSpecs[] = ['type' => 'content', 'title' => 'Evidence Sources & Privacy Boundaries' . ($index > 0 ? ' (' . ($index + 1) . ')' : ''), 'kicker' => 'SOURCE GOVERNANCE', 'lines' => $lines];
    }

    $conclusionLines = [];
    foreach (($report['conclusion'] ?? []) as $index => $line) {
        $conclusionLines[] = ['text' => ($index + 1) . '. ' . (string)$line, 'size' => 1100, 'height' => 440000, 'fill' => $index === 0 ? 'F5EEFF' : 'FFFFFF'];
    }
    $slideSpecs[] = ['type' => 'content', 'title' => 'Conclusion / System Assessment', 'kicker' => 'FINAL ADMINISTRATIVE ASSESSMENT', 'lines' => $conclusionLines ?: [['text' => 'No conclusion is available for this report snapshot.', 'size' => 1380, 'height' => 480000, 'fill' => 'FFFFFF']]];

    $limitationLines = [];
    foreach (($report['limitations'] ?? []) as $index => $line) {
        $limitationLines[] = ['text' => ($index + 1) . '. ' . (string)$line, 'size' => 1020, 'height' => 390000, 'fill' => 'FFFFFF'];
    }
    $slideSpecs[] = ['type' => 'content', 'title' => 'Limitations and Assumptions', 'kicker' => 'INTERPRETATION BOUNDARIES', 'lines' => $limitationLines ?: [['text' => 'No limitations are available for this report snapshot.', 'size' => 1380, 'height' => 480000, 'fill' => 'FFFFFF']]];

    $slides = [];
    $totalPages = count($slideSpecs);
    foreach ($slideSpecs as $index => $spec) {
        if (($spec['type'] ?? '') === 'cover') {
            $slides[] = fortress_ppt_cover_slide_xml($report, $index + 1, $totalPages);
            continue;
        }
        $slides[] = fortress_ppt_slide_xml(
            (string)$spec['title'],
            is_array($spec['lines'] ?? null) ? $spec['lines'] : [],
            (string)($spec['kicker'] ?? 'FORTRESSAUTH SECURITY DOCUMENTATION'),
            [
                'page_no' => $index + 1,
                'total_pages' => $totalPages,
                'report_id' => (string)($meta['report_id'] ?? 'Not assigned'),
                'scope_label' => (string)($meta['scope_label'] ?? 'Documentation'),
            ]
        );
    }

    $zip = new FortressZipBuilder();
    $slideOverrides = '';
    $slideIds = '';
    $presentationRels = '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>';

    foreach ($slides as $index => $xml) {
        $n = $index + 1;
        $zip->add('ppt/slides/slide' . $n . '.xml', $xml);
        $zip->add('ppt/slides/_rels/slide' . $n . '.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/></Relationships>');
        $slideOverrides .= '<Override PartName="/ppt/slides/slide' . $n . '.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>';
        $rid = $n + 1;
        $slideIds .= '<p:sldId id="' . (255 + $n) . '" r:id="rId' . $rid . '"/>';
        $presentationRels .= '<Relationship Id="rId' . $rid . '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide' . $n . '.xml"/>';
    }

    $zip->add('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/><Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/><Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' . $slideOverrides . '</Types>');
    $zip->add('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>');
    $zip->add('ppt/presentation.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst>' . $slideIds . '</p:sldIdLst><p:sldSz cx="12192000" cy="6858000" type="screen16x9"/><p:notesSz cx="6858000" cy="9144000"/><p:defaultTextStyle><a:defPPr><a:defRPr lang="en-US"/></a:defPPr></p:defaultTextStyle></p:presentation>');
    $zip->add('ppt/_rels/presentation.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' . $presentationRels . '</Relationships>');
    $zip->add('ppt/slideMasters/slideMaster1.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld name="FortressAuth Master"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMap accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" bg1="lt1" bg2="lt2" folHlink="folHlink" hlink="hlink" tx1="dk1" tx2="dk2"/><p:sldLayoutIdLst><p:sldLayoutId id="1" r:id="rId1"/></p:sldLayoutIdLst><p:txStyles><p:titleStyle><a:lvl1pPr><a:defRPr sz="3200" b="1"/></a:lvl1pPr></p:titleStyle><p:bodyStyle><a:lvl1pPr><a:defRPr sz="1800"/></a:lvl1pPr></p:bodyStyle><p:otherStyle><a:defPPr><a:defRPr sz="1600"/></a:defPPr></p:otherStyle></p:txStyles></p:sldMaster>');
    $zip->add('ppt/slideMasters/_rels/slideMaster1.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/></Relationships>');
    $zip->add('ppt/slideLayouts/slideLayout1.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank" preserve="1"><p:cSld name="Blank"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>');
    $zip->add('ppt/slideLayouts/_rels/slideLayout1.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/></Relationships>');
    $zip->add('ppt/theme/theme1.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="FortressAuth"><a:themeElements><a:clrScheme name="FortressAuth"><a:dk1><a:srgbClr val="16091F"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="2B123A"/></a:dk2><a:lt2><a:srgbClr val="F5ECFA"/></a:lt2><a:accent1><a:srgbClr val="7F3FBF"/></a:accent1><a:accent2><a:srgbClr val="D497FF"/></a:accent2><a:accent3><a:srgbClr val="52E6A5"/></a:accent3><a:accent4><a:srgbClr val="5CC8FF"/></a:accent4><a:accent5><a:srgbClr val="FFB84D"/></a:accent5><a:accent6><a:srgbClr val="FF6B8A"/></a:accent6><a:hlink><a:srgbClr val="0563C1"/></a:hlink><a:folHlink><a:srgbClr val="954F72"/></a:folHlink></a:clrScheme><a:fontScheme name="FortressAuth"><a:majorFont><a:latin typeface="Aptos Display"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Aptos"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme><a:fmtScheme name="FortressAuth"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:gradFill rotWithShape="1"><a:gsLst><a:gs pos="0"><a:schemeClr val="phClr"><a:tint val="50000"/><a:satMod val="300000"/></a:schemeClr></a:gs><a:gs pos="100000"><a:schemeClr val="phClr"><a:shade val="100000"/><a:satMod val="200000"/></a:schemeClr></a:gs></a:gsLst><a:lin ang="16200000" scaled="1"/></a:gradFill><a:noFill/></a:fillStyleLst><a:lnStyleLst><a:ln w="9525" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/><a:miter lim="800000"/></a:ln><a:ln w="25400" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/><a:miter lim="800000"/></a:ln><a:ln w="38100" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/><a:miter lim="800000"/></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements></a:theme>');

    $created = gmdate('Y-m-d\TH:i:s\Z');
    $zip->add('docProps/core.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>' . fortress_report_xml((string)($meta['title'] ?? 'FortressAuth')) . '</dc:title><dc:creator>FortressAuth</dc:creator><cp:lastModifiedBy>FortressAuth</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">' . $created . '</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">' . $created . '</dcterms:modified></cp:coreProperties>');
    $zip->add('docProps/app.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>FortressAuth</Application><PresentationFormat>Widescreen</PresentationFormat><Slides>' . count($slides) . '</Slides><Company>FortressAuth</Company><AppVersion>1.0</AppVersion></Properties>');
    return $zip->build();
}

function fortress_render_documentation_report(array $report, string $format): array
{
    return match ($format) {
        'pdf' => [fortress_report_pdf($report), 'application/pdf', fortress_report_filename($report, 'pdf')],
        'xlsx' => [fortress_report_xlsx($report), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', fortress_report_filename($report, 'xlsx')],
        'pptx' => [fortress_report_pptx($report), 'application/vnd.openxmlformats-officedocument.presentationml.presentation', fortress_report_filename($report, 'pptx')],
        default => throw new InvalidArgumentException('Unsupported report format.'),
    };
}
