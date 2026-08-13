<?php

declare(strict_types=1);

// This endpoint is a low-cost revision check. It must never generate request
// telemetry, ML predictions, or audit entries of its own.
define('FORTRESS_BACKGROUND_REQUEST', true);
define('FORTRESS_LIVE_REFRESH_REQUEST', true);

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

function fortress_live_tail(string $path, int $maxBytes = 196608): string
{
    if (!is_file($path)) return '';

    $size = (int)filesize($path);
    if ($size <= 0) return '';

    $read = min($size, $maxBytes);
    $handle = @fopen($path, 'rb');
    if (!$handle) return '';

    if ($size > $read) {
        @fseek($handle, -$read, SEEK_END);
    }

    $data = (string)@fread($handle, $read);
    fclose($handle);

    // If reading from the middle of the file, drop the partial first line.
    if ($size > $read) {
        $newline = strpos($data, "\n");
        if ($newline !== false) {
            $data = substr($data, $newline + 1);
        }
    }

    return $data;
}

function fortress_live_file_token(string $path): string
{
    if (!is_file($path)) return 'missing';
    clearstatcache(true, $path);
    return implode(':', [
        (string)((int)@filemtime($path)),
        (string)((int)@filesize($path)),
    ]);
}

$dataDir = __DIR__ . '/../data';
$auditPath = $dataDir . '/audit.log';

// Only events that can materially change a visible security page are included.
// Page-open/view events are intentionally excluded.
$stateNeedles = [
    'ml_threat_prediction',
    'request_threat_detected',
    'malicious_input_detected',
    'shell_attack_detected',
    'csp_violation_reported',
    'scanner_user_agent_detected',
    'sensitive_path_probe',
    'reconnaissance_probe',
    'csrf_validation_failed',
    'http_method_blocked',
    'http_method_anomaly',
    'endpoint_method_rejected',
    'oversized_request_detected',
    'oversized_uri_detected',
    'banned_ip_middleware_block',
    'banned_ip_attempt',
    'bruteforce_detected',
    'ip_banned',
    'failed_attempts_cleared',
    'password_factor_success',
    'password_factor_failed',
    'login_success',
    'login_failed',
    'login_disabled_account',
    'school_id_qr_registered',
    'school_id_qr_reset',
    'school_id_qr_success',
    'school_id_qr_failed',
    'school_id_qr_locked',
    'school_id_qr_rate_limited',
    'school_id_reverification_started',
    'school_id_2fa_not_required',
    'auth_rejected',
    'honeypot_triggered',
    'logout',
    'dashboard_session_timeout',
    'user_2fa_enabled',
    'user_2fa_disabled',
    'user_2fa_replaced',
    'current_user_security_policy_changed',
    'user_account_created',
    'user_account_updated',
    'user_account_enabled',
    'user_account_disabled',
    'user_password_reset',
    'user_personal_id_reset',
    'user_account_deleted',
    'security_report_generated',
];

$meaningfulLines = [];
$tail = fortress_live_tail($auditPath);
if ($tail !== '') {
    foreach (preg_split('/\R/', $tail) ?: [] as $line) {
        $line = trim((string)$line);
        if ($line === '' || !fortress_line_has_any($line, $stateNeedles)) continue;
        $meaningfulLines[] = $line;
    }
}

// Keep the digest bounded even when the audit file is busy.
$meaningfulLines = array_slice($meaningfulLines, -80);

$revisionParts = [
    implode("\n", $meaningfulLines),
    'bans-file=' . fortress_live_file_token($dataDir . '/banned_ips.txt'),
    'honeypot=' . fortress_live_file_token($dataDir . '/honeypot_log.txt'),
    'ml-latest=' . fortress_live_file_token($dataDir . '/ml/latest_prediction.json'),
    'ml-history=' . fortress_live_file_token($dataDir . '/ml/predictions.jsonl'),
];

// Include active database bans because Blocked IPs and threat pressure can
// change when a ban expires even if no new audit line is written.
try {
    $banState = $pdo->query(
        "SELECT COUNT(*)::int AS active_count,
                COALESCE(MAX(EXTRACT(EPOCH FROM banned_until))::bigint, 0) AS latest_until
         FROM banned_ips
         WHERE banned_until > NOW()"
    )->fetch(PDO::FETCH_ASSOC) ?: [];
    $revisionParts[] = 'db-bans='
        . (string)($banState['active_count'] ?? 0)
        . ':'
        . (string)($banState['latest_until'] ?? 0);
} catch (Throwable $e) {
    $revisionParts[] = 'db-bans=unavailable';
}

$revision = substr(hash('sha256', implode('|', $revisionParts)), 0, 24);

echo json_encode([
    'success' => true,
    'revision' => $revision,
    'server_time' => time(),
], JSON_UNESCAPED_SLASHES);
