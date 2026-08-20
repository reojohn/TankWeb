<?php

declare(strict_types=1);

require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/sanitize.php';
require_once __DIR__ . '/user_accounts.php';

function fortress_read_lines(string $path): array
{
    if (!is_file($path)) {
        return [];
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return is_array($lines) ? $lines : [];
}

/**
 * Read only the tail of a newline-delimited log without loading the entire file.
 * This keeps local-development navigation fast even after audit.log grows large.
 */
function fortress_read_last_lines(string $path, int $limit = 600): array
{
    if ($limit <= 0 || !is_file($path)) {
        return [];
    }

    $handle = @fopen($path, 'rb');
    if (!$handle) {
        return [];
    }

    @fseek($handle, 0, SEEK_END);
    $position = (int)@ftell($handle);
    $buffer = '';
    $chunkSize = 65536;
    $newlineTarget = $limit + 1;

    while ($position > 0 && substr_count($buffer, "\n") < $newlineTarget) {
        $read = min($chunkSize, $position);
        $position -= $read;
        @fseek($handle, $position, SEEK_SET);
        $chunk = (string)@fread($handle, $read);
        if ($chunk === '') {
            break;
        }
        $buffer = $chunk . $buffer;
    }
    fclose($handle);

    $lines = preg_split('/\R/', $buffer) ?: [];
    $lines = array_values(array_filter(array_map('trim', $lines), static fn(string $line): bool => $line !== ''));
    return array_slice($lines, -$limit);
}

/**
 * Read recent audit evidence from durable PostgreSQL storage and merge it with
 * the recent local audit.log fallback. The previous implementation transferred
 * up to 10,000 raw log rows on every protected page request. Dashboard metrics
 * are now calculated with compact SQL aggregates, so ordinary navigation only
 * needs the recent evidence that is actually rendered in the UI.
 */
function fortress_read_persistent_audit_lines(PDO $pdo, string $fallbackPath, int $limit = 650): array
{
    $limit = max(100, min(10000, $limit));
    $fileLines = fortress_read_last_lines($fallbackPath, $limit);
    $databaseLines = [];

    try {
        $stmt = $pdo->prepare(
            "SELECT raw_line
             FROM public.security_events
             WHERE raw_line IS NOT NULL AND BTRIM(raw_line) <> ''
             ORDER BY occurred_at DESC, id DESC
             LIMIT :limit"
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);
        if (is_array($rows)) {
            foreach (array_reverse($rows) as $row) {
                $line = trim((string)$row);
                if ($line !== '') {
                    $databaseLines[] = $line;
                }
            }
        }
    } catch (Throwable $e) {
        // During rollout, local development, or a temporary DB outage, keep
        // the existing flat-file behavior instead of breaking dashboards.
        error_log('FortressAuth security_events recent read failed: ' . $e->getMessage());
    }

    if (!$databaseLines) {
        return $fileLines;
    }

    // Merge local-only and durable events without double-counting the logger's
    // intentional dual write. The merge remains small (normally <= 1,300 rows).
    $merged = [];
    $seen = [];
    foreach (array_merge($fileLines, $databaseLines) as $line) {
        $line = trim((string)$line);
        if ($line === '') continue;
        $fingerprint = hash('sha256', $line);
        if (isset($seen[$fingerprint])) continue;
        $seen[$fingerprint] = true;
        $merged[] = $line;
    }

    usort($merged, static function (string $a, string $b): int {
        $aDate = fortress_event_datetime($a);
        $bDate = fortress_event_datetime($b);
        if ($aDate && $bDate) {
            $cmp = $aDate->getTimestamp() <=> $bDate->getTimestamp();
            if ($cmp !== 0) return $cmp;
        } elseif ($aDate) {
            return -1;
        } elseif ($bDate) {
            return 1;
        }
        return strcmp($a, $b);
    });

    return array_slice($merged, -($limit * 2));
}

function fortress_event_datetime(string $line): ?DateTimeImmutable
{
    if (!preg_match('/^\[([^\]]+)\]/', $line, $matches)) {
        return null;
    }

    try {
        return new DateTimeImmutable($matches[1]);
    } catch (Throwable $e) {
        return null;
    }
}

function fortress_event_time(string $line, string $format = 'H:i:s'): string
{
    $dateTime = fortress_event_datetime($line);
    if (!$dateTime) {
        return 'Recent';
    }

    try {
        return $dateTime->setTimezone(new DateTimeZone(date_default_timezone_get()))->format($format);
    } catch (Throwable $e) {
        return 'Recent';
    }
}

function fortress_relative_time(?DateTimeImmutable $dateTime): string
{
    if (!$dateTime) {
        return 'No recent event';
    }

    $now = new DateTimeImmutable('now', $dateTime->getTimezone());
    $seconds = max(0, $now->getTimestamp() - $dateTime->getTimestamp());

    if ($seconds < 60) return 'Just now';
    $minutes = intdiv($seconds, 60);
    if ($minutes < 60) return $minutes . ' min' . ($minutes === 1 ? '' : 's') . ' ago';
    $hours = intdiv($minutes, 60);
    if ($hours < 24) return $hours . ' hr' . ($hours === 1 ? '' : 's') . ' ago';
    $days = intdiv($hours, 24);
    return $days . ' day' . ($days === 1 ? '' : 's') . ' ago';
}

function fortress_line_has_any(string $line, array $needles): bool
{
    foreach ($needles as $needle) {
        if (str_contains($line, (string)$needle)) {
            return true;
        }
    }
    return false;
}

function fortress_event_key(string $line): string
{
    $keys = [
        'automated_recon_blocked_source_attempt',
        'automated_recon_block',
        'automated_recon_detected',
        'ml_assisted_block',
        'ml_assisted_strike',
        'ml_threat_prediction',
        'request_threat_detected',
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
        'issued_qr_missing',
        'issued_qr_self_enrollment_blocked',
        'school_id_qr_reset',
        'school_id_reverification_started',
        'school_id_qr_registered',
        'school_id_qr_success',
        'school_id_qr_failed',
        'school_id_qr_locked',
        'school_id_qr_rate_limited',
        'school_id_enrollment_required',
        'school_id_verification_required',
        'school_id_2fa_not_required',
        'user_2fa_enabled',
        'user_2fa_disabled',
        'user_2fa_replaced',
        'current_user_security_policy_changed',
        'password_factor_success',
        'password_factor_failed',
        'login_success',
        'login_failed',
        'bruteforce_detected',
        'ip_banned',
        'malicious_input_detected',
        'shell_attack_detected',
        'banned_ip_attempt',
        'auth_rejected',
        'honeypot_triggered',
        'failed_attempts_cleared',
        'logout',
        'dashboard_session_timeout',
        'school_id_manage_access',
        'dashboard_access',
        'login_page_accessed',
        'login_attempt recorded',
        'security_report_generated',
        'user_management_access',
        'user_account_created',
        'user_account_updated',
        'user_role_changed',
        'user_management_denied',
        'user_account_enabled',
        'user_account_disabled',
        'user_password_reset',
        'user_personal_id_reset',
        'user_account_deleted',
        'login_disabled_account',
        'vault_flag_viewed',
    ];

    foreach ($keys as $key) {
        if (str_contains($line, $key)) {
            return $key;
        }
    }

    return 'security_event';
}

function fortress_event_title(string $line): string
{
    $map = [
        'ml_assisted_block' => 'AI-assisted temporary ban enforced',
        'ml_assisted_strike' => 'AI-assisted threat strike recorded',
        'ml_threat_prediction' => 'ML behavioral threat prediction',
        'request_threat_detected' => 'Suspicious request payload detected',
        'csp_violation_reported' => 'Browser CSP violation blocked',
        'scanner_user_agent_detected' => 'Scanner fingerprint detected',
        'sensitive_path_probe' => 'Sensitive path reconnaissance detected',
        'reconnaissance_probe' => 'Unknown path reconnaissance recorded',
        'csrf_validation_failed' => 'CSRF validation failed',
        'http_method_blocked' => 'Dangerous HTTP method blocked',
        'http_method_anomaly' => 'Unusual HTTP method detected',
        'endpoint_method_rejected' => 'Endpoint method rejected',
        'oversized_request_detected' => 'Oversized request detected',
        'oversized_uri_detected' => 'Oversized URI detected',
        'banned_ip_middleware_block' => 'Banned source blocked by middleware',
        'issued_qr_missing' => 'Issued QR credential unavailable',
        'issued_qr_self_enrollment_blocked' => 'Issued QR self-enrollment blocked',
        'school_id_qr_reset' => 'QR credential reset',
        'school_id_reverification_started' => 'Personal ID re-verification started',
        'school_id_qr_registered' => 'Personal ID registered',
        'school_id_qr_success' => 'Personal ID verified',
        'school_id_qr_failed' => 'Personal ID rejected',
        'school_id_qr_locked' => 'Personal ID verification locked',
        'school_id_qr_rate_limited' => 'Personal ID rate limit triggered',
        'school_id_enrollment_required' => 'Personal ID enrollment required',
        'school_id_verification_required' => 'Personal ID verification requested',
        'school_id_2fa_not_required' => 'Personal ID 2FA not required',
        'user_2fa_enabled' => 'Administrator 2FA enabled',
        'user_2fa_disabled' => 'Administrator 2FA disabled',
        'user_2fa_replaced' => 'Administrator 2FA credential replaced',
        'current_user_security_policy_changed' => 'Current account security policy changed',
        'password_factor_success' => 'Password factor accepted',
        'password_factor_failed' => 'Password factor rejected',
        'login_success' => 'Administrator session opened',
        'login_failed' => 'Login attempt rejected',
        'bruteforce_detected' => 'Brute-force pattern detected',
        'ip_banned' => 'IP address temporarily banned',
        'malicious_input_detected' => 'Suspicious input blocked',
        'shell_attack_detected' => 'Shell-style payload blocked',
        'banned_ip_attempt' => 'Banned IP blocked',
        'auth_rejected' => 'Protected resource access rejected',
        'honeypot_triggered' => 'Honeypot intrusion detected',
        'failed_attempts_cleared' => 'Failed-attempt counter cleared',
        'logout' => 'Administrator session ended',
        'dashboard_session_timeout' => 'Session expired after inactivity',
        'school_id_manage_access' => 'Personal ID controls opened',
        'dashboard_access' => 'Protected dashboard accessed',
        'login_page_accessed' => 'Login gateway viewed',
        'login_attempt recorded' => 'Authentication attempt recorded',
        'security_report_generated' => 'Security documentation report generated',
        'user_management_access' => 'User management opened',
        'user_account_created' => 'Administrator account created',
        'user_account_updated' => 'Administrator account updated',
        'user_role_changed' => 'Administrator role changed',
        'user_management_denied' => 'User management action denied',
        'user_account_enabled' => 'Administrator account activated',
        'user_account_disabled' => 'Administrator account disabled',
        'user_password_reset' => 'Administrator password reset',
        'user_personal_id_reset' => 'Administrator Personal ID reset',
        'user_account_deleted' => 'Administrator account deleted',
        'login_disabled_account' => 'Disabled account login rejected',
        'vault_flag_viewed' => 'Fortress Vault objective captured',
    ];

    $key = fortress_event_key($line);
    if (
        $key === 'auth_rejected'
        && (
            str_contains($line, 'reason=missing_primary_session')
            || str_contains($line, 'reason=incomplete_primary_auth')
        )
    ) {
        return 'Forced browsing attempt blocked';
    }
    $issuedQr = str_contains($line, 'factor=generated_qr');
    if ($issuedQr) {
        if ($key === 'school_id_qr_registered') return 'Administrator-issued QR registered';
        if ($key === 'school_id_qr_success') return 'Issued QR verified';
        if ($key === 'school_id_qr_failed') return 'Issued QR rejected';
        if ($key === 'school_id_qr_locked') return 'Issued QR verification locked';
        if ($key === 'school_id_qr_rate_limited') return 'Issued QR rate limit triggered';
        if ($key === 'user_2fa_enabled') return 'Administrator-issued QR 2FA enabled';
        if ($key === 'user_2fa_replaced') return 'Administrator-issued QR regenerated';
    }
    return $map[$key] ?? 'Security activity recorded';
}

function fortress_event_category(string $line): string
{
    $key = fortress_event_key($line);
    if (in_array($key, ['ml_threat_prediction', 'ml_assisted_strike', 'ml_assisted_block', 'auth_rejected', 'honeypot_triggered'], true)) return 'Threat';
    if (fortress_line_has_any($key, ['request_threat', 'csp_violation', 'scanner_user_agent', 'sensitive_path_probe', 'reconnaissance_probe', 'csrf_validation_failed', 'http_method_', 'endpoint_method_rejected', 'oversized_'])) return 'Threat';
    if (str_contains($key, 'school_id')) return 'Identity';
    if (str_contains($key, 'password') || str_starts_with($key, 'login_') || $key === 'login_attempt recorded') return 'Authentication';
    if ($key === 'security_report_generated') return 'Documentation';
    if (str_starts_with($key, 'user_')) return 'Accounts';
    if (fortress_line_has_any($key, ['bruteforce', 'ip_banned', 'banned_ip'])) return 'Network';
    if (fortress_line_has_any($key, ['malicious', 'shell_attack'])) return 'Threat';
    if ($key === 'vault_flag_viewed') return 'System';
    if (fortress_line_has_any($key, ['logout', 'session', 'dashboard'])) return 'Session';
    return 'System';
}

function fortress_event_outcome(string $line): string
{
    if (fortress_line_has_any($line, ['ml_assisted_block', 'malicious_input_detected', 'shell_attack_detected', 'banned_ip_attempt', 'banned_ip_middleware_block', 'ip_banned', 'csrf_validation_failed', 'csp_violation_reported', 'http_method_blocked', 'endpoint_method_rejected', 'sensitive_path_probe', 'reconnaissance_probe', 'auth_rejected', 'school_id_qr_rate_limited', 'honeypot_triggered'])) return 'BLOCKED';
    if (fortress_line_has_any($line, ['failed', 'rejected', 'locked', 'bruteforce_detected'])) return 'REJECTED';
    if (fortress_line_has_any($line, ['success', 'verified', 'registered', 'factor_success'])) return 'PASSED';
    if (fortress_line_has_any($line, ['logout', 'session_timeout'])) return 'CLOSED';
    return 'RECORDED';
}

function fortress_event_type(string $line): string
{
    $outcome = fortress_event_outcome($line);
    if (in_array($outcome, ['BLOCKED', 'REJECTED'], true)) return 'alert';
    if ($outcome === 'PASSED') return 'success';
    return 'info';
}

function fortress_event_description(string $line): string
{
    if (str_contains($line, 'ml_assisted_block')) return 'The AI-assisted defense layer temporarily banned a source only after a high-confidence malicious model result was corroborated by deterministic security evidence.';
    if (str_contains($line, 'ml_assisted_strike')) return 'The hybrid ML engine recorded an enforcement strike because a malicious model classification was corroborated by deterministic FortressAuth evidence.';
    if (str_contains($line, 'ml_threat_prediction')) return 'The hybrid ML engine combined XGBoost attack classification, autoencoder anomaly detection, and deterministic rule evidence into a behavioral risk assessment used by the guarded AI-assisted defense policy.';
    if (str_contains($line, 'request_threat_detected')) return 'A suspicious payload signature was detected outside the login gateway without recording sensitive field contents.';
    if (str_contains($line, 'csp_violation_reported')) return 'The browser reported content that violated the Content Security Policy and was blocked from executing or loading.';
    if (str_contains($line, 'scanner_user_agent_detected')) return 'The request identified itself with a user-agent commonly associated with security scanners or command-line reconnaissance.';
    if (str_contains($line, 'sensitive_path_probe')) return 'A client requested a path commonly used to discover secrets, source metadata, backups, or administrative tooling.';
    if (str_contains($line, 'reconnaissance_probe')) return 'A missing or reconnaissance-style path was requested and recorded while the application returned a generic 404 response.';
    if (str_contains($line, 'csrf_validation_failed')) return 'A state-changing request failed CSRF validation; the submitted token value was not logged.';
    if (str_contains($line, 'http_method_blocked')) return 'A dangerous HTTP method such as TRACE, TRACK, or CONNECT was blocked at the request-security layer.';
    if (str_contains($line, 'http_method_anomaly')) return 'An uncommon HTTP method reached the application and was recorded for investigation.';
    if (str_contains($line, 'endpoint_method_rejected')) return 'The request used a method that is not allowed for this security-sensitive endpoint.';
    if (str_contains($line, 'oversized_request_detected')) return 'The declared request body exceeded the monitoring threshold and was recorded as abnormal traffic.';
    if (str_contains($line, 'oversized_uri_detected')) return 'The request URI exceeded the monitoring threshold and was recorded as abnormal traffic.';
    if (str_contains($line, 'banned_ip_middleware_block')) return 'A source listed in the middleware ban file was stopped before protected application logic executed.';
    if (str_contains($line, 'malicious_input_detected')) return 'Suspicious login input was stopped before authentication continued.';
    if (str_contains($line, 'shell_attack_detected')) return 'A command-style payload pattern was stopped at the access gateway.';
    if (str_contains($line, 'bruteforce_detected')) return 'Repeated failed authentication attempts triggered brute-force defense.';
    if (str_contains($line, 'ip_banned') || str_contains($line, 'banned_ip_attempt')) return 'Network access controls blocked or restricted the source address.';
    if (str_contains($line, 'issued_qr_missing')) return 'Password verification succeeded, but the administrator-issued QR credential was unavailable and must be regenerated by an authorized administrator.';
    if (str_contains($line, 'issued_qr_self_enrollment_blocked')) return 'Self-enrollment was blocked because administrator-issued QR credentials can only be generated from privileged User Management.';
    $issuedQr = str_contains($line, 'factor=generated_qr');
    if ($issuedQr && str_contains($line, 'school_id_qr_rate_limited')) return 'Repeated issued-QR verification attempts exceeded the configured account or IP rate limit.';
    if ($issuedQr && str_contains($line, 'school_id_qr_failed')) return 'The scanned administrator-issued QR did not match the credential registered for this account.';
    if ($issuedQr && str_contains($line, 'school_id_qr_success')) return 'The administrator-issued QR completed the possession check.';
    if ($issuedQr && str_contains($line, 'school_id_qr_registered')) return 'A new administrator-issued QR credential was securely registered for this account.';
    if ($issuedQr && str_contains($line, 'user_2fa_enabled')) return 'An administrator changed the target account policy to require Password + administrator-issued QR authentication.';
    if ($issuedQr && str_contains($line, 'user_2fa_replaced')) return "An administrator regenerated the target account's issued QR credential while keeping 2FA enabled.";
    if (str_contains($line, 'school_id_qr_rate_limited')) return 'Repeated Personal ID verification attempts exceeded the configured account or IP rate limit.';
    if (str_contains($line, 'school_id_qr_failed')) return 'The scanned Personal ID did not match the registered credential.';
    if (str_contains($line, 'school_id_qr_success')) return 'The registered physical Personal ID completed the possession check.';
    if (str_contains($line, 'school_id_qr_registered')) return 'A Personal ID QR credential was securely enrolled for this administrator account.';
    if (str_contains($line, 'school_id_qr_reset')) return 'The previous Personal ID credential was revoked for secure replacement.';
    if (str_contains($line, 'school_id_reverification_started')) return 'A fresh possession check was requested before sensitive Personal ID changes.';
    if (str_contains($line, 'school_id_2fa_not_required')) return 'The account policy explicitly allows password-only authentication, so no Personal ID QR scan was required for this login.';
    if (str_contains($line, 'user_2fa_enabled')) return 'An administrator changed the target account policy to require Password + Personal ID QR authentication.';
    if (str_contains($line, 'user_2fa_disabled')) return 'An administrator changed the target account policy to password-only authentication and revoked any stored Personal ID QR credential.';
    if (str_contains($line, 'user_2fa_replaced')) return 'An administrator replaced the target account\'s registered Personal ID QR credential while keeping 2FA enabled.';
    if (str_contains($line, 'current_user_security_policy_changed')) return 'The current administrator changed a credential or 2FA policy and the existing session was revoked.';
    if (str_contains($line, 'password_factor_success')) return 'The first authentication factor was accepted.';
    if (str_contains($line, 'password_factor_failed') || str_contains($line, 'login_failed')) return 'A password authentication attempt was rejected.';
    if (str_contains($line, 'login_success')) return 'A fully verified administrator session was established.';
    if (str_contains($line, 'logout') || str_contains($line, 'session_timeout')) return 'The protected administrator session was closed.';
    if (str_contains($line, 'dashboard_access')) return 'A fully verified session entered the protected command center.';
    if (str_contains($line, 'school_id_manage_access')) return 'The protected Personal ID management area was opened.';
    if (str_contains($line, 'security_report_generated')) return 'An authenticated administrator generated a documentation export from the Current Operator reporting center. Secret credentials are excluded from the report.';
    if (str_contains($line, 'user_management_access')) return 'The authenticated administrator opened privileged account management.';
    if (str_contains($line, 'user_account_created')) return 'A new privileged administrator account was created.';
    if (str_contains($line, 'user_account_updated')) return 'Administrator identity or account settings were updated.';
    if (str_contains($line, 'user_role_changed')) return 'A Super Admin changed the target account role and the affected session was revoked when required.';
    if (str_contains($line, 'user_management_denied')) return 'An Admin attempted a Super Admin-only account-management action and FortressAuth rejected the request.';
    if (str_contains($line, 'user_account_enabled')) return 'A previously disabled administrator account was re-enabled.';
    if (str_contains($line, 'user_account_disabled')) return 'An administrator account was prevented from authenticating.';
    if (str_contains($line, 'user_password_reset')) return 'A new server-side password hash was issued for an administrator account.';
    if (str_contains($line, 'user_personal_id_reset')) return 'The registered Personal ID credential was revoked and must be enrolled again.';
    if (str_contains($line, 'user_account_deleted')) return 'A privileged administrator account was permanently removed.';
    if (str_contains($line, 'login_disabled_account')) return 'A disabled administrator account attempted to authenticate and was rejected.';
    if (str_contains($line, 'honeypot_triggered')) return 'A client interacted with the decoy administrator login and triggered the honeypot defense.';
    if (
        str_contains($line, 'auth_rejected')
        && (
            str_contains($line, 'reason=missing_primary_session')
            || str_contains($line, 'reason=incomplete_primary_auth')
        )
    ) return 'A real protected FortressAuth resource was requested without a valid authenticated administrator session and the access attempt was blocked as forced browsing.';
    if (str_contains($line, 'auth_rejected')) return 'A request for a protected resource failed the required authentication or session-security checks and was blocked.';
    if (str_contains($line, 'vault_flag_viewed')) return 'The penetration-test crown-jewel objective was reached from a fully verified administrator session.';
    return 'Security activity was recorded by FortressAuth.';
}

function fortress_log_ip(string $line): string
{
    if (preg_match('/\bip=([^\s]+)/', $line, $matches)) {
        return trim($matches[1]);
    }
    if (preg_match('/IP:\s*([^\s]+)/i', $line, $matches)) {
        return trim($matches[1]);
    }
    return 'unknown';
}

function fortress_log_user(string $line, string $fallback = 'admin'): string
{
    foreach (['username=', 'user=', 'username_attempt='] as $needle) {
        if (preg_match('/' . preg_quote($needle, '/') . '([^\s]*)/', $line, $matches) && trim($matches[1]) !== '') {
            return trim($matches[1]);
        }
    }
    return $fallback;
}

function fortress_is_meaningful_event(string $line): bool
{
    return fortress_line_has_any($line, [
        'automated_recon_block', 'automated_recon_detected', 'automated_recon_blocked_source_attempt',
        'ml_assisted_block', 'ml_assisted_strike', 'ml_threat_prediction',
        'school_id_qr_reset', 'school_id_reverification_started', 'school_id_qr_registered',
        'school_id_qr_success', 'school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited',
        'school_id_2fa_not_required', 'user_2fa_enabled', 'user_2fa_disabled', 'user_2fa_replaced',
        'current_user_security_policy_changed',
        'password_factor_success', 'password_factor_failed', 'login_success', 'login_failed',
        'bruteforce_detected', 'ip_banned', 'malicious_input_detected', 'shell_attack_detected',
        'banned_ip_attempt',
        'auth_rejected', 'logout', 'dashboard_session_timeout', 'dashboard_access',
        'security_report_generated', 'user_management_access', 'user_account_created', 'user_account_updated',
        'user_account_enabled', 'user_account_disabled', 'user_password_reset',
        'user_personal_id_reset', 'user_account_deleted', 'login_disabled_account',
        'vault_flag_viewed',
    ]);
}

function fortress_is_auth_event(string $line): bool
{
    return fortress_line_has_any($line, [
        'password_factor_success', 'password_factor_failed', 'school_id_qr_success',
        'school_id_qr_failed', 'school_id_qr_locked', 'school_id_2fa_not_required', 'login_success', 'logout',
    ]);
}

function fortress_format_date_value(?string $value, string $fallback = 'Not recorded'): string
{
    if (!$value) return $fallback;
    try {
        return (new DateTimeImmutable($value))->setTimezone(new DateTimeZone(date_default_timezone_get()))->format('Y-m-d H:i:s');
    } catch (Throwable $e) {
        return $value;
    }
}



/**
 * Return compact 24-hour dashboard metrics directly from structured security
 * events. This replaces repeatedly parsing thousands of raw audit strings in
 * PHP while preserving the same counters and security semantics.
 */
function fortress_security_metrics_24h_db(PDO $pdo): ?array
{
    try {
        $stmt = $pdo->query(
            "WITH recent AS (
                SELECT id, occurred_at, event_key, source_ip, issues, raw_line, metadata
                FROM public.security_events
                WHERE occurred_at >= NOW() - INTERVAL '24 hours'
            ),
            forced AS (
                SELECT
                    occurred_at,
                    COALESCE(NULLIF(source_ip, ''), 'unknown') AS source_key,
                    CASE
                        WHEN COALESCE(metadata->>'reason', '') IN ('incomplete_primary_auth', 'missing_primary_session')
                            THEN metadata->>'reason'
                        WHEN COALESCE(raw_line, '') LIKE '%reason=incomplete_primary_auth%'
                            THEN 'incomplete_primary_auth'
                        ELSE 'missing_primary_session'
                    END AS reason_key,
                    LAG(occurred_at) OVER (
                        PARTITION BY
                            COALESCE(NULLIF(source_ip, ''), 'unknown'),
                            CASE
                                WHEN COALESCE(metadata->>'reason', '') IN ('incomplete_primary_auth', 'missing_primary_session')
                                    THEN metadata->>'reason'
                                WHEN COALESCE(raw_line, '') LIKE '%reason=incomplete_primary_auth%'
                                    THEN 'incomplete_primary_auth'
                                ELSE 'missing_primary_session'
                            END
                        ORDER BY occurred_at, id
                    ) AS previous_at
                FROM recent
                WHERE event_key = 'auth_rejected'
                  AND (
                       COALESCE(raw_line, '') LIKE '%uid=0%'
                       OR COALESCE(metadata->>'uid', '') = '0'
                  )
                  AND (
                       COALESCE(raw_line, '') LIKE '%reason=incomplete_primary_auth%'
                       OR COALESCE(raw_line, '') LIKE '%reason=missing_primary_session%'
                       OR COALESCE(metadata->>'reason', '') IN ('incomplete_primary_auth', 'missing_primary_session')
                  )
            )
            SELECT
                (SELECT COALESCE(MAX(id), 0)::bigint FROM public.security_events) AS total_audit_events,
                COUNT(*) FILTER (WHERE event_key = 'password_factor_failed') AS failed_passwords,
                COUNT(*) FILTER (WHERE event_key = 'password_factor_success') AS successful_passwords,
                COUNT(*) FILTER (WHERE event_key = 'school_id_qr_success') AS school_id_success,
                COUNT(*) FILTER (WHERE event_key IN ('school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited')) AS school_id_failures,
                COUNT(*) FILTER (WHERE event_key IN (
                    'ml_assisted_block', 'ml_assisted_strike',
                    'malicious_input_detected', 'shell_attack_detected', 'request_threat_detected', 'csp_violation_reported',
                    'scanner_user_agent_detected', 'sensitive_path_probe', 'reconnaissance_probe',
                    'csrf_validation_failed', 'http_method_blocked', 'http_method_anomaly',
                    'endpoint_method_rejected', 'oversized_request_detected', 'oversized_uri_detected',
                    'banned_ip_attempt', 'auth_rejected', 'banned_ip_middleware_block', 'bruteforce_detected'
                )) AS suspicious_requests,
                COUNT(*) FILTER (WHERE event_key = 'bruteforce_detected') AS brute_force,
                COUNT(*) FILTER (WHERE event_key IN ('banned_ip_attempt', 'banned_ip_middleware_block')) AS banned_request_hits,
                COUNT(*) FILTER (
                    WHERE (event_key = 'malicious_input_detected' AND COALESCE(issues, '') ILIKE '%sql_attack%')
                       OR (event_key = 'request_threat_detected' AND COALESCE(raw_line, '') ILIKE '%sqli%')
                ) AS sql_attacks,
                COUNT(*) FILTER (
                    WHERE (event_key = 'malicious_input_detected' AND COALESCE(issues, '') ILIKE '%xss_attack%')
                       OR (event_key = 'request_threat_detected' AND COALESCE(raw_line, '') ILIKE '%xss%')
                ) AS xss_attacks,
                COUNT(*) FILTER (
                    WHERE (event_key = 'malicious_input_detected' AND COALESCE(issues, '') ILIKE '%path_traversal%')
                       OR (event_key = 'request_threat_detected' AND COALESCE(raw_line, '') ILIKE '%path%')
                ) AS path_attacks,
                COUNT(*) FILTER (
                    WHERE event_key = 'shell_attack_detected'
                       OR (event_key = 'request_threat_detected' AND COALESCE(raw_line, '') ILIKE '%shell%')
                ) AS shell_attacks,
                COUNT(*) FILTER (WHERE event_key = 'csrf_validation_failed') AS csrf_attacks,
                COUNT(*) FILTER (WHERE event_key = 'csp_violation_reported') AS csp_violations,
                COUNT(*) FILTER (WHERE event_key IN ('sensitive_path_probe', 'reconnaissance_probe')) AS recon_probes,
                COUNT(*) FILTER (WHERE event_key = 'scanner_user_agent_detected') AS scanners,
                COUNT(*) FILTER (WHERE event_key IN ('http_method_blocked', 'http_method_anomaly', 'endpoint_method_rejected')) AS method_anomalies,
                COUNT(*) FILTER (WHERE event_key IN ('oversized_request_detected', 'oversized_uri_detected')) AS oversized_requests,
                COUNT(*) FILTER (WHERE event_key = 'honeypot_triggered') AS honeypot_events,
                (SELECT COUNT(*) FROM forced WHERE previous_at IS NULL OR occurred_at - previous_at > INTERVAL '2 seconds') AS forced_browsing
            FROM recent"
        );
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    } catch (Throwable $e) {
        error_log('FortressAuth compact 24h metric query failed: ' . $e->getMessage());
        return null;
    }
}

function fortress_security_hourly_chart_db(PDO $pdo): ?array
{
    try {
        $timezone = date_default_timezone_get();
        $stmt = $pdo->prepare(
            "SELECT
                TO_CHAR(occurred_at AT TIME ZONE :timezone, 'YYYY-MM-DD HH24') AS hour_key,
                COUNT(*) FILTER (WHERE event_key = 'password_factor_success') AS password_success,
                COUNT(*) FILTER (WHERE event_key = 'password_factor_failed') AS password_failed,
                COUNT(*) FILTER (WHERE event_key = 'school_id_qr_success') AS school_success,
                COUNT(*) FILTER (WHERE event_key IN (
                    'ml_assisted_block', 'ml_assisted_strike',
                    'malicious_input_detected', 'shell_attack_detected', 'request_threat_detected', 'csp_violation_reported',
                    'scanner_user_agent_detected', 'sensitive_path_probe', 'reconnaissance_probe',
                    'csrf_validation_failed', 'http_method_blocked', 'http_method_anomaly',
                    'endpoint_method_rejected', 'oversized_request_detected', 'oversized_uri_detected',
                    'banned_ip_attempt', 'auth_rejected', 'banned_ip_middleware_block', 'bruteforce_detected'
                )) AS blocked
             FROM public.security_events
             WHERE occurred_at >= NOW() - INTERVAL '24 hours'
             GROUP BY 1
             ORDER BY 1"
        );
        $stmt->execute(['timezone' => $timezone]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return is_array($rows) ? $rows : [];
    } catch (Throwable $e) {
        error_log('FortressAuth hourly chart query failed: ' . $e->getMessage());
        return null;
    }
}

function fortress_top_threat_sources_24h_db(PDO $pdo, int $limit = 5): ?array
{
    try {
        $limit = max(1, min(20, $limit));
        $stmt = $pdo->prepare(
            "SELECT source_ip, COUNT(*)::int AS event_count
             FROM public.security_events
             WHERE occurred_at >= NOW() - INTERVAL '24 hours'
               AND source_ip IS NOT NULL
               AND BTRIM(source_ip) <> ''
               AND event_key IN (
                    'ml_assisted_block', 'ml_assisted_strike', 'ml_threat_prediction',
                    'malicious_input_detected', 'shell_attack_detected', 'request_threat_detected', 'csp_violation_reported',
                    'scanner_user_agent_detected', 'sensitive_path_probe', 'reconnaissance_probe',
                    'csrf_validation_failed', 'http_method_blocked', 'http_method_anomaly',
                    'endpoint_method_rejected', 'oversized_request_detected', 'oversized_uri_detected',
                    'banned_ip_attempt', 'auth_rejected', 'banned_ip_middleware_block', 'bruteforce_detected', 'ip_banned',
                    'school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited', 'password_factor_failed', 'honeypot_triggered'
               )
             GROUP BY source_ip
             ORDER BY event_count DESC, source_ip ASC
             LIMIT :limit"
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $result = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) ?: [] as $row) {
            $ip = trim((string)($row['source_ip'] ?? ''));
            if ($ip !== '') $result[$ip] = (int)($row['event_count'] ?? 0);
        }
        return $result;
    } catch (Throwable $e) {
        error_log('FortressAuth top-threat-source query failed: ' . $e->getMessage());
        return null;
    }
}

/**
 * Fetch a small, filtered recent event stream for pages that render detailed
 * tables. This avoids downloading unrelated audit rows first and filtering them
 * in PHP.
 */
function fortress_recent_security_event_lines(PDO $pdo, array $eventKeys, int $limit): ?array
{
    $eventKeys = array_values(array_unique(array_filter(array_map('strval', $eventKeys), static fn(string $key): bool => $key !== '')));
    if (!$eventKeys || $limit <= 0) return [];
    $limit = max(1, min(1000, $limit));

    try {
        $placeholders = implode(',', array_fill(0, count($eventKeys), '?'));
        $sql = "SELECT raw_line
                FROM public.security_events
                WHERE event_key IN ($placeholders)
                  AND raw_line IS NOT NULL
                  AND BTRIM(raw_line) <> ''
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?";
        $stmt = $pdo->prepare($sql);
        $position = 1;
        foreach ($eventKeys as $key) {
            $stmt->bindValue($position++, $key, PDO::PARAM_STR);
        }
        $stmt->bindValue($position, $limit, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);
        return is_array($rows)
            ? array_values(array_filter(array_map(static fn($line): string => trim((string)$line), $rows), static fn(string $line): bool => $line !== ''))
            : [];
    } catch (Throwable $e) {
        error_log('FortressAuth filtered recent-event query failed: ' . $e->getMessage());
        return null;
    }
}

/**
 * 30-day analytics are grouped inside PostgreSQL instead of reconstructed from
 * a 10,000-line audit transfer. The CASE expressions mirror the existing PHP
 * event category/outcome rules so the charts retain their previous meaning.
 */
function fortress_analytics_30d_db(PDO $pdo): ?array
{
    $categoryCase = "CASE
        WHEN event_key IN ('ml_threat_prediction','ml_assisted_strike','ml_assisted_block','auth_rejected','honeypot_triggered') THEN 'Threat'
        WHEN event_key LIKE 'request_threat%' OR event_key LIKE 'csp_violation%' OR event_key LIKE 'scanner_user_agent%' OR event_key IN ('sensitive_path_probe','reconnaissance_probe','csrf_validation_failed','endpoint_method_rejected') OR event_key LIKE 'http_method_%' OR event_key LIKE 'oversized_%' THEN 'Threat'
        WHEN event_key LIKE '%school_id%' THEN 'Identity'
        WHEN event_key LIKE '%password%' OR event_key LIKE 'login_%' OR event_key = 'login_attempt recorded' THEN 'Authentication'
        WHEN event_key = 'security_report_generated' THEN 'Documentation'
        WHEN event_key LIKE 'user_%' THEN 'Accounts'
        WHEN event_key LIKE '%bruteforce%' OR event_key = 'ip_banned' OR event_key LIKE '%banned_ip%' THEN 'Network'
        WHEN event_key LIKE '%malicious%' OR event_key LIKE '%shell_attack%' THEN 'Threat'
        WHEN event_key = 'vault_flag_viewed' THEN 'System'
        WHEN event_key LIKE '%logout%' OR event_key LIKE '%session%' OR event_key LIKE '%dashboard%' THEN 'Session'
        ELSE 'System'
    END";
    $outcomeCase = "CASE
        WHEN event_key IN ('ml_assisted_block','malicious_input_detected','shell_attack_detected','banned_ip_attempt','banned_ip_middleware_block','ip_banned','csrf_validation_failed','csp_violation_reported','http_method_blocked','endpoint_method_rejected','sensitive_path_probe','reconnaissance_probe','auth_rejected','school_id_qr_rate_limited','honeypot_triggered') THEN 'BLOCKED'
        WHEN event_key LIKE '%failed%' OR event_key LIKE '%rejected%' OR event_key LIKE '%locked%' OR event_key = 'bruteforce_detected' THEN 'REJECTED'
        WHEN event_key LIKE '%success%' OR event_key LIKE '%verified%' OR event_key LIKE '%registered%' OR event_key LIKE '%factor_success%' THEN 'PASSED'
        WHEN event_key = 'logout' OR event_key LIKE '%session_timeout%' THEN 'CLOSED'
        ELSE 'RECORDED'
    END";

    try {
        $timezone = date_default_timezone_get();
        $dailyStmt = $pdo->prepare(
            "SELECT
                TO_CHAR(occurred_at AT TIME ZONE :timezone, 'YYYY-MM-DD') AS day_key,
                $outcomeCase AS outcome_key,
                COUNT(*)::int AS event_count
             FROM public.security_events
             WHERE occurred_at >= NOW() - INTERVAL '7 days'
             GROUP BY 1, 2
             ORDER BY 1, 2"
        );
        $dailyStmt->execute(['timezone' => $timezone]);

        $summaryStmt = $pdo->query(
            "SELECT
                $categoryCase AS category_key,
                $outcomeCase AS outcome_key,
                COUNT(*)::int AS event_count
             FROM public.security_events
             WHERE occurred_at >= NOW() - INTERVAL '30 days'
             GROUP BY 1, 2"
        );

        return [
            'daily' => $dailyStmt->fetchAll(PDO::FETCH_ASSOC) ?: [],
            'summary' => $summaryStmt->fetchAll(PDO::FETCH_ASSOC) ?: [],
        ];
    } catch (Throwable $e) {
        error_log('FortressAuth 30-day analytics query failed: ' . $e->getMessage());
        return null;
    }
}

function fortress_audit_category_counts_db(PDO $pdo): ?array
{
    try {
        $stmt = $pdo->query(
            "SELECT
                CASE
                    WHEN event_key IN ('ml_threat_prediction','ml_assisted_strike','ml_assisted_block','auth_rejected','honeypot_triggered') THEN 'Threat'
                    WHEN event_key LIKE 'request_threat%' OR event_key LIKE 'csp_violation%' OR event_key LIKE 'scanner_user_agent%' OR event_key IN ('sensitive_path_probe','reconnaissance_probe','csrf_validation_failed','endpoint_method_rejected') OR event_key LIKE 'http_method_%' OR event_key LIKE 'oversized_%' THEN 'Threat'
                    WHEN event_key LIKE '%school_id%' THEN 'Identity'
                    WHEN event_key LIKE '%password%' OR event_key LIKE 'login_%' OR event_key = 'login_attempt recorded' THEN 'Authentication'
                    WHEN event_key = 'security_report_generated' THEN 'Documentation'
                    WHEN event_key LIKE 'user_%' THEN 'Accounts'
                    WHEN event_key LIKE '%bruteforce%' OR event_key = 'ip_banned' OR event_key LIKE '%banned_ip%' THEN 'Network'
                    WHEN event_key LIKE '%malicious%' OR event_key LIKE '%shell_attack%' THEN 'Threat'
                    WHEN event_key = 'vault_flag_viewed' THEN 'System'
                    WHEN event_key LIKE '%logout%' OR event_key LIKE '%session%' OR event_key LIKE '%dashboard%' THEN 'Session'
                    ELSE 'System'
                END AS category_key,
                COUNT(*)::int AS event_count
             FROM public.security_events
             GROUP BY 1"
        );
        $result = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) ?: [] as $row) {
            $result[(string)$row['category_key']] = (int)$row['event_count'];
        }
        return $result;
    } catch (Throwable $e) {
        error_log('FortressAuth audit category aggregate failed: ' . $e->getMessage());
        return null;
    }
}

/**
 * Return persistent, all-time threat-category totals.
 *
 * These totals intentionally do not use the rolling 24-hour cutoff used by
 * live threat pressure, source rankings, and charts. The primary source is
 * public.security_events in Supabase/PostgreSQL so the category cards survive
 * Render spin-downs, restarts, and redeployments. If the database is
 * temporarily unavailable, the function falls back to the merged audit lines.
 */
function fortress_all_time_threat_category_totals(PDO $pdo, array $auditLines, array $honeypotLines): array
{
    $totals = [
        'passwordRejection' => 0,
        'personalIdRejection' => 0,
        'sqlInjection' => 0,
        'xssTraversal' => 0,
        'shellPayload' => 0,
        'csrfRejection' => 0,
        'cspViolations' => 0,
        'reconProbes' => 0,
        'scannerFingerprints' => 0,
        'httpMethodAbuse' => 0,
        'oversizedRequests' => 0,
        'bruteForce' => 0,
        'honeypot' => 0,
        'bannedSourceHits' => 0,
        'forcedBrowsing' => 0,
    ];

    try {
        $stmt = $pdo->query(
            "SELECT
                COUNT(*) FILTER (WHERE event_key = 'password_factor_failed') AS password_rejection,
                COUNT(*) FILTER (WHERE event_key IN ('school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited')) AS personal_id_rejection,
                COUNT(*) FILTER (
                    WHERE (event_key = 'malicious_input_detected' AND COALESCE(issues, '') ILIKE '%sql_attack%')
                       OR (event_key = 'request_threat_detected' AND COALESCE(raw_line, '') ILIKE '%sqli%')
                ) AS sql_injection,
                COUNT(*) FILTER (
                    WHERE (event_key = 'malicious_input_detected' AND (COALESCE(issues, '') ILIKE '%xss_attack%' OR COALESCE(issues, '') ILIKE '%path_traversal%'))
                       OR (event_key = 'request_threat_detected' AND (COALESCE(raw_line, '') ILIKE '%xss%' OR COALESCE(raw_line, '') ILIKE '%path%'))
                ) AS xss_traversal,
                COUNT(*) FILTER (
                    WHERE event_key = 'shell_attack_detected'
                       OR (event_key = 'request_threat_detected' AND COALESCE(raw_line, '') ILIKE '%shell%')
                ) AS shell_payload,
                COUNT(*) FILTER (WHERE event_key = 'csrf_validation_failed') AS csrf_rejection,
                COUNT(*) FILTER (WHERE event_key = 'csp_violation_reported') AS csp_violations,
                COUNT(*) FILTER (WHERE event_key IN ('sensitive_path_probe', 'reconnaissance_probe', 'automated_recon_detected', 'automated_recon_block')) AS recon_probes,
                COUNT(*) FILTER (WHERE event_key = 'scanner_user_agent_detected') AS scanner_fingerprints,
                COUNT(*) FILTER (WHERE event_key IN ('http_method_blocked', 'http_method_anomaly', 'endpoint_method_rejected')) AS http_method_abuse,
                COUNT(*) FILTER (WHERE event_key IN ('oversized_request_detected', 'oversized_uri_detected')) AS oversized_requests,
                COUNT(*) FILTER (WHERE event_key = 'bruteforce_detected') AS brute_force,
                COUNT(*) FILTER (WHERE event_key = 'honeypot_triggered') AS honeypot,
                COUNT(*) FILTER (WHERE event_key IN ('banned_ip_attempt', 'banned_ip_middleware_block')) AS banned_source_hits
             FROM public.security_events
             WHERE event_key IN (
                'password_factor_failed',
                'school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited',
                'malicious_input_detected', 'request_threat_detected', 'shell_attack_detected',
                'csrf_validation_failed', 'csp_violation_reported',
                'sensitive_path_probe', 'reconnaissance_probe', 'automated_recon_detected', 'automated_recon_block',
                'scanner_user_agent_detected',
                'http_method_blocked', 'http_method_anomaly', 'endpoint_method_rejected',
                'oversized_request_detected', 'oversized_uri_detected',
                'bruteforce_detected', 'honeypot_triggered',
                'banned_ip_attempt', 'banned_ip_middleware_block'
             )"
        );
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Threat-category aggregate query returned no row.');
        }

        $totals['passwordRejection'] = (int)($row['password_rejection'] ?? 0);
        $totals['personalIdRejection'] = (int)($row['personal_id_rejection'] ?? 0);
        $totals['sqlInjection'] = (int)($row['sql_injection'] ?? 0);
        $totals['xssTraversal'] = (int)($row['xss_traversal'] ?? 0);
        $totals['shellPayload'] = (int)($row['shell_payload'] ?? 0);
        $totals['csrfRejection'] = (int)($row['csrf_rejection'] ?? 0);
        $totals['cspViolations'] = (int)($row['csp_violations'] ?? 0);
        $totals['reconProbes'] = (int)($row['recon_probes'] ?? 0);
        $totals['scannerFingerprints'] = (int)($row['scanner_fingerprints'] ?? 0);
        $totals['httpMethodAbuse'] = (int)($row['http_method_abuse'] ?? 0);
        $totals['oversizedRequests'] = (int)($row['oversized_requests'] ?? 0);
        $totals['bruteForce'] = (int)($row['brute_force'] ?? 0);
        $totals['honeypot'] = (int)($row['honeypot'] ?? 0);
        $totals['bannedSourceHits'] = (int)($row['banned_source_hits'] ?? 0);

        // Forced browsing is incident-based rather than raw-line based. Perform
        // the de-duplication in PostgreSQL so the application never downloads
        // the complete historical auth_rejected stream merely to count it.
        $forcedStmt = $pdo->query(
            "WITH forced AS (
                SELECT
                    occurred_at,
                    COALESCE(NULLIF(source_ip, ''), 'unknown') AS source_key,
                    CASE
                        WHEN COALESCE(metadata->>'reason', '') IN ('incomplete_primary_auth', 'missing_primary_session')
                            THEN metadata->>'reason'
                        WHEN COALESCE(raw_line, '') LIKE '%reason=incomplete_primary_auth%'
                            THEN 'incomplete_primary_auth'
                        ELSE 'missing_primary_session'
                    END AS reason_key,
                    LAG(occurred_at) OVER (
                        PARTITION BY
                            COALESCE(NULLIF(source_ip, ''), 'unknown'),
                            CASE
                                WHEN COALESCE(metadata->>'reason', '') IN ('incomplete_primary_auth', 'missing_primary_session')
                                    THEN metadata->>'reason'
                                WHEN COALESCE(raw_line, '') LIKE '%reason=incomplete_primary_auth%'
                                    THEN 'incomplete_primary_auth'
                                ELSE 'missing_primary_session'
                            END
                        ORDER BY occurred_at, id
                    ) AS previous_at
                FROM public.security_events
                WHERE event_key = 'auth_rejected'
                  AND (
                       COALESCE(raw_line, '') LIKE '%uid=0%'
                       OR COALESCE(metadata->>'uid', '') = '0'
                  )
                  AND (
                       COALESCE(raw_line, '') LIKE '%reason=incomplete_primary_auth%'
                       OR COALESCE(raw_line, '') LIKE '%reason=missing_primary_session%'
                       OR COALESCE(metadata->>'reason', '') IN ('incomplete_primary_auth', 'missing_primary_session')
                  )
            )
            SELECT COUNT(*)
            FROM forced
            WHERE previous_at IS NULL
               OR occurred_at - previous_at > INTERVAL '2 seconds'"
        );
        $totals['forcedBrowsing'] = (int)$forcedStmt->fetchColumn();

        return $totals;
    } catch (Throwable $e) {
        // Keep the Threats page usable during a temporary database outage.
        error_log('FortressAuth all-time threat-category query failed: ' . $e->getMessage());
    }

    // Flat-file fallback. This path preserves the previous behavior if the
    // database is unavailable, while still calculating totals without 24h cutoff.
    $forcedLastSeen = [];
    $auditHoneypotCount = 0;

    foreach ($auditLines as $line) {
        if (str_contains($line, 'password_factor_failed')) $totals['passwordRejection']++;
        if (fortress_line_has_any($line, ['school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited'])) $totals['personalIdRejection']++;

        if (
            (str_contains($line, 'malicious_input_detected') && str_contains($line, 'issues=') && str_contains($line, 'sql_attack'))
            || (str_contains($line, 'request_threat_detected') && str_contains($line, 'sqli'))
        ) $totals['sqlInjection']++;

        if (
            (str_contains($line, 'malicious_input_detected') && str_contains($line, 'issues=') && (str_contains($line, 'xss_attack') || str_contains($line, 'path_traversal')))
            || (str_contains($line, 'request_threat_detected') && (str_contains($line, 'xss') || str_contains($line, 'path')))
        ) $totals['xssTraversal']++;

        if (str_contains($line, 'shell_attack_detected') || (str_contains($line, 'request_threat_detected') && str_contains($line, 'shell'))) $totals['shellPayload']++;
        if (str_contains($line, 'csrf_validation_failed')) $totals['csrfRejection']++;
        if (str_contains($line, 'csp_violation_reported')) $totals['cspViolations']++;
        if (fortress_line_has_any($line, ['sensitive_path_probe', 'reconnaissance_probe'])) $totals['reconProbes']++;
        if (str_contains($line, 'scanner_user_agent_detected')) $totals['scannerFingerprints']++;
        if (fortress_line_has_any($line, ['http_method_blocked', 'http_method_anomaly', 'endpoint_method_rejected'])) $totals['httpMethodAbuse']++;
        if (fortress_line_has_any($line, ['oversized_request_detected', 'oversized_uri_detected'])) $totals['oversizedRequests']++;
        if (str_contains($line, 'bruteforce_detected')) $totals['bruteForce']++;
        if (str_contains($line, 'banned_ip_attempt') || str_contains($line, 'banned_ip_middleware_block')) $totals['bannedSourceHits']++;
        if (str_contains($line, 'honeypot_triggered')) $auditHoneypotCount++;

        if (
            str_contains($line, 'auth_rejected')
            && preg_match('/\buid=0\b/', $line) === 1
            && (str_contains($line, 'reason=incomplete_primary_auth') || str_contains($line, 'reason=missing_primary_session'))
        ) {
            $dt = fortress_event_datetime($line);
            if ($dt) {
                $reason = str_contains($line, 'reason=incomplete_primary_auth') ? 'incomplete_primary_auth' : 'missing_primary_session';
                $key = fortress_log_ip($line) . '|' . $reason;
                $timestamp = $dt->getTimestamp();
                $previous = (int)($forcedLastSeen[$key] ?? 0);
                if ($previous === 0 || ($timestamp - $previous) > 2) {
                    $totals['forcedBrowsing']++;
                }
                $forcedLastSeen[$key] = $timestamp;
            }
        }
    }

    $totals['honeypot'] = max($auditHoneypotCount, count($honeypotLines));
    return $totals;
}

function fortress_build_security_context(PDO $pdo, int $userId, array $options = []): array
{
    $dataPath = __DIR__ . '/../data/';
    $auditLimit = max(100, min(10000, (int)($options['audit_limit'] ?? 650)));
    $includeAllTimeThreats = !empty($options['include_all_time_threats']);
    $includeAllBans = !empty($options['include_all_bans']);
    $includeCharts = !empty($options['include_charts']);
    $includeTopThreatSources = !empty($options['include_top_threat_sources']);
    $minimal = !empty($options['minimal']);

    $requestAccount = $GLOBALS['FORTRESS_AUTH_ACCOUNT'] ?? null;
    $requestAccountUid = (int)($GLOBALS['FORTRESS_AUTH_ACCOUNT_UID'] ?? 0);
    if (is_array($requestAccount) && $requestAccountUid === $userId && isset($requestAccount['username'])) {
        $user = $requestAccount;
        if (!array_key_exists('school_id_2fa_required', $user)) $user['school_id_2fa_required'] = true;
        if (!array_key_exists('second_factor_type', $user)) $user['second_factor_type'] = 'personal_id';
        if (!array_key_exists('role', $user)) $user['role'] = 'superadmin';
        if (!array_key_exists('school_id_qr_updated_at', $user)) $user['school_id_qr_updated_at'] = null;
    } else {
        $policyField = fortress_optional_2fa_policy_available($pdo)
            ? 'school_id_2fa_required'
            : 'TRUE AS school_id_2fa_required';
        $factorTypeField = fortress_second_factor_type_available($pdo)
            ? "COALESCE(second_factor_type, 'personal_id') AS second_factor_type"
            : "'personal_id' AS second_factor_type";
        $roleField = fortress_role_policy_available($pdo)
            ? "COALESCE(role, 'admin') AS role"
            : "'superadmin' AS role";
        $updatedAtField = fortress_column_exists($pdo, 'school_id_qr_updated_at')
            ? 'school_id_qr_updated_at'
            : 'NULL AS school_id_qr_updated_at';

        $stmt = $pdo->prepare(
            'SELECT username, ' . $policyField . ', ' . $factorTypeField . ', ' . $roleField . ', school_id_qr_enabled, ' . $updatedAtField . '
             FROM public.users WHERE id = ? LIMIT 1'
        );
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    }

    $usernameRaw = (string)($user['username'] ?? 'Unknown');
    $userRole = fortress_normalize_role($user['role'] ?? 'superadmin');
    $schoolIdRequired = (bool)($user['school_id_2fa_required'] ?? true);
    $schoolIdEnabled = !empty($user['school_id_qr_enabled']);
    $schoolIdFactorType = fortress_second_factor_type_value($user);
    $schoolIdUpdatedAt = $user['school_id_qr_updated_at'] ?? null;
    $schoolIdVerified = $schoolIdRequired && !empty($_SESSION['school_id_verified']);

    // These header/posture values depend only on the already-validated account
    // and static security controls, so they can be returned without touching
    // audit history or analytics tables on lightweight pages.
    $defenseLayers = [
        ['Password authentication', true, 'Primary credential verification', 20, 'fa-key'],
        [
            'QR-based 2FA',
            $schoolIdRequired && $schoolIdEnabled && $schoolIdVerified,
            $schoolIdRequired
                ? ($schoolIdFactorType === 'generated_qr'
                    ? 'Required account policy · administrator-issued QR possession check'
                    : 'Required account policy · registered physical-ID possession check')
                : 'Disabled for this account · password-only authentication',
            20,
            'fa-id-card'
        ],
        ['CSRF protection', true, 'Security tokens protect state-changing authentication requests', 10, 'fa-shield'],
        ['Brute-force defense', true, 'Repeated failures trigger detection and temporary blocking', 10, 'fa-lock'],
        ['Suspicious input detection', true, 'SQLi, XSS, traversal and shell-pattern checks', 10, 'fa-filter'],
        ['IP ban enforcement', true, 'Restricted network sources are blocked before access proceeds', 10, 'fa-ban'],
        ['Session protection', true, 'Strict cookies, regeneration and inactivity controls', 10, 'fa-cookie-bite'],
        ['Audit logging', true, 'Authentication and defense activity is retained as evidence', 10, 'fa-clipboard-list'],
    ];
    $activeDefenseCount = count(array_filter($defenseLayers, static fn(array $layer): bool => (bool)$layer[1]));
    $protectionScore = 0;
    foreach ($defenseLayers as $layer) {
        if ($layer[1]) $protectionScore += (int)$layer[3];
    }
    $protectionLabel = $protectionScore >= 90 ? 'STRONGLY PROTECTED' : ($protectionScore >= 70 ? 'PROTECTED' : ($protectionScore >= 50 ? 'ATTENTION REQUIRED' : 'AT RISK'));

    if ($minimal) {
        return [
            'user' => $user,
            'usernameRaw' => $usernameRaw,
            'userRole' => $userRole,
            'schoolIdRequired' => $schoolIdRequired,
            'schoolIdEnabled' => $schoolIdEnabled,
            'schoolIdFactorType' => $schoolIdFactorType,
            'schoolIdUpdatedAt' => $schoolIdUpdatedAt,
            'schoolIdVerified' => $schoolIdVerified,
            'defenseLayers' => $defenseLayers,
            'activeDefenseCount' => $activeDefenseCount,
            'protectionScore' => $protectionScore,
            'protectionLabel' => $protectionLabel,
        ];
    }

    $auditLines = fortress_read_persistent_audit_lines($pdo, $dataPath . 'audit.log', $auditLimit);
    $honeypotLines = ($includeAllTimeThreats || $auditLimit >= 10000)
        ? fortress_read_lines($dataPath . 'honeypot_log.txt')
        : fortress_read_last_lines($dataPath . 'honeypot_log.txt', max(1000, min(5000, $auditLimit)));
    $threatCategoryAllTime = $includeAllTimeThreats
        ? fortress_all_time_threat_category_totals($pdo, $auditLines, $honeypotLines)
        : [
            'passwordRejection'=>0,'personalIdRejection'=>0,'sqlInjection'=>0,'xssTraversal'=>0,
            'shellPayload'=>0,'csrfRejection'=>0,'cspViolations'=>0,'reconProbes'=>0,
            'scannerFingerprints'=>0,'httpMethodAbuse'=>0,'oversizedRequests'=>0,'bruteForce'=>0,
            'honeypot'=>0,'bannedSourceHits'=>0,'forcedBrowsing'=>0,
        ];

    $activeBans = 0;
    $allBans = [];
    try {
        $activeBans = (int)$pdo->query("SELECT COUNT(*) FROM banned_ips WHERE banned_until > NOW()")->fetchColumn();
        if ($includeAllBans) {
            $banStmt = $pdo->query('SELECT ip, banned_until FROM banned_ips ORDER BY banned_until DESC LIMIT 500');
            $allBans = $banStmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
        }
    } catch (Throwable $e) {
        error_log('Fortress security metrics ban query failed: ' . $e->getMessage());
    }

    $cutoff24h = new DateTimeImmutable('-24 hours');
    $failedAttempts24h = 0;
    $successfulPassword24h = 0;
    $schoolIdSuccess24h = 0;
    $schoolIdFailures24h = 0;
    $suspiciousRequests24h = 0;
    $bruteforce24h = 0;
    $bannedRequest24h = 0;
    $forcedBrowsing24h = 0;
    // De-duplicate browser retries/prefetches so one forced-browsing incident
    // does not inflate the category counter with multiple auth_rejected lines.
    $forcedBrowsingLastSeen = [];
    $sqlAttack24h = 0;
    $xssAttack24h = 0;
    $pathAttack24h = 0;
    $shellAttack24h = 0;
    $csrfAttack24h = 0;
    $cspViolation24h = 0;
    $reconProbe24h = 0;
    $scanner24h = 0;
    $methodAnomaly24h = 0;
    $oversizedRequest24h = 0;
    $lastThreatLine = null;
    $lastSuccessfulLoginLine = null;
    $lastSchoolIdSuccessLine = null;
    $lastMeaningfulLine = null;

    $hourKeys = [];
    $chartSuccess = [];
    $chartFailed = [];
    $chartSchool = [];
    $chartBlocked = [];
    $hourNow = new DateTimeImmutable('now');
    for ($i = 23; $i >= 0; $i--) {
        $hour = $hourNow->modify('-' . $i . ' hours')->format('Y-m-d H');
        $hourKeys[] = $hour;
        $chartSuccess[$hour] = 0;
        $chartFailed[$hour] = 0;
        $chartSchool[$hour] = 0;
        $chartBlocked[$hour] = 0;
    }

    $threatPatterns = [
        'ml_assisted_block', 'ml_assisted_strike', 'ml_threat_prediction',
        'malicious_input_detected', 'shell_attack_detected', 'request_threat_detected', 'csp_violation_reported',
        'scanner_user_agent_detected', 'sensitive_path_probe', 'reconnaissance_probe',
        'csrf_validation_failed', 'http_method_blocked', 'http_method_anomaly',
        'endpoint_method_rejected', 'oversized_request_detected', 'oversized_uri_detected',
        'banned_ip_attempt',
        'auth_rejected', 'banned_ip_middleware_block', 'bruteforce_detected', 'ip_banned',
        'school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited', 'password_factor_failed', 'auth_rejected', 'honeypot_triggered',
    ];

    foreach ($auditLines as $line) {
        if (fortress_is_meaningful_event($line)) {
            $lastMeaningfulLine = $line;
        }
        if (str_contains($line, 'login_success')) $lastSuccessfulLoginLine = $line;
        if (str_contains($line, 'school_id_qr_success')) $lastSchoolIdSuccessLine = $line;
        if (fortress_line_has_any($line, $threatPatterns)) $lastThreatLine = $line;

        $eventDate = fortress_event_datetime($line);
        if (!$eventDate || $eventDate < $cutoff24h) continue;

        $hourKey = $eventDate->setTimezone($hourNow->getTimezone())->format('Y-m-d H');
        if (str_contains($line, 'password_factor_failed')) {
            $failedAttempts24h++;
            if (isset($chartFailed[$hourKey])) $chartFailed[$hourKey]++;
        }
        if (str_contains($line, 'password_factor_success')) {
            $successfulPassword24h++;
            if (isset($chartSuccess[$hourKey])) $chartSuccess[$hourKey]++;
        }
        if (str_contains($line, 'school_id_qr_success')) {
            $schoolIdSuccess24h++;
            if (isset($chartSchool[$hourKey])) $chartSchool[$hourKey]++;
        }
        if (str_contains($line, 'school_id_qr_failed') || str_contains($line, 'school_id_qr_locked') || str_contains($line, 'school_id_qr_rate_limited')) {
            $schoolIdFailures24h++;
        }
        if (fortress_line_has_any($line, [
            'ml_assisted_block', 'ml_assisted_strike',
            'malicious_input_detected', 'shell_attack_detected', 'request_threat_detected', 'csp_violation_reported',
            'scanner_user_agent_detected', 'sensitive_path_probe', 'reconnaissance_probe',
            'csrf_validation_failed', 'http_method_blocked', 'http_method_anomaly',
            'endpoint_method_rejected', 'oversized_request_detected', 'oversized_uri_detected',
            'banned_ip_attempt',
        'auth_rejected', 'banned_ip_middleware_block', 'bruteforce_detected'
        ])) {
            $suspiciousRequests24h++;
            if (isset($chartBlocked[$hourKey])) $chartBlocked[$hourKey]++;
        }
        if (str_contains($line, 'bruteforce_detected')) $bruteforce24h++;
        if (str_contains($line, 'banned_ip_attempt') || str_contains($line, 'banned_ip_middleware_block')) $bannedRequest24h++;
        // Count forced browsing as an incident, not as raw auth_rejected log lines.
        // Browsers/proxies can retry or duplicate a navigation, producing two nearly
        // identical auth_rejected entries for one user action. Collapse repeats from
        // the same source/reason that arrive within two seconds.
        if (
            str_contains($line, 'auth_rejected')
            && preg_match('/\buid=0\b/', $line) === 1
            && (
                str_contains($line, 'reason=incomplete_primary_auth')
                || str_contains($line, 'reason=missing_primary_session')
            )
        ) {
            $forcedIp = fortress_log_ip($line);
            $forcedReason = str_contains($line, 'reason=incomplete_primary_auth')
                ? 'incomplete_primary_auth'
                : 'missing_primary_session';
            $forcedKey = $forcedIp . '|' . $forcedReason;
            $forcedTimestamp = $eventDate->getTimestamp();
            $lastForcedTimestamp = (int)($forcedBrowsingLastSeen[$forcedKey] ?? 0);

            if ($lastForcedTimestamp === 0 || ($forcedTimestamp - $lastForcedTimestamp) > 2) {
                $forcedBrowsing24h++;
            }

            $forcedBrowsingLastSeen[$forcedKey] = $forcedTimestamp;
        }
        if (str_contains($line, 'issues=') && str_contains($line, 'sql_attack')) $sqlAttack24h++;
        if (str_contains($line, 'issues=') && str_contains($line, 'xss_attack')) $xssAttack24h++;
        if (str_contains($line, 'issues=') && str_contains($line, 'path_traversal')) $pathAttack24h++;
        if (str_contains($line, 'shell_attack_detected') || (str_contains($line, 'request_threat_detected') && str_contains($line, 'shell'))) $shellAttack24h++;
        if (str_contains($line, 'csrf_validation_failed')) $csrfAttack24h++;
        if (str_contains($line, 'csp_violation_reported')) $cspViolation24h++;
        if (str_contains($line, 'sensitive_path_probe') || str_contains($line, 'reconnaissance_probe')) $reconProbe24h++;
        if (str_contains($line, 'scanner_user_agent_detected')) $scanner24h++;
        if (fortress_line_has_any($line, ['http_method_blocked', 'http_method_anomaly', 'endpoint_method_rejected'])) $methodAnomaly24h++;
        if (fortress_line_has_any($line, ['oversized_request_detected', 'oversized_uri_detected'])) $oversizedRequest24h++;
        if (str_contains($line, 'request_threat_detected') && str_contains($line, 'sqli')) $sqlAttack24h++;
        if (str_contains($line, 'request_threat_detected') && str_contains($line, 'xss')) $xssAttack24h++;
        if (str_contains($line, 'request_threat_detected') && str_contains($line, 'path')) $pathAttack24h++;
    }

    $honeypot24h = 0;
    foreach ($honeypotLines as $line) {
        $dt = fortress_event_datetime($line);
        if ($dt && $dt >= $cutoff24h) $honeypot24h++;
    }

    // Structured database aggregates are the authoritative fast path for
    // rolling metrics. If the query is unavailable, the counters calculated
    // from the local/recent evidence above remain as a safe fallback.
    $totalAuditEvents = count($auditLines);
    $dbMetrics24h = fortress_security_metrics_24h_db($pdo);
    if (is_array($dbMetrics24h)) {
        $totalAuditEvents = max(0, (int)($dbMetrics24h['total_audit_events'] ?? $totalAuditEvents));
        $failedAttempts24h = (int)($dbMetrics24h['failed_passwords'] ?? $failedAttempts24h);
        $successfulPassword24h = (int)($dbMetrics24h['successful_passwords'] ?? $successfulPassword24h);
        $schoolIdSuccess24h = (int)($dbMetrics24h['school_id_success'] ?? $schoolIdSuccess24h);
        $schoolIdFailures24h = (int)($dbMetrics24h['school_id_failures'] ?? $schoolIdFailures24h);
        $suspiciousRequests24h = (int)($dbMetrics24h['suspicious_requests'] ?? $suspiciousRequests24h);
        $bruteforce24h = (int)($dbMetrics24h['brute_force'] ?? $bruteforce24h);
        $bannedRequest24h = (int)($dbMetrics24h['banned_request_hits'] ?? $bannedRequest24h);
        $forcedBrowsing24h = (int)($dbMetrics24h['forced_browsing'] ?? $forcedBrowsing24h);
        $sqlAttack24h = (int)($dbMetrics24h['sql_attacks'] ?? $sqlAttack24h);
        $xssAttack24h = (int)($dbMetrics24h['xss_attacks'] ?? $xssAttack24h);
        $pathAttack24h = (int)($dbMetrics24h['path_attacks'] ?? $pathAttack24h);
        $shellAttack24h = (int)($dbMetrics24h['shell_attacks'] ?? $shellAttack24h);
        $csrfAttack24h = (int)($dbMetrics24h['csrf_attacks'] ?? $csrfAttack24h);
        $cspViolation24h = (int)($dbMetrics24h['csp_violations'] ?? $cspViolation24h);
        $reconProbe24h = (int)($dbMetrics24h['recon_probes'] ?? $reconProbe24h);
        $scanner24h = (int)($dbMetrics24h['scanners'] ?? $scanner24h);
        $methodAnomaly24h = (int)($dbMetrics24h['method_anomalies'] ?? $methodAnomaly24h);
        $oversizedRequest24h = (int)($dbMetrics24h['oversized_requests'] ?? $oversizedRequest24h);
        $honeypot24h = (int)($dbMetrics24h['honeypot_events'] ?? $honeypot24h);
    }

    if ($includeCharts) {
        $dbChartRows = fortress_security_hourly_chart_db($pdo);
        if (is_array($dbChartRows)) {
            foreach ($chartSuccess as $key => $_) {
                $chartSuccess[$key] = 0;
                $chartFailed[$key] = 0;
                $chartSchool[$key] = 0;
                $chartBlocked[$key] = 0;
            }
            foreach ($dbChartRows as $row) {
                $key = (string)($row['hour_key'] ?? '');
                if (!array_key_exists($key, $chartSuccess)) continue;
                $chartSuccess[$key] = (int)($row['password_success'] ?? 0);
                $chartFailed[$key] = (int)($row['password_failed'] ?? 0);
                $chartSchool[$key] = (int)($row['school_success'] ?? 0);
                $chartBlocked[$key] = (int)($row['blocked'] ?? 0);
            }
        }
    }

    $authLines = array_values(array_filter($auditLines, 'fortress_is_auth_event'));
    $recentAuthLines = array_slice(array_reverse($authLines), 0, 12);
    $meaningfulLines = array_values(array_filter($auditLines, 'fortress_is_meaningful_event'));
    $recentLines = array_slice(array_reverse($meaningfulLines), 0, 8);

    $schoolHistory = array_values(array_filter($auditLines, static fn(string $line): bool => fortress_line_has_any($line, [
        'school_id_qr_registered', 'school_id_qr_success', 'school_id_qr_failed', 'school_id_qr_locked', 'school_id_qr_rate_limited',
        'school_id_qr_reset', 'school_id_reverification_started',
    ])));
    $schoolHistory = array_slice(array_reverse($schoolHistory), 0, 20);

    $sessionStart = (int)($_SESSION['logged_in_at'] ?? time());
    $sessionAgeSeconds = max(0, time() - $sessionStart);
    $sessionStartDisplay = date('Y-m-d H:i:s', $sessionStart);
    $clientIp = getRealIP();

    $threatPoints = $failedAttempts24h + ($suspiciousRequests24h * 2) + ($activeBans * 3) + ($schoolIdFailures24h * 2);
    if ($threatPoints >= 8) {
        $threatLevel = 'ELEVATED';
        $threatClass = 'risk-elevated';
    } elseif ($threatPoints >= 3) {
        $threatLevel = 'WATCH';
        $threatClass = 'risk-watch';
    } else {
        $threatLevel = 'LOW';
        $threatClass = 'risk-low';
    }

    $protectedAssets = [
        ['fa-user-shield', 'Administrator identity', 'Only the verified operator can enter privileged areas.'],
        ['fa-key', 'Privileged access', 'Sensitive administrator functions remain behind layered authentication.'],
        ['fa-vault', 'Protected resources', 'Administrator-only system resources stay behind the access gateway.'],
        ['fa-id-card', 'Identity verification flow', $schoolIdRequired
            ? ($schoolIdFactorType === 'generated_qr'
                ? 'This account requires password plus its administrator-issued QR credential.'
                : 'This account requires password plus the registered physical Personal ID.')
            : 'This account is configured for password-only authentication; QR-based 2FA is disabled.'],
        ['fa-clock-rotate-left', 'Audit evidence', 'Security events remain available for investigation and accountability.'],
        ['fa-network-wired', 'Active login session', 'The authenticated session and client IP remain monitored.'],
    ];

    $protectedResources = [
        ['Administrator Dashboard', '/dashboard.php', 'fa-chart-line'],
        ['Security Analytics', '/analytics.php', 'fa-chart-pie'],
        ['Personal ID Management', '/personal_id_manage.php', 'fa-id-card'],
        ['Security Logs', '/admin_logs.php', 'fa-clipboard-list'],
        ['IP Ban Management', '/blocked_ips.php', 'fa-ban'],
        ['Security Controls', '/security_controls.php', 'fa-sliders'],
        ['Administrator User Management', '/user_management.php', 'fa-users-gear'],
    ];

    $timeline = [];
    foreach (array_reverse($auditLines) as $line) {
        $dt = fortress_event_datetime($line);
        if (!$dt || $dt->getTimestamp() < ($sessionStart - 10)) continue;
        if (!fortress_line_has_any($line, [
            'password_factor_success', 'school_id_qr_success', 'school_id_2fa_not_required', 'login_success', 'dashboard_access',
            'school_id_manage_access', 'logout', 'password_factor_failed', 'school_id_qr_failed',
        ])) continue;
        $timeline[] = $line;
        if (count($timeline) >= 7) break;
    }
    $timeline = array_reverse($timeline);

    $topThreatSources = [];
    foreach ($auditLines as $line) {
        $dt = fortress_event_datetime($line);
        if (!$dt || $dt < $cutoff24h || !fortress_line_has_any($line, $threatPatterns)) continue;
        $ip = fortress_log_ip($line);
        if ($ip === 'unknown') continue;
        $topThreatSources[$ip] = ($topThreatSources[$ip] ?? 0) + 1;
    }
    arsort($topThreatSources);
    $topThreatSources = array_slice($topThreatSources, 0, 5, true);

    if ($includeTopThreatSources) {
        $dbTopSources = fortress_top_threat_sources_24h_db($pdo, 5);
        if (is_array($dbTopSources)) {
            $topThreatSources = $dbTopSources;
        }
    }

    $chartLabels = array_map(static fn(string $key): string => substr($key, 11, 2) . ':00', $hourKeys);

    return [
        'user' => $user,
        'usernameRaw' => $usernameRaw,
        'userRole' => $userRole,
        'schoolIdRequired' => $schoolIdRequired,
        'schoolIdEnabled' => $schoolIdEnabled,
        'schoolIdFactorType' => $schoolIdFactorType,
        'schoolIdUpdatedAt' => $schoolIdUpdatedAt,
        'schoolIdVerified' => $schoolIdVerified,
        'activeBans' => $activeBans,
        'allBans' => $allBans,
        'auditLines' => $auditLines,
        'honeypotLines' => $honeypotLines,
        'totalAuditEvents' => $totalAuditEvents,
        'totalHoneypotEvents' => count($honeypotLines),
        'threatCategoryAllTime' => $threatCategoryAllTime,
        'failedAttempts24h' => $failedAttempts24h,
        'successfulPassword24h' => $successfulPassword24h,
        'schoolIdSuccess24h' => $schoolIdSuccess24h,
        'schoolIdFailures24h' => $schoolIdFailures24h,
        'suspiciousRequests24h' => $suspiciousRequests24h,
        'bruteforce24h' => $bruteforce24h,
        'bannedRequest24h' => $bannedRequest24h,
        'forcedBrowsing24h' => $forcedBrowsing24h,
        'sqlAttack24h' => $sqlAttack24h,
        'xssAttack24h' => $xssAttack24h,
        'pathAttack24h' => $pathAttack24h,
        'shellAttack24h' => $shellAttack24h,
        'csrfAttack24h' => $csrfAttack24h,
        'cspViolation24h' => $cspViolation24h,
        'reconProbe24h' => $reconProbe24h,
        'scanner24h' => $scanner24h,
        'methodAnomaly24h' => $methodAnomaly24h,
        'oversizedRequest24h' => $oversizedRequest24h,
        'honeypot24h' => $honeypot24h,
        'blockedRequests24h' => $suspiciousRequests24h + $schoolIdFailures24h,
        'totalLoginAttempts24h' => $failedAttempts24h + $successfulPassword24h,
        'recentLines' => $recentLines,
        'recentAuthLines' => $recentAuthLines,
        'schoolHistory' => $schoolHistory,
        'lastEventLine' => $lastMeaningfulLine,
        'lastEventRelative' => fortress_relative_time($lastMeaningfulLine ? fortress_event_datetime($lastMeaningfulLine) : null),
        'lastThreatRelative' => fortress_relative_time($lastThreatLine ? fortress_event_datetime($lastThreatLine) : null),
        'lastSuccessfulLoginRelative' => fortress_relative_time($lastSuccessfulLoginLine ? fortress_event_datetime($lastSuccessfulLoginLine) : null),
        'lastSchoolIdRelative' => fortress_relative_time($lastSchoolIdSuccessLine ? fortress_event_datetime($lastSchoolIdSuccessLine) : null),
        'lastSchoolIdLine' => $lastSchoolIdSuccessLine,
        'threatLevel' => $threatLevel,
        'threatClass' => $threatClass,
        'threatPoints' => $threatPoints,
        'defenseLayers' => $defenseLayers,
        'activeDefenseCount' => $activeDefenseCount,
        'protectionScore' => $protectionScore,
        'protectionLabel' => $protectionLabel,
        'protectedAssets' => $protectedAssets,
        'protectedResources' => $protectedResources,
        'clientIp' => $clientIp,
        'sessionStart' => $sessionStart,
        'sessionStartDisplay' => $sessionStartDisplay,
        'sessionAgeSeconds' => $sessionAgeSeconds,
        'timeline' => $timeline,
        'topThreatSources' => $topThreatSources,
        'chartLabels' => $chartLabels,
        'chartSuccess' => array_values($chartSuccess),
        'chartFailed' => array_values($chartFailed),
        'chartSchool' => array_values($chartSchool),
        'chartBlocked' => array_values($chartBlocked),
    ];
}
