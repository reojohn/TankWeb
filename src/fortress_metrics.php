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
 * Read audit evidence from durable PostgreSQL storage and merge it with the
 * local audit.log fallback. Exact duplicate entries are removed because the
 * logger intentionally dual-writes the same event to both destinations.
 *
 * The database query is capped to the most recent 10,000 events so dashboard
 * rendering remains bounded even after long-running deployments. All 24-hour
 * metrics and recent timelines therefore remain fully covered.
 */
function fortress_read_persistent_audit_lines(PDO $pdo, string $fallbackPath): array
{
    $fileLines = fortress_read_lines($fallbackPath);
    $databaseLines = [];

    try {
        $stmt = $pdo->query(
            "SELECT raw_line
             FROM (
                 SELECT id, occurred_at, raw_line
                 FROM public.security_events
                 WHERE raw_line IS NOT NULL AND BTRIM(raw_line) <> ''
                 ORDER BY occurred_at DESC, id DESC
                 LIMIT 10000
             ) AS recent_events
             ORDER BY occurred_at ASC, id ASC"
        );
        $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);
        if (is_array($rows)) {
            foreach ($rows as $row) {
                $line = trim((string)$row);
                if ($line !== '') {
                    $databaseLines[] = $line;
                }
            }
        }
    } catch (Throwable $e) {
        // During rollout, local development, or a temporary DB outage, keep
        // the existing flat-file behavior instead of breaking dashboards.
        error_log('FortressAuth security_events read failed: ' . $e->getMessage());
    }

    if (!$databaseLines) {
        return $fileLines;
    }

    // Merge legacy/local-only lines with durable events without double-counting
    // the entries that audit_log() wrote to both destinations.
    $merged = [];
    $seen = [];
    foreach (array_merge($fileLines, $databaseLines) as $line) {
        $line = trim((string)$line);
        if ($line === '') {
            continue;
        }
        $fingerprint = hash('sha256', $line);
        if (isset($seen[$fingerprint])) {
            continue;
        }
        $seen[$fingerprint] = true;
        $merged[] = $line;
    }

    // Keep the same oldest-to-newest ordering audit.log historically used.
    usort($merged, static function (string $a, string $b): int {
        $aDate = fortress_event_datetime($a);
        $bDate = fortress_event_datetime($b);
        if ($aDate && $bDate) {
            $cmp = $aDate->getTimestamp() <=> $bDate->getTimestamp();
            if ($cmp !== 0) {
                return $cmp;
            }
        } elseif ($aDate) {
            return -1;
        } elseif ($bDate) {
            return 1;
        }
        return strcmp($a, $b);
    });

    return $merged;
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
             FROM public.security_events"
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

        // Forced browsing is incident-based rather than raw-line based. Collapse
        // browser/proxy retries from the same source/reason within two seconds.
        $forcedStmt = $pdo->query(
            "SELECT id, occurred_at, source_ip, raw_line, metadata
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
             ORDER BY occurred_at ASC, id ASC"
        );
        $forcedRows = $forcedStmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
        $lastSeen = [];
        foreach ($forcedRows as $forcedRow) {
            $line = (string)($forcedRow['raw_line'] ?? '');
            $metadata = [];
            $rawMetadata = $forcedRow['metadata'] ?? null;
            if (is_string($rawMetadata) && $rawMetadata !== '') {
                $decoded = json_decode($rawMetadata, true);
                if (is_array($decoded)) $metadata = $decoded;
            } elseif (is_array($rawMetadata)) {
                $metadata = $rawMetadata;
            }

            $reason = (string)($metadata['reason'] ?? '');
            if ($reason === '') {
                if (str_contains($line, 'reason=incomplete_primary_auth')) {
                    $reason = 'incomplete_primary_auth';
                } elseif (str_contains($line, 'reason=missing_primary_session')) {
                    $reason = 'missing_primary_session';
                }
            }
            if (!in_array($reason, ['incomplete_primary_auth', 'missing_primary_session'], true)) {
                continue;
            }

            $ip = trim((string)($forcedRow['source_ip'] ?? ''));
            if ($ip === '') {
                $ip = fortress_log_ip($line);
            }
            $key = $ip . '|' . $reason;

            try {
                $timestamp = (new DateTimeImmutable((string)$forcedRow['occurred_at']))->getTimestamp();
            } catch (Throwable $e) {
                $dt = fortress_event_datetime($line);
                if (!$dt) continue;
                $timestamp = $dt->getTimestamp();
            }

            $previous = (int)($lastSeen[$key] ?? 0);
            if ($previous === 0 || ($timestamp - $previous) > 2) {
                $totals['forcedBrowsing']++;
            }
            $lastSeen[$key] = $timestamp;
        }

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

function fortress_build_security_context(PDO $pdo, int $userId): array
{
    $dataPath = __DIR__ . '/../data/';
    $auditLines = fortress_read_persistent_audit_lines($pdo, $dataPath . 'audit.log');
    $honeypotLines = fortress_read_lines($dataPath . 'honeypot_log.txt');
    $threatCategoryAllTime = fortress_all_time_threat_category_totals($pdo, $auditLines, $honeypotLines);

    $policyField = fortress_optional_2fa_policy_available($pdo)
        ? 'school_id_2fa_required'
        : 'TRUE AS school_id_2fa_required';
    $factorTypeField = fortress_second_factor_type_available($pdo)
        ? "COALESCE(second_factor_type, 'personal_id') AS second_factor_type"
        : "'personal_id' AS second_factor_type";
    $roleField = fortress_role_policy_available($pdo)
        ? "COALESCE(role, 'admin') AS role"
        : "'superadmin' AS role";

    $stmt = $pdo->prepare(
        'SELECT username, ' . $policyField . ', ' . $factorTypeField . ', ' . $roleField . ', school_id_qr_enabled, school_id_qr_updated_at
         FROM public.users WHERE id = ? LIMIT 1'
    );
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];

    $usernameRaw = (string)($user['username'] ?? 'Unknown');
    $userRole = fortress_normalize_role($user['role'] ?? 'superadmin');
    $schoolIdRequired = (bool)($user['school_id_2fa_required'] ?? true);
    $schoolIdEnabled = !empty($user['school_id_qr_enabled']);
    $schoolIdFactorType = fortress_second_factor_type_value($user);
    $schoolIdUpdatedAt = $user['school_id_qr_updated_at'] ?? null;
    $schoolIdVerified = $schoolIdRequired && !empty($_SESSION['school_id_verified']);

    $activeBans = 0;
    $allBans = [];
    try {
        $activeBans = (int)$pdo->query("SELECT COUNT(*) FROM banned_ips WHERE banned_until > NOW()")->fetchColumn();
        $banStmt = $pdo->query('SELECT ip, banned_until FROM banned_ips ORDER BY banned_until DESC LIMIT 500');
        $allBans = $banStmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
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
        'totalAuditEvents' => count($auditLines),
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
