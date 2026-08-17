<?php

declare(strict_types=1);

/**
 * FortressAuth security policy.
 *
 * Keep enforcement values and UI labels in one place so the dashboard never
 * advertises limits that differ from the actual backend controls.
 */
function fortress_policy_int(string $env, int $default, int $minimum = 1): int
{
    $raw = getenv($env);
    if ($raw === false || trim((string)$raw) === '' || !is_numeric($raw)) {
        return $default;
    }
    return max($minimum, (int)$raw);
}

function fortress_security_policy(): array
{
    $idle = fortress_policy_int('SESSION_IDLE_TIMEOUT', 900, 300);
    $absolute = fortress_policy_int('SESSION_ABSOLUTE_TIMEOUT', 28800, $idle);

    return [
        'session_idle_seconds' => $idle,
        'session_absolute_seconds' => $absolute,
        'school_id_verification_window_seconds' => fortress_policy_int('SCHOOL_ID_VERIFY_WINDOW', 300, 60),
        'school_id_session_attempt_limit' => fortress_policy_int('SCHOOL_ID_SESSION_ATTEMPT_LIMIT', 5, 1),
        'school_id_ip_attempt_limit' => fortress_policy_int('SCHOOL_ID_IP_ATTEMPT_LIMIT', 10, 1),
        'school_id_account_attempt_limit' => fortress_policy_int('SCHOOL_ID_ACCOUNT_ATTEMPT_LIMIT', 5, 1),
        'school_id_rate_window_seconds' => fortress_policy_int('SCHOOL_ID_RATE_WINDOW', 300, 60),
        'password_ip_failure_limit' => fortress_policy_int('PASSWORD_IP_FAILURE_LIMIT', 5, 1),
        'password_account_failure_limit' => fortress_policy_int('PASSWORD_ACCOUNT_FAILURE_LIMIT', 10, 1),
        'password_failure_window_seconds' => fortress_policy_int('PASSWORD_FAILURE_WINDOW', 900, 60),
        'ip_ban_seconds' => fortress_policy_int('IP_BAN_DURATION', 900, 60),
        'request_body_monitor_bytes' => fortress_policy_int('REQUEST_BODY_MONITOR_BYTES', 1048576, 1024),
        'request_uri_monitor_length' => fortress_policy_int('REQUEST_URI_MONITOR_LENGTH', 2048, 256),

        // Deterministic automated-reconnaissance / fuzzer defense. These
        // thresholds require path-probe or explicit scanner evidence so normal
        // browser asset loading does not become a network ban by itself.
        'recon_probe_limit' => fortress_policy_int('RECON_PROBE_LIMIT', 8, 3),
        'recon_sensitive_probe_limit' => fortress_policy_int('RECON_SENSITIVE_PROBE_LIMIT', 4, 2),
        'recon_request_limit' => fortress_policy_int('RECON_REQUEST_LIMIT', 25, 10),
        'recon_unique_path_limit' => fortress_policy_int('RECON_UNIQUE_PATH_LIMIT', 15, 6),
        'recon_automation_probe_limit' => fortress_policy_int('RECON_AUTOMATION_PROBE_LIMIT', 5, 2),
        'recon_tool_probe_limit' => fortress_policy_int('RECON_TOOL_PROBE_LIMIT', 3, 1),
        'recon_tool_request_limit' => fortress_policy_int('RECON_TOOL_REQUEST_LIMIT', 12, 5),
        'recon_tool_unique_path_limit' => fortress_policy_int('RECON_TOOL_UNIQUE_PATH_LIMIT', 8, 4),
        'recon_ban_seconds' => fortress_policy_int('RECON_BAN_SECONDS', 900, 60),

        'alert_poll_seconds' => fortress_policy_int('SECURITY_ALERT_POLL_SECONDS', 4, 2),
        // Tiny revision check only. Full page content is fetched only when
        // meaningful security state actually changes.
        'live_state_poll_seconds' => fortress_policy_int('SECURITY_LIVE_POLL_SECONDS', 2, 2),
    ];
}

function fortress_policy_minutes(int $seconds): string
{
    $minutes = max(1, (int)ceil($seconds / 60));
    return $minutes . ' minute' . ($minutes === 1 ? '' : 's');
}
