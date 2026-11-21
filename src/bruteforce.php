<?php

declare(strict_types=1);

require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/security_policy.php';

function record_login_attempt(PDO $pdo, string $ip, string $username, bool $success): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO login_attempts (ip_address, username, success, attempted_at)
         VALUES (:ip, :username, :success, NOW())'
    );
    $stmt->bindValue(':ip', $ip, PDO::PARAM_STR);
    $stmt->bindValue(':username', $username, PDO::PARAM_STR);
    $stmt->bindValue(':success', $success, PDO::PARAM_BOOL);
    $stmt->execute();

    audit_log('login_attempt recorded user=' . preg_replace('/[^A-Za-z0-9_\-]/', '_', $username) . ' success=' . ($success ? '1' : '0'));
}

function failed_attempt_count(PDO $pdo, string $ip, string $username, int $minutes = 15): array
{
    /*
     * Count only the current failure streak. A successful authentication
     * resets the active brute-force counter without deleting historical
     * login_attempt rows, so the audit trail remains intact.
     *
     * Previously every failure inside the time window remained active even
     * after a successful login. That could eventually lock out a legitimate
     * operator who had already authenticated successfully between mistakes.
     */
    $stmt = $pdo->prepare(
        "WITH recent AS (
            SELECT ip_address, username, success, attempted_at
            FROM login_attempts
            WHERE attempted_at > NOW() - (CAST(? AS INTEGER) * INTERVAL '1 minute')
         ), last_success AS (
            SELECT
                MAX(attempted_at) FILTER (WHERE success = TRUE AND ip_address = ?) AS ip_success_at,
                MAX(attempted_at) FILTER (WHERE success = TRUE AND LOWER(username) = LOWER(?)) AS account_success_at
            FROM recent
         )
         SELECT
            COUNT(*) FILTER (
                WHERE recent.success = FALSE
                  AND recent.ip_address = ?
                  AND (last_success.ip_success_at IS NULL OR recent.attempted_at > last_success.ip_success_at)
            ) AS ip_failures,
            COUNT(*) FILTER (
                WHERE recent.success = FALSE
                  AND LOWER(recent.username) = LOWER(?)
                  AND (last_success.account_success_at IS NULL OR recent.attempted_at > last_success.account_success_at)
            ) AS account_failures
         FROM recent
         CROSS JOIN last_success"
    );
    $stmt->execute([
        $minutes,
        $ip,
        $username,
        $ip,
        $username,
    ]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    return [
        'ip' => (int)($row['ip_failures'] ?? 0),
        'account' => (int)($row['account_failures'] ?? 0),
    ];
}

function too_many_failed_attempts(PDO $pdo, string $ip, string $username = '', ?int $ipLimit = null, ?int $accountLimit = null, ?int $minutes = null): bool
{
    $policy = fortress_security_policy();
    $ipLimit ??= (int)$policy['password_ip_failure_limit'];
    $accountLimit ??= (int)$policy['password_account_failure_limit'];
    $minutes ??= max(1, (int)ceil(((int)$policy['password_failure_window_seconds']) / 60));
    $counts = failed_attempt_count($pdo, $ip, $username, $minutes);
    $blocked = $counts['ip'] >= $ipLimit || ($username !== '' && $counts['account'] >= $accountLimit);

    if ($blocked) {
        audit_log('bruteforce_detected ip_failures=' . $counts['ip'] . ' account_failures=' . $counts['account']);
    }

    return $blocked;
}

// Retained for compatibility, but successful authentication no longer erases
// forensic evidence of recent failed attempts.
function clear_failed_attempts(PDO $pdo, string $ip): void
{
    audit_log('failed_attempt_history_retained');
}

function is_ip_banned(PDO $pdo, string $ip): bool
{
    $stmt = $pdo->prepare('SELECT banned_until FROM banned_ips WHERE ip = :ip LIMIT 1');
    $stmt->execute(['ip' => $ip]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return false;
    }

    $bannedUntil = strtotime((string)$row['banned_until']);
    if ($bannedUntil !== false && $bannedUntil > time()) {
        return true;
    }

    $stmt = $pdo->prepare('DELETE FROM banned_ips WHERE ip = :ip');
    $stmt->execute(['ip' => $ip]);
    return false;
}

function ban_ip(PDO $pdo, string $ip, ?int $durationSeconds = null): void
{
    $durationSeconds ??= (int)fortress_security_policy()['ip_ban_seconds'];
    $until = date('Y-m-d H:i:s', time() + max(60, $durationSeconds));

    $stmt = $pdo->prepare(
        'INSERT INTO banned_ips (ip, banned_until)
         VALUES (:ip, :until)
         ON CONFLICT (ip) DO UPDATE SET banned_until = EXCLUDED.banned_until'
    );
    $stmt->execute(['ip' => $ip, 'until' => $until]);

    audit_log('ip_banned until=' . $until);
}
