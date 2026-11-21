<?php

declare(strict_types=1);

/**
 * Runtime FortressAuth defense profiles.
 *
 * The selected mode is persisted in PostgreSQL so every authorized operator
 * sees the same state. A tiny local cache avoids adding a Supabase round-trip
 * to every security-policy lookup; the database remains authoritative and the
 * cache is refreshed at most a few seconds later.
 */

function fortress_security_profile_definitions(): array
{
    return [
        'standard' => [
            'label' => 'STANDARD',
            'title' => 'Standard',
            'description' => 'Normal layered protection with conservative automated response thresholds.',
            'policy' => [
                'password_ip_failure_limit' => 6,
                'password_account_failure_limit' => 12,
                'ip_ban_seconds' => 600,
                'recon_probe_limit' => 10,
                'recon_sensitive_probe_limit' => 5,
                'recon_request_limit' => 30,
                'recon_unique_path_limit' => 18,
                'recon_automation_probe_limit' => 6,
                'recon_tool_probe_limit' => 4,
                'recon_tool_request_limit' => 15,
                'recon_tool_unique_path_limit' => 10,
                'recon_ban_seconds' => 600,
            ],
            'ml' => [
                'strike_risk' => 70.0,
                'repeat_risk' => 78.0,
                'block_risk' => 90.0,
                'min_confidence' => 0.85,
                'repeat_confidence' => 0.88,
                'block_confidence' => 0.93,
                'required_strikes' => 3,
                'ban_seconds' => 600,
            ],
            'queue_replay_limit' => 1,
        ],
        'balanced' => [
            'label' => 'BALANCED',
            'title' => 'Balanced',
            'description' => 'Current FortressAuth policy with strong protection and measured automated enforcement.',
            // Empty overrides intentionally preserve deployment environment values.
            'policy' => [],
            'ml' => [],
            'queue_replay_limit' => null,
        ],
        'fortress_boost' => [
            'label' => 'FORTRESS BOOST',
            'title' => 'Fortress Boost',
            'description' => 'High-alert defense profile with faster corroborated blocking and accelerated ML replay.',
            'policy' => [
                'password_ip_failure_limit' => 3,
                'password_account_failure_limit' => 6,
                'ip_ban_seconds' => 1800,
                'recon_probe_limit' => 6,
                'recon_sensitive_probe_limit' => 3,
                'recon_request_limit' => 20,
                'recon_unique_path_limit' => 12,
                'recon_automation_probe_limit' => 4,
                'recon_tool_probe_limit' => 2,
                'recon_tool_request_limit' => 10,
                'recon_tool_unique_path_limit' => 6,
                'recon_ban_seconds' => 1800,
            ],
            'ml' => [
                'strike_risk' => 60.0,
                'repeat_risk' => 68.0,
                'block_risk' => 82.0,
                'min_confidence' => 0.80,
                'repeat_confidence' => 0.83,
                'block_confidence' => 0.88,
                'required_strikes' => 2,
                'ban_seconds' => 1800,
            ],
            'queue_replay_limit' => 4,
        ],
    ];
}

function fortress_security_profile_normalize(mixed $mode): string
{
    $mode = strtolower(trim((string)$mode));
    return array_key_exists($mode, fortress_security_profile_definitions()) ? $mode : 'balanced';
}

function fortress_security_profile_cache_path(): string
{
    $dir = __DIR__ . '/../data/runtime';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    return $dir . '/security_profile.json';
}

function fortress_security_profile_read_cache(bool $force = false): ?array
{
    if ($force) {
        return null;
    }
    $path = fortress_security_profile_cache_path();
    if (!is_file($path)) {
        return null;
    }
    $decoded = json_decode((string)@file_get_contents($path), true);
    if (!is_array($decoded)) {
        return null;
    }
    $fetchedAt = (int)($decoded['fetched_at'] ?? 0);
    $available = !empty($decoded['available']);
    $ttl = $available ? 5 : 30;
    if ($fetchedAt <= 0 || $fetchedAt < time() - $ttl) {
        return null;
    }
    $decoded['mode'] = fortress_security_profile_normalize($decoded['mode'] ?? 'balanced');
    return $decoded;
}

function fortress_security_profile_write_cache(array $state): void
{
    $record = [
        'mode' => fortress_security_profile_normalize($state['mode'] ?? 'balanced'),
        'available' => !empty($state['available']),
        'changed_by' => isset($state['changed_by']) && is_numeric($state['changed_by']) ? (int)$state['changed_by'] : null,
        'changed_by_username' => trim((string)($state['changed_by_username'] ?? '')),
        'changed_at' => trim((string)($state['changed_at'] ?? '')),
        'fetched_at' => time(),
    ];
    @file_put_contents(
        fortress_security_profile_cache_path(),
        json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    );
}

function fortress_security_profile_state(?PDO $pdo = null, bool $force = false): array
{
    $cached = fortress_security_profile_read_cache($force);
    if (is_array($cached)) {
        return $cached;
    }

    // Resolve the application PDO from the global configuration when callers
    // do not explicitly provide it.
    if (!$pdo instanceof PDO && isset($GLOBALS['pdo']) && $GLOBALS['pdo'] instanceof PDO) {
        $pdo = $GLOBALS['pdo'];
    }

    $fallback = [
        'mode' => 'balanced',
        'available' => false,
        'changed_by' => null,
        'changed_by_username' => '',
        'changed_at' => '',
        'fetched_at' => time(),
    ];

    if (!$pdo instanceof PDO) {
        fortress_security_profile_write_cache($fallback);
        return $fallback;
    }

    try {
        $stmt = $pdo->query(
            "SELECT mode, changed_by, changed_by_username, changed_at\n" .
            "FROM public.security_runtime_settings\n" .
            "WHERE singleton_id = 1\n" .
            "LIMIT 1"
        );
        $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
        $state = [
            'mode' => fortress_security_profile_normalize($row['mode'] ?? 'balanced'),
            'available' => true,
            'changed_by' => isset($row['changed_by']) && is_numeric($row['changed_by']) ? (int)$row['changed_by'] : null,
            'changed_by_username' => trim((string)($row['changed_by_username'] ?? '')),
            'changed_at' => trim((string)($row['changed_at'] ?? '')),
            'fetched_at' => time(),
        ];
        fortress_security_profile_write_cache($state);
        return $state;
    } catch (Throwable $e) {
        // Missing migration or a temporary DB issue must never weaken/interrupt
        // the application. Balanced remains the safe compatibility profile.
        fortress_security_profile_write_cache($fallback);
        return $fallback;
    }
}

function fortress_security_profile_mode(): string
{
    return fortress_security_profile_normalize(fortress_security_profile_state()['mode'] ?? 'balanced');
}

function fortress_security_profile_definition(?string $mode = null): array
{
    $mode = fortress_security_profile_normalize($mode ?? fortress_security_profile_mode());
    return fortress_security_profile_definitions()[$mode];
}

function fortress_security_profile_policy_overrides(?string $mode = null): array
{
    return (array)(fortress_security_profile_definition($mode)['policy'] ?? []);
}

function fortress_security_profile_ml_overrides(?string $mode = null): array
{
    return (array)(fortress_security_profile_definition($mode)['ml'] ?? []);
}

function fortress_security_profile_queue_replay_limit(?string $mode = null): ?int
{
    $value = fortress_security_profile_definition($mode)['queue_replay_limit'] ?? null;
    return is_numeric($value) ? max(1, min(5, (int)$value)) : null;
}

function fortress_security_profile_update(PDO $pdo, string $mode, int $userId, string $username): array
{
    $requestedMode = strtolower(trim($mode));
    if (!array_key_exists($requestedMode, fortress_security_profile_definitions())) {
        throw new InvalidArgumentException('Invalid FortressAuth defense profile.');
    }
    $mode = $requestedMode;

    try {
        $stmt = $pdo->prepare(
            "INSERT INTO public.security_runtime_settings (singleton_id, mode, changed_by, changed_by_username, changed_at)\n" .
            "VALUES (1, :mode, :changed_by, :username, NOW())\n" .
            "ON CONFLICT (singleton_id) DO UPDATE SET\n" .
            "  mode = EXCLUDED.mode,\n" .
            "  changed_by = EXCLUDED.changed_by,\n" .
            "  changed_by_username = EXCLUDED.changed_by_username,\n" .
            "  changed_at = NOW()\n" .
            "RETURNING mode, changed_by, changed_by_username, changed_at"
        );
        $stmt->execute([
            'mode' => $mode,
            'changed_by' => $userId > 0 ? $userId : null,
            'username' => substr(trim($username), 0, 160),
        ]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        throw new RuntimeException('Runtime settings table is not installed. Apply sql/security_runtime_settings.sql in Supabase first.');
    }

    $state = [
        'mode' => fortress_security_profile_normalize($row['mode'] ?? $mode),
        'available' => true,
        'changed_by' => isset($row['changed_by']) && is_numeric($row['changed_by']) ? (int)$row['changed_by'] : null,
        'changed_by_username' => trim((string)($row['changed_by_username'] ?? $username)),
        'changed_at' => trim((string)($row['changed_at'] ?? '')),
        'fetched_at' => time(),
    ];
    fortress_security_profile_write_cache($state);
    return $state;
}
