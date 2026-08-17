<?php

declare(strict_types=1);

require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/security_policy.php';
require_once __DIR__ . '/bruteforce.php';
require_once __DIR__ . '/error_pages.php';

/**
 * Deterministic automated-reconnaissance / fuzzer defense.
 *
 * The control intentionally does not depend on the ML service. It keeps a tiny
 * per-IP, instance-local rolling state so bursty path enumeration can be
 * stopped immediately without writing every ordinary request to PostgreSQL.
 * When PostgreSQL is available, the resulting temporary ban is also persisted
 * through the existing banned_ips table.
 */
function fortress_recon_env_bool(string $name, bool $default = false): bool
{
    $raw = getenv($name);
    if ($raw === false || trim((string)$raw) === '') {
        return $default;
    }
    return filter_var($raw, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? $default;
}

function fortress_recon_enabled(): bool
{
    return fortress_recon_env_bool('RECON_DEFENSE_ENABLED', true);
}

function fortress_recon_tool_name(string $userAgent): ?string
{
    $ua = strtolower(trim($userAgent));
    if ($ua === '') {
        return null;
    }

    // High-signal scanner/fuzzer identifiers only. Generic curl/wget traffic is
    // still visible to the existing monitor, but is not enough by itself to
    // activate deterministic fuzzer enforcement.
    $tools = [
        'ffuf' => ['ffuf', 'fuzz faster u fool'],
        'gobuster' => ['gobuster'],
        'feroxbuster' => ['feroxbuster'],
        'dirsearch' => ['dirsearch'],
        'dirbuster' => ['dirbuster'],
        'wfuzz' => ['wfuzz'],
        'nuclei' => ['nuclei'],
        'nikto' => ['nikto'],
        'sqlmap' => ['sqlmap'],
        'acunetix' => ['acunetix'],
        'wapiti' => ['wapiti'],
    ];

    foreach ($tools as $name => $needles) {
        foreach ($needles as $needle) {
            if (str_contains($ua, $needle)) {
                return $name;
            }
        }
    }

    return null;
}

function fortress_recon_exempt(string $ip): bool
{
    $exempt = fortress_recon_env_bool('RECON_ENFORCEMENT_EXEMPT_LOOPBACK', true)
        ? ['127.0.0.1', '::1']
        : [];

    $configured = trim((string)(getenv('RECON_ENFORCEMENT_EXEMPT_IPS') ?: ''));
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

function fortress_recon_state_dir(): string
{
    $dir = __DIR__ . '/../data/recon';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    return $dir;
}

function fortress_recon_state_path(string $ip): string
{
    return fortress_recon_state_dir() . '/ip_' . hash('sha256', $ip) . '.json';
}

function fortress_recon_prune_state(array $state, int $now): array
{
    $state['requests'] = array_values(array_filter(
        is_array($state['requests'] ?? null) ? $state['requests'] : [],
        static fn($entry): bool => is_array($entry) && (int)($entry[0] ?? 0) >= $now - 300
    ));
    $state['probes'] = array_values(array_filter(
        is_array($state['probes'] ?? null) ? $state['probes'] : [],
        static fn($entry): bool => is_array($entry) && (int)($entry[0] ?? 0) >= $now - 300
    ));
    $state['scanner_hits'] = array_values(array_filter(
        is_array($state['scanner_hits'] ?? null) ? $state['scanner_hits'] : [],
        static fn($entry): bool => is_array($entry) && (int)($entry[0] ?? 0) >= $now - 300
    ));

    // Hard caps keep the state small even under extreme concurrency. Normal
    // enforcement occurs long before these caps are reached.
    $state['requests'] = array_slice($state['requests'], -320);
    $state['probes'] = array_slice($state['probes'], -120);
    $state['scanner_hits'] = array_slice($state['scanner_hits'], -120);
    $state['blocked_until'] = max(0, (int)($state['blocked_until'] ?? 0));
    $state['last_detection_log'] = max(0, (int)($state['last_detection_log'] ?? 0));
    $state['last_block_hit_log'] = max(0, (int)($state['last_block_hit_log'] ?? 0));

    return $state;
}

/**
 * Execute a locked update against one compact per-IP state file.
 * Returns [updated state, callback metadata].
 */
function fortress_recon_update_state(string $ip, callable $mutator): array
{
    $path = fortress_recon_state_path($ip);
    $handle = @fopen($path, 'c+');
    if (!$handle) {
        $state = fortress_recon_prune_state([], time());
        $meta = $mutator($state);
        return [$state, is_array($meta) ? $meta : []];
    }

    $locked = @flock($handle, LOCK_EX);
    @rewind($handle);
    $raw = stream_get_contents($handle);
    $decoded = is_string($raw) && trim($raw) !== '' ? json_decode($raw, true) : [];
    $state = fortress_recon_prune_state(is_array($decoded) ? $decoded : [], time());

    $meta = $mutator($state);
    $state = fortress_recon_prune_state($state, time());

    $encoded = json_encode($state, JSON_UNESCAPED_SLASHES);
    if (is_string($encoded)) {
        @rewind($handle);
        @ftruncate($handle, 0);
        @fwrite($handle, $encoded);
        @fflush($handle);
    }

    if ($locked) {
        @flock($handle, LOCK_UN);
    }
    @fclose($handle);

    return [$state, is_array($meta) ? $meta : []];
}

function fortress_recon_stats(array $state, int $now): array
{
    $requests = is_array($state['requests'] ?? null) ? $state['requests'] : [];
    $probes = is_array($state['probes'] ?? null) ? $state['probes'] : [];
    $scannerHits = is_array($state['scanner_hits'] ?? null) ? $state['scanner_hits'] : [];

    $request60 = array_values(array_filter($requests, static fn(array $r): bool => (int)($r[0] ?? 0) >= $now - 60));
    $request300 = array_values(array_filter($requests, static fn(array $r): bool => (int)($r[0] ?? 0) >= $now - 300));
    $probe60 = array_values(array_filter($probes, static fn(array $p): bool => (int)($p[0] ?? 0) >= $now - 60));
    $probe300 = array_values(array_filter($probes, static fn(array $p): bool => (int)($p[0] ?? 0) >= $now - 300));
    $sensitive300 = array_values(array_filter($probe300, static fn(array $p): bool => !empty($p[1])));
    $scanner60 = array_values(array_filter($scannerHits, static fn(array $s): bool => (int)($s[0] ?? 0) >= $now - 60));

    $uniquePaths = [];
    foreach ($request300 as $entry) {
        $hash = (string)($entry[1] ?? '');
        if ($hash !== '') {
            $uniquePaths[$hash] = true;
        }
    }

    return [
        'requests_1m' => count($request60),
        'requests_5m' => count($request300),
        'unique_paths_5m' => count($uniquePaths),
        'probes_1m' => count($probe60),
        'probes_5m' => count($probe300),
        'sensitive_probes_5m' => count($sensitive300),
        'scanner_hits_1m' => count($scanner60),
    ];
}

function fortress_recon_detection_reason(array $stats, ?string $tool): ?string
{
    $policy = fortress_security_policy();

    if ((int)$stats['probes_1m'] >= (int)$policy['recon_probe_limit']) {
        return 'probe_burst';
    }

    if ((int)$stats['sensitive_probes_5m'] >= (int)$policy['recon_sensitive_probe_limit']) {
        return 'sensitive_path_sweep';
    }

    if ($tool !== null && (int)$stats['probes_5m'] >= (int)$policy['recon_tool_probe_limit']) {
        return 'identified_scanner_probe';
    }

    if (
        (int)$stats['requests_1m'] >= (int)$policy['recon_request_limit'] &&
        (int)$stats['unique_paths_5m'] >= (int)$policy['recon_unique_path_limit'] &&
        (int)$stats['probes_5m'] >= (int)$policy['recon_automation_probe_limit']
    ) {
        return 'automated_path_sweep';
    }

    if (
        $tool !== null &&
        (int)$stats['requests_1m'] >= (int)$policy['recon_tool_request_limit'] &&
        (int)$stats['unique_paths_5m'] >= (int)$policy['recon_tool_unique_path_limit']
    ) {
        return 'identified_scanner_sweep';
    }

    return null;
}

function fortress_recon_log_fields(string $event, string $reason, array $stats, ?string $tool, int $banSeconds = 0, string $action = ''): void
{
    $parts = [
        $event,
        'reason=' . fortress_log_safe_value($reason),
        'requests_1m=' . (int)($stats['requests_1m'] ?? 0),
        'unique_paths_5m=' . (int)($stats['unique_paths_5m'] ?? 0),
        'probes_1m=' . (int)($stats['probes_1m'] ?? 0),
        'probes_5m=' . (int)($stats['probes_5m'] ?? 0),
        'sensitive_5m=' . (int)($stats['sensitive_probes_5m'] ?? 0),
        'scanner=' . fortress_log_safe_value($tool ?? 'behavioral'),
    ];
    if ($banSeconds > 0) {
        $parts[] = 'ban_seconds=' . $banSeconds;
    }
    if ($action !== '') {
        $parts[] = 'action=' . fortress_log_safe_value($action);
    }
    audit_log(implode(' ', $parts));
}

/**
 * Record one normal application request. This executes from middleware before
 * the request monitor and does not generate an audit event per request.
 */
function fortress_recon_observe_request(): void
{
    if (!fortress_recon_enabled()) {
        return;
    }
    if (defined('FORTRESS_BACKGROUND_REQUEST') && FORTRESS_BACKGROUND_REQUEST === true) {
        return;
    }

    $ip = getRealIP();
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return;
    }

    $now = time();
    $uri = (string)($_SERVER['REQUEST_URI'] ?? '/');
    $path = parse_url($uri, PHP_URL_PATH);
    $path = is_string($path) && $path !== '' ? substr($path, 0, 500) : '/';
    $pathHash = substr(hash('sha256', strtolower($path)), 0, 20);
    $tool = fortress_recon_tool_name((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    $exempt = fortress_recon_exempt($ip);

    [$state, $meta] = fortress_recon_update_state($ip, static function (array &$state) use ($now, $pathHash, $tool, $exempt): array {
        $state['requests'][] = [$now, $pathHash];
        if ($tool !== null) {
            $state['scanner_hits'][] = [$now, $tool];
        }

        $stats = fortress_recon_stats($state, $now);
        $reason = fortress_recon_detection_reason($stats, $tool);
        $alreadyBlocked = (int)($state['blocked_until'] ?? 0) > $now;
        $logExempt = false;
        $logLocalBlockHit = false;

        if ($alreadyBlocked && !$exempt && (int)($state['last_block_hit_log'] ?? 0) < $now - 10) {
            $state['last_block_hit_log'] = $now;
            $logLocalBlockHit = true;
        }

        if ($reason !== null && $exempt && (int)($state['last_detection_log'] ?? 0) < $now - 60) {
            $state['last_detection_log'] = $now;
            $logExempt = true;
        }

        return [
            'stats' => $stats,
            'reason' => $reason,
            'already_blocked' => $alreadyBlocked,
            'log_exempt' => $logExempt,
            'log_local_block_hit' => $logLocalBlockHit,
        ];
    });

    $stats = (array)($meta['stats'] ?? fortress_recon_stats($state, $now));
    $reason = is_string($meta['reason'] ?? null) ? (string)$meta['reason'] : null;

    if (!empty($meta['log_exempt']) && $reason !== null) {
        fortress_recon_log_fields('automated_recon_detected', $reason, $stats, $tool, 0, 'observe_exempt');
    }

    if (!empty($meta['already_blocked']) && !$exempt) {
        if (!empty($meta['log_local_block_hit'])) {
            fortress_recon_log_fields('automated_recon_blocked_source_attempt', 'active_local_recon_ban', $stats, $tool, 0, 'blocked');
        }
        fortress_render_security_error(403, 'automated_recon_temporary_ban');
    }

    // A scanner can enumerate real endpoints too. If its explicit tool
    // fingerprint plus request/unique-path behavior reaches the deterministic
    // threshold, block it even before a 404 probe is necessary.
    if ($reason !== null && !$exempt && str_starts_with($reason, 'identified_scanner_')) {
        fortress_recon_activate_block($ip, $reason, $stats, $tool);
    }
}

/**
 * Register an unknown/sensitive path probe from security_probe.php and enforce
 * once deterministic reconnaissance thresholds are met.
 */
function fortress_recon_register_probe(string $path, bool $sensitive = false): void
{
    if (!fortress_recon_enabled()) {
        return;
    }

    $ip = getRealIP();
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return;
    }

    $now = time();
    $tool = fortress_recon_tool_name((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    $exempt = fortress_recon_exempt($ip);

    [$state, $meta] = fortress_recon_update_state($ip, static function (array &$state) use ($now, $sensitive, $tool, $exempt): array {
        $state['probes'][] = [$now, $sensitive ? 1 : 0];
        $stats = fortress_recon_stats($state, $now);
        $reason = fortress_recon_detection_reason($stats, $tool);
        $logExempt = false;

        if ($reason !== null && $exempt && (int)($state['last_detection_log'] ?? 0) < $now - 60) {
            $state['last_detection_log'] = $now;
            $logExempt = true;
        }

        return [
            'stats' => $stats,
            'reason' => $reason,
            'log_exempt' => $logExempt,
        ];
    });

    $stats = (array)($meta['stats'] ?? fortress_recon_stats($state, $now));
    $reason = is_string($meta['reason'] ?? null) ? (string)$meta['reason'] : null;

    if ($reason === null) {
        return;
    }

    if ($exempt) {
        if (!empty($meta['log_exempt'])) {
            fortress_recon_log_fields('automated_recon_detected', $reason, $stats, $tool, 0, 'observe_exempt');
        }
        return;
    }

    fortress_recon_activate_block($ip, $reason, $stats, $tool);
}

function fortress_recon_activate_block(string $ip, string $reason, array $stats, ?string $tool): never
{
    $policy = fortress_security_policy();
    $banSeconds = (int)$policy['recon_ban_seconds'];
    $now = time();

    // Set the local ban first. Even if the database is temporarily unavailable,
    // the current instance keeps rejecting this source for the ban window.
    fortress_recon_update_state($ip, static function (array &$state) use ($now, $banSeconds): array {
        $state['blocked_until'] = max((int)($state['blocked_until'] ?? 0), $now + $banSeconds);
        $state['last_block_hit_log'] = $now;
        return [];
    });

    $persistence = 'local_fallback';
    global $pdo;
    if (isset($pdo) && $pdo instanceof PDO) {
        try {
            ban_ip($pdo, $ip, $banSeconds);
            $persistence = 'database_and_local';
        } catch (Throwable $e) {
            error_log('FortressAuth automated recon ban persistence failed: ' . $e->getMessage());
        }
    }

    fortress_recon_log_fields('automated_recon_block', $reason, $stats, $tool, $banSeconds, $persistence);
    fortress_render_security_error(403, 'automated_recon_temporary_ban');
}
