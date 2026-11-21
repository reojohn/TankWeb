<?php
/**
 * IT113 demo rate limiting. All publicly hosted inference and history requests
 * MUST use the same Supabase/PostgreSQL counters. No file-based cloud fallback.
 * No usernames, raw IPs, credentials, or model inputs are stored here.
 */
declare(strict_types=1);

require_once __DIR__ . '/it113_public_store.php';

function it113_limit_is_loopback(): bool {
    $host = strtolower((string)(parse_url('http://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST) ?: ''));
    $peer = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    return in_array($host, ['127.0.0.1', 'localhost', '::1'], true)
        && in_array($peer, ['127.0.0.1', '::1'], true);
}

function it113_limit_is_configured(): bool {
    $secret = (string)(getenv('IT113_RATE_LIMIT_SECRET') ?: '');
    return (string)(getenv('IT113_RATE_LIMIT_MODE') ?: '') === 'database'
        && strlen($secret) >= 32 && strlen($secret) <= 256
        && !preg_match('/^(REPLACE|CHOOSE|CHANGE)/i', $secret)
        && it113_store_enabled();
}

/** Return 'allowed', 'limited' or 'unavailable'. */
function it113_shared_limit(string $action): string {
    $limits = [
        'infer' => [10, 60, 20, 180],
        'read' => [30, 300, 120, 1200],
        'write' => [12, 80, 30, 240],
    ];
    if (!isset($limits[$action]) || !it113_limit_is_configured()) return 'unavailable';
    $pdo = it113_store_db();
    if (!$pdo) return 'unavailable';

    $secret = (string)getenv('IT113_RATE_LIMIT_SECRET');
    // REMOTE_ADDR is the immediate peer supplied by the web server, not a
    // user-supplied X-Forwarded-For/CF-Connecting-IP header. If the cloud ingress
    // collapses peers into one IP, limits become stricter, never weaker.
    $peer = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $now = time();
    [$perMinute, $perDay, $globalMinute, $globalDay] = $limits[$action];
    $buckets = [
        ['peer', $peer, 'minute', intdiv($now, 60), $perMinute, (intdiv($now, 60)+1)*60],
        ['peer', $peer, 'day', intdiv($now, 86400), $perDay, (intdiv($now, 86400)+1)*86400],
        ['global', 'all', 'minute', intdiv($now, 60), $globalMinute, (intdiv($now, 60)+1)*60],
        ['global', 'all', 'day', intdiv($now, 86400), $globalDay, (intdiv($now, 86400)+1)*86400],
    ];
    try {
        $pdo->beginTransaction();
        // Atomic counters ensure concurrent PHP workers and Render instances
        // cannot each independently spend the same assessment allowance.
        $stmt = $pdo->prepare('INSERT INTO public.it113_demo_rate_buckets AS bucket
            (bucket_key, hits, expires_at) VALUES (:key, 1, to_timestamp(:expiry))
            ON CONFLICT (bucket_key) DO UPDATE
              SET hits = bucket.hits + 1
              WHERE bucket.hits < :cap
            RETURNING hits');
        foreach ($buckets as [$kind, $subject, $period, $index, $cap, $expiry]) {
            $key = hash_hmac('sha256', 'v1|' . $action . '|' . $kind . '|' . $subject . '|' . $period . '|' . $index, $secret);
            $stmt->execute([':key'=>$key, ':expiry'=>$expiry, ':cap'=>$cap]);
            if ($stmt->fetchColumn() === false) {
                $pdo->rollBack();
                return 'limited';
            }
            $stmt->closeCursor();
        }
        $pdo->commit();
        // A small bounded chance of pruning expired anonymous counters.
        if (random_int(1, 100) === 1) {
            try { $pdo->exec("DELETE FROM public.it113_demo_rate_buckets WHERE expires_at < NOW() - INTERVAL '1 day'"); }
            catch (Throwable) { /* Never affect an already allowed request. */ }
        }
        return 'allowed';
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        // Never reveal SQL queries, private DB hostname or credentials.
        it113_store_log_error('shared rate limiting', $error);
        return 'unavailable';
    }
}

/** Retain the original local-only, file-locked rate limiter for school labs. */
function it113_local_limit(string $action): string {
    if (!it113_limit_is_loopback()) return 'unavailable';
    $limits = ['infer'=>[10,100], 'read'=>[60,1000], 'write'=>[20,200]];
    if (!isset($limits[$action])) return 'unavailable';
    $path = __DIR__ . '/../data/it113_demo_rates';
    if (!is_dir($path) && !@mkdir($path, 0700, true) && !is_dir($path)) return 'unavailable';
    $name = hash('sha256', $action . '|' . date('Y-m-d') . '|' . ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'));
    $handle = @fopen($path . '/' . $name . '.json', 'c+');
    if (!$handle) return 'unavailable';
    try {
        if (!flock($handle, LOCK_EX)) return 'unavailable';
        $state = json_decode((string)stream_get_contents($handle), true);
        $times = is_array($state['times'] ?? null) ? $state['times'] : [];
        $now = time();
        $times = array_values(array_filter($times, fn($ts) => is_int($ts) && $ts > $now - 86400));
        [$min,$day] = $limits[$action];
        if (count($times) >= $day || count(array_filter($times, fn($t) => $t > $now-60)) >= $min) return 'limited';
        $times[] = $now;
        rewind($handle); ftruncate($handle, 0);
        if (fwrite($handle, json_encode(['times'=>$times], JSON_THROW_ON_ERROR)) === false) return 'unavailable';
        fflush($handle);
        return 'allowed';
    } catch (Throwable) {
        return 'unavailable';
    } finally {
        flock($handle, LOCK_UN); fclose($handle);
    }
}

function it113_demo_limit(string $action): string {
    if (it113_limit_is_configured()) return it113_shared_limit($action);
    if (it113_limit_is_loopback() && (string)(getenv('IT113_RATE_LIMIT_MODE') ?: '') !== 'database') {
        return it113_local_limit($action);
    }
    // Public Render services cannot fall back to per-instance local files.
    return 'unavailable';
}
