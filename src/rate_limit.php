    <?php
// src/rate_limit.php
// Simple per-IP limiter using temporary files.
// For production, use Redis or DB-based counters.

function rate_limit_check($action = 'login', $limit = 3, $window_seconds = 60) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $dir = sys_get_temp_dir() . "/fa_rl_$action";
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $file = $dir . '/' . hash('sha256', $ip);
    $now = time();
    $data = [];

    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        $data = json_decode($raw, true) ?: [];
        // keep timestamps within window
        $data = array_filter($data, function($t) use ($now, $window_seconds) {
            return ($t + $window_seconds) >= $now;
        });
    }

    if (count($data) >= $limit) {
        return false;
    }

    $data[] = $now;
    @file_put_contents($file, json_encode($data), LOCK_EX);
    return true;
}
