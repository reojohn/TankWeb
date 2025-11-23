<?php
// src/logger.php

// Get real IP even behind Render / Cloudflare / proxies
function getRealIP() {
    $keys = [
        'HTTP_CF_CONNECTING_IP',   // Cloudflare
        'HTTP_X_FORWARDED_FOR',    // Proxies / Render
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR'
    ];

    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ipList = explode(',', $_SERVER[$key]);
            return trim($ipList[0]);
        }
    }
    return 'unknown';
}

function audit_log($message) {
    $file = __DIR__ . '/../data/audit.log';

    // Prevent log injection
    $safe_message = str_replace(["\n", "\r"], ["\\n", "\\r"], $message);

    $time = (new DateTime('now', new DateTimeZone('UTC')))
            ->format('Y-m-d H:i:sP');

    $ip = getRealIP();
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    // Sanitize
    $ip = filter_var($ip, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $ua = substr(filter_var($ua, FILTER_SANITIZE_FULL_SPECIAL_CHARS), 0, 200);

    $entry = "[$time] ip=$ip ua=$ua $safe_message\n";

    @file_put_contents($file, $entry, FILE_APPEND | LOCK_EX);
}
