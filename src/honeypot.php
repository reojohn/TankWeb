<?php

$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$logFile = __DIR__ . '/../data/honeypot_log.txt';

// ➤ DEV MODE — your IP won’t get banned (change to your IP)
$SAFE_IP = "127.0.0.1";  // update to your real IP if needed

// Log ANY visit
file_put_contents($logFile, "[" . date("Y-m-d H:i:s") . "] Visit from IP: $ip\n", FILE_APPEND);

// If POST request → someone is trying to login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    file_put_contents($logFile, "[" . date("Y-m-d H:i:s") . "] LOGIN ATTEMPT from $ip\n", FILE_APPEND);

    // If not developer → BAN THEM
    if ($ip !== $SAFE_IP) {
        $banFile = __DIR__ . '/../data/banned_ips.txt';
        file_put_contents($banFile, $ip . "\n", FILE_APPEND);

        http_response_code(403);
        exit("Access Denied (Honeypot Triggered)");
    }

    // Developer testing → allow harmless redirect
    header("Location: /admin.php?error=1");
    exit;
}
