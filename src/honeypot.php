<?php

declare(strict_types=1);

require_once __DIR__ . '/security_policy.php';
require_once __DIR__ . '/error_pages.php';

$ip = function_exists('getRealIP') ? getRealIP() : (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$logFile = __DIR__ . '/../data/honeypot_log.txt';
$safeIp = (string)(getenv('HONEYPOT_SAFE_IP') ?: '127.0.0.1');
$time = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:sP');

@file_put_contents($logFile, sprintf('[%s] visit ip=%s%s', $time, $ip, PHP_EOL), FILE_APPEND | LOCK_EX);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    @file_put_contents($logFile, sprintf('[%s] login_attempt ip=%s%s', $time, $ip, PHP_EOL), FILE_APPEND | LOCK_EX);
    audit_log('honeypot_triggered');

    if ($ip !== $safeIp) {
        if (isset($pdo) && $pdo instanceof PDO && function_exists('ban_ip')) {
            ban_ip($pdo, $ip, (int)fortress_security_policy()['ip_ban_seconds']);
        }
        fortress_render_security_error(403, 'honeypot_triggered');
    }

    header('Location: /admin.php?error=1');
    exit;
}
