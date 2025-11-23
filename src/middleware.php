<?php
require_once __DIR__ . '/logger.php'; // ensure getRealIP() is available

$ip = getRealIP();

$whitelist = ['127.0.0.1', '::1'];

$banFile = __DIR__ . '/../data/banned_ips.txt';

// Skip banning for localhost
if (!in_array($ip, $whitelist)) {

    // Check if IP is banned
    if (file_exists($banFile)) {
        $banned = file($banFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (in_array($ip, $banned)) {
            http_response_code(403);
            exit("Your IP is banned.");
        }
    }
}

// Security headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: geolocation=(), microphone=()");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none';");

function safe_redirect($url) {
    if (strpos($url, '/') === 0) {
        header("Location: $url");
        exit;
    }
    http_response_code(400);
    exit('Bad redirect');
}
