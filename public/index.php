<?php

declare(strict_types=1);

$path = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';

/*
 * PHP's built-in development server searches parent directories for an
 * index.php when the requested path does not exist. Use that native fallback
 * instead of a custom router file so local Aegis AI can capture
 * reconnaissance while still being started with:
 *
 *     php -S localhost:8082 -t public
 *
 * Real files/directories such as /app/, /login.php, CSS, JS and images are
 * served by PHP before this file is involved. Only the site root and missing
 * paths normally reach this script.
 */
if (!in_array($path, ['/', '/index.php'], true)) {
    require __DIR__ . '/security_probe.php';
    exit;
}

// The public landing page introduces the academic research workspace.
// Keep /assessment/ and all protected application routes unchanged.
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'");
readfile(__DIR__ . '/landing/index.html');
exit;
