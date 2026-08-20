<?php

declare(strict_types=1);

$path = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';

/*
 * PHP's built-in development server searches parent directories for an
 * index.php when the requested path does not exist. Use that native fallback
 * instead of a custom router file so local FortressAuth can capture
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

require __DIR__ . '/../src/middleware.php';

header('Location: /login.php');
exit;
