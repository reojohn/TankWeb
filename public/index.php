<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';

$path = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
if (!in_array($path, ['/', '/index.php'], true)) {
    http_response_code(404);
    exit('Not Found');
}

header('Location: /login.php');
exit;
