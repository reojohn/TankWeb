<?php

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/logger.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$userId = (int)($_SESSION['uid'] ?? 0);
if ($userId > 0) {
    audit_log('logout uid=' . $userId);
}

fortress_destroy_session();

header('Location: /login.php');
exit;
