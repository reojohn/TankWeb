<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_admin_auth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed.');
}

$csrfToken = $_POST['csrf_token'] ?? '';
if (!verify_csrf_token($csrfToken)) {
    http_response_code(403);
    exit('Invalid security token.');
}

$userId = (int)($_SESSION['uid'] ?? 0);

$stmt = $pdo->prepare(
    'SELECT school_id_qr_enabled, school_id_qr_hash
     FROM public.users
     WHERE id = ?
     LIMIT 1'
);
$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || !(bool)$user['school_id_qr_enabled'] || empty($user['school_id_qr_hash'])) {
    header('Location: /user_management.php#personal-id');
    exit;
}

$_SESSION['pending_user_id'] = $userId;
$_SESSION['pending_school_id_verification'] = true;
$_SESSION['school_id_verify_started_at'] = time();
$_SESSION['school_id_failed_attempts'] = 0;
$_SESSION['school_id_redirect_after_verify'] = '/user_management.php?reverified=1#personal-id';

audit_log('school_id_reverification_started uid=' . $userId);

header('Location: /personal_id_verify.php');
exit;
