<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/security_policy.php';
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

$verifiedAt = (int)($_SESSION['school_id_verified_at'] ?? 0);
if (
    empty($_SESSION['school_id_verified']) ||
    $verifiedAt === 0 ||
    (time() - $verifiedAt) > (int)fortress_security_policy()['school_id_verification_window_seconds']
) {
    http_response_code(403);
    exit('Recent Personal ID verification required before replacement.');
}

$userId = (int)($_SESSION['uid'] ?? 0);

$stmt = $pdo->prepare(
    'UPDATE public.users
     SET school_id_qr_hash = NULL,
         school_id_qr_enabled = FALSE,
         school_id_qr_updated_at = NOW()
     WHERE id = ?'
);
$stmt->execute([$userId]);
fortress_increment_session_version($pdo, $userId);

audit_log('school_id_qr_reset uid=' . $userId);

fortress_destroy_session();

header('Location: /login.php');
exit;
