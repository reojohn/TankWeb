<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/security_policy.php';

require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';

header(
    'Content-Type: application/json; charset=utf-8'
);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function qr_json_error(
    string $message,
    int $status = 400
): never {

    http_response_code($status);

    echo json_encode([
        'success' => false,
        'error' => $message
    ]);

    exit;
}


if ($_SERVER['REQUEST_METHOD'] !== 'POST') {

    qr_json_error(
        'Method not allowed.',
        405
    );
}


if (
    empty($_SESSION['pending_user_id']) ||
    empty($_SESSION['pending_school_id_verification'])
) {

    qr_json_error(
        'Password authentication required.',
        401
    );
}

$passwordVerifiedAt = (int)($_SESSION['password_verified_at'] ?? 0);
if ($passwordVerifiedAt <= 0 || (time() - $passwordVerifiedAt) > (int)fortress_security_policy()['school_id_verification_window_seconds']) {
    unset($_SESSION['pending_user_id'], $_SESSION['pending_school_id_verification'], $_SESSION['password_verified_at']);
    qr_json_error('Password verification expired. Please log in again.', 401);
}


$csrfToken =
    $_SERVER['HTTP_X_CSRF_TOKEN']
    ?? '';


if (!verify_csrf_token($csrfToken)) {

    qr_json_error(
        'Invalid security token.',
        403
    );
}


$input =
    file_get_contents('php://input');


$data =
    json_decode(
        $input ?: '',
        true
    );


$qrValue =
    trim(
        (string) (
            $data['qr_value']
            ?? ''
        )
    );


if ($qrValue === '') {

    qr_json_error(
        'No QR code data was received.'
    );
}


if (strlen($qrValue) > 4096) {

    qr_json_error(
        'QR code data is too large.'
    );
}


$userId =
    (int) $_SESSION['pending_user_id'];


$stmt =
    $pdo->prepare(
        'SELECT school_id_qr_enabled
         FROM public.users
         WHERE id = ?
         LIMIT 1'
    );


$stmt->execute([$userId]);


$user =
    $stmt->fetch(
        PDO::FETCH_ASSOC
    );


if (!$user) {

    qr_json_error(
        'User account was not found.',
        404
    );
}


if ((bool) $user['school_id_qr_enabled']) {

    qr_json_error(
        'A personal ID is already registered.',
        409
    );
}


/*
 * Store only a password-style hash of
 * the scanned QR value.
 *
 * The actual QR contents are not saved.
 */
$qrHash =
    password_hash(
        $qrValue,
        PASSWORD_DEFAULT
    );


if ($qrHash === false) {

    qr_json_error(
        'Unable to secure QR credential.',
        500
    );
}


$factorSet = fortress_second_factor_type_available($pdo)
    ? ", second_factor_type = 'personal_id'"
    : '';

$stmt =
    $pdo->prepare(
        'UPDATE public.users

         SET
            school_id_qr_hash = :qr_hash,
            school_id_qr_enabled = TRUE,
            school_id_qr_updated_at = NOW()' . $factorSet . '

         WHERE id = :user_id'
    );


$stmt->execute([

    ':qr_hash' =>
        $qrHash,

    ':user_id' =>
        $userId

]);


$_SESSION['school_id_qr_enrolled'] =
    true;

$_SESSION['school_id_verify_started_at'] =
    time();

$_SESSION['school_id_failed_attempts'] =
    0;


audit_log(
    'school_id_qr_registered uid=' .
    $userId
);


echo json_encode([
    'success' => true,
    'redirect' => '/personal_id_verify.php'
]);