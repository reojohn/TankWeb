<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';

require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';
require_once __DIR__ . '/../src/rate_limit.php';
require_once __DIR__ . '/../src/security_policy.php';

header(
    'Content-Type: application/json; charset=utf-8'
);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function school_id_json_error(
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

    school_id_json_error(
        'Method not allowed.',
        405
    );
}


if (
    empty($_SESSION['pending_user_id']) ||
    empty($_SESSION['pending_school_id_verification'])
) {

    school_id_json_error(
        'Password authentication required.',
        401
    );
}


/*
 * Five-minute second-factor window.
 */
$startedAt =
    (int) (
        $_SESSION['school_id_verify_started_at']
        ?? 0
    );


$policy = fortress_security_policy();
$verifyWindow = (int)$policy['school_id_verification_window_seconds'];
$sessionAttemptLimit = (int)$policy['school_id_session_attempt_limit'];
$rateWindow = (int)$policy['school_id_rate_window_seconds'];
$ipAttemptLimit = (int)$policy['school_id_ip_attempt_limit'];
$userAttemptLimit = (int)$policy['school_id_account_attempt_limit'];

if (
    $startedAt === 0 ||
    (time() - $startedAt) > $verifyWindow
) {

    unset(
        $_SESSION['pending_user_id'],
        $_SESSION['pending_school_id_verification'],
        $_SESSION['school_id_verify_started_at']
    );

    school_id_json_error(
        'Verification session expired. Please log in again.',
        401
    );
}


/*
 * Maximum five incorrect QR attempts.
 */
$attempts =
    (int) (
        $_SESSION['school_id_failed_attempts']
        ?? 0
    );


if ($attempts >= $sessionAttemptLimit) {

    audit_log(
        'school_id_qr_locked uid=' .
        (int) $_SESSION['pending_user_id']
    );

    unset(
        $_SESSION['pending_user_id'],
        $_SESSION['pending_school_id_verification'],
        $_SESSION['school_id_verify_started_at'],
        $_SESSION['school_id_failed_attempts']
    );

    school_id_json_error(
        'Too many failed QR verification attempts. Please log in again.',
        429
    );
}


$csrfToken =
    $_SERVER['HTTP_X_CSRF_TOKEN']
    ?? '';


if (!verify_csrf_token($csrfToken)) {

    school_id_json_error(
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

    school_id_json_error(
        'No QR code data was received.'
    );
}


if (strlen($qrValue) > 4096) {

    school_id_json_error(
        'Invalid QR code.'
    );
}


$userId =
    (int) $_SESSION['pending_user_id'];

$clientIp = getRealIP();
$ipLimitKey = $clientIp;
$userLimitKey = 'uid:' . $userId;

if (
    fortress_rate_limit_is_blocked('school_id_ip', $ipLimitKey, $ipAttemptLimit, $rateWindow) ||
    fortress_rate_limit_is_blocked('school_id_user', $userLimitKey, $userAttemptLimit, $rateWindow)
) {
    audit_log('school_id_qr_rate_limited uid=' . $userId);
    school_id_json_error('Too many QR verification attempts. Please log in again later.', 429);
}


$factorTypeField = fortress_second_factor_type_available($pdo)
    ? "COALESCE(second_factor_type, 'personal_id') AS second_factor_type"
    : "'personal_id' AS second_factor_type";

$stmt =
    $pdo->prepare(
        'SELECT
            id,
            username,
            ' . $factorTypeField . ',
            school_id_qr_hash,
            school_id_qr_enabled,
            is_active

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

    school_id_json_error(
        'User account was not found.',
        404
    );
}

$factorType = fortress_second_factor_type_value($user);
$usesGeneratedQr = $factorType === 'generated_qr';
$factorLabel = $usesGeneratedQr ? 'issued QR credential' : 'Personal ID';

if (array_key_exists('is_active', $user) && !(bool)$user['is_active']) {
    school_id_json_error('Account is disabled.', 403);
}

if (
    !(bool) $user['school_id_qr_enabled'] ||
    empty($user['school_id_qr_hash'])
) {

    school_id_json_error(
        'No active QR credential is registered to this account.',
        403
    );
}


/*
 * Compare the scanned QR with
 * the hash stored during enrollment.
 */
$verified =
    password_verify(
        $qrValue,
        (string) $user['school_id_qr_hash']
    );


if (!$verified) {

    $_SESSION['school_id_failed_attempts'] =
        $attempts + 1;

    fortress_rate_limit_record_failure('school_id_ip', $ipLimitKey, $rateWindow);
    fortress_rate_limit_record_failure('school_id_user', $userLimitKey, $rateWindow);

    audit_log(
        'school_id_qr_failed uid=' .
        $userId
    );

    $remaining =
        $sessionAttemptLimit -
        $_SESSION['school_id_failed_attempts'];

    school_id_json_error(
        ucfirst($factorLabel) . ' does not match this account. Attempts remaining: ' .
        max(0, $remaining),
        401
    );
}


/*
 * BOTH factors are now complete:
 *
 * 1. Password
 * 2. Registered QR possession credential
 */
fortress_rate_limit_clear('school_id_user', $userLimitKey);

login_user($userId, $pdo);


$_SESSION['admin_verified'] =
    true;


$_SESSION['school_id_verified'] =
    true;


$_SESSION['school_id_verified_at'] =
    time();

$_SESSION['auth_level'] =
    'password+school_id';


audit_log(
    'school_id_qr_success uid=' .
    $userId
);


$redirect =
    $_SESSION['school_id_redirect_after_verify']
    ?? '/dashboard.php';


unset(
    $_SESSION['pending_user_id'],
    $_SESSION['pending_school_id_verification'],
    $_SESSION['password_verified_at'],
    $_SESSION['school_id_verify_started_at'],
    $_SESSION['school_id_failed_attempts'],
    $_SESSION['school_id_qr_enrolled'],
    $_SESSION['school_id_redirect_after_verify'],
    $_SESSION['pending_mfa_secret'],
    $_SESSION['pending_mfa_user_id']
);


echo json_encode([
    'success' => true,
    'redirect' => $redirect
]);