<?php

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/security.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/sanitize.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/bruteforce.php';


/**
 * The regular browser flow still works without JavaScript. When the login
 * form is sent through login_ui.js, this endpoint returns JSON instead of an
 * HTTP redirect so the verification animation can reflect the real server
 * decision before navigating to the Personal ID step.
 */
function fortress_login_wants_json(): bool
{
    $requestedWith = strtolower((string) ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? ''));
    $accept = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));

    return $requestedWith === 'xmlhttprequest'
        || strpos($accept, 'application/json') !== false
        || (string) ($_POST['response_format'] ?? '') === 'json';
}

function fortress_login_json(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

$wantsJson = fortress_login_wants_json();

// Keep AJAX responses valid JSON even if PHP emits a runtime warning.
// Errors remain available to the server log for debugging.
if ($wantsJson) {
    ini_set('display_errors', '0');
}

// ------------------------------------------------------
// Log page access
// ------------------------------------------------------
audit_log(
    "login_page_accessed username_attempt=" .
    e($_POST['username'] ?? '')
);

// ------------------------------------------------------
// Get client IP
// ------------------------------------------------------
$ip = getRealIP();

$error = '';
$error_class = '';

// ------------------------------------------------------
// BLOCK ACCESS IF IP IS ALREADY BANNED
// ------------------------------------------------------
if (is_ip_banned($pdo, $ip)) {
    audit_log("banned_ip_attempt ip=$ip");

    $error = "Your IP is temporarily banned. Try again later.";
    $error_class = 'ban';

    if ($wantsJson) {
        fortress_login_json([
            'success' => false,
            'verified' => false,
            'stage' => 'network_policy',
            'message' => $error,
            'verification' => [
                'network' => 'blocked',
                'csrf' => 'not_run',
                'input_security' => 'not_run',
                'bruteforce' => 'not_run',
                'password' => 'not_run',
            ],
        ], 429);
    }

    include __DIR__ . '/templates/login_form.php';
    exit;
}

// ------------------------------------------------------
// HANDLE LOGIN
// ------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ==================================================
    // SECURITY INPUT DETECTION
    // ==================================================
    $raw_username = $_POST['username'] ?? '';
    $raw_password = $_POST['password'] ?? '';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $issues = [];

    if (detect_sqli($raw_username)) {
        $issues[] = 'sql_attack';
    }

    if (detect_xss($raw_username)) {
        $issues[] = 'xss_attack';
    }

    if (detect_path_traversal($raw_username)) {
        $issues[] = 'path_traversal';
    }

    if (detect_suspicious_ua($ua)) {
        $issues[] = 'bad_user_agent';
    }

    // --------------------------------------------------
    // Block detected malicious input
    // --------------------------------------------------
    if (!empty($issues)) {
        audit_log(
            "malicious_input_detected ip=$ip issues=" .
            implode(',', $issues) .
            " username=" . e((string)$raw_username)
        );

        $error = 'Invalid input.';
        $error_class = 'ban';

        if ($wantsJson) {
            fortress_login_json([
                'success' => false,
                'verified' => false,
                'stage' => 'request_security',
                'message' => 'The sign-in request was rejected by FortressAuth security controls.',
                'verification' => [
                    'network' => 'passed',
                    'csrf' => 'not_run',
                    'input_security' => 'rejected',
                    'bruteforce' => 'not_run',
                    'password' => 'not_run',
                ],
            ], 400);
        }

        include __DIR__ . '/templates/login_form.php';
        exit;
    }

    // --------------------------------------------------
    // Shell attack detection
    // --------------------------------------------------
    if (detect_shell_attack($raw_username)) {
        audit_log(
            "shell_attack_detected ip=$ip username=" . e((string)$raw_username)
        );

        $error = 'Invalid input.';
        $error_class = 'ban';

        if ($wantsJson) {
            fortress_login_json([
                'success' => false,
                'verified' => false,
                'stage' => 'request_security',
                'message' => 'The sign-in request was rejected by FortressAuth security controls.',
                'verification' => [
                    'network' => 'passed',
                    'csrf' => 'not_run',
                    'input_security' => 'rejected',
                    'bruteforce' => 'not_run',
                    'password' => 'not_run',
                ],
            ], 400);
        }

        include __DIR__ . '/templates/login_form.php';
        exit;
    }

    // ==================================================
    // SANITIZE LOGIN INPUT
    // ==================================================
    $username = sanitize_username($_POST['username'] ?? '');
    $password = sanitize_password($_POST['password'] ?? '');
    $csrf_token = $_POST['csrf_token'] ?? '';

    // --------------------------------------------------
    // CSRF CHECK
    // --------------------------------------------------
    if (!verify_csrf_token($csrf_token)) {
        $error = 'Invalid CSRF token';

        if ($wantsJson) {
            fortress_login_json([
                'success' => false,
                'verified' => false,
                'stage' => 'csrf',
                'message' => 'The secure sign-in request could not be validated. Refresh the page and try again.',
                'verification' => [
                    'network' => 'passed',
                    'input_security' => 'passed',
                    'csrf' => 'rejected',
                    'bruteforce' => 'not_run',
                    'password' => 'not_run',
                ],
            ], 403);
        }
    }

    // --------------------------------------------------
    // LOGIN FORMAT CHECK
    // --------------------------------------------------
    elseif (!$username || !$password) {
        $error = 'Invalid username or password format';

        if ($wantsJson) {
            fortress_login_json([
                'success' => false,
                'verified' => false,
                'stage' => 'credential_format',
                'message' => 'The submitted credentials could not be verified.',
                'verification' => [
                    'network' => 'passed',
                    'input_security' => 'passed',
                    'csrf' => 'passed',
                    'bruteforce' => 'not_run',
                    'password' => 'rejected',
                ],
            ], 400);
        }
    }

    // --------------------------------------------------
    // TOO MANY FAILED ATTEMPTS
    // --------------------------------------------------
    elseif (too_many_failed_attempts($pdo, $ip, (string)$username)) {
        record_login_attempt($pdo, $ip, $username, false);

        $policy = fortress_security_policy();
        $banSeconds = (int)$policy['ip_ban_seconds'];
        ban_ip($pdo, $ip, $banSeconds);

        audit_log("ip_banned ip=$ip reason=too_many_attempts");

        $error = 'Too many failed attempts. Your IP is banned for ' . fortress_policy_minutes($banSeconds) . '.';
        $error_class = 'ban';

        if ($wantsJson) {
            fortress_login_json([
                'success' => false,
                'verified' => false,
                'stage' => 'bruteforce',
                'message' => $error,
                'verification' => [
                    'network' => 'passed',
                    'input_security' => 'passed',
                    'csrf' => 'passed',
                    'bruteforce' => 'blocked',
                    'password' => 'not_run',
                ],
            ], 429);
        }
    }

    // ==================================================
    // VERIFY USERNAME + PASSWORD
    // ==================================================
    else {
        $user_id = verify_login($username, $password, $pdo);

        // ==================================================
        // PASSWORD CORRECT
        // ==================================================
        if ($user_id) {
            /*
             * Regenerate session identifier after
             * successful first-factor authentication.
             */
            session_regenerate_id(true);

            // --------------------------------------------------
            // FIRST FACTOR PASSED
            // --------------------------------------------------
            $_SESSION['pending_school_id_verification'] = true;
            $_SESSION['pending_user_id'] = (int) $user_id;
            $_SESSION['password_verified_at'] = time();

            /*
             * Remove any previous Personal ID verification
             * state before starting a new authentication.
             */
            unset(
                $_SESSION['uid'],
                $_SESSION['admin_verified'],
                $_SESSION['school_id_verified'],
                $_SESSION['school_id_verified_at'],
                $_SESSION['auth_level'],
                $_SESSION['auth_fingerprint'],
                $_SESSION['session_version'],
                $_SESSION['school_id_verify_started_at'],
                $_SESSION['school_id_failed_attempts'],
                $_SESSION['school_id_qr_enrolled']
            );

            audit_log(
                'password_factor_success uid=' .
                (int) $user_id .
                " ip=$ip"
            );

            // ==================================================
            // CHECK PERSONAL ID ENROLLMENT
            // ==================================================
            $optional2faPolicyAvailable = fortress_optional_2fa_policy_available($pdo);
            $policyField = $optional2faPolicyAvailable
                ? 'school_id_2fa_required'
                : 'TRUE AS school_id_2fa_required';

            try {
                $stmt = $pdo->prepare(
                    'SELECT ' . $policyField . ',
                        school_id_qr_enabled,
                        school_id_qr_hash
                     FROM public.users
                     WHERE id = ?
                     LIMIT 1'
                );

                $stmt->execute([(int) $user_id]);
                $schoolId = $stmt->fetch(PDO::FETCH_ASSOC);
            } catch (Throwable $e) {
                error_log('FortressAuth account security lookup failed for uid=' . (int)$user_id);
                $schoolId = false;
            }

            if (!$optional2faPolicyAvailable) {
                audit_log(
                    'optional_2fa_schema_pending uid=' .
                    (int)$user_id .
                    ' fallback=mandatory_school_id'
                );
            }

            if (!$schoolId) {
                audit_log(
                    'school_id_account_lookup_failed uid=' .
                    (int) $user_id
                );

                $error = 'Unable to load account security settings.';

                if ($wantsJson) {
                    fortress_login_json([
                        'success' => false,
                        'verified' => false,
                        'stage' => 'account_security',
                        'message' => 'Credentials were accepted, but the account security profile could not be loaded.',
                        'verification' => [
                            'network' => 'passed',
                            'input_security' => 'passed',
                            'csrf' => 'passed',
                            'bruteforce' => 'passed',
                            'password' => 'passed',
                            'personal_id_profile' => 'error',
                        ],
                    ], 500);
                }
            }

            // ==================================================
            // PERSONAL ID 2FA DISABLED FOR THIS ACCOUNT
            // Password authentication is sufficient only because
            // the database explicitly says this account does not
            // require the School ID factor.
            // ==================================================
            elseif (!(bool)$schoolId['school_id_2fa_required']) {
                unset(
                    $_SESSION['pending_user_id'],
                    $_SESSION['pending_school_id_verification'],
                    $_SESSION['password_verified_at'],
                    $_SESSION['school_id_verify_started_at'],
                    $_SESSION['school_id_failed_attempts'],
                    $_SESSION['school_id_qr_enrolled'],
                    $_SESSION['school_id_verified'],
                    $_SESSION['school_id_verified_at']
                );

                login_user((int)$user_id, $pdo);
                $_SESSION['admin_verified'] = true;
                $_SESSION['auth_level'] = 'password';

                audit_log(
                    'school_id_2fa_not_required uid=' .
                    (int)$user_id
                );

                $redirect = '/dashboard.php';

                if ($wantsJson) {
                    fortress_login_json([
                        'success' => true,
                        'verified' => true,
                        'stage' => 'authenticated',
                        'message' => 'Administrator password verified. Personal ID 2FA is disabled for this account.',
                        'next_step' => 'dashboard',
                        'redirect' => $redirect,
                        'verification' => [
                            'network' => 'passed',
                            'input_security' => 'passed',
                            'csrf' => 'passed',
                            'bruteforce' => 'passed',
                            'password' => 'passed',
                            'personal_id_profile' => 'not_required',
                        ],
                    ]);
                }

                header('Location: ' . $redirect);
                exit;
            }

            // ==================================================
            // 2FA REQUIRED BUT NO PERSONAL ID IS ENROLLED YET
            // Send the operator to one-time enrollment.
            // ==================================================
            elseif (
                !(bool)$schoolId['school_id_qr_enabled'] ||
                empty($schoolId['school_id_qr_hash'])
            ) {
                audit_log(
                    'school_id_enrollment_required uid=' .
                    (int)$user_id
                );

                $redirect = '/personal_id_register.php';

                if ($wantsJson) {
                    fortress_login_json([
                        'success' => true,
                        'verified' => true,
                        'stage' => 'password_verified',
                        'message' => 'Administrator credentials verified by the server.',
                        'next_step' => 'personal_id_enrollment',
                        'redirect' => $redirect,
                        'verification' => [
                            'network' => 'passed',
                            'input_security' => 'passed',
                            'csrf' => 'passed',
                            'bruteforce' => 'passed',
                            'password' => 'passed',
                            'personal_id_profile' => 'enrollment_required',
                        ],
                    ]);
                }

                header('Location: ' . $redirect);
                exit;
            }

            // ==================================================
            // PERSONAL ID ALREADY REGISTERED
            // Send user to QR verification
            // ==================================================
            else {
                $_SESSION['school_id_verify_started_at'] = time();
                $_SESSION['school_id_failed_attempts'] = 0;

                audit_log(
                    'school_id_verification_required uid=' .
                    (int) $user_id
                );

                $redirect = '/personal_id_verify.php';

                if ($wantsJson) {
                    fortress_login_json([
                        'success' => true,
                        'verified' => true,
                        'stage' => 'password_verified',
                        'message' => 'Administrator credentials verified by the server.',
                        'next_step' => 'personal_id_verification',
                        'redirect' => $redirect,
                        'verification' => [
                            'network' => 'passed',
                            'input_security' => 'passed',
                            'csrf' => 'passed',
                            'bruteforce' => 'passed',
                            'password' => 'passed',
                            'personal_id_profile' => 'registered',
                        ],
                    ]);
                }

                header('Location: ' . $redirect);
                exit;
            }
        }

        // ==================================================
        // PASSWORD INCORRECT
        // ==================================================
        else {
            audit_log(
                'password_factor_failed username=' .
                $username .
                " ip=$ip"
            );

            $error = 'Invalid username or password';

            if ($wantsJson) {
                fortress_login_json([
                    'success' => false,
                    'verified' => false,
                    'stage' => 'password',
                    'message' => 'The submitted credentials could not be verified.',
                    'verification' => [
                        'network' => 'passed',
                        'input_security' => 'passed',
                        'csrf' => 'passed',
                        'bruteforce' => 'passed',
                        'password' => 'rejected',
                    ],
                ], 401);
            }
        }
    }
}

// ------------------------------------------------------
// DISPLAY LOGIN FORM
// ------------------------------------------------------
include __DIR__ . '/templates/login_form.php';

?>
