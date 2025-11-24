<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/sanitize.php';

// -------------------------
// Secure Session Settings
// -------------------------
// Detect if HTTPS is available for production
$cookie_secure = (!in_array($_SERVER['SERVER_NAME'], ['localhost', '127.0.0.1']) &&
                  (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'));

// Start session only if none exists
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => $cookie_secure,
        'use_strict_mode' => true,
        'cookie_samesite' => 'Strict'
    ]);
}

// -------------------------
// Session Timeout / Auto-Logout
// -------------------------
$SESSION_TIMEOUT = 1800; // 30 minutes
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $SESSION_TIMEOUT) {
    session_unset();
    session_destroy();
    if (session_status() === PHP_SESSION_NONE) {
        session_start([
            'cookie_httponly' => true,
            'cookie_secure' => $cookie_secure,
            'use_strict_mode' => true,
            'cookie_samesite' => 'Strict'
        ]);
    }
}
$_SESSION['last_activity'] = time();

// -------------------------
// Brute-force protection
// -------------------------
$max_attempts = 3;
$lockout_time = 15 * 60;

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt'] = time();
}

function check_brute_force() {
    global $max_attempts, $lockout_time;
    if ($_SESSION['login_attempts'] >= $max_attempts &&
        (time() - $_SESSION['last_attempt']) < $lockout_time) {
        audit_log("login_locked_out");
        die('Too many login attempts. Please try again later.');
    }
}

// -------------------------
// Login Verification
// -------------------------
function verify_login($username, $password, $pdo) {
    check_brute_force();

    $stmt = $pdo->prepare('SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    $_SESSION['last_attempt'] = time();

    if (!$user || !password_verify($password, $user['password_hash'])) {
        $_SESSION['login_attempts']++;
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        record_login_attempt($pdo, $ip, $username, false);
        audit_log("login_failed username=" . e($username));
        return false;
    }

    $_SESSION['login_attempts'] = 0;
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    record_login_attempt($pdo, $ip, $username, true);

    return intval($user['id']);
}

// -------------------------
// Log the user in
// -------------------------
function login_user($user_id) {
    session_regenerate_id(true);
    $_SESSION['uid'] = $user_id;
    $_SESSION['logged_in_at'] = time();
    audit_log("login_success uid=$user_id");
}

// -------------------------
// Require authentication
// -------------------------
function require_auth() {
    if (empty($_SESSION['uid'])) {
        http_response_code(403);
        exit('Forbidden');
    }
}

// -------------------------
// Require full admin login (including 2FA)
// -------------------------
function require_admin_auth() {
    if (empty($_SESSION['uid']) || empty($_SESSION['admin_verified'])) {
        http_response_code(403);
        exit('Forbidden: Admin access requires full verification.');
    }
}

// -------------------------
// CSRF Token
// -------------------------
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function generate_csrf_token() {
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}
?>
