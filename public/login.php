<?php
require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/security.php';
require_once __DIR__ . '/../src/config.php';  
require_once __DIR__ . '/../src/sanitize.php'; 
require_once __DIR__ . '/../src/auth.php';   
require_once __DIR__ . '/../src/bruteforce.php';

ini_set('display_errors', 1);
error_reporting(E_ALL);

// Log page access
audit_log("login_page_accessed username_attempt=" . e($_POST['username'] ?? ''));

// Get IP
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

$error = '';
$error_class = ''; // ⭐ for styling specific messages

// -------------------------------------
// ✅ BLOCK ACCESS IF IP IS ALREADY BANNED
// -------------------------------------
if (is_ip_banned($pdo, $ip)) {
    audit_log("banned_ip_attempt ip=$ip");
    $error = "Your IP is temporarily banned. Try again later.";
    $error_class = 'ban';
    include __DIR__ . '/templates/login_form.php';
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

  // ======================================================
// ⭐⭐ ADDITIONAL DETECTION ADDED — WITHOUT CHANGING ANYTHING ELSE
// ======================================================

$raw_username = $_POST['username'] ?? '';
$raw_password = $_POST['password'] ?? '';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

$issues = [];

// SQL injection patterns
if (detect_sqli($raw_username) || detect_sqli($raw_password)) {
    $issues[] = "sql_attack"; 
}

// XSS patterns
if (detect_xss($raw_username) || detect_xss($raw_password)) {
    $issues[] = "xss_attack";
}

// Path traversal
if (detect_path_traversal($raw_username) || detect_path_traversal($raw_password)) {
    $issues[] = "path_traversal";
}

// Suspicious user agent
if (detect_suspicious_ua($ua)) {
    $issues[] = "bad_user_agent";
}

// If any issues found -> block
if (!empty($issues)) {
    audit_log("malicious_input_detected ip=$ip issues=" . implode(",", $issues) . " input=" . json_encode($_POST));
    $error = "Invalid input.";
    $error_class = "ban";
    include __DIR__ . '/templates/login_form.php';
    exit;
}

// -------------------------------------
// ❗ SHELL ATTACK DETECTION  (MOVE HERE)
// -------------------------------------
if (detect_shell_attack($raw_username) || detect_shell_attack($raw_password)) {
    audit_log("shell_attack_detected ip=$ip input=" . json_encode($_POST));
    $error = "Invalid input.";
    $error_class = "ban";
    include __DIR__ . '/templates/login_form.php';
    exit;
}


    $username = sanitize_username($_POST['username'] ?? '');
    $password = sanitize_password($_POST['password'] ?? '');
    $csrf_token = $_POST['csrf_token'] ?? '';

    // -------------------------------------
    // ❗ CSRF CHECK
    // -------------------------------------
    if (!verify_csrf_token($csrf_token)) {
        $error = 'Invalid CSRF token';
    } 
    elseif (!$username || !$password) {
        $error = 'Invalid username or password format';
    } 
    // -------------------------------------
    // ❗ Too many attempts → Ban IP
    // -------------------------------------
    elseif (too_many_failed_attempts($pdo, $ip)) {

        // Log attempt
        record_login_attempt($pdo, $ip, $username, false);

        // 🔥 Ban for 15 minutes
        ban_ip($pdo, $ip, 15 * 60);

        audit_log("ip_banned ip=$ip reason=too_many_attempts");

        $error = "Too many failed attempts. Your IP is banned for 15 minutes.";
        $error_class = "ban";
    } 
    else {

        // Try to login
        $user_id = verify_login($username, $password, $pdo);

        if ($user_id) {
            record_login_attempt($pdo, $ip, $username, true);
            clear_failed_attempts($pdo, $ip);

            // -------------------------------------
            // ✅ 2FA STEP
            // -------------------------------------
            $_SESSION['pending_admin_2fa'] = true;
            $_SESSION['pending_user_id'] = $user_id;

            header("Location: admin_2fa.php");
            exit;

        } else {
            record_login_attempt($pdo, $ip, $username, false);
            $error = 'Invalid username or password';
        }
    }
}

include __DIR__ . '/templates/login_form.php';
?>
