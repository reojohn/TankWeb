<?php



error_reporting(E_ALL);
ini_set('display_errors', 1);


ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Start session if not active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}


require __DIR__ . '/../src/config.php';   // <--- REQUIRED
require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/sanitize.php';
require_once __DIR__ . '/../src/auth.php'; // login_user() available
require_once __DIR__ . '/../src/session.php';

// Secondary password (2FA)
$secondary_password = 'The$Sky^Burns&At_4AM_When*Giants_Fight#2025';

// Ensure pending 2FA exists
if (!isset($_SESSION['pending_admin_2fa']) || !isset($_SESSION['pending_user_id'])) {
    header("Location: login.php");
    exit;
}

// Handle POST submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = trim($_POST['two_factor'] ?? '');

    if (hash_equals($secondary_password, $input)) {
        // ✅ FULL ADMIN LOGIN

        // Set session UID
        login_user($_SESSION['pending_user_id']);

        // Mark admin fully verified for require_admin_auth()
        $_SESSION['admin_verified'] = true;

        // Clean up pending vars
        unset($_SESSION['pending_user_id']);
        unset($_SESSION['pending_admin_2fa']);

        // Hardened session
        session_regenerate_id(true);

        // Log 2FA success
        audit_log("2fa_success uid=" . intval($_SESSION['uid']));

        // Redirect to dashboard
        header("Location: ./dashboard.php");
        exit;

    } else {
        // Wrong 2FA → set error & redirect back
        $_SESSION['2fa_error'] = "Invalid 2FA password.";
        audit_log("2fa_failed uid=" . intval($_SESSION['pending_user_id']));
        header("Location: ./admin_2fa.php");
        exit;
    }
} else {
    // Non-POST requests → redirect to form
    header("Location: ./admin_2fa.php");
    exit;
}
