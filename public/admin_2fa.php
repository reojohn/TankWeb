<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Include secure session first
require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/sanitize.php';
require_once __DIR__ . '/../src/auth.php'; // login_user() available
require_once __DIR__ . '/../src/session.php'; // ✅ Correct path

// Ensure session is started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Redirect if first login stage not passed
if (!isset($_SESSION['pending_admin_2fa']) || !isset($_SESSION['pending_user_id'])) {
    header("Location: login.php");
    exit;
}

// Secondary password for 2FA
$secondary_password = 'The$Sky^Burns&At_4AM_When*Giants_Fight#2025';
$error = $_SESSION['2fa_error'] ?? '';
unset($_SESSION['2fa_error']); // clear previous error

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin — 2FA Verification</title>
<link rel="stylesheet" href="/css/login.css">
</head>
<body>
    <div class="card">
        <div class="logo-container">
            <img src="/images/wolf.png" alt="Logo">
        </div>
        <h2>Second Verification Required</h2>
        <p style="margin-bottom: 20px; color: #d6b3ff;">Please enter your secondary admin password.</p>

        <?php if ($error): ?>
            <div class="error-message"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <form method="POST" action="verify_2fa.php">
            <input type="password" name="two_factor" placeholder="Enter secondary admin password" required>
            <button type="submit">Verify</button>
        </form>
    </div>
</body>
</html>
