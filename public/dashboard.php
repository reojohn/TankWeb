<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';

require_once __DIR__ . '/../src/session.php';
if (session_status() === PHP_SESSION_NONE) session_start();


require_admin_auth(); // exit if not logged in or 2FA not verified

// Put at the top of each page
$timeout = 15 * 60; // 15 minutes

if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
    session_unset();
    session_destroy();
    header("Location: login.php");
    exit;
}

$_SESSION['last_activity'] = time();



$username = 'Unknown';
$login_time = date('Y-m-d H:i:s');
if (isset($_SESSION['uid'])) {
    $stmt = $pdo->prepare('SELECT username FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([intval($_SESSION['uid'])]);
    $row = $stmt->fetch();
    if ($row) $username = e($row['username']);
}

$flag = 'FLAG{this_is_a_test_flag}';
audit_log("flag_access uid=" . intval($_SESSION['uid']));
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>FortressAuth — Dashboard</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <link rel="stylesheet" href="/css/dashboard.css">
<link rel="stylesheet" href="css/all.min.css">

</head>
<body>
  <div class="dashboard-card">

    <div class="header-box">
      <h2>FortressAuth Dashboard</h2>
    </div>

    <div class="dashboard-grid">

     <!-- Left column: info + security -->
<div class="left-column">
  <div class="section-box info-section">
    <h3>[ USER INFORMATION ]</h3>
    <div class="info-row">
      <span class="info-icon"><i class="fa-solid fa-user"></i></span>
      <span class="info-label">Username</span>
      <span class="info-value"><?php echo $username; ?></span>
    </div>
    <div class="info-row">
      <span class="info-icon"><i class="fa-solid fa-clock"></i></span>
      <span class="info-label">Login Time</span>
      <span class="info-value" id="liveClock"><?php echo $login_time; ?></span>
    </div>
  </div>

  <div class="section-box status-section">
    <h3>[ SECURITY STATUS ]</h3>
    <div class="status-row">
      <span class="status-icon check"><i class="fa-solid fa-circle-check"></i></span>
      <span class="status-label">Session Valid</span>
    </div>
    <div class="status-row">
      <span class="status-icon check"><i class="fa-solid fa-circle-check"></i></span>
      <span class="status-label">IP Logged</span>
    </div>
    <div class="status-row">
      <span class="status-icon check"><i class="fa-solid fa-circle-check"></i></span>
      <span class="status-label">Rate Limiting Active</span>
    </div>
  </div>
</div>

<!-- Right column: flag + troll -->
<div class="right-column">
  <div class="flag-container">
    <img src="/images/flag.png" alt="Flag" class="flag-icon">
  </div>

<div class="flag-container security-card">
    <div class="header-box">Security Logs</div>
    <p>View audit logs, honeypot logs, and banned IPs.</p>
    <a href="/admin_logs.php" class="troll-btn">View Logs</a>
</div>


</div>


    </div> <!-- end dashboard-grid -->

    <a class="logout-btn" href="/login.php">LOGOUT</a>
  </div>



<script src="/js/auto_logout.js"></script>

</body>
</html>
