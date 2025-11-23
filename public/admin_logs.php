<?php
require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/session.php';

if (session_status() === PHP_SESSION_NONE) session_start();

// ✅ Check admin login with 2FA verification
if (empty($_SESSION['uid']) || empty($_SESSION['admin_verified'])) {
    http_response_code(403);
    exit("Unauthorized: You must be fully verified as admin to view this page.");
}

// Path to log files
$logPath = __DIR__ . '/../data/';

// ✅ Function to safely read log files
function read_log_file($logPath, $filename) {
    $path = $logPath . $filename;
    if (!file_exists($path)) return ["Log file not found: $filename"];
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    return array_slice($lines, -500); // last 500 lines
}

// Read the logs
$auditLog    = read_log_file($logPath, "audit.log");
$honeypotLog = read_log_file($logPath, "honeypot_log.txt");
$bannedLog   = read_log_file($logPath, "banned_ips.txt");

// Function to highlight log content
function parse_log_line($line) {
    $line = htmlspecialchars($line, ENT_QUOTES, 'UTF-8');
    $line = preg_replace('/ip=([\d:.]+)/', '<span style="color:#ff7b72;">ip=$1</span>', $line);
    $line = preg_replace('/username_attempt=([\w]*)/', '<span style="color:#7bd1ff;">$1</span>', $line);
    $line = preg_replace('/msg=([\w_]+)/', '<span style="color:#d6b3ff;">$1</span>', $line);
    return $line;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Logs</title>
<link rel="stylesheet" href="/css/dashboard.css">
<link rel="stylesheet" href="/css/admin_logs.css">
<!-- ... your existing CSS ... -->
</head>
<body>




<div class="dashboard-card">
    <a href="./dashboard.php" class="back-btn">← Back to Dashboard</a>

    <div class="dashboard-grid">
        <!-- Left: Audit Logs -->
        <div class="left-column">
            <div class="header-box">Audit Logs</div>
            <div class="scroll-table">
                <table id="audit-log-table">

                    <tbody>
                        <?php foreach($auditLog as $line): ?>
                        <tr><td><?= parse_log_line($line) ?></td></tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Right: Honeypot Logs + Banned IPs -->
        <div class="right-column">
            <div class="header-box">Honeypot Logs</div>
            <div class="scroll-table">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp & Info</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($honeypotLog as $line): ?>
                        <tr><td><?= parse_log_line($line) ?></td></tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="header-box">Banned IPs</div>
            <div class="scroll-table">
                <table>
                    <thead>
                        <tr>
                            <th>IP & Info</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($bannedLog as $line): ?>
                        <tr><td><?= htmlspecialchars($line) ?></td></tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>


<script src="/js/auto_logout.js"></script>

</body>
</html>
