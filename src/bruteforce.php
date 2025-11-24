<?php
require_once __DIR__ . '/logger.php';
/* ============================================================
    LOG LOGIN ATTEMPTS
   ============================================================ */
function record_login_attempt($pdo, $ip, $username, $success) {

    // FORCE boolean for PostgreSQL
    $success = $success ? true : false;

    $stmt = $pdo->prepare("
        INSERT INTO login_attempts (ip_address, username, success, attempted_at)
        VALUES (:ip, :username, :success, NOW())
    ");

    $stmt->bindValue(':ip', $ip, PDO::PARAM_STR);
    $stmt->bindValue(':username', $username, PDO::PARAM_STR);
    $stmt->bindValue(':success', $success, PDO::PARAM_BOOL);

    $stmt->execute();

    audit_log("login_attempt recorded ip=$ip user=$username success=$success");
}


/* ============================================================
    BRUTE FORCE CHECK (old logic kept)
   ============================================================ */
function too_many_failed_attempts($pdo, $ip, $limit = 3, $minutes = 15) {

    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM login_attempts
        WHERE ip_address = ?
          AND success = FALSE
          AND attempted_at > NOW() - (? * INTERVAL '1 minute')
    ");

    $stmt->execute([$ip, $minutes]);
    $count = $stmt->fetchColumn();

    if ($count >= $limit) {
        audit_log("bruteforce_detected ip=$ip count=$count");
    }

    return $count >= $limit;
}


/* ============================================================
    CLEAR FAILS AFTER SUCCESSFUL LOGIN
   ============================================================ */
function clear_failed_attempts($pdo, $ip) {

    $stmt = $pdo->prepare("
        DELETE FROM login_attempts
        WHERE ip_address = ?
          AND success = FALSE
    ");

    $stmt->execute([$ip]);

    audit_log("failed_attempts_cleared ip=$ip");
}


/* ============================================================
    NEW PART: IP BANNING SYSTEM
   ============================================================ */

function is_ip_banned($pdo, $ip) {

    $stmt = $pdo->prepare("
        SELECT banned_until
        FROM banned_ips
        WHERE ip = :ip
        LIMIT 1
    ");
    $stmt->execute(['ip' => $ip]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return false; // not banned
    }

    $banned_until = strtotime($row['banned_until']);

    if ($banned_until > time()) {
        return true; // still banned
    }

    // Ban expired → remove it
    $stmt = $pdo->prepare("DELETE FROM banned_ips WHERE ip = :ip");
    $stmt->execute(['ip' => $ip]);

    return false;
}

function ban_ip($pdo, $ip, $duration_seconds = 900) { // default 15 minutes
    $until = date('Y-m-d H:i:s', time() + $duration_seconds);

    $stmt = $pdo->prepare("
        INSERT INTO banned_ips (ip, banned_until)
        VALUES (:ip, :until)
        ON CONFLICT (ip) DO UPDATE SET banned_until = :until
    ");

    $stmt->execute([
        'ip' => $ip,
        'until' => $until
    ]);

    audit_log("ip_banned ip=$ip until=$until");
}
?>
