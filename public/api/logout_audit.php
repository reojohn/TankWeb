<?php

declare(strict_types=1);

// This endpoint is intentionally separate from middleware.php. Its only job is
// to persist a short-lived, signed logout audit token after the session has
// already been revoked by logout.php.
require_once __DIR__ . '/../../src/logout_audit_token.php';
require_once __DIR__ . '/../../src/logger.php';

header_remove('X-Powered-By');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');

if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit;
}

$contentType = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
$token = '';

if (str_starts_with($contentType, 'application/json')) {
    $raw = file_get_contents('php://input');
    $data = is_string($raw) ? json_decode($raw, true) : null;
    if (is_array($data)) {
        $token = trim((string)($data['token'] ?? ''));
    }
} else {
    $token = trim((string)($_POST['token'] ?? ''));
}

$verified = fortress_verify_logout_audit_token($token);
if ($verified === null) {
    // Do not turn this tiny fire-and-forget endpoint into a threat-notification
    // source. Invalid tokens are simply rejected without bootstrapping the DB.
    http_response_code(204);
    exit;
}

// Best-effort local replay guard. Render's filesystem is sufficient for this
// short 45-second token lifetime; if the directory cannot be written, the
// signed/expiring token still prevents unauthenticated audit forgery.
$replayDir = __DIR__ . '/../../data/logout_audit_replay';
@mkdir($replayDir, 0700, true);
$replayPath = $replayDir . '/' . hash('sha256', $token) . '.once';
$replayHandle = @fopen($replayPath, 'x');
if ($replayHandle === false && is_file($replayPath)) {
    http_response_code(204);
    exit;
}
if (is_resource($replayHandle)) {
    @fwrite($replayHandle, (string)time());
    @fclose($replayHandle);
}

// Occasionally clear stale replay markers without adding work to every request.
if (random_int(1, 40) === 1 && is_dir($replayDir)) {
    $cutoff = time() - 300;
    foreach ((array)glob($replayDir . '/*.once') as $file) {
        if (is_file($file) && (int)@filemtime($file) < $cutoff) {
            @unlink($file);
        }
    }
}

// Only now, after validation and outside the user's critical logout request,
// open PostgreSQL/Supabase and persist the durable audit row.
require_once __DIR__ . '/../../src/config.php';

$userId = (int)$verified['uid'];
$nonce = (string)$verified['nonce'];
$safeMessage = 'logout uid=' . $userId . ' async=1 nonce=' . $nonce;
$time = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:sP');
$ip = getRealIP();
$ua = str_replace(["\r", "\n"], '', (string)($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'));
$ua = substr($ua, 0, 200);
$rid = fortress_request_id();
$rawEntry = sprintf('[%s] rid=%s ip=%s ua=%s %s%s', $time, $rid, $ip, $ua, $safeMessage, PHP_EOL);

fortress_persist_security_event($safeMessage, $rawEntry, $time, $ip, $ua, $rid);

http_response_code(204);
