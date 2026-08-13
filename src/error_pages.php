<?php

declare(strict_types=1);

/** Render a generic, branded denial page without reflecting attacker input. */
function fortress_render_security_error(int $status, string $reason = 'request_blocked'): never
{
    $status = in_array($status, [400, 401, 403, 404, 405, 429], true) ? $status : 403;

    $copy = [
        400 => ['Request Rejected', 'The request could not be accepted by the FortressAuth security gateway.', 'fa-triangle-exclamation'],
        401 => ['Authentication Required', 'A verified authentication session is required to continue.', 'fa-user-shield'],
        403 => ['Access Forbidden', 'FortressAuth blocked this request because the required security authorization was not satisfied.', 'fa-shield-halved'],
        404 => ['Protected Resource Not Found', 'The requested resource is unavailable. Reconnaissance attempts may be recorded by FortressAuth.', 'fa-radar'],
        405 => ['Method Blocked', 'The HTTP method used for this request is not permitted by the FortressAuth security policy.', 'fa-hand'],
        429 => ['Request Rate Limited', 'Too many security-sensitive requests were detected. Access has been temporarily restricted.', 'fa-gauge-high'],
    ];

    [$title, $message, $icon] = $copy[$status];
    $requestId = function_exists('fortress_request_id') ? fortress_request_id() : bin2hex(random_bytes(6));
    $reasonSafe = preg_replace('/[^a-z0-9_\-]/i', '_', $reason) ?: 'request_blocked';

    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

    $statusEsc = htmlspecialchars((string)$status, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $titleEsc = htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $messageEsc = htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $iconEsc = htmlspecialchars($icon, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $requestEsc = htmlspecialchars($requestId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $reasonEsc = htmlspecialchars($reasonSafe, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#160817">
<title>FortressAuth — {$statusEsc} {$titleEsc}</title>
<link rel="stylesheet" href="/css/all.min.css">
<link rel="stylesheet" href="/css/security_error.css">
</head>
<body class="security-error-page">
<div class="security-error-ambient one" aria-hidden="true"></div>
<div class="security-error-ambient two" aria-hidden="true"></div>
<main class="security-error-shell">
    <section class="security-error-card" role="alert" aria-live="assertive">
        <div class="security-error-beacon"><i class="fa-solid {$iconEsc}"></i><span></span></div>
        <div class="security-error-code">FORTRESSAUTH · SECURITY GATEWAY · HTTP {$statusEsc}</div>
        <h1>{$titleEsc}</h1>
        <p>{$messageEsc}</p>
        <div class="security-error-status">
            <span><i class="fa-solid fa-circle-xmark"></i> REQUEST BLOCKED</span>
            <span><i class="fa-solid fa-file-shield"></i> EVENT MONITORED</span>
        </div>
        <div class="security-error-meta">
            <div><small>Response</small><strong>{$statusEsc}</strong></div>
            <div><small>Policy</small><strong>{$reasonEsc}</strong></div>
            <div><small>Request ID</small><strong>{$requestEsc}</strong></div>
        </div>
        <p class="security-error-note"><i class="fa-solid fa-lock"></i> No protected resource details are disclosed by this response.</p>
        <a class="security-error-action" href="/login.php"><i class="fa-solid fa-arrow-left"></i> Return to secure gateway</a>
    </section>
</main>
</body>
</html>
HTML;
    exit;
}
