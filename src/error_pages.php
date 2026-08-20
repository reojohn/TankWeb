<?php

declare(strict_types=1);

/** Render a generic, branded denial page without reflecting attacker input. */
function fortress_render_security_error(int $status, string $reason = 'request_blocked', ?int $redirectSeconds = null, ?string $redirectUrl = null): never
{
    $status = in_array($status, [400, 401, 403, 404, 405, 429], true) ? $status : 403;

    $copy = [
        400 => ['Request Rejected', 'The request could not be accepted by the FortressAuth security gateway.', 'fa-triangle-exclamation'],
        401 => ['Authentication Required', 'A verified authentication session is required to continue.', 'fa-user-shield'],
        403 => ['Access Forbidden', 'FortressAuth blocked this request because the required security authorization was not satisfied.', 'fa-shield-halved'],
        404 => ['Route Concealed', 'The requested route is not exposed by FortressAuth. Unknown-path probes are intercepted and may be recorded as reconnaissance evidence.', 'fa-crosshairs'],
        405 => ['Method Blocked', 'The HTTP method used for this request is not permitted by the FortressAuth security policy.', 'fa-hand'],
        429 => ['Request Rate Limited', 'Too many security-sensitive requests were detected. Access has been temporarily restricted.', 'fa-gauge-high'],
    ];

    [$title, $message, $icon] = $copy[$status];
    $requestId = function_exists('fortress_request_id') ? fortress_request_id() : bin2hex(random_bytes(6));
    $reasonSafe = preg_replace('/[^a-z0-9_\-]/i', '_', $reason) ?: 'request_blocked';

    $isRecon404 = $status === 404;
    $statusPrimary = $isRecon404 ? 'PROBE INTERCEPTED' : 'REQUEST BLOCKED';
    $statusSecondary = $isRecon404 ? 'ROUTE CONCEALED' : 'EVENT MONITORED';
    $primaryIcon = $isRecon404 ? 'fa-crosshairs' : 'fa-circle-xmark';
    $secondaryIcon = $isRecon404 ? 'fa-eye-slash' : 'fa-file-shield';

    $hasSession = session_status() === PHP_SESSION_ACTIVE && (int)($_SESSION['uid'] ?? 0) > 0;
    $reactReady = is_file(__DIR__ . '/../public/app/index.html');
    $returnHref = $hasSession
        ? ($reactReady ? '/app/#/overview' : '/dashboard.php')
        : '/login.php';
    $returnLabel = $hasSession ? 'Return to command center' : 'Return to secure gateway';

    // Optional short, same-origin redirect used by the React entry gate.
    // The security page is rendered first; the browser then returns to the
    // secure login gateway after the requested delay.
    $autoRedirectEnabled = false;
    $autoRedirectSeconds = 0;
    $autoRedirectUrlSafe = '';
    if ($redirectSeconds !== null && $redirectUrl !== null) {
        $candidateSeconds = max(1, min(15, (int)$redirectSeconds));
        $candidateUrl = trim($redirectUrl);
        if (
            preg_match('#^/[A-Za-z0-9._~!$&\'()*+,;=:@%/?-]*$#', $candidateUrl) === 1 &&
            !str_starts_with($candidateUrl, '//') &&
            !preg_match('/[\r\n]/', $candidateUrl)
        ) {
            $autoRedirectEnabled = true;
            $autoRedirectSeconds = $candidateSeconds;
            $autoRedirectUrlSafe = $candidateUrl;
        }
    }

    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

    $statusEsc = htmlspecialchars((string)$status, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $titleEsc = htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $messageEsc = htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $iconEsc = htmlspecialchars($icon, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $requestEsc = htmlspecialchars($requestId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $reasonEsc = htmlspecialchars($reasonSafe, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $statusPrimaryEsc = htmlspecialchars($statusPrimary, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $statusSecondaryEsc = htmlspecialchars($statusSecondary, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $primaryIconEsc = htmlspecialchars($primaryIcon, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $secondaryIconEsc = htmlspecialchars($secondaryIcon, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $returnHrefEsc = htmlspecialchars($returnHref, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $returnLabelEsc = htmlspecialchars($returnLabel, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $autoRedirectUrlEsc = htmlspecialchars($autoRedirectUrlSafe, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $autoRedirectSecondsEsc = htmlspecialchars((string)$autoRedirectSeconds, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $reconClass = $isRecon404 ? ' security-error-recon' : '';

    $reconPanel = $isRecon404 ? <<<HTML
        <div class="security-error-recon-panel" aria-hidden="true">
            <div class="security-error-radar">
                <span class="radar-ring ring-one"></span>
                <span class="radar-ring ring-two"></span>
                <span class="radar-ring ring-three"></span>
                <span class="radar-sweep"></span>
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div class="security-error-recon-copy">
                <small>PERIMETER RESPONSE</small>
                <strong>Unknown route intercepted</strong>
                <span>FortressAuth disclosed no protected resource details.</span>
            </div>
        </div>
HTML : '';

    $redirectHead = $autoRedirectEnabled
        ? '<meta http-equiv="refresh" content="' . $autoRedirectSecondsEsc . ';url=' . $autoRedirectUrlEsc . '">'
        : '';

    $redirectPanel = $autoRedirectEnabled ? <<<HTML
        <div class="security-error-redirect" role="status" aria-live="polite">
            <div class="security-error-redirect-copy">
                <span><i class="fa-solid fa-shield-check"></i> Perimeter response complete</span>
                <strong>Returning to secure gateway in {$autoRedirectSecondsEsc} seconds</strong>
            </div>
            <div class="security-error-redirect-track" aria-hidden="true">
                <span style="--redirect-seconds: {$autoRedirectSecondsEsc}s"></span>
            </div>
        </div>
HTML : '';

    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#160817">
<meta name="robots" content="noindex,nofollow">
{$redirectHead}
<title>FortressAuth — {$statusEsc} {$titleEsc}</title>
<link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
<link rel="stylesheet" href="/css/all.min.css">
<link rel="stylesheet" href="/css/security_error.css">
</head>
<body class="security-error-page status-{$statusEsc}{$reconClass}">
<div class="security-error-grid" aria-hidden="true"></div>
<div class="security-error-ambient one" aria-hidden="true"></div>
<div class="security-error-ambient two" aria-hidden="true"></div>
<main class="security-error-shell">
    <section class="security-error-card" role="alert" aria-live="assertive">
        <div class="security-error-brand"><img src="/images/wolf1.png" alt=""><span><small>SECURE ACCESS</small><strong>FortressAuth</strong></span></div>
        <div class="security-error-beacon"><i class="fa-solid {$iconEsc}"></i><span></span></div>
        <div class="security-error-code">FORTRESSAUTH · PERIMETER GATEWAY · HTTP {$statusEsc}</div>
        <h1>{$titleEsc}</h1>
        <p>{$messageEsc}</p>
        {$reconPanel}
        <div class="security-error-status">
            <span><i class="fa-solid {$primaryIconEsc}"></i> {$statusPrimaryEsc}</span>
            <span><i class="fa-solid {$secondaryIconEsc}"></i> {$statusSecondaryEsc}</span>
        </div>
        <div class="security-error-meta">
            <div><small>Response</small><strong>{$statusEsc}</strong></div>
            <div><small>Policy</small><strong>{$reasonEsc}</strong></div>
            <div><small>Request ID</small><strong>{$requestEsc}</strong></div>
        </div>
        <p class="security-error-note"><i class="fa-solid fa-lock"></i> No requested path, database detail, stack trace, or protected resource metadata is reflected in this response.</p>
        {$redirectPanel}
        <a class="security-error-action" href="{$returnHrefEsc}"><i class="fa-solid fa-arrow-left"></i> {$returnLabelEsc}</a>
    </section>
</main>
</body>
</html>
HTML;
    exit;
}
