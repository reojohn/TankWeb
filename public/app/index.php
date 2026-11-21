<?php

declare(strict_types=1);

// FortressAuth v3 React entry gate.
// The SPA shell itself must never be served before the same server-side
// administrator authentication used by the protected PHP pages succeeds.
require __DIR__ . '/../../src/middleware.php';
require_once __DIR__ . '/../../src/config.php';
require_once __DIR__ . '/../../src/auth.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// A completely logged-out visitor receives the branded FortressAuth 403
// response before any React markup is sent. Keep it visible briefly so the
// denial is clear, then return the browser to the secure login gateway.
if ((int)($_SESSION['uid'] ?? 0) <= 0) {
    audit_log('auth_rejected reason=missing_primary_session uid=0');
    fortress_render_security_error(403, 'missing_primary_session', 2, '/login.php');
}

// Incomplete MFA, revoked, disabled, or otherwise invalid sessions continue
// through the normal authoritative authentication checks.
require_admin_auth();

$reactEntry = __DIR__ . '/index.html';
if (!is_file($reactEntry)) {
    fortress_render_security_error(404, 'react_workspace_unavailable');
}

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

readfile($reactEntry);
