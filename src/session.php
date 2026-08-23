<?php

declare(strict_types=1);

function fortress_env_bool(string $name, bool $default = false): bool
{
    $raw = getenv($name);
    if ($raw === false || trim((string)$raw) === '') {
        return $default;
    }

    return filter_var($raw, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? $default;
}

function fortress_request_is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }

    if ((string)($_SERVER['SERVER_PORT'] ?? '') === '443') {
        return true;
    }

    // Forwarded headers are trusted only when deployment explicitly opts in.
    if (fortress_env_bool('TRUST_PROXY_HEADERS', false)) {
        $proto = strtolower(trim(explode(',', (string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))[0] ?? ''));
        if ($proto === 'https') {
            return true;
        }
    }

    return false;
}

function fortress_cookie_secure(): bool
{
    $configured = getenv('COOKIE_SECURE');
    if ($configured !== false && trim((string)$configured) !== '') {
        return filter_var($configured, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true;
    }

    return fortress_request_is_https();
}

function fortress_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_trans_sid', '0');

    session_start([
        'cookie_lifetime' => 0,
        'cookie_httponly' => true,
        'cookie_secure' => fortress_cookie_secure(),
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true,
        'use_only_cookies' => true,
    ]);
}

function fortress_release_session_read_lock(): void
{
    // PHP serializes requests that share the same session while the session
    // file/handler is open. Read-only dashboard/background requests should
    // release that lock immediately after authentication so a user-initiated
    // logout never waits behind telemetry, fragment, or notification queries.
    // The already-loaded $_SESSION values remain readable for the rest of the
    // request; this only prevents further writes from this request.
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
}

function fortress_destroy_session(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        fortress_start_session();
    }

    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'] ?: '/',
            'domain' => $params['domain'] ?? '',
            'secure' => (bool)($params['secure'] ?? false),
            'httponly' => (bool)($params['httponly'] ?? true),
            'samesite' => $params['samesite'] ?? 'Strict',
        ]);
    }

    session_destroy();
}

function fortress_rotate_session_security_state(): void
{
    session_regenerate_id(true);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

fortress_start_session();
