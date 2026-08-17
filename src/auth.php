<?php

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/sanitize.php';
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/user_accounts.php';
require_once __DIR__ . '/bruteforce.php';
require_once __DIR__ . '/security_policy.php';
require_once __DIR__ . '/error_pages.php';

$FORTRESS_POLICY = fortress_security_policy();
$SESSION_TIMEOUT = (int)$FORTRESS_POLICY['session_idle_seconds'];
$SESSION_ABSOLUTE_TIMEOUT = (int)$FORTRESS_POLICY['session_absolute_seconds'];


function fortress_password_hash_value(string $password): string
{
    if (defined('PASSWORD_ARGON2ID')) {
        $hash = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 19456,
            'time_cost' => 2,
            'threads' => 1,
        ]);
    } else {
        $hash = password_hash($password, PASSWORD_DEFAULT);
    }

    if ($hash === false) {
        throw new RuntimeException('Unable to hash password securely.');
    }
    return $hash;
}

function fortress_password_needs_rehash(string $hash): bool
{
    if (defined('PASSWORD_ARGON2ID')) {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
            'memory_cost' => 19456,
            'time_cost' => 2,
            'threads' => 1,
        ]);
    }
    return password_needs_rehash($hash, PASSWORD_DEFAULT);
}

function fortress_auth_fail(string $reason = 'forbidden', int $status = 403): never
{
    $uid = (int)($_SESSION['uid'] ?? 0);
    $isBackground = defined('FORTRESS_BACKGROUND_REQUEST')
        && FORTRESS_BACKGROUND_REQUEST === true;

    // A stale live-security poll after logout/session expiry is expected and
    // should not become a security event itself. Return a machine-readable 401
    // so the browser poller can stop immediately. Do not destroy anything here:
    // uid=0 means there is no authenticated primary session to revoke.
    if (
        $isBackground
        && $uid <= 0
        && in_array($reason, ['incomplete_primary_auth', 'missing_primary_session'], true)
    ) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        echo json_encode([
            'success' => false,
            'auth' => 'expired',
            'reason' => $reason,
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    audit_log('auth_rejected reason=' . preg_replace('/[^a-z0-9_\-]/i', '_', $reason) . ' uid=' . $uid);
    fortress_destroy_session();
    fortress_render_security_error($status, $reason);
}

function fortress_session_fingerprint(): string
{
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    return hash('sha256', $ua);
}

function fortress_session_binding_enabled(): bool
{
    $raw = getenv('SESSION_BIND_USER_AGENT');
    if ($raw === false || trim((string)$raw) === '') {
        return true;
    }
    return filter_var($raw, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true;
}

function fortress_enforce_session_lifetime(): void
{
    global $SESSION_TIMEOUT, $SESSION_ABSOLUTE_TIMEOUT;

    $now = time();
    $lastActivity = (int)($_SESSION['last_activity'] ?? 0);
    $createdAt = (int)($_SESSION['session_created_at'] ?? 0);

    if ($lastActivity > 0 && ($now - $lastActivity) > $SESSION_TIMEOUT) {
        audit_log('session_expired reason=idle_timeout uid=' . (int)($_SESSION['uid'] ?? 0));
        fortress_destroy_session();
        fortress_start_session();
        $_SESSION['last_activity'] = $now;
        $_SESSION['session_created_at'] = $now;
        return;
    }

    if ($createdAt > 0 && ($now - $createdAt) > $SESSION_ABSOLUTE_TIMEOUT) {
        audit_log('session_expired reason=absolute_timeout uid=' . (int)($_SESSION['uid'] ?? 0));
        fortress_destroy_session();
        fortress_start_session();
        $_SESSION['last_activity'] = $now;
        $_SESSION['session_created_at'] = $now;
        return;
    }

    if ($createdAt === 0) {
        $_SESSION['session_created_at'] = $now;
    }
    if (!defined('FORTRESS_BACKGROUND_REQUEST') || FORTRESS_BACKGROUND_REQUEST !== true) {
        $_SESSION['last_activity'] = $now;
    }
}

fortress_enforce_session_lifetime();

function verify_login(string $username, string $password, PDO $pdo): int|false
{
    $managementReady = fortress_user_management_columns_available($pdo);
    $hasSessionVersion = fortress_session_version_available($pdo);

    $fields = ['id', 'username', 'password_hash'];
    if ($managementReady) {
        $fields[] = 'is_active';
    }
    if ($hasSessionVersion) {
        $fields[] = 'session_version';
    }

    $stmt = $pdo->prepare('SELECT ' . implode(', ', $fields) . ' FROM public.users WHERE username = ? LIMIT 1');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    $ip = getRealIP();

    if ($user && $managementReady && array_key_exists('is_active', $user) && !(bool)$user['is_active']) {
        record_login_attempt($pdo, $ip, $username, false);
        audit_log('login_disabled_account username=' . e($username));
        return false;
    }

    if (!$user || !password_verify($password, (string)$user['password_hash'])) {
        record_login_attempt($pdo, $ip, $username, false);
        audit_log('login_failed username=' . e($username));
        return false;
    }

    // Transparently upgrade older password hashes when PHP's current default changes.
    if (fortress_password_needs_rehash((string)$user['password_hash'])) {
        try {
            $rehash = fortress_password_hash_value($password);
            if ($rehash !== false) {
                $upgrade = $pdo->prepare('UPDATE public.users SET password_hash = ? WHERE id = ?');
                $upgrade->execute([$rehash, (int)$user['id']]);
            }
        } catch (Throwable $e) {
            error_log('FortressAuth password rehash failed for uid=' . (int)$user['id']);
        }
    }

    record_login_attempt($pdo, $ip, $username, true);
    fortress_mark_login_success($pdo, (int)$user['id']);

    return (int)$user['id'];
}

function login_user(int $userId, ?PDO $pdo = null): void
{
    fortress_rotate_session_security_state();

    $_SESSION['uid'] = $userId;
    $_SESSION['logged_in_at'] = time();
    $_SESSION['session_created_at'] = time();
    $_SESSION['last_activity'] = time();
    $_SESSION['auth_fingerprint'] = fortress_session_fingerprint();

    if ($pdo instanceof PDO && fortress_session_version_available($pdo)) {
        $version = fortress_get_session_version($pdo, $userId);
        if ($version !== null) {
            $_SESSION['session_version'] = $version;
        }
    }

    audit_log('login_success uid=' . $userId);
}

function require_auth(): void
{
    if (empty($_SESSION['uid'])) {
        fortress_auth_fail('missing_primary_session');
    }
}

function require_admin_auth(): void
{
    global $pdo;

    $uid = (int)($_SESSION['uid'] ?? 0);

    // Every protected session must at minimum contain a successfully
    // authenticated password session. The database, not a client-controlled
    // session flag, decides whether School ID 2FA is additionally required.
    if ($uid <= 0 || empty($_SESSION['admin_verified'])) {
        fortress_auth_fail('incomplete_primary_auth');
    }

    if (!($pdo instanceof PDO)) {
        fortress_auth_fail('security_database_unavailable');
    }

    // Backward-compatible safety behavior:
    // until the optional-2FA migration is installed, preserve the previous
    // mandatory School ID QR requirement rather than locking administrators out.
    $optional2faPolicyAvailable = fortress_optional_2fa_policy_available($pdo);

    $fields = ['username', 'is_active', 'school_id_qr_enabled'];
    $hasRolePolicy = fortress_role_policy_available($pdo);
    if ($hasRolePolicy) {
        $fields[] = 'role';
    }
    if ($optional2faPolicyAvailable) {
        $fields[] = 'school_id_2fa_required';
    }
    $hasSecondFactorType = fortress_second_factor_type_available($pdo);
    if ($hasSecondFactorType) {
        $fields[] = 'second_factor_type';
    }
    $hasSchoolIdUpdatedAt = fortress_column_exists($pdo, 'school_id_qr_updated_at');
    if ($hasSchoolIdUpdatedAt) {
        $fields[] = 'school_id_qr_updated_at';
    }
    $hasSessionVersion = fortress_session_version_available($pdo);
    if ($hasSessionVersion) {
        $fields[] = 'session_version';
    }

    $stmt = $pdo->prepare(
        'SELECT ' . implode(', ', $fields) . '
         FROM public.users
         WHERE id = ?
         LIMIT 1'
    );
    $stmt->execute([$uid]);
    $account = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$account || !(bool)$account['is_active']) {
        fortress_auth_fail('account_disabled_or_missing');
    }

    // Make the already-authoritative account row available to the rest of
    // this request. Dashboard metric builders can reuse it instead of issuing
    // a second users-table query after require_admin_auth() succeeds.
    $GLOBALS['FORTRESS_AUTH_ACCOUNT'] = $account;
    $GLOBALS['FORTRESS_AUTH_ACCOUNT_UID'] = $uid;

    $_SESSION['role'] = $hasRolePolicy
        ? fortress_normalize_role($account['role'] ?? 'admin')
        : 'superadmin';

    $requiresSchoolId2fa = $optional2faPolicyAvailable
        ? (bool)$account['school_id_2fa_required']
        : true;

    if ($requiresSchoolId2fa) {
        $verifiedAt = (int)($_SESSION['school_id_verified_at'] ?? 0);

        if (
            !(bool)$account['school_id_qr_enabled'] ||
            empty($_SESSION['school_id_verified']) ||
            $verifiedAt <= 0 ||
            (string)($_SESSION['auth_level'] ?? '') !== 'password+school_id'
        ) {
            fortress_auth_fail('incomplete_multifactor_auth');
        }
    } else {
        // A password-only session is valid only when the database explicitly
        // marks School ID 2FA as not required for this account.
        if ((string)($_SESSION['auth_level'] ?? '') !== 'password') {
            fortress_auth_fail('account_auth_policy_changed');
        }
    }

    if (fortress_session_binding_enabled()) {
        $expected = (string)($_SESSION['auth_fingerprint'] ?? '');
        if ($expected === '' || !hash_equals($expected, fortress_session_fingerprint())) {
            fortress_auth_fail('session_fingerprint_changed');
        }
    }

    // Immediate account/session revocation after password, account-status, or
    // 2FA-policy changes.
    if ($hasSessionVersion) {
        $browserVersion = (int)($_SESSION['session_version'] ?? -1);
        $databaseVersion = (int)$account['session_version'];
        if ($browserVersion < 0 || $browserVersion !== $databaseVersion) {
            fortress_auth_fail('session_revoked');
        }
    }
}

function require_recent_school_id(?int $maxAgeSeconds = null): void
{
    global $pdo;

    require_admin_auth();

    $uid = (int)($_SESSION['uid'] ?? 0);
    if (fortress_optional_2fa_policy_available($pdo)) {
        $stmt = $pdo->prepare(
            'SELECT school_id_2fa_required
             FROM public.users
             WHERE id = ?
             LIMIT 1'
        );
        $stmt->execute([$uid]);
        $required = $stmt->fetchColumn();

        if ($required === false || !(bool)$required) {
            fortress_render_security_error(403, 'school_id_2fa_not_enabled');
        }
    }
    // Without the optional-2FA migration, legacy behavior applies and
    // School ID verification remains mandatory.

    if ($maxAgeSeconds === null) {
        $maxAgeSeconds = (int)fortress_security_policy()['school_id_verification_window_seconds'];
    }

    $verifiedAt = (int)($_SESSION['school_id_verified_at'] ?? 0);
    if (
        empty($_SESSION['school_id_verified']) ||
        $verifiedAt <= 0 ||
        (time() - $verifiedAt) > $maxAgeSeconds
    ) {
        fortress_render_security_error(403, 'recent_school_id_verification_required');
    }
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function generate_csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['csrf_token'];
}

function verify_csrf_token(mixed $token): bool
{
    $valid = is_string($token)
        && $token !== ''
        && !empty($_SESSION['csrf_token'])
        && hash_equals((string)$_SESSION['csrf_token'], $token);

    if (!$valid) {
        $path = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
        $path = is_string($path) && $path !== '' ? $path : '/';
        audit_log(
            'csrf_validation_failed method=' . fortress_log_safe_value((string)($_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN')) .
            ' path=' . fortress_log_safe_value($path) .
            ' uid=' . (int)($_SESSION['uid'] ?? $_SESSION['pending_user_id'] ?? 0)
        );
    }

    return $valid;
}
