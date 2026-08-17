<?php

declare(strict_types=1);

require_once __DIR__ . '/logger.php';

function fortress_column_exists(PDO $pdo, string $column): bool
{
    if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $column)) {
        return false;
    }

    try {
        $stmt = $pdo->prepare(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'users'
                  AND column_name = ?
            )"
        );
        $stmt->execute([$column]);
        return (bool)$stmt->fetchColumn();
    } catch (Throwable $e) {
        error_log('FortressAuth schema check failed for users.' . $column);
        return false;
    }
}

function fortress_user_management_columns_available(PDO $pdo): bool
{
    try {
        $stmt = $pdo->query(
            "SELECT COUNT(*)
             FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'users'
               AND column_name IN ('full_name', 'is_active', 'last_login_at', 'updated_at')"
        );
        return (int)$stmt->fetchColumn() === 4;
    } catch (Throwable $e) {
        error_log('FortressAuth user-management schema check failed.');
        return false;
    }
}

function fortress_ensure_user_management_schema(PDO $pdo): bool
{
    // Hardened behavior: the web application never modifies its own schema.
    // Apply sql/hardening.sql with a migration/owner account instead.
    $ready = fortress_user_management_columns_available($pdo);
    if (!$ready) {
        error_log('FortressAuth schema incomplete. Apply sql/hardening.sql with a migration account.');
    }
    return $ready;
}

function fortress_optional_2fa_policy_available(PDO $pdo): bool
{
    static $cache = [];
    $key = spl_object_id($pdo);

    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }

    return $cache[$key] = fortress_column_exists($pdo, 'school_id_2fa_required');
}


function fortress_second_factor_type_available(PDO $pdo): bool
{
    static $cache = [];
    $key = spl_object_id($pdo);

    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }

    return $cache[$key] = fortress_column_exists($pdo, 'second_factor_type');
}

function fortress_second_factor_type_value(array $user): string
{
    $type = strtolower(trim((string)($user['second_factor_type'] ?? 'personal_id')));
    return $type === 'generated_qr' ? 'generated_qr' : 'personal_id';
}


function fortress_role_policy_available(PDO $pdo): bool
{
    static $cache = [];
    $key = spl_object_id($pdo);

    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }

    return $cache[$key] = fortress_column_exists($pdo, 'role');
}

function fortress_normalize_role(mixed $role): string
{
    return strtolower(trim((string)$role)) === 'admin' ? 'admin' : 'superadmin';
}

function fortress_user_role(PDO $pdo, int $userId): string
{
    if ($userId <= 0) {
        return 'admin';
    }

    // Backward-compatible safety: before the role migration is applied, all
    // existing privileged accounts retain the legacy full-access behavior.
    if (!fortress_role_policy_available($pdo)) {
        return 'superadmin';
    }

    try {
        $stmt = $pdo->prepare('SELECT role FROM public.users WHERE id = ? LIMIT 1');
        $stmt->execute([$userId]);
        $role = $stmt->fetchColumn();
        return $role === false ? 'admin' : fortress_normalize_role($role);
    } catch (Throwable $e) {
        error_log('FortressAuth role lookup failed for uid=' . $userId);
        return 'admin';
    }
}

function fortress_is_superadmin(PDO $pdo, int $userId): bool
{
    return fortress_user_role($pdo, $userId) === 'superadmin';
}

function fortress_active_superadmin_count(PDO $pdo): int
{
    if (!fortress_ensure_user_management_schema($pdo)) {
        return 0;
    }

    if (!fortress_role_policy_available($pdo)) {
        return fortress_active_user_count($pdo);
    }

    try {
        $stmt = $pdo->query("SELECT COUNT(*) FROM public.users WHERE is_active = TRUE AND role = 'superadmin'");
        return (int)$stmt->fetchColumn();
    } catch (Throwable $e) {
        error_log('FortressAuth active-superadmin count failed.');
        return 0;
    }
}

function fortress_session_version_available(PDO $pdo): bool
{
    static $cache = [];
    $key = spl_object_id($pdo);
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }
    return $cache[$key] = fortress_column_exists($pdo, 'session_version');
}

function fortress_get_session_version(PDO $pdo, int $userId): ?int
{
    if ($userId <= 0 || !fortress_session_version_available($pdo)) {
        return null;
    }
    $stmt = $pdo->prepare('SELECT session_version FROM public.users WHERE id = ? LIMIT 1');
    $stmt->execute([$userId]);
    $value = $stmt->fetchColumn();
    return $value === false ? null : (int)$value;
}

function fortress_increment_session_version(PDO $pdo, int $userId): void
{
    if ($userId <= 0 || !fortress_session_version_available($pdo)) {
        return;
    }
    $stmt = $pdo->prepare('UPDATE public.users SET session_version = session_version + 1, updated_at = NOW() WHERE id = ?');
    $stmt->execute([$userId]);
}

function fortress_fetch_users(PDO $pdo): array
{
    if (!fortress_ensure_user_management_schema($pdo)) {
        return [];
    }

    $policyField = fortress_optional_2fa_policy_available($pdo)
        ? 'COALESCE(school_id_2fa_required, TRUE) AS school_id_2fa_required'
        : 'TRUE AS school_id_2fa_required';
    $factorTypeField = fortress_second_factor_type_available($pdo)
        ? "COALESCE(second_factor_type, 'personal_id') AS second_factor_type"
        : "'personal_id' AS second_factor_type";
    $roleField = fortress_role_policy_available($pdo)
        ? "COALESCE(role, 'admin') AS role"
        : "'superadmin' AS role";

    $stmt = $pdo->query(
        'SELECT id, username, full_name, is_active, created_at, updated_at, last_login_at, ' .
        $policyField . ', ' . $factorTypeField . ', ' . $roleField . ',
                COALESCE(school_id_qr_enabled, FALSE) AS school_id_qr_enabled,
                school_id_qr_updated_at
         FROM public.users
         ORDER BY LOWER(COALESCE(full_name, username)), LOWER(username), id'
    );

    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return is_array($rows) ? $rows : [];
}

function fortress_fetch_user(PDO $pdo, int $userId): ?array
{
    if ($userId <= 0 || !fortress_ensure_user_management_schema($pdo)) {
        return null;
    }

    $policyField = fortress_optional_2fa_policy_available($pdo)
        ? 'COALESCE(school_id_2fa_required, TRUE) AS school_id_2fa_required'
        : 'TRUE AS school_id_2fa_required';
    $factorTypeField = fortress_second_factor_type_available($pdo)
        ? "COALESCE(second_factor_type, 'personal_id') AS second_factor_type"
        : "'personal_id' AS second_factor_type";
    $roleField = fortress_role_policy_available($pdo)
        ? "COALESCE(role, 'admin') AS role"
        : "'superadmin' AS role";

    $stmt = $pdo->prepare(
        'SELECT id, username, full_name, is_active, created_at, updated_at, last_login_at, ' .
        $policyField . ', ' . $factorTypeField . ', ' . $roleField . ',
                COALESCE(school_id_qr_enabled, FALSE) AS school_id_qr_enabled,
                school_id_qr_updated_at
         FROM public.users
         WHERE id = ?
         LIMIT 1'
    );
    $stmt->execute([$userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row ?: null;
}

function fortress_active_user_count(PDO $pdo): int
{
    if (!fortress_ensure_user_management_schema($pdo)) {
        return 0;
    }

    return (int)$pdo->query('SELECT COUNT(*) FROM public.users WHERE is_active = TRUE')->fetchColumn();
}

function fortress_mark_login_success(PDO $pdo, int $userId): void
{
    if ($userId <= 0 || !fortress_user_management_columns_available($pdo)) {
        return;
    }

    try {
        $stmt = $pdo->prepare('UPDATE public.users SET last_login_at = NOW(), updated_at = NOW() WHERE id = ?');
        $stmt->execute([$userId]);
    } catch (Throwable $e) {
        error_log('FortressAuth last-login update failed for uid=' . $userId);
    }
}

function fortress_table_exists(PDO $pdo, string $tableName): bool
{
    if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $tableName)) {
        return false;
    }

    try {
        $stmt = $pdo->prepare(
            "SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name = ?
            )"
        );
        $stmt->execute([$tableName]);
        return (bool)$stmt->fetchColumn();
    } catch (Throwable $e) {
        error_log('FortressAuth table-existence check failed.');
        return false;
    }
}

function fortress_delete_user_account(PDO $pdo, int $userId): void
{
    if ($userId <= 0) {
        throw new InvalidArgumentException('Invalid administrator account.');
    }

    $pdo->beginTransaction();
    try {
        // Compatibility cleanup only. Legacy public MFA/WebAuthn routes are removed.
        foreach (['user_mfa', 'webauthn_credentials'] as $tableName) {
            if (fortress_table_exists($pdo, $tableName)) {
                $stmt = $pdo->prepare('DELETE FROM public.' . $tableName . ' WHERE user_id = ?');
                $stmt->execute([$userId]);
            }
        }

        $stmt = $pdo->prepare('DELETE FROM public.users WHERE id = ?');
        $stmt->execute([$userId]);
        if ($stmt->rowCount() !== 1) {
            throw new RuntimeException('Administrator account could not be deleted.');
        }

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}
