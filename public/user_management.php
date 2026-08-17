<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/logger.php';
require_once __DIR__ . '/../src/fortress_metrics.php';
require_once __DIR__ . '/../src/user_accounts.php';
require_once __DIR__ . '/../src/security_policy.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
require_admin_auth();

$userId = (int)($_SESSION['uid'] ?? 0);
$schemaReady = fortress_ensure_user_management_schema($pdo)
    && fortress_optional_2fa_policy_available($pdo);
$generatedQrReady = fortress_second_factor_type_available($pdo);
$roleReady = fortress_role_policy_available($pdo);
$currentRole = fortress_user_role($pdo, $userId);
$isSuperAdmin = $currentRole === 'superadmin';
$ctx = fortress_build_security_context($pdo, $userId);
extract($ctx, EXTR_SKIP);
$activeNav = 'operator';
$csrfToken = generate_csrf_token();

// Current-operator Personal ID state is shown on this same page so account
// administration and the operator's own possession factor are managed from
// one workspace.
$personalIdRequired = (bool)($schoolIdRequired ?? true);
$personalIdEnabled = (bool)($schoolIdEnabled ?? false);
$personalIdUpdatedAt = $schoolIdUpdatedAt ?? null;
$personalIdFactorType = (string)($schoolIdFactorType ?? 'personal_id');
$personalIdUsesGeneratedQr = $personalIdFactorType === 'generated_qr';
$personalIdVerifiedAt = (int)($_SESSION['school_id_verified_at'] ?? 0);
$personalIdVerifyWindow = (int)fortress_security_policy()['school_id_verification_window_seconds'];
$personalIdRecentlyVerified = !empty($_SESSION['school_id_verified'])
    && $personalIdVerifiedAt > 0
    && (time() - $personalIdVerifiedAt) <= $personalIdVerifyWindow;
$personalIdUpdatedDisplay = fortress_format_date_value($personalIdUpdatedAt, 'Not registered');
$personalIdVerifiedDisplay = $personalIdRequired
    ? ($personalIdVerifiedAt > 0 ? date('Y-m-d H:i:s', $personalIdVerifiedAt) : 'Not verified in this session')
    : 'Not required by account policy';

function fortress_clean_full_name(string $value): string
{
    $value = preg_replace('/\s+/', ' ', trim($value)) ?? '';
    return function_exists('mb_substr') ? mb_substr($value, 0, 160) : substr($value, 0, 160);
}

function fortress_management_redirect(array $params = []): never
{
    $query = $params ? ('?' . http_build_query($params)) : '';
    header('Location: /user_management.php' . $query);
    exit;
}

function fortress_user_flash(string $type, string $message): void
{
    $_SESSION['user_management_flash'] = ['type' => $type, 'message' => $message];
}

function fortress_log_field(string $value): string
{
    return str_replace(["\r", "\n", " ", "="], ['', '', '_', '-'], trim($value));
}

function fortress_personal_id_hash_value(string $value): string
{
    $value = trim($value);

    if ($value === '') {
        throw new RuntimeException('Enter the Personal ID QR value before enabling 2FA.');
    }

    if (strlen($value) > 4096) {
        throw new RuntimeException('Personal ID QR value is too large.');
    }

    $hash = password_hash($value, PASSWORD_DEFAULT);
    if ($hash === false) {
        throw new RuntimeException('Unable to secure the Personal ID credential.');
    }

    return $hash;
}

function fortress_generated_qr_credential(): string
{
    $random = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    return 'FORTRESSAUTH-2FA:v1:' . $random;
}

function fortress_queue_generated_qr_handoff(int $targetId, string $username, string $fullName, string $credential, string $mode): void
{
    $_SESSION['generated_qr_handoff'] = [
        'target_id' => $targetId,
        'username' => $username,
        'full_name' => $fullName,
        'credential' => $credential,
        'mode' => $mode,
        'created_at' => time(),
    ];
}

function fortress_requested_second_factor_type(bool $available): string
{
    $type = strtolower(trim((string)($_POST['second_factor_type'] ?? 'personal_id')));
    if ($type === 'generated_qr') {
        if (!$available) {
            throw new RuntimeException('Administrator-issued QR is not available yet. Run sql/generated_qr_2fa.sql in Supabase, then refresh this page.');
        }
        return 'generated_qr';
    }
    return 'personal_id';
}

function fortress_requested_role(bool $available, string $default = 'admin'): string
{
    if (!$available) {
        return 'superadmin';
    }

    $role = strtolower(trim((string)($_POST['role'] ?? $default)));
    if (!in_array($role, ['superadmin', 'admin'], true)) {
        throw new RuntimeException('Invalid account role.');
    }
    return $role;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = (string)($_POST['csrf_token'] ?? '');
    if (!verify_csrf_token($token)) {
        http_response_code(403);
        exit('Invalid CSRF token.');
    }

    if (!$schemaReady) {
        fortress_user_flash('error', 'User management could not initialize its account fields. Check database permissions.');
        fortress_management_redirect();
    }

    $action = (string)($_POST['action'] ?? '');

    if (!$isSuperAdmin) {
        audit_log('user_management_denied actor_uid=' . $userId . ' role=' . $currentRole . ' action=' . fortress_log_field($action));
        fortress_user_flash('error', 'Super Admin authorization is required to create, edit, disable, reset, or delete user accounts.');
        fortress_management_redirect();
    }

    try {
        if ($action === 'create_user') {
            $username = sanitize_username((string)($_POST['username'] ?? ''));
            $fullName = fortress_clean_full_name((string)($_POST['full_name'] ?? ''));
            $password = (string)($_POST['password'] ?? '');
            $isActive = isset($_POST['is_active']);
            $require2fa = isset($_POST['require_school_id_2fa']);
            $factorType = $require2fa ? fortress_requested_second_factor_type($generatedQrReady) : 'personal_id';
            $personalIdValue = trim((string)($_POST['personal_id_qr'] ?? ''));
            $targetRole = fortress_requested_role($roleReady, 'admin');

            if ($username === false) {
                throw new RuntimeException('Username must be 3–32 characters and use only letters, numbers, or underscores.');
            }
            if ($fullName === '') {
                throw new RuntimeException('Enter a display name for the administrator.');
            }
            if (strlen($password) < 12 || strlen($password) > 128) {
                throw new RuntimeException('Temporary password must contain 12–128 characters.');
            }

            $qrCredential = null;
            $qrHash = null;
            if ($require2fa) {
                if ($factorType === 'generated_qr') {
                    $qrCredential = fortress_generated_qr_credential();
                    $qrHash = fortress_personal_id_hash_value($qrCredential);
                } else {
                    $qrHash = fortress_personal_id_hash_value($personalIdValue);
                }
            }

            $factorColumn = $generatedQrReady ? ', second_factor_type' : '';
            $factorValue = $generatedQrReady ? ', :second_factor_type' : '';
            $roleColumn = $roleReady ? ', role' : '';
            $roleValue = $roleReady ? ', :role' : '';
            $stmt = $pdo->prepare(
                'INSERT INTO public.users (
                    username, full_name, password_hash, is_active, updated_at,
                    school_id_2fa_required' . $factorColumn . $roleColumn . ',
                    school_id_qr_hash, school_id_qr_enabled, school_id_qr_updated_at
                 )
                 VALUES (
                    :username, :full_name, :password_hash, :is_active, NOW(),
                    :school_id_2fa_required' . $factorValue . $roleValue . ',
                    :school_id_qr_hash, :school_id_qr_enabled, NOW()
                 )'
            );
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->bindValue(':full_name', $fullName, PDO::PARAM_STR);
            $stmt->bindValue(':password_hash', fortress_password_hash_value($password), PDO::PARAM_STR);
            $stmt->bindValue(':is_active', $isActive, PDO::PARAM_BOOL);
            $stmt->bindValue(':school_id_2fa_required', $require2fa, PDO::PARAM_BOOL);
            if ($generatedQrReady) {
                $stmt->bindValue(':second_factor_type', $factorType, PDO::PARAM_STR);
            }
            if ($roleReady) {
                $stmt->bindValue(':role', $targetRole, PDO::PARAM_STR);
            }
            if ($qrHash === null) {
                $stmt->bindValue(':school_id_qr_hash', null, PDO::PARAM_NULL);
            } else {
                $stmt->bindValue(':school_id_qr_hash', $qrHash, PDO::PARAM_STR);
            }
            $stmt->bindValue(':school_id_qr_enabled', $require2fa, PDO::PARAM_BOOL);
            $stmt->execute();

            $newId = (int)$pdo->lastInsertId();

            audit_log(
                'user_account_created actor_uid=' . $userId .
                ' target_uid=' . $newId .
                ' target=' . fortress_log_field($username) .
                ' role=' . $targetRole .
                ' 2fa=' . ($require2fa ? 'enabled' : 'disabled') .
                ($require2fa ? ' factor=' . $factorType : '')
            );

            if ($require2fa) {
                audit_log(
                    'user_2fa_enabled actor_uid=' . $userId .
                    ' target_uid=' . $newId .
                    ' target=' . fortress_log_field($username) .
                    ' factor=' . $factorType
                );
                audit_log(
                    'school_id_qr_registered uid=' . $newId .
                    ' actor_uid=' . $userId .
                    ' source=user_management factor=' . $factorType
                );
            }

            if ($require2fa && $factorType === 'generated_qr' && is_string($qrCredential)) {
                fortress_queue_generated_qr_handoff($newId, $username, $fullName, $qrCredential, 'created');
            }

            fortress_user_flash(
                'success',
                !$require2fa
                    ? (($targetRole === 'superadmin' ? 'Super Admin' : 'Admin') . ' account created with password-only authentication.')
                    : ($factorType === 'generated_qr'
                        ? (($targetRole === 'superadmin' ? 'Super Admin' : 'Admin') . ' account created. Save the issued QR credential shown below and give it to the account owner.')
                        : (($targetRole === 'superadmin' ? 'Super Admin' : 'Admin') . ' account created. Password + Personal ID QR will be required at login.'))
            );
            fortress_management_redirect();
        }

        if ($action === 'update_user') {
            $targetId = (int)($_POST['user_id'] ?? 0);
            $target = fortress_fetch_user($pdo, $targetId);
            if (!$target) throw new RuntimeException('Administrator account was not found.');

            $username = sanitize_username((string)($_POST['username'] ?? ''));
            $fullName = fortress_clean_full_name((string)($_POST['full_name'] ?? ''));
            $isActive = isset($_POST['is_active']);
            $require2fa = isset($_POST['require_school_id_2fa']);
            $factorType = $require2fa ? fortress_requested_second_factor_type($generatedQrReady) : 'personal_id';
            $personalIdValue = trim((string)($_POST['personal_id_qr'] ?? ''));
            $regenerateGeneratedQr = isset($_POST['regenerate_generated_qr']);
            $oldRole = fortress_normalize_role($target['role'] ?? 'superadmin');
            $targetRole = fortress_requested_role($roleReady, $oldRole);

            if ($username === false) throw new RuntimeException('Username format is invalid.');
            if ($fullName === '') throw new RuntimeException('Display name is required.');
            if ($targetId === $userId) $isActive = true;

            if (
                $oldRole === 'superadmin'
                && (bool)$target['is_active']
                && (!$isActive || $targetRole !== 'superadmin')
                && fortress_active_superadmin_count($pdo) <= 1
            ) {
                throw new RuntimeException('At least one active Super Admin must remain. Promote another active account before demoting or disabling this one.');
            }

            $newPassword = (string)($_POST['new_password'] ?? '');
            if ($newPassword !== '' && (strlen($newPassword) < 12 || strlen($newPassword) > 128)) {
                throw new RuntimeException('New password must contain 12–128 characters.');
            }

            $was2faRequired = (bool)($target['school_id_2fa_required'] ?? true);
            $hadQr = (bool)($target['school_id_qr_enabled'] ?? false);
            $oldFactorType = fortress_second_factor_type_value($target);
            $factorTypeChanged = $require2fa && $factorType !== $oldFactorType;
            $qrCredential = null;
            $newQrHash = null;
            $replaceQr = false;

            if ($require2fa) {
                if ($factorType === 'generated_qr') {
                    $needsGeneratedQr = !$was2faRequired || !$hadQr || $factorTypeChanged || $regenerateGeneratedQr;
                    if ($needsGeneratedQr) {
                        if ($targetId === $userId) {
                            throw new RuntimeException('For safety, a different active administrator must issue or regenerate the QR credential for the account currently signed in.');
                        }
                        $qrCredential = fortress_generated_qr_credential();
                        $newQrHash = fortress_personal_id_hash_value($qrCredential);
                        $replaceQr = true;
                    }
                } else {
                    $replaceQr = $personalIdValue !== '';
                    $needsPersonalId = !$was2faRequired || !$hadQr || $factorTypeChanged;
                    if ($needsPersonalId || $replaceQr) {
                        $newQrHash = fortress_personal_id_hash_value($personalIdValue);
                        $replaceQr = true;
                    }
                }
            }

            $roleChanged = $targetRole !== $oldRole;
            $accountSets = [
                'username = :username',
                'full_name = :full_name',
                'is_active = :is_active',
                'updated_at = NOW()',
            ];
            if ($roleReady) {
                $accountSets[] = 'role = :role';
            }
            if ($newPassword !== '') {
                $accountSets[] = 'password_hash = :password_hash';
            }

            $stmt = $pdo->prepare('UPDATE public.users SET ' . implode(', ', $accountSets) . ' WHERE id = :id');
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->bindValue(':full_name', $fullName, PDO::PARAM_STR);
            $stmt->bindValue(':is_active', $isActive, PDO::PARAM_BOOL);
            if ($roleReady) {
                $stmt->bindValue(':role', $targetRole, PDO::PARAM_STR);
            }
            if ($newPassword !== '') {
                $stmt->bindValue(':password_hash', fortress_password_hash_value($newPassword), PDO::PARAM_STR);
            }
            $stmt->bindValue(':id', $targetId, PDO::PARAM_INT);
            $stmt->execute();

            if ($newPassword !== '') {
                audit_log('user_password_changed_during_edit actor_uid=' . $userId . ' target_uid=' . $targetId . ' target=' . fortress_log_field($username));
            }
            if ($roleChanged) {
                audit_log('user_role_changed actor_uid=' . $userId . ' target_uid=' . $targetId . ' target=' . fortress_log_field($username) . ' from=' . $oldRole . ' to=' . $targetRole);
            }

            $twoFactorChanged = false;
            $twoFactorResult = '';

            if (!$require2fa) {
                if ($was2faRequired || $hadQr) {
                    $factorReset = $generatedQrReady ? ", second_factor_type = 'personal_id'" : '';
                    $stmt = $pdo->prepare(
                        'UPDATE public.users
                         SET school_id_2fa_required = FALSE, school_id_qr_hash = NULL,
                             school_id_qr_enabled = FALSE, school_id_qr_updated_at = NOW(),
                             updated_at = NOW()' . $factorReset . '
                         WHERE id = ?'
                    );
                    $stmt->execute([$targetId]);
                    $twoFactorChanged = true;
                    $twoFactorResult = 'disabled';
                    audit_log('user_2fa_disabled actor_uid=' . $userId . ' target_uid=' . $targetId . ' target=' . fortress_log_field($username));
                }
            } else {
                $policyChanged = !$was2faRequired || $factorTypeChanged;
                if ($policyChanged || $replaceQr) {
                    $sets = [
                        'school_id_2fa_required = TRUE',
                        'school_id_qr_enabled = TRUE',
                        'school_id_qr_updated_at = NOW()',
                        'updated_at = NOW()',
                    ];
                    if ($generatedQrReady) {
                        $sets[] = 'second_factor_type = :second_factor_type';
                    }
                    if ($replaceQr) {
                        $sets[] = 'school_id_qr_hash = :qr_hash';
                    }
                    $stmt = $pdo->prepare('UPDATE public.users SET ' . implode(', ', $sets) . ' WHERE id = :id');
                    if ($generatedQrReady) {
                        $stmt->bindValue(':second_factor_type', $factorType, PDO::PARAM_STR);
                    }
                    if ($replaceQr) {
                        $stmt->bindValue(':qr_hash', $newQrHash, PDO::PARAM_STR);
                    }
                    $stmt->bindValue(':id', $targetId, PDO::PARAM_INT);
                    $stmt->execute();

                    $twoFactorChanged = true;
                    $twoFactorResult = ($was2faRequired && $hadQr) ? 'replaced' : 'enabled';
                    audit_log(
                        ($twoFactorResult === 'replaced' ? 'user_2fa_replaced' : 'user_2fa_enabled') .
                        ' actor_uid=' . $userId . ' target_uid=' . $targetId .
                        ' target=' . fortress_log_field($username) . ' factor=' . $factorType
                    );
                    if ($replaceQr) {
                        audit_log('school_id_qr_registered uid=' . $targetId . ' actor_uid=' . $userId . ' source=user_management mode=' . $twoFactorResult . ' factor=' . $factorType);
                    }
                }
            }

            if ($newPassword !== '' || $isActive !== (bool)$target['is_active'] || $twoFactorChanged || $roleChanged) {
                fortress_increment_session_version($pdo, $targetId);
            }

            audit_log(
                'user_account_updated actor_uid=' . $userId . ' target_uid=' . $targetId .
                ' target=' . fortress_log_field($username) .
                ' role=' . $targetRole .
                ($twoFactorResult !== '' ? ' 2fa=' . $twoFactorResult : '') .
                ($require2fa ? ' factor=' . $factorType : '')
            );

            if ($qrCredential !== null) {
                fortress_queue_generated_qr_handoff($targetId, $username, $fullName, $qrCredential, 'regenerated');
            }

            $message = ($targetRole === 'superadmin' ? 'Super Admin' : 'Admin') . ' account updated successfully.';
            if ($twoFactorResult === 'enabled') {
                $message .= $factorType === 'generated_qr' ? ' An administrator-issued QR is now required.' : ' Personal ID 2FA is now required.';
            } elseif ($twoFactorResult === 'replaced') {
                $message .= $factorType === 'generated_qr' ? ' A new QR credential was issued; save the one-time handoff below.' : ' The Personal ID 2FA credential was replaced.';
            } elseif ($twoFactorResult === 'disabled') {
                $message .= ' 2FA was disabled; future logins require the password only.';
            }

            if ($targetId === $userId && ($twoFactorChanged || $newPassword !== '' || $roleChanged)) {
                audit_log('current_user_security_policy_changed uid=' . $userId);
                fortress_destroy_session();
                header('Location: /login.php?security_policy_changed=1');
                exit;
            }

            fortress_user_flash('success', $message);
            fortress_management_redirect();
        }

        if ($action === 'toggle_user') {
            $targetId = (int)($_POST['user_id'] ?? 0);
            $target = fortress_fetch_user($pdo, $targetId);
            if (!$target) throw new RuntimeException('Administrator account was not found.');
            if ($targetId === $userId) throw new RuntimeException('The current operator cannot disable their own active account.');

            $newState = !(bool)$target['is_active'];
            if (!$newState && fortress_active_user_count($pdo) <= 1) {
                throw new RuntimeException('At least one active administrator must remain available.');
            }
            if (
                !$newState
                && fortress_normalize_role($target['role'] ?? 'superadmin') === 'superadmin'
                && fortress_active_superadmin_count($pdo) <= 1
            ) {
                throw new RuntimeException('The last active Super Admin cannot be disabled.');
            }

            $stmt = $pdo->prepare('UPDATE public.users SET is_active = ?, updated_at = NOW() WHERE id = ?');
            $stmt->bindValue(1, $newState, PDO::PARAM_BOOL);
            $stmt->bindValue(2, $targetId, PDO::PARAM_INT);
            $stmt->execute();
            fortress_increment_session_version($pdo, $targetId);
            audit_log(($newState ? 'user_account_enabled' : 'user_account_disabled') . ' actor_uid=' . $userId . ' target_uid=' . $targetId . ' target=' . fortress_log_field((string)$target['username']));
            fortress_user_flash('success', $newState ? 'Administrator account activated.' : 'Administrator account disabled.');
            fortress_management_redirect();
        }

        if ($action === 'reset_password') {
            $targetId = (int)($_POST['user_id'] ?? 0);
            $target = fortress_fetch_user($pdo, $targetId);
            if (!$target) throw new RuntimeException('Administrator account was not found.');
            $password = (string)($_POST['password'] ?? '');
            if (strlen($password) < 12 || strlen($password) > 128) {
                throw new RuntimeException('New temporary password must contain 12–128 characters.');
            }

            $stmt = $pdo->prepare('UPDATE public.users SET password_hash = ?, updated_at = NOW() WHERE id = ?');
            $stmt->execute([fortress_password_hash_value($password), $targetId]);
            fortress_increment_session_version($pdo, $targetId);
            audit_log('user_password_reset actor_uid=' . $userId . ' target_uid=' . $targetId . ' target=' . fortress_log_field((string)$target['username']));
            fortress_user_flash('success', 'Temporary password reset for ' . (string)$target['username'] . '.');
            fortress_management_redirect();
        }

        if ($action === 'disable_2fa') {
            $targetId = (int)($_POST['user_id'] ?? 0);
            $target = fortress_fetch_user($pdo, $targetId);
            if (!$target) throw new RuntimeException('Administrator account was not found.');

            $factorReset = $generatedQrReady ? ", second_factor_type = 'personal_id'" : '';
            $stmt = $pdo->prepare(
                'UPDATE public.users
                 SET school_id_2fa_required = FALSE,
                     school_id_qr_hash = NULL,
                     school_id_qr_enabled = FALSE,
                     school_id_qr_updated_at = NOW(),
                     updated_at = NOW()' . $factorReset . '
                 WHERE id = ?'
            );
            $stmt->execute([$targetId]);
            fortress_increment_session_version($pdo, $targetId);

            audit_log(
                'user_2fa_disabled actor_uid=' . $userId .
                ' target_uid=' . $targetId .
                ' target=' . fortress_log_field((string)$target['username']) .
                ' source=user_management_quick_action'
            );

            if ($targetId === $userId) {
                fortress_destroy_session();
                header('Location: /login.php?security_policy_changed=1');
                exit;
            }

            fortress_user_flash('success', '2FA disabled. This administrator will use password-only authentication on the next login.');
            fortress_management_redirect();
        }

        if ($action === 'delete_user') {
            $targetId = (int)($_POST['user_id'] ?? 0);
            $target = fortress_fetch_user($pdo, $targetId);
            if (!$target) throw new RuntimeException('Administrator account was not found.');

            $isSelfDelete = $targetId === $userId;
            $activeCountBeforeDelete = fortress_active_user_count($pdo);

            if ((bool)$target['is_active'] && $activeCountBeforeDelete <= 1) {
                throw new RuntimeException('This is the last active administrator. Create and activate another administrator first, then this account can be deleted safely.');
            }
            if (
                (bool)$target['is_active']
                && fortress_normalize_role($target['role'] ?? 'superadmin') === 'superadmin'
                && fortress_active_superadmin_count($pdo) <= 1
            ) {
                throw new RuntimeException('The last active Super Admin cannot be deleted.');
            }

            fortress_delete_user_account($pdo, $targetId);
            audit_log('user_account_deleted actor_uid=' . $userId . ' target_uid=' . $targetId . ' target=' . fortress_log_field((string)$target['username']) . ($isSelfDelete ? ' self_delete=1' : ''));

            if ($isSelfDelete) {
                fortress_destroy_session();
                header('Location: /login.php?account_deleted=1');
                exit;
            }

            fortress_user_flash('success', 'Administrator account deleted permanently.');
            fortress_management_redirect();
        }

        throw new RuntimeException('Unknown user-management action.');
    } catch (PDOException $e) {
        $message = $e->getCode() === '23505'
            ? 'That username is already registered.'
            : 'The account change could not be saved.';
        error_log('FortressAuth user-management database error: ' . $e->getMessage());
        fortress_user_flash('error', $message);
        fortress_management_redirect();
    } catch (Throwable $e) {
        fortress_user_flash('error', $e->getMessage());
        fortress_management_redirect();
    }
}

$flash = $_SESSION['user_management_flash'] ?? null;
unset($_SESSION['user_management_flash']);
$generatedQrHandoff = $_SESSION['generated_qr_handoff'] ?? null;
unset($_SESSION['generated_qr_handoff']);
if (is_array($generatedQrHandoff)) {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

$users = $schemaReady ? fortress_fetch_users($pdo) : [];
$totalUsers = count($users);
$activeUsers = count(array_filter($users, static fn(array $u): bool => (bool)$u['is_active']));
$inactiveUsers = $totalUsers - $activeUsers;
$personalIdUsers = count(array_filter($users, static fn(array $u): bool => (bool)($u['school_id_2fa_required'] ?? true)));
$superAdminUsers = count(array_filter($users, static fn(array $u): bool => fortress_normalize_role($u['role'] ?? 'superadmin') === 'superadmin'));
$adminUsers = $totalUsers - $superAdminUsers;
$activeRate = $totalUsers > 0 ? (int)round(($activeUsers / $totalUsers) * 100) : 0;

$q = trim((string)($_GET['q'] ?? ''));
$statusFilter = (string)($_GET['status'] ?? 'all');
$idFilter = (string)($_GET['identity'] ?? 'all');
$roleFilter = (string)($_GET['role'] ?? 'all');
$filteredUsers = array_values(array_filter($users, static function (array $u) use ($q, $statusFilter, $idFilter, $roleFilter): bool {
    if ($statusFilter === 'active' && !(bool)$u['is_active']) return false;
    if ($statusFilter === 'inactive' && (bool)$u['is_active']) return false;
    $requires2fa = (bool)($u['school_id_2fa_required'] ?? true);
    if ($idFilter === 'enabled' && !$requires2fa) return false;
    if ($idFilter === 'disabled' && $requires2fa) return false;
    $accountRole = fortress_normalize_role($u['role'] ?? 'superadmin');
    if ($roleFilter === 'superadmin' && $accountRole !== 'superadmin') return false;
    if ($roleFilter === 'admin' && $accountRole !== 'admin') return false;
    if ($q === '') return true;
    $haystack = strtolower((string)$u['username'] . ' ' . (string)$u['full_name']);
    return str_contains($haystack, strtolower($q));
}));

$editId = $isSuperAdmin ? (int)($_GET['edit'] ?? 0) : 0;
$resetId = $isSuperAdmin ? (int)($_GET['reset'] ?? 0) : 0;
$deleteId = $isSuperAdmin ? (int)($_GET['confirm_delete'] ?? 0) : 0;
$profileId = $isSuperAdmin ? (int)($_GET['profile'] ?? 0) : 0;
$editUser = $editId > 0 ? fortress_fetch_user($pdo, $editId) : null;
$resetUser = $resetId > 0 ? fortress_fetch_user($pdo, $resetId) : null;
$deleteUser = $deleteId > 0 ? fortress_fetch_user($pdo, $deleteId) : null;
$profileUser = $profileId > 0 ? fortress_fetch_user($pdo, $profileId) : null;
if ($profileUser) {
    audit_log('user_profile_viewed actor_uid=' . $userId . ' target_uid=' . (int)$profileUser['id'] . ' target=' . fortress_log_field((string)$profileUser['username']));
}
$deleteUserIsCurrent = $deleteUser && (int)$deleteUser['id'] === $userId;
$deleteBlockedAsLastActive = $deleteUser && (bool)$deleteUser['is_active'] && (
    $activeUsers <= 1
    || (fortress_normalize_role($deleteUser['role'] ?? 'superadmin') === 'superadmin' && fortress_active_superadmin_count($pdo) <= 1)
);

$managementAuditLines = array_values(array_filter(
    fortress_read_lines(__DIR__ . '/../data/audit.log'),
    static fn(string $line): bool => fortress_line_has_any($line, [
        'security_report_generated', 'user_management_access', 'user_account_created', 'user_account_updated',
        'user_account_enabled', 'user_account_disabled', 'user_password_reset',
        'user_password_changed_during_edit', 'user_personal_id_reset', 'user_account_deleted', 'login_disabled_account',
        'user_2fa_enabled', 'user_2fa_disabled', 'user_2fa_replaced', 'user_role_changed', 'user_profile_viewed', 'user_management_denied', 'current_user_security_policy_changed',
    ])
));
$managementAuditLines = array_slice(array_reverse($managementAuditLines), 0, 12);

audit_log('user_management_access uid=' . $userId);
?>
<!doctype html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#10071f">
    <title>FortressAuth — Current Operator</title>
    <link rel="stylesheet" href="/css/all.min.css">
    <link rel="stylesheet" href="/css/dashboard.css">
    <link rel="stylesheet" href="/css/user_management_profile.css">
<link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head>
<body class="command-page user-management-page">
<div class="ambient ambient-one" aria-hidden="true"></div>
<div class="ambient ambient-two" aria-hidden="true"></div>
<main class="command-shell">
    <?php require __DIR__ . '/partials/command_header.php'; ?>

    <section class="user-management-hero" id="user-management">
        <div class="user-management-copy">
            <div class="user-management-badges">
                <span><i class="fa-solid fa-user-shield"></i> CURRENT OPERATOR WORKSPACE</span>
                <span class="verified"><i class="fa-solid fa-lock"></i> <?= $isSuperAdmin ? 'SUPER ADMIN CONTROL' : 'ADMIN ACCESS' ?></span>
            </div>
            <h1>Manage users, QR factors, and reports from one <span>secure workspace.</span></h1>
            <p>This Current Operator page combines role-aware account oversight, your QR possession-factor controls, and documentation exports in one protected workspace.</p>
        </div>
        <aside class="access-health-card">
            <div class="access-health-top">
                <div><span>ACCESS HEALTH</span><strong><?= $activeRate ?>% active</strong><small>Current administrator availability</small></div>
                <div class="access-health-ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="access-ring-track" cx="50" cy="50" r="42" pathLength="100"></circle><circle class="access-ring-value" cx="50" cy="50" r="42" pathLength="100" stroke-dasharray="<?= max(0, min(100, $activeRate)) ?> 100"></circle></svg><div><strong><?= $activeUsers ?></strong><span>ACTIVE</span></div></div>
            </div>
            <div class="access-health-mini"><div><span>Inactive</span><strong><?= $inactiveUsers ?></strong></div><div><span>2FA accounts</span><strong><?= $personalIdUsers ?></strong></div></div>
            <progress class="access-health-track" max="100" value="<?= max(0, min(100, $activeRate)) ?>" aria-label="Active account percentage"></progress>
        </aside>
    </section>

    <nav class="operator-workspace-tabs" aria-label="Current Operator workspace sections">
        <a href="#user-management"><i class="fa-solid fa-users-gear"></i><span><strong>User Management</strong><small>Accounts, access and passwords</small></span></a>
        <a href="#personal-id"><i class="fa-solid fa-qrcode"></i><span><strong>QR Factor</strong><small>Your possession credential</small></span></a>
        <a href="#reports"><i class="fa-solid fa-file-export"></i><span><strong>Reports</strong><small>PDF, PowerPoint and Excel documentation</small></span></a>
    </nav>

    <?php if ($flash): ?>
        <div class="user-management-message <?= ($flash['type'] ?? '') === 'error' ? 'error' : 'success' ?>">
            <i class="fa-solid <?= ($flash['type'] ?? '') === 'error' ? 'fa-triangle-exclamation' : 'fa-circle-check' ?>"></i>
            <span><?= e((string)($flash['message'] ?? '')) ?></span>
        </div>
    <?php endif; ?>

    <?php if ($isSuperAdmin && is_array($generatedQrHandoff) && !empty($generatedQrHandoff['credential'])): ?>
        <section class="generated-qr-handoff" id="generated-qr-handoff" role="dialog" aria-modal="true" aria-labelledby="generated-qr-title">
            <div class="generated-qr-handoff-card">
                <div class="generated-qr-handoff-head">
                    <span class="generated-qr-shield"><i class="fa-solid fa-qrcode"></i></span>
                    <div>
                        <span class="eyebrow">ONE-TIME QR HANDOFF</span>
                        <h2 id="generated-qr-title"><?= ($generatedQrHandoff['mode'] ?? '') === 'created' ? 'QR credential issued' : 'QR credential regenerated' ?></h2>
                        <p>Give this QR to <strong><?= e((string)($generatedQrHandoff['full_name'] ?: $generatedQrHandoff['username'])) ?></strong> for future 2FA verification.</p>
                    </div>
                </div>
                <div class="generated-qr-handoff-body">
                    <div class="generated-qr-display" id="generated-qr-code" data-qr-value="<?= e((string)$generatedQrHandoff['credential']) ?>" data-qr-username="<?= e((string)$generatedQrHandoff['username']) ?>"></div>
                    <div class="generated-qr-instructions">
                        <div><span>01</span><p><strong>Save or print this QR now</strong><small>The raw credential is shown only on this page load.</small></p></div>
                        <div><span>02</span><p><strong>Give it only to the account owner</strong><small>Anyone holding a copy can present it as the possession factor after the password step.</small></p></div>
                        <div><span>03</span><p><strong>Regenerate if it is lost or copied</strong><small>A regenerated QR immediately replaces the previous credential.</small></p></div>
                    </div>
                </div>
                <div class="generated-qr-handoff-actions">
                    <button type="button" id="generated-qr-download"><i class="fa-solid fa-download"></i> Download QR</button>
                    <button type="button" id="generated-qr-print"><i class="fa-solid fa-print"></i> Print QR</button>
                    <button type="button" class="primary" id="generated-qr-dismiss"><i class="fa-solid fa-circle-check"></i> I saved the QR</button>
                </div>
                <p class="generated-qr-warning"><i class="fa-solid fa-triangle-exclamation"></i> FortressAuth stores only the credential hash. After you dismiss or reload this page, this exact QR cannot be displayed again.</p>
            </div>
        </section>
    <?php endif; ?>

    <?php if (!$schemaReady): ?>
        <div class="user-management-message error"><i class="fa-solid fa-database"></i><span>Optional 2FA account controls are not ready yet. Apply sql/optional_2fa.sql once with the database owner or migration account.</span></div>
    <?php elseif (!$generatedQrReady): ?>
        <div class="user-management-message warning"><i class="fa-solid fa-qrcode"></i><span>Personal ID 2FA is still available. To enable administrator-issued QR credentials, run <b>sql/generated_qr_2fa.sql</b> once in Supabase.</span></div>
    <?php endif; ?>
    <?php if (!$roleReady): ?>
        <div class="user-management-message warning"><i class="fa-solid fa-user-shield"></i><span>Role separation is not active yet. Run <b>sql/user_roles.sql</b> once in Supabase. Until then, existing privileged accounts retain legacy Super Admin access.</span></div>
    <?php elseif (!$isSuperAdmin): ?>
        <div class="user-management-message role-info"><i class="fa-solid fa-eye"></i><span>You are signed in as <b>Admin</b>. All system pages remain available, but user-account creation, editing, password resets, activation changes, 2FA changes, and deletion are reserved for Super Admins.</span></div>
    <?php endif; ?>

    <section class="user-management-stats">
        <article><span class="user-stat-icon"><i class="fa-solid fa-users"></i></span><div><small>TOTAL OPERATORS</small><strong><?= $totalUsers ?></strong><p>Registered privileged accounts</p></div></article>
        <article><span class="user-stat-icon identity"><i class="fa-solid fa-crown"></i></span><div><small>SUPER ADMINS</small><strong><?= $superAdminUsers ?></strong><p>Full account-management authority</p></div></article>
        <article><span class="user-stat-icon success"><i class="fa-solid fa-user-shield"></i></span><div><small>ADMINS</small><strong><?= $adminUsers ?></strong><p>System access without user administration</p></div></article>
        <article><span class="user-stat-icon danger"><i class="fa-solid fa-user-check"></i></span><div><small>ACTIVE ACCESS</small><strong><?= $activeUsers ?></strong><p>Accounts allowed to authenticate</p></div></article>
    </section>

    <?php if ($isSuperAdmin && $deleteUser): ?>
        <section class="delete-confirm-panel <?= $deleteBlockedAsLastActive ? 'blocked' : '' ?>" id="delete-confirmation">
            <span class="delete-confirm-icon"><i class="fa-solid <?= $deleteBlockedAsLastActive ? 'fa-shield-halved' : 'fa-triangle-exclamation' ?>"></i></span>
            <div>
                <small><?= $deleteBlockedAsLastActive ? 'ACCOUNT SAFEGUARD' : 'DESTRUCTIVE ACTION' ?></small>
                <h2>Delete <?= e((string)$deleteUser['username']) ?>?</h2>
                <?php if ($deleteBlockedAsLastActive): ?>
                    <p>This is currently the last active administrator. Create and activate another administrator first so FortressAuth is not left with no usable administrator account.</p>
                <?php elseif ($deleteUserIsCurrent): ?>
                    <p>This is the account you are currently using. Deleting it permanently removes the account and its registered QR credential, then FortressAuth will immediately end this session and return you to the login page.</p>
                <?php else: ?>
                    <p>This permanently removes the administrator account and its registered QR credential. Audit evidence already written to the security log is retained.</p>
                <?php endif; ?>
            </div>
            <div class="delete-confirm-actions">
                <a href="/user_management.php">Cancel</a>
                <?php if ($deleteBlockedAsLastActive): ?>
                    <a class="create-admin-first" href="/user_management.php#account-editor"><i class="fa-solid fa-user-plus"></i> Create another admin</a>
                <?php else: ?>
                    <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                        <input type="hidden" name="action" value="delete_user">
                        <input type="hidden" name="user_id" value="<?= (int)$deleteUser['id'] ?>">
                        <button type="submit"><i class="fa-solid fa-trash-can"></i> <?= $deleteUserIsCurrent ? 'Delete & sign out' : 'Delete administrator' ?></button>
                    </form>
                <?php endif; ?>
            </div>
        </section>
    <?php endif; ?>

    <section class="user-management-workspace">
        <?php if ($isSuperAdmin): ?>
        <article class="panel user-editor-panel" id="account-editor">
            <div class="panel-heading">
                <div><span class="eyebrow"><?= $editUser ? 'EDIT ACCOUNT' : 'CREATE ACCOUNT' ?></span><h2><?= $editUser ? 'Update administrator details' : 'New administrator' ?></h2><p><?= $editUser ? 'Modify account identity and access status.' : 'Issue a new privileged FortressAuth account.' ?></p></div>
                <span class="panel-symbol"><i class="fa-solid <?= $editUser ? 'fa-user-pen' : 'fa-user-plus' ?>"></i></span>
            </div>
            <form method="post" class="user-editor-form">
                <?php if ($editUser): ?>
                    <div class="editing-account-banner">
                        <i class="fa-solid fa-user-pen"></i>
                        <div>
                            <strong>Editing <?= e((string)($editUser['full_name'] ?: $editUser['username'])) ?></strong>
                            <span>Change the fields below, then press <b>Save changes</b>.</span>
                        </div>
                    </div>
                <?php endif; ?>
                <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                <input type="hidden" name="action" value="<?= $editUser ? 'update_user' : 'create_user' ?>">
                <?php if ($editUser): ?><input type="hidden" name="user_id" value="<?= (int)$editUser['id'] ?>"><?php endif; ?>

                <label><span><i class="fa-solid fa-address-card"></i> Display name</span><input name="full_name" required maxlength="160" value="<?= e((string)($editUser['full_name'] ?? '')) ?>" placeholder="Example: Security Administrator"></label>
                <label><span><i class="fa-solid fa-at"></i> Username</span><input name="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9_]{3,32}" value="<?= e((string)($editUser['username'] ?? '')) ?>" placeholder="admin_operator"></label>
                <?php $editRole = $editUser ? fortress_normalize_role($editUser['role'] ?? 'superadmin') : 'admin'; ?>
                <div class="account-role-field">
                    <span class="account-role-label"><i class="fa-solid fa-user-shield"></i> Account role</span>
                    <div class="fortress-role-picker" data-role-picker data-role-value="<?= e($editRole) ?>">
                        <input type="hidden" name="role" value="<?= e($editRole) ?>" data-role-input>
                        <button type="button" class="fortress-role-trigger" data-role-trigger aria-haspopup="listbox" aria-expanded="false" <?= !$roleReady ? 'disabled' : '' ?>>
                            <span class="fortress-role-trigger-icon"><i class="fa-solid <?= $editRole === 'superadmin' ? 'fa-crown' : 'fa-user-shield' ?>"></i></span>
                            <span class="fortress-role-trigger-copy">
                                <strong data-role-title><?= $editRole === 'superadmin' ? 'Super Admin' : 'Admin' ?></strong>
                                <small data-role-description><?= $editRole === 'superadmin' ? 'Full system and account-management authority' : 'Full system access without account administration' ?></small>
                            </span>
                            <span class="fortress-role-trigger-badge" data-role-badge><?= $editRole === 'superadmin' ? 'FULL CONTROL' : 'STANDARD' ?></span>
                            <i class="fa-solid fa-chevron-down fortress-role-chevron" aria-hidden="true"></i>
                        </button>
                        <div class="fortress-role-menu" data-role-menu role="listbox" aria-label="Account role" hidden>
                            <button type="button" class="fortress-role-option <?= $editRole === 'admin' ? 'selected' : '' ?>" data-role-option="admin" data-role-icon="fa-user-shield" data-role-title-value="Admin" data-role-description-value="Full system access without account administration" data-role-badge-value="STANDARD" role="option" aria-selected="<?= $editRole === 'admin' ? 'true' : 'false' ?>">
                                <span class="fortress-role-option-icon"><i class="fa-solid fa-user-shield"></i></span>
                                <span><strong>Admin</strong><small>Can navigate all system pages, but cannot create, edit, delete, reset, or manage other accounts.</small></span>
                                <i class="fa-solid fa-check role-option-check"></i>
                            </button>
                            <button type="button" class="fortress-role-option superadmin <?= $editRole === 'superadmin' ? 'selected' : '' ?>" data-role-option="superadmin" data-role-icon="fa-crown" data-role-title-value="Super Admin" data-role-description-value="Full system and account-management authority" data-role-badge-value="FULL CONTROL" role="option" aria-selected="<?= $editRole === 'superadmin' ? 'true' : 'false' ?>">
                                <span class="fortress-role-option-icon"><i class="fa-solid fa-crown"></i></span>
                                <span><strong>Super Admin</strong><small>Full authority including account creation, roles, passwords, 2FA, activation, and deletion.</small></span>
                                <i class="fa-solid fa-check role-option-check"></i>
                            </button>
                        </div>
                    </div>
                    <small class="account-role-help"><?= $roleReady ? 'New accounts default to Admin. Assign Super Admin only when full account-management authority is required.' : 'Run sql/user_roles.sql in Supabase before assigning roles.' ?></small>
                </div>
                <?php if (!$editUser): ?>
                    <label><span><i class="fa-solid fa-key"></i> Temporary password</span><input type="password" name="password" required minlength="12" maxlength="128" autocomplete="new-password" placeholder="Minimum 12 characters"><small>The password is hashed server-side and is never stored in plain text.</small></label>
                <?php else: ?>
                    <label>
                        <span><i class="fa-solid fa-key"></i> Change password <em>OPTIONAL</em></span>
                        <input type="password" name="new_password" minlength="12" maxlength="128" autocomplete="new-password" placeholder="Leave blank to keep the current password">
                        <small>Enter a new password only if you want to replace this administrator's existing password.</small>
                    </label>
                <?php endif; ?>
                <?php
                    $editRequires2fa = $editUser ? (bool)($editUser['school_id_2fa_required'] ?? true) : true;
                    $editHasPersonalId = $editUser ? (bool)($editUser['school_id_qr_enabled'] ?? false) : false;
                    $editFactorType = $editUser ? fortress_second_factor_type_value($editUser) : 'personal_id';
                    $editingCurrentAccount = $editUser && (int)$editUser['id'] === $userId;
                ?>
                <section class="two-factor-config-panel" aria-labelledby="two-factor-config-title">
                    <div class="two-factor-config-header">
                        <div class="two-factor-config-heading">
                            <span class="two-factor-config-icon"><i class="fa-solid fa-shield-halved"></i></span>
                            <div>
                                <span class="two-factor-kicker">ACCOUNT PROTECTION</span>
                                <strong id="two-factor-config-title">Second-factor access</strong>
                                <small>Choose whether this administrator must verify a QR credential after the password step.</small>
                            </div>
                        </div>
                        <span
                            class="two-factor-status-chip <?= $editRequires2fa ? ($editFactorType === 'generated_qr' ? 'is-generated' : 'is-personal') : 'is-off' ?>"
                            id="two-factor-status-chip"
                            aria-live="polite"
                        ><?= !$editRequires2fa ? 'PASSWORD ONLY' : ($editFactorType === 'generated_qr' ? 'ISSUED QR' : 'PERSONAL ID QR') ?></span>
                    </div>

                    <label class="user-active-switch two-factor-master-switch">
                        <span class="two-factor-switch-copy">
                            <strong>Require QR verification</strong>
                            <small><?= $editUser
                                ? 'Turn this off for password-only access. Keep it on to require a QR credential after the password is accepted.'
                                : 'Recommended for privileged accounts. The administrator completes a QR verification step after entering the correct password.' ?></small>
                        </span>
                        <input
                            type="checkbox"
                            id="require-school-id-2fa"
                            name="require_school_id_2fa"
                            data-editing="<?= $editUser ? '1' : '0' ?>"
                            data-has-qr="<?= $editHasPersonalId ? '1' : '0' ?>"
                            data-current-factor="<?= e($editFactorType) ?>"
                            data-current-account="<?= $editingCurrentAccount ? '1' : '0' ?>"
                            <?= $editRequires2fa ? 'checked' : '' ?>
                        >
                        <i aria-hidden="true"></i>
                    </label>

                    <fieldset class="second-factor-method-control" id="second-factor-method-control" <?= $editRequires2fa ? '' : 'disabled' ?>>
                        <legend>Credential method</legend>
                        <label class="factor-method-card">
                            <input type="radio" name="second_factor_type" value="personal_id" <?= $editFactorType === 'personal_id' ? 'checked' : '' ?>>
                            <span class="factor-method-icon"><i class="fa-solid fa-id-card"></i></span>
                            <span class="factor-method-copy">
                                <strong>Personal ID QR</strong>
                                <small>Use the QR already assigned to the account owner's Personal ID.</small>
                            </span>
                            <span class="factor-method-select"><i class="fa-solid fa-check"></i></span>
                        </label>
                        <label class="factor-method-card factor-method-card-generated <?= !$generatedQrReady ? 'unavailable' : '' ?>">
                            <input type="radio" name="second_factor_type" value="generated_qr" <?= $editFactorType === 'generated_qr' ? 'checked' : '' ?> <?= !$generatedQrReady ? 'disabled' : '' ?>>
                            <span class="factor-method-icon generated"><i class="fa-solid fa-qrcode"></i></span>
                            <span class="factor-method-copy">
                                <strong>FortressAuth-issued QR</strong>
                                <small><?= $generatedQrReady ? 'Generate a dedicated QR credential for this administrator after the account is saved.' : 'Run sql/generated_qr_2fa.sql in Supabase once to enable this option.' ?></small>
                            </span>
                            <span class="factor-method-select"><i class="fa-solid fa-check"></i></span>
                        </label>
                    </fieldset>

                    <label id="personal-id-qr-control" class="factor-detail-control">
                        <span class="factor-detail-label">
                            <span><i class="fa-solid fa-id-card-clip"></i> <?= $editUser && $editHasPersonalId && $editFactorType === 'personal_id' ? 'Replace Personal ID QR' : 'Personal ID QR value' ?></span>
                            <em><?= $editUser && $editHasPersonalId && $editFactorType === 'personal_id' ? 'OPTIONAL' : 'REQUIRED' ?></em>
                        </span>
                        <input
                            type="password"
                            id="personal-id-qr-value"
                            name="personal_id_qr"
                            maxlength="4096"
                            autocomplete="off"
                            placeholder="<?= $editUser && $editHasPersonalId && $editFactorType === 'personal_id' ? 'Leave blank to keep the current QR' : 'Paste the Personal ID QR value' ?>"
                        >
                        <small><?= $editUser && $editHasPersonalId && $editFactorType === 'personal_id'
                            ? 'Leave this blank to keep the existing Personal ID QR. Enter a new value only when replacing it.'
                            : 'Paste the QR payload assigned to the account owner.' ?></small>
                        <small id="personal-id-2fa-live-status" class="factor-detail-status" aria-live="polite"></small>
                    </label>

                    <div class="generated-qr-config" id="generated-qr-config" hidden>
                        <span class="generated-qr-config-icon"><i class="fa-solid fa-qrcode"></i></span>
                        <div>
                            <span class="generated-qr-kicker">ISSUED CREDENTIAL</span>
                            <strong>Administrator-issued QR</strong>
                            <p id="generated-qr-config-copy">FortressAuth will create a unique QR when this account is saved. Save or print the one-time handoff before leaving the page.</p>
                            <?php if ($editUser && $editHasPersonalId && $editFactorType === 'generated_qr'): ?>
                                <?php if ($editingCurrentAccount): ?>
                                    <small class="generated-qr-self-note"><i class="fa-solid fa-circle-info"></i> Another active administrator must regenerate the QR for the account currently signed in.</small>
                                <?php else: ?>
                                    <label class="generated-qr-regenerate">
                                        <input type="checkbox" name="regenerate_generated_qr" value="1">
                                        <span><strong>Issue a new QR on save</strong><small>The current QR will stop working after the replacement is saved.</small></span>
                                    </label>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </section>

                <?php if ($editUser): ?>
                    <div class="editing-account-banner">
                        <i class="fa-solid <?= $editRequires2fa ? 'fa-shield-halved' : 'fa-key' ?>"></i>
                        <div>
                            <strong>Current login policy: <?= !$editRequires2fa ? 'PASSWORD ONLY' : ($editFactorType === 'generated_qr' ? 'PASSWORD + ISSUED QR' : 'PASSWORD + PERSONAL ID QR') ?></strong>
                            <span>
                                <?php if ($editRequires2fa && $editHasPersonalId && $editFactorType === 'generated_qr'): ?>
                                    2FA is enabled with an administrator-issued QR credential.
                                <?php elseif ($editRequires2fa && $editHasPersonalId): ?>
                                    2FA is enabled with a registered Personal ID QR.
                                <?php elseif ($editRequires2fa): ?>
                                    2FA is required, but this account does not currently have a usable QR credential.
                                <?php else: ?>
                                    QR-based 2FA is disabled for this account.
                                <?php endif; ?>
                                <?php if ((int)$editUser['id'] === $userId): ?>
                                    Changing your own password or 2FA policy will sign you out immediately.
                                <?php endif; ?>
                            </span>
                        </div>
                    </div>
                <?php endif; ?>

                <label class="user-active-switch"><span><strong>Active account</strong><small>Inactive administrators cannot pass the password factor.</small></span><input type="checkbox" name="is_active" <?= !$editUser || (bool)$editUser['is_active'] ? 'checked' : '' ?>><i></i></label>

                <div class="user-form-actions <?= $editUser ? 'editing' : '' ?>">
                    <?php if ($editUser): ?>
                        <a href="/user_management.php">Cancel edit</a>
                        <?php if ((int)$editUser['id'] !== $userId): ?>
                            <a class="editor-delete-action" href="/user_management.php?confirm_delete=<?= (int)$editUser['id'] ?>#delete-confirmation">
                                <i class="fa-solid fa-trash"></i> Delete account
                            </a>
                        <?php endif; ?>
                    <?php endif; ?>
                    <button type="submit"><i class="fa-solid <?= $editUser ? 'fa-floppy-disk' : 'fa-plus' ?>"></i> <?= $editUser ? 'Save changes' : 'Create administrator' ?></button>
                </div>
            </form>
        </article>
        <?php else: ?>
        <article class="panel user-editor-panel role-readonly-panel" id="account-editor">
            <div class="panel-heading">
                <div><span class="eyebrow">ROLE-BASED ACCESS</span><h2>User administration is read-only</h2><p>Admins can navigate every FortressAuth page and review the operator directory, but only a Super Admin can create, edit, reset, disable, or delete accounts.</p></div>
                <span class="panel-symbol"><i class="fa-solid fa-user-shield"></i></span>
            </div>
            <div class="role-readonly-body"><i class="fa-solid fa-lock"></i><div><strong>Super Admin authorization required</strong><span>Ask a Super Admin when an account needs to be created or changed.</span></div></div>
        </article>
        <?php endif; ?>

        <article class="panel user-directory-panel">
            <div class="panel-heading user-directory-heading">
                <div><span class="eyebrow">OPERATOR DIRECTORY</span><h2>Registered operators</h2><p><?= count($filteredUsers) ?> of <?= $totalUsers ?> accounts shown</p></div>
                <a class="text-link" href="/user_management.php"><i class="fa-solid fa-arrows-rotate"></i> Refresh</a>
            </div>
            <form method="get" class="user-directory-filters">
                <label class="user-search-control"><i class="fa-solid fa-magnifying-glass"></i><input name="q" value="<?= e($q) ?>" placeholder="Search administrators..."></label>
                <select name="status" aria-label="Filter account status"><option value="all" <?= $statusFilter==='all'?'selected':'' ?>>All status</option><option value="active" <?= $statusFilter==='active'?'selected':'' ?>>Active</option><option value="inactive" <?= $statusFilter==='inactive'?'selected':'' ?>>Inactive</option></select>
                <select name="identity" aria-label="Filter QR-based 2FA"><option value="all" <?= $idFilter==='all'?'selected':'' ?>>All 2FA policies</option><option value="enabled" <?= $idFilter==='enabled'?'selected':'' ?>>2FA enabled</option><option value="disabled" <?= $idFilter==='disabled'?'selected':'' ?>>2FA disabled</option></select>
                <select name="role" aria-label="Filter account role"><option value="all" <?= $roleFilter==='all'?'selected':'' ?>>All roles</option><option value="superadmin" <?= $roleFilter==='superadmin'?'selected':'' ?>>Super Admin</option><option value="admin" <?= $roleFilter==='admin'?'selected':'' ?>>Admin</option></select>
                <button type="submit"><i class="fa-solid fa-filter"></i> Filter</button>
            </form>

            <div class="user-directory-list">
                <?php if (!$filteredUsers): ?>
                    <div class="user-directory-empty"><i class="fa-solid fa-users-slash"></i><strong>No administrators found</strong><span>Try changing the search or filters.</span></div>
                <?php else: foreach ($filteredUsers as $account):
                    $isCurrent = (int)$account['id'] === $userId;
                    $displayName = trim((string)$account['full_name']) !== '' ? (string)$account['full_name'] : (string)$account['username'];
                    $initial = strtoupper(substr($displayName, 0, 1));
                    $lastLogin = fortress_format_date_value($account['last_login_at'] ? (string)$account['last_login_at'] : null, 'Not yet');
                    $created = fortress_format_date_value($account['created_at'] ? (string)$account['created_at'] : null, 'Unknown');
                    $accountRole = fortress_normalize_role($account['role'] ?? 'superadmin');
                ?>
                    <section class="user-account-card <?= $isCurrent ? 'current' : '' ?>">
                        <div class="user-account-avatar"><?= e($initial) ?></div>
                        <div class="user-account-main">
                            <div class="user-account-title"><strong><?= e($displayName) ?></strong><span class="admin-chip <?= $accountRole === 'superadmin' ? 'superadmin' : '' ?>"><?= $accountRole === 'superadmin' ? 'SUPER ADMIN' : 'ADMIN' ?></span><span class="account-state <?= (bool)$account['is_active'] ? 'active' : 'inactive' ?>"><?= (bool)$account['is_active'] ? 'ACTIVE' : 'INACTIVE' ?></span><?php if ($isCurrent): ?><span class="current-chip">CURRENT</span><?php endif; ?></div>
                            <p>@<?= e((string)$account['username']) ?></p>
                            <div class="user-account-meta"><span><i class="fa-solid fa-id-card"></i>
                                <?php $accountFactorType = fortress_second_factor_type_value($account); ?>
                                <?php if (!(bool)($account['school_id_2fa_required'] ?? true)): ?>
                                    2FA: DISABLED · Password only
                                <?php elseif ((bool)$account['school_id_qr_enabled'] && $accountFactorType === 'generated_qr'): ?>
                                    2FA: ENABLED · Issued QR active
                                <?php elseif ((bool)$account['school_id_qr_enabled']): ?>
                                    2FA: ENABLED · Personal ID enrolled
                                <?php else: ?>
                                    2FA: ENABLED · Credential required
                                <?php endif; ?>
                            </span><span><i class="fa-solid fa-clock"></i> Last login: <?= e($lastLogin) ?></span><span><i class="fa-solid fa-calendar"></i> Created: <?= e($created) ?></span></div>
                        </div>
                        <div class="user-account-actions">
                            <?php if ($isSuperAdmin): ?>
                            <a class="profile-action" href="/user_management.php?profile=<?= (int)$account['id'] ?>#operator-profile" title="View operator profile">
                                <i class="fa-solid fa-address-card"></i><span>View profile</span>
                            </a>
                            <a class="edit-action" href="/user_management.php?edit=<?= (int)$account['id'] ?>#account-editor" title="Edit administrator">
                                <i class="fa-solid fa-user-pen"></i><span>Edit account</span>
                            </a>
                            <a href="/user_management.php?reset=<?= (int)$account['id'] ?>#password-reset" title="Reset password">
                                <i class="fa-solid fa-key"></i><span>Password</span>
                            </a>

                            <?php if (!$isCurrent): ?>
                                <form method="post">
                                    <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                                    <input type="hidden" name="action" value="toggle_user">
                                    <input type="hidden" name="user_id" value="<?= (int)$account['id'] ?>">
                                    <button class="<?= (bool)$account['is_active'] ? 'warning' : 'success' ?>" type="submit">
                                        <i class="fa-solid <?= (bool)$account['is_active'] ? 'fa-user-lock' : 'fa-user-check' ?>"></i>
                                        <span><?= (bool)$account['is_active'] ? 'Disable' : 'Activate' ?></span>
                                    </button>
                                </form>

                                <?php if ((bool)($account['school_id_2fa_required'] ?? true)): ?>
                                    <form method="post">
                                        <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                                        <input type="hidden" name="action" value="disable_2fa">
                                        <input type="hidden" name="user_id" value="<?= (int)$account['id'] ?>">
                                        <button type="submit"><i class="fa-solid fa-id-card-clip"></i><span>Disable 2FA</span></button>
                                    </form>
                                <?php endif; ?>

                                <a class="danger delete-action" href="/user_management.php?confirm_delete=<?= (int)$account['id'] ?>#delete-confirmation" title="Delete administrator permanently">
                                    <i class="fa-solid fa-trash-can"></i><span>Delete account</span>
                                </a>
                            <?php else: ?>
                                <a class="danger delete-action current-delete-action" href="/user_management.php?confirm_delete=<?= (int)$account['id'] ?>#delete-confirmation" title="Delete this current account">
                                    <i class="fa-solid fa-trash-can"></i><span>Delete account</span>
                                </a>
                            <?php endif; ?>
                            <?php else: ?>
                                <span class="role-readonly-chip"><i class="fa-solid fa-eye"></i> View only</span>
                            <?php endif; ?>
                        </div>
                    </section>
                <?php endforeach; endif; ?>
            </div>
        </article>
    </section>

    <?php if ($isSuperAdmin && $profileUser): ?>
        <?php
            $profileDisplayName = trim((string)($profileUser['full_name'] ?? '')) ?: (string)$profileUser['username'];
            $profileRole = fortress_normalize_role($profileUser['role'] ?? 'superadmin');
            $profileFactorType = fortress_second_factor_type_value($profileUser);
            $profileRequires2fa = (bool)($profileUser['school_id_2fa_required'] ?? true);
            $profileHasQr = (bool)($profileUser['school_id_qr_enabled'] ?? false);
            $profileCreated = fortress_format_date_value($profileUser['created_at'] ? (string)$profileUser['created_at'] : null, 'Unknown');
            $profileUpdated = fortress_format_date_value($profileUser['updated_at'] ? (string)$profileUser['updated_at'] : null, 'Unknown');
            $profileLastLogin = fortress_format_date_value($profileUser['last_login_at'] ? (string)$profileUser['last_login_at'] : null, 'Not yet');
            $profileQrUpdated = fortress_format_date_value($profileUser['school_id_qr_updated_at'] ? (string)$profileUser['school_id_qr_updated_at'] : null, 'Not registered');
            $profile2faLabel = !$profileRequires2fa
                ? 'Password only'
                : ($profileFactorType === 'generated_qr' ? 'FortressAuth-issued QR' : 'Personal ID QR');
            $profileQrState = !$profileRequires2fa ? 'Not required' : ($profileHasQr ? 'Credential active' : 'Credential required');
        ?>
        <section class="operator-profile-overlay" id="operator-profile" role="dialog" aria-modal="true" aria-labelledby="operator-profile-title" data-operator-profile>
            <a class="operator-profile-backdrop" href="/user_management.php#operator-directory" aria-label="Close operator profile"></a>
            <article class="operator-profile-card">
                <header class="operator-profile-header">
                    <div class="operator-profile-identity">
                        <span class="operator-profile-avatar"><?= e(strtoupper(substr($profileDisplayName, 0, 1))) ?></span>
                        <div>
                            <span class="eyebrow">OPERATOR PROFILE</span>
                            <h2 id="operator-profile-title"><?= e($profileDisplayName) ?></h2>
                            <p>@<?= e((string)$profileUser['username']) ?></p>
                        </div>
                    </div>
                    <div class="operator-profile-header-actions">
                        <span class="admin-chip <?= $profileRole === 'superadmin' ? 'superadmin' : '' ?>"><?= $profileRole === 'superadmin' ? 'SUPER ADMIN' : 'ADMIN' ?></span>
                        <span class="account-state <?= (bool)$profileUser['is_active'] ? 'active' : 'inactive' ?>"><?= (bool)$profileUser['is_active'] ? 'ACTIVE' : 'INACTIVE' ?></span>
                        <a class="operator-profile-close" href="/user_management.php#operator-directory" aria-label="Close profile"><i class="fa-solid fa-xmark"></i></a>
                    </div>
                </header>

                <div class="operator-profile-grid">
                    <section class="operator-profile-section">
                        <div class="operator-profile-section-title"><i class="fa-solid fa-address-card"></i><div><strong>Account information</strong><small>Identity and lifecycle details for this operator.</small></div></div>
                        <dl class="operator-profile-details">
                            <div><dt>Display name</dt><dd><?= e($profileDisplayName) ?></dd></div>
                            <div><dt>Username</dt><dd>@<?= e((string)$profileUser['username']) ?></dd></div>
                            <div><dt>Account ID</dt><dd>#<?= (int)$profileUser['id'] ?></dd></div>
                            <div><dt>Role</dt><dd><?= $profileRole === 'superadmin' ? 'Super Admin' : 'Admin' ?></dd></div>
                            <div><dt>Status</dt><dd><?= (bool)$profileUser['is_active'] ? 'Active' : 'Inactive' ?></dd></div>
                            <div><dt>Current operator</dt><dd><?= (int)$profileUser['id'] === $userId ? 'Yes' : 'No' ?></dd></div>
                        </dl>
                    </section>

                    <section class="operator-profile-section">
                        <div class="operator-profile-section-title"><i class="fa-solid fa-clock-rotate-left"></i><div><strong>Activity</strong><small>Recent account lifecycle timestamps.</small></div></div>
                        <dl class="operator-profile-details">
                            <div><dt>Last login</dt><dd><?= e($profileLastLogin) ?></dd></div>
                            <div><dt>Created</dt><dd><?= e($profileCreated) ?></dd></div>
                            <div><dt>Last updated</dt><dd><?= e($profileUpdated) ?></dd></div>
                            <div><dt>QR updated</dt><dd><?= e($profileQrUpdated) ?></dd></div>
                        </dl>
                    </section>

                    <section class="operator-profile-section">
                        <div class="operator-profile-section-title"><i class="fa-solid fa-qrcode"></i><div><strong>Second-factor access</strong><small>Current QR possession-factor policy.</small></div></div>
                        <dl class="operator-profile-details">
                            <div><dt>2FA policy</dt><dd><?= e($profile2faLabel) ?></dd></div>
                            <div><dt>QR state</dt><dd><?= e($profileQrState) ?></dd></div>
                        </dl>
                    </section>

                    <section class="operator-profile-section password-profile-section">
                        <div class="operator-profile-section-title"><i class="fa-solid fa-key"></i><div><strong>Password credential</strong><small>Super Admin credential controls.</small></div></div>
                        <div class="password-protection-box">
                            <div class="password-protection-row">
                                <span class="password-mask" aria-label="Password protected">••••••••••••••••</span>
                                <span class="password-hash-chip"><i class="fa-solid fa-lock"></i> ONE-WAY HASH</span>
                            </div>
                            <p>The current password cannot be revealed because FortressAuth never stores the plaintext password. A Super Admin can issue a new temporary password and reveal it before the reset is submitted.</p>
                            <a class="operator-profile-password-action" href="/user_management.php?reset=<?= (int)$profileUser['id'] ?>#password-reset"><i class="fa-solid fa-key"></i> Reset & reveal new temporary password</a>
                        </div>
                    </section>
                </div>

                <footer class="operator-profile-footer">
                    <a href="/user_management.php?edit=<?= (int)$profileUser['id'] ?>#account-editor"><i class="fa-solid fa-user-pen"></i> Edit account</a>
                    <?php if ((int)$profileUser['id'] !== $userId): ?>
                        <a class="danger" href="/user_management.php?confirm_delete=<?= (int)$profileUser['id'] ?>#delete-confirmation"><i class="fa-solid fa-trash-can"></i> Delete account</a>
                    <?php endif; ?>
                    <a class="secondary" href="/user_management.php#operator-directory"><i class="fa-solid fa-arrow-left"></i> Back to directory</a>
                </footer>
            </article>
        </section>
    <?php endif; ?>

    <?php if ($isSuperAdmin && $resetUser): ?>
        <section class="panel password-reset-panel" id="password-reset">
            <div class="panel-heading"><div><span class="eyebrow">CREDENTIAL CONTROL</span><h2>Reset password for <?= e((string)$resetUser['username']) ?></h2><p>Issue a new temporary password. The existing QR-based second factor remains registered.</p></div><a class="text-link" href="/user_management.php">Close</a></div>
            <form method="post" class="password-reset-form"><input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>"><input type="hidden" name="action" value="reset_password"><input type="hidden" name="user_id" value="<?= (int)$resetUser['id'] ?>"><label><span>New temporary password</span><div class="password-reset-field"><input id="superadmin-reset-password" type="password" name="password" minlength="12" maxlength="128" required autocomplete="new-password" placeholder="Minimum 12 characters"><button type="button" class="password-helper-button" data-generate-password><i class="fa-solid fa-wand-magic-sparkles"></i> Generate</button><button type="button" class="password-helper-button" data-toggle-password><i class="fa-solid fa-eye"></i> Show</button></div><small>Existing passwords cannot be displayed because FortressAuth stores only one-way password hashes. A Super Admin can reset the account and reveal the new temporary password before submitting.</small></label><button type="submit"><i class="fa-solid fa-key"></i> Reset password</button></form>
        </section>
    <?php endif; ?>

    <section class="operator-personal-id-section" id="personal-id">
        <div class="operator-section-heading">
            <div>
                <span class="eyebrow">2FA CREDENTIAL</span>
                <h2>Current operator possession factor</h2>
                <p>Review the QR-based second factor used by the administrator account that is currently signed in.</p>
            </div>
            <a class="operator-section-back" href="#user-management"><i class="fa-solid fa-arrow-up"></i> User Management</a>
        </div>

        <?php if (isset($_GET['reverified'])): ?>
            <div class="system-message success"><i class="fa-solid fa-circle-check"></i> QR possession was re-verified successfully. Replacement controls are unlocked for five minutes.</div>
        <?php endif; ?>

        <section class="school-id-overview-grid operator-school-id-overview">
            <article class="panel school-identity-card">
                <div class="panel-heading compact">
                    <div><span class="eyebrow">CURRENT ADMINISTRATOR IDENTITY</span><h2><?= e($usernameRaw) ?></h2></div>
                    <span class="status-pill <?= $personalIdEnabled ? 'status-passed' : 'status-rejected' ?>"><?= !$personalIdRequired ? '2FA DISABLED' : ($personalIdEnabled ? 'REGISTERED & ACTIVE' : 'ENROLLMENT REQUIRED') ?></span>
                </div>
                <div class="school-id-visual">
                    <div class="school-id-chip"><img src="/images/wolf.png" alt=""><span>FORTRESSAUTH</span></div>
                    <div class="school-id-qr-placeholder"><i class="fa-solid fa-qrcode"></i></div>
                    <div><small>POSSESSION FACTOR</small><strong><?= $personalIdUsesGeneratedQr ? 'FortressAuth-issued QR' : 'Physical Personal ID QR' ?></strong><span>Credential value hidden</span></div>
                </div>
                <div class="panel-note"><i class="fa-solid fa-lock"></i> FortressAuth does not display the raw QR payload. Only the protected matching credential is retained server-side.</div>
            </article>

            <article class="panel">
                <div class="panel-heading compact"><div><span class="eyebrow">ID SECURITY STATUS</span><h2>Verification State</h2></div><span class="session-orb"></span></div>
                <dl class="session-details school-page-details">
                    <div><dt>2FA policy</dt><dd><?= $personalIdRequired ? 'REQUIRED' : 'DISABLED' ?></dd></div>
                    <div><dt>Credential state</dt><dd><?= !$personalIdRequired ? 'NOT REQUIRED' : ($personalIdEnabled ? 'ENABLED' : 'NOT ENROLLED') ?></dd></div>
                    <div><dt>Authentication method</dt><dd><?= !$personalIdRequired ? 'PASSWORD ONLY' : ($personalIdUsesGeneratedQr ? 'PASSWORD + ISSUED QR' : 'PASSWORD + PERSONAL ID QR') ?></dd></div>
                    <div><dt>Current session verification</dt><dd><?= $personalIdRequired ? ($schoolIdVerified ? 'PASSED' : 'PENDING') : 'NOT REQUIRED' ?></dd></div>
                    <div><dt>Last successful scan</dt><dd><?= e($lastSchoolIdRelative) ?></dd></div>
                    <div><dt>Credential updated</dt><dd><?= e($personalIdUpdatedDisplay) ?></dd></div>
                    <div><dt>Successful scans / 24h</dt><dd><?= (int)$schoolIdSuccess24h ?></dd></div>
                    <div><dt>Failed scans / 24h</dt><dd><?= (int)$schoolIdFailures24h ?></dd></div>
                    <div><dt>Replacement state</dt><dd><?= $personalIdRecentlyVerified ? 'UNLOCKED / 5 MIN' : 'LOCKED' ?></dd></div>
                </dl>
            </article>
        </section>

        <section class="school-management-grid operator-school-management">
            <article class="panel manage-control-card">
                <div class="panel-heading compact"><div><span class="eyebrow">SECURITY CONTROLS</span><h2>Manage 2FA credential</h2></div><i class="fa-solid fa-shield-halved panel-symbol"></i></div>
                <div class="manage-control-body">
                    <p><?= $personalIdUsesGeneratedQr
                        ? 'This account uses an administrator-issued QR. It can be re-verified here, while regeneration must be performed by a different active administrator.'
                        : 'Replacing a Personal ID is intentionally protected. A fresh successful Personal ID scan is required before the current credential can be revoked.' ?></p>
                    <div class="manage-actions">
                        <?php if ($personalIdRequired && $personalIdEnabled): ?>
                            <form method="post" action="/school_id_reverify.php">
                                <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                                <button class="manage-button" type="submit"><span><i class="fa-solid fa-qrcode"></i> Re-verify current QR credential</span><i class="fa-solid fa-chevron-right"></i></button>
                            </form>
                            <?php if ($personalIdUsesGeneratedQr): ?>
                                <?php if ($isSuperAdmin): ?>
                                <a class="manage-button" href="/user_management.php?edit=<?= $userId ?>#account-editor"><span><i class="fa-solid fa-user-gear"></i> View issued-QR policy</span><i class="fa-solid fa-chevron-right"></i></a>
                                <?php else: ?>
                                <span class="manage-button is-readonly"><span><i class="fa-solid fa-lock"></i> Issued-QR policy is managed by a Super Admin</span></span>
                                <?php endif; ?>
                                <p class="manage-note">For safety, another active Super Admin must regenerate this account's issued QR from User Management.</p>
                            <?php else: ?>
                                <form method="post" action="/school_id_reset.php">
                                    <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                                    <button class="manage-button danger" type="submit" <?= $personalIdRecentlyVerified ? '' : 'disabled' ?>><span><i class="fa-solid fa-id-card-clip"></i> Replace registered Personal ID</span><i class="fa-solid fa-chevron-right"></i></button>
                                </form>
                                <?php if (!$personalIdRecentlyVerified): ?>
                                    <p class="manage-note">Re-verify the current Personal ID first. After a successful possession check, replacement remains unlocked for five minutes.</p>
                                <?php else: ?>
                                    <p class="manage-note">Replacement is unlocked. Continuing revokes the current QR credential, ends this session, and requires enrollment of a new Personal ID on the next login.</p>
                                <?php endif; ?>
                            <?php endif; ?>
                        <?php elseif ($personalIdRequired): ?>
                            <a class="manage-button" href="/logout.php"><span><i class="fa-solid fa-right-from-bracket"></i> Start a new login to complete enrollment</span><i class="fa-solid fa-chevron-right"></i></a>
                        <?php else: ?>
                            <?php if ($isSuperAdmin): ?>
                            <a class="manage-button" href="/user_management.php?edit=<?= $userId ?>#account-editor"><span><i class="fa-solid fa-user-gear"></i> Enable 2FA for this operator</span><i class="fa-solid fa-chevron-right"></i></a>
                            <?php else: ?>
                            <span class="manage-button is-readonly"><span><i class="fa-solid fa-lock"></i> Ask a Super Admin to enable 2FA</span></span>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </article>

            <article class="panel">
                <div class="panel-heading compact"><div><span class="eyebrow">VERIFICATION POLICY</span><h2>QR Factor Guardrails</h2></div><i class="fa-solid fa-list-check panel-symbol"></i></div>
                <div class="policy-list">
                    <div><span>01</span><p><strong>Password first</strong><small>The QR verification step is reached only after the account password has been accepted.</small></p></div>
                    <div><span>02</span><p><strong>Time-limited scan</strong><small>The possession check must finish before the verification session expires.</small></p></div>
                    <div><span>03</span><p><strong>Failed-scan limit</strong><small>Repeated QR mismatches lock the verification attempt and require a fresh login.</small></p></div>
                    <div><span>04</span><p><strong>Protected replacement</strong><small>Personal IDs require re-verification before replacement; issued QR credentials require another Super Admin to regenerate them.</small></p></div>
                </div>
            </article>
        </section>

        <article class="panel data-panel operator-id-history">
            <div class="panel-heading filter-heading">
                <div><span class="eyebrow">VERIFICATION HISTORY</span><h2>QR Factor Security Events</h2><p>Enrollment, issuance, verification, failure, lock, re-verification, regeneration, and reset activity for the possession factor.</p></div>
                <label class="search-control"><i class="fa-solid fa-magnifying-glass"></i><input type="search" data-table-search="schoolHistory" placeholder="Search ID history..."></label>
            </div>
            <div class="responsive-table-wrap">
                <table class="security-table" data-table="schoolHistory">
                    <thead><tr><th>Timestamp</th><th>Source IP</th><th>Event</th><th>Outcome</th><th>Explanation</th></tr></thead>
                    <tbody>
                    <?php if (!$schoolHistory): ?>
                        <tr><td colspan="5" class="table-empty">No QR-factor history is available.</td></tr>
                    <?php else: foreach ($schoolHistory as $line): $outcome = fortress_event_outcome($line); ?>
                        <tr data-search="<?= e(strtolower(fortress_event_title($line) . ' ' . fortress_log_ip($line))) ?>" data-category="<?= e(strtolower($outcome)) ?>">
                            <td><?= e(fortress_event_time($line, 'Y-m-d H:i:s')) ?></td>
                            <td><?= e(fortress_log_ip($line)) ?></td>
                            <td><?= e(fortress_event_title($line)) ?></td>
                            <td><span class="status-pill status-<?= strtolower($outcome) ?>"><?= e($outcome) ?></span></td>
                            <td><?= e(fortress_event_description($line)) ?></td>
                        </tr>
                    <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>
        </article>
    </section>

    <section class="operator-report-section" id="reports">
        <div class="operator-section-heading">
            <div>
                <span class="eyebrow">DOCUMENTATION CENTER</span>
                <h2>Generate administrator reports</h2>
                <p>Create a presentation-ready FortressAuth documentation package from live system findings, AI/ML model analysis, authentication records, Personal ID evidence, threat findings, defense posture, administrator changes, and recent audit logs.</p>
            </div>
            <a class="operator-section-back" href="#user-management"><i class="fa-solid fa-arrow-up"></i> User Management</a>
        </div>

        <section class="operator-report-grid">
            <article class="panel report-builder-panel">
                <div class="panel-heading compact">
                    <div><span class="eyebrow">REPORT BUILDER</span><h2>Documentation export</h2><p>Select what should be documented, then choose a file format.</p></div>
                    <i class="fa-solid fa-file-shield panel-symbol"></i>
                </div>
                <form class="operator-report-form" method="post" action="/report_export.php">
                    <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                    <div class="report-form-fields">
                        <label>
                            <span><i class="fa-solid fa-layer-group"></i> Report coverage</span>
                            <select name="report_scope">
                                <option value="full">Full security documentation</option>
                                <option value="identity">Access &amp; identity documentation</option>
                                <option value="security">Security &amp; audit documentation</option>
                            </select>
                            <small>Full documentation includes AI/model findings, validation metrics, threat findings, authentication and Personal ID records, administrators, defense posture, audit evidence, sources, conclusions, and limitations.</small>
                        </label>
                        <label>
                            <span><i class="fa-solid fa-clock-rotate-left"></i> Recent evidence</span>
                            <select name="event_limit">
                                <option value="25">25 recent events</option>
                                <option value="50" selected>50 recent events</option>
                                <option value="100">100 recent events</option>
                            </select>
                            <small>The selected evidence count controls the detailed records. PowerPoint keeps the strongest findings and recent evidence presentation-friendly while PDF and Excel retain the deeper documentation structure.</small>
                        </label>
                    </div>

                    <div class="report-format-grid" aria-label="Report download formats">
                        <button class="report-format-card pdf" type="submit" name="format" value="pdf">
                            <span class="report-format-icon"><i class="fa-solid fa-file-pdf"></i></span>
                            <span><strong>PDF Report</strong><small>Detailed documentation with AI findings, model validation, records, logs, conclusions, and limitations</small></span>
                            <i class="fa-solid fa-download"></i>
                        </button>
                        <button class="report-format-card powerpoint" type="submit" name="format" value="pptx">
                            <span class="report-format-icon"><i class="fa-solid fa-file-powerpoint"></i></span>
                            <span><strong>PowerPoint</strong><small>Presentation-ready briefing deck based on the system and model findings</small></span>
                            <i class="fa-solid fa-download"></i>
                        </button>
                        <button class="report-format-card excel" type="submit" name="format" value="xlsx">
                            <span class="report-format-icon"><i class="fa-solid fa-file-excel"></i></span>
                            <span><strong>Excel Workbook</strong><small>Multi-sheet evidence workbook for AI, models, threats, authentication, accounts, defenses, and logs</small></span>
                            <i class="fa-solid fa-download"></i>
                        </button>
                    </div>
                </form>
            </article>

            <aside class="panel report-contents-panel">
                <div class="panel-heading compact"><div><span class="eyebrow">DOCUMENT CONTENTS</span><h2>What is included</h2></div><i class="fa-solid fa-list-check panel-symbol"></i></div>
                <div class="report-content-list">
                    <div><span>01</span><p><strong>Executive security snapshot</strong><small>Protection score, threat level, active defenses, account counts, 24-hour authentication activity, bans, and the latest hybrid risk result.</small></p></div>
                    <div><span>02</span><p><strong>AI &amp; model findings</strong><small>XGBoost classification and probabilities, Autoencoder anomaly score, rule-engine signal, hybrid risk, behavioral features, AI Analyst interpretation, and recent AI analyses.</small></p></div>
                    <div><span>03</span><p><strong>Model validation evidence</strong><small>Training/holdout metadata, XGBoost accuracy and macro F1, class-level metrics, feature importance, Autoencoder validation, risk-fusion weights, and model limitations.</small></p></div>
                    <div><span>04</span><p><strong>Threat &amp; authentication findings</strong><small>24-hour threat-signal counts, top reportable source IPs, password/login records, protected-resource rejections, and Personal ID verification evidence.</small></p></div>
                    <div><span>05</span><p><strong>Administrators, defenses &amp; audit logs</strong><small>Account inventory, account changes, defense-layer state, security outcomes, and selected recent meaningful audit evidence.</small></p></div>
                    <div><span>06</span><p><strong>Documentation conclusion &amp; limitations</strong><small>Evidence-source provenance, privacy boundaries, system assessment, model interpretation warnings, and limitations to keep with presentations and formal records.</small></p></div>
                </div>
                <div class="report-privacy-note"><i class="fa-solid fa-shield-halved"></i><span><strong>Safe export boundary</strong><small>Passwords, password hashes, QR values/hashes, cookies, session IDs, CSRF tokens, and authorization secrets are never placed in generated reports.</small></span></div>
            </aside>
        </section>
    </section>

    <section class="panel user-audit-panel">
        <div class="panel-heading compact"><div><span class="eyebrow">ACCOUNT AUDIT TRAIL</span><h2>Recent user-management activity</h2><p>Administrative account changes are retained as security evidence.</p></div><span class="panel-status"><i class="fa-solid fa-clipboard-check"></i> <?= count($managementAuditLines) ?> RECENT</span></div>
        <div class="user-audit-list">
            <?php if (!$managementAuditLines): ?><div class="user-directory-empty"><i class="fa-solid fa-clipboard"></i><strong>No account-management events yet</strong><span>Create or modify an administrator to generate audit evidence.</span></div>
            <?php else: foreach ($managementAuditLines as $line): ?>
                <article><span class="user-audit-marker"><i class="fa-solid fa-user-gear"></i></span><div><strong><?= e(fortress_event_title($line)) ?></strong><p><?= e(fortress_event_description($line)) ?></p></div><time><?= e(fortress_event_time($line, 'M d · H:i:s')) ?></time></article>
            <?php endforeach; endif; ?>
        </div>
    </section>

    <footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> FortressAuth current operator controls</span><span>Users + QR Factor + Reports · Protected operator workspace</span></footer>

</div><!-- /.fortress-main-column -->
</main>
<script src="/js/qrcode.min.js"></script>
<script src="/js/user_management.js"></script>

<script src="/js/dashboard.js"></script>
</body>
</html>
