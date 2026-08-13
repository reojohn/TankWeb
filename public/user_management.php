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

    try {
        if ($action === 'create_user') {
            $username = sanitize_username((string)($_POST['username'] ?? ''));
            $fullName = fortress_clean_full_name((string)($_POST['full_name'] ?? ''));
            $password = (string)($_POST['password'] ?? '');
            $isActive = isset($_POST['is_active']);
            $require2fa = isset($_POST['require_school_id_2fa']);
            $personalIdValue = trim((string)($_POST['personal_id_qr'] ?? ''));

            if ($username === false) {
                throw new RuntimeException('Username must be 3–32 characters and use only letters, numbers, or underscores.');
            }
            if ($fullName === '') {
                throw new RuntimeException('Enter a display name for the administrator.');
            }
            if (strlen($password) < 12 || strlen($password) > 128) {
                throw new RuntimeException('Temporary password must contain 12–128 characters.');
            }

            $personalIdHash = null;
            if ($require2fa) {
                $personalIdHash = fortress_personal_id_hash_value($personalIdValue);
            }

            $stmt = $pdo->prepare(
                'INSERT INTO public.users (
                    username, full_name, password_hash, is_active, updated_at,
                    school_id_2fa_required,
                    school_id_qr_hash, school_id_qr_enabled, school_id_qr_updated_at
                 )
                 VALUES (
                    :username, :full_name, :password_hash, :is_active, NOW(),
                    :school_id_2fa_required,
                    :school_id_qr_hash, :school_id_qr_enabled, NOW()
                 )'
            );
            // Bind PostgreSQL BOOLEAN values explicitly. Passing PHP false through
            // execute([...]) can be serialized as an empty string by PDO_PGSQL,
            // which PostgreSQL rejects for BOOLEAN columns. This matters when
            // creating a password-only account because both 2FA flags are false.
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->bindValue(':full_name', $fullName, PDO::PARAM_STR);
            $stmt->bindValue(':password_hash', fortress_password_hash_value($password), PDO::PARAM_STR);
            $stmt->bindValue(':is_active', $isActive, PDO::PARAM_BOOL);
            $stmt->bindValue(':school_id_2fa_required', $require2fa, PDO::PARAM_BOOL);
            if ($personalIdHash === null) {
                $stmt->bindValue(':school_id_qr_hash', null, PDO::PARAM_NULL);
            } else {
                $stmt->bindValue(':school_id_qr_hash', $personalIdHash, PDO::PARAM_STR);
            }
            $stmt->bindValue(':school_id_qr_enabled', $require2fa, PDO::PARAM_BOOL);
            $stmt->execute();

            $newId = (int)$pdo->lastInsertId();

            audit_log(
                'user_account_created actor_uid=' . $userId .
                ' target_uid=' . $newId .
                ' target=' . fortress_log_field($username) .
                ' 2fa=' . ($require2fa ? 'enabled' : 'disabled')
            );

            if ($require2fa) {
                audit_log(
                    'user_2fa_enabled actor_uid=' . $userId .
                    ' target_uid=' . $newId .
                    ' target=' . fortress_log_field($username)
                );
                audit_log(
                    'school_id_qr_registered uid=' . $newId .
                    ' actor_uid=' . $userId .
                    ' source=user_management'
                );
            }

            fortress_user_flash(
                'success',
                $require2fa
                    ? 'Administrator account created. Password + Personal ID QR will be required at login.'
                    : 'Administrator account created with password-only authentication. Personal ID QR scanning is not required for this account.'
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
            $personalIdValue = trim((string)($_POST['personal_id_qr'] ?? ''));

            if ($username === false) throw new RuntimeException('Username format is invalid.');
            if ($fullName === '') throw new RuntimeException('Display name is required.');
            if ($targetId === $userId) $isActive = true;

            $newPassword = (string)($_POST['new_password'] ?? '');
            if ($newPassword !== '' && (strlen($newPassword) < 12 || strlen($newPassword) > 128)) {
                throw new RuntimeException('New password must contain 12–128 characters.');
            }

            $was2faRequired = (bool)($target['school_id_2fa_required'] ?? true);
            $hadPersonalId = (bool)($target['school_id_qr_enabled'] ?? false);

            // Enabling 2FA on an account that does not already have a usable QR
            // requires a new QR value. Entering a new value while 2FA remains
            // enabled replaces the existing credential.
            $newPersonalIdHash = null;
            $replacePersonalId = $personalIdValue !== '';

            if ($require2fa && (!$was2faRequired || !$hadPersonalId || $replacePersonalId)) {
                $newPersonalIdHash = fortress_personal_id_hash_value($personalIdValue);
            }

            if ($newPassword !== '') {
                $stmt = $pdo->prepare(
                    'UPDATE public.users
                     SET username = :username,
                         full_name = :full_name,
                         is_active = :is_active,
                         password_hash = :password_hash,
                         updated_at = NOW()
                     WHERE id = :id'
                );
                $stmt->bindValue(':username', $username, PDO::PARAM_STR);
                $stmt->bindValue(':full_name', $fullName, PDO::PARAM_STR);
                $stmt->bindValue(':is_active', $isActive, PDO::PARAM_BOOL);
                $stmt->bindValue(':password_hash', fortress_password_hash_value($newPassword), PDO::PARAM_STR);
                $stmt->bindValue(':id', $targetId, PDO::PARAM_INT);
                $stmt->execute();
                audit_log(
                    'user_password_changed_during_edit actor_uid=' . $userId .
                    ' target_uid=' . $targetId .
                    ' target=' . fortress_log_field($username)
                );
            } else {
                $stmt = $pdo->prepare(
                    'UPDATE public.users
                     SET username = :username,
                         full_name = :full_name,
                         is_active = :is_active,
                         updated_at = NOW()
                     WHERE id = :id'
                );
                $stmt->bindValue(':username', $username, PDO::PARAM_STR);
                $stmt->bindValue(':full_name', $fullName, PDO::PARAM_STR);
                $stmt->bindValue(':is_active', $isActive, PDO::PARAM_BOOL);
                $stmt->bindValue(':id', $targetId, PDO::PARAM_INT);
                $stmt->execute();
            }

            $twoFactorChanged = false;
            $twoFactorResult = '';

            if (!$require2fa) {
                if ($was2faRequired || $hadPersonalId) {
                    $stmt = $pdo->prepare(
                        'UPDATE public.users
                         SET school_id_2fa_required = FALSE,
                             school_id_qr_hash = NULL,
                             school_id_qr_enabled = FALSE,
                             school_id_qr_updated_at = NOW(),
                             updated_at = NOW()
                         WHERE id = ?'
                    );
                    $stmt->execute([$targetId]);
                    $twoFactorChanged = true;
                    $twoFactorResult = 'disabled';

                    audit_log(
                        'user_2fa_disabled actor_uid=' . $userId .
                        ' target_uid=' . $targetId .
                        ' target=' . fortress_log_field($username)
                    );
                }
            } else {
                if (!$was2faRequired || !$hadPersonalId || $replacePersonalId) {
                    $stmt = $pdo->prepare(
                        'UPDATE public.users
                         SET school_id_2fa_required = TRUE,
                             school_id_qr_hash = :qr_hash,
                             school_id_qr_enabled = TRUE,
                             school_id_qr_updated_at = NOW(),
                             updated_at = NOW()
                         WHERE id = :id'
                    );
                    $stmt->execute([
                        'qr_hash' => $newPersonalIdHash,
                        'id' => $targetId,
                    ]);

                    $twoFactorChanged = true;
                    $twoFactorResult = $was2faRequired && $hadPersonalId ? 'replaced' : 'enabled';

                    audit_log(
                        ($twoFactorResult === 'replaced' ? 'user_2fa_replaced' : 'user_2fa_enabled') .
                        ' actor_uid=' . $userId .
                        ' target_uid=' . $targetId .
                        ' target=' . fortress_log_field($username)
                    );
                    audit_log(
                        'school_id_qr_registered uid=' . $targetId .
                        ' actor_uid=' . $userId .
                        ' source=user_management mode=' . $twoFactorResult
                    );
                }
            }

            if (
                $newPassword !== '' ||
                $isActive !== (bool)$target['is_active'] ||
                $twoFactorChanged
            ) {
                fortress_increment_session_version($pdo, $targetId);
            }

            audit_log(
                'user_account_updated actor_uid=' . $userId .
                ' target_uid=' . $targetId .
                ' target=' . fortress_log_field($username) .
                ($twoFactorResult !== '' ? ' 2fa=' . $twoFactorResult : '')
            );

            $message = 'Administrator account updated successfully.';
            if ($twoFactorResult === 'enabled') {
                $message .= ' Personal ID 2FA is now required.';
            } elseif ($twoFactorResult === 'replaced') {
                $message .= ' The Personal ID 2FA credential was replaced.';
            } elseif ($twoFactorResult === 'disabled') {
                $message .= ' Personal ID 2FA was disabled; future logins require the password only.';
            }

            // If the current operator changes their own authentication policy or
            // password, revoke this browser session cleanly and return to login.
            if ($targetId === $userId && ($twoFactorChanged || $newPassword !== '')) {
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

            $stmt = $pdo->prepare(
                'UPDATE public.users
                 SET school_id_2fa_required = FALSE,
                     school_id_qr_hash = NULL,
                     school_id_qr_enabled = FALSE,
                     school_id_qr_updated_at = NOW(),
                     updated_at = NOW()
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

            fortress_user_flash('success', 'Personal ID 2FA disabled. This administrator will use password-only authentication on the next login.');
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

$users = $schemaReady ? fortress_fetch_users($pdo) : [];
$totalUsers = count($users);
$activeUsers = count(array_filter($users, static fn(array $u): bool => (bool)$u['is_active']));
$inactiveUsers = $totalUsers - $activeUsers;
$personalIdUsers = count(array_filter($users, static fn(array $u): bool => (bool)($u['school_id_2fa_required'] ?? true)));
$activeRate = $totalUsers > 0 ? (int)round(($activeUsers / $totalUsers) * 100) : 0;

$q = trim((string)($_GET['q'] ?? ''));
$statusFilter = (string)($_GET['status'] ?? 'all');
$idFilter = (string)($_GET['identity'] ?? 'all');
$filteredUsers = array_values(array_filter($users, static function (array $u) use ($q, $statusFilter, $idFilter): bool {
    if ($statusFilter === 'active' && !(bool)$u['is_active']) return false;
    if ($statusFilter === 'inactive' && (bool)$u['is_active']) return false;
    $requires2fa = (bool)($u['school_id_2fa_required'] ?? true);
    if ($idFilter === 'enabled' && !$requires2fa) return false;
    if ($idFilter === 'disabled' && $requires2fa) return false;
    if ($q === '') return true;
    $haystack = strtolower((string)$u['username'] . ' ' . (string)$u['full_name']);
    return str_contains($haystack, strtolower($q));
}));

$editId = (int)($_GET['edit'] ?? 0);
$resetId = (int)($_GET['reset'] ?? 0);
$deleteId = (int)($_GET['confirm_delete'] ?? 0);
$editUser = $editId > 0 ? fortress_fetch_user($pdo, $editId) : null;
$resetUser = $resetId > 0 ? fortress_fetch_user($pdo, $resetId) : null;
$deleteUser = $deleteId > 0 ? fortress_fetch_user($pdo, $deleteId) : null;
$deleteUserIsCurrent = $deleteUser && (int)$deleteUser['id'] === $userId;
$deleteBlockedAsLastActive = $deleteUser && (bool)$deleteUser['is_active'] && $activeUsers <= 1;

$managementAuditLines = array_values(array_filter(
    fortress_read_lines(__DIR__ . '/../data/audit.log'),
    static fn(string $line): bool => fortress_line_has_any($line, [
        'security_report_generated', 'user_management_access', 'user_account_created', 'user_account_updated',
        'user_account_enabled', 'user_account_disabled', 'user_password_reset',
        'user_password_changed_during_edit', 'user_personal_id_reset', 'user_account_deleted', 'login_disabled_account',
        'user_2fa_enabled', 'user_2fa_disabled', 'user_2fa_replaced', 'current_user_security_policy_changed',
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
                <span class="verified"><i class="fa-solid fa-lock"></i> ADMIN ONLY</span>
            </div>
            <h1>Manage users, Personal ID, and reports from one <span>secure workspace.</span></h1>
            <p>This Current Operator page combines administrator account management, your Personal ID security controls, and documentation exports in one protected workspace.</p>
        </div>
        <aside class="access-health-card">
            <div class="access-health-top">
                <div><span>ACCESS HEALTH</span><strong><?= $activeRate ?>% active</strong><small>Current administrator availability</small></div>
                <div class="access-health-ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="access-ring-track" cx="50" cy="50" r="42" pathLength="100"></circle><circle class="access-ring-value" cx="50" cy="50" r="42" pathLength="100" stroke-dasharray="<?= max(0, min(100, $activeRate)) ?> 100"></circle></svg><div><strong><?= $activeUsers ?></strong><span>ACTIVE</span></div></div>
            </div>
            <div class="access-health-mini"><div><span>Inactive</span><strong><?= $inactiveUsers ?></strong></div><div><span>Personal IDs</span><strong><?= $personalIdUsers ?></strong></div></div>
            <progress class="access-health-track" max="100" value="<?= max(0, min(100, $activeRate)) ?>" aria-label="Active account percentage"></progress>
        </aside>
    </section>

    <nav class="operator-workspace-tabs" aria-label="Current Operator workspace sections">
        <a href="#user-management"><i class="fa-solid fa-users-gear"></i><span><strong>User Management</strong><small>Accounts, access and passwords</small></span></a>
        <a href="#personal-id"><i class="fa-solid fa-id-card"></i><span><strong>Personal ID</strong><small>Your QR possession factor</small></span></a>
        <a href="#reports"><i class="fa-solid fa-file-export"></i><span><strong>Reports</strong><small>PDF, PowerPoint and Excel documentation</small></span></a>
    </nav>

    <?php if ($flash): ?>
        <div class="user-management-message <?= ($flash['type'] ?? '') === 'error' ? 'error' : 'success' ?>">
            <i class="fa-solid <?= ($flash['type'] ?? '') === 'error' ? 'fa-triangle-exclamation' : 'fa-circle-check' ?>"></i>
            <span><?= e((string)($flash['message'] ?? '')) ?></span>
        </div>
    <?php endif; ?>

    <?php if (!$schemaReady): ?>
        <div class="user-management-message error"><i class="fa-solid fa-database"></i><span>Optional 2FA account controls are not ready yet. Apply sql/optional_2fa.sql once with the database owner or migration account.</span></div>
    <?php endif; ?>

    <section class="user-management-stats">
        <article><span class="user-stat-icon"><i class="fa-solid fa-users"></i></span><div><small>TOTAL ADMINS</small><strong><?= $totalUsers ?></strong><p>Registered privileged accounts</p></div></article>
        <article><span class="user-stat-icon success"><i class="fa-solid fa-user-check"></i></span><div><small>ACTIVE ACCESS</small><strong><?= $activeUsers ?></strong><p>Accounts allowed to authenticate</p></div></article>
        <article><span class="user-stat-icon identity"><i class="fa-solid fa-id-card"></i></span><div><small>2FA ENABLED</small><strong><?= $personalIdUsers ?></strong><p>Accounts requiring Personal ID QR</p></div></article>
        <article><span class="user-stat-icon danger"><i class="fa-solid fa-user-lock"></i></span><div><small>INACTIVE</small><strong><?= $inactiveUsers ?></strong><p>Sign-in access disabled</p></div></article>
    </section>

    <?php if ($deleteUser): ?>
        <section class="delete-confirm-panel <?= $deleteBlockedAsLastActive ? 'blocked' : '' ?>" id="delete-confirmation">
            <span class="delete-confirm-icon"><i class="fa-solid <?= $deleteBlockedAsLastActive ? 'fa-shield-halved' : 'fa-triangle-exclamation' ?>"></i></span>
            <div>
                <small><?= $deleteBlockedAsLastActive ? 'ACCOUNT SAFEGUARD' : 'DESTRUCTIVE ACTION' ?></small>
                <h2>Delete <?= e((string)$deleteUser['username']) ?>?</h2>
                <?php if ($deleteBlockedAsLastActive): ?>
                    <p>This is currently the last active administrator. Create and activate another administrator first so FortressAuth is not left with no usable administrator account.</p>
                <?php elseif ($deleteUserIsCurrent): ?>
                    <p>This is the account you are currently using. Deleting it permanently removes the account and its Personal ID, then FortressAuth will immediately end this session and return you to the login page.</p>
                <?php else: ?>
                    <p>This permanently removes the administrator account and its registered Personal ID credential. Audit evidence already written to the security log is retained.</p>
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
                ?>
                <label class="user-active-switch">
                    <span>
                        <strong>Require Personal ID 2FA</strong>
                        <small>
                            <?= $editUser
                                ? 'Turn this off for password-only login. Turn it on to require Password + School ID QR.'
                                : 'Recommended. Turn this off only if this administrator should use password-only login.' ?>
                        </small>
                    </span>
                    <input
                        type="checkbox"
                        id="require-school-id-2fa"
                        name="require_school_id_2fa"
                        data-editing="<?= $editUser ? '1' : '0' ?>"
                        data-has-qr="<?= $editHasPersonalId ? '1' : '0' ?>"
                        <?= $editRequires2fa ? 'checked' : '' ?>
                    >
                    <i></i>
                </label>

                <label id="personal-id-qr-control">
                    <span>
                        <i class="fa-solid fa-id-card-clip"></i>
                        <?= $editUser && $editHasPersonalId ? 'Replace Personal ID QR' : 'Personal ID QR value' ?>
                        <em><?= $editUser && $editHasPersonalId ? 'OPTIONAL' : 'REQUIRED WHEN 2FA IS ON' ?></em>
                    </span>
                    <input
                        type="password"
                        id="personal-id-qr-value"
                        name="personal_id_qr"
                        maxlength="4096"
                        autocomplete="off"
                        placeholder="<?= $editUser && $editHasPersonalId
                            ? 'Leave blank to keep the current QR'
                            : 'Paste the QR value when enabling 2FA' ?>"
                    >
                    <small>
                        <?= $editUser && $editHasPersonalId
                            ? 'Leave this blank to keep the existing QR. Enter a new value only to replace it.'
                            : 'If Personal ID 2FA is enabled, a QR value is required. FortressAuth stores only a one-way hash.' ?>
                    </small>
                    <small id="personal-id-2fa-live-status" aria-live="polite"></small>
                </label>

                <?php if ($editUser): ?>
                    <div class="editing-account-banner">
                        <i class="fa-solid <?= $editRequires2fa ? 'fa-shield-halved' : 'fa-key' ?>"></i>
                        <div>
                            <strong>Current login policy: <?= $editRequires2fa ? 'PASSWORD + PERSONAL ID QR' : 'PASSWORD ONLY' ?></strong>
                            <span>
                                <?php if ($editRequires2fa && $editHasPersonalId): ?>
                                    2FA is enabled and a Personal ID QR credential is registered.
                                <?php elseif ($editRequires2fa): ?>
                                    2FA is required, but this account still needs a Personal ID QR enrollment.
                                <?php else: ?>
                                    Personal ID QR scanning is disabled for this account.
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

        <article class="panel user-directory-panel">
            <div class="panel-heading user-directory-heading">
                <div><span class="eyebrow">ADMINISTRATOR DIRECTORY</span><h2>Registered operators</h2><p><?= count($filteredUsers) ?> of <?= $totalUsers ?> accounts shown</p></div>
                <a class="text-link" href="/user_management.php"><i class="fa-solid fa-arrows-rotate"></i> Refresh</a>
            </div>
            <form method="get" class="user-directory-filters">
                <label class="user-search-control"><i class="fa-solid fa-magnifying-glass"></i><input name="q" value="<?= e($q) ?>" placeholder="Search administrators..."></label>
                <select name="status" aria-label="Filter account status"><option value="all" <?= $statusFilter==='all'?'selected':'' ?>>All status</option><option value="active" <?= $statusFilter==='active'?'selected':'' ?>>Active</option><option value="inactive" <?= $statusFilter==='inactive'?'selected':'' ?>>Inactive</option></select>
                <select name="identity" aria-label="Filter Personal ID 2FA"><option value="all" <?= $idFilter==='all'?'selected':'' ?>>All 2FA policies</option><option value="enabled" <?= $idFilter==='enabled'?'selected':'' ?>>2FA enabled</option><option value="disabled" <?= $idFilter==='disabled'?'selected':'' ?>>2FA disabled</option></select>
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
                ?>
                    <section class="user-account-card <?= $isCurrent ? 'current' : '' ?>">
                        <div class="user-account-avatar"><?= e($initial) ?></div>
                        <div class="user-account-main">
                            <div class="user-account-title"><strong><?= e($displayName) ?></strong><span class="admin-chip">ADMIN</span><span class="account-state <?= (bool)$account['is_active'] ? 'active' : 'inactive' ?>"><?= (bool)$account['is_active'] ? 'ACTIVE' : 'INACTIVE' ?></span><?php if ($isCurrent): ?><span class="current-chip">CURRENT</span><?php endif; ?></div>
                            <p>@<?= e((string)$account['username']) ?></p>
                            <div class="user-account-meta"><span><i class="fa-solid fa-id-card"></i>
                                <?php if (!(bool)($account['school_id_2fa_required'] ?? true)): ?>
                                    2FA: DISABLED · Password only
                                <?php elseif ((bool)$account['school_id_qr_enabled']): ?>
                                    2FA: ENABLED · Personal ID enrolled
                                <?php else: ?>
                                    2FA: ENABLED · Enrollment required
                                <?php endif; ?>
                            </span><span><i class="fa-solid fa-clock"></i> Last login: <?= e($lastLogin) ?></span><span><i class="fa-solid fa-calendar"></i> Created: <?= e($created) ?></span></div>
                        </div>
                        <div class="user-account-actions">
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
                        </div>
                    </section>
                <?php endforeach; endif; ?>
            </div>
        </article>
    </section>

    <?php if ($resetUser): ?>
        <section class="panel password-reset-panel" id="password-reset">
            <div class="panel-heading"><div><span class="eyebrow">CREDENTIAL CONTROL</span><h2>Reset password for <?= e((string)$resetUser['username']) ?></h2><p>Issue a new temporary password. The existing Personal ID remains registered.</p></div><a class="text-link" href="/user_management.php">Close</a></div>
            <form method="post" class="password-reset-form"><input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>"><input type="hidden" name="action" value="reset_password"><input type="hidden" name="user_id" value="<?= (int)$resetUser['id'] ?>"><label><span>New temporary password</span><input type="password" name="password" minlength="12" maxlength="128" required autocomplete="new-password" placeholder="Minimum 12 characters"></label><button type="submit"><i class="fa-solid fa-key"></i> Reset password</button></form>
        </section>
    <?php endif; ?>

    <section class="operator-personal-id-section" id="personal-id">
        <div class="operator-section-heading">
            <div>
                <span class="eyebrow">PERSONAL ID</span>
                <h2>Current operator identity factor</h2>
                <p>Manage the Personal ID QR possession factor for the administrator account that is currently signed in.</p>
            </div>
            <a class="operator-section-back" href="#user-management"><i class="fa-solid fa-arrow-up"></i> User Management</a>
        </div>

        <?php if (isset($_GET['reverified'])): ?>
            <div class="system-message success"><i class="fa-solid fa-circle-check"></i> Personal ID possession was re-verified successfully. Replacement controls are unlocked for five minutes.</div>
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
                    <div><small>POSSESSION FACTOR</small><strong>Physical Personal ID QR</strong><span>Credential value hidden</span></div>
                </div>
                <div class="panel-note"><i class="fa-solid fa-lock"></i> FortressAuth does not display the raw QR payload. Only the protected matching credential is retained server-side.</div>
            </article>

            <article class="panel">
                <div class="panel-heading compact"><div><span class="eyebrow">ID SECURITY STATUS</span><h2>Verification State</h2></div><span class="session-orb"></span></div>
                <dl class="session-details school-page-details">
                    <div><dt>2FA policy</dt><dd><?= $personalIdRequired ? 'REQUIRED' : 'DISABLED' ?></dd></div>
                    <div><dt>Credential state</dt><dd><?= !$personalIdRequired ? 'NOT REQUIRED' : ($personalIdEnabled ? 'ENABLED' : 'NOT ENROLLED') ?></dd></div>
                    <div><dt>Authentication method</dt><dd><?= $personalIdRequired ? 'PASSWORD + PERSONAL ID QR' : 'PASSWORD ONLY' ?></dd></div>
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
                <div class="panel-heading compact"><div><span class="eyebrow">SECURITY CONTROLS</span><h2>Manage Personal ID</h2></div><i class="fa-solid fa-shield-halved panel-symbol"></i></div>
                <div class="manage-control-body">
                    <p>Replacing a Personal ID is intentionally protected. A fresh successful Personal ID scan is required before the current credential can be revoked.</p>
                    <div class="manage-actions">
                        <?php if ($personalIdRequired && $personalIdEnabled): ?>
                            <form method="post" action="/school_id_reverify.php">
                                <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                                <button class="manage-button" type="submit"><span><i class="fa-solid fa-qrcode"></i> Re-verify current Personal ID</span><i class="fa-solid fa-chevron-right"></i></button>
                            </form>
                            <form method="post" action="/school_id_reset.php">
                                <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
                                <button class="manage-button danger" type="submit" <?= $personalIdRecentlyVerified ? '' : 'disabled' ?>><span><i class="fa-solid fa-id-card-clip"></i> Replace registered Personal ID</span><i class="fa-solid fa-chevron-right"></i></button>
                            </form>
                            <?php if (!$personalIdRecentlyVerified): ?>
                                <p class="manage-note">Re-verify the current Personal ID first. After a successful possession check, replacement remains unlocked for five minutes.</p>
                            <?php else: ?>
                                <p class="manage-note">Replacement is unlocked. Continuing revokes the current QR credential, ends this session, and requires enrollment of a new Personal ID on the next login.</p>
                            <?php endif; ?>
                        <?php elseif ($personalIdRequired): ?>
                            <a class="manage-button" href="/logout.php"><span><i class="fa-solid fa-right-from-bracket"></i> Start a new login to enroll an ID</span><i class="fa-solid fa-chevron-right"></i></a>
                        <?php else: ?>
                            <a class="manage-button" href="/user_management.php?edit=<?= $userId ?>#account-editor"><span><i class="fa-solid fa-user-gear"></i> Enable 2FA for this operator</span><i class="fa-solid fa-chevron-right"></i></a>
                        <?php endif; ?>
                    </div>
                </div>
            </article>

            <article class="panel">
                <div class="panel-heading compact"><div><span class="eyebrow">VERIFICATION POLICY</span><h2>Personal ID Guardrails</h2></div><i class="fa-solid fa-list-check panel-symbol"></i></div>
                <div class="policy-list">
                    <div><span>01</span><p><strong>Password first</strong><small>The Personal ID scanner is reached only after the account password has been accepted.</small></p></div>
                    <div><span>02</span><p><strong>Time-limited scan</strong><small>The possession check must finish before the verification session expires.</small></p></div>
                    <div><span>03</span><p><strong>Failed-scan limit</strong><small>Repeated QR mismatches lock the verification attempt and require a fresh login.</small></p></div>
                    <div><span>04</span><p><strong>Protected replacement</strong><small>The current ID must be re-verified before FortressAuth allows credential replacement.</small></p></div>
                </div>
            </article>
        </section>

        <article class="panel data-panel operator-id-history">
            <div class="panel-heading filter-heading">
                <div><span class="eyebrow">VERIFICATION HISTORY</span><h2>Personal ID Security Events</h2><p>Enrollment, verification, failure, lock, re-verification, and reset activity for the possession factor.</p></div>
                <label class="search-control"><i class="fa-solid fa-magnifying-glass"></i><input type="search" data-table-search="schoolHistory" placeholder="Search ID history..."></label>
            </div>
            <div class="responsive-table-wrap">
                <table class="security-table" data-table="schoolHistory">
                    <thead><tr><th>Timestamp</th><th>Source IP</th><th>Event</th><th>Outcome</th><th>Explanation</th></tr></thead>
                    <tbody>
                    <?php if (!$schoolHistory): ?>
                        <tr><td colspan="5" class="table-empty">No Personal ID history is available.</td></tr>
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

    <footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> FortressAuth current operator controls</span><span>Users + Personal ID + Reports · CSRF-protected and audit logged</span></footer>

</div><!-- /.fortress-main-column -->
</main>
<script src="/js/user_management.js"></script>

<script src="/js/dashboard.js"></script>
</body>
</html>
