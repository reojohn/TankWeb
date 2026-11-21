<?php

declare(strict_types=1);

// Changing the operator-selected defense profile is an administrative control,
// not threat telemetry. Keep the endpoint out of recon/ML behavioral sampling.
define('FORTRESS_BACKGROUND_REQUEST', true);

require __DIR__ . '/../../src/middleware.php';
require_once __DIR__ . '/../../src/auth.php';
require_once __DIR__ . '/../../src/security_profile.php';
require_once __DIR__ . '/../../src/security_policy.php';
require_once __DIR__ . '/../../src/ml_threat.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

require_admin_auth();

function fortress_profile_json(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

$userId = (int)($_SESSION['uid'] ?? 0);
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));

if ($method === 'GET') {
    $state = fortress_security_profile_state($pdo, true);
    $mode = fortress_security_profile_normalize($state['mode'] ?? 'balanced');
    $definition = fortress_security_profile_definition($mode);
    fortress_profile_json([
        'ok' => true,
        'data' => [
            'mode' => $mode,
            'label' => (string)($definition['label'] ?? 'BALANCED'),
            'title' => (string)($definition['title'] ?? 'Balanced'),
            'description' => (string)($definition['description'] ?? ''),
            'available' => !empty($state['available']),
            'changedAt' => (string)($state['changed_at'] ?? ''),
            'changedBy' => (string)($state['changed_by_username'] ?? ''),
            'canManage' => fortress_is_superadmin($pdo, $userId),
        ],
    ]);
}

if ($method !== 'POST') {
    header('Allow: GET, POST');
    fortress_profile_json(['ok' => false, 'message' => 'Unsupported defense-profile action.'], 405);
}

if (!fortress_is_superadmin($pdo, $userId)) {
    fortress_profile_json(['ok' => false, 'message' => 'Only a Super Admin can change the Fortress Defense Engine profile.'], 403);
}

$input = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($input)) {
    fortress_profile_json(['ok' => false, 'message' => 'Invalid defense-profile request.'], 400);
}

$csrf = (string)($input['csrfToken'] ?? $input['csrf_token'] ?? '');
if (!verify_csrf_token($csrf)) {
    fortress_profile_json(['ok' => false, 'message' => 'The defense-profile request was rejected because the security token was invalid.'], 419);
}

$requestedMode = strtolower(trim((string)($input['mode'] ?? '')));
if (!array_key_exists($requestedMode, fortress_security_profile_definitions())) {
    fortress_profile_json(['ok' => false, 'message' => 'Unknown Fortress Defense Engine profile.'], 422);
}

$before = fortress_security_profile_state($pdo, true);
$beforeMode = fortress_security_profile_normalize($before['mode'] ?? 'balanced');
$username = trim((string)($_SESSION['username'] ?? ''));
if ($username === '') {
    try {
        $stmt = $pdo->prepare('SELECT username FROM public.users WHERE id = ? LIMIT 1');
        $stmt->execute([$userId]);
        $username = trim((string)($stmt->fetchColumn() ?: 'administrator'));
    } catch (Throwable $e) {
        $username = 'administrator';
    }
}

try {
    $state = fortress_security_profile_update($pdo, $requestedMode, $userId, $username);
} catch (RuntimeException $e) {
    fortress_profile_json(['ok' => false, 'message' => $e->getMessage()], 503);
} catch (Throwable $e) {
    error_log('FortressAuth defense-profile update failed: ' . $e->getMessage());
    fortress_profile_json(['ok' => false, 'message' => 'FortressAuth could not change the defense profile right now.'], 500);
}

$definition = fortress_security_profile_definition($requestedMode);
$policy = fortress_security_policy();
$ml = fortress_ml_enforcement_config();

if ($beforeMode !== $requestedMode) {
    audit_log(
        'security_profile_changed uid=' . $userId .
        ' username=' . fortress_log_safe_value($username) .
        ' from=' . fortress_log_safe_value($beforeMode) .
        ' to=' . fortress_log_safe_value($requestedMode)
    );
}

fortress_profile_json([
    'ok' => true,
    'data' => [
        'mode' => $requestedMode,
        'label' => (string)($definition['label'] ?? strtoupper($requestedMode)),
        'title' => (string)($definition['title'] ?? $requestedMode),
        'description' => (string)($definition['description'] ?? ''),
        'changedAt' => (string)($state['changed_at'] ?? ''),
        'changedBy' => (string)($state['changed_by_username'] ?? $username),
        'policy' => [
            'passwordIpFailureLimit' => (int)$policy['password_ip_failure_limit'],
            'passwordAccountFailureLimit' => (int)$policy['password_account_failure_limit'],
            'ipBanSeconds' => (int)$policy['ip_ban_seconds'],
            'reconProbeLimit' => (int)$policy['recon_probe_limit'],
            'reconSensitiveProbeLimit' => (int)$policy['recon_sensitive_probe_limit'],
            'reconBanSeconds' => (int)$policy['recon_ban_seconds'],
        ],
        'ml' => [
            'strikeRisk' => (float)$ml['strike_risk'],
            'immediateBlockRisk' => (float)$ml['block_risk'],
            'requiredStrikes' => (int)$ml['required_strikes'],
            'banSeconds' => (int)$ml['ban_seconds'],
            'queueReplayLimit' => fortress_ml_queue_replay_limit(),
        ],
    ],
]);
