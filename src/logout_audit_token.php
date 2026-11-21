<?php

declare(strict_types=1);

/**
 * Lightweight signed token used only to persist a logout audit row after the
 * authenticated session has already been destroyed.
 *
 * This helper deliberately does not load config.php, so issuing the token never
 * opens PostgreSQL or contacts any remote service on the critical logout path.
 */

function fortress_logout_audit_base64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function fortress_logout_audit_base64url_decode(string $value): string|false
{
    if ($value === '' || preg_match('/[^A-Za-z0-9_-]/', $value)) {
        return false;
    }

    $padding = (4 - (strlen($value) % 4)) % 4;
    return base64_decode(strtr($value . str_repeat('=', $padding), '-_', '+/'), true);
}

/**
 * Read a single value without bootstrapping the database configuration.
 * Production normally exposes these values directly as environment variables;
 * the small .env fallback keeps local `php -S` development working too.
 */
function fortress_logout_audit_env_value(string $name): ?string
{
    $value = getenv($name);
    if ($value !== false && trim((string)$value) !== '') {
        return trim((string)$value);
    }

    $envPath = __DIR__ . '/../.env';
    if (!is_file($envPath) || !is_readable($envPath)) {
        return null;
    }

    $lines = @file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return null;
    }

    foreach ($lines as $line) {
        $line = trim((string)$line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }

        [$key, $raw] = array_map('trim', explode('=', $line, 2));
        if ($key !== $name) {
            continue;
        }

        if (
            strlen($raw) >= 2 &&
            (($raw[0] === '"' && substr($raw, -1) === '"') ||
             ($raw[0] === "'" && substr($raw, -1) === "'"))
        ) {
            $raw = substr($raw, 1, -1);
        }

        return trim($raw) !== '' ? trim($raw) : null;
    }

    return null;
}

function fortress_logout_audit_signing_key(): ?string
{
    // Prefer a dedicated secret when deployments provide one. Existing installs
    // remain compatible by deriving an isolated HMAC key from DB_PASS without
    // exposing or transmitting the database password itself.
    $secret = fortress_logout_audit_env_value('FORTRESS_AUDIT_SECRET');
    $domain = 'dedicated';

    if ($secret === null) {
        $secret = fortress_logout_audit_env_value('APP_SECRET');
        $domain = 'app';
    }

    if ($secret === null) {
        $secret = fortress_logout_audit_env_value('ML_SERVICE_TOKEN');
        $domain = 'ml-token-fallback';
    }

    if ($secret === null) {
        $secret = fortress_logout_audit_env_value('DB_PASS');
        $domain = 'db-fallback';
    }

    if ($secret === null) {
        $secret = fortress_logout_audit_env_value('FORTRESS_VAULT_FLAG');
        $domain = 'vault-fallback';
    }

    if ($secret === null) {
        return null;
    }

    return hash('sha256', "FortressAuth/logout-audit/v1/{$domain}\0" . $secret, true);
}

function fortress_issue_logout_audit_token(int $userId): ?string
{
    if ($userId <= 0) {
        return null;
    }

    $key = fortress_logout_audit_signing_key();
    if ($key === null) {
        return null;
    }

    try {
        $nonce = bin2hex(random_bytes(12));
    } catch (Throwable $e) {
        return null;
    }

    $now = time();
    $userAgent = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 200);
    $payload = [
        'v' => 1,
        'uid' => $userId,
        'iat' => $now,
        'exp' => $now + 45,
        'nonce' => $nonce,
        // Binding the token to the browser UA reduces usefulness if it is copied.
        'ua' => hash('sha256', $userAgent),
    ];

    $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        return null;
    }

    $encoded = fortress_logout_audit_base64url_encode($json);
    $signature = hash_hmac('sha256', $encoded, $key, true);

    return $encoded . '.' . fortress_logout_audit_base64url_encode($signature);
}

/**
 * @return array{uid:int,nonce:string,iat:int,exp:int}|null
 */
function fortress_verify_logout_audit_token(string $token): ?array
{
    if ($token === '' || strlen($token) > 2048 || substr_count($token, '.') !== 1) {
        return null;
    }

    [$encoded, $signatureText] = explode('.', $token, 2);
    $key = fortress_logout_audit_signing_key();
    if ($key === null) {
        return null;
    }

    $providedSignature = fortress_logout_audit_base64url_decode($signatureText);
    if (!is_string($providedSignature)) {
        return null;
    }

    $expectedSignature = hash_hmac('sha256', $encoded, $key, true);
    if (!hash_equals($expectedSignature, $providedSignature)) {
        return null;
    }

    $decoded = fortress_logout_audit_base64url_decode($encoded);
    if (!is_string($decoded)) {
        return null;
    }

    $payload = json_decode($decoded, true);
    if (!is_array($payload) || (int)($payload['v'] ?? 0) !== 1) {
        return null;
    }

    $uid = (int)($payload['uid'] ?? 0);
    $iat = (int)($payload['iat'] ?? 0);
    $exp = (int)($payload['exp'] ?? 0);
    $nonce = (string)($payload['nonce'] ?? '');
    $uaHash = (string)($payload['ua'] ?? '');
    $now = time();

    if (
        $uid <= 0 ||
        $iat <= 0 ||
        $exp <= 0 ||
        $iat > ($now + 5) ||
        $exp < $now ||
        ($exp - $iat) > 60 ||
        !preg_match('/^[a-f0-9]{24}$/', $nonce)
    ) {
        return null;
    }

    $currentUa = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 200);
    if ($uaHash === '' || !hash_equals($uaHash, hash('sha256', $currentUa))) {
        return null;
    }

    return [
        'uid' => $uid,
        'nonce' => $nonce,
        'iat' => $iat,
        'exp' => $exp,
    ];
}
