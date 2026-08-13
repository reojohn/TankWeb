<?php

declare(strict_types=1);

/**
 * FortressAuth application/database configuration.
 *
 * Security rules:
 * - Secrets never have source-code fallbacks.
 * - Local development may use a gitignored .env file.
 * - Production errors are logged server-side, never rendered to the browser.
 */

function fortress_load_local_env(string $path): void
{
    if (!is_file($path) || !is_readable($path)) {
        return;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }

        [$key, $value] = array_map('trim', explode('=', $line, 2));
        if ($key === '' || !preg_match('/^[A-Z_][A-Z0-9_]*$/i', $key)) {
            continue;
        }

        if (getenv($key) !== false || array_key_exists($key, $_ENV)) {
            continue;
        }

        if (
            strlen($value) >= 2 &&
            (($value[0] === '"' && substr($value, -1) === '"') ||
             ($value[0] === "'" && substr($value, -1) === "'"))
        ) {
            $value = substr($value, 1, -1);
        }

        putenv($key . '=' . $value);
        $_ENV[$key] = $value;
    }
}

fortress_load_local_env(__DIR__ . '/../.env');

$appEnv = strtolower((string) (getenv('APP_ENV') ?: 'production'));
$isDevelopment = in_array($appEnv, ['dev', 'development', 'local'], true);

ini_set('display_errors', $isDevelopment ? '1' : '0');
ini_set('display_startup_errors', $isDevelopment ? '1' : '0');
error_reporting(E_ALL);
ini_set('log_errors', '1');

$logDir = __DIR__ . '/../logs';
if (!is_dir($logDir)) {
    @mkdir($logDir, 0700, true);
}
ini_set('error_log', $logDir . '/errors.log');

function fortress_required_env(string $name): string
{
    $value = getenv($name);
    if ($value === false || trim((string) $value) === '') {
        error_log('FortressAuth configuration error: missing required environment variable ' . $name);
        http_response_code(500);
        exit('Internal server error');
    }

    return trim((string) $value);
}

$DB_HOST = fortress_required_env('DB_HOST');
$DB_NAME = fortress_required_env('DB_NAME');
$DB_USER = fortress_required_env('DB_USER');
$DB_PASS = fortress_required_env('DB_PASS');

$portRaw = getenv('DB_PORT');
$DB_PORT = ($portRaw !== false && ctype_digit((string) $portRaw)) ? (int) $portRaw : 5432;
if ($DB_PORT < 1 || $DB_PORT > 65535) {
    error_log('FortressAuth configuration error: invalid DB_PORT');
    http_response_code(500);
    exit('Internal server error');
}

$sslMode = strtolower((string) (getenv('DB_SSLMODE') ?: 'require'));
$allowedSslModes = ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'];
if (!in_array($sslMode, $allowedSslModes, true)) {
    $sslMode = 'require';
}

$dsn = sprintf(
    'pgsql:host=%s;port=%d;dbname=%s;sslmode=%s',
    $DB_HOST,
    $DB_PORT,
    $DB_NAME,
    $sslMode
);

$persistentRaw = getenv('DB_PERSISTENT');
if ($persistentRaw === false || trim((string)$persistentRaw) === '') {
    // Local development commonly talks to a remote PostgreSQL instance.
    // Reusing the already-authenticated connection removes the TLS/handshake
    // cost from every PJAX page request. Production remains opt-in.
    $dbPersistent = $isDevelopment;
} else {
    $dbPersistent = filter_var($persistentRaw, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? false;
}

try {
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_PERSISTENT => $dbPersistent,
    ]);
} catch (Throwable $e) {
    // Do not expose connection strings, hosts, usernames, or driver errors to clients.
    error_log('FortressAuth database connection failed. code=' . $e->getCode());
    http_response_code(500);
    exit('Internal server error');
}
