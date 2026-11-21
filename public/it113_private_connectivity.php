<?php
/**
 * TEMPORARY, READ-ONLY IT113 DEPLOYMENT DIAGNOSTIC.
 * Deploy only for verification; remove from the repository and redeploy afterward.
 * No model inference, database writes, credentials, token or row data are returned.
 * Protection: a separate 64-hex-character secret supplied in an HTTP header.
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private, max-age=0');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Referrer-Policy: no-referrer');

function it113_diag_response(int $httpCode, array $payload): never
{
    http_response_code($httpCode);
    echo json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    exit;
}

// Do not reveal that this endpoint is available until it is correctly configured.
$expected = (string) (getenv('IT113_DIAGNOSTIC_TOKEN') ?: '');
$provided = (string) ($_SERVER['HTTP_X_IT113_DIAGNOSTIC_TOKEN'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/D', $expected) ||
    !preg_match('/^[a-f0-9]{64}$/D', $provided) ||
    !hash_equals($expected, $provided)) {
    it113_diag_response(404, ['ok' => false, 'error' => 'Not found']);
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    it113_diag_response(405, ['ok' => false, 'error' => 'Method not allowed']);
}

$dbStatus = 'not_configured';
$mlStatus = 'not_configured';
$modelVersion = null;

$dbVars = ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASS'];
$dbConfigured = true;
foreach ($dbVars as $name) {
    if (trim((string) (getenv($name) ?: '')) === '') {
        $dbConfigured = false;
    }
}

if ($dbConfigured) {
    if (!in_array('pgsql', PDO::getAvailableDrivers(), true)) {
        $dbStatus = 'pdo_pgsql_missing';
    } else {
        try {
            $port = (string) getenv('DB_PORT');
            if (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
                throw new RuntimeException('invalid port');
            }
            $ssl = (string) (getenv('DB_SSLMODE') ?: 'require');
            if (!in_array($ssl, ['require', 'verify-ca', 'verify-full'], true)) {
                $ssl = 'require';
            }
            $dsn = sprintf('pgsql:host=%s;port=%d;dbname=%s;sslmode=%s',
                getenv('DB_HOST'), (int) $port, getenv('DB_NAME'), $ssl);
            $pdo = new PDO($dsn, (string) getenv('DB_USER'), (string) getenv('DB_PASS'), [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_TIMEOUT => 8,
            ]);
            // Explicit read-only transaction. No count or row content is returned.
            $pdo->beginTransaction();
            $pdo->exec('SET TRANSACTION READ ONLY');
            $pdo->query('SELECT 1 FROM public.it113_demo_assessments LIMIT 0')->closeCursor();
            $pdo->query('SELECT 1 FROM public.it113_demo_case_events LIMIT 0')->closeCursor();
            $pdo->rollBack();
            $dbStatus = 'connected_tables_accessible';
        } catch (Throwable $e) {
            if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            $dbStatus = 'connection_or_table_check_failed';
            // Intentionally do not echo or log the exception: it can contain a DSN.
        }
    }
}

$serviceUrl = rtrim((string) (getenv('ML_SERVICE_URL') ?: ''), '/');
$serviceToken = (string) (getenv('ML_SERVICE_TOKEN') ?: '');
if ($serviceUrl !== '' && strlen($serviceToken) >= 24) {
    $parts = parse_url($serviceUrl);
    $validUrl = is_array($parts)
        && (($parts['scheme'] ?? '') === 'https')
        && isset($parts['host'])
        && !isset($parts['user'])
        && !isset($parts['pass'])
        && !isset($parts['query'])
        && !isset($parts['fragment']);
    if (!$validUrl) {
        $mlStatus = 'invalid_service_url';
    } else {
        $options = [
            'http' => [
                'method' => 'GET',
                'header' => "Authorization: Bearer " . str_replace(["\r", "\n"], '', $serviceToken) . "\r\n"
                    . "Accept: application/json\r\n",
                'timeout' => 12,
                'ignore_errors' => true,
                'follow_location' => 0,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ];
        $context = stream_context_create($options);
        $body = @file_get_contents($serviceUrl . '/model-info', false, $context, 0, 200000);
        $headers = $http_response_header ?? [];
        $httpCode = 0;
        foreach ($headers as $header) {
            if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $header, $m)) {
                $httpCode = (int) $m[1];
                break;
            }
        }
        if ($httpCode === 401 || $httpCode === 403) {
            $mlStatus = 'authentication_rejected';
        } elseif ($httpCode === 200 && is_string($body)) {
            $data = json_decode($body, true);
            if (is_array($data) && is_string($data['model_version'] ?? null)
                && preg_match('/^[a-f0-9]{8,64}$/D', $data['model_version'])) {
                $modelVersion = $data['model_version'];
                $mlStatus = 'authenticated_model_metadata_received';
            } else {
                $mlStatus = 'invalid_model_response';
            }
        } else {
            $mlStatus = 'unavailable_or_timeout';
        }
    }
}

$passed = ($dbStatus === 'connected_tables_accessible'
    && $mlStatus === 'authenticated_model_metadata_received');
it113_diag_response($passed ? 200 : 503, [
    'ok' => $passed,
    'database' => $dbStatus,
    'ml' => $mlStatus,
    'model_version' => $modelVersion,
    'read_only' => true,
]);
