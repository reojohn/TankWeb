<?php
/**
 * IT113 public, login-free, SYNTHETIC-ONLY model inference gateway.
 * Accepts curated synthetic samples or bounded numeric features; no raw logs,
 * URLs, IP addresses, credentials or legacy administrator table access.
 * Admin authentication and operational routes remain unchanged.
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Cross-Origin-Resource-Policy: same-origin');

function it113_demo_reply(int $code, array $data): never {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    it113_demo_reply(405, ['ok' => false, 'error' => 'Use POST to analyze a curated example.']);
}
if (stripos((string)($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') !== 0) {
    it113_demo_reply(415, ['ok' => false, 'error' => 'JSON content type required.']);
}
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 4096) {
    it113_demo_reply(413, ['ok' => false, 'error' => 'Payload too large.']);
}
// Keep this public handler independent of the PostgreSQL connection so a DB
// outage does not block safe analysis. The private ML token is server-side only.
$dotenv = __DIR__ . '/../.env';
if (is_readable($dotenv)) {
    foreach (file($dotenv, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) continue;
        [$key, $value] = array_map('trim', explode('=', $line, 2));
        if (!preg_match('/^[A-Z_][A-Z0-9_]*$/D', $key) || getenv($key) !== false) continue;
        if (strlen($value) >= 2 && $value[0] === substr($value, -1) && in_array($value[0], ['"', "'"], true)) {
            $value = substr($value, 1, -1);
        }
        putenv($key . '=' . $value);
    }
}

// Cross-site HTML forms cannot produce this JSON request. Check Origin for
// browsers; a permitted reverse-proxy origin can be set explicitly by operator.
$origin = rtrim((string)($_SERVER['HTTP_ORIGIN'] ?? ''), '/');
$forwardedSite = strtolower((string)($_SERVER['HTTP_SEC_FETCH_SITE'] ?? ''));
if (in_array($forwardedSite, ['cross-site', 'none'], true)) {
    it113_demo_reply(403, ['ok' => false, 'error' => 'Cross-site requests not permitted.']);
}
if ($origin !== '') {
    $host = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    $originHost = strtolower((string)(parse_url($origin, PHP_URL_HOST) ?: ''));
    $originPort = parse_url($origin, PHP_URL_PORT);
    $originAuthority = $originHost . ($originPort === null ? '' : ':' . $originPort);
    $scheme = strtolower((string)(parse_url($origin, PHP_URL_SCHEME) ?: ''));
    // The allowed origins list is an operator setting, not a client parameter.
    $allowed = array_map('trim', explode(',', (string)(getenv('IT113_DEMO_ALLOWED_ORIGINS') ?: '')));
    if (!in_array($scheme, ['http', 'https'], true) ||
        ($originAuthority !== $host && !in_array($origin, $allowed, true))) {
        it113_demo_reply(403, ['ok' => false, 'error' => 'Origin not authorized.']);
    }
}

$raw = file_get_contents('php://input', false, null, 0, 4097);
if (!is_string($raw) || strlen($raw) > 4096) {
    it113_demo_reply(413, ['ok' => false, 'error' => 'Payload too large.']);
}
$request = json_decode($raw, true);
if (!is_array($request) || array_is_list($request)) {
    it113_demo_reply(400, ['ok'=>false,'error'=>'A JSON object is required.']);
}
$isCurated = array_keys($request) === ['sample_id']
    && is_string($request['sample_id'])
    && preg_match('/^[a-z0-9_]{3,60}$/D', $request['sample_id']);
$isNumeric = isset($request['source'], $request['features'], $request['confirm_synthetic'])
    && $request['source'] === 'numeric_csv'
    && $request['confirm_synthetic'] === true
    && is_array($request['features']) && !array_is_list($request['features'])
    && count($request) === 3;
if (!$isCurated && !$isNumeric) {
    it113_demo_reply(400, ['ok'=>false,'error'=>'Choose a curated sample or submit numeric-only synthetic features.']);
}

// Public model calls are opt-in even when the private ML engine is enabled.
if (!filter_var(getenv('IT113_PUBLIC_DEMO_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL)) {
    it113_demo_reply(503, ['ok' => false, 'error' => 'Public model demonstration is disabled on this deployment.']);
}

require_once __DIR__ . '/../src/it113_shared_limiter.php';
function it113_demo_rate_limit(): string { return it113_demo_limit('infer'); }
$limit = it113_demo_rate_limit();
if ($limit === 'unavailable') {
    header('Retry-After: 60');
    it113_demo_reply(503, ['ok'=>false, 'code'=>'SAFETY_GATE_UNAVAILABLE',
        'error'=>'Online assessment safeguards are not ready. Local research evidence remains available.']);
}
if ($limit === 'limited') {
    header('Retry-After: 60');
    it113_demo_reply(429, ['ok'=>false, 'code'=>'DEMO_LIMIT_REACHED',
        'error'=>'Shared demo limit reached. Try again after the limit resets.']);
}

$metadata = json_decode((string)@file_get_contents(__DIR__ . '/assessment/model_summary.json'), true);
$expected = $metadata['dataset']['features'] ?? [];
if (!is_array($expected) || count($expected) !== 20) {
    it113_demo_reply(503, ['ok'=>false,'error'=>'Model schema not available.']);
}
$sourceType = $isCurated ? 'curated' : 'numeric_csv';
$sampleId = null;
$trueLabel = '';
if ($isCurated) {
    $evidence = json_decode((string)@file_get_contents(__DIR__ . '/assessment/evidence.json'), true);
    if (!is_array($evidence) || ($evidence['not_live_inference'] ?? null) !== true ||
        ($evidence['contains_real_personal_data'] ?? null) !== false ||
        !is_array($evidence['examples'] ?? null)) {
        it113_demo_reply(503, ['ok'=>false,'error'=>'Synthetic evidence unavailable.']);
    }
    $sample = null;
    foreach ($evidence['examples'] as $candidate) {
        if (($candidate['id'] ?? '') === $request['sample_id']) { $sample = $candidate; break; }
    }
    if (!$sample || !is_array($sample['features'] ?? null)) {
        it113_demo_reply(400, ['ok'=>false,'error'=>'Unknown synthetic sample.']);
    }
    $features = $sample['features'];
    $sampleId = $request['sample_id'];
    $trueLabel = (string)$sample['true_label'];
} else {
    // CSV import is never sent as a file or free-form text; only one strictly
    // bounded, 20-feature numeric row reaches the model at a time.
    $features = $request['features'];
    foreach ($features as $value) {
        if (!is_float($value) && !is_int($value)) {
            it113_demo_reply(422, ['ok'=>false,'error'=>'Every feature must be a JSON number.']);
        }
        if (!is_finite((float)$value) || $value < 0 || $value > 1000000) {
            it113_demo_reply(422, ['ok'=>false,'error'=>'Numeric features must be finite and in range.']);
        }
    }
    if (($features['off_hours'] ?? null) !== 0 && ($features['off_hours'] ?? null) !== 1 &&
        ($features['off_hours'] ?? null) !== 0.0 && ($features['off_hours'] ?? null) !== 1.0) {
        it113_demo_reply(422, ['ok'=>false,'error'=>'off_hours must be 0 or 1.']);
    }
}
if (count($features) !== 20 || array_diff(array_keys($features), $expected) ||
    array_diff($expected, array_keys($features))) {
    it113_demo_reply(422, ['ok'=>false,'error'=>'Exactly 20 expected numeric features are required.']);
}

require_once __DIR__ . '/../src/ml_threat.php';
if (!fortress_ml_enabled()) {
    it113_demo_reply(503, ['ok' => false, 'error' => 'Live inference is disabled. Saved research evidence remains available.']);
}
$trace = bin2hex(random_bytes(16));
$result = fortress_ml_post([
    'features' => $features,
    'rule_score' => fortress_ml_rule_score($features),
    'trace_id' => $trace,
]);
if (!is_array($result) || ($result['trace_id'] ?? null) !== $trace) {
    $state = (string)(fortress_ml_service_status()['state'] ?? 'UNKNOWN');
    $waking = in_array($state, ['TIMEOUT','TRANSPORT_ERROR','SERVICE_UNAVAILABLE'], true);
    if ($waking) header('Retry-After: 45');
    it113_demo_reply(503, ['ok'=>false, 'code'=>$waking?'ML_STARTING':'ML_UNAVAILABLE',
        'error'=>$waking
            ? 'The hosted AI engine is waking up or temporarily unreachable. Retry in about a minute; no result was saved.'
            : 'Live model inference is unavailable. No simulated result was substituted.']);
}

// Explicit allowlist prevents accidental disclosure if the private API grows.
$indicators = [];
foreach (array_slice((array)($result['indicator_evidence'] ?? []), 0, 6) as $item) {
    if (!is_array($item)) continue;
    $indicators[] = [
        'description' => substr((string)($item['description'] ?? ''), 0, 160),
        'feature' => substr((string)($item['feature'] ?? ''), 0, 60),
        'observed' => (float)($item['observed'] ?? 0),
    ];
}
require_once __DIR__ . '/../src/it113_public_store.php';
$classification = (string)$result['classification'];
$version = (string)$result['model_version'];
if (!preg_match('/^[a-f0-9]{16}$/D', $version) ||
    !in_array($classification, (array)($metadata['dataset']['classes'] ?? []), true)) {
    it113_demo_reply(503, ['ok'=>false,'error'=>'Unverified model response.']);
}
$record = [
    'sample_id'=>$sampleId, 'source_type'=>$sourceType, 'expected_label'=>$trueLabel,
    'classification'=>$classification, 'confidence'=>(float)$result['confidence'],
    'risk_score'=>(float)$result['risk_score'], 'severity'=>(string)$result['severity'],
    'anomaly_score'=>(float)$result['anomaly_score'], 'rule_score'=>(float)$result['rule_score'],
    'model_version'=>$version, 'trace_id'=>$trace, 'indicator_evidence'=>$indicators,
];
$written = it113_store_record($record);
$record['ok'] = true;
$record['mode'] = $isCurated ? 'live_inference_on_curated_synthetic_sample' : 'live_inference_on_numeric_security_features';
$record['reconstruction_error'] = (float)$result['reconstruction_error'];
$record['feature_count'] = 20;
$record['synthetic'] = true;
$record['database_written'] = $written;
$record['persistence_status'] = $written ? 'saved' : it113_store_diagnostic();
$record['automatic_block'] = false;
$record['status'] = 'OPEN';
$record['revision'] = 0;
$record['persistence_mode'] = $written ? 'server_private_session' : 'browser_only';
it113_demo_reply(200, $record);
