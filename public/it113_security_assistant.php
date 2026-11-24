<?php
/**
 * Opt-in, curated-synthetic-only Groq analyst/chat gateway.
 * No private numeric CSV, passwords, real IPs or raw logs accepted.
 * Reuses ML_SERVICE_TOKEN: browser never contacts Python or Groq directly.
 * Never writes public findings or modifies ML results.
 */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Robots-Tag: noindex, nofollow');
function assistant_length(string $value): int { return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value); }
function assistant_reply(int $code, array $value): never {
    http_response_code($code);
    echo json_encode($value, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    assistant_reply(405, ['ok'=>false,'error'=>'POST is required.']);
}
if (stripos((string)($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') !== 0) {
    assistant_reply(415, ['ok'=>false,'error'=>'JSON required.']);
}
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 4096) {
    assistant_reply(413, ['ok'=>false,'error'=>'Request too large.']);
}
// Match the existing public inference gateway's .env bootstrap (local dev only).
$dotenv = __DIR__ . '/../.env';
if (is_readable($dotenv)) {
    foreach (file($dotenv, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) continue;
        [$name,$value] = array_map('trim', explode('=', $line, 2));
        if (!preg_match('/^[A-Z_][A-Z0-9_]*$/D',$name) || getenv($name) !== false) continue;
        if (strlen($value) >= 2 && $value[0] === substr($value,-1) && in_array($value[0],['"',"'"],true)) $value=substr($value,1,-1);
        putenv($name . '=' . $value);
    }
}
if (!filter_var(getenv('IT113_GROQ_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL)) {
    assistant_reply(503, ['ok'=>false,'code'=>'LLM_DISABLED','error'=>'AI Security Analyst is not enabled on this deployment.']);
}
if (!filter_var(getenv('IT113_PUBLIC_DEMO_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL)) {
    assistant_reply(503, ['ok'=>false,'code'=>'DEMO_DISABLED','error'=>'The public synthetic assessment demo is disabled.']);
}
if (strtolower((string)($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')) === 'cross-site') {
    assistant_reply(403, ['ok'=>false,'error'=>'Cross-site request rejected.']);
}
$origin = rtrim((string)($_SERVER['HTTP_ORIGIN'] ?? ''), '/');
if ($origin !== '') {
    $scheme = strtolower((string)(parse_url($origin, PHP_URL_SCHEME) ?: ''));
    $originHost = strtolower((string)(parse_url($origin, PHP_URL_HOST) ?: ''));
    $originPort = parse_url($origin, PHP_URL_PORT);
    $host = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    $allowed = array_map('trim', explode(',', (string)(getenv('IT113_DEMO_ALLOWED_ORIGINS') ?: '')));
    if (!in_array($scheme,['http','https'],true) || ($originHost . ($originPort===null?'':':'.$originPort) !== $host && !in_array($origin,$allowed,true))) {
        assistant_reply(403, ['ok'=>false,'error'=>'Origin not authorized.']);
    }
}
$raw = file_get_contents('php://input', false, null, 0, 4097);
if (!is_string($raw) || strlen($raw)>4096) assistant_reply(413,['ok'=>false,'error'=>'Request too large.']);
$input = json_decode($raw,true);
if (!is_array($input) || array_is_list($input) || count(array_diff(array_keys($input),['sample_id','mode','question','history'])) !== 0) {
    assistant_reply(400,['ok'=>false,'error'=>'Invalid request fields.']);
}
$id=$input['sample_id'] ?? null;
$mode=$input['mode'] ?? null;
$question=$input['question'] ?? '';
$history=$input['history'] ?? [];
if (!is_string($id) || !preg_match('/^[a-z0-9_]{3,60}$/D',$id)
 || !in_array($mode,['analyst','chat'],true) || !is_string($question)
 || assistant_length($question)>500 || ($mode==='chat' && trim($question)==='')
 || !is_array($history) || count($history)>6) {
    assistant_reply(422,['ok'=>false,'error'=>'Invalid sample, mode, question or history.']);
}
$historyOut=[];
foreach ($history as $item) {
    if (!is_array($item) || array_diff(array_keys($item), ['role','content'])
        || !in_array($item['role'] ?? null, ['user','assistant'],true)
        || !is_string($item['content'] ?? null) || assistant_length($item['content'])>700) {
        assistant_reply(422,['ok'=>false,'error'=>'Invalid conversation history.']);
    }
    $historyOut[]=['role'=>$item['role'],'content'=>$item['content']];
}
// Fail closed if the same shared DB-backed limiter used by the existing demo is unavailable.
require_once __DIR__ . '/../src/it113_shared_limiter.php';
$limit = it113_demo_limit('llm');
if ($limit !== 'allowed') {
    header('Retry-After: 60');
    assistant_reply($limit==='limited'?429:503,['ok'=>false,'code'=>$limit==='limited'?'LLM_LIMIT_REACHED':'SAFETY_GATE_UNAVAILABLE',
        'error'=>$limit==='limited'?'AI request limit reached. Try again shortly.':'AI request safeguards are unavailable.']);
}
$evidence = json_decode((string)@file_get_contents(__DIR__ . '/assessment/evidence.json'),true);
if (!is_array($evidence) || ($evidence['not_live_inference'] ?? null)!==true
    || ($evidence['contains_real_personal_data'] ?? null)!==false || !is_array($evidence['examples']??null)) {
    assistant_reply(503,['ok'=>false,'error'=>'Synthetic evidence unavailable.']);
}
$sample=null;
foreach ($evidence['examples'] as $candidate) {
    if (($candidate['id'] ?? '') === $id) { $sample=$candidate; break; }
}
$metadata=json_decode((string)@file_get_contents(__DIR__ . '/assessment/model_summary.json'),true);
$features=$sample['features']??null;
$expected=$metadata['dataset']['features']??null;
if (!is_array($features) || !is_array($expected) || count($expected)!==20 || count($features)!==20
    || array_diff(array_keys($features),$expected) || array_diff($expected,array_keys($features))) {
    assistant_reply(422,['ok'=>false,'error'=>'Unknown curated synthetic sample.']);
}
foreach ($features as $value) {
    if ((!is_float($value) && !is_int($value)) || !is_finite((float)$value) || $value<0 || $value>1000000) {
        assistant_reply(503,['ok'=>false,'error'=>'Invalid synthetic source data.']);
    }
}
require_once __DIR__ . '/../src/ml_threat.php';
if (!fortress_ml_enabled()) assistant_reply(503,['ok'=>false,'error'=>'The private ML service is disabled.']);
$url=rtrim(trim((string)(getenv('ML_SERVICE_URL') ?: '')), '/');
$scheme=strtolower((string)parse_url($url,PHP_URL_SCHEME));
$host=strtolower((string)parse_url($url,PHP_URL_HOST));
$token=trim((string)(getenv('ML_SERVICE_TOKEN') ?: ''));
if (!$url || !in_array($scheme,['http','https'],true) || !$host || parse_url($url, PHP_URL_USER)!==null
    || parse_url($url, PHP_URL_PASS)!==null
    || ($scheme==='http' && !in_array($host,['localhost','127.0.0.1','::1','ml-service'],true))
    || strlen($token)<24 || strlen($token)>256
    || !preg_match('/^[A-Za-z0-9._~+\/=\-]{24,256}$/D',$token)) {
    assistant_reply(503,['ok'=>false,'error'=>'The private AI service is not configured.']);
}
$payload=[
    'features'=>$features,
    'rule_score'=>fortress_ml_rule_score($features),
    'mode'=>$mode, 'question'=>$question, 'history'=>$historyOut,
];
// A curated held-out label is evaluation metadata; it must not influence prediction.
$expectedLabel = $sample['true_label'] ?? null;
if (is_string($expectedLabel) && in_array($expectedLabel,
        ['NORMAL','BRUTE_FORCE','CREDENTIAL_STUFFING','RECONNAISSANCE','WEB_ATTACK','MFA_ABUSE','SESSION_ABUSE'], true)) {
    $payload['expected_label'] = $expectedLabel;
}
$body=json_encode($payload,JSON_UNESCAPED_SLASHES);
if (!is_string($body)) assistant_reply(503,['ok'=>false,'error'=>'Unable to prepare assessment.']);
$headers="Content-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nAuthorization: Bearer {$token}\r\n";
$context=stream_context_create(['http'=>[
    'method'=>'POST','header'=>$headers,'content'=>$body,
    'timeout'=>20,'ignore_errors'=>true,'follow_location'=>0,
]]);
$upstream=@file_get_contents($url . '/security-assistant',false,$context,0,16001);
$httpCode=0;
foreach (($http_response_header??[]) as $line) {
    if (preg_match('/^HTTP\/\S+\s+(\d{3})/',(string)$line,$m)) {$httpCode=(int)$m[1];break;}
}
if (!is_string($upstream) || $httpCode!==200) {
    assistant_reply(503,['ok'=>false,'code'=>'LLM_UNAVAILABLE',
        'error'=>'AI Security Analyst is temporarily unavailable. Existing ML analysis remains unaffected.']);
}
$result=json_decode($upstream,true);
if (!is_array($result) || !in_array($result['engine']??null,['groq','deterministic_fallback'],true)
  || !is_string($result['answer']??null) || strlen($result['answer'])>6000
  || !is_array($result['context']??null)
  || !in_array($result['context']['classification']??null, ['NORMAL','BRUTE_FORCE','CREDENTIAL_STUFFING','RECONNAISSANCE','WEB_ATTACK','MFA_ABUSE','SESSION_ABUSE'],true)) {
    assistant_reply(503,['ok'=>false,'error'=>'AI response validation failed.']);
}
$assessment=$result['context'];
// Non-secret model identifiers support verification of 120B analyst vs 20B chat.
// Never echo SDK errors, tokens or arbitrary vendor metadata to the browser.
$model_requested = $result['llm_model_requested'] ?? null;
$model_reported = $result['llm_model_reported'] ?? null;
foreach (['model_requested', 'model_reported'] as $name) {
    if (!is_string($$name) || !preg_match('~^[A-Za-z0-9_./-]{3,100}$~D', $$name)) $$name = null;
}
if ($result['engine'] !== 'groq') { $model_requested = null; $model_reported = null; }
assistant_reply(200,[
    'ok'=>true, 'sample_id'=>$id, 'engine'=>$result['engine'], 'mode'=>$mode,
    'answer'=>substr($result['answer'],0,4500),
    'classification'=>$assessment['classification'],
    'risk_score'=>$assessment['risk_score'],
    'confidence'=>$assessment['confidence'],
    'severity'=>$assessment['severity'],
    'indicators'=>$assessment['indicator_evidence'] ?? [],
    'llm_model_requested'=>$model_requested,
    'llm_model_reported'=>$model_reported,
    'synthetic'=>true, 'publicly_shared'=>false,
]);
