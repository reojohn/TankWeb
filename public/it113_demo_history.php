<?php
/** Public, session-scoped academic history and mitigation status. No account UI. */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: private, no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Robots-Tag: noindex, nofollow');
function response(int $code, array $body): never {
    http_response_code($code);
    echo json_encode($body, JSON_INVALID_UTF8_SUBSTITUTE|JSON_UNESCAPED_SLASHES);
    exit;
}
$env = __DIR__.'/../.env';
if (is_readable($env)) {
    foreach (file($env,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $line=trim($line);
        if ($line==='' || str_starts_with($line,'#') || !str_contains($line,'=')) continue;
        [$k,$v]=array_map('trim',explode('=',$line,2));
        if (!preg_match('/^[A-Z_][A-Z0-9_]*$/D',$k) || getenv($k)!==false) continue;
        if (strlen($v)>=2 && in_array($v[0],["'",'"'],true) && substr($v,-1)===$v[0]) $v=substr($v,1,-1);
        putenv($k.'='.$v);
    }
}
require_once __DIR__.'/../src/it113_public_store.php';
if (!filter_var(getenv('IT113_PUBLIC_DEMO_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL)) {
    response(503,['ok'=>false,'error'=>'Academic demonstration unavailable.']);
}
$method=(string)($_SERVER['REQUEST_METHOD']??'GET');
if ($method==='GET') {
    $records=it113_store_history();
    if ($records===null) response(200,['ok'=>true,'enabled'=>false,
        'storage_state'=>it113_store_diagnostic(),'entries'=>[]]);
    $trace=(string)($_GET['trace_id'] ?? '');
    $events=$trace!=='' ? it113_store_events($trace) : [];
    response(200,['ok'=>true,'enabled'=>true,'storage_state'=>'ready',
        'entries'=>$records,'events'=>$events ?: []]);
}
if ($method!=='POST') { header('Allow: GET, POST'); response(405,['ok'=>false,'error'=>'Unsupported method.']); }
if (stripos((string)($_SERVER['CONTENT_TYPE']??''),'application/json')!==0 ||
    (int)($_SERVER['CONTENT_LENGTH']??0)>1000) response(415,['ok'=>false,'error'=>'JSON request required.']);
if (strtolower((string)($_SERVER['HTTP_SEC_FETCH_SITE']??''))==='cross-site') {
    response(403,['ok'=>false,'error'=>'Cross-site update rejected.']);
}
$origin=rtrim((string)($_SERVER['HTTP_ORIGIN']??''),'/');
if ($origin!=='') {
    $expectedHost=strtolower((string)($_SERVER['HTTP_HOST']??''));
    $domain=strtolower((string)(parse_url($origin,PHP_URL_HOST) ?: ''));
    $port=parse_url($origin,PHP_URL_PORT);
    $originHost=$domain.($port===null?'':':'.$port);
    $scheme=strtolower((string)(parse_url($origin,PHP_URL_SCHEME) ?: ''));
    $allowed=array_map('trim',explode(',',(string)(getenv('IT113_DEMO_ALLOWED_ORIGINS') ?: '')));
    if (!in_array($scheme,['http','https'],true) || ($originHost!==$expectedHost && !in_array($origin,$allowed,true))) {
        response(403,['ok'=>false,'error'=>'Origin not allowed.']);
    }
}
$data=json_decode((string)file_get_contents('php://input',false,null,0,1001),true);
if (is_array($data) && count($data)===1 && ($data['action']??'')==='clear') {
    if (it113_store_clear()) response(200,['ok'=>true,'cleared'=>true]);
    response(503,['ok'=>false,'error'=>'Could not clear saved history.']);
}
if (!is_array($data) || count($data)!==5 ||
    array_diff(array_keys($data),['action','trace_id','status','revision','note']) ||
    ($data['action']??'')!=='status' || !is_string($data['trace_id']??null) ||
    !is_string($data['status']??null) || !is_int($data['revision']??null) ||
    !is_string($data['note']??null)) response(400,['ok'=>false,'error'=>'Invalid case update.']);
$status=it113_store_status($data['trace_id'],$data['status'],$data['note'],$data['revision']);
if ($status==='updated') response(200,['ok'=>true,'updated'=>true]);
response($status==='conflict'?409:($status==='unavailable'?503:422),
    ['ok'=>false,'error'=>match($status) {
        'conflict'=>'Case changed elsewhere. Refresh and retry.',
        'unavailable'=>'Case persistence unavailable.',
        default=>'Case update rejected.',
    }]);
