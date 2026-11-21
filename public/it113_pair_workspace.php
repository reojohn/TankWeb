<?php
/** Two-seat, login-free and invite-only synthetic research collaboration API. */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Cross-Origin-Resource-Policy: same-origin');
function pair_reply(int $status,array $data): never {
    http_response_code($status);
    echo json_encode($data,JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
if (!in_array(($_SERVER['REQUEST_METHOD']??''),['GET','POST'],true)) {
    header('Allow: GET, POST');pair_reply(405,['ok'=>false,'error'=>'Use GET or POST.']);
}
$env=__DIR__.'/../.env';
if (is_readable($env)) {
    foreach(file($env,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[] as $line) {
        $line=trim($line);
        if($line===''||str_starts_with($line,'#')||!str_contains($line,'='))continue;
        [$key,$value]=array_map('trim',explode('=',$line,2));
        if(!preg_match('/^[A-Z_][A-Z0-9_]*$/D',$key)||getenv($key)!==false)continue;
        if(strlen($value)>=2&&in_array($value[0],["'",'"'],true)&&substr($value,-1)===$value[0])$value=substr($value,1,-1);
        putenv($key.'='.$value);
    }
}
require_once __DIR__.'/../src/it113_public_store.php';
require_once __DIR__.'/../src/it113_shared_limiter.php';
if (!filter_var(getenv('IT113_PUBLIC_DEMO_ENABLED')?:'false',FILTER_VALIDATE_BOOL) || !it113_pair_enabled()) {
    pair_reply(503,['ok'=>false,'error'=>'Shared research workspace is not enabled.']);
}
$method=(string)($_SERVER['REQUEST_METHOD']??'GET');
$limit=it113_demo_limit($method==='GET'?'read':'write');
if($limit==='unavailable') {header('Retry-After: 60');pair_reply(503,['ok'=>false,'code'=>'SAFETY_GATE_UNAVAILABLE','error'=>'Shared security checks are unavailable.']);}
if($limit==='limited') {header('Retry-After: 60');pair_reply(429,['ok'=>false,'code'=>'DEMO_LIMIT_REACHED','error'=>'Shared demo limit reached. Try later.']);}
if($method==='GET') {
    $data=it113_pair_status();
    if($data===null)pair_reply(503,['ok'=>false,'error'=>'Workspace service is temporarily unavailable.']);
    pair_reply(200,['ok'=>true,'enabled'=>true,'workspace'=>$data]);
}
if(stripos((string)($_SERVER['CONTENT_TYPE']??''),'application/json')!==0 ||
    (int)($_SERVER['CONTENT_LENGTH']??0)>512) pair_reply(415,['ok'=>false,'error'=>'Small JSON body required.']);
$site=strtolower((string)($_SERVER['HTTP_SEC_FETCH_SITE']??''));
if(in_array($site,['cross-site','none'],true))pair_reply(403,['ok'=>false,'error'=>'Cross-site request rejected.']);
$origin=rtrim((string)($_SERVER['HTTP_ORIGIN']??''),'/');
if($origin!=='') {
    $host=strtolower((string)($_SERVER['HTTP_HOST']??''));
    $domain=strtolower((string)(parse_url($origin,PHP_URL_HOST)?:''));
    $port=parse_url($origin,PHP_URL_PORT);
    $authority=$domain.($port===null?'':':'.$port);
    $scheme=strtolower((string)(parse_url($origin,PHP_URL_SCHEME)?:''));
    $allowed=array_map('trim',explode(',',(string)(getenv('IT113_DEMO_ALLOWED_ORIGINS')?:'')));
    if(!in_array($scheme,['http','https'],true)||($authority!==$host&&!in_array($origin,$allowed,true))) {
        pair_reply(403,['ok'=>false,'error'=>'Origin not allowed.']);
    }
}
$raw=file_get_contents('php://input',false,null,0,513);
if(!is_string($raw)||strlen($raw)>512)pair_reply(413,['ok'=>false,'error'=>'Payload too large.']);
$data=json_decode($raw,true);
if(!is_array($data)||array_is_list($data)||!is_string($data['action']??null)) {
    pair_reply(400,['ok'=>false,'error'=>'Invalid action.']);
}
$action=$data['action'];
if(!in_array($action,['create','join','invite','remove_partner','leave'],true)) {
    pair_reply(400,['ok'=>false,'error'=>'Unsupported action.']);
}
[$success,$code,$invitation]=array_pad(it113_pair_action($action,$data),3,null);
if(!$success) {
    $http=match($code) { 'invalid'=>400,'not_member','forbidden'=>403,
        'already_member','full'=>409,'invalid_or_expired_invite'=>410,
        'disabled','unavailable'=>503,default=>400 };
    $errors=[
        'invalid'=>'Request is invalid.','not_member'=>'Not a workspace member.',
        'forbidden'=>'Only the workspace owner can do that.',
        'already_member'=>'This browser already belongs to a pair workspace.',
        'full'=>'This workspace already has two members.',
        'invalid_or_expired_invite'=>'Invitation has expired, was used, or was replaced.',
        'unavailable'=>'Workspace database unavailable.',
        'disabled'=>'Shared research is disabled.',
    ];
    pair_reply($http,['ok'=>false,'error'=>$errors[$code]??'Workspace action rejected.']);
}
$status=it113_pair_status();
if($status===null)pair_reply(503,['ok'=>false,'error'=>'Workspace status unavailable.']);
$body=['ok'=>true,'status'=>$code,'workspace'=>$status];
if($action==='invite'&&is_string($invitation)) $body['invite_token']=$invitation;
pair_reply(200,$body);
