<?php
/** Anonymous, read-only collection of real curated synthetic model assessments. */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Allow: GET');
function project_reply(int $status, array $body): never {
    http_response_code($status);
    echo json_encode($body,JSON_INVALID_UTF8_SUBSTITUTE|JSON_UNESCAPED_SLASHES);
    exit;
}
if (($_SERVER['REQUEST_METHOD']??'GET')!=='GET') {
    project_reply(405,['ok'=>false,'error'=>'Public project is read-only.']);
}
$env=__DIR__.'/../.env';
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
require_once __DIR__.'/../src/it113_public_project.php';
if (!it113_public_project_configured()) {
    project_reply(200,['ok'=>true,'enabled'=>false,'read_only'=>true,
        'status'=>'storage_disabled','entries'=>[]]);
}
require_once __DIR__.'/../src/it113_shared_limiter.php';
$limit=it113_demo_limit('public_read');
if($limit==='unavailable') {
    header('Retry-After: 60');
    project_reply(503,['ok'=>false,'code'=>'SAFETY_GATE_UNAVAILABLE','error'=>'Public research safeguards unavailable.']);
}
if($limit==='limited') {
    header('Retry-After: 60');
    project_reply(429,['ok'=>false,'code'=>'DEMO_LIMIT_REACHED','error'=>'Public research request limit reached.']);
}
$records=it113_public_project_history();
if ($records===null) {
    project_reply(503,['ok'=>false,'status'=>'unavailable','error'=>'Published research is temporarily unavailable.']);
}
project_reply(200,['ok'=>true,'enabled'=>true,'read_only'=>true,
    'status'=>'public','project_name'=>'Aegis AI IT113 Research Project',
    'entries'=>$records]);
