<?php

declare(strict_types=1);

define('FORTRESS_BACKGROUND_REQUEST', true);

require __DIR__ . '/../../src/middleware.php';
require_once __DIR__ . '/../../src/config.php';
require_once __DIR__ . '/../../src/auth.php';
require_once __DIR__ . '/../../src/logger.php';
require_once __DIR__ . '/../../src/fortress_metrics.php';
require_once __DIR__ . '/../../src/security_policy.php';
require_once __DIR__ . '/../../src/ml_threat.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

require_admin_auth();

$userId = (int)($_SESSION['uid'] ?? 0);
$view = strtolower(trim((string)($_GET['view'] ?? 'bootstrap')));

function fortress_v3_json(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function fortress_v3_event(string $line, string $fallbackUser): array
{
    $outcome = fortress_event_outcome($line);
    return [
        'timestamp' => fortress_event_time($line, 'Y-m-d H:i:s'),
        'time' => fortress_event_time($line),
        'category' => fortress_event_category($line),
        'title' => fortress_event_title($line),
        'description' => fortress_event_description($line),
        'outcome' => $outcome,
        'outcomeKey' => strtolower($outcome),
        'ip' => fortress_log_ip($line),
        'user' => fortress_log_user($line, $fallbackUser),
        'factor' => str_contains($line, 'school_id') ? 'Personal ID' : (str_contains($line, 'password') ? 'Password' : 'Session'),
        'raw' => $line,
    ];
}

function fortress_v3_header_context(PDO $pdo, int $userId): array
{
    $ctx = fortress_build_security_context($pdo, $userId, ['minimal' => true]);
    $policy = fortress_security_policy();
    $role = fortress_normalize_role($ctx['userRole'] ?? ($_SESSION['role'] ?? 'superadmin'));

    return [
        'userId' => $userId,
        'username' => (string)($ctx['usernameRaw'] ?? 'admin'),
        'role' => $role,
        'roleLabel' => $role === 'superadmin' ? 'SUPER ADMIN' : 'ADMIN',
        'protectionScore' => (int)($ctx['protectionScore'] ?? 0),
        'protectionLabel' => (string)($ctx['protectionLabel'] ?? 'PROTECTED'),
        'activeDefenseCount' => (int)($ctx['activeDefenseCount'] ?? 0),
        'defenseTotal' => count((array)($ctx['defenseLayers'] ?? [])),
        'defenseLayers' => array_map(static fn(array $layer): array => [
            'name' => (string)($layer[0] ?? ''),
            'active' => (bool)($layer[1] ?? false),
            'description' => (string)($layer[2] ?? ''),
            'weight' => (int)($layer[3] ?? 0),
            'icon' => (string)($layer[4] ?? 'fa-shield'),
        ], (array)($ctx['defenseLayers'] ?? [])),
        'schoolIdRequired' => (bool)($ctx['schoolIdRequired'] ?? true),
        'schoolIdEnabled' => (bool)($ctx['schoolIdEnabled'] ?? false),
        'schoolIdVerified' => (bool)($ctx['schoolIdVerified'] ?? false),
        'schoolIdFactorType' => (string)($ctx['schoolIdFactorType'] ?? 'personal_id'),
        'clientIp' => getRealIP(),
        'csrfToken' => generate_csrf_token(),
        'policy' => [
            'alertPollSeconds' => (int)$policy['alert_poll_seconds'],
            'livePollSeconds' => (int)$policy['live_state_poll_seconds'],
            'sessionIdleSeconds' => (int)$policy['session_idle_seconds'],
            'sessionAbsoluteSeconds' => (int)$policy['session_absolute_seconds'],
        ],
    ];
}

try {
    if ($view === 'bootstrap') {
        fortress_v3_json(['ok' => true, 'data' => fortress_v3_header_context($pdo, $userId)]);
    }

    if ($view === 'overview') {
        $ctx = fortress_build_security_context($pdo, $userId, ['include_charts' => true, 'include_top_threat_sources' => true]);
        $username = (string)$ctx['usernameRaw'];
        $verifiedAt = (int)($_SESSION['school_id_verified_at'] ?? 0);
        $secondFactorIssued = (bool)$ctx['schoolIdRequired'] && ($ctx['schoolIdFactorType'] ?? 'personal_id') === 'generated_qr';
        $secondFactorLabel = !$ctx['schoolIdRequired'] ? 'Password only' : ($secondFactorIssued ? 'Issued QR' : 'Personal ID');
        $accessChainComplete = !$ctx['schoolIdRequired'] || $ctx['schoolIdVerified'];

        $attackSurface = [
            ['icon'=>'fa-database','label'=>'SQL injection patterns','value'=>(int)$ctx['sqlAttack24h'],'note'=>'Detected and blocked / 24h'],
            ['icon'=>'fa-code','label'=>'XSS / suspicious input','value'=>(int)$ctx['xssAttack24h'] + (int)$ctx['pathAttack24h'],'note'=>'Input defense events / 24h'],
            ['icon'=>'fa-terminal','label'=>'Shell-style payloads','value'=>(int)$ctx['shellAttack24h'],'note'=>'Command-pattern detections / 24h'],
            ['icon'=>'fa-spider','label'=>'Honeypot triggers','value'=>(int)$ctx['honeypot24h'],'note'=>'Honeypot events / 24h'],
            ['icon'=>'fa-gauge-high','label'=>'Rate-limit pressure','value'=>(int)$ctx['bruteforce24h'],'note'=>'Brute-force triggers / 24h'],
            ['icon'=>'fa-shield-halved','label'=>'Blocked requests','value'=>(int)$ctx['blockedRequests24h'],'note'=>'Defense rejections / 24h'],
        ];

        fortress_v3_json(['ok'=>true,'data'=>[
            'header' => fortress_v3_header_context($pdo, $userId),
            'metrics' => [
                'currentOperator' => $username,
                'failedAttempts24h' => (int)$ctx['failedAttempts24h'],
                'suspiciousRequests24h' => (int)$ctx['suspiciousRequests24h'],
                'activeBans' => (int)$ctx['activeBans'],
                'successfulPassword24h' => (int)$ctx['successfulPassword24h'],
                'schoolIdSuccess24h' => (int)$ctx['schoolIdSuccess24h'],
                'schoolIdFailures24h' => (int)$ctx['schoolIdFailures24h'],
                'blockedRequests24h' => (int)$ctx['blockedRequests24h'],
                'totalAuditEvents' => (int)$ctx['totalAuditEvents'],
                'totalHoneypotEvents' => (int)$ctx['totalHoneypotEvents'],
            ],
            'threat' => [
                'level' => (string)$ctx['threatLevel'],
                'className' => (string)$ctx['threatClass'],
                'points' => (int)$ctx['threatPoints'],
                'lastThreatRelative' => (string)$ctx['lastThreatRelative'],
                'topSources' => array_map(static fn($ip, $count): array => ['ip'=>(string)$ip,'count'=>(int)$count], array_keys($ctx['topThreatSources']), array_values($ctx['topThreatSources'])),
            ],
            'verification' => [
                'accessChainComplete' => $accessChainComplete,
                'secondFactorLabel' => $secondFactorLabel,
                'secondFactorIcon' => $secondFactorIssued ? 'fa-qrcode' : 'fa-id-card',
                'verifiedDisplay' => !$ctx['schoolIdRequired'] ? 'Not required by account policy' : ($verifiedAt > 0 ? date('Y-m-d H:i:s', $verifiedAt) : 'Not verified in this session'),
                'sessionStartDisplay' => (string)$ctx['sessionStartDisplay'],
            ],
            'attackSurface' => $attackSurface,
            'recentEvents' => array_map(fn(string $line): array => fortress_v3_event($line, $username), (array)$ctx['recentLines']),
            'recentAuth' => array_map(fn(string $line): array => fortress_v3_event($line, $username), (array)$ctx['recentAuthLines']),
            'timeline' => array_map(fn(string $line): array => fortress_v3_event($line, $username), (array)$ctx['timeline']),
            'chart' => [
                'labels'=>(array)$ctx['chartLabels'],
                'success'=>(array)$ctx['chartSuccess'],
                'failed'=>(array)$ctx['chartFailed'],
                'school'=>(array)$ctx['chartSchool'],
                'blocked'=>(array)$ctx['chartBlocked'],
            ],
            'protectedAssets' => array_map(static fn(array $a): array => ['icon'=>$a[0],'name'=>$a[1],'description'=>$a[2]], (array)$ctx['protectedAssets']),
            'protectedResources' => array_map(static fn(array $a): array => ['name'=>$a[0],'href'=>$a[1],'icon'=>$a[2]], (array)$ctx['protectedResources']),
            'lastEventRelative' => (string)$ctx['lastEventRelative'],
        ]]);
    }

    if ($view === 'access') {
        $headerCtx = fortress_build_security_context($pdo, $userId, ['minimal'=>true]);
        $username = (string)$headerCtx['usernameRaw'];
        $metricState = fortress_security_metrics_24h_db($pdo) ?: [];
        $chartState = fortress_security_hourly_chart_db($pdo) ?: [];
        $failed = (int)($metricState['failed_passwords'] ?? 0);
        $passed = (int)($metricState['successful_passwords'] ?? 0);
        $schoolPassed = (int)($metricState['school_id_success'] ?? 0);
        $schoolFailed = (int)($metricState['school_id_failures'] ?? 0);

        $now = new DateTimeImmutable('now');
        $maps = ['success'=>[],'failed'=>[],'school'=>[],'blocked'=>[]];
        $keys = [];
        for ($i=23;$i>=0;$i--) {
            $key = $now->modify('-'.$i.' hours')->format('Y-m-d H');
            $keys[]=$key;
            foreach ($maps as &$m) $m[$key]=0;
            unset($m);
        }
        foreach ($chartState as $row) {
            $key=(string)($row['hour_key']??'');
            if (!isset($maps['success'][$key])) continue;
            $maps['success'][$key]=(int)($row['password_success']??0);
            $maps['failed'][$key]=(int)($row['password_failed']??0);
            $maps['school'][$key]=(int)($row['school_success']??0);
            $maps['blocked'][$key]=(int)($row['blocked']??0);
        }
        $eventKeys=['password_factor_success','password_factor_failed','school_id_qr_success','school_id_qr_failed','school_id_qr_locked','school_id_2fa_not_required','login_success','logout'];
        $history = fortress_recent_security_event_lines($pdo,$eventKeys,160) ?: [];
        fortress_v3_json(['ok'=>true,'data'=>[
            'header'=>fortress_v3_header_context($pdo,$userId),
            'metrics'=>['passed'=>$passed,'rejected'=>$failed+$schoolFailed,'schoolPassed'=>$schoolPassed,'attempts'=>$passed+$failed],
            'chart'=>[
                'labels'=>array_map(static fn(string $k): string=>substr($k,11,2).':00',$keys),
                'success'=>array_values($maps['success']),'failed'=>array_values($maps['failed']),'school'=>array_values($maps['school']),'blocked'=>array_values($maps['blocked'])
            ],
            'history'=>array_map(fn(string $line): array=>fortress_v3_event($line,$username),$history),
        ]]);
    }

    if ($view === 'analytics') {
        $ctx = fortress_build_security_context($pdo,$userId,['include_charts'=>true]);
        $today=new DateTimeImmutable('today');
        $dayKeys=[];$dailyPassed=[];$dailyRejected=[];$dailyBlocked=[];
        for($i=6;$i>=0;$i--){$day=$today->modify('-'.$i.' days');$key=$day->format('Y-m-d');$dayKeys[]=$key;$dailyPassed[$key]=0;$dailyRejected[$key]=0;$dailyBlocked[$key]=0;}
        $categories=['Authentication'=>0,'Identity'=>0,'Network'=>0,'Threat'=>0,'Session'=>0,'System'=>0];
        $outcomes=['PASSED'=>0,'REJECTED'=>0,'BLOCKED'=>0,'RECORDED'=>0,'CLOSED'=>0];
        $db=fortress_analytics_30d_db($pdo);
        if(is_array($db)){
            foreach((array)($db['daily']??[]) as $row){$k=(string)($row['day_key']??'');$o=(string)($row['outcome_key']??'RECORDED');$c=(int)($row['event_count']??0);if(!isset($dailyPassed[$k]))continue;if($o==='PASSED')$dailyPassed[$k]+=$c;elseif($o==='BLOCKED')$dailyBlocked[$k]+=$c;elseif($o==='REJECTED')$dailyRejected[$k]+=$c;}
            foreach((array)($db['summary']??[]) as $row){$cat=(string)($row['category_key']??'System');$o=(string)($row['outcome_key']??'RECORDED');$c=(int)($row['event_count']??0);$categories[$cat]=($categories[$cat]??0)+$c;$outcomes[$o]=($outcomes[$o]??0)+$c;}
        }
        $success=(int)($outcomes['PASSED']??0);$rejected=(int)($outcomes['REJECTED']??0)+(int)($outcomes['BLOCKED']??0);$rate=($success+$rejected)>0?(int)round($success/($success+$rejected)*100):0;
        $pressure=[(int)$ctx['failedAttempts24h'],(int)$ctx['schoolIdFailures24h'],(int)$ctx['suspiciousRequests24h'],(int)$ctx['bruteforce24h'],(int)$ctx['honeypot24h'],(int)$ctx['activeBans']];$max=max(1,...$pressure);$pressure=array_map(static fn(int $v):int=>(int)round(($v/$max)*100),$pressure);
        $recent=array_slice(array_reverse(array_values(array_filter((array)$ctx['auditLines'],'fortress_is_meaningful_event'))),0,8);
        fortress_v3_json(['ok'=>true,'data'=>[
            'header'=>fortress_v3_header_context($pdo,$userId),
            'summary'=>['successRate'=>$rate,'totalAuditEvents'=>(int)$ctx['totalAuditEvents'],'threatLevel'=>(string)$ctx['threatLevel'],'threatPoints'=>(int)$ctx['threatPoints'],'activeDefenseCount'=>(int)$ctx['activeDefenseCount'],'defenseTotal'=>count((array)$ctx['defenseLayers']),'protectionLabel'=>(string)$ctx['protectionLabel']],
            'hour'=>['labels'=>(array)$ctx['chartLabels'],'success'=>(array)$ctx['chartSuccess'],'failed'=>(array)$ctx['chartFailed'],'school'=>(array)$ctx['chartSchool'],'blocked'=>(array)$ctx['chartBlocked']],
            'week'=>['labels'=>array_map(static fn(string $k):string=>(new DateTimeImmutable($k))->format('D'),$dayKeys),'passed'=>array_values($dailyPassed),'rejected'=>array_values($dailyRejected),'blocked'=>array_values($dailyBlocked)],
            'categories'=>['labels'=>array_keys($categories),'values'=>array_values($categories)],
            'outcomes'=>['labels'=>array_keys($outcomes),'values'=>array_values($outcomes)],
            'pressure'=>['labels'=>['Password','Personal ID','Suspicious','Brute Force','Honeypot','Bans'],'values'=>$pressure],
            'recent'=>array_map(fn(string $line):array=>fortress_v3_event($line,(string)$ctx['usernameRaw']),$recent),
        ]]);
    }

    if ($view === 'threats') {
        $ctx=fortress_build_security_context($pdo,$userId,['include_all_time_threats'=>true,'include_top_threat_sources'=>true]);
        $username=(string)$ctx['usernameRaw'];
        $needles=['ml_assisted_block','ml_assisted_strike','ml_threat_prediction','malicious_input_detected','shell_attack_detected','request_threat_detected','csp_violation_reported','scanner_user_agent_detected','sensitive_path_probe','reconnaissance_probe','csrf_validation_failed','http_method_blocked','http_method_anomaly','endpoint_method_rejected','oversized_request_detected','oversized_uri_detected','banned_ip_attempt','banned_ip_middleware_block','bruteforce_detected','ip_banned','school_id_qr_failed','school_id_qr_locked','school_id_qr_rate_limited','password_factor_failed','auth_rejected','honeypot_triggered'];
        $history=fortress_recent_security_event_lines($pdo,$needles,120)?:[];
        $all=(array)$ctx['threatCategoryAllTime'];
        $defs=[
            ['fa-key','Password rejection','passwordRejection','All-time first-factor failures'],['fa-id-card','Personal ID rejection','personalIdRejection','All-time possession-factor failures'],['fa-database','SQL injection','sqlInjection','Persistent SQL-pattern detections'],['fa-code','XSS / traversal','xssTraversal','Persistent input-pattern detections'],['fa-terminal','Shell payload','shellPayload','Persistent command-pattern detections'],['fa-shield-halved','CSRF rejection','csrfRejection','Persistent anti-CSRF rejections'],['fa-shield','CSP violations','cspViolations','Persistent browser CSP reports'],['fa-magnifying-glass','Recon / 404 probes','reconProbes','Persistent path-probe detections'],['fa-robot','Scanner fingerprints','scannerFingerprints','Persistent scanner-style user agents'],['fa-code-branch','HTTP method abuse','httpMethodAbuse','Persistent blocked/anomalous methods'],['fa-file-circle-exclamation','Oversized requests','oversizedRequests','Persistent abnormal request sizes'],['fa-gauge-high','Brute force','bruteForce','Persistent rate-limit triggers'],['fa-spider','Honeypot','honeypot','Persistent honeypot events'],['fa-ban','Banned-source hits','bannedSourceHits','Persistent blocked banned clients'],['fa-door-open','Forced Browsing','forcedBrowsing','Persistent unauthorized page access']
        ];
        $cats=array_map(static fn(array $d):array=>['icon'=>$d[0],'label'=>$d[1],'value'=>(int)($all[$d[2]]??0),'note'=>$d[3]],$defs);
        fortress_v3_json(['ok'=>true,'data'=>[
            'header'=>fortress_v3_header_context($pdo,$userId),
            'threat'=>['level'=>(string)$ctx['threatLevel'],'className'=>(string)$ctx['threatClass'],'points'=>(int)$ctx['threatPoints'],'failed'=>(int)$ctx['failedAttempts24h'],'suspicious'=>(int)$ctx['suspiciousRequests24h'],'activeBans'=>(int)$ctx['activeBans'],'schoolFailed'=>(int)$ctx['schoolIdFailures24h'],'lastThreatRelative'=>(string)$ctx['lastThreatRelative']],
            'topSources'=>array_map(static fn($ip,$count):array=>['ip'=>(string)$ip,'count'=>(int)$count],array_keys($ctx['topThreatSources']),array_values($ctx['topThreatSources'])),
            'categories'=>$cats,
            'history'=>array_map(fn(string $line):array=>fortress_v3_event($line,$username),$history),
        ]]);
    }

    if ($view === 'logs') {
        $ctx=fortress_build_security_context($pdo,$userId,['audit_limit'=>500]);
        $username=(string)$ctx['usernameRaw'];
        $logRows=array_slice(array_reverse((array)$ctx['auditLines']),0,500);
        $honeypotRows=array_slice(array_reverse((array)$ctx['honeypotLines']),0,80);
        $cats=fortress_audit_category_counts_db($pdo);
        if(!is_array($cats)){$cats=['Authentication'=>0,'Identity'=>0,'Network'=>0,'Threat'=>0,'Session'=>0,'System'=>0];foreach((array)$ctx['auditLines'] as $line){$cat=fortress_event_category($line);$cats[$cat]=($cats[$cat]??0)+1;}}
        fortress_v3_json(['ok'=>true,'data'=>[
            'header'=>fortress_v3_header_context($pdo,$userId),
            'metrics'=>['auditEvents'=>(int)$ctx['totalAuditEvents'],'honeypotEvents'=>(int)$ctx['totalHoneypotEvents'],'activeBans'=>(int)$ctx['activeBans'],'lastEventRelative'=>(string)$ctx['lastEventRelative']],
            'logs'=>array_map(fn(string $line):array=>fortress_v3_event($line,$username),$logRows),
            'honeypot'=>array_map(static fn(string $line):array=>['timestamp'=>fortress_event_time($line,'Y-m-d H:i:s'),'description'=>(string)preg_replace('/^\[[^\]]+\]\s*/','',$line)],$honeypotRows),
            'categories'=>$cats,
        ]]);
    }

    if ($view === 'blocked') {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $input=json_decode((string)file_get_contents('php://input'),true); if(!is_array($input))$input=$_POST;
            $token=(string)($input['csrfToken']??$input['csrf_token']??'');$action=(string)($input['action']??'');$ip=trim((string)($input['ip']??''));
            if(!verify_csrf_token($token)) fortress_v3_json(['ok'=>false,'message'=>'The unblock request was rejected because the security token was invalid.'],419);
            if($action!=='unblock'||filter_var($ip,FILTER_VALIDATE_IP)===false) fortress_v3_json(['ok'=>false,'message'=>'The requested IP address was invalid.'],422);
            $stmt=$pdo->prepare('DELETE FROM banned_ips WHERE ip = ?');$stmt->execute([$ip]);audit_log('ip_unblocked uid='.$userId.' ip='.$ip);
            fortress_v3_json(['ok'=>true,'message'=>$stmt->rowCount()>0?'The selected IP address was removed from the database-backed ban list.':'That IP address was not present in the active ban table.']);
        }
        $ctx=fortress_build_security_context($pdo,$userId,['minimal'=>true]);$rows=[];$reasons=[];$hits=0;
        try{$stmt=$pdo->query("SELECT b.ip,b.banned_until,latest.event_key AS latest_event_key FROM banned_ips b LEFT JOIN LATERAL (SELECT se.event_key FROM public.security_events se WHERE se.source_ip=b.ip AND se.event_key IN ('automated_recon_block','ml_assisted_block','bruteforce_detected','honeypot_triggered') ORDER BY se.occurred_at DESC,se.id DESC LIMIT 1) latest ON TRUE ORDER BY b.banned_until DESC LIMIT 500");$rows=$stmt->fetchAll(PDO::FETCH_ASSOC)?:[];$hits=(int)$pdo->query("SELECT COUNT(*) FROM public.security_events WHERE occurred_at >= NOW() - INTERVAL '24 hours' AND event_key IN ('banned_ip_attempt','banned_ip_middleware_block')")->fetchColumn();}catch(Throwable $e){$rows=[];}
        $active=[];$expired=[];
        foreach($rows as $r){$key=(string)($r['latest_event_key']??'');$reason=match($key){'automated_recon_block'=>'Automated reconnaissance defense','ml_assisted_block'=>'AI-assisted threat defense','bruteforce_detected'=>'Brute-force defense','honeypot_triggered'=>'Honeypot defense',default=>'Security policy'};$until=strtotime((string)($r['banned_until']??''));$item=['ip'=>(string)($r['ip']??''),'bannedUntil'=>(string)($r['banned_until']??''),'reason'=>$reason,'remainingSeconds'=>$until===false?0:max(0,$until-time())];if($until!==false&&$until>time())$active[]=$item;else$expired[]=$item;}
        fortress_v3_json(['ok'=>true,'data'=>['header'=>fortress_v3_header_context($pdo,$userId),'active'=>$active,'expired'=>array_slice($expired,0,100),'bannedHits24h'=>$hits,'clientIp'=>getRealIP()]]);
    }

    if ($view === 'controls') {
        $ctx=fortress_build_security_context($pdo,$userId,['minimal'=>true]);$policy=fortress_security_policy();$metric=fortress_security_metrics_24h_db($pdo)?:[];
        $mlEnabled=fortress_ml_enabled();$mlAssist=fortress_ml_assisted_enforcement_enabled();
        $items=[
            ['icon'=>'fa-key','name'=>'Password authentication','status'=>'ENFORCED','description'=>'Primary administrator credential validation remains server-side in PHP.'],
            ['icon'=>'fa-id-card','name'=>'Personal ID 2FA','status'=>$ctx['schoolIdRequired']?'REQUIRED':'OPTIONAL','description'=>'Per-account possession-factor policy enforced by the PHP authentication layer.'],
            ['icon'=>'fa-shield','name'=>'CSRF protection','status'=>'ENFORCED','description'=>'State-changing actions require a valid server-generated CSRF token.'],
            ['icon'=>'fa-gauge-high','name'=>'Brute-force defense','status'=>'ENFORCED','description'=>'Repeated password failures are tracked and can trigger temporary IP bans.'],
            ['icon'=>'fa-magnifying-glass','name'=>'Recon defense','status'=>'ENFORCED','description'=>'Scanner fingerprints, path probes, method anomalies, and request bursts are monitored.'],
            ['icon'=>'fa-brain','name'=>'ML service','status'=>$mlEnabled?'ENABLED':'DISABLED','description'=>'Hybrid ML analysis is called by PHP and never directly by the browser.'],
            ['icon'=>'fa-shield-virus','name'=>'AI-assisted enforcement','status'=>$mlAssist?'ENABLED':'ADVISORY','description'=>'Model findings require deterministic evidence before contributing to enforcement.'],
            ['icon'=>'fa-cookie-bite','name'=>'Session protection','status'=>'ENFORCED','description'=>'HttpOnly cookies, SameSite Strict, session rotation, idle timeout, and session binding.'],
        ];
        fortress_v3_json(['ok'=>true,'data'=>['header'=>fortress_v3_header_context($pdo,$userId),'controls'=>$items,'policy'=>[
            'passwordIpFailureLimit'=>(int)$policy['password_ip_failure_limit'],'passwordAccountFailureLimit'=>(int)$policy['password_account_failure_limit'],'failureWindowSeconds'=>(int)$policy['password_failure_window_seconds'],'ipBanSeconds'=>(int)$policy['ip_ban_seconds'],'reconProbeLimit'=>(int)$policy['recon_probe_limit'],'reconRequestLimit'=>(int)$policy['recon_request_limit'],'sessionIdleSeconds'=>(int)$policy['session_idle_seconds'],'sessionAbsoluteSeconds'=>(int)$policy['session_absolute_seconds']
        ],'metrics'=>['failed24h'=>(int)($metric['failed_passwords']??0),'suspicious24h'=>(int)($metric['suspicious_requests']??0),'bannedHits24h'=>(int)($metric['banned_request_hits']??0)]]]);
    }

    if ($view === 'ai') {
        $ctx=fortress_build_security_context($pdo,$userId,['minimal'=>true]);
        $enabled=fortress_ml_enabled();$status=fortress_ml_service_status();$connected=is_array($status)&&!empty($status['ok']);$queue=fortress_ml_queue_status();$latest=fortress_ml_latest_prediction();$result=is_array($latest['result']??null)?$latest['result']:null;$features=is_array($latest['features']??null)?$latest['features']:[];$probs=$result&&is_array($result['probabilities']??null)?$result['probabilities']:[];arsort($probs);
        $history=fortress_ml_prediction_history(20);$assist=fortress_ml_assisted_enforcement_enabled();
        $risk=$result?(float)($result['risk_score']??0):0;$class=$result?(string)($result['classification']??'UNKNOWN'):'NOT_ANALYZED';$confidence=$result?((float)($result['confidence']??0)*100):0;$anomaly=$result?((float)($result['anomaly_score']??0)*100):0;$rule=$result?(float)($result['rule_score']??0):0;$xgb=$result?(float)($result['xgboost_risk']??0):0;
        $messages=[];
        if(!$enabled){$messages[]='The hybrid machine-learning service is disabled. Core FortressAuth defenses remain operational.';}elseif(!$result){$messages[]='The ML service is enabled and waiting for a protected request to produce the next behavioral analysis.';}else{$messages[]='Latest behavior classification: '.ucwords(strtolower(str_replace('_',' ',$class))).'.';$messages[]=sprintf('Hybrid risk is %.1f/100 with %.1f%% classifier confidence and %.1f%% anomaly deviation.',$risk,$confidence,$anomaly);$messages[]=sprintf('Deterministic rule evidence contributes %.1f/100. AI-assisted enforcement is %s.',$rule,$assist?'active':'advisory only');}
        fortress_v3_json(['ok'=>true,'data'=>[
            'header'=>fortress_v3_header_context($pdo,$userId),
            'service'=>['enabled'=>$enabled,'connected'=>$connected,'state'=>is_array($status)?strtoupper((string)($status['state']??'UNKNOWN')):($enabled?'ENABLED':'DISABLED'),'httpCode'=>is_array($status)?(int)($status['http_code']??0):0,'latencyMs'=>is_array($status)?(int)($status['latency_ms']??0):0,'pending'=>(int)($queue['pending']??0),'completed24h'=>(int)($queue['completed_24h']??0)],
            'latest'=>[
                'risk'=>$risk,
                'severity'=>$result ? (string)($result['severity']??'NO DATA') : ($enabled?'WAITING':'DISABLED'),
                'classification'=>$class,
                'confidence'=>$confidence,
                'anomaly'=>$anomaly,
                'ruleScore'=>$rule,
                'xgboostRisk'=>$xgb,
                'analysisMode'=>$result ? strtoupper((string)($result['analysis_mode']??'LIVE')) : 'NONE',
                'queueDelaySeconds'=>$result ? (int)($result['queue_delay_seconds']??0) : 0,
                'indicators'=>$result && is_array($result['indicators']??null) ? $result['indicators'] : [],
                'sourceIp'=>is_array($latest) ? (string)($latest['ip']??'No source yet') : 'No source yet',
                'time'=>is_array($latest) && (int)($latest['ts']??0)>0 ? date('Y-m-d H:i:s',(int)$latest['ts']) : 'Waiting for first analysis',
                'enforcementAction'=>$result ? (string)($result['enforcement_action']??($assist?'OBSERVE':'ADVISORY_ONLY')) : ($assist?'WAITING':'ADVISORY_ONLY'),
                'enforcementStrikes'=>$result ? (int)($result['enforcement_strikes']??0) : 0,
                'requiredStrikes'=>$result
                    ? (int)($result['enforcement_required_strikes'] ?? max(2,(int)(getenv('ML_ASSISTED_REQUIRED_STRIKES') ?: 2)))
                    : max(2,(int)(getenv('ML_ASSISTED_REQUIRED_STRIKES') ?: 2)),
            ],
            'features'=>$features,'probabilities'=>$probs,'history'=>$history,'assistedEnabled'=>$assist,'messages'=>$messages,
        ]]);
    }

    if ($view === 'vault') {
        $ctx=fortress_build_security_context($pdo,$userId,['minimal'=>true]);$username=trim((string)($ctx['usernameRaw']??'admin'))?:'admin';
        if(empty($_SESSION['fortress_vault_breach_id']))$_SESSION['fortress_vault_breach_id']='FRT-'.strtoupper(bin2hex(random_bytes(5)));
        $flag=trim((string)(getenv('FORTRESS_VAULT_FLAG')?:''));if($flag==='')$flag='FORTRESS{FLAG_NOT_CONFIGURED}';
        if(empty($_SESSION['fortress_vault_logged'])){audit_log('vault_flag_viewed uid='.$userId.' username='.$username.' breach_id='.(string)$_SESSION['fortress_vault_breach_id'].' objective=crown_jewel');$_SESSION['fortress_vault_logged']=true;}
        fortress_v3_json(['ok'=>true,'data'=>['breachId'=>(string)$_SESSION['fortress_vault_breach_id'],'operator'=>$username,'sourceIp'=>getRealIP(),'captured'=>(new DateTimeImmutable('now'))->format('Y-m-d H:i:s T'),'flag'=>$flag,'personalIdRequired'=>(bool)$ctx['schoolIdRequired'],'personalIdVerified'=>!empty($_SESSION['school_id_verified'])]]);
    }

    fortress_v3_json(['ok'=>false,'message'=>'Unknown FortressAuth v3 API view.'],404);
} catch (Throwable $e) {
    error_log('FortressAuth v3 API error ['.$view.']: '.$e->getMessage());
    fortress_v3_json(['ok'=>false,'message'=>'FortressAuth could not load this workspace right now.'],500);
}
