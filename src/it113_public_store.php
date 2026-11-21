<?php
/**
 * Isolated, anonymous IT113 academic assessment store.
 * Never reads or modifies legacy security tables, accounts, or raw logs.
 * Database persistence is opt-in and scoped to a cryptographically random
 * HttpOnly/SameSite cookie; public API roles have no database permissions.
 */
declare(strict_types=1);
require_once __DIR__ . '/it113_pair_workspace.php';

/**
 * A deliberately non-sensitive state code for the academic UI and local
 * troubleshooting. Never expose SQL errors, connection strings or secrets.
 */
function it113_store_diagnostic(?string $newState = null): string {
    static $state = 'not_checked';
    if ($newState !== null) $state = $newState;
    return $state;
}

function it113_store_log_error(string $operation, Throwable $error): void {
    // SQLSTATE alone is useful for a local diagnosis without revealing host,
    // username, password, SQL text, input data, or connection details.
    $code = strtoupper((string)$error->getCode());
    $code = preg_match('/^[0-9A-Z]{5}$/D', $code) ? $code : 'UNKNOWN';
    error_log('IT113 academic persistence ' . $operation . ' failed; code=' . $code);
}

function it113_store_enabled(): bool {
    return filter_var(getenv('IT113_DEMO_PERSISTENCE_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL);
}

function it113_store_session(bool $create = true): ?string {
    $token = (string)($_COOKIE['it113_demo_sid'] ?? '');
    if (!preg_match('/^[a-f0-9]{64}$/D', $token)) {
        if (!$create) return null;
        $token = bin2hex(random_bytes(32));
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https'
            || filter_var(getenv('IT113_DEMO_COOKIE_SECURE') ?: 'false', FILTER_VALIDATE_BOOL);
        setcookie('it113_demo_sid', $token, [
            'expires' => time() + 60 * 60 * 24 * 30,
            'path' => '/', 'secure' => $https, 'httponly' => true,
            'samesite' => 'Strict',
        ]);
        $_COOKIE['it113_demo_sid'] = $token;
    }
    return hash('sha256', $token);
}

function it113_store_db(): ?PDO {
    // Cache one connection per PHP request. Reading the history and its case
    // events must not perform two remote PostgreSQL TLS handshakes.
    static $pdo = null;
    static $attempted = false;
    if (!it113_store_enabled()) {
        it113_store_diagnostic('disabled');
        return null;
    }
    if ($pdo instanceof PDO) return $pdo;
    if ($attempted) return null;
    $attempted = true;
    foreach (['DB_HOST','DB_PORT','DB_NAME','DB_USER','DB_PASS'] as $key) {
        if (trim((string)getenv($key)) === '') {
            it113_store_diagnostic('missing_database_config');
            return null;
        }
    }
    if (!in_array('pgsql', PDO::getAvailableDrivers(), true)) {
        it113_store_diagnostic('pgsql_driver_missing');
        return null;
    }
    $ssl = (string)(getenv('DB_SSLMODE') ?: 'require');
    if (!in_array($ssl, ['require','verify-ca','verify-full'], true)) $ssl = 'require';
    // A local PHP instance can be connecting to a remote Supabase pooler.
    // The previous 4-second connect timeout could fail during TLS setup.
    // Keep it bounded so a remote outage cannot hang the public request.
    $connectTimeout = max(4, min(10, (int)(getenv('IT113_DB_CONNECT_TIMEOUT_SECONDS') ?: 8)));
    try {
        $pdo = new PDO(sprintf('pgsql:host=%s;port=%d;dbname=%s;sslmode=%s',
            getenv('DB_HOST'), (int)getenv('DB_PORT'), getenv('DB_NAME'), $ssl),
            getenv('DB_USER'), getenv('DB_PASS'), [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_TIMEOUT => $connectTimeout,
            ]);
        it113_store_diagnostic('connected');
        return $pdo;
    } catch (Throwable $error) {
        it113_store_diagnostic('database_connection_failed');
        it113_store_log_error('connection', $error);
        return null;
    }
}

function it113_store_record(array $safe): bool {
    $pdo = it113_store_db();
    $scope = $pdo ? it113_pair_scope(true) : null;
    if (!$pdo || !$scope) { it113_store_diagnostic('workspace_unavailable'); return false; }
    $sid=$scope['sid']; $wid=$scope['workspace_id'];
    try {
        $pdo->beginTransaction();
        if ($wid !== null) {
            // Serialize competing writers to the same workspace before the cap check.
            $lock=$pdo->prepare('SELECT workspace_id FROM public.it113_pair_workspaces WHERE workspace_id=? FOR UPDATE');
            $lock->execute([$wid]);
            if (!$lock->fetchColumn()) { $pdo->rollBack();return false; }
            $auth=$pdo->prepare('SELECT 1 FROM public.it113_pair_members
                WHERE workspace_id=? AND session_digest=? FOR SHARE');
            $auth->execute([$wid,$sid]);
            if (!$auth->fetchColumn()) { $pdo->rollBack();return false; }
            $stmt=$pdo->prepare('SELECT COUNT(*) FROM public.it113_demo_assessments WHERE workspace_id=?');
            $stmt->execute([$wid]);
        } else {
            $stmt=$pdo->prepare('SELECT COUNT(*) FROM public.it113_demo_assessments
                WHERE session_digest=? AND workspace_id IS NULL');
            $stmt->execute([$sid]);
        }
        if ((int)$stmt->fetchColumn() >= 80) {
            $pdo->rollBack();it113_store_diagnostic('session_limit_reached');return false;
        }
        $stmt=$pdo->prepare('INSERT INTO public.it113_demo_assessments (
            session_digest, workspace_id, trace_id, source_type, sample_id, expected_label,
            classification, confidence, anomaly_score, rule_score, risk_score,
            severity, model_version, indicators
        ) VALUES (:sid,:wid,:trace,:source,:sample,:expected,:class,:confidence,:anomaly,:rule,:risk,:severity,:version,CAST(:indicators AS jsonb))');
        $stmt->execute([
            ':sid'=>$sid, ':wid'=>$wid, ':trace'=>$safe['trace_id'], ':source'=>$safe['source_type'],
            ':sample'=>$safe['sample_id'] ?? null, ':expected'=>$safe['expected_label'] ?: null,
            ':class'=>$safe['classification'], ':confidence'=>$safe['confidence'],
            ':anomaly'=>$safe['anomaly_score'], ':rule'=>$safe['rule_score'],
            ':risk'=>$safe['risk_score'], ':severity'=>$safe['severity'],
            ':version'=>$safe['model_version'],
            ':indicators'=>json_encode($safe['indicator_evidence'],JSON_THROW_ON_ERROR),
        ]);
        $pdo->commit();it113_store_diagnostic('saved');return true;
    } catch(Throwable $e) {
        if($pdo->inTransaction())$pdo->rollBack();
        it113_store_diagnostic('database_write_failed');it113_store_log_error('write',$e);return false;
    }
}

function it113_store_history(): ?array {
    $pdo=it113_store_db();$scope=$pdo?it113_pair_scope(true):null;
    if (!$pdo || !$scope) return null;
    try {
        $where=$scope['workspace_id']!==null ? 'workspace_id = ?' : 'session_digest = ? AND workspace_id IS NULL';
        $guard=$scope['workspace_id']!==null ? ' AND EXISTS (SELECT 1 FROM public.it113_pair_members m
            WHERE m.workspace_id=? AND m.session_digest=?)' : '';
        $stmt=$pdo->prepare('SELECT trace_id,source_type,sample_id,expected_label,classification,confidence,
           anomaly_score,rule_score,risk_score,severity,model_version,indicators,status,revision,
           created_at,updated_at
           FROM public.it113_demo_assessments WHERE '.$where.$guard.' ORDER BY created_at DESC LIMIT 80');
        $params=[$scope['workspace_id']??$scope['sid']];
        if ($scope['workspace_id']!==null) array_push($params,$scope['workspace_id'],$scope['sid']);
        $stmt->execute($params);
        $entries=[];
        foreach ($stmt->fetchAll() as $row) {
            $entries[] = [
                'trace_id'=>$row['trace_id'],'source_type'=>$row['source_type'],
                'sample_id'=>$row['sample_id'] ?: 'NUMERIC_CSV',
                'expected_label'=>$row['expected_label'],'classification'=>$row['classification'],
                'confidence'=>(float)$row['confidence'],'anomaly_score'=>(float)$row['anomaly_score'],
                'rule_score'=>(float)$row['rule_score'],'risk_score'=>(float)$row['risk_score'],
                'severity'=>$row['severity'],'model_version'=>$row['model_version'],
                'indicator_evidence'=>json_decode($row['indicators'],true) ?: [],
                'status'=>$row['status'],'revision'=>(int)$row['revision'],
                'at'=>$row['created_at'],'updated_at'=>$row['updated_at'],
                'synthetic'=>true,'database_written'=>true,
            ];
        }
        it113_store_diagnostic('ready');return $entries;
    } catch(Throwable $e) {
        it113_store_diagnostic('database_read_failed');it113_store_log_error('history read',$e);return null;
    }
}

function it113_store_status(string $trace, string $status, string $note, int $revision): string {
    $allowed=['OPEN','INVESTIGATING','MITIGATED','RESOLVED'];
    if (!in_array($status,$allowed,true) || strlen($note)>240 || $revision<0 || $revision>15
        || !preg_match('/^[a-f0-9]{32}$/D',$trace)) return 'invalid';
    $pdo=it113_store_db();$scope=$pdo?it113_pair_scope(false):null;
    if (!$pdo || !$scope) return 'unavailable';
    $where=$scope['workspace_id']!==null ? 'workspace_id = ?' : 'session_digest = ? AND workspace_id IS NULL';
    $scopeValue=$scope['workspace_id']??$scope['sid'];
    try {
        $pdo->beginTransaction();
        if ($scope['workspace_id']!==null) {
            $auth=$pdo->prepare('SELECT 1 FROM public.it113_pair_members
                WHERE workspace_id=? AND session_digest=? FOR SHARE');
            $auth->execute([$scope['workspace_id'],$scope['sid']]);
            if (!$auth->fetchColumn()) { $pdo->rollBack();return 'conflict'; }
        }
        $lookup=$pdo->prepare('SELECT status,revision,classification FROM public.it113_demo_assessments
          WHERE trace_id=? AND '.$where.' FOR UPDATE');
        $lookup->execute([$trace,$scopeValue]);
        $current=$lookup->fetch(PDO::FETCH_ASSOC);
        if (!$current || $current['classification']==='NORMAL' || (int)$current['revision']!==$revision) {
            $pdo->rollBack();return 'conflict';
        }
        $transitions=[
          'OPEN'=>['OPEN','INVESTIGATING'],
          'INVESTIGATING'=>['INVESTIGATING','MITIGATED','OPEN'],
          'MITIGATED'=>['MITIGATED','RESOLVED','INVESTIGATING'],
          'RESOLVED'=>['RESOLVED','OPEN'],
        ];
        if (!in_array($status,$transitions[$current['status']]??[],true)) {
            $pdo->rollBack();return 'invalid';
        }
        $stmt=$pdo->prepare('UPDATE public.it113_demo_assessments
           SET status=?,revision=revision+1,updated_at=NOW()
           WHERE trace_id=? AND '.$where.' AND revision=? AND revision<15 RETURNING status');
        $stmt->execute([$status,$trace,$scopeValue,$revision]);
        if (!$stmt->fetchColumn()) { $pdo->rollBack(); return 'conflict'; }
        $stmt=$pdo->prepare('INSERT INTO public.it113_demo_case_events (trace_id,session_digest,revision,status,note)
         VALUES(?,?,?,?,?)');
        // Attribution is deliberately anonymous; this session digest is used
        // only for security scoping and is never returned to the browser.
        $stmt->execute([$trace,$scope['sid'],$revision+1,$status,$note]);
        $pdo->commit();return 'updated';
    } catch(Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        it113_store_diagnostic('database_update_failed');it113_store_log_error('case update',$e);return 'unavailable';
    }
}

function it113_store_events(string $trace): ?array {
    if (!preg_match('/^[a-f0-9]{32}$/D',$trace)) return [];
    $pdo=it113_store_db();$scope=$pdo?it113_pair_scope(false):null;
    if (!$pdo || !$scope) return null;
    $where=$scope['workspace_id']!==null ? 'a.workspace_id = ?' : 'a.session_digest = ? AND a.workspace_id IS NULL';
    try {
        $guard=$scope['workspace_id']!==null ? ' AND EXISTS (SELECT 1 FROM public.it113_pair_members m
            WHERE m.workspace_id=? AND m.session_digest=?)' : '';
        $stmt=$pdo->prepare('SELECT e.revision,e.status,e.note,e.changed_at
          FROM public.it113_demo_case_events e
          JOIN public.it113_demo_assessments a ON a.trace_id=e.trace_id
          WHERE e.trace_id=? AND '.$where.$guard.' ORDER BY e.revision ASC LIMIT 15');
        $params=[$trace,$scope['workspace_id']??$scope['sid']];
        if ($scope['workspace_id']!==null) array_push($params,$scope['workspace_id'],$scope['sid']);
        $stmt->execute($params);return $stmt->fetchAll();
    } catch(Throwable $e) {it113_store_log_error('events read',$e);return null;}
}

function it113_store_clear(): bool {
    $pdo=it113_store_db();$scope=$pdo?it113_pair_scope(false):null;
    if (!$pdo || !$scope) return false;
    // Never allow a partner to wipe the entire shared team's findings.
    if ($scope['workspace_id']!==null) {it113_store_diagnostic('shared_clear_blocked');return false;}
    try {
        $stmt=$pdo->prepare('DELETE FROM public.it113_demo_assessments
            WHERE session_digest = ? AND workspace_id IS NULL');
        return $stmt->execute([$scope['sid']]);
    } catch(Throwable $e) {it113_store_log_error('private clear',$e);return false;}
}
