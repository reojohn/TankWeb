<?php
/**
 * Isolated, anonymous IT113 academic assessment store.
 * Never reads or modifies legacy security tables, accounts, or raw logs.
 * Database persistence is opt-in and scoped to a cryptographically random
 * HttpOnly/SameSite cookie; public API roles have no database permissions.
 */
declare(strict_types=1);

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
    if (!$pdo) return false;
    $sid = it113_store_session(true);
    if (!$sid) { it113_store_diagnostic('session_unavailable'); return false; }
    try {
        $pdo->beginTransaction();
        // Cap per-session durable records to prevent an anonymous client from
        // growing the table without bound (additional per-IP limits elsewhere).
        $stmt=$pdo->prepare('SELECT COUNT(*) FROM public.it113_demo_assessments WHERE session_digest = ?');
        $stmt->execute([$sid]);
        if ((int)$stmt->fetchColumn() >= 80) {
            $pdo->rollBack();
            it113_store_diagnostic('session_limit_reached');
            return false;
        }
        $stmt=$pdo->prepare('INSERT INTO public.it113_demo_assessments (
            session_digest, trace_id, source_type, sample_id, expected_label,
            classification, confidence, anomaly_score, rule_score, risk_score,
            severity, model_version, indicators
        ) VALUES (:sid,:trace,:source,:sample,:expected,:class,:confidence,:anomaly,:rule,:risk,:severity,:version,CAST(:indicators AS jsonb))');
        $stmt->execute([
            ':sid'=>$sid, ':trace'=>$safe['trace_id'], ':source'=>$safe['source_type'],
            ':sample'=>$safe['sample_id'] ?? null, ':expected'=>$safe['expected_label'] ?: null,
            ':class'=>$safe['classification'], ':confidence'=>$safe['confidence'],
            ':anomaly'=>$safe['anomaly_score'], ':rule'=>$safe['rule_score'],
            ':risk'=>$safe['risk_score'], ':severity'=>$safe['severity'],
            ':version'=>$safe['model_version'],
            ':indicators'=>json_encode($safe['indicator_evidence'], JSON_THROW_ON_ERROR),
        ]);
        $pdo->commit();
        it113_store_diagnostic('saved');
        return true;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        it113_store_diagnostic('database_write_failed');
        it113_store_log_error('write', $e);
        return false;
    }
}

function it113_store_history(): ?array {
    $pdo=it113_store_db();
    if (!$pdo) return null;
    $sid=it113_store_session(true);
    if (!$sid) { it113_store_diagnostic('session_unavailable'); return null; }
    try {
        $stmt=$pdo->prepare('SELECT trace_id,source_type,sample_id,expected_label,classification,confidence,
           anomaly_score,rule_score,risk_score,severity,model_version,indicators,status,revision,
           created_at,updated_at
           FROM public.it113_demo_assessments WHERE session_digest = ? ORDER BY created_at DESC LIMIT 80');
        $stmt->execute([$sid]);
        $entries=[];
        foreach ($stmt->fetchAll() as $row) {
            $entries[] = [
                'trace_id'=>$row['trace_id'], 'source_type'=>$row['source_type'],
                'sample_id'=>$row['sample_id'] ?: 'NUMERIC_CSV',
                'expected_label'=>$row['expected_label'], 'classification'=>$row['classification'],
                'confidence'=>(float)$row['confidence'], 'anomaly_score'=>(float)$row['anomaly_score'],
                'rule_score'=>(float)$row['rule_score'], 'risk_score'=>(float)$row['risk_score'],
                'severity'=>$row['severity'], 'model_version'=>$row['model_version'],
                'indicator_evidence'=>json_decode($row['indicators'],true) ?: [],
                'status'=>$row['status'], 'revision'=>(int)$row['revision'],
                'at'=>$row['created_at'], 'updated_at'=>$row['updated_at'],
                'synthetic'=>true, 'database_written'=>true,
            ];
        }
        it113_store_diagnostic('ready');
        return $entries;
    } catch (Throwable $e) {
        it113_store_diagnostic('database_read_failed');
        it113_store_log_error('history read', $e);
        return null;
    }
}

function it113_store_status(string $trace, string $status, string $note, int $revision): string {
    $allowed=['OPEN','INVESTIGATING','MITIGATED','RESOLVED'];
    if (!in_array($status,$allowed,true) || strlen($note)>240 || $revision<0 || $revision>15
        || !preg_match('/^[a-f0-9]{32}$/D',$trace)) return 'invalid';
    $pdo=it113_store_db();
    if (!$pdo) return 'unavailable';
    $sid=it113_store_session(false);
    if (!$sid) return 'not_found';
    try {
        $pdo->beginTransaction();
        $lookup=$pdo->prepare('SELECT status,revision,classification FROM public.it113_demo_assessments
          WHERE trace_id=? AND session_digest=? FOR UPDATE');
        $lookup->execute([$trace,$sid]);
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
           WHERE trace_id=? AND session_digest=? AND revision=? AND revision<15 RETURNING status');
        $stmt->execute([$status,$trace,$sid,$revision]);
        if (!$stmt->fetchColumn()) { $pdo->rollBack(); return 'conflict'; }
        $stmt=$pdo->prepare('INSERT INTO public.it113_demo_case_events (trace_id,session_digest,revision,status,note)
         VALUES(?,?,?,?,?)');
        $stmt->execute([$trace,$sid,$revision+1,$status,$note]);
        $pdo->commit();
        return 'updated';
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        it113_store_diagnostic('database_update_failed');
        it113_store_log_error('case update', $e);
        return 'unavailable';
    }
}

function it113_store_events(string $trace): ?array {
    if (!preg_match('/^[a-f0-9]{32}$/D',$trace)) return [];
    $pdo=it113_store_db();$sid=it113_store_session(false);
    if (!$pdo || !$sid) return null;
    try {
        $stmt=$pdo->prepare('SELECT e.revision,e.status,e.note,e.changed_at
          FROM public.it113_demo_case_events e
          JOIN public.it113_demo_assessments a ON a.trace_id=e.trace_id
          AND a.session_digest=e.session_digest
          WHERE e.trace_id=? AND e.session_digest=? ORDER BY e.revision ASC LIMIT 15');
        $stmt->execute([$trace,$sid]);return $stmt->fetchAll();
    } catch(Throwable $e) { return null; }
}

function it113_store_clear(): bool {
    $pdo=it113_store_db(); $sid=it113_store_session(false);
    if (!$pdo || !$sid) return false;
    try {
        $stmt=$pdo->prepare('DELETE FROM public.it113_demo_assessments WHERE session_digest = ?');
        return $stmt->execute([$sid]);
    } catch (Throwable $e) { return false; }
}
