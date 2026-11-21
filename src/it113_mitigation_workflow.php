<?php

declare(strict_types=1);

/**
 * IT113 analyst mitigation case notes. An analyst's status is separate from an
 * ML inference/enforcement outcome, and updating it never bans an IP.
 *
 * PostgreSQL is authoritative when both optional migration tables exist.
 * A locked JSON store outside public/ supports offline, single-host practice.
 * Do not treat that local store as durable on ephemeral/cloud instances.
 */

function fortress_it113_statuses(): array
{
    return ['OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED'];
}

function fortress_it113_allowed_next(string $current): array
{
    return match ($current) {
        'OPEN' => ['OPEN', 'INVESTIGATING'],
        'INVESTIGATING' => ['INVESTIGATING', 'MITIGATED', 'OPEN'],
        'MITIGATED' => ['MITIGATED', 'RESOLVED', 'INVESTIGATING'],
        'RESOLVED' => ['RESOLVED', 'OPEN'],
        default => [],
    };
}

/** Stable key for exactly the saved ML record, never a user-supplied case ID. */
function fortress_it113_case_id(array $prediction): string
{
    $sourceId = (string)($prediction['_it113_record_fingerprint'] ?? '');
    return preg_match('/^[a-f0-9]{64}$/', $sourceId) === 1
        ? $sourceId : fortress_ml_prediction_fingerprint($prediction);
}

function fortress_it113_workflow_meta(array $prediction): array
{
    $result = is_array($prediction['result'] ?? null) ? $prediction['result'] : [];
    $class = strtoupper(trim((string)($result['classification'] ?? 'UNKNOWN')));
    if (!in_array($class, ['BRUTE_FORCE','CREDENTIAL_STUFFING','RECONNAISSANCE','WEB_ATTACK','MFA_ABUSE','SESSION_ABUSE'], true)) {
        throw new InvalidArgumentException('Only saved, non-normal, recognized ML assessments can become mitigation cases.');
    }
    return [
        'case_id' => fortress_it113_case_id($prediction),
        'classification' => $class,
        'severity' => substr(strtoupper((string)($result['severity'] ?? 'UNKNOWN')), 0, 12),
        'trace_id' => substr((string)($result['trace_id'] ?? ''), 0, 80),
        'model_version' => substr((string)($result['model_version'] ?? ''), 0, 80),
        'observed_at' => max(0, (int)($prediction['ts'] ?? 0)),
    ];
}

function fortress_it113_workflow_local_path(): string
{
    $override = getenv('FORTRESS_MITIGATION_STORE_PATH');
    return $override !== false && trim($override) !== ''
        ? trim($override)
        : dirname(__DIR__) . '/data/it113_mitigation_cases.json';
}

/** Never automatically migrate records or silently switch on a failed DB query. */
function fortress_it113_workflow_backend(?PDO $pdo = null): string
{
    if ($pdo === null) return 'local';
    try {
        $stmt = $pdo->query("SELECT to_regclass('public.ml_mitigation_cases') AS cases_table, to_regclass('public.ml_mitigation_events') AS events_table");
        $tables = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : false;
        return !empty($tables['cases_table']) && !empty($tables['events_table']) ? 'postgresql' : 'local';
    } catch (Throwable $e) {
        error_log('FortressAuth mitigation backend availability check failed: ' . get_class($e));
        return 'unavailable';
    }
}

/** Local records are immutable-snapshot writes protected by an adjacent lock file. */
function fortress_it113_workflow_with_file_lock(callable $operation): mixed
{
    $path = fortress_it113_workflow_local_path();
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('Local mitigation storage directory cannot be created.');
    }
    if (is_link($path) || is_link($path . '.lock')) {
        throw new RuntimeException('Mitigation storage cannot be a symbolic link.');
    }
    $lock = @fopen($path . '.lock', 'c+b');
    if ($lock === false) throw new RuntimeException('Local mitigation storage lock unavailable.');
    @chmod($path . '.lock', 0600);
    try {
        if (!flock($lock, LOCK_EX)) throw new RuntimeException('Unable to lock mitigation storage.');
        $state = ['cases' => []];
        if (is_file($path)) {
            $content = file_get_contents($path);
            if (!is_string($content)) throw new RuntimeException('Unable to read saved mitigation data.');
            $decoded = json_decode($content, true);
            if (!is_array($decoded) || !is_array($decoded['cases'] ?? null)) {
                throw new RuntimeException('Mitigation storage is malformed; refusing to overwrite its contents.');
            }
            $state = $decoded;
        }
        [$response, $write] = $operation($state);
        if ($write) {
            if (count($state['cases']) > 3000) throw new RuntimeException('Mitigation case limit reached; archive records before continuing.');
            $encoded = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            $tmp = tempnam($dir, '.it113-case-');
            if ($tmp === false) throw new RuntimeException('Unable to create a temporary mitigation file.');
            try {
                @chmod($tmp, 0600);
                if (file_put_contents($tmp, $encoded, LOCK_EX) === false || !rename($tmp, $path)) {
                    throw new RuntimeException('Unable to atomically save mitigation data.');
                }
                @chmod($path, 0600);
            } finally {
                if (is_file($tmp)) @unlink($tmp);
            }
        }
        return $response;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function fortress_it113_workflow_get(?PDO $pdo, string $caseId, ?string $backend = null): ?array
{
    if (preg_match('/^[a-f0-9]{64}$/', $caseId) !== 1) return null;
    $backend ??= fortress_it113_workflow_backend($pdo);
    if ($backend === 'unavailable') throw new RuntimeException('Mitigation backend cannot be verified. No fallback writes will be attempted.');
    if ($backend === 'postgresql') {
        if ($pdo === null) throw new RuntimeException('PostgreSQL mitigation storage unavailable.');
        $stmt = $pdo->prepare('SELECT case_id, classification, severity, trace_id, model_version, status, revision, updated_by, updated_at FROM public.ml_mitigation_cases WHERE case_id = ?');
        $stmt->execute([$caseId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;
        $history = $pdo->prepare('SELECT old_status, new_status, note, actor_uid, changed_at FROM public.ml_mitigation_events WHERE case_id = ? ORDER BY revision DESC LIMIT 12');
        $history->execute([$caseId]);
        $row['history'] = array_map(static fn(array $e): array => [
            'from' => (string)$e['old_status'], 'to' => (string)$e['new_status'],
            'note' => (string)$e['note'], 'actor_uid' => (int)$e['actor_uid'],
            'at' => (string)$e['changed_at'],
        ], $history->fetchAll(PDO::FETCH_ASSOC) ?: []);
        return $row;
    }
    return fortress_it113_workflow_with_file_lock(static function (array &$state) use ($caseId): array {
        return [$state['cases'][$caseId] ?? null, false];
    });
}

/** Return cases for the visible predictions without leaking private notes publicly. */
function fortress_it113_workflow_recent(?PDO $pdo, int $limit = 20, ?string $backend = null): array
{
    $limit = max(1, min(50, $limit));
    $backend ??= fortress_it113_workflow_backend($pdo);
    if ($backend === 'unavailable') throw new RuntimeException('Mitigation backend cannot be verified. No fallback writes will be attempted.');
    if ($backend === 'postgresql') {
        if ($pdo === null) throw new RuntimeException('PostgreSQL mitigation storage unavailable.');
        $stmt = $pdo->prepare('SELECT case_id, classification, severity, trace_id, model_version, status, revision, updated_at, updated_by FROM public.ml_mitigation_cases ORDER BY updated_at DESC LIMIT :row_limit');
        $stmt->bindValue(':row_limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    }
    return fortress_it113_workflow_with_file_lock(static function (array &$state) use ($limit): array {
        $cases = array_values($state['cases']);
        usort($cases, static fn(array $a, array $b): int => strcmp((string)($b['updated_at'] ?? ''), (string)($a['updated_at'] ?? '')));
        return [array_slice($cases, 0, $limit), false];
    });
}

function fortress_it113_workflow_get_many(?PDO $pdo, array $ids, ?string $backend = null): array
{
    $result = [];
    $backend ??= fortress_it113_workflow_backend($pdo);
    if ($backend === 'unavailable') throw new RuntimeException('Mitigation storage not available.');
    foreach (array_slice(array_values(array_unique($ids)), 0, 35) as $id) {
        if (!is_string($id) || preg_match('/^[a-f0-9]{64}$/', $id) !== 1) continue;
        $case = fortress_it113_workflow_get($pdo, $id, $backend);
        if ($case !== null) $result[$id] = $case;
    }
    return $result;
}

/** Validates and returns an actionable transition; request authorization is done by the caller. */
function fortress_it113_workflow_validate(string $current, string $next, string $note, int $actor, int $expectedRevision): string
{
    if ($actor <= 0) throw new InvalidArgumentException('An authenticated administrator is required.');
    if ($expectedRevision < 0) throw new InvalidArgumentException('Invalid case revision.');
    if (!in_array($next, fortress_it113_allowed_next($current), true)) {
        throw new InvalidArgumentException('That status transition is not permitted. Review the current case state.');
    }
    $note = trim(preg_replace('/\s+/u', ' ', $note) ?? '');
    if (strlen($note) < 8 || strlen($note) > 500 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $note)) {
        throw new InvalidArgumentException('Provide an analyst note between 8 and 500 bytes. Avoid passwords, tokens and personal data.');
    }
    return $note;
}

/**
 * @throws InvalidArgumentException on invalid action or stale form.
 * @throws RuntimeException on storage failure.
 */
function fortress_it113_workflow_update(?PDO $pdo, array $prediction, string $next, string $note, int $actor, int $expectedRevision, ?string $backend = null): array
{
    $meta = fortress_it113_workflow_meta($prediction);
    $caseId = $meta['case_id'];
    $backend ??= fortress_it113_workflow_backend($pdo);
    if ($backend === 'unavailable') throw new RuntimeException('Mitigation backend cannot be verified. No fallback writes will be attempted.');
    if ($backend === 'postgresql') {
        if ($pdo === null) throw new RuntimeException('PostgreSQL mitigation storage unavailable.');
        $pdo->beginTransaction();
        try {
            $insert = $pdo->prepare("INSERT INTO public.ml_mitigation_cases (case_id, classification, severity, trace_id, model_version, status, revision) VALUES (?, ?, ?, ?, ?, 'OPEN', 0) ON CONFLICT (case_id) DO NOTHING");
            $insert->execute([$caseId, $meta['classification'], $meta['severity'], $meta['trace_id'], $meta['model_version']]);
            $lock = $pdo->prepare('SELECT status, revision FROM public.ml_mitigation_cases WHERE case_id = ? FOR UPDATE');
            $lock->execute([$caseId]);
            $old = $lock->fetch(PDO::FETCH_ASSOC);
            if (!$old) throw new RuntimeException('Mitigation case missing after creation.');
            $revision = (int)$old['revision'];
            if ($revision !== $expectedRevision) throw new InvalidArgumentException('This case was updated elsewhere. Refresh and try again.');
            $current = (string)$old['status'];
            $note = fortress_it113_workflow_validate($current, $next, $note, $actor, $expectedRevision);
            $up = $pdo->prepare('UPDATE public.ml_mitigation_cases SET status = ?, revision = revision + 1, updated_by = ?, updated_at = NOW() WHERE case_id = ?');
            $up->execute([$next, $actor, $caseId]);
            $event = $pdo->prepare('INSERT INTO public.ml_mitigation_events (case_id, revision, old_status, new_status, note, actor_uid) VALUES (?, ?, ?, ?, ?, ?)');
            $event->execute([$caseId, $revision + 1, $current, $next, $note, $actor]);
            $pdo->commit();
            return ['status' => $next, 'revision' => $revision + 1, 'backend' => $backend];
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw $e;
        }
    }
    return fortress_it113_workflow_with_file_lock(static function (array &$state) use ($meta, $caseId, $next, $note, $actor, $expectedRevision): array {
        $old = $state['cases'][$caseId] ?? null;
        $revision = (int)($old['revision'] ?? 0);
        if ($revision !== $expectedRevision) throw new InvalidArgumentException('This case was updated elsewhere. Refresh and try again.');
        $current = (string)($old['status'] ?? 'OPEN');
        $note = fortress_it113_workflow_validate($current, $next, $note, $actor, $expectedRevision);
        $history = is_array($old['history'] ?? null) ? $old['history'] : [];
        array_unshift($history, ['from'=>$current,'to'=>$next,'note'=>$note,'actor_uid'=>$actor,'at'=>gmdate('c')]);
        if (count($history) > 1000) throw new RuntimeException('Case history cap reached; archive the case before adding more events.');
        $state['cases'][$caseId] = array_merge($meta, [
            'status' => $next, 'revision' => $revision + 1,
            'updated_at' => gmdate('c'), 'updated_by' => $actor,
            'history' => $history,
        ]);
        return [['status'=>$next,'revision'=>$revision + 1,'backend'=>'local'], true];
    });
}
