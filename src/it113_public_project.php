<?php
/**
 * Read-only, publicly published synthetic IT113 research findings.
 * The project owner pins ONE pair workspace using a server-side UUID setting.
 * No session cookie, browser identity, invitation, DB credentials or analyst
 * notes are ever returned to anonymous viewers. No write methods here.
 */
declare(strict_types=1);

function it113_public_project_configured(): bool {
    return filter_var(getenv('IT113_PUBLIC_PROJECT_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL)
        && filter_var(getenv('IT113_PAIR_WORKSPACE_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL)
        && it113_store_enabled()
        && preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/Di',
            (string)(getenv('IT113_PUBLIC_PROJECT_WORKSPACE_ID') ?: '')) === 1;
}

/** A safe, bounded output built from allowlisted SQL columns only. */
function it113_public_project_entry(array $row): array {
    $indicators = json_decode((string)($row['indicators'] ?? '[]'), true);
    if (!is_array($indicators)) $indicators = [];
    $clean=[];
    foreach (array_slice($indicators, 0, 6) as $item) {
        if (!is_array($item) || !is_string($item['description'] ?? null) ||
            !is_numeric($item['observed'] ?? null)) continue;
        $value=(float)$item['observed'];
        if (!is_finite($value)) continue;
        $clean[]=['description'=>substr(strip_tags($item['description']),0,110),
            'observed'=>$value];
    }
    return [
        'trace_id'=>(string)$row['trace_id'],
        'at'=>(string)$row['created_at'],
        'source_type'=>(string)$row['source_type'],
        'sample_id'=>(string)($row['sample_id'] ?: 'NUMERIC_CSV'),
        'expected_label'=>$row['expected_label'],
        'classification'=>(string)$row['classification'],
        'confidence'=>(float)$row['confidence'],
        'anomaly_score'=>(float)$row['anomaly_score'],
        'rule_score'=>(float)$row['rule_score'],
        'risk_score'=>(float)$row['risk_score'],
        'severity'=>(string)$row['severity'],
        'model_version'=>(string)$row['model_version'],
        'indicator_evidence'=>$clean,
        'status'=>(string)$row['status'],
        'revision'=>(int)$row['revision'],
        'synthetic'=>true,
        'database_written'=>true,
        'public_read_only'=>true,
    ];
}

/** Returns null on backend error; never falls back to private visitor records. */
function it113_public_project_history(): ?array {
    if (!it113_public_project_configured()) return [];
    $pdo = it113_store_db();
    if (!$pdo) return null;
    try {
        // The pinned project is chosen only through the Render server config.
        // Never accept a client-provided workspace ID or switch workspaces by URL.
        $stmt=$pdo->prepare('SELECT a.trace_id,a.created_at,a.source_type,a.sample_id,a.expected_label,
            a.classification,a.confidence,a.anomaly_score,a.rule_score,a.risk_score,a.severity,
            a.model_version,a.indicators,a.status,a.revision
            FROM public.it113_demo_assessments a
            INNER JOIN public.it113_pair_workspaces w ON a.workspace_id=w.workspace_id
            WHERE a.workspace_id=CAST(? AS uuid) ORDER BY a.created_at DESC LIMIT 80');
        $stmt->execute([(string)getenv('IT113_PUBLIC_PROJECT_WORKSPACE_ID')]);
        return array_map('it113_public_project_entry', $stmt->fetchAll(PDO::FETCH_ASSOC));
    } catch (Throwable $e) {
        it113_store_log_error('public project read', $e);
        return null;
    }
}
