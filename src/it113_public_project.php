<?php
/**
 * Read-only, publicly published synthetic IT113 research findings.
 * Curated synthetic XGBoost assessments saved in the academic database are
 * publicly visible without login, invitations, project IDs or per-browser
 * session cookies. Numeric CSV uploads remain private to their submitter.
 * No session identity, raw features, invitations or analyst notes are exposed.
 */
declare(strict_types=1);

function it113_public_project_configured(): bool {
    // No additional workspace or publication switch: the deployed, already
    // enabled academic PostgreSQL persistence is the public project source.
    return it113_store_enabled();
}

/** Only sample IDs from the shipped, controlled held-out evidence may publish. */
function it113_public_curated_labels(): array {
    $path = __DIR__ . '/../public/assessment/evidence.json';
    $data = json_decode((string)@file_get_contents($path), true);
    if (!is_array($data) || ($data['not_live_inference'] ?? null) !== true
        || ($data['contains_real_personal_data'] ?? null) !== false
        || !is_array($data['examples'] ?? null)) return [];
    $labels = [];
    foreach ($data['examples'] as $example) {
        $id = $example['id'] ?? null;
        $label = $example['true_label'] ?? null;
        if (is_string($id) && preg_match('/^[a-z0-9_]{3,60}$/D', $id)
            && is_string($label) && preg_match('/^[A-Z_]{3,48}$/D', $label)) {
            $labels[$id] = $label;
        }
    }
    return $labels;
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

/** Returns null on backend errors. Never falls back to arbitrary session data. */
function it113_public_project_history(): ?array {
    if (!it113_public_project_configured()) return [];
    $labels = it113_public_curated_labels();
    if (!$labels) return null; // Fail closed if evidence provenance is missing.
    $pdo = it113_store_db();
    if (!$pdo) return null;
    try {
        // Only curated model runs are public. They are strictly selected by the
        // server from evidence.json, not client-provided IDs or free-form CSV.
        // Existing curated findings become public automatically after deploy.
        $stmt = $pdo->prepare("SELECT a.trace_id,a.created_at,a.source_type,a.sample_id,a.expected_label,
            a.classification,a.confidence,a.anomaly_score,a.rule_score,a.risk_score,a.severity,
            a.model_version,a.indicators,a.status,a.revision
            FROM public.it113_demo_assessments a
            WHERE a.source_type = 'curated' AND a.sample_id IS NOT NULL
              AND a.expected_label IS NOT NULL
            ORDER BY a.created_at DESC LIMIT 200");
        $stmt->execute();
        $entries = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $sampleId = (string)$row['sample_id'];
            // Safe synthetic provenance: never publish anything whose ID or
            // ground truth differs from the known, packaged sample catalog.
            if (!isset($labels[$sampleId]) || $labels[$sampleId] !== (string)$row['expected_label']) continue;
            $entries[] = it113_public_project_entry($row);
            if (count($entries) === 80) break;
        }
        return $entries;
    } catch (Throwable $e) {
        it113_store_log_error('public project read', $e);
        return null;
    }
}
