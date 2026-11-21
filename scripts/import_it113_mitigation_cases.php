<?php

declare(strict_types=1);

/**
 * One-way, operator-controlled import of local analyst cases to PostgreSQL.
 * Dry-run by default. Apply ONLY after Supabase has finished restoration and
 * sql/ml_mitigation_workflow.sql has been installed.
 *
 *   php scripts/import_it113_mitigation_cases.php
 *   php scripts/import_it113_mitigation_cases.php --apply
 *
 * Never run via the web server; imports keep existing DB cases untouched.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Not found');
}

require_once dirname(__DIR__) . '/src/it113_mitigation_workflow.php';
$apply = in_array('--apply', $argv, true);
if (count(array_diff(array_slice($argv, 1), ['--apply'])) > 0) {
    fwrite(STDERR, "Usage: php scripts/import_it113_mitigation_cases.php [--apply]\n");
    exit(2);
}

try {
    $storedCases = fortress_it113_workflow_with_file_lock(static function (array &$state): array {
        return [$state['cases'], false];
    });
    $eligible = array_filter($storedCases, static fn($case, $id): bool =>
        is_array($case) && is_string($id) && preg_match('/^[a-f0-9]{64}$/', $id) === 1,
        ARRAY_FILTER_USE_BOTH);
    printf("Local mitigation cases: %d\nEligible for import: %d\nMode: %s\n", count($storedCases), count($eligible), $apply ? 'APPLY' : 'DRY RUN');
    if (!$apply) {
        echo "No database connection or change was made. Pass --apply only after the SQL migration is installed.\n";
        exit(0);
    }

    require_once dirname(__DIR__) . '/src/config.php'; // Makes the configured PDO connection.
    if (fortress_it113_workflow_backend($pdo) !== 'postgresql') {
        throw new RuntimeException('Required mitigation tables are not available. Apply the migration first.');
    }
    $imported = 0;
    $skipped = 0;
    foreach ($eligible as $caseId => $case) {
        $revision = (int)($case['revision'] ?? 0);
        $status = (string)($case['status'] ?? 'OPEN');
        if (!in_array($status, fortress_it113_statuses(), true) || $revision < 1) {
            $skipped++;
            continue;
        }
        $history = is_array($case['history'] ?? null) ? $case['history'] : [];
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare('INSERT INTO public.ml_mitigation_cases (case_id, classification, severity, trace_id, model_version, status, revision, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (case_id) DO NOTHING');
            $stmt->execute([
                $caseId,
                substr((string)($case['classification'] ?? 'UNKNOWN'), 0, 48),
                substr((string)($case['severity'] ?? 'UNKNOWN'), 0, 12),
                substr((string)($case['trace_id'] ?? ''), 0, 80),
                substr((string)($case['model_version'] ?? ''), 0, 80),
                $status, $revision, (int)($case['updated_by'] ?? 0),
                (string)($case['updated_at'] ?? gmdate('c')),
            ]);
            if ($stmt->rowCount() === 0) {
                // Never overwrite a DB case that another administrator updated.
                $pdo->rollBack();
                $skipped++;
                continue;
            }
            $event = $pdo->prepare('INSERT INTO public.ml_mitigation_events (case_id, revision, old_status, new_status, note, actor_uid, changed_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (case_id, revision) DO NOTHING');
            // File history is newest first. For histories longer than the local
            // bounded retention window, preserve the retained true revisions.
            foreach (array_reverse($history) as $index => $row) {
                $historyRevision = max(1, $revision - count($history) + $index + 1);
                $event->execute([
                    $caseId, $historyRevision,
                    substr((string)($row['from'] ?? 'OPEN'),0,16),
                    substr((string)($row['to'] ?? 'OPEN'),0,16),
                    substr((string)($row['note'] ?? 'Legacy analyst note'),0,500),
                    (int)($row['actor_uid'] ?? 0),
                    (string)($row['at'] ?? gmdate('c')),
                ]);
            }
            $pdo->commit();
            $imported++;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw $e;
        }
    }
    printf("Imported: %d\nSkipped (existing/invalid): %d\n", $imported, $skipped);
    echo "Review cases in the protected Threat Center. Keep a backup of the original local file.\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'Import failed safely: ' . $e->getMessage() . "\n");
    exit(1);
}
