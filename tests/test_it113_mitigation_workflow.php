<?php

declare(strict_types=1);

// Standalone offline integration tests. Real PostgreSQL and admin sessions are
// deliberately not required; those are tested after Supabase is restored.
require_once dirname(__DIR__) . '/src/it113_mitigation_workflow.php';

function fortress_ml_prediction_fingerprint(array $record): string
{
    return hash('sha256', json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

function confirm(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException('FAIL: ' . $message);
}

$dir = sys_get_temp_dir() . '/fortress-it113-mitigation-test-' . bin2hex(random_bytes(8));
mkdir($dir, 0700, true);
putenv('FORTRESS_MITIGATION_STORE_PATH=' . $dir . '/workflow.json');
$prediction = [
    'ts'=>1730000000, 'ip'=>'192.0.2.4',
    'result'=>['classification'=>'BRUTE_FORCE', 'severity'=>'HIGH','trace_id'=>'lab-trace','model_version'=>'model-v2'],
];
$caseId = fortress_it113_case_id($prediction);
$assertions = 0;
try {
    confirm(strlen($caseId) === 64 && ctype_xdigit($caseId), 'case fingerprint'); $assertions++;
    confirm(fortress_it113_workflow_backend(null) === 'local', 'offline fallback'); $assertions++;
    confirm(fortress_it113_workflow_get(null, $caseId) === null, 'missing case starts open'); $assertions++;
    confirm(fortress_it113_workflow_recent(null) === [], 'no manufactured cases'); $assertions++;
    confirm(fortress_it113_allowed_next('OPEN') === ['OPEN','INVESTIGATING'], 'transition map'); $assertions++;

    foreach (['NORMAL','MALWARE','UNKNOWN'] as $invalidClass) {
        $bad = $prediction;
        $bad['result']['classification'] = $invalidClass;
        try {
            fortress_it113_workflow_update(null, $bad, 'OPEN', 'Reviewed normal sample', 2, 0);
            throw new RuntimeException('Invalid class accepted: ' . $invalidClass);
        } catch (InvalidArgumentException $e) {
            confirm(str_contains($e->getMessage(), 'non-normal'), 'non-normal safeguard'); $assertions++;
        }
    }
    foreach ([['OPEN','','No note'], ['RESOLVED','Testing invalid transition','Invalid transition'], ['OPEN','short','Too short']] as $invalid) {
        try {
            fortress_it113_workflow_update(null, $prediction, $invalid[0], $invalid[1], 2, 0);
            throw new RuntimeException($invalid[2] . ' accepted');
        } catch (InvalidArgumentException $e) { $assertions++; }
    }
    $first = fortress_it113_workflow_update(null, $prediction, 'OPEN', 'Confirmed signals need investigation', 5, 0);
    confirm($first['revision'] === 1, 'initial note revision'); $assertions++;
    $case = fortress_it113_workflow_get(null, $caseId);
    confirm($case['status'] === 'OPEN' && count($case['history']) === 1, 'initial note persisted'); $assertions++;
    confirm($case['history'][0]['actor_uid'] === 5 && $case['history'][0]['note'] === 'Confirmed signals need investigation', 'note actor history'); $assertions++;
    // PHP's POSIX mode bits are not an NTFS ACL check on Windows. Verify
    // 0600 on POSIX; on Windows, verify the isolated store is created outside
    // public/ and readable by the test account, then audit ACLs separately.
    $storePath = $dir . '/workflow.json';
    if (PHP_OS_FAMILY === 'Windows') {
        $actualPath = realpath($storePath);
        $publicRoot = realpath(dirname(__DIR__) . '/public');
        $insideWebRoot = $actualPath !== false && $publicRoot !== false
            && str_starts_with(strtolower(str_replace('\\', '/', $actualPath)) . '/',
                rtrim(strtolower(str_replace('\\', '/', $publicRoot)), '/') . '/');
        confirm($actualPath !== false && is_file($storePath) && is_readable($storePath) && !$insideWebRoot,
            'Windows test store created outside public web root');
        fwrite(STDERR, "INFO: Windows NTFS permissions require a separate icacls check; PHP fileperms() cannot validate ACLs.\n");
    } else {
        confirm(is_file($storePath) && (fileperms($storePath) & 0777) === 0600,
            'private POSIX file permissions (0600)');
    }
    $assertions++;

    try {
        fortress_it113_workflow_update(null, $prediction, 'INVESTIGATING', 'Conflicting analyst update', 6, 0);
        throw new RuntimeException('Stale revision was accepted');
    } catch (InvalidArgumentException $e) { $assertions++; }
    confirm(count(fortress_it113_workflow_get(null, $caseId)['history']) === 1, 'stale update did not append'); $assertions++;

    $rev = 1;
    foreach (['INVESTIGATING','MITIGATED','RESOLVED','OPEN'] as $next) {
        $updated = fortress_it113_workflow_update(null, $prediction, $next, 'Validated remediation in controlled exercise', 5, $rev);
        $rev++;
        confirm($updated['revision'] === $rev && $updated['status'] === $next, 'valid state transition ' . $next); $assertions++;
    }
    $saved = fortress_it113_workflow_get(null, $caseId);
    confirm($saved['revision'] === 5 && count($saved['history']) === 5, 'complete history persisted'); $assertions++;
    confirm(count(fortress_it113_workflow_get_many(null, [$caseId, $caseId])) === 1, 'read many does not duplicate'); $assertions++;
    confirm(count(fortress_it113_workflow_recent(null)) === 1, 'recent case persists'); $assertions++;

    $raw = json_decode(file_get_contents($dir . '/workflow.json'), true);
    confirm($raw['cases'][$caseId]['status'] === 'OPEN', 'disk state survives calls'); $assertions++;
    file_put_contents($dir . '/workflow.json', '{malformed-json');
    try {
        fortress_it113_workflow_update(null, $prediction, 'INVESTIGATING', 'Preserve malformed storage without reset', 5, 5);
        throw new RuntimeException('Corrupt store overwritten');
    } catch (RuntimeException $e) {
        confirm(str_contains($e->getMessage(), 'malformed'), 'corrupted local store fails closed'); $assertions++;
    }
    confirm(file_get_contents($dir . '/workflow.json') === '{malformed-json', 'corrupted content preserved'); $assertions++;
    echo "PASS: {$assertions} offline workflow assertions (state, authorization input, stale writes, persistence, audit history)\n";
} finally {
    foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
    @rmdir($dir);
    putenv('FORTRESS_MITIGATION_STORE_PATH');
}
