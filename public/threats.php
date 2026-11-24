<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/fortress_metrics.php';
require_once __DIR__ . '/../src/ml_threat.php';
require_once __DIR__ . '/../src/it113_threat_guidance.php';
require_once __DIR__ . '/../src/it113_mitigation_workflow.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_admin_auth();

// React v3 fragment/live-refresh requests only read session state after auth.
// Release PHP's per-session lock before the heavier metrics/database work so
// /logout.php can revoke the session immediately instead of queuing behind it.
if (defined('FORTRESS_BACKGROUND_REQUEST') && FORTRESS_BACKGROUND_REQUEST === true) {
    fortress_release_session_read_lock();
}
$userId = (int)($_SESSION['uid'] ?? 0);
$it113CaseMessage = '';
$it113CaseMessageType = 'error';
$it113MitigationBackend = fortress_it113_workflow_backend($pdo);
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['it113_case_action'] ?? '') === 'update') {
    // Route remains behind require_admin_auth(). Verify CSRF before any write.
    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        http_response_code(419);
        $it113CaseMessage = 'Security verification failed. Refresh the page and submit again.';
    } else {
        try {
            $submittedCaseId = (string)($_POST['case_id'] ?? '');
            if (preg_match('/^[a-f0-9]{64}$/', $submittedCaseId) !== 1) {
                throw new InvalidArgumentException('Invalid case reference.');
            }
            // Check this fingerprint against genuine, saved ML history. The form
            // cannot manufacture a threat, edit source evidence or alter ML scores.
            $matched = null;
            foreach (fortress_ml_prediction_history(500) as $savedPrediction) {
                if (fortress_it113_case_id($savedPrediction) === $submittedCaseId) {
                    $matched = $savedPrediction;
                    break;
                }
            }
            if ($matched === null) throw new InvalidArgumentException('Saved prediction not found. Refresh the threat list.');
            $revisionText = (string)($_POST['expected_revision'] ?? '');
            if (!ctype_digit($revisionText) || strlen($revisionText) > 9) {
                throw new InvalidArgumentException('Invalid case revision.');
            }
            $updated = fortress_it113_workflow_update(
                $pdo, $matched, (string)($_POST['status'] ?? ''),
                (string)($_POST['analyst_note'] ?? ''), $userId,
                (int)$revisionText, $it113MitigationBackend
            );
            // Never log the note: it might contain sensitive analyst context.
            audit_log('it113_mitigation_case_updated uid=' . $userId
                . ' case=' . substr($submittedCaseId, 0, 16)
                . ' status=' . $updated['status'] . ' store=' . $updated['backend']);
            header('Location: /threats.php?it113_case=updated#it113-model-findings', true, 303);
            exit;
        } catch (InvalidArgumentException $e) {
            http_response_code(422);
            $it113CaseMessage = $e->getMessage();
        } catch (Throwable $e) {
            error_log('Aegis AI mitigation update failed: ' . get_class($e));
            http_response_code(503);
            $it113CaseMessage = 'Case update could not be saved. Existing case data was not intentionally changed. Please retry later.';
        }
    }
}
$ctx = fortress_build_security_context($pdo, $userId, ['include_all_time_threats' => true, 'include_top_threat_sources' => true]);
extract($ctx, EXTR_SKIP);
$activeNav = 'threats';

// Saved operational predictions only: read from the authorized ML history
// (PostgreSQL when available, otherwise the existing bounded local fallback).
// No inference call, test payload, write, or enforcement is performed here.
$it113PredictionHistory = array_map(static function (array $row): array {
    $summary = fortress_it113_prediction_summary($row);
    $summary['case_id'] = fortress_it113_case_id($row);
    return $summary;
}, fortress_ml_prediction_history(35));
$it113Cases = [];
$it113TrackedCases = [];
$it113CaseReadWarning = '';
try {
    $caseIds = array_column(array_slice($it113PredictionHistory, 0, 12), 'case_id');
    $it113Cases = fortress_it113_workflow_get_many($pdo, $caseIds, $it113MitigationBackend);
    $it113TrackedCases = fortress_it113_workflow_recent($pdo, 20, $it113MitigationBackend);
} catch (Throwable $e) {
    error_log('Aegis AI mitigation case lookup failed: ' . get_class($e));
    $it113CaseReadWarning = 'Saved case statuses are temporarily unavailable; no records were modified.';
}
$it113ThreatPredictions = array_values(array_filter(
    $it113PredictionHistory,
    static fn(array $row): bool => $row['class'] !== 'NORMAL' && $row['class'] !== 'UNKNOWN'
));
$it113HighRiskPredictions = count(array_filter(
    $it113PredictionHistory,
    static fn(array $row): bool => in_array($row['severity'], ['HIGH','CRITICAL'], true)
));
$it113LastModel = (string)($it113PredictionHistory[0]['model'] ?? 'Not available');
$it113EvidenceMode = fortress_ml_enabled() ? 'MODEL CONFIGURED' : 'MODEL NOT ENABLED';


$threatNeedles = ['automated_recon_blocked_source_attempt','automated_recon_block','automated_recon_detected','unsafe_redirect_blocked','ml_assisted_block','ml_assisted_strike','ml_threat_prediction','malicious_input_detected','shell_attack_detected','request_threat_detected','csp_violation_reported','scanner_user_agent_detected','sensitive_path_probe','reconnaissance_probe','csrf_validation_failed','http_method_blocked','http_method_anomaly','endpoint_method_rejected','oversized_request_detected','oversized_uri_detected','banned_ip_attempt','banned_ip_middleware_block','bruteforce_detected','ip_banned','school_id_qr_failed','school_id_qr_locked','school_id_qr_rate_limited','password_factor_failed','auth_rejected','honeypot_triggered'];
$dbThreatHistory = fortress_recent_security_event_lines($pdo, $threatNeedles, 120);
if (is_array($dbThreatHistory)) {
    $threatHistory = $dbThreatHistory;
} else {
    $threatHistory = array_values(array_filter($auditLines, static fn(string $line): bool => fortress_line_has_any($line, $threatNeedles)));
    $threatHistory = array_slice(array_reverse($threatHistory), 0, 120);
}

$allTime = is_array($threatCategoryAllTime ?? null) ? $threatCategoryAllTime : [];
$threatCategories = [
    ['fa-key', 'Password rejection', (int)($allTime['passwordRejection'] ?? 0), 'All-time first-factor failures'],
    ['fa-id-card', 'Personal ID rejection', (int)($allTime['personalIdRejection'] ?? 0), 'All-time possession-factor failures'],
    ['fa-database', 'SQL injection', (int)($allTime['sqlInjection'] ?? 0), 'Persistent SQL-pattern detections'],
    ['fa-code', 'XSS / traversal', (int)($allTime['xssTraversal'] ?? 0), 'Persistent input-pattern detections'],
    ['fa-terminal', 'Shell payload', (int)($allTime['shellPayload'] ?? 0), 'Persistent command-pattern detections'],
    ['fa-shield-halved', 'CSRF rejection', (int)($allTime['csrfRejection'] ?? 0), 'Persistent anti-CSRF rejections'],
    ['fa-shield', 'CSP violations', (int)($allTime['cspViolations'] ?? 0), 'Persistent browser CSP reports'],
    ['fa-magnifying-glass', 'Recon / 404 probes', (int)($allTime['reconProbes'] ?? 0), 'Persistent path-probe detections'],
    ['fa-robot', 'Scanner fingerprints', (int)($allTime['scannerFingerprints'] ?? 0), 'Persistent scanner-style user agents'],
    ['fa-code-branch', 'HTTP method abuse', (int)($allTime['httpMethodAbuse'] ?? 0), 'Persistent blocked/anomalous methods'],
    ['fa-file-circle-exclamation', 'Oversized requests', (int)($allTime['oversizedRequests'] ?? 0), 'Persistent abnormal request sizes'],
    ['fa-gauge-high', 'Brute force', (int)($allTime['bruteForce'] ?? 0), 'Persistent rate-limit triggers'],
    ['fa-spider', 'Honeypot', (int)($allTime['honeypot'] ?? 0), 'Persistent honeypot events'],
    ['fa-ban', 'Banned-source hits', (int)($allTime['bannedSourceHits'] ?? 0), 'Persistent blocked banned clients'],
    ['fa-door-open', 'Forced Browsing', (int)($allTime['forcedBrowsing'] ?? 0), 'Persistent unauthorized page access'],
];

audit_log('threat_center_viewed uid=' . $userId);
?>
<!doctype html><html lang="en"><head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#10071f"><title>Aegis AI — Threat Center</title><link rel="stylesheet" href="/css/all.min.css"><link rel="stylesheet" href="/css/dashboard.css?v=20260824-0845"><link rel="stylesheet" href="/css/pjax.css"><link rel="stylesheet" href="/css/it113_phase3_completion.css?v=20261120"><link rel="stylesheet" href="/css/it113_mitigation_workflow.css?v=20261120">
<script src="/js/fortress_pjax.js" defer></script>
</head>
<body class="command-page"><div class="ambient ambient-one" aria-hidden="true"></div><div class="ambient ambient-two" aria-hidden="true"></div><main class="command-shell">
<?php require __DIR__ . '/partials/command_header.php'; ?>
<section class="page-hero compact-page-hero threat-page-hero"><div><span class="eyebrow">INTRUSION MONITORING</span><h1>Threat Center</h1><p>Review recorded security signals alongside traceable ML assessments, triage priorities and practical mitigations. A detection is not automatically a confirmed incident.</p></div><div class="page-hero-icon"><i class="fa-solid fa-shield-virus"></i></div></section>


<section class="it113-findings-banner" aria-label="Evidence status">
    <div class="it113-findings-banner-main"><span class="it113-eyebrow"><i class="fa-solid fa-microscope"></i> IT113 / EVIDENCE-BASED ANALYSIS</span><h2>Threat Findings <span>&amp; Response Intelligence</span></h2><p>This protected workspace shows operational evidence recorded by Aegis AI, not the public synthetic test dataset. Predictions and deterministic audit events are presented separately to support honest validation.</p>
        <div class="it113-findings-actions"><a href="/ai_threat_intelligence.php"><i class="fa-solid fa-brain"></i> Operational AI Defense</a><a href="/assessment/#evaluation"><i class="fa-solid fa-chart-line"></i> Research model evaluation</a><a href="/assessment/#mitigations"><i class="fa-solid fa-shield-halved"></i> Mitigation reference</a></div>
    </div>
    <div class="it113-findings-insights">
        <div><small>Saved ML analyses</small><strong><?= count($it113PredictionHistory) ?></strong></div>
        <div><small>Non-normal classifications</small><strong><?= count($it113ThreatPredictions) ?></strong></div>
        <div><small>High / critical model risk</small><strong><?= $it113HighRiskPredictions ?></strong></div>
        <span class="it113-model-state"><i class="fa-solid fa-circle-info"></i> <?= e($it113EvidenceMode) ?> · last model <?= e($it113LastModel) ?></span>
    </div>
</section>

<section class="panel it113-ml-findings" aria-label="Saved ML threat assessments" id="it113-model-findings">
    <?php if (($_GET['it113_case'] ?? '') === 'updated'): ?><div class="it113-workflow-flash success" role="status"><i class="fa-solid fa-circle-check"></i> Analyst case update saved.</div><?php endif; ?>
    <?php if ($it113CaseMessage !== ''): ?><div class="it113-workflow-flash error" role="alert"><i class="fa-solid fa-triangle-exclamation"></i> <?= e($it113CaseMessage) ?></div><?php endif; ?>
    <?php if ($it113CaseReadWarning !== ''): ?><div class="it113-workflow-flash error" role="alert"><?= e($it113CaseReadWarning) ?></div><?php endif; ?>
    <div class="it113-workflow-top">
       <div><span class="eyebrow">ANALYST CASE MANAGEMENT · ADMIN ONLY</span><h2>Mitigation Status Tracking</h2><p>Investigate recorded ML findings, document corrective actions, and close cases with an auditable history. A resolved case means an analyst marked its response complete, not that the model proved an attack.</p></div>
       <span class="it113-workflow-backend <?= $it113MitigationBackend === 'postgresql' ? 'is-db' : 'is-local' ?>"><i class="fa-solid fa-database"></i> <?= $it113MitigationBackend === 'postgresql' ? 'POSTGRESQL · DURABLE' : ($it113MitigationBackend === 'local' ? 'LOCAL FILE · SINGLE HOST' : 'STORAGE UNAVAILABLE') ?></span>
    </div>
    <?php if ($it113MitigationBackend === 'local'): ?><p class="it113-workflow-storage-note"><i class="fa-solid fa-circle-info"></i> Local case records are stored outside public/ and survive ordinary local restarts. On cloud hosts with ephemeral disks, they may disappear after redeployment. Apply <code>sql/ml_mitigation_workflow.sql</code> after database recovery for durable shared history. Existing local cases require migration before switching storage.</p><?php endif; ?>
    <div class="panel-heading"><div><span class="eyebrow">MODEL FINDINGS · SAVED PREDICTIONS</span><h2>Explainable Behavioral Assessments</h2><p>Historical XGBoost / autoencoder results. Risk and confidence are model outputs, not proof of successful exploitation. Actions reflect recorded policy outcomes and may be advisory or retrospective.</p></div><span class="it113-secure-label"><i class="fa-solid fa-lock"></i> ADMIN ONLY</span></div>
    <?php if (!$it113PredictionHistory): ?>
        <div class="it113-ml-empty"><i class="fa-solid fa-database"></i><div><strong>No stored operational predictions available</strong><p>The ML service may not have analyzed activity yet, or its database and local history may be unavailable. We do not display fabricated live findings. The offline research workspace remains available.</p></div></div>
    <?php else: ?>
        <div class="it113-ml-cards">
          <?php foreach (array_slice($it113PredictionHistory, 0, 12) as $prediction): ?>
            <article class="it113-ml-card" data-severity="<?= e(strtolower($prediction['severity'])) ?>">
              <div class="it113-ml-card-head">
                <div><span class="it113-ml-class"><?= e($prediction['label']) ?></span><small><?= $prediction['ts'] > 0 ? e(date('Y-m-d H:i:s', $prediction['ts'])) : 'Time unavailable' ?> · <code><?= e($prediction['ip']) ?></code></small></div>
                <span class="it113-risk-tag risk-<?= e(strtolower($prediction['severity'])) ?>"><?= e($prediction['severity']) ?> RISK</span>
              </div>
              <div class="it113-ml-numbers"><div><span>Hybrid risk</span><strong><?= number_format($prediction['risk'], 1) ?><small>/100</small></strong></div><div><span>Model confidence</span><strong><?= number_format($prediction['confidence'] * 100, 1) ?><small>%</small></strong></div><div><span>Recorded outcome</span><strong class="it113-outcome"><?= e(str_replace('_', ' ', $prediction['action'])) ?></strong></div></div>
              <?php if (!in_array($prediction['class'], ['NORMAL','UNKNOWN'], true)):
                $caseKey = $prediction['case_id'];
                $savedCase = $it113Cases[$caseKey] ?? null;
                $currentStatus = (string)($savedCase['status'] ?? 'OPEN');
                $caseRevision = (int)($savedCase['revision'] ?? 0);
              ?>
              <div class="it113-workflow-state">
                 <span class="it113-workflow-state-label"><i class="fa-solid fa-clipboard-check"></i> Mitigation case</span>
                 <span class="it113-workflow-pill it113-workflow-<?= e(strtolower($currentStatus)) ?>"><?= e(str_replace('_',' ',$currentStatus)) ?></span>
                 <small>Revision <?= $caseRevision ?> · <?= $savedCase ? 'Tracked' : 'Not yet reviewed' ?></small>
              </div>
              <details class="it113-workflow-details"><summary><span><i class="fa-solid fa-pen-to-square"></i> Update response status &amp; analyst notes</span><i class="fa-solid fa-chevron-down"></i></summary>
                 <form action="/threats.php#it113-model-findings" method="post" class="it113-workflow-form" data-no-pjax autocomplete="off">
                   <input type="hidden" name="it113_case_action" value="update">
                   <input type="hidden" name="case_id" value="<?= e($caseKey) ?>">
                   <input type="hidden" name="expected_revision" value="<?= $caseRevision ?>">
                   <input type="hidden" name="csrf_token" value="<?= e(generate_csrf_token()) ?>">
                   <label>Next status
                     <select name="status" required aria-label="Mitigation case status for <?= e($prediction['label']) ?>">
                       <?php foreach (fortress_it113_allowed_next($currentStatus) as $option): ?><option value="<?= e($option) ?>" <?= $option === $currentStatus ? 'selected' : '' ?>><?= e(ucwords(strtolower($option))) ?><?= $option === $currentStatus ? ' (add note)' : '' ?></option><?php endforeach; ?>
                     </select>
                   </label>
                   <label>Analyst note <small>8–500 bytes. Do not include passwords or personal data.</small>
                     <textarea name="analyst_note" rows="3" maxlength="500" minlength="8" required placeholder="Record validation, remediation steps, or evidence reviewed"></textarea>
                   </label>
                   <button type="submit"><i class="fa-solid fa-floppy-disk"></i> Save case update</button>
                 </form>
                 <div class="it113-workflow-history">
                   <strong>Case activity history</strong>
                   <?php if (empty($savedCase['history'])): ?><p>No analyst actions have been recorded for this finding.</p>
                   <?php else: ?><ol><?php foreach (array_slice($savedCase['history'], 0, 8) as $change): ?>
                     <li><strong><?= e($change['from'] ?? 'OPEN') ?> → <?= e($change['to'] ?? 'OPEN') ?></strong><small><?= e($change['at'] ?? '') ?> · Admin #<?= (int)($change['actor_uid'] ?? 0) ?></small><p><?= e($change['note'] ?? '') ?></p></li>
                   <?php endforeach; ?></ol><?php endif; ?>
                 </div>
              </details>
              <?php endif; ?>
              <details class="it113-evidence-details"><summary>Evidence, validation &amp; mitigation <i class="fa-solid fa-chevron-down"></i></summary>
                <div class="it113-evidence-body">
                  <div><strong>Interpretation check</strong><p><?= e($prediction['validation']) ?></p></div>
                  <div><strong>Recommended mitigation</strong><p><?= e($prediction['mitigation']) ?></p></div>
                  <div><strong>Observed threshold indicators</strong>
                    <?php if (!$prediction['indicators']): ?><p>No per-indicator evidence is recorded in this saved result.</p><?php else: ?><ul><?php foreach ($prediction['indicators'] as $indicator): ?><li><?= e($indicator) ?></li><?php endforeach; ?></ul><?php endif; ?>
                  </div>
                  <div class="it113-ml-provenance"><span>Trace <code><?= e($prediction['trace'] ?: 'Not recorded') ?></code></span><span>Model <code><?= e($prediction['model'] ?: 'Not recorded') ?></code></span><span>Mode <b><?= e($prediction['mode']) ?></b></span><span>Request source <b><?= e($prediction['request_source']) ?></b></span><span>Audit source <b><?= e($prediction['event_source']) ?></b></span><?php if ($prediction['window_truncated']): ?><span class="it113-warning">Evidence window was truncated; verify before enforcement</span><?php endif; ?></div>
                </div>
              </details>
            </article>
          <?php endforeach; ?>
        </div>
        <?php if (count($it113PredictionHistory) > 12): ?><p class="it113-bounded-note">Displaying the latest 12 assessments. Open AI Defense for the broader saved prediction history.</p><?php endif; ?>
    <?php endif; ?>
    <div class="it113-workflow-ledger">
      <div class="it113-workflow-ledger-head"><div><span class="eyebrow">PERSISTENT CASE HISTORY</span><h3>Recent Analyst Cases</h3><p>Saved response statuses remain visible in this register even when newer predictions replace a finding in the cards above.</p></div><span><?= count($it113TrackedCases) ?> recent cases</span></div>
      <?php if (!$it113TrackedCases): ?><p class="it113-workflow-ledger-empty">No analyst case updates yet. Open a non-normal ML finding above to record the first review.</p>
      <?php else: ?><div class="it113-workflow-ledger-table"><table><thead><tr><th>Classification</th><th>Case</th><th>Status</th><th>Last updated</th><th>Revision</th></tr></thead><tbody>
      <?php foreach ($it113TrackedCases as $tracked): ?><tr><td><?= e(str_replace('_', ' ', (string)($tracked['classification'] ?? 'UNKNOWN'))) ?></td><td><code title="<?= e((string)($tracked['case_id'] ?? '')) ?>"><?= e(substr((string)($tracked['case_id'] ?? ''),0,12)) ?>…</code></td><td><span class="it113-workflow-pill it113-workflow-<?= e(strtolower((string)($tracked['status'] ?? 'OPEN'))) ?>"><?= e((string)($tracked['status'] ?? 'OPEN')) ?></span></td><td><?= e((string)($tracked['updated_at'] ?? '')) ?></td><td><?= (int)($tracked['revision'] ?? 0) ?></td></tr><?php endforeach; ?>
      </tbody></table></div><?php endif; ?>
    </div>
</section>

<section class="threat-overview-grid">
    <article class="panel threat-panel threat-center-gauge"><div class="panel-heading compact"><div><span class="eyebrow">CURRENT THREAT LEVEL</span><h2>Threat Pressure</h2></div><span class="panel-status"><i class="fa-solid fa-satellite-dish"></i> Live</span></div><div class="threat-gauge"><div class="gauge-ring <?= e($threatClass) ?> large-gauge"><div><strong><?= e($threatLevel) ?></strong><span><?= $threatPoints ?> pressure points</span></div></div></div><div class="threat-equation"><div><span>Failed passwords</span><strong><?= $failedAttempts24h ?></strong></div><div><span>Suspicious requests ×2</span><strong><?= $suspiciousRequests24h ?></strong></div><div><span>Active bans ×3</span><strong><?= $activeBans ?></strong></div><div><span>Personal ID failures ×2</span><strong><?= $schoolIdFailures24h ?></strong></div></div></article>
    <article class="panel"><div class="panel-heading compact"><div><span class="eyebrow">SOURCE INTELLIGENCE</span><h2>Top Threat Sources / 24h</h2></div><i class="fa-solid fa-network-wired panel-symbol"></i></div><div class="source-list"><?php if (!$topThreatSources): ?><div class="empty-state">No threat-producing source IPs were recorded in the last 24 hours.</div><?php else: $rank=0; foreach ($topThreatSources as $ip=>$count): $rank++; ?><div><span class="source-rank"><?= str_pad((string)$rank,2,'0',STR_PAD_LEFT) ?></span><code><?= e($ip) ?></code><strong><?= (int)$count ?> events</strong></div><?php endforeach; endif; ?></div><div class="panel-note"><i class="fa-solid fa-circle-info"></i> Localhost and trusted development addresses may appear while testing the project locally.</div></article>
</section>


<article class="panel request-defense-panel"><div class="panel-heading"><div><span class="eyebrow">THREAT CATEGORIES</span><h2>Detected Security Pressure</h2><p>All-time category totals are read from persistent Supabase security evidence, while the live threat pressure and source intelligence above remain rolling 24-hour metrics.</p></div></div><div class="attack-grid threat-category-grid"><?php foreach($threatCategories as $item): ?><div class="attack-card"><span class="attack-icon"><i class="fa-solid <?= e($item[0]) ?>"></i></span><div><strong class="metric-number" data-count="<?= (int)$item[2] ?>"><?= (int)$item[2] ?></strong><span><?= e($item[1]) ?></span><small><?= e($item[3]) ?></small></div></div><?php endforeach; ?></div></article>

<article class="panel data-panel"><div class="panel-heading filter-heading"><div><span class="eyebrow">DETERMINISTIC AUDIT SIGNALS</span><h2>Recorded Security Events</h2><p>These are logged controls and observations, <strong>not</strong> independently ML-classified attacks. Review priority is suggested triage guidance, not a CVSS score.</p></div><div class="table-tools"><label class="search-control"><i class="fa-solid fa-magnifying-glass"></i><input type="search" data-table-search="threatHistory" placeholder="Search threats..."></label><select data-table-category="threatHistory"><option value="all">All categories</option><option value="authentication">Authentication</option><option value="identity">Identity</option><option value="network">Network</option><option value="threat">Threat</option></select></div></div><div class="responsive-table-wrap mobile-bounded-table threat-history-table-wrap"><table class="security-table" data-table="threatHistory"><thead><tr><th>Timestamp</th><th>Source IP</th><th>Category</th><th>Detection</th><th>Review priority</th><th>Outcome</th><th>Evidence &amp; response</th></tr></thead><tbody><?php if(!$threatHistory): ?><tr><td colspan="7" class="table-empty">No threat events have been recorded.</td></tr><?php else: foreach($threatHistory as $line): $category=fortress_event_category($line); $outcome=fortress_event_outcome($line); $it113Event=fortress_it113_event_guidance(fortress_event_key($line)); ?><tr data-search="<?= e(strtolower(fortress_event_title($line).' '.fortress_log_ip($line).' '.$category)) ?>" data-category="<?= e(strtolower($category)) ?>"><td><?= e(fortress_event_time($line,'Y-m-d H:i:s')) ?></td><td><?= e(fortress_log_ip($line)) ?></td><td><?= e($category) ?></td><td><?= e(fortress_event_title($line)) ?></td><td><span class="it113-priority <?= $it113Event['priority'] === 'High' ? 'is-high' : 'is-review' ?>"><?= e($it113Event['priority']) ?></span></td><td><span class="status-pill status-<?= strtolower($outcome) ?>"><?= e($outcome) ?></span></td><td><?= e(fortress_event_description($line)) ?><div class="it113-event-guidance"><strong>Suggested review:</strong> <?= e($it113Event['recommendation']) ?></div></td></tr><?php endforeach; endif; ?></tbody></table></div></article>
<footer class="command-footer"><span><i class="fa-solid fa-shield-halved"></i> Aegis AI intrusion monitoring</span><span>Last threat: <?= e($lastThreatRelative) ?></span></footer>

</div><!-- /.fortress-main-column -->
</main><script src="/js/dashboard.js?v=20260824-0845"></script><script src="/js/auto_logout.js"></script></body></html>
