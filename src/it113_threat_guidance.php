<?php

declare(strict_types=1);

/**
 * IT113 Phase 3: curated, non-executable analyst guidance for threat indicators.
 * These are review suggestions, not evidence of exploitation or validated severity.
 * A database or machine-learning service is NOT required to load this file.
 */
function fortress_it113_class_guidance(string $classification): array
{
    $profiles = [
        'NORMAL' => [
            'label' => 'Normal behavior',
            'validation' => 'Compare the observation window with ordinary traffic before closing the case.',
            'mitigation' => 'Continue routine monitoring; do not restrict access from a normal label alone.',
        ],
        'BRUTE_FORCE' => [
            'label' => 'Brute force',
            'validation' => 'Check repeated failures, request timing, targeted accounts, and corresponding authentication events.',
            'mitigation' => 'Review adaptive rate limits, account-focused alerts, and MFA for privileged accounts.',
        ],
        'CREDENTIAL_STUFFING' => [
            'label' => 'Credential stuffing',
            'validation' => 'Check how many distinct accounts were targeted and correlate failures and successes.',
            'mitigation' => 'Use per-account and per-source rate limits, compromised-password controls, and MFA.',
        ],
        'RECONNAISSANCE' => [
            'label' => 'Reconnaissance',
            'validation' => 'Review unique paths, sensitive-path probes, scanner signals, and known benign crawlers.',
            'mitigation' => 'Restrict administrative endpoints, review probing sources, and patch exposed services.',
        ],
        'WEB_ATTACK' => [
            'label' => 'Web attack',
            'validation' => 'Correlate request-security events with the affected endpoint; confirm whether payloads were rejected.',
            'mitigation' => 'Enforce input validation, parameterized SQL, output encoding, and safe HTTP method handling.',
        ],
        'MFA_ABUSE' => [
            'label' => 'Personal ID / MFA abuse',
            'validation' => 'Correlate repeated second-factor failures, challenge lifetimes, and account activity.',
            'mitigation' => 'Apply challenge attempt limits, short expirations, session binding, and operator alerts.',
        ],
        'SESSION_ABUSE' => [
            'label' => 'Session abuse',
            'validation' => 'Review CSRF failures, unauthorized route access, session changes, and related audit entries.',
            'mitigation' => 'Enforce CSRF tokens, secure session cookies, session renewal, and idle expiry.',
        ],
    ];
    $key = strtoupper(trim($classification));
    return $profiles[$key] ?? [
        'label' => 'Unclassified model output',
        'validation' => 'Review the raw trace and model version before interpreting this output.',
        'mitigation' => 'Escalate for manual review; do not enforce a block from an unknown label.',
    ];
}

/**
 * Map a deterministic audit event to triage guidance without pretending that
 * the event has been independently classified by the trained model.
 */
function fortress_it113_event_guidance(string $eventKey): array
{
    $groups = [
        'bruteforce_detected' => ['Authentication', 'High', 'Inspect attempt volume, targeted accounts, and configured rate limits.'],
        'password_factor_failed' => ['Authentication', 'Review', 'Compare this failed factor with other attempts; a single failure is not an attack.'],
        'auth_rejected' => ['Access control', 'Review', 'Confirm the rejection reason and check for repeated unauthorized access.'],
        'school_id_qr_failed' => ['Identity factor', 'Review', 'Check whether failed Personal ID challenges repeat for the same account.'],
        'school_id_qr_locked' => ['Identity factor', 'High', 'Review repeated challenge failures and challenge expiry settings.'],
        'school_id_qr_rate_limited' => ['Identity factor', 'High', 'Verify abuse counters and challenge rate limits.'],
        'scanner_user_agent_detected' => ['Reconnaissance', 'Review', 'Correlate the scanner signature with requested paths; fingerprints can be spoofed.'],
        'sensitive_path_probe' => ['Reconnaissance', 'High', 'Check targeted paths and confirm sensitive files remain inaccessible.'],
        'reconnaissance_probe' => ['Reconnaissance', 'Review', 'Check for repeated unique-path requests and distinguish benign missing assets.'],
        'automated_recon_detected' => ['Reconnaissance', 'High', 'Inspect the supporting volume and timing of probe events.'],
        'automated_recon_block' => ['Reconnaissance', 'High', 'Verify the temporary block and check whether the source continues probing.'],
        'automated_recon_blocked_source_attempt' => ['Reconnaissance', 'High', 'Monitor continued blocked probes; review current ban scope.'],
        'request_threat_detected' => ['Application', 'High', 'Review the flagged endpoint, signature, and whether the request was blocked.'],
        'malicious_input_detected' => ['Application', 'High', 'Investigate the blocked input class without storing sensitive payload contents.'],
        'shell_attack_detected' => ['Application', 'High', 'Check affected endpoint hardening and blocked command-pattern indicators.'],
        'csrf_validation_failed' => ['Session', 'High', 'Confirm the rejected action, token state, and originating session.'],
        'csp_violation_reported' => ['Application', 'Review', 'Check blocked resource origins and rule out legitimate application resources.'],
        'http_method_blocked' => ['Application', 'High', 'Review method allowlists and affected endpoint.'],
        'http_method_anomaly' => ['Application', 'Review', 'Check whether the unusual request method matches an approved client.'],
        'endpoint_method_rejected' => ['Application', 'Review', 'Check route-specific method restrictions.'],
        'oversized_request_detected' => ['Application', 'Review', 'Check request size policy and repeated anomalous attempts.'],
        'oversized_uri_detected' => ['Application', 'Review', 'Check URL length policy and repeated probes.'],
        'banned_ip_attempt' => ['Network', 'High', 'Check whether the source is repeatedly attempting access while blocked.'],
        'banned_ip_middleware_block' => ['Network', 'High', 'Check active enforcement scope and expiration.'],
        'ip_banned' => ['Network', 'High', 'Verify the block trigger and that legitimate clients are not affected.'],
        'honeypot_triggered' => ['Reconnaissance', 'High', 'Check why a decoy endpoint was accessed and correlate source activity.'],
        'unsafe_redirect_blocked' => ['Application', 'High', 'Check redirect validation and referer/origin indicators where available.'],
        'ml_threat_prediction' => ['ML assessment', 'Review', 'Cross-reference the model prediction history and matching trace ID.'],
        'ml_assisted_strike' => ['ML enforcement', 'High', 'Verify model confidence, rule corroboration, and strike policy.'],
        'ml_assisted_block' => ['ML enforcement', 'High', 'Review the corroborating evidence, temporary-ban duration, and appeal process.'],
    ];
    $key = strtolower(trim($eventKey));
    $match = $groups[$key] ?? ['Security event', 'Review', 'Correlate this event with audit history before assigning severity.'];
    return ['group' => $match[0], 'priority' => $match[1], 'recommendation' => $match[2]];
}

/** Display limited, safely interpreted provenance from a saved ML record. */
function fortress_it113_prediction_summary(array $row): array
{
    $result = is_array($row['result'] ?? null) ? $row['result'] : [];
    $evidence = is_array($row['evidence'] ?? null) ? $row['evidence'] : [];
    $classification = strtoupper(trim((string)($result['classification'] ?? 'UNKNOWN')));
    $profile = fortress_it113_class_guidance($classification);
    $severity = strtoupper(trim((string)($result['severity'] ?? 'UNKNOWN')));
    if (!in_array($severity, ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], true)) $severity = 'UNKNOWN';
    $action = strtoupper(trim((string)($result['enforcement_action'] ?? 'UNRECORDED')));
    if (!in_array($action, ['OBSERVE', 'ADVISORY_ONLY', 'RETROSPECTIVE', 'STRIKE', 'BLOCK', 'EXEMPT', 'UNRECORDED'], true)) {
        $action = 'OTHER';
    }
    $confidence = is_numeric($result['confidence'] ?? null) ? (float)$result['confidence'] : 0.0;
    $risk = is_numeric($result['risk_score'] ?? null) ? (float)$result['risk_score'] : 0.0;
    $indicators = is_array($result['indicator_evidence'] ?? null) ? $result['indicator_evidence'] : [];
    $descriptions = [];
    foreach (array_slice($indicators, 0, 3) as $indicator) {
        if (!is_array($indicator)) continue;
        $description = trim((string)($indicator['description'] ?? ''));
        if ($description !== '') $descriptions[] = substr($description, 0, 200);
    }
    return [
        'class' => $classification,
        'label' => $profile['label'],
        'validation' => $profile['validation'],
        'mitigation' => $profile['mitigation'],
        'severity' => $severity,
        'action' => $action,
        'confidence' => max(0.0, min(1.0, $confidence)),
        'risk' => max(0.0, min(100.0, $risk)),
        'ip' => substr((string)($row['ip'] ?? 'unknown'), 0, 64),
        'ts' => max(0, (int)($row['ts'] ?? 0)),
        'trace' => substr((string)($result['trace_id'] ?? ''), 0, 80),
        'model' => substr((string)($result['model_version'] ?? ''), 0, 80),
        'mode' => substr((string)($result['analysis_mode'] ?? 'UNKNOWN'), 0, 40),
        'request_source' => substr((string)($evidence['request_source'] ?? 'not recorded'), 0, 64),
        'event_source' => substr((string)($evidence['security_event_source'] ?? 'not recorded'), 0, 64),
        'window_truncated' => !empty($evidence['window_truncated']),
        'indicators' => $descriptions,
    ];
}
