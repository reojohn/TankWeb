<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/auth.php';
require_once __DIR__ . '/../src/fortress_metrics.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_admin_auth();
$userId = (int)($_SESSION['uid'] ?? 0);
$ctx = fortress_build_security_context($pdo, $userId);
extract($ctx, EXTR_SKIP);
$activeNav = 'ai';

$mlEnabled = fortress_ml_enabled();
$mlLatest = fortress_ml_latest_prediction();
$mlResult = is_array($mlLatest['result'] ?? null) ? $mlLatest['result'] : null;
$mlFeatures = is_array($mlLatest['features'] ?? null) ? $mlLatest['features'] : [];
$mlProbabilities = $mlResult && is_array($mlResult['probabilities'] ?? null) ? $mlResult['probabilities'] : [];
arsort($mlProbabilities);

$mlRisk = $mlResult ? (float)($mlResult['risk_score'] ?? 0) : 0.0;
$mlSeverity = $mlResult ? (string)($mlResult['severity'] ?? 'NO DATA') : ($mlEnabled ? 'WAITING' : 'DISABLED');
$mlClass = $mlResult ? (string)($mlResult['classification'] ?? 'UNKNOWN') : 'NOT_ANALYZED';
$mlConfidence = $mlResult ? ((float)($mlResult['confidence'] ?? 0) * 100.0) : 0.0;
$mlAnomaly = $mlResult ? ((float)($mlResult['anomaly_score'] ?? 0) * 100.0) : 0.0;
$mlRuleScore = $mlResult ? (float)($mlResult['rule_score'] ?? 0) : 0.0;
$mlXgbRisk = $mlResult ? (float)($mlResult['xgboost_risk'] ?? 0) : 0.0;
$mlIndicators = $mlResult && is_array($mlResult['indicators'] ?? null) ? $mlResult['indicators'] : [];
$mlSourceIp = is_array($mlLatest) ? (string)($mlLatest['ip'] ?? 'No source yet') : 'No source yet';
$mlPredictionTs = is_array($mlLatest) ? (int)($mlLatest['ts'] ?? 0) : 0;
$mlPredictionTime = $mlPredictionTs > 0 ? date('Y-m-d H:i:s', $mlPredictionTs) : 'Waiting for first analysis';

$featureLabels = [
    'requests_1m' => 'Requests / 1 min',
    'requests_5m' => 'Requests / 5 min',
    'unique_paths_5m' => 'Unique paths / 5 min',
    'post_ratio_5m' => 'POST request ratio',
    'auth_endpoint_requests_5m' => 'Authentication endpoint requests',
    'failed_logins_5m' => 'Failed passwords / 5 min',
    'failed_logins_15m' => 'Failed passwords / 15 min',
    'unique_usernames_15m' => 'Unique usernames / 15 min',
    'successful_logins_15m' => 'Successful logins / 15 min',
    'qr_failures_15m' => 'Personal ID failures / 15 min',
    'sensitive_path_probes_15m' => 'Sensitive-path probes',
    'suspicious_requests_15m' => 'Suspicious requests',
    'scanner_events_15m' => 'Scanner indicators',
    'csrf_failures_15m' => 'CSRF failures',
    'method_anomalies_15m' => 'HTTP method anomalies',
    'auth_rejections_15m' => 'Protected-resource rejections',
    'ban_events_15m' => 'Ban events',
    'avg_request_interval_5m' => 'Average request interval',
    'ua_changes_15m' => 'User-agent changes',
    'off_hours' => 'Off-hours activity',
];

$predictionHistory = [];
$predictionPath = fortress_ml_data_dir() . '/predictions.jsonl';
foreach (array_reverse(fortress_ml_tail_lines($predictionPath, 30)) as $line) {
    $row = json_decode($line, true);
    if (!is_array($row) || !is_array($row['result'] ?? null)) continue;
    $predictionHistory[] = $row;
    if (count($predictionHistory) >= 20) break;
}


$aiBehaviorLabel = ucwords(strtolower(str_replace('_', ' ', $mlClass)));
$aiClassKey = strtoupper(trim($mlClass));

$aiAnomalyInterpretation = $mlAnomaly >= 70
    ? 'strongly outside the learned normal baseline'
    : ($mlAnomaly >= 50
        ? 'showing a significant deviation from the learned normal baseline'
        : ($mlAnomaly >= 30
            ? 'showing a noticeable but moderate deviation from the learned normal baseline'
            : 'remaining close to the learned normal baseline'));

$aiRiskInterpretation = $mlRisk >= 85
    ? 'critical'
    : ($mlRisk >= 70
        ? 'high'
        : ($mlRisk >= 50
            ? 'suspicious'
            : ($mlRisk >= 30 ? 'watch-level' : 'normal')));

$aiClassFindingMap = [
    'NORMAL' => 'I did not find a learned attack pattern in the latest behavior. The activity currently looks most similar to normal FortressAuth usage.',
    'BRUTE_FORCE' => 'I found a behavioral pattern that resembles brute-force activity, where repeated authentication attempts may be trying to guess valid credentials.',
    'CREDENTIAL_STUFFING' => 'I found a behavioral pattern that resembles credential stuffing, where multiple account credentials may be tested against the authentication system.',
    'RECONNAISSANCE' => 'I found a behavioral pattern that resembles reconnaissance. The source appears to be exploring paths or system behavior in a way that deserves review.',
    'WEB_ATTACK' => 'I found a behavioral pattern that resembles a web attack. The request activity is similar to malicious web-input or endpoint probing behavior learned by the classifier.',
    'MFA_ABUSE' => 'I found a behavioral pattern that resembles second-factor abuse, including activity that may be repeatedly targeting the Personal ID verification step.',
    'SESSION_ABUSE' => 'I found a behavioral pattern that resembles session abuse. The current session-related behavior differs from ordinary authenticated use and should be reviewed.',
];

$aiClassFinding = $aiClassFindingMap[$aiClassKey]
    ?? sprintf(
        'I classified the latest behavior as %s. This is the closest learned behavior category for the current observation window.',
        $aiBehaviorLabel
    );

$aiConversationMessages = [];

if (!$mlEnabled) {
    $aiConversationMessages = [
        'Hello. I am the FortressAuth AI security analyst. I checked the system, but the hybrid machine-learning service is currently disabled, so I cannot produce a live behavioral finding yet.',
        'The core security system is still protecting FortressAuth. Password authentication, Personal ID verification, rate limits, rule-based detection, session controls, and audit logging remain operational without the ML service.',
        'Once the ML service is enabled, I can continuously review non-sensitive security telemetry and report what XGBoost, the Autoencoder, and the rule engine find about current activity.',
    ];
} elseif (!$mlResult) {
    $aiConversationMessages = [
        'Hello. I am the FortressAuth AI security analyst. I checked the system and confirmed that the ML service is online, but I am still waiting for the first completed behavioral analysis.',
        'I have not found a security result to report yet because no completed analysis window has been saved. Normal protected-page activity will give the request monitor enough telemetry to generate one.',
        'While I wait, FortressAuth continues enforcing its normal protections. The AI layer is supplementary and does not replace authentication, rate limits, deterministic rules, or session security.',
    ];
} else {
    $aiConversationMessages[] = sprintf(
        'Hello. I reviewed the latest FortressAuth security activity from source %s. My current assessment is %s, with a hybrid risk score of %.1f out of 100.',
        $mlSourceIp,
        strtolower($mlSeverity),
        $mlRisk
    );

    $aiConversationMessages[] = $aiClassFinding;

    $aiConversationMessages[] = sprintf(
        'XGBoost supports that finding with %.1f percent confidence. In other words, the current behavior most closely matches the %s behavior class learned during training.',
        $mlConfidence,
        $aiBehaviorLabel
    );

    if ($mlProbabilities) {
        $topProbabilityParts = [];
        foreach (array_slice($mlProbabilities, 0, 3, true) as $probabilityClass => $probability) {
            $topProbabilityParts[] = sprintf(
                '%s at %.1f percent',
                ucwords(strtolower(str_replace('_', ' ', (string)$probabilityClass))),
                ((float)$probability) * 100.0
            );
        }

        if ($topProbabilityParts) {
            $aiConversationMessages[] = 'I also compared the strongest XGBoost alternatives. The leading model probabilities are ' . implode(', ', $topProbabilityParts) . '.';
        }
    }

    if ($mlAnomaly < 30) {
        $aiConversationMessages[] = sprintf(
            'I compared the current behavior with the Autoencoder normal baseline. The anomaly deviation is %.1f percent, so the activity does not stand out strongly from behavior the model learned as normal.',
            $mlAnomaly
        );
    } elseif ($mlAnomaly < 50) {
        $aiConversationMessages[] = sprintf(
            'The Autoencoder found a %.1f percent deviation from the learned normal baseline. I can see some unusual behavior, but the deviation is still moderate and should be interpreted together with the other security signals.',
            $mlAnomaly
        );
    } elseif ($mlAnomaly < 70) {
        $aiConversationMessages[] = sprintf(
            'The Autoencoder found a %.1f percent anomaly deviation. That is a significant departure from the learned normal baseline, so I would review the related activity even if the classifier has not labeled it as a known attack.',
            $mlAnomaly
        );
    } else {
        $aiConversationMessages[] = sprintf(
            'The Autoencoder found a %.1f percent anomaly deviation. This behavior is strongly outside the learned normal baseline and deserves prompt investigation.',
            $mlAnomaly
        );
    }

    if ($mlRuleScore <= 0.1) {
        $aiConversationMessages[] = 'I checked the deterministic FortressAuth rule engine as well. It is currently contributing 0 out of 100 attack signal, so I did not find rule-based evidence of a known malicious request in this latest assessment.';
    } elseif ($mlRuleScore < 50) {
        $aiConversationMessages[] = sprintf(
            'The deterministic rule engine contributes %.1f out of 100. I found some rule-based security evidence, but it is not yet a strong deterministic signal by itself.',
            $mlRuleScore
        );
    } else {
        $aiConversationMessages[] = sprintf(
            'The deterministic rule engine contributes %.1f out of 100. I found substantial rule-based evidence, so the related audit events and request details should be reviewed promptly.',
            $mlRuleScore
        );
    }

    $windowParts = [];
    $requests5m = (int)($mlFeatures['requests_5m'] ?? 0);
    $failed15m = (int)($mlFeatures['failed_logins_15m'] ?? 0);
    $authRequests5m = (int)($mlFeatures['auth_endpoint_requests_5m'] ?? 0);
    $suspicious15m = (int)($mlFeatures['suspicious_requests_15m'] ?? 0);
    $scanner15m = (int)($mlFeatures['scanner_events_15m'] ?? 0);
    $probe15m = (int)($mlFeatures['sensitive_path_probes_15m'] ?? 0);
    $qrFailures15m = (int)($mlFeatures['qr_failures_15m'] ?? 0);

    $windowParts[] = sprintf('%d requests during the last five minutes', $requests5m);
    $windowParts[] = sprintf('%d authentication-endpoint requests', $authRequests5m);
    $windowParts[] = sprintf('%d failed password attempts during the last fifteen minutes', $failed15m);

    if ($qrFailures15m > 0) {
        $windowParts[] = sprintf('%d Personal ID verification failures', $qrFailures15m);
    }
    if ($suspicious15m > 0) {
        $windowParts[] = sprintf('%d suspicious-request events', $suspicious15m);
    }
    if ($scanner15m > 0) {
        $windowParts[] = sprintf('%d scanner indicators', $scanner15m);
    }
    if ($probe15m > 0) {
        $windowParts[] = sprintf('%d sensitive-path probes', $probe15m);
    }

    $aiConversationMessages[] = 'Looking at the current behavioral window, I found ' . implode(', ', $windowParts) . '. I use these values as behavioral evidence, not as proof of an attack by themselves.';

    if ($mlIndicators) {
        $indicatorLabels = array_map(
            static fn($indicator): string => ucwords(strtolower(str_replace('_', ' ', (string)$indicator))),
            array_slice($mlIndicators, 0, 5)
        );
        $aiConversationMessages[] = 'I also found these supporting indicators in the latest analysis: ' . implode(', ', $indicatorLabels) . '. I treat them as investigation clues and combine them with the classifier, anomaly score, and deterministic rules.';
    } else {
        $aiConversationMessages[] = 'I did not find any additional ML warning indicators attached to this analysis. The current conclusion is therefore based mainly on the classifier result, anomaly deviation, behavioral window, and deterministic rule score.';
    }

    if ($mlRisk < 30 && $aiClassKey === 'NORMAL') {
        $aiConversationMessages[] = sprintf(
            'My overall conclusion is that FortressAuth currently appears to be operating normally. The hybrid score is only %.1f out of 100, XGBoost sees normal behavior, and the rule engine has not found deterministic attack evidence.',
            $mlRisk
        );
        $aiConversationMessages[] = 'I recommend continuing normal monitoring. If request volume, failed logins, anomaly deviation, scanning behavior, or rule evidence rises, I will reassess the activity on the next protected request.';
    } elseif ($mlRisk < 50) {
        $aiConversationMessages[] = sprintf(
            'My overall conclusion is watch-level activity. The system is not reporting an immediate high-risk event, but the %.1f out of 100 hybrid score contains enough unusual behavior for continued observation.',
            $mlRisk
        );
        $aiConversationMessages[] = 'I recommend reviewing the newest audit events from this source and watching whether the anomaly score, failed authentication attempts, or deterministic rule evidence increases.';
    } elseif ($mlRisk < 70) {
        $aiConversationMessages[] = sprintf(
            'My overall conclusion is suspicious activity. The hybrid score has reached %.1f out of 100, so I would investigate the source and correlate this finding with Security Logs and Access Activity.',
            $mlRisk
        );
        $aiConversationMessages[] = 'I recommend checking the related authentication failures, request paths, rule detections, and session activity before deciding whether additional enforcement is necessary.';
    } else {
        $aiConversationMessages[] = sprintf(
            'My overall conclusion is a high-priority security finding. The hybrid risk score is %.1f out of 100 and the current activity deserves immediate review.',
            $mlRisk
        );
        $aiConversationMessages[] = 'I recommend opening the related threat and audit records now, validating the deterministic evidence, and using FortressAuth enforcement controls if the activity is confirmed as malicious.';
    }

    $aiConversationMessages[] = sprintf(
        'This report is based on the latest analysis completed at %s. I will continue updating my findings as FortressAuth receives new protected requests.',
        $mlPredictionTime
    );

    $aiConversationMessages[] = 'One final note: I am an advisory security analyst. I can classify, compare, score, and explain what I find, but automatic ML blocking remains off so deterministic FortressAuth controls stay authoritative for enforcement.';
}


audit_log('ai_threat_intelligence_viewed uid=' . $userId);
?>
<!doctype html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#10071f">
    <title>FortressAuth — AI Defense</title>
    <link rel="stylesheet" href="/css/all.min.css">
    <link rel="stylesheet" href="/css/dashboard.css">
    <link rel="stylesheet" href="/css/ai_threat_intelligence.css">
<link rel="stylesheet" href="/css/pjax.css">
<script src="/js/fortress_pjax.js" defer></script>
</head>
<body class="command-page ai-intelligence-page">
<div class="ambient ambient-one" aria-hidden="true"></div>
<div class="ambient ambient-two" aria-hidden="true"></div>
<main class="command-shell">
<?php require __DIR__ . '/partials/command_header.php'; ?>

<section class="page-hero compact-page-hero ai-page-hero">
    <div>
        <span class="eyebrow">HYBRID MACHINE LEARNING</span>
        <h1>AI Threat Intelligence</h1>
        <p>FortressAuth combines XGBoost attack classification, Autoencoder behavioral anomaly detection, and the deterministic rule engine into one explainable, non-blocking security risk assessment.</p>
    </div>
    <div class="page-hero-icon"><i class="fa-solid fa-brain"></i></div>
</section>

<section class="posture-summary-strip ai-summary-strip">
    <div><span>ML service</span><strong><?= $mlEnabled ? 'ENABLED' : 'DISABLED' ?></strong></div>
    <div><span>Hybrid risk</span><strong><?= number_format($mlRisk, 1) ?>/100</strong></div>
    <div><span>Detected behavior</span><strong><?= e(str_replace('_', ' ', $mlClass)) ?></strong></div>
    <div><span>AI response mode</span><strong>ADVISORY</strong></div>
</section>

<article class="panel request-defense-panel ai-live-analysis">
    <div class="panel-heading">
        <div>
            <span class="eyebrow">LIVE MODEL ANALYSIS</span>
            <h2>Intelligent Threat Analysis</h2>
            <p>Latest behavioral assessment for the most recently evaluated source. The AI layer assists detection and scoring; existing FortressAuth controls remain authoritative for blocking.</p>
        </div>
        <span class="panel-status"><i class="fa-solid fa-satellite-dish"></i> <?= e($mlSeverity) ?></span>
    </div>
    <div class="attack-grid threat-category-grid ai-metric-grid">
        <div class="attack-card"><span class="attack-icon"><i class="fa-solid fa-gauge-high"></i></span><div><strong><?= number_format($mlRisk, 1) ?>/100</strong><span>Hybrid risk score</span><small><?= e($mlSeverity) ?></small></div></div>
        <div class="attack-card"><span class="attack-icon"><i class="fa-solid fa-diagram-project"></i></span><div><strong><?= e(str_replace('_', ' ', $mlClass)) ?></strong><span>XGBoost classification</span><small><?= number_format($mlConfidence, 1) ?>% model confidence</small></div></div>
        <div class="attack-card"><span class="attack-icon"><i class="fa-solid fa-wave-square"></i></span><div><strong><?= number_format($mlAnomaly, 1) ?>%</strong><span>Autoencoder anomaly</span><small>Deviation from learned normal behavior</small></div></div>
        <div class="attack-card"><span class="attack-icon"><i class="fa-solid fa-shield-halved"></i></span><div><strong><?= number_format($mlRuleScore, 1) ?>/100</strong><span>Rule-engine signal</span><small>Deterministic FortressAuth evidence</small></div></div>
    </div>
    <div class="ai-analysis-meta">
        <span><i class="fa-solid fa-network-wired"></i> Source: <code><?= e($mlSourceIp) ?></code></span>
        <span><i class="fa-solid fa-clock"></i> Last analysis: <?= e($mlPredictionTime) ?></span>
        <span><i class="fa-solid fa-shield"></i> Automatic ML blocking: OFF</span>
    </div>
    <?php if ($mlIndicators): ?>
        <div class="ai-indicator-list">
            <?php foreach ($mlIndicators as $indicator): ?><span><i class="fa-solid fa-circle-exclamation"></i><?= e((string)$indicator) ?></span><?php endforeach; ?>
        </div>
    <?php elseif (!$mlEnabled): ?>
        <div class="panel-note"><i class="fa-solid fa-circle-info"></i> The AI service is currently disabled. Set <code>ML_SERVICE_ENABLED=true</code>, configure the private service URL/token, and start the ML service. Existing defenses continue working normally.</div>
    <?php else: ?>
        <div class="panel-note"><i class="fa-solid fa-circle-info"></i> The AI service is enabled. Use the system normally or run controlled security tests to populate the behavioral window and generate the first analysis.</div>
    <?php endif; ?>
</article>


<section class="panel fortress-ai-conversation-panel fortress-ai-analyst-panel">
    <div class="fortress-ai-analyst-shell">
        <div class="fortress-ai-analyst-hero">
            <div class="fortress-ai-analyst-visual">
                <div class="fortress-ai-analyst-orbit fortress-ai-analyst-orbit-one"></div>
                <div class="fortress-ai-analyst-orbit fortress-ai-analyst-orbit-two"></div>
                <div class="fortress-ai-analyst-glow"></div>
                <div class="fortress-ai-analyst-image-frame">
                    <img src="/images/ai.gif" alt="Animated FortressAuth AI security analyst" class="fortress-ai-analyst-image">
                </div>
                <span class="fortress-ai-analyst-selected-badge"><span></span> LIVE ANALYST</span>
            </div>

            <div class="fortress-ai-analyst-copy">
                <div class="fortress-ai-analyst-badges">
                    <span class="success"><i class="fa-solid fa-circle-check"></i> LIVE SECURITY ANALYST</span>
                    <span><i class="fa-solid fa-satellite-dish"></i> <?= $mlEnabled ? 'ML ENGINE ONLINE' : 'ML ENGINE OFFLINE' ?></span>
                </div>

                <h2>FortressAuth AI Analyst</h2>
                <p>
                    Synthesizes XGBoost behavior classification, Autoencoder baseline deviation, deterministic FortressAuth evidence, and the hybrid risk score into one conversational security report.
                </p>

                <div class="fortress-ai-analyst-tags">
                    <span>XGBoost</span>
                    <span>Autoencoder</span>
                    <span>Rule Engine</span>
                    <span>Hybrid Security Intelligence</span>
                </div>

                <div class="fortress-ai-analyst-detail-grid">
                    <div>
                        <span>Detected behavior</span>
                        <strong><?= e(str_replace('_', ' ', $mlClass)) ?></strong>
                    </div>
                    <div>
                        <span>Current source</span>
                        <strong><?= e($mlSourceIp) ?></strong>
                    </div>
                    <div>
                        <span>Response mode</span>
                        <strong>ADVISORY · ML BLOCKING OFF</strong>
                    </div>
                </div>
            </div>

            <div class="fortress-ai-analyst-metrics">
                <div class="fortress-ai-analyst-metric risk">
                    <span>HYBRID RISK</span>
                    <strong><?= number_format($mlRisk, 1) ?>/100</strong>
                    <small><?= e($mlSeverity) ?> security posture</small>
                </div>
                <div class="fortress-ai-analyst-metric classifier">
                    <span>XGBOOST CONFIDENCE</span>
                    <strong><?= number_format($mlConfidence, 1) ?>%</strong>
                    <small><?= e(str_replace('_', ' ', $mlClass)) ?> classification confidence</small>
                </div>
                <div class="fortress-ai-analyst-metric anomaly">
                    <span>ANOMALY DEVIATION</span>
                    <strong><?= number_format($mlAnomaly, 1) ?>%</strong>
                    <small>Distance from learned normal baseline</small>
                </div>
            </div>
        </div>

        <div class="fortress-ai-conversation-shell fortress-ai-conversation-shell-embedded">
            <div class="fortress-ai-conversation-topline">
                <div>
                    <span class="fortress-ai-conversation-kicker"><span></span> AI SECURITY CONVERSATION</span>
                    <p>Choose Automatic for continuous playback or Manual to advance through each live security finding.</p>
                </div>
                <span class="fortress-ai-playback-label">AUTO OR MANUAL PLAYBACK</span>
            </div>

            <div class="fortress-ai-chat fortress-ai-chat-embedded" id="fortress-ai-chat">
                <div class="fortress-ai-chat-compact-avatar" aria-hidden="true">
                    <span class="fortress-ai-chat-compact-online"></span>
                    <img src="/images/ai.gif" alt="">
                </div>

                <div class="fortress-ai-chat-main">
                    <div class="fortress-ai-chat-header">
                        <div class="fortress-ai-chat-identity">
                            <div>
                                <strong>FortressAuth AI Analyst</strong>
                                <span class="fortress-ai-live-chip">LIVE</span>
                            </div>
                            <small>Hybrid security intelligence assistant</small>
                        </div>

                        <div class="fortress-ai-chat-controls">
                            <div class="fortress-ai-mode-switch" role="group" aria-label="AI conversation playback mode">
                                <button type="button" class="fortress-ai-mode-button active" data-ai-mode="auto" aria-pressed="true">
                                    <i class="fa-solid fa-play"></i> Automatic
                                </button>
                                <button type="button" class="fortress-ai-mode-button" data-ai-mode="manual" aria-pressed="false">
                                    <i class="fa-solid fa-arrow-pointer"></i> Manual
                                </button>
                            </div>
                            <span class="fortress-ai-insight-count" id="fortress-ai-insight-count">Insight 0 of 0</span>
                        </div>
                    </div>

                    <div class="fortress-ai-speech" aria-live="polite" aria-atomic="true">
                        <div class="fortress-ai-thinking" id="fortress-ai-thinking" hidden>
                            <span>Analyzing security signals</span>
                            <span class="fortress-ai-thinking-dots" aria-hidden="true"><i></i><i></i><i></i></span>
                        </div>
                        <p id="fortress-ai-message"><span id="fortress-ai-visible-text"></span><span class="fortress-ai-caret" id="fortress-ai-caret" aria-hidden="true"></span></p>
                    </div>

                    <div class="fortress-ai-chat-footer">
                        <div class="fortress-ai-chat-status">
                            <span class="fortress-ai-status-dot" id="fortress-ai-status-dot"></span>
                            <span id="fortress-ai-status-text">Preparing the first security insight...</span>
                        </div>

                        <div class="fortress-ai-chat-actions">
                            <button type="button" class="fortress-ai-next-button" id="fortress-ai-next" hidden disabled>
                                <span>Next insight</span>
                                <i class="fa-solid fa-forward-step"></i>
                            </button>

                            <div class="fortress-ai-progress" aria-hidden="true">
                                <span id="fortress-ai-progress-label">0%</span>
                                <div><i id="fortress-ai-progress-bar"></i></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="fortress-ai-conversation-note">
                <i class="fa-solid fa-shield-halved"></i>
                <span>Security interpretation only. Machine learning remains advisory; deterministic FortressAuth controls remain authoritative for enforcement.</span>
            </div>
        </div>
    </div>
</section>

<div id="fortress-ai-insights" hidden aria-hidden="true">
    <?php foreach ($aiConversationMessages as $message): ?>
        <?php if (trim((string)$message) === '') continue; ?>
        <span data-ai-insight><?= e((string)$message) ?></span>
    <?php endforeach; ?>
</div>

<section class="panel fortress-defense-board-panel">
    <div class="panel-heading fortress-defense-board-heading">
        <div>
            <span class="eyebrow">DEFENSE INTELLIGENCE BOARD</span>
            <h2>Specialized Security Components</h2>
            <p>Each component has a different responsibility, so this board shows live roles and outputs instead of ranking unlike models against one another.</p>
        </div>
        <span class="panel-status"><i class="fa-solid fa-microchip"></i> 6 DEFENSE COMPONENTS</span>
    </div>

    <div class="fortress-defense-board-grid">
        <article class="fortress-defense-board-card fortress-defense-board-card-xgb">
            <div class="fortress-defense-board-card-top">
                <span class="fortress-defense-board-role">KNOWN BEHAVIOR</span>
                <span class="fortress-defense-board-state <?= $mlResult ? 'active' : 'waiting' ?>"><i class="fa-solid fa-circle"></i><?= $mlResult ? 'ACTIVE' : 'WAITING' ?></span>
            </div>
            <div class="fortress-defense-board-main">
                <div class="fortress-defense-board-avatar"><img src="/images/ai5.png" alt="XGBoost defense agent"></div>
                <div class="fortress-defense-board-copy">
                    <h3>XGBoost Classifier</h3>
                    <p>Recognizes learned attack and normal-behavior patterns from the current telemetry window.</p>
                    <div class="fortress-defense-board-tags"><span>Supervised ML</span><span>Behavior classifier</span></div>
                </div>
            </div>
            <div class="fortress-defense-board-metrics">
                <div><span>Classification</span><strong><?= e(str_replace('_', ' ', $mlClass)) ?></strong></div>
                <div><span>Confidence</span><strong><?= number_format($mlConfidence, 1) ?>%</strong></div>
                <div><span>Risk contribution</span><strong><?= number_format($mlXgbRisk, 1) ?>/100</strong></div>
            </div>
            <div class="fortress-defense-board-foot"><span>Known-pattern specialist</span><i class="fa-solid fa-diagram-project"></i></div>
        </article>

        <article class="fortress-defense-board-card fortress-defense-board-card-auto">
            <div class="fortress-defense-board-card-top">
                <span class="fortress-defense-board-role">UNKNOWN BEHAVIOR</span>
                <span class="fortress-defense-board-state <?= $mlResult ? 'active' : 'waiting' ?>"><i class="fa-solid fa-circle"></i><?= $mlResult ? 'ACTIVE' : 'WAITING' ?></span>
            </div>
            <div class="fortress-defense-board-main">
                <div class="fortress-defense-board-avatar"><img src="/images/ai6.png" alt="Autoencoder anomaly agent"></div>
                <div class="fortress-defense-board-copy">
                    <h3>Autoencoder Detector</h3>
                    <p>Measures how far current activity moves away from behavior learned as the normal baseline.</p>
                    <div class="fortress-defense-board-tags"><span>Anomaly detection</span><span>Baseline learning</span></div>
                </div>
            </div>
            <div class="fortress-defense-board-metrics">
                <div><span>Anomaly</span><strong><?= number_format($mlAnomaly, 1) ?>%</strong></div>
                <div><span>Interpretation</span><strong><?= $mlAnomaly >= 70 ? 'Strong' : ($mlAnomaly >= 40 ? 'Elevated' : 'Near baseline') ?></strong></div>
                <div><span>Baseline</span><strong>LEARNED NORMAL</strong></div>
            </div>
            <div class="fortress-defense-board-foot"><span>Unknown-pattern specialist</span><i class="fa-solid fa-wave-square"></i></div>
        </article>

        <article class="fortress-defense-board-card fortress-defense-board-card-rule">
            <div class="fortress-defense-board-card-top">
                <span class="fortress-defense-board-role">DETERMINISTIC EVIDENCE</span>
                <span class="fortress-defense-board-state enforced"><i class="fa-solid fa-circle-check"></i>ENFORCED</span>
            </div>
            <div class="fortress-defense-board-main">
                <div class="fortress-defense-board-avatar"><img src="/images/ai7.png" alt="Rule engine defense agent"></div>
                <div class="fortress-defense-board-copy">
                    <h3>Rule Engine</h3>
                    <p>Validates known FortressAuth attack signatures and remains authoritative for deterministic enforcement.</p>
                    <div class="fortress-defense-board-tags"><span>Known signatures</span><span>Authoritative controls</span></div>
                </div>
            </div>
            <div class="fortress-defense-board-metrics">
                <div><span>Rule signal</span><strong><?= number_format($mlRuleScore, 1) ?>/100</strong></div>
                <div><span>Indicators</span><strong><?= count($mlIndicators) ?></strong></div>
                <div><span>Enforcement</span><strong>ACTIVE</strong></div>
            </div>
            <div class="fortress-defense-board-foot"><span>Deterministic specialist</span><i class="fa-solid fa-shield-halved"></i></div>
        </article>

        <article class="fortress-defense-board-card fortress-defense-board-card-telemetry">
            <div class="fortress-defense-board-card-top">
                <span class="fortress-defense-board-role">BEHAVIOR WINDOW</span>
                <span class="fortress-defense-board-state <?= $mlEnabled ? 'active' : 'waiting' ?>"><i class="fa-solid fa-circle"></i><?= $mlEnabled ? 'STREAMING' : 'STANDBY' ?></span>
            </div>
            <div class="fortress-defense-board-main">
                <div class="fortress-defense-board-avatar"><img src="/images/ai4.png" alt="Telemetry defense agent"></div>
                <div class="fortress-defense-board-copy">
                    <h3>Telemetry Monitor</h3>
                    <p>Builds the non-sensitive numerical request and authentication window consumed by the ML service.</p>
                    <div class="fortress-defense-board-tags"><span>No secrets</span><span>20 features</span></div>
                </div>
            </div>
            <div class="fortress-defense-board-metrics">
                <div><span>Requests / 5m</span><strong><?= (int)($mlFeatures['requests_5m'] ?? 0) ?></strong></div>
                <div><span>Auth requests</span><strong><?= (int)($mlFeatures['auth_endpoint_requests_5m'] ?? 0) ?></strong></div>
                <div><span>Failed / 15m</span><strong><?= (int)($mlFeatures['failed_logins_15m'] ?? 0) ?></strong></div>
            </div>
            <div class="fortress-defense-board-foot"><span>Signal collection specialist</span><i class="fa-solid fa-satellite-dish"></i></div>
        </article>

        <article class="fortress-defense-board-card fortress-defense-board-card-hybrid">
            <div class="fortress-defense-board-card-top">
                <span class="fortress-defense-board-role">SIGNAL FUSION</span>
                <span class="fortress-defense-board-state <?= $mlResult ? 'active' : 'waiting' ?>"><i class="fa-solid fa-circle"></i><?= $mlResult ? 'ACTIVE' : 'WAITING' ?></span>
            </div>
            <div class="fortress-defense-board-main">
                <div class="fortress-defense-board-avatar"><img src="/images/ai1.png" alt="Hybrid risk defense core"></div>
                <div class="fortress-defense-board-copy">
                    <h3>Hybrid Risk Engine</h3>
                    <p>Fuses rule evidence, XGBoost classification, and Autoencoder deviation into one advisory risk score.</p>
                    <div class="fortress-defense-board-tags"><span>Signal fusion</span><span>Explainable score</span></div>
                </div>
            </div>
            <div class="fortress-defense-board-metrics">
                <div><span>Hybrid risk</span><strong><?= number_format($mlRisk, 1) ?>/100</strong></div>
                <div><span>Severity</span><strong><?= e($mlSeverity) ?></strong></div>
                <div><span>Response</span><strong>ADVISORY</strong></div>
            </div>
            <div class="fortress-defense-board-foot"><span>Risk-fusion specialist</span><i class="fa-solid fa-gauge-high"></i></div>
        </article>

        <article class="fortress-defense-board-card fortress-defense-board-card-shield">
            <div class="fortress-defense-board-card-top">
                <span class="fortress-defense-board-role">DEFENSE BOUNDARY</span>
                <span class="fortress-defense-board-state enforced"><i class="fa-solid fa-shield"></i>PROTECTED</span>
            </div>
            <div class="fortress-defense-board-main">
                <div class="fortress-defense-board-avatar"><img src="/images/ai8.png" alt="FortressAuth shield defense agent"></div>
                <div class="fortress-defense-board-copy">
                    <h3>FortressAuth Shield</h3>
                    <p>Keeps authentication, sessions, rate limits, and deterministic controls independent from ML availability.</p>
                    <div class="fortress-defense-board-tags"><span>Fail-safe</span><span>Authentication independent</span></div>
                </div>
            </div>
            <div class="fortress-defense-board-metrics">
                <div><span>ML blocking</span><strong>OFF</strong></div>
                <div><span>Auth dependency</span><strong>NONE</strong></div>
                <div><span>ML failure</span><strong>RULES CONTINUE</strong></div>
            </div>
            <div class="fortress-defense-board-foot"><span>Authoritative protection boundary</span><i class="fa-solid fa-lock"></i></div>
        </article>
    </div>
</section>

<section class="panel ai-coordination-panel">
    <div class="panel-heading">
        <div>
            <span class="eyebrow">COORDINATED DEFENSE</span>
            <h2>AI Defense Coordination</h2>
            <p>Animated view of the rule engine, XGBoost, and Autoencoder working together to evaluate current activity and reinforce FortressAuth without taking over authentication decisions.</p>
        </div>
        <span class="panel-status"><i class="fa-solid fa-shield-halved"></i> DEFENSE FLOW</span>
    </div>
    <div class="ai-coordination-grid">
        <div class="ai-flow-stage" aria-label="Animated AI defense workflow">
            <div class="ai-flow-node ai-flow-node-wide ai-flow-node-ingress">
                <span class="ai-node-kicker">Input stream</span>
                <strong>Incoming Activity</strong>
                <small>Request monitor, login attempts, QR checks, and rule-engine telemetry</small>
            </div>
            <div class="ai-flow-connector ai-flow-connector-down"></div>
            <div class="ai-flow-node ai-flow-node-rule">
                <span class="ai-node-kicker">Known threats</span>
                <strong>Rule Engine</strong>
                <small>Deterministic evidence · <?= number_format($mlRuleScore, 1) ?>/100</small>
            </div>
            <div class="ai-flow-node ai-flow-node-xgb">
                <span class="ai-node-kicker">Known behavior</span>
                <strong>XGBoost</strong>
                <small><?= e(str_replace('_', ' ', $mlClass)) ?> · <?= number_format($mlConfidence, 1) ?>% confidence</small>
            </div>
            <div class="ai-flow-node ai-flow-node-auto">
                <span class="ai-node-kicker">Unknown behavior</span>
                <strong>Autoencoder</strong>
                <small><?= number_format($mlAnomaly, 1) ?>% anomaly deviation</small>
            </div>
            <div class="ai-flow-connector ai-flow-connector-up"></div>
            <div class="ai-flow-node ai-flow-node-hybrid">
                <span class="ai-node-kicker">Threat fusion</span>
                <strong>Hybrid Risk Engine</strong>
                <small><?= number_format($mlRisk, 1) ?>/100 · <?= e($mlSeverity) ?></small>
            </div>
            <div class="ai-flow-node ai-flow-node-shield">
                <span class="ai-node-kicker">Defense posture</span>
                <strong>FortressAuth Shield</strong>
                <small>Advisory AI · existing controls remain authoritative</small>
            </div>
        </div>

        <div class="ai-coordination-feed">
            <div class="ai-feed-ticker">
                <span>Live coordination</span>
                <strong id="ai-coordination-rotator">Preparing behavioral analysis...</strong>
            </div>
            <div class="ai-feed-list">
                <div class="ai-feed-item" style="--feed-delay:0s">
                    <span class="ai-feed-dot"></span>
                    <div><strong>Request Monitor</strong><small>Building the current behavioral window from non-sensitive telemetry.</small></div>
                </div>
                <div class="ai-feed-item" style="--feed-delay:.7s">
                    <span class="ai-feed-dot"></span>
                    <div><strong>Rule Engine</strong><small>Existing FortressAuth protections contributed <?= number_format($mlRuleScore, 1) ?>/100 deterministic signal.</small></div>
                </div>
                <div class="ai-feed-item" style="--feed-delay:1.4s">
                    <span class="ai-feed-dot"></span>
                    <div><strong>XGBoost</strong><small>Current behavior classified as <?= e(str_replace('_', ' ', $mlClass)) ?> with <?= number_format($mlConfidence, 1) ?>% model confidence.</small></div>
                </div>
                <div class="ai-feed-item" style="--feed-delay:2.1s">
                    <span class="ai-feed-dot"></span>
                    <div><strong>Autoencoder</strong><small>Deviation from learned normal behavior is currently <?= number_format($mlAnomaly, 1) ?>%.</small></div>
                </div>
                <div class="ai-feed-item" style="--feed-delay:2.8s">
                    <span class="ai-feed-dot"></span>
                    <div><strong>Hybrid Engine</strong><small>Fused risk is <?= number_format($mlRisk, 1) ?>/100. Response mode remains advisory to avoid false lockouts.</small></div>
                </div>
            </div>
        </div>
    </div>
</section>

<section class="panel ai-agent-panel">
    <div class="panel-heading">
        <div>
            <span class="eyebrow">AGENT AI COLLABORATION</span>
            <h2>Autonomous Defense Agents</h2>
            <p>Visual simulation of specialized AI agents continuously exchanging signals, validating one another, and supporting FortressAuth defense decisions in real time.</p>
        </div>
        <span class="panel-status"><i class="fa-solid fa-robot"></i> AGENT MESH</span>
    </div>
    <div class="ai-agent-grid">
        <div class="ai-agent-scene" aria-label="Animated AI agent collaboration scene">
            <img src="/images/agentbg.png?v=20260813" alt="" class="ai-agent-scene-background" aria-hidden="true">
            <div class="ai-agent-orbit ai-agent-orbit-one"></div>
            <div class="ai-agent-orbit ai-agent-orbit-two"></div>
            <div class="ai-agent-node ai-agent-node-core">
                <span class="ai-agent-icon ai-agent-icon-core"><img class="ai-agent-robot-image" src="/images/ai1.png" alt="" aria-hidden="true"></span>
                <strong>FortressAuth Core</strong>
                <small>Defense state: <?= e($mlSeverity) ?></small>
            </div>

            <div class="ai-agent-link ai-agent-link-top"></div>
            <div class="ai-agent-link ai-agent-link-left"></div>
            <div class="ai-agent-link ai-agent-link-right"></div>
            <div class="ai-agent-link ai-agent-link-bottom"></div>

            <div class="ai-agent-node ai-agent-node-top">
                <span class="ai-agent-icon"><img class="ai-agent-robot-image" src="/images/ai4.png" alt="" aria-hidden="true"></span>
                <strong>Telemetry Agent</strong>
                <small>Behavior window active</small>
            </div>
            <div class="ai-agent-node ai-agent-node-left">
                <span class="ai-agent-icon"><img class="ai-agent-robot-image" src="/images/ai5.png" alt="" aria-hidden="true"></span>
                <strong>XGBoost Agent</strong>
                <small><?= e(str_replace('_', ' ', $mlClass)) ?></small>
            </div>
            <div class="ai-agent-node ai-agent-node-right">
                <span class="ai-agent-icon"><img class="ai-agent-robot-image" src="/images/ai6.png" alt="" aria-hidden="true"></span>
                <strong>Anomaly Agent</strong>
                <small><?= number_format($mlAnomaly, 1) ?>% deviation</small>
            </div>
            <div class="ai-agent-node ai-agent-node-bottom">
                <span class="ai-agent-icon"><img class="ai-agent-robot-image" src="/images/ai7.png" alt="" aria-hidden="true"></span>
                <strong>Rule Agent</strong>
                <small><?= number_format($mlRuleScore, 1) ?>/100 evidence</small>
            </div>

            <span class="ai-packet ai-packet-one"></span>
            <span class="ai-packet ai-packet-two"></span>
            <span class="ai-packet ai-packet-three"></span>
            <span class="ai-packet ai-packet-four"></span>
        </div>

        <div class="ai-agent-status-panel">
            <div class="ai-agent-status-card">
                <div class="ai-agent-status-head"><span class="ai-agent-mini-icon"><img class="ai-agent-robot-image" src="/images/ai4.png" alt="" aria-hidden="true"></span><strong>Telemetry Agent</strong></div>
                <p>Collects non-sensitive request, authentication, and QR telemetry before handing the behavioral window to the other agents.</p>
                <span class="ai-agent-badge">Streaming signals</span>
            </div>
            <div class="ai-agent-status-card">
                <div class="ai-agent-status-head"><span class="ai-agent-mini-icon"><img class="ai-agent-robot-image" src="/images/ai5.png" alt="" aria-hidden="true"></span><strong>XGBoost Agent</strong></div>
                <p>Classifies the current pattern as <strong><?= e(str_replace('_', ' ', $mlClass)) ?></strong> with <strong><?= number_format($mlConfidence, 1) ?>%</strong> confidence.</p>
                <span class="ai-agent-badge">Known-behavior specialist</span>
            </div>
            <div class="ai-agent-status-card">
                <div class="ai-agent-status-head"><span class="ai-agent-mini-icon"><img class="ai-agent-robot-image" src="/images/ai6.png" alt="" aria-hidden="true"></span><strong>Autoencoder Agent</strong></div>
                <p>Measures how far the latest activity diverges from the learned normal baseline, currently <strong><?= number_format($mlAnomaly, 1) ?>%</strong>.</p>
                <span class="ai-agent-badge">Unknown-behavior specialist</span>
            </div>
            <div class="ai-agent-status-card">
                <div class="ai-agent-status-head"><span class="ai-agent-mini-icon"><img class="ai-agent-robot-image" src="/images/ai7.png" alt="" aria-hidden="true"></span><strong>Rule Agent</strong></div>
                <p>Validates known FortressAuth evidence patterns and contributes <strong><?= number_format($mlRuleScore, 1) ?>/100</strong> deterministic signal.</p>
                <span class="ai-agent-badge">Deterministic enforcement</span>
            </div>
        </div>
    </div>
</section>

<section class="ai-model-grid">
    <article class="panel ai-model-card">
        <div class="panel-heading compact"><div><span class="eyebrow">KNOWN BEHAVIOR CLASSIFIER</span><h2>XGBoost</h2><p>Classifies behavioral telemetry into learned attack categories generated for the controlled FortressAuth project environment.</p></div><i class="fa-solid fa-diagram-project panel-symbol"></i></div>
        <div class="ai-model-stat"><span>Detected behavior</span><strong><?= e(str_replace('_', ' ', $mlClass)) ?></strong></div>
        <div class="ai-model-stat"><span>Model confidence</span><strong><?= number_format($mlConfidence, 1) ?>%</strong></div>
        <div class="ai-model-stat"><span>XGBoost risk contribution</span><strong><?= number_format($mlXgbRisk, 1) ?>/100</strong></div>
        <div class="ai-probability-list">
            <?php if (!$mlProbabilities): ?><div class="empty-state">No class probabilities are available yet.</div><?php else: foreach (array_slice($mlProbabilities, 0, 7, true) as $class => $probability): $pct=max(0,min(100,(float)$probability*100)); ?>
                <div class="ai-probability-row">
                    <div><span><?= e(str_replace('_', ' ', (string)$class)) ?></span><strong><?= number_format($pct, 1) ?>%</strong></div>
                    <div class="ai-probability-track"><span style="width:<?= number_format($pct, 2, '.', '') ?>%"></span></div>
                </div>
            <?php endforeach; endif; ?>
        </div>
    </article>

    <article class="panel ai-model-card">
        <div class="panel-heading compact"><div><span class="eyebrow">UNKNOWN BEHAVIOR DETECTOR</span><h2>Autoencoder</h2><p>Measures how far recent activity deviates from the normal behavioral patterns learned during model training.</p></div><i class="fa-solid fa-wave-square panel-symbol"></i></div>
        <div class="ai-anomaly-orb <?= $mlAnomaly >= 70 ? 'critical' : ($mlAnomaly >= 40 ? 'watch' : 'normal') ?>">
            <div><strong><?= number_format($mlAnomaly, 1) ?>%</strong><span>Anomaly score</span></div>
        </div>
        <div class="ai-model-stat"><span>Interpretation</span><strong><?= $mlAnomaly >= 70 ? 'Strong deviation' : ($mlAnomaly >= 40 ? 'Elevated deviation' : 'Near baseline') ?></strong></div>
        <div class="panel-note"><i class="fa-solid fa-circle-info"></i> Anomaly percentage measures deviation from the learned baseline. It is not a percentage probability that a person is an attacker.</div>
    </article>
</section>

<section class="ai-model-grid ai-runtime-grid">
    <article class="panel configuration-panel">
        <div class="panel-heading compact"><div><span class="eyebrow">RUNTIME SAFETY</span><h2>AI Defense Boundaries</h2><p>The machine-learning layer is deliberately isolated from authentication decisions.</p></div><i class="fa-solid fa-shield-halved panel-symbol"></i></div>
        <div class="configuration-grid">
            <div><i class="fa-solid fa-toggle-on"></i><span>ML service state</span><strong><?= $mlEnabled ? 'ENABLED' : 'DISABLED' ?></strong></div>
            <div><i class="fa-solid fa-ban"></i><span>Automatic ML blocking</span><strong>OFF</strong></div>
            <div><i class="fa-solid fa-key"></i><span>Authentication dependency</span><strong>NONE</strong></div>
            <div><i class="fa-solid fa-user-secret"></i><span>Sensitive values sent</span><strong>NONE</strong></div>
            <div><i class="fa-solid fa-lock"></i><span>Service authentication</span><strong>PRIVATE TOKEN</strong></div>
            <div><i class="fa-solid fa-shield"></i><span>Failure behavior</span><strong>RULES CONTINUE</strong></div>
        </div>
    </article>

    <article class="panel ai-feature-panel">
        <div class="panel-heading compact"><div><span class="eyebrow">BEHAVIORAL WINDOW</span><h2>Current ML Features</h2><p>Only non-sensitive numerical behavior is evaluated. Passwords, QR values, cookies, session IDs, CSRF tokens, and authorization headers are excluded.</p></div><i class="fa-solid fa-chart-simple panel-symbol"></i></div>
        <div class="ai-feature-grid">
            <?php if (!$mlFeatures): ?><div class="empty-state">No behavioral feature window is available yet.</div><?php else: foreach ($featureLabels as $key => $label): if (!array_key_exists($key, $mlFeatures)) continue; $value=$mlFeatures[$key]; ?>
                <div><span><?= e($label) ?></span><strong><?= is_float($value) ? number_format((float)$value, 2) : e((string)$value) ?></strong></div>
            <?php endforeach; endif; ?>
        </div>
    </article>
</section>

<article class="panel data-panel ai-history-panel">
    <div class="panel-heading filter-heading">
        <div><span class="eyebrow">MODEL HISTORY</span><h2>Recent AI Analyses</h2><p>Latest non-blocking hybrid assessments recorded by FortressAuth.</p></div>
    </div>
    <div class="responsive-table-wrap">
        <table class="security-table">
            <thead><tr><th>Timestamp</th><th>Source</th><th>Classification</th><th>Confidence</th><th>Anomaly</th><th>Hybrid risk</th><th>Severity</th></tr></thead>
            <tbody>
            <?php if (!$predictionHistory): ?>
                <tr><td colspan="7" class="table-empty">No AI analyses have been recorded yet.</td></tr>
            <?php else: foreach ($predictionHistory as $row): $result=(array)$row['result']; ?>
                <tr>
                    <td><?= e(date('Y-m-d H:i:s', (int)($row['ts'] ?? 0))) ?></td>
                    <td><code><?= e((string)($row['ip'] ?? 'unknown')) ?></code></td>
                    <td><?= e(str_replace('_', ' ', (string)($result['classification'] ?? 'UNKNOWN'))) ?></td>
                    <td><?= number_format(((float)($result['confidence'] ?? 0))*100, 1) ?>%</td>
                    <td><?= number_format(((float)($result['anomaly_score'] ?? 0))*100, 1) ?>%</td>
                    <td><strong><?= number_format((float)($result['risk_score'] ?? 0), 1) ?>/100</strong></td>
                    <td><span class="status-pill <?= in_array((string)($result['severity'] ?? ''), ['HIGH','CRITICAL'], true) ? 'status-rejected' : 'status-passed' ?>"><?= e((string)($result['severity'] ?? 'UNKNOWN')) ?></span></td>
                </tr>
            <?php endforeach; endif; ?>
            </tbody>
        </table>
    </div>
</article>

<footer class="command-footer"><span><i class="fa-solid fa-brain"></i> FortressAuth hybrid machine-learning defense</span><span>Advisory intelligence · deterministic defenses remain enforced</span></footer>

</div><!-- /.fortress-main-column -->
</main>
<script src="/js/ai_threat_intelligence.js"></script>
<script src="/js/dashboard.js"></script>
<script src="/js/auto_logout.js"></script>
</body>
</html>
