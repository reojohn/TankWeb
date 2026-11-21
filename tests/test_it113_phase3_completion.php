<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/it113_threat_guidance.php';

function check(bool $condition, string $message): void { if (!$condition) throw new RuntimeException($message); }
$classes = ['NORMAL','BRUTE_FORCE','CREDENTIAL_STUFFING','RECONNAISSANCE','WEB_ATTACK','MFA_ABUSE','SESSION_ABUSE'];
foreach ($classes as $class) {
    $profile = fortress_it113_class_guidance($class);
    check($profile['label'] !== '' && $profile['validation'] !== '' && $profile['mitigation'] !== '', $class . ' guidance missing');
}
check(fortress_it113_class_guidance('untrusted')['label'] === 'Unclassified model output', 'Unknown class fallback missing');
check(fortress_it113_event_guidance('sensitive_path_probe')['group'] === 'Reconnaissance', 'Recon mapping failed');
check(fortress_it113_event_guidance('password_factor_failed')['priority'] === 'Review', 'Single login failure should not be severe');
check(fortress_it113_event_guidance('made_up_event')['group'] === 'Security event', 'Unknown event fallback missing');
$sample = fortress_it113_prediction_summary([
    'ip'=>'127.0.0.1', 'ts'=>1730000000,
    'result'=>['classification'=>'BRUTE_FORCE','severity'=>'HIGH','enforcement_action'=>'OBSERVE','confidence'=>1.5,'risk_score'=>101,
        'trace_id'=>'123abc','model_version'=>'deadbeef12345678','indicator_evidence'=>[['description'=>'Repeated failed logins']]],
    'evidence'=>['request_source'=>'db','security_event_source'=>'audit','window_truncated'=>true],
]);
check($sample['label'] === 'Brute force', 'Class profile not applied');
check($sample['confidence'] === 1.0 && $sample['risk'] === 100.0, 'Display bounds not clamped');
check($sample['trace'] === '123abc' && $sample['window_truncated'] === true, 'Provenance incomplete');
$unknown = fortress_it113_prediction_summary(['result'=>['classification'=>'made_up','severity'=>'UNTRUSTED','enforcement_action'=>'ATTACK']]);
check($unknown['severity'] === 'UNKNOWN' && $unknown['action'] === 'OTHER', 'Unknown result display should be constrained');
echo 'PASS: threat guidance and prediction display checks (' . (count($classes) + 7) . " assertions)\n";
