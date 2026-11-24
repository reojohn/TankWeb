/* IT113 Rubric A case-study panel.
   Reads only the existing immutable synthetic test evidence and saved metrics.
   No model calls, no database writes, no global event interception. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  if (!byId('rubric-a-lab')) return;
  const esc = v => String(v ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const name = s => String(s || '').replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
  const contexts = Object.freeze({
    NORMAL: {label:'Baseline behavior', risk:'No specific threat pattern is established by this example.', weakness:'No weakness can be inferred from a normal synthetic case.', features:['requests_1m','failed_logins_15m','suspicious_requests_15m','csrf_failures_15m']},
    BRUTE_FORCE: {label:'Repeated authentication attempts',risk:'High-volume failed sign-ins could lead to account compromise if guessing protections are weak.',weakness:'Review password-guessing rate limits, account lockout safeguards and authentication alerts.',features:['failed_logins_5m','failed_logins_15m','auth_endpoint_requests_5m','auth_rejections_15m']},
    CREDENTIAL_STUFFING: {label:'Multi-account login failures',risk:'Failed authentication across multiple usernames may signal reuse of exposed credentials.',weakness:'Review credential-abuse detection, throttling, breached-password screening and MFA.',features:['unique_usernames_15m','failed_logins_15m','auth_endpoint_requests_5m','successful_logins_15m']},
    RECONNAISSANCE: {label:'Scanning and discovery behavior',risk:'Requests probing many paths may indicate exploration of exposed services.',weakness:'Review exposed administrative endpoints, path monitoring and service hardening.',features:['unique_paths_5m','sensitive_path_probes_15m','scanner_events_15m','requests_5m']},
    WEB_ATTACK: {label:'Suspicious web request behavior',risk:'Unusual or rejected web requests may indicate attempts to exploit application input handling.',weakness:'Review server-side validation, query parameterization, application logs and WAF rules.',features:['suspicious_requests_15m','csrf_failures_15m','method_anomalies_15m','sensitive_path_probes_15m']},
    MFA_ABUSE: {label:'Repeated verification failures',risk:'Repeated second-factor failures may indicate account takeover attempts or prompt abuse.',weakness:'Review MFA attempt throttling, challenge expiration and user alerts.',features:['qr_failures_15m','failed_logins_15m','auth_rejections_15m','ban_events_15m']},
    SESSION_ABUSE: {label:'Session-related suspicious behavior',risk:'Unusual session or CSRF-related indicators may signal misuse of authenticated sessions.',weakness:'Review session renewal, secure cookies, CSRF checks and revocation handling.',features:['csrf_failures_15m','method_anomalies_15m','ua_changes_15m','suspicious_requests_15m']}
  });
  let cases = [], summary = null, selected = null;
  const safeNumber = x => typeof x === 'number' && Number.isFinite(x);
  function checkRecord(features) {
    const failed = [];
    const count = k => features[k];
    const nested = [
      ['requests_1m','requests_5m'],
      ['unique_paths_5m','requests_5m'],
      ['auth_endpoint_requests_5m','requests_5m'],
      ['failed_logins_5m','auth_endpoint_requests_5m'],
      ['failed_logins_5m','failed_logins_15m']
    ];
    for (const [a,b] of nested) if (safeNumber(count(a)) && safeNumber(count(b)) && count(a)>count(b)) failed.push(`${a} > ${b}`);
    for (const [k,v] of Object.entries(features)) if (!safeNumber(v)) failed.push(`${k}: non-finite value`);
    if (safeNumber(count('post_ratio_5m')) && (count('post_ratio_5m')<0 || count('post_ratio_5m')>1)) failed.push('post_ratio_5m outside 0–1');
    return failed;
  }
  function proof() {
    const d = summary.dataset;
    const splits = ['train','validation','test'];
    const rows = splits.map(split => {
      const n = split === 'train' ? d.training_rows : split === 'validation' ? d.validation_rows : d.test_rows;
      const counts = d.class_counts?.[split] || {};
      const invariant = d.data_quality_invariant_violations?.[split] || {};
      const violations = Object.values(invariant).reduce((a,b) => a+(Number(b)||0),0);
      return `<div class="rubric-a-proof-cell"><small>${esc(name(split))} split</small><strong>${Number(n).toLocaleString('en-US')} rows</strong><span>${Object.keys(counts).length} classes · ${violations} reported invariant violations</span></div>`;
    }).join('');
    byId('rubric-a-dataset-proof').innerHTML = rows;
  }
  function render() {
    selected = cases.find(x => x.id === byId('rubric-a-case').value) || null;
    byId('rubric-a-download').disabled = !selected;
    if (!selected) { byId('rubric-a-inspection').textContent='Choose an example to cross-check.'; return; }
    const c=selected, f=c.features, ctx=contexts[c.true_label];
    const valid = c.correct === (c.true_label===c.predicted_label);
    const issues = checkRecord(f);
    const featureList = ctx.features.filter(k => Object.prototype.hasOwnProperty.call(f,k));
    byId('rubric-a-inspection').innerHTML = `
      <div class="rubric-a-status ${c.correct?'rubric-a-correct':'rubric-a-mismatch'}"><strong>${c.correct?'Prediction matched synthetic label':'Prediction differed from synthetic label'}</strong><span>${c.correct?'Agreement on this single saved example.':'An observed classification error; it must not be concealed.'}</span></div>
      <div class="rubric-a-summary">
        <div><small>TRUE SYNTHETIC LABEL</small><b>${esc(name(c.true_label))}</b></div>
        <div><small>MODEL PREDICTION</small><b>${esc(name(c.predicted_label))}</b></div>
        <div><small>MODEL CONFIDENCE</small><b>${safeNumber(c.confidence)?(100*c.confidence).toFixed(2)+'%':'Unavailable'}</b></div>
        <div><small>ANOMALY FLAG</small><b>${c.anomaly===true?'Yes':c.anomaly===false?'No':'Not recorded'}</b></div>
      </div>
      <div class="rubric-a-case-grid">
        <section><h3>Security interpretation</h3><p><strong>${esc(ctx.label)}.</strong> ${esc(ctx.risk)}</p><h4>Potential control to assess</h4><p>${esc(ctx.weakness)}</p><p class="hint">Context is tied to the known synthetic test label for teaching. It is not a causal attribution or a confirmed exploitable weakness.</p></section>
        <section><h3>Observed numeric evidence</h3><div class="rubric-a-feature-list">${featureList.map(k=>`<div><code>${esc(k)}</code><strong>${esc(f[k])}</strong></div>`).join('')}</div><p class="hint">These values are copied from the saved example. Highlighting them does not mean the model used them causally to decide its class.</p></section>
      </div>
      <section class="rubric-a-crosscheck"><h3>Validation and cross-checking</h3>
        <p><strong>Ground truth comparison:</strong> ${c.correct?'Match':'Mismatch'} · <strong>Saved correctness field:</strong> ${valid?'Internally consistent':'Inconsistent with prediction/label comparison'} · <strong>Numeric quality spot-check:</strong> ${issues.length?'Issues detected: '+esc(issues.join('; ')):'Passed the displayed-feature checks'}</p>
        <p><strong>Method:</strong> Compare the held-out synthetic label with the saved model prediction, inspect selected feature values, and check basic numeric invariants. ${c.correct?'One correct example is not a population-level accuracy estimate.':'A high confidence score, if present, does not make an incorrect prediction correct.'}</p>
        <p class="hint">The source's complete dataset-level invariant results appear above. This record-level spot-check covers only selected constraints, not the full training pipeline.</p>
      </section>`;
  }
  function exportCase(){
    if (!selected || !summary) return;
    const ctx = contexts[selected.true_label];
    const payload = {
      study: 'IT113 Rubric A — held-out synthetic case assessment',
      source: 'Bundled model_summary.json and evidence.json (precomputed test predictions)',
      generated_at: new Date().toISOString(),
      synthetic: true, verified_incident: false, confirmed_vulnerability: false,
      example_id: selected.id, true_label: selected.true_label,
      predicted_label: selected.predicted_label, prediction_matches_label: selected.true_label===selected.predicted_label,
      saved_correct_field: selected.correct, confidence: selected.confidence, anomaly_flag: selected.anomaly,
      features: selected.features, feature_spotcheck_issues: checkRecord(selected.features),
      security_context: ctx.label, risk_interpretation: ctx.risk,
      potential_controls_to_review: ctx.weakness,
      test_set_rows: summary.dataset.test_rows,
      limitations: ['Computer-generated labels and signals; not real-world incident validation.',
        'Selected signals are not a causal model explanation or independently verified vulnerability.',
        'Precomputed inference record; choosing it does not rerun or publish the model.']
    };
    const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));
    const link=document.createElement('a'); link.href=url;link.download='it113-rubric-a-case-'+selected.id+'.json';
    document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1500);
  }
  byId('rubric-a-case').addEventListener('change',render);
  byId('rubric-a-download').addEventListener('click',exportCase);
  Promise.all([
    fetch('/assessment/evidence.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Evidence unavailable');return r.json();}),
    fetch('/assessment/model_summary.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Model summary unavailable');return r.json();})
  ]).then(([ev,m])=>{
    if (!Array.isArray(ev.examples) || !m.dataset || !Array.isArray(m.dataset.features)) throw Error('Evidence schema unsupported');
    const expectedFeatures=new Set(m.dataset.features);
    cases=ev.examples.filter(x=>contexts[x.true_label] && contexts[x.predicted_label] && typeof x.id==='string' && typeof x.correct==='boolean' && x.features &&
      Object.keys(x.features).length===expectedFeatures.size && Object.keys(x.features).every(k=>expectedFeatures.has(k) && safeNumber(x.features[k])));
    if (!cases.length) throw Error('No valid synthetic examples');
    summary=m;proof();
    byId('rubric-a-case').innerHTML=cases.map(x=>`<option value="${esc(x.id)}">${esc(name(x.true_label))} · ${x.correct?'matched':'misclassified'} · ${esc(x.id)}</option>`).join('');
    render();
  }).catch(err=>{
    byId('rubric-a-dataset-proof').textContent='Saved dataset evidence is currently unavailable.';
    byId('rubric-a-case').innerHTML='<option value="">Cannot load examples</option>';
    byId('rubric-a-inspection').textContent='No assessment was generated. '+err.message;
  });
})();
