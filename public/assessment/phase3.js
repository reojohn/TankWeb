/* IT113 Phase 3: read-only academic insights. No private API or database access. */
'use strict';
(() => {
  const el = id => document.getElementById(id);
  const escapeHTML = value => String(value == null ? '—' : value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const number = value => Number(value).toLocaleString('en-US');
  const percent = value => `${(Number(value) * 100).toFixed(2)}%`;
  const title = value => String(value).replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, ch => ch.toUpperCase()).replace(/\bMfa\b/g,'MFA');
  const fact = (name, value, note) => `<div class="metric"><span class="metric-label">${escapeHTML(name)}</span><strong class="metric-value">${escapeHTML(value)}</strong><small>${escapeHTML(note)}</small></div>`;
  const link = (name, view) => `<button type="button" class="text-action" data-go-to="${escapeHTML(view)}">${escapeHTML(name)} ↗</button>`;

  const featureGroups = [
    { label:'Request velocity & navigation', note:'Frequency and breadth of HTTP activity', items:['requests_1m','requests_5m','unique_paths_5m','post_ratio_5m','avg_request_interval_5m'] },
    { label:'Authentication pressure', note:'Login-related behavior, not credentials or passwords', items:['auth_endpoint_requests_5m','failed_logins_5m','failed_logins_15m','unique_usernames_15m','successful_logins_15m','qr_failures_15m'] },
    { label:'Application security indicators', note:'Request-policy and sensitive-route evidence', items:['sensitive_path_probes_15m','suspicious_requests_15m','scanner_events_15m','csrf_failures_15m','method_anomalies_15m','auth_rejections_15m','ban_events_15m'] },
    { label:'Behavior context', note:'Changes in client behavior and observation time', items:['ua_changes_15m','off_hours'] },
  ];
  const featureHints = {
    requests_1m:'HTTP requests within one minute', requests_5m:'HTTP requests within five minutes', unique_paths_5m:'Distinct paths visited in five minutes', post_ratio_5m:'Fraction of five-minute requests using POST', avg_request_interval_5m:'Average gap between requests, in seconds',
    auth_endpoint_requests_5m:'Requests to authentication endpoints', failed_logins_5m:'Password failures over five minutes', failed_logins_15m:'Password failures over fifteen minutes', unique_usernames_15m:'Distinct attempted usernames', successful_logins_15m:'Successful password sign-ins', qr_failures_15m:'Failed Personal ID or second-factor checks',
    sensitive_path_probes_15m:'Probes of restricted paths', suspicious_requests_15m:'Flagged request patterns', scanner_events_15m:'Detected scanner-style indicators', csrf_failures_15m:'Rejected CSRF validation events', method_anomalies_15m:'Unexpected HTTP methods', auth_rejections_15m:'Denied protected-route accesses', ban_events_15m:'Recorded temporary block events', ua_changes_15m:'Changes in user-agent fingerprint', off_hours:'Binary off-hours flag',
  };
  // Mirrors threshold indicator descriptions in ml-service/app.py, not XGBoost feature attribution.
  const indicatorRules = [
    ['failed_logins_5m',4,'Elevated failed-password frequency'],['failed_logins_15m',8,'Repeated authentication failures'],
    ['unique_usernames_15m',4,'Multiple usernames attempted'],['qr_failures_15m',3,'Repeated Personal ID failures'],
    ['sensitive_path_probes_15m',1,'Sensitive-resource probing'],['suspicious_requests_15m',2,'Suspicious request patterns'],
    ['scanner_events_15m',1,'Scanner indicators'],['csrf_failures_15m',1,'CSRF validation failures'],
    ['auth_rejections_15m',3,'Protected-resource rejections'],['ua_changes_15m',2,'User-agent changes'],
    ['unique_paths_5m',12,'Broad endpoint enumeration'],['requests_1m',12,'High short-window request rate'],
  ];
  const responseCategories = {
    NORMAL:{level:'Baseline',review:'No enforcement. Check unusual deviations against historical baselines and document benign explanations.',phase:'Monitor'},
    BRUTE_FORCE:{level:'High review',review:'Confirm authentication failure counts, repeated source behavior and legitimate user impact before any block.',phase:'Detect · Contain'},
    CREDENTIAL_STUFFING:{level:'High review',review:'Correlate attempts across accounts and check for account takeover, using privacy-preserving audit signals.',phase:'Detect · Contain'},
    RECONNAISSANCE:{level:'Review',review:'Cross-check targeted paths and scanner patterns; scanning alone does not prove an exploit.',phase:'Analyze'},
    WEB_ATTACK:{level:'High review',review:'Review sanitized application logs and validate the suspected weakness without assuming exploit success.',phase:'Analyze · Contain'},
    MFA_ABUSE:{level:'High review',review:'Verify repeated second-factor attempts and challenge lifecycles without exposing secrets.',phase:'Detect · Contain'},
    SESSION_ABUSE:{level:'High review',review:'Review signed-in session anomalies, CSRF rejects and session expiry using authorized logs.',phase:'Analyze · Contain'},
  };
  const statuses = (items, label) => items.map(item => `<div class="slim-row"><span>${escapeHTML(title(item))}</span><strong>${escapeHTML(label)}</strong></div>`).join('');

  function renderDataset(model) {
    const d = model.dataset;
    const groupTarget = el('phase3-feature-groups');
    groupTarget.innerHTML = featureGroups.map(group => `<article class="feature-group"><div><h3>${escapeHTML(group.label)}</h3><p>${escapeHTML(group.note)}</p></div><div class="feature-meaning-list">${group.items.map(item=>`<div><code>${escapeHTML(item)}</code><span>${escapeHTML(featureHints[item] || '')}</span></div>`).join('')}</div></article>`).join('');
    const target = el('phase3-split-comparison');
    target.innerHTML = `<h3 class="subheading">Independent dataset splits</h3><div class="split-rail"><span style="flex:${d.training_rows}">Train ${number(d.training_rows)}</span><span style="flex:${d.validation_rows}">Validation ${number(d.validation_rows)}</span><span style="flex:${d.test_rows}">Test ${number(d.test_rows)}</span></div><p class="hint">Training fits the model; validation sets the anomaly threshold; the test set is reserved for final evaluation. Seeds and per-class counts are recorded in the downloaded metrics JSON.</p>`;
  }
  function renderEvaluation(model) {
    const d=model.dataset, x=model.xgboost, a=model.autoencoder;
    const mistakes = [];
    let correct = 0, total = 0;
    x.confusion_matrix.forEach((row,i)=>row.forEach((val,j)=>{total+=val;if(i===j)correct+=val;else if(val>0)mistakes.push({actual:d.classes[i],pred:d.classes[j],count:val});}));
    mistakes.sort((a,b)=>b.count-a.count);
    const byClass = x.confusion_matrix.map((row,i)=>({name:d.classes[i],wrong:row.reduce((sum,v)=>sum+v,0)-row[i],count:row.reduce((sum,v)=>sum+v,0)})).sort((a,b)=>b.wrong-a.wrong);
    el('phase3-error-analysis').innerHTML = `<div class="error-total"><strong>${number(total-correct)}</strong><span>Incorrect classifications among ${number(total)} held-out records (${percent((total-correct)/total)} error rate)</span></div><h3 class="subheading">Most frequent confusion pairs</h3>${mistakes.slice(0,5).map(row=>`<div class="slim-row"><span>${escapeHTML(title(row.actual))} <b class="arrow-sep">→</b> ${escapeHTML(title(row.pred))}</span><strong>${number(row.count)}</strong></div>`).join('')}<p class="hint">The model may confuse behavior categories sharing features. Misclassification examples are available in Validation Examples.</p>${link('Inspect recorded errors','examples')}`;
    el('phase3-evaluation-protocol').innerHTML = `<div class="protocol-steps"><div><b>01</b><span>Train XGBoost on ${number(d.training_rows)} synthetic labeled records</span></div><div><b>02</b><span>Calibrate autoencoder on normal validation observations (${number(a.validation_normal_rows)})</span></div><div><b>03</b><span>Evaluate both components on a separate ${number(d.test_rows)}-record test split</span></div><div><b>04</b><span>Analyze false positives, false negatives, error pairs and limits</span></div></div><div class="metadata-micro">Highest misclassification count by true class: <strong>${escapeHTML(title(byClass[0].name))}</strong> (${number(byClass[0].wrong)} of ${number(byClass[0].count)})</div>`;
    document.querySelectorAll('#confusion-matrix tbody td').forEach(td=>{
      if (!td.classList.contains('diagonal')) td.classList.add('misclass-cell');
      td.title = td.classList.contains('diagonal')?'Correctly predicted examples':'Incorrectly predicted examples';
    });
  }
  function pipeline(model) {
    const f=model.risk_fusion;
    const steps=[
      ['01','Behavior input','20 engineered numeric features. The public replay uses synthetic held-out test records.'],
      ['02','XGBoost classifier','Predicts one of seven known behavior categories and a class confidence.'],
      ['03','Autoencoder','Reconstructs features to detect deviation from the learned normal baseline.'],
      ['04','Rule engine','Evaluates approved synthetic numeric features against deterministic thresholds in controlled live assessments.'],
    ];
    el('phase3-pipeline').innerHTML=steps.map(step=>`<div class="pipeline-step"><small>${step[0]} / SIGNAL</small><h3>${step[1]}</h3><p>${step[2]}</p></div>`).join('');
    el('phase3-fusion-note').innerHTML=`<span>HYBRID RISK FORMULA</span><strong>${Math.round(f.rule_weight*100)}% rules + ${Math.round(f.xgboost_weight*100)}% classifier risk + ${Math.round(f.autoencoder_weight*100)}% anomaly</strong><small>Risk fusion is used for controlled live synthetic predictions. Anomaly review uses the stored normalized score above 40% (error divided by 2.5 times the calibrated threshold). Precomputed Phase 1 test examples do not contain deterministic rule scores, so this page does not fabricate their hybrid risk or enforcement actions.</small>`;
  }
  function renderDefense(model, evidence, manifest){
    const d=model.dataset,a=model.autoencoder;
    el('phase3-defense-metrics').innerHTML=fact('SAVED MODEL VERSION',manifest.classifier_autoencoder_version,'SHA-256 fingerprint prefix')+fact('FEATURE SIGNALS',String(d.features.length),'Strictly numeric input')+fact('ANOMALY THRESHOLD',a.threshold_p99.toFixed(4),'Calibrated on validation normals')+fact('TEST CASES',String(evidence.examples.length),'Selected labeled synthetic records');
    pipeline(model);
    const chooser=el('phase3-case-select');
    chooser.innerHTML=evidence.examples.map((item,i)=>`<option value="${i}">${escapeHTML(title(item.true_label))} — ${item.correct?'Correct':'Misclassified'}</option>`).join('');
    function selectCase(index){
      const c=evidence.examples[index];if(!c)return;
      const indicators=indicatorRules.filter(([k,threshold])=>Number(c.features[k])>=threshold).map(([name,threshold,explanation])=>({name,threshold,explanation,observed:Number(c.features[name])})).sort((a,b)=>b.observed/b.threshold-a.observed/a.threshold).slice(0,5);
      const anomalySignal=Number(c.reconstruction_error)>a.threshold_p99;
      el('phase3-case-analysis').innerHTML=`<div class="case-pill-row"><span class="state-pill ${c.correct?'state-ok':'state-warn'}">${c.correct?'Correct classification':'Misclassification recorded'}</span><span class="state-pill">${anomalySignal?'Anomaly detected':'Within anomaly threshold'}</span></div><div class="case-hero"><span>Recorded XGBoost decision</span><strong>${escapeHTML(title(c.predicted_label))}</strong><p>True label: <b>${escapeHTML(title(c.true_label))}</b></p></div><div class="case-numbers"><div><small>Model confidence</small><b>${percent(c.confidence)}</b></div><div><small>Reconstruction error</small><b>${Number(c.reconstruction_error).toFixed(3)}</b></div></div><p class="hint">This is precomputed inference from a single test sample. Neither this confidence value nor the anomaly status proves an actual attack.</p>${link('See complete input vector','examples')}`;
      el('phase3-evidence-analysis').innerHTML=`<div class="evidence-source"><small>EVIDENCE ORIGIN</small><strong>Independent synthetic test split</strong><span>Sample: ${escapeHTML(c.id)} · model ${escapeHTML(manifest.classifier_autoencoder_version)}</span></div><h3 class="subheading">Threshold indicators in this sample</h3>${indicators.length?indicators.map(item=>`<div class="signal-row"><div><b>${escapeHTML(item.explanation)}</b><small>${escapeHTML(item.name)}</small></div><span>${number(item.observed)} / ${number(item.threshold)}</span></div>`).join(''):'<p class="hint">No indicator rule crossed its static threshold in this saved example.</p>'}<div class="notice evidence-disclaimer"><strong>Interpretation boundary</strong><span>These rules flag noteworthy feature values and are not SHAP values, causal explanations, or the model’s internal decision path. Live synthetic assessments provide trace IDs; private operational request/event identifiers are not exposed.</span></div>`;
    }
    chooser.addEventListener('change',()=>selectCase(Number(chooser.value)));
    selectCase(0);
  }
  function renderMitigationFilters(){
    const holder=el('phase3-mitigation-filters');
    const categories=Object.keys(responseCategories);
    const filters=['ALL',...categories];
    holder.innerHTML=filters.map((v,i)=>`<button type="button" data-filter="${v}" class="filter-button${i===0?' active':''}" aria-pressed="${i===0}">${escapeHTML(v==='ALL'?'All categories':title(v))}</button>`).join('');
    document.querySelectorAll('.mitigation-card').forEach(card=>{
      const category=card.dataset.category;
      const meta=responseCategories[category];
      if(!meta)return;
      const insert=document.createElement('div');
      insert.className='response-meta';
      insert.innerHTML=`<span>${escapeHTML(meta.level)}</span><span>${escapeHTML(meta.phase)}</span>`;
      card.insertBefore(insert,card.querySelector('p'));
      const note=document.createElement('p');note.className='mitigation-validation';note.innerHTML=`<b>Before taking action:</b> ${escapeHTML(meta.review)}`;
      card.appendChild(note);
    });
    holder.addEventListener('click',event=>{
      const btn=event.target.closest('button[data-filter]');if(!btn)return;
      const category=btn.dataset.filter;
      holder.querySelectorAll('button').forEach(b=>{b.classList.toggle('active',b===btn);b.setAttribute('aria-pressed',String(b===btn));});
      document.querySelectorAll('.mitigation-card').forEach(c=>{c.hidden=category!=='ALL'&&c.dataset.category!==category;});
      el('phase3-mitigation-explanation').textContent=category==='ALL'?'Seven behavior categories with matching prevention, response and validation steps. No real incident is implied.':responseCategories[category].review;
    });
  }
  function renderReports(model,manifest){
    const d=model.dataset,x=model.xgboost;
    el('phase3-report-facts').innerHTML=fact('MODEL ACCURACY',percent(x.accuracy),'Held-out synthetic test split')+fact('TOTAL STUDY ROWS',number(d.training_rows+d.validation_rows+d.test_rows),'Separate train, validation and test')+fact('CLASS COUNT',String(d.classes.length),'Known behavior categories')+fact('MODEL FINGERPRINT',manifest.classifier_autoencoder_version,'Matches Phase 2 runtime model code');
  }
  Promise.all([
    fetch('/assessment/model_summary.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Model metadata unavailable');return r.json();}),
    fetch('/assessment/evidence.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Synthetic evidence unavailable');return r.json();}),
    fetch('/assessment/phase3_manifest.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Evidence manifest unavailable');return r.json();}),
  ]).then(([model,evidence,manifest])=>{
    if(!evidence.not_live_inference||evidence.contains_real_personal_data||manifest.live_inference||manifest.contains_private_data){throw Error('Unsafe evidence provenance: refusing to render');}
    renderDataset(model);renderEvaluation(model);renderDefense(model,evidence,manifest);renderMitigationFilters();renderReports(model,manifest);
    document.body.dataset.phase3Ready='true';
  }).catch(error=>{
    for(const id of ['phase3-defense-metrics','phase3-report-facts','phase3-error-analysis']){
      const target=el(id);if(target)target.textContent=`Saved academic evidence unavailable: ${error.message}`;
    }
    document.body.dataset.phase3Ready='error';
  });
})();
