'use strict';
(function(){
const $ = id => document.getElementById(id);
const safeText = value => String(value == null ? '—' : value);
const esc = s => safeText(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pct = number => (Number(number)*100).toFixed(2)+'%';
const num = number => Number(number).toLocaleString('en-US');
const metric = (label,value,note,kind='')=>`<div class="metric"><span class="metric-label">${esc(label)}</span><span class="metric-value ${kind}">${esc(value)}</span><small>${esc(note)}</small></div>`;
const className = name => safeText(name).replace(/_/g,' ');
const pages=['overview','dataset','evaluation','defense','findings','examples','mitigations','analytics','reports'];
const titles=['Overview','Dataset Assessment','Model Evaluation','AI Defense','Threat Findings','Validation Examples','Threat Mitigations','Security Analytics','Research Reports'];
function closeSidebar(){
  $('sidebar').classList.remove('open');
  document.body.classList.remove('sidebar-open');
  $('menu-toggle').setAttribute('aria-expanded', 'false');
}
function navigate(name){
  if(!pages.includes(name)) name='overview';
  document.querySelectorAll('.nav-link').forEach(e=>{
    const active=e.dataset.view===name;
    e.classList.toggle('active',active);
    if(active)e.setAttribute('aria-current','page');
    else e.removeAttribute('aria-current');
  });
  document.querySelectorAll('.view').forEach(e=>e.classList.toggle('active',e.id==='view-'+name));
  $('page-crumb').textContent=titles[pages.indexOf(name)];
  closeSidebar();
  history.replaceState(null,'','#'+name);
  window.scrollTo({top:0,behavior:'auto'});
}
document.querySelectorAll('.nav-link').forEach(e=>e.addEventListener('click',()=>navigate(e.dataset.view)));
document.querySelectorAll('[data-go-to]').forEach(e=>e.addEventListener('click',()=>navigate(e.dataset.goTo)));
document.addEventListener('click',e=>{const control=e.target.closest('[data-go-to]');if(control&&!control.dataset.phase3Bound&&!control.closest('.hero-actions'))navigate(control.dataset.goTo);});
$('menu-toggle').addEventListener('click',()=>{
  const open=!$('sidebar').classList.contains('open');
  $('sidebar').classList.toggle('open',open);
  document.body.classList.toggle('sidebar-open',open);
  $('menu-toggle').setAttribute('aria-expanded',String(open));
});
$('sidebar-backdrop').addEventListener('click',closeSidebar);
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeSidebar();});
window.addEventListener('hashchange',()=>navigate(location.hash.slice(1)));
if(location.hash)navigate(location.hash.slice(1));
else document.querySelector('[data-view="overview"]').setAttribute('aria-current','page');
const mitigations = [
['NORMAL','Expected baseline traffic','Preserve ordinary access and continue normal monitoring.',['Keep baseline traffic logs appropriately minimized','Regularly review changes in traffic patterns','Avoid sanctions for isolated weak anomalies']],
['BRUTE_FORCE','Repeated password failures','Slow repeated guesses while protecting legitimate users.',['Apply rate limits and progressive cooldowns','Use MFA for privileged accounts','Review source behavior and notify affected users']],
['CREDENTIAL_STUFFING','Many usernames in automated login attempts','Reduce damage from reused credentials.',['Rate-limit by source and targeted account','Block known compromised passwords when appropriate','Use MFA and investigate repeated account targeting']],
['RECONNAISSANCE','Broad endpoint discovery and scanning','Limit sensitive endpoint exposure and investigate unusual probes.',['Restrict access to administrative routes','Maintain up-to-date inventories and patching','Correlate scan indicators with request logs']],
['WEB_ATTACK','Suspicious request patterns','Apply application-layer defenses and validate actual findings.',['Use server-side input validation and parameterized SQL','Apply output encoding and request-size restrictions','Review WAF events without assuming every alert is an exploit']],
['MFA_ABUSE','Repeated second-factor verification failures','Protect the second factor from replay and guessing.',['Enforce attempt limits for second-factor checks','Expire and bind challenges to sessions','Alert on unusual failure spikes and investigate']],
['SESSION_ABUSE','Suspicious session and CSRF events','Prevent unauthorized or forged session activity.',['Rotate session identifiers after authentication','Require CSRF tokens on state-changing operations','Set secure cookie attributes and enforce session expiry']],
];
$('mitigation-list').innerHTML = mitigations.map(m=>`<article class="mitigation-card" data-category="${esc(m[0])}"><h2>${esc(className(m[0]))}</h2><p>${esc(m[1])}. ${esc(m[2])}</p><ul>${m[3].map(action=>`<li>${esc(action)}</li>`).join('')}</ul></article>`).join('');
function initialize(m,evidence){
const d=m.dataset,x=m.xgboost,a=m.autoencoder;
$('overview-metrics').innerHTML = metric('CLASSIFIER ACCURACY',pct(x.accuracy),'Independent synthetic test set','good')+metric('MACRO F1-SCORE',pct(x.macro_f1),'Average across seven classes','purple')+metric('TRAINING OBSERVATIONS',num(d.training_rows),'Synthetic, labeled records')+metric('TEST OBSERVATIONS',num(d.test_rows),'Untouched evaluation split');
$('class-pills').innerHTML=d.classes.map(c=>`<span>${esc(className(c))}</span>`).join('');
$('dataset-stats').innerHTML=metric('TRAINING RECORDS',num(d.training_rows),'Seed '+d.split_seeds.train)+metric('VALIDATION RECORDS',num(d.validation_rows),'Seed '+d.split_seeds.validation)+metric('TEST RECORDS',num(d.test_rows),'Seed '+d.split_seeds.test)+metric('MODEL FEATURES',num(d.features.length),'Numeric behavior indicators');
const distribution=d.class_counts.train;
$('distribution').innerHTML=d.classes.map(c=>`<div class="distribution-row"><span>${esc(className(c))}</span><div class="bar-track"><div class="bar-fill" style="width:${100*distribution[c]/Math.max(...Object.values(distribution))}%"></div></div><b>${num(distribution[c])}</b></div>`).join('');
const findings=d.data_quality_invariant_violations;
const issues=Object.values(findings).flatMap(v=>Object.values(v)).reduce((a,b)=>a+b,0);
$('quality-status').innerHTML=`<div class="quality-badge">${issues===0?'✓ ALL VALIDATION CHECKS PASSED':'! INVARIANT VIOLATIONS DETECTED'}</div><div class="quality-stats"><span>Training: <strong>${num(Object.values(findings.train).reduce((a,b)=>a+b,0))}</strong> violations</span><span>Validation: <strong>${num(Object.values(findings.validation).reduce((a,b)=>a+b,0))}</strong></span><span>Test: <strong>${num(Object.values(findings.test).reduce((a,b)=>a+b,0))}</strong></span></div>`;
$('feature-count').textContent=d.features.length+' numeric features';
$('feature-list').innerHTML=d.features.map(f=>`<span>${esc(f)}</span>`).join('');
$('evaluation-metrics').innerHTML=metric('TEST ACCURACY',pct(x.accuracy),'XGBoost','good')+metric('MACRO PRECISION',pct(x.macro_precision),'All seven labels','purple')+metric('MACRO RECALL',pct(x.macro_recall),'All seven labels')+metric('MACRO F1',pct(x.macro_f1),'All seven labels');
const matrix=x.confusion_matrix;
$('confusion-matrix').innerHTML=`<table><thead><tr><th>TRUE / PREDICTED</th>${d.classes.map(c=>`<th title="${esc(className(c))}">${esc(c.split('_').map(w=>w.slice(0,3)).join('_'))}</th>`).join('')}</tr></thead><tbody>${d.classes.map((c,i)=>`<tr><th>${esc(className(c))}</th>${matrix[i].map((v,j)=>`<td class="${i===j?'diagonal':''}">${num(v)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
const reports=x.classification_report;
$('class-metrics').innerHTML=`<table><thead><tr><th>Label</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead><tbody>${d.classes.map(c=>`<tr><td>${esc(className(c))}</td><td>${pct(reports[c].precision)}</td><td>${pct(reports[c].recall)}</td><td>${pct(reports[c]['f1-score'])}</td><td>${num(reports[c].support)}</td></tr>`).join('')}</tbody></table>`;
const importance=x.top_feature_importance, top=Math.max(...importance.map(v=>v[1]));
$('feature-importance').innerHTML=importance.map(row=>`<div class="importance-row"><span class="importance-label">${esc(row[0])}</span><div><div class="bar-track"><div class="bar-fill" style="width:${100*row[1]/top}%"></div></div><div class="importance-score">${pct(row[1])}</div></div></div>`).join('')+'<p class="hint">Global XGBoost importance estimates, not individual causal explanations.</p>';
$('autoencoder-stats').innerHTML=[['TEST RECALL',pct(a.holdout_anomaly_recall)],['TEST FALSE-POSITIVE RATE',pct(a.holdout_normal_false_positive_rate)],['TEST PRECISION',pct(a.test_anomaly_precision)],['TEST F1',pct(a.test_anomaly_f1)],['TEST ROC AUC',a.test_anomaly_roc_auc.toFixed(4)],['VALIDATION THRESHOLD',a.threshold_p99.toFixed(4)]].map(([label,v])=>`<div class="ae-stat"><b>${esc(v)}</b><small>${esc(label)}</small></div>`).join('');
const cases=evidence.examples;
$('example-list').innerHTML=cases.map((c,i)=>`<button class="example-btn" data-example="${i}"><strong>${esc(className(c.true_label))}</strong><small class="${c.correct?'good-text':'bad-text'}">${c.correct?'✓ Correct':'✗ Misclassified'} · ${pct(c.confidence)} confidence</small></button>`).join('');
const showExample=i=>{const c=cases[i];if(!c)return;document.querySelectorAll('.example-btn').forEach((e,j)=>e.classList.toggle('selected',j===i));$('example-detail').innerHTML=`<h3>${esc(className(c.true_label))}</h3><div class="detail-tags"><span>Actual: <b>${esc(c.true_label)}</b></span><span>Predicted: <b>${esc(c.predicted_label)}</b></span><span>Confidence: <b>${pct(c.confidence)}</b></span><span class="${c.correct?'good-text':'bad-text'}">${c.correct?'Correct prediction':'Misclassification'}</span><span>Autoencoder: ${c.anomaly?'Anomalous':'Within threshold'}</span></div><p class="hint">Model reconstruction error: ${c.reconstruction_error.toFixed(4)}. Test inputs (synthetic behavior counts):</p><div class="feature-list">${Object.entries(c.features).map(([f,v])=>`<span>${esc(f)}: <strong>${esc(v)}</strong></span>`).join('')}</div>`;};
document.querySelectorAll('.example-btn').forEach(e=>e.addEventListener('click',()=>showExample(Number(e.dataset.example))));showExample(0);
}
Promise.all([fetch('/assessment/model_summary.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Metrics response unavailable');return r.json();}),fetch('/assessment/evidence.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Evidence response unavailable');return r.json();})]).then(([m,e])=>initialize(m,e)).catch(error=>{$('overview-metrics').innerHTML=`<div class="notice"><strong>Evaluation unavailable</strong><span>${esc(error.message)}. The saved metrics must be generated with the model training scripts.</span></div>`;});
})();
