/* IT113 Rubric E: documentation derived from versioned public synthetic metrics. Read-only. */
'use strict';
(() => {
  const el = id => document.getElementById(id);
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fmt = n => Number(n).toLocaleString('en-US');
  const percent = n => (Number(n)*100).toFixed(2)+'%';
  const rows = details => details.map(([label,text]) => `<div class="rubric-e-row"><b>${esc(label)}</b><span>${esc(text)}</span></div>`).join('');
  async function init(){
    const target=el('rubric-e-documentation');if(!target)return;
    try{
      const [summaryResp,evidenceResp]=await Promise.all([fetch('/assessment/model_summary.json',{cache:'no-store'}),fetch('/assessment/evidence.json',{cache:'no-store'})]);
      if(!summaryResp.ok||!evidenceResp.ok)throw Error('Saved academic metrics unavailable');
      const [s,ev]=await Promise.all([summaryResp.json(),evidenceResp.json()]);
      if(!s.dataset||!s.xgboost||!s.autoencoder||!s.reproducibility||!ev.not_live_inference||ev.contains_real_personal_data||!Array.isArray(ev.examples))throw Error('Unrecognized or unsafe evidence provenance');
      const d=s.dataset,x=s.xgboost,a=s.autoencoder,r=s.reproducibility,errors=ev.examples.filter(q=>q.correct===false).length;
      target.innerHTML=`<div class="rubric-e-section"><h3>Research design and evaluation protocol</h3>${rows([
        ['Research objective','Assess and classify suspicious simulated security behavior using numeric features, model predictions, and anomaly scores.'],
        ['Study data',`${fmt(d.training_rows+d.validation_rows+d.test_rows)} synthetically generated observations with ${d.features.length} numeric fields and ${d.classes.length} balanced behavior categories.`],
        ['Separation of data',`${fmt(d.training_rows)} training rows, ${fmt(d.validation_rows)} validation rows, and ${fmt(d.test_rows)} held-out test rows; deterministic split seeds ${d.split_seeds.train}/${d.split_seeds.validation}/${d.split_seeds.test}.`],
        ['Algorithms','XGBoost supervised multi-class classifier; scikit-learn MLPRegressor trained to reconstruct normal records as a compact autoencoder; illustrative hybrid rule scoring.'],
        ['Held-out measurements',`XGBoost accuracy ${percent(x.accuracy)}; macro-F1 ${percent(x.macro_f1)}; autoencoder anomaly recall ${percent(a.holdout_anomaly_recall)} and normal false-positive rate ${percent(a.holdout_normal_false_positive_rate)}.`],
        ['Example validation',`${ev.examples.length} selected saved held-out examples, including ${errors} visibly misclassified examples; this subset is not an unbiased accuracy estimate.`],
        ['Reproducibility',`Recorded Python version ${r.python}, scikit-learn ${r.scikit_learn}, XGBoost ${r.xgboost}, random state ${r.random_state}. Scripts and fingerprints live in the project source.`]
      ])}</div><div class="rubric-e-section"><h3>Security interpretation and boundaries</h3>${rows([
        ['What a result means','A model class, anomaly score, and threshold indicators support analyst triage but do not verify an exploit, attacker identity, or vulnerability.'],
        ['Model limitations','Synthetic class balance and generated distribution shift differ from operational traffic. No independent field validation is claimed.'],
        ['Ethical safeguards','Public study uses simulated and curated numeric features; do not include user names, IP addresses, passwords, raw logs, or privileged tokens.'],
        ['Response process','Validate the observation, investigate with authorized sources, apply proportionate defensive controls, and retest before resolving.'],
        ['Documentation status','Draft report and presentation contain evidence-based content, but final participant details, screenshots, hosted QA and academic review still need completion.']
      ])}</div>`;
      el('rubric-e-readiness').textContent='Saved model evidence loaded. Documentation is a draft until hosted screenshots, team identifiers, and final QA sign-off are added.';
    } catch(e){target.textContent='Methodology panel could not load verified model evidence: '+e.message;el('rubric-e-readiness').textContent='Do not submit unverified numbers; recheck model_summary.json and evidence.json.';}
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
})();
