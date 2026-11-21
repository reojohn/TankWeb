/* FortressAuth IT113 / Dynamic academic research, no login.
   Only curated or explicitly synthetic NUMERIC security features are accepted.
   Remote persistence is opt-in; legacy operational and user data stay private. */
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const pretty = value => String(value ?? '—').replace(/_/g,' ').toLowerCase().replace(/\b\w/g,c=>c.toUpperCase());
  const pct = value => Number.isFinite(Number(value)) ? (Number(value)*100).toFixed(2)+'%' : '—';
  const num = value => Number(value || 0).toLocaleString('en-US');
  const categories = ['NORMAL','BRUTE_FORCE','CREDENTIAL_STUFFING','RECONNAISSANCE','WEB_ATTACK','MFA_ABUSE','SESSION_ABUSE'];
  const states = ['OPEN','INVESTIGATING','MITIGATED','RESOLVED'];
  const transitions={OPEN:['OPEN','INVESTIGATING'],INVESTIGATING:['INVESTIGATING','MITIGATED','OPEN'],MITIGATED:['MITIGATED','RESOLVED','INVESTIGATING'],RESOLVED:['RESOLVED','OPEN']};
  const key='fortress-it113-dynamic-v2';
  const advice = {
    NORMAL:['Baseline monitoring','Continue observation. Avoid treating benign behavior as an attack.'],
    BRUTE_FORCE:['Authentication protections','Review failed-login trends; limit repeated attempts and apply challenges.'],
    CREDENTIAL_STUFFING:['Account abuse protections','Review multi-account login failures; apply rate limits and MFA.'],
    RECONNAISSANCE:['Exposure reduction','Review endpoint discovery, minimize exposed admin paths and correlate logs.'],
    WEB_ATTACK:['Application-layer defenses','Validate input, parameterize SQL and inspect suspicious request patterns.'],
    MFA_ABUSE:['Verification hardening','Limit and expire repeated MFA prompts; review verification failures.'],
    SESSION_ABUSE:['Session protections','Rotate session tokens, verify CSRF protections and secure cookies.'],
  };
  const metric=(label,value,note)=>`<div class="metric"><span class="metric-label">${esc(label)}</span><span class="metric-value">${esc(value)}</span><small>${esc(note)}</small></div>`;
  let model=null, samples=[], featureNames=[], entries=readLocal(), selectedTrace='', busy=false, queuedCsv=[], persistence=false, processingCsv=false, storeState='not_checked';
  function readLocal(){ try { const x=JSON.parse(localStorage.getItem(key)||'[]');return Array.isArray(x)?x.filter(e=>e?.synthetic===true&&categories.includes(e.classification)).slice(0,80):[];} catch {return [];} }
  function saveLocal(){try{localStorage.setItem(key,JSON.stringify(entries.slice(0,80)));}catch{/* unavailable */}}
  function normalized(e){return {...e, synthetic:true, status:e.status||'OPEN',revision:Number(e.revision||0),indicator_evidence:Array.isArray(e.indicator_evidence)?e.indicator_evidence:[]};}
  function mergeHistory(remote){const merged=new Map();for(const e of [...entries,...remote])if(e.trace_id)merged.set(e.trace_id,normalized(e));entries=[...merged.values()].sort((a,b)=>Date.parse(b.at||0)-Date.parse(a.at||0)).slice(0,80);saveLocal();}
  function setEngine(label,state){const e=$('live-engine-status');if(e){e.textContent=label;e.dataset.state=state;}}
  function storageBadge(){
    const e=$('store-status');if(!e)return;
    const messages={disabled:'Server persistence is disabled. Check IT113_DEMO_PERSISTENCE_ENABLED.',
      missing_database_config:'Database configuration is missing in the running PHP process.',
      pgsql_driver_missing:'PHP needs the pdo_pgsql driver.',
      database_connection_failed:'PHP could not connect to the private Supabase database. Check the PHP server environment and PostgreSQL connection.',
      database_write_failed:'The model responded, but the database rejected or failed to save the record. Review the local PHP error log.',
      database_read_failed:'The database connection succeeded, but assessment history could not be read. Review the local PHP error log.',
      session_unavailable:'The session cookie could not be created. Check cookie settings and the browser.',
      session_limit_reached:'This browser has reached the 80-record academic history limit.',
      not_checked:'Checking private assessment storage…'};
    e.innerHTML=persistence?'<span class="storage-dot"></span><strong>Private Supabase history active</strong><span>Only this anonymous browser session can list or update its synthetic assessments.</span>':
      '<span class="storage-dot off"></span><strong>Browser-only history</strong><span>'+esc(messages[storeState]||'Private assessment storage is unavailable. Check the running PHP server logs.')+'</span>';
  }
  async function syncHistory(trace=''){
    try{
      const q=trace?'?trace_id='+encodeURIComponent(trace):'';
      const r=await fetch('/it113_demo_history.php'+q,{cache:'no-store',credentials:'same-origin'});
      if(!r.ok)throw Error('History API not available');
      const j=await r.json();
      persistence=j.enabled===true;
      storeState=String(j.storage_state|| (persistence?'ready':'not_checked'));
      if(persistence&&Array.isArray(j.entries))mergeHistory(j.entries);
      storageBadge();renderFindings();renderAnalytics();renderReport();
      return j;
    }catch {persistence=false;storeState='history_api_unavailable';storageBadge();renderFindings();renderAnalytics();renderReport();return null;}
  }
  function download(filename,content,type){const url=URL.createObjectURL(new Blob([content],{type}));const a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500);}
  async function postInference(body){
    const ctrl=new AbortController();const timer=setTimeout(()=>ctrl.abort(),25000);
    try{
      const response=await fetch('/it113_demo_infer.php',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(body),signal:ctrl.signal});
      const data=await response.json().catch(()=>({}));
      if(!response.ok||data.ok!==true||data.synthetic!==true){
        const message = data.error || `Inference HTTP ${response.status}`;
        const suffix = response.status===429 ? ' This limit protects the shared school demonstration.'
          : data.code==='ML_STARTING' ? ' A Free Render service may take time to restart after inactivity.'
          : data.code==='SAFETY_GATE_UNAVAILABLE' ? ' Your existing offline evaluation is still available.' : '';
        const failure = new Error(message + suffix);
        failure.code = String(data.code || 'INFERENCE_ERROR');
        throw failure;
      }
      if(!categories.includes(data.classification)||!/^[a-f0-9]{16}$/.test(String(data.model_version))||!/^[a-f0-9]{32}$/.test(String(data.trace_id)))throw Error('Unverified model response');
      if(data.mode!==(body.sample_id?'live_inference_on_curated_synthetic_sample':'live_inference_on_numeric_security_features'))throw Error('Unexpected inference mode');
      return data;
    }finally{clearTimeout(timer);}
  }
  function addResult(data){
    const e=normalized({...data,at:new Date().toISOString(),sample_id:data.sample_id||'NUMERIC_CSV',expected_label:data.expected_label||null,source_type:data.source_type||'curated'});
    if(!entries.some(x=>x.trace_id===e.trace_id))entries.unshift(e);
    if(e.database_written){persistence=true;storeState='ready';}
    else if(e.persistence_status)storeState=e.persistence_status;
    storageBadge();
    entries=entries.slice(0,80);selectedTrace=e.trace_id;saveLocal();renderLive(e);renderFindings();renderAnalytics();renderReport();
    setEngine('MODEL INFERENCE VERIFIED','success');
  }
  function renderLive(r){
    const labeled=!!r.expected_label,matched=labeled&&r.classification===r.expected_label;
    const risk=Math.max(0,Math.min(100,Number(r.risk_score)));
    const flags=(r.indicator_evidence||[]).slice(0,6);
    $('live-result').innerHTML=`<div class="analysis-summary"><div class="analysis-primary"><div class="section-micro">FRESH MODEL INFERENCE / ${esc(r.source_type==='numeric_csv'?'NUMERIC DATASET':'HELD-OUT SYNTHETIC SAMPLE')}</div><strong>${esc(pretty(r.classification))}</strong><div class="result-chips"><span class="result-chip ${!labeled?'':matched?'chip-good':'chip-warn'}">${labeled?matched?'Matches held-out label':'Differs from held-out label':'Unlabeled numeric assessment'}</span><span class="result-chip">${esc(r.severity)} risk</span><span class="result-chip">Advisory only</span></div></div><div class="risk-dial" style="--risk:${risk}"><div><b>${risk.toFixed(1)}</b><small>HYBRID RISK / 100</small></div></div></div><div class="analysis-grid"><div><small>CLASS CONFIDENCE</small><b>${pct(r.confidence)}</b></div><div><small>ANOMALY SCORE</small><b>${pct(r.anomaly_score)}</b></div><div><small>RULE SCORE</small><b>${Number(r.rule_score).toFixed(1)} / 100</b></div><div><small>EXPECTED LABEL</small><b>${labeled?esc(pretty(r.expected_label)):'Not supplied'}</b></div></div><div class="result-evidence"><div><h3>Supporting indicators</h3><p>Threshold signals describe features, not causal proof of an attack.</p></div>${flags.length?flags.map(f=>`<div class="result-evidence-row"><span>${esc(f.description)}</span><b>${num(f.observed)}</b></div>`).join(''):'<p class="hint">No rule thresholds crossed.</p>'}</div><div class="result-trace"><span>MODEL <code>${esc(r.model_version)}</code></span><span>TRACE <code>${esc(r.trace_id)}</code></span><span>STORAGE <b>${r.database_written?'PRIVATE DATABASE':'BROWSER ONLY'}</b></span></div>${!r.database_written&&r.persistence_status?`<p class="store-hint">Database storage: ${esc(({'disabled':'disabled by configuration','missing_database_config':'missing server database settings','pgsql_driver_missing':'PHP PostgreSQL driver missing','database_connection_failed':'private database connection failed','database_write_failed':'database write failed','session_limit_reached':'session record limit reached'})[r.persistence_status]||'unavailable')}. Prediction was still completed successfully.</p>`:''}<button class="subtle-btn" data-go-to="findings" type="button">Review finding & mitigation ↗</button>`;
  }
  async function analyze(){
    if(busy)return;const sampleId=$('live-sample-select')?.value;if(!samples.some(s=>s.id===sampleId))return;
    busy=true;$('live-run-button').disabled=true;$('live-run-button').textContent='Analyzing…';
    $('live-result').innerHTML='<div class="live-wait"><span class="wait-orb"></span><div><strong>Running XGBoost and autoencoder…</strong><p>Computing a fresh model prediction from a held-out numeric sample.</p></div></div>';setEngine('INFERENCE IN PROGRESS','busy');
    try{
      const data=await postInference({sample_id:sampleId});addResult(data);
      if(data.database_written)await syncHistory();
    }catch(e){setEngine(e.code==='ML_STARTING'?'MODEL WAKING UP':e.code==='DEMO_LIMIT_REACHED'?'DEMO LIMIT REACHED':'ENGINE UNAVAILABLE','error');$('live-result').innerHTML=`<div class="live-error"><strong>Inference was not completed.</strong><p>${esc(e.name==='AbortError'?'Request timed out while the hosted ML service was waking up. Please retry shortly.':e.message)}</p><p>Saved model evaluation remains available; no fabricated result was added.</p></div>`;}
    finally{busy=false;$('live-run-button').disabled=false;$('live-run-button').textContent='Run model analysis ↗';}
  }
  function sampleCsv(){
    const seed=samples[0];if(!seed||!featureNames.length)return;
    const header=featureNames.join(',');const row=featureNames.map(x=>Number(seed.features[x]));
    download('fortressauth-it113-numeric-template.csv',[header,row.join(',')].join('\r\n')+'\r\n','text/csv');
  }
  function readCsv(text){
    const lines=text.replace(/^\uFEFF/,'').trim().split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    if(lines.length<2||lines.length>9)throw Error('CSV must contain a header and 1–8 numeric rows.');
    const keys=lines[0].split(',').map(s=>s.trim());
    if(keys.length!==20||new Set(keys).size!==20||!featureNames.every(k=>keys.includes(k)))throw Error('CSV header must contain exactly the 20 official model feature names.');
    const rows=[];
    for(const [i,line] of lines.slice(1).entries()){
      const cells=line.split(',').map(s=>s.trim());if(cells.length!==20)throw Error(`Row ${i+2}: expected 20 numeric values.`);
      const obj={};for(let j=0;j<20;j++){
        // Only plain numeric literals. Reject formulas, strings, exponent bombs and cells with embedded separators.
        if(!/^(?:\d+(?:\.\d+)?|\.\d+)$/.test(cells[j]))throw Error(`Row ${i+2}: ${keys[j]} must be a nonnegative number.`);
        const value=Number(cells[j]);if(!Number.isFinite(value)||value>1000000)throw Error(`Row ${i+2}: value exceeds safe bounds.`);obj[keys[j]]=value;
      }
      if(obj.off_hours!==0&&obj.off_hours!==1)throw Error(`Row ${i+2}: off_hours must be 0 or 1.`);
      if(obj.post_ratio_5m>1||obj.requests_1m>obj.requests_5m||obj.unique_paths_5m>obj.requests_5m||obj.auth_endpoint_requests_5m>obj.requests_5m||obj.failed_logins_5m>obj.failed_logins_15m)throw Error(`Row ${i+2}: inconsistent feature relationships.`);
      rows.push(obj);
    }
    return rows;
  }
  async function importCsv(file){
    queuedCsv=[];$('csv-run').disabled=true;
    if(!file)return;
    if(file.size>16000){$('csv-status').textContent='CSV exceeds the 16 KB limit.';return;}
    try{queuedCsv=readCsv(await file.text());$('csv-run').disabled=false;$('csv-status').textContent=`Validated ${queuedCsv.length} numeric-only row(s). Confirm they are synthetic or fully anonymized before analyzing.`;}
    catch(e){$('csv-status').textContent=e.message;}
  }
  async function analyzeCsv(){
    if(processingCsv||busy||!queuedCsv.length)return;
    if(!window.confirm(`Analyze ${queuedCsv.length} rows using the real AI model? Confirm the data contains NO personal identifiers or raw logs.`))return;
    processingCsv=true;$('csv-run').disabled=true;$('live-run-button').disabled=true;
    let ok=0;let fail='';
    try{
      for(let i=0;i<queuedCsv.length;i++){
        $('csv-status').textContent=`Analyzing numeric row ${i+1} of ${queuedCsv.length}…`;
        try{const result=await postInference({source:'numeric_csv',features:queuedCsv[i],confirm_synthetic:true});addResult(result);ok++;}
        catch(e){fail=e.message;break;}
      }
      $('csv-status').textContent=`${ok}/${queuedCsv.length} rows analyzed. ${fail?'Stopped: '+fail:'Open Threat Findings to inspect model decisions and status.'}`;
      if(ok)await syncHistory();
    }finally{processingCsv=false;$('csv-run').disabled=false;$('live-run-button').disabled=false;}
  }
  function renderFindings(){
    const flagged=entries.filter(x=>x.classification!=='NORMAL').length;
    $('findings-overview').innerHTML=metric('ANALYZED RECORDS',num(entries.length),persistence?'Private browser-scoped database':'Local browser history')+metric('FLAGGED PREDICTIONS',num(flagged),'Not confirmed incidents')+metric('NORMAL PREDICTIONS',num(entries.length-flagged),'Synthetic baseline')+metric('OPEN REVIEWS',num(entries.filter(e=>e.classification!=='NORMAL'&&e.status!=='RESOLVED').length),'Academic mitigation cases');
    const list=$('findings-timeline');
    if(!entries.length){list.innerHTML='<div class="empty-state"><span>◇</span><h3>No assessments recorded</h3><p>Analyze a curated sample or import numeric features in AI Defense to populate this timeline.</p><button class="subtle-btn" type="button" data-go-to="defense">Open AI Defense ↗</button></div>';$('finding-detail').innerHTML='<p class="hint">Select an assessment to inspect evidence and recommendations.</p>';return;}
    if(!entries.some(e=>e.trace_id===selectedTrace))selectedTrace=entries[0].trace_id;
    list.innerHTML=entries.map(e=>`<button type="button" class="finding-row ${selectedTrace===e.trace_id?'active':''}" data-trace="${esc(e.trace_id)}"><div class="finding-row-icon ${e.classification==='NORMAL'?'icon-safe':'icon-risk'}">${e.classification==='NORMAL'?'✓':'!'}</div><div class="finding-row-main"><strong>${esc(pretty(e.classification))}</strong><small>${esc(e.sample_id||'NUMERIC_CSV')} · ${esc(new Date(e.at).toLocaleString())}</small></div><span class="severity-pill severity-${esc(String(e.severity).toLowerCase())}">${esc(e.severity)}</span><b>${Number(e.risk_score).toFixed(1)}<small>/100</small></b><span class="finding-arrow">↗</span></button>`).join('');
    showFinding(selectedTrace);
  }
  function showFinding(trace){
    selectedTrace=trace;document.querySelectorAll('[data-trace]').forEach(b=>b.classList.toggle('active',b.dataset.trace===trace));
    const e=entries.find(x=>x.trace_id===trace);if(!e)return;
    const a=advice[e.classification]||advice.NORMAL;
    const showStatus=e.classification!=='NORMAL';
    $('finding-detail').innerHTML=`<div class="finding-topline"><div><span class="section-micro">SYNTHETIC INFERENCE / ${e.database_written?'PRIVATE HISTORY':'BROWSER HISTORY'}</span><h3>${esc(pretty(e.classification))}</h3></div><span class="severity-pill severity-${esc(String(e.severity).toLowerCase())}">${esc(e.severity)}</span></div><div class="finding-data-grid"><div><small>MODEL CONFIDENCE</small><b>${pct(e.confidence)}</b></div><div><small>HYBRID RISK</small><b>${Number(e.risk_score).toFixed(1)} / 100</b></div><div><small>TRUE TEST LABEL</small><b>${e.expected_label?esc(pretty(e.expected_label)):'Unlabeled'}</b></div><div><small>ANOMALY</small><b>${pct(e.anomaly_score)}</b></div></div><div class="finding-advice"><span class="section-micro">RECOMMENDATION / REVIEW ONLY</span><h4>${esc(a[0])}</h4><p>${esc(a[1])}</p></div><h4 class="finding-subhead">Supporting indicators</h4>${(e.indicator_evidence||[]).length?(e.indicator_evidence||[]).map(f=>`<div class="result-evidence-row"><span>${esc(f.description)}</span><b>${num(f.observed)}</b></div>`).join(''):'<p class="hint">No static threshold exceeded.</p>'}<div class="result-trace"><span>TRACE <code>${esc(e.trace_id)}</code></span><span>MODEL <code>${esc(e.model_version)}</code></span></div>${showStatus?`<div class="case-workflow"><div class="section-micro">MITIGATION TRACKING / ${e.database_written&&persistence?'PERSISTENT':'LOCAL ONLY'}</div><h4>Review status</h4><div class="case-form"><select id="case-status" class="premium-select" aria-label="Mitigation status">${states.map(st=>`<option ${st===(e.status||'OPEN')?'selected':''} ${transitions[e.status||'OPEN']?.includes(st)?'':'disabled'} value="${st}">${pretty(st)}</option>`).join('')}</select><input type="text" id="case-note" maxlength="240" placeholder="Optional analyst note (240 characters)" aria-label="Analyst note" /><button class="subtle-btn" type="button" id="case-save">Save status</button></div><p class="hint" id="case-feedback">These are academic follow-up actions, not automated enforcement.</p><div id="case-events" class="case-events"></div></div>`:''}<p class="hint">These are synthetic numeric behavior indicators, not verified network incidents or confirmed vulnerabilities.</p>`;
    $('case-save')?.addEventListener('click',()=>updateCase(trace));
    if(showStatus&&e.database_written&&persistence)loadEvents(trace);
  }
  async function loadEvents(trace){
    try{
      const r=await fetch('/it113_demo_history.php?trace_id='+encodeURIComponent(trace),{credentials:'same-origin',cache:'no-store'});
      const body=await r.json();if(!body.ok||!Array.isArray(body.events)||selectedTrace!==trace)return;
      $('case-events').innerHTML=body.events.length?body.events.map(x=>`<div class="case-event"><b>${esc(pretty(x.status))}</b><span>${esc(x.note||'No note')}</span><small>${esc(new Date(x.changed_at).toLocaleString())}</small></div>`).join(''):'<p class="hint">No status changes recorded yet.</p>';
    }catch{/* history optional */}
  }
  async function updateCase(trace){
    const e=entries.find(x=>x.trace_id===trace);if(!e)return;
    const status=$('case-status')?.value;const note=$('case-note')?.value.trim()||'';const feedback=$('case-feedback');
    if(!states.includes(status)||!transitions[e.status||'OPEN']?.includes(status))return;
    $('case-save').disabled=true;
    if(e.database_written&&persistence){
      try{
        const res=await fetch('/it113_demo_history.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'status',trace_id:trace,status,revision:e.revision,note})});
        const body=await res.json();if(!res.ok||!body.ok)throw Error(body.error||'Save failed');
        e.status=status;e.revision++;saveLocal();feedback.textContent='Saved in your private demo history.';await syncHistory(trace);showFinding(trace);
      }catch(err){feedback.textContent='Could not save: '+err.message;}
    }else{e.status=status;e.revision=Math.min(15,e.revision+1);saveLocal();feedback.textContent='Saved locally in this browser only.';renderFindings();renderAnalytics();renderReport();}
    const button=$('case-save');if(button)button.disabled=false;
  }
  function renderAnalytics(){
    const labeled=entries.filter(e=>!!e.expected_label),matches=labeled.filter(e=>e.expected_label===e.classification).length;
    $('analytics-overview').innerHTML=metric('HELD-OUT ACCURACY',model?pct(model.xgboost.accuracy):'—','Independent 10,500-record evaluation')+metric('RECENT ASSESSMENTS',num(entries.length),'Browser-scoped synthetic history')+metric('LABELED SAMPLE MATCHES',labeled.length?`${matches} / ${labeled.length}`:'—','Not real-world accuracy')+metric('CASE FOLLOW-UPS',num(entries.filter(e=>e.status==='INVESTIGATING'||e.status==='MITIGATED'||e.status==='RESOLVED').length),'Recorded academic review statuses');
    if(model){$('analytics-recall').innerHTML=model.dataset.classes.map(cls=>{const r=Number(model.xgboost.classification_report[cls].recall)*100;return `<div class="analytic-bar"><div><span>${esc(pretty(cls))}</span><strong>${r.toFixed(2)}%</strong></div><div class="bar-track"><div class="bar-fill" style="width:${Math.max(0,Math.min(100,r))}%"></div></div></div>`;}).join('');}
    const counts=Object.fromEntries(categories.map(cls=>[cls,0]));for(const e of entries)counts[e.classification]=(counts[e.classification]||0)+1;
    const max=Math.max(1,...Object.values(counts));$('analytics-session').innerHTML=entries.length?categories.map(cls=>`<div class="analytic-bar"><div><span>${esc(pretty(cls))}</span><strong>${counts[cls]}</strong></div><div class="bar-track"><div class="bar-fill" style="width:${100*counts[cls]/max}%"></div></div></div>`).join(''):'<div class="empty-state"><span>⌁</span><h3>Nothing analyzed yet</h3><p>Run AI Defense to populate the dynamic distribution.</p></div>';
  }
  function renderReport(){
    const target=$('dynamic-report-preview');if(!target)return;
    const flagged=entries.filter(e=>e.classification!=='NORMAL').length;
    const labeled=entries.filter(e=>e.expected_label);const correct=labeled.filter(e=>e.expected_label===e.classification).length;
    target.innerHTML=`<div class="dynamic-report-lead"><div class="section-micro">GENERATED ${esc(new Date().toLocaleString())}</div><h3>Academic assessment summary</h3><p>${num(entries.length)} actual model inference(s) on synthetic numeric behavior; ${flagged} flagged predictions. Results are advisory, and no real incidents were evaluated.</p><p>${labeled.length?`${correct}/${labeled.length} labeled curated examples matched. This is not the model's held-out test accuracy.`:'No ground-truth labels were provided for the current records.'}</p></div><div class="table-scroll"><table class="dynamic-table"><thead><tr><th>Classification</th><th>Risk</th><th>Confidence</th><th>Case status</th><th>Source</th></tr></thead><tbody>${entries.length?entries.slice(0,30).map(e=>`<tr><td>${esc(pretty(e.classification))}</td><td>${Number(e.risk_score).toFixed(1)}</td><td>${pct(e.confidence)}</td><td>${esc(pretty(e.status))}</td><td>${esc(e.source_type==='numeric_csv'?'Numeric CSV':'Curated sample')}</td></tr>`).join(''):'<tr><td colspan="5">Analyze a synthetic sample to populate this live report.</td></tr>'}</tbody></table></div><p class="hint">Model version: ${esc(entries[0]?.model_version||'No run yet')}. Held-out evaluation and dynamically analyzed records are separate sources. Maximum 30 findings displayed in this print preview; JSON/CSV exports include the bounded current history.</p>`;
  }
  function exportJson(){download('fortressauth-it113-dynamic-findings.json',JSON.stringify({source:'IT113 synthetic numeric academic assessments',real_incidents:false,exported_at:new Date().toISOString(),persistence_mode:persistence?'private_session':'browser_only',entries},null,2),'application/json');}
  function exportCsv(){const cols=['at','source_type','sample_id','expected_label','classification','confidence','risk_score','anomaly_score','severity','status','model_version','trace_id'];const csv=[cols.join(','),...entries.map(e=>cols.map(k=>`"${String(e[k]??'').replace(/"/g,'""')}"`).join(','))].join('\r\n');download('fortressauth-it113-dynamic-findings.csv',csv,'text/csv');}
  async function clearHistory(){
    if(!entries.length)return;
    if(!window.confirm('Delete your current demo history? This removes server-saved findings for this anonymous browser too, if enabled.'))return;
    if(persistence){try{const r=await fetch('/it113_demo_history.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'clear'})});if(!r.ok)throw Error('Server deletion failed');}catch{window.alert('Server history could not be deleted. No local data changed.');return;}}
    entries=[];selectedTrace='';saveLocal();renderFindings();renderAnalytics();renderReport();
  }
  $('live-run-button')?.addEventListener('click',analyze);
  $('csv-template')?.addEventListener('click',sampleCsv);
  $('csv-input')?.addEventListener('change',ev=>importCsv(ev.target.files?.[0]));
  $('csv-run')?.addEventListener('click',analyzeCsv);
  $('findings-timeline')?.addEventListener('click',e=>{const b=e.target.closest('[data-trace]');if(b)showFinding(b.dataset.trace);});
  $('findings-refresh')?.addEventListener('click',()=>syncHistory());
  $('findings-clear')?.addEventListener('click',clearHistory);
  $('findings-export')?.addEventListener('click',exportJson);
  $('report-export-session')?.addEventListener('click',exportJson);
  $('report-export-csv')?.addEventListener('click',exportCsv);
  $('report-print')?.addEventListener('click',()=>window.print());
  storageBadge();renderFindings();renderAnalytics();renderReport();
  Promise.all([
    fetch('/assessment/evidence.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Sample catalog unavailable');return r.json();}),
    fetch('/assessment/model_summary.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Evaluation metadata unavailable');return r.json();})
  ]).then(([e,m])=>{
    if(e.not_live_inference!==true||e.contains_real_personal_data!==false)throw Error('Unverified data source');
    samples=e.examples.filter(x=>x.id&&x.features&&categories.includes(x.true_label));model=m;featureNames=m.dataset.features;
    const sel=$('live-sample-select');sel.innerHTML=samples.map(s=>`<option value="${esc(s.id)}">${esc(pretty(s.true_label))} · ${s.correct?'correct':'misclassified'} held-out example</option>`).join('');
    sel.addEventListener('change',()=>{const s=samples.find(x=>x.id===sel.value);$('live-sample-note').textContent=s?`Expected label: ${pretty(s.true_label)} · ${s.correct?'Correct':'Misclassified'} during saved evaluation · 20 features`:'';});sel.dispatchEvent(new Event('change'));
    renderAnalytics();setEngine('READY FOR REAL INFERENCE','ready');
  }).catch(e=>{setEngine('EVIDENCE UNAVAILABLE','error');$('live-result').textContent=`Unable to load synthetic catalog: ${e.message}`;});
  syncHistory();
})();
