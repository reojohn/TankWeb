/* IT113 Rubric D: advisory, read-only category-to-control mapping. No existing APIs are changed. */
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const pretty = v => String(v).split('_').map(w => w==='MFA'?'MFA':w.charAt(0)+w.slice(1).toLowerCase()).join(' ');
  const reference = {
    auth: {label:'OWASP Authentication Cheat Sheet', url:'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'},
    mfa: {label:'OWASP Multifactor Authentication Cheat Sheet',url:'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html'},
    logging:{label:'OWASP Logging Cheat Sheet',url:'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'},
    csrf:{label:'OWASP CSRF Prevention Cheat Sheet',url:'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'},
    session:{label:'OWASP Session Management Cheat Sheet',url:'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'},
    sql:{label:'OWASP SQL Injection Prevention Cheat Sheet',url:'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'},
    xss:{label:'OWASP XSS Prevention Cheat Sheet',url:'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'},
    access:{label:'OWASP Authorization Cheat Sheet',url:'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'},
    nist:{label:'NIST SP 800-61 Rev. 3 (2025)',url:'https://csrc.nist.gov/pubs/sp/800/61/r3/final'}
  };
  const plans = {
    NORMAL:{priority:'Monitor / baseline',basis:'Expected low-risk synthetic behavior; no confirmed vulnerability.',evidence:['Compare request rate and authentication outcomes against the approved baseline','Look for mismatches across time windows before flagging an anomaly'],actions:['Preserve proportionate security telemetry and baselines','Do not block, punish, or reset sessions solely because of an isolated score'],verify:['Confirm baseline test samples remain unblocked','Review false-positive trends after any detection-rule change'],refs:['logging','nist']},
    BRUTE_FORCE:{priority:'High review / authentication',basis:'Repeated failed-password attempts may indicate password guessing; successful compromise is not demonstrated.',evidence:['Correlate failed_logins_5m and failed_logins_15m with auth_endpoint_requests_5m','Check whether failures cluster around the same account or source, using authorized, minimized logs'],actions:['Apply per-account and per-source request throttling with non-disruptive cooldowns','Require appropriate MFA and review attempted account access','Review alerts without exposing passwords or account identifiers'],verify:['Run authorized synthetic repeated-login tests to confirm throttling responds','Confirm a legitimate user can recover access and rate limits do not create lockout abuse'],refs:['auth','mfa','nist']},
    CREDENTIAL_STUFFING:{priority:'High review / account protection',basis:'Attempts across multiple accounts are consistent with credential-stuffing patterns but do not confirm stolen credentials.',evidence:['Compare unique_usernames_15m with failures and successful_logins_15m','Review anonymized authentication outcomes for account-takeover signals'],actions:['Enforce throttling by both account and source to limit automation','Promote MFA and deny known compromised passwords where supported','Investigate possible account compromise through authorized channels'],verify:['Test synthetic multi-account login attempts for appropriate throttling','Verify account recovery and legitimate authentication remain usable'],refs:['auth','mfa','nist']},
    RECONNAISSANCE:{priority:'Investigate / attack-surface review',basis:'Broad path enumeration and restricted-route probing may indicate reconnaissance, not exploitation.',evidence:['Inspect unique_paths_5m, sensitive_path_probes_15m and scanner_events_15m','Check whether targeted routes are expected, exposed, or misconfigured'],actions:['Limit administrative surface exposure and enforce authorization on restricted routes','Patch vulnerable components using an approved change process','Retain proportionate audit evidence for follow-up review'],verify:['Confirm authorization denies synthetic unauthorized route requests','Verify approved services remain accessible and routing is unchanged'],refs:['access','logging','nist']},
    WEB_ATTACK:{priority:'High review / application security',basis:'Suspicious request and method anomalies suggest application-layer probes; no SQL injection or XSS exploit is verified.',evidence:['Examine suspicious_requests_15m, csrf_failures_15m and method_anomalies_15m','Use sanitized authorized application test evidence to distinguish malformed requests from actual vulnerable handling'],actions:['Use prepared or parameterized database queries in dynamic SQL paths','Apply contextual output encoding for rendered untrusted content','Confirm server-side input validation and limit inappropriate methods'],verify:['Run authorized non-destructive input-validation regression tests','Verify unsafe example inputs are safely handled without false claims of an exploit'],refs:['sql','xss','csrf','nist']},
    MFA_ABUSE:{priority:'High review / second factor',basis:'Repeated second-factor failures may indicate guessing or friction; the factor itself is not proven bypassed.',evidence:['Review qr_failures_15m against login outcomes and challenge retries','Inspect sanitized challenge expiry, binding and reuse metadata where permitted'],actions:['Rate-limit second-factor attempts without allowing infinite challenges','Bind and expire verification challenges appropriately','Monitor repeated failures and support safe recovery procedures'],verify:['Test expiration and replay rejection with controlled synthetic challenges','Verify legitimate account recovery remains available'],refs:['mfa','auth','nist']},
    SESSION_ABUSE:{priority:'High review / session controls',basis:'CSRF rejection, user-agent changes and session anomalies can warrant review; they do not establish hijacking.',evidence:['Check csrf_failures_15m, ua_changes_15m and auth_rejections_15m','Inspect protected session lifecycle and auth transitions using authorized audit data'],actions:['Rotate session identifiers after privilege change and authentication','Use appropriately scoped Secure, HttpOnly and SameSite cookie attributes','Apply CSRF defenses to state-changing requests and enforce session expiration'],verify:['Verify session regeneration and expiration in authorized regression tests','Test safe CSRF rejection while confirming legitimate state changes still work'],refs:['session','csrf','access','nist']}
  };
  const link = key => {const r=reference[key];return `<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.label)} ↗</a>`;};
  const rows = (label,items) => `<div class="rubric-d-column"><h4>${esc(label)}</h4><ol>${items.map(s=>`<li>${esc(s)}</li>`).join('')}</ol></div>`;
  function renderPlan(category, compact=false) {
    const p=plans[category];if(!p)return '<p class="hint">Select an existing synthetic finding for category-linked guidance.</p>';
    return `<div class="rubric-d-plan" data-plan="${esc(category)}"><div class="rubric-d-plan-head"><div><span class="section-micro">${compact?'SELECTED FINDING /':'RUBRIC D /'} ADVISORY RESPONSE PLAN</span><h3>${esc(pretty(category))}</h3></div><strong>${esc(p.priority)}</strong></div><p class="rubric-d-basis"><b>Observed-pattern interpretation:</b> ${esc(p.basis)}</p><div class="rubric-d-plan-grid">${rows('1. Confirm the evidence',p.evidence)}${rows('2. Response / prevention',p.actions)}${rows('3. Verify effectiveness',p.verify)}</div><div class="rubric-d-framework"><b>Security guidance:</b> ${p.refs.map(link).join(' ')}</div><p class="hint">Mapping is category-based and derived from known synthetic behaviors. An actual vulnerability, identity, cause, and remediation effectiveness must be confirmed by authorized review.</p></div>`;
  }
  function exportPlan(category){
    const p=plans[category]; if(!p)return;
    const output={study:'Aegis AI IT113 Rubric D category response plan',generated_at:new Date().toISOString(),category,synthetic:true,confirmed_incident:false,confirmed_vulnerability:false,priority:p.priority,interpretation:p.basis,evidence_to_verify:p.evidence,mitigation_actions:p.actions,effectiveness_checks:p.verify,security_references:p.refs.map(k=>reference[k]),review_required:true,notes:'A model category does not prove an exploitable weakness or an actual incident. Validate controls on an authorized environment.'};
    const url=URL.createObjectURL(new Blob([JSON.stringify(output,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='it113-response-plan-'+category.toLowerCase()+'.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  // Finding-specific control mapping is deterministic. It adapts to the exact
  // saved indicator names and observed counts; it never claims a missing control.
  const findingControls = {
    NORMAL:[
      {title:'Monitor and preserve baseline',features:[],action:'Maintain proportionate logging and review for changes from this baseline.',verify:'Check that normal synthetic activity is not unnecessarily blocked.'}
    ],
    BRUTE_FORCE:[
      {title:'Review authentication throttling',features:['failed_logins_15m','failed_logins_5m','requests_1m'],action:'Check whether per-account and per-source throttling, progressive delays, and recovery safeguards are configured; consider strengthening them where needed.',verify:'In an authorized test environment, confirm repeated failures trigger the expected throttling without enabling lockout abuse.'},
      {title:'Investigate authentication denials',features:['auth_rejections_15m'],action:'Correlate rejected access with failed-logins using approved, minimized audit data; investigate unusual patterns.',verify:'Confirm alert events and log windows align with known test actions.'},
      {title:'Assess MFA coverage',features:[],action:'Review the applicable MFA policy and challenge enforcement; recommend MFA where risk and policy warrant.',verify:'Inspect configuration and authorized sign-in tests to confirm applicable MFA controls operate.'}
    ],
    CREDENTIAL_STUFFING:[
      {title:'Assess multi-account protection',features:['unique_usernames_15m','failed_logins_15m'],action:'Review failed logins across multiple accounts and evaluate per-account/source cooldowns and compromised-password screening.',verify:'Use synthetic multi-account attempts to verify appropriate throttling and recovery behavior.'},
      {title:'Investigate request bursts',features:['requests_1m','auth_rejections_15m'],action:'Review abnormal request bursts and resource rejections; correlate them with anonymized login outcomes.',verify:'Compare detection alerts with authorized test inputs and investigate false positives.'},
      {title:'Validate MFA and credential controls',features:[],action:'Confirm MFA coverage and password-handling policy independently before concluding a control is absent.',verify:'Review applicable policy, configuration and authorized sign-in enforcement.'}
    ],
    RECONNAISSANCE:[
      {title:'Review endpoint probing',features:['unique_paths_5m','sensitive_path_probes_15m','scanner_events_15m'],action:'Check whether probed paths are expected and whether access restrictions protect administrative endpoints.',verify:'Test denial of unauthorized access to known synthetic routes while preserving legitimate access.'},
      {title:'Review suspicious request rates',features:['requests_1m'],action:'Correlate request bursts with endpoint discovery signals before describing behavior as scanning.',verify:'Confirm log and alert timestamps against a controlled synthetic probe.'},
      {title:'Maintain attack-surface inventory',features:[],action:'Review exposed services and patch status through authorized inventory processes.',verify:'Compare inventory findings against approved configurations.'}
    ],
    WEB_ATTACK:[
      {title:'Inspect abnormal application inputs',features:['suspicious_requests_15m','method_anomalies_15m'],action:'Review sanitized abnormal requests and evaluate server-side validation and contextual output encoding.',verify:'Run non-destructive tests to check that inputs are handled safely.'},
      {title:'Verify CSRF control behavior',features:['csrf_failures_15m'],action:'Review CSRF rejection patterns without assuming bypass; check server validation on state-changing routes.',verify:'Check safe CSRF rejection and authorized workflow success.'},
      {title:'Review SQL query safety',features:[],action:'Check whether relevant database code uses parameterized queries; suspicious traffic alone does not prove injection.',verify:'Confirm secure query construction through code review and approved regression tests.'}
    ],
    MFA_ABUSE:[
      {title:'Inspect second-factor failures',features:['qr_failures_15m','auth_rejections_15m'],action:'Review second-factor rejection trends and configured attempt limits.',verify:'Test controlled expired, repeated and invalid challenges for appropriate rejection.'},
      {title:'Validate challenge lifecycle',features:[],action:'Review challenge binding, expiration, replay protection and recovery policy.',verify:'Confirm one-time use, expiry and authorized recovery behavior.'}
    ],
    SESSION_ABUSE:[
      {title:'Review session transitions',features:['ua_changes_15m','auth_rejections_15m'],action:'Correlate session and authentication changes with authorized activity before alleging hijacking.',verify:'Check session regeneration, expiry and authorized access across test transitions.'},
      {title:'Review CSRF rejections',features:['csrf_failures_15m'],action:'Inspect synthetic CSRF failures and confirm server-side validation on state-changing requests.',verify:'Test rejection of invalid tokens without breaking legitimate operations.'},
      {title:'Validate cookie hardening',features:[],action:'Review the Secure, HttpOnly and SameSite settings and session lifetime rules.',verify:'Inspect effective response headers and cookie behavior in a controlled environment.'}
    ]
  };
  let linkedItems=[],linkedScope='public',linkedSelected='',linkedConnected=false;
  const clampNumber=(v,min,max)=>Number.isFinite(Number(v))?Math.min(max,Math.max(min,Number(v))):0;
  function cleanFinding(x){
    if(!x || !plans[x.classification] || !/^[a-f0-9]{32}$/.test(String(x.trace_id||'')))return null;
    return {
      trace_id:x.trace_id,classification:x.classification,
      expected_label:plans[x.expected_label]?x.expected_label:null,
      risk_score:clampNumber(x.risk_score,0,100),confidence:clampNumber(x.confidence,0,1),
      status:['OPEN','INVESTIGATING','MITIGATED','RESOLVED'].includes(x.status)?x.status:'OPEN',
      severity:String(x.severity||'').slice(0,20),sample_id:String(x.sample_id||'').slice(0,60),at:String(x.at||'').slice(0,50),
      indicator_evidence:(Array.isArray(x.indicator_evidence)?x.indicator_evidence:[]).slice(0,6)
        .filter(i=>i&&/^[a-z][a-z0-9_]{0,59}$/.test(String(i.feature||'')) && Number.isFinite(Number(i.observed)))
        .map(i=>({feature:i.feature,observed:clampNumber(i.observed,0,1000000),description:String(i.description||'').slice(0,160)}))
    };
  }
  function selectedFinding(){return linkedItems.find(x=>x.trace_id===linkedSelected)||null;}
  function caseControls(finding){
    const detected=new Map(finding.indicator_evidence.map(i=>[i.feature,i]));
    return (findingControls[finding.classification]||[]).map((item,i)=>{
      const hits=item.features.map(k=>detected.get(k)).filter(Boolean);
      return {...item,order:i,hits,linked:hits.length>0};
    }).sort((a,b)=>Number(b.linked)-Number(a.linked)||a.order-b.order);
  }
  function findingPlanData(finding){
    const p=plans[finding.classification];
    const concerns=[];
    if(finding.expected_label&&finding.expected_label!==finding.classification)concerns.push('Held-out label differs from the model prediction; validate the category before prioritizing category-specific controls.');
    if(finding.confidence<0.5)concerns.push('Low classification score: alternative behaviors should be investigated before choosing a response.');
    const controls=caseControls(finding);
    return {study:'Aegis AI IT113 / finding-linked mitigation review',generated_at:new Date().toISOString(),scope:linkedScope,
      synthetic:true,confirmed_incident:false,confirmed_vulnerability:false,enforcement_performed:false,
      finding:{trace_id:finding.trace_id,sample_id:finding.sample_id,classification:finding.classification,
        expected_label:finding.expected_label,confidence:finding.confidence,risk_score:finding.risk_score,
        recorded_review_status:finding.status,observed_indicators:finding.indicator_evidence},
      research_cautions:concerns,verification_required:true,
      prioritized_controls:controls.map(c=>({name:c.title,evidence_linked:c.linked,
        supporting_indicators:c.hits,proposed_action:c.action,effectiveness_check:c.verify})),
      framework_guidance:p.refs.map(k=>reference[k]),
      note:'These are preventive and verification recommendations, not confirmation of a missing control. Status is recorded analyst review, not a measurement of remediation effectiveness.'};
  }
  function renderLinkedPlan(){
    const host=$('rubric-d-case-plan'),sel=$('rubric-d-case-select');if(!host||!sel)return;
    const flagged=linkedItems.filter(x=>x.classification!=='NORMAL');
    const prior=linkedSelected;
    if(!flagged.some(x=>x.trace_id===prior))linkedSelected=flagged[0]?.trace_id||'';
    sel.innerHTML=flagged.length?flagged.map(f=>`<option value="${esc(f.trace_id)}" ${linkedSelected===f.trace_id?'selected':''}>${esc(pretty(f.classification))} · Risk ${f.risk_score.toFixed(1)} · ${esc(pretty(f.status))} · ${esc(f.sample_id||'Synthetic test')}</option>`).join(''):
      '<option value="">No flagged synthetic findings in this view</option>';
    const f=selectedFinding(),exportButton=$('rubric-d-export-case'),open=$('rubric-d-open-finding');
    if(exportButton)exportButton.disabled=!f;
    if(open)open.disabled=!f;
    const scope=$('rubric-d-scope');if(scope)scope.textContent=linkedScope==='public'?
      `${flagged.length} public curated flagged finding(s) · synchronized with the existing public research feed${linkedConnected?'':' · public storage may be unavailable'}.`:
      `${flagged.length} flagged finding(s) from My tests · private to this browser session; never published by this workspace.`;
    if(!f){host.innerHTML='<div class="rubric-d-case-empty"><strong>No flagged findings yet</strong><p>Run a curated synthetic example in AI Defense, or select My tests in Threat Findings to inspect your own private numeric analyses. Category reference plans remain available below.</p><button type="button" class="subtle-btn" data-go-to="defense">Open AI Defense ↗</button></div>';return;}
    const p=plans[f.classification];const controls=caseControls(f);
    const low=f.confidence<0.5, mismatch=f.expected_label&&f.expected_label!==f.classification;
    const warnings=[...(mismatch?[`The saved held-out label is ${pretty(f.expected_label)}, but the model predicted ${pretty(f.classification)}. Treat this as a classification mismatch.`]:[]),...(low?['Low model classification score; alternative interpretations may be plausible.']:[])];
    host.innerHTML=`<div class="rubric-d-case-hero"><div><span class="section-micro">${linkedScope==='public'?'PUBLIC CURATED':'MY SESSION'} / SELECTED MODEL INFERENCE</span><h3>${esc(pretty(f.classification))}</h3><p>${esc(p.basis)}</p></div><div class="rubric-d-case-metrics"><div><span>HYBRID RISK</span><b>${f.risk_score.toFixed(1)}<small> / 100</small></b></div><div><span>CLASS SCORE</span><b>${(100*f.confidence).toFixed(2)}%</b></div><div><span>REVIEW STATUS</span><b>${esc(pretty(f.status))}</b></div></div></div>
      ${warnings.length?`<div class="rubric-d-warning"><strong>Review before action</strong><ul>${warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul></div>`:''}
      <div class="rubric-d-case-columns"><section><h4>Evidence recorded with this finding</h4>${f.indicator_evidence.length?`<div class="rubric-d-indicators">${f.indicator_evidence.map(i=>`<div><code>${esc(i.feature)}</code><b>${esc(i.observed)}</b><span>${esc(i.description)}</span></div>`).join('')}</div>`:'<p class="hint">No threshold indicators were recorded for this finding; do not infer absent or ineffective controls.</p>'}<p class="hint">These supporting indicators are not XGBoost feature attributions. Aggregate numeric measurements alone cannot confirm a vulnerability.</p></section>
      <section><h4>Priority response plan</h4><div class="rubric-d-control-list">${controls.map((c,i)=>`<article class="rubric-d-control"><div class="rubric-d-control-title"><b>${i+1}. ${esc(c.title)}</b><span class="${c.linked?'linked':'general'}">${c.linked?'Indicator-linked':'Best-practice review'}</span></div>${c.linked?`<p class="rubric-d-why"><strong>Observed:</strong> ${c.hits.map(h=>`<code>${esc(h.feature)}</code> ${esc(h.observed)}`).join(' · ')}</p>`:''}<p><strong>Consider:</strong> ${esc(c.action)}</p><p><strong>Verify:</strong> ${esc(c.verify)}</p></article>`).join('')}</div></section></div>
      <div class="rubric-d-case-footer"><p><strong>Case follow-up:</strong> Recorded status is <b>${esc(pretty(f.status))}</b>. To change it, open this finding in Threat Findings. Only the submitting session may update public cases; status does not certify control effectiveness.</p><p><strong>Relevant guidance:</strong> ${p.refs.map(link).join(' ')}</p><p class="hint">This response plan is determined from the saved synthetic model finding and approved category guidance; no LLM request or enforcement action is made.</p></div>`;
  }
  function setupLinkedWorkspace(){
    const sel=$('rubric-d-case-select');if(!sel)return;
    sel.addEventListener('change',()=>{
      if(!linkedItems.some(x=>x.trace_id===sel.value))return;
      linkedSelected=sel.value;renderLinkedPlan();
      window.dispatchEvent(new CustomEvent('fortress:select-mitigation-finding',{detail:{trace_id:linkedSelected}}));
    });
    $('rubric-d-export-case')?.addEventListener('click',()=>{
      const finding=selectedFinding();if(!finding)return;
      const data=findingPlanData(finding);
      const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
      const a=document.createElement('a');a.href=url;a.download='it113-finding-mitigation-'+finding.trace_id.slice(0,10)+'.json';
      document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500);
    });
    window.addEventListener('fortress:mitigation-context',event=>{
      const d=event.detail;if(!d||!Array.isArray(d.items)||!['public','session'].includes(d.scope))return;
      const oldScope=linkedScope;
      linkedScope=d.scope;linkedConnected=d.public_connected===true;
      linkedItems=d.items.slice(0,80).map(cleanFinding).filter(Boolean);
      if(oldScope!==linkedScope)linkedSelected='';
      if(linkedItems.some(f=>f.trace_id===d.selected_trace&&f.classification!=='NORMAL'))linkedSelected=d.selected_trace;
      renderLinkedPlan();
    });
    renderLinkedPlan();
    window.dispatchEvent(new Event('fortress:request-mitigation-context'));
  }

  function setup(){
    const sel=$('rubric-d-category');if(!sel||!$('rubric-d-detail'))return;
    const categories=Object.keys(plans);
    sel.innerHTML='<option value="ALL">Choose a behavior category</option>'+categories.map(c=>`<option value="${esc(c)}">${esc(pretty(c))}</option>`).join('');
    const current=()=>sel.value;
    const update=()=>{ $('rubric-d-detail').innerHTML=renderPlan(current());$('rubric-d-export').disabled=!plans[current()];};
    sel.addEventListener('change',()=>{
      update();
      // Reuse the existing Rubric D category filter; do not change its original handler.
      const existing=[...document.querySelectorAll('#phase3-mitigation-filters button[data-filter]')].find(b=>b.dataset.filter===current());
      if(existing)existing.click();
    });
    // Keep new and original dropdown/filter controls consistent in either direction.
    $('phase3-mitigation-filters')?.addEventListener('click',ev=>{
      const button=ev.target.closest('button[data-filter]');
      if(!button||!(button.dataset.filter==='ALL'||plans[button.dataset.filter]))return;
      sel.value=button.dataset.filter;update();
    });
    $('rubric-d-export')?.addEventListener('click',()=>exportPlan(current()));update();setupLinkedWorkspace();
    const finding=$('finding-detail'),context=$('rubric-d-finding-guidance');if(!finding||!context)return;
    let last='';const updateFinding=()=>{
      const label=(finding.querySelector('.finding-topline h3')?.textContent||'').trim().toUpperCase().replace(/\s+/g,'_');
      if(label===last)return;last=label;
      context.innerHTML=plans[label]?renderPlan(label,true):'<p class="hint">Choose a finding from the assessment timeline to see category-specific response and verification guidance.</p>';
    };
    new MutationObserver(updateFinding).observe(finding,{subtree:true,childList:true});updateFinding();
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',setup,{once:true});else setup();
})();
