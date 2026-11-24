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
    const output={study:'FortressAuth IT113 Rubric D category response plan',generated_at:new Date().toISOString(),category,synthetic:true,confirmed_incident:false,confirmed_vulnerability:false,priority:p.priority,interpretation:p.basis,evidence_to_verify:p.evidence,mitigation_actions:p.actions,effectiveness_checks:p.verify,security_references:p.refs.map(k=>reference[k]),review_required:true,notes:'A model category does not prove an exploitable weakness or an actual incident. Validate controls on an authorized environment.'};
    const url=URL.createObjectURL(new Blob([JSON.stringify(output,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='it113-response-plan-'+category.toLowerCase()+'.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
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
    $('rubric-d-export')?.addEventListener('click',()=>exportPlan(current()));update();
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
