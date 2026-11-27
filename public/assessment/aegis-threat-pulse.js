/* Aegis AI Threat Pulse: presentation-only, public curated feed only.
   No network calls, no private CSV data, no new timers. */
'use strict';
(() => {
  const widget=document.getElementById('aegis-threat-pulse');
  if(!widget)return;
  const lookup=id=>document.getElementById(id);
  const state=lookup('aegis-pulse-status');
  const name=lookup('aegis-pulse-class');
  const kicker=lookup('aegis-pulse-kicker');
  const severity=lookup('aegis-pulse-severity');
  const risk=lookup('aegis-pulse-risk');
  const action=lookup('aegis-pulse-action');
  const announcement=lookup('aegis-pulse-announcement');
  const allowed=['NORMAL','BRUTE_FORCE','CREDENTIAL_STUFFING','RECONNAISSANCE','WEB_ATTACK','MFA_ABUSE','SESSION_ABUSE'];
  let selectedTrace='';
  let lastAnnounced='';
  const pretty=value=>String(value).replace(/_/g,' ').toLowerCase().replace(/\b\w/g,c=>c.toUpperCase()).replace(/\bMfa\b/g,'MFA');
  function setStatus(value,label){
    widget.dataset.state=value;
    state.querySelector('span').textContent=label;
  }
  function update(event){
    const d=event.detail;
    if(!d || d.source!=='public_curated')return;
    const f=d.latest;
    const valid=f && /^[a-f0-9]{32}$/.test(String(f.trace_id||'')) && allowed.includes(f.classification) &&
      Number.isFinite(Number(f.risk_score)) && Number(f.risk_score)>=0 && Number(f.risk_score)<=100;
    if(!valid){
      selectedTrace='';name.textContent='No findings yet';
      kicker.textContent='PUBLIC SYNTHETIC FEED';severity.textContent=d.connected?'Awaiting first assessment':'Public feed unavailable';
      risk.textContent='—';widget.style.setProperty('--pulse-fill','0%');
      action.textContent='Open Threat Findings';widget.setAttribute('aria-label','Open public Threat Findings');setStatus(d.connected?'empty':'stale',d.connected?'Ready':'Offline');
      return;
    }
    selectedTrace=f.trace_id;
    const riskNumber=Number(f.risk_score);
    name.textContent=pretty(f.classification);
    const anomalyOnly=window.AegisReview.anomalyOnly(f);
    kicker.textContent=anomalyOnly?'ANOMALY REQUIRING REVIEW':'LATEST SYNTHETIC ASSESSMENT';
    severity.textContent=pretty(f.severity||'Advisory')+' risk · Advisory';
    risk.textContent=riskNumber.toFixed(1);
    widget.style.setProperty('--pulse-fill',riskNumber+'%');
    action.textContent='Review this finding';widget.setAttribute('aria-label','Open latest public synthetic '+pretty(f.classification)+' finding in Threat Findings');
    setStatus(d.connected?'synced':'stale',d.connected?'Synced':'Last known');
    const signature=f.trace_id+':'+(d.connected?'connected':'stale');
    if(signature!==lastAnnounced){
      announcement.textContent=(d.connected?'Latest public synthetic finding: ':'Last known public synthetic finding: ')+pretty(f.classification)+', risk '+riskNumber.toFixed(1)+' out of 100';
      lastAnnounced=signature;
    }
  }
  window.addEventListener('aegis:public-threat-pulse',update);
  widget.addEventListener('click',()=>{
    // The sidebar always opens public results, never the selected user's CSV history.
    const publicToggle=document.querySelector('[data-project-mode="public"]');
    if(publicToggle && publicToggle.getAttribute('aria-pressed')!=='true')publicToggle.click();
    document.querySelector('.sidebar .nav-link[data-view="findings"]')?.click();
    if(selectedTrace){
      window.dispatchEvent(new CustomEvent('fortress:select-mitigation-finding',{
        detail:{trace_id:selectedTrace}
      }));
    }
  });
  // The data module may have restored a previously cached public result
  // before this presentation script registered its listener.
  window.dispatchEvent(new Event('aegis:request-threat-pulse'));
})();
