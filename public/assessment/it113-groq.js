/* FortressAuth optional LLM security research assistant.
 * No keys in browser. Only a selected curated synthetic sample identifier leaves
 * this page; backend retrieves and validates numeric evidence and ML prediction.
 * Neither chat nor its explanations are saved to the shared public feed.
 */
'use strict';
(() => {
  const byId = id => document.getElementById(id);
  const MAX_TURNS = 6;
  let conversation = [];
  let busy = false;
  let activeSample = '';

  function sampleId() {
    const selected = byId('live-sample-select')?.value || '';
    return /^[a-z0-9_]{3,60}$/.test(selected) ? selected : '';
  }
  function message(text, kind = '') {
    const el = byId('groq-status');
    if (el) {
      el.textContent = text;
      el.dataset.kind = kind;
    }
  }
  function enableControls() {
    const valid = Boolean(sampleId());
    const analyst = byId('groq-run-analyst');
    const send = byId('groq-chat-send');
    const input = byId('groq-chat-input');
    if (analyst) analyst.disabled = !valid || busy;
    if (send) send.disabled = !valid || busy || !input?.value.trim();
    if (input) input.disabled = !valid || busy;
  }
  function appendChat(role, text, engine) {
    const target = byId('groq-chat-messages');
    if (!target) return;
    const article = document.createElement('article');
    article.className = 'groq-chat-turn groq-chat-turn--' + (role === 'user' ? 'user' : 'assistant');
    const heading = document.createElement('strong');
    heading.textContent = role === 'user' ? 'You' : (engine === 'groq' ? 'Groq Security Analyst' : 'Verified baseline guidance');
    const body = window.FortressGroqMarkdown?.render(text) || document.createTextNode(text);
    article.append(heading, body);
    target.append(article);
    target.scrollTop = target.scrollHeight;
  }
  function resetForSample() {
    const chosen = sampleId();
    if (chosen === activeSample) return;
    activeSample = chosen;
    conversation = [];
    const output = byId('groq-analyst-result');
    const chat = byId('groq-chat-messages');
    if (output) output.textContent = 'No AI explanation has been requested for this sample yet.';
    if (chat) chat.replaceChildren();
    message(chosen ? 'Ready · curated synthetic example · explanations are private to this tab.' : 'Choose a curated synthetic example first.');
    enableControls();
  }
  async function request(mode, question = '') {
    resetForSample();
    const chosen = activeSample;
    if (!chosen || busy) return;
    busy = true;
    const previousHistory = conversation.slice(-MAX_TURNS);
    enableControls();
    message(mode === 'analyst' ? 'Generating an evidence-grounded assessment…' : 'Preparing a contextual answer…');
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 23000);
    try {
      const response = await fetch('/it113_security_assistant.php', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type':'application/json', 'Accept':'application/json'},
        body: JSON.stringify({sample_id:chosen, mode, question, history:mode==='chat'?previousHistory:[]}),
        signal: ctrl.signal
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok !== true || data.sample_id !== chosen || data.synthetic !== true ||
          !['groq','deterministic_fallback'].includes(data.engine) || typeof data.answer !== 'string') {
        throw new Error(data.error || `Service returned HTTP ${response.status}.`);
      }
      // If the sample changed while a request was in flight, discard its result.
      if (sampleId() !== chosen) return;
      const modelResult = `Trained model: ${String(data.classification).replaceAll('_',' ')} · Risk: ${Number(data.risk_score).toFixed(1)}/100 · Confidence: ${(Number(data.confidence)*100).toFixed(2)}%`;
      if (mode === 'analyst') {
        const target = byId('groq-analyst-result');
        if (target) {
          const summary = document.createElement('div');
          summary.className = 'groq-model-summary';
          summary.textContent = modelResult;
          const content = window.FortressGroqMarkdown?.render(data.answer) || document.createTextNode(data.answer);
          target.replaceChildren(summary, content);
        }
        // A new assessment invalidates the prior follow-up conversation.
        conversation = [];
        byId('groq-chat-messages')?.replaceChildren();
      } else {
        appendChat('user',question);
        appendChat('assistant',data.answer,data.engine);
        conversation.push({role:'user',content:question},{role:'assistant',content:data.answer.slice(0,700)});
        conversation = conversation.slice(-MAX_TURNS);
      }
      message(data.engine==='groq' ? 'Groq AI response · grounded in a freshly recomputed synthetic ML prediction.' :
        'Groq unavailable or not configured · deterministic baseline guidance shown.',
        data.engine==='groq'?'success':'fallback');
    } catch(error) {
      if (sampleId() === chosen) message(error?.name==='AbortError' ?
        'The AI request timed out. Existing ML analysis is unaffected.' :
        (error?.message || 'AI explanation unavailable.'), 'error');
    } finally {
      clearTimeout(timeout);
      busy = false;
      resetForSample();
      enableControls();
    }
  }
  function init() {
    const panel = byId('it113-groq-panel');
    const selector = byId('live-sample-select');
    if (!panel || !selector) return;
    selector.addEventListener('change', resetForSample);
    byId('groq-run-analyst')?.addEventListener('click', () => request('analyst'));
    const form = byId('groq-chat-form');
    const input = byId('groq-chat-input');
    input?.addEventListener('input', enableControls);
    form?.addEventListener('submit', e => {
      e.preventDefault();
      const question = input?.value.trim() || '';
      if (!question || busy || !sampleId()) return;
      if (input) input.value = '';
      request('chat', question);
    });
    byId('groq-chat-clear')?.addEventListener('click', () => {
      conversation = [];
      byId('groq-chat-messages')?.replaceChildren();
      message('Chat cleared in this tab. No public assessment records were changed.');
      enableControls();
    });
    resetForSample();
    // Existing live JS populates sample choices asynchronously. No polling or
    // mutation of its state is required; user interaction triggers update.
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',init,{once:true});
  else init();
})();
