/* Aegis AI optional security research assistant.
 * Keeps curated synthetic chat private to this tab; never publishes to shared feed.
 * User messages render immediately and pending replies remain visible on failures.
 */
'use strict';
(() => {
  const byId = id => document.getElementById(id);
  const MAX_TURNS = 6;
  let conversation = [];
  let busy = false;
  let activeSample = '';
  let requestSerial = 0;
  let currentController = null;
  let inFlightMode = '';
  let headerOrb = null;
  let statusOrb = null;

  function sampleId() {
    const selected = byId('live-sample-select')?.value || '';
    return /^[a-z0-9_]{3,60}$/.test(selected) ? selected : '';
  }
  function message(text, kind = '') {
    const element = byId('groq-status');
    if (!element) return;
    element.textContent = text;
    element.dataset.kind = kind;
    if (headerOrb) headerOrb.setState(kind === 'pending' ? 'thinking' : (kind === 'error' ? 'error' : (kind === 'success' ? 'ready' : 'idle')));
    const holder = byId('groq-status-orb');
    if (holder) holder.hidden = kind !== 'pending';
    if (kind === 'pending') statusOrb?.setState('thinking');
  }
  function chatTarget() { return byId('groq-chat-messages'); }
  function scrollChat() {
    const target = chatTarget();
    if (target) target.scrollTop = target.scrollHeight;
  }
  function updateSuggestions() {
    const suggestions = byId('groq-chat-suggestions');
    if (suggestions) suggestions.hidden = Boolean(chatTarget()?.children.length);
  }
  function resizeComposer() {
    const input = byId('groq-chat-input');
    if (!input) return;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 192) + 'px';
    input.style.overflowY = input.scrollHeight > 192 ? 'auto' : 'hidden';
    const count = byId('groq-chat-count');
    if (count) {
      count.textContent = `${input.value.length} / 500`;
      count.dataset.nearLimit = input.value.length >= 450 ? 'true' : 'false';
    }
  }
  function enableControls() {
    const valid = Boolean(sampleId());
    const analyst = byId('groq-run-analyst');
    const send = byId('groq-chat-send');
    const input = byId('groq-chat-input');
    if (analyst) {
      analyst.disabled = !valid || busy;
      analyst.classList.toggle('groq-is-busy', busy && inFlightMode === 'analyst');
      analyst.setAttribute('aria-busy', String(busy && inFlightMode === 'analyst'));
    }
    if (input) input.disabled = !valid;
    if (send) {
      send.disabled = !valid || busy || !input?.value.trim();
      send.classList.toggle('groq-is-busy', busy && inFlightMode === 'chat');
      send.setAttribute('aria-busy', String(busy && inFlightMode === 'chat'));
    }
  }
  function createChatTurn(role, text = '', engine = 'groq') {
    const article = document.createElement('article');
    const isUser = role === 'user';
    article.className = 'groq-chat-turn ' + (isUser ? 'groq-chat-turn--user' : 'groq-chat-turn--assistant');
    const heading = document.createElement('div');
    heading.className = 'groq-chat-turn-heading';
    const avatar = document.createElement('span');
    avatar.className = 'groq-chat-avatar';
    avatar.setAttribute('aria-hidden', 'true');
    avatar.textContent = isUser ? 'Y' : '✧';
    const label = document.createElement('strong');
    label.textContent = isUser ? 'You' : (engine === 'groq' ? 'Security Analyst' : 'Verified baseline guidance');
    heading.append(avatar, label);
    const body = document.createElement('div');
    body.className = 'groq-chat-body';
    if (text) {
      const content = isUser ? document.createTextNode(text) :
        (window.FortressGroqMarkdown?.render(text) || document.createTextNode(text));
      body.append(content);
    }
    article.append(heading, body);
    chatTarget()?.append(article);
    scrollChat();
    updateSuggestions();
    return article;
  }
  function makePending() {
    const article = createChatTurn('assistant');
    article.classList.add('groq-chat-turn--pending');
    article.setAttribute('role', 'status');
    article.setAttribute('aria-label', 'Security Analyst is responding');
    const body = article.querySelector('.groq-chat-body');
    const progress = document.createElement('div');
    progress.className = 'groq-thinking';
    const orbHost = document.createElement('span');
    orbHost.className = 'groq-thinking-orb';
    orbHost.setAttribute('aria-hidden', 'true');
    const orb = window.FortressThinkingOrb?.mount(orbHost, 'thinking', 32);
    if (!orb) {
      const dots = document.createElement('span');
      dots.className = 'groq-thinking-dots';
      for (let i = 0; i < 3; i++) dots.append(document.createElement('i'));
      orbHost.append(dots);
    }
    const text = document.createElement('span');
    text.textContent = 'Reviewing verified evidence…';
    progress.append(orbHost, text);
    body?.append(progress);
    return article;
  }
  function completePending(article, text, engine) {
    if (!article?.isConnected) return;
    article.classList.remove('groq-chat-turn--pending', 'groq-chat-turn--error');
    article.removeAttribute('role');
    article.removeAttribute('aria-label');
    const label = article.querySelector('.groq-chat-turn-heading strong');
    if (label) label.textContent = engine === 'groq' ? 'Security Analyst' : 'Verified baseline guidance';
    const body = article.querySelector('.groq-chat-body');
    const rendered = window.FortressGroqMarkdown?.render(text) || document.createTextNode(text);
    body?.replaceChildren(rendered);
    scrollChat();
  }
  function failedPending(article, question, detail) {
    if (!article?.isConnected) return;
    article.classList.remove('groq-chat-turn--pending');
    article.classList.add('groq-chat-turn--error');
    article.removeAttribute('role');
    article.removeAttribute('aria-label');
    const body = article.querySelector('.groq-chat-body');
    const note = document.createElement('p');
    note.textContent = detail === 'timeout' ?
      'The request took too long. Your question is still here.' :
      'The analyst could not respond. Your question was not lost.';
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'groq-retry-button';
    retry.textContent = 'Retry response ↗';
    retry.addEventListener('click', () => { if (!busy && article.isConnected) void request('chat', question, article); });
    body?.replaceChildren(note, retry);
    scrollChat();
  }
  function cancelInFlight() {
    requestSerial++;
    currentController?.abort();
    currentController = null;
    busy = false;
    inFlightMode = '';
  }
  function emptyAssessment() {
    const target = byId('groq-analyst-result');
    if (!target) return;
    const empty = document.createElement('div');
    empty.className = 'groq-placeholder';
    const marker = document.createElement('span');
    marker.textContent = '◇'; marker.setAttribute('aria-hidden','true');
    const copy = document.createElement('p');
    copy.textContent = 'Run a curated example above, then generate an evidence-grounded assessment.';
    empty.append(marker, copy);
    target.replaceChildren(empty);
  }
  function resetForSample() {
    const chosen = sampleId();
    if (chosen === activeSample) return;
    cancelInFlight();
    activeSample = chosen;
    conversation = [];
    emptyAssessment();
    chatTarget()?.replaceChildren();
    const input = byId('groq-chat-input');
    if (input) input.value = '';
    resizeComposer();
    updateSuggestions();
    message(chosen ? 'Ready · curated synthetic evidence · private session.' : 'Choose a curated synthetic example first.');
    enableControls();
  }
  async function request(mode, question = '', reusePending = null) {
    resetForSample();
    const chosen = activeSample;
    if (!chosen || busy) return;
    const previousHistory = conversation.slice(-MAX_TURNS);
    busy = true;
    inFlightMode = mode;
    const token = ++requestSerial;
    const pending = mode === 'chat' ? (reusePending || (createChatTurn('user', question), makePending())) : null;
    if (reusePending) {
      reusePending.classList.remove('groq-chat-turn--error');
      reusePending.classList.add('groq-chat-turn--pending');
      const spinner = document.createElement('div');
      spinner.className = 'groq-thinking';
      const orbHost = document.createElement('span');
      orbHost.className = 'groq-thinking-orb';
      orbHost.setAttribute('aria-hidden', 'true');
      window.FortressThinkingOrb?.mount(orbHost, 'thinking', 32);
      const label = document.createElement('span');
      label.textContent = 'Reviewing verified evidence…';
      spinner.append(orbHost, label);
      reusePending.querySelector('.groq-chat-body')?.replaceChildren(spinner);
      scrollChat();
    }
    enableControls();
    message(mode === 'analyst' ? 'Analyzing verified synthetic evidence…' : 'Message sent · Analyst is responding…', 'pending');
    const controller = new AbortController();
    currentController = controller;
    const timeout = setTimeout(() => controller.abort(), 23000);
    try {
      const response = await fetch('/it113_security_assistant.php', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type':'application/json', 'Accept':'application/json'},
        body: JSON.stringify({sample_id:chosen, mode, question, history:mode === 'chat' ? previousHistory : []}),
        signal: controller.signal
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok !== true || data.sample_id !== chosen || data.synthetic !== true ||
          !['groq','deterministic_fallback'].includes(data.engine) || typeof data.answer !== 'string') {
        throw new Error(data.error || `Service returned HTTP ${response.status}.`);
      }
      if (token !== requestSerial || sampleId() !== chosen) return;
      if (mode === 'analyst') {
        const target = byId('groq-analyst-result');
        if (target) {
          const summary = document.createElement('div');
          summary.className = 'groq-model-summary';
          summary.textContent = `Trained model: ${String(data.classification).replaceAll('_',' ')} · Risk: ${Number(data.risk_score).toFixed(1)}/100 · Confidence: ${(Number(data.confidence)*100).toFixed(2)}%`;
          const content = window.FortressGroqMarkdown?.render(data.answer) || document.createTextNode(data.answer);
          target.replaceChildren(summary, content);
        }
        conversation = [];
        chatTarget()?.replaceChildren();
        updateSuggestions();
      } else {
        completePending(pending, data.answer, data.engine);
        conversation.push({role:'user',content:question},{role:'assistant',content:data.answer.slice(0,700)});
        conversation = conversation.slice(-MAX_TURNS);
      }
      message(data.engine === 'groq' ? 'AI response ready · grounded in freshly recomputed synthetic ML evidence.' :
        'AI service unavailable · verified baseline guidance displayed.', data.engine === 'groq' ? 'success' : 'fallback');
    } catch (error) {
      if (token === requestSerial && sampleId() === chosen) {
        const isTimeout = error?.name === 'AbortError';
        if (mode === 'chat') failedPending(pending, question, isTimeout ? 'timeout' : 'error');
        message(isTimeout ? 'The AI request timed out. Your existing ML analysis is unaffected.' :
          (error?.message || 'AI explanation unavailable.'), 'error');
      }
    } finally {
      clearTimeout(timeout);
      if (token === requestSerial) {
        currentController = null;
        busy = false;
        inFlightMode = '';
        enableControls();
      }
    }
  }
  function init() {
    if (!byId('it113-groq-panel') || !byId('live-sample-select')) return;
    const brand = document.querySelector('#it113-groq-panel .groq-brand-icon');
    headerOrb = window.FortressThinkingOrb?.mount(brand, 'idle', 51) || null;
    if (headerOrb) brand?.classList.add('groq-has-orb');
    const status = byId('groq-status');
    if (status) {
      const holder = document.createElement('span');
      holder.id = 'groq-status-orb';
      holder.className = 'groq-status-orb';
      holder.hidden = true;
      holder.setAttribute('aria-hidden', 'true');
      status.before(holder);
      statusOrb = window.FortressThinkingOrb?.mount(holder, 'thinking', 22) || null;
    }
    byId('live-sample-select').addEventListener('change', resetForSample);
    byId('groq-run-analyst')?.addEventListener('click', () => { void request('analyst'); });
    const form = byId('groq-chat-form');
    const input = byId('groq-chat-input');
    input?.addEventListener('input', () => { resizeComposer(); enableControls(); });
    input?.addEventListener('keydown', event => {
      if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
      event.preventDefault();
      if (!busy && input?.value.trim()) form?.requestSubmit();
    });
    form?.addEventListener('submit', event => {
      event.preventDefault();
      const question = input?.value.trim() || '';
      if (!question || busy || !sampleId()) return;
      if (input) input.value = '';
      resizeComposer();
      // request() synchronously appends the user bubble and pending indicator
      // before the first network await, making sends immediately visible.
      void request('chat', question);
    });
    byId('groq-chat-clear')?.addEventListener('click', () => {
      if (inFlightMode === 'chat') cancelInFlight();
      conversation = [];
      chatTarget()?.replaceChildren();
      updateSuggestions();
      message('Chat cleared in this tab. No public assessment records were changed.');
      enableControls();
    });
    byId('groq-chat-suggestions')?.addEventListener('click', event => {
      const choice = event.target.closest('[data-groq-suggestion]');
      if (!choice || !input || input.disabled) return;
      input.value = choice.dataset.groqSuggestion || '';
      resizeComposer(); enableControls(); input.focus();
    });
    resetForSample();
    resizeComposer();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, {once:true});
  else init();
})();
