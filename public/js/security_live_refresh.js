(() => {
  'use strict';

  if (window.FortressLiveRefresh) return;

  const state = window.FortressLiveRefreshState || {
    revision: null,
    lastAppliedRevision: null,
  };
  window.FortressLiveRefreshState = state;

  let intervalId = null;
  let visibilityHandler = null;
  let polling = false;
  let refreshing = false;
  let destroyed = false;
  let generation = 0;
  let pendingRevision = null;
  let retryTimer = null;

  const STATIC_MAIN_SELECTORS = [
    '.fortress-page-header',
    '#fortress-security-runtime',
    '#fortress-security-alert-host',
  ];

  const isStaticMainChild = (node) =>
    node instanceof Element &&
    STATIC_MAIN_SELECTORS.some((selector) => node.matches(selector));

  const destroy = () => {
    destroyed = true;
    generation += 1;

    if (intervalId !== null) window.clearInterval(intervalId);
    if (retryTimer !== null) window.clearTimeout(retryTimer);
    if (visibilityHandler) {
      document.removeEventListener('visibilitychange', visibilityHandler);
    }

    intervalId = null;
    retryTimer = null;
    visibilityHandler = null;
    polling = false;
    refreshing = false;
    pendingRevision = null;
  };

  const controlKey = (control, index) => {
    const form = control.form;
    const formKey = form?.id || form?.getAttribute('action') || 'form';
    return [
      formKey,
      control.id || control.name || control.getAttribute('data-table-search') || control.getAttribute('data-table-category') || `control-${index}`,
    ].join('::');
  };

  const captureUiState = () => {
    const controls = {};
    Array.from(document.querySelectorAll(
      '.fortress-main-column input, .fortress-main-column textarea, .fortress-main-column select'
    )).forEach((control, index) => {
      if (!(control instanceof HTMLInputElement ||
            control instanceof HTMLTextAreaElement ||
            control instanceof HTMLSelectElement)) return;

      const key = controlKey(control, index);
      controls[key] = {
        value: control.value,
        checked: control instanceof HTMLInputElement ? control.checked : undefined,
        selectionStart: 'selectionStart' in control ? control.selectionStart : null,
        selectionEnd: 'selectionEnd' in control ? control.selectionEnd : null,
      };
    });

    const active = document.activeElement;
    return {
      scrollX: window.scrollX,
      scrollY: window.scrollY,
      controls,
      activeId: active instanceof HTMLElement ? active.id : '',
    };
  };

  const restoreUiState = (snapshot) => {
    if (!snapshot) return;

    Array.from(document.querySelectorAll(
      '.fortress-main-column input, .fortress-main-column textarea, .fortress-main-column select'
    )).forEach((control, index) => {
      if (!(control instanceof HTMLInputElement ||
            control instanceof HTMLTextAreaElement ||
            control instanceof HTMLSelectElement)) return;

      const saved = snapshot.controls[controlKey(control, index)];
      if (!saved) return;

      // Never restore password/file values into a newly-rendered DOM.
      if (control instanceof HTMLInputElement && ['password', 'file'].includes(control.type)) {
        return;
      }

      control.value = saved.value;
      if (control instanceof HTMLInputElement && typeof saved.checked === 'boolean') {
        control.checked = saved.checked;
      }
    });

    window.scrollTo({
      left: snapshot.scrollX,
      top: snapshot.scrollY,
      behavior: 'auto',
    });

    if (snapshot.activeId) {
      const active = document.getElementById(snapshot.activeId);
      if (active instanceof HTMLElement) {
        active.focus({ preventScroll: true });
      }
    }
  };

  const syncStaticStatus = (incomingDocument) => {
    const pairs = [
      ['.sidebar-score strong', '.sidebar-score strong'],
      ['.header-score-card strong', '.header-score-card strong'],
      ['.fortress-page-header .page-heading-left p', '.fortress-page-header .page-heading-left p'],
    ];

    pairs.forEach(([currentSelector, incomingSelector]) => {
      const current = document.querySelector(currentSelector);
      const incoming = incomingDocument.querySelector(incomingSelector);
      if (current && incoming) current.textContent = incoming.textContent;
    });
  };

  const replaceDynamicPageContent = (incomingDocument) => {
    const currentMain = document.querySelector('.fortress-main-column');
    const incomingMain = incomingDocument.querySelector('.fortress-main-column');
    if (!currentMain || !incomingMain) {
      throw new Error('Live page region was not found.');
    }

    const currentDynamic = Array.from(currentMain.children).filter(
      (node) => !isStaticMainChild(node)
    );
    const incomingDynamic = Array.from(incomingMain.children).filter(
      (node) => !isStaticMainChild(node)
    );

    if (!incomingDynamic.length) {
      throw new Error('Incoming live page contained no dynamic content.');
    }

    const fragment = document.createDocumentFragment();
    incomingDynamic.forEach((node) => {
      fragment.appendChild(document.importNode(node, true));
    });

    currentDynamic.forEach((node) => node.remove());
    currentMain.appendChild(fragment);

    syncStaticStatus(incomingDocument);
  };

  const reinitializeCurrentPage = () => {
    try {
      window.FortressDashboard?.destroy?.();
      window.FortressDashboard?.init?.();
    } catch (error) {
      console.error('FortressAuth dashboard live re-init failed:', error);
    }

    if (window.location.pathname === '/ai_threat_intelligence.php') {
      try {
        window.FortressAI?.destroy?.();
        window.FortressAI?.init?.();
      } catch (error) {
        console.error('FortressAuth AI live re-init failed:', error);
      }
    }

    if (window.location.pathname === '/user_management.php') {
      try {
        window.FortressUserManagement?.destroy?.();
        window.FortressUserManagement?.init?.();
      } catch (error) {
        console.error('FortressAuth user-management live re-init failed:', error);
      }
    }
  };

  const refreshCurrentPage = async (revision, runGeneration) => {
    if (destroyed || refreshing || runGeneration !== generation) return;
    refreshing = true;

    const snapshot = captureUiState();

    try {
      const response = await fetch(window.location.href, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'follow',
        headers: {
          'Accept': 'text/html,application/xhtml+xml',
          'X-Requested-With': 'XMLHttpRequest',
          'X-Fortress-Live-Refresh': '1',
        },
      });

      if (!response.ok || destroyed || runGeneration !== generation) return;

      const finalUrl = new URL(response.url, window.location.href);
      if (finalUrl.origin !== window.location.origin ||
          finalUrl.pathname !== window.location.pathname) {
        // Session/auth state changed. Let the normal navigation flow handle it.
        window.location.assign(finalUrl.href);
        return;
      }

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('text/html')) return;

      const html = await response.text();
      if (destroyed || runGeneration !== generation) return;

      const incomingDocument = new DOMParser().parseFromString(html, 'text/html');
      replaceDynamicPageContent(incomingDocument);
      restoreUiState(snapshot);
      reinitializeCurrentPage();

      state.lastAppliedRevision = revision;
      window.dispatchEvent(new CustomEvent('fortress:live-security-updated', {
        detail: { revision },
      }));
    } catch (error) {
      // Live synchronization is enhancement-only. Never interrupt the app.
      console.error('FortressAuth live security synchronization failed:', error);
    } finally {
      refreshing = false;

      if (pendingRevision && pendingRevision !== state.lastAppliedRevision) {
        const next = pendingRevision;
        pendingRevision = null;
        retryTimer = window.setTimeout(() => {
          refreshCurrentPage(next, runGeneration);
        }, 250);
      }
    }
  };

  const poll = async (runGeneration) => {
    if (destroyed || polling || document.hidden || runGeneration !== generation) return;
    polling = true;

    try {
      const response = await fetch('/security_live_state.php', {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
      });

      if (response.status === 401 || response.status === 403) {
        // The authenticated session is gone/revoked. Stop the interval first so
        // DevTools is not flooded with repeated forbidden requests, then leave
        // the stale protected page through the normal login route.
        destroy();
        if (window.location.pathname !== '/login.php') {
          window.location.assign('/login.php?reason=session_expired');
        }
        return;
      }

      if (!response.ok || destroyed || runGeneration !== generation) return;

      const payload = await response.json();
      if (!payload || payload.success !== true || !payload.revision) return;

      const revision = String(payload.revision);

      if (state.revision === null) {
        state.revision = revision;
        state.lastAppliedRevision = revision;
        return;
      }

      if (revision === state.revision) return;
      state.revision = revision;

      if (refreshing) {
        pendingRevision = revision;
        return;
      }

      await refreshCurrentPage(revision, runGeneration);
    } catch (_) {
      // A temporary polling failure should never affect FortressAuth.
    } finally {
      polling = false;
    }
  };

  const init = () => {
    destroy();
    destroyed = false;
    const runGeneration = generation;

    const runtime = document.getElementById('fortress-security-runtime');
    if (!runtime) return;

    const seconds = Math.max(
      2,
      Number(runtime.dataset.livePollSeconds || 2)
    );

    poll(runGeneration);
    intervalId = window.setInterval(
      () => poll(runGeneration),
      seconds * 1000
    );

    visibilityHandler = () => {
      if (!document.hidden) poll(runGeneration);
    };
    document.addEventListener('visibilitychange', visibilityHandler);
  };

  window.FortressLiveRefresh = { init, destroy };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
