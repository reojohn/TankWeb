(() => {
  'use strict';

  if (window.FortressPJAX) return;

  const PROTECTED_PATHS = new Set([
    '/dashboard.php',
    '/access_activity.php',
    '/analytics.php',
    '/threats.php',
    '/ai_threat_intelligence.php',
    '/admin_logs.php',
    '/blocked_ips.php',
    '/security_controls.php',
    '/user_management.php',
    '/fortress_vault.php',
  ]);

  const COMMAND_PATHS = new Set([
    '/dashboard.php',
    '/access_activity.php',
    '/analytics.php',
    '/threats.php',
    '/ai_threat_intelligence.php',
    '/admin_logs.php',
    '/blocked_ips.php',
    '/security_controls.php',
    '/user_management.php',
  ]);

  const loadedScripts = new Set(
    Array.from(document.scripts)
      .map((script) => script.src)
      .filter(Boolean)
      .map((src) => new URL(src, window.location.href).pathname)
  );
  const scriptLoads = new Map();

  let navigating = false;
  let activeController = null;

  const normalizePath = (pathname) => {
    if (!pathname || pathname === '/') return '/dashboard.php';
    return pathname.replace(/\/{2,}/g, '/');
  };

  const isProtectedUrl = (url) =>
    url.origin === window.location.origin && PROTECTED_PATHS.has(normalizePath(url.pathname));

  const isCommandPath = (pathname) => COMMAND_PATHS.has(normalizePath(pathname));

  const setBusy = (busy) => {
    navigating = busy;
    document.documentElement.classList.toggle('fortress-pjax-busy', busy);
    document.documentElement.setAttribute('aria-busy', busy ? 'true' : 'false');
  };

  const showNavigationError = (message) => {
    let toast = document.getElementById('fortress-pjax-error');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'fortress-pjax-error';
      toast.className = 'fortress-pjax-error';
      toast.setAttribute('role', 'alert');
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('visible');
    window.setTimeout(() => toast?.classList.remove('visible'), 4200);
  };

  const destroyCurrentPage = () => {
    try { window.FortressAI?.destroy?.(); } catch (_) {}
    try { window.FortressVault?.destroy?.(); } catch (_) {}
    try { window.FortressSecurityAlerts?.destroy?.(); } catch (_) {}
    try { window.FortressLiveRefresh?.destroy?.(); } catch (_) {}
    try { window.FortressDashboard?.destroy?.(); } catch (_) {}
  };

  const ensureScript = (path) => {
    const normalized = new URL(path, window.location.href).pathname;
    if (loadedScripts.has(normalized)) return Promise.resolve(false);
    if (scriptLoads.has(normalized)) return scriptLoads.get(normalized);

    const loadPromise = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = normalized;
      script.defer = true;
      script.dataset.fortressPjaxScript = '1';
      script.addEventListener('load', () => {
        loadedScripts.add(normalized);
        scriptLoads.delete(normalized);
        resolve(true);
      }, { once: true });
      script.addEventListener('error', () => {
        scriptLoads.delete(normalized);
        reject(new Error(`Unable to load ${normalized}`));
      }, { once: true });
      document.head.appendChild(script);
    });

    scriptLoads.set(normalized, loadPromise);
    return loadPromise;
  };

  const ensureStyles = async (incomingDocument) => {
    const incoming = Array.from(incomingDocument.querySelectorAll('link[rel="stylesheet"][href]'))
      .map((link) => new URL(link.getAttribute('href'), window.location.href).pathname);

    const incomingSet = new Set(incoming);
    const currentLinks = Array.from(document.querySelectorAll('link[rel="stylesheet"][href]'));
    const currentSet = new Set(
      currentLinks.map((link) => new URL(link.getAttribute('href'), window.location.href).pathname)
    );

    const loads = [];
    incoming.forEach((href) => {
      if (currentSet.has(href)) return;
      loads.push(new Promise((resolve) => {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = href;
        link.dataset.fortressPjaxStyle = '1';
        link.addEventListener('load', resolve, { once: true });
        link.addEventListener('error', resolve, { once: true });
        document.head.appendChild(link);
      }));
    });

    await Promise.all(loads);

    currentLinks.forEach((link) => {
      const href = new URL(link.getAttribute('href'), window.location.href).pathname;
      if (!incomingSet.has(href) && href.startsWith('/css/')) {
        link.remove();
      }
    });
  };

  const syncBodyAttributes = (incomingBody) => {
    const preserved = new Set(['class']);
    Array.from(document.body.attributes).forEach((attribute) => {
      if (!preserved.has(attribute.name)) document.body.removeAttribute(attribute.name);
    });
    Array.from(incomingBody.attributes).forEach((attribute) => {
      if (attribute.name !== 'class') document.body.setAttribute(attribute.name, attribute.value);
    });
    document.body.className = incomingBody.className;
  };

  const initExistingOrLoadedModule = async (scriptPath, getter) => {
    const loadedNow = await ensureScript(scriptPath);
    if (!loadedNow) getter()?.init?.();
  };

  const initCurrentPage = async (pathname) => {
    // Keep one idle timer for the whole protected browser session. This is
    // intentionally not restarted on every in-app navigation.
    await ensureScript('/js/auto_logout.js');

    if (isCommandPath(pathname)) {
      await initExistingOrLoadedModule('/js/dashboard.js', () => window.FortressDashboard);
      await initExistingOrLoadedModule('/js/security_alerts.js', () => window.FortressSecurityAlerts);
      await initExistingOrLoadedModule('/js/security_live_refresh.js', () => window.FortressLiveRefresh);

      if (normalizePath(pathname) === '/user_management.php') {
        await ensureScript('/js/qrcode.min.js');
        await initExistingOrLoadedModule('/js/user_management.js', () => window.FortressUserManagement);
      }
      if (normalizePath(pathname) === '/ai_threat_intelligence.php') {
        await initExistingOrLoadedModule('/js/ai_threat_intelligence.js', () => window.FortressAI);
      }
      return;
    }

    if (normalizePath(pathname) === '/fortress_vault.php') {
      await initExistingOrLoadedModule('/js/vault.js', () => window.FortressVault);
    }
  };

  const performBodySwap = (incomingDocument) => {
    const incomingBody = incomingDocument.body;
    if (!incomingBody) throw new Error('The requested page did not contain a document body.');

    syncBodyAttributes(incomingBody);
    document.body.innerHTML = incomingBody.innerHTML;
    document.title = incomingDocument.title || document.title;

    const incomingTheme = incomingDocument.querySelector('meta[name="theme-color"]')?.getAttribute('content');
    const currentTheme = document.querySelector('meta[name="theme-color"]');
    if (incomingTheme && currentTheme) currentTheme.setAttribute('content', incomingTheme);
  };

  const renderResponse = async (response, options = {}) => {
    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}.`);
    }

    const finalUrl = new URL(response.url || options.requestUrl, window.location.href);
    const requestedUrl = new URL(options.requestUrl || finalUrl.href, window.location.href);
    if (
      options.preserveRequestHash &&
      !finalUrl.hash &&
      requestedUrl.hash &&
      finalUrl.pathname === requestedUrl.pathname &&
      finalUrl.search === requestedUrl.search
    ) {
      finalUrl.hash = requestedUrl.hash;
    }
    if (!isProtectedUrl(finalUrl)) {
      window.location.assign(finalUrl.href);
      return false;
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/html')) {
      throw new Error('The server returned an unexpected response format.');
    }

    const html = await response.text();
    const incomingDocument = new DOMParser().parseFromString(html, 'text/html');
    if (!incomingDocument.body) throw new Error('Unable to read the requested page.');

    await ensureStyles(incomingDocument);
    destroyCurrentPage();

    let swapped = false;
    const swap = () => {
      if (swapped) return;
      performBodySwap(incomingDocument);
      swapped = true;
    };
    if (typeof document.startViewTransition === 'function' && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      try {
        const transition = document.startViewTransition(swap);
        await transition.updateCallbackDone;
      } catch (_) {
        swap();
      }
    } else {
      swap();
    }

    const historyMode = options.historyMode || 'push';
    if (historyMode === 'push') {
      history.pushState({ fortressPjax: true }, '', finalUrl.href);
    } else if (historyMode === 'replace') {
      history.replaceState({ fortressPjax: true }, '', finalUrl.href);
    }

    await initCurrentPage(finalUrl.pathname);

    const targetHash = finalUrl.hash;
    if (targetHash) {
      requestAnimationFrame(() => {
        const target = document.getElementById(decodeURIComponent(targetHash.slice(1)));
        target?.scrollIntoView({ block: 'start', behavior: options.smoothScroll ? 'smooth' : 'auto' });
      });
    } else if (options.preserveScroll) {
      const y = Math.max(0, Math.min(Number(options.scrollY || 0), Math.max(0, document.documentElement.scrollHeight - window.innerHeight)));
      window.scrollTo({ top: y, left: 0, behavior: 'auto' });
    } else {
      window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
    }

    return true;
  };

  const fetchPage = async (url, fetchOptions, renderOptions) => {
    if (navigating) {
      activeController?.abort();
    }

    const controller = new AbortController();
    activeController = controller;
    setBusy(true);

    try {
      const response = await fetch(url.href, {
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'follow',
        ...fetchOptions,
        signal: controller.signal,
        headers: {
          'X-Fortress-PJAX': '1',
          'X-Requested-With': 'XMLHttpRequest',
          'Accept': 'text/html,application/xhtml+xml',
          ...(fetchOptions?.headers || {}),
        },
      });

      return await renderResponse(response, {
        requestUrl: url.href,
        ...renderOptions,
      });
    } finally {
      if (activeController === controller) activeController = null;
      setBusy(false);
    }
  };

  const navigate = async (url, options = {}) => {
    try {
      await fetchPage(url, { method: 'GET' }, {
        historyMode: options.historyMode || 'push',
        preserveScroll: Boolean(options.preserveScroll),
        scrollY: options.scrollY || 0,
        smoothScroll: Boolean(options.smoothScroll),
        preserveRequestHash: true,
      });
    } catch (error) {
      if (error?.name === 'AbortError') return;
      if (options.fallback !== false) {
        window.location.assign(url.href);
        return;
      }
      showNavigationError('The page could not be updated without reloading. Please try again.');
      console.error('FortressAuth PJAX navigation failed:', error);
    }
  };

  const sameDocumentHashNavigation = (target) =>
    target.pathname === window.location.pathname &&
    target.search === window.location.search &&
    target.hash &&
    target.hash !== window.location.hash;

  document.addEventListener('click', (event) => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;

    const anchor = event.target instanceof Element ? event.target.closest('a[href]') : null;
    if (!anchor) return;
    if (anchor.hasAttribute('download') || anchor.dataset.noPjax !== undefined) return;
    if (anchor.target && anchor.target !== '_self') return;

    let target;
    try { target = new URL(anchor.href, window.location.href); } catch (_) { return; }
    if (!isProtectedUrl(target)) return;
    if (sameDocumentHashNavigation(target)) return;

    event.preventDefault();
    navigate(target, { historyMode: 'push', fallback: true });
  });

  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.noPjax !== undefined || form.target) return;

    const submitter = event.submitter instanceof HTMLElement ? event.submitter : null;
    if (submitter?.dataset.noPjax !== undefined) return;

    const method = (submitter?.getAttribute('formmethod') || form.method || 'get').toUpperCase();
    const actionValue = submitter?.getAttribute('formaction') || form.getAttribute('action') || window.location.href;
    let actionUrl;
    try { actionUrl = new URL(actionValue, window.location.href); } catch (_) { return; }

    if (!isProtectedUrl(actionUrl) || !['GET', 'POST'].includes(method)) return;

    event.preventDefault();
    if (navigating) return;
    const scrollY = window.scrollY;
    const formData = new FormData(form);
    const submitterName = submitter?.getAttribute('name');
    if (submitterName) formData.append(submitterName, submitter.getAttribute('value') || '');

    if (method === 'GET') {
      const query = new URLSearchParams();
      for (const [key, value] of formData.entries()) {
        if (typeof value === 'string') query.append(key, value);
      }
      actionUrl.search = query.toString();
      navigate(actionUrl, {
        historyMode: 'push',
        preserveScroll: true,
        scrollY,
        fallback: true,
      });
      return;
    }

    setBusy(true);
    const controller = new AbortController();
    activeController = controller;
    fetch(actionUrl.href, {
      method: 'POST',
      body: formData,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'X-Fortress-PJAX': '1',
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'text/html,application/xhtml+xml',
      },
    }).then((response) => renderResponse(response, {
      requestUrl: actionUrl.href,
      historyMode: 'replace',
      preserveScroll: true,
      scrollY,
      smoothScroll: false,
    })).catch((error) => {
      if (error?.name === 'AbortError') return;
      // Never auto-resubmit a POST after a network ambiguity. Doing so could
      // duplicate a create/delete action if the first request reached PHP.
      showNavigationError('The action may not have completed. Check the page before trying it again.');
      console.error('FortressAuth PJAX form submission failed:', error);
    }).finally(() => {
      if (activeController === controller) activeController = null;
      setBusy(false);
    });
  });

  window.addEventListener('popstate', () => {
    const target = new URL(window.location.href);
    if (!isProtectedUrl(target)) return;

    navigate(target, {
      historyMode: 'none',
      preserveScroll: false,
      fallback: true,
    });
  });

  history.replaceState({ ...(history.state || {}), fortressPjax: true }, '', window.location.href);

  // Some older protected pages did not include the idle timer directly. Load
  // it once here so PJAX navigation never weakens the existing session policy.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => ensureScript('/js/auto_logout.js').catch(() => {}), { once: true });
  } else {
    ensureScript('/js/auto_logout.js').catch(() => {});
  }

  window.FortressPJAX = {
    navigate: (href) => navigate(new URL(href, window.location.href)),
    isNavigating: () => navigating,
  };
})();
