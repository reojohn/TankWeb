/* FortressAuth v3 parity runtime - generated without network build tooling. */
(function(){
'use strict';
const React = window.React;
const ReactDOM = window.ReactDOM;
const { useEffect, useMemo, useState, useRef } = React;
const { HashRouter, NavLink, useLocation, useNavigate, Navigate, Route, Routes, Link } = window.ReactRouterDOM;

/* ---- api/fortressApi.js ---- */
const cache = new Map();
const inflight = new Map();
const TTL = 120_000;
function keyFor(view) {
  return String(view || 'bootstrap');
}
async function fetchView(view, {
  force = false
} = {}) {
  const key = keyFor(view);
  const cached = cache.get(key);
  if (!force && cached && Date.now() - cached.at < TTL) return cached.data;
  if (!force && inflight.has(key)) return inflight.get(key);
  const promise = fetch(`/api/v3.php?view=${encodeURIComponent(key)}`, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'X-Fortress-React': '1'
    }
  }).then(async response => {
    if (response.status === 401 || response.status === 403) {
      window.location.href = '/login.php';
      throw new Error('Authentication expired');
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) throw new Error(payload.message || 'Unable to load FortressAuth data.');
    const data = payload.data ?? payload;
    cache.set(key, {
      at: Date.now(),
      data
    });
    return data;
  }).finally(() => inflight.delete(key));
  inflight.set(key, promise);
  return promise;
}
function getCachedView(view) {
  return cache.get(keyFor(view))?.data ?? null;
}
function isViewFresh(view) {
  const cached = cache.get(keyFor(view));
  return !!cached && Date.now() - cached.at < TTL;
}
function prefetchView(view) {
  fetchView(view).catch(() => {});
}
function clearView(view) {
  cache.delete(keyFor(view));
}
async function postView(view, body) {
  const response = await fetch(`/api/v3.php?view=${encodeURIComponent(view)}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Fortress-React': '1'
    },
    body: JSON.stringify(body)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.ok === false) throw new Error(payload.message || 'The FortressAuth action failed.');
  clearView(view);
  return payload;
}

/* ---- hooks/useFortressView.js ---- */
function useFortressView(view) {
  const [state, setState] = useState(() => {
    const cached = getCachedView(view);
    return {
      loading: cached == null,
      refreshing: false,
      data: cached,
      error: ''
    };
  });
  const load = (force = false) => {
    setState(old => ({
      ...old,
      loading: old.data == null,
      refreshing: old.data != null,
      error: ''
    }));
    return fetchView(view, {
      force
    }).then(data => setState({
      loading: false,
      refreshing: false,
      data,
      error: ''
    })).catch(error => setState(old => ({
      ...old,
      loading: false,
      refreshing: false,
      error: error.message || String(error)
    })));
  };
  useEffect(() => {
    const cached = getCachedView(view);
    if (cached != null) {
      setState(old => ({
        ...old,
        loading: false,
        data: cached,
        error: ''
      }));
    }
    load();
  }, [view]);
  return {
    ...state,
    reload: () => load(true)
  };
}

/* ---- components/LegacyParityPage.jsx ---- */
const parityFragmentCache = new Map();
const parityInflight = new Map();
const legacyRouteMap = {
  '/dashboard.php': '/overview',
  '/access_activity.php': '/activity',
  '/analytics.php': '/analytics',
  '/threats.php': '/threats',
  '/ai_threat_intelligence.php': '/ai-defense',
  '/admin_logs.php': '/logs',
  '/blocked_ips.php': '/blocked-ips',
  '/security_controls.php': '/security-controls',
  '/user_management.php': '/operator',
  '/personal_id_manage.php': '/operator',
  '/school_id_manage.php': '/operator',
  '/fortress_vault.php': '/vault'
};
const pagePathMap = {
  dashboard: '/dashboard.php',
  access_activity: '/access_activity.php',
  analytics: '/analytics.php',
  threats: '/threats.php',
  ai_threat_intelligence: '/ai_threat_intelligence.php',
  admin_logs: '/admin_logs.php',
  blocked_ips: '/blocked_ips.php',
  security_controls: '/security_controls.php'
};
const routePageMap = {
  '/overview': ['dashboard', '/dashboard.php'],
  '/activity': ['access_activity', '/access_activity.php'],
  '/analytics': ['analytics', '/analytics.php'],
  '/threats': ['threats', '/threats.php'],
  '/ai-defense': ['ai_threat_intelligence', '/ai_threat_intelligence.php'],
  '/logs': ['admin_logs', '/admin_logs.php'],
  '/blocked-ips': ['blocked_ips', '/blocked_ips.php'],
  '/security-controls': ['security_controls', '/security_controls.php']
};
function cacheKey(page, legacyUrl = '') {
  return `${page}|${legacyUrl || pagePathMap[page] || ''}`;
}
function buildFragmentUrl(page, legacyUrl = '') {
  const source = new URL(legacyUrl || pagePathMap[page] || '/', window.location.origin);
  const target = new URL('/api/v3_fragment.php', window.location.origin);
  target.searchParams.set('page', page);
  source.searchParams.forEach((value, key) => target.searchParams.append(key, value));
  return target.pathname + target.search;
}
function extractLegacyContent(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const main = doc.querySelector('.fortress-main-column');
  if (!main) return '';
  main.querySelector('.fortress-page-header')?.remove();
  main.querySelector('#fortress-security-runtime')?.remove();
  main.querySelector('#fortress-notification-backdrop')?.remove();
  main.querySelector('#fortress-notification-panel')?.remove();
  main.querySelector('#fortress-security-alert-host')?.remove();
  main.querySelectorAll('script').forEach(node => node.remove());
  return main.innerHTML.trim();
}
async function requestFragment(page, legacyUrl = '', {
  force = false
} = {}) {
  const key = cacheKey(page, legacyUrl);
  const cached = parityFragmentCache.get(key);
  if (!force && cached) return cached.html;
  if (parityInflight.has(key)) return parityInflight.get(key);
  const promise = fetch(buildFragmentUrl(page, legacyUrl), {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      Accept: 'text/html',
      'X-Fortress-React': '1',
      'X-Fortress-Live-Refresh': '1'
    }
  }).then(async response => {
    if (response.status === 401 || response.status === 403) {
      window.location.href = '/login.php';
      throw new Error('Authentication expired');
    }
    const html = await response.text();
    if (!response.ok) throw new Error(html || 'Unable to load FortressAuth page content.');
    parityFragmentCache.set(key, {
      at: Date.now(),
      html
    });
    return html;
  }).finally(() => parityInflight.delete(key));
  parityInflight.set(key, promise);
  return promise;
}
async function touchPage(page) {
  try {
    const response = await fetch(`/api/v3_touch.php?page=${encodeURIComponent(page)}`, {
      credentials: 'same-origin',
      headers: {
        Accept: 'application/json',
        'X-Fortress-React': '1'
      }
    });
    if (response.status === 401 || response.status === 403) window.location.href = '/login.php';
  } catch (_) {
    // Content rendering should remain usable even if a route heartbeat fails.
  }
}
function prefetchLegacyPage(page, legacyUrl = '') {
  if (!pagePathMap[page]) return Promise.resolve('');
  return requestFragment(page, legacyUrl).catch(() => '');
}
async function warmLegacyPages(items = []) {
  const jobs = items.map(item => Array.isArray(item) ? item : [item, '']).filter(([page]) => pagePathMap[page]).map(([page, legacyUrl]) => prefetchLegacyPage(page, legacyUrl));
  await Promise.allSettled(jobs);
}
function updateFragmentCache(page, legacyUrl, html) {
  parityFragmentCache.set(cacheKey(page, legacyUrl), {
    at: Date.now(),
    html
  });
}
function formatRouteTarget(resolved) {
  const route = legacyRouteMap[resolved.pathname];
  if (!route) return null;
  return route + (resolved.search || '');
}
function LegacyParityPage({
  page,
  legacyUrl,
  ai = false
}) {
  const navigate = useNavigate();
  const root = useRef(null);
  const currentLegacyUrl = useRef(legacyUrl || pagePathMap[page] || '/');
  const initialCached = parityFragmentCache.get(cacheKey(page, currentLegacyUrl.current))?.html || '';
  const [html, setHtml] = useState(initialCached);
  const [loading, setLoading] = useState(!initialCached);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const pendingAnchor = useRef('');
  const renderFullLegacyResponse = async (response, requestedUrl) => {
    if (response.status === 401 || response.status === 403 || response.url.includes('/login.php')) {
      window.location.href = '/login.php';
      return;
    }
    const text = await response.text();
    if (!response.ok) throw new Error('FortressAuth could not complete that action.');
    const extracted = extractLegacyContent(text);
    if (!extracted) throw new Error('FortressAuth could not read the updated page content.');
    const finalUrl = response.url ? new URL(response.url) : new URL(requestedUrl, window.location.origin);
    const normalized = finalUrl.pathname + finalUrl.search;
    currentLegacyUrl.current = normalized;
    updateFragmentCache(page, normalized, extracted);
    setHtml(extracted);
  };
  const load = async ({
    force = false,
    url = currentLegacyUrl.current
  } = {}) => {
    const key = cacheKey(page, url);
    const cached = parityFragmentCache.get(key)?.html || '';
    setError('');
    if (cached && !force) {
      currentLegacyUrl.current = url;
      setHtml(cached);
      setLoading(false);
      setRefreshing(false);
      requestFragment(page, url, {
        force: true
      }).then(next => {
        currentLegacyUrl.current = url;
        if (next && next !== cached) setHtml(next);
      }).catch(() => {});
      return cached;
    }
    setLoading(!html);
    setRefreshing(Boolean(html));
    try {
      const next = await requestFragment(page, url, {
        force
      });
      currentLegacyUrl.current = url;
      setHtml(next);
      return next;
    } catch (e) {
      setError(e?.message || String(e));
      return '';
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };
  useEffect(() => {
    currentLegacyUrl.current = legacyUrl || pagePathMap[page] || '/';
    const cached = parityFragmentCache.get(cacheKey(page, currentLegacyUrl.current))?.html || '';
    if (cached) setHtml(cached);else setHtml('');
    touchPage(page);
    load({
      url: currentLegacyUrl.current
    });
  }, [page, legacyUrl]);
  useEffect(() => {
    const refresh = () => load({
      force: true
    });
    window.addEventListener('fortress:v3-route-refresh', refresh);
    return () => window.removeEventListener('fortress:v3-route-refresh', refresh);
  });
  useEffect(() => {
    if (!html) return;
    const timer = window.setTimeout(() => {
      window.FortressDashboard?.init?.();
      if (ai) window.FortressAI?.init?.();
      if (pendingAnchor.current) {
        const id = pendingAnchor.current.replace(/^#/, '');
        if (id) root.current?.querySelector(`#${CSS.escape(id)}`)?.scrollIntoView({
          block: 'start'
        });
        pendingAnchor.current = '';
      }
    }, 20);
    return () => window.clearTimeout(timer);
  }, [html, ai]);
  useEffect(() => {
    const node = root.current;
    if (!node) return undefined;
    const onClick = async event => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const anchor = event.target.closest?.('a[href]');
      if (!anchor || !node.contains(anchor) || anchor.target === '_blank' || anchor.hasAttribute('download')) return;
      const href = anchor.getAttribute('href') || '';
      if (!href || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) return;
      if (href.startsWith('#')) {
        event.preventDefault();
        const id = href.slice(1);
        if (id) root.current?.querySelector(`#${CSS.escape(id)}`)?.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
        return;
      }
      const resolved = new URL(href, window.location.origin);
      if (resolved.origin !== window.location.origin) return;
      const target = formatRouteTarget(resolved);
      if (!target) return;
      event.preventDefault();
      pendingAnchor.current = resolved.hash || '';
      const routePath = target.split('?')[0];
      const targetPage = routePageMap[routePath];
      if (targetPage) {
        prefetchLegacyPage(targetPage[0], targetPage[1] + (resolved.search || ''));
      }
      navigate(target, {
        state: resolved.hash ? {
          legacyAnchor: resolved.hash
        } : undefined
      });
    };
    const onSubmit = async event => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement) || !node.contains(form)) return;
      const rawAction = form.getAttribute('action') || currentLegacyUrl.current;
      const resolved = new URL(rawAction || currentLegacyUrl.current, window.location.origin);
      const currentPath = new URL(currentLegacyUrl.current, window.location.origin).pathname;

      // Report exports and dedicated handoff endpoints retain their native
      // browser behavior. They either download a file or intentionally change
      // authentication state outside this content-only bridge.
      if (resolved.pathname === '/report_export.php') return;
      if (resolved.pathname !== currentPath) return;
      event.preventDefault();
      setRefreshing(true);
      setError('');
      try {
        const formData = new FormData(form);
        const method = (form.method || 'GET').toUpperCase();
        let requestUrl = resolved.pathname + resolved.search;
        const options = {
          method,
          credentials: 'same-origin',
          headers: {
            'X-Fortress-React': '1'
          }
        };
        if (method === 'GET') {
          const params = new URLSearchParams(resolved.search);
          for (const [key, value] of formData.entries()) params.set(key, String(value));
          requestUrl = resolved.pathname + (params.toString() ? `?${params}` : '');
        } else {
          options.body = formData;
        }
        const response = await fetch(requestUrl, options);
        await renderFullLegacyResponse(response, requestUrl);
      } catch (e) {
        setError(e?.message || String(e));
      } finally {
        setRefreshing(false);
      }
    };
    node.addEventListener('click', onClick);
    node.addEventListener('submit', onSubmit);
    return () => {
      node.removeEventListener('click', onClick);
      node.removeEventListener('submit', onSubmit);
    };
  }, [html, navigate, page]);
  return React.createElement(React.Fragment, null, loading && !html ? React.createElement("section", {
    className: "v3-route-skeleton",
    "aria-label": "Loading FortressAuth page",
    "aria-busy": "true",
    role: "status"
  }, React.createElement("span", {
    className: "sr-only"
  }, "Loading FortressAuth page"), React.createElement("div", {
    className: "v3-skeleton-metrics"
  }, [0, 1, 2, 3].map(item => React.createElement("span", {
    key: item
  }))), React.createElement("div", {
    className: "v3-skeleton-panels"
  }, React.createElement("span", null), React.createElement("span", null))) : null, error ? React.createElement("section", {
    className: "panel v3-error-panel"
  }, React.createElement("i", {
    className: "fa-solid fa-triangle-exclamation"
  }), React.createElement("div", null, React.createElement("strong", null, "Unable to load this workspace"), React.createElement("span", null, error))) : null, React.createElement("div", {
    ref: root,
    className: "v3-v2-parity-content",
    "aria-busy": loading || refreshing ? "true" : "false",
    dangerouslySetInnerHTML: {
      __html: html
    }
  }));

}

/* ---- pages/Overview.jsx ---- */
function Overview() {
  return React.createElement(LegacyParityPage, {
    page: "dashboard",
    legacyUrl: "/dashboard.php"
  });
}

/* ---- pages/AccessActivity.jsx ---- */
function AccessActivity() {
  return React.createElement(LegacyParityPage, {
    page: "access_activity",
    legacyUrl: "/access_activity.php"
  });
}

/* ---- pages/Analytics.jsx ---- */
function Analytics() {
  return React.createElement(LegacyParityPage, {
    page: "analytics",
    legacyUrl: "/analytics.php"
  });
}

/* ---- pages/Threats.jsx ---- */
function Threats() {
  return React.createElement(LegacyParityPage, {
    page: "threats",
    legacyUrl: "/threats.php"
  });
}

/* ---- pages/AIDefense.jsx ---- */
function AIDefense() {
  return React.createElement(LegacyParityPage, {
    page: "ai_threat_intelligence",
    legacyUrl: "/ai_threat_intelligence.php",
    ai: true
  });
}

/* ---- pages/SecurityLogs.jsx ---- */
function SecurityLogs() {
  return React.createElement(LegacyParityPage, {
    page: "admin_logs",
    legacyUrl: "/admin_logs.php"
  });
}

/* ---- pages/BlockedIPs.jsx ---- */
function BlockedIPs() {
  return React.createElement(LegacyParityPage, {
    page: "blocked_ips",
    legacyUrl: "/blocked_ips.php"
  });
}

/* ---- pages/SecurityControls.jsx ---- */
function SecurityControls() {
  return React.createElement(LegacyParityPage, {
    page: "security_controls",
    legacyUrl: "/security_controls.php"
  });
}

/* ---- pages/CurrentOperator.jsx ---- */
const OPERATOR_TTL = 30_000;
let operatorCache = null;
let operatorInflight = null;
function extractContent(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const main = doc.querySelector('.fortress-main-column');
  if (!main) return '<section class="panel v3-error-panel"><strong>Unable to read the operator workspace.</strong></section>';
  main.querySelector('.fortress-page-header')?.remove();
  main.querySelector('#fortress-security-runtime')?.remove();
  main.querySelector('#fortress-notification-backdrop')?.remove();
  main.querySelector('#fortress-notification-panel')?.remove();
  main.querySelector('#fortress-security-alert-host')?.remove();
  main.querySelectorAll('script').forEach(node => node.remove());
  return main.innerHTML;
}
async function requestOperatorHtml({
  force = false
} = {}) {
  if (!force && operatorCache && Date.now() - operatorCache.at < OPERATOR_TTL) {
    return operatorCache.html;
  }
  if (!force && operatorInflight) return operatorInflight;
  operatorInflight = fetch('/api/v3_fragment.php?page=operator', {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      Accept: 'text/html',
      'X-Fortress-React': '1',
      'X-Fortress-Live-Refresh': '1'
    }
  }).then(async response => {
    if (response.status === 401 || response.status === 403 || response.url.includes('/login.php')) {
      window.location.href = '/login.php';
      throw new Error('Authentication expired');
    }
    const text = await response.text();
    if (!response.ok) throw new Error('Operator workspace failed to load.');
    const html = text.trim();
    operatorCache = {
      at: Date.now(),
      html
    };
    return html;
  }).finally(() => {
    operatorInflight = null;
  });
  return operatorInflight;
}
function prefetchCurrentOperator() {
  return requestOperatorHtml().catch(() => '');
}
async function touchOperatorRoute() {
  try {
    const response = await fetch('/api/v3_touch.php?page=operator', {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        'X-Fortress-React': '1'
      }
    });
    if (response.status === 401 || response.status === 403) window.location.href = '/login.php';
  } catch (_) {
    // Navigation remains usable even if the audit heartbeat is temporarily unavailable.
  }
}
function loadScript(src, id) {
  document.getElementById(id)?.remove();
  const script = document.createElement('script');
  script.id = id;
  script.src = `${src}${src.includes('?') ? '&' : '?'}v3=${Date.now()}`;
  script.defer = false;
  document.body.appendChild(script);
}
function CurrentOperator() {
  const cachedHtml = operatorCache?.html || '';
  const [html, setHtml] = useState(cachedHtml);
  const [loading, setLoading] = useState(!cachedHtml);
  const [error, setError] = useState('');
  const root = useRef(null);
  const currentUrl = useRef('/user_management.php');
  const pendingAnchor = useRef('');
  const load = async (url = currentUrl.current, options = {}) => {
    const requested = new URL(url, window.location.origin);
    pendingAnchor.current = requested.hash || '';
    requested.hash = '';
    const method = String(options.method || 'GET').toUpperCase();
    setLoading(true);
    setError('');
    try {
      if (method === 'GET' && requested.pathname === '/user_management.php' && !requested.search) {
        const content = await requestOperatorHtml();
        currentUrl.current = '/user_management.php';
        setHtml(content);
        return;
      }
      const response = await fetch(requested.pathname + requested.search, {
        credentials: 'same-origin',
        ...options,
        headers: {
          ...(options.headers || {}),
          'X-Fortress-React': '1'
        }
      });
      if (response.status === 401 || response.status === 403 || response.url.includes('/login.php')) {
        window.location.href = '/login.php';
        return;
      }
      const text = await response.text();
      if (!response.ok) throw new Error('Operator workspace failed to load.');
      currentUrl.current = response.url ? new URL(response.url).pathname + new URL(response.url).search : requested.pathname + requested.search;
      const content = extractContent(text);
      if (currentUrl.current === '/user_management.php') {
        operatorCache = {
          at: Date.now(),
          html: content
        };
      }
      setHtml(content);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    touchOperatorRoute();
    load();
  }, []);
  useEffect(() => {
    if (!html) return;
    const timer = window.setTimeout(() => {
      if (!window.QRCode) loadScript('/js/qrcode.min.js', 'fortress-v3-qrcode');
      loadScript('/js/user_management.js', 'fortress-v3-user-management');
      window.FortressDashboard?.init?.();
      if (pendingAnchor.current) {
        const id = pendingAnchor.current.slice(1);
        root.current?.querySelector(`[id="${CSS.escape(id)}"]`)?.scrollIntoView({
          block: 'start'
        });
        pendingAnchor.current = '';
      }
    }, 20);
    return () => window.clearTimeout(timer);
  }, [html]);
  useEffect(() => {
    const node = root.current;
    if (!node) return;
    const click = event => {
      const anchor = event.target.closest?.('a[href]');
      if (!anchor || !node.contains(anchor)) return;
      const href = anchor.getAttribute('href') || '';
      if (href.startsWith('#')) {
        event.preventDefault();
        const target = root.current?.querySelector(`[id="${CSS.escape(href.slice(1))}"]`);
        target?.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
        return;
      }
      const resolved = new URL(href, window.location.origin);
      if (resolved.pathname === '/user_management.php') {
        event.preventDefault();
        load(resolved.pathname + resolved.search + resolved.hash);
      }
    };
    const submit = async event => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement) || !node.contains(form)) return;
      const action = form.getAttribute('action') || currentUrl.current || '/user_management.php';
      if (!action.includes('user_management.php') && action !== '') return;
      event.preventDefault();
      const formData = new FormData(form);
      const method = (form.method || 'POST').toUpperCase();
      if (method === 'GET') {
        const target = new URL(action || currentUrl.current, window.location.origin);
        target.search = new URLSearchParams(formData).toString();
        await load(target.pathname + target.search + target.hash);
        return;
      }
      operatorCache = null;
      await load(action || currentUrl.current, {
        method,
        body: formData
      });
    };
    node.addEventListener('click', click);
    node.addEventListener('submit', submit);
    return () => {
      node.removeEventListener('click', click);
      node.removeEventListener('submit', submit);
    };
  }, [html]);
  return React.createElement(React.Fragment, null, loading && !html ? React.createElement("section", {
    className: "v3-route-skeleton",
    "aria-label": "Loading Current Operator",
    "aria-busy": "true",
    role: "status"
  }, React.createElement("span", {
    className: "sr-only"
  }, "Loading Current Operator"), React.createElement("div", {
    className: "v3-skeleton-metrics"
  }, [0, 1, 2, 3].map(item => React.createElement("span", {
    key: item
  }))), React.createElement("div", {
    className: "v3-skeleton-panels"
  }, React.createElement("span", null), React.createElement("span", null))) : null, error ? React.createElement("section", {
    className: "panel v3-error-panel"
  }, React.createElement("i", {
    className: "fa-solid fa-triangle-exclamation"
  }), React.createElement("div", null, React.createElement("strong", null, "Operator workspace failed to load"), React.createElement("span", null, error))) : null, React.createElement("div", {
    ref: root,
    className: "v3-legacy-bridge",
    "aria-busy": loading ? "true" : "false",
    dangerouslySetInnerHTML: {
      __html: html
    }
  }));
}

/* ---- pages/Vault.jsx ---- */
const VAULT_TTL = 30_000;
let vaultCache = null;
let vaultInflight = null;
function extractVaultBody(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.body.querySelectorAll('script').forEach(node => node.remove());
  return doc.body.innerHTML.trim();
}
async function requestVault({
  force = false
} = {}) {
  if (!force && vaultCache && Date.now() - vaultCache.at < VAULT_TTL) {
    return vaultCache.html;
  }
  if (!force && vaultInflight) return vaultInflight;
  vaultInflight = fetch('/fortress_vault.php', {
    credentials: 'same-origin',
    headers: {
      Accept: 'text/html',
      'X-Fortress-React': '1'
    }
  }).then(async response => {
    if (response.status === 401 || response.status === 403 || response.url.includes('/login.php')) {
      window.location.href = '/login.php';
      throw new Error('Authentication expired');
    }
    const text = await response.text();
    if (!response.ok) throw new Error('The Fortress Vault could not be opened.');
    const html = extractVaultBody(text);
    vaultCache = {
      at: Date.now(),
      html
    };
    return html;
  }).finally(() => {
    vaultInflight = null;
  });
  return vaultInflight;
}
function prefetchVault() {
  return requestVault().catch(() => '');
}
function Vault() {
  const navigate = useNavigate();
  const root = useRef(null);
  const [html, setHtml] = useState(vaultCache?.html || '');
  const [error, setError] = useState('');
  useEffect(() => {
    document.body.className = 'vault-page';
    document.body.dataset.vaultStage = 'boot';
    let active = true;
    requestVault().then(content => {
      if (active && content) setHtml(content);
    }).catch(e => {
      if (active) setError(e?.message || String(e));
    });
    return () => {
      active = false;
      window.FortressVault?.destroy?.();
      delete document.body.dataset.vaultStage;
    };
  }, []);
  useEffect(() => {
    if (!html) return;
    const id = window.setTimeout(() => window.FortressVault?.init?.(), 30);
    return () => window.clearTimeout(id);
  }, [html]);
  useEffect(() => {
    const node = root.current;
    if (!node) return undefined;
    const click = async event => {
      const anchor = event.target.closest?.('a[href]');
      if (!anchor || !node.contains(anchor)) return;
      const resolved = new URL(anchor.getAttribute('href') || '', window.location.origin);
      if (resolved.origin === window.location.origin && resolved.pathname === '/dashboard.php') {
        event.preventDefault();
        await prefetchLegacyPage('dashboard', '/dashboard.php');
        navigate('/overview');
      }
    };
    node.addEventListener('click', click);
    return () => node.removeEventListener('click', click);
  }, [html, navigate]);
  if (error) {
    return React.createElement("main", {
      className: "vault-shell"
    }, React.createElement("section", {
      className: "vault-stage-card"
    }, React.createElement("div", {
      className: "vault-copy"
    }, React.createElement("h1", null, "Vault unavailable"), React.createElement("p", null, error), React.createElement("button", {
      type: "button",
      onClick: () => navigate('/overview')
    }, "Return to command center"))));
  }
  if (!html) {
    return React.createElement("main", {
      className: "vault-shell"
    }, React.createElement("section", {
      className: "v3-route-skeleton",
      "aria-label": "Opening Fortress Vault",
      "aria-busy": "true",
      role: "status"
    }, React.createElement("span", {
      className: "sr-only"
    }, "Verifying protected objective"), React.createElement("div", {
      className: "v3-skeleton-metrics"
    }, [0, 1, 2, 3].map(item => React.createElement("span", {
      key: item
    }))), React.createElement("div", {
      className: "v3-skeleton-panels"
    }, React.createElement("span", null), React.createElement("span", null))));
  }
  return React.createElement("div", {
    ref: root,
    className: "v3-vault-parity",
    dangerouslySetInnerHTML: {
      __html: html
    }
  });
}

/* ---- components/AppShell.jsx ---- */
const navItems = [['/overview', 'dashboard', '/dashboard.php', 'fa-table-cells-large', 'Overview', 'Security command center'], ['/activity', 'access_activity', '/access_activity.php', 'fa-wave-square', 'Access Activity', 'Authentication history'], ['/analytics', 'analytics', '/analytics.php', 'fa-chart-pie', 'Security Analytics', 'Charts and trends'], ['/threats', 'threats', '/threats.php', 'fa-shield-virus', 'Threats', 'Intrusion monitoring'], ['/ai-defense', 'ai_threat_intelligence', '/ai_threat_intelligence.php', 'fa-brain', 'AI Defense', 'ML threat intelligence'], ['/logs', 'admin_logs', '/admin_logs.php', 'fa-clipboard-list', 'Security Logs', 'Audit evidence'], ['/blocked-ips', 'blocked_ips', '/blocked_ips.php', 'fa-ban', 'Blocked IPs', 'Network enforcement'], ['/security-controls', 'security_controls', '/security_controls.php', 'fa-sliders', 'Security Controls', 'Defense configuration']];
const pageMap = {
  '/overview': ['Overview', 'Security command center', 'fa-table-cells-large'],
  '/activity': ['Access Activity', 'Authentication history', 'fa-wave-square'],
  '/analytics': ['Security Analytics', 'Charts and trends', 'fa-chart-pie'],
  '/threats': ['Threats', 'Intrusion monitoring', 'fa-shield-virus'],
  '/ai-defense': ['AI Defense', 'ML threat intelligence', 'fa-brain'],
  '/logs': ['Security Logs', 'Audit evidence', 'fa-clipboard-list'],
  '/blocked-ips': ['Blocked IPs', 'Network enforcement', 'fa-ban'],
  '/security-controls': ['Security Controls', 'Defense configuration', 'fa-sliders'],
  '/operator': ['Current Operator', 'Users, Personal ID and documentation reports', 'fa-user-shield']
};
function AppShell({
  children
}) {
  const {
    data,
    loading,
    reload
  } = useFortressView('bootstrap');
  const location = useLocation();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [runtimeDefenseMode, setRuntimeDefenseMode] = useState(null);
  const liveRevision = useRef(null);
  const livePollBusy = useRef(false);
  const meta = pageMap[location.pathname] || pageMap['/overview'];
  useEffect(() => {
    const legacyBodyClass = {
      '/analytics': 'analytics-page',
      '/ai-defense': 'ai-intelligence-page',
      '/operator': 'user-management-page'
    }[location.pathname] || '';
    document.body.className = `command-page fortress-react-v3 ${legacyBodyClass}`.trim();
    setOpen(false);
  }, [location.pathname]);
  useEffect(() => {
    if (data?.defenseProfileMode) setRuntimeDefenseMode(data.defenseProfileMode);
  }, [data?.defenseProfileMode]);
  useEffect(() => {
    const onProfileChanged = event => {
      const mode = event?.detail?.mode;
      if (mode) setRuntimeDefenseMode(mode);
      reload();
    };
    window.addEventListener('fortress:defense-profile-changed', onProfileChanged);
    return () => window.removeEventListener('fortress:defense-profile-changed', onProfileChanged);
  }, [reload]);
  useEffect(() => {
    if (!data) return;
    const id = window.setTimeout(() => {
      window.FortressSecurityAlerts?.destroy?.();
      window.FortressSecurityAlerts?.init?.();
    }, 40);
    return () => window.clearTimeout(id);
  }, [data?.userId, data?.username, data?.policy?.alertPollSeconds]);
  useEffect(() => {
    if (!data) return undefined;
    let cancelled = false;
    let timerId = null;
    const queue = navItems.filter(([path]) => path !== location.pathname).map(([, page, legacyUrl]) => [page, legacyUrl]);
    const warm = () => {
      if (cancelled) return;
      warmLegacyPages(queue);
      // Safe silent fragment warm-up for Current Operator. The real route
      // entry is audited separately by /api/v3_touch.php?page=operator.
      prefetchCurrentOperator();
      // Crown Jewel remains excluded because opening it is the pentest objective.
    };
    timerId = window.setTimeout(warm, 60);
    return () => {
      cancelled = true;
      if (timerId !== null) window.clearTimeout(timerId);
    };
  }, [data?.userId]);
  useEffect(() => {
    let cancelled = false;
    let timerId = null;
    const pollSeconds = Math.max(2, Number(data?.policy?.livePollSeconds || 2));
    const pollSecurityRevision = async () => {
      if (cancelled || document.hidden || livePollBusy.current) return;
      livePollBusy.current = true;
      try {
        const response = await fetch('/security_live_state.php', {
          method: 'GET',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: {
            Accept: 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Fortress-React': '1'
          }
        });
        if (response.status === 401 || response.status === 403) {
          window.location.assign('/login.php?reason=session_expired');
          return;
        }
        if (!response.ok || cancelled) return;
        const payload = await response.json().catch(() => null);
        if (!payload || payload.success !== true || !payload.revision) return;
        const revision = String(payload.revision);
        if (liveRevision.current === null) {
          liveRevision.current = revision;
          return;
        }
        if (revision === liveRevision.current) return;
        liveRevision.current = revision;
        reload();
        window.dispatchEvent(new CustomEvent('fortress:v3-route-refresh', {
          detail: { revision, source: 'security-live-state' }
        }));
        window.dispatchEvent(new CustomEvent('fortress:live-security-updated', {
          detail: { revision }
        }));
        window.FortressSecurityAlerts?.pollNow?.();
      } catch (_) {
        // Live synchronization is enhancement-only.
      } finally {
        livePollBusy.current = false;
      }
    };
    pollSecurityRevision();
    timerId = window.setInterval(pollSecurityRevision, pollSeconds * 1000);
    const onVisibility = () => {
      if (!document.hidden) pollSecurityRevision();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      cancelled = true;
      if (timerId !== null) window.clearInterval(timerId);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [data?.policy?.livePollSeconds]);
  const header = data || {
    username: 'Loading…',
    roleLabel: 'ADMIN',
    protectionScore: 0,
    activeDefenseCount: 0,
    defenseTotal: 8,
    defenseProfileMode: 'balanced',
    defenseProfileLabel: 'BALANCED',
    policy: {
      alertPollSeconds: 4,
      livePollSeconds: 2,
      sessionIdleSeconds: 900
    }
  };
  const activeDefenseMode = runtimeDefenseMode || header.defenseProfileMode || 'balanced';
  useEffect(() => {
    window.FortressTheme?.apply?.(activeDefenseMode);
  }, [activeDefenseMode]);
  const boostActive = activeDefenseMode === 'fortress_boost';
  const runtimeAttrs = {
    'data-alert-poll-seconds': header.policy?.alertPollSeconds || 4,
    'data-live-poll-seconds': header.policy?.livePollSeconds || 2,
    'data-session-idle-seconds': header.policy?.sessionIdleSeconds || 900,
    'data-notification-user': String(header.userId || header.username || '')
  };
  const prefetch = (page, legacyUrl) => () => prefetchLegacyPage(page, legacyUrl);
  const openLegacyRoute = (path, page, legacyUrl) => event => {
    if (location.pathname === path) return;
    event.preventDefault();
    prefetchLegacyPage(page, legacyUrl);
    navigate(path);
  };
  const openOperator = event => {
    if (location.pathname === '/operator') return;
    event.preventDefault();
    prefetchCurrentOperator();
    navigate('/operator');
  };
  const openVault = event => {
    if (location.pathname === '/vault') return;
    event.preventDefault();
    // Kick off the protected request without holding the route transition.
    // Vault joins the same in-flight request and paints a loading skeleton.
    prefetchVault();
    navigate('/vault');
  };
  const refreshWorkspace = () => {
    reload();
    window.dispatchEvent(new CustomEvent('fortress:v3-route-refresh'));
  };
  return React.createElement(React.Fragment, null, React.createElement("div", {
    className: "ambient ambient-one",
    "aria-hidden": "true"
  }), React.createElement("div", {
    className: "ambient ambient-two",
    "aria-hidden": "true"
  }), React.createElement("main", {
    className: "command-shell fortress-react-shell"
  }, ReactDOM.createPortal(React.createElement("div", {
    className: "fortress-mobile-bar"
  }, React.createElement("button", {
    className: "fortress-mobile-menu",
    type: "button",
    "aria-label": "Open navigation",
    "aria-expanded": open,
    onClick: () => setOpen(!open)
  }, React.createElement("i", {
    className: "fa-solid fa-bars"
  })), React.createElement("div", {
    className: "fortress-mobile-title"
  }, React.createElement("strong", null, meta[0]), React.createElement("span", null, boostActive ? "FortressAuth \xB7 Fortress Boost active" : "FortressAuth \xB7 Protection enforced")), React.createElement("div", {
    className: "fortress-mobile-actions"
  }, React.createElement("button", {
    className: "fortress-mobile-notifications fortress-notification-toggle",
    type: "button",
    "data-notification-toggle": true,
    "aria-label": "Open notifications"
  }, React.createElement("i", {
    className: "fa-solid fa-bell"
  }), React.createElement("span", {
    className: "fortress-notification-badge",
    "data-notification-badge": true,
    hidden: true
  }, "0")), React.createElement("button", {
    className: "fortress-mobile-refresh",
    type: "button",
    onClick: refreshWorkspace,
    "aria-label": "Refresh security status"
  }, React.createElement("i", {
    className: "fa-solid fa-arrows-rotate"
  })), React.createElement("a", {
    className: "fortress-mobile-logout",
    href: "/logout.php",
    "aria-label": "Log out"
  }, React.createElement("i", {
    className: "fa-solid fa-arrow-right-from-bracket"
  })))), document.body), React.createElement("div", {
    className: `fortress-sidebar-overlay ${open ? 'open' : ''}`,
    onClick: () => setOpen(false)
  }), React.createElement("aside", {
    className: `command-chrome fortress-sidebar ${open ? 'open' : ''}`,
    "data-fortress-sidebar": true
  }, React.createElement("div", {
    className: "sidebar-brand-card"
  }, React.createElement(NavLink, {
    className: "brand-lockup",
    to: "/overview",
    "aria-label": "FortressAuth command center",
    onMouseEnter: prefetch('dashboard', '/dashboard.php'),
    onFocus: prefetch('dashboard', '/dashboard.php'),
    onClick: openLegacyRoute('/overview', 'dashboard', '/dashboard.php')
  }, React.createElement("span", {
    className: "topbar-logo"
  }, React.createElement("img", {
    src: "/images/wolf1.png",
    alt: ""
  })), React.createElement("span", {
    className: "brand-copy"
  }, React.createElement("small", null, "SECURE ACCESS"), React.createElement("strong", null, "FortressAuth"), React.createElement("em", null, "Command Center"))), React.createElement("button", {
    type: "button",
    className: "sidebar-close",
    onClick: () => setOpen(false),
    "aria-label": "Close navigation"
  }, React.createElement("i", {
    className: "fa-solid fa-xmark"
  }))), React.createElement("div", {
    className: "sidebar-status-card"
  }, React.createElement("div", null, React.createElement("span", null, "Workspace status"), React.createElement("strong", null, React.createElement("i", {
    className: "live-dot"
  }), boostActive ? " Boosted" : " Enforced")), React.createElement("div", {
    className: "sidebar-score"
  }, React.createElement("span", null, "Score"), React.createElement("strong", null, header.protectionScore))), React.createElement(NavLink, {
    className: ({
      isActive
    }) => `sidebar-operator-card operator-management-link ${isActive ? 'active' : ''}`,
    to: "/operator",
    onMouseEnter: prefetchCurrentOperator,
    onFocus: prefetchCurrentOperator,
    onPointerDown: prefetchCurrentOperator,
    onClick: openOperator
  }, React.createElement("span", {
    className: "sidebar-operator-icon"
  }, React.createElement("i", {
    className: "fa-solid fa-user-shield"
  })), React.createElement("span", {
    className: "operator-card-copy"
  }, React.createElement("small", null, "Current operator"), React.createElement("strong", null, header.username), React.createElement("em", {
    className: "operator-manage-hint"
  }, React.createElement("i", {
    className: "fa-solid fa-users-gear"
  }), " Users ", React.createElement("span", null, "+"), " ", React.createElement("i", {
    className: "fa-solid fa-id-card"
  }), " ID ", React.createElement("span", null, "+"), " ", React.createElement("i", {
    className: "fa-solid fa-file-export"
  }), " Reports")), React.createElement("span", {
    className: `sidebar-operator-badge ${header.role === 'superadmin' ? 'superadmin' : ''}`
  }, header.roleLabel)), React.createElement("nav", {
    className: "command-nav",
    "aria-label": "FortressAuth navigation"
  }, React.createElement("p", {
    className: "sidebar-section-label"
  }, "Navigation"), React.createElement("div", {
    className: "command-nav-links",
    id: "command-nav-links"
  }, navItems.map(([path, page, legacyUrl, icon, label, sub]) => React.createElement(NavLink, {
    key: path,
    to: path,
    onMouseEnter: prefetch(page, legacyUrl),
    onFocus: prefetch(page, legacyUrl),
    onPointerDown: prefetch(page, legacyUrl),
    onClick: openLegacyRoute(path, page, legacyUrl),
    className: ({
      isActive
    }) => isActive ? 'active' : ''
  }, React.createElement("span", {
    className: "nav-icon"
  }, React.createElement("i", {
    className: `fa-solid ${icon}`
  })), React.createElement("span", {
    className: "nav-copy"
  }, React.createElement("strong", null, label), React.createElement("small", null, sub)), location.pathname === path && React.createElement("span", {
    className: "nav-active-rail",
    "aria-hidden": "true"
  }))), React.createElement(NavLink, {
    className: ({
      isActive
    }) => `nav-crown-jewel ${isActive ? 'active' : ''}`,
    to: "/vault",
    onClick: openVault
  }, React.createElement("span", {
    className: "crown-jewel-caption",
    "aria-hidden": "true"
  }, "Pentest objective"), React.createElement("span", {
    className: "crown-jewel-image-frame",
    "aria-hidden": "true"
  }, React.createElement("img", {
    className: "crown-jewel-image",
    src: "/images/jewel.png",
    alt: ""
  }), React.createElement("span", {
    className: "crown-jewel-sweep"
  }), React.createElement("span", {
    className: "crown-jewel-flare crown-jewel-flare-one"
  }), React.createElement("span", {
    className: "crown-jewel-flare crown-jewel-flare-two"
  })), React.createElement("span", {
    className: "crown-jewel-accessible-text"
  }, "Crown Jewel - Pentest Objective"))))), React.createElement("div", {
    className: "fortress-main-column"
  }, React.createElement("header", {
    className: "fortress-page-header"
  }, React.createElement("div", {
    className: "page-heading-left"
  }, React.createElement("span", {
    className: "page-heading-icon"
  }, React.createElement("i", {
    className: `fa-solid ${meta[2]}`
  })), React.createElement("div", null, React.createElement("div", {
    className: "page-heading-chips"
  }, React.createElement("span", null, "FORTRESSAUTH"), React.createElement("span", {
    className: `status-chip ${boostActive ? 'boost-active' : ''}`
  }, React.createElement("i", {
    className: boostActive ? 'fa-solid fa-bolt' : 'live-dot'
  }), boostActive ? " FORTRESS BOOST ACTIVE" : " PROTECTION ENFORCED")), React.createElement("h1", null, meta[0]), React.createElement("p", null, meta[1], " \xB7 ", header.activeDefenseCount, "/", header.defenseTotal, " defense layers operational"))), React.createElement("div", {
    className: "page-heading-actions"
  }, React.createElement("div", {
    className: "header-score-card"
  }, React.createElement("span", null, "Protection"), React.createElement("strong", null, header.protectionScore, "/100")), React.createElement("button", {
    className: "icon-action fortress-notification-toggle",
    type: "button",
    "data-notification-toggle": true,
    title: "Security notifications",
    "aria-label": "Open security notifications"
  }, React.createElement("i", {
    className: "fa-solid fa-bell"
  }), React.createElement("span", {
    className: "fortress-notification-badge",
    "data-notification-badge": true,
    hidden: true
  }, "0")), React.createElement("button", {
    className: "icon-action",
    type: "button",
    onClick: refreshWorkspace,
    title: "Refresh security status"
  }, React.createElement("i", {
    className: "fa-solid fa-arrows-rotate"
  })), React.createElement("a", {
    className: "logout-mini",
    href: "/logout.php"
  }, React.createElement("i", {
    className: "fa-solid fa-arrow-right-from-bracket"
  }), React.createElement("span", null, "Log out")))), React.createElement("div", {
    id: "fortress-security-runtime",
    hidden: true,
    ...runtimeAttrs
  }), React.createElement("div", {
    id: "fortress-notification-backdrop",
    className: "fortress-notification-backdrop",
    "data-notification-close": true,
    hidden: true
  }), React.createElement("section", {
    id: "fortress-notification-panel",
    className: "fortress-notification-panel",
    "aria-label": "Security notifications",
    "aria-hidden": "true",
    hidden: true
  }, React.createElement("div", {
    className: "fortress-notification-panel-glow fortress-notification-panel-glow-one",
    "aria-hidden": "true"
  }), React.createElement("div", {
    className: "fortress-notification-panel-glow fortress-notification-panel-glow-two",
    "aria-hidden": "true"
  }), React.createElement("div", {
    className: "fortress-notification-panel-header"
  }, React.createElement("div", {
    className: "fortress-notification-panel-heading"
  }, React.createElement("span", {
    className: "fortress-notification-panel-icon"
  }, React.createElement("i", {
    className: "fa-solid fa-bell"
  })), React.createElement("div", null, React.createElement("h2", null, "Fortress security notifications"), React.createElement("p", null, "Threat detections, blocked attacks, authentication events, account changes, and security reports."))), React.createElement("button", {
    type: "button",
    className: "fortress-notification-close",
    "data-notification-close": true,
    "aria-label": "Close notifications"
  }, React.createElement("i", {
    className: "fa-solid fa-xmark"
  }))), React.createElement("div", {
    className: "fortress-notification-toolbar"
  }, React.createElement("button", {
    type: "button",
    className: "fortress-notification-tool",
    "data-notification-mark-all": true
  }, React.createElement("i", {
    className: "fa-solid fa-check-double"
  }), React.createElement("span", null, "Mark all read")), React.createElement("button", {
    type: "button",
    className: "fortress-notification-tool",
    "data-notification-enable-toggle": true
  }, React.createElement("i", {
    className: "fa-solid fa-bell"
  }), React.createElement("span", null, "Live notifications on"))), React.createElement("div", {
    className: "fortress-notification-list",
    "data-notification-list": true
  }, React.createElement("div", {
    className: "fortress-notification-empty fortress-notification-clear"
  }, React.createElement("span", {
    className: "fortress-notification-empty-icon"
  }, React.createElement("i", {
    className: "fa-solid fa-circle-check"
  })), React.createElement("strong", null, "No notification events yet"), React.createElement("span", null, "Saved notifications appear instantly here while FortressAuth syncs newer security events in the background.")))), React.createElement("div", {
    id: "fortress-security-alert-host",
    className: "fortress-security-alert-host",
    "aria-live": "assertive",
    "aria-atomic": "false"
  }), children)));
}

/* ---- App.jsx ---- */
function ShellRoutes() {
  return React.createElement(AppShell, null, React.createElement(Routes, null, React.createElement(Route, {
    path: "/overview",
    element: React.createElement(Overview, null)
  }), React.createElement(Route, {
    path: "/activity",
    element: React.createElement(AccessActivity, null)
  }), React.createElement(Route, {
    path: "/analytics",
    element: React.createElement(Analytics, null)
  }), React.createElement(Route, {
    path: "/threats",
    element: React.createElement(Threats, null)
  }), React.createElement(Route, {
    path: "/ai-defense",
    element: React.createElement(AIDefense, null)
  }), React.createElement(Route, {
    path: "/logs",
    element: React.createElement(SecurityLogs, null)
  }), React.createElement(Route, {
    path: "/blocked-ips",
    element: React.createElement(BlockedIPs, null)
  }), React.createElement(Route, {
    path: "/security-controls",
    element: React.createElement(SecurityControls, null)
  }), React.createElement(Route, {
    path: "/operator",
    element: React.createElement(CurrentOperator, null)
  }), React.createElement(Route, {
    path: "*",
    element: React.createElement(Navigate, {
      to: "/overview",
      replace: true
    })
  })));
}
function App() {
  const location = useLocation();
  if (location.pathname === '/vault') return React.createElement(Vault, null);
  return React.createElement(ShellRoutes, null);
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(React.StrictMode, null, React.createElement(HashRouter, null, React.createElement(App))));
})();
