import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const parityFragmentCache = new Map();
// Each in-flight entry owns an AbortController and request id so a forced
// refresh can supersede older stale-while-revalidate work instead of joining it.
const parityInflight = new Map();
const parityRequestSequence = new Map();

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
  '/fortress_vault.php': '/vault',
};

const pagePathMap = {
  dashboard: '/dashboard.php',
  access_activity: '/access_activity.php',
  analytics: '/analytics.php',
  threats: '/threats.php',
  ai_threat_intelligence: '/ai_threat_intelligence.php',
  admin_logs: '/admin_logs.php',
  blocked_ips: '/blocked_ips.php',
  security_controls: '/security_controls.php',
};

const routePageMap = {
  '/overview': ['dashboard', '/dashboard.php'],
  '/activity': ['access_activity', '/access_activity.php'],
  '/analytics': ['analytics', '/analytics.php'],
  '/threats': ['threats', '/threats.php'],
  '/ai-defense': ['ai_threat_intelligence', '/ai_threat_intelligence.php'],
  '/logs': ['admin_logs', '/admin_logs.php'],
  '/blocked-ips': ['blocked_ips', '/blocked_ips.php'],
  '/security-controls': ['security_controls', '/security_controls.php'],
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
  main.querySelectorAll('script').forEach((node) => node.remove());
  return main.innerHTML.trim();
}

async function requestFragment(page, legacyUrl = '', { force = false } = {}) {
  const key = cacheKey(page, legacyUrl);
  const cached = parityFragmentCache.get(key);
  if (!force && cached) return cached.html;

  const existing = parityInflight.get(key);
  if (!force && existing) return existing.promise;

  // A forced refresh represents newer server state (for example immediately
  // after changing the defense engine). Abort an older background fragment
  // request so it cannot repaint the page with stale profile HTML afterwards.
  if (force && existing?.controller) existing.controller.abort();

  const controller = new AbortController();
  const requestId = (parityRequestSequence.get(key) || 0) + 1;
  parityRequestSequence.set(key, requestId);

  const promise = fetch(buildFragmentUrl(page, legacyUrl), {
    credentials: 'same-origin',
    cache: 'no-store',
    signal: controller.signal,
    headers: { Accept: 'text/html', 'X-Fortress-React': '1', 'X-Fortress-Live-Refresh': '1' },
  }).then(async (response) => {
    if (response.status === 401 || response.status === 403) {
      window.location.href = '/login.php';
      throw new Error('Authentication expired');
    }
    const html = await response.text();
    if (!response.ok) throw new Error(html || 'Unable to load FortressAuth page content.');
    if (parityRequestSequence.get(key) === requestId) {
      parityFragmentCache.set(key, { at: Date.now(), html });
    }
    return html;
  }).finally(() => {
    if (parityInflight.get(key)?.requestId === requestId) parityInflight.delete(key);
  });

  parityInflight.set(key, { promise, controller, requestId });
  return promise;
}

async function touchPage(page) {
  try {
    const response = await fetch(`/api/v3_touch.php?page=${encodeURIComponent(page)}`, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'X-Fortress-React': '1' },
    });
    if (response.status === 401 || response.status === 403) window.location.href = '/login.php';
  } catch (_) {
    // Content rendering should remain usable even if a route heartbeat fails.
  }
}

export function prefetchLegacyPage(page, legacyUrl = '') {
  if (!pagePathMap[page]) return Promise.resolve('');
  return requestFragment(page, legacyUrl).catch(() => '');
}

export async function warmLegacyPages(items = []) {
  const jobs = items
    .map((item) => (Array.isArray(item) ? item : [item, '']))
    .filter(([page]) => pagePathMap[page])
    .map(([page, legacyUrl]) => prefetchLegacyPage(page, legacyUrl));

  await Promise.allSettled(jobs);
}

function updateFragmentCache(page, legacyUrl, html) {
  parityFragmentCache.set(cacheKey(page, legacyUrl), { at: Date.now(), html });
}

function formatRouteTarget(resolved) {
  const route = legacyRouteMap[resolved.pathname];
  if (!route) return null;
  return route + (resolved.search || '');
}

export default function LegacyParityPage({ page, legacyUrl, ai = false }) {
  const navigate = useNavigate();
  const root = useRef(null);
  const currentLegacyUrl = useRef(legacyUrl || pagePathMap[page] || '/');
  const initialCached = parityFragmentCache.get(cacheKey(page, currentLegacyUrl.current))?.html || '';
  const [html, setHtml] = useState(initialCached);
  const [loading, setLoading] = useState(!initialCached);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const pendingAnchor = useRef('');
  const loadRevision = useRef(0);

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

  const load = async ({ force = false, url = currentLegacyUrl.current } = {}) => {
    const revision = ++loadRevision.current;
    const key = cacheKey(page, url);
    const cached = parityFragmentCache.get(key)?.html || '';
    setError('');

    // Stale-while-revalidate: a cached page is painted immediately. The PHP
    // fragment refresh happens silently afterwards and only replaces the DOM
    // when it is still the newest load for this component.
    if (cached && !force) {
      currentLegacyUrl.current = url;
      setHtml(cached);
      setLoading(false);
      setRefreshing(false);

      requestFragment(page, url, { force: true })
        .then((next) => {
          if (loadRevision.current !== revision) return;
          currentLegacyUrl.current = url;
          if (next && next !== cached) setHtml(next);
        })
        .catch(() => {
          // Keep the known-good cached page visible if a background refresh
          // fails or is intentionally superseded by a newer forced refresh.
        });
      return cached;
    }

    setLoading(!html);
    setRefreshing(Boolean(html));
    try {
      const next = await requestFragment(page, url, { force });
      if (loadRevision.current !== revision) return next;
      currentLegacyUrl.current = url;
      setHtml(next);
      return next;
    } catch (e) {
      if (loadRevision.current === revision && e?.name !== 'AbortError') {
        setError(e?.message || String(e));
      }
      return '';
    } finally {
      if (loadRevision.current === revision) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  };

  useEffect(() => {
    currentLegacyUrl.current = legacyUrl || pagePathMap[page] || '/';
    const cached = parityFragmentCache.get(cacheKey(page, currentLegacyUrl.current))?.html || '';
    if (cached) setHtml(cached);
    else setHtml('');
    touchPage(page);
    load({ url: currentLegacyUrl.current });
  }, [page, legacyUrl]);

  useEffect(() => {
    const refresh = () => load({ force: true });
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
        if (id) root.current?.querySelector(`#${CSS.escape(id)}`)?.scrollIntoView({ block: 'start' });
        pendingAnchor.current = '';
      }
    }, 20);
    return () => window.clearTimeout(timer);
  }, [html, ai]);

  useEffect(() => {
    const node = root.current;
    if (!node) return undefined;

    const onClick = async (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const anchor = event.target.closest?.('a[href]');
      if (!anchor || !node.contains(anchor) || anchor.target === '_blank' || anchor.hasAttribute('download')) return;
      const href = anchor.getAttribute('href') || '';
      if (!href || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) return;

      if (href.startsWith('#')) {
        event.preventDefault();
        const id = href.slice(1);
        if (id) root.current?.querySelector(`#${CSS.escape(id)}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        return;
      }

      const resolved = new URL(href, window.location.origin);
      if (resolved.origin !== window.location.origin) return;
      const target = formatRouteTarget(resolved);
      if (!target) return;

      event.preventDefault();
      pendingAnchor.current = resolved.hash || '';

      // Start any missing fragment request, but never hold the route change
      // behind network latency. In normal use the parallel warmer has already
      // filled this cache, so the destination paints from memory immediately.
      const routePath = target.split('?')[0];
      const targetPage = routePageMap[routePath];
      if (targetPage) {
        prefetchLegacyPage(targetPage[0], targetPage[1] + (resolved.search || ''));
      }

      navigate(target, { state: resolved.hash ? { legacyAnchor: resolved.hash } : undefined });
    };

    const onSubmit = async (event) => {
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
        const options = { method, credentials: 'same-origin', headers: { 'X-Fortress-React': '1' } };
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

  return (
    <>
      {loading && !html ? (
        <section
          className="v3-route-skeleton"
          aria-label="Loading FortressAuth page"
          aria-busy="true"
          role="status"
        >
          <span className="sr-only">Loading FortressAuth page</span>
          <div className="v3-skeleton-metrics">
            {[0, 1, 2, 3].map((item) => <span key={item} />)}
          </div>
          <div className="v3-skeleton-panels">
            <span />
            <span />
          </div>
        </section>
      ) : null}
      {error ? <section className="panel v3-error-panel"><i className="fa-solid fa-triangle-exclamation" /><div><strong>Unable to load this workspace</strong><span>{error}</span></div></section> : null}
      <div
        ref={root}
        className="v3-v2-parity-content"
        aria-busy={loading || refreshing ? 'true' : 'false'}
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </>
  );
}
