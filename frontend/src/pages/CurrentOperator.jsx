import React, { useEffect, useRef, useState } from 'react';

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
  main.querySelectorAll('script').forEach((node) => node.remove());
  return main.innerHTML;
}

async function requestOperatorHtml({ force = false } = {}) {
  if (!force && operatorCache && Date.now() - operatorCache.at < OPERATOR_TTL) {
    return operatorCache.html;
  }
  if (!force && operatorInflight) return operatorInflight;

  operatorInflight = fetch('/user_management.php', {
    credentials: 'same-origin',
    headers: { 'X-Fortress-React': '1' },
  }).then(async (response) => {
    if (response.status === 401 || response.status === 403 || response.url.includes('/login.php')) {
      window.location.href = '/login.php';
      throw new Error('Authentication expired');
    }
    const text = await response.text();
    if (!response.ok) throw new Error('Operator workspace failed to load.');
    const html = extractContent(text);
    operatorCache = { at: Date.now(), html };
    return html;
  }).finally(() => {
    operatorInflight = null;
  });

  return operatorInflight;
}

export function prefetchCurrentOperator() {
  return requestOperatorHtml().catch(() => '');
}

function loadScript(src, id) {
  document.getElementById(id)?.remove();
  const script = document.createElement('script');
  script.id = id;
  script.src = `${src}${src.includes('?') ? '&' : '?'}v3=${Date.now()}`;
  script.defer = false;
  document.body.appendChild(script);
}

export default function CurrentOperator() {
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
      // Default operator navigation can use the warmed in-memory copy.
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
          'X-Fortress-React': '1',
        },
      });
      if (response.status === 401 || response.status === 403 || response.url.includes('/login.php')) {
        window.location.href = '/login.php';
        return;
      }

      const text = await response.text();
      if (!response.ok) throw new Error('Operator workspace failed to load.');

      currentUrl.current = response.url
        ? new URL(response.url).pathname + new URL(response.url).search
        : requested.pathname + requested.search;

      const content = extractContent(text);
      if (currentUrl.current === '/user_management.php') {
        operatorCache = { at: Date.now(), html: content };
      }
      setHtml(content);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
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
        root.current?.querySelector(`[id="${CSS.escape(id)}"]`)?.scrollIntoView({ block: 'start' });
        pendingAnchor.current = '';
      }
    }, 20);
    return () => window.clearTimeout(timer);
  }, [html]);

  useEffect(() => {
    const node = root.current;
    if (!node) return;

    const click = (event) => {
      const anchor = event.target.closest?.('a[href]');
      if (!anchor || !node.contains(anchor)) return;
      const href = anchor.getAttribute('href') || '';

      if (href.startsWith('#')) {
        event.preventDefault();
        const target = root.current?.querySelector(`[id="${CSS.escape(href.slice(1))}"]`);
        target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        return;
      }

      const resolved = new URL(href, window.location.origin);
      if (resolved.pathname === '/user_management.php') {
        event.preventDefault();
        load(resolved.pathname + resolved.search + resolved.hash);
      }
    };

    const submit = async (event) => {
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

      // Account changes invalidate the warmed operator copy.
      operatorCache = null;
      await load(action || currentUrl.current, { method, body: formData });
    };

    node.addEventListener('click', click);
    node.addEventListener('submit', submit);
    return () => {
      node.removeEventListener('click', click);
      node.removeEventListener('submit', submit);
    };
  }, [html]);

  return (
    <>
      {error ? <section className="panel v3-error-panel"><i className="fa-solid fa-triangle-exclamation"/><div><strong>Operator workspace failed to load</strong><span>{error}</span></div></section> : null}
      <div
        ref={root}
        className="v3-legacy-bridge"
        aria-busy={loading ? 'true' : 'false'}
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </>
  );
}
