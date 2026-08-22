import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { prefetchLegacyPage } from '../components/LegacyParityPage.jsx';

const VAULT_TTL = 30_000;
let vaultCache = null;
let vaultInflight = null;

function extractVaultBody(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.body.querySelectorAll('script').forEach((node) => node.remove());
  return doc.body.innerHTML.trim();
}

async function requestVault({ force = false } = {}) {
  if (!force && vaultCache && Date.now() - vaultCache.at < VAULT_TTL) {
    return vaultCache.html;
  }
  if (!force && vaultInflight) return vaultInflight;

  vaultInflight = fetch('/fortress_vault.php', {
    credentials: 'same-origin',
    headers: { Accept: 'text/html', 'X-Fortress-React': '1' },
  }).then(async (response) => {
    if (response.status === 401 || response.status === 403 || response.url.includes('/login.php')) {
      window.location.href = '/login.php';
      throw new Error('Authentication expired');
    }
    const text = await response.text();
    if (!response.ok) throw new Error('The Fortress Vault could not be opened.');
    const html = extractVaultBody(text);
    vaultCache = { at: Date.now(), html };
    return html;
  }).finally(() => {
    vaultInflight = null;
  });

  return vaultInflight;
}

export function prefetchVault() {
  return requestVault().catch(() => '');
}

export default function Vault() {
  const navigate = useNavigate();
  const root = useRef(null);
  const [html, setHtml] = useState(vaultCache?.html || '');
  const [error, setError] = useState('');

  useEffect(() => {
    document.body.className = 'vault-page';
    document.body.dataset.vaultStage = 'boot';
    let active = true;

    requestVault().then((content) => {
      if (active && content) setHtml(content);
    }).catch((e) => {
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

    const click = async (event) => {
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
    return <main className="vault-shell"><section className="vault-stage-card"><div className="vault-copy"><h1>Vault unavailable</h1><p>{error}</p><button type="button" onClick={() => navigate('/overview')}>Return to command center</button></div></section></main>;
  }

  if (!html) {
    return (
      <main className="vault-shell">
        <section className="v3-route-skeleton" aria-label="Opening Fortress Vault" aria-busy="true" role="status">
          <span className="sr-only">Verifying protected objective</span>
          <div className="v3-skeleton-metrics">{[0, 1, 2, 3].map((item) => <span key={item} />)}</div>
          <div className="v3-skeleton-panels"><span /><span /></div>
        </section>
      </main>
    );
  }

  return <div ref={root} className="v3-vault-parity" dangerouslySetInnerHTML={{ __html: html }} />;
}
