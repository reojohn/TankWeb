import React, { useEffect, useRef, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import useFortressView from '../hooks/useFortressView.js';
import { prefetchLegacyPage, warmLegacyPages } from './LegacyParityPage.jsx';
import { prefetchCurrentOperator } from '../pages/CurrentOperator.jsx';
import { prefetchVault } from '../pages/Vault.jsx';

const navItems = [
  ['/overview', 'dashboard', '/dashboard.php', 'fa-table-cells-large', 'Overview', 'Security command center'],
  ['/activity', 'access_activity', '/access_activity.php', 'fa-wave-square', 'Access Activity', 'Authentication history'],
  ['/analytics', 'analytics', '/analytics.php', 'fa-chart-pie', 'Security Analytics', 'Charts and trends'],
  ['/threats', 'threats', '/threats.php', 'fa-shield-virus', 'Threats', 'Intrusion monitoring'],
  ['/ai-defense', 'ai_threat_intelligence', '/ai_threat_intelligence.php', 'fa-brain', 'AI Defense', 'ML threat intelligence'],
  ['/logs', 'admin_logs', '/admin_logs.php', 'fa-clipboard-list', 'Security Logs', 'Audit evidence'],
  ['/blocked-ips', 'blocked_ips', '/blocked_ips.php', 'fa-ban', 'Blocked IPs', 'Network enforcement'],
  ['/security-controls', 'security_controls', '/security_controls.php', 'fa-sliders', 'Security Controls', 'Defense configuration'],
];

const pageMap = {
  '/overview': ['Overview', 'Security command center', 'fa-table-cells-large'],
  '/activity': ['Access Activity', 'Authentication history', 'fa-wave-square'],
  '/analytics': ['Security Analytics', 'Charts and trends', 'fa-chart-pie'],
  '/threats': ['Threats', 'Intrusion monitoring', 'fa-shield-virus'],
  '/ai-defense': ['AI Defense', 'ML threat intelligence', 'fa-brain'],
  '/logs': ['Security Logs', 'Audit evidence', 'fa-clipboard-list'],
  '/blocked-ips': ['Blocked IPs', 'Network enforcement', 'fa-ban'],
  '/security-controls': ['Security Controls', 'Defense configuration', 'fa-sliders'],
  '/operator': ['Current Operator', 'Users, Personal ID and documentation reports', 'fa-user-shield'],
};

export default function AppShell({ children }) {
  const { data, loading, reload } = useFortressView('bootstrap');
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
      '/operator': 'user-management-page',
    }[location.pathname] || '';
    document.body.className = `command-page fortress-react-v3 ${legacyBodyClass}`.trim();
    setOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (data?.defenseProfileMode) setRuntimeDefenseMode(data.defenseProfileMode);
  }, [data?.defenseProfileMode]);

  useEffect(() => {
    const onProfileChanged = (event) => {
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

  // Warm the page fragments while the user is reading the current screen.
  // This turns normal sidebar navigation into an in-memory switch instead of
  // showing a skeleton while PHP/Supabase prepares the next page.
  useEffect(() => {
    if (!data) return undefined;
    let cancelled = false;
    let timerId = null;

    const queue = navItems
      .filter(([path]) => path !== location.pathname)
      .map(([, page, legacyUrl]) => [page, legacyUrl]);

    const warm = () => {
      if (cancelled) return;
      warmLegacyPages(queue);
      // Current Operator now has a silent v3 fragment endpoint, so it can be
      // warmed safely without creating a false user_management_access event.
      prefetchCurrentOperator();

      // Crown Jewel remains excluded because opening it is the pentest objective.
    };

    // Begin warming almost immediately after bootstrap. Running the ordinary
    // fragments in parallel avoids the old page-1 -> page-2 -> page-3 waterfall.
    timerId = window.setTimeout(warm, 60);
    return () => {
      cancelled = true;
      if (timerId !== null) window.clearTimeout(timerId);
    };
  }, [data?.userId]);

  // React v3 keeps the shell mounted between route changes, so the legacy
  // v2 live-refresh script cannot reload the current PHP pathname anymore.
  // Watch the lightweight server-side security revision instead and tell the
  // active React route to re-fetch its original v2 fragment when evidence
  // changes. This preserves SPA navigation while keeping threat counters,
  // tables, charts and feeds live without a manual browser refresh.
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
            'X-Fortress-React': '1',
          },
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

        // Refresh the persistent shell score/defense summary and the active
        // v2-parity content. Existing content remains visible while the new
        // server snapshot arrives.
        reload();
        window.dispatchEvent(new CustomEvent('fortress:v3-route-refresh', {
          detail: { revision, source: 'security-live-state' },
        }));
        window.dispatchEvent(new CustomEvent('fortress:live-security-updated', {
          detail: { revision },
        }));

        // Pull the matching notification immediately instead of waiting for
        // the normal notification interval.
        window.FortressSecurityAlerts?.pollNow?.();
      } catch (_) {
        // Live synchronization is enhancement-only. A temporary failure must
        // never interrupt the authenticated workspace.
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
    username: 'Loading…', roleLabel: 'ADMIN', protectionScore: 0, activeDefenseCount: 0, defenseTotal: 8,
    defenseProfileMode: 'balanced', defenseProfileLabel: 'BALANCED',
    policy: { alertPollSeconds: 4, livePollSeconds: 2, sessionIdleSeconds: 900 },
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
    'data-notification-user': String(header.userId || header.username || ''),
  };

  const prefetch = (page, legacyUrl) => () => prefetchLegacyPage(page, legacyUrl);

  const openLegacyRoute = (path, page, legacyUrl) => (event) => {
    if (location.pathname === path) return;
    event.preventDefault();
    prefetchLegacyPage(page, legacyUrl);
    navigate(path);
  };

  const openOperator = (event) => {
    if (location.pathname === '/operator') return;
    event.preventDefault();
    // Start fetching immediately, but never hold the route transition hostage.
    // CurrentOperator will join the same in-flight request and paint a skeleton
    // if the warmed copy is not ready yet.
    prefetchCurrentOperator();
    navigate('/operator');
  };

  const openVault = (event) => {
    if (location.pathname === '/vault') return;
    event.preventDefault();
    // Start the protected vault request immediately, but do not block the SPA
    // route transition on network/PHP latency. Vault joins this same in-flight
    // request and shows its loading state until the protected content arrives.
    prefetchVault();
    navigate('/vault');
  };

  const refreshWorkspace = () => {
    reload();
    window.dispatchEvent(new CustomEvent('fortress:v3-route-refresh'));
  };

  return (
    <>
      <div className="ambient ambient-one" aria-hidden="true" />
      <div className="ambient ambient-two" aria-hidden="true" />

      {/* Keep the mobile command bar outside the scrolling/grid shell.
          iOS Safari can delay painting a fixed descendant of a positioned
          grid container until the first scroll. As a root-level sibling the
          bar is composited immediately and remains pinned from first paint. */}
      <div className="fortress-mobile-bar">
        <button className="fortress-mobile-menu" type="button" aria-label="Open navigation" aria-expanded={open} onClick={() => setOpen(!open)}>
          <i className="fa-solid fa-bars" />
        </button>
        <div className="fortress-mobile-title"><strong>{meta[0]}</strong><span>{boostActive ? 'FortressAuth · Fortress Boost active' : 'FortressAuth · Protection enforced'}</span></div>
        <div className="fortress-mobile-actions">
          <button className="fortress-mobile-notifications fortress-notification-toggle" type="button" data-notification-toggle aria-label="Open notifications"><i className="fa-solid fa-bell" /><span className="fortress-notification-badge" data-notification-badge hidden>0</span></button>
          <button className="fortress-mobile-refresh" type="button" onClick={refreshWorkspace} aria-label="Refresh security status"><i className="fa-solid fa-arrows-rotate" /></button>
          <a className="fortress-mobile-logout" href="/logout.php" aria-label="Log out"><i className="fa-solid fa-arrow-right-from-bracket" /></a>
        </div>
      </div>
      <div className={`fortress-sidebar-overlay ${open ? 'open' : ''}`} onClick={() => setOpen(false)} />

      <main className="command-shell fortress-react-shell">
        <aside className={`command-chrome fortress-sidebar ${open ? 'open' : ''}`} data-fortress-sidebar>
          <div className="sidebar-brand-card">
            <NavLink
              className="brand-lockup"
              to="/overview"
              aria-label="FortressAuth command center"
              onMouseEnter={prefetch('dashboard', '/dashboard.php')}
              onFocus={prefetch('dashboard', '/dashboard.php')}
              onClick={openLegacyRoute('/overview', 'dashboard', '/dashboard.php')}
            >
              <span className="topbar-logo"><img src="/images/wolf1.png" alt="" /></span>
              <span className="brand-copy"><small>SECURE ACCESS</small><strong>FortressAuth</strong><em>Command Center</em></span>
            </NavLink>
            <button type="button" className="sidebar-close" onClick={() => setOpen(false)} aria-label="Close navigation"><i className="fa-solid fa-xmark" /></button>
          </div>
          <div className="sidebar-status-card">
            <div><span>Workspace status</span><strong><i className="live-dot" /> {boostActive ? 'Boosted' : 'Enforced'}</strong></div>
            <div className="sidebar-score"><span>Score</span><strong>{header.protectionScore}</strong></div>
          </div>
          <NavLink
            className={({isActive}) => `sidebar-operator-card operator-management-link ${isActive ? 'active' : ''}`}
            to="/operator"
            onMouseEnter={prefetchCurrentOperator}
            onFocus={prefetchCurrentOperator}
            onPointerDown={prefetchCurrentOperator}
            onClick={openOperator}
          >
            <span className="sidebar-operator-icon"><i className="fa-solid fa-user-shield" /></span>
            <span className="operator-card-copy"><small>Current operator</small><strong>{header.username}</strong><em className="operator-manage-hint"><i className="fa-solid fa-users-gear" /> Users <span>+</span> <i className="fa-solid fa-id-card" /> ID <span>+</span> <i className="fa-solid fa-file-export" /> Reports</em></span>
            <span className={`sidebar-operator-badge ${header.role === 'superadmin' ? 'superadmin' : ''}`}>{header.roleLabel}</span>
          </NavLink>
          <nav className="command-nav" aria-label="FortressAuth navigation">
            <p className="sidebar-section-label">Navigation</p>
            <div className="command-nav-links" id="command-nav-links">
              {navItems.map(([path, page, legacyUrl, icon, label, sub]) => (
                <NavLink
                  key={path}
                  to={path}
                  onMouseEnter={prefetch(page, legacyUrl)}
                  onFocus={prefetch(page, legacyUrl)}
                  onPointerDown={prefetch(page, legacyUrl)}
                  onClick={openLegacyRoute(path, page, legacyUrl)}
                  className={({isActive}) => isActive ? 'active' : ''}
                >
                  <span className="nav-icon"><i className={`fa-solid ${icon}`} /></span>
                  <span className="nav-copy"><strong>{label}</strong><small>{sub}</small></span>
                  {location.pathname === path && <span className="nav-active-rail" aria-hidden="true" />}
                </NavLink>
              ))}
              <NavLink
                className={({isActive}) => `nav-crown-jewel ${isActive ? 'active' : ''}`}
                to="/vault"
                onClick={openVault}
              >
                <span className="crown-jewel-caption" aria-hidden="true">Pentest objective</span>
                <span className="crown-jewel-image-frame" aria-hidden="true"><img className="crown-jewel-image" src="/images/jewel.png" alt="" /><span className="crown-jewel-sweep" /><span className="crown-jewel-flare crown-jewel-flare-one" /><span className="crown-jewel-flare crown-jewel-flare-two" /></span>
                <span className="crown-jewel-accessible-text">Crown Jewel - Pentest Objective</span>
              </NavLink>
            </div>
          </nav>
        </aside>

        <div className="fortress-main-column">
          <header className="fortress-page-header">
            <div className="page-heading-left">
              <span className="page-heading-icon"><i className={`fa-solid ${meta[2]}`} /></span>
              <div><div className="page-heading-chips"><span>FORTRESSAUTH</span><span className={`status-chip ${boostActive ? 'boost-active' : ''}`}><i className={boostActive ? 'fa-solid fa-bolt' : 'live-dot'} /> {boostActive ? 'FORTRESS BOOST ACTIVE' : 'PROTECTION ENFORCED'}</span></div><h1>{meta[0]}</h1><p>{meta[1]} · {header.activeDefenseCount}/{header.defenseTotal} defense layers operational</p></div>
            </div>
            <div className="page-heading-actions">
              <div className="header-score-card"><span>Protection</span><strong>{header.protectionScore}/100</strong></div>
              <button className="icon-action fortress-notification-toggle" type="button" data-notification-toggle title="Security notifications" aria-label="Open security notifications"><i className="fa-solid fa-bell" /><span className="fortress-notification-badge" data-notification-badge hidden>0</span></button>
              <button className="icon-action" type="button" onClick={refreshWorkspace} title="Refresh security status"><i className="fa-solid fa-arrows-rotate" /></button>
              <a className="logout-mini" href="/logout.php"><i className="fa-solid fa-arrow-right-from-bracket" /><span>Log out</span></a>
            </div>
          </header>

          <div id="fortress-security-runtime" hidden {...runtimeAttrs} />
          <div id="fortress-notification-backdrop" className="fortress-notification-backdrop" data-notification-close hidden />
          <section id="fortress-notification-panel" className="fortress-notification-panel" aria-label="Security notifications" aria-hidden="true" hidden>
            <div className="fortress-notification-panel-glow fortress-notification-panel-glow-one" aria-hidden="true" />
            <div className="fortress-notification-panel-glow fortress-notification-panel-glow-two" aria-hidden="true" />
            <div className="fortress-notification-panel-header"><div className="fortress-notification-panel-heading"><span className="fortress-notification-panel-icon"><i className="fa-solid fa-bell" /></span><div><h2>Fortress security notifications</h2><p>Threat detections, blocked attacks, authentication events, account changes, and security reports.</p></div></div><button type="button" className="fortress-notification-close" data-notification-close aria-label="Close notifications"><i className="fa-solid fa-xmark" /></button></div>
            <div className="fortress-notification-toolbar"><button type="button" className="fortress-notification-tool" data-notification-mark-all><i className="fa-solid fa-check-double" /><span>Mark all read</span></button><button type="button" className="fortress-notification-tool" data-notification-enable-toggle><i className="fa-solid fa-bell" /><span>Live notifications on</span></button></div>
            <div className="fortress-notification-list" data-notification-list><div className="fortress-notification-empty fortress-notification-clear"><span className="fortress-notification-empty-icon"><i className="fa-solid fa-circle-check" /></span><strong>No notification events yet</strong><span>Saved notifications appear instantly here while FortressAuth syncs newer security events in the background.</span></div></div>
          </section>
          <div id="fortress-security-alert-host" className="fortress-security-alert-host" aria-live="assertive" aria-atomic="false" />

          {children}
        </div>
      </main>
    </>
  );
}
