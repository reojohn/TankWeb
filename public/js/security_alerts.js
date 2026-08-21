(() => {
  'use strict';

  const state = window.FortressSecurityAlertsState || {
    cursor: null,
    streamId: '',
    notifications: [],
    toastSeen: new Set(),
    historyLoaded: false,
  };
  if (!(state.toastSeen instanceof Set)) state.toastSeen = new Set(state.toastSeen || []);
  if (!Array.isArray(state.notifications)) state.notifications = [];
  window.FortressSecurityAlertsState = state;

  let intervalId = null;
  let visibilityHandler = null;
  let outsideHandler = null;
  let keyHandler = null;
  let uiAbortController = null;
  let toastDismissTimer = null;
  let toastRemovalTimer = null;
  let polling = false;
  let destroyed = false;
  let generation = 0;
  let activeToast = null;
  let toastQueue = [];
  let panelOpen = false;
  let owner = '0';
  let notificationsEnabled = true;
  let readIds = new Set();

  const NOTIFICATION_CACHE_VERSION = 2;
  const MAX_CACHED_NOTIFICATIONS = 40;
  const CACHE_HISTORY_REFRESH_MS = 15 * 60 * 1000;

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[char]));

  const storageKey = (name) => `fortress-${name}-${owner}`;

  const loadStoredReadIds = () => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey('read-notifications')) || '[]');
      return new Set(Array.isArray(saved) ? saved.slice(-250).map(String) : []);
    } catch (_) {
      return new Set();
    }
  };

  const saveReadIds = () => {
    try {
      localStorage.setItem(storageKey('read-notifications'), JSON.stringify(Array.from(readIds).slice(-250)));
    } catch (_) {}
  };

  const loadEnabledPreference = () => {
    try {
      const saved = localStorage.getItem(storageKey('notifications-enabled'));
      return saved === null ? true : saved !== 'false';
    } catch (_) {
      return true;
    }
  };

  const saveEnabledPreference = () => {
    try {
      localStorage.setItem(storageKey('notifications-enabled'), String(notificationsEnabled));
    } catch (_) {}
  };

  const normalizeEvent = (event = {}) => ({
    id: String(event.id || ''),
    key: String(event.key || 'security_event'),
    title: String(event.title || 'Security notification'),
    description: String(event.description || 'A FortressAuth security event was recorded.'),
    source_ip: String(event.source_ip || 'unknown'),
    time: String(event.time || 'Recent'),
    timestamp: String(event.timestamp || ''),
    outcome: String(event.outcome || 'RECORDED'),
    category: String(event.category || 'System'),
    severity: ['danger', 'warning', 'success', 'activity'].includes(String(event.severity))
      ? String(event.severity)
      : 'activity',
    target: String(event.target || '/admin_logs.php#audit-logs'),
  });

  const loadNotificationCache = () => {
    try {
      const raw = localStorage.getItem(storageKey('notification-cache'));
      if (!raw) return null;

      const cached = JSON.parse(raw);
      if (!cached || Number(cached.version) !== NOTIFICATION_CACHE_VERSION) return null;

      const notifications = Array.isArray(cached.notifications)
        ? cached.notifications.map(normalizeEvent).filter((item) => item.id).slice(0, MAX_CACHED_NOTIFICATIONS)
        : [];
      const hasCursor = cached.cursor !== null && cached.cursor !== undefined && cached.cursor !== '';
      const cursorValue = hasCursor ? Number(cached.cursor) : NaN;
      const cursor = Number.isFinite(cursorValue) && cursorValue >= 0 ? cursorValue : null;
      const streamId = typeof cached.streamId === 'string' ? cached.streamId : '';
      const lastSyncAtValue = Number(cached.lastSyncAt || cached.savedAt || 0);
      const lastSyncAt = Number.isFinite(lastSyncAtValue) && lastSyncAtValue > 0 ? lastSyncAtValue : 0;

      return { notifications, cursor, streamId, lastSyncAt };
    } catch (_) {
      return null;
    }
  };

  const saveNotificationCache = () => {
    try {
      localStorage.setItem(storageKey('notification-cache'), JSON.stringify({
        version: NOTIFICATION_CACHE_VERSION,
        cursor: state.cursor !== null && state.cursor !== undefined && state.cursor !== '' && Number.isFinite(Number(state.cursor))
          ? Number(state.cursor)
          : null,
        streamId: String(state.streamId || ''),
        notifications: state.notifications.slice(0, MAX_CACHED_NOTIFICATIONS),
        lastSyncAt: Number(state.lastSyncAt || 0),
        savedAt: Date.now(),
      }));
    } catch (_) {}
  };

  const severityRank = (severity) => ({ danger: 4, warning: 3, activity: 2, success: 1 }[severity] || 0);

  const mergeNotifications = (events = []) => {
    const merged = new Map(state.notifications.map((item) => [String(item.id), normalizeEvent(item)]));
    events.forEach((raw) => {
      const item = normalizeEvent(raw);
      if (item.id) merged.set(item.id, item);
    });

    state.notifications = Array.from(merged.values())
      .sort((a, b) => {
        const at = Date.parse(a.timestamp) || 0;
        const bt = Date.parse(b.timestamp) || 0;
        if (bt !== at) return bt - at;
        return severityRank(b.severity) - severityRank(a.severity);
      })
      .slice(0, MAX_CACHED_NOTIFICATIONS);
  };

  const formatNotificationTime = (timestamp, fallback = 'Recent') => {
    if (!timestamp) return fallback;
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return fallback;

    const now = Date.now();
    const diff = Math.max(0, now - date.getTime());
    if (diff < 60_000) return 'Just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} hr ago`;

    return date.toLocaleString([], {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const tone = (severity) => {
    if (severity === 'danger') {
      return {
        label: 'Priority alert',
        icon: 'fa-triangle-exclamation',
        dot: 'danger',
      };
    }
    if (severity === 'warning') {
      return {
        label: 'Monitoring notice',
        icon: 'fa-circle-exclamation',
        dot: 'warning',
      };
    }
    if (severity === 'success') {
      return {
        label: 'Security update',
        icon: 'fa-circle-check',
        dot: 'success',
      };
    }
    return {
      label: 'Activity update',
      icon: 'fa-wave-square',
      dot: 'activity',
    };
  };

  const unreadNotifications = () => notificationsEnabled
    ? state.notifications.filter((item) => item.id && !readIds.has(item.id))
    : [];

  const updateBellState = () => {
    const unread = unreadNotifications().length;

    document.querySelectorAll('[data-notification-badge]').forEach((badge) => {
      badge.textContent = unread > 99 ? '99+' : String(unread);
      badge.hidden = unread === 0;
    });

    document.querySelectorAll('[data-notification-toggle]').forEach((button) => {
      const icon = button.querySelector('i');
      if (icon) {
        icon.classList.toggle('fa-bell', notificationsEnabled);
        icon.classList.toggle('fa-bell-slash', !notificationsEnabled);
      }
      button.classList.toggle('notifications-disabled', !notificationsEnabled);
      button.setAttribute('aria-label', notificationsEnabled ? 'Open security notifications' : 'Security notifications are paused');
      button.setAttribute('aria-expanded', panelOpen ? 'true' : 'false');
    });

    const toggle = document.querySelector('[data-notification-enable-toggle]');
    if (toggle) {
      const icon = toggle.querySelector('i');
      const label = toggle.querySelector('span');
      if (icon) {
        icon.classList.toggle('fa-bell', notificationsEnabled);
        icon.classList.toggle('fa-bell-slash', !notificationsEnabled);
      }
      if (label) label.textContent = notificationsEnabled ? 'Live notifications on' : 'Live notifications off';
      toggle.classList.toggle('is-off', !notificationsEnabled);
    }
  };

  const renderPanel = () => {
    const list = document.querySelector('[data-notification-list]');
    if (!list) return;

    if (!notificationsEnabled) {
      list.innerHTML = `
        <div class="fortress-notification-empty fortress-notification-paused">
          <span class="fortress-notification-empty-icon"><i class="fa-solid fa-bell-slash"></i></span>
          <strong>Live notifications are paused</strong>
          <span>Turn them back on above to resume security badges, polling, and toast reminders.</span>
        </div>`;
      updateBellState();
      return;
    }

    if (state.notifications.length === 0) {
      list.innerHTML = `
        <div class="fortress-notification-empty fortress-notification-clear">
          <span class="fortress-notification-empty-icon"><i class="fa-solid fa-circle-check"></i></span>
          <strong>No notification events yet</strong>
          <span>FortressAuth will surface meaningful threat, authentication, and account events here.</span>
        </div>`;
      updateBellState();
      return;
    }

    list.innerHTML = state.notifications.map((item) => {
      const isRead = readIds.has(item.id);
      const itemTone = tone(item.severity);
      return `
        <a class="fortress-notification-item tone-${escapeHtml(item.severity)} ${isRead ? 'is-read' : 'is-unread'}"
           href="${escapeHtml(item.target)}"
           data-notification-id="${escapeHtml(item.id)}">
          <span class="fortress-notification-status-dot ${escapeHtml(itemTone.dot)}"></span>
          <span class="fortress-notification-item-body">
            <span class="fortress-notification-title-row">
              <strong>${escapeHtml(item.title)}</strong>
              ${isRead ? '' : '<em>New</em>'}
            </span>
            <span class="fortress-notification-message">${escapeHtml(item.description)}</span>
            <span class="fortress-notification-meta">
              <span><i class="fa-regular fa-clock"></i> ${escapeHtml(formatNotificationTime(item.timestamp, item.time))}</span>
              <span><i class="fa-solid fa-layer-group"></i> ${escapeHtml(item.category)}</span>
              <span><i class="fa-solid fa-network-wired"></i> ${escapeHtml(item.source_ip || 'unknown')}</span>
            </span>
            <span class="fortress-notification-open">Open details <i class="fa-solid fa-arrow-up-right-from-square"></i></span>
          </span>
        </a>`;
    }).join('');

    list.querySelectorAll('[data-notification-id]').forEach((item) => {
      item.addEventListener('click', (eventObject) => {
        const openDetails = eventObject.target?.closest?.('.fortress-notification-open');

        // React v3 keeps the notification drawer mounted while the user is
        // reviewing alerts. A normal click on a notification should therefore
        // mark it as read without dismissing the entire panel. Only the
        // explicit "Open details" action is allowed to navigate away.
        if (!openDetails) {
          eventObject.preventDefault();
          eventObject.stopPropagation();
          markRead(item.dataset.notificationId || '');
          return;
        }

        markRead(item.dataset.notificationId || '');
        closePanel();
      });
    });

    updateBellState();
  };

  const markRead = (id) => {
    if (!id) return;
    readIds.add(String(id));
    saveReadIds();
    renderPanel();
  };

  const markAllRead = () => {
    state.notifications.forEach((item) => {
      if (item.id) readIds.add(item.id);
    });
    saveReadIds();
    renderPanel();
  };

  const openTarget = (event) => {
    if (!event) return;
    markRead(event.id);
    closePanel();
    const target = event.target || '/admin_logs.php#audit-logs';
    if (window.FortressPJAX?.navigate) {
      window.FortressPJAX.navigate(target);
    } else {
      window.location.assign(target);
    }
  };

  const openPanel = () => {
    const panel = document.getElementById('fortress-notification-panel');
    const backdrop = document.getElementById('fortress-notification-backdrop');
    if (!panel) return;

    // PJAX replaces the header markup between pages. Re-render from the
    // in-memory/localStorage cache before showing the panel so a stale server
    // placeholder can never flash as a fake loading state.
    renderPanel();
    panelOpen = true;
    panel.hidden = false;
    panel.setAttribute('aria-hidden', 'false');
    backdrop?.removeAttribute('hidden');
    requestAnimationFrame(() => panel.classList.add('is-open'));
    document.body.classList.add('fortress-notification-panel-open');
    updateBellState();
  };

  const closePanel = () => {
    const panel = document.getElementById('fortress-notification-panel');
    const backdrop = document.getElementById('fortress-notification-backdrop');
    panelOpen = false;
    if (panel) {
      panel.classList.remove('is-open');
      panel.setAttribute('aria-hidden', 'true');
      window.setTimeout(() => {
        if (!panelOpen && panel.isConnected) panel.hidden = true;
      }, 180);
    }
    if (backdrop) backdrop.hidden = true;
    document.body.classList.remove('fortress-notification-panel-open');
    updateBellState();
  };

  const dismissToast = () => {
    const alert = activeToast;
    if (!alert) return;

    alert.classList.remove('visible');
    if (toastDismissTimer !== null) window.clearTimeout(toastDismissTimer);
    toastDismissTimer = null;

    if (toastRemovalTimer !== null) window.clearTimeout(toastRemovalTimer);
    toastRemovalTimer = window.setTimeout(() => {
      alert.remove();
      if (activeToast === alert) activeToast = null;
      presentNextToast();
    }, 260);
  };

  const presentNextToast = () => {
    const host = document.getElementById('fortress-security-alert-host');
    if (destroyed || !notificationsEnabled || !host || activeToast || toastQueue.length === 0) return;

    const event = toastQueue.shift();
    if (!event || state.toastSeen.has(event.id)) return presentNextToast();
    state.toastSeen.add(event.id);

    const itemTone = tone(event.severity);
    const alert = document.createElement('section');
    alert.className = `fortress-threat-alert tone-${event.severity}`;
    alert.setAttribute('role', 'status');
    alert.innerHTML = `
      <div class="fortress-threat-alert-glow" aria-hidden="true"></div>
      <div class="fortress-threat-alert-icon"><i class="fa-solid ${itemTone.icon}"></i><span></span></div>
      <div class="fortress-threat-alert-copy">
        <div class="fortress-threat-alert-kicker"><i class="fa-solid fa-satellite-dish"></i> ${escapeHtml(itemTone.label)}</div>
        <h2>${escapeHtml(event.title)}</h2>
        <p>${escapeHtml(event.description)}</p>
        <div class="fortress-threat-alert-meta">
          <span><i class="fa-solid fa-network-wired"></i> ${escapeHtml(event.source_ip || 'unknown')}</span>
          <span><i class="fa-solid fa-shield"></i> ${escapeHtml(event.outcome || 'RECORDED')}</span>
          <span><i class="fa-regular fa-clock"></i> ${escapeHtml(formatNotificationTime(event.timestamp, event.time))}</span>
        </div>
        <button class="fortress-threat-alert-open" type="button">Open details <i class="fa-solid fa-arrow-right"></i></button>
      </div>
      <button class="fortress-threat-alert-close" type="button" aria-label="Dismiss security notification"><i class="fa-solid fa-xmark"></i></button>
      <div class="fortress-threat-alert-progress" aria-hidden="true"><span></span></div>`;

    host.appendChild(alert);
    activeToast = alert;
    requestAnimationFrame(() => alert.classList.add('visible'));

    alert.querySelector('.fortress-threat-alert-close')?.addEventListener('click', (eventObject) => {
      eventObject.stopPropagation();
      dismissToast();
    }, { once: true });

    alert.querySelector('.fortress-threat-alert-open')?.addEventListener('click', () => {
      dismissToast();
      openTarget(event);
    }, { once: true });

    toastDismissTimer = window.setTimeout(dismissToast, 5200);
  };

  const queueToast = (event) => {
    if (!notificationsEnabled || !event?.id || state.toastSeen.has(event.id)) return;
    if (toastQueue.some((queued) => queued.id === event.id)) return;
    toastQueue.push(event);
    toastQueue.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    presentNextToast();
  };

  const handleAuthFailure = (response) => {
    if (response.status !== 401 && response.status !== 403) return false;
    destroy();
    if (window.location.pathname !== '/login.php') {
      window.location.assign('/login.php?reason=session_expired');
    }
    return true;
  };

  const loadHistory = async (runGeneration) => {
    if (!notificationsEnabled) {
      renderPanel();
      return;
    }

    try {
      const response = await fetch('/security_alert_feed.php?history=1', {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Accept': 'application/json' },
      });
      if (handleAuthFailure(response)) return;
      if (!response.ok || destroyed || runGeneration !== generation) return;

      const payload = await response.json();
      if (!payload || payload.success !== true || destroyed || runGeneration !== generation) return;

      const knownIds = new Set(state.notifications.map((item) => item.id));
      state.cursor = Number(payload.cursor || 0);
      state.streamId = String(payload.stream_id || '');
      const events = Array.isArray(payload.events) ? payload.events.map(normalizeEvent) : [];
      mergeNotifications(events);
      state.lastSyncAt = Date.now();
      saveNotificationCache();
      renderPanel();

      if (!state.historyLoaded) {
        // Initial history is a snapshot, not a newly detected attack. Never
        // replay an old security event as a fresh toast after a hard refresh
        // or on a second device whose local notification cache is empty. New
        // events that arrive after this cursor is established are still
        // toasted by poll() below.
        state.historyLoaded = true;
      } else {
        const newestUnseen = events.find((item) => item.id && !knownIds.has(item.id) && !readIds.has(item.id));
        if (newestUnseen) queueToast(newestUnseen);
      }
    } catch (_) {
      const list = document.querySelector('[data-notification-list]');
      if (list && state.notifications.length === 0) {
        list.innerHTML = `
          <div class="fortress-notification-empty fortress-notification-paused">
            <span class="fortress-notification-empty-icon"><i class="fa-solid fa-triangle-exclamation"></i></span>
            <strong>Notifications temporarily unavailable</strong>
            <span>The security feed could not be reached. Existing protection remains active.</span>
          </div>`;
      }
    }
  };

  const poll = async (runGeneration) => {
    if (destroyed || runGeneration !== generation || polling || document.hidden || !notificationsEnabled) return;
    if (state.cursor === null) {
      await loadHistory(runGeneration);
      return;
    }

    polling = true;
    try {
      const streamQuery = state.streamId ? `&stream=${encodeURIComponent(state.streamId)}` : '';
      const response = await fetch(`/security_alert_feed.php?cursor=${encodeURIComponent(state.cursor)}${streamQuery}`, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Accept': 'application/json' },
      });
      if (handleAuthFailure(response)) return;
      if (!response.ok || destroyed || runGeneration !== generation) return;

      const payload = await response.json();
      if (!payload || payload.success !== true || destroyed || runGeneration !== generation) return;

      const knownIds = new Set(state.notifications.map((item) => item.id));
      state.cursor = Number(payload.cursor || state.cursor || 0);
      state.streamId = String(payload.stream_id || state.streamId || '');
      const events = Array.isArray(payload.events) ? payload.events.map(normalizeEvent) : [];
      if (events.length > 0) {
        mergeNotifications(events);
        renderPanel();

        // A container restart can reset the server-side audit stream while the
        // browser still has the previous cursor. The feed then returns recent
        // history with reset=true. Only toast events that were not already in
        // this browser's cache, avoiding a replay storm of old notifications.
        const toastEvents = payload.reset === true
          ? events.filter((item) => item.id && !knownIds.has(item.id) && !readIds.has(item.id))
          : events;
        toastEvents.forEach(queueToast);
      }
      state.lastSyncAt = Date.now();
      saveNotificationCache();
    } catch (_) {
      // Notification UI must never interrupt the protected application.
    } finally {
      polling = false;
    }
  };

  const destroy = () => {
    destroyed = true;
    generation += 1;
    if (intervalId !== null) window.clearInterval(intervalId);
    if (toastDismissTimer !== null) window.clearTimeout(toastDismissTimer);
    if (toastRemovalTimer !== null) window.clearTimeout(toastRemovalTimer);
    if (visibilityHandler) document.removeEventListener('visibilitychange', visibilityHandler);
    if (outsideHandler) document.removeEventListener('pointerdown', outsideHandler, true);
    if (keyHandler) document.removeEventListener('keydown', keyHandler);
    if (uiAbortController) uiAbortController.abort();
    intervalId = null;
    toastDismissTimer = null;
    toastRemovalTimer = null;
    visibilityHandler = null;
    outsideHandler = null;
    keyHandler = null;
    uiAbortController = null;
    polling = false;
    toastQueue = [];
    panelOpen = false;
    activeToast?.remove();
    activeToast = null;
    document.body.classList.remove('fortress-notification-panel-open');
  };

  const init = () => {
    destroy();
    destroyed = false;
    const runGeneration = generation;

    const runtime = document.getElementById('fortress-security-runtime');
    if (!runtime) return;

    owner = String(runtime.dataset.notificationUser || '0');
    const pollSeconds = Math.max(2, Number(runtime.dataset.alertPollSeconds || 4));
    const previousOwner = String(state.owner || '');
    const ownerChanged = previousOwner !== owner;

    if (ownerChanged) {
      state.cursor = null;
      state.streamId = '';
      state.notifications = [];
      state.historyLoaded = false;
      state.lastSyncAt = 0;
      state.toastSeen = new Set();
    }
    state.owner = owner;

    const cachedState = loadNotificationCache();
    if (cachedState && (ownerChanged || state.notifications.length === 0)) {
      state.notifications = cachedState.notifications;
      state.cursor = cachedState.cursor;
      state.streamId = cachedState.streamId;
      state.lastSyncAt = cachedState.lastSyncAt;
      // Cached items are already-known history. They should render instantly,
      // but they should not replay old toast popups after every page refresh.
      state.historyLoaded = true;
    }

    readIds = loadStoredReadIds();
    notificationsEnabled = loadEnabledPreference();

    // React v3 can re-initialize this module when the persistent shell data
    // refreshes. Abort the previous UI-listener group before binding a new
    // one so a single click can never run multiple open/close handlers.
    if (uiAbortController) uiAbortController.abort();
    uiAbortController = new AbortController();
    const uiSignal = uiAbortController.signal;

    document.querySelectorAll('[data-notification-toggle]').forEach((button) => {
      button.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        panelOpen ? closePanel() : openPanel();
      }, { signal: uiSignal });
    });

    document.querySelectorAll('[data-notification-close]').forEach((button) => {
      button.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        closePanel();
      }, { signal: uiSignal });
    });

    document.querySelector('[data-notification-mark-all]')?.addEventListener('click', markAllRead, { signal: uiSignal });
    document.querySelector('[data-notification-enable-toggle]')?.addEventListener('click', () => {
      notificationsEnabled = !notificationsEnabled;
      saveEnabledPreference();

      if (!notificationsEnabled) {
        toastQueue = [];
        activeToast?.remove();
        activeToast = null;
        if (toastDismissTimer !== null) window.clearTimeout(toastDismissTimer);
        if (toastRemovalTimer !== null) window.clearTimeout(toastRemovalTimer);
      } else {
        // Keep the persisted list visible and do a silent history refresh so
        // events recorded while notifications were paused are recovered.
        loadHistory(runGeneration).catch(() => {});
      }

      renderPanel();
      updateBellState();
    }, { signal: uiSignal });

    outsideHandler = (event) => {
      if (!panelOpen) return;
      const panel = document.getElementById('fortress-notification-panel');
      if (panel?.contains(event.target)) return;
      if (event.target?.closest?.('[data-notification-toggle]')) return;
      closePanel();
    };
    document.addEventListener('pointerdown', outsideHandler, true);

    keyHandler = (event) => {
      if (event.key === 'Escape' && panelOpen) closePanel();
    };
    document.addEventListener('keydown', keyHandler);

    renderPanel();
    updateBellState();

    if (notificationsEnabled) {
      const cacheAge = Date.now() - Number(state.lastSyncAt || 0);
      if (state.cursor === null || !state.streamId || cacheAge > CACHE_HISTORY_REFRESH_MS) {
        // The cached list is already on screen. This full history refresh is
        // background synchronization only; it never replaces the panel with a
        // loading state.
        loadHistory(runGeneration).then(() => poll(runGeneration));
      } else {
        // Recent cache: resume exactly from the saved audit-log cursor.
        poll(runGeneration);
      }
    }

    intervalId = window.setInterval(() => poll(runGeneration), pollSeconds * 1000);
    visibilityHandler = () => {
      if (!document.hidden) poll(runGeneration);
    };
    document.addEventListener('visibilitychange', visibilityHandler);
  };

  const pollNow = () => {
    if (destroyed) return;
    poll(generation);
  };

  window.FortressSecurityAlerts = { init, destroy, pollNow };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
