(() => {
  'use strict';

  const token = document.body?.dataset?.logoutAuditToken || '';
  if (!token) return;

  const body = new URLSearchParams({ token }).toString();
  let queued = false;

  try {
    if (typeof navigator.sendBeacon === 'function') {
      const payload = new Blob([body], {
        type: 'application/x-www-form-urlencoded;charset=UTF-8',
      });
      queued = navigator.sendBeacon('/api/logout_audit.php', payload);
    }
  } catch (_) {
    queued = false;
  }

  if (!queued) {
    try {
      fetch('/api/logout_audit.php', {
        method: 'POST',
        credentials: 'omit',
        cache: 'no-store',
        keepalive: true,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        },
        body,
      }).catch(() => {});
    } catch (_) {
      // Logout has already completed. Durable audit persistence is best effort
      // and must never delay or reverse session termination.
    }
  }
})();
