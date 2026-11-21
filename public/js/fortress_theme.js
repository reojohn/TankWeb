(() => {
  'use strict';

  if (window.FortressTheme) return;

  const normalize = (mode) => {
    const value = String(mode || 'balanced').trim().toLowerCase();
    if (value === 'standard') return 'standard';
    if (value === 'fortress_boost' || value === 'fortress-boost' || value === 'fortress') return 'fortress_boost';
    return 'balanced';
  };

  const themeColor = {
    standard: '#06160f',
    balanced: '#10071f',
    fortress_boost: '#180307',
  };

  let switchTimer = 0;

  const apply = (mode, options = {}) => {
    const normalized = normalize(mode);
    const body = document.body;
    if (!body) return normalized;

    const previous = body.dataset.fortressTheme || '';
    body.dataset.fortressTheme = normalized;

    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', themeColor[normalized]);

    if (options.animate !== false && previous && previous !== normalized) {
      body.classList.remove('fortress-theme-switching');
      // Restart the ignition sweep even when profiles are changed quickly.
      void body.offsetWidth;
      body.classList.add('fortress-theme-switching');
      if (switchTimer) window.clearTimeout(switchTimer);
      switchTimer = window.setTimeout(() => {
        body.classList.remove('fortress-theme-switching');
        switchTimer = 0;
      }, 820);
    }

    return normalized;
  };

  const syncFromDom = () => {
    const marker = document.querySelector('[data-runtime-defense-theme]');
    if (marker instanceof HTMLElement) {
      apply(marker.dataset.runtimeDefenseTheme || 'balanced', { animate: false });
      return;
    }

    const engine = document.querySelector('[data-defense-engine]');
    if (engine instanceof HTMLElement) {
      apply(engine.dataset.engineMode || 'balanced', { animate: false });
    }
  };

  window.FortressTheme = { apply, normalize, syncFromDom };

  window.addEventListener('fortress:defense-profile-changed', (event) => {
    apply(event?.detail?.mode || 'balanced');
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', syncFromDom, { once: true });
  } else {
    syncFromDom();
  }
})();
