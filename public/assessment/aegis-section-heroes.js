'use strict';
// Independent visual enhancement: scroll within the already-active research view.
(() => {
  document.addEventListener('click', event => {
    const button = event.target.closest('button[data-aegis-scroll]');
    if (!button) return;
    const id = button.getAttribute('data-aegis-scroll');
    if (!/^[a-z0-9-]+$/i.test(id || '')) return;
    const target = document.getElementById(id);
    if (!target || !button.closest('.view.active')?.contains(target)) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    target.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
  });
})();
