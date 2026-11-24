/* Aegis AI — non-invasive hero scroll controls. No model/API changes. */
(() => {
  document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-defense-jump]');
    if (!button) return;
    const targetId = button.getAttribute('data-defense-jump');
    if (!['live-lab', 'it113-groq-panel'].includes(targetId)) return;
    const target = document.getElementById(targetId);
    if (!target) return;
    target.scrollIntoView({behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',block:'start'});
  });
})();
