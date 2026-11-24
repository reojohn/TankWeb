(() => {
  'use strict';
  const toggle = document.getElementById('menu-toggle');
  const nav = document.getElementById('site-nav');
  const header = document.getElementById('site-header');
  const bar = document.getElementById('scroll-progress');
  let scheduled = false;

  const closeMenu = () => {
    if (!nav || !toggle) return;
    nav.classList.remove('is-open');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Open navigation');
    document.body.classList.remove('mobile-menu-open');
  };
  if (toggle && nav) {
    toggle.addEventListener('click', () => {
      const open = !nav.classList.contains('is-open');
      nav.classList.toggle('is-open', open);
      toggle.setAttribute('aria-expanded', String(open));
      toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
      document.body.classList.toggle('mobile-menu-open', open);
    });
    nav.querySelectorAll('a').forEach(link => link.addEventListener('click', closeMenu));
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && nav.classList.contains('is-open')) {
        closeMenu();
        toggle.focus();
      }
    });
    document.addEventListener('click', event => {
      if (nav.classList.contains('is-open') && !nav.contains(event.target) && !toggle.contains(event.target)) closeMenu();
    });
    matchMedia('(min-width: 901px)').addEventListener('change', event => { if (event.matches) closeMenu(); });
  }

  function updateScroll() {
    scheduled = false;
    if (header) header.classList.toggle('is-scrolled', window.scrollY > 12);
    if (bar) {
      const max = document.documentElement.scrollHeight - window.innerHeight;
      const progress = max > 0 ? Math.min(100, (window.scrollY / max) * 100) : 0;
      bar.style.transform = `scaleX(${progress / 100})`;
    }
  }
  const onScroll = () => {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(updateScroll);
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });
  updateScroll();

  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!reduceMotion && 'IntersectionObserver' in window) {
    const elements = [...document.querySelectorAll('.feature-card,.step,.research-card,.metric,.section-heading,.final-cta')];
    // The content is visible by default. Only hide elements shortly before observing them,
    // with an immediate fallback when observers are unavailable.
    const io = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add('is-visible');
        io.unobserve(entry.target);
      }
    }, { rootMargin: '0px 0px -32px 0px', threshold: 0.06 });
    elements.forEach(el => {
      if (el.getBoundingClientRect().top > window.innerHeight + 40) {
        el.classList.add('reveal-ready');
        io.observe(el);
      }
    });
  }
})();
