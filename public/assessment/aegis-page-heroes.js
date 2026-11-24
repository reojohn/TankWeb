/* Aegis AI premium section heroes with abstract backgrounds.
   Presentation only: does not modify data flow, model execution, persistence or navigation state. */
(() => {
  'use strict';

  const safeScroll = (id) => {
    const target = document.getElementById(id);
    if (!target) return;
    target.scrollIntoView({ behavior: window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  };

  const makeIcon = (kind) => {
    const icons = {
      target: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"></circle><path d="M12 8v4l3 2"></path></svg>',
      graph: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 19V5"></path><path d="M4 19h16"></path><path d="m7 15 4-4 3 2 4-6"></path></svg>',
      file: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3h8l5 5v13H8z"></path><path d="M16 3v5h5"></path></svg>',
      shield: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 6v6c0 5 3 8 8 10 5-2 8-5 8-10V6Z"></path><path d="m9 12 2 2 4-4"></path></svg>',
      spark: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 2 1.8 6.2L20 10l-6.2 1.8L12 18l-1.8-6.2L4 10l6.2-1.8z"></path></svg>'
    };
    return icons[kind] || icons.target;
  };

  const heroes = {
    dataset: {
      title: 'Know the data.<br><span>Trust the signal.</span>',
      eyebrow: 'AEGIS AI',
      divider: 'DATA INTELLIGENCE',
      kicker: 'RUBRIC A · DATASET ASSESSMENT',
      desc: 'Trace the synthetic evidence foundation behind every prediction, from class balance and feature engineering to consistency validation.',
      chips: ['35,000 synthetic records', '20 engineered features', 'Consistency checks'],
      primary: { label: 'Explore model inputs', target: 'feature-list', icon: 'graph' },
      secondary: { label: 'Open case study', target: 'rubric-a-lab', icon: 'file' },
      caption: 'AEGIS / DATASET INTELLIGENCE',
      image: '/assessment/hero-dataset-bg.webp'
    },
    evaluation: {
      title: 'Measure the model.<br><span>See the evidence.</span>',
      eyebrow: 'AEGIS AI',
      divider: 'MODEL VERIFICATION',
      kicker: 'RUBRIC C · EVALUATION & INTERPRETATION',
      desc: 'Review confusion patterns, class-level performance, anomaly behavior, and the evaluation protocol used on the untouched synthetic test split.',
      chips: ['10,500 held-out records', 'Confusion matrix', 'Error analysis'],
      primary: { label: 'See confusion matrix', target: 'confusion-matrix', icon: 'graph' },
      secondary: { label: 'Review error audit', target: 'phase3-error-analysis', icon: 'file' },
      caption: 'AEGIS / MODEL EVALUATION',
      image: '/assessment/hero-evaluation-bg.webp'
    },
    examples: {
      title: 'Validate the outcome.<br><span>Interrogate the case.</span>',
      eyebrow: 'AEGIS AI',
      divider: 'CASE VALIDATION',
      kicker: 'RUBRIC A & C · FINDINGS VALIDATION',
      desc: 'Inspect saved model outputs for held-out synthetic records and compare correct and incorrect predictions without running live inference again.',
      chips: ['Held-out examples', 'Confidence review', 'Evidence-first'],
      primary: { label: 'Browse test cases', target: 'example-list', icon: 'target' },
      secondary: { label: 'Inspect prediction', target: 'example-detail', icon: 'file' },
      caption: 'AEGIS / VALIDATION WORKSPACE',
      image: '/assessment/hero-examples-bg.webp'
    },
    mitigations: {
      title: 'Recommend the response.<br><span>Reduce the risk.</span>',
      eyebrow: 'AEGIS AI',
      divider: 'RESPONSE GUIDANCE',
      kicker: 'RUBRIC D · THREAT MITIGATIONS',
      desc: 'Turn detected behavior into practical next steps with human-reviewed safeguards, response priorities, and mitigation strategies.',
      chips: ['OWASP-aligned', 'Analyst review', 'Control guidance'],
      primary: { label: 'Prioritize a threat', target: 'phase3-mitigation-filters', icon: 'shield' },
      secondary: { label: 'Open response plan', target: 'rubric-d-linked', icon: 'file' },
      caption: 'AEGIS / THREAT MITIGATIONS',
      image: '/assessment/hero-mitigations-bg.webp'
    },
    findings: {
      title: 'Follow the findings.<br><span>Track the pattern.</span>',
      eyebrow: 'AEGIS AI',
      divider: 'PUBLIC RESEARCH FEED',
      kicker: 'RUBRIC A & D · EVIDENCE REVIEW',
      desc: 'Review curated synthetic assessments, compare public findings with your own tests, and inspect evidence before any mitigation is proposed.',
      chips: ['Public assessments', 'Curated evidence', 'Session-safe tests'],
      primary: { label: 'Open public timeline', target: 'findings-timeline', icon: 'graph' },
      secondary: { label: 'Inspect evidence detail', target: 'finding-detail-panel', icon: 'file' },
      caption: 'AEGIS / FINDINGS TIMELINE',
      image: '/assessment/hero-findings-bg.webp'
    },
    analytics: {
      title: 'Read the metrics.<br><span>Understand the story.</span>',
      eyebrow: 'AEGIS AI',
      divider: 'SECURITY ANALYTICS',
      kicker: 'RUBRIC C · EXPLAINABLE METRICS',
      desc: 'Compare held-out performance with recent curated assessments and read the dashboard in a risk-aware, evidence-based way.',
      chips: ['Recall insights', 'Session trends', 'Interpretation guidance'],
      primary: { label: 'Compare recall', target: 'analytics-recall', icon: 'graph' },
      secondary: { label: 'View classifications', target: 'analytics-session', icon: 'target' },
      caption: 'AEGIS / ANALYTICS ENGINE',
      image: '/assessment/hero-analytics-bg.webp'
    },
    reports: {
      title: 'Package the evidence.<br><span>Present the research.</span>',
      eyebrow: 'AEGIS AI',
      divider: 'ACADEMIC DOCUMENTATION',
      kicker: 'RUBRIC A–E · RESEARCH REPORTS',
      desc: 'Access the final documentation workspace, export the latest public findings, and prepare the evidence trail for presentation and submission.',
      chips: ['PDF brief', 'JSON & CSV exports', 'Submission-ready pack'],
      primary: { label: 'Open current report', target: 'dynamic-report-preview', icon: 'file' },
      secondary: { label: 'View methodology pack', target: 'rubric-e-documentation', icon: 'spark' },
      caption: 'AEGIS / RESEARCH ARCHIVE',
      image: '/assessment/hero-reports-bg.webp'
    }
  };

  const attachHero = (viewId, config) => {
    const section = document.getElementById(`view-${viewId}`);
    if (!section || section.querySelector('.aegis-page-hero')) return;
    const heading = section.querySelector(':scope > .section-heading');
    if (heading) heading.classList.add('aegis-page-heading-hidden');

    const hero = document.createElement('div');
    hero.className = 'aegis-page-hero';
    hero.setAttribute('aria-labelledby', `${viewId}-hero-title`);
    hero.style.setProperty('--hero-image', `url("${config.image}")`);
    hero.innerHTML = `
      <div class="aegis-page-hero-art" aria-hidden="true"></div>
      <div class="aegis-page-hero-overlay" aria-hidden="true"></div>
      <div class="aegis-page-hero-grid" aria-hidden="true"></div>
      <div class="aegis-page-hero-content">
        <div class="aegis-page-hero-eyebrow"><span class="aegis-page-hero-pulse" aria-hidden="true"></span> ${config.eyebrow} <span class="aegis-page-hero-divider" aria-hidden="true">/</span> ${config.divider}</div>
        <div class="aegis-page-hero-kicker">${config.kicker}</div>
        <h1 id="${viewId}-hero-title">${config.title}</h1>
        <p>${config.desc}</p>
        <div class="aegis-page-hero-actions">
          <button type="button" class="aegis-page-hero-action aegis-page-hero-action-primary" data-hero-scroll="${config.primary.target}">${makeIcon(config.primary.icon)} ${config.primary.label} <span aria-hidden="true">↗</span></button>
          <button type="button" class="aegis-page-hero-action aegis-page-hero-action-secondary" data-hero-scroll="${config.secondary.target}">${makeIcon(config.secondary.icon)} ${config.secondary.label} <span aria-hidden="true">↗</span></button>
        </div>
        <div class="aegis-page-hero-chips">${config.chips.map((chip, index) => `<span>${index === 0 ? '<span class="aegis-page-hero-pulse" aria-hidden="true"></span>' : ''}${chip}</span>`).join('')}</div>
      </div>
      <div class="aegis-page-hero-caption" aria-hidden="true"><span></span> ${config.caption}</div>
    `;

    const anchor = heading || section.firstElementChild;
    if (anchor) section.insertBefore(hero, anchor.nextSibling);
    else section.prepend(hero);
  };

  const init = () => {
    document.documentElement.style.setProperty('--overview-hero-bg', 'url("/assessment/hero-overview-bg.webp")');
    const overviewHero = document.querySelector('#view-overview > .hero');
    if (overviewHero) overviewHero.classList.add('hero--with-bg');

    Object.entries(heroes).forEach(([viewId, config]) => attachHero(viewId, config));

    document.addEventListener('click', (event) => {
      const trigger = event.target.closest('[data-hero-scroll]');
      if (!trigger) return;
      safeScroll(trigger.getAttribute('data-hero-scroll'));
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
