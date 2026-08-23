(() => {
  'use strict';

  const lifecycle = window.FortressDashboardLifecycle || { cleanups: [] };
  window.FortressDashboardLifecycle = lifecycle;

  const destroy = () => {
    while (lifecycle.cleanups.length) {
      const cleanup = lifecycle.cleanups.pop();
      try { cleanup?.(); } catch (_) {}
    }
    document.body?.classList.remove('fortress-nav-open');
  };

  const listen = (target, type, handler, options) => {
    if (!target?.addEventListener) return;
    target.addEventListener(type, handler, options);
    lifecycle.cleanups.push(() => target.removeEventListener(type, handler, options));
  };

  const trackInterval = (handler, delay) => {
    const id = window.setInterval(handler, delay);
    lifecycle.cleanups.push(() => window.clearInterval(id));
    return id;
  };

  const init = () => {
    destroy();
  const palette = ['#b45cff', '#d497ff', '#8b5cf6', '#c084fc', '#a855f7', '#e0b8ff', '#7c3aed', '#f29aff'];

  // Fortress Defense Engine. The browser only requests a profile change; the
  // PHP endpoint remains authoritative, requires CSRF, and restricts changes to
  // Super Admin accounts. The UI animation deliberately continues briefly even
  // when the server responds quickly so the mode transition remains visible.
  const defenseEngine = document.querySelector('[data-defense-engine]');
  if (defenseEngine instanceof HTMLElement) {
    const canManage = defenseEngine.dataset.engineCanManage === '1';
    const csrfToken = defenseEngine.dataset.engineCsrf || '';
    const buttons = Array.from(defenseEngine.querySelectorAll('[data-defense-mode]'));
    const overlay = defenseEngine.querySelector('[data-engine-activation]');
    const overlayTitle = defenseEngine.querySelector('[data-engine-activation-title]');
    const profileTitle = defenseEngine.querySelector('[data-engine-profile-title]');
    const profileDescription = defenseEngine.querySelector('[data-engine-profile-description]');
    const profileIcon = defenseEngine.querySelector('[data-engine-profile-icon]');
    const readyLabel = defenseEngine.querySelector('[data-engine-ready-label]');
    const message = defenseEngine.querySelector('[data-engine-message]');
    const reducedEngineMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const applyGlobalTheme = (mode, animate = true) => {
      if (window.FortressTheme?.apply) {
        return window.FortressTheme.apply(mode, { animate });
      }
      const normalized = mode === 'standard' || mode === 'fortress_boost' ? mode : 'balanced';
      document.body.dataset.fortressTheme = normalized;
      return normalized;
    };

    applyGlobalTheme(defenseEngine.dataset.engineMode || 'balanced', false);

    const copy = {
      standard: {
        title: 'Standard',
        label: 'ENGINE READY',
        description: 'Normal layered protection with conservative automated response thresholds.',
        iconPath: '/images/standard.png',
      },
      balanced: {
        title: 'Balanced',
        label: 'ENGINE READY',
        description: 'Current FortressAuth policy with strong protection and measured automated enforcement.',
        iconPath: '/images/balanced.png',
      },
      fortress_boost: {
        title: 'Fortress Boost',
        label: 'BOOST ACTIVE',
        description: 'High-alert defense profile with faster corroborated blocking and accelerated ML replay.',
        iconPath: '/images/fortressboost.png',
      },
    };


    const countupNodes = Array.from(defenseEngine.querySelectorAll('[data-engine-countup]'));
    const stepNodes = Array.from(defenseEngine.querySelectorAll('[data-engine-step]'));
    let processingTicker = 0;

    const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);

    const animateEngineCount = (node, target, duration = 950) => {
      if (!(node instanceof HTMLElement)) return;
      const safeTarget = Number.isFinite(target) ? target : Number.parseInt(node.textContent || '0', 10) || 0;
      if (reducedEngineMotion) {
        node.textContent = String(safeTarget);
        return;
      }
      const startValue = 0;
      const startTime = performance.now();
      const tick = (now) => {
        const progress = Math.min(1, (now - startTime) / duration);
        const value = Math.round(startValue + ((safeTarget - startValue) * easeOutCubic(progress)));
        node.textContent = String(value);
        if (progress < 1) {
          window.requestAnimationFrame(tick);
        } else {
          node.textContent = String(safeTarget);
        }
      };
      window.requestAnimationFrame(tick);
    };

    const runTelemetryIntro = () => {
      countupNodes.forEach((node, index) => {
        const target = Number.parseInt(node.dataset.engineCountupTarget || node.textContent || '0', 10) || 0;
        schedule(() => animateEngineCount(node, target, 860 + (index * 120)), 180 + (index * 110));
      });
    };

    const resetProcessingSteps = () => {
      stepNodes.forEach((node) => node.classList.remove('active', 'complete'));
    };

    const setProcessingStep = (activeIndex, markCompleteAll = false) => {
      stepNodes.forEach((node, index) => {
        node.classList.toggle('active', !markCompleteAll && index === activeIndex);
        node.classList.toggle('complete', markCompleteAll || index < activeIndex);
      });
    };

    const stopProcessingAnimation = (markCompleteAll = false) => {
      if (processingTicker) {
        window.clearInterval(processingTicker);
        processingTicker = 0;
      }
      buttons.forEach((button) => button.classList.remove('processing'));
      defenseEngine.classList.remove('engine-processing');
      if (markCompleteAll) {
        setProcessingStep(stepNodes.length, true);
      } else {
        resetProcessingSteps();
      }
    };

    const startProcessingAnimation = (targetButton) => {
      stopProcessingAnimation(false);
      defenseEngine.classList.add('engine-processing');
      if (targetButton instanceof HTMLElement) targetButton.classList.add('processing');
      if (!stepNodes.length) return;
      let index = 0;
      setProcessingStep(index, false);
      processingTicker = window.setInterval(() => {
        index = (index + 1) % stepNodes.length;
        setProcessingStep(index, false);
      }, 240);
    };

    lifecycle.cleanups.push(() => stopProcessingAnimation(false));

    const schedule = (fn, delay) => {
      const id = window.setTimeout(fn, delay);
      lifecycle.cleanups.push(() => window.clearTimeout(id));
      return id;
    };

    const setMessage = (text, state = '') => {
      if (!(message instanceof HTMLElement)) return;
      message.classList.remove('error', 'success');
      if (state) message.classList.add(state);
      const icon = message.querySelector('i');
      const span = message.querySelector('span');
      if (icon) {
        icon.className = `fa-solid ${state === 'error' ? 'fa-triangle-exclamation' : state === 'success' ? 'fa-circle-check' : canManage ? 'fa-circle-info' : 'fa-lock'}`;
      }
      if (span) span.textContent = text;
    };

    const applyModeUi = (mode) => {
      const selected = copy[mode] || copy.balanced;
      defenseEngine.dataset.engineMode = mode;
      defenseEngine.classList.remove('mode-standard', 'mode-balanced', 'mode-fortress_boost');
      defenseEngine.classList.add(`mode-${mode}`);
      buttons.forEach((button) => button.classList.toggle('active', button.dataset.defenseMode === mode));
      if (profileTitle) profileTitle.textContent = selected.title;
      if (profileDescription) profileDescription.textContent = selected.description;
      if (readyLabel) readyLabel.textContent = selected.label;
      if (profileIcon instanceof HTMLImageElement) {
        profileIcon.src = selected.iconPath || '/images/balanced.png';
        profileIcon.alt = `${selected.title} profile icon`;
      }
      if (mode === 'fortress_boost') {
        defenseEngine.classList.remove('engine-boost-pulse');
        // Force a new animation when Boost is re-engaged after another profile.
        void defenseEngine.offsetWidth;
        defenseEngine.classList.add('engine-boost-pulse');
      }
    };

    const setBusy = (busy) => {
      buttons.forEach((button) => { button.disabled = busy || !canManage; });
      if (overlay instanceof HTMLElement) overlay.setAttribute('aria-hidden', busy ? 'false' : 'true');
      if (!busy) defenseEngine.classList.remove('engine-processing');
    };

    schedule(() => defenseEngine.classList.add('engine-premium-ready'), 120);
    schedule(runTelemetryIntro, 210);

    if (!reducedEngineMotion) {
      const premiumTargets = [
        ...defenseEngine.querySelectorAll('.engine-dial'),
        ...defenseEngine.querySelectorAll('.engine-mode-button'),
        defenseEngine.querySelector('.engine-active-profile'),
      ].filter(Boolean);

      let premiumRaf = 0;
      let premiumX = 0;
      let premiumY = 0;

      const resetPremiumMotion = () => {
        premiumTargets.forEach((target) => {
          if (!(target instanceof HTMLElement)) return;
          target.style.transform = '';
        });
      };

      const renderPremiumMotion = () => {
        premiumRaf = 0;
        premiumTargets.forEach((target, index) => {
          if (!(target instanceof HTMLElement)) return;
          const depth = target.classList.contains('engine-active-profile') ? .22 : index < 3 ? .34 : .18;
          const x = premiumX * depth;
          const y = premiumY * depth;
          target.style.transform = `translate3d(${x.toFixed(2)}px, ${y.toFixed(2)}px, 0)`;
        });
      };

      listen(defenseEngine, 'pointermove', (event) => {
        const rect = defenseEngine.getBoundingClientRect();
        const normalizedX = ((event.clientX - rect.left) / Math.max(1, rect.width)) - .5;
        const normalizedY = ((event.clientY - rect.top) / Math.max(1, rect.height)) - .5;
        premiumX = normalizedX * 10;
        premiumY = normalizedY * 8;
        if (!premiumRaf) premiumRaf = window.requestAnimationFrame(renderPremiumMotion);
      });

      listen(defenseEngine, 'pointerleave', () => {
        premiumX = 0;
        premiumY = 0;
        if (premiumRaf) {
          window.cancelAnimationFrame(premiumRaf);
          premiumRaf = 0;
        }
        resetPremiumMotion();
      });

      lifecycle.cleanups.push(() => {
        if (premiumRaf) window.cancelAnimationFrame(premiumRaf);
        resetPremiumMotion();
      });
    }

    buttons.forEach((button) => {
      listen(button, 'click', async () => {
        if (!canManage || button.disabled) return;
        const mode = button.dataset.defenseMode || 'balanced';
        if (!copy[mode]) return;
        const previousMode = defenseEngine.dataset.engineMode || 'balanced';
        if (mode === previousMode) {
          setMessage(`${copy[mode].title} is already the active server-side defense profile.`, 'success');
          return;
        }

        if (overlayTitle) {
          overlayTitle.textContent = mode === 'fortress_boost'
            ? 'ENGAGING FORTRESS BOOST'
            : mode === 'balanced'
              ? 'CALIBRATING BALANCED DEFENSE'
              : 'APPLYING STANDARD DEFENSE';
        }
        setBusy(true);
        startProcessingAnimation(button);
        // Preview the target operating palette while the engine revs. If the
        // server rejects the profile change, the previous palette is restored.
        applyGlobalTheme(mode, true);
        setMessage('Applying the new enforcement thresholds securely...');
        const animationStarted = performance.now();

        try {
          const response = await fetch('/api/security_profile.php', {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'X-Fortress-React': '1',
            },
            body: JSON.stringify({ mode, csrfToken }),
          });
          const payload = await response.json().catch(() => ({}));
          if (response.status === 401 || response.status === 403 && !payload?.message) {
            window.location.href = '/login.php';
            return;
          }
          if (!response.ok || payload.ok === false) {
            throw new Error(payload.message || 'FortressAuth could not change the defense profile.');
          }

          const activeMode = payload?.data?.mode || mode;
          applyModeUi(activeMode);
          applyGlobalTheme(activeMode, false);
          const selected = copy[activeMode] || copy.balanced;
          const minAnimationMs = 1320;
          const remaining = Math.max(0, minAnimationMs - (performance.now() - animationStarted));
          schedule(() => {
            stopProcessingAnimation(true);
            schedule(() => {
              setBusy(false);
              stopProcessingAnimation(false);
            }, 140);
            setMessage(`${selected.title} is active. The change was recorded in Security Logs.`, 'success');
            window.dispatchEvent(new CustomEvent('fortress:defense-profile-changed', {
              detail: { mode: activeMode, label: payload?.data?.label || selected.title.toUpperCase() },
            }));
            schedule(() => window.dispatchEvent(new CustomEvent('fortress:v3-route-refresh')), 450);
          }, remaining);
        } catch (error) {
          const remaining = Math.max(0, 760 - (performance.now() - animationStarted));
          schedule(() => {
            stopProcessingAnimation(false);
            setBusy(false);
            applyGlobalTheme(previousMode, true);
            setMessage(error?.message || 'The defense profile could not be changed.', 'error');
          }, remaining);
        }
      });
    });
  }


  // Tactile micro-interactions for buttons and button-like command controls.
  // Uses the Web Animations API so no inline styles or CSP exceptions are needed.
  const tactileMotionReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!tactileMotionReduced && typeof Element.prototype.animate === 'function') {
    const tactileSelector = [
      'button',
      'input[type="button"]',
      'input[type="submit"]',
      'input[type="reset"]',
      '.icon-action',
      '.logout-mini',
      '.fortress-mobile-refresh',
      '.sidebar-operator-card.operator-management-link',
      '.command-nav-links > a',
      '.operator-workspace-tabs a',
      '.manage-button',
      '.operator-section-back',
      '.user-form-actions a',
      '.user-account-actions a',
      '.delete-confirm-actions a',
      '.report-format-card'
    ].join(',');

    const pressedByPointer = new Map();
    const pressAnimations = new WeakMap();

    const tactileTarget = (node) => {
      if (!(node instanceof Element)) return null;
      const target = node.closest(tactileSelector);
      if (!target) return null;
      if (target.matches(':disabled') || target.getAttribute('aria-disabled') === 'true') return null;
      return target;
    };

    const pressControl = (target) => {
      pressAnimations.get(target)?.cancel();
      const animation = target.animate(
        [
          { scale: '1', filter: 'brightness(1)' },
          { scale: '.98', filter: 'brightness(1.10)' }
        ],
        { duration: 85, easing: 'cubic-bezier(.22,.8,.28,1)', fill: 'forwards' }
      );
      pressAnimations.set(target, animation);

      const icon = target.querySelector?.('i');
      icon?.animate(
        [{ scale: '1' }, { scale: '.88' }],
        { duration: 85, easing: 'ease-out', fill: 'forwards' }
      );
    };

    const releaseControl = (target) => {
      pressAnimations.get(target)?.cancel();
      pressAnimations.delete(target);
      target.animate(
        [
          { scale: '.98', filter: 'brightness(1.10)' },
          { scale: '1.018', filter: 'brightness(1.06)', offset: .48 },
          { scale: '1', filter: 'brightness(1)' }
        ],
        { duration: 245, easing: 'cubic-bezier(.16,1,.3,1)' }
      );

      const icon = target.querySelector?.('i');
      icon?.animate(
        [
          { scale: '.88' },
          { scale: '1.14', offset: .48 },
          { scale: '1' }
        ],
        { duration: 245, easing: 'cubic-bezier(.16,1,.3,1)' }
      );
    };

    listen(document, 'pointerdown', (event) => {
      if (event.button !== undefined && event.button !== 0) return;
      const target = tactileTarget(event.target);
      if (!target) return;
      pressedByPointer.set(event.pointerId, target);
      pressControl(target);
    }, { passive: true });

    const finishPointerPress = (event) => {
      const target = pressedByPointer.get(event.pointerId);
      if (!target) return;
      pressedByPointer.delete(event.pointerId);
      releaseControl(target);
    };
    listen(document, 'pointerup', finishPointerPress, { passive: true });
    listen(document, 'pointercancel', finishPointerPress, { passive: true });

    listen(document, 'keydown', (event) => {
      if (event.repeat || !['Enter', ' '].includes(event.key)) return;
      const target = tactileTarget(event.target);
      if (target) pressControl(target);
    });
    listen(document, 'keyup', (event) => {
      if (!['Enter', ' '].includes(event.key)) return;
      const target = tactileTarget(event.target);
      if (target) releaseControl(target);
    });
  }

  // Premium desktop/mobile AppShell navigation.
  const sidebar = document.querySelector('[data-fortress-sidebar]');
  const overlay = document.querySelector('[data-sidebar-overlay]');
  const toggles = document.querySelectorAll('[data-sidebar-toggle]');
  const closeButtons = document.querySelectorAll('[data-sidebar-close]');

  const setSidebarOpen = (open) => {
    if (!sidebar) return;
    sidebar.classList.toggle('open', open);
    overlay?.classList.toggle('open', open);
    document.body.classList.toggle('fortress-nav-open', open);
    toggles.forEach((button) => button.setAttribute('aria-expanded', open ? 'true' : 'false'));
  };

  toggles.forEach((button) => listen(button, 'click', () => setSidebarOpen(!sidebar?.classList.contains('open'))));
  closeButtons.forEach((button) => listen(button, 'click', () => setSidebarOpen(false)));
  if (overlay) listen(overlay, 'click', () => setSidebarOpen(false));
  sidebar?.querySelectorAll('a').forEach((link) => listen(link, 'click', () => {
    if (window.matchMedia('(max-width: 900px)').matches) setSidebarOpen(false);
  }));
  listen(window, 'keydown', (event) => {
    if (event.key === 'Escape') setSidebarOpen(false);
  });

  // Animated totals.
  document.querySelectorAll('.metric-number[data-count]').forEach((node) => {
    const target = Number.parseInt(node.dataset.count || '0', 10);
    if (!Number.isFinite(target) || target <= 0) return;

    const duration = 650;
    const start = performance.now();
    function frame(now) {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      node.textContent = Math.round(target * eased).toLocaleString();
      if (progress < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  });

  // Pointer-reactive premium card lighting.
  document.querySelectorAll('.panel, .metric-card, .attack-card').forEach((card) => {
    card.addEventListener('pointermove', (event) => {
      const rect = card.getBoundingClientRect();
      card.style.setProperty('--pointer-x', `${event.clientX - rect.left}px`);
      card.style.setProperty('--pointer-y', `${event.clientY - rect.top}px`);
    });
  });

  // Live protected-session duration.
  document.querySelectorAll('.session-duration[data-start]').forEach((node) => {
    const start = Number.parseInt(node.dataset.start || '0', 10) * 1000;
    if (!start) return;
    const updateDuration = () => {
      const total = Math.max(0, Math.floor((Date.now() - start) / 1000));
      const hours = String(Math.floor(total / 3600)).padStart(2, '0');
      const minutes = String(Math.floor((total % 3600) / 60)).padStart(2, '0');
      const seconds = String(total % 60).padStart(2, '0');
      node.textContent = `${hours}:${minutes}:${seconds}`;
    };
    updateDuration();
    trackInterval(updateDuration, 1000);
  });

  // Defense integrity bar.
  document.querySelectorAll('.integrity-track span[data-integrity]').forEach((bar) => {
    const value = Math.max(0, Math.min(100, Number.parseInt(bar.dataset.integrity || '0', 10)));
    requestAnimationFrame(() => { bar.style.width = `${value}%`; });
  });

  // Generic client-side table search/category filtering.
  document.querySelectorAll('[data-table]').forEach((table) => {
    const name = table.dataset.table;
    if (!name) return;
    const search = document.querySelector(`[data-table-search="${name}"]`);
    const category = document.querySelector(`[data-table-category="${name}"]`);
    const rows = Array.from(table.querySelectorAll('tbody tr[data-search]'));

    const applyFilter = () => {
      const query = (search?.value || '').trim().toLowerCase();
      const wantedCategory = (category?.value || 'all').toLowerCase();
      rows.forEach((row) => {
        const haystack = (row.dataset.search || row.textContent || '').toLowerCase();
        const rowCategory = (row.dataset.category || '').toLowerCase();
        row.hidden = !((!query || haystack.includes(query)) && (wantedCategory === 'all' || rowCategory === wantedCategory));
      });
    };

    search?.addEventListener('input', applyFilter);
    category?.addEventListener('change', applyFilter);
  });

  const parseJson = (value, fallback = []) => {
    try { return JSON.parse(value || JSON.stringify(fallback)); } catch (_) { return fallback; }
  };

  const withAlpha = (hex, alpha) => {
    const clean = String(hex || '#ffffff').replace('#', '');
    if (!/^[0-9a-fA-F]{6}$/.test(clean)) return `rgba(255,255,255,${alpha})`;
    const number = Number.parseInt(clean, 16);
    const r = (number >> 16) & 255;
    const g = (number >> 8) & 255;
    const b = number & 255;
    return `rgba(${r},${g},${b},${alpha})`;
  };

  const mixWithWhite = (hex, amount = .28) => {
    const clean = String(hex || '#ffffff').replace('#', '');
    if (!/^[0-9a-fA-F]{6}$/.test(clean)) return '#ffffff';
    const number = Number.parseInt(clean, 16);
    const r = (number >> 16) & 255;
    const g = (number >> 8) & 255;
    const b = number & 255;
    const blend = (channel) => Math.round(channel + (255 - channel) * amount);
    return `rgb(${blend(r)},${blend(g)},${blend(b)})`;
  };

  const mixWithBlack = (hex, amount = .28) => {
    const clean = String(hex || '#ffffff').replace('#', '');
    if (!/^[0-9a-fA-F]{6}$/.test(clean)) return '#08040f';
    const number = Number.parseInt(clean, 16);
    const r = (number >> 16) & 255;
    const g = (number >> 8) & 255;
    const b = number & 255;
    const blend = (channel) => Math.round(channel * (1 - amount));
    return `rgb(${blend(r)},${blend(g)},${blend(b)})`;
  };

  const easeOutCubic = (value) => 1 - Math.pow(1 - Math.max(0, Math.min(1, value)), 3);
  const easeOutBack = (value) => {
    const x = Math.max(0, Math.min(1, value));
    const c1 = 1.70158;
    const c3 = c1 + 1;
    return 1 + c3 * Math.pow(x - 1, 3) + c1 * Math.pow(x - 1, 2);
  };

  const setupCanvas = (canvas, minHeight = 240) => {
    const parent = canvas.parentElement;
    if (!parent) return null;

    // Keep canvas sizing tied to the wrapper's stable content box. Measuring
    // the wrapper's rendered height on every hover frame created a feedback
    // loop where the canvas made its own parent taller after each redraw.
    const styles = window.getComputedStyle(parent);
    const paddingX = (parseFloat(styles.paddingLeft) || 0) + (parseFloat(styles.paddingRight) || 0);
    const paddingY = (parseFloat(styles.paddingTop) || 0) + (parseFloat(styles.paddingBottom) || 0);
    const width = Math.max(300, Math.floor(parent.clientWidth - paddingX));
    const stableParentHeight = parent.clientHeight || minHeight;
    const height = Math.max(minHeight, Math.floor(stableParentHeight - paddingY));
    const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    const targetWidth = Math.floor(width * dpr);
    const targetHeight = Math.floor(height * dpr);

    if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
      canvas.width = targetWidth;
      canvas.height = targetHeight;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) return null;

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    return { ctx, width, height };
  };

  const drawEmpty = (ctx, width, height) => {
    const glow = ctx.createRadialGradient(width / 2, height / 2, 0, width / 2, height / 2, Math.min(width, height) * .38);
    glow.addColorStop(0, 'rgba(180,92,255,.10)');
    glow.addColorStop(1, 'rgba(180,92,255,0)');
    ctx.fillStyle = glow;
    ctx.fillRect(0, 0, width, height);

    ctx.fillStyle = 'rgba(188,174,201,.66)';
    ctx.font = '700 11px Inter, Segoe UI, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No recorded data yet', width / 2, height / 2);
  };

  const drawGlassPlot = (ctx, left, top, graphWidth, graphHeight) => {
    // Reference-inspired recessed chart surface, kept in FortressAuth purple glass.
    ctx.save();
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(left, top, graphWidth, graphHeight, 18);
    else ctx.rect(left, top, graphWidth, graphHeight);

    const panelGradient = ctx.createLinearGradient(0, top, 0, top + graphHeight);
    panelGradient.addColorStop(0, 'rgba(38,16,59,.54)');
    panelGradient.addColorStop(.52, 'rgba(23,9,39,.34)');
    panelGradient.addColorStop(1, 'rgba(11,4,20,.17)');
    ctx.fillStyle = panelGradient;
    ctx.fill();

    ctx.strokeStyle = 'rgba(212,151,255,.08)';
    ctx.lineWidth = 1;
    ctx.stroke();

    ctx.clip();
    const shine = ctx.createLinearGradient(left, top, left + graphWidth, top + graphHeight);
    shine.addColorStop(0, 'rgba(255,255,255,.04)');
    shine.addColorStop(.27, 'rgba(212,151,255,.032)');
    shine.addColorStop(.64, 'rgba(255,255,255,0)');
    shine.addColorStop(1, 'rgba(180,92,255,.026)');
    ctx.fillStyle = shine;
    ctx.fillRect(left, top, graphWidth, graphHeight);
    ctx.restore();
  };

  const drawPerspectiveFloor = (ctx, left, top, graphWidth, graphHeight) => {
    const floorY = top + graphHeight;
    const depth = Math.min(18, graphHeight * .075);

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(left + 3, floorY);
    ctx.lineTo(left + graphWidth - 3, floorY);
    ctx.lineTo(left + graphWidth - 15, floorY + depth);
    ctx.lineTo(left + 15, floorY + depth);
    ctx.closePath();

    const floorGradient = ctx.createLinearGradient(0, floorY, 0, floorY + depth);
    floorGradient.addColorStop(0, 'rgba(180,92,255,.085)');
    floorGradient.addColorStop(.5, 'rgba(180,92,255,.026)');
    floorGradient.addColorStop(1, 'rgba(28,8,45,0)');
    ctx.fillStyle = floorGradient;
    ctx.fill();

    ctx.strokeStyle = 'rgba(212,151,255,.07)';
    ctx.lineWidth = 1;
    for (let i = 1; i < 4; i += 1) {
      const t = i / 4;
      const y = floorY + depth * t;
      const inset = 15 * t;
      ctx.beginPath();
      ctx.moveTo(left + inset, y);
      ctx.lineTo(left + graphWidth - inset, y);
      ctx.stroke();
    }
    ctx.restore();
  };

  const drawTooltip = (canvas, hit, event) => {
    const wrap = canvas.parentElement;
    if (!wrap) return;
    let tooltip = wrap.querySelector('.premium-chart-tooltip');
    if (!(tooltip instanceof HTMLElement)) {
      tooltip = document.createElement('div');
      tooltip.className = 'premium-chart-tooltip';
      tooltip.innerHTML = '<span class="premium-chart-tooltip-kicker"></span><strong></strong><small></small>';
      wrap.appendChild(tooltip);
    }

    if (!hit || !event) {
      tooltip.classList.remove('visible');
      return;
    }

    const wrapRect = wrap.getBoundingClientRect();
    const label = String(hit.label ?? '');
    const seriesLabel = String(hit.seriesLabel ?? hit.kind ?? 'Security data');
    const value = Number.isFinite(Number(hit.value)) ? Number(hit.value).toLocaleString() : String(hit.value ?? '');

    const kicker = tooltip.querySelector('.premium-chart-tooltip-kicker');
    const strong = tooltip.querySelector('strong');
    const small = tooltip.querySelector('small');
    if (kicker) kicker.textContent = seriesLabel;
    if (strong) strong.textContent = label || 'Recorded event';
    if (small) small.textContent = hit.suffix ? `${value}${hit.suffix}` : value;

    const tooltipWidth = Math.min(190, wrapRect.width - 18);
    let left = event.clientX - wrapRect.left + 15;
    let top = event.clientY - wrapRect.top - 18;
    if (left + tooltipWidth > wrapRect.width - 8) left = event.clientX - wrapRect.left - tooltipWidth - 12;
    if (top < 8) top = event.clientY - wrapRect.top + 16;

    tooltip.style.left = `${Math.max(8, left)}px`;
    tooltip.style.top = `${Math.max(8, top)}px`;
    tooltip.classList.add('visible');
  };

  const pointInPieHit = (hit, x, y) => {
    const dx = x - hit.cx;
    const dy = y - hit.cy;
    const distance = Math.sqrt(dx * dx + dy * dy);
    if (distance < hit.innerRadius || distance > hit.outerRadius) return false;
    let angle = Math.atan2(dy, dx);
    if (angle < -Math.PI / 2) angle += Math.PI * 2;
    let start = hit.start;
    let end = hit.end;
    while (start < -Math.PI / 2) { start += Math.PI * 2; end += Math.PI * 2; }
    if (angle < start) angle += Math.PI * 2;
    return angle >= start && angle <= end;
  };

  const findHit = (regions, x, y) => {
    if (!Array.isArray(regions)) return null;

    for (let i = regions.length - 1; i >= 0; i -= 1) {
      const hit = regions[i];
      if (hit.shape === 'circle') {
        const dx = x - hit.x;
        const dy = y - hit.y;
        if (Math.sqrt(dx * dx + dy * dy) <= hit.radius) return hit;
      } else if (hit.shape === 'rect') {
        if (x >= hit.x && x <= hit.x + hit.width && y >= hit.y && y <= hit.y + hit.height) return hit;
      } else if (hit.shape === 'pie' && pointInPieHit(hit, x, y)) {
        return hit;
      }
    }

    return null;
  };

  const drawLine = (canvas, labels, series, options = {}) => {
    const ready = setupCanvas(canvas, options.minHeight || 235);
    if (!ready) return [];
    const { ctx, width, height } = ready;
    if (!labels.length || !series.length) {
      drawEmpty(ctx, width, height);
      return [];
    }

    const progress = easeOutCubic(options.progress ?? 1);
    const hover = options.hover || null;
    const hoverStrength = Math.max(0, Math.min(1, options.hoverStrength ?? 0));
    const left = 48, right = 18, top = 22, bottom = 46;
    const graphWidth = width - left - right;
    const graphHeight = height - top - bottom;
    const maxValue = Math.max(1, ...series.flatMap((item) => item.values || []).map((n) => Number(n) || 0));
    const roundedMax = Math.max(2, Math.ceil(maxValue / 2) * 2);
    const hitRegions = [];

    drawGlassPlot(ctx, left, top, graphWidth, graphHeight);

    ctx.font = '700 9px Inter, Segoe UI, sans-serif';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= 4; i += 1) {
      const y = top + (graphHeight * i) / 4;
      ctx.strokeStyle = i === 4 ? 'rgba(218,177,255,.18)' : 'rgba(204,174,229,.09)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(left, y);
      ctx.lineTo(left + graphWidth, y);
      ctx.stroke();

      ctx.fillStyle = 'rgba(194,176,211,.72)';
      ctx.textAlign = 'right';
      ctx.fillText(String(Math.round(roundedMax * (1 - i / 4))), left - 9, y);
    }

    const count = Math.max(labels.length, 1);
    const xFor = (index) => left + (count <= 1 ? graphWidth / 2 : (graphWidth * index) / (count - 1));
    const yFor = (value) => top + graphHeight - ((Number(value) || 0) / roundedMax) * graphHeight;

    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    labels.forEach((label, index) => {
      const every = labels.length > 14 ? Math.ceil(labels.length / 6) : Math.max(1, Math.ceil(labels.length / 7));
      if (index % every !== 0 && index !== labels.length - 1) return;
      ctx.fillStyle = 'rgba(196,180,210,.74)';
      ctx.fillText(String(label), xFor(index), top + graphHeight + 13);
    });

    const smoothPath = (points) => {
      if (!points.length) return;
      ctx.moveTo(points[0].x, points[0].y);
      for (let i = 1; i < points.length; i += 1) {
        const prev = points[i - 1];
        const current = points[i];
        const midX = (prev.x + current.x) / 2;
        ctx.bezierCurveTo(midX, prev.y, midX, current.y, current.x, current.y);
      }
    };

    series.forEach((spec, specIndex) => {
      const values = spec.values || [];
      if (!values.length) return;
      const color = spec.color || palette[specIndex % palette.length];
      const revealCount = Math.max(1, Math.ceil(values.length * progress));
      const visibleValues = values.slice(0, revealCount);
      const linePoints = visibleValues.map((value, index) => ({
        x: xFor(index),
        y: yFor((Number(value) || 0) * progress),
        value: Number(value) || 0,
      }));
      if (!linePoints.length) return;

      if (specIndex === 0 && linePoints.length > 1) {
        ctx.beginPath();
        smoothPath(linePoints);
        ctx.lineTo(linePoints[linePoints.length - 1].x, top + graphHeight);
        ctx.lineTo(linePoints[0].x, top + graphHeight);
        ctx.closePath();
        const fillGradient = ctx.createLinearGradient(0, top, 0, top + graphHeight);
        fillGradient.addColorStop(0, withAlpha(color, .20));
        fillGradient.addColorStop(.58, withAlpha(color, .055));
        fillGradient.addColorStop(1, withAlpha(color, 0));
        ctx.fillStyle = fillGradient;
        ctx.fill();
      }

      ctx.beginPath();
      smoothPath(linePoints);
      ctx.strokeStyle = color;
      ctx.lineWidth = specIndex === 0 ? 2.7 : 1.9;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.stroke();

      linePoints.forEach((point, index) => {
        const isHovered = hover?.kind === 'line-point' && hover.seriesIndex === specIndex && hover.index === index;
        const radius = isHovered ? 5.2 : (specIndex === 0 ? 3.2 : 2.5);

        if (isHovered) {
          ctx.beginPath();
          ctx.arc(point.x, point.y, radius + 6 * hoverStrength, 0, Math.PI * 2);
          ctx.fillStyle = withAlpha(color, .13);
          ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(point.x, point.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = isHovered ? '#ffffff' : mixWithWhite(color, .16);
        ctx.fill();
        ctx.strokeStyle = color;
        ctx.lineWidth = isHovered ? 2.5 : 1.4;
        ctx.stroke();

        hitRegions.push({
          shape: 'circle',
          kind: 'line-point',
          x: point.x,
          y: point.y,
          radius: 12,
          index,
          seriesIndex: specIndex,
          label: labels[index] ?? `Point ${index + 1}`,
          seriesLabel: spec.label || `Series ${specIndex + 1}`,
          value: point.value,
          color,
        });
      });
    });

    return hitRegions;
  };

  const drawBars = (canvas, labels, series, options = {}) => {
    const ready = setupCanvas(canvas, options.minHeight || 235);
    if (!ready) return [];
    const { ctx, width, height } = ready;
    if (!labels.length || !series.length) {
      drawEmpty(ctx, width, height);
      return [];
    }

    const progress = easeOutCubic(options.progress ?? 1);
    const hover = options.hover || null;
    const left = 46, right = 18, top = 22, bottom = 48;
    const graphWidth = width - left - right;
    const graphHeight = height - top - bottom;
    const maxValue = Math.max(1, ...series.flatMap((item) => item.values || []).map((n) => Number(n) || 0));
    const roundedMax = Math.max(2, Math.ceil(maxValue / 2) * 2);
    const hitRegions = [];

    drawGlassPlot(ctx, left, top, graphWidth, graphHeight);

    ctx.font = '700 9px Inter, Segoe UI, sans-serif';
    for (let i = 0; i <= 4; i += 1) {
      const y = top + graphHeight * i / 4;
      ctx.strokeStyle = i === 4 ? 'rgba(218,177,255,.18)' : 'rgba(204,174,229,.085)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(left, y);
      ctx.lineTo(left + graphWidth, y);
      ctx.stroke();
      ctx.fillStyle = 'rgba(194,176,211,.72)';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(String(Math.round(roundedMax * (1 - i / 4))), left - 8, y);
    }

    const groups = labels.length;
    const groupWidth = graphWidth / Math.max(groups, 1);
    const inner = Math.min(groupWidth * .72, 78);
    const gap = Math.max(3, Math.min(6, groupWidth * .07));
    const barWidth = Math.max(6, Math.min(28, (inner - gap * Math.max(series.length - 1, 0)) / Math.max(series.length, 1)));

    labels.forEach((label, index) => {
      const center = left + groupWidth * index + groupWidth / 2;

      series.forEach((spec, sIndex) => {
        const rawValue = Number(spec.values?.[index]) || 0;
        const animatedValue = rawValue * Math.max(0, progress);
        const barHeight = graphHeight * animatedValue / roundedMax;
        const totalSeriesWidth = series.length * barWidth + Math.max(0, series.length - 1) * gap;
        const x = center - totalSeriesWidth / 2 + sIndex * (barWidth + gap);
        const y = top + graphHeight - barHeight;
        const isHovered = hover?.kind === 'bar' && hover.seriesIndex === sIndex && hover.index === index;
        // When a single-series category chart provides a color per label, use
        // those category colors for each bar. Multi-series charts keep their
        // semantic series colors (Passed, Rejected, Blocked, etc.).
        const color = (series.length === 1 && Array.isArray(options.colors) && options.colors.length)
          ? (options.colors[index % options.colors.length] || spec.color || palette[index % palette.length])
          : (spec.color || palette[sIndex % palette.length]);
        const renderedHeight = Math.max(3, barHeight);
        const radius = Math.min(barWidth / 2, 7);

        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(x, y, barWidth, renderedHeight, radius);
        else ctx.rect(x, y, barWidth, renderedHeight);
        const gradient = ctx.createLinearGradient(0, y, 0, top + graphHeight);
        gradient.addColorStop(0, isHovered ? mixWithWhite(color, .26) : mixWithWhite(color, .12));
        gradient.addColorStop(1, withAlpha(color, isHovered ? .90 : .68));
        ctx.fillStyle = gradient;
        ctx.fill();

        if (isHovered) {
          ctx.strokeStyle = mixWithWhite(color, .30);
          ctx.lineWidth = 1.5;
          ctx.stroke();
          if (rawValue > 0) {
            ctx.fillStyle = 'rgba(247,238,255,.96)';
            ctx.font = '900 9px Inter, Segoe UI, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'bottom';
            ctx.fillText(rawValue.toLocaleString(), x + barWidth / 2, Math.max(top + 10, y - 6));
          }
        }

        hitRegions.push({
          shape: 'rect',
          kind: 'bar',
          x: x - 3,
          y: y - 5,
          width: barWidth + 6,
          height: renderedHeight + 10,
          index,
          seriesIndex: sIndex,
          label: labels[index] ?? `Bar ${index + 1}`,
          seriesLabel: spec.label || `Series ${sIndex + 1}`,
          value: rawValue,
          color,
        });
      });

      const chartTitle = String(canvas.dataset.chartTitle || '');
      const mobileCategoryLabels = {
        Authentication: 'Auth',
        Identity: 'ID',
        Network: 'Net',
        Threat: 'Threat',
        Session: 'Session',
        System: 'System',
        Accounts: 'Acct',
        Configuration: 'Config',
        Documentation: 'Docs',
      };
      const displayLabel = (width < 540 && chartTitle === 'Security Event Volume')
        ? (mobileCategoryLabels[String(label)] || String(label).slice(0, 7))
        : String(label);

      ctx.fillStyle = 'rgba(196,180,210,.74)';
      ctx.font = '800 8px Inter, Segoe UI, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(displayLabel, center, top + graphHeight + 14);
    });

    return hitRegions;
  };

  const drawPieLike = (canvas, labels, values, options = {}) => {
    const ready = setupCanvas(canvas, options.minHeight || 230);
    if (!ready) return [];
    const { ctx, width, height } = ready;
    const nums = values.map((value) => Math.max(0, Number(value) || 0));
    const total = nums.reduce((sum, value) => sum + value, 0);
    if (!total) {
      drawEmpty(ctx, width, height);
      return [];
    }

    const progress = easeOutCubic(options.progress ?? 1);
    const hover = options.hover || null;
    const colors = options.colors || palette;
    const cx = width / 2;
    const cy = height / 2 - 3;
    const radius = Math.min(width, height) * (options.donut ? .32 : .34);
    const donutWidth = Math.max(20, radius * .28);
    const hitRegions = [];
    let angle = -Math.PI / 2;

    nums.forEach((value, index) => {
      const fullSweep = (value / total) * Math.PI * 2;
      const sweep = fullSweep * progress;
      const start = angle;
      const end = angle + sweep;
      const color = colors[index % colors.length] || palette[index % palette.length];
      const isHovered = hover?.kind === 'pie-slice' && hover.index === index;
      const mid = start + sweep / 2;
      const offset = isHovered ? 4 : 0;
      const ox = Math.cos(mid) * offset;
      const oy = Math.sin(mid) * offset;

      ctx.beginPath();
      if (options.donut) {
        ctx.arc(cx + ox, cy + oy, radius, start, end);
        ctx.strokeStyle = color;
        ctx.lineWidth = donutWidth + (isHovered ? 3 : 0);
        ctx.lineCap = 'butt';
        ctx.stroke();
      } else {
        ctx.moveTo(cx + ox, cy + oy);
        ctx.arc(cx + ox, cy + oy, radius + (isHovered ? 3 : 0), start, end);
        ctx.closePath();
        ctx.fillStyle = isHovered ? mixWithWhite(color, .16) : color;
        ctx.fill();
      }

      hitRegions.push({
        shape: 'pie',
        kind: 'pie-slice',
        cx: cx + ox,
        cy: cy + oy,
        innerRadius: options.donut ? radius - donutWidth / 2 - 5 : 0,
        outerRadius: options.donut ? radius + donutWidth / 2 + 6 : radius + 5,
        start,
        end,
        index,
        label: labels[index] ?? `Slice ${index + 1}`,
        seriesLabel: options.donut ? 'Outcome distribution' : 'Security category',
        value,
        suffix: total > 0 ? ` · ${Math.round((value / total) * 100)}%` : '',
        color,
      });

      angle += fullSweep;
    });

    if (options.donut) {
      ctx.fillStyle = 'rgba(15,7,26,.94)';
      ctx.beginPath();
      ctx.arc(cx, cy, radius - donutWidth / 2 - 2, 0, Math.PI * 2);
      ctx.fill();

      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#ffffff';
      ctx.font = '900 26px Inter, Segoe UI, sans-serif';
      ctx.fillText(String(options.centerValue ?? total), cx, cy - 5);
      ctx.fillStyle = 'rgba(188,171,202,.72)';
      ctx.font = '900 8px Inter, Segoe UI, sans-serif';
      ctx.fillText(String(options.centerLabel || 'TOTAL EVENTS').toUpperCase(), cx, cy + 18);
    }

    return hitRegions;
  };

  // Segmented flat donut inspired by the reference dashboard: chunky separated
  // annular pieces, subtle purple glow, and a gentle hover "explode" interaction.
  // The angular size remains data-proportional; offsets are decorative only.
  const drawSegmentedDonut = (canvas, labels, values, options = {}) => {
    const ready = setupCanvas(canvas, options.minHeight || 230);
    if (!ready) return [];
    const { ctx, width, height } = ready;
    const nums = values.map((value) => Math.max(0, Number(value) || 0));
    const total = nums.reduce((sum, value) => sum + value, 0);
    if (!total) {
      drawEmpty(ctx, width, height);
      return [];
    }

    const progress = easeOutCubic(options.progress ?? 1);
    const hover = options.hover || null;
    const colors = options.colors || palette;
    const cx = width / 2;
    const cy = height / 2 - 2;
    const outerRadius = Math.min(width, height) * .34;
    const innerRadius = outerRadius * .54;
    const activeCount = Math.max(1, nums.filter((value) => value > 0).length);
    const gap = activeCount > 1 ? Math.min(.055, (Math.PI * 2) / activeCount * .11) : 0;
    const hitRegions = [];
    const decorativeOffsets = [4, 2, 5, 2, 4, 3];
    let angle = -Math.PI * .72;

    // Faint full ring behind the data, similar to the recessed track in the reference.
    ctx.beginPath();
    ctx.arc(cx, cy, (outerRadius + innerRadius) / 2, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(205, 161, 239, .075)';
    ctx.lineWidth = outerRadius - innerRadius;
    ctx.stroke();

    nums.forEach((value, index) => {
      const fullSweep = (value / total) * Math.PI * 2;
      if (fullSweep <= 0) {
        angle += fullSweep;
        return;
      }

      const animatedSweep = fullSweep * progress;
      const halfGap = Math.min(gap / 2, animatedSweep * .18);
      const start = angle + halfGap;
      const end = angle + Math.max(halfGap, animatedSweep - halfGap);
      const mid = angle + animatedSweep / 2;
      const color = colors[index % colors.length] || palette[index % palette.length];
      const isHovered = hover?.kind === 'donut-segment' && hover.index === index;
      const baseOffset = decorativeOffsets[index % decorativeOffsets.length];
      const offset = baseOffset + (isHovered ? 7 : 0);
      const ox = Math.cos(mid) * offset;
      const oy = Math.sin(mid) * offset;
      const segCx = cx + ox;
      const segCy = cy + oy;

      if (end > start) {
        ctx.save();
        ctx.shadowColor = withAlpha(color, isHovered ? .36 : .16);
        ctx.shadowBlur = isHovered ? 18 : 9;

        // True annular sector so each chunk has the block-like donut silhouette
        // shown in the reference instead of looking like a stroked circular line.
        ctx.beginPath();
        ctx.arc(segCx, segCy, outerRadius + (isHovered ? 2 : 0), start, end);
        ctx.arc(segCx, segCy, innerRadius, end, start, true);
        ctx.closePath();

        const gx1 = segCx + Math.cos(mid + Math.PI) * outerRadius;
        const gy1 = segCy + Math.sin(mid + Math.PI) * outerRadius;
        const gx2 = segCx + Math.cos(mid) * outerRadius;
        const gy2 = segCy + Math.sin(mid) * outerRadius;
        const gradient = ctx.createLinearGradient(gx1, gy1, gx2, gy2);
        gradient.addColorStop(0, mixWithWhite(color, .02));
        gradient.addColorStop(.52, color);
        gradient.addColorStop(1, mixWithWhite(color, isHovered ? .28 : .16));
        ctx.fillStyle = gradient;
        ctx.fill();

        // Soft polished rim, still flat rather than 3D/extruded.
        ctx.strokeStyle = withAlpha(mixWithWhite(color, .42), isHovered ? .62 : .34);
        ctx.lineWidth = isHovered ? 1.6 : 1;
        ctx.stroke();
        ctx.restore();

        // Small inner highlight follows the chunky segmented reference style.
        ctx.save();
        ctx.beginPath();
        ctx.arc(segCx, segCy, innerRadius + 2, start + .012, Math.max(start + .012, end - .012));
        ctx.strokeStyle = 'rgba(255,255,255,.10)';
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.restore();
      }

      hitRegions.push({
        shape: 'pie',
        kind: 'donut-segment',
        cx: segCx,
        cy: segCy,
        innerRadius: innerRadius - 5,
        outerRadius: outerRadius + 10,
        start,
        end,
        index,
        label: labels[index] ?? `Outcome ${index + 1}`,
        seriesLabel: 'Outcome distribution',
        value,
        suffix: total > 0 ? ` · ${Math.round((value / total) * 100)}%` : '',
        color,
      });

      angle += fullSweep;
    });

    // Clean dark center with a faint purple rim. This keeps your useful total while
    // preserving the open-hole appearance of the reference donut.
    ctx.beginPath();
    ctx.arc(cx, cy, innerRadius - 7, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(10,4,18,.97)';
    ctx.fill();
    ctx.strokeStyle = 'rgba(216, 174, 250, .11)';
    ctx.lineWidth = 1;
    ctx.stroke();

    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#ffffff';
    ctx.font = '900 24px Inter, Segoe UI, sans-serif';
    ctx.fillText(String(options.centerValue ?? total), cx, cy - 4);
    ctx.fillStyle = 'rgba(190,170,204,.72)';
    ctx.font = '900 7px Inter, Segoe UI, sans-serif';
    ctx.fillText(String(options.centerLabel || 'TOTAL EVENTS').toUpperCase(), cx, cy + 16);

    return hitRegions;
  };

  const drawRadar = (canvas, labels, series, options = {}) => {
    const ready = setupCanvas(canvas, options.minHeight || 240);
    if (!ready) return [];
    const { ctx, width, height } = ready;
    if (!labels.length || !series.length) {
      drawEmpty(ctx, width, height);
      return [];
    }

    const progress = easeOutCubic(options.progress ?? 1);
    const hover = options.hover || null;
    const cx = width / 2;
    const cy = height / 2 + 5;
    const radius = Math.min(width, height) * .31;
    const count = labels.length;
    const max = 100;
    const hitRegions = [];

    const point = (index, value = 1) => {
      const angle = -Math.PI / 2 + index * Math.PI * 2 / count;
      return [cx + Math.cos(angle) * radius * value, cy + Math.sin(angle) * radius * value];
    };

    for (let ring = 1; ring <= 5; ring += 1) {
      ctx.beginPath();
      for (let i = 0; i < count; i += 1) {
        const [x, y] = point(i, ring / 5);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.strokeStyle = ring === 5 ? 'rgba(218,177,255,.26)' : 'rgba(198,159,229,.13)';
      ctx.lineWidth = ring === 5 ? 1.2 : 1;
      ctx.stroke();
    }

    for (let i = 0; i < count; i += 1) {
      const [x, y] = point(i, 1);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(x, y);
      ctx.strokeStyle = 'rgba(205,164,236,.12)';
      ctx.stroke();

      const [lx, ly] = [cx + (x - cx) * 1.18, cy + (y - cy) * 1.18];
      ctx.fillStyle = 'rgba(216,199,229,.82)';
      ctx.font = '800 8px Inter, Segoe UI, sans-serif';
      ctx.textAlign = lx < cx - 8 ? 'right' : lx > cx + 8 ? 'left' : 'center';
      ctx.textBaseline = ly < cy ? 'bottom' : 'top';
      ctx.fillText(String(labels[i]), lx, ly);
    }

    series.forEach((spec, sIndex) => {
      const values = spec.values || [];
      const color = spec.color || palette[sIndex % palette.length];
      const points = values.map((value, index) => point(index, Math.max(0, Number(value) || 0) / max * progress));

      ctx.beginPath();
      points.forEach(([x, y], index) => {
        if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.closePath();
      ctx.fillStyle = withAlpha(color, .16);
      ctx.fill();
      ctx.strokeStyle = mixWithWhite(color, .12);
      ctx.lineWidth = 2;
      ctx.stroke();

      points.forEach(([x, y], index) => {
        const isHovered = hover?.kind === 'radar-point' && hover.seriesIndex === sIndex && hover.index === index;
        const nodeRadius = isHovered ? 5.2 : 3.2;
        if (isHovered) {
          ctx.beginPath();
          ctx.arc(x, y, nodeRadius + 6, 0, Math.PI * 2);
          ctx.fillStyle = withAlpha(color, .13);
          ctx.fill();
        }
        ctx.beginPath();
        ctx.arc(x, y, nodeRadius, 0, Math.PI * 2);
        ctx.fillStyle = isHovered ? '#ffffff' : mixWithWhite(color, .15);
        ctx.fill();
        ctx.strokeStyle = color;
        ctx.lineWidth = isHovered ? 2.4 : 1.3;
        ctx.stroke();

        hitRegions.push({
          shape: 'circle',
          kind: 'radar-point',
          x,
          y,
          radius: 13,
          index,
          seriesIndex: sIndex,
          label: labels[index] ?? `Axis ${index + 1}`,
          seriesLabel: spec.label || 'Relative pressure',
          value: Number(values[index]) || 0,
          suffix: '/100',
          color,
        });
      });
    });

    return hitRegions;
  };

  const drawSpiral = (canvas, labels, values, options = {}) => {
    const ready = setupCanvas(canvas, options.minHeight || 240);
    if (!ready) return [];
    const { ctx, width, height } = ready;
    const nums = values.map((value) => Math.max(0, Number(value) || 0));
    const maxValue = Math.max(1, ...nums);
    if (!nums.some((value) => value > 0)) {
      drawEmpty(ctx, width, height);
      return [];
    }

    const progress = easeOutCubic(options.progress ?? 1);
    const hover = options.hover || null;
    const colors = options.colors || palette;
    const compact = width < 480;
    const cx = compact ? width / 2 : width * .36;
    const cy = compact ? height * .45 : height / 2;
    const outerRadius = Math.min(height * (compact ? .30 : .37), width * (compact ? .30 : .25));
    const count = nums.length;
    const gap = Math.max(3, Math.min(5, outerRadius * .045));
    const ringWidth = Math.max(6, Math.min(11, (outerRadius - 24 - gap * Math.max(0, count - 1)) / Math.max(1, count)));
    const startAngle = -Math.PI * .82;
    const fullSweep = Math.PI * 1.66;
    const hitRegions = [];

    nums.forEach((value, index) => {
      const radius = outerRadius - index * (ringWidth + gap);
      if (radius <= ringWidth) return;
      const color = colors[index % colors.length] || palette[index % palette.length];
      const isHovered = hover?.kind === 'spiral-ring' && hover.index === index;
      const sweep = fullSweep * (value / maxValue) * progress;
      const endAngle = startAngle + sweep;

      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, startAngle + fullSweep);
      ctx.strokeStyle = 'rgba(205,175,226,.095)';
      ctx.lineWidth = ringWidth;
      ctx.lineCap = 'round';
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, endAngle);
      ctx.strokeStyle = isHovered ? mixWithWhite(color, .22) : color;
      ctx.lineWidth = ringWidth + (isHovered ? 3 : 0);
      ctx.lineCap = 'round';
      ctx.stroke();

      const ex = cx + Math.cos(endAngle) * radius;
      const ey = cy + Math.sin(endAngle) * radius;
      ctx.beginPath();
      ctx.arc(ex, ey, isHovered ? 4.2 : 2.7, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.fill();

      hitRegions.push({
        shape: 'pie',
        kind: 'spiral-ring',
        cx,
        cy,
        innerRadius: radius - ringWidth / 2 - 5,
        outerRadius: radius + ringWidth / 2 + 5,
        start: startAngle,
        end: startAngle + fullSweep,
        index,
        label: labels[index] ?? `Category ${index + 1}`,
        seriesLabel: 'Security category',
        value,
        suffix: ` · ${Math.round((value / maxValue) * 100)}% of peak`,
        color,
      });
    });

    if (!compact) {
      const legendX = width * .69;
      const startY = Math.max(28, cy - Math.min(82, count * 14));
      labels.forEach((label, index) => {
        const color = colors[index % colors.length] || palette[index % palette.length];
        const y = startY + index * 27;
        const isHovered = hover?.kind === 'spiral-ring' && hover.index === index;
        ctx.beginPath();
        ctx.arc(legendX, y, isHovered ? 4.5 : 3.5, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.fillStyle = isHovered ? '#ffffff' : 'rgba(218,202,231,.86)';
        ctx.font = `${isHovered ? 900 : 800} 9px Inter, Segoe UI, sans-serif`;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillText(String(label), legendX + 10, y - 4);
        ctx.fillStyle = 'rgba(167,147,182,.76)';
        ctx.font = '800 8px Inter, Segoe UI, sans-serif';
        ctx.fillText(`${nums[index].toLocaleString()} events`, legendX + 10, y + 7);
      });
    }

    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#ffffff';
    ctx.font = '900 20px Inter, Segoe UI, sans-serif';
    ctx.fillText(String(nums.reduce((sum, value) => sum + value, 0)), cx, cy - 3);
    ctx.fillStyle = 'rgba(181,163,194,.70)';
    ctx.font = '900 7px Inter, Segoe UI, sans-serif';
    ctx.fillText('CATEGORY EVENTS', cx, cy + 14);

    return hitRegions;
  };

  const registerPremiumChart = (canvas, renderer, options = {}) => {
    const wrap = canvas.parentElement;
    if (!wrap) return;

    wrap.classList.remove('premium-3d-chart');
    wrap.classList.add('interactive-flat-chart');
    canvas.setAttribute('tabindex', '0');

    const state = {
      progress: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 1 : 0,
      hover: null,
      hoverTarget: 0,
      hoverStrength: 0,
      regions: [],
    };

    let frameId = null;
    let startTime = performance.now();
    let resizeTimer = null;
    const duration = options.duration || 820;

    const requestDraw = () => {
      if (frameId !== null) return;
      frameId = window.requestAnimationFrame(renderFrame);
    };

    const renderFrame = (now) => {
      frameId = null;
      if (state.progress < 1) state.progress = Math.min(1, (now - startTime) / duration);

      const delta = state.hoverTarget - state.hoverStrength;
      if (Math.abs(delta) > .015) state.hoverStrength += delta * .2;
      else state.hoverStrength = state.hoverTarget;

      state.regions = renderer({
        progress: state.progress,
        hover: state.hover,
        hoverStrength: state.hoverStrength,
      }) || [];

      if (state.progress < 1 || Math.abs(state.hoverTarget - state.hoverStrength) > .015) requestDraw();
    };

    const hitFromPointer = (event) => {
      const rect = canvas.getBoundingClientRect();
      if (!rect.width || !rect.height) return null;
      const x = (event.clientX - rect.left) * (canvas.clientWidth / rect.width);
      const y = (event.clientY - rect.top) * (canvas.clientHeight / rect.height);
      return findHit(state.regions, x, y);
    };

    canvas.addEventListener('pointermove', (event) => {
      const rect = wrap.getBoundingClientRect();
      const nx = rect.width ? Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width)) : .5;
      const ny = rect.height ? Math.max(0, Math.min(1, (event.clientY - rect.top) / rect.height)) : .5;
      wrap.style.setProperty('--chart-glow-x', `${(nx * 100).toFixed(1)}%`);
      wrap.style.setProperty('--chart-glow-y', `${(ny * 100).toFixed(1)}%`);

      const nextHover = hitFromPointer(event);
      const sameHit = nextHover && state.hover && nextHover.kind === state.hover.kind && nextHover.index === state.hover.index && nextHover.seriesIndex === state.hover.seriesIndex;
      if (!sameHit) {
        state.hover = nextHover;
        state.hoverTarget = nextHover ? 1 : 0;
      }

      wrap.classList.toggle('is-interacting', Boolean(nextHover));
      canvas.style.cursor = nextHover ? 'pointer' : 'default';
      drawTooltip(canvas, nextHover, event);
      requestDraw();
    });

    canvas.addEventListener('pointerleave', () => {
      state.hover = null;
      state.hoverTarget = 0;
      wrap.classList.remove('is-interacting');
      wrap.style.setProperty('--chart-glow-x', '50%');
      wrap.style.setProperty('--chart-glow-y', '45%');
      canvas.style.cursor = 'default';
      drawTooltip(canvas, null, null);
      requestDraw();
    });

    canvas.addEventListener('focus', () => wrap.classList.add('is-keyboard-focused'));
    canvas.addEventListener('blur', () => wrap.classList.remove('is-keyboard-focused'));

    const handleResize = () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        startTime = performance.now() - duration;
        state.progress = 1;
        requestDraw();
      }, 120);
    };
    listen(window, 'resize', handleResize);
    lifecycle.cleanups.push(() => window.clearTimeout(resizeTimer));

    requestDraw();
  };


  // Existing authentication activity chart, rendered in the same flat interactive style.
  const authChart = document.getElementById('authActivityChart');
  if (authChart instanceof HTMLCanvasElement) {
    const labels = parseJson(authChart.dataset.labels, []);
    const series = [
      { label: 'Password passed', values: parseJson(authChart.dataset.success, []), color: '#61f7bd' },
      { label: 'Password rejected', values: parseJson(authChart.dataset.failed, []), color: '#ff6c93' },
      { label: 'Personal ID passed', values: parseJson(authChart.dataset.school, []), color: '#d497ff' },
      { label: 'Defense rejection', values: parseJson(authChart.dataset.blocked, []), color: '#ffc86a' },
    ];

    registerPremiumChart(
      authChart,
      (state) => drawLine(authChart, labels, series, { minHeight: 220, ...state }),
      { duration: 880 }
    );
  }

  // Flat interactive analytics charts.
  document.querySelectorAll('canvas[data-security-chart]').forEach((canvas) => {
    if (!(canvas instanceof HTMLCanvasElement)) return;

    const type = canvas.dataset.securityChart || 'line';
    const labels = parseJson(canvas.dataset.labels, []);
    const series = parseJson(canvas.dataset.series, []);
    const values = parseJson(canvas.dataset.values, []);
    const colors = parseJson(canvas.dataset.colors, palette);

    series.forEach((spec, index) => {
      if (!spec.color) spec.color = colors[index % colors.length] || palette[index % palette.length];
    });

    const render = (state) => {
      if (type === 'bar') {
        return drawBars(canvas, labels, series, { colors, minHeight: 230, ...state });
      }
      if (type === 'pie') {
        return drawPieLike(canvas, labels, values, { colors, minHeight: 230, ...state });
      }
      if (type === 'donut') {
        return drawSegmentedDonut(canvas, labels, values, {
          colors,
          centerValue: canvas.dataset.centerValue,
          centerLabel: canvas.dataset.centerLabel,
          minHeight: 230,
          ...state,
        });
      }
      if (type === 'radar') {
        return drawRadar(canvas, labels, series, { minHeight: 245, ...state });
      }
      if (type === 'spiral') {
        return drawSpiral(canvas, labels, values, { colors, minHeight: 245, ...state });
      }

      return drawLine(canvas, labels, series, { minHeight: 235, ...state });
    };

    registerPremiumChart(canvas, render, {
      duration: type === 'bar' ? 900 : type === 'pie' || type === 'donut' || type === 'spiral' ? 860 : 820,
    });
  });
  };

  window.FortressDashboard = { init, destroy };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
