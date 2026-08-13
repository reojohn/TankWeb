(() => {
  'use strict';

  const timeoutIds = new Set();
  const intervalIds = new Set();

  const later = (callback, delay) => {
    const id = window.setTimeout(() => {
      timeoutIds.delete(id);
      callback();
    }, delay);
    timeoutIds.add(id);
    return id;
  };

  const repeat = (callback, delay) => {
    const id = window.setInterval(callback, delay);
    intervalIds.add(id);
    return id;
  };

  const destroy = () => {
    timeoutIds.forEach((id) => window.clearTimeout(id));
    intervalIds.forEach((id) => window.clearInterval(id));
    timeoutIds.clear();
    intervalIds.clear();
  };

  const reduceMotion = () =>
    Boolean(
      window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    );

  /* =========================================================
     AUTONOMOUS DEFENSE AGENT MESH — REAL PROCESSING ANIMATION
     Targets the exact .ai-agent-scene markup in ai_threat_intelligence.php.
     ========================================================= */

  const ensureAgentMeshStyles = () => {
    if (document.getElementById('fortress-agent-mesh-processing-css')) return;

    const style = document.createElement('style');
    style.id = 'fortress-agent-mesh-processing-css';
    style.textContent = `
      /* Disable the old decorative packet pulse when the real processor is active. */
      .ai-agent-scene.fa-agent-processing-enabled > .ai-packet {
        animation: none !important;
        opacity: 0 !important;
      }

      .ai-agent-scene.fa-agent-processing-enabled .ai-agent-node {
        position: absolute;
        isolation: isolate;
        overflow: hidden;
        transition:
          border-color .25s ease,
          background .25s ease,
          box-shadow .25s ease,
          filter .25s ease,
          transform .25s ease !important;
      }

      .fa-agent-node-scan {
        position: absolute;
        z-index: 30;
        left: 7px;
        right: 7px;
        top: 7px;
        height: 2px;
        border-radius: 999px;
        opacity: 0;
        pointer-events: none;
        background: linear-gradient(
          90deg,
          transparent 0%,
          rgba(97,247,189,.16) 8%,
          rgba(97,247,189,1) 46%,
          rgba(212,151,255,.86) 72%,
          transparent 100%
        );
        box-shadow:
          0 0 7px rgba(97,247,189,.92),
          0 0 16px rgba(97,247,189,.34);
      }

      .fa-agent-node-progress {
        position: absolute;
        z-index: 31;
        left: 8px;
        right: 8px;
        bottom: 6px;
        height: 3px;
        overflow: hidden;
        border-radius: 999px;
        opacity: 0;
        pointer-events: none;
        background: rgba(255,255,255,.055);
      }

      .fa-agent-node-progress > i {
        display: block;
        width: 0;
        height: 100%;
        border-radius: inherit;
        background: linear-gradient(90deg,#61f7bd 0%,#8cf6d4 52%,#d497ff 100%);
        box-shadow:
          0 0 7px rgba(97,247,189,.78),
          0 0 13px rgba(180,92,255,.28);
      }

      .fa-agent-node-state {
        position: absolute;
        z-index: 34;
        top: 7px;
        right: 7px;
        min-height: 18px;
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 0 6px;
        border: 1px solid rgba(205,159,255,.12);
        border-radius: 999px;
        background: rgba(10,4,18,.82);
        color: #7f7189;
        font-size: 8px;
        font-weight: 900;
        line-height: 1;
        letter-spacing: .08em;
        text-transform: uppercase;
        pointer-events: none;
        backdrop-filter: blur(7px);
      }

      .fa-agent-node-state::before {
        content: "";
        width: 4px;
        height: 4px;
        flex: 0 0 4px;
        border-radius: 50%;
        background: #665a70;
      }

      .ai-agent-node.fa-agent-queued {
        filter: brightness(.77) saturate(.72);
        opacity: .78;
      }

      .ai-agent-node.fa-agent-processing {
        opacity: 1;
        transform: translateY(-2px) scale(1.018) !important;
        border-color: rgba(97,247,189,.46) !important;
        background:
          radial-gradient(circle at 50% 18%,rgba(97,247,189,.095),transparent 56%),
          linear-gradient(145deg,rgba(32,18,45,.96),rgba(17,9,29,.98)) !important;
        box-shadow:
          inset 0 0 24px rgba(97,247,189,.045),
          0 0 0 1px rgba(97,247,189,.035),
          0 0 23px rgba(97,247,189,.13) !important;
        filter: brightness(1.10) saturate(1.10);
      }

      .ai-agent-node.fa-agent-processing .fa-agent-node-scan {
        animation: fortressAgentNodeScan 1.28s cubic-bezier(.22,.75,.23,1) infinite;
      }

      .ai-agent-node.fa-agent-processing .fa-agent-node-progress {
        opacity: 1;
      }

      .ai-agent-node.fa-agent-processing .fa-agent-node-progress > i {
        animation: fortressAgentNodeProgress 1.45s linear both;
      }

      .ai-agent-node.fa-agent-processing .fa-agent-node-state {
        color: #caffea;
        border-color: rgba(97,247,189,.24);
        background: rgba(8,31,25,.82);
      }

      .ai-agent-node.fa-agent-processing .fa-agent-node-state::before {
        background: #61f7bd;
        box-shadow:
          0 0 4px rgba(97,247,189,.95),
          0 0 9px rgba(97,247,189,.52);
        animation: fortressAgentStateBlink .42s steps(2,end) infinite;
      }

      .ai-agent-node.fa-agent-complete {
        opacity: 1;
        border-color: rgba(97,247,189,.20) !important;
        box-shadow:
          inset 0 0 17px rgba(97,247,189,.025),
          0 0 12px rgba(97,247,189,.05) !important;
        filter: brightness(1.02) saturate(1);
      }

      .ai-agent-node.fa-agent-complete .fa-agent-node-state {
        color: #aeeed3;
        border-color: rgba(97,247,189,.16);
        background: rgba(97,247,189,.045);
      }

      .ai-agent-node.fa-agent-complete .fa-agent-node-state::before {
        background: #61f7bd;
        box-shadow: 0 0 6px rgba(97,247,189,.38);
      }

      /* The Core has a stronger purple fusion treatment. */
      .ai-agent-node-core.fa-agent-processing {
        border-color: rgba(212,151,255,.50) !important;
        background:
          radial-gradient(circle at 50% 40%,rgba(180,92,255,.18),transparent 58%),
          linear-gradient(145deg,rgba(45,19,65,.97),rgba(19,8,34,.99)) !important;
        box-shadow:
          inset 0 0 31px rgba(180,92,255,.09),
          0 0 0 1px rgba(212,151,255,.045),
          0 0 32px rgba(180,92,255,.20) !important;
      }

      .ai-agent-node-core.fa-agent-processing .fa-agent-node-scan {
        background: linear-gradient(
          90deg,
          transparent,
          rgba(212,151,255,.22),
          rgba(212,151,255,1),
          rgba(97,247,189,.72),
          transparent
        );
        box-shadow:
          0 0 8px rgba(212,151,255,.92),
          0 0 18px rgba(180,92,255,.42);
      }

      .ai-agent-node-core.fa-agent-processing .fa-agent-node-progress > i {
        background: linear-gradient(90deg,#b45cff,#d497ff 58%,#61f7bd);
        box-shadow:
          0 0 8px rgba(212,151,255,.82),
          0 0 15px rgba(180,92,255,.38);
      }

      .ai-agent-node-core.fa-agent-processing .fa-agent-node-state {
        color: #f0d8ff;
        border-color: rgba(212,151,255,.26);
        background: rgba(63,24,91,.78);
      }

      /* Connector lanes */
      .ai-agent-scene.fa-agent-processing-enabled .ai-agent-link {
        position: absolute !important;
        overflow: visible !important;
        transition:
          filter .2s ease,
          opacity .2s ease,
          background .2s ease !important;
      }

      .ai-agent-link.fa-agent-link-active {
        opacity: 1 !important;
        filter:
          drop-shadow(0 0 4px rgba(97,247,189,.82))
          drop-shadow(0 0 9px rgba(180,92,255,.25));
      }

      .fa-agent-signal-packet {
        position: absolute;
        z-index: 50;
        width: 7px;
        height: 7px;
        border-radius: 50%;
        opacity: 0;
        pointer-events: none;
        background: #e6fff5;
        box-shadow:
          0 0 4px #61f7bd,
          0 0 10px rgba(97,247,189,.98),
          0 0 18px rgba(180,92,255,.52);
      }

      /* Telemetry -> Core */
      .ai-agent-link-top .fa-agent-signal-packet {
        left: 50%;
        top: 0;
        margin-left: -3.5px;
      }

      .ai-agent-link-top.fa-agent-transfer-in .fa-agent-signal-packet {
        animation: fortressPacketTopIn .62s cubic-bezier(.2,.72,.2,1) both;
      }

      .ai-agent-link-top.fa-agent-transfer-out .fa-agent-signal-packet {
        animation: fortressPacketTopOut .62s cubic-bezier(.2,.72,.2,1) both;
      }

      /* XGBoost <-> Core */
      .ai-agent-link-left .fa-agent-signal-packet {
        left: 0;
        top: 50%;
        margin-top: -3.5px;
      }

      .ai-agent-link-left.fa-agent-transfer-in .fa-agent-signal-packet {
        animation: fortressPacketLeftIn .62s cubic-bezier(.2,.72,.2,1) both;
      }

      .ai-agent-link-left.fa-agent-transfer-out .fa-agent-signal-packet {
        animation: fortressPacketLeftOut .62s cubic-bezier(.2,.72,.2,1) both;
      }

      /* Anomaly <-> Core */
      .ai-agent-link-right .fa-agent-signal-packet {
        right: 0;
        top: 50%;
        margin-top: -3.5px;
      }

      .ai-agent-link-right.fa-agent-transfer-in .fa-agent-signal-packet {
        animation: fortressPacketRightIn .62s cubic-bezier(.2,.72,.2,1) both;
      }

      .ai-agent-link-right.fa-agent-transfer-out .fa-agent-signal-packet {
        animation: fortressPacketRightOut .62s cubic-bezier(.2,.72,.2,1) both;
      }

      /* Rule Agent <-> Core */
      .ai-agent-link-bottom .fa-agent-signal-packet {
        left: 50%;
        bottom: 0;
        margin-left: -3.5px;
      }

      .ai-agent-link-bottom.fa-agent-transfer-in .fa-agent-signal-packet {
        animation: fortressPacketBottomIn .62s cubic-bezier(.2,.72,.2,1) both;
      }

      .ai-agent-link-bottom.fa-agent-transfer-out .fa-agent-signal-packet {
        animation: fortressPacketBottomOut .62s cubic-bezier(.2,.72,.2,1) both;
      }

      /* Core fusion ring */
      .ai-agent-scene.fa-agent-core-fusing .ai-agent-orbit-one,
      .ai-agent-scene.fa-agent-core-fusing .ai-agent-orbit-two {
        border-color: rgba(212,151,255,.30) !important;
        box-shadow:
          0 0 18px rgba(180,92,255,.11),
          inset 0 0 18px rgba(180,92,255,.055);
      }

      .ai-agent-scene.fa-agent-core-fusing .ai-agent-orbit-one {
        animation: fortressFusionOrbit 2.1s linear infinite !important;
      }

      .ai-agent-scene.fa-agent-core-fusing .ai-agent-orbit-two {
        animation: fortressFusionOrbit 1.55s linear infinite reverse !important;
      }

      /* Matching status cards below the scene */
      .ai-agent-status-card.fa-agent-status-active {
        border-color: rgba(97,247,189,.25) !important;
        background:
          linear-gradient(145deg,rgba(97,247,189,.045),rgba(180,92,255,.035)) !important;
        box-shadow:
          inset 0 0 18px rgba(97,247,189,.025),
          0 0 18px rgba(97,247,189,.06);
        transform: translateY(-2px);
      }

      .ai-agent-status-card.fa-agent-status-active .ai-agent-badge {
        color: #c5ffe6 !important;
        border-color: rgba(97,247,189,.20) !important;
      }

      @keyframes fortressAgentNodeScan {
        0% { top: 7px; opacity: 0; }
        8% { opacity: .9; }
        50% { top: 50%; opacity: 1; }
        90% { top: calc(100% - 14px); opacity: .84; }
        100% { top: calc(100% - 10px); opacity: 0; }
      }

      @keyframes fortressAgentNodeProgress {
        0% { width: 0; }
        14% { width: 9%; }
        34% { width: 29%; }
        57% { width: 55%; }
        78% { width: 82%; }
        93% { width: 96%; }
        100% { width: 100%; }
      }

      @keyframes fortressAgentStateBlink {
        50% { opacity: .35; }
      }

      @keyframes fortressFusionOrbit {
        to { transform: rotate(360deg); }
      }

      @keyframes fortressPacketTopIn {
        0% { top: 0; opacity: 0; transform: scale(.5); }
        12% { opacity: 1; transform: scale(.9); }
        52% { opacity: 1; transform: scale(1.24); }
        90% { top: 100%; opacity: .9; transform: scale(.8); }
        100% { top: 108%; opacity: 0; transform: scale(.5); }
      }

      @keyframes fortressPacketTopOut {
        0% { top: 100%; opacity: 0; transform: scale(.5); }
        12% { opacity: 1; transform: scale(.9); }
        52% { opacity: 1; transform: scale(1.24); }
        90% { top: 0; opacity: .9; transform: scale(.8); }
        100% { top: -8%; opacity: 0; transform: scale(.5); }
      }

      @keyframes fortressPacketLeftIn {
        0% { left: 0; opacity: 0; transform: scale(.5); }
        12% { opacity: 1; transform: scale(.9); }
        52% { opacity: 1; transform: scale(1.24); }
        90% { left: 100%; opacity: .9; transform: scale(.8); }
        100% { left: 108%; opacity: 0; transform: scale(.5); }
      }

      @keyframes fortressPacketLeftOut {
        0% { left: 100%; opacity: 0; transform: scale(.5); }
        12% { opacity: 1; transform: scale(.9); }
        52% { opacity: 1; transform: scale(1.24); }
        90% { left: 0; opacity: .9; transform: scale(.8); }
        100% { left: -8%; opacity: 0; transform: scale(.5); }
      }

      @keyframes fortressPacketRightIn {
        0% { right: 0; opacity: 0; transform: scale(.5); }
        12% { opacity: 1; transform: scale(.9); }
        52% { opacity: 1; transform: scale(1.24); }
        90% { right: 100%; opacity: .9; transform: scale(.8); }
        100% { right: 108%; opacity: 0; transform: scale(.5); }
      }

      @keyframes fortressPacketRightOut {
        0% { right: 100%; opacity: 0; transform: scale(.5); }
        12% { opacity: 1; transform: scale(.9); }
        52% { opacity: 1; transform: scale(1.24); }
        90% { right: 0; opacity: .9; transform: scale(.8); }
        100% { right: -8%; opacity: 0; transform: scale(.5); }
      }

      @keyframes fortressPacketBottomIn {
        0% { bottom: 0; opacity: 0; transform: scale(.5); }
        12% { opacity: 1; transform: scale(.9); }
        52% { opacity: 1; transform: scale(1.24); }
        90% { bottom: 100%; opacity: .9; transform: scale(.8); }
        100% { bottom: 108%; opacity: 0; transform: scale(.5); }
      }

      @keyframes fortressPacketBottomOut {
        0% { bottom: 100%; opacity: 0; transform: scale(.5); }
        12% { opacity: 1; transform: scale(.9); }
        52% { opacity: 1; transform: scale(1.24); }
        90% { bottom: 0; opacity: .9; transform: scale(.8); }
        100% { bottom: -8%; opacity: 0; transform: scale(.5); }
      }

      @media (max-width: 700px) {
        .fa-agent-node-state {
          top: 5px;
          right: 5px;
          min-height: 16px;
          padding-inline: 5px;
          font-size: 7px;
        }

        .fa-agent-node-progress {
          left: 6px;
          right: 6px;
          bottom: 4px;
        }

        .fa-agent-node-scan {
          left: 5px;
          right: 5px;
        }
      }

      @media (prefers-reduced-motion: reduce) {
        .fa-agent-node-scan,
        .fa-agent-node-progress > i,
        .fa-agent-signal-packet,
        .ai-agent-orbit {
          animation: none !important;
        }

        .ai-agent-node,
        .ai-agent-status-card {
          transform: none !important;
        }
      }
    `;

    document.head.appendChild(style);
  };

  const initAgentMeshProcessor = () => {
    const scene = document.querySelector('.ai-agent-scene');
    if (!scene) return;

    ensureAgentMeshStyles();
    scene.classList.add('fa-agent-processing-enabled');

    const nodes = {
      core: scene.querySelector('.ai-agent-node-core'),
      telemetry: scene.querySelector('.ai-agent-node-top'),
      xgb: scene.querySelector('.ai-agent-node-left'),
      anomaly: scene.querySelector('.ai-agent-node-right'),
      rule: scene.querySelector('.ai-agent-node-bottom')
    };

    const links = {
      telemetry: scene.querySelector('.ai-agent-link-top'),
      xgb: scene.querySelector('.ai-agent-link-left'),
      anomaly: scene.querySelector('.ai-agent-link-right'),
      rule: scene.querySelector('.ai-agent-link-bottom')
    };

    const statusCards = Array.from(
      document.querySelectorAll('.ai-agent-status-panel .ai-agent-status-card')
    );

    const statusMap = {
      telemetry: statusCards[0] || null,
      xgb: statusCards[1] || null,
      anomaly: statusCards[2] || null,
      rule: statusCards[3] || null
    };

    const labels = {
      telemetry: 'Collecting',
      xgb: 'Classifying',
      anomaly: 'Analyzing',
      rule: 'Validating',
      core: 'Fusing'
    };

    const decorateNode = (node) => {
      if (!node || node.dataset.agentProcessorReady === '1') return;

      node.dataset.agentProcessorReady = '1';

      const scan = document.createElement('span');
      scan.className = 'fa-agent-node-scan';
      scan.setAttribute('aria-hidden', 'true');

      const progress = document.createElement('span');
      progress.className = 'fa-agent-node-progress';
      progress.setAttribute('aria-hidden', 'true');

      const fill = document.createElement('i');
      progress.appendChild(fill);

      const state = document.createElement('span');
      state.className = 'fa-agent-node-state';
      state.textContent = 'Queued';
      state.setAttribute('aria-hidden', 'true');

      node.append(scan, progress, state);
    };

    const decorateLink = (link) => {
      if (!link || link.dataset.agentProcessorReady === '1') return;

      link.dataset.agentProcessorReady = '1';

      const packet = document.createElement('span');
      packet.className = 'fa-agent-signal-packet';
      packet.setAttribute('aria-hidden', 'true');
      link.appendChild(packet);
    };

    Object.values(nodes).forEach(decorateNode);
    Object.values(links).forEach(decorateLink);

    const setNodeState = (key, state, text = null) => {
      const node = nodes[key];
      if (!node) return;

      node.classList.remove(
        'fa-agent-queued',
        'fa-agent-processing',
        'fa-agent-complete'
      );
      node.classList.add(`fa-agent-${state}`);

      const badge = node.querySelector('.fa-agent-node-state');
      if (badge) {
        badge.textContent =
          text ||
          (state === 'processing'
            ? labels[key] || 'Processing'
            : state === 'complete'
              ? 'Verified'
              : 'Queued');
      }

      if (state === 'processing' && !reduceMotion()) {
        const scan = node.querySelector('.fa-agent-node-scan');
        const fill = node.querySelector('.fa-agent-node-progress > i');

        [scan, fill].forEach((element) => {
          if (!element) return;
          element.style.animation = 'none';
          void element.offsetWidth;
          element.style.animation = '';
        });
      }
    };

    const setStatusCard = (key, active) => {
      const card = statusMap[key];
      if (!card) return;
      card.classList.toggle('fa-agent-status-active', active);
    };

    const transfer = (key, direction, duration = 620) => {
      const link = links[key];
      if (!link) return;

      link.classList.remove(
        'fa-agent-transfer-in',
        'fa-agent-transfer-out',
        'fa-agent-link-active'
      );

      void link.offsetWidth;

      link.classList.add(
        'fa-agent-link-active',
        direction === 'out'
          ? 'fa-agent-transfer-out'
          : 'fa-agent-transfer-in'
      );

      later(() => {
        link.classList.remove(
          'fa-agent-transfer-in',
          'fa-agent-transfer-out',
          'fa-agent-link-active'
        );
      }, duration + 80);
    };

    const reset = () => {
      scene.classList.remove('fa-agent-core-fusing');

      Object.keys(nodes).forEach((key) => {
        setNodeState(key, 'queued');
      });

      Object.keys(statusMap).forEach((key) => {
        setStatusCard(key, false);
      });

      Object.values(links).forEach((link) => {
        if (!link) return;
        link.classList.remove(
          'fa-agent-transfer-in',
          'fa-agent-transfer-out',
          'fa-agent-link-active'
        );
      });
    };

    const processTime = reduceMotion() ? 180 : 1450;
    const transferTime = reduceMotion() ? 120 : 620;
    const shortPause = reduceMotion() ? 80 : 280;
    const holdTime = reduceMotion() ? 250 : 1550;

    const runCycle = () => {
      reset();

      /* 1. Telemetry collects the behavior window. */
      setNodeState('telemetry', 'processing', 'Collecting');
      setStatusCard('telemetry', true);

      later(() => {
        setNodeState('telemetry', 'complete', 'Window ready');
        setStatusCard('telemetry', false);
        transfer('telemetry', 'in', transferTime);

        /* 2. Core receives telemetry and dispatches analysis jobs. */
        later(() => {
          setNodeState('core', 'processing', 'Dispatching');

          later(() => {
            transfer('xgb', 'out', transferTime);
            transfer('anomaly', 'out', transferTime);
            transfer('rule', 'out', transferTime);

            later(() => {
              setNodeState('core', 'complete', 'Dispatched');

              /* 3. Three specialist agents process in parallel. */
              setNodeState('xgb', 'processing', 'Classifying');
              setStatusCard('xgb', true);

              later(() => {
                setNodeState('anomaly', 'processing', 'Analyzing');
                setStatusCard('anomaly', true);
              }, reduceMotion() ? 0 : 130);

              later(() => {
                setNodeState('rule', 'processing', 'Validating');
                setStatusCard('rule', true);
              }, reduceMotion() ? 0 : 260);

              later(() => {
                setNodeState('xgb', 'complete', 'Classified');
                setNodeState('anomaly', 'complete', 'Scored');
                setNodeState('rule', 'complete', 'Validated');

                setStatusCard('xgb', false);
                setStatusCard('anomaly', false);
                setStatusCard('rule', false);

                /* 4. Their results are returned to FortressAuth Core together. */
                transfer('xgb', 'in', transferTime);
                transfer('anomaly', 'in', transferTime);
                transfer('rule', 'in', transferTime);

                later(() => {
                  /* 5. Core fuses all signals into the advisory defense state. */
                  scene.classList.add('fa-agent-core-fusing');
                  setNodeState('core', 'processing', 'Fusing signals');

                  later(() => {
                    setNodeState('core', 'complete', 'Decision ready');

                    Object.keys(nodes).forEach((key) => {
                      if (key !== 'core') {
                        const node = nodes[key];
                        if (node) node.classList.remove('fa-agent-queued');
                      }
                    });

                    later(() => {
                      runCycle();
                    }, holdTime);
                  }, processTime + 180);
                }, transferTime + shortPause);
              }, processTime + 380);
            }, transferTime + shortPause);
          }, reduceMotion() ? 120 : 760);
        }, transferTime + shortPause);
      }, processTime);
    };

    runCycle();
  };


  /* =========================================================
     AI DEFENSE COORDINATION — REAL PROCESSING PIPELINE
     Targets the exact .ai-coordination-panel markup.
     Incoming Activity -> Rule/XGBoost/Autoencoder -> Hybrid -> Shield
     ========================================================= */

  const ensureCoordinationFlowStyles = () => {
    if (document.getElementById('fortress-coordination-processing-css')) return;

    const style = document.createElement('style');
    style.id = 'fortress-coordination-processing-css';
    style.textContent = `
      .ai-flow-stage.fa-coordination-processing-enabled {
        position: relative !important;
        isolation: isolate;
        overflow: hidden !important;
      }

      .ai-flow-stage.fa-coordination-processing-enabled .ai-flow-node {
        /* Keep the original CSS Grid placement. Absolute positioning here
           breaks the coordination layout by stacking every node at the same
           origin. Relative positioning still gives the processing overlays
           a containing block without removing the node from the grid. */
        position: relative !important;
        isolation: isolate;
        overflow: hidden !important;
        transition:
          border-color .25s ease,
          background .25s ease,
          box-shadow .25s ease,
          filter .25s ease,
          transform .25s ease !important;
      }

      .fa-flow-scan {
        position: absolute;
        z-index: 35;
        left: 8px;
        right: 8px;
        top: 8px;
        height: 2px;
        border-radius: 999px;
        opacity: 0;
        pointer-events: none;
        background: linear-gradient(
          90deg,
          transparent 0%,
          rgba(97,247,189,.16) 8%,
          rgba(97,247,189,1) 48%,
          rgba(212,151,255,.84) 72%,
          transparent 100%
        );
        box-shadow:
          0 0 7px rgba(97,247,189,.92),
          0 0 16px rgba(97,247,189,.34);
      }

      .fa-flow-progress {
        position: absolute;
        z-index: 36;
        left: 9px;
        right: 9px;
        bottom: 7px;
        height: 4px;
        overflow: hidden;
        border-radius: 999px;
        opacity: 0;
        pointer-events: none;
        background: rgba(255,255,255,.055);
      }

      .fa-flow-progress > i {
        display: block;
        width: 0;
        height: 100%;
        border-radius: inherit;
        background: linear-gradient(90deg,#61f7bd 0%,#8df6d4 52%,#d497ff 100%);
        box-shadow:
          0 0 7px rgba(97,247,189,.78),
          0 0 14px rgba(180,92,255,.28);
      }

      .fa-flow-state {
        position: absolute;
        z-index: 38;
        top: 8px;
        right: 8px;
        min-height: 20px;
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 0 7px;
        border: 1px solid rgba(205,159,255,.12);
        border-radius: 999px;
        background: rgba(10,4,18,.84);
        color: #81738c;
        font-size: 8.5px;
        font-weight: 900;
        letter-spacing: .08em;
        line-height: 1;
        text-transform: uppercase;
        pointer-events: none;
        backdrop-filter: blur(7px);
      }

      .fa-flow-state::before {
        content: '';
        width: 5px;
        height: 5px;
        flex: 0 0 5px;
        border-radius: 50%;
        background: #665a70;
      }

      .ai-flow-node.fa-flow-queued {
        filter: brightness(.79) saturate(.73);
        opacity: .80;
      }

      .ai-flow-node.fa-flow-processing {
        opacity: 1;
        transform: translateY(-2px) scale(1.012) !important;
        border-color: rgba(97,247,189,.48) !important;
        background:
          radial-gradient(circle at 50% 18%,rgba(97,247,189,.095),transparent 58%),
          linear-gradient(145deg,rgba(35,18,49,.97),rgba(17,8,29,.99)) !important;
        box-shadow:
          inset 0 0 25px rgba(97,247,189,.045),
          0 0 0 1px rgba(97,247,189,.04),
          0 0 24px rgba(97,247,189,.14) !important;
        filter: brightness(1.09) saturate(1.08);
      }

      .ai-flow-node.fa-flow-processing .fa-flow-scan {
        animation: fortressFlowScan 1.25s cubic-bezier(.22,.75,.23,1) infinite;
      }

      .ai-flow-node.fa-flow-processing .fa-flow-progress {
        opacity: 1;
      }

      .ai-flow-node.fa-flow-processing .fa-flow-progress > i {
        animation: fortressFlowProgress 1.48s linear both;
      }

      .ai-flow-node.fa-flow-processing .fa-flow-state {
        color: #c8ffe9;
        border-color: rgba(97,247,189,.24);
        background: rgba(8,31,25,.84);
      }

      .ai-flow-node.fa-flow-processing .fa-flow-state::before {
        background: #61f7bd;
        box-shadow:
          0 0 4px rgba(97,247,189,.95),
          0 0 9px rgba(97,247,189,.52);
        animation: fortressFlowStateBlink .42s steps(2,end) infinite;
      }

      .ai-flow-node.fa-flow-complete {
        opacity: 1;
        border-color: rgba(97,247,189,.20) !important;
        box-shadow:
          inset 0 0 16px rgba(97,247,189,.025),
          0 0 11px rgba(97,247,189,.05) !important;
        filter: brightness(1.02) saturate(1);
      }

      .ai-flow-node.fa-flow-complete .fa-flow-state {
        color: #aeeed3;
        border-color: rgba(97,247,189,.16);
        background: rgba(97,247,189,.045);
      }

      .ai-flow-node.fa-flow-complete .fa-flow-state::before {
        background: #61f7bd;
        box-shadow: 0 0 6px rgba(97,247,189,.38);
      }

      .ai-flow-node-hybrid.fa-flow-processing,
      .ai-flow-node-shield.fa-flow-processing {
        border-color: rgba(212,151,255,.48) !important;
        background:
          radial-gradient(circle at 50% 35%,rgba(180,92,255,.16),transparent 58%),
          linear-gradient(145deg,rgba(46,19,66,.97),rgba(18,7,33,.99)) !important;
        box-shadow:
          inset 0 0 30px rgba(180,92,255,.08),
          0 0 0 1px rgba(212,151,255,.04),
          0 0 30px rgba(180,92,255,.18) !important;
      }

      .ai-flow-node-hybrid.fa-flow-processing .fa-flow-scan,
      .ai-flow-node-shield.fa-flow-processing .fa-flow-scan {
        background: linear-gradient(
          90deg,
          transparent,
          rgba(212,151,255,.20),
          rgba(212,151,255,1),
          rgba(97,247,189,.70),
          transparent
        );
        box-shadow:
          0 0 8px rgba(212,151,255,.90),
          0 0 18px rgba(180,92,255,.40);
      }

      .ai-flow-node-hybrid.fa-flow-processing .fa-flow-progress > i,
      .ai-flow-node-shield.fa-flow-processing .fa-flow-progress > i {
        background: linear-gradient(90deg,#b45cff,#d497ff 58%,#61f7bd);
      }

      .ai-flow-stage.fa-flow-fusing .ai-flow-connector {
        filter: drop-shadow(0 0 5px rgba(180,92,255,.45));
      }

      /* The page already has a decorative connector-dot animation. While the
         real processing pipeline is enabled, keep the lane but suppress that
         unrelated moving dot so the generated signal packets are unambiguous. */
      .ai-flow-stage.fa-coordination-processing-enabled .ai-flow-connector::after {
        animation: none !important;
        opacity: .28 !important;
      }

      /* Signal packet rendered in scene coordinates so it works on desktop/mobile. */
      .fa-flow-packet {
        position: absolute;
        z-index: 70;
        left: 0;
        top: 0;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        opacity: 0;
        pointer-events: none;
        background: #e8fff6;
        box-shadow:
          0 0 5px #61f7bd,
          0 0 11px rgba(97,247,189,.98),
          0 0 19px rgba(180,92,255,.52);
        will-change: transform, opacity;
      }

      .fa-flow-packet.fa-flow-packet-purple {
        background: #f1dcff;
        box-shadow:
          0 0 5px #d497ff,
          0 0 12px rgba(212,151,255,.96),
          0 0 20px rgba(180,92,255,.55);
      }

      /* Live coordination card reflects the current pipeline stage. */
      .ai-coordination-feed.fa-flow-live-processing .ai-feed-ticker {
        border-color: rgba(97,247,189,.20) !important;
        box-shadow: inset 0 0 20px rgba(97,247,189,.025);
      }

      .ai-feed-item.fa-flow-feed-active {
        border-color: rgba(97,247,189,.23) !important;
        background:
          linear-gradient(145deg,rgba(97,247,189,.045),rgba(180,92,255,.03)) !important;
        box-shadow:
          inset 0 0 16px rgba(97,247,189,.025),
          0 0 14px rgba(97,247,189,.05);
        transform: translateX(3px);
      }

      .ai-feed-item.fa-flow-feed-active .ai-feed-dot {
        background: #61f7bd !important;
        box-shadow:
          0 0 5px rgba(97,247,189,.95),
          0 0 11px rgba(97,247,189,.48) !important;
        animation: fortressFlowStateBlink .42s steps(2,end) infinite !important;
      }

      @keyframes fortressFlowScan {
        0% { top: 8px; opacity: 0; }
        8% { opacity: .92; }
        50% { top: 50%; opacity: 1; }
        90% { top: calc(100% - 15px); opacity: .84; }
        100% { top: calc(100% - 11px); opacity: 0; }
      }

      @keyframes fortressFlowProgress {
        0% { width: 0; }
        15% { width: 10%; }
        36% { width: 31%; }
        58% { width: 57%; }
        79% { width: 82%; }
        94% { width: 97%; }
        100% { width: 100%; }
      }

      @keyframes fortressFlowStateBlink {
        50% { opacity: .35; }
      }

      @media (max-width: 700px) {
        .fa-flow-state {
          top: 5px;
          right: 5px;
          min-height: 17px;
          padding-inline: 5px;
          font-size: 7px;
        }

        .fa-flow-progress {
          left: 6px;
          right: 6px;
          bottom: 4px;
        }

        .fa-flow-scan {
          left: 5px;
          right: 5px;
        }
      }

      @media (prefers-reduced-motion: reduce) {
        .fa-flow-scan,
        .fa-flow-progress > i,
        .fa-flow-packet,
        .ai-feed-dot {
          animation: none !important;
        }

        .ai-flow-node,
        .ai-feed-item {
          transform: none !important;
        }
      }
    `;

    document.head.appendChild(style);
  };

  const initCoordinationFlowProcessor = () => {
    const panel = document.querySelector('.ai-coordination-panel');
    if (!panel) return;

    const stage = panel.querySelector('.ai-flow-stage');
    const feed = panel.querySelector('.ai-coordination-feed');
    const rotator = panel.querySelector('#ai-coordination-rotator');

    if (!stage) return;

    ensureCoordinationFlowStyles();
    stage.classList.add('fa-coordination-processing-enabled');
    if (feed) feed.classList.add('fa-flow-live-processing');

    const nodes = {
      ingress: stage.querySelector('.ai-flow-node-ingress'),
      rule: stage.querySelector('.ai-flow-node-rule'),
      xgb: stage.querySelector('.ai-flow-node-xgb'),
      auto: stage.querySelector('.ai-flow-node-auto'),
      hybrid: stage.querySelector('.ai-flow-node-hybrid'),
      shield: stage.querySelector('.ai-flow-node-shield')
    };

    const feedItems = Array.from(panel.querySelectorAll('.ai-feed-item'));
    const feedMap = {
      ingress: feedItems[0] || null,
      rule: feedItems[1] || null,
      xgb: feedItems[2] || null,
      auto: feedItems[3] || null,
      hybrid: feedItems[4] || null
    };

    const labels = {
      ingress: 'Collecting',
      rule: 'Validating',
      xgb: 'Classifying',
      auto: 'Analyzing',
      hybrid: 'Fusing signals',
      shield: 'Applying posture'
    };

    const decorateNode = (node) => {
      if (!node || node.dataset.flowProcessorReady === '1') return;
      node.dataset.flowProcessorReady = '1';

      const scan = document.createElement('span');
      scan.className = 'fa-flow-scan';
      scan.setAttribute('aria-hidden', 'true');

      const progress = document.createElement('span');
      progress.className = 'fa-flow-progress';
      progress.setAttribute('aria-hidden', 'true');
      const fill = document.createElement('i');
      progress.appendChild(fill);

      const state = document.createElement('span');
      state.className = 'fa-flow-state';
      state.textContent = 'Queued';
      state.setAttribute('aria-hidden', 'true');

      node.append(scan, progress, state);
    };

    Object.values(nodes).forEach(decorateNode);

    const setNodeState = (key, stateName, customText = null) => {
      const node = nodes[key];
      if (!node) return;

      node.classList.remove('fa-flow-queued','fa-flow-processing','fa-flow-complete');
      node.classList.add(`fa-flow-${stateName}`);

      const state = node.querySelector('.fa-flow-state');
      if (state) {
        state.textContent = customText || (
          stateName === 'processing'
            ? labels[key]
            : stateName === 'complete'
              ? 'Verified'
              : 'Queued'
        );
      }

      if (stateName === 'processing' && !reduceMotion()) {
        const scan = node.querySelector('.fa-flow-scan');
        const fill = node.querySelector('.fa-flow-progress > i');
        [scan, fill].forEach((element) => {
          if (!element) return;
          element.style.animation = 'none';
          void element.offsetWidth;
          element.style.animation = '';
        });
      }
    };

    const setFeedActive = (...keys) => {
      Object.values(feedMap).forEach((item) => {
        if (item) item.classList.remove('fa-flow-feed-active');
      });
      keys.forEach((key) => {
        const item = feedMap[key];
        if (item) item.classList.add('fa-flow-feed-active');
      });
    };

    const setRotator = (message) => {
      if (!rotator) return;
      rotator.classList.remove('is-visible');
      window.requestAnimationFrame(() => {
        rotator.textContent = message;
        rotator.classList.add('is-visible');
      });
    };

    const nodeCenter = (node) => {
      if (!node) return null;
      const stageRect = stage.getBoundingClientRect();
      const rect = node.getBoundingClientRect();
      return {
        x: rect.left - stageRect.left + rect.width / 2,
        y: rect.top - stageRect.top + rect.height / 2
      };
    };

    const flyPacket = (fromKey, toKey, options = {}) => {
      const from = nodeCenter(nodes[fromKey]);
      const to = nodeCenter(nodes[toKey]);
      if (!from || !to) return;

      const packet = document.createElement('span');
      packet.className = 'fa-flow-packet' + (options.purple ? ' fa-flow-packet-purple' : '');
      packet.setAttribute('aria-hidden', 'true');
      stage.appendChild(packet);

      const duration = reduceMotion() ? 80 : (options.duration || 680);
      const startX = from.x - 4;
      const startY = from.y - 4;
      const dx = to.x - from.x;
      const dy = to.y - from.y;

      if (typeof packet.animate === 'function' && !reduceMotion()) {
        const animation = packet.animate([
          { transform: `translate(${startX}px, ${startY}px) scale(.55)`, opacity: 0 },
          { transform: `translate(${startX + dx * .12}px, ${startY + dy * .12}px) scale(.9)`, opacity: 1, offset: .12 },
          { transform: `translate(${startX + dx * .52}px, ${startY + dy * .52}px) scale(1.28)`, opacity: 1, offset: .52 },
          { transform: `translate(${startX + dx * .90}px, ${startY + dy * .90}px) scale(.82)`, opacity: .9, offset: .90 },
          { transform: `translate(${startX + dx}px, ${startY + dy}px) scale(.5)`, opacity: 0 }
        ], {
          duration,
          easing: 'cubic-bezier(.2,.72,.2,1)',
          fill: 'forwards'
        });
        animation.onfinish = () => packet.remove();
      } else {
        packet.style.transform = `translate(${to.x - 4}px, ${to.y - 4}px)`;
        packet.style.opacity = '0';
        later(() => packet.remove(), duration + 20);
      }
    };

    const reset = () => {
      stage.classList.remove('fa-flow-fusing');
      Object.keys(nodes).forEach((key) => setNodeState(key, 'queued'));
      setFeedActive();
    };

    const processTime = reduceMotion() ? 160 : 1420;
    const transferTime = reduceMotion() ? 90 : 680;
    const stagger = reduceMotion() ? 0 : 130;
    const pause = reduceMotion() ? 60 : 260;
    const hold = reduceMotion() ? 220 : 1450;

    const runCycle = () => {
      reset();

      /* 1) Gather the live input stream. */
      setNodeState('ingress', 'processing', 'Collecting');
      setFeedActive('ingress');
      setRotator('Request Monitor is collecting the current behavioral window...');

      later(() => {
        setNodeState('ingress', 'complete', 'Window ready');

        /* 2) Fan the same activity window out to the three specialists. */
        flyPacket('ingress', 'rule');
        later(() => flyPacket('ingress', 'xgb'), stagger);
        later(() => flyPacket('ingress', 'auto'), stagger * 2);

        later(() => {
          setNodeState('rule', 'processing', 'Validating');
          setFeedActive('rule');
          setRotator('Rule Engine is validating deterministic FortressAuth evidence...');

          later(() => {
            setNodeState('xgb', 'processing', 'Classifying');
            setFeedActive('rule','xgb');
            setRotator('XGBoost is classifying the current behavior pattern...');
          }, stagger);

          later(() => {
            setNodeState('auto', 'processing', 'Analyzing');
            setFeedActive('rule','xgb','auto');
            setRotator('Autoencoder is measuring deviation from the learned baseline...');
          }, stagger * 2);

          later(() => {
            setNodeState('rule', 'complete', 'Validated');
            setNodeState('xgb', 'complete', 'Classified');
            setNodeState('auto', 'complete', 'Scored');

            /* 3) Return all three outputs to Hybrid Risk Engine. */
            flyPacket('rule', 'hybrid', { purple: true });
            later(() => flyPacket('xgb', 'hybrid', { purple: true }), stagger);
            later(() => flyPacket('auto', 'hybrid', { purple: true }), stagger * 2);

            later(() => {
              stage.classList.add('fa-flow-fusing');
              setNodeState('hybrid', 'processing', 'Fusing signals');
              setFeedActive('hybrid');
              setRotator('Hybrid Engine is fusing rule, classifier, and anomaly signals...');

              later(() => {
                setNodeState('hybrid', 'complete', 'Risk ready');

                /* 4) Send final advisory risk to the authoritative shield. */
                flyPacket('hybrid', 'shield', { purple: true });

                later(() => {
                  setNodeState('shield', 'processing', 'Applying posture');
                  setFeedActive('hybrid');
                  setRotator('FortressAuth Shield is applying the final advisory defense posture...');

                  later(() => {
                    setNodeState('shield', 'complete', 'Protected');
                    setFeedActive();
                    setRotator('Defense cycle complete. FortressAuth remains protected and monitoring continues.');

                    later(runCycle, hold);
                  }, processTime);
                }, transferTime + pause);
              }, processTime + 160);
            }, transferTime + pause);
          }, processTime + 420);
        }, transferTime + pause);
      }, processTime);
    };

    runCycle();
  };

  /* =========================================================
     Existing coordination text rotator
     ========================================================= */

  const initCoordinationRotator = () => {
    const rotator = document.getElementById('ai-coordination-rotator');
    if (!rotator) return;

    const messages = [
      'Request monitor is preparing the current behavioral analysis window.',
      'Rule engine is validating known FortressAuth attack signatures.',
      'XGBoost is classifying the current behavior pattern.',
      'Autoencoder is measuring deviation from the learned baseline.',
      'Hybrid engine is fusing signals into one advisory defense score.'
    ];

    let index = 0;
    rotator.textContent = messages[0];
    rotator.classList.add('is-visible');

    repeat(() => {
      index = (index + 1) % messages.length;
      rotator.classList.remove('is-visible');

      window.requestAnimationFrame(() => {
        rotator.textContent = messages[index];
        rotator.classList.add('is-visible');
      });
    }, 2600);
  };

  /* =========================================================
     Existing AI conversation/typewriter
     ========================================================= */

  const initAiConversation = () => {
    const root = document.getElementById('fortress-ai-chat');
    const insightSource = document.getElementById('fortress-ai-insights');

    if (!root || !insightSource) return;

    const messages = Array.from(
      insightSource.querySelectorAll('[data-ai-insight]')
    )
      .map((node) => (node.textContent || '').trim())
      .filter(Boolean);

    const visibleText = document.getElementById('fortress-ai-visible-text');
    const caret = document.getElementById('fortress-ai-caret');
    const thinking = document.getElementById('fortress-ai-thinking');
    const messageElement = document.getElementById('fortress-ai-message');
    const countElement = document.getElementById('fortress-ai-insight-count');
    const statusText = document.getElementById('fortress-ai-status-text');
    const statusDot = document.getElementById('fortress-ai-status-dot');
    const progressLabel = document.getElementById('fortress-ai-progress-label');
    const progressBar = document.getElementById('fortress-ai-progress-bar');
    const nextButton = document.getElementById('fortress-ai-next');
    const modeButtons = Array.from(root.querySelectorAll('[data-ai-mode]'));

    if (
      !visibleText ||
      !caret ||
      !thinking ||
      !messageElement ||
      !countElement ||
      !statusText ||
      !statusDot ||
      !progressLabel ||
      !progressBar ||
      !nextButton
    ) {
      return;
    }

    let index = 0;
    let mode = 'auto';
    let typingTimer = null;
    let advanceTimer = null;
    let switchTimer = null;
    let generation = 0;
    let messageComplete = false;

    const reduced = reduceMotion();

    const clearTimers = () => {
      if (typingTimer) window.clearTimeout(typingTimer);
      if (advanceTimer) window.clearTimeout(advanceTimer);
      if (switchTimer) window.clearTimeout(switchTimer);

      typingTimer = null;
      advanceTimer = null;
      switchTimer = null;
    };

    const updateProgress = () => {
      const total = messages.length;
      const current = total ? index + 1 : 0;
      const progress = total ? Math.round((current / total) * 100) : 0;

      countElement.textContent = `Insight ${current} of ${total}`;
      progressLabel.textContent = `${progress}%`;
      progressBar.style.width = `${progress}%`;
    };

    const setWorkingState = (working, text) => {
      statusDot.classList.toggle('working', working);
      statusText.textContent = text;
    };

    const scheduleAutoAdvance = (message) => {
      if (mode !== 'auto' || !messageComplete || messages.length < 2) return;

      const readingDelay = Math.min(
        9000,
        Math.max(4200, message.length * 24)
      );

      advanceTimer = later(() => {
        root.classList.add('is-switching');

        switchTimer = later(() => {
          index = (index + 1) % messages.length;
          root.classList.remove('is-switching');
          renderMessage();
        }, 260);
      }, readingDelay);
    };

    const finishMessage = (message) => {
      messageComplete = true;
      caret.classList.remove('typing');
      thinking.hidden = true;
      messageElement.hidden = false;

      if (mode === 'manual') {
        setWorkingState(
          false,
          'Finding complete. Select Next insight when you are ready.'
        );
        nextButton.disabled = false;
      } else {
        setWorkingState(
          false,
          'Finding complete. The next insight will play automatically.'
        );
        scheduleAutoAdvance(message);
      }
    };

    const typeMessage = (message, token) => {
      if (reduced) {
        visibleText.textContent = message;
        finishMessage(message);
        return;
      }

      let characterIndex = 0;

      const typeNext = () => {
        if (token !== generation) return;

        characterIndex = Math.min(message.length, characterIndex + 1);
        visibleText.textContent = message.slice(0, characterIndex);

        if (characterIndex >= message.length) {
          finishMessage(message);
          return;
        }

        const typedCharacter = message.charAt(characterIndex - 1);
        const delay = /[.!?]/.test(typedCharacter)
          ? 135
          : /[,;:]/.test(typedCharacter)
            ? 72
            : 30;

        typingTimer = later(typeNext, delay);
      };

      typeNext();
    };

    const renderMessage = () => {
      clearTimers();
      generation += 1;

      const token = generation;
      messageComplete = false;
      nextButton.disabled = true;
      updateProgress();

      const message =
        messages[index] ||
        'I do not have a completed FortressAuth security finding to report yet.';

      visibleText.textContent = '';
      caret.classList.remove('typing');
      thinking.hidden = false;
      messageElement.hidden = true;

      setWorkingState(true, 'Reviewing the latest FortressAuth security analysis...');

      const thinkingDelay = reduced ? 0 : 720;

      typingTimer = later(() => {
        if (token !== generation) return;

        thinking.hidden = true;
        messageElement.hidden = false;
        caret.classList.add('typing');

        setWorkingState(true, 'Preparing my security report...');
        typeMessage(message, token);
      }, thinkingDelay);
    };

    const setMode = (nextMode) => {
      if (!['auto', 'manual'].includes(nextMode) || mode === nextMode) return;

      mode = nextMode;

      if (advanceTimer) {
        window.clearTimeout(advanceTimer);
        advanceTimer = null;
      }

      modeButtons.forEach((button) => {
        const active = button.dataset.aiMode === mode;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
      });

      nextButton.hidden = mode !== 'manual';

      if (messageComplete) {
        if (mode === 'manual') {
          nextButton.disabled = false;
          setWorkingState(
            false,
            'Finding complete. Select Next insight when you are ready.'
          );
        } else {
          nextButton.disabled = true;
          setWorkingState(
            false,
            'Finding complete. The next insight will play automatically.'
          );
          scheduleAutoAdvance(messages[index] || '');
        }
      }
    };

    modeButtons.forEach((button) => {
      button.addEventListener('click', () => {
        setMode(button.dataset.aiMode || 'auto');
      });
    });

    nextButton.addEventListener('click', () => {
      if (
        mode !== 'manual' ||
        !messageComplete ||
        !messages.length
      ) {
        return;
      }

      root.classList.add('is-switching');
      nextButton.disabled = true;

      switchTimer = later(() => {
        index = (index + 1) % messages.length;
        root.classList.remove('is-switching');
        renderMessage();
      }, 260);
    });

    nextButton.hidden = true;

    if (!messages.length) {
      countElement.textContent = 'Insight 0 of 0';
      progressLabel.textContent = '0%';
      progressBar.style.width = '0%';
      visibleText.textContent =
        'I do not have a completed FortressAuth security finding to report yet.';
      thinking.hidden = true;
      messageElement.hidden = false;
      caret.classList.remove('typing');
      setWorkingState(false, 'Waiting for a completed security analysis.');
      return;
    }

    renderMessage();
  };

  const init = () => {
    destroy();
    initCoordinationFlowProcessor();
    initAgentMeshProcessor();
    initAiConversation();
  };

  window.FortressAI = { init, destroy };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
