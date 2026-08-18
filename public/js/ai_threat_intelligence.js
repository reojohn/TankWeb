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
          translate .32s cubic-bezier(.2,.8,.2,1),
          scale .32s cubic-bezier(.2,.8,.2,1) !important;
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
        scale: 1.025;
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

      .ai-agent-node.fa-agent-processing .ai-agent-icon {
        animation: fortressAgentIconWork 1.55s ease-in-out infinite;
      }

      .ai-agent-node.fa-agent-processing .ai-agent-robot-image {
        animation: fortressAgentRobotPulse 1.55s ease-in-out infinite;
      }

      .ai-agent-node.fa-agent-complete {
        opacity: 1;
        scale: 1;
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

      .ai-agent-scene.fa-agent-processing-enabled {
        --fa-agent-transfer-duration: .68s;
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
          0 0 18px rgba(180,92,255,.52),
          0 0 28px rgba(97,247,189,.18);
      }

      .fa-agent-signal-packet::after {
        content: "";
        position: absolute;
        left: 50%;
        top: 50%;
        width: 18px;
        height: 18px;
        border-radius: 50%;
        transform: translate(-50%,-50%);
        background: radial-gradient(circle,rgba(97,247,189,.22),transparent 68%);
        filter: blur(1px);
      }

      /* Telemetry -> Core */
      .ai-agent-link-top .fa-agent-signal-packet {
        left: 50%;
        top: 0;
        margin-left: -3.5px;
      }

      .ai-agent-link-top.fa-agent-transfer-in .fa-agent-signal-packet {
        animation: fortressPacketTopIn var(--fa-agent-transfer-duration) cubic-bezier(.18,.76,.22,1) both;
      }

      .ai-agent-link-top.fa-agent-transfer-out .fa-agent-signal-packet {
        animation: fortressPacketTopOut var(--fa-agent-transfer-duration) cubic-bezier(.18,.76,.22,1) both;
      }

      /* XGBoost <-> Core */
      .ai-agent-link-left .fa-agent-signal-packet {
        left: 0;
        top: 50%;
        margin-top: -3.5px;
      }

      .ai-agent-link-left.fa-agent-transfer-in .fa-agent-signal-packet {
        animation: fortressPacketLeftIn var(--fa-agent-transfer-duration) cubic-bezier(.18,.76,.22,1) both;
      }

      .ai-agent-link-left.fa-agent-transfer-out .fa-agent-signal-packet {
        animation: fortressPacketLeftOut var(--fa-agent-transfer-duration) cubic-bezier(.18,.76,.22,1) both;
      }

      /* Anomaly <-> Core */
      .ai-agent-link-right .fa-agent-signal-packet {
        right: 0;
        top: 50%;
        margin-top: -3.5px;
      }

      .ai-agent-link-right.fa-agent-transfer-in .fa-agent-signal-packet {
        animation: fortressPacketRightIn var(--fa-agent-transfer-duration) cubic-bezier(.18,.76,.22,1) both;
      }

      .ai-agent-link-right.fa-agent-transfer-out .fa-agent-signal-packet {
        animation: fortressPacketRightOut var(--fa-agent-transfer-duration) cubic-bezier(.18,.76,.22,1) both;
      }

      /* Rule Agent <-> Core */
      .ai-agent-link-bottom .fa-agent-signal-packet {
        left: 50%;
        bottom: 0;
        margin-left: -3.5px;
      }

      .ai-agent-link-bottom.fa-agent-transfer-in .fa-agent-signal-packet {
        animation: fortressPacketBottomIn var(--fa-agent-transfer-duration) cubic-bezier(.18,.76,.22,1) both;
      }

      .ai-agent-link-bottom.fa-agent-transfer-out .fa-agent-signal-packet {
        animation: fortressPacketBottomOut var(--fa-agent-transfer-duration) cubic-bezier(.18,.76,.22,1) both;
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
        animation: fortressFusionOrbit 7.5s linear infinite !important;
      }

      .ai-agent-scene.fa-agent-core-fusing .ai-agent-orbit-two {
        animation: fortressFusionOrbit 10s linear infinite reverse !important;
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


      .ai-agent-node {
        overflow: visible !important;
      }

      .fa-agent-dialog-bubble {
        position: absolute;
        z-index: 60;
        min-width: 126px;
        max-width: 188px;
        padding: 9px 10px 10px;
        border: 1px solid rgba(212,151,255,.18);
        border-radius: 14px;
        background: linear-gradient(145deg,rgba(20,8,34,.96),rgba(9,3,18,.96));
        box-shadow:
          0 12px 26px rgba(0,0,0,.24),
          0 0 18px rgba(180,92,255,.12),
          inset 0 1px 0 rgba(255,255,255,.05);
        color: #ecdfff;
        opacity: 0;
        pointer-events: none;
        transform: translate3d(0, 8px, 0) scale(.92);
        transition:
          opacity .24s ease,
          transform .28s cubic-bezier(.2,.8,.2,1),
          box-shadow .28s ease;
      }

      .fa-agent-dialog-bubble::after {
        content: "";
        position: absolute;
        width: 10px;
        height: 10px;
        background: inherit;
        border-right: 1px solid rgba(212,151,255,.16);
        border-bottom: 1px solid rgba(212,151,255,.16);
        transform: rotate(45deg);
      }

      .fa-agent-dialog-route {
        display: block;
        margin-bottom: 4px;
        color: #8af5cf;
        font-size: 9px;
        font-weight: 900;
        letter-spacing: .12em;
        text-transform: uppercase;
      }

      .fa-agent-dialog-text {
        display: block;
        color: #f3e7fc;
        font-size: 10.5px;
        line-height: 1.45;
      }

      .ai-agent-node.fa-agent-speaking .fa-agent-dialog-bubble {
        opacity: 1;
        transform: translate3d(0, 0, 0) scale(1);
      }

      .ai-agent-node.fa-agent-speaking {
        z-index: 7 !important;
        box-shadow:
          0 0 0 1px rgba(212,151,255,.06),
          0 0 28px rgba(180,92,255,.16),
          0 18px 38px rgba(0,0,0,.24) !important;
      }

      .ai-agent-node-top .fa-agent-dialog-bubble {
        left: calc(100% - 8px);
        top: 10px;
      }
      .ai-agent-node-top .fa-agent-dialog-bubble::after {
        left: -6px;
        top: 18px;
      }

      .ai-agent-node-left .fa-agent-dialog-bubble {
        left: calc(100% - 6px);
        top: 14px;
      }
      .ai-agent-node-left .fa-agent-dialog-bubble::after {
        left: -6px;
        top: 18px;
      }

      .ai-agent-node-right .fa-agent-dialog-bubble {
        right: calc(100% - 6px);
        top: 14px;
      }
      .ai-agent-node-right .fa-agent-dialog-bubble::after {
        right: -6px;
        top: 18px;
      }

      .ai-agent-node-bottom .fa-agent-dialog-bubble {
        left: calc(100% - 8px);
        bottom: 10px;
      }
      .ai-agent-node-bottom .fa-agent-dialog-bubble::after {
        left: -6px;
        bottom: 18px;
      }

      .ai-agent-node-core .fa-agent-dialog-bubble {
        left: 50%;
        bottom: calc(100% + 10px);
        transform: translate3d(-50%, 8px, 0) scale(.92);
        text-align: center;
      }
      .ai-agent-node-core.fa-agent-speaking .fa-agent-dialog-bubble {
        transform: translate3d(-50%, 0, 0) scale(1);
      }
      .ai-agent-node-core .fa-agent-dialog-bubble::after {
        left: 50%;
        bottom: -6px;
        margin-left: -5px;
      }

      .ai-agent-comm-panel {
        padding: 12px 14px 14px;
        border: 1px solid rgba(205,159,255,.10);
        border-radius: 18px;
        background:
          linear-gradient(145deg,rgba(16,6,28,.82),rgba(8,3,16,.88));
        box-shadow:
          inset 0 1px 0 rgba(255,255,255,.03),
          0 16px 34px rgba(0,0,0,.14);
      }

      .ai-agent-comm-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 10px;
      }

      .ai-agent-comm-head strong {
        color: #f3e7fc;
        font-size: 14px;
      }

      .ai-agent-comm-head span {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        color: #a98dbd;
        font-size: 10.5px;
        font-weight: 900;
        letter-spacing: .12em;
        text-transform: uppercase;
      }

      .ai-agent-comm-head span::before {
        content: "";
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #61f7bd;
        box-shadow: 0 0 12px rgba(97,247,189,.72);
        animation: fortressAgentStateBlink .8s steps(2,end) infinite;
      }

      .ai-agent-comm-log {
        display: grid;
        gap: 8px;
      }

      .ai-agent-comm-item {
        display: grid;
        grid-template-columns: auto 1fr;
        gap: 8px 10px;
        align-items: start;
        padding: 10px 11px;
        border: 1px solid rgba(205,159,255,.08);
        border-radius: 14px;
        background: rgba(255,255,255,.018);
        opacity: .72;
        transform: translateY(6px);
        transition:
          opacity .24s ease,
          transform .24s ease,
          border-color .24s ease,
          background .24s ease;
      }

      .ai-agent-comm-item.fa-agent-comm-live {
        opacity: 1;
        transform: translateY(0);
        border-color: rgba(97,247,189,.18);
        background: linear-gradient(145deg,rgba(97,247,189,.045),rgba(180,92,255,.04));
      }

      .ai-agent-comm-arrow {
        color: #8af5cf;
        font-size: 10px;
        font-weight: 900;
        letter-spacing: .1em;
        text-transform: uppercase;
      }

      .ai-agent-comm-text {
        color: #e9dcf6;
        font-size: 11.5px;
        line-height: 1.55;
      }

      .ai-agent-comm-text strong {
        color: #f9f0ff;
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
        from { transform: translate(-50%,-50%) rotate(0deg); }
        to { transform: translate(-50%,-50%) rotate(360deg); }
      }

      @keyframes fortressAgentIconWork {
        0%,100% { transform: translateY(0) scale(1); }
        45% { transform: translateY(-2px) scale(1.035); }
        70% { transform: translateY(1px) scale(.995); }
      }

      @keyframes fortressAgentRobotPulse {
        0%,100% { filter: brightness(1) drop-shadow(0 5px 5px rgba(0,0,0,.30)) drop-shadow(0 0 8px rgba(212,151,255,.13)); }
        50% { filter: brightness(1.14) drop-shadow(0 5px 5px rgba(0,0,0,.28)) drop-shadow(0 0 13px rgba(97,247,189,.28)); }
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
        .ai-agent-scene.fa-agent-processing-enabled {
          --fa-agent-transfer-duration: .78s;
        }

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

      @media (max-width: 860px) {
        .fa-agent-dialog-bubble {
          max-width: 156px;
          min-width: 112px;
          padding: 8px 9px 9px;
        }
      }

      @media (max-width: 620px) {
        .fa-agent-dialog-bubble {
          max-width: 132px;
          min-width: 96px;
          padding: 7px 8px 8px;
        }

        .fa-agent-dialog-route {
          font-size: 8px;
        }

        .fa-agent-dialog-text {
          font-size: 9.5px;
          line-height: 1.38;
        }

        .ai-agent-node-left .fa-agent-dialog-bubble {
          top: -6px;
        }

        .ai-agent-node-right .fa-agent-dialog-bubble {
          top: -6px;
        }

        .ai-agent-node-bottom .fa-agent-dialog-bubble {
          bottom: calc(100% - 12px);
          left: 50%;
          transform: translate3d(-50%, 8px, 0) scale(.92);
        }

        .ai-agent-node-bottom.fa-agent-speaking .fa-agent-dialog-bubble {
          transform: translate3d(-50%, 0, 0) scale(1);
        }

        .ai-agent-node-bottom .fa-agent-dialog-bubble::after {
          left: 50%;
          bottom: -6px;
          margin-left: -5px;
        }

        .ai-agent-comm-panel {
          padding: 11px 12px 12px;
        }

        .ai-agent-comm-item {
          padding: 9px 10px;
        }
      }

      @media (prefers-reduced-motion: reduce) {
        .fa-agent-node-scan,
        .fa-agent-node-progress > i,
        .fa-agent-signal-packet,
        .ai-agent-orbit,
        .ai-agent-icon,
        .ai-agent-robot-image {
          animation: none !important;
        }

        .ai-agent-node {
          translate: 0 0 !important;
          scale: 1 !important;
        }

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

    let connectorLayer = scene.querySelector('.fa-agent-connector-layer');
    if (!connectorLayer) {
      connectorLayer = document.createElement('div');
      connectorLayer.className = 'fa-agent-connector-layer';
      scene.insertBefore(connectorLayer, nodes.core || scene.firstChild);
    }

    const connectors = {};
    ['telemetry', 'xgb', 'anomaly', 'rule'].forEach((key) => {
      let connector = connectorLayer.querySelector(`[data-connector="${key}"]`);
      if (!connector) {
        connector = document.createElement('span');
        connector.className = 'fa-agent-connector';
        connector.dataset.connector = key;
        connectorLayer.appendChild(connector);
      }
      connectors[key] = connector;
    });

    let attackerLayer = scene.querySelector('.fa-agent-attacker-layer');
    if (!attackerLayer) {
      attackerLayer = document.createElement('div');
      attackerLayer.className = 'fa-agent-attacker-layer';
      scene.appendChild(attackerLayer);
    }

    let defenseLayer = scene.querySelector('.fa-agent-defense-layer');
    if (!defenseLayer) {
      defenseLayer = document.createElement('div');
      defenseLayer.className = 'fa-agent-defense-layer';
      scene.appendChild(defenseLayer);
    }

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

    const names = {
      telemetry: 'Telemetry',
      xgb: 'XGBoost',
      anomaly: 'Anomaly',
      rule: 'Rule',
      core: 'Core',
      all: 'Agent Mesh'
    };

    const fullNames = {
      telemetry: 'Telemetry Agent',
      xgb: 'XGBoost Agent',
      anomaly: 'Anomaly Agent',
      rule: 'Rule Agent',
      core: 'FortressAuth Core',
      all: 'Agent Mesh'
    };

    const threatTemplates = [
      { type: 'botnet', image: 'botnet.png', label: 'BOTNET', detail: 'credential storm', origin: 'left' },
      { type: 'sqli', image: 'sqli.png', label: 'SQLi', detail: 'payload injection', origin: 'right' },
      { type: 'recon', image: 'recon.png', label: 'RECON', detail: 'forced-browse probe', origin: 'top' },
      { type: 'brute', image: 'brute.png', label: 'BRUTE', detail: 'login hammer', origin: 'left' },
      { type: 'xss', image: 'xss.png', label: 'XSS', detail: 'script vector', origin: 'right' }
    ];

    const numberFromData = (value, fallback = 0) => {
      const parsed = Number.parseFloat(String(value ?? ''));
      return Number.isFinite(parsed) ? parsed : fallback;
    };

    const data = {
      classification: (scene.dataset.agentClassification || 'NOT ANALYZED').trim(),
      confidence: numberFromData(scene.dataset.agentConfidence),
      anomaly: numberFromData(scene.dataset.agentAnomaly),
      rule: numberFromData(scene.dataset.agentRuleScore),
      risk: numberFromData(scene.dataset.agentRisk),
      severity: (scene.dataset.agentSeverity || 'WAITING').trim(),
      response: (scene.dataset.agentResponse || 'ADVISORY').trim(),
      action: (scene.dataset.agentAction || 'OBSERVE').trim(),
      source: (scene.dataset.agentSource || 'No source yet').trim(),
      assisted: scene.dataset.agentAssisted === '1',
      strikes: Number.parseInt(scene.dataset.agentStrikes || '0', 10) || 0,
      requiredStrikes: Number.parseInt(scene.dataset.agentRequiredStrikes || '0', 10) || 0
    };

    const classKey = data.classification.toUpperCase().replace(/\s+/g, '_');
    const modelHasFinding = ![
      'NORMAL',
      'NOT_ANALYZED',
      'NOT_ANALYSED',
      'UNKNOWN',
      'WAITING',
      'NO_DATA',
      'DISABLED'
    ].includes(classKey);

    const escalated = Boolean(
      data.risk >= 50 ||
      data.anomaly >= 50 ||
      data.rule >= 50 ||
      modelHasFinding ||
      /(block|ban|deny|strike|challenge|quarantine|lock)/i.test(data.action)
    );

    scene.classList.toggle('fa-agent-escalated', escalated);
    scene.style.setProperty(
      '--fa-agent-transfer-duration',
      escalated ? '.50s' : (window.matchMedia('(max-width: 700px)').matches ? '.78s' : '.68s')
    );

    const anomalyInterpretation =
      data.anomaly >= 70 ? 'strong deviation' :
      data.anomaly >= 50 ? 'elevated deviation' :
      data.anomaly >= 30 ? 'mild deviation' :
      'near-baseline behavior';

    const ruleInterpretation =
      data.rule >= 70 ? 'strong deterministic corroboration' :
      data.rule >= 50 ? 'material deterministic evidence' :
      data.rule >= 20 ? 'partial deterministic evidence' :
      'no material deterministic signature';

    const signalsAligned = Boolean(
      (classKey === 'NORMAL' && data.anomaly < 30 && data.rule < 20) ||
      (modelHasFinding && (data.anomaly >= 30 || data.rule >= 20))
    );

    const compactAgentMesh = Boolean(
      window.matchMedia && window.matchMedia('(max-width: 700px)').matches
    );

    const wait = (delay) => new Promise((resolve) => later(resolve, delay));

    const timing = {
      typing: reduceMotion() ? 80 : (escalated ? 340 : (compactAgentMesh ? 430 : 520)),
      message: reduceMotion() ? 140 : (escalated ? 1050 : (compactAgentMesh ? 1250 : 1450)),
      short: reduceMotion() ? 70 : (escalated ? 180 : 280),
      processing: reduceMotion() ? 120 : (escalated ? 650 : 900),
      monitoring: reduceMotion() ? 300 : (escalated ? 2600 : 5200)
    };

    const consensusPanel = document.getElementById('ai-agent-consensus-panel');
    const consensusTitle = document.getElementById('ai-agent-consensus-title');
    const consensusState = document.getElementById('ai-agent-consensus-state');
    const consensusSummary = document.getElementById('ai-agent-consensus-summary');

    const setConsensus = (phase, title, summary) => {
      if (!consensusPanel) return;

      consensusPanel.classList.toggle('fa-consensus-active', phase !== 'monitoring');
      consensusPanel.classList.toggle('fa-consensus-alert', escalated && phase !== 'monitoring');

      const stateLabels = {
        monitoring: 'MONITORING',
        collecting: 'COLLECTING',
        analyzing: 'ANALYZING',
        correlating: 'CORRELATING',
        threat: 'LIVE HOSTILE ACTIVITY',
        simulation: 'SIMULATED HOSTILE CONTACT',
        consensus: escalated ? 'ACTION READY' : 'CONSENSUS'
      };

      if (consensusTitle) consensusTitle.textContent = title;
      if (consensusState) {
        const dot = consensusState.querySelector('i');
        consensusState.textContent = '';
        if (dot) consensusState.appendChild(dot);
        consensusState.appendChild(
          document.createTextNode(` ${stateLabels[phase] || String(phase).toUpperCase()}`)
        );
      }
      if (consensusSummary) consensusSummary.textContent = summary;
    };

    const panelHost = scene.parentElement;
    let commPanel = panelHost ? panelHost.querySelector('.ai-agent-comm-panel') : null;
    if (!commPanel && panelHost) {
      commPanel = document.createElement('div');
      commPanel.className = 'ai-agent-comm-panel';

      const head = document.createElement('div');
      head.className = 'ai-agent-comm-head';

      const heading = document.createElement('strong');
      heading.textContent = 'Live Mesh Dialogue';

      const state = document.createElement('span');
      state.textContent = 'monitoring';

      const log = document.createElement('div');
      log.className = 'ai-agent-comm-log';
      log.setAttribute('aria-live', 'polite');

      head.append(heading, state);
      commPanel.append(head, log);

      const statusPanel = panelHost.querySelector('.ai-agent-status-panel');
      panelHost.insertBefore(commPanel, statusPanel || null);
    }

    const commLog = commPanel ? commPanel.querySelector('.ai-agent-comm-log') : null;
    const commState = commPanel ? commPanel.querySelector('.ai-agent-comm-head span') : null;

    if (commLog) commLog.textContent = '';

    const setCommState = (text) => {
      if (commState) commState.textContent = text;
    };

    const activeThreats = new Set();
    let collaborationBusy = false;
    let defenseSequenceActive = false;
    let simulatedBurstActive = false;
    let pendingSimulatedContact = false;
    let lastThreatType = '';
    let lastDefensePattern = '';
    let defenseRotation = [];
    let defenseRotationIndex = 0;

    const randomBetween = (min, max) =>
      Math.round(min + (Math.random() * (max - min)));

    const getNodeCenter = (node) => {
      if (!node) return { x: 0, y: 0 };
      const sceneRect = scene.getBoundingClientRect();
      const rect = node.getBoundingClientRect();
      return {
        x: rect.left - sceneRect.left + (rect.width / 2),
        y: rect.top - sceneRect.top + (rect.height / 2)
      };
    };

    const coreCenter = () => getNodeCenter(nodes.core);

    const createThreatNode = (template, index = 0, mode = 'live') => {
      const threat = document.createElement('div');
      threat.className = `fa-threat-node fa-threat-${mode}`;
      threat.dataset.threatType = template.type;
      threat.dataset.origin = template.origin;
      threat.dataset.contactMode = mode;

      const icon = document.createElement('span');
      icon.className = 'fa-threat-icon';

      const iconImage = document.createElement('img');
      iconImage.className = 'fa-threat-image';
      iconImage.src = `/images/${template.image || ''}`;
      iconImage.alt = `${template.label} hostile bot`;
      iconImage.loading = 'eager';
      iconImage.decoding = 'async';
      icon.appendChild(iconImage);

      const label = document.createElement('strong');
      label.className = 'fa-threat-label';
      label.textContent = template.label;

      const detail = document.createElement('small');
      detail.className = 'fa-threat-detail';
      detail.textContent = template.detail;

      const state = document.createElement('span');
      state.className = 'fa-threat-state';
      state.textContent = mode === 'simulated' ? 'SIMULATED HOSTILE' : 'LIVE HOSTILE';

      const quarantine = document.createElement('span');
      quarantine.className = 'fa-threat-quarantine-grid';
      quarantine.setAttribute('aria-hidden', 'true');
      quarantine.append(
        document.createElement('i'),
        document.createElement('i'),
        document.createElement('i'),
        document.createElement('i')
      );

      threat.append(icon, label, detail, state, quarantine);
      attackerLayer.appendChild(threat);
      activeThreats.add(threat);
      return threat;
    };

    const placeThreat = (threat, index = 0) => {
      const sceneRect = scene.getBoundingClientRect();
      const core = coreCenter();
      const orbitRadiusX = Math.max(160, sceneRect.width * .18);
      const orbitRadiusY = Math.max(120, sceneRect.height * .18);
      const spawnPresets = {
        left:  { x: -56, y: 90 + (index * 86) % Math.max(160, sceneRect.height - 140) },
        right: { x: sceneRect.width + 56, y: 116 + (index * 74) % Math.max(150, sceneRect.height - 160) },
        top:   { x: sceneRect.width * (0.22 + ((index * 0.27) % 0.56)), y: -52 }
      };
      const origin = threat.dataset.origin || 'left';
      const start = spawnPresets[origin] || spawnPresets.left;
      const approachOffsets = {
        left:  { x: -orbitRadiusX, y: [-50, 24, 80][index % 3] || -26 },
        right: { x: orbitRadiusX, y: [-46, 28, 78][index % 3] || 18 },
        top:   { x: [-70, 0, 64][index % 3] || 0, y: -orbitRadiusY }
      };
      const offset = approachOffsets[origin] || approachOffsets.left;
      const targetX = core.x + offset.x;
      const targetY = core.y + offset.y;
      threat.style.left = `${start.x}px`;
      threat.style.top = `${start.y}px`;
      threat.dataset.targetLeft = `${targetX}`;
      threat.dataset.targetTop = `${targetY}`;
      return { start, target: { x: targetX, y: targetY } };
    };

    const advanceThreat = (threat) => {
      const targetLeft = Number.parseFloat(threat.dataset.targetLeft || '0');
      const targetTop = Number.parseFloat(threat.dataset.targetTop || '0');
      threat.classList.add('fa-threat-active');
      requestAnimationFrame(() => {
        threat.classList.add('fa-threat-approaching');
        threat.style.left = `${targetLeft}px`;
        threat.style.top = `${targetTop}px`;
      });
    };

    const removeThreat = (threat) => {
      if (!threat) return;
      activeThreats.delete(threat);
      threat.remove();
    };

    const clearThreatVisuals = () => {
      attackerLayer.querySelectorAll('.fa-threat-node').forEach((node) => node.remove());
      defenseLayer.textContent = '';
      activeThreats.clear();
    };

    const emitCoreShield = (mode = 'guard') => {
      const shield = document.createElement('span');
      shield.className = `fa-core-shield fa-core-shield-${mode}`;
      defenseLayer.appendChild(shield);
      later(() => shield.remove(), mode === 'surge' ? 1200 : 980);
    };

    const fireInterceptBeam = (fromKey, threat, tone = fromKey) => {
      const from = getNodeCenter(nodes[fromKey]);
      const sceneRect = scene.getBoundingClientRect();
      const rect = threat.getBoundingClientRect();
      const to = {
        x: rect.left - sceneRect.left + (rect.width / 2),
        y: rect.top - sceneRect.top + (rect.height / 2)
      };
      const dx = to.x - from.x;
      const dy = to.y - from.y;
      const distance = Math.max(1, Math.hypot(dx, dy));
      const angle = Math.atan2(dy, dx) * (180 / Math.PI);
      const beam = document.createElement('span');
      beam.className = 'fa-threat-beam';
      beam.dataset.tone = tone;
      beam.style.left = `${from.x}px`;
      beam.style.top = `${from.y}px`;
      beam.style.width = `${distance}px`;
      beam.style.transform = `rotate(${angle}deg)`;
      beam.style.setProperty('--fa-beam-distance', `${distance}px`);
      defenseLayer.appendChild(beam);
      later(() => beam.remove(), 760);
    };

    const releaseSwarm = (fromKeys, threat, count = 7) => {
      const sceneRect = scene.getBoundingClientRect();
      const threatRect = threat.getBoundingClientRect();
      const targetX = threatRect.left - sceneRect.left + (threatRect.width / 2);
      const targetY = threatRect.top - sceneRect.top + (threatRect.height / 2);

      for (let i = 0; i < count; i += 1) {
        const sourceKey = fromKeys[i % fromKeys.length];
        const from = getNodeCenter(nodes[sourceKey]);
        const packet = document.createElement('span');
        packet.className = 'fa-threat-swarm-packet';
        packet.dataset.tone = sourceKey;
        packet.style.left = `${from.x}px`;
        packet.style.top = `${from.y}px`;
        packet.style.setProperty('--fa-swarm-dx', `${targetX - from.x}px`);
        packet.style.setProperty('--fa-swarm-dy', `${targetY - from.y}px`);
        packet.style.animationDelay = `${i * 48}ms`;
        defenseLayer.appendChild(packet);
        later(() => packet.remove(), 980 + (i * 48));
      }
    };

    const getThreatCenter = (threat) => {
      const sceneRect = scene.getBoundingClientRect();
      const rect = threat.getBoundingClientRect();
      return {
        x: rect.left - sceneRect.left + (rect.width / 2),
        y: rect.top - sceneRect.top + (rect.height / 2)
      };
    };

    const performSlashStrike = (fromKey, threat) => {
      const sourceNode = nodes[fromKey];
      const from = getNodeCenter(sourceNode);
      const to = getThreatCenter(threat);

      const assault = document.createElement('div');
      assault.className = 'fa-threat-assault-clone';
      assault.dataset.tone = fromKey;
      assault.style.left = `${from.x}px`;
      assault.style.top = `${from.y}px`;
      assault.style.setProperty('--fa-assault-dx', `${to.x - from.x}px`);
      assault.style.setProperty('--fa-assault-dy', `${to.y - from.y}px`);

      const assaultIcon = document.createElement('span');
      assaultIcon.className = 'fa-threat-assault-icon';
      const sourceImg = sourceNode?.querySelector('.ai-agent-robot-image');
      if (sourceImg) {
        const img = document.createElement('img');
        img.src = sourceImg.getAttribute('src') || '';
        img.alt = '';
        img.setAttribute('aria-hidden', 'true');
        assaultIcon.appendChild(img);
      }

      const assaultName = document.createElement('strong');
      assaultName.className = 'fa-threat-assault-name';
      assaultName.textContent = sourceNode?.querySelector('strong')?.textContent || 'Agent';

      const assaultAction = document.createElement('small');
      assaultAction.className = 'fa-threat-assault-action';
      assaultAction.textContent = 'Katana slash';

      const katana = document.createElement('span');
      katana.className = 'fa-threat-assault-katana';
      const trail = document.createElement('span');
      trail.className = 'fa-threat-assault-trail';

      assault.append(assaultIcon, assaultName, assaultAction, katana, trail);
      defenseLayer.appendChild(assault);

      const striker = document.createElement('span');
      striker.className = 'fa-threat-striker';
      striker.dataset.tone = fromKey;
      striker.style.left = `${from.x}px`;
      striker.style.top = `${from.y}px`;
      striker.style.setProperty('--fa-strike-dx', `${to.x - from.x}px`);
      striker.style.setProperty('--fa-strike-dy', `${to.y - from.y}px`);
      defenseLayer.appendChild(striker);

      for (let i = 0; i < 4; i += 1) {
        const slash = document.createElement('span');
        slash.className = 'fa-threat-slash-mark';
        slash.style.left = `${to.x + (-18 + (i * 12))}px`;
        slash.style.top = `${to.y + (12 - (i * 8))}px`;
        slash.style.animationDelay = `${120 + (i * 80)}ms`;
        defenseLayer.appendChild(slash);
        later(() => slash.remove(), 980 + (i * 90));
      }

      later(() => assault.remove(), 1180);
      later(() => striker.remove(), 960);
    };

    const emitThreatImpact = (threat, variant = 'default') => {
      const center = getThreatCenter(threat);
      const burst = document.createElement('span');
      burst.className = `fa-threat-impact fa-threat-impact-${variant}`;
      burst.style.left = `${center.x}px`;
      burst.style.top = `${center.y}px`;
      defenseLayer.appendChild(burst);
      later(() => burst.remove(), 920);
    };

    const emitThreatFragments = (threat, variant = 'default', count = 8) => {
      const center = getThreatCenter(threat);
      for (let i = 0; i < count; i += 1) {
        const fragment = document.createElement('span');
        const angle = (Math.PI * 2 * i) / count;
        const distance = 26 + ((i % 3) * 14);
        fragment.className = `fa-threat-fragment fa-threat-fragment-${variant}`;
        fragment.style.left = `${center.x}px`;
        fragment.style.top = `${center.y}px`;
        fragment.style.setProperty('--fa-fragment-x', `${Math.cos(angle) * distance}px`);
        fragment.style.setProperty('--fa-fragment-y', `${Math.sin(angle) * distance}px`);
        fragment.style.animationDelay = `${i * 18}ms`;
        defenseLayer.appendChild(fragment);
        later(() => fragment.remove(), 980 + (i * 18));
      }
    };

    const emitQuarantineSnap = (threat) => {
      const center = getThreatCenter(threat);
      const snap = document.createElement('span');
      snap.className = 'fa-threat-quarantine-snap';
      snap.style.left = `${center.x}px`;
      snap.style.top = `${center.y}px`;
      defenseLayer.appendChild(snap);
      later(() => snap.remove(), 960);
    };

    const repelThreat = (threat, force = 32) => {
      const core = coreCenter();
      const currentLeft = Number.parseFloat(threat.style.left || '0');
      const currentTop = Number.parseFloat(threat.style.top || '0');
      const dx = currentLeft - core.x;
      const dy = currentTop - core.y;
      const distance = Math.max(1, Math.hypot(dx, dy));
      threat.style.left = `${currentLeft + (dx / distance) * force}px`;
      threat.style.top = `${currentTop + (dy / distance) * force}px`;
      threat.classList.add('fa-threat-repelled');
    };

    const quarantineThreat = (threat, finalState = 'QUARANTINED') => {
      threat.classList.remove('fa-threat-approaching');
      threat.classList.add('fa-threat-quarantined');
      const state = threat.querySelector('.fa-threat-state');
      if (state) state.textContent = finalState;
    };

    const engagementCount = escalated
      ? Math.min(2, data.risk >= 82 || data.rule >= 62 || data.strikes >= 2 ? 2 : 1)
      : 0;

    const defensePatterns = [
      { name: 'intercept', label: 'INTERCEPT BEAM', defender: 'rule', effects: ['beam'] },
      { name: 'barrier', label: 'CORE SHIELD', defender: 'core', effects: ['shield', 'repel'] },
      { name: 'swarm', label: 'AGENT SWARM', defender: 'anomaly', effects: ['swarm'] },
      { name: 'quarantine', label: 'QUARANTINE LOCK', defender: 'xgb', effects: ['quarantine'] },
      { name: 'slash', label: 'SLASH STRIKE', defender: 'anomaly', effects: ['slash'] }
    ];

    const shuffleArray = (items) => {
      const copy = items.slice();
      for (let i = copy.length - 1; i > 0; i -= 1) {
        const j = Math.floor(Math.random() * (i + 1));
        [copy[i], copy[j]] = [copy[j], copy[i]];
      }
      return copy;
    };

    const nextDefensePattern = () => {
      if (!defenseRotation.length || defenseRotationIndex >= defenseRotation.length) {
        defenseRotation = shuffleArray(defensePatterns);
        if (lastDefensePattern && defenseRotation[0]?.name === lastDefensePattern && defenseRotation.length > 1) {
          [defenseRotation[0], defenseRotation[1]] = [defenseRotation[1], defenseRotation[0]];
        }
        defenseRotationIndex = 0;
      }
      const pattern = defenseRotation[defenseRotationIndex++];
      lastDefensePattern = pattern.name;
      return pattern;
    };

    const pickThreatTemplate = (preferredIndex = null) => {
      if (Number.isInteger(preferredIndex)) {
        return threatTemplates[preferredIndex % threatTemplates.length];
      }
      let pool = threatTemplates.filter((template) => template.type !== lastThreatType);
      if (!pool.length) pool = threatTemplates.slice();
      const template = pool[Math.floor(Math.random() * pool.length)];
      lastThreatType = template.type;
      return template;
    };

    const pickDefensePattern = (preferredIndex = null) => {
      if (Number.isInteger(preferredIndex)) {
        const pattern = defensePatterns[preferredIndex % defensePatterns.length];
        lastDefensePattern = pattern.name;
        return pattern;
      }
      return nextDefensePattern();
    };

    const showDefenseEffectLabel = (pattern) => {
      const badge = document.createElement('span');
      badge.className = `fa-defense-effect-label fa-defense-effect-${pattern.name}`;
      badge.textContent = pattern.label || pattern.name.toUpperCase();
      defenseLayer.appendChild(badge);
      later(() => badge.classList.add('fa-defense-effect-show'), 30);
      later(() => badge.classList.add('fa-defense-effect-hide'), 1450);
      later(() => badge.remove(), 1900);
    };

    const simulateThreatDefense = async (
      index = 0,
      { mode = 'live', randomize = false, ambient = false } = {}
    ) => {
      defenseSequenceActive = true;
      const template = randomize
        ? pickThreatTemplate()
        : pickThreatTemplate(index + Math.max(0, data.strikes));
      const pattern = randomize
        ? pickDefensePattern()
        : pickDefensePattern(index);
      const threat = createThreatNode(template, index, mode);
      placeThreat(threat, index);

      const simulated = mode === 'simulated';
      if (!ambient) {
        setConsensus(
          simulated ? 'simulation' : 'threat',
          simulated ? 'Simulated hostile contact' : 'Live threat corroboration underway',
          simulated
            ? `Defense drill: a simulated ${template.label.toLowerCase()} node is closing toward the FortressAuth Core. No fake security event or log is being created.`
            : `Live hostile ${template.label.toLowerCase()} activity is closing toward the FortressAuth Core. Agents are intercepting before core contact.`
        );
        setCommState(simulated ? `simulation · ${template.label.toLowerCase()}` : `live intercept · ${template.label.toLowerCase()}`);

        await speakDialogue(
          'telemetry',
          'core',
          simulated
            ? `Simulation contact detected: ${template.label.toLowerCase()} profile. ${template.detail} is approaching the crown-jewel perimeter for a defense drill.`
            : `Live inbound ${template.label.toLowerCase()} node detected. ${template.detail} is approaching the crown-jewel perimeter.`
        );
      }

      advanceThreat(threat);
      await wait(ambient ? 650 : timing.short + 180);

      const contactPrefix = simulated ? 'simulated hostile' : 'live hostile';
      const engageLine = pattern.name === 'barrier'
        ? `FortressAuth Core, raise the shield barrier and reject the ${contactPrefix} ${template.label.toLowerCase()} node before impact.`
        : pattern.name === 'swarm'
          ? `Agents, swarm and neutralize the ${contactPrefix} ${template.label.toLowerCase()} node before it reaches the core.`
          : pattern.name === 'quarantine'
            ? `XGBoost Agent, isolate the ${contactPrefix} ${template.label.toLowerCase()} node and lock it inside the quarantine field.`
            : pattern.name === 'slash'
              ? `Anomaly Agent, close in and slash through the ${contactPrefix} ${template.label.toLowerCase()} node before it reaches the core.`
              : `Rule Agent, fire an intercept beam at the ${contactPrefix} ${template.label.toLowerCase()} node.`;

      if (!ambient) {
        await speakDialogue('core', 'all', engageLine, { duration: timing.message - 120 });
      }

      showDefenseEffectLabel(pattern);

      if (pattern.name === 'intercept') {
        fireInterceptBeam('rule', threat, 'rule');
        later(() => fireInterceptBeam('rule', threat, 'rule'), 110);
        threat.classList.add('fa-threat-engaged');
        await wait(520);
        emitThreatImpact(threat, 'beam');
        emitThreatFragments(threat, 'beam', 10);
        await wait(260);
        threat.classList.add('fa-threat-beam-hit', 'fa-threat-death-beam', 'fa-threat-neutralized');
      } else if (pattern.name === 'barrier') {
        emitCoreShield('surge');
        later(() => emitCoreShield('pulse'), 140);
        threat.classList.add('fa-threat-engaged');
        await wait(340);
        repelThreat(threat, 96);
        emitThreatImpact(threat, 'shield');
        const state = threat.querySelector('.fa-threat-state');
        if (state) state.textContent = 'REPELLED';
        await wait(420);
        emitThreatFragments(threat, 'shield', 8);
        threat.classList.add('fa-threat-death-shield', 'fa-threat-neutralized');
      } else if (pattern.name === 'swarm') {
        releaseSwarm(['telemetry', 'xgb', 'anomaly', 'rule'], threat, 18);
        later(() => releaseSwarm(['telemetry', 'xgb', 'anomaly', 'rule'], threat, 10), 180);
        threat.classList.add('fa-threat-engaged', 'fa-threat-swarm-locked');
        await wait(760);
        emitThreatImpact(threat, 'swarm');
        const state = threat.querySelector('.fa-threat-state');
        if (state) state.textContent = 'NEUTRALIZED';
        emitThreatFragments(threat, 'swarm', 12);
        threat.classList.add('fa-threat-death-swarm', 'fa-threat-neutralized');
      } else if (pattern.name === 'slash') {
        threat.classList.add('fa-threat-engaged');
        performSlashStrike('anomaly', threat);
        await wait(420);
        emitThreatImpact(threat, 'slash');
        emitThreatFragments(threat, 'slash', 12);
        const state = threat.querySelector('.fa-threat-state');
        if (state) state.textContent = 'SLASHED';
        threat.classList.add('fa-threat-slashed', 'fa-threat-death-slash', 'fa-threat-neutralized');
      } else {
        threat.classList.add('fa-threat-engaged');
        await wait(220);
        quarantineThreat(threat, 'QUARANTINED');
        emitQuarantineSnap(threat);
        threat.classList.add('fa-threat-quarantine-locked');
        await wait(820);
        emitThreatImpact(threat, 'quarantine');
        emitThreatFragments(threat, 'quarantine', 8);
        threat.classList.add('fa-threat-death-quarantine', 'fa-threat-neutralized');
      }

      const resultPrefix = simulated ? 'Simulation complete.' : 'Live threat contained.';
      if (!ambient) {
        await speakDialogue(
          pattern.defender === 'core' ? 'rule' : pattern.defender,
          'core',
          pattern.name === 'barrier'
            ? `${resultPrefix} ${template.label} was rejected by the Core shield before impact.`
            : pattern.name === 'swarm'
              ? `${resultPrefix} ${template.label} was surrounded and neutralized by the agent swarm.`
              : pattern.name === 'quarantine'
                ? `${resultPrefix} ${template.label} is frozen inside the quarantine field outside the Core perimeter.`
                : pattern.name === 'slash'
                  ? `${resultPrefix} ${template.label} was slashed apart by the Anomaly Agent before it could touch the Core.`
                  : `${resultPrefix} ${template.label} was stopped by the Rule Agent intercept beam.`,
          { duration: timing.message - 120 }
        );
      }

      threat.classList.add('fa-threat-fade');
      later(() => removeThreat(threat), 620);
      await wait(ambient ? 180 : 260);
      defenseSequenceActive = false;
    };

    const decorateNode = (node, key) => {
      if (!node || node.dataset.agentProcessorReady === '1') return;

      node.dataset.agentProcessorReady = '1';
      node.dataset.agentKey = key;

      const bubble = document.createElement('span');
      bubble.className = 'fa-agent-dialog-bubble';
      bubble.setAttribute('aria-hidden', 'true');

      const route = document.createElement('span');
      route.className = 'fa-agent-dialog-route';

      const typing = document.createElement('span');
      typing.className = 'fa-agent-dialog-typing';
      typing.setAttribute('aria-hidden', 'true');
      typing.append(document.createElement('i'), document.createElement('i'), document.createElement('i'));

      const message = document.createElement('span');
      message.className = 'fa-agent-dialog-text';

      bubble.append(route, typing, message);

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

      node.append(bubble, scan, progress, state);
    };

    const decorateLink = (link) => {
      if (!link || link.dataset.agentProcessorReady === '1') return;

      link.dataset.agentProcessorReady = '1';

      const packet = document.createElement('span');
      packet.className = 'fa-agent-signal-packet';
      packet.setAttribute('aria-hidden', 'true');
      link.appendChild(packet);
    };

    Object.entries(nodes).forEach(([key, node]) => decorateNode(node, key));
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

    const positionConnector = (key) => {
      const connector = connectors[key];
      const target = nodes[key];
      const core = nodes.core;
      if (!connector || !target || !core) return;

      const sceneRect = scene.getBoundingClientRect();
      const coreRect = core.getBoundingClientRect();
      const targetRect = target.getBoundingClientRect();

      const coreX = coreRect.left - sceneRect.left + (coreRect.width / 2);
      const coreY = coreRect.top - sceneRect.top + (coreRect.height / 2);
      const targetX = targetRect.left - sceneRect.left + (targetRect.width / 2);
      const targetY = targetRect.top - sceneRect.top + (targetRect.height / 2);

      const dx = targetX - coreX;
      const dy = targetY - coreY;
      const distance = Math.max(1, Math.hypot(dx, dy));
      const ux = dx / distance;
      const uy = dy / distance;
      const coreInset = Math.min(coreRect.width, coreRect.height) * 0.28;
      const targetInset = Math.min(targetRect.width, targetRect.height) * 0.34;
      const startX = coreX + (ux * coreInset);
      const startY = coreY + (uy * coreInset);
      const endX = targetX - (ux * targetInset);
      const endY = targetY - (uy * targetInset);
      const finalDx = endX - startX;
      const finalDy = endY - startY;
      const finalDistance = Math.max(1, Math.hypot(finalDx, finalDy));
      const angle = Math.atan2(finalDy, finalDx) * (180 / Math.PI);

      connector.style.left = `${startX}px`;
      connector.style.top = `${startY}px`;
      connector.style.width = `${finalDistance}px`;
      connector.style.transform = `rotate(${angle}deg)`;
    };

    const updateConnectors = () => {
      Object.keys(connectors).forEach(positionConnector);
      if (scene.isConnected) {
        window.requestAnimationFrame(updateConnectors);
      }
    };

    const activateConnectors = (keys, duration = 900) => {
      const list = Array.isArray(keys) ? keys : [keys];
      list.forEach((key) => connectors[key]?.classList.add('fa-connector-active'));
      later(() => {
        list.forEach((key) => connectors[key]?.classList.remove('fa-connector-active'));
      }, duration);
    };

    /* Start the dynamic connector tracker only after all connector helpers
       exist. Starting it above this point throws a temporal-dead-zone
       ReferenceError and prevents the entire agent collaboration cycle from
       starting, leaving every card stuck at QUEUED. */
    updateConnectors();

    const focusAgents = (keys = []) => {
      const focusKeys = keys.filter((key) => nodes[key]);
      const enabled = focusKeys.length > 0 && focusKeys.length < Object.keys(nodes).length;

      scene.classList.toggle('fa-agent-focus-mode', enabled);
      Object.entries(nodes).forEach(([key, node]) => {
        if (!node) return;
        node.classList.toggle('fa-agent-focus', !enabled || focusKeys.includes(key));
      });
    };

    const hideDialogue = (key) => {
      const node = nodes[key];
      if (!node) return;
      node.classList.remove('fa-agent-speaking', 'fa-agent-typing');
    };

    const hideAllDialogues = () => {
      Object.keys(nodes).forEach(hideDialogue);
    };

    const appendDialogueLog = (fromKey, toKey, textMessage) => {
      if (!commLog) return;

      const item = document.createElement('div');
      item.className = 'ai-agent-comm-item fa-agent-comm-live';

      const route = document.createElement('div');
      route.className = 'ai-agent-comm-arrow';
      route.textContent = `${names[fromKey] || fromKey} → ${names[toKey] || toKey}`;

      const message = document.createElement('div');
      message.className = 'ai-agent-comm-text';

      const speaker = document.createElement('strong');
      speaker.textContent = fullNames[fromKey] || fromKey;
      message.append(speaker, document.createTextNode(`: ${textMessage}`));

      item.append(route, message);
      commLog.prepend(item);

      while (commLog.children.length > 5) {
        commLog.removeChild(commLog.lastElementChild);
      }

      later(() => item.classList.remove('fa-agent-comm-live'), 1900);
    };

    const transfer = (key, direction, duration = 680) => {
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
      }, duration + 120);
    };

    const peerColors = {
      telemetry: '#61f7bd',
      xgb: '#ffbe74',
      anomaly: '#70ffa4',
      rule: '#d497ff',
      core: '#ecb6ff'
    };

    const peerTransfer = (fromKey, toKey) => {
      const fromNode = nodes[fromKey];
      const toNode = nodes[toKey];
      if (!fromNode || !toNode || reduceMotion()) return;

      const sceneRect = scene.getBoundingClientRect();
      const fromRect = fromNode.getBoundingClientRect();
      const toRect = toNode.getBoundingClientRect();

      const startX = fromRect.left - sceneRect.left + (fromRect.width / 2);
      const startY = fromRect.top - sceneRect.top + (fromRect.height / 2);
      const endX = toRect.left - sceneRect.left + (toRect.width / 2);
      const endY = toRect.top - sceneRect.top + (toRect.height / 2);

      const dx = endX - startX;
      const dy = endY - startY;
      const distance = Math.max(1, Math.hypot(dx, dy));
      const angle = Math.atan2(dy, dx) * (180 / Math.PI);
      const color = peerColors[fromKey] || '#d497ff';

      const lane = document.createElement('span');
      lane.className = 'fa-agent-peer-link';
      lane.style.left = `${startX}px`;
      lane.style.top = `${startY}px`;
      lane.style.width = `${distance}px`;
      lane.style.transform = `rotate(${angle}deg)`;
      lane.style.setProperty('--fa-peer-distance', `${distance}px`);
      lane.style.setProperty('--fa-peer-half-distance', `${distance * 0.52}px`);
      lane.style.background = `linear-gradient(90deg,transparent,${color},rgba(212,151,255,.45),transparent)`;

      const packet = document.createElement('span');
      packet.className = 'fa-agent-peer-packet';
      packet.style.background = color;
      packet.style.boxShadow = `0 0 5px ${color},0 0 13px ${color},0 0 22px rgba(212,151,255,.38)`;

      lane.appendChild(packet);
      scene.appendChild(lane);
      later(() => lane.remove(), 1050);
    };

    const routeSignal = (fromKey, toKey) => {
      const transferDuration = escalated ? 500 : (compactAgentMesh ? 780 : 680);

      if (fromKey === 'core' && toKey === 'all') {
        activateConnectors(Object.keys(connectors), transferDuration + 180);
        Object.keys(links).forEach((key) => transfer(key, 'out', transferDuration));
        return;
      }

      if (toKey === 'all' && fromKey !== 'core') {
        activateConnectors(fromKey === 'telemetry' ? ['telemetry'] : [fromKey], transferDuration + 220);
        Object.keys(nodes)
          .filter((key) => key !== fromKey && key !== 'core')
          .forEach((key, index) => {
            later(() => peerTransfer(fromKey, key), reduceMotion() ? 0 : index * 90);
          });
        return;
      }

      if (fromKey === 'core' && links[toKey]) {
        activateConnectors([toKey], transferDuration + 180);
        transfer(toKey, 'out', transferDuration);
        return;
      }

      if (toKey === 'core' && links[fromKey]) {
        activateConnectors([fromKey], transferDuration + 180);
        transfer(fromKey, 'in', transferDuration);
        return;
      }

      activateConnectors([fromKey, toKey].filter((key) => connectors[key]), transferDuration + 180);
      peerTransfer(fromKey, toKey);
    };

    const speakDialogue = async (
      fromKey,
      toKey,
      textMessage,
      { duration = timing.message, typing = timing.typing, keepFocus = false } = {}
    ) => {
      const fromNode = nodes[fromKey];
      if (!fromNode || !scene.isConnected) return;

      if (compactAgentMesh) hideAllDialogues();
      else hideDialogue(fromKey);

      const focusKeys = toKey === 'all'
        ? Object.keys(nodes)
        : [fromKey, toKey];
      focusAgents(focusKeys);

      const bubble = fromNode.querySelector('.fa-agent-dialog-bubble');
      const route = bubble ? bubble.querySelector('.fa-agent-dialog-route') : null;
      const message = bubble ? bubble.querySelector('.fa-agent-dialog-text') : null;

      if (route) {
        route.textContent = `${names[fromKey] || fromKey} → ${names[toKey] || toKey}`;
      }
      if (message) message.textContent = textMessage;

      fromNode.classList.add('fa-agent-typing');
      setCommState(`${fullNames[fromKey]} typing`);

      await wait(typing);
      if (!scene.isConnected) return;

      fromNode.classList.remove('fa-agent-typing');
      fromNode.classList.add('fa-agent-speaking');
      routeSignal(fromKey, toKey);
      appendDialogueLog(fromKey, toKey, textMessage);
      setCommState(`${fullNames[fromKey]} transmitting`);

      await wait(duration);
      hideDialogue(fromKey);

      if (!keepFocus) focusAgents([]);
    };

    const randomSimulationDelay = () => randomBetween(3000, 9000);

    const runRandomSimulatedContact = async () => {
      if (!scene.isConnected || escalated || defenseSequenceActive || simulatedBurstActive) return false;

      simulatedBurstActive = true;
      defenseSequenceActive = true;
      pendingSimulatedContact = false;
      const burstCount = Math.random() < 0.12 ? 2 : 1;

      for (let index = 0; index < burstCount; index += 1) {
        if (!scene.isConnected) break;
        await simulateThreatDefense(index, { mode: 'simulated', randomize: true, ambient: true });
        if (index + 1 < burstCount) await wait(randomBetween(550, 950));
      }

      defenseSequenceActive = false;
      simulatedBurstActive = false;
      return true;
    };

    const scheduleRandomSimulatedContact = () => {
      later(async () => {
        if (!scene.isConnected) return;
        if (escalated || defenseSequenceActive || simulatedBurstActive) {
          scheduleRandomSimulatedContact();
          return;
        }
        await runRandomSimulatedContact();
        scheduleRandomSimulatedContact();
      }, randomSimulationDelay());
    };

    const reset = () => {
      scene.classList.remove('fa-agent-core-fusing', 'fa-agent-monitoring');
      focusAgents([]);
      hideAllDialogues();

      Object.keys(nodes).forEach((key) => setNodeState(key, 'queued'));
      Object.keys(statusMap).forEach((key) => setStatusCard(key, false));

      Object.values(links).forEach((link) => {
        if (!link) return;
        link.classList.remove(
          'fa-agent-transfer-in',
          'fa-agent-transfer-out',
          'fa-agent-link-active'
        );
      });

      clearThreatVisuals();
    };

    const runCycle = async () => {
      collaborationBusy = true;
      while ((defenseSequenceActive || simulatedBurstActive) && scene.isConnected) {
        await wait(180);
      }
      reset();
      if (!scene.isConnected) return;

      setConsensus(
        'collecting',
        'Telemetry window is being prepared',
        `The mesh is collecting non-sensitive behavior signals for ${data.source}.`
      );
      setCommState('collecting telemetry');

      setNodeState('telemetry', 'processing', 'Collecting');
      setStatusCard('telemetry', true);
      await speakDialogue(
        'telemetry',
        'core',
        `Behavior window sealed for ${data.source}. Non-sensitive request and authentication signals are ready.`
      );
      setNodeState('telemetry', 'complete', 'Window ready');
      setStatusCard('telemetry', false);

      await wait(timing.short);

      setConsensus(
        'analyzing',
        'Specialist analysis in progress',
        'FortressAuth Core is distributing the same behavior window to classification, anomaly, and deterministic-rule specialists.'
      );
      setNodeState('core', 'processing', 'Dispatching');

      await speakDialogue(
        'core',
        'xgb',
        'Classify the current behavior pattern and report confidence.'
      );
      setNodeState('xgb', 'processing', 'Classifying');
      setStatusCard('xgb', true);

      await speakDialogue(
        'core',
        'anomaly',
        'Compare this behavior window against the learned normal baseline.'
      );
      setNodeState('anomaly', 'processing', 'Analyzing');
      setStatusCard('anomaly', true);

      await speakDialogue(
        'core',
        'rule',
        'Validate deterministic FortressAuth evidence and known signatures.'
      );
      setNodeState('rule', 'processing', 'Validating');
      setStatusCard('rule', true);
      setNodeState('core', 'complete', 'Awaiting reports');

      await wait(timing.processing);

      setNodeState('xgb', 'complete', 'Classified');
      setStatusCard('xgb', false);
      await speakDialogue(
        'xgb',
        'core',
        `Classification complete: ${data.classification} at ${data.confidence.toFixed(1)}% confidence.`
      );

      setNodeState('anomaly', 'complete', 'Scored');
      setStatusCard('anomaly', false);
      await speakDialogue(
        'anomaly',
        'core',
        `Baseline analysis complete: ${data.anomaly.toFixed(1)}% deviation, interpreted as ${anomalyInterpretation}.`
      );

      await speakDialogue(
        'anomaly',
        'xgb',
        signalsAligned
          ? `My deviation result supports your ${data.classification} classification.`
          : `My deviation result does not fully align with your ${data.classification} classification. Preserve both signals for fusion.`,
        { duration: timing.message - 100 }
      );

      setNodeState('rule', 'complete', 'Validated');
      setStatusCard('rule', false);
      await speakDialogue(
        'rule',
        'core',
        `Deterministic validation complete: ${data.rule.toFixed(1)}/100 evidence, ${ruleInterpretation}.`
      );

      await speakDialogue(
        'rule',
        'xgb',
        signalsAligned
          ? 'Deterministic evidence is consistent with the model posture. Corroboration status is aligned.'
          : 'Model and deterministic evidence are mixed. No single agent should decide enforcement alone.',
        { duration: timing.message - 80 }
      );

      await speakDialogue(
        'xgb',
        'rule',
        signalsAligned
          ? 'Acknowledged. Classification and rule evidence are aligned. Returning both signals to Core.'
          : 'Acknowledged. I will keep my confidence score separate so Core can apply guarded fusion.',
        { duration: timing.message - 120 }
      );

      setConsensus(
        'correlating',
        'Correlating specialist evidence',
        'The Core is combining XGBoost confidence, anomaly deviation, and deterministic rule evidence into the guarded hybrid risk score.'
      );
      scene.classList.add('fa-agent-core-fusing');
      setNodeState('core', 'processing', 'Fusing signals');
      await wait(timing.short);

      const strikeText = data.strikes > 0 && data.requiredStrikes > 0
        ? ` Strike state ${data.strikes}/${data.requiredStrikes}.`
        : '';

      await speakDialogue(
        'core',
        'all',
        `Consensus reached: hybrid risk ${data.risk.toFixed(1)}/100, posture ${data.severity}. Response ${data.response}; action ${data.action}.${strikeText}`,
        { duration: timing.message + 250, typing: timing.typing + 80, keepFocus: true }
      );

      setNodeState('core', 'complete', 'Decision ready');
      scene.classList.remove('fa-agent-core-fusing');
      focusAgents([]);

      setConsensus(
        'consensus',
        escalated ? 'Guarded response decision ready' : 'Consensus reached',
        `The synchronized agents produced ${data.risk.toFixed(1)}/100 hybrid risk for ${data.source}. Current action: ${data.action}.`
      );
      setCommState(escalated ? 'guarded response ready' : 'consensus reached');

      if (engagementCount > 0) {
        for (let threatIndex = 0; threatIndex < engagementCount; threatIndex += 1) {
          await wait(timing.short + (threatIndex === 0 ? 320 : 180));
          await simulateThreatDefense(threatIndex, { mode: 'live', randomize: false });
        }
        setConsensus(
          'consensus',
          'Core perimeter preserved',
          `Hostile approach indicators were intercepted and quarantined outside the FortressAuth Core. Guarded action remains ${data.action}.`
        );
        setCommState('threats blocked · perimeter stable');
      } else {
        await wait(timing.short + 500);
      }

      await speakDialogue(
        'core',
        'telemetry',
        escalated
          ? `Maintain a tighter behavior window for ${data.source}. Continue feeding fresh evidence while guarded controls remain authoritative.`
          : `Maintain normal monitoring for ${data.source}. Continue feeding fresh telemetry without escalating controls.`,
        { duration: timing.message - 80 }
      );

      await speakDialogue(
        'telemetry',
        'all',
        'Acknowledged. Next behavior window is queued. All agents remain synchronized.',
        { duration: timing.message - 120 }
      );

      scene.classList.add('fa-agent-monitoring');
      setNodeState('telemetry', 'complete', 'Monitoring');
      setNodeState('xgb', 'complete', 'Standing by');
      setNodeState('anomaly', 'complete', 'Standing by');
      setNodeState('rule', 'complete', 'Standing by');
      setNodeState('core', 'complete', 'Synchronized');
      focusAgents([]);
      hideAllDialogues();

      setConsensus(
        'monitoring',
        'Agent mesh synchronized',
        `Monitoring ${data.source}. Simulated hostile contacts may appear at irregular intervals while real elevated detections take priority.`
      );
      setCommState('monitoring · synchronized');
      collaborationBusy = false;

      await wait(timing.monitoring);
      while ((defenseSequenceActive || simulatedBurstActive) && scene.isConnected) {
        await wait(350);
      }
      if (scene.isConnected) runCycle();
    };

    scheduleRandomSimulatedContact();
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

    Object.entries(nodes).forEach(([key, node]) => decorateNode(node, key));

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

                /* 4) Send final hybrid risk and corroboration state to the authoritative shield. */
                flyPacket('hybrid', 'shield', { purple: true });

                later(() => {
                  setNodeState('shield', 'processing', 'Applying posture');
                  setFeedActive('hybrid');
                  setRotator('FortressAuth Shield is evaluating guarded AI-assisted enforcement...');

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
      'Hybrid engine is fusing signals into one guarded defense score.'
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
