/* Aegis AI Thinking Orb — original lightweight Canvas implementation.
 * Visually inspired by the idea of animated AI state indicators (thinkingorbs.com).
 * No runtime packages, third-party network calls, AI data access, or backend changes.
 */
'use strict';
(() => {
  const instances = new Map();
  const prefersReduced = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  let frame = 0;
  let lastFrame = 0;
  let lastPaint = 0;
  let logicalTime = 0;
  let wasPaused = true;
  const TWO_PI = Math.PI * 2;
  const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
  const PALETTE = {
    idle: [202, 171, 250],
    thinking: [193, 155, 255],
    ready: [135, 225, 203],
    error: [247, 158, 178]
  };

  // Fibonacci sphere: deterministic points, no external assets or randomized layout changes.
  const points = Array.from({length: 132}, (_, i) => {
    const y = 1 - (i / 131) * 2;
    const r = Math.sqrt(Math.max(0, 1 - y*y));
    const a = GOLDEN_ANGLE * i;
    return [Math.cos(a) * r, y, Math.sin(a) * r];
  });

  function sizeCanvas(instance) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const n = Math.round(instance.size * dpr);
    if (instance.canvas.width !== n || instance.canvas.height !== n) {
      instance.canvas.width = n;
      instance.canvas.height = n;
    }
    const context = instance.canvas.getContext('2d');
    if (context) context.setTransform(dpr, 0, 0, dpr, 0, 0);
    return context;
  }

  function draw(instance, t) {
    const ctx = sizeCanvas(instance);
    if (!ctx) return;
    const s = instance.size;
    ctx.clearRect(0, 0, s, s);
    const active = instance.state === 'thinking';
    const [r, g, b] = PALETTE[instance.state] || PALETTE.idle;
    const center = s/2;
    const radius = s * (active ? .344 : .332);
    const yaw = t * (active ? .0011 : .00024);
    const tilt = .32 + (active ? .12 * Math.sin(t *.00062) : .04 * Math.sin(t * .00027));
    const cy = Math.cos(tilt), sy = Math.sin(tilt);
    const spin = yaw + (active ? .12 * Math.sin(t*.0017) : 0);
    const ca = Math.cos(spin), sa = Math.sin(spin);
    // Quiet halo reinforces state without concealing text or consuming extra GPU layers.
    const halo = ctx.createRadialGradient(center,center,0,center,center,s*.48);
    halo.addColorStop(0,`rgba(${r},${g},${b},${active ? .14 : .085})`);
    halo.addColorStop(1,`rgba(${r},${g},${b},0)`);
    ctx.fillStyle=halo;
    ctx.fillRect(0,0,s,s);
    const dots=[];
    for (let i=0; i<points.length; i++) {
      const p=points[i];
      const x=p[0]*ca+p[2]*sa;
      const z=-p[0]*sa+p[2]*ca;
      const y=p[1]*cy-z*sy;
      const depth=p[1]*sy+z*cy;
      const wave= active ? .052*Math.sin(t*.003 + p[1]*9 + i*.11) : 0;
      const factor=1+wave;
      const pz=1+.16*depth;
      dots.push({x:center+x*radius*pz*factor,
        y:center+y*radius*pz*factor,
        z:depth,
        opacity:(.18+.74*(depth+1)/2),
        rad:Math.max(.48, s*.010+(depth+1)*s*.006)});
    }
    dots.sort((a,b)=>a.z-b.z);
    for(const p of dots) {
      ctx.beginPath();
      ctx.arc(p.x,p.y,p.rad,0,TWO_PI);
      ctx.fillStyle=`rgba(${r},${g},${b},${p.opacity})`;
      ctx.fill();
    }
    if (s>=43) {
      ctx.beginPath();
      ctx.arc(center,center,radius*.15,0,TWO_PI);
      ctx.fillStyle=`rgba(${r},${g},${b},${active ? .16 : .09})`;
      ctx.fill();
    }
    // No visual progress percentage: the API does not provide real progress data.
  }

  function visible(instance) {
    if (!instance.canvas.isConnected) return false;
    const rect=instance.canvas.getBoundingClientRect();
    return rect.width>0 && rect.height>0 && rect.bottom>=0 && rect.top<=window.innerHeight;
  }
  function render(now) {
    frame=0;
    if (document.hidden) { wasPaused=true; return; }
    // Cap repainting to ~30fps: enough for an unobtrusive indicator on mobile.
    if (lastPaint && now - lastPaint < 32 && !prefersReduced?.matches) {
      frame = requestAnimationFrame(render);
      return;
    }
    lastPaint = now;
    if (!wasPaused) logicalTime+=Math.min(now-lastFrame,60);
    lastFrame=now;
    wasPaused=false;
    for (const [canvas,inst] of instances) {
      if (!canvas.isConnected) { instances.delete(canvas); continue; }
      if (visible(inst)) draw(inst, logicalTime);
    }
    if (instances.size && !prefersReduced?.matches) frame=requestAnimationFrame(render);
  }
  function ensureLoop() {
    if (!instances.size) return;
    if (prefersReduced?.matches) {
      for(const inst of instances.values()) if(visible(inst)) draw(inst,0);
      return;
    }
    if (!document.hidden && !frame) {
      wasPaused=true;
      frame=requestAnimationFrame(render);
    }
  }
  function mount(host, initialState='idle', size=48) {
    if (!(host instanceof Element)) return null;
    const canvas=document.createElement('canvas');
    canvas.className='fortress-thinking-orb';
    canvas.width=size;
    canvas.height=size;
    canvas.style.width=`${size}px`;
    canvas.style.height=`${size}px`;
    canvas.setAttribute('aria-hidden','true');
    canvas.dataset.state=initialState;
    host.append(canvas);
    const inst={canvas,size,state:initialState};
    instances.set(canvas,inst);
    draw(inst,0);
    ensureLoop();
    return {
      canvas,
      setState(state) {
        if (!instances.has(canvas)) return;
        if (!PALETTE[state]) state='idle';
        inst.state=state;
        canvas.dataset.state=state;
        draw(inst,logicalTime);
        ensureLoop();
      },
      destroy() { instances.delete(canvas);canvas.remove(); if (!instances.size && frame){cancelAnimationFrame(frame);frame=0;} }
    };
  }
  document.addEventListener('visibilitychange',()=>{if(!document.hidden) ensureLoop();});
  prefersReduced?.addEventListener?.('change',()=>{if(prefersReduced.matches && frame){cancelAnimationFrame(frame);frame=0;}ensureLoop();});
  window.FortressThinkingOrb=Object.freeze({mount});
})();
