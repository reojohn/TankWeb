/* Aegis AI · Lightweight interface enhancements.
 * Only presentation and navigation: no changes to the detection engine, data
 * loading, saved case status, API requests or chat state machines.
 */
(() => {
  'use strict';
  const nav = [...document.querySelectorAll('.sidebar .nav-link[data-view]')];
  const topbar = document.querySelector('.topbar');
  if (!topbar || !nav.length) return;
  const svgIcon = (path) => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox','0 0 24 24');
    svg.setAttribute('aria-hidden','true');
    svg.setAttribute('focusable','false');
    svg.innerHTML = path; // All paths below are fixed, application-authored SVG markup.
    return svg;
  };
  const icons = {
    chart: '<path d="M4 20V10M10 20V4M16 20v-8M22 20v-5"/>',
    data: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7"/>',
    shield: '<path d="M12 2 4 6v6c0 5 3 8 8 10 5-2 8-5 8-10V6Z"/><path d="m9 12 2 2 4-4"/>',
    file: '<path d="M8 3h9l4 4v14H5V3Z"/><path d="M16 3v5h5M8 12h10M8 16h10"/>',
    activity: '<path d="M2 12h5l3-7 4 14 3-7h5"/>',
    layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/>',
    spark: '<path d="m12 2 1.7 6.3L20 10l-6.3 1.7L12 18l-1.7-6.3L4 10l6.3-1.7L12 2ZM19 16l.7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7L19 16Z"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    clipboard: '<rect x="5" y="5" width="14" height="17" rx="2"/><path d="M9 3h6l1 4H8l1-4ZM9 12h6M9 16h5"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m16 16 5 5"/>',
    arrow: '<path d="m12 5 0 14M5 12l7-7 7 7"/>',
    maximize: '<path d="M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5"/>',
    minimize: '<path d="M3 8h5V3M21 8h-5V3M3 16h5v5M21 16h-5v5"/>'
  };
  const iconFor = label => {
    const s=label.toLowerCase();
    if(/matrix|metric|accuracy|performance|importance|distribution|analytics|recall|chart/.test(s))return icons.chart;
    if(/dataset|feature|training|split|input|quality|consistency/.test(s))return icons.data;
    if(/threat|mitigat|control|security|defense|response|risk/.test(s))return icons.shield;
    if(/report|document|research|scope|evidence|audit|finding/.test(s))return icons.file;
    if(/timeline|recent|assessment|status|validation|test cases|examples/.test(s))return icons.activity;
    if(/protocol|method|architecture|pipeline|interpretation/.test(s))return icons.layers;
    if(/verification|check/.test(s))return icons.check;
    return icons.spark;
  };
  // Decorate headings once, without changing their text or event handlers.
  document.querySelectorAll('.view .panel-head h2, .view .panel > h2').forEach(heading => {
    if (heading.querySelector('.luxe-panel-symbol')) return;
    heading.classList.add('luxe-panel-title');
    const marker=document.createElement('span');
    marker.className='luxe-panel-symbol';
    marker.setAttribute('aria-hidden','true');
    marker.append(svgIcon(iconFor(heading.textContent || '')));
    heading.prepend(marker);
  });
  // Quickly jump across the nine pages using their existing navigation handlers.
  const action = document.createElement('button');
  action.type='button'; action.className='luxe-quick-button';
  action.setAttribute('aria-label','Quick navigation. Keyboard shortcut Control K');
  action.append(svgIcon(icons.search));
  const actionText=document.createElement('span');actionText.className='luxe-quick-label';actionText.textContent='Quick jump'; action.append(actionText);
  const keyHint=document.createElement('kbd');keyHint.textContent='Ctrl K';action.append(keyHint);
  const right=topbar.querySelector('.topbar-right');
  right?.prepend(action);
  const dialog=document.createElement('dialog');
  dialog.className='luxe-quick-dialog';dialog.setAttribute('aria-label','Quick navigation');
  const heading=document.createElement('div');heading.className='luxe-quick-heading';
  const headline=document.createElement('span');headline.textContent='Jump to workspace';
  const close=document.createElement('button');close.type='button';close.className='luxe-quick-close';close.setAttribute('aria-label','Close quick navigation');close.textContent='×';
  heading.append(headline,close);
  const searchWrap=document.createElement('label');searchWrap.className='luxe-quick-search';
  searchWrap.append(svgIcon(icons.search));
  const input=document.createElement('input');input.type='search';input.autocomplete='off';input.setAttribute('aria-label','Search workspace pages');input.placeholder='Search pages, findings, reports…';
  searchWrap.append(input);
  const list=document.createElement('div');list.className='luxe-quick-list';list.setAttribute('aria-label','Available pages');
  const foot=document.createElement('div');foot.className='luxe-quick-footer';foot.textContent='Enter to open  ·  ↑ ↓ to navigate  ·  Esc to close';
  dialog.append(heading,searchWrap,list,foot);document.body.append(dialog);
  const pageNames=nav.map((link,i)=>({link,label:link.querySelector('span:nth-child(2)')?.textContent.trim() || link.dataset.view,index:i+1}));
  const renderOptions=()=>{
    const q=input.value.trim().toLowerCase();
    list.replaceChildren();
    const options=pageNames.filter(p=>p.label.toLowerCase().includes(q)||p.link.dataset.view.toLowerCase().includes(q));
    if(!options.length){const empty=document.createElement('p');empty.className='luxe-quick-empty';empty.textContent='No matching pages';list.append(empty);return;}
    options.forEach(p=>{
      const item=document.createElement('button');item.type='button';item.className='luxe-quick-item';
      const count=document.createElement('span');count.className='luxe-quick-index';count.textContent=String(p.index).padStart(2,'0');
      const text=document.createElement('span');text.textContent=p.label;
      const arrow=document.createElement('span');arrow.className='luxe-quick-arrow';arrow.textContent='↗';arrow.setAttribute('aria-hidden','true');
      item.append(count,text,arrow);
      item.addEventListener('click',()=>{dialog.close();p.link.click();});
      list.append(item);
    });
  };
  const openQuick=()=>{
    if(typeof dialog.showModal!=='function')return;
    if(!dialog.open){input.value='';renderOptions();dialog.showModal();input.focus();}
  };
  action.addEventListener('click',openQuick);
  close.addEventListener('click',()=>dialog.close());
  dialog.addEventListener('click',e=>{if(e.target===dialog)dialog.close();});
  input.addEventListener('input',renderOptions);
  input.addEventListener('keydown',e=>{
    if(e.key==='ArrowDown'||e.key==='ArrowUp'){
      e.preventDefault();const items=[...list.querySelectorAll('.luxe-quick-item')];
      if(items.length)(e.key==='ArrowDown'?items[0]:items[items.length-1]).focus();
    }
    if(e.key==='Enter'){
      const first=list.querySelector('.luxe-quick-item');if(first){e.preventDefault();first.click();}
    }
  });
  list.addEventListener('keydown',e=>{
    if(!['ArrowDown','ArrowUp'].includes(e.key))return;
    const items=[...list.querySelectorAll('.luxe-quick-item')],index=items.indexOf(document.activeElement);
    if(index<0)return;e.preventDefault();items[(index+(e.key==='ArrowDown'?1:items.length-1))%items.length]?.focus();
  });
  document.addEventListener('keydown',e=>{
    if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){
      e.preventDefault();if(dialog.open)dialog.close();else openQuick();
    }
  });
  // Subtle page read-progress and a back-to-top affordance, both throttled to frames.
  const track=document.createElement('div');track.id='luxe-scroll-track';track.setAttribute('aria-hidden','true');
  const progress=document.createElement('div');progress.id='luxe-scroll-progress';track.append(progress);topbar.append(track);
  const toTop=document.createElement('button');toTop.type='button';toTop.className='luxe-to-top';toTop.setAttribute('aria-label','Scroll to top of page');toTop.dataset.visible='false';toTop.append(svgIcon(icons.arrow));document.body.append(toTop);
  const reduceMotion=window.matchMedia?.('(prefers-reduced-motion: reduce)');
  toTop.addEventListener('click',()=>window.scrollTo({top:0,behavior:reduceMotion?.matches?'auto':'smooth'}));
  let scheduled=false;
  const refreshScroll=()=>{
    scheduled=false;
    const page=document.documentElement;
    const max=Math.max(0,page.scrollHeight-window.innerHeight);
    const fraction=max?Math.max(0,Math.min(1,window.scrollY/max)):0;
    progress.style.transform=`scaleX(${fraction.toFixed(4)})`;
    toTop.dataset.visible=String(window.scrollY>480);
  };
  const scheduleScroll=()=>{if(!scheduled){scheduled=true;requestAnimationFrame(refreshScroll);}};
  window.addEventListener('scroll',scheduleScroll,{passive:true});
  window.addEventListener('resize',scheduleScroll,{passive:true});
  // Preserve the long lists but allow them to scroll or expand on demand.
  const surfaces=[
    {selector:'#findings-timeline',caption:'Scroll through findings'},
    {selector:'#dynamic-report-preview',caption:'Scroll through report rows'},
    {selector:'#example-list',caption:'Scroll through examples'},
    {selector:'#rubric-a-inspection',caption:'Scroll through case-study evidence'},
    {selector:'#rubric-d-case-plan',caption:'Scroll through the response plan'},
    {selector:'#rubric-e-documentation',caption:'Scroll through research methodology'}
  ];
  surfaces.forEach(({selector,caption})=>{
    const target=document.querySelector(selector);if(!target)return;
    const toolbar=document.createElement('div');toolbar.className='luxe-scroll-toolbar';
    const note=document.createElement('span');note.className='luxe-scroll-hint';note.textContent=caption;
    const btn=document.createElement('button');btn.className='luxe-expand-btn';btn.type='button';btn.setAttribute('aria-expanded','false');
    let graphic=svgIcon(icons.maximize);
    const label=document.createElement('span');label.textContent='Expand list';
    btn.append(graphic,label);
    btn.addEventListener('click',()=>{
      const expanded=target.classList.toggle('luxe-scroll-expanded');
      btn.setAttribute('aria-expanded',String(expanded));
      const nextGraphic=svgIcon(expanded?icons.minimize:icons.maximize);
      graphic.replaceWith(nextGraphic);graphic=nextGraphic;
      label.textContent=expanded?'Use compact view':'Expand list';
      scheduleScroll();
    });
    // Avoid duplicating existing action buttons in their panel header.
    toolbar.append(note,btn);target.before(toolbar);
  });
  // keep progress correct on route changes; navigation is owned by site.js.
  nav.forEach(link=>link.addEventListener('click',()=>{scheduleScroll();requestAnimationFrame(scheduleScroll);}));
  window.addEventListener('hashchange',()=>requestAnimationFrame(scheduleScroll));
  requestAnimationFrame(scheduleScroll);
})();
