/* Optional consumer for sandboxed work. Receives appearance, never credentials. */
"use strict";
(() => {
  if(window.parent===window || document.documentElement.dataset.styleSelection==='explicit')return;
  const names={background:['--space','--home-background'],surface:['--panel','--panel2','--home-surface'],text:['--ink','--muted','--home-text'],accent:['--cyan','--amber','--mauve','--line','--home-accent'],bodyFont:['--home-font'],headingFont:['--home-heading-font'],radius:['--home-radius'],gap:['--home-gap']};
  window.addEventListener('message',event=>{
    if(event.source!==parent || !/^https:\/\/[^/]+$/.test(event.origin) || event.data?.type!=='home-artifact:style' || event.data.contract!=='homemaker.appearance/v1') return;
    const a=event.data.appearance;
    if(a!==null && (!a || !['background','surface','text','accent'].every(k=>/^#[a-f0-9]{6}$/i.test(a[k])) || !['bodyFont','headingFont'].every(k=>typeof a[k]==='string' && a[k].length<128 && /^[A-Za-z0-9 ,\"'-]+$/.test(a[k])) || !['0px','12px'].includes(a.radius) || !['12px','24px'].includes(a.gap) || !['dark','light'].includes(a.scheme)))return;
    for(const [key,vars]of Object.entries(names))for(const name of vars){if(a)document.documentElement.style.setProperty(name,a[key]);else document.documentElement.style.removeProperty(name);}
    if(a){document.documentElement.style.colorScheme=a.scheme;document.body.style.fontFamily=a.bodyFont;}else{document.documentElement.style.removeProperty('color-scheme');document.body.style.removeProperty('font-family');}
  });
})();
