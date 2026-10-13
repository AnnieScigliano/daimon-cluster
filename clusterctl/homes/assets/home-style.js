/* Foreground appearance reconciliation. Style data never authorizes access. */
"use strict";
(() => {
  const names={background:['--space','--home-background'],surface:['--panel','--panel2','--home-surface'],text:['--ink','--muted','--home-text'],accent:['--cyan','--amber','--mauve','--line','--home-accent'],bodyFont:['--home-font'],headingFont:['--home-heading-font'],radius:['--home-radius'],gap:['--home-gap']};
  let current=null, pending=false, timer;
  const match=location.pathname.match(/^\/view\/([a-f0-9]{32})$/);
  const surface=match?match[1]:'home';
  const listeners=new Set();
  function publish(frame) { if(current) frame.contentWindow?.postMessage({type:'home-artifact:style',contract:'homemaker.appearance/v1',appearance:current.appearance}, '*'); }
  async function refresh() {
    if(pending) return;
    pending=true;
    try {
      const response=await fetch('/style.json?surface='+surface,{credentials:'same-origin',redirect:'error'});
      if(!response.ok) return;
      const value=await response.json(), a=value.appearance;
      if(value.contract!=='homemaker.resolved/v1') return;
      if(a && (!['background','surface','text','accent'].every(k=>/^#[a-f0-9]{6}$/i.test(a[k])) || !['bodyFont','headingFont'].every(k=>typeof a[k]==='string' && a[k].length<128 && /^[A-Za-z0-9 ,\"'-]+$/.test(a[k])) || !['0px','12px'].includes(a.radius) || !['12px','24px'].includes(a.gap) || !['dark','light'].includes(a.scheme))) return;
      for(const [key,vars] of Object.entries(names)) for(const name of vars) {
        if(a) document.documentElement.style.setProperty(name,a[key]); else document.documentElement.style.removeProperty(name);
      }
      if(a) { document.documentElement.style.colorScheme=a.scheme; document.body.style.fontFamily=a.bodyFont; }
      else { document.documentElement.style.removeProperty('color-scheme');document.body.style.removeProperty('font-family'); }
      current=value;
      document.querySelectorAll('iframe.preview').forEach(frame=>{publish(frame);if(!listeners.has(frame)){frame.addEventListener('load',()=>publish(frame));listeners.add(frame);}});
      window.dispatchEvent(new CustomEvent('home-style:resolved',{detail:{mode:value.mode,design_ref:value.design_ref,design_revision:value.design_revision}}));
    } catch { /* Keep the last valid accessible presentation. */ }
    finally {pending=false;}
  }
  function foreground() {
    clearTimeout(timer);
    if(document.visibilityState!=='visible')return;
    refresh();
    timer=setTimeout(foreground,15000);
  }
  const channel=typeof BroadcastChannel==='function'?new BroadcastChannel('dm.home-style/v1'):null;
  if(channel)channel.addEventListener('message',()=>refresh());
  window.addEventListener('pageshow',foreground);
  window.addEventListener('pagehide',()=>clearTimeout(timer));
  document.addEventListener('visibilitychange',foreground);
  window.addEventListener('home-style:refresh',()=>{refresh();channel?.postMessage('changed');});
  foreground();
})();
