// This bridge carries only a fragment within the selected work. Artifact
// messages cannot select a resource, change audience or invoke owner APIs.
'use strict';
const frame = document.querySelector('iframe[data-src]');
const validFragment = value => typeof value === 'string' && value.length < 2048 && /^(?:#[A-Za-z0-9/_-]*)?$/.test(value);
if (frame) {
  function openFragment() {
    if (!validFragment(location.hash)) return;
    const source = new URL(frame.dataset.src);
    if (source.href + location.hash !== frame.src) {
      source.hash = location.hash;
      frame.src = source.href;
    }
  }
  openFragment();
  window.addEventListener('hashchange', openFragment);
  window.addEventListener('message', event => {
    if (event.source !== frame.contentWindow || event.origin !== 'null') return;
    if (event.data?.type !== 'home-artifact:fragment' || !validFragment(event.data.fragment)) return;
    history.replaceState(null, '', location.pathname + location.search + event.data.fragment);
  });
}
