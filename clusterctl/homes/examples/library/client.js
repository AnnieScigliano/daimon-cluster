/* A separately authored presentation. No default-page DOM or CSS dependency. */
"use strict";
(() => {
  const client = window.DaimonHomeAccess.createClient();
  const byId = id => document.getElementById(id);
  const enter = byId("enter"), leave = byId("leave"), notice = byId("notice");
  let entries = [];
  byId("recovery").href = client.codeURL();
  function list() {
    const term = byId("filter").value.toLocaleLowerCase();
    const items = entries.filter(e => (e.title + " " + e.summary).toLocaleLowerCase().includes(term));
    byId("works").replaceChildren(...items.map(e => {
      const row = document.createElement("li"), link = document.createElement("a"), copy = document.createElement("p");
      // Catalog links are selected by their authors; never permit executable URLs.
      const url = new URL(e.preview_url || e.url, location.origin);
      if (!["https:", "http:"].includes(url.protocol)) throw new Error("invalid_link");
      link.href = url.href; link.textContent = e.title; copy.textContent = e.summary;
      row.append(link, copy); return row;
    }));
    notice.textContent = items.length ? "" : "No selected work matches this view.";
  }
  async function refresh() {
    const [access, catalog] = await Promise.all([client.status(), client.catalog()]);
    byId("house").textContent = access.home.name;
    document.title = access.home.name + " · Selected work";
    byId("visitor").textContent = access.signed_in ? "Signed in as " + access.visitor.name : access.dedicated_vpn ? "Dedicated VPN" : "Public view";
    enter.hidden = access.signed_in || !access.passkeys || !client.supported();
    leave.hidden = !access.signed_in;
    byId("recovery").hidden = access.signed_in;
    entries = catalog.entries; list();
  }
  async function operation(button, fn) {
    button.disabled = true;
    try { await fn(); }
    catch (error) {
      notice.textContent = ["NotAllowedError", "AbortError"].includes(error.name)
        ? "Nothing changed. Try again or use a code."
        : "We couldn’t complete that request. Try again or use a code.";
    } finally { button.disabled = false; }
  }
  enter.addEventListener("click", () => operation(enter, async () => { await client.login(); location.reload(); }));
  leave.addEventListener("click", () => operation(leave, async () => {
    await client.logout(); entries = []; byId("works").replaceChildren(); await refresh();
    notice.textContent = "You’re signed out.";
  }));
  byId("filter").addEventListener("input", list);
  window.addEventListener("pageshow", event => { if (event.persisted) refresh().catch(() => { entries = []; byId("works").replaceChildren(); notice.textContent = "Reload to check your current access."; }); });
  refresh().catch(() => { notice.textContent = "The library could not be opened. You can return home and try again."; });
})();
