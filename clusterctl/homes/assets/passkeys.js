/* Default-page adapter. Auth capabilities live in access-client.js. */
"use strict";
(() => {
  const action = document.getElementById("passkey-action");
  const status = document.getElementById("passkey-status");
  if (!action || !status) return;
  const client = window.DaimonHomeAccess.createClient();
  const revocations = [...document.querySelectorAll("[data-revoke]")];
  const controls = [action, ...revocations];
  for (const link of document.querySelectorAll("[data-code-login]")) link.href = client.codeURL();
  function busy(value) { for (const button of controls) button.disabled = value; }
  function failed(error) {
    if (error.name === "NotSupportedError" || error.name === "SecurityError") {
      status.textContent = "Open this page in your phone’s regular browser to use passkeys. The approved-code route remains available.";
      return;
    }
    status.textContent = error.name === "NotAllowedError" || error.name === "AbortError"
      ? "Nothing changed. You can try again or use an approved code."
      : action.dataset.mode === "login"
        ? "We couldn’t sign in with that passkey. Try again or use an approved code."
        : "We couldn’t verify that access key. To add or revoke keys, sign in again with a passkey or a new approved code, then retry. Your existing access is unchanged.";
  }
  if (!client.supported() && action.dataset.mode !== "sso") {
    action.disabled = true;
    status.textContent = "Open this page in your phone’s regular browser to use passkeys. You can still sign in with an approved code.";
  }
  action.addEventListener("click", async () => {
    if(action.dataset.mode === "sso") {
      location.assign("/access/sso/start?return="+encodeURIComponent(location.pathname+location.search+location.hash));
      return;
    }
    busy(true);
    const mode = action.dataset.mode;
    status.textContent = "Follow your phone’s prompt…";
    try {
      if (mode === "register") await client.register(); else await client.login();
      if (mode === "register") location.assign("/access/keys?registered=1");
      else if (action.dataset.reload === "true") location.reload();
      else location.assign("/");
    } catch (error) { failed(error); busy(false); }
  });
  for (const button of revocations) button.addEventListener("click", async () => {
    if (!confirm("Revoke this key and end sessions opened with it across our homes?")) return;
    busy(true);
    try { await client.revoke(button.dataset.revoke); location.assign("/?key-revoked=1"); }
    catch (error) { failed(error); busy(false); }
  });
})();
