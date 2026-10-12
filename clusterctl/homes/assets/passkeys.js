/* Native WebAuthn, no external scripts or persistent browser credential store. */
"use strict";
const action = document.getElementById("passkey-action");
const status = document.getElementById("passkey-status");
const buttons = document.querySelectorAll("button");
for (const link of document.querySelectorAll("[data-code-login]"))
  link.href = "/access?return=" + encodeURIComponent(location.pathname + location.search + location.hash);
const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function payload(credential) {
  const response = credential.response;
  const fields = {clientDataJSON: encode(response.clientDataJSON)};
  for (const name of ["attestationObject", "authenticatorData", "signature", "userHandle"])
    if (response[name]) fields[name] = encode(response[name]);
  return {id: credential.id, rawId: encode(credential.rawId), type: credential.type,
          response: fields, clientExtensionResults: credential.getClientExtensionResults(),
          authenticatorAttachment: credential.authenticatorAttachment};
}
async function post(operation, body) {
  const response = await fetch("/access/passkeys/" + operation, {
    method: "POST", credentials: "same-origin", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error("verification");
  return response.json();
}
function busy(value) { for (const button of buttons) button.disabled = value; }
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
if (!window.PublicKeyCredential || window.top !== window.self) {
  busy(true);
  status.textContent = "Open this page in your phone’s regular browser to use passkeys. You can still sign in with an approved code.";
} else {
  action.addEventListener("click", async () => {
    busy(true);
    const mode = action.dataset.mode;
    status.textContent = "Follow your phone’s prompt…";
    try {
      const start = await post(mode + "-options", {});
      const options = start.options;
      options.challenge = decode(options.challenge);
      if (options.user) options.user.id = decode(options.user.id);
      for (const name of ["excludeCredentials", "allowCredentials"])
        if (options[name]) options[name] = options[name].map(c => ({...c, id: decode(c.id)}));
      const credential = mode === "register"
        ? await navigator.credentials.create({publicKey: options})
        : await navigator.credentials.get({publicKey: options});
      if (!credential) throw new Error("verification");
      await post(mode + "-finish", {nonce: start.nonce, credential: payload(credential)});
      if (mode === "login") {
        if (action.dataset.reload === "true") location.reload();
        else location.assign("/");
      } else location.assign("/access/keys?registered=1");
    } catch (error) { failed(error); busy(false); }
  });
  for (const button of document.querySelectorAll("[data-revoke]"))
    button.addEventListener("click", async () => {
      if (!confirm("Revoke this key and end sessions opened with it across our homes?")) return;
      busy(true);
      try { await post("revoke", {id: button.dataset.revoke}); location.assign("/?key-revoked=1"); }
      catch (error) { failed(error); busy(false); }
    });
}
