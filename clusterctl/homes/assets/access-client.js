/* dm.home-browser/v1: same-origin capabilities, independent of markup and style. */
"use strict";
(() => {
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  function payload(credential) {
    const fields = {clientDataJSON: encode(credential.response.clientDataJSON)};
    for (const name of ["attestationObject", "authenticatorData", "signature", "userHandle"])
      if (credential.response[name]) fields[name] = encode(credential.response[name]);
    return {id: credential.id, rawId: encode(credential.rawId), type: credential.type,
      response: fields, clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment};
  }
  function codeURL(path = location.pathname + location.search + location.hash) {
    const decoded = decodeURIComponent(path);
    if (path.length > 2048 || !path.startsWith("/") || decoded.startsWith("//") ||
        /[\\\x00-\x1f]/.test(decoded) || new URL(path, location.origin).origin !== location.origin)
      throw new TypeError("A home return must be a local path.");
    return "/access?return=" + encodeURIComponent(path);
  }
  function createClient() {
    let active = false;
    const supported = () => Boolean(window.PublicKeyCredential && window.isSecureContext && window.top === window.self);
    async function request(path, body, signal) {
      const response = await fetch(path, {method: body === undefined ? "GET" : "POST",
        credentials: "same-origin", redirect: "error", signal,
        headers: body === undefined ? {Accept: "application/json"} : {Accept: "application/json", "Content-Type": "application/json"},
        body: body === undefined ? undefined : JSON.stringify(body)});
      if (!response.ok) throw new DOMException("Home access could not be verified.", "OperationError");
      return response.json();
    }
    async function exclusive(operation) {
      if (active) throw new DOMException("An access operation is already in progress.", "InvalidStateError");
      active = true;
      try { return await operation(); } finally { active = false; }
    }
    async function ceremony(mode, signal) {
      if (!supported()) throw new DOMException("Use a trusted top-level browser page.", "NotSupportedError");
      return exclusive(async () => {
        const start = await request("/access/passkeys/" + mode + "-options", {}, signal);
        const options = start.options;
        options.challenge = decode(options.challenge);
        if (options.user) options.user.id = decode(options.user.id);
        for (const name of ["excludeCredentials", "allowCredentials"])
          if (options[name]) options[name] = options[name].map(c => ({...c, id: decode(c.id)}));
        const credential = mode === "register"
          ? await navigator.credentials.create({publicKey: options, signal})
          : await navigator.credentials.get({publicKey: options, signal});
        if (!credential) throw new DOMException("The access operation was cancelled.", "NotAllowedError");
        return request("/access/passkeys/" + mode + "-finish", {nonce: start.nonce, credential: payload(credential)}, signal);
      });
    }
    return Object.freeze({supported, codeURL,
      status: ({signal} = {}) => request("/access/status", undefined, signal),
      catalog: ({signal} = {}) => request("/catalog.json", undefined, signal),
      login: ({signal} = {}) => ceremony("login", signal),
      register: ({signal} = {}) => ceremony("register", signal),
      revoke: (id, {signal} = {}) => exclusive(() => request("/access/passkeys/revoke", {id}, signal)),
      logout: ({signal} = {}) => exclusive(() => request("/access/logout", {}, signal))});
  }
  window.DaimonHomeAccess = Object.freeze({contract: "dm.home-browser/v1", createClient});
})();
