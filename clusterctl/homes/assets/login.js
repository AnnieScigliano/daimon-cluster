"use strict";
(() => {
  const returning=document.getElementById("login-return");
  if(returning){ returning.submit();return; }
  const action=document.getElementById("passkey-action"),status=document.getElementById("passkey-status");
  const client=window.DaimonHomeAccess.createClient();
  const unlink=document.querySelector('form[action="/google/unlink"]');
  if(unlink && status) unlink.addEventListener("submit",async event => {
    if(!client.supported()) return; // Existing fresh approved-code proof remains usable.
    event.preventDefault();
    const button=unlink.querySelector("button");button.disabled=true;
    status.textContent="Confirmá con tu huella para desvincular Google…";
    try {await client.login();unlink.submit();}
    catch {status.textContent="No se completó la confirmación. Google sigue vinculado.";button.disabled=false;}
  });
  if(!action || !status) return;
  async function login(){
    action.disabled=true;status.textContent="Seguí la indicación de tu teléfono…";
    try {await client.login();location.assign(action.dataset.loginReturn || "/");}
    catch {status.textContent="No se completó el ingreso. Podés reintentar o recuperar el acceso con tu propio daimon.";action.disabled=false;}
  }
  action.addEventListener("click",login);
  if(client.supported()) {if(action.dataset.autoLogin==="true") void login();}
  else {action.disabled=true;status.textContent="Abrí esta página en el navegador de tu teléfono para usar la huella.";}
})();
