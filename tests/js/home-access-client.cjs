const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const source = fs.readFileSync('clusterctl/homes/assets/access-client.js', 'utf8');
function fixture() {
  const calls = [];
  const credential = {id:'key',rawId:new Uint8Array([1]).buffer,type:'public-key',
    response:{clientDataJSON:new Uint8Array([2]).buffer,signature:new Uint8Array([3]).buffer},
    getClientExtensionResults:()=>({}),authenticatorAttachment:'platform'};
  const window = {PublicKeyCredential: function(){}, isSecureContext:true};
  window.top=window.self=window;
  const ctx = {window, navigator:{credentials:{get:async()=>credential,create:async()=>credential}},
    location:{pathname:'/different',search:'?q=1',hash:'#part',origin:'https://home.example'},
    URL, DOMException, atob, btoa, Uint8Array, fetch:async(path, options)=>{
      calls.push({path,options});
      return {ok:true,json:async()=>path.endsWith('-options')
        ? {nonce:'one-shot', options:{challenge:'AQ',user:{id:'Ag'},allowCredentials:[{id:'Aw',type:'public-key'}]}}
        : {status:'complete'}};
    }};
  vm.createContext(ctx);vm.runInContext(source,ctx);
  return {ctx,calls,client:window.DaimonHomeAccess.createClient()};
}
test('DOM-free client decodes WebAuthn and finishes the existing same-origin ceremony', async()=>{
  const f=fixture();let seen;
  f.ctx.navigator.credentials.get=async value=>{seen=value;return {id:'key',rawId:new Uint8Array([1]).buffer,type:'public-key',response:{clientDataJSON:new Uint8Array([2]).buffer},getClientExtensionResults:()=>({})};};
  await f.client.login();
  assert.equal(seen.publicKey.challenge[0],1);assert.equal(seen.publicKey.user.id[0],2);
  assert.equal(seen.publicKey.allowCredentials[0].id[0],3);
  assert.deepEqual(f.calls.map(x=>x.path),['/access/passkeys/login-options','/access/passkeys/login-finish']);
  assert.equal(JSON.parse(f.calls[1].options.body).nonce,'one-shot');
  for(const call of f.calls){assert.equal(call.options.credentials,'same-origin');assert.equal(call.options.redirect,'error');}
});
test('cancellation never finishes, unlocks retry, and sandbox cannot start WebAuthn', async()=>{
  const f=fixture();f.ctx.navigator.credentials.get=async()=>{throw new DOMException('cancelled','NotAllowedError');};
  await assert.rejects(f.client.login(),{name:'NotAllowedError'});
  await assert.rejects(f.client.login(),{name:'NotAllowedError'});
  assert.equal(f.calls.length,2);
  f.ctx.window.top={};assert.equal(f.client.supported(),false);
  await assert.rejects(f.client.register(),{name:'NotSupportedError'});assert.equal(f.calls.length,2);
});
test('overlapping ceremonies do not issue another challenge', async()=>{
  const f=fixture();let finish;
  f.ctx.navigator.credentials.get=()=>new Promise(resolve=>{finish=resolve;});
  const pending=f.client.login();await new Promise(resolve=>setImmediate(resolve));
  await assert.rejects(f.client.login(),{name:'InvalidStateError'});
  assert.equal(f.calls.length,1);finish(null);
  await assert.rejects(pending,{name:'NotAllowedError'});
});
test('catalog, visitor status and JSON logout reuse only reader endpoints',async()=>{
  const f=fixture();await f.client.catalog();await f.client.status();await f.client.logout();
  assert.deepEqual(f.calls.map(x=>x.path),['/catalog.json','/access/status','/access/logout']);
  assert.equal(f.calls[2].options.headers.Accept,'application/json');
});
test('approved-code recovery retains path/query/fragment and refuses foreign redirects',()=>{
  const f=fixture();assert.equal(f.client.codeURL(),'/access?return=%2Fdifferent%3Fq%3D1%23part');
  for(const p of ['https://elsewhere.test','//elsewhere.test','/%2felsewhere.test','/%5celsewhere.test','/x%0a'])assert.throws(()=>f.client.codeURL(p));
});
test('default-page adapter only disables its own controls and preserves cancellation recovery',async()=>{
  const f=fixture();const handlers={};const action={dataset:{mode:'login',reload:'true'},disabled:false,addEventListener:(name,fn)=>{handlers[name]=fn;}};
  const status={textContent:''}, unrelated={disabled:false};
  f.ctx.document={getElementById:id=>id==='passkey-action'?action:status,
    querySelectorAll:selector=>selector==='button'?[action,unrelated]:[]};
  f.ctx.navigator.credentials.get=async()=>{assert.equal(action.disabled,true);assert.equal(unrelated.disabled,false);throw new DOMException('cancelled','NotAllowedError');};
  vm.runInContext(fs.readFileSync('clusterctl/homes/assets/passkeys.js','utf8'),f.ctx);
  await handlers.click();assert.equal(action.disabled,false);assert.match(status.textContent,/Nothing changed/);
});
