"""Shared human login, existing identities/passkeys and exact-origin handoffs.

Request IDs are correlation only. A fresh response secret AND the initiating
home's HttpOnly proof are needed to redeem identity. No resource grants change.
"""
from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import re
from urllib.parse import urlencode, urlsplit

from clusterd.auth import hash_token


class Login:
    context = 'dm.home-login/v1'

    def __init__(self, app, origin, google=None):
        parsed = urlsplit(origin)
        occupied = [h[k] for h in app.homes.values() for k in ('public_url','vpn_url')]
        occupied += [app.config.get(k) for k in ('content_public_url','content_vpn_url')]
        if (parsed.scheme != 'https' or parsed.username or parsed.password or
                parsed.path or parsed.query or parsed.fragment or
                not app.passkeys or not parsed.hostname or not parsed.hostname.endswith('.'+app.passkeys.rp_id) or
                any(parsed.hostname == urlsplit(value).hostname for value in occupied if value)):
            raise ValueError('invalid_shared_login_origin')
        self.app, self.sessions, self.origin, self.google = app, app.sessions, origin, google
        with closing(self.sessions.connect()) as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS login_requests(
                id TEXT PRIMARY KEY, home TEXT NOT NULL, origin TEXT NOT NULL,
                destination TEXT NOT NULL, proof TEXT NOT NULL, expires INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS login_responses(
                digest TEXT PRIMARY KEY, request TEXT NOT NULL, parent TEXT NOT NULL,
                expires INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS google_links(
                subject TEXT PRIMARY KEY, actor TEXT NOT NULL, revision TEXT NOT NULL,
                created INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
              CREATE UNIQUE INDEX IF NOT EXISTS google_current_actor
                ON google_links(actor) WHERE revoked=0;
              CREATE TABLE IF NOT EXISTS google_link_history(
                id INTEGER PRIMARY KEY, subject TEXT NOT NULL, actor TEXT NOT NULL,
                revision TEXT NOT NULL, action TEXT NOT NULL, observed INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS google_flows(
                state TEXT PRIMARY KEY, proof TEXT NOT NULL, nonce TEXT NOT NULL,
                verifier TEXT NOT NULL, mode TEXT NOT NULL, parent TEXT,
                request TEXT, expires INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS google_sessions(
                digest TEXT PRIMARY KEY, subject TEXT NOT NULL);
            ''')

    def identity(self, token):
        row = self.sessions.resolve(token,home=self.context,origin=self.origin)
        if not row: return None
        actor = self.app.policy.current(row['actor'],row['revision'])
        if not actor or actor.kind != 'human': return None
        with closing(self.sessions.connect()) as db:
            key = db.execute('SELECT subject FROM google_sessions WHERE digest=?', (row['digest'],)).fetchone()
            if key:
                link = db.execute('SELECT * FROM google_links WHERE subject=?', (key['subject'],)).fetchone()
                if not link or link['revoked'] or (link['actor'],link['revision']) != (actor.ref,actor.revision): return None
        return actor

    def linked(self, actor):
        if not actor: return False
        with closing(self.sessions.connect()) as db:
            return bool(db.execute('SELECT 1 FROM google_links WHERE actor=? AND revision=? AND revoked=0',
                                   (actor.ref,actor.revision)).fetchone())

    def begin(self, home, origin, destination):
        from .service import return_target
        if home not in self.app.homes or origin != self.app.homes[home]['public_url']:
            raise ValueError('invalid_login_target')
        destination = return_target(destination)
        identifier,proof = self.sessions.secret(),self.sessions.secret()
        with closing(self.sessions.connect()) as db:
            now=self.sessions.now(db)
            db.execute('DELETE FROM login_responses WHERE expires<?',(now,))
            db.execute('DELETE FROM login_requests WHERE expires<?',(now,))
            if db.execute('SELECT count(*) FROM login_requests WHERE home=?',(home,)).fetchone()[0] >= 1000:
                raise ValueError('login_busy')
            db.execute('INSERT INTO login_requests VALUES(?,?,?,?,?,?)',
                       (identifier,home,origin,destination,hash_token(proof),now+300))
        return identifier,proof

    def response(self, request, parent_token):
        if not self.identity(parent_token): raise ValueError('human_login_required')
        with closing(self.sessions.connect()) as db:
            now=self.sessions.now(db)
            row=db.execute('SELECT * FROM login_requests WHERE id=?',(request,)).fetchone()
            if not row or row['expires']<=now or row['origin']!=self.app.homes[row['home']]['public_url']:
                raise ValueError('login_request_unavailable')
            # The response secret is sent by a form POST, never in a URL/log.
            secret=self.sessions.secret()
            db.execute('INSERT INTO login_responses VALUES(?,?,?,?)',
                       (hash_token(secret),request,hash_token(parent_token),min(now+60,row['expires'])))
        return row['origin']+'/access/sso/finish',secret

    def redeem(self, home, origin, request, secret, proof):
        with closing(self.sessions.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                now=self.sessions.now(db)
                target=db.execute('SELECT * FROM login_requests WHERE id=?',(request,)).fetchone()
                response=db.execute('SELECT * FROM login_responses WHERE digest=?',(hash_token(secret),)).fetchone()
                parent=db.execute('SELECT * FROM sessions WHERE digest=?',(response['parent'],)).fetchone() if response else None
                if (not target or target['expires']<=now or target['home']!=home or target['origin']!=origin or
                        not hmac.compare_digest(target['proof'],hash_token(proof)) or not response or
                        response['request']!=request or response['expires']<=now or not parent or
                        parent['home']!=self.context or parent['origin']!=self.origin or parent['revoked'] or
                        not parent['created']<=now<parent['expires']):
                    raise ValueError('login_response_unavailable')
                subject=self.app.policy.current(parent['actor'],parent['revision'])
                if not subject or subject.kind!='human': raise ValueError('login_identity_changed')
                google=db.execute('SELECT subject FROM google_sessions WHERE digest=?',(parent['digest'],)).fetchone()
                if google:
                    link=db.execute('SELECT * FROM google_links WHERE subject=?',(google['subject'],)).fetchone()
                    if not link or link['revoked'] or (link['actor'],link['revision']) != (subject.ref,subject.revision):
                        raise ValueError('login_identity_changed')
                token=self.sessions._issue(db,home,origin,subject,min(7*86400,parent['expires']-now))
                child=hash_token(token)
                db.execute('INSERT INTO session_parents VALUES(?,?)',(child,parent['digest']))
                # Credential revocation also invalidates ordinary home checks.
                key=db.execute('SELECT credential FROM passkey_sessions WHERE digest=?',(parent['digest'],)).fetchone()
                if key:db.execute('INSERT INTO passkey_sessions VALUES(?,?)',(child,key['credential']))
                db.execute('DELETE FROM login_responses WHERE request=?',(request,))
                db.execute('DELETE FROM login_requests WHERE id=?',(request,))
                db.commit()
                return token,target['destination']
            except BaseException: db.rollback();raise

    def google_begin(self, mode, token, request=None):
        if not self.google or mode not in ('login','link'): raise ValueError('google_login_unavailable')
        if request is not None:
            with closing(self.sessions.connect()) as db:
                row=db.execute('SELECT expires FROM login_requests WHERE id=?',(request,)).fetchone()
                if not row or row['expires']<=self.sessions.now(db): raise ValueError('login_request_unavailable')
        if mode=='link':
            if not self.identity(token): raise ValueError('human_login_required')
            with closing(self.sessions.connect()) as db:
                row=db.execute('SELECT created FROM sessions WHERE digest=?',(hash_token(token),)).fetchone()
                if self.sessions.now(db)-row['created']>900: raise ValueError('fresh_browser_sign_in_required')
        state,proof,nonce,verifier=[self.sessions.secret() for _ in range(4)]
        with closing(self.sessions.connect()) as db:
            now=self.sessions.now(db)
            db.execute('DELETE FROM google_flows WHERE expires<?',(now,))
            if db.execute('SELECT count(*) FROM google_flows').fetchone()[0]>=1000: raise ValueError('login_busy')
            db.execute('INSERT INTO google_flows VALUES(?,?,?,?,?,?,?,?)',
                       (state,hash_token(proof),nonce,verifier,mode,hash_token(token) if mode=='link' else None,request,now+300))
        return self.google.authorization(state,nonce,verifier,self.origin+'/google/callback'),proof

    def google_finish(self, state, code, proof, token):
        if not self.google: raise ValueError('google_login_unavailable')
        with closing(self.sessions.connect()) as db:
            row=db.execute('SELECT * FROM google_flows WHERE state=?',(state,)).fetchone()
            if not row or row['expires']<=self.sessions.now(db) or not hmac.compare_digest(row['proof'],hash_token(proof)):
                raise ValueError('google_flow_unavailable')
        if row['mode']=='link' and (not hmac.compare_digest(row['parent'],hash_token(token)) or not self.identity(token)):
            raise ValueError('google_link_identity_changed')
        claims=self.google.exchange(code,row['verifier'],row['nonce'],self.origin+'/google/callback')
        subject=claims.get('sub')
        if not isinstance(subject,str) or not 1<=len(subject)<=255: raise ValueError('invalid_google_subject')
        with closing(self.sessions.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                now=self.sessions.now(db)
                if db.execute('DELETE FROM google_flows WHERE state=? AND expires>?',(state,now)).rowcount!=1:
                    raise ValueError('google_flow_unavailable')
                if row['mode']=='link':
                    parent=db.execute('SELECT * FROM sessions WHERE digest=?',(row['parent'],)).fetchone()
                    actor=self.app.policy.current(parent['actor'],parent['revision']) if parent else None
                    if (not actor or actor.kind!='human' or parent['revoked'] or
                            not parent['created']<=now<parent['expires'] or now-parent['created']>900):
                        raise ValueError('google_link_identity_changed')
                    prior=db.execute('SELECT * FROM google_links WHERE subject=? OR actor=?',(subject,actor.ref)).fetchall()
                    if any((p['subject']==subject and p['actor']!=actor.ref) or
                           (not p['revoked'] and (p['subject']!=subject or p['revision']!=actor.revision)) for p in prior):
                        raise ValueError('google_link_conflict')
                    db.execute('INSERT OR REPLACE INTO google_links VALUES(?,?,?,?,0)',(subject,actor.ref,actor.revision,now))
                    db.execute('INSERT INTO google_link_history(subject,actor,revision,action,observed) VALUES(?,?,?,?,?)',
                               (subject,actor.ref,actor.revision,'linked',now))
                    db.commit();return None,row['request']
                link=db.execute('SELECT * FROM google_links WHERE subject=? AND revoked=0',(subject,)).fetchone()
                actor=self.app.policy.current(link['actor'],link['revision']) if link else None
                if not actor or actor.kind!='human': raise ValueError('google_account_not_linked')
                session=self.sessions._issue(db,self.context,self.origin,actor,7*86400)
                db.execute('INSERT INTO google_sessions VALUES(?,?)',(hash_token(session),subject))
                db.commit();return session,row['request']
            except BaseException:db.rollback();raise

    def unlink_google(self, token, proof):
        with closing(self.sessions.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                actor=self.app.passkeys.elevated(db,self.context,self.origin,token,proof)
                links=db.execute('SELECT subject FROM google_links WHERE actor=? AND revoked=0',(actor.ref,)).fetchall()
                db.execute('UPDATE google_links SET revoked=1 WHERE actor=?',(actor.ref,))
                for link in links:
                    db.execute('INSERT INTO google_link_history(subject,actor,revision,action,observed) VALUES(?,?,?,?,?)',
                               (link['subject'],actor.ref,actor.revision,'unlinked',self.sessions.now(db)))
                    db.execute('UPDATE sessions SET revoked=1 WHERE digest IN (SELECT digest FROM google_sessions WHERE subject=?)',
                               (link['subject'],))
                db.commit()
            except BaseException:db.rollback();raise


class Google:
    """Official Google ID-token verifier; no email-based identity matching."""
    def __init__(self, filename):
        from .service import private_text
        value=json.loads(private_text(filename))
        if set(value)!={'client_id','client_secret'} or any(not isinstance(v,str) or not v for v in value.values()):
            raise ValueError('invalid_google_client')
        self.client_id,self.client_secret=value['client_id'],value['client_secret']

    def authorization(self,state,nonce,verifier,callback):
        import base64
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        return 'https://accounts.google.com/o/oauth2/v2/auth?'+urlencode({
            'client_id':self.client_id,'redirect_uri':callback,'response_type':'code','scope':'openid',
            'state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'})

    def exchange(self,code,verifier,nonce,callback):
        import requests
        from google.auth.exceptions import GoogleAuthError
        from google.oauth2.id_token import verify_oauth2_token
        from google.auth.transport.requests import Request
        try:
            with requests.Session() as client:
                client.trust_env=False
                with client.post('https://oauth2.googleapis.com/token',data={
                    'client_id':self.client_id,'client_secret':self.client_secret,'code':code,
                    'code_verifier':verifier,'redirect_uri':callback,'grant_type':'authorization_code'},
                    timeout=10,allow_redirects=False,stream=True) as response:
                    if response.status_code!=200: raise ValueError('google_exchange_failed')
                    body=bytearray()
                    for chunk in response.iter_content(8192):
                        body.extend(chunk)
                        if len(body)>65536: raise ValueError('google_exchange_failed')
                    value=json.loads(body)
                    if not isinstance(value,dict) or not isinstance(value.get('id_token'),str):
                        raise ValueError('google_exchange_failed')
                verify_request=Request(client)
                claims=verify_oauth2_token(value['id_token'],
                                          lambda *args,**kwargs: verify_request(*args,timeout=10,**kwargs),self.client_id)
        except (requests.RequestException,GoogleAuthError,ValueError) as exc:
            raise ValueError('google_sign_in_failed') from exc
        if claims.get('nonce')!=nonce: raise ValueError('google_nonce_mismatch')
        return claims


def routes(handler, app, method, data=b''):
    """Explicit trusted origin; isolated content and home handlers stay separate."""
    import html
    from http.cookies import SimpleCookie
    from urllib.parse import parse_qs
    from .service import key_page
    sso=app.sso
    if not sso or handler.headers.get('Host','') != urlsplit(sso.origin).netloc: return False
    supplied=handler.headers.get('Origin')
    if (supplied is not None and supplied!=sso.origin) or handler.headers.get('X-Daimon-Vpn')=='1' or handler.headers.get('Authorization'):
        raise ValueError('login_origin_mismatch')
    if method=='POST' and supplied!=sso.origin: raise ValueError('login_post_requires_origin')
    path=urlsplit(handler.path).path;query=parse_qs(urlsplit(handler.path).query)
    cookies=SimpleCookie();cookies.load(handler.headers.get('Cookie',''))
    def cookie(name): return cookies[name].value if cookies.get(name) else ''
    token=cookie('__Host-home');actor=sso.identity(token)
    def set_cookie(name,value,ttl=300,strict=False):
        return f'{name}={value}; Secure; HttpOnly; SameSite={"Strict" if strict else "Lax"}; Path=/; Max-Age={ttl}'
    def one(name,default=None):
        values=query.get(name,[default])
        if len(values)!=1: raise ValueError('invalid_login_parameter')
        return values[0]
    request=one('request')
    def page(title,content,script=''):
        return ('<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<link rel="stylesheet" href="/home.css"><title>'+html.escape(title)+' · Daimon Matrix</title><main>'+
            content+'</main>'+script+'</html>').encode()
    if method=='GET':
        if path in ('/home.css','/access-client.js','/passkeys.js','/login.js','/fonts/space-grotesk-latin.woff2'):
            asset=Path(__file__).parent/'assets'/path.lstrip('/')
            mime='text/javascript' if path.endswith('.js') else 'text/css'
            if path.startswith('/fonts/'):
                asset=Path(__file__).resolve().parents[2]/'clusterd/assets/fonts/space-grotesk-latin.woff2';mime='font/woff2'
            handler.respond(200,asset.read_bytes(),mime);return True
        if path=='/access/status':
            handler.respond(200,{'contract':'dm.home-browser/v1','signed_in':bool(actor),'visitor':{'kind':'human','name':actor.name} if actor else None,
                                'passkeys':True,'shared_login':False});return True
        if path=='/google/callback':
            try:
                if one('error') is not None or not one('state') or not one('code'):
                    raise ValueError('google_sign_in_not_completed')
                session,continued=sso.google_finish(one('state'),one('code'),cookie('__Host-google-flow'),token)
            except ValueError as exc:
                explanation = ('Esa cuenta de Google todavía no está vinculada. Entrá con tu huella o con tu daimon y elegí Vincular Google.'
                    if str(exc)=='google_account_not_linked' else
                    'No se completó el ingreso con Google. Podés reintentar, usar tu huella o recuperar el acceso con tu daimon.')
                handler.respond(400,page('Ingreso pendiente','<h1>Volvamos a intentar</h1><p>'+explanation+
                    '</p><p><a href="/">Volver al ingreso</a></p>'), 'text/html; charset=utf-8',
                    cookies=(set_cookie('__Host-google-flow','',0),));return True
            headers=[set_cookie('__Host-google-flow','',0)]
            if session:headers.append(set_cookie('__Host-home',session,604800))
            destination='/signin?'+urlencode({'request':continued}) if continued else '/?google-linked=1'
            handler.respond(303,b'',cookies=tuple(headers),headers=(('Location',destination),));return True
        if path=='/access':
            grant,proof=app.sessions.request(home=sso.context,origin=sso.origin)
            body='<h1>Entrá con tu daimon</h1><p>Para identificarte por primera vez o recuperar el acceso, enviá este código a tu propio daimon:</p><p><strong>'+grant['code']+'</strong></p><form method="post" action="/access/claim"><input type="hidden" name="code" value="'+grant['code']+'"><input type="hidden" name="request" value="'+html.escape(request or '',quote=True)+'"><button>Continuar después de aprobar</button></form>'
            handler.respond(200,page('Recuperar acceso',body), 'text/html; charset=utf-8',cookies=(set_cookie('__Host-home-proof',proof,900),));return True
        if path=='/access/keys':
            if not actor: raise ValueError('human_login_required')
            handler.respond(200,key_page(app,actor), 'text/html; charset=utf-8');return True
        if path in ('/','/signin'):
            if request and actor:
                action,secret=sso.response(request,token)
                body='<h1>Volviendo a tu espacio…</h1><form id="login-return" method="post" action="'+html.escape(action,quote=True)+'"><input type="hidden" name="request" value="'+html.escape(request,quote=True)+'"><input type="hidden" name="response" value="'+secret+'"><button>Continuar</button></form>'
                handler.respond(200,page('Continuar',body,'<script src="/login.js" defer></script>'), 'text/html; charset=utf-8',form_action=action);return True
            continuation='/signin?'+urlencode({'request':request}) if request else '/'
            notice = ('<p role="status">Cerraste la sesión común. Los espacios que entraron por este ingreso ya no tienen acceso.</p>'
                      if one('signed-out')=='1' else
                      '<p role="status">Google quedó vinculado a tu identidad.</p>' if one('google-linked')=='1' else
                      '<p role="status">Google quedó desvinculado. Podés seguir usando tu huella.</p>' if one('google-unlinked')=='1' else '')
            if actor:
                body='<h1>Hola, '+html.escape(actor.name)+'</h1><p>Tu identidad está disponible para nuestras homes. Cada espacio conserva sus permisos.</p><p><a href="/access/keys">Administrar huella y llaves</a></p>'
                if sso.google:
                    body+= ('<p>Google está vinculado a tu identidad.</p><form method="post" action="/google/unlink"><button>Desvincular Google</button></form>'
                        if sso.linked(actor) else '<form method="post" action="/google/link"><button>Vincular mi cuenta de Google</button></form>')
                    body+='<p id="passkey-status" role="status" aria-live="polite"></p>'
                body+='<form method="post" action="/access/logout"><button>Cerrar sesión en todos los espacios</button></form>'
                body+=''.join('<p><a href="'+html.escape(h['public_url'],quote=True)+'">'+html.escape(h['name'])+'</a></p>' for h in app.homes.values())
            else:
                body='<h1>Entrá a nuestros espacios</h1><p>Usá tu huella o la llave que ya guardaste. Tu identidad y tus permisos se conservan entre homes.</p><button id="passkey-action" data-mode="login" data-auto-login="'+str(path=='/signin').lower()+'" data-login-return="'+html.escape(continuation,quote=True)+'">Entrar con huella</button><p id="passkey-status" role="status" aria-live="polite"></p>'
                if sso.google:body+='<form method="post" action="/google/login"><input type="hidden" name="request" value="'+html.escape(request or '',quote=True)+'"><button>Entrar con Google</button></form>'
                body+='<p><a href="/access?'+html.escape(urlencode({'request':request or ''}),quote=True)+'">Primera vez o recuperar acceso con mi daimon</a></p>'
            handler.respond(200,page('Entrar',notice+body,'<script src="/access-client.js" defer></script><script src="/login.js" defer></script>'), 'text/html; charset=utf-8');return True
        handler.respond(404,{});return True
    if method=='POST':
        if path.startswith('/access/passkeys/'):
            payload=json.loads(data)
            if not isinstance(payload,dict) or len(data)>32768:raise ValueError('invalid_passkey_payload')
            operation=path.removeprefix('/access/passkeys/')
            proof=cookie('__Host-home-proof')
            if operation in ('register-options','login-options'):
                if payload:raise ValueError('unexpected_passkey_fields')
                result,challenge=app.passkeys.begin(home=sso.context,origin=sso.origin,mode=operation.split('-')[0],token=token,browser_proof=proof)
                handler.respond(200,result,cookies=(set_cookie('__Host-home-passkey',challenge,300,True),));return True
            if operation in ('register-finish','login-finish'):
                if set(payload)!={'nonce','credential'}:raise ValueError('unexpected_passkey_fields')
                result,session=app.passkeys.finish(home=sso.context,origin=sso.origin,mode=operation.split('-')[0],nonce=payload['nonce'],proof=cookie('__Host-home-passkey'),credential=payload['credential'],token=token,browser_proof=proof)
                headers=[set_cookie('__Host-home-passkey','',0,True)]
                if session:headers.append(set_cookie('__Host-home',session,604800))
                handler.respond(200,result,cookies=tuple(headers));return True
            if operation=='revoke' and set(payload)=={'id'}:
                app.passkeys.revoke(home=sso.context,origin=sso.origin,token=token,browser_proof=proof,identifier=payload['id'])
                handler.respond(200,{'status':'revoked'});return True
            raise ValueError('unknown_passkey_operation')
        if path=='/access/logout':
            app.sessions.revoke(home=sso.context,token=token)
            browser='text/html' in handler.headers.get('Accept','')
            handler.respond(303 if browser else 200,b'' if browser else {'status':'signed-out'},cookies=(set_cookie('__Host-home','',0),),headers=(('Location','/?signed-out=1'),) if browser else ());return True
        values=parse_qs(data.decode(),keep_blank_values=True,strict_parsing=True)
        if any(len(v)!=1 for v in values.values()):raise ValueError('invalid_login_form')
        if path=='/google/unlink' and not values:
            sso.unlink_google(token,cookie('__Host-home-proof'))
            handler.respond(303,b'',headers=(('Location','/?google-unlinked=1'),));return True
        if path=='/access/claim' and set(values)=={'code','request'}:
            result,session=app.sessions.claim(home=sso.context,origin=sso.origin,code=values['code'][0],proof=cookie('__Host-home-proof'),current_actor=app.policy.current)
            destination='/signin?'+urlencode({'request':values['request'][0]}) if values['request'][0] else '/'
            if session:handler.respond(303,b'',cookies=(set_cookie('__Host-home',session,604800),),headers=(('Location',destination),))
            else:handler.respond(200,page('Esperando aprobación','<h1>Todavía falta la aprobación</h1><p>Volvé atrás y continuá cuando tu daimon haya aprobado el código.</p>'),'text/html; charset=utf-8')
            return True
        if path in ('/google/link','/google/login') and set(values)<= {'request'}:
            target,proof=sso.google_begin(path.rsplit('/',1)[-1],token,values.get('request',[''])[0] or None)
            handler.respond(303,b'',cookies=(set_cookie('__Host-google-flow',proof,300),),headers=(('Location',target),));return True
        raise ValueError('unknown_login_operation')
    return False
