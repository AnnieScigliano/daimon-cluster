"""Shared login preserves identity, exact origins and existing permissions."""
from dataclasses import replace
from contextlib import closing
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
import json
import time
from urllib.parse import urlencode, urlsplit
import pytest

from clusterctl.homes.login import Google, Login
from clusterctl.homes.service import handler
from tests.test_home_gateway import serving
from tests.test_home_passkeys import system, enrolled, assertion, registration
from clusterd.auth import hash_token


@pytest.fixture
def login_system(system):
    app, clock = system
    app.sso = Login(app, 'https://auth.example.test')
    return app, clock


def master(app):
    key, identifier, handle = enrolled(app)
    options, proof = app.passkeys.begin(home=app.sso.context, origin=app.sso.origin, mode='login')
    credential = assertion(options['options'], key, identifier, handle, origin=app.sso.origin)
    _, token = app.passkeys.finish(home=app.sso.context, origin=app.sso.origin, mode='login',
        nonce=options['nonce'], proof=proof, credential=credential)
    return token, identifier


def handoff(app, token, home='two'):
    origin = app.homes[home]['public_url']
    request, proof = app.sso.begin(home, origin, '/view/resource?version=current#section')
    _, secret = app.sso.response(request, token)
    return request, secret, proof


def test_existing_passkey_identifies_same_human_on_other_home(login_system):
    app, _ = login_system
    token, _ = master(app)
    request, secret, proof = handoff(app, token)
    session, destination = app.sso.redeem('two', app.homes['two']['public_url'], request, secret, proof)
    assert destination == '/view/resource?version=current#section'
    assert app.identity(session, 'two', app.homes['two']['public_url']).ref == 'human'
    assert app.authority.paired_human('two') == 'other'
    actor = app.identity(session, 'two', app.homes['two']['public_url'])
    assert not app.policy.allows({'visibility': 'human'}, home='two', subject=actor)
    assert app.policy.allows({'visibility': 'individual', 'recipients': ['human']}, home='two', subject=actor)
    with pytest.raises(ValueError, match='unavailable'):
        app.sso.redeem('two', app.homes['two']['public_url'], request, secret, proof)


def test_existing_owner_approves_only_its_paired_human_for_shared_login(login_system, tmp_path):
    app, _ = login_system
    credential=tmp_path/'owner-token';credential.write_text('fixture-owner-token');credential.chmod(0o600)
    app.homes['one']['owner_token_file']=str(credential)
    app.sessions.register_owner(home='one',actor='owner',revision='v1',token='fixture-owner-token')
    request,proof=app.sessions.request(home=app.sso.context,origin=app.sso.origin)
    app.owner('one','fixture-owner-token','approve-browser',{'home':app.sso.context,'code':request['code']})
    _,token=app.sessions.claim(home=app.sso.context,origin=app.sso.origin,
        code=request['code'],proof=proof,current_actor=app.policy.current)
    assert app.sso.identity(token).ref=='human'
    assert app.sso.identity(token).ref!=app.authority.paired_human('two')


@pytest.mark.parametrize('alter', ['proof', 'secret', 'request', 'home', 'origin'])
def test_handoff_rejects_substitution_without_consuming_valid_response(login_system, alter):
    app, _ = login_system
    token, _ = master(app)
    request, secret, proof = handoff(app, token)
    args = dict(home='two', origin=app.homes['two']['public_url'], request=request, secret=secret, proof=proof)
    args[alter] = 'one' if alter == 'home' else 'https://one.example.test' if alter == 'origin' else 'wrong'
    with pytest.raises(ValueError): app.sso.redeem(**args)
    session, _ = app.sso.redeem('two', app.homes['two']['public_url'], request, secret, proof)
    assert app.identity(session, 'two', app.homes['two']['public_url']).ref == 'human'


@pytest.mark.parametrize('failure', ['expiry', 'logout', 'revision', 'credential'])
def test_handoff_cannot_reanimate_expired_or_revoked_identity(login_system, failure):
    app, clock = login_system
    token, identifier = master(app)
    request, secret, proof = handoff(app, token)
    if failure == 'expiry': clock[0] += 61
    if failure == 'logout': app.sessions.revoke(home=app.sso.context, token=token)
    if failure == 'revision': app.authority.people['human'] = replace(app.authority.people['human'], revision='v2')
    if failure == 'credential':
        app.passkeys.revoke(home=app.sso.context, origin=app.sso.origin, token=token,
                            browser_proof='', identifier=identifier)
    with pytest.raises(ValueError): app.sso.redeem('two', app.homes['two']['public_url'], request, secret, proof)


def test_global_logout_invalidates_derived_home_session(login_system):
    app, _ = login_system
    token, _ = master(app)
    request, secret, proof = handoff(app, token)
    child, _ = app.sso.redeem('two', app.homes['two']['public_url'], request, secret, proof)
    ticket = app.sessions.content_read(home='two', origin=app.homes['two']['public_url'],
        content_origin='https://content.example.test', resource='resource', version='version',
        subject=app.sso.identity(token), parent_token=child)
    assert app.sessions.resolve_content(ticket, content_origin='https://content.example.test')
    app.sessions.revoke(home=app.sso.context, token=token)
    assert app.identity(child, 'two', app.homes['two']['public_url']) is None
    assert app.sessions.resolve_content(ticket, content_origin='https://content.example.test') is None


@pytest.mark.parametrize('invalid', ['logout', 'expiry'])
def test_invalid_master_cannot_enroll_finish_or_revoke_from_child(login_system, invalid):
    app, clock = login_system
    token, identifier = master(app)
    request, secret, browser = handoff(app, token)
    origin=app.homes['two']['public_url']
    child, _ = app.sso.redeem('two', origin, request, secret, browser)
    start, proof=app.passkeys.begin(home='two',origin=origin,mode='register',token=child)
    _, credential=registration(start['options'],origin=origin)
    if invalid=='logout': app.sessions.revoke(home=app.sso.context,token=token)
    else:
        with closing(app.sessions.connect()) as db:
            db.execute('UPDATE sessions SET expires=? WHERE digest=?',(clock[0]+1,hash_token(token)))
        clock[0]+=2
    with pytest.raises(ValueError,match='fresh_browser'):
        app.passkeys.begin(home='two',origin=origin,mode='register',token=child)
    with pytest.raises(ValueError,match='fresh_browser'):
        app.passkeys.finish(home='two',origin=origin,mode='register',token=child,
            nonce=start['nonce'],proof=proof,credential=credential)
    with pytest.raises(ValueError,match='fresh_browser'):
        app.passkeys.revoke(home='two',origin=origin,token=child,browser_proof='',identifier=identifier)
    assert len(app.passkeys.list(app.authority.actor('human')))==1


def test_new_handoff_does_not_refresh_an_old_passkey_ceremony(login_system):
    app, clock = login_system
    token, identifier = master(app)
    clock[0]+=901
    request, secret, proof=handoff(app,token)
    origin=app.homes['two']['public_url']
    child, _=app.sso.redeem('two',origin,request,secret,proof)
    assert app.identity(child,'two',origin).ref=='human'
    with pytest.raises(ValueError,match='fresh_browser'):
        app.passkeys.begin(home='two',origin=origin,mode='register',token=child)
    with pytest.raises(ValueError,match='fresh_browser'):
        app.passkeys.revoke(home='two',origin=origin,token=child,browser_proof='',identifier=identifier)


@pytest.mark.parametrize('origin', ['https://', 'http://auth.example.test', 'https://one.example.test',
                                  'https://one.example.test:8443', 'https://private-one.example.test:8443',
                                  'https://evil.test', 'https://auth.example.test/path'])
def test_login_origin_is_explicit_separate_and_in_passkey_domain(system, origin):
    app, _ = system
    with pytest.raises(ValueError): Login(app, origin)


class FakeGoogle:
    subject = 'google-human-1'
    def authorization(self, state, nonce, verifier, callback):
        self.state = state
        return 'https://accounts.google.com/example', None
    def exchange(self, code, verifier, nonce, callback):
        return {'sub': self.subject, 'email': 'irrelevant@example.test'}


def flow(app, mode, token=''):
    values = iter(['state-value', 'proof-value', 'nonce-value', 'verifier-value'])
    original = app.sessions.secret
    app.sessions.secret = lambda: next(values)
    try: _, proof = app.sso.google_begin(mode, token)
    finally: app.sessions.secret = original
    return 'state-value', proof


def test_google_unknown_account_does_not_create_matrix_identity(login_system):
    app, _ = login_system
    app.sso.google = FakeGoogle()
    state, proof = flow(app, 'login')
    with pytest.raises(ValueError, match='not_linked'):
        app.sso.google_finish(state, 'code', proof, '')
    assert set(app.authority.people) == {'owner', 'human', 'other'}


def test_google_link_login_and_unlink_keep_same_existing_identity(login_system):
    app, _ = login_system
    token, _ = master(app)
    app.sso.google = FakeGoogle()
    state, proof = flow(app, 'link', token)
    app.sso.google_finish(state, 'code', proof, token)
    state, proof = flow(app, 'login')
    google_token, _ = app.sso.google_finish(state, 'code', proof, '')
    assert app.sso.identity(google_token).ref == 'human'
    request, secret, browser = handoff(app, google_token)
    child, _ = app.sso.redeem('two', app.homes['two']['public_url'], request, secret, browser)
    app.sso.unlink_google(token, '')
    assert app.sso.identity(google_token) is None
    assert app.identity(child, 'two', app.homes['two']['public_url']) is None
    assert app.sso.identity(token).ref == 'human'


def test_google_link_requires_the_same_browser_and_human(login_system):
    app, _ = login_system
    token, _ = master(app)
    app.sso.google = FakeGoogle()
    state, proof = flow(app, 'link', token)
    with pytest.raises(ValueError): app.sso.google_finish(state, 'code', 'different-browser', token)
    with pytest.raises(ValueError): app.sso.google_finish(state, 'code', proof, 'different-session')
    app.sso.google_finish(state, 'code', proof, token)
    with pytest.raises(ValueError): app.sso.google_finish(state, 'code', proof, token)


def test_unlink_allows_a_new_google_account_without_reanimating_old_sessions(login_system):
    app, _ = login_system
    token, _ = master(app)
    app.sso.google = FakeGoogle()
    state, proof = flow(app, 'link', token)
    app.sso.google_finish(state, 'code', proof, token)
    app.sso.unlink_google(token, '')
    app.sso.google.subject = 'replacement-google-account'
    state, proof = flow(app, 'link', token)
    app.sso.google_finish(state, 'code', proof, token)
    state, proof = flow(app, 'login')
    session, _ = app.sso.google_finish(state, 'code', proof, '')
    assert app.sso.identity(session).ref == 'human'
    app.sso.google.subject = 'google-human-1'
    state, proof = flow(app, 'login')
    with pytest.raises(ValueError, match='not_linked'): app.sso.google_finish(state, 'code', proof, '')


def test_http_exact_origin_return_post_and_no_secret_in_redirect_url(login_system):
    app, _ = login_system
    token, _ = master(app)
    with serving(handler(app)) as base:
        conn = HTTPConnection(urlsplit(base).netloc)
        def call(method, path, headers, body=None):
            conn.request(method, path, body, headers)
            response=conn.getresponse(); payload=response.read()
            return response.status, dict(response.getheaders()), payload
        status, headers, _ = call('GET','/access/sso/start?'+urlencode({'return':'/view/resource?x=1#section'}),
            {'Host':'two.example.test'})
        assert status == 303
        proof=headers['Set-Cookie'].split(';')[0]
        request=urlsplit(headers['Location']).query.split('=')[1]
        status, headers, body = call('GET', '/signin?request='+request,
            {'Host':'auth.example.test','Cookie':'__Host-home='+token})
        assert status == 200
        assert 'form-action https://two.example.test/access/sso/finish' in headers['Content-Security-Policy']
        from html.parser import HTMLParser
        class Form(HTMLParser):
            fields={}
            def handle_starttag(self, tag, attrs):
                attrs=dict(attrs)
                if tag=='input': self.fields[attrs['name']]=attrs['value']
        form=Form();form.feed(body.decode())
        payload=urlencode(form.fields)
        for bad in ['null','https://evil.example.test','https://one.example.test']:
            status, _, _ = call('POST','/access/sso/finish',
                {'Host':'two.example.test','Origin':bad,'Cookie':proof},payload)
            assert status == 403
        status, headers, _ = call('POST','/access/sso/finish',
            {'Host':'two.example.test','Origin':app.sso.origin,'Cookie':proof},payload)
        assert status == 303 and headers['Location']=='/view/resource?x=1#section'
        assert form.fields['response'] not in headers['Location']
        assert 'Secure; HttpOnly; SameSite=Lax' in headers['Set-Cookie']
        conn.close()


def test_opaque_and_owner_origins_cannot_use_shared_login(login_system):
    app, _ = login_system
    with serving(handler(app)) as base:
        conn=HTTPConnection(urlsplit(base).netloc)
        for extras in [{'Origin':'null'}, {'Authorization':'Bearer wrong'}, {'X-Daimon-Vpn':'1'}]:
            conn.request('GET','/signin',headers={'Host':'auth.example.test',**extras})
            response=conn.getresponse();response.read()
            assert response.status in (403,404)
        conn.close()


@pytest.mark.parametrize('invalid', [None,'signature','audience','issuer','expiry','nonce','network'])
def test_official_google_verifier_checks_real_signed_claims(tmp_path, monkeypatch, invalid):
    from google.auth import jwt
    from google.auth.crypt import RSASigner
    import requests
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'test Google key')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1)).sign(key,hashes.SHA256()))
    claims={'iss':'https://accounts.google.com','aud':'test-client','sub':'stable-google-sub',
            'iat':int(time.time())-10,'exp':int(time.time())+300,'nonce':'expected-nonce'}
    if invalid=='audience':claims['aud']='other-client'
    if invalid=='issuer':claims['iss']='https://fake.example'
    if invalid=='expiry':claims['exp']=int(time.time())-1
    if invalid=='nonce':claims['nonce']='different-nonce'
    signing_key=rsa.generate_private_key(public_exponent=65537,key_size=2048) if invalid=='signature' else key
    signer=RSASigner.from_string(signing_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    encoded=jwt.encode(signer,claims,key_id='fixture-key').decode()

    class Reply:
        status_code=200
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def iter_content(self,*_):yield json.dumps({'id_token':encoded}).encode()
    class Client:
        trust_env=True
        calls=[]
        def close(self):pass
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def post(self,url,**kwargs):
            assert url=='https://oauth2.googleapis.com/token'
            assert self.trust_env is False
            assert kwargs['timeout']==10 and kwargs['allow_redirects'] is False and kwargs['stream'] is True
            assert kwargs['data']['code_verifier']=='verifier'
            if invalid=='network':raise requests.ConnectionError('fixture failure')
            return Reply()
        def request(self,method,url,**kwargs):
            assert method=='GET' and url=='https://www.googleapis.com/oauth2/v1/certs'
            assert kwargs['timeout']==10
            result=requests.Response();result.status_code=200
            result._content=json.dumps({'fixture-key':cert.public_bytes(serialization.Encoding.PEM).decode()}).encode()
            return result
    monkeypatch.setattr(requests,'Session',Client)
    config=tmp_path/'google.json'
    config.write_text(json.dumps({'client_id':'test-client','client_secret':'fixture-only'}));config.chmod(0o600)
    google=Google(config)
    if invalid:
        with pytest.raises(ValueError):google.exchange('code','verifier','expected-nonce','https://auth.example.test/google/callback')
    else:
        assert google.exchange('code','verifier','expected-nonce','https://auth.example.test/google/callback')['sub']=='stable-google-sub'
