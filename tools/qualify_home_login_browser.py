"""Actual HTTPS/Chromium/passkey handoff; synthetic humans, no live changes.

Run with the optional home/login dependencies, pytest and Playwright installed.
This is browser protocol evidence, not a phone or live Google acceptance test.
"""
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from clusterctl.homes.login import Login
from clusterctl.homes.service import handler
from tests.test_home_passkeys import system
from playwright.sync_api import sync_playwright


@contextmanager
def gateway(directory):
    app, _ = system.__wrapped__(directory)
    app.client_example = True
    class DiagnosticHandler(handler(app)):
        def context(self, **kwargs):
            try:return super().context(**kwargs)
            except ValueError as error:
                if urlsplit(self.path).path=='/access/sso/finish':
                    print(json.dumps({'context_failure':str(error),'origin':self.headers.get('Origin')}),flush=True)
                raise
    server = ThreadingHTTPServer(('127.0.0.1', 0), DiagnosticHandler)
    port = server.server_port
    for name, home in app.homes.items():
        home['public_url'] = f'https://{name}.example.test:{port}'
        home['vpn_url'] = f'https://private-{name}.example.test:{port}'
    app.sso = Login(app, f'https://auth.example.test:{port}')
    cert, key = directory/'tls.crt', directory/'tls.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
        '-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=example.test',
        '-addext','subjectAltName=DNS:*.example.test'], check=True, capture_output=True)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try: yield app
    finally: server.shutdown();server.server_close();worker.join(timeout=2)


def main():
    with tempfile.TemporaryDirectory(prefix='home-login-browser-') as tmp:
        with gateway(Path(tmp)) as app, sync_playwright() as pw:
            browser = pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),
                args=['--no-proxy-server','--host-resolver-rules=MAP *.example.test 127.0.0.1'])
            context = browser.new_context(ignore_https_errors=True, viewport={'width':390,'height':844})
            page = context.new_page()
            errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            def callback_result(response):
                if urlsplit(response.url).path == '/access/sso/finish' and response.status != 303:
                    print(json.dumps({'callback_status':response.status,'failure':response.json()}),flush=True)
            page.on('response',callback_result)
            cdp = context.new_cdp_session(page)
            cdp.send('WebAuthn.enable')
            cdp.send('WebAuthn.addVirtualAuthenticator',{'options':{
                'protocol':'ctap2','transport':'internal','hasResidentKey':True,
                'hasUserVerification':True,'isUserVerified':True,
                'automaticPresenceSimulation':True}})
            one, two = [app.homes[name]['public_url'] for name in ('one','two')]
            page.goto(one+'/access')
            code = page.locator('strong').inner_text()
            app.sessions.approve(home='one',code=code,subject=app.authority.actor('human'))
            page.get_by_role('button',name='Continue after approval').click()
            page.wait_for_url(one+'/')
            page.get_by_role('link',name='Access keys').click()
            page.locator('#passkey-action').click()
            page.wait_for_url('**/access/keys?registered=1')
            assert page.locator('[data-revoke]').count()==1
            # Remove the local approved-code session; the new journey must use
            # the actual registered credential at the shared login origin.
            page.goto(one+'/')
            page.get_by_role('button',name='Sign out',exact=True).click()
            page.goto(two+'/?origin=trip#notes')
            page.get_by_role('button',name='Sign in',exact=True).click()
            page.wait_for_url(two+'/?origin=trip#notes',timeout=15000)
            status=page.evaluate('fetch("/access/status").then(r=>r.json())')
            assert status['signed_in'] and status['visitor']['name']=='Human'
            # Existing central session hands off to a second home without a
            # second credential ceremony and preserves its URL too.
            independent=one+'/examples/home-client/?origin=second#continuity'
            page.goto(independent)
            with page.expect_navigation(url=independent):
                page.get_by_role('button',name='Sign in',exact=True).click()
            assert page.evaluate('fetch("/access/status").then(r=>r.json())')['signed_in']
            page.wait_for_function('document.getElementById("visitor").textContent === "Signed in as Human"')
            page.goto(app.sso.origin+'/')
            assert page.get_by_role('heading',name='Hola, Human').count()==1
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.get_by_role('button',name='Cerrar sesión en todos los espacios').click()
            page.wait_for_url(app.sso.origin+'/?signed-out=1')
            assert page.locator('#passkey-action').get_attribute('data-auto-login')=='false'
            for origin in (one,two):
                page.goto(origin+'/')
                assert not page.evaluate('fetch("/access/status").then(r=>r.json())')['signed_in']
            assert not errors,errors
            print(json.dumps({'https_passkey_shared_login':'passed','homes':2,
                'independent_client':'passed',
                'return_query_fragment':'preserved','global_logout':'passed',
                'phone_acceptance':False,'google_live_exchange':False}))
            browser.close()


if __name__=='__main__': main()
