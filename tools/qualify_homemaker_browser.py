"""Receiving gateway + actual Homemaker source; synthetic identities only.

Qualifies the existing creator/MiniApp against the real canonical component and
HTTPS receiving adapter. This changes no live deployment or human preferences.
"""
import argparse
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from clusterctl.homes.homemaker import Homemaker
from clusterctl.homes.styles import StyleConsumer
from tests.test_home_passkeys import approved
from tools.qualify_home_login_browser import gateway
from playwright.sync_api import sync_playwright


def wait(page, expression, arg=None):
    """DevTools evaluation avoids a string-eval waiter under the real CSP."""
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        if page.evaluate(expression, arg):return
        page.wait_for_timeout(100)
    raise AssertionError("browser_condition_timed_out: "+expression)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',required=True)
    parser.add_argument('--out',required=True)
    parser.add_argument('--telegram-sdk',required=True,help='Unmodified official Telegram SDK snapshot for network-isolated qualification')
    args=parser.parse_args();out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='homemaker-gateway-') as tmp:
        with gateway(Path(tmp)) as app,sync_playwright() as pw:
            app.designs=Homemaker(app,args.source,Path(tmp)/'designs')
            app.styles=StyleConsumer(app.designs,app.authority,app.homes)
            token,_=approved(app)
            origin=app.homes['one']['public_url']
            browser=pw.chromium.launch(executable_path='/usr/bin/chromium',
                args=['--no-proxy-server','--host-resolver-rules=MAP *.example.test 127.0.0.1'])
            context=browser.new_context(ignore_https_errors=True,viewport={'width':390,'height':844})
            context.route('https://telegram.org/js/telegram-web-app.js',lambda route:route.fulfill(
                status=200,content_type='text/javascript',body=Path(args.telegram_sdk).read_bytes()))
            context.add_init_script('window.nativeEvents=[];window.TelegramWebviewProxy={postEvent:(name,data)=>window.nativeEvents.push({name,data})};')
            context.add_cookies([{'name':'__Host-home','value':token,'url':origin,
                                 'httpOnly':True,'secure':True,'sameSite':'Lax'}])
            editor=context.new_page();errors=[]
            editor.on('pageerror',lambda error:errors.append(str(error)))
            response=editor.goto(origin+'/homemaker/')
            assert 'https://telegram.org' not in response.headers['content-security-policy']
            editor.locator('[data-choose=tricorder]').click()
            editor.locator('[data-use-shared-default]').click()
            editor.locator('[data-shared-default-status]').filter(has_text='predeterminado guardado').wait_for()
            home=context.new_page();home.goto(origin+'/')
            home.wait_for_function('getComputedStyle(document.documentElement).getPropertyValue("--dm-background").trim() !== ""')
            initial=home.evaluate('fetch("/style.json?surface=home").then(r=>r.json())')
            home.wait_for_function('document.getElementById("homemaker-font-assets") !== null')
            home.evaluate('document.fonts.ready')
            home.wait_for_function('[...document.fonts].some(font=>font.family.includes("Syne") && font.status==="loaded")')
            home.screenshot(path=str(out/'home-default-390.png'))
            mini=context.new_page();mini.on('pageerror',lambda error:errors.append(str(error)))
            mini.on('console',lambda message:errors.append(message.text) if message.type=='error' else None)
            response=mini.goto(origin+'/homemaker/miniapp.html#tgWebAppPlatform=android&tgWebAppVersion=9.1')
            assert 'https://telegram.org/js/telegram-web-app.js' in response.headers['content-security-policy']
            wait(mini, '()=>window.Telegram?.WebApp?.platform === "android" && window.nativeEvents.some(e=>e.name==="web_app_ready")')
            mini.evaluate('Telegram.WebView.receiveEvent("safe_area_changed",{top:12,bottom:16,left:0,right:0})')
            wait(mini, '()=>document.documentElement.style.getPropertyValue("--telegram-safe-top") === "12px"')
            wait(mini, '()=>getComputedStyle(document.documentElement).getPropertyValue("--dm-background").trim() !== ""')
            assert mini.evaluate('getComputedStyle(document.body).backgroundColor')==home.evaluate('getComputedStyle(document.body).backgroundColor')
            wait(mini, '(background)=>window.nativeEvents.some(e=>e.name==="web_app_set_header_color" && JSON.parse(e.data).color?.toLowerCase()===background.toLowerCase())',
                                   arg=initial['appearance']['background'])
            assert mini.locator('[data-compact-nav]').is_visible()
            assert mini.evaluate('document.documentElement.scrollWidth <= innerWidth')
            mini.screenshot(path=str(out/'miniapp-default-390.png'))
            # An explicit canonical application choice follows the old design;
            # switching default chooses another variant, rather than editing it.
            app.designs.authority.select('human',scope={'kind':'being','ref':'owner'},surface='homemaker',
                selection={'mode':'explicit','design_ref':initial['design_ref']},expected_revision=0,operation_id='fixture-explicit')
            editor.locator('[data-choose=paper]').click()
            editor.locator('[data-use-shared-default]').click()
            editor.locator('[data-shared-default-status]').filter(has_text='predeterminado guardado').wait_for()
            home.evaluate('window.dispatchEvent(new CustomEvent("home-style:refresh"))')
            home.wait_for_function('(old)=>getComputedStyle(document.documentElement).getPropertyValue("--dm-background").trim() !== old',
                                   arg=initial['appearance']['background'])
            mini.evaluate('window.dispatchEvent(new CustomEvent("home-style:refresh"))')
            wait(mini, '(old)=>getComputedStyle(document.documentElement).getPropertyValue("--dm-background").trim() === old',
                                   arg=initial['appearance']['background'])
            changed=home.evaluate('fetch("/style.json?surface=home").then(r=>r.json())')
            assert initial['design_ref']!=changed['design_ref']
            assert mini.evaluate('fetch("/style.json?surface=homemaker").then(r=>r.json())')['mode']=='explicit'
            home.route('**/style.json?*',lambda route:route.fulfill(status=503,body='unavailable'))
            fallback=home.evaluate('getComputedStyle(document.body).backgroundColor')
            home.evaluate('window.dispatchEvent(new CustomEvent("home-style:refresh"))')
            home.wait_for_timeout(200)
            assert home.evaluate('getComputedStyle(document.body).backgroundColor')==fallback
            assert not errors,errors
            result={'fixture':'HTTPS gateway + maintained Homemaker source + canonical authority',
                    'authenticated_writer':'existing verified human session and current pair',
                    'home_and_miniapp':'same canonical style and real font assets',
                    'default_switch':'new variant reference','explicit_application':'preserved',
                    '503_fallback':'last valid readable presentation','phone_acceptance':False,
                    'telegram_sdk':'official SDK loaded under receiving CSP; simulated Android ready/safe-area bridge',
                    'live_deployment':False}
            (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result));browser.close()


if __name__=='__main__':main()
