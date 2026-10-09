"""Exercise weather controls and native dropdown contrast on a disposable app."""
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect


def verify():
    with tempfile.TemporaryDirectory(prefix='godseye-weather-') as folder:
        env=dict(os.environ,GODSEYE_DB=str(Path(folder)/'demo.db'),GODSEYE_DATA_DIR=str(Path(folder)/'data'),GODSEYE_COOKIE_SECURE='false',PORT='8793')
        subprocess.run([sys.executable,'scripts/seed_screenshot_data.py'],env=env,check=True)
        with open(Path(folder)/'server.log','w') as log:
            server=subprocess.Popen([sys.executable,'-m','app'],env=env,stdout=log,stderr=log)
            try:
                base='http://127.0.0.1:8793'
                for _ in range(100):
                    try: urllib.request.urlopen(base,timeout=1);break
                    except Exception: time.sleep(.1)
                with sync_playwright() as p:
                    browser=p.chromium.launch(args=['--no-sandbox']);page=browser.new_page(viewport={'width':1600,'height':1200});errors=[];page.on('pageerror',lambda e:(errors.append(str(e)),print('BROWSER ERROR',str(e),flush=True)))
                    # Provider availability is not part of deterministic control tests. Live captures use unmodified providers.
                    page.route('**/api/v1/weather/tiles/**',lambda r:r.fulfill(content_type='image/png',body=__import__('base64').b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==')))
                    page.goto(base)
                    if page.locator('#setupOverlay').is_visible():
                        page.fill('#setupPass','GodseyeDemo!2026');page.fill('#setupPass2','GodseyeDemo!2026');page.click('#setupForm button[type=submit]')
                    page.fill('#loginUser','admin');page.fill('#loginPass','GodseyeDemo!2026');page.click('#loginForm button[type=submit]');expect(page.locator('#app')).to_be_visible(timeout=15000)
                    page.evaluate("showView('weather')");frame=page.frame_locator('#weatherWorkspace');expect(frame.locator('#cityList .citytile')).to_have_count(2,timeout=15000)
                    frame.locator('#refreshInterval').select_option('0');expect(frame.locator('#refreshDescription')).to_contain_text('off',timeout=30000);
                    frame.locator('#newyork').click();frame.get_by_role('button',name='View weather for Buffalo').click();expect(frame.locator('#detailTitle')).to_have_text('Buffalo, New York')
                    frame.locator('#add').click();expect(frame.locator('#addDialog')).to_be_visible();frame.get_by_role('button',name='Close add city').click();expect(frame.locator('#addDialog')).to_be_hidden()
                    # Fixed ZIP response for deterministic interaction tests; screenshots use live providers.
                    page.route('**/api/v1/weather/zip/32801',lambda route:route.fulfill(json={'places':[{'place name':'Orlando','state':'Florida','state abbreviation':'FL','latitude':'28.54','longitude':'-81.38'}]}))
                    frame.locator('#add').click();frame.locator('#zip').fill('32801');frame.locator('#label').fill('Orlando office');frame.locator('#zipSubmit').click();expect(frame.locator('#addDialog')).to_be_hidden(timeout=15000);expect(frame.locator('#cityList .citytile')).to_have_count(3)
                    page.reload();expect(page.locator('#app')).to_be_visible(timeout=15000);frame=page.frame_locator('#weatherWorkspace');expect(frame.locator('#cityList .citytile')).to_have_count(3,timeout=15000);expect(frame.locator('#refreshInterval')).to_have_value('0')
                    frame.locator('#manage').click();frame.get_by_role('button',name='Remove Orlando').click();expect(frame.locator('#cityList .citytile')).to_have_count(2)
                    page.route('**/api/v1/weather/cities',lambda route:route.fulfill(status=500,json={'detail':'Test save failure'}) if route.request.method=='PUT' else route.continue_())
                    frame.locator('#add').click();frame.locator('#zip').fill('32801');frame.locator('#zipSubmit').click();expect(frame.locator('#zipError')).to_contain_text('Could not save cities');expect(frame.locator('#addDialog')).to_be_visible();expect(frame.locator('#cityList .citytile')).to_have_count(2);frame.get_by_role('button',name='Close add city').click();page.unroute('**/api/v1/weather/cities')
                    frame.locator('#pause').click();expect(frame.locator('#ticker')).to_have_class('paused');frame.locator('#radar').check();frame.locator('#radar').uncheck()
                    for view in ('cyber-tools','reports','crm','kb','security','edr','users','health','devices','integrations'):
                        page.evaluate(f"showView('{view}')");page.wait_for_timeout(300)
                        checks=page.evaluate("""()=>[...document.querySelectorAll('select option')].map(el=>({bg:getComputedStyle(el).backgroundColor,color:getComputedStyle(el).color})).filter(x=>x.bg==='rgb(255, 255, 255)'&&x.color==='rgb(237, 245, 255)')""")
                        assert not checks,view
                    assert page.locator('#weatherWorkspace').get_attribute('src') is None
                    page.evaluate("showView('weather')");expect(page.frame_locator('#weatherWorkspace').locator('#cityList .citytile')).to_have_count(2,timeout=15000)
                    for width in (390,900,1600):
                        page.set_viewport_size({'width':width,'height':1200});page.wait_for_timeout(250)
                        overflow=page.frame_locator('#weatherWorkspace').locator('body').evaluate('(el)=>el.scrollWidth>innerWidth+2');assert not overflow,width
                    page.evaluate('logout()');expect(page.locator('#authOverlay')).to_be_visible(timeout=15000);assert page.locator('#weatherWorkspace').get_attribute('src') is None
                    assert not errors,errors
                    browser.close();print('PASS: cities, save/reload/remove/failure, close, ticker, navigation/logout, responsive and shared dropdown styling')
            finally:
                server.terminate();server.wait(timeout=15)


if __name__=='__main__':verify()
