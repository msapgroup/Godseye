from __future__ import annotations
import asyncio
import os
import socket
import subprocess
import tempfile
from pathlib import Path
from playwright.async_api import async_playwright

BASE = "http://127.0.0.1:8080"
OUT = Path("docs/screenshots")
PASSWORD = "GodseyeDemo!2026"

CAPTURES = [
    ("overview", "v431-dashboard-map-logo.png"),
    ("devices", "v431-devices-guide.png"),
    ("network", "v431-network-map-card.png"),
    ("crm", "v431-crm-live.png"),
    ("kb", "v431-kb-outlook-guide.png"),
    ("calendar", "v431-calendar-guide.png"),
    ("email", "v431-email-guide.png"),
    ("health", "v431-system-health-guide.png"),
    ("remote-access", "v431-remote-access-guide.png"),
    ("event-findings", "v431-event-findings-guide.png"),
    ("cyber-tools", "v431-cyber-tools-overview.png"),
    ("about", "godseye-about.png"),
]

async def main():
    OUT.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox"])
        page = await browser.new_page(viewport={"width": 1600, "height": 1050}, device_scale_factor=1)
        await page.goto(BASE, wait_until="networkidle")
        await page.evaluate("localStorage.setItem('godseye-theme','dark')")
        await page.reload(wait_until="networkidle")

        # Fresh screenshot DB: complete first-run password setup.
        if await page.locator("#setupOverlay").is_visible():
            await page.fill("#setupPass", PASSWORD)
            await page.fill("#setupPass2", PASSWORD)
            await page.click("#setupForm button[type=submit]")
            await page.wait_for_selector("#authOverlay", state="visible")

        # Record the current login copy before signing in.
        if await page.locator("#authOverlay").is_visible():
            assert await page.locator("#authOverlay .login-scene-footer").inner_text() == (
                "GODSEYE\nNetwork Intelligence · Security Operations · MSP Workflow · Self-Hosted Control"
            )
            await page.screenshot(path=str(OUT / "v431-login.png"), full_page=True)

        # Sign in.
        if await page.locator("#authOverlay").is_visible():
            await page.fill("#loginUser", "admin")
            await page.fill("#loginPass", PASSWORD)
            await page.click("#loginForm button[type=submit]")
            await page.wait_for_selector("#app", state="visible", timeout=15000)

        await page.locator(".godseye-approved-lockup").wait_for(state="visible")
        assert await page.locator(".godseye-approved-lockup").evaluate("img => img.complete && img.naturalWidth > 0")

        # Make capture output deterministic and marketing-clean without changing app code/data.
        await page.add_style_tag(content="""
            .sidebar-customize-controls,.healthbar:empty{display:none!important}
            *{animation:none!important;transition:none!important}
        """)

        for view, filename in CAPTURES:
            await page.evaluate("(v)=>showView(v,true)", view)
            await page.wait_for_timeout(1500)
            if view == "crm":
                await page.get_by_role('button', name='+ Add Customer').click()
                await page.fill('#crmCustomerForm [name=name]', 'North Shore Dental')
                await page.fill('#crmCustomerForm [name=email]', 'office@example.com')
                await page.fill('#crmCustomerForm [name=phone]', '(555) 010-2200')
                await page.fill('#crmCustomerForm [name=address]', 'Tampa, Florida')
                await page.fill('#crmCustomerForm [name=notes]', 'Preferred contact: email. On-site visits by appointment.')
                await page.locator('#crmRecord button[form=crmCustomerForm]').click()
                await page.locator('#crmRecord .crm-save-success').wait_for()
                assert not await page.locator('#crmCustomerForm').count(), 'New customer card did not close after save'
                await page.get_by_role('button', name='Open customer').click()
                await page.get_by_role('button', name='+ Add contact').click()
                await page.fill('#crmContactEditor [name=name]', 'Jordan Lee')
                await page.fill('#crmContactEditor [name=role]', 'Office Manager')
                await page.fill('#crmContactEditor [name=email]', 'jordan@example.com')
                await page.fill('#crmContactEditor [name=phone]', '(555) 010-2200')
                await page.get_by_role('button', name='Save contact').click()
                await page.locator('#crmRecord .crm-contact-card').first.wait_for()
                await page.locator('#crmRecord .kb-upload-label input').set_input_files({
                    'name':'office-notes.txt','mimeType':'text/plain','buffer':b'Customer support notes for screenshot demo.'})
                await page.locator('#crmRecord .crm-contact-card').filter(has_text='office-notes.txt').wait_for()
            if view == "kb":
                await page.locator('#kbSearch').fill('MFA')
                await page.locator('#kbList .crm-customer-card').first.wait_for()
                await page.locator('#kbList .crm-customer-card').first.click()
                await page.locator('#kbRecord .kb-step-image').first.wait_for()
                assert await page.locator('#kbRecord .kb-step').count() == 3
                assert await page.locator('#kbRecord .kb-step-image').first.evaluate('img => img.complete && img.naturalWidth > 0')
                await page.get_by_role('button', name='+ New article').click()
                await page.locator('#kbForm [name=title]').fill('Sample printer troubleshooting')
                await page.locator('#kbForm [name=product]').fill('HP LaserJet')
                await page.locator('#kbForm [name=category]').fill('Printers')
                await page.locator('#kbForm [name=summary]').fill('Use when a printer reports a paper jam.')
                await page.locator('#kbSteps [name=step_title]').first.fill('Check the paper path')
                await page.locator('#kbSteps [name=step_instructions]').first.fill('Power off the printer and remove any visible paper from the tray.')
                await page.screenshot(path=str(OUT / 'v431-kb-new-article.png'), full_page=True)
                await page.locator('#kbRecord button[form=kbForm]').click()
                await page.locator('#kbRecord .kb-save-success').wait_for()
                assert not await page.locator('#kbForm').count(), 'New KB card did not close after save'
                await page.get_by_role('button', name='Open article').click()
                await page.get_by_role('button', name='Edit article').click()
                await page.locator('#kbForm').wait_for()
                await page.get_by_role('button', name='Cancel').click()
                page.once('dialog', lambda dialog: dialog.accept())
                await page.get_by_role('button', name='Delete', exact=True).click()
                await page.locator('#kbRecord .crm-empty').wait_for()
                await page.locator('#kbSearch').fill('')
                await page.locator('#kbList .crm-customer-card').first.click()
                await page.locator('#kbRecord .kb-step-image').first.wait_for()
                assert await page.locator('#kbRecord .kb-step-image').first.evaluate('img => img.complete && img.naturalWidth > 0')
            if view == "overview":
                assert await page.locator("#view-overview").inner_text() != ""
            if view == "about":
                assert await page.locator("#view-about .about-tagline").inner_text() == (
                    "Network Intelligence · Security Operations · MSP Workflow · Self-Hosted Control"
                )
            await page.screenshot(path=str(OUT / filename), full_page=True)

        # Pair a second, seeded GODSEYE over authenticated HTTPS and capture
        # the actual workspace, including remotely loaded devices and tickets.
        private_ip = socket.gethostbyname(socket.gethostname())
        with tempfile.TemporaryDirectory() as temp:
            cert, key = Path(temp) / 'site.crt', Path(temp) / 'site.key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-days', '1',
                            '-subj', '/CN=GODSEYE Screenshot Site',
                            '-addext', 'subjectAltName=IP:' + private_ip,
                            '-addext', 'basicConstraints=critical,CA:TRUE'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            env = dict(os.environ, GODSEYE_DB=str(Path(temp) / 'remote.db'), GODSEYE_COOKIE_SECURE='false',
                       GODSEYE_DATA_DIR=str(Path(temp) / 'remote-data'), PYTHONPATH=str(Path.cwd()))
            subprocess.run(['python', 'scripts/seed_screenshot_data.py'], env=env, check=True)
            log = open(Path(temp) / 'remote.log', 'w')
            remote = subprocess.Popen(['python', '-m', 'uvicorn', 'app.main:app',
                                       '--host', '0.0.0.0', '--port', '8443',
                                       '--ssl-certfile', str(cert), '--ssl-keyfile', str(key)],
                                      env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                address = f'https://{private_ip}:8443'
                context = await p.request.new_context(ignore_https_errors=True)
                for attempt in range(50):
                    try:
                        response = await context.get(address + '/api/v1/auth/setup/status', timeout=1000)
                        if response.ok: break
                    except Exception:
                        await asyncio.sleep(.2)
                else:
                    raise RuntimeError('Remote screenshot instance did not start')
                response = await context.post(address + '/api/v1/auth/setup', data={'current_password': '', 'new_password': PASSWORD})
                assert response.ok, await response.text()
                response = await context.post(address + '/api/v1/auth/login', data={'username': 'admin', 'password': PASSWORD})
                assert response.ok, await response.text()
                cookies = (await context.storage_state())['cookies']
                csrf = next(c['value'] for c in cookies if c['name'] == 'godseye_csrf')
                response = await context.post(address + '/api/v1/federation/pairing-tokens', headers={'X-CSRF-Token': csrf})
                assert response.ok, await response.text()
                token = (await response.json())['pairing_token']
                linked = await page.evaluate('async data => json("/api/v1/sites", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)})',
                                             {'name': 'Law Office · Florida', 'endpoint': address,
                                              'pairing_token': token, 'ca_cert': cert.read_text()})
                await page.evaluate('(id)=>showView("sites",true)', linked['id'])
                await page.locator('.site-card').first.click()
                await page.locator('#siteWorkspace table').first.wait_for()
                await page.screenshot(path=str(OUT / 'v431-sites-management.png'), full_page=True)
                await context.dispose()
            finally:
                remote.terminate()
                remote.wait(timeout=10)
                log.close()

        # A second Cyber Tools capture records the real card/result workspace.
        await page.evaluate("()=>showView('cyber-tools',true)")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=str(OUT / "v431-cyber-tools-working.png"), full_page=True)

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
