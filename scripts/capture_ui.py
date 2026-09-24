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
            if view == "overview":
                assert await page.locator("#view-overview").inner_text() != ""
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
                       PYTHONPATH=str(Path.cwd()))
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
                cookies = await context.cookies(address)
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
