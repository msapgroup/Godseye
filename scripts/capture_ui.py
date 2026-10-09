from __future__ import annotations
import asyncio
import os
import socket
import sys
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
    ("custom-dashboard", "v431-custom-dashboard.png"),
    ("monitoring", "v431-monitoring.png"),
    ("findings", "v431-findings.png"),
    ("tickets", "v431-tickets.png"),
    ("reports", "v431-reports.png"),
    ("weather", "v431-weather-alerts.png"),
    ("integrations", "v431-integrations.png"),
    ("tools", "v431-tools.png"),
    ("security", "v431-settings.png"),
    ("audit", "v431-audit-activity-guide.png"),
    ("kb", "v431-kb-outlook-guide.png"),
    ("network", "v431-network-map-card.png"),
    ("crm", "v431-crm-live.png"),
    ("calendar", "v431-calendar-guide.png"),
    ("email", "v431-email-guide.png"),
    ("health", "v431-system-health-guide.png"),
    ("remote-access", "v431-remote-access-guide.png"),
    ("event-findings", "v431-event-findings-guide.png"),
    ("cyber-tools", "v431-cyber-tools-overview.png"),
    ("edr", "v431-godseye-edr-defender-guide.png"),
    ("about", "godseye-about.png"),
    ("windows-updates", "v431-windows-updates.png"),
    ("antivirus", "v431-antivirus.png"),
    ("rules", "v431-alert-rules.png"),
]

async def main():
    OUT.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox"])
        page = await browser.new_page(viewport={"width": 1600, "height": 1050}, device_scale_factor=1)
        await page.goto(BASE, wait_until="networkidle")
        await page.evaluate("localStorage.setItem('godseye-theme','dark')")
        await page.reload(wait_until="networkidle")

        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

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
            print("Capturing", view, flush=True)
            await page.evaluate("(v)=>showView(v,true)", view)
            await page.wait_for_timeout(1500)
            if view == "weather":
                frame = page.frame_locator('#weatherWorkspace')
                await frame.locator('#cityList .citytile').first.wait_for()
                await page.wait_for_timeout(14000)
                await frame.locator('#add').click()
                await frame.locator('#addDialog').screenshot(path=str(OUT / 'v431-weather-add-city.png'))
                await frame.get_by_role('button', name='Close add city').click()
            if view == "custom-dashboard":
                await page.wait_for_function("() => customDashboardStatus.textContent.startsWith('Live data')")
                assert await page.locator("#customDashboardGrid > .custom-card").count() == 10
                await page.get_by_role("button", name="Customize cards", exact=True).click()
                await page.get_by_role("button", name="＋ Add cards", exact=True).click()
                await page.locator("#dashboardCardPicker").wait_for(state="visible")
                await page.screenshot(path=str(OUT / "v431-custom-dashboard-picker.png"), full_page=True)
                await page.get_by_role("button", name="Close card picker", exact=True).click()
                await page.get_by_role("button", name="Cancel", exact=True).click()
            if view == "kb":
                await page.locator("#kbList .crm-customer-card").first.click()
                await page.locator("#kbRecord .kb-step").first.wait_for()
            if view == "about":
                for kind, filename in [("notice", "v431-about-license-notice.png"), ("terms", "v431-about-terms-of-use.png")]:
                    await page.evaluate("kind=>openAboutLegal(kind)", kind)
                    await page.locator("#aboutLegalDialog").screenshot(path=str(OUT / filename))
                    await page.keyboard.press("Escape")
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
            if view == "cyber-tools":
                await page.locator('[data-cyber-run="endpoint_posture"]').click()
                await page.locator('#cyber-result-endpoint_posture.cyber-report').wait_for()
                assert await page.locator('#cyber-result-endpoint_posture .cyber-report-metric').count() == 3
                await page.locator('#cyber-result-endpoint_posture').scroll_into_view_if_needed()
                await page.locator('#cyber-result-endpoint_posture').locator('xpath=..').screenshot(path=str(OUT / "v431-endpoint-posture-report.png"))
            if view == "overview":
                assert await page.locator("#view-overview").inner_text() != ""
            if view == "about":
                assert await page.locator("#view-about .about-tagline").inner_text() == (
                    "Network Intelligence · Security Operations · MSP Workflow · Self-Hosted Control"
                )
            if view == "edr":
                await page.locator("#edrEndpoints .edr-endpoint").first.wait_for()
                assert await page.locator("#edrEndpoints .edr-endpoint").count() == 3
                assert await page.locator("#edrProtected").inner_text() == "2 / 3"
            await page.screenshot(path=str(OUT / filename), full_page=True)
            if view == "edr":
                await page.get_by_role("tab", name="Alerts & review").click()
                await page.locator("#edrAlertList .edr-activity-row").first.wait_for()
                await page.screenshot(path=str(OUT / "v431-godseye-edr-alerts-guide.png"), full_page=True)
                await page.get_by_role("tab", name="Rule Center").click()
                await page.screenshot(path=str(OUT / "v431-godseye-edr-rules-guide.png"), full_page=True)
                # Exercise the live endpoint filter and command path after the captures.
                await page.get_by_role("tab", name="Overview").click()
                await page.fill("#edrSearch", "FS01")
                assert await page.locator("#edrEndpoints .edr-endpoint").count() == 1
                await page.locator("#edrEndpoints .edr-endpoint").get_by_role(
                    "button", name="Defender quick scan"
                ).click()
                await page.wait_for_function(
                    "() => document.getElementById('edrPending').textContent === '1'"
                )
                await page.get_by_role("tab", name="Scans & activity").click()
                assert "pending" in (await page.locator("#edrJobs").inner_text()).lower()

        await page.evaluate("()=>showView('kb',true)")
        await page.evaluate("()=>kbNew()")
        await page.screenshot(path=str(OUT / "v431-kb-new-article.png"), full_page=True)
        await page.evaluate("()=>kbClose()")
        await page.evaluate("()=>showView('devices',true)")
        await page.wait_for_timeout(700)
        await page.evaluate("()=>openDeviceIconFromButton(document.querySelector('[data-icon-id]'))")
        for category, filename in [("home", "v431-device-icons-home.png"), ("security", "v431-device-icons-security.png")]:
            await page.evaluate("c=>setDeviceIconCategory(c)", category)
            await page.wait_for_timeout(600)
            await page.locator("#deviceIconModal .modal-card").screenshot(path=str(OUT / filename))
        await page.evaluate("()=>closeDeviceIcon()")

        # Pair a second, seeded GODSEYE over authenticated HTTPS and capture
        # the actual workspace, including remotely loaded devices and tickets.
        private_ip = os.environ.get("GODSEYE_CAPTURE_REMOTE_IP") or socket.gethostbyname(socket.gethostname())
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
            subprocess.run([sys.executable, 'scripts/seed_screenshot_data.py'], env=env, check=True)
            log = open(Path(temp) / 'remote.log', 'w')
            remote = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app',
                                       '--host', '0.0.0.0', '--port', '8443',
                                       '--ssl-certfile', str(cert), '--ssl-keyfile', str(key)],
                                      env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                address = f'https://{private_ip}:8443'
                connect_address = 'https://' + (os.environ.get('GODSEYE_CAPTURE_REMOTE_CONNECT') or private_ip) + ':8443'
                context = await p.request.new_context(ignore_https_errors=True)
                for attempt in range(50):
                    try:
                        response = await context.get(connect_address + '/api/v1/auth/setup/status', timeout=1000)
                        if response.ok: break
                    except Exception:
                        await asyncio.sleep(.2)
                else:
                    raise RuntimeError('Remote screenshot instance did not start')
                response = await context.post(connect_address + '/api/v1/auth/setup', data={'current_password': '', 'new_password': PASSWORD})
                assert response.ok, await response.text()
                response = await context.post(connect_address + '/api/v1/auth/login', data={'username': 'admin', 'password': PASSWORD})
                assert response.ok, await response.text()
                cookies = (await context.storage_state())['cookies']
                csrf = next(c['value'] for c in cookies if c['name'] == 'godseye_csrf')
                response = await context.post(connect_address + '/api/v1/federation/pairing-tokens', headers={'X-CSRF-Token': csrf})
                assert response.ok, await response.text()
                token = (await response.json())['pairing_token']
                linked = await page.evaluate('async data => json("/api/v1/sites", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)})',
                                             {'name': 'Law Office · Florida', 'endpoint': address,
                                              'pairing_token': token, 'ca_cert': cert.read_text()})
                await page.evaluate('(id)=>showView("sites",true)', linked['id'])
                await page.locator('.site-card').first.click()
                await page.locator('#siteWorkspace table').first.wait_for()
                await page.screenshot(path=str(OUT / 'v431-sites-management.png'), full_page=True)
                await page.evaluate("()=>showView('custom-dashboard',true)")
                await page.wait_for_function("() => customDashboardStatus.textContent.startsWith('Live data')")
                await page.screenshot(path=str(OUT / 'v431-custom-dashboard.png'), full_page=True)
                await context.dispose()
            finally:
                remote.terminate()
                remote.wait(timeout=10)
                log.close()

        # Refresh older permission and backup images using the current app styles.
        await page.evaluate("()=>showView('users',true)")
        await page.locator('#roleAccessRows .role-access-row').first.wait_for()
        await page.screenshot(path=str(OUT / 'v431-permissions-restore.png'), full_page=True)
        await page.evaluate("()=>showView('health',true)")
        await page.wait_for_timeout(1000)
        await page.evaluate("document.getElementById('healthAdvanced').open=true")
        backup_card=page.locator('#view-health section.panel').filter(has=page.get_by_role('heading', name='Full Backup & Server Restore', exact=True))
        await backup_card.screenshot(path=str(OUT / 'v431-full-backup-restore.png'))
        await page.evaluate("document.getElementById('healthAdvanced').open=false")

        # Capture the existing admin reset dialog without resetting an account.
        await page.evaluate("async()=>{await json('/api/v1/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'demo-operator',display_name:'Demo Operator',role:'operator',password:'Demo-Only!2026-Strong'})});await loadUsers()}")
        await page.evaluate("()=>showView('users',true)")
        await page.get_by_role('button', name='Reset password', exact=True).first.click()
        await page.locator('#userPasswordResetModal .modal-card').screenshot(path=str(OUT / 'v431-user-password-reset.png'))
        await page.evaluate("()=>closeUserPasswordReset()")

        await page.evaluate("()=>showView('audit',true)")
        await page.wait_for_timeout(800)
        await page.fill('#auditSearch', 'PC-07 (demo)')
        await page.locator('.audit-entry').first.locator(':scope > summary').click()
        await page.screenshot(path=str(OUT / 'v431-audit-defender-details.png'), full_page=True)
        await page.evaluate("()=>auditResetFilters()")
        await page.evaluate("()=>showView('edr',true)")
        await page.wait_for_timeout(800)
        await page.evaluate("()=>openEdrSummary('pending')")
        await page.screenshot(path=str(OUT / 'v431-edr-pending-actions.png'), full_page=True)

        # Record the actual installer target and endpoint versions from the API.
        await page.evaluate("()=>openWindowsAgentModal()")
        await page.wait_for_timeout(1500)
        await page.get_by_role('button', name='↓ Download Agent 2.4.5', exact=True).wait_for()
        assert '2.5.2' not in await page.locator('#windowsAgentModal').inner_text()
        await page.locator('#windowsAgentModal .modal-card').screenshot(path=str(OUT / 'v431-windows-agent-245.png'))
        await page.evaluate("()=>closeWindowsAgentModal()")
        assert not await page.locator('#windowsAgentModal').is_visible()

        # A second Cyber Tools capture records the real card/result workspace.
        await page.evaluate("()=>showView('cyber-tools',true)")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=str(OUT / "v431-cyber-tools-working.png"), full_page=True)

        # A real receipt through the authenticated demo Agent API.
        agent_context = await p.request.new_context()
        receipt = await agent_context.post(BASE + '/api/v1/windows-agents/tickets',
            headers={'Authorization':'Bearer demo-edr-key-1'}, data={
              'request_id':'visual-refresh-demo-ticket', 'requester_name':'Demo user',
              'requester_email':'demo@example.com', 'category':'Email',
              'issue_notes':'Demonstration ticket: Outlook needs a profile review.'})
        assert receipt.ok, await receipt.text()
        await agent_context.dispose()
        await page.evaluate("()=>showView('tickets',true)")
        await page.wait_for_timeout(800)
        await page.screenshot(path=str(OUT / 'v431-agent-ticket-receipt.png'), full_page=True)

        # The same real overview serves the EDR clickable-card guide.
        import shutil
        shutil.copyfile(OUT / "v431-godseye-edr-defender-guide.png", OUT / "v431-edr-clickable-cards.png")
        shutil.copyfile(OUT / "v431-dashboard-map-logo.png", OUT / "v431-map-animated-hops.png")
        for path, filename in [('/device/1', 'v431-device-details.png'), ('/tools', 'v431-tools-standalone.png'), ('/monitoring', 'v431-monitoring-standalone.png')]:
            await page.goto(BASE + path, wait_until='networkidle')
            await page.screenshot(path=str(OUT / filename), full_page=True)
        assert not errors, errors
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
