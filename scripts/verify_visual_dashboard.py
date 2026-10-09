"""Browser regression checks against a disposable app, never a customer's server."""
from __future__ import annotations
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

PASSWORD = 'GodseyeDemo!2026'


def verify():
    with tempfile.TemporaryDirectory(prefix='godseye-visual-check-') as folder:
        env = dict(os.environ, GODSEYE_DB=str(Path(folder) / 'demo.db'),
                   GODSEYE_DATA_DIR=str(Path(folder) / 'data'),
                   GODSEYE_COOKIE_SECURE='false', PORT='8791')
        subprocess.run([sys.executable, 'scripts/seed_screenshot_data.py'], env=env, check=True)
        from app.main import hash_password, now
        salt, hashed = hash_password(PASSWORD)
        with sqlite3.connect(env['GODSEYE_DB']) as db:
            for role in ('operator', 'auditor', 'readonly'):
                db.execute('''INSERT INTO users(username,display_name,password_hash,password_salt,role,
                           must_change_password,created_at,password_changed_at) VALUES(?,?,?,?,?,0,?,?)''',
                           (role, role.title(), hashed, salt, role, now(), now()))
            db.execute("INSERT OR REPLACE INTO role_page_permissions(role,page,access) VALUES('readonly','sites','none')")
        with open(Path(folder) / 'server.log', 'w') as log:
            server = subprocess.Popen([sys.executable, '-m', 'app'], env=env, stdout=log, stderr=log)
            try:
                base = 'http://127.0.0.1:8791'
                for _ in range(100):
                    try:
                        urllib.request.urlopen(base, timeout=1)
                        break
                    except Exception:
                        time.sleep(.1)
                with sync_playwright() as p:
                    browser = p.chromium.launch(args=['--no-sandbox'])
                    page = browser.new_page(viewport={'width':1600, 'height':1050})
                    errors = []
                    page.on('pageerror', lambda e: errors.append(str(e)))
                    page.goto(base)
                    if page.locator('#setupOverlay').is_visible():
                        page.fill('#setupPass', PASSWORD)
                        page.fill('#setupPass2', PASSWORD)
                        page.click('#setupForm button[type=submit]')
                        expect(page.locator('#authOverlay')).to_be_visible()
                    def login(name):
                        page.fill('#loginUser', name)
                        page.fill('#loginPass', PASSWORD)
                        page.click('#loginForm button[type=submit]')
                        expect(page.locator('#app')).to_be_visible(timeout=15000)
                        page.evaluate("showView('custom-dashboard')")
                        page.wait_for_function("() => customDashboardStatus.textContent.startsWith('Live data')")
                    login('admin')
                    grid = page.locator('#customDashboardGrid')
                    assert grid.locator('>.custom-card').count() == 10
                    original = page.evaluate("[...document.querySelectorAll('#view-overview .v430-kpi-grid > button')].map(x=>x.querySelector('.statmeta').textContent)")
                    page.get_by_role('button', name='Customize cards', exact=True).click()
                    grid.locator('[data-card-id=devices] select').select_option('half')
                    page.get_by_role('button', name='Remove Active Findings', exact=True).click()
                    page.get_by_role('button', name='＋ Add cards', exact=True).click()
                    page.fill('#dashboardCardSearch', 'health')
                    page.locator('[data-add=health]').click()
                    page.keyboard.press('Escape')
                    expect(page.locator('#dashboardCardPicker')).to_be_hidden()
                    page.get_by_role('button', name='Move System Health earlier', exact=True).click()
                    page.get_by_role('button', name='Save layout', exact=True).click()
                    page.wait_for_function("() => customDashboardStatus.textContent.startsWith('Layout saved')")
                    expected = page.evaluate("UI_LAYOUTS.custom_dashboard.layout.cards")
                    assert 'devices:half' in expected and 'findings:compact' not in expected and 'health:standard' in expected
                    actual = page.evaluate("async()=> (await json('/api/v1/ui/layouts')).layouts.custom_dashboard.layout.cards")
                    assert actual == expected
                    page.reload()
                    expect(page.locator('#app')).to_be_visible()
                    page.wait_for_function("() => customDashboardStatus.textContent.startsWith('Live data')")
                    assert grid.locator('[data-card-id=devices]').get_attribute('data-size') == 'half'
                    page.get_by_role('button', name='Customize cards', exact=True).click()
                    grid.locator('[data-card-id=devices] select').select_option('full')
                    page.get_by_role('button', name='Cancel', exact=True).click()
                    assert grid.locator('[data-card-id=devices]').get_attribute('data-size') == 'half'
                    page.get_by_role('button', name='Customize cards', exact=True).click()
                    page.get_by_role('button', name='Reset', exact=True).click()
                    # A failed save must retain the editable draft for retry.
                    page.route('**/api/v1/ui/layouts/custom_dashboard/personal', lambda route: route.fulfill(status=500, content_type='application/json', body='{"detail":"Test failure"}'))
                    page.get_by_role('button', name='Save layout', exact=True).click()
                    page.wait_for_function("() => customDashboardStatus.textContent.startsWith('Could not save')")
                    expect(page.locator('#customDashboardEditBar')).to_be_visible()
                    page.unroute('**/api/v1/ui/layouts/custom_dashboard/personal')
                    page.get_by_role('button', name='Save layout', exact=True).click()
                    page.wait_for_function("() => customDashboardStatus.textContent.startsWith('Layout saved')")
                    assert page.evaluate("[...document.querySelectorAll('#view-overview .v430-kpi-grid > button')].map(x=>x.querySelector('.statmeta').textContent)") == original
                    # Existing summary actions work inside the cloned live cards.
                    grid.locator('[data-card-id=devices] button.statcard').click()
                    expect(page.locator('#view-devices')).to_be_visible()
                    page.evaluate("showView('custom-dashboard')")
                    page.wait_for_function("() => customDashboardStatus.textContent.startsWith('Live data')")
                    for width in (390, 900, 1600):
                        page.set_viewport_size({'width':width, 'height':1050})
                        assert page.evaluate("[...customDashboardGrid.children].every(el=>el.getBoundingClientRect().width<=customDashboardGrid.getBoundingClientRect().width+1)")
                    page.evaluate('logout()')
                    expect(page.locator('#authOverlay')).to_be_visible()
                    assert grid.locator('>.custom-card').count() == 0
                    assert page.evaluate('DASHBOARD_REFRESH_TIMER===null')
                    for role in ('operator', 'auditor', 'readonly'):
                        login(role)
                        assert grid.locator('[data-card-id=protection]').count() == 0
                        page.get_by_role('button', name='Customize cards', exact=True).click()
                        page.get_by_role('button', name='＋ Add cards', exact=True).click()
                        assert page.locator('[data-add=protection]').count() == 0
                        if role == 'readonly':
                            assert page.locator('[data-add=sites]').count() == 0
                        page.get_by_role('button', name='Close card picker', exact=True).click()
                        page.get_by_role('button', name='Cancel', exact=True).click()
                        page.evaluate('logout()')
                        expect(page.locator('#authOverlay')).to_be_visible()
                    assert not errors, errors
                    browser.close()
                print('PASS: live cards, saved sizes/order, user isolation, cancel/reset, failed-save retry, role filters, actions, responsive grid, logout cleanup.')
            finally:
                server.terminate()
                server.wait(timeout=10)

if __name__ == '__main__':
    verify()
