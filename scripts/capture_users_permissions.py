"""Capture the running Users & Permissions UI with the app's approved logo.

Uses the same disposable demonstration instance as scripts/capture_ui.py.
No production accounts, agent binaries, or Windows code are involved.
"""
import asyncio
from playwright.async_api import async_playwright
from capture_ui import BASE, OUT, PASSWORD


async def main():
    OUT.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(args=["--no-sandbox"])
        page = await browser.new_page(viewport={"width": 1760, "height": 1080}, device_scale_factor=1)
        await page.goto(BASE, wait_until="networkidle")
        await page.evaluate("localStorage.setItem('godseye-theme','dark')")
        await page.reload(wait_until="networkidle")
        await page.fill("#loginUser", "admin")
        await page.fill("#loginPass", PASSWORD)
        await page.click("#loginForm button[type=submit]")
        await page.locator("#app").wait_for(state="visible")
        # Create demonstration-only accounts inside the temporary capture database.
        accounts = [
            ("Jordan Rivera", "jordan-operator", "operator"),
            ("Casey Morgan", "casey-auditor", "auditor"),
            ("Front Desk", "front-desk", "readonly"),
        ]
        for display, username, role in accounts:
            # Use the authenticated in-app request function to preserve CSRF behavior.
            result = await page.evaluate("""async ({display,username,role,password}) => {
              try {
                await json('/api/v1/users', {
                  method:'POST', headers:{'Content-Type':'application/json'},
                  body:JSON.stringify({display_name:display,username,role,password})
                });
                return 'ok';
              } catch (error) { return String(error.message); }
            }""", {"display": display, "username": username, "role": role, "password": PASSWORD})
            if result not in ("ok",) and "already exists" not in result.lower():
                raise AssertionError(f"Could not seed screenshot account: {result}")
        await page.evaluate("() => showView('users')")
        await page.locator("#usersCards .up-account").nth(2).wait_for()
        await page.locator("#usersCards .up-account").nth(2).click()
        await page.locator("#upPermissionRows .up-permission-row").first.wait_for()
        await page.locator('input[name="up-crm"][value="read"]').check()
        await page.locator('input[name="up-reports"][value="read"]').check()
        await page.locator("#upSave").click()
        await page.get_by_text("Permissions saved.", exact=False).first.wait_for()
        await page.add_style_tag(content="""
            .sidebar-customize-controls {display:none!important}
            * {animation:none!important;transition:none!important}
        """)
        logo = page.locator(".godseye-approved-lockup")
        await logo.wait_for(state="visible")
        assert await logo.evaluate("img => img.complete && img.naturalWidth > 0"), "Approved GODSEYE logo did not load"
        assert await page.locator("#upSelectedHeader").inner_text()
        await page.screenshot(path=str(OUT / "v431-permissions-restore.png"), full_page=True)
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
