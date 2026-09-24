from __future__ import annotations
import asyncio
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

        # Make capture output deterministic and marketing-clean without changing app code/data.
        await page.add_style_tag(content="""
            .sidebar-customize-controls,.healthbar:empty{display:none!important}
            *{animation:none!important;transition:none!important}
        """)

        for view, filename in CAPTURES:
            await page.evaluate("(v)=>showView(v,true)", view)
            await page.wait_for_timeout(1500)
            await page.screenshot(path=str(OUT / filename), full_page=True)

        # A second Cyber Tools capture records the real card/result workspace.
        await page.evaluate("()=>showView('cyber-tools',true)")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=str(OUT / "v431-cyber-tools-working.png"), full_page=True)

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
