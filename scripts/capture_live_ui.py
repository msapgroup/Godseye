from __future__ import annotations

import os
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

BASE = os.environ.get("GODSEYE_CAPTURE_URL", "http://127.0.0.1:8080")
OUT = Path(os.environ.get("GODSEYE_CAPTURE_DIR", "artifacts/ui-captures"))
OUT.mkdir(parents=True, exist_ok=True)
PASSWORD = "Capture-Only!2026-Strong"

VIEWS = [
    ("overview", "godseye-dashboard.png"),
    ("devices", "godseye-devices.png"),
    ("network", "godseye-network-map.png"),
    ("findings", "godseye-findings.png"),
    ("cyber-tools", "godseye-cyber-tools.png"),
    ("event-findings", "godseye-event-findings.png"),
    ("health", "godseye-system-health.png"),
    ("reports", "godseye-reports.png"),
    ("security", "godseye-settings.png"),
    ("about", "godseye-about.png"),
]


def capture() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1600, "height": 900}, device_scale_factor=1)
        page = context.new_page()
        page.goto(BASE, wait_until="domcontentloaded")
        page.wait_for_timeout(700)

        if page.locator("#setupOverlay").is_visible():
            page.fill("#setupPass", PASSWORD)
            page.fill("#setupPass2", PASSWORD)
            page.click("#setupForm button[type=submit]")
            expect(page.locator("#authOverlay")).to_be_visible(timeout=10000)

        if page.locator("#authOverlay").is_visible():
            page.fill("#loginUser", "admin")
            page.fill("#loginPass", PASSWORD)
            page.click("#loginForm button[type=submit]")

        expect(page.locator("#app")).to_be_visible(timeout=15000)
        page.wait_for_timeout(1800)

        # Branding must be the canonical asset, not an inline legacy mark.
        expect(page.locator(".v430-brand img[src='/assets/godseye-mark.svg']")).to_be_visible()
        expect(page.locator(".v430-brand img[src='/assets/godseye-wordmark.svg']")).to_be_visible()

        # Guard against the two typo variants found in earlier generated mockups.
        body_text = page.locator("body").inner_text()
        assert "Devices Inventory" not in body_text
        assert "Recent Result\n" not in body_text
        assert page.locator("img[alt='GODSEYE']").count() >= 1

        for view, filename in VIEWS:
            page.evaluate("(name) => window.showView(name, true)", view)
            page.wait_for_timeout(1500)
            expect(page.locator("#view-" + view)).to_be_visible(timeout=10000)
            page.evaluate("window.scrollTo(0, 0)")
            page.screenshot(path=str(OUT / filename), full_page=False)

        # About is a required part of the approved visual set.
        about_text = page.locator("#view-about").inner_text()
        for phrase in [
            "About",
            "Network Intelligence",
            "Security Operations",
            "MSP Workflow",
            "Self-Hosted Control",
            "Powerful MSP tools without the enterprise price tag.",
        ]:
            assert phrase in about_text, phrase

        browser.close()


if __name__ == "__main__":
    capture()
    print(f"Captured {len(VIEWS)} live GODSEYE screens in {OUT}")
