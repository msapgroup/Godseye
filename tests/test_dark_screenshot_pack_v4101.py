from pathlib import Path

LEGACY = {
    "dashboard-full.png","dashboard-overview.png","godseye-reference-design.png",
    "godseye-ui-overview.png","login-2fa.png","login.png","mfa-setup.png",
    "rules.png","users.png","ui-v19-dashboard.png","ui-v19-login.png",
}

def test_version():
    assert Path("VERSION").read_text().strip().startswith(("4.10.1-","4.11.0-", "4.12.0-", "4.13.0-", "4.14.0-"))

def test_only_dark_screenshot_pack_remains():
    shots=Path("docs/screenshots")
    names={p.name for p in shots.glob("*.png")}
    assert not (names & LEGACY)
    required={
        "godseye-dark-mode-overview.png","godseye-dark-mode-header-help.png",
        "dark-dashboard.png","dark-network-map.png","dark-devices.png",
        "dark-findings.png","dark-monitoring.png","dark-integrations.png",
        "dark-network-tools.png","dark-reports.png","dark-system-health.png",
    }
    assert required <= names

def test_old_ui_v19_images_removed():
    assert not Path("docs/ui-v19-dashboard.png").exists()
    assert not Path("docs/ui-v19-login.png").exists()

def test_markdown_references_current_dark_images_only():
    import re
    for md in Path(".").rglob("*.md"):
        text=md.read_text(errors="ignore")
        refs=set(re.findall(r"[A-Za-z0-9_./-]+\\.(?:png|jpg|jpeg|webp)",text,re.I))
        for name in LEGACY:
            assert not any(ref.endswith(name) for ref in refs), (md,name,refs)
    screenshots=Path("docs/SCREENSHOTS.md").read_text()
    assert "godseye-dark-mode-overview.png" in screenshots
    assert "dark-dashboard.png" in screenshots
    assert "dark-system-health.png" in screenshots

def test_ui_design_describes_dark_workspace():
    text=Path("docs/UI_DESIGN.md").read_text()
    assert "dark-mode workspace" in text
    assert "white/light workspace" not in text
