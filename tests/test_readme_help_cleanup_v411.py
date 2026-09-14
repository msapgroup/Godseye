from pathlib import Path

def test_version():
    assert Path("VERSION").read_text().strip().startswith(("4.11.0-","4.12.0-", "4.13.0-", "4.14.0-", "4.15.0-", "4.16.0-", "4.17.0-", "4.18.0-", "4.19.0-", "4.20.0-", "4.21.0-"))

def test_readme_is_godseye_first():
    text=Path("README.md").read_text()
    assert "GODSEYE is a self-hosted network visibility and security appliance" in text
    assert ("pi"+".alert").lower() not in text.lower()
    assert ("net"+"alertx").lower() not in text.lower()

def test_obsolete_parity_doc_not_packaged():
    assert not any("parity" in x.name.lower() for x in Path("docs").glob("*.md"))

def test_requested_help_copy_is_hidden_and_dynamic():
    source=Path("app/main.py").read_text()
    assert 'class="muted header-help-extra">Prometheus can authenticate' in source
    assert 'id="httpsOut" class="muted header-help-extra"' in source
    assert '.header-help-extra{display:none!important}' in source
    assert "querySelectorAll('.header-help-extra')" in source
    assert "const helpText=[text,...extras]" in source

def test_dark_screenshot_pack_carried_forward():
    shots=Path("docs/screenshots")
    assert (shots/"godseye-dark-mode-overview.png").exists()
    assert (shots/"godseye-dark-mode-header-help.png").exists()
