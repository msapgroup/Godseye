from pathlib import Path

def test_v45_version():
    assert Path("VERSION").read_text().strip().startswith(("4.5.0-","4.6.0-"))

def test_integration_card_metadata_uses_pihole_blue():
    source=Path("app/main.py").read_text()
    assert ".integration-card .integration-meta," in source
    assert "color:#1872d7!important" in source
    assert 'html[data-theme="dark"] .integration-card .integration-meta' in source
    assert "color:#9cc9f5!important" in source

def test_integration_card_still_contains_target_sync_and_enabled_metadata():
    source=Path("app/main.py").read_text()
    assert "<b>Target:</b>" in source
    assert "<b>Last sync:</b>" in source
    assert "c.enabled?'● Enabled':'○ Disabled'" in source
    assert "interval_seconds||300" in source
