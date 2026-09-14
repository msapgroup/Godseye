from pathlib import Path

def test_v45_version():
    assert Path("VERSION").read_text().strip().startswith(("4.5.0-","4.6.0-", "4.7.0-", "4.8.0-", "4.9.0-", "4.10.0-", "4.10.1-", "4.11.0-", "4.12.0-", "4.13.0-", "4.14.0-", "4.15.0-", "4.16.0-", "4.17.0-", "4.18.0-", "4.19.0-", "4.20.0-", "4.21.0-"))

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
