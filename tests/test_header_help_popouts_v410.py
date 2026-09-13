from pathlib import Path

def test_v410_version():
    assert Path("VERSION").read_text().strip()=="4.10.0-header-help-popouts"

def test_dashboard_has_header_help_modal():
    from app import main
    html=main.DASHBOARD
    assert 'id="headerHelpModal"' in html
    assert 'id="headerHelpModalTitle"' in html
    assert 'id="headerHelpModalBody"' in html
    assert 'class="header-help-close"' in html

def test_header_help_functions_are_present():
    source=Path("app/main.py").read_text()
    for token in (
        "function decorateHeaderHelp()",
        "function openHeaderHelp(title,text)",
        "function closeHeaderHelp()",
        "function headerHelpTextFor(container)",
    ):
        assert token in source

def test_header_descriptions_are_hidden_until_help_requested():
    source=Path("app/main.py").read_text()
    assert ".hero h1 + .muted" in source
    assert ".table-head h2 + .muted" in source
    assert ".table-head > .muted" in source
    assert "display:none!important" in source

def test_system_health_backup_help_text_remains_available():
    from app import main
    html=main.DASHBOARD
    assert "Database Backups" in html
    assert "SQLite online backups with integrity checks." in html
    assert "Restore automatically creates a pre-restore safety backup." in html

def test_dark_mode_help_uses_pihole_blue():
    source=Path("app/main.py").read_text()
    assert 'html[data-theme="dark"] .header-help-btn' in source
    assert "color:#9cc9f5!important" in source

def test_tools_standalone_has_help_popout():
    source=Path("app/main.py").read_text()
    assert 'id="standaloneToolsHelp"' in source
    assert 'class="standalone-help-btn"' in source
    assert "Diagnostics and management tools for your local network." in source
