from pathlib import Path

def test_v48_version():
    assert Path("VERSION").read_text().strip().startswith(("4.8.0-","4.9.0-"))

def test_monitoring_dark_mode_uses_pihole_blue():
    source=Path("app/main.py").read_text()
    assert 'html[data-theme="dark"] #view-monitoring .monitor-summary-card .k' in source
    assert 'html[data-theme="dark"] #view-monitoring .monitor-target' in source
    assert 'html[data-theme="dark"] #view-monitoring .monitor-type-badge' in source
    assert 'color:#9cc9f5!important' in source
    assert 'monitor-summary-card.good .v{color:#35d391!important}' in source
    assert 'monitor-summary-card.bad .v{color:#ff6278!important}' in source

def test_tools_dashboard_has_exactly_six_launcher_cards():
    from app import main
    html=main.DASHBOARD
    start=html.index('id="view-tools"')
    end=html.index('id="view-integrations"',start)
    block=html[start:end]
    assert block.count('class="tool-card"')==6

def test_tools_launcher_is_three_columns_two_rows():
    source=Path("app/main.py").read_text()
    assert '#view-tools .tool-grid{' in source
    assert 'grid-template-columns:repeat(3,minmax(0,1fr))!important' in source
    assert 'min-height:122px!important' in source
    assert 'padding:14px!important' in source

def test_tools_responsive_breakpoints_remain():
    source=Path("app/main.py").read_text()
    assert '#view-tools .tool-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}' in source
    assert '#view-tools .tool-grid{grid-template-columns:1fr!important}' in source
