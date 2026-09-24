from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readme_uses_current_branded_screenshot_gallery():
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    shots = [
        'v431-dashboard-map-logo.png',
        'v431-devices-guide.png',
        'v431-network-map-card.png',
        'v431-calendar-guide.png',
        'v431-email-guide.png',
        'v431-system-health-guide.png',
        'v431-remote-access-guide.png',
        'v431-event-findings-guide.png',
        'v431-cyber-tools-overview.png',
        'v431-cyber-tools-working.png',
    ]
    for shot in shots:
        assert f'docs/screenshots/{shot}' in readme
        path = ROOT / 'docs' / 'screenshots' / shot
        assert path.exists() and path.stat().st_size > 20_000
    assert 'captures from the running app' in readme
    assert 'representative sample data' in readme


def test_readme_release_zip_install_and_first_run_admin_are_current():
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    assert 'sudo ./install.sh --fresh' in readme
    assert 'sudo ./install.sh --upgrade' in readme
    assert 'http://YOUR-GODSEYE-IP:8080' in readme
    assert 'no default admin password' in readme


def test_v430_primary_ui_shell_and_cards_are_present():
    source = (ROOT / 'app' / 'main.py').read_text(encoding='utf-8')
    for label in ('Dashboard','Devices','Network Map','Monitoring','Findings','Tools','Integrations','Reports','Calendar','Email','Event Findings','Remote Access','Ticket Portal','System Health','Alert Rules','Users','Audit Log','Settings'):
        assert label in source
    for element_id in ('dashboardGreeting','systemHealthState','trafficSvg','trafficRx','v430Services','v430Tickets'):
        assert element_id in source
    assert 'Unlock Layout' in source
    assert 'Reset My Layout' in source
    assert '/api/v1/ui/layouts/' in source


def test_v430_actual_screen_layouts_include_approved_workspaces():
    source = (ROOT / 'app' / 'main.py').read_text(encoding='utf-8')
    assert 'Network Traffic (Last 24 Hours)' in source
    assert 'Recent Alerts &amp; Findings' in source
    assert 'Monitored Services' in source
    assert 'Recent Tickets' in source
    assert 'Network Map Overview' in source
    assert 'Quick Actions' in source
    assert 'Gmail' in source and 'Microsoft 365' in source and 'Account Settings' in source
    assert 'CPU Usage' in source and 'Memory Usage' in source and 'Disk Usage' in source
    assert 'Remote Session' in source and 'Take Screenshot' in source
