from pathlib import Path

def test_v43_version():
    assert Path("VERSION").read_text().strip().startswith(("4.3.0-","4.4.0-", "4.5.0-", "4.6.0-", "4.7.0-"))

def test_final_dark_normalization_is_last_dashboard_layer():
    source=Path("app/main.py").read_text()
    marker="v4.3 — hard dark-surface normalization"
    assert marker in source
    tail=source[source.index(marker):]
    assert 'html[data-theme="dark"] .card' in tail
    assert 'html[data-theme="dark"] .tool-card' in tail
    assert 'html[data-theme="dark"] .panel' in tail
    assert 'html[data-theme="dark"] .network-device-card' in tail
    assert 'html[data-theme="dark"] .report-type-card' in tail
    assert 'background:var(--gs-surface)!important' in tail

def test_rest_and_hover_states_are_both_dark():
    source=Path("app/main.py").read_text()
    assert 'html[data-theme="dark"] .tool-card:hover' in source
    assert 'background:var(--gs-surface-hover)!important' in source
    assert 'html[data-theme="dark"] .card,' in source
    assert 'background:var(--gs-surface)!important' in source

def test_future_card_panel_surface_safety_net_present():
    source=Path("app/main.py").read_text()
    for token in (
        'html[data-theme="dark"] .view [class$="-card"]',
        'html[data-theme="dark"] .view [class*="-card "]',
        'html[data-theme="dark"] .view [class$="-panel"]',
        'html[data-theme="dark"] .view [class$="-surface"]',
        'html[data-theme="dark"] .view [style*="background:#fff"]',
    ):
        assert token in source

def test_traffic_collection_is_fully_card_based():
    from app import main
    html=main.DASHBOARD
    assert 'class="traffic-card-workspace"' in html
    assert html.count('class="traffic-stat-card"')==4
    assert 'class="traffic-source-section-card"' in html
    assert html.count('class="traffic-source-card"')==4
    assert 'class="traffic-config-section-card"' in html
    assert html.count('class="traffic-mini-card"')==2
    assert 'class="traffic-usage-card"' in html
    for element_id in (
        "trafficSourceLabel","traffic24Rx","traffic24Tx","trafficDeviceCount",
        "trafficIntegration","trafficInterface","trafficInterval","trafficEnabled",
        "trafficDeviceRows",
    ):
        assert f'id="{element_id}"' in html

def test_dark_login_is_still_enforced():
    source=Path("app/main.py").read_text()
    assert 'html[data-theme="dark"] .overlay' in source
    assert 'html[data-theme="dark"] .authcard' in source
    assert "linear-gradient(rgba(2,7,12,.64),rgba(2,7,12,.84))" in source

def test_all_report_cards_remain_present():
    from app import main
    html=main.DASHBOARD
    for report_type in (
        "network_summary","device_inventory","security_findings",
        "availability_monitoring","integrations_health","traffic_usage",
        "audit_activity","device_changes",
    ):
        assert f'data-report-type="{report_type}"' in html
