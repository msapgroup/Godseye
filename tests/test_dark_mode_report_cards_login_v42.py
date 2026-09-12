from pathlib import Path

def _rgb(v):
    v=v.lstrip("#")
    return tuple(int(v[i:i+2],16)/255 for i in (0,2,4))

def _lum(v):
    def c(x): return x/12.92 if x<=.04045 else ((x+.055)/1.055)**2.4
    r,g,b=_rgb(v); return .2126*c(r)+.7152*c(g)+.0722*c(b)

def _contrast(a,b):
    hi,lo=sorted((_lum(a),_lum(b)),reverse=True)
    return (hi+.05)/(lo+.05)

def test_v42_version():
    assert Path("VERSION").read_text().strip().startswith(("4.2.0-","4.3.0-", "4.4.0-", "4.5.0-", "4.6.0-"))

def test_final_dark_layer_covers_white_card_families():
    source=Path("app/main.py").read_text()
    required=(
        'html[data-theme="dark"] .tool-card',
        'html[data-theme="dark"] .network-topology-panel',
        'html[data-theme="dark"] .network-device-card',
        'html[data-theme="dark"] .network-connected-card',
        'html[data-theme="dark"] .network-controls-card',
        'html[data-theme="dark"] .intel-section',
        'html[data-theme="dark"] .analytics-card',
        'html[data-theme="dark"] .monitor-summary-card',
        'html[data-theme="dark"] .report-kpi',
        'html[data-theme="dark"] .traffic-source-card',
    )
    for token in required:
        assert token in source
    assert 'background:#101923!important' in source

def test_dark_text_is_brighter_than_v41():
    pairs={
        "body":("#f5f9ff","#080e16"),
        "heading":("#ffffff","#101923"),
        "secondary":("#c8d4e3","#101923"),
        "table":("#f3f7fc","#101923"),
    }
    for name,(fg,bg) in pairs.items():
        assert _contrast(fg,bg)>=4.5,(name,_contrast(fg,bg))

def test_login_has_dark_mode_overrides():
    source=Path("app/main.py").read_text()
    for token in (
        'html[data-theme="dark"] .login-scene',
        'html[data-theme="dark"] .authcard',
        'html[data-theme="dark"] .authcard input',
        'html[data-theme="dark"] .authcard label',
        'html[data-theme="dark"] .login-scene-footer',
    ):
        assert token in source
    assert "localStorage.getItem('godseye_theme')" in source

def test_all_eight_reports_are_visible_selectable_cards():
    from app import main
    html=main.DASHBOARD
    types=(
        "network_summary","device_inventory","security_findings",
        "availability_monitoring","integrations_health","traffic_usage",
        "audit_activity","device_changes",
    )
    for report_type in types:
        assert f'data-report-type="{report_type}"' in html
        assert f"selectReportType('{report_type}')" in html
    assert html.count('class="report-type-card') >= 8
    assert "Generate Selected Report" in html

def test_report_card_selection_is_wired_to_generation_select():
    source=Path("app/main.py").read_text()
    assert "function selectReportType(type)" in source
    assert "sel.value=type" in source
    assert "el.dataset.reportType===type" in source
    assert "encodeURIComponent(reportGenerateType.value)" in source

def test_report_cards_have_dark_theme_states():
    source=Path("app/main.py").read_text()
    assert 'html[data-theme="dark"] .report-type-card' in source
    assert 'html[data-theme="dark"] .report-type-card.active' in source
    assert 'html[data-theme="dark"] .report-type-name' in source
    assert 'html[data-theme="dark"] .report-type-desc' in source


def test_dark_card_safety_net_and_actual_login_overlay():
    source=Path("app/main.py").read_text()
    assert 'html[data-theme="dark"] .view [class$="-card"]' in source
    assert 'html[data-theme="dark"] .view [class*="-card "]' in source
    assert 'html[data-theme="dark"] .overlay' in source
    assert "linear-gradient(rgba(2,7,12,.55),rgba(2,7,12,.78))" in source
