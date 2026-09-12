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

def test_v41_version():
    assert Path("VERSION").read_text().strip()=="4.1.0-dark-surfaces-report-workspace"

def test_dark_mode_covers_device_discovery_and_other_cards():
    source=Path("app/main.py").read_text()
    for selector in (
        '[data-theme="dark"] .tool-card',
        '[data-theme="dark"] .network-device-card',
        '[data-theme="dark"] .network-connected-card',
        '[data-theme="dark"] .network-controls-card',
        '[data-theme="dark"] .map-summary-card',
        '[data-theme="dark"] .intel-section',
        '[data-theme="dark"] .monitor-summary-card',
        '[data-theme="dark"] .analytics-card',
    ):
        assert selector in source
    assert 'background:#111a25!important' in source

def test_dark_text_is_brighter_and_accessible():
    pairs={
        "body":("#f1f6fc","#0b1119"),
        "heading":("#fbfdff","#111a25"),
        "muted":("#bdcada","#111a25"),
        "table":("#f0f5fb","#111a25"),
        "link":("#8fcbff","#111a25"),
    }
    for name,(fg,bg) in pairs.items():
        assert _contrast(fg,bg)>=4.5,(name,_contrast(fg,bg))

def test_standalone_network_tools_respects_saved_dark_theme():
    source=Path("app/main.py").read_text()
    tools=source[source.index('<title>GODSEYE — Network Tools</title>'):]
    assert "localStorage.getItem('godseye_theme')" in tools[:1200]
    assert '[data-theme="dark"] .tool-card' in tools[:12000]
    assert "Network Discovery" in tools

def test_report_workspace_matches_preview_structure():
    from app import main
    html=main.DASHBOARD
    assert 'class="report-workspace"' in html
    assert 'class="report-kpi-grid"' in html
    assert 'id="reportGeneratedCount"' in html
    assert 'id="reportScheduleCount"' in html
    assert 'id="reportLatestType"' in html
    assert 'class="report-grid-two"' in html
    assert 'class="report-summary-box"' in html
    assert "Scheduled Reports" in html
    assert "Report History" in html

def test_report_kpis_are_populated_by_loader():
    source=Path("app/main.py").read_text()
    assert "reportGeneratedCount.textContent=String(h.length||0)" in source
    assert "reportScheduleCount.textContent=String(sc.length||0)" in source
    assert "reportLatestType.textContent=reportTypeLabel(h[0].report_type)" in source

def test_dark_report_surfaces_are_not_white():
    source=Path("app/main.py").read_text()
    assert '[data-theme="dark"] .report-kpi' in source
    assert '[data-theme="dark"] .report-section-card' in source
    assert '[data-theme="dark"] .report-summary-box' in source
    assert 'background:#111a25!important' in source
