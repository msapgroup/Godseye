from pathlib import Path

def test_version():
    assert Path("VERSION").read_text().strip().startswith(("4.12.0-","4.13.0-", "4.14.0-", "4.15.0-", "4.16.0-", "4.17.0-", "4.18.0-", "4.19.0-", "4.20.0-", "4.21.0-", "4.22.0-", "4.22.1-", "4.23.0-", '4.28.0-'))

def test_analytics_modal_has_full_dark_surface_rules():
    source=Path("app/main.py").read_text()
    for token in (
        'html[data-theme="dark"] .modal .modal-card',
        'html[data-theme="dark"] .modal .modal-head',
        'html[data-theme="dark"] .modal .analytics-summary div',
        'html[data-theme="dark"] #analyticsDetail',
        'html[data-theme="dark"] .modal textarea',
        'html[data-theme="dark"] .modal .secondary',
        'html[data-theme="dark"] .modal .danger',
    ):
        assert token in source

def test_modal_header_is_not_white_in_dark_mode():
    source=Path("app/main.py").read_text()
    assert 'background:#0d1621!important' in source
    assert 'background-image:none!important' in source
    assert 'color:#ffffff!important' in source

def test_inline_white_modal_surfaces_are_caught():
    source=Path("app/main.py").read_text()
    for token in (
        'html[data-theme="dark"] .modal [style*="background:#fff"]',
        'html[data-theme="dark"] .modal [style*="background: #fff"]',
        'html[data-theme="dark"] .modal [style*="background:white"]',
    ):
        assert token in source

def test_all_dashboard_modals_share_modal_class():
    from app import main
    html=main.DASHBOARD
    ids=(
        "analyticsModal","clearDataModal","integrationModal","notificationHistoryModal",
        "deviceDeleteModal","deviceCleanupModal","monitorModal","addDeviceModal",
    )
    present=[x for x in ids if f'id="{x}"' in html]
    assert "analyticsModal" in present
    assert "clearDataModal" in present
    import re
    for x in present:
        tag=re.search(rf'<div[^>]*id="{x}"[^>]*>',html)
        assert tag and re.search(r'class="[^"]*\bmodal\b[^"]*"',tag.group(0)), (x,tag.group(0) if tag else None)
