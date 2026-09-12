from pathlib import Path

SOURCE = Path('app/main.py').read_text()


def test_device_add_is_centered_modal():
    assert 'id="deviceModal" class="modal"' in SOURCE
    assert "onclick=\"if(event.target===this)closeAddDevice()\"" in SOURCE
    assert "function openAddDevice(){const m=document.getElementById('deviceModal')" in SOURCE
    assert "document.body.style.overflow='hidden'" in SOURCE


def test_monitor_editor_is_centered_modal():
    assert 'id="monitorModal" class="modal"' in SOURCE
    assert 'aria-labelledby="monitorModalTitle"' in SOURCE
    assert "onclick=\"if(event.target===this)closeMonitorEditor()\"" in SOURCE
    assert 'Create a persistent Raspberry Pi-native health check.' in SOURCE


def test_dashboard_has_real_modal_overlay_css():
    assert '.modal{position:fixed!important;inset:0!important;z-index:4800!important' in SOURCE
    assert 'backdrop-filter:blur(2px)' in SOURCE
    assert '.modal-card{width:min(620px,calc(100vw - 36px))' in SOURCE


def test_monitoring_page_cleanup():
    for key in ['monitorTotalSummary','monitorHealthySummary','monitorFailingSummary','monitorDisabledSummary']:
        assert key in SOURCE
    assert 'monitor-type-badge' in SOURCE
    assert 'monitor-empty' in SOURCE


def test_escape_closes_new_modals():
    assert "if(e.key!=='Escape')return" in SOURCE
    assert 'closeMonitorEditor();return' in SOURCE
    assert 'closeAddDevice();return' in SOURCE


def test_v30_version():
    assert Path('VERSION').read_text().strip().startswith(('3.0.0-', '3.1.0-', '3.2.0-', '3.3.0-', '3.4.0-', '3.5.0-', '3.6.0-', '3.7.0-', '3.8.0-', '3.9.0-', '4.0.0-', '4.1.0-', '4.2.0-'))
