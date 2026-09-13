from pathlib import Path


def test_delete_button_uses_safe_data_attributes():
    html = Path('app/main.py').read_text()
    assert 'data-delete-id="${x.id}"' in html
    assert 'data-delete-name="${esc(x.name||x.hostname||x.mac||\'Device\')}"' in html
    assert 'data-delete-status="${esc(x.status||\'unknown\')}"' in html
    assert 'openDeleteDeviceFromButton(this)' in html
    assert "deleteInventoryDevice(${x.id},${JSON.stringify" not in html


def test_delete_button_adapter_and_reason_flow_present():
    html = Path('app/main.py').read_text()
    assert 'function openDeleteDeviceFromButton(btn)' in html
    assert "btn.dataset.deleteId" in html
    assert "btn.dataset.deleteName" in html
    assert "btn.dataset.deleteStatus" in html
    assert "method:'DELETE'" in html
    assert "JSON.stringify({reason})" in html
    assert 'The reason and administrator were recorded in the Audit Log.' in html


def test_v36_version():
    assert Path('VERSION').read_text().strip().startswith(('3.6.0-', '3.7.0-', '3.8.0-', '3.9.0-', '4.0.0-', '4.1.0-', '4.2.0-', '4.3.0-', '4.4.0-', '4.5.0-', '4.6.0-', '4.7.0-', '4.8.0-', '4.9.0-'))
