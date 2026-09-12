from pathlib import Path


def test_v35_version_and_ui_contract():
    from app import main
    assert Path("VERSION").read_text().strip().startswith(("3.5.0-", "3.6.0-", "3.7.0-", "3.8.0-", "3.9.0-", "4.0.0-"))
    html = main.DASHBOARD
    assert 'id="deviceDeleteModal"' in html
    assert 'id="deviceDeleteReason"' in html
    assert 'id="deviceCleanupReason"' in html
    assert "Keep Known and Managed devices" not in html
    assert "applyRoleVisibility()}catch" in html


def test_delete_requires_reason_schema():
    from app.main import DeviceDeleteRequest, DeviceCleanupRequest
    import pytest
    with pytest.raises(Exception):
        DeviceDeleteRequest(reason="")
    with pytest.raises(Exception):
        DeviceCleanupRequest(mode="offline", older_than_days=30, reason="")
    assert DeviceDeleteRequest(reason="Retired device").reason == "Retired device"
