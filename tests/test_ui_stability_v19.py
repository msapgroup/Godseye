from pathlib import Path


def test_dashboard_critical_ui_contracts():
    from app import main
    html = main.DASHBOARD
    # Boot/runtime regressions that previously disabled the whole application.
    assert "async function loadDashboard()" in html
    assert "async function load(){return loadDashboard()}" in html
    assert "updated.textContent" not in html
    assert "function goDevice(id)" in html
    assert "window.location.assign('/device/'" in html
    assert 'id="view-device"' not in html  # details are a dedicated page, not a hidden global block
    assert "id=\"scanStatus\"" in html
    assert "const req=st.request" in html
    for fn in [
        "loadUsers", "loadAudit", "loadSecurity", "loadRules", "csrfToken",
        "loadEvents", "loadTraffic", "loadInventory",
    ]:
        assert f"function {fn}" in html or f"function {fn}(" in html or f"async function {fn}(" in html


def test_device_detail_is_a_dedicated_page():
    from app import main
    html = main.device_detail_page(7).body.decode()
    assert "← Back to Devices" in html
    assert 'href="/#devices"' in html
    assert "const DEVICE_ID=7" in html
    assert "Device Overview" in html
    assert "Recent Activity" in html
    assert "IP History" in html
    assert "Evidence Sources" in html


def test_login_background_asset_exists():
    from app import main
    asset = Path(main.BASE_DIR) / "app" / "assets" / "login-bg.jpg"
    assert asset.exists()
    assert asset.stat().st_size > 10_000
    assert "url('/assets/login-bg.jpg')" in main.DASHBOARD


def test_scan_api_queues_and_status_is_readable(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / "ui-stability.db"
    try:
        main.init_db()
        with TestClient(main.app) as client:
            password = "Godseye-Test-2026!Strong"
            setup = client.post(
                "/api/v1/auth/setup",
                json={"current_password": "", "new_password": password},
            )
            assert setup.status_code == 200
            login = client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": password},
            )
            assert login.status_code == 200
            csrf = client.cookies.get("godseye_csrf")
            assert csrf
            queued = client.post("/api/v1/scan", headers={"X-CSRF-Token": csrf})
            assert queued.status_code == 200
            q = queued.json()
            assert q["request_id"] >= 1
            status = client.get("/api/v1/scan/status")
            assert status.status_code == 200
            req = status.json()["request"]
            assert req["id"] == q["request_id"]
            assert req["status"] == "pending"
    finally:
        main.DB_PATH = old
