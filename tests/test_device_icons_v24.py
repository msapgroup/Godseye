import base64


def _login_admin(main, client):
    password = "Godseye-Test-2026!Strong"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
    csrf = client.cookies.get("godseye_csrf")
    assert csrf
    return {"X-CSRF-Token": csrf}


def test_device_icon_fields_migrate_and_can_be_updated(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v24-icons.db"
    try:
        main.init_db()
        stamp = main.now()
        with main.db() as c:
            cols = {r[1] for r in c.execute("PRAGMA table_info(devices)")}
            assert {"icon_key", "icon_data"} <= cols
            c.execute(
                "INSERT INTO devices(mac,ip,name,device_type,status,first_seen,last_seen,classification) VALUES(?,?,?,?,?,?,?,?)",
                ("aa:bb:cc:dd:ee:24", "192.168.1.24", "Gateway", "Router", "online", stamp, stamp, "managed"),
            )
            device_id = c.execute("SELECT id FROM devices WHERE mac=?", ("aa:bb:cc:dd:ee:24",)).fetchone()[0]
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            r = client.patch(f"/api/v1/devices/{device_id}", headers=headers, json={"icon_key": "router", "icon_data": None})
            assert r.status_code == 200
            d = client.get(f"/api/v1/devices/{device_id}").json()
            assert d["icon_key"] == "router"
            assert d["icon_data"] is None
    finally:
        main.DB_PATH = old


def test_custom_icon_is_supported_and_preset_clears_it(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v24-custom-icon.db"
    try:
        main.init_db()
        stamp = main.now()
        with main.db() as c:
            c.execute(
                "INSERT INTO devices(mac,device_type,status,first_seen,last_seen,classification) VALUES(?,?,?,?,?,?)",
                ("aa:bb:cc:dd:ee:25", "Camera", "online", stamp, stamp, "known"),
            )
            device_id = c.execute("SELECT id FROM devices WHERE mac=?", ("aa:bb:cc:dd:ee:25",)).fetchone()[0]
        png = b"\x89PNG\r\n\x1a\n" + b"test-icon"
        data_url = "data:image/png;base64," + base64.b64encode(png).decode()
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            r = client.patch(f"/api/v1/devices/{device_id}", headers=headers, json={"icon_key": "other", "icon_data": data_url})
            assert r.status_code == 200
            assert client.get(f"/api/v1/devices/{device_id}").json()["icon_data"] == data_url
            r = client.patch(f"/api/v1/devices/{device_id}", headers=headers, json={"icon_key": "camera", "icon_data": None})
            assert r.status_code == 200
            d = client.get(f"/api/v1/devices/{device_id}").json()
            assert d["icon_key"] == "camera"
            assert d["icon_data"] is None
    finally:
        main.DB_PATH = old


def test_device_icon_ui_contracts_and_assets():
    from app import main
    html = main.DASHBOARD
    assert 'id="deviceIconModal"' in html
    assert 'Select Device Icon' in html
    assert 'openDeviceIconFromButton' in html
    assert 'previewCustomDeviceIcon' in html
    assert 'deviceIconHtml(x)' in html
    assert '>Icon</button>' in html
    assert "inferredDeviceIcon" in html
    detail = main.device_detail_page(24).body.decode()
    assert 'id="detailDeviceIcon"' in detail
    assert 'Change Icon in Inventory' in detail
    for key in main.VALID_DEVICE_ICONS - {"auto"}:
        assert (main.DEVICE_ICON_DIR / f"{key}.svg").exists()


def test_device_icon_validation_rejects_bad_key_and_oversize_custom_image():
    from app.main import DeviceUpdate
    from pydantic import ValidationError

    try:
        DeviceUpdate(icon_key="spaceship")
        assert False, "invalid icon key should fail"
    except ValidationError:
        pass

    raw = b"x" * (262144 + 1)
    data_url = "data:image/png;base64," + base64.b64encode(raw).decode()
    try:
        DeviceUpdate(icon_data=data_url)
        assert False, "oversize icon should fail"
    except ValidationError:
        pass
