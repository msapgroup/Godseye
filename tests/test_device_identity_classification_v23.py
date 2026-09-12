def _login_admin(main, client):
    password = "Godseye-Test-2026!Strong"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
    csrf = client.cookies.get("godseye_csrf")
    assert csrf
    return {"X-CSRF-Token": csrf}


def test_identity_api_accepts_hostname_type_and_managed_classification(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v23-identity.db"
    try:
        main.init_db()
        stamp = main.now()
        with main.db() as c:
            c.execute(
                "INSERT INTO devices(mac,ip,hostname,vendor,name,device_type,status,first_seen,last_seen,classification) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("aa:bb:cc:dd:ee:23", "192.168.1.23", None, "Vendor", "Office Device", "unknown", "online", stamp, stamp, "new"),
            )
            device_id = c.execute("SELECT id FROM devices WHERE mac=?", ("aa:bb:cc:dd:ee:23",)).fetchone()[0]
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            r = client.patch(
                f"/api/v1/devices/{device_id}",
                headers=headers,
                json={"hostname": "office-router", "device_type": "Router", "classification": "managed"},
            )
            assert r.status_code == 200
            d = client.get(f"/api/v1/devices/{device_id}").json()
            assert d["hostname"] == "office-router"
            assert d["device_type"] == "Router"
            assert d["classification"] == "managed"
        with main.db() as c:
            audit = c.execute("SELECT actor,action,details FROM audit_log WHERE action='device_updated' ORDER BY id DESC LIMIT 1").fetchone()
            assert audit["actor"] == "admin"
            assert "hostname=?" in audit["details"]
            assert "device_type=?" in audit["details"]
            assert "classification=?" in audit["details"]
    finally:
        main.DB_PATH = old


def test_managed_is_valid_for_scanner_rules_and_device_model():
    from app import main, scanner
    assert "managed" in main.VALID_CLASSIFICATIONS
    assert "managed" in scanner.VALID_CLASSIFICATIONS


def test_v23_inventory_has_type_and_classification_editor():
    from app import main
    html = main.DASHBOARD
    assert '<th>Classification</th>' in html
    assert 'id="classifyDeviceModal"' in html
    assert 'openClassifyDeviceFromButton' in html
    assert '>Classify</button>' in html
    assert '<option value="managed">Managed</option>' in html
    assert 'Router, PC, Camera, Switch' in html


def test_v23_device_identity_box_is_editable():
    from app import main
    detail = main.device_detail_page(23).body.decode()
    assert 'id="identityHostname"' in detail
    assert 'id="identityType"' in detail
    assert 'id="identityClassification"' in detail
    assert 'Save Identity' in detail
    assert 'function saveIdentity()' in detail
    assert '<option value="managed"' in detail
    assert 'deviceTypeChoices' in detail
