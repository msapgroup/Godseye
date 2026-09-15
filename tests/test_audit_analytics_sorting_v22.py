import datetime as dt


def _login_admin(main, client):
    password = "Godseye-Test-2026!Strong"
    setup = client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password})
    assert setup.status_code == 200
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert login.status_code == 200
    csrf = client.cookies.get("godseye_csrf")
    assert csrf
    return {"X-CSRF-Token": csrf}


def test_clear_analytics_requires_reason_and_records_actor(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v22-analytics.db"
    try:
        main.init_db()
        with main.db() as c:
            main.ensure_ir_schema(c)
            c.execute(
                "INSERT INTO analytics_snapshots(source,captured_at,data_json) VALUES(?,?,?)",
                ("pihole", main.now(), '{"queries": 42}'),
            )
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            bad = client.post("/api/v1/analytics/clear", headers=headers, json={"reason": "no"})
            assert bad.status_code == 400
            good = client.post(
                "/api/v1/analytics/clear",
                headers=headers,
                json={"reason": "Reviewed the findings and archived the incident."},
            )
            assert good.status_code == 200
            body = good.json()
            assert body["deleted"] == 1
            assert body["cleared_by"] == "admin"
        with main.db() as c:
            assert c.execute("SELECT COUNT(*) FROM analytics_snapshots").fetchone()[0] == 0
            row = c.execute("SELECT * FROM audit_log WHERE action='client_query_analytics_cleared' ORDER BY id DESC LIMIT 1").fetchone()
            assert row["actor"] == "admin"
            assert "Reviewed the findings" in row["details"]
    finally:
        main.DB_PATH = old


def test_clear_analytics_does_not_delete_devices(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v22-device-safety.db"
    try:
        main.init_db()
        with main.db() as c:
            main.ensure_ir_schema(c)
            stamp = main.now()
            c.execute("INSERT INTO devices(mac,name,status,first_seen,last_seen) VALUES(?,?,?,?,?)", ("AA:BB:CC:DD:EE:FF", "Test Device", "online", stamp, stamp))
            c.execute("INSERT INTO analytics_snapshots(source,captured_at,data_json) VALUES(?,?,?)", ("pihole", stamp, '{}'))
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            r = client.post("/api/v1/analytics/clear", headers=headers, json={"reason": "Analytics reviewed and no longer required."})
            assert r.status_code == 200
        with main.db() as c:
            assert c.execute("SELECT COUNT(*) FROM devices WHERE mac='AA:BB:CC:DD:EE:FF'").fetchone()[0] == 1
    finally:
        main.DB_PATH = old


def test_audit_clear_creates_seven_day_protected_marker(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v22-audit.db"
    try:
        main.init_db()
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            first = client.post("/api/v1/audit/clear", headers=headers, json={"reason": "Reviewed security findings for case 2026-09."})
            assert first.status_code == 200
            b1 = first.json()
            assert b1["cleared_by"] == "admin"
            assert dt.datetime.fromisoformat(b1["protected_until"]) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=6)
            second = client.post("/api/v1/audit/clear", headers=headers, json={"reason": "Second review confirmed cleanup was appropriate."})
            assert second.status_code == 200
            assert second.json()["preserved_protected"] >= 1
        with main.db() as c:
            rows = c.execute("SELECT actor,details,protected_until FROM audit_log WHERE action='audit_log_cleared' ORDER BY id").fetchall()
            assert len(rows) == 2
            assert all(r["actor"] == "admin" for r in rows)
            assert all(r["protected_until"] for r in rows)
            assert "Reviewed security findings" in rows[0]["details"]
    finally:
        main.DB_PATH = old


def test_audit_clear_reason_is_mandatory(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v22-audit-reason.db"
    try:
        main.init_db()
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            r = client.post("/api/v1/audit/clear", headers=headers, json={"reason": "   "})
            assert r.status_code == 400
    finally:
        main.DB_PATH = old


def test_v22_ui_has_protected_clear_and_global_sorting_controls():
    from app import main

    html = main.DASHBOARD
    assert "Clear Client & Query Analytics" in html
    assert "Clear Audit Log" in html
    assert "The new audit_log_cleared event is protected and cannot be removed for 7 days." in html
    assert "function sortTableByHeader" in html
    assert "function enableSortableTables" in html
    assert "sortable-head" in html
    assert "const ip=v.match" in html
    assert "admin-only" in html and "admin-visible" in html
