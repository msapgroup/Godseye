import datetime as dt
import json
from pathlib import Path


def _login_admin(main, client):
    password = "Godseye-Test-2026!Strong"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
    return {"X-CSRF-Token": client.cookies.get("godseye_csrf")}


def test_v34_version():
    assert Path("VERSION").read_text().strip().startswith(("3.4.0-", "3.5.0-", "3.6.0-", "3.7.0-", "3.8.0-", "3.9.0-", "4.0.0-", "4.1.0-", "4.2.0-", "4.3.0-", "4.4.0-", "4.5.0-", "4.6.0-"))


def test_inventory_has_cleanup_and_per_device_delete_ui():
    from app import main
    html = main.DASHBOARD
    assert "Clean Up Devices" in html
    assert 'id="deviceCleanupModal"' in html
    assert "deleteInventoryDevice" in html
    assert "Delete all offline devices" in html
    assert "Delete old devices" in html


def test_rule_ui_has_expanded_options():
    from app import main
    html = main.DASHBOARD
    for value in ["ip_change_burst", "reconnect_burst", "offline_count", "scanner_stale", "classification_count"]:
        assert f'value="{value}"' in html
    assert len(main.VALID_RULE_TYPES) >= 7


def test_bulk_cleanup_deletes_old_devices_without_status_or_classification_safety(tmp_path):
    from app import main
    from fastapi.testclient import TestClient
    old_db = main.DB_PATH
    main.DB_PATH = tmp_path / "v35.db"
    try:
        main.init_db()
        now = dt.datetime.now(dt.timezone.utc)
        old = (now - dt.timedelta(days=90)).isoformat()
        recent = now.isoformat()
        with main.db() as c:
            rows = [
                ("AA:00:00:00:00:01", "10.0.0.1", "Old unknown", "offline", old, "new"),
                ("AA:00:00:00:00:02", "10.0.0.2", "Old managed", "offline", old, "managed"),
                ("AA:00:00:00:00:03", "10.0.0.3", "Online old timestamp", "online", old, "known"),
                ("AA:00:00:00:00:04", "10.0.0.4", "Recent offline", "offline", recent, "new"),
            ]
            for mac, ip, name, status, last_seen, classification in rows:
                c.execute("INSERT INTO devices(mac,ip,name,status,first_seen,last_seen,classification) VALUES(?,?,?,?,?,?,?)",
                          (mac, ip, name, status, last_seen, last_seen, classification))
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            r = client.post("/api/v1/devices/cleanup", headers=headers, json={"mode":"old","older_than_days":30,"reason":"Retiring stale inventory"})
            assert r.status_code == 200, r.text
            assert r.json()["deleted"] == 3
        with main.db() as c:
            remaining = {r["mac"] for r in c.execute("SELECT mac FROM devices")}
            assert remaining == {"AA:00:00:00:00:04"}
            audit = c.execute("SELECT details FROM audit_log WHERE action='device_cleanup' ORDER BY id DESC LIMIT 1").fetchone()
            assert audit and "deleted=3" in audit["details"] and "reason=Retiring stale inventory" in audit["details"]
    finally:
        main.DB_PATH = old_db


def test_individual_delete_cleans_owned_history_and_preserves_audit(tmp_path):
    from app import main
    from fastapi.testclient import TestClient
    old_db = main.DB_PATH
    main.DB_PATH = tmp_path / "v34-delete.db"
    try:
        main.init_db()
        t = main.now()
        with main.db() as c:
            c.execute("INSERT INTO devices(mac,ip,name,status,first_seen,last_seen,classification) VALUES(?,?,?,?,?,?,?)",
                      ("AA:BB:CC:DD:EE:01", "10.1.1.8", "Retired", "offline", t, t, "new"))
            did = c.execute("SELECT id FROM devices WHERE mac='AA:BB:CC:DD:EE:01'").fetchone()[0]
            c.execute("INSERT INTO events(mac,event_type,ip,created_at,details,severity) VALUES(?,?,?,?,?,?)",
                      ("AA:BB:CC:DD:EE:01", "disconnected", "10.1.1.8", t, "test", "warning"))
            c.execute("INSERT INTO device_sources(mac,source,ip,first_seen,last_seen) VALUES(?,?,?,?,?)",
                      ("AA:BB:CC:DD:EE:01", "arp", "10.1.1.8", t, t))
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            r = client.request("DELETE", f"/api/v1/devices/{did}", headers=headers, json={"reason":"Device retired"})
            assert r.status_code == 200, r.text
        with main.db() as c:
            assert c.execute("SELECT COUNT(*) FROM devices WHERE id=?", (did,)).fetchone()[0] == 0
            assert c.execute("SELECT COUNT(*) FROM events WHERE mac='AA:BB:CC:DD:EE:01'").fetchone()[0] == 0
            assert c.execute("SELECT COUNT(*) FROM device_sources WHERE mac='AA:BB:CC:DD:EE:01'").fetchone()[0] == 0
            audit = c.execute("SELECT details FROM audit_log WHERE action='device_deleted' AND target='AA:BB:CC:DD:EE:01' ORDER BY id DESC LIMIT 1").fetchone()
            assert audit and 'reason=Device retired' in audit['details']
    finally:
        main.DB_PATH = old_db


def test_new_rule_types_validate_and_save(tmp_path):
    from app import main
    from fastapi.testclient import TestClient
    old_db = main.DB_PATH
    main.DB_PATH = tmp_path / "v34-rules.db"
    try:
        main.init_db()
        cases = [
            ("ip_change_burst", {"count": 2, "window_minutes": 5}),
            ("reconnect_burst", {"count": 3, "window_minutes": 10}),
            ("offline_count", {"count": 5, "cooldown_minutes": 15}),
            ("scanner_stale", {"minutes": 10}),
            ("classification_count", {"count": 1, "classifications": ["new", "investigate"], "cooldown_minutes": 15}),
        ]
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            for typ, params in cases:
                r = client.post("/api/v1/rules", headers=headers, json={"name": typ, "rule_type": typ, "params": params, "severity": "warning"})
                assert r.status_code == 200, (typ, r.text)
        with main.db() as c:
            assert c.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == len(cases)
    finally:
        main.DB_PATH = old_db
