import sqlite3


def _login_admin(main, client):
    password = "Godseye-Test-2026!Strong"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
    csrf = client.cookies.get("godseye_csrf")
    assert csrf
    return {"X-CSRF-Token": csrf}


def test_multi_instance_schema_migrates_legacy_unique_kind(tmp_path):
    from app.integration_reporting import ensure_schema
    db = tmp_path / "legacy.db"
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE integration_configs(
        id INTEGER PRIMARY KEY, kind TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 0,
        target TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '', secret TEXT NOT NULL DEFAULT '',
        verify_tls INTEGER NOT NULL DEFAULT 1, sync_interval_seconds INTEGER NOT NULL DEFAULT 300,
        options_json TEXT NOT NULL DEFAULT '{}', last_sync_at TEXT, last_sync_status TEXT NOT NULL DEFAULT 'never',
        last_sync_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    c.execute("INSERT INTO integration_configs(kind,enabled,target,created_at,updated_at) VALUES('pihole',1,'http://pi1','x','x')")
    ensure_schema(c)
    cols = {r['name'] for r in c.execute("PRAGMA table_info(integration_configs)")}
    assert 'name' in cols
    c.execute("INSERT INTO integration_configs(name,kind,enabled,target,created_at,updated_at) VALUES('Pi-hole 2','pihole',1,'http://pi2','x','x')")
    assert c.execute("SELECT COUNT(*) FROM integration_configs WHERE kind='pihole'").fetchone()[0] == 2
    c.close()


def test_api_allows_multiple_pihole_instances_and_targeted_analytics_clear(tmp_path):
    from app import main
    from fastapi.testclient import TestClient
    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v31.db"
    try:
        main.init_db()
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            for name, target in [("Home Pi-hole", "http://192.168.1.2"), ("Lab Pi-hole", "http://192.168.1.3")]:
                r = client.post("/api/v1/integrations/configs", headers=headers, json={
                    "name": name, "kind": "pihole", "target": target, "enabled": True,
                    "secret": None, "verify_tls": False, "sync_interval_seconds": 300,
                    "options": {}
                })
                assert r.status_code == 200, r.text
            configs = client.get("/api/v1/integrations/configs").json()["configs"]
            pi = [x for x in configs if x["kind"] == "pihole"]
            assert len(pi) == 2
            assert {x["name"] for x in pi} == {"Home Pi-hole", "Lab Pi-hole"}
            first = pi[0]
            with main.db() as c:
                c.execute("INSERT INTO analytics_snapshots(source,integration_id,integration_name,captured_at,data_json) VALUES(?,?,?,?,?)",
                          ("pihole", first["id"], first["name"], main.now(), '{"queries":123,"blocked":7}'))
                second = pi[1]
                c.execute("INSERT INTO analytics_snapshots(source,integration_id,integration_name,captured_at,data_json) VALUES(?,?,?,?,?)",
                          ("pihole", second["id"], second["name"], main.now(), '{"queries":456,"blocked":8}'))
            analytics = client.get("/api/v1/analytics/clients").json()["integration_analytics"]
            assert len(analytics) == 2
            cleared = client.post(f"/api/v1/analytics/clear/{first['id']}", headers=headers, json={"reason": "Reviewed dashboard analytics"})
            assert cleared.status_code == 200
            with main.db() as c:
                assert c.execute("SELECT COUNT(*) FROM analytics_snapshots WHERE integration_id=?", (first["id"],)).fetchone()[0] == 0
                assert c.execute("SELECT COUNT(*) FROM analytics_snapshots WHERE integration_id=?", (second["id"],)).fetchone()[0] == 1
                audit = c.execute("SELECT actor,action,details FROM audit_log WHERE action='integration_analytics_cleared' ORDER BY id DESC LIMIT 1").fetchone()
                assert audit["actor"] == "admin"
                assert "Reviewed dashboard analytics" in audit["details"]
    finally:
        main.DB_PATH = old


def test_integrations_ui_is_card_based_and_modal_driven():
    from app import main
    html = main.DASHBOARD
    assert 'id="integrationList"' in html
    assert 'id="integrationModal"' in html
    assert '+ Add Integration' in html
    assert 'id="analyticsModal"' in html
    assert 'Clear This Analytics' in html
    assert 'class="notify-grid"' in html
    assert '>Webhook<' in html and '>ntfy Push<' in html and '>Email / SMTP<' in html
    assert 'openIntegrationModal' in html
    assert 'integration_analytics' in html
