from pathlib import Path


def _login_admin(main, client):
    password = "Godseye-Test-2026!Strong"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
    csrf = client.cookies.get("godseye_csrf")
    return {"X-CSRF-Token": csrf}


def test_v32_version():
    assert Path("VERSION").read_text().strip().startswith(("3.2.0-", "3.3.0-", "3.4.0-", "3.5.0-", "3.6.0-", "3.7.0-", "3.8.0-", "3.9.0-", "4.0.0-", "4.1.0-", "4.2.0-", "4.3.0-", "4.4.0-", "4.5.0-", "4.6.0-", "4.7.0-", "4.8.0-"))


def test_integrations_have_visible_remove_workflow():
    from app import main
    html = main.DASHBOARD
    assert 'id="deleteIntegrationModal"' in html
    assert 'openDeleteIntegrationModal' in html
    assert 'confirmDeleteIntegration' in html
    assert 'Type REMOVE to confirm' in html
    assert '>Remove</button>' in html
    assert 'Saved analytics will remain until cleared' not in html


def test_delete_integration_removes_owned_history_and_audits(tmp_path):
    from app import main
    from fastapi.testclient import TestClient
    old = main.DB_PATH
    main.DB_PATH = tmp_path / "v32.db"
    try:
        main.init_db()
        with TestClient(main.app) as client:
            headers = _login_admin(main, client)
            r = client.post("/api/v1/integrations/configs", headers=headers, json={
                "name": "Retired Pi-hole", "kind": "pihole", "target": "http://192.168.50.2",
                "enabled": True, "secret": None, "verify_tls": False,
                "sync_interval_seconds": 300, "options": {}
            })
            assert r.status_code == 200, r.text
            iid = r.json()["id"]
            with main.db() as c:
                main.ensure_ir_schema(c)
                c.execute("INSERT INTO analytics_snapshots(source,integration_id,integration_name,captured_at,data_json) VALUES(?,?,?,?,?)",
                          ("pihole", iid, "Retired Pi-hole", main.now(), '{"queries":99}'))
                c.execute("INSERT INTO integration_sync_runs(integration_kind,started_at,completed_at,status,observations,analytics_json,error,integration_id,integration_name) VALUES(?,?,?,?,?,?,?,?,?)",
                          ("pihole", main.now(), main.now(), "success", 1, '{}', None, iid, "Retired Pi-hole"))
            d = client.delete(f"/api/v1/integrations/configs/{iid}", headers=headers)
            assert d.status_code == 200, d.text
            body = d.json()
            assert body["analytics_deleted"] == 1
            assert body["sync_runs_deleted"] == 1
            with main.db() as c:
                assert c.execute("SELECT COUNT(*) FROM integration_configs WHERE id=?", (iid,)).fetchone()[0] == 0
                assert c.execute("SELECT COUNT(*) FROM analytics_snapshots WHERE integration_id=?", (iid,)).fetchone()[0] == 0
                assert c.execute("SELECT COUNT(*) FROM integration_sync_runs WHERE integration_id=?", (iid,)).fetchone()[0] == 0
                row = c.execute("SELECT actor,details FROM audit_log WHERE action='integration_config_deleted' ORDER BY id DESC LIMIT 1").fetchone()
                assert row["actor"] == "admin"
                assert "Retired Pi-hole" in row["details"]
                assert "analytics_deleted=1" in row["details"]
    finally:
        main.DB_PATH = old
