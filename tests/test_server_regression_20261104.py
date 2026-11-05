"""Server-side regression coverage using real login and CSRF protection.

Avoids the legacy dependency-override patterns that no longer bypass the
authentication middleware.
"""
from fastapi.testclient import TestClient
from app import main


def _admin(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "server-regression.db")
    main.init_db()
    client = TestClient(main.app)
    password = "Regression-Admin-Strong!2026"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
    return client, {"X-CSRF-Token": client.cookies["godseye_csrf"]}


def test_crm_customer_create_update_delete_real_session(tmp_path, monkeypatch):
    client, csrf = _admin(tmp_path, monkeypatch)
    created = client.post("/api/v1/crm/customers", json={"name": "Sandbox Customer", "notes": "Initial"}, headers=csrf)
    assert created.status_code == 201, created.text
    cid = created.json()["id"]
    assert client.get(f"/api/v1/crm/customers/{cid}").status_code == 200
    updated = client.put(f"/api/v1/crm/customers/{cid}", json={"name": "Sandbox Customer", "notes": "Updated"}, headers=csrf)
    assert updated.status_code == 200, updated.text
    assert updated.json()["notes"] == "Updated"
    deleted = client.delete(f"/api/v1/crm/customers/{cid}", headers=csrf)
    assert deleted.status_code == 200, deleted.text
    assert client.get(f"/api/v1/crm/customers/{cid}").status_code == 404


def test_kb_create_search_delete_real_session(tmp_path, monkeypatch):
    client, csrf = _admin(tmp_path, monkeypatch)
    payload = {"title": "Regression printer repair", "product": "Printer",
               "category": "Hardware", "summary": "Clean jam",
               "steps": [{"title": "Clear tray", "instructions": "Remove stuck paper"}]}
    created = client.post("/api/v1/kb/articles", json=payload, headers=csrf)
    assert created.status_code == 201, created.text
    aid = created.json()["id"]
    assert any(x["id"] == aid for x in client.get("/api/v1/kb/articles?q=Regression").json())
    assert client.delete(f"/api/v1/kb/articles/{aid}", headers=csrf).status_code == 200
    assert client.get(f"/api/v1/kb/articles/{aid}").status_code == 404


def test_crm_mutations_require_auth_and_csrf(tmp_path, monkeypatch):
    client, csrf = _admin(tmp_path, monkeypatch)
    assert client.post("/api/v1/crm/customers", json={"name": "No CSRF"}).status_code in (401, 403)
    anonymous = TestClient(main.app)
    assert anonymous.post("/api/v1/crm/customers", json={"name": "Anonymous"}).status_code in (401, 403)
    assert client.post("/api/v1/crm/customers", json={"name": "With CSRF"}, headers=csrf).status_code == 201


# TEMPORARY RULESET ENFORCEMENT PROBE. DO NOT MERGE.
def test_ruleset_rejects_intentionally_failing_server_test():
    assert False, "Expected failure: verify main-branch required checks prevent merging"
