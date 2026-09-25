from fastapi.testclient import TestClient

from app import main
from app.crm import ensure_schema


def test_customer_contact_lifecycle_and_site_link(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "crm.db")
    main.init_db()
    role = {"username": "crm-test", "role": "admin"}
    main.app.dependency_overrides[main.get_current_user] = lambda: role
    try:
        client = TestClient(main.app)
        with main.db() as c:
            c.execute("""INSERT INTO managed_sites(name,endpoint,remote_id,key_enc,status,created_at)
                VALUES('Florida', 'https://127.0.0.1:8443', 'test-remote', 'encrypted', 'connected', ?)""", (main.now(),))
            site_id = c.execute("SELECT id FROM managed_sites WHERE name='Florida'").fetchone()[0]
        customer = {"name": "Law Office Florida", "customer_type": "business", "status": "active",
                    "email": "office@example.com", "phone": "555-0100", "address": "Tampa, FL",
                    "notes": "Call before visiting", "site_id": site_id}
        created = client.post("/api/v1/crm/customers", json=customer)
        assert created.status_code == 201, created.text
        customer_id = created.json()["id"]
        assert created.json()["site_name"] == "Florida"
        contact = client.post(f"/api/v1/crm/customers/{customer_id}/contacts",
                              json={"name": "Jordan Lee", "role": "Office Manager", "email": "jordan@example.com"})
        assert contact.status_code == 201, contact.text
        assert client.get("/api/v1/crm/customers?q=Law").json()[0]["contact_count"] == 1
        assert client.get("/api/v1/crm/customers?q=%25").json() == []
        contact_id = contact.json()["id"]
        assert client.put(f"/api/v1/crm/customers/{customer_id}/contacts/{contact_id}",
                          json={"name": "Jordan Lee", "role": "IT Contact"}).json()["role"] == "IT Contact"
        customer["name"] = "Law Office of Florida"
        assert client.put(f"/api/v1/crm/customers/{customer_id}", json=customer).json()["name"] == customer["name"]
        assert client.get(f"/api/v1/crm/customers/{customer_id}").json()["contacts"][0]["name"] == "Jordan Lee"
        role["role"] = "readonly"
        assert client.get(f"/api/v1/crm/customers/{customer_id}").status_code == 200
        assert client.put(f"/api/v1/crm/customers/{customer_id}", json=customer).status_code == 403
        role["role"] = "operator"
        assert client.delete(f"/api/v1/crm/customers/{customer_id}").status_code == 403
        role["role"] = "admin"
        assert client.delete(f"/api/v1/crm/customers/{customer_id}").json()["ok"]
        with main.db() as c:
            assert c.execute("SELECT COUNT(*) FROM crm_contacts WHERE customer_id=?", (customer_id,)).fetchone()[0] == 0
    finally:
        main.app.dependency_overrides.clear()


def test_old_customer_tables_are_upgraded_before_saving(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "existing.db")
    main.init_db()
    with main.db() as c:
        c.execute("DROP TABLE crm_contacts")
        c.execute("DROP TABLE crm_customers")
        c.execute("CREATE TABLE crm_customers (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
        c.execute("CREATE TABLE crm_contacts (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
    with main.db() as c:
        ensure_schema(c)
    main.app.dependency_overrides[main.get_current_user] = lambda: {"username": "crm-test", "role": "admin"}
    try:
        client = TestClient(main.app)
        result = client.post("/api/v1/crm/customers", json={"name": "MSAPGROUP LLC.",
            "email": "info@msapgroupllc.com", "phone": "8134197511", "address": "8870 N. HIMES AVE",
            "notes": "TEST NOTES", "site_id": None})
        assert result.status_code == 201, result.text
        assert result.json()["name"] == "MSAPGROUP LLC."
    finally:
        main.app.dependency_overrides.clear()


def test_real_login_can_save_customer_with_form_values(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "auth.db")
    main.init_db()
    client = TestClient(main.app)
    password = "Strong-Crm-Setup!2026"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
    result = client.post("/api/v1/crm/customers", headers={"X-CSRF-Token": client.cookies["godseye_csrf"]},
        json={"name": "MSAPGROUP LLC.", "customer_type": "business", "status": "active",
              "email": "info@msapgroupllc.com", "phone": "8134197511",
              "address": "8870 N. HIMES AVE", "notes": "TEST NOTES", "site_id": None})
    assert result.status_code == 201, result.text
    assert result.json()["name"] == "MSAPGROUP LLC."
