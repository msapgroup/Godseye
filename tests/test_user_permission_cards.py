"""Per-user permissions must not leak across accounts and must enforce API access."""
from fastapi.testclient import TestClient
from app import main


def test_account_access_overrides_and_role_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "permissions-v2.db")
    main.init_db()
    password = "Godseye-Role-Review!2026"
    with TestClient(main.app) as admin:
        assert admin.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
        assert admin.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
        headers = {"X-CSRF-Token": admin.cookies["godseye_csrf"]}
        salt, digest = main.hash_password(password)
        ids = []
        with main.db() as c:
            for username in ("person-a", "person-b"):
                ids.append(c.execute(
                    "INSERT INTO users(username,display_name,password_hash,password_salt,role,must_change_password,created_at,password_changed_at)"
                    " VALUES(?,?,?,?,?,0,?,?)",
                    (username, username, digest, salt, "operator", main.now(), main.now()),
                ).lastrowid)
        first, second = ids
        initial = admin.get(f"/api/v1/users/{first}/access")
        assert initial.status_code == 200, initial.text
        payload = initial.json()["pages"]
        assert payload["crm"] == "full"
        assert admin.get(f"/api/v1/users/{second}/access").json()["pages"]["crm"] == "full"
        payload["crm"] = "none"
        saved = admin.put(f"/api/v1/users/{first}/access", headers=headers, json={"pages": payload})
        assert saved.status_code == 200, saved.text
        assert admin.get(f"/api/v1/users/{first}/access").json()["pages"]["crm"] == "none"
        assert admin.get(f"/api/v1/users/{second}/access").json()["pages"]["crm"] == "full"

        with TestClient(main.app) as a, TestClient(main.app) as b:
            for client, username in [(a, "person-a"), (b, "person-b")]:
                assert client.post("/api/v1/auth/login", json={"username": username, "password": password}).status_code == 200
            assert a.get("/api/v1/auth/me").json()["page_access"]["crm"] == "none"
            assert b.get("/api/v1/auth/me").json()["page_access"]["crm"] == "full"
            assert a.get("/api/v1/crm/customers").status_code == 403
            assert b.get("/api/v1/crm/customers").status_code == 200
            assert a.put(f"/api/v1/users/{second}/access", headers={"X-CSRF-Token": a.cookies["godseye_csrf"]}, json={"pages": payload}).status_code == 403

        assert admin.delete(f"/api/v1/users/{first}/access", headers=headers).status_code == 200
        assert admin.get(f"/api/v1/users/{first}/access").json()["pages"]["crm"] == "full"
        assert admin.put(f"/api/v1/users/1/access", headers=headers, json={"pages": payload}).status_code == 400
        assert admin.put(f"/api/v1/users/{second}/access", headers=headers, json={"pages": {"crm": "full"}}).status_code == 400


def test_account_role_change_clears_overrides(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "permissions-change.db")
    main.init_db()
    password = "Godseye-Role-Review!2026"
    with TestClient(main.app) as admin:
        assert admin.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
        assert admin.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
        headers = {"X-CSRF-Token": admin.cookies["godseye_csrf"]}
        with main.db() as c:
            salt, digest = main.hash_password(password)
            uid = c.execute(
                "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,created_at,password_changed_at)"
                " VALUES(?,?,?,?,0,?,?)",
                ("role-change", digest, salt, "operator", main.now(), main.now()),
            ).lastrowid
        pages = admin.get(f"/api/v1/users/{uid}/access").json()["pages"]
        pages["crm"] = "none"
        assert admin.put(f"/api/v1/users/{uid}/access", headers=headers, json={"pages":pages}).status_code == 200
        assert admin.put(f"/api/v1/users/{uid}/role", headers=headers, json={"role":"auditor"}).status_code == 200
        updated = admin.get(f"/api/v1/users/{uid}/access").json()
        assert updated["overrides"] == {}
        assert updated["pages"]["crm"] == "read"
