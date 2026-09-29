from fastapi.testclient import TestClient

from app import main


def test_admin_reset_password_revokes_sessions_and_forces_change(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "password-reset.db")
    main.init_db()
    admin_password = "Godseye-admin-strong-2026!"
    old_password = "Godseye-operator-old-2026!"
    temporary_password = "Godseye-operator-temp-2026!"
    final_password = "Godseye-operator-new-2026!"

    with TestClient(main.app) as admin, TestClient(main.app) as operator:
        assert admin.post("/api/v1/auth/setup", json={"current_password": "", "new_password": admin_password}).status_code == 200
        assert admin.post("/api/v1/auth/login", json={"username": "admin", "password": admin_password}).status_code == 200
        admin_headers = {"X-CSRF-Token": admin.cookies["godseye_csrf"]}
        salt, hashed = main.hash_password(old_password)
        with main.db() as c:
            user_id = c.execute(
                "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,created_at,password_changed_at) "
                "VALUES(?,?,?,?,0,?,?)",
                ("operator", hashed, salt, "operator", main.now(), main.now()),
            ).lastrowid

        assert operator.post("/api/v1/auth/login", json={"username": "operator", "password": old_password}).status_code == 200
        operator_headers = {"X-CSRF-Token": operator.cookies["godseye_csrf"]}
        endpoint = f"/api/v1/users/{user_id}/reset-password"
        assert operator.post(endpoint, headers=operator_headers, json={"new_password": temporary_password}).status_code == 403
        assert admin.post("/api/v1/users/1/reset-password", headers=admin_headers,
                          json={"new_password": temporary_password}).status_code == 400
        response = admin.post(endpoint, headers=admin_headers, json={"new_password": temporary_password})
        assert response.status_code == 200, response.text
        assert operator.get("/api/v1/auth/me").status_code == 401
        assert operator.post("/api/v1/auth/login", json={"username": "operator", "password": old_password}).status_code == 401
        login = operator.post("/api/v1/auth/login", json={"username": "operator", "password": temporary_password})
        assert login.status_code == 200, login.text
        assert login.json()["must_change_password"] is True
        assert operator.get("/api/v1/users").status_code == 403
        operator_headers = {"X-CSRF-Token": operator.cookies["godseye_csrf"]}
        changed = operator.post("/api/v1/auth/change-password", headers=operator_headers,
                                json={"current_password": temporary_password, "new_password": final_password})
        assert changed.status_code == 200, changed.text
        assert operator.get("/api/v1/auth/me").status_code == 401
        assert operator.post("/api/v1/auth/login", json={"username": "operator", "password": final_password}).json()["must_change_password"] is False
        with main.db() as c:
            assert c.execute("SELECT COUNT(*) FROM audit_log WHERE action='password_reset_by_admin' AND target='operator'").fetchone()[0] == 1
