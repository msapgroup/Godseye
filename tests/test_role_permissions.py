"""Validate permissions through authenticated HTTP requests, not direct dependency calls.

The older tests called a FastAPI dependency without its required Request
object, producing AttributeError regardless of actual authorization behavior.
"""
import pytest
from fastapi.testclient import TestClient
from app import main


@pytest.mark.parametrize("role,allowed", [
    ("admin", True),
    ("operator", True),
    ("auditor", False),
    ("readonly", False),
])
def test_crm_role_permissions_through_real_sessions(role, allowed, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "role-permissions.db")
    main.init_db()
    password = "Godseye-RBAC-Strong!2026"
    with TestClient(main.app) as admin:
        assert admin.post("/api/v1/auth/setup", json={
            "current_password": "", "new_password": password
        }).status_code == 200
        if role != "admin":
            salt, hashed = main.hash_password(password)
            with main.db() as c:
                c.execute(
                    "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,created_at,password_changed_at) "
                    "VALUES(?,?,?,?,0,?,?)",
                    ("test-" + role, hashed, salt, role, main.now(), main.now())
                )
        client = TestClient(main.app)
        username = "admin" if role == "admin" else "test-" + role
        assert client.post("/api/v1/auth/login", json={
            "username": username, "password": password
        }).status_code == 200
        csrf = {"X-CSRF-Token": client.cookies["godseye_csrf"]}
        assert client.get("/api/v1/crm/customers").status_code == 200
        response = client.post("/api/v1/crm/customers", json={"name": "RBAC Customer"}, headers=csrf)
        assert response.status_code == (201 if allowed else 403), response.text
        assert client.get("/api/v1/kb/articles").status_code == 200
        article = client.post("/api/v1/kb/articles", headers=csrf, json={
            "title": "Role permission article", "product": "Printer", "category": "Hardware",
            "summary": "Test", "steps": [{"title": "Check", "instructions": "Run checks"}]
        })
        assert article.status_code == (201 if allowed else 403), article.text
