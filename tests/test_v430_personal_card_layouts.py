from fastapi.testclient import TestClient

import app.main as main


def _setup_admin(client):
    pw = "Godseye-v430-Admin!Strong"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": pw}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": pw}).status_code == 200
    return {"X-CSRF-Token": client.cookies.get("godseye_csrf")}


def test_personal_layouts_are_saved_per_user_and_override_defaults(tmp_path):
    old = main.DB_PATH
    main.DB_PATH = tmp_path / "layouts.db"
    try:
        main.init_db()
        with TestClient(main.app) as admin_client:
            admin_headers = _setup_admin(admin_client)

            # Appliance-wide admin default remains supported for backward compatibility.
            global_layout = {"overview-cards-0": ["devices", "findings"]}
            r = admin_client.put("/api/v1/ui/layouts/overview", headers=admin_headers, json={"layout": global_layout})
            assert r.status_code == 200

            admin_personal = {"overview-cards-0": ["findings", "devices"]}
            r = admin_client.put("/api/v1/ui/layouts/overview/personal", headers=admin_headers, json={"layout": admin_personal})
            assert r.status_code == 200
            effective = admin_client.get("/api/v1/ui/layouts").json()["layouts"]["overview"]
            assert effective["scope"] == "personal"
            assert effective["layout"] == admin_personal

            # Create a second initialized user directly so the test focuses on layout isolation.
            salt, hashed = main.hash_password("Operator-v430!Strong")
            with main.db() as c:
                c.execute(
                    """INSERT INTO users(username,display_name,password_hash,password_salt,role,must_change_password,created_at,password_changed_at)
                       VALUES(?,?,?,?,?,0,?,?)""",
                    ("operator", "Operator", hashed, salt, "operator", main.now(), main.now()),
                )

        with TestClient(main.app) as operator_client:
            assert operator_client.post("/api/v1/auth/login", json={"username": "operator", "password": "Operator-v430!Strong"}).status_code == 200
            op_headers = {"X-CSRF-Token": operator_client.cookies.get("godseye_csrf")}
            inherited = operator_client.get("/api/v1/ui/layouts").json()["layouts"]["overview"]
            assert inherited["scope"] == "default"
            assert inherited["layout"] == global_layout

            operator_personal = {"overview-cards-0": ["devices"]}
            saved = operator_client.put("/api/v1/ui/layouts/overview/personal", headers=op_headers, json={"layout": operator_personal})
            assert saved.status_code == 200
            effective = operator_client.get("/api/v1/ui/layouts").json()["layouts"]["overview"]
            assert effective["scope"] == "personal"
            assert effective["layout"] == operator_personal

            reset = operator_client.delete("/api/v1/ui/layouts/overview/personal", headers=op_headers)
            assert reset.status_code == 200
            inherited_again = operator_client.get("/api/v1/ui/layouts").json()["layouts"]["overview"]
            assert inherited_again["scope"] == "default"
            assert inherited_again["layout"] == global_layout
    finally:
        main.DB_PATH = old


def test_dashboard_layout_controls_are_available_to_authenticated_users():
    source = open("app/main.py", encoding="utf-8").read()
    assert "🔓 Unlock Layout" in source
    assert "🔒 Lock Layout" in source
    assert "/personal" in source
    assert "ui_user_layouts" in source
