from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main
from app import cyber_tools


def _login_admin(client: TestClient):
    password = "Godseye-v431-Cyber!Test"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200


def _csrf(client: TestClient):
    return {"X-CSRF-Token": client.cookies.get("godseye_csrf")}


def test_cyber_console_has_one_operational_card_per_tool():
    source = Path("app/main.py").read_text(encoding="utf-8")
    for title in (
        "Network Exposure Scan",
        "Endpoint Security Posture",
        "Web &amp; TLS Audit",
        "Malware &amp; IOC Scan",
        "DNS &amp; Email Security",
        "Linux Security Audit",
        "Network Threat Detection",
        "Evidence Capture",
    ):
        assert title in source
    assert "runCyberTool('network_exposure')" in source
    assert "createCyberFinding" in source
    assert "createCyberTicket" in source
    assert "scheduleCyberTool" in source


def test_cyber_schema_and_endpoint_posture_workflow(tmp_path):
    old_db = main.DB_PATH
    main.DB_PATH = tmp_path / "godseye.db"
    try:
        main.init_db()
        with TestClient(main.app) as client:
            _login_admin(client)
            caps = client.get("/api/v1/cyber-tools/capabilities")
            assert caps.status_code == 200
            assert set(caps.json()) == cyber_tools.TOOLS

            run = client.post(
                "/api/v1/cyber-tools/run",
                json={"tool": "endpoint_posture", "target": "All enrolled endpoints", "profile": "standard", "options": {}},
                headers=_csrf(client),
            )
            assert run.status_code == 200
            body = run.json()
            assert body["status"] == "completed"
            assert body["result"]["agent_count"] == 0

            finding = client.post(f"/api/v1/cyber-tools/runs/{body['id']}/create-finding", headers=_csrf(client))
            assert finding.status_code == 200
            assert finding.json()["issue_type"] == "cyber_tool"

            ticket = client.post(f"/api/v1/cyber-tools/runs/{body['id']}/create-ticket", headers=_csrf(client))
            assert ticket.status_code == 200
            assert ticket.json()["ticket_number"].startswith("TKT-")

            history = client.get("/api/v1/cyber-tools/runs")
            assert history.status_code == 200
            assert history.json()[0]["ticket_id"] == ticket.json()["id"]
    finally:
        main.DB_PATH = old_db


def test_cyber_schedules_are_persisted_and_removable(tmp_path):
    old_db = main.DB_PATH
    main.DB_PATH = tmp_path / "godseye.db"
    try:
        main.init_db()
        with TestClient(main.app) as client:
            _login_admin(client)
            created = client.post(
                "/api/v1/cyber-tools/schedules",
                json={"tool": "endpoint_posture", "target": "All enrolled endpoints", "profile": "standard", "options": {}, "interval_minutes": 60},
                headers=_csrf(client),
            )
            assert created.status_code == 200
            schedule_id = created.json()["id"]
            assert client.get("/api/v1/cyber-tools/schedules").json()[0]["interval_minutes"] == 60
            assert client.delete(f"/api/v1/cyber-tools/schedules/{schedule_id}", headers=_csrf(client)).status_code == 200
            assert client.get("/api/v1/cyber-tools/schedules").json() == []
    finally:
        main.DB_PATH = old_db


def test_network_targets_are_bounded_to_private_space():
    assert cyber_tools._private_target("192.168.50.0/24", True) == "192.168.50.0/24"
    try:
        cyber_tools._private_target("8.8.8.8", True)
    except ValueError as exc:
        assert "private/link-local" in str(exc)
    else:
        raise AssertionError("Public network targets must be rejected")
