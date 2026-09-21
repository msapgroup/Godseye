import datetime as dt
import json
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main
from app.windows_agent import token_hash


def _insert_agent(key: str, *, version: str = "2.4.4") -> int:
    timestamp = main.now()
    with main.db() as c:
        return c.execute(
            """INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,hostname,agent_version,status,enabled,last_heartbeat_at,enrolled_at,updated_at)
               VALUES(?,?,?,?,?,'online',1,?,?,?)""",
            ("agent-ticket-test", token_hash(key), "HELPDESK-PC", "helpdesk-pc", version, timestamp, timestamp, timestamp),
        ).lastrowid


def _login_admin(client: TestClient):
    password = "Godseye-v431-Agent!Test"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200


def test_agent_ticket_submission_is_authenticated_complete_and_idempotent(tmp_path):
    old_db = main.DB_PATH
    main.DB_PATH = tmp_path / "godseye.db"
    try:
        main.init_db()
        key = "gsa_ticket_test_key"
        agent_id = _insert_agent(key)
        payload = {
            "request_id": "3f26fb11-a3ab-46af-a1cf-959efcc822b6",
            "requester_name": "Jamie User",
            "requester_department": "Accounting",
            "requester_phone": "555-0199",
            "requester_email": "jamie@example.com",
            "category": "Hardware",
            "issue_notes": "Laptop dock no longer detects either monitor.",
        }
        with TestClient(main.app) as client:
            headers = {"Authorization": f"Bearer {key}"}
            first = client.post("/api/v1/windows-agents/tickets", json=payload, headers=headers)
            assert first.status_code == 200
            assert first.json()["ticket_number"].startswith("TKT-")
            assert first.json()["duplicate"] is False
            repeated = client.post("/api/v1/windows-agents/tickets", json=payload, headers=headers)
            assert repeated.status_code == 200
            assert repeated.json()["ticket_id"] == first.json()["ticket_id"]
            assert repeated.json()["duplicate"] is True
        with main.db() as c:
            rows = c.execute("SELECT * FROM tickets WHERE agent_request_id=?", (payload["request_id"],)).fetchall()
            assert len(rows) == 1
            ticket = rows[0]
            assert ticket["linked_type"] == "windows_agent"
            assert ticket["linked_id"] == agent_id
            assert ticket["device_name"] == "HELPDESK-PC"
            assert ticket["requester_name"] == "Jamie User"
            assert ticket["requester_department"] == "Accounting"
            assert ticket["requester_phone"] == "555-0199"
            assert ticket["requester_email"] == "jamie@example.com"
            assert ticket["description"] == payload["issue_notes"]
    finally:
        main.DB_PATH = old_db


def test_remote_frames_use_the_configured_writable_data_directory(tmp_path):
    old_db, old_base = main.DB_PATH, main.BASE_DIR
    main.DB_PATH = tmp_path / "writable-data" / "godseye.db"
    main.BASE_DIR = tmp_path / "read-only-application"
    try:
        frame = main._remote_frame_path(71)
        assert frame == main.DB_PATH.parent / "remote-frames" / "session-71.jpg"
        assert frame.parent.is_dir()
        assert main.BASE_DIR not in frame.parents
    finally:
        main.DB_PATH, main.BASE_DIR = old_db, old_base


def test_stale_capture_session_is_failed_and_replaced(tmp_path):
    old_db = main.DB_PATH
    main.DB_PATH = tmp_path / "godseye.db"
    try:
        main.init_db()
        agent_id = _insert_agent("gsa_stale_remote_test")
        stale_at = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=3)).isoformat()
        with main.db() as c:
            stale_id = c.execute(
                """INSERT INTO windows_remote_sessions(agent_id,status,requested_by,requested_at,last_state_at)
                   VALUES(?,'capture_started','admin',?,?)""",
                (agent_id, stale_at, stale_at),
            ).lastrowid
            stale_command_id = c.execute(
                """INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at)
                   VALUES(?,'remote_session_start',?,'pending','admin',?)""",
                (agent_id, json.dumps({"session_id": stale_id}), stale_at),
            ).lastrowid
        with TestClient(main.app) as client:
            _login_admin(client)
            response = client.post(
                "/api/v1/remote-access/sessions",
                json={"agent_id": agent_id},
                headers={"X-CSRF-Token": client.cookies.get("godseye_csrf")},
            )
            assert response.status_code == 200
            assert response.json()["session"]["id"] != stale_id
            assert response.json()["session"]["status"] == "requested"
        with main.db() as c:
            stale = c.execute("SELECT * FROM windows_remote_sessions WHERE id=?", (stale_id,)).fetchone()
            assert stale["status"] == "failed"
            assert "did not start after approval" in stale["last_error"]
            stale_command = c.execute("SELECT * FROM windows_agent_commands WHERE id=?", (stale_command_id,)).fetchone()
            assert stale_command["status"] == "failed"
    finally:
        main.DB_PATH = old_db


def test_tray_exposes_submit_ticket_form_and_service_delivery_pipe():
    tray = Path("windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs").read_text(encoding="utf-8")
    service = Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text(encoding="utf-8")
    assert 'menu.Items.Add("Submit Ticket..."' in tray
    for field in ("requester_name", "requester_department", "requester_phone", "requester_email", "issue_notes"):
        assert field in tray
    for category in ("Email", "Internet", "Phone", "Hardware", "Software", "Security", "Other"):
        assert f'"{category}"' in tray
    assert '"ticket-peek"' in service
    assert '"ticket-result"' in service
    assert '"/api/v1/windows-agents/tickets"' in service
