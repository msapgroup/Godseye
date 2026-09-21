import base64
import io
from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image

import app.main as main
from app.windows_agent import token_hash


def _login_admin(client: TestClient):
    password = "Godseye-v430-Test!Strong"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
    csrf = client.cookies.get("godseye_csrf")
    assert csrf
    return {"X-CSRF-Token": csrf}


def _jpeg_bytes(width=10, height=6, value=(12, 34, 56)):
    buf = io.BytesIO()
    Image.new("RGB", (width, height), value).save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def test_remote_access_requires_240_and_separate_control_approval(tmp_path, monkeypatch):
    old_db = main.DB_PATH
    old_base = main.BASE_DIR
    main.DB_PATH = tmp_path / "remote-v430.db"
    main.BASE_DIR = tmp_path
    try:
        main.init_db()
        api_key = "gsa_v430_test_key"
        stamp = main.now()
        with main.db() as c:
            agent_id = c.execute(
                """INSERT INTO windows_agents(
                    agent_uuid,api_key_hash,computer_name,machine_guid,hostname,ip_address,
                    os_version,architecture,agent_version,status,enabled,channels_json,
                    poll_interval_seconds,last_heartbeat_at,enrolled_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,'online',1,'[\"System\",\"Application\"]',60,?,?,?)""",
                (
                    "v430-agent", token_hash(api_key), "TEST-PC", "guid", "TEST-PC", "127.0.0.1",
                    "Windows 11", "x64", "2.4.0", stamp, stamp, stamp,
                ),
            ).lastrowid

        with TestClient(main.app) as client:
            admin_headers = _login_admin(client)
            agent_headers = {"Authorization": f"Bearer {api_key}"}

            started = client.post("/api/v1/remote-access/sessions", headers=admin_headers, json={"agent_id": agent_id})
            assert started.status_code == 200, started.text
            session = started.json()["session"]
            sid = session["id"]
            assert session["status"] == "requested"

            # Browser input is forbidden until a validated screen frame has made the session active.
            early_input = client.post(
                f"/api/v1/remote-access/sessions/{sid}/input",
                headers=admin_headers,
                json={"kind": "pointer", "action": "click", "x": 0.5, "y": 0.5, "button": "left"},
            )
            assert early_input.status_code == 409

            for state in ("waiting_for_tray", "tray_ready", "waiting_for_user", "approved", "capture_started"):
                r = client.post(
                    f"/api/v1/windows-agents/remote/sessions/{sid}/state",
                    headers=agent_headers,
                    json={"status": state},
                )
                assert r.status_code == 200, (state, r.text)
                current = client.get(f"/api/v1/remote-access/sessions/{sid}").json()
                assert current["status"] == state

            # Old Agent vocabulary must not bypass first-frame validation.
            legacy_active = client.post(
                f"/api/v1/windows-agents/remote/sessions/{sid}/state",
                headers=agent_headers,
                json={"status": "active"},
            )
            assert legacy_active.status_code == 200
            assert client.get(f"/api/v1/remote-access/sessions/{sid}").json()["status"] == "capture_started"

            bad = base64.b64encode(b"\xff\xd8not-a-complete-jpeg\xff\xd9").decode()
            bad_frame = client.post(
                f"/api/v1/windows-agents/remote/sessions/{sid}/frame",
                headers=agent_headers,
                json={"image_base64": bad, "width": 999, "height": 999},
            )
            assert bad_frame.status_code == 400
            assert client.get(f"/api/v1/remote-access/sessions/{sid}").json()["status"] == "capture_started"

            first = _jpeg_bytes(10, 6)
            good_frame = client.post(
                f"/api/v1/windows-agents/remote/sessions/{sid}/frame",
                headers=agent_headers,
                json={"image_base64": base64.b64encode(first).decode(), "width": 999, "height": 999},
            )
            assert good_frame.status_code == 200, good_frame.text
            assert good_frame.json()["sequence"] == 1
            assert good_frame.json()["width"] == 10
            assert good_frame.json()["height"] == 6

            active = client.get(f"/api/v1/remote-access/sessions/{sid}").json()
            assert active["status"] == "active"
            assert active["frame_seq"] == 1
            assert active["last_width"] == 10 and active["last_height"] == 6
            assert active["control_status"] == "view_only"

            screenshot = client.get(f"/api/v1/remote-access/sessions/{sid}/frame")
            assert screenshot.status_code == 200
            assert screenshot.content == first
            assert screenshot.headers["x-godseye-frame-sequence"] == "1"

            view_only_input = client.post(
                f"/api/v1/remote-access/sessions/{sid}/input",
                headers=admin_headers,
                json={"kind": "pointer", "action": "click", "x": 0.25, "y": 0.75, "button": "left"},
            )
            assert view_only_input.status_code == 409

            requested = client.post(
                f"/api/v1/remote-access/sessions/{sid}/control/request",
                headers=admin_headers,
                json={},
            )
            assert requested.status_code == 200
            poll = client.get(
                f"/api/v1/windows-agents/remote/sessions/{sid}/events?after=0",
                headers=agent_headers,
            ).json()
            assert poll["control_status"] == "requested"
            decision = client.post(
                f"/api/v1/windows-agents/remote/sessions/{sid}/control/decision",
                headers=agent_headers,
                json={"approved": True},
            )
            assert decision.status_code == 200

            queued = client.post(
                f"/api/v1/remote-access/sessions/{sid}/input",
                headers=admin_headers,
                json={"kind": "pointer", "action": "click", "x": 0.25, "y": 0.75, "button": "left"},
            )
            assert queued.status_code == 200
            events = client.get(
                f"/api/v1/windows-agents/remote/sessions/{sid}/events?after=0",
                headers=agent_headers,
            ).json()["events"]
            assert len(events) == 1
            assert events[0]["event"]["kind"] == "pointer"
            # Delivered input is not replayed if the same cursor is polled again.
            events_again = client.get(
                f"/api/v1/windows-agents/remote/sessions/{sid}/events?after=0",
                headers=agent_headers,
            ).json()["events"]
            assert events_again == []

            second = _jpeg_bytes(12, 7, (80, 40, 20))
            second_frame = client.post(
                f"/api/v1/windows-agents/remote/sessions/{sid}/frame",
                headers=agent_headers,
                json={"image_base64": base64.b64encode(second).decode(), "width": 1, "height": 1},
            )
            assert second_frame.status_code == 200
            assert second_frame.json()["sequence"] == 2
            screenshot2 = client.get(f"/api/v1/remote-access/sessions/{sid}/frame")
            assert screenshot2.content == second
            assert screenshot2.headers["x-godseye-frame-sequence"] == "2"

            ended = client.post(
                f"/api/v1/windows-agents/remote/sessions/{sid}/state",
                headers=agent_headers,
                json={"status": "ended"},
            )
            assert ended.status_code == 200
            assert client.get(f"/api/v1/remote-access/sessions/{sid}").json()["status"] == "ended"
    finally:
        main.DB_PATH = old_db
        main.BASE_DIR = old_base


def test_remote_access_rejects_pre_240_agent(tmp_path):
    old_db = main.DB_PATH
    main.DB_PATH = tmp_path / "old-agent.db"
    try:
        main.init_db()
        api_key = "gsa_old_agent"
        stamp = main.now()
        with main.db() as c:
            aid = c.execute(
                """INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,status,enabled,last_heartbeat_at,enrolled_at,updated_at)
                   VALUES(?,?,?,?, 'online',1,?,?,?)""",
                ("old-agent", token_hash(api_key), "OLD-PC", "2.3.9", stamp, stamp, stamp),
            ).lastrowid
        with TestClient(main.app) as client:
            headers = _login_admin(client)
            r = client.post("/api/v1/remote-access/sessions", headers=headers, json={"agent_id": aid})
            assert r.status_code == 409
            assert "2.4.0" in r.text
    finally:
        main.DB_PATH = old_db

def test_remote_access_ui_understands_v241_consent_and_requirement():
    source=Path("app/main.py").read_text(encoding="utf-8")
    assert 'd["remote_supported"]=_agent_version_tuple(installed_version) >= (2,4,0)' in source
    assert 'Upgrade to Agent 2.4.4' in source
    for state in ("requested","waiting_for_tray","tray_ready","waiting_for_user","approved","capture_started","active","denied","failed","ended"):
        assert state in source
    assert "const pending=['requested','waiting_for_tray','tray_ready','waiting_for_user','approved','capture_started']" in source
    assert "Screen capture started. Waiting for the first verified JPEG frame" in source
    assert "requestRemoteControl" in source
    assert "The signed-in Windows user has not approved remote control" in source
