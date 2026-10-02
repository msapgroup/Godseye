"""Exercise the optional EDR policy, verified rules, and agent command path."""
import hashlib
from fastapi.testclient import TestClient

import app.main as main
from app.windows_agent import token_hash


def test_integrated_245_reports_edr_capability_without_relabeling_original(tmp_path, monkeypatch):
    old_db, old_base = main.DB_PATH, main.BASE_DIR
    main.DB_PATH, main.BASE_DIR = tmp_path / "edr-245.db", tmp_path
    fake_yr = tmp_path / "yr"
    fake_yr.write_text('#!/bin/sh\n[ "$1" = compile ] || exit 5\nexit 0\n')
    fake_yr.chmod(0o700)
    monkeypatch.setenv("GODSEYE_YARAX_CLI", str(fake_yr))
    try:
        main.init_db()
        with TestClient(main.app) as client:
            password = "Godseye-EDR-245!Test"
            assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
            assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
            headers = {"X-CSRF-Token": client.cookies[main.CSRF_COOKIE]}
            with main.db() as c:
                aid = c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,enrolled_at,updated_at)
                    VALUES(?,?,?,?,?,?)""", ("edr-245-agent", token_hash("edr-245-key"), "PC-245", "2.4.5", main.now(), main.now())).lastrowid
            assert client.post(f"/api/v1/edr/agents/{aid}/policy", headers=headers, json={"enabled": True}).status_code == 200
            assert client.post("/api/v1/edr/rules", headers=headers,
                json={"name": "Test", "rules": 'rule test { condition: true }'}).status_code == 200
            assert client.post(f"/api/v1/edr/agents/{aid}/scan", headers=headers, json={"scan_type": "quick"}).status_code == 409
            beat = client.post("/api/v1/windows-agents/heartbeat", headers={"Authorization": "Bearer edr-245-key"},
                json={"agent_version": "2.4.5", "edr_capable": True})
            assert beat.status_code == 200
            assert client.get("/api/v1/edr/overview").json()["agents"][0]["edr_capable"] == 1
            assert client.post(f"/api/v1/edr/agents/{aid}/scan", headers=headers, json={"scan_type": "quick"}).status_code == 200
            assert client.post(f"/api/v1/edr/agents/{aid}/defender/update", headers=headers).status_code == 200
    finally:
        main.DB_PATH, main.BASE_DIR = old_db, old_base


def test_edr_policy_rules_scan_and_agent_checkin(tmp_path, monkeypatch):
    old_db, old_base = main.DB_PATH, main.BASE_DIR
    main.DB_PATH, main.BASE_DIR = tmp_path / "edr.db", tmp_path
    fake_yr = tmp_path / "yr"
    fake_yr.write_text('#!/bin/sh\n[ "$1" = compile ] || exit 5\n[ -f "$4" ] || exit 6\nexit 0\n')
    fake_yr.chmod(0o700)
    monkeypatch.setenv("GODSEYE_YARAX_CLI", str(fake_yr))
    try:
        main.init_db()
        with TestClient(main.app) as client:
            password = "Godseye-EDR-Integration!Test"
            assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
            assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
            headers = {"X-CSRF-Token": client.cookies[main.CSRF_COOKIE]}
            with main.db() as c:
                agent_id = c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,enrolled_at,updated_at)
                    VALUES(?,?,?,?,?,?)""", ("edr-test-agent", token_hash("edr-test-key"), "PC-EDR", "2.4.5", main.now(), main.now())).lastrowid
                c.execute("UPDATE windows_agents SET edr_capable=1 WHERE id=?", (agent_id,))
            rule = 'rule godseye_test { strings: $marker = "GODSEYE_TEST" condition: $marker }'
            published = client.post("/api/v1/edr/rules", headers=headers,
                json={"name": "Test rules", "source": "Local test", "rules": rule})
            assert published.status_code == 200, published.text
            assert published.json()["sha256"] == hashlib.sha256(rule.encode()).hexdigest()
            assert client.post(f"/api/v1/edr/agents/{agent_id}/policy", headers=headers,
                json={"enabled": True}).status_code == 200
            queued = client.post(f"/api/v1/edr/agents/{agent_id}/scan", headers=headers,
                json={"scan_type": "quick"})
            assert queued.status_code == 200, queued.text
            heartbeat = client.post("/api/v1/windows-agents/heartbeat",
                headers={"Authorization": "Bearer edr-test-key"}, json={"agent_version": "2.4.5", "edr_capable": True})
            assert heartbeat.status_code == 200, heartbeat.text
            assert heartbeat.json()["edr"]["enabled"] is True
            assert any(command["type"] == "edr_scan" for command in heartbeat.json()["commands"])
            rules = client.get("/api/v1/edr/agent/rules", headers={"Authorization": "Bearer edr-test-key"})
            assert rules.status_code == 200 and rules.json()["rules"] == rule
            assert client.post(f"/api/v1/edr/agents/{agent_id}/policy", headers=headers,
                json={"enabled": False}).status_code == 200
            assert client.get("/api/v1/edr/agent/rules", headers={"Authorization": "Bearer edr-test-key"}).status_code == 403
    finally:
        main.DB_PATH, main.BASE_DIR = old_db, old_base


def test_defender_status_and_capability_gated_update(tmp_path):
    old_db, old_base = main.DB_PATH, main.BASE_DIR
    main.DB_PATH, main.BASE_DIR = tmp_path / "defender.db", tmp_path
    try:
        main.init_db()
        with TestClient(main.app) as client:
            password = "Godseye-Defender-Integration!Test"
            assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
            assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200
            headers = {"X-CSRF-Token": client.cookies[main.CSRF_COOKIE]}
            with main.db() as c:
                agent_id = c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,enrolled_at,updated_at)
                    VALUES(?,?,?,?,?,?)""", ("defender-test-agent", token_hash("defender-test-key"), "PC-DEF", "2.4.5", main.now(), main.now())).lastrowid
            assert client.post(f"/api/v1/edr/agents/{agent_id}/policy", headers=headers, json={"enabled": True}).status_code == 200
            agent_headers = {"Authorization": "Bearer defender-test-key"}
            heartbeat = client.post("/api/v1/windows-agents/heartbeat", headers=agent_headers, json={"agent_version": "2.4.5", "edr_capable": True})
            assert heartbeat.status_code == 200, heartbeat.text
            assert "Microsoft-Windows-Windows Defender/Operational" in heartbeat.json()["channels"]
            review = [x for x in heartbeat.json()["commands"] if x["type"] == "defender_review"]
            assert len(review) == 1
            assert client.post("/api/v1/windows-agents/heartbeat", headers=agent_headers, json={"agent_version": "2.4.5", "edr_capable": True}).json()["commands"][0]["command_id"] == review[0]["command_id"]
            result = {"ok": True, "details": '{"AntivirusEnabled":true,"AMRunningMode":"Normal","RealTimeProtectionEnabled":true,"RecentDetections":[]}' }
            assert client.post(f"/api/v1/windows-agents/commands/{review[0]['command_id']}/result", headers=agent_headers, json=result).status_code == 200
            overview = client.get("/api/v1/edr/overview").json()
            assert overview["agents"][0]["defender"]["RealTimeProtectionEnabled"] is True
            assert client.post(f"/api/v1/edr/agents/{agent_id}/defender/quick", headers=headers).status_code == 200
            assert client.post(f"/api/v1/edr/agents/{agent_id}/defender/update", headers=headers).status_code == 200
            assert client.post(f"/api/v1/edr/agents/{agent_id}/policy", headers=headers, json={"enabled": False}).status_code == 200
            off = client.post("/api/v1/windows-agents/heartbeat", headers=agent_headers, json={"agent_version": "2.4.5", "edr_capable": True})
            assert "Microsoft-Windows-Windows Defender/Operational" not in off.json()["channels"]
    finally:
        main.DB_PATH, main.BASE_DIR = old_db, old_base
