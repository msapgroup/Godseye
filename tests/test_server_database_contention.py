"""Real SQLite contention regressions for scanner/agent/dashboard coexistence."""
import datetime as dt
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app import main, scanner
from app.windows_agent import token_hash


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "godseye.db"
    monkeypatch.setattr(main, "DB_PATH", path)
    monkeypatch.setattr(scanner, "DB_PATH", path)
    main.init_db()
    # Isolate SQLite behavior from optional GitHub release metadata latency.
    monkeypatch.setattr(main, "_windows_agent_update_manifest", lambda: {
        "version": "2.4.5", "sha256": "A" * 64,
        "filename": "GODSEYE-Windows-Agent-x64.msi", "url": "https://example.com/agent.msi",
    })
    return path


def login(client):
    password = "Godseye-Db-Test!Strong"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200


def test_polling_remains_authenticated_during_another_writer(database):
    # A held writer used to turn authentication itself into a 10-second HTTP 500.
    with TestClient(main.app) as client:
        login(client)
        token = client.cookies[main.SESSION_COOKIE]
        stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=120)).isoformat()
        with main.db() as c:
            c.execute("UPDATE sessions SET last_seen_at=? WHERE token=?", (stale, token))
            command = c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,status,requested_by,requested_at) VALUES(1,'windows_update_scan','pending','admin',?)", (main.now(),)).lastrowid
        blocker = sqlite3.connect(database)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            for path in ("/api/v1/auth/me", "/api/v1/windows-agents/package-status", f"/api/v1/windows-agents/commands/{command}"):
                response = client.get(path)
                assert response.status_code == 200, response.text
            assert time.monotonic() - started < 2
        finally:
            blocker.rollback()
            blocker.close()
        assert client.get("/api/v1/auth/me").status_code == 200
        assert client.post("/api/v1/windows-agents/enrollment-tokens", json={}).status_code == 403
        with main.db() as c:
            assert c.execute("SELECT last_seen_at FROM sessions WHERE token=?", (token,)).fetchone()[0] != stale
        # A busy DB must never revive an expired/idle session or bypass CSRF.
        expired = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=main.IDLE_TIMEOUT_SECONDS + 1)).isoformat()
        with main.db() as c:
            c.execute("UPDATE sessions SET last_seen_at=? WHERE token=?", (expired, token))
        blocker = sqlite3.connect(database)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            assert client.get("/api/v1/auth/me").status_code == 401
        finally:
            blocker.rollback()
            blocker.close()


@pytest.mark.parametrize("probe", ["dns", "ping"])
def test_slow_scanner_probes_do_not_block_agent_heartbeats(database, monkeypatch, probe):
    stamp = main.now()
    key = "gsa_database_contention_test"
    with main.db() as c:
        agent_id = c.execute("INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,status,enabled,last_heartbeat_at,enrolled_at,updated_at) VALUES(?,?,?,'2.4.5','offline',1,?,?,?)",
                             ("db-test", token_hash(key), "TEST-PC", stamp, stamp, stamp)).lastrowid
        c.execute("INSERT INTO devices(mac,ip,status,first_seen,last_seen,classification,missed_scans) VALUES('aa:00:00:00:00:01','192.0.2.1','online',?,?,'known',0)", (stamp, stamp))
    entered, release = threading.Event(), threading.Event()
    probe_count = 0

    def slow_probe(ip):
        nonlocal probe_count
        probe_count += 1
        if probe == "dns" and probe_count == 1:
            return "first-pc"
        entered.set()
        assert release.wait(5)
        return "new-pc" if probe == "dns" else True

    monkeypatch.setattr(scanner, "resolve_hostname", slow_probe if probe == "dns" else lambda ip: "new-pc")
    monkeypatch.setattr(scanner, "ping_reachable", slow_probe if probe == "ping" else lambda ip: True)
    # Two new devices catch DNS being called after the first insert. Missing
    # existing device catches ping being called after all new-device inserts.
    found = [{"mac": f"aa:00:00:00:00:0{index}", "ip": f"192.0.2.{index}", "vendor": "Test"} for index in (2, 3)]
    with TestClient(main.app) as client, ThreadPoolExecutor(max_workers=1) as pool:
        login(client)
        future = pool.submit(scanner.record_scan, found)
        try:
            assert entered.wait(3)
            for _ in range(5):
                response = client.post("/api/v1/windows-agents/heartbeat", headers={"Authorization": f"Bearer {key}"}, json={"agent_version": "2.4.5"})
                assert response.status_code == 200, response.text
                assert client.get("/api/v1/windows-agents/package-status").status_code == 200
                agents = client.get("/api/v1/windows-agents")
                assert agents.status_code == 200, agents.text
                assert next(a for a in agents.json() if a["id"] == agent_id)["status"] == "online"
        finally:
            release.set()
        future.result(timeout=5)
    with main.db() as c:
        agent = c.execute("SELECT status,agent_version,last_heartbeat_at FROM windows_agents WHERE id=?", (agent_id,)).fetchone()
        assert agent["status"] == "online" and agent["agent_version"] == "2.4.5"
        assert agent["last_heartbeat_at"] >= stamp
        assert c.execute("SELECT missed_scans FROM devices WHERE mac='aa:00:00:00:00:01'").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 3


def test_winrm_sources_release_writes_before_contacting_next_server(database, monkeypatch):
    stamp = main.now()
    with main.db() as c:
        for name in ("first", "second"):
            c.execute("INSERT INTO windows_event_sources(name,hostname,created_at,updated_at) VALUES(?,?,?,?)", (name, name, stamp, stamp))
    manager = main.WindowsEventCollectorManager(main.db)

    class OneCycle:
        calls = 0

        def wait(self, timeout):
            self.calls += 1
            return self.calls > 1

    manager._stop = OneCycle()
    visited = []

    def poll(c, row):
        # Every simulated network call can coexist with a separate writer.
        writer = sqlite3.connect(database, timeout=0)
        try:
            writer.execute("BEGIN IMMEDIATE")
        finally:
            writer.rollback()
            writer.close()
        visited.append(row["name"])
        c.execute("UPDATE windows_event_sources SET last_status='ok' WHERE id=?", (row["id"],))

    monkeypatch.setattr(manager, "_poll_one", poll)
    manager._loop()
    assert visited == ["first", "second"]
