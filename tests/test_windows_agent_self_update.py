from pathlib import Path
import app.main as main
import app.windows_agent as windows_agent


def manifest(version="2.4.5"):
    return {"version":version,"filename":"GODSEYE-Windows-Agent-x64.msi","sha256":"A"*64}


def make_agent(c, version="2.1.0"):
    now=main.now()
    return c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,status,enabled,channels_json,poll_interval_seconds,enrolled_at,updated_at)
                        VALUES(?,?,?,?, 'online',1,'[\"System\"]',60,?,?)""",
                     ("uuid-"+version,"hash-"+version,"PC-"+version,version,now,now)).lastrowid


def req():
    class R:
        client=None
    return R()


def admin():
    return {"username":"admin","role":"admin"}


def test_manifest_loader_rejects_bad_filename_and_hash(tmp_path):
    p=tmp_path/"manifest.json";p.write_text('{"version":"2.2.0","filename":"evil.exe","sha256":"A"}')
    try: windows_agent.load_update_manifest(p);assert False
    except ValueError: pass


def test_upgrade_queues_only_version_and_hash(tmp_path, monkeypatch):
    db=tmp_path/"upgrade.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db();monkeypatch.setattr(main,"audit",lambda *a,**k:None)
    monkeypatch.setattr(windows_agent,"load_update_manifest",lambda path:manifest("2.4.5"))
    with main.db() as c: aid=make_agent(c,"2.1.0")
    out=main.windows_agent_upgrade(aid,req(),admin())
    assert out["queued"] is True
    with main.db() as c:
        row=c.execute("SELECT * FROM windows_agent_commands WHERE id=?",(out["command_id"],)).fetchone()
        import json
        payload=json.loads(row["payload_json"])
        assert payload=={"version":"2.4.5","sha256":"A"*64}
        assert "url" not in payload and "command" not in payload


def test_pre_21_agent_requires_one_manual_baseline_update(tmp_path, monkeypatch):
    db=tmp_path/"baseline.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db();monkeypatch.setattr(main,"audit",lambda *a,**k:None)
    monkeypatch.setattr(windows_agent,"load_update_manifest",lambda path:manifest("2.4.5"))
    with main.db() as c: aid=make_agent(c,"2.0.1")
    try: main.windows_agent_upgrade(aid,req(),admin());assert False
    except main.HTTPException as exc:
        assert exc.status_code==409 and "manual upgrade" in str(exc.detail).lower()


def test_x64_agent_updater_is_fixed_hash_verified_msi_path():
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    csproj=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    assert '<Version>2.4.5</Version>' in csproj
    assert 'Assembly.GetName().Version' in src
    assert '"upgrade_agent"' in src
    assert '"/api/v1/windows-agents/package/msi"' in src
    assert 'SHA256.Create()' in src and 'Upgrade MSI SHA-256 verification failed.' in src
    assert 'Environment.SystemDirectory' in src and '"msiexec.exe"' in src
    assert 'cmd.exe' not in src.lower()
    assert 'RunDefenderCommand(string action)' in src
    assert 'Remove-MpThreat -ErrorAction Stop' in src
    assert '-EncodedCommand ' in src
    assert 'payload.ContainsKey("script")' not in src
    assert 'payload.ContainsKey("url")' not in src


def test_update_ui_and_server_routes_present():
    source=Path("app/main.py").read_text()
    html=main.DASHBOARD
    route_paths={getattr(route,"path",None) for route in main.app.routes}
    assert '/windows-agents/package/msi' in source
    assert '/api/v1/windows-agents/{agent_id}/upgrade' in route_paths
    assert 'Check for Updates' in html
    assert 'checkWindowsAgentUpdates' in html
    assert 'upgradeWindowsAgent' in html
    assert 'one manual baseline update required' in html


def test_mismatched_newer_agent_requires_current_setup_without_queuing_downgrade(tmp_path, monkeypatch):
    monkeypatch.setattr(main,"DB_PATH",tmp_path/"mismatch.db")
    main.init_db()
    monkeypatch.setattr(main,"_windows_agent_update_manifest",lambda:manifest())
    with main.db() as c: aid=make_agent(c,"2.5.1")
    out=main.windows_agent_upgrade(aid,req(),admin())
    assert out["repair_required"] is True and out["queued"] is False
    assert out["installed_version"] == "2.5.1" and out["available_version"] == "2.4.5"
    with main.db() as c:
        assert c.execute("SELECT COUNT(*) FROM windows_agent_commands WHERE agent_id=?",(aid,)).fetchone()[0] == 0


def test_setup_manifest_rejects_old_tampered_and_malformed_packages(tmp_path):
    import hashlib, json
    path=tmp_path/"GODSEYE-Windows-Agent-x64-Setup-2.4.5.exe"
    path.write_bytes(b"current installer")
    manifest_path=tmp_path/"setup-manifest.json"
    info={"version":"2.4.5","filename":path.name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    manifest_path.write_text(json.dumps(info))
    assert windows_agent.verified_setup_path(tmp_path) == path
    path.write_bytes(b"stale installer")
    assert windows_agent.verified_setup_path(tmp_path) is None
    info["version"]="2.5.2"
    manifest_path.write_text(json.dumps(info))
    assert windows_agent.verified_setup_path(tmp_path) is None
    manifest_path.write_text("[]")
    assert windows_agent.verified_setup_path(tmp_path) is None
