from pathlib import Path
from types import SimpleNamespace
import json
import app.main as main
import app.windows_agent as windows_agent


def req(ip="192.168.1.50"):
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers={})


def admin():
    return {"username":"admin","role":"admin"}


def make_agent(c, version="2.1.0"):
    ts=main.now()
    return c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,status,enabled,last_heartbeat_at,enrolled_at,updated_at)
                        VALUES('update-agent','hash','FILESERVER01',?,'online',1,?,?,?)""",(version,ts,ts,ts)).lastrowid


def manifest(version="2.2.0"):
    return {"version":version,"filename":"GODSEYE-Windows-Agent-x64.msi","sha256":"A"*64}


def test_manifest_validation(tmp_path):
    p=tmp_path/"update-manifest.json"
    p.write_text(json.dumps(manifest("2.1.0")))
    assert windows_agent.load_update_manifest(p)["version"]=="2.1.0"
    p.write_text(json.dumps({**manifest(),"filename":"evil.exe"}))
    try: windows_agent.load_update_manifest(p); assert False
    except ValueError: pass


def test_update_inventory_and_upgrade_queue(tmp_path, monkeypatch):
    db=tmp_path/"update.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db();monkeypatch.setattr(main,"audit",lambda *a,**k:None)
    monkeypatch.setattr(windows_agent,"load_update_manifest",lambda path:manifest("2.2.0"))
    with main.db() as c: aid=make_agent(c,"2.1.0")
    rows=main.windows_agent_list(admin());row=next(x for x in rows if x["id"]==aid)
    assert row["update_available"] is True and row["upgrade_supported"] is True and row["available_version"]=="2.2.0"
    queued=main.windows_agent_upgrade(aid,req(),admin())
    assert queued["queued"] and queued["available_version"]=="2.2.0"
    again=main.windows_agent_upgrade(aid,req(),admin())
    assert again["command_id"]==queued["command_id"]
    with main.db() as c:
        cmd=c.execute("SELECT * FROM windows_agent_commands WHERE id=?",(queued["command_id"],)).fetchone()
    assert cmd["command_type"]=="upgrade_agent"
    payload=json.loads(cmd["payload_json"])
    assert payload=={"version":"2.2.0","sha256":"A"*64}
    assert "url" not in payload and "command" not in payload


def test_pre_21_agent_requires_one_manual_baseline_update(tmp_path, monkeypatch):
    db=tmp_path/"baseline.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db();monkeypatch.setattr(main,"audit",lambda *a,**k:None)
    monkeypatch.setattr(windows_agent,"load_update_manifest",lambda path:manifest("2.1.0"))
    with main.db() as c: aid=make_agent(c,"2.0.1")
    try: main.windows_agent_upgrade(aid,req(),admin());assert False
    except main.HTTPException as exc:
        assert exc.status_code==409 and "manual upgrade" in str(exc.detail).lower()


def test_x64_agent_updater_is_fixed_hash_verified_msi_path():
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    csproj=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    assert '<Version>2.1.0</Version>' in csproj
    assert 'Assembly.GetName().Version' in src
    assert '"upgrade_agent"' in src
    assert '"/api/v1/windows-agents/package/msi"' in src
    assert 'SHA256.Create()' in src and 'Upgrade MSI SHA-256 verification failed.' in src
    assert 'Environment.SystemDirectory' in src and '"msiexec.exe"' in src
    assert 'cmd.exe' not in src.lower()
    assert 'powershell.exe' not in src.lower()
    assert 'payload.ContainsKey("url")' not in src


def test_update_ui_and_server_routes_present():
    source=Path("app/main.py").read_text()
    html=main.DASHBOARD
    assert '/windows-agents/package/msi' in source
    assert '/windows-agents/{agent_id}/upgrade' in source
    assert 'Check for Updates' in html
    assert 'checkWindowsAgentUpdates' in html
    assert 'upgradeWindowsAgent' in html
    assert 'one manual baseline update required' in html
