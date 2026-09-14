from pathlib import Path
from types import SimpleNamespace
import json
import app.main as main


def req(ip="192.168.1.50"):
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers={})


def user():
    return {"username":"admin","role":"admin"}


def make_agent(c, version="1.1.0"):
    ts=main.now()
    aid=c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,status,enabled,last_heartbeat_at,enrolled_at,updated_at)
                     VALUES('pull-agent','hash','FILESERVER01',?,'online',1,?,?,?)""",(version,ts,ts,ts)).lastrowid
    return aid


def test_version_v422():
    assert Path("VERSION").read_text().strip() in {"4.22.0-windows-agent-pull-now","4.22.1-windows-agent-upgrade-hotfix"}


def test_pull_command_schema(tmp_path, monkeypatch):
    db=tmp_path/"commands.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db()
    with main.db() as c:
        tables={r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        cols={r["name"] for r in c.execute("PRAGMA table_info(windows_agent_commands)")}
    assert "windows_agent_commands" in tables
    assert {"agent_id","command_type","status","requested_by","requested_at","delivered_at","completed_at","result_json"} <= cols


def test_pull_now_queues_and_heartbeat_delivers(tmp_path, monkeypatch):
    db=tmp_path/"pull.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db(); monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    with main.db() as c: aid=make_agent(c,"1.1.0")
    queued=main.windows_agent_pull_now(aid,req(),user())
    assert queued["queued"] and queued["status"]=="pending"
    with main.db() as c: agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(aid,)).fetchone()
    hb=main.windows_agent_heartbeat(main.WindowsAgentHeartbeatRequest(computer_name="FILESERVER01",agent_version="1.1.0"),req(),agent)
    assert len(hb["commands"])==1
    assert hb["commands"][0]["type"]=="pull_events"
    assert hb["commands"][0]["command_id"]==queued["command_id"]
    with main.db() as c:
        row=c.execute("SELECT * FROM windows_agent_commands WHERE id=?",(queued["command_id"],)).fetchone()
    assert row["status"]=="delivered" and row["delivered_at"]


def test_pull_command_result_completes_and_records_counts(tmp_path, monkeypatch):
    db=tmp_path/"result.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db(); monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    with main.db() as c:
        aid=make_agent(c,"1.1.0")
        cid=c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,status,requested_by,requested_at) VALUES(?,'pull_events','delivered','admin',?)",(aid,main.now())).lastrowid
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(aid,)).fetchone()
    main.windows_agent_command_result(cid,main.WindowsAgentCommandResult(ok=True,events=7,new_findings=2,details="Pull complete"),req(),agent)
    with main.db() as c:
        row=c.execute("SELECT * FROM windows_agent_commands WHERE id=?",(cid,)).fetchone()
    result=json.loads(row["result_json"])
    assert row["status"]=="completed" and row["completed_at"]
    assert result["events"]==7 and result["new_findings"]==2


def test_duplicate_pending_pull_is_not_duplicated(tmp_path, monkeypatch):
    db=tmp_path/"duplicate.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db(); monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    with main.db() as c: aid=make_agent(c,"1.1.0")
    a=main.windows_agent_pull_now(aid,req(),user())
    b=main.windows_agent_pull_now(aid,req(),user())
    assert a["command_id"]==b["command_id"]
    with main.db() as c: count=c.execute("SELECT COUNT(*) FROM windows_agent_commands WHERE agent_id=?",(aid,)).fetchone()[0]
    assert count==1


def test_v10_agent_requires_update_for_pull_now(tmp_path, monkeypatch):
    db=tmp_path/"old.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db(); monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    with main.db() as c: aid=make_agent(c,"1.0.0")
    try:
        main.windows_agent_pull_now(aid,req(),user())
        assert False,"old agent should be rejected"
    except main.HTTPException as exc:
        assert exc.status_code==409
        assert "1.1.0" in str(exc.detail)


def test_agent_list_exposes_pull_support_and_status(tmp_path, monkeypatch):
    db=tmp_path/"list.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db()
    with main.db() as c:
        aid=make_agent(c,"1.1.0")
        c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,status,requested_by,requested_at,completed_at,result_json) VALUES(?,'pull_events','completed','admin',?,?,?)",(aid,main.now(),main.now(),json.dumps({"events":3,"new_findings":1})))
    rows=main.windows_agent_list(user())
    row=next(x for x in rows if x["id"]==aid)
    assert row["pull_now_supported"] is True
    assert row["last_pull_status"]=="completed"
    assert row["last_pull_result"]["events"]==3


def test_pull_now_ui_present():
    html=main.DASHBOARD
    assert "Pull Events Now (Agents)" in html
    assert "Pull All Online" in html
    assert "pullWindowsAgentNow" in html
    assert "pullAllWindowsAgentsNow" in html
    assert "Update Agent for Pull Now" in html


def test_agent_v11_command_loop_and_no_arbitrary_execution():
    src=Path("windows/agent/src/GodseyeAgentService.cs").read_text()
    assert ('AgentVersion = "1.1.0"' in src) or ('AgentVersion = "1.1.1"' in src)
    assert 'wait = 10' in src
    assert 'ProcessCommands(cfg, hb)' in src
    assert '"pull_events"' in src
    assert 'PullEventsNow' in src
    assert '/api/v1/windows-agents/commands/' in src
    assert 'Process.Start' not in src
    assert 'cmd.exe' not in src.lower()
    assert 'powershell.exe' not in src.lower()


def test_agent_upgrade_preserves_existing_enrollment():
    ps=Path("windows/agent/Install-GODSEYEAgent.ps1").read_text()
    assert '$existingEnrollment' in ps
    assert ('Existing enrollment and DPAPI-protected API key preserved.' in ps) or ('Existing enrollment, agent UUID, config, and DPAPI-protected API key preserved.' in ps)
    assert '[string]$EnrollmentToken = ""' in ps
    assert 'EnrollmentToken is required for a new installation' in ps


def test_agent_v11_package_embedded():
    import zipfile
    package=Path("windows/agent/GODSEYE-Windows-Agent.zip")
    with zipfile.ZipFile(package) as z:
        src=z.read("src/GodseyeAgentService.cs").decode()
        readme=z.read("README.md").decode()
        assert ('AgentVersion = "1.1.0"' in src) or ('AgentVersion = "1.1.1"' in src)
        assert "Pull Events Now" in readme
        assert z.testzip() is None
