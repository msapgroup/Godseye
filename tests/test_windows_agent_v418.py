from pathlib import Path
from types import SimpleNamespace
import json
import zipfile

import app.main as main
from app import windows_agent
from app import event_ticketing


def req(ip="192.168.1.50", headers=None):
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers=headers or {})


def test_version_v418():
    assert Path("VERSION").read_text().strip().startswith(("4.18.0-","4.19.0-", "4.20.0-", "4.21.0-", "4.22.0-", "4.22.1-", "4.23.0-", "4.24.0", "4.25.0"))


def test_agent_schema_and_event_finding_agent_link(tmp_path, monkeypatch):
    db=tmp_path/"agent.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db()
    with main.db() as c:
        tables={r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        cols={r["name"] for r in c.execute("PRAGMA table_info(event_findings)")}
    assert {"windows_agents","windows_agent_enrollment_tokens","windows_agent_rechecks"} <= tables
    assert "agent_id" in cols


def test_agent_tokens_are_random_prefixed_and_server_hashes_only():
    a=windows_agent.new_enrollment_token(); b=windows_agent.new_enrollment_token(); k=windows_agent.new_agent_key()
    assert a.startswith("gse_") and b.startswith("gse_") and a != b
    assert k.startswith("gsa_") and len(k)>40
    assert windows_agent.token_hash(a) != a
    assert windows_agent.verify_token(a,windows_agent.token_hash(a))


def test_one_time_enrollment_and_dpapi_contract(tmp_path, monkeypatch):
    db=tmp_path/"enroll.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db()
    user={"username":"admin","role":"admin"}
    token_result=main.windows_agent_create_enrollment(main.WindowsAgentEnrollmentRequest(label="FILESERVER01",expires_minutes=30),req(),user)
    raw=token_result["enrollment_token"]
    with main.db() as c:
        row=c.execute("SELECT * FROM windows_agent_enrollment_tokens").fetchone()
        assert row["token_hash"] == windows_agent.token_hash(raw)
        assert raw not in dict(row).values()
    enroll=main.windows_agent_enroll(main.WindowsAgentEnrollRequest(enrollment_token=raw,agent_uuid="uuid-1",computer_name="FILESERVER01",machine_guid="machine-1",hostname="fileserver01",os_version="Windows Server",architecture="x64",agent_version="1.0.0"),req())
    assert enroll["agent_id"]>0 and enroll["api_key"].startswith("gsa_")
    with main.db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(enroll["agent_id"],)).fetchone()
        assert agent["api_key_hash"] == windows_agent.token_hash(enroll["api_key"])
        token=c.execute("SELECT * FROM windows_agent_enrollment_tokens").fetchone()
        assert token["used_at"]
    try:
        main.windows_agent_enroll(main.WindowsAgentEnrollRequest(enrollment_token=raw,agent_uuid="uuid-2",computer_name="PC02"),req())
        assert False,"used enrollment token should fail"
    except main.HTTPException as e:
        assert e.status_code==401
    csharp=Path("windows/agent/src/GodseyeAgentService.cs").read_text()
    assert "ProtectedData.Protect" in csharp and "DataProtectionScope.LocalMachine" in csharp


def test_agent_event_upload_creates_event_finding_bound_to_agent(tmp_path, monkeypatch):
    db=tmp_path/"events.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db()
    ts=main.now()
    with main.db() as c:
        aid=c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,enrolled_at,updated_at) VALUES('a','h','FILESERVER01',?,?)""",(ts,ts)).lastrowid
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(aid,)).fetchone()
    batch=main.WindowsAgentEventBatch(events=[main.WindowsAgentEvent(computer_name="SPOOFED",channel="System",provider="disk",event_id=7,level="Error",record_id=99,event_time=ts,message="The device has a bad block")])
    result=main.windows_agent_events(batch,req(),agent)
    assert result["events"]==1 and result["new_findings"]==1
    with main.db() as c:
        finding=c.execute("SELECT * FROM event_findings").fetchone()
    assert finding["agent_id"]==aid
    assert finding["computer_name"]=="FILESERVER01"  # server binds events to enrolled identity
    assert finding["category"]=="Storage"


def test_agent_recheck_queue_delivered_and_completed(tmp_path, monkeypatch):
    db=tmp_path/"recheck.db"; monkeypatch.setattr(main,"DB_PATH",db); main.init_db()
    monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    ts=main.now(); user={"username":"admin","role":"admin"}
    with main.db() as c:
        aid=c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,enrolled_at,updated_at,last_heartbeat_at) VALUES('a','h','PC01',?,?,?)""",(ts,ts,ts)).lastrowid
        fid,_=event_ticketing.ingest_event(c,None,{"computer_name":"PC01","channel":"System","provider":"WHEA-Logger","event_id":18,"level":"Error","record_id":100,"message":"hardware error"},ts,agent_id=aid)
    queued=main.event_finding_recheck(fid,req(),user)
    assert queued["pending"] and queued["recheck_id"]>0
    with main.db() as c: agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(aid,)).fetchone()
    hb=main.windows_agent_heartbeat(main.WindowsAgentHeartbeatRequest(computer_name="PC01",agent_version="1.0.0"),req(),agent)
    assert len(hb["rechecks"])==1 and hb["rechecks"][0]["finding"]["event_id"]==18
    main.windows_agent_recheck_result(queued["recheck_id"],main.WindowsAgentRecheckResult(seen_again=False,details="No newer matching WHEA event."),req(),agent)
    with main.db() as c:
        rr=c.execute("SELECT * FROM windows_agent_rechecks WHERE id=?",(queued["recheck_id"],)).fetchone()
    assert rr["status"]=="completed"
    assert json.loads(rr["result_json"])["seen_again"] is False


def test_agent_rechecks_are_redelivered_until_acknowledged():
    source=Path("app/main.py").read_text()
    assert "status IN ('pending','delivered')" in source


def test_agent_ui_recommended_and_winrm_retained_as_fallback():
    html=main.DASHBOARD
    assert "Windows Agent is the recommended collection method" in html
    assert 'id="windowsAgentModal"' in html
    assert "Create Enrollment Token" in html
    assert ("Download Agent" in html) or ("Download x64 Installer" in html)
    assert "WinRM Sources" in html and "Pull Events Now (WinRM)" in html
    assert "outbound HTTPS" in html.lower() or "Outbound HTTPS" in html


def test_agent_service_is_read_only_event_collector_with_durable_queue():
    src=Path("windows/agent/src/GodseyeAgentService.cs").read_text()
    assert "System.Diagnostics.Eventing.Reader" in src
    assert "Level=1 or Level=2 or Level=3" in src
    assert "EventRecordID >" in src
    assert "pending-events.json" in src
    assert "Uploaded " in src
    assert "Process.Start" not in src
    assert "System.Management.Automation" not in src
    assert "cmd.exe" not in src.lower()
    assert "powershell.exe" not in src.lower()


def test_agent_installer_creates_64bit_windows_service_and_https_default():
    ps=Path("windows/agent/Install-GODSEYEAgent.ps1").read_text()
    assert "Framework64" in ps
    assert "GODSEYEWindowsAgent" in ps
    assert "sc.exe create" in ps
    assert "Start-Service" in ps
    assert "Use an HTTPS GODSEYE URL" in ps
    assert "-AllowHttp" in ps
    assert "icacls" in ps


def test_agent_package_is_embedded_for_dashboard_download():
    package=Path("windows/agent/GODSEYE-Windows-Agent.zip")
    assert package.exists()
    with zipfile.ZipFile(package) as z:
        names=set(z.namelist())
        assert "Install-GODSEYEAgent.ps1" in names
        assert "Uninstall-GODSEYEAgent.ps1" in names
        assert "src/GodseyeAgentService.cs" in names
        assert z.testzip() is None
    source=Path("app/main.py").read_text()
    assert '@app.get(f"{router_prefix}/windows-agents/package")' in source


def test_agent_management_api_and_revoke_present():
    source=Path("app/main.py").read_text()
    for token in (
        '/windows-agents/enrollment-tokens', '/windows-agents/enroll', '/windows-agents/heartbeat',
        '/windows-agents/events', '/windows-agents/rechecks/{{recheck_id}}/result', '/windows-agents/{{agent_id}}'
    ):
        assert token in source
    assert "api_key_hash" in source
    assert "windows_agent_revoked" in source


def test_windows_agent_screenshot_packaged():
    assert Path("docs/screenshots/dark-windows-agent.png").exists()
    docs=Path("docs/SCREENSHOTS.md").read_text()
    assert "dark-windows-agent.png" in docs
    assert Path("docs/screenshots/godseye-dark-mode-overview.png").exists()
