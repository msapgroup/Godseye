from pathlib import Path
from types import SimpleNamespace
import json
import app.main as main
from app import event_ticketing

def test_version():
    assert Path("VERSION").read_text().strip().startswith(("4.17.0-","4.18.0-", "4.19.0-", "4.20.0-", "4.21.0-", "4.22.0-", "4.22.1-", "4.23.0-"))

def test_event_and_ticket_schema_bootstrap(tmp_path,monkeypatch):
    db=tmp_path/"event-ticket.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    with main.db() as c:
        src={r["name"] for r in c.execute("PRAGMA table_info(windows_event_sources)")}
        ef={r["name"] for r in c.execute("PRAGMA table_info(event_findings)")}
        tk={r["name"] for r in c.execute("PRAGMA table_info(tickets)")}
        notes={r["name"] for r in c.execute("PRAGMA table_info(ticket_notes)")}
    assert {"hostname","password_enc","poll_interval_minutes","last_record_json","last_status"} <= src
    assert {"computer_name","provider","event_id","category","severity","recommendation","occurrence_count","last_recheck_at"} <= ef
    assert {"ticket_number","status","priority","linked_type","linked_id","calendar_event_id","closed_at"} <= tk
    assert {"ticket_id","note","author","created_at"} <= notes

def test_winrm_query_filters_only_critical_error_warning_and_bookmarks():
    ps=event_ticketing.winrm_powershell_query(["System"],{"System":123})
    assert "Level=1,2,3" in ps
    assert "RecordId -gt $last" in ps
    assert "Get-WinEvent" in ps
    assert "System" not in ps  # channel list is base64 encoded, not interpolated into script
    assert "ConvertTo-Json" in ps

def test_storage_event_becomes_critical_actionable_finding(tmp_path,monkeypatch):
    db=tmp_path/"storage.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db()
    event={"computer_name":"FILESERVER01","channel":"System","provider":"disk","event_id":7,"level":"Error","record_id":100,"event_time":"2026-09-13T10:00:00+00:00","message":"The device has a bad block."}
    with main.db() as c:
        fid,created=event_ticketing.ingest_event(c,None,event,main.now())
        row=c.execute("SELECT * FROM event_findings WHERE id=?",(fid,)).fetchone()
    assert created
    assert row["severity"]=="critical"
    assert row["category"]=="Storage"
    assert "disk reliability" in row["title"].lower()
    actions=json.loads(row["suggested_actions_json"])
    assert any("SMART" in x for x in actions)
    assert any("Back up" in x for x in actions)

def test_repeated_event_updates_occurrence_not_duplicate(tmp_path,monkeypatch):
    db=tmp_path/"repeat.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db()
    event={"computer_name":"PC01","channel":"System","provider":"storahci","event_id":129,"level":"Warning","record_id":1,"message":"Reset to device."}
    with main.db() as c:
        a,new1=event_ticketing.ingest_event(c,1,event,main.now())
        event["record_id"]=2
        b,new2=event_ticketing.ingest_event(c,1,event,main.now())
        count=c.execute("SELECT COUNT(*) n FROM event_findings").fetchone()["n"]
        row=c.execute("SELECT * FROM event_findings WHERE id=?",(a,)).fetchone()
    assert a==b and new1 and not new2 and count==1 and row["occurrence_count"]==2

def test_management_sidebar_has_event_findings_and_ticket_portal():
    html=main.DASHBOARD
    management=html[html.index('<div class="navsection">Management</div>'):html.index('<div class="navsection">Administration</div>')]
    assert 'data-view="event-findings"' in management
    assert '<span>Event Findings</span>' in management
    assert 'data-view="tickets"' in management
    assert '<span>Ticket Portal</span>' in management

def test_event_findings_workflow_ui_and_source_manager():
    html=main.DASHBOARD
    for token in ('id="view-event-findings"','id="windowsSourceModal"','Pull Events Now','Suggested Fix','Create Ticket','Recheck','Resolve'):
        assert token in html
    source=Path("app/main.py").read_text()
    assert '@app.post(f"{router_prefix}/windows-event-sources/{{source_id}}/poll")' in source
    assert '@app.post(f"{router_prefix}/event-findings/{{finding_id}}/recheck")' in source
    assert '@app.post(f"{router_prefix}/event-findings/{{finding_id}}/resolve")' in source
    assert '@app.post(f"{router_prefix}/event-findings/{{finding_id}}/create-ticket")' in source

def test_ticket_portal_calendar_controls_present():
    html=main.DASHBOARD
    for token in ('id="view-tickets"','id="ticketEditorModal"','Schedule on Calendar','Work Notes','Close Ticket','id="calendarTicketActions"','Open Ticket','Add Work Note'):
        assert token in html
    source=Path("app/main.py").read_text()
    assert '@app.post(f"{router_prefix}/tickets/{{ticket_id}}/schedule")' in source
    assert '@app.post(f"{router_prefix}/tickets/{{ticket_id}}/close")' in source
    assert 'source=\'ticket\'' in source or "'ticket'" in source

def test_event_finding_creates_ticket_and_calendar_schedule(tmp_path,monkeypatch):
    db=tmp_path/"flow.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db()
    monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    request=SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
    user={"username":"admin","role":"admin"}
    event={"computer_name":"FILESERVER01","channel":"System","provider":"disk","event_id":7,"level":"Error","record_id":100,"message":"bad block"}
    with main.db() as c:
        fid,_=event_ticketing.ingest_event(c,None,event,main.now())
    ticket=main.event_finding_create_ticket(fid,request,user)
    assert ticket["ticket_number"].startswith("TKT-")
    assert ticket["linked_type"]=="event_finding"
    sched=main.ticket_schedule(ticket["id"],main.TicketScheduleRequest(start_at="2026-09-14T13:00:00+00:00",end_at="2026-09-14T14:00:00+00:00"),request,user)
    assert sched["calendar_event_id"]>0
    with main.db() as c:
        cal=c.execute("SELECT * FROM calendar_events WHERE id=?",(sched["calendar_event_id"],)).fetchone()
        t=c.execute("SELECT * FROM tickets WHERE id=?",(ticket["id"],)).fetchone()
    assert cal["source"]=="ticket"
    assert cal["external_uid"]==str(ticket["id"])
    assert t["calendar_event_id"]==sched["calendar_event_id"]

def test_close_ticket_can_resolve_linked_event_finding(tmp_path,monkeypatch):
    db=tmp_path/"close.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db()
    monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    request=SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
    user={"username":"admin","role":"admin"}
    event={"computer_name":"PC01","channel":"System","provider":"WHEA-Logger","event_id":18,"level":"Error","record_id":1,"message":"hardware error"}
    with main.db() as c:
        fid,_=event_ticketing.ingest_event(c,None,event,main.now())
    ticket=main.event_finding_create_ticket(fid,request,user)
    main.ticket_close(ticket["id"],main.TicketCloseRequest(note="Replaced failing component; diagnostics passed.",resolve_linked_finding=True),request,user)
    with main.db() as c:
        t=c.execute("SELECT * FROM tickets WHERE id=?",(ticket["id"],)).fetchone()
        f=c.execute("SELECT * FROM event_findings WHERE id=?",(fid,)).fetchone()
        n=c.execute("SELECT * FROM ticket_notes WHERE ticket_id=?",(ticket["id"],)).fetchall()
    assert t["status"]=="closed" and t["closed_at"]
    assert f["status"]=="resolved"
    assert len(n)==1 and "diagnostics passed" in n[0]["note"]

def test_network_findings_can_create_tickets():
    source=Path("app/main.py").read_text()
    assert '@app.post(f"{router_prefix}/intelligence/issues/{{issue_id}}/create-ticket")' in source
    assert "createTicketFromNetworkFinding" in source

def test_winrm_credentials_encrypted_at_rest():
    source=Path("app/main.py").read_text()
    assert "encrypt_secret(req.password)" in source
    assert 'decrypt_secret(source.get("password_enc"))' in source
    assert "https://" in Path("app/event_ticketing.py").read_text()

def test_pywinrm_dependency_packaged():
    req=Path("requirements.txt").read_text()
    assert "pywinrm" in req

def test_v417_dark_screenshots_packaged():
    for name in ("dark-event-findings.png","dark-ticket-portal.png","dark-calendar.png","godseye-dark-mode-overview.png"):
        assert Path("docs/screenshots",name).exists()
    docs=Path("docs/SCREENSHOTS.md").read_text()
    assert "dark-event-findings.png" in docs
    assert "dark-ticket-portal.png" in docs

def test_windows_setup_docs_packaged():
    assert Path("docs/WINDOWS_EVENT_FINDINGS.md").exists()
    assert Path("windows/GODSEYE-WinRM-EventLog-Setup.ps1").exists()
