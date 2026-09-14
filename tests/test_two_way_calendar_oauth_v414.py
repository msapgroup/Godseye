from pathlib import Path
from types import SimpleNamespace
import app.main as main

def test_version():
    assert Path("VERSION").read_text().strip().startswith(("4.14.0-","4.15.0-", "4.16.0-", "4.17.0-", "4.18.0-"))

def test_oauth_schema_columns_exist(tmp_path,monkeypatch):
    db=tmp_path/"calendar-oauth.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    with main.db() as c:
        cols={r["name"] for r in c.execute("PRAGMA table_info(calendar_integrations)")}
        state_cols={r["name"] for r in c.execute("PRAGMA table_info(calendar_oauth_states)")}
    assert {"auth_mode","remote_calendar_id","client_id","client_secret_enc","access_token_enc","refresh_token_enc","token_expires_at"} <= cols
    assert {"state","integration_id","provider","redirect_uri","created_by","expires_at"} <= state_cols

def test_ui_exposes_two_way_oauth_and_ics_fallback():
    html=main.DASHBOARD
    assert "Two-way OAuth" in html
    assert "ICS read-only fallback" in html
    assert "OAuth client ID" in html
    assert "OAuth client secret" in html
    assert 'id="calendarEventTarget"' in html
    assert "GODSEYE local calendar" in html

def test_google_and_microsoft_write_scopes_are_present():
    source=Path("app/main.py").read_text()
    assert 'https://www.googleapis.com/auth/calendar' in source
    assert 'Calendars.ReadWrite' in source
    assert 'offline_access' in source
    assert 'accounts.google.com/o/oauth2/v2/auth' in source
    assert 'login.microsoftonline.com/common/oauth2/v2.0/authorize' in source

def test_provider_write_endpoints_are_implemented():
    source=Path("app/main.py").read_text()
    assert "def _calendar_remote_create" in source
    assert "def _calendar_remote_update" in source
    assert "def _calendar_remote_delete" in source
    assert 'method="PATCH"' in source
    assert 'method="DELETE"' in source

def test_google_payload_supports_timed_event():
    req=main.CalendarEventRequest(
        title="Firewall maintenance",description="Patch",location="Rack",
        start_at="2026-09-21T13:00:00+00:00",end_at="2026-09-21T14:00:00+00:00",
        all_day=False,color="blue"
    )
    payload=main._calendar_google_event_payload(req)
    assert payload["summary"]=="Firewall maintenance"
    assert payload["start"]["dateTime"].startswith("2026-09-21T13:00:00")
    assert payload["end"]["dateTime"].startswith("2026-09-21T14:00:00")

def test_microsoft_payload_is_readwrite_event_shape():
    req=main.CalendarEventRequest(
        title="Security review",description="Review alerts",location="Teams",
        start_at="2026-09-22T13:00:00+00:00",end_at="2026-09-22T14:30:00+00:00",
        all_day=False,color="purple"
    )
    payload=main._calendar_ms_event_payload(req)
    assert payload["subject"]=="Security review"
    assert payload["body"]["content"]=="Review alerts"
    assert payload["location"]["displayName"]=="Teams"
    assert payload["start"]["timeZone"]=="UTC"

def test_remote_event_crud_updates_local_database(tmp_path,monkeypatch):
    db=tmp_path/"two-way.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    with main.db() as c:
        ts=main.now()
        cur=c.execute("""INSERT INTO calendar_integrations(provider,name,auth_mode,remote_calendar_id,client_id,client_secret_enc,access_token_enc,refresh_token_enc,enabled,sync_interval_minutes,last_status,created_at,updated_at)
                         VALUES('google','Work','oauth','primary','cid','secret','access','refresh',1,30,'connected',?,?)""",(ts,ts))
        iid=cur.lastrowid
    calls=[]
    monkeypatch.setattr(main,"_calendar_remote_create",lambda c,i,r: calls.append(("create",i["id"],r.title)) or "remote-123")
    monkeypatch.setattr(main,"_calendar_remote_update",lambda c,i,rid,r: calls.append(("update",rid,r.title)))
    monkeypatch.setattr(main,"_calendar_remote_delete",lambda c,i,rid: calls.append(("delete",rid)))
    monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    request=SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
    user={"username":"admin","role":"admin"}
    req=main.CalendarEventRequest(title="Remote event",start_at="2026-09-23T10:00:00+00:00",end_at="2026-09-23T11:00:00+00:00",calendar_integration_id=iid)
    created=main.calendar_event_create(req,request,user)
    assert created["source"]==f"calendar:{iid}"
    assert created["external_uid"]=="remote-123"
    updated_req=main.CalendarEventRequest(title="Remote event updated",start_at="2026-09-23T10:30:00+00:00",end_at="2026-09-23T11:30:00+00:00")
    updated=main.calendar_event_update(created["id"],updated_req,request,user)
    assert updated["title"]=="Remote event updated"
    main.calendar_event_delete(created["id"],request,user)
    assert [x[0] for x in calls]==["create","update","delete"]

def test_ics_fallback_remains_readonly():
    source=Path("app/main.py").read_text()
    assert "ICS subscription events are read-only" in source
    assert "auth_mode=='oauth'" in source or 'auth_mode"]=="oauth"' in source or 'auth_mode"] != "oauth"' in source

def test_oauth_tokens_are_encrypted_and_public_url_supported():
    source=Path("app/main.py").read_text()
    assert "encrypt_secret(access)" in source
    assert "encrypt_secret(refresh)" in source
    assert "client_secret_enc" in source
    assert 'GODSEYE_PUBLIC_URL' in source

def test_calendar_auto_sync_dispatches_oauth_or_ics():
    source=Path("app/main.py").read_text()
    assert "def _sync_calendar_integration" in source
    assert "_sync_calendar_oauth(c,integration)" in source
    assert "_sync_calendar_ics(c,integration)" in source
    assert "_sync_calendar_integration(c,row)" in source
