from pathlib import Path
from types import SimpleNamespace
import app.main as main

def _admin_user():
    return {"username":"admin","role":"admin"}

def _request():
    return SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))

def test_version():
    assert Path("VERSION").read_text().strip() in {"4.21.0-ticket-assignee-picker","4.22.0-windows-agent-pull-now","4.22.1-windows-agent-upgrade-hotfix","4.23.0-permanent-x64-windows-agent","4.28.0-clean-rebuild"}

def test_users_schema_has_display_name(tmp_path, monkeypatch):
    db=tmp_path/"users.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    with main.db() as c:
        cols={r["name"] for r in c.execute("PRAGMA table_info(users)")}
    assert "display_name" in cols

def test_ticket_assignees_endpoint_returns_safe_directory(tmp_path, monkeypatch):
    db=tmp_path/"picker.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    with main.db() as c:
        c.execute("UPDATE users SET display_name='Administrator' WHERE username='admin'")
        c.execute("""INSERT INTO users(username,display_name,password_hash,password_salt,role,must_change_password,created_at,password_changed_at)
                     VALUES('tech','Taylor Technician','','','operator',0,?,?)""",(main.now(),main.now()))
    rows=main.ticket_assignees(_admin_user())
    assert {r["username"] for r in rows}=={"admin","tech"}
    admin=next(r for r in rows if r["username"]=="admin")
    assert admin["display_name"]=="Administrator"
    assert set(admin)=={"id","username","display_name","role"}
    assert "password_hash" not in admin

def test_ticket_editor_uses_select_name_picker():
    html=main.DASHBOARD
    assert '<select id="ticketAssignee"' in html
    assert '<input id="ticketAssignee"' not in html
    assert "loadTicketAssignees" in html
    assert "/api/v1/ticket-assignees" in html
    assert "Unassigned" in html

def test_user_admin_can_capture_display_name():
    html=main.DASHBOARD
    assert 'id="newUserDisplayName"' in html
    assert "display_name:document.getElementById('newUserDisplayName').value.trim()" in html

def test_new_ticket_assignment_must_reference_existing_user(tmp_path, monkeypatch):
    db=tmp_path/"tickets.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    req=main.TicketCreateRequest(title="Test",assignee="missing-user")
    try:
        main.ticket_create(req,_request(),_admin_user())
        assert False,"expected invalid assignee rejection"
    except main.HTTPException as exc:
        assert exc.status_code==400
        assert "existing GODSEYE user" in str(exc.detail)

def test_new_ticket_accepts_existing_user(tmp_path, monkeypatch):
    db=tmp_path/"tickets-valid.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    req=main.TicketCreateRequest(title="Test",assignee="admin")
    ticket=main.ticket_create(req,_request(),_admin_user())
    assert ticket["assignee"]=="admin"

def test_legacy_free_text_assignment_survives_unrelated_ticket_update(tmp_path, monkeypatch):
    db=tmp_path/"legacy.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    monkeypatch.setattr(main,"audit",lambda *a,**k: None)
    ts=main.now()
    with main.db() as c:
        cur=c.execute("""INSERT INTO tickets(ticket_number,title,status,priority,assignee,created_by,created_at,updated_at)
                         VALUES('TKT-00001','Legacy','open','medium','Administrator / technician','admin',?,?)""",(ts,ts))
        tid=cur.lastrowid
    out=main.ticket_update(tid,main.TicketUpdateRequest(title="Legacy updated",assignee="Administrator / technician"),_request(),_admin_user())
    assert out["assignee"]=="Administrator / technician"
    assert out["title"]=="Legacy updated"
