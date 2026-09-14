from pathlib import Path
from types import SimpleNamespace
import datetime as dt
import app.main as main


def _req():
    return SimpleNamespace(client=SimpleNamespace(host='127.0.0.1'))


def _admin():
    return {'username':'admin','role':'admin'}


def test_version_v420():
    assert Path('VERSION').read_text().strip() in ('4.20.0-event-ticket-cleanup','4.21.0-ticket-assignee-picker')


def test_ticket_cleanup_api_declarations_are_admin_only():
    src=Path('app/main.py').read_text()
    assert '@app.delete(f"{router_prefix}/tickets/{{ticket_id}}")' in src
    assert 'def ticket_delete(ticket_id: int, request: Request, user=Depends(require_admin))' in src
    assert '@app.post(f"{router_prefix}/tickets/bulk-delete")' in src
    assert 'def ticket_bulk_delete(req: TicketBulkDeleteRequest, request: Request, user=Depends(require_admin))' in src
    assert '@app.post(f"{router_prefix}/tickets/delete-old")' in src
    assert 'def ticket_delete_old(req: TicketDeleteOldRequest, request: Request, user=Depends(require_admin))' in src


def test_ticket_cleanup_ui_controls_present():
    html=main.DASHBOARD
    for token in ('ticketDeleteSelected','Delete Selected','ticketOldDays','Delete Old Tickets','ticket-row-check','deleteSelectedTickets','deleteOldTickets','ticketDeleteBtn'):
        assert token in html
    assert 'Closed / resolved &gt; 90 days' in html


def test_single_ticket_delete_removes_notes_and_local_calendar_but_preserves_finding(tmp_path,monkeypatch):
    db=tmp_path/'single.db'; monkeypatch.setattr(main,'DB_PATH',db); main.init_db(); monkeypatch.setattr(main,'audit',lambda *a,**k: None)
    ts=main.now()
    with main.db() as c:
        fid=c.execute("INSERT INTO network_issues(issue_type,severity,target,title,evidence,recommendation,status,first_seen,last_seen) VALUES('service_failure','high','PC01','Test finding','{}','','open',?,?)",(ts,ts)).lastrowid
        eid=c.execute("INSERT INTO calendar_events(title,description,location,start_at,end_at,all_day,color,source,external_uid,external_readonly,created_by,created_at,updated_at) VALUES('TKT','', '', ?, ?,0,'blue','ticket','1',0,'admin',?,?)",(ts,ts,ts,ts)).lastrowid
        tid=c.execute("INSERT INTO tickets(ticket_number,title,status,priority,linked_type,linked_id,calendar_event_id,created_by,created_at,updated_at) VALUES('TKT-00001','Work','closed','high','network_finding',?,?, 'admin',?,?)",(fid,eid,ts,ts)).lastrowid
        c.execute("INSERT INTO ticket_notes(ticket_id,note,author,created_at) VALUES(?,?,?,?)",(tid,'done','admin',ts))
    r=main.ticket_delete(tid,_req(),_admin())
    assert r['deleted']==1
    with main.db() as c:
        assert c.execute('SELECT COUNT(*) n FROM tickets WHERE id=?',(tid,)).fetchone()['n']==0
        assert c.execute('SELECT COUNT(*) n FROM ticket_notes WHERE ticket_id=?',(tid,)).fetchone()['n']==0
        assert c.execute('SELECT COUNT(*) n FROM calendar_events WHERE id=?',(eid,)).fetchone()['n']==0
        assert c.execute('SELECT COUNT(*) n FROM network_issues WHERE id=?',(fid,)).fetchone()['n']==1


def test_bulk_delete_deletes_selected_only(tmp_path,monkeypatch):
    db=tmp_path/'bulk.db'; monkeypatch.setattr(main,'DB_PATH',db); main.init_db(); monkeypatch.setattr(main,'audit',lambda *a,**k: None)
    ts=main.now()
    with main.db() as c:
        ids=[]
        for i in range(3):
            ids.append(c.execute("INSERT INTO tickets(ticket_number,title,status,priority,created_by,created_at,updated_at) VALUES(?,?, 'closed','medium','admin',?,?)",(f'TKT-{i+1:05d}',f'T{i}',ts,ts)).lastrowid)
    r=main.ticket_bulk_delete(main.TicketBulkDeleteRequest(ticket_ids=ids[:2]),_req(),_admin())
    assert r['deleted']==2
    with main.db() as c:
        left=[x['id'] for x in c.execute('SELECT id FROM tickets ORDER BY id').fetchall()]
    assert left==[ids[2]]


def test_old_ticket_cleanup_only_removes_old_resolved_closed(tmp_path,monkeypatch):
    db=tmp_path/'old.db'; monkeypatch.setattr(main,'DB_PATH',db); main.init_db(); monkeypatch.setattr(main,'audit',lambda *a,**k: None)
    now=dt.datetime.now(dt.timezone.utc)
    old=(now-dt.timedelta(days=120)).isoformat(); recent=(now-dt.timedelta(days=5)).isoformat()
    with main.db() as c:
        old_closed=c.execute("INSERT INTO tickets(ticket_number,title,status,priority,created_by,created_at,updated_at,closed_at) VALUES('TKT-00001','old closed','closed','medium','admin',?,?,?)",(old,old,old)).lastrowid
        old_resolved=c.execute("INSERT INTO tickets(ticket_number,title,status,priority,created_by,created_at,updated_at,resolved_at) VALUES('TKT-00002','old resolved','resolved','medium','admin',?,?,?)",(old,old,old)).lastrowid
        old_open=c.execute("INSERT INTO tickets(ticket_number,title,status,priority,created_by,created_at,updated_at) VALUES('TKT-00003','old open','open','medium','admin',?,?)",(old,old)).lastrowid
        recent_closed=c.execute("INSERT INTO tickets(ticket_number,title,status,priority,created_by,created_at,updated_at,closed_at) VALUES('TKT-00004','recent closed','closed','medium','admin',?,?,?)",(recent,recent,recent)).lastrowid
    r=main.ticket_delete_old(main.TicketDeleteOldRequest(older_than_days=90),_req(),_admin())
    assert r['deleted']==2
    with main.db() as c:
        left={x['id'] for x in c.execute('SELECT id FROM tickets').fetchall()}
    assert old_closed not in left and old_resolved not in left
    assert old_open in left and recent_closed in left


def test_ticket_cleanup_audit_action_names_present():
    src=Path('app/main.py').read_text()
    assert 'ticket_deleted' in src
    assert 'tickets_bulk_deleted' in src
    assert 'old_tickets_deleted' in src


def test_ticket_cleanup_screenshot_packaged():
    assert Path('docs/screenshots/dark-ticket-portal.png').exists()
    assert Path('docs/screenshots/godseye-dark-mode-overview.png').exists()
