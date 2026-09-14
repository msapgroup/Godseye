from pathlib import Path
from types import SimpleNamespace
import datetime as dt
import app.main as main
from app import event_ticketing


def _request():
    return SimpleNamespace(client=SimpleNamespace(host='127.0.0.1'))


def _admin():
    return {'username':'admin','role':'admin'}


def _seed(db_path, monkeypatch, status='open', days_old=0):
    monkeypatch.setattr(main,'DB_PATH',db_path)
    main.init_db()
    event={'computer_name':'GMRS','channel':'System','provider':'Microsoft-Windows-Time-Service','event_id':134,'level':'Warning','record_id':1,'message':'time warning'}
    with main.db() as c:
        fid,_=event_ticketing.ingest_event(c,None,event,main.now())
        if status=='resolved':
            ts=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days_old)).isoformat()
            c.execute("UPDATE event_findings SET status='resolved',resolved_at=?,last_seen=? WHERE id=?",(ts,ts,fid))
    return fid


def test_version_v419():
    assert Path('VERSION').read_text().strip().startswith(('4.19.0-','4.20.0-', '4.21.0-', '4.22.0-', '4.22.1-'))


def test_single_event_finding_delete(tmp_path,monkeypatch):
    fid=_seed(tmp_path/'single.db',monkeypatch)
    monkeypatch.setattr(main,'audit',lambda *a,**k: None)
    result=main.event_finding_delete(fid,_request(),_admin())
    assert result['deleted']==1
    with main.db() as c:
        assert c.execute('SELECT * FROM event_findings WHERE id=?',(fid,)).fetchone() is None


def test_delete_preserves_linked_ticket_history(tmp_path,monkeypatch):
    fid=_seed(tmp_path/'ticket.db',monkeypatch)
    monkeypatch.setattr(main,'audit',lambda *a,**k: None)
    ticket=main.event_finding_create_ticket(fid,_request(),_admin())
    main.event_finding_delete(fid,_request(),_admin())
    with main.db() as c:
        row=c.execute('SELECT * FROM tickets WHERE id=?',(ticket['id'],)).fetchone()
    assert row is not None
    assert row['linked_type']=='event_finding_deleted'
    assert row['linked_id']==fid


def test_bulk_event_finding_delete(tmp_path,monkeypatch):
    db=tmp_path/'bulk.db'
    fid1=_seed(db,monkeypatch)
    event={'computer_name':'GMRS','channel':'System','provider':'Win32k','event_id':263,'level':'Warning','record_id':2,'message':'warning'}
    with main.db() as c:
        fid2,_=event_ticketing.ingest_event(c,None,event,main.now())
    monkeypatch.setattr(main,'audit',lambda *a,**k: None)
    req=main.EventFindingBulkDeleteRequest(finding_ids=[fid1,fid2,fid2])
    result=main.event_findings_bulk_delete(req,_request(),_admin())
    assert result['deleted']==2
    with main.db() as c:
        assert c.execute('SELECT COUNT(*) n FROM event_findings').fetchone()['n']==0


def test_old_cleanup_only_deletes_resolved_old_findings(tmp_path,monkeypatch):
    db=tmp_path/'old.db'
    old_id=_seed(db,monkeypatch,status='resolved',days_old=40)
    event={'computer_name':'GMRS2','channel':'System','provider':'Win32k','event_id':263,'level':'Warning','record_id':2,'message':'warning'}
    with main.db() as c:
        open_id,_=event_ticketing.ingest_event(c,None,event,main.now())
    monkeypatch.setattr(main,'audit',lambda *a,**k: None)
    result=main.event_findings_delete_old(main.EventFindingOldDeleteRequest(older_than_days=30),_request(),_admin())
    assert result['deleted']==1
    with main.db() as c:
        assert c.execute('SELECT * FROM event_findings WHERE id=?',(old_id,)).fetchone() is None
        assert c.execute('SELECT * FROM event_findings WHERE id=?',(open_id,)).fetchone() is not None


def test_event_findings_delete_ui_controls_present():
    html=main.DASHBOARD
    for token in ('Delete Selected','Delete Old Findings','eventFindingSelectAll','eventFindingSearch','deleteEventFinding','deleteSelectedEventFindings'):
        assert token in html
    assert 'delete-link admin-only' in html


def test_event_finding_delete_api_admin_only_declared():
    source=Path('app/main.py').read_text()
    assert '@app.delete(f"{router_prefix}/event-findings/{{finding_id}}")' in source
    assert '@app.post(f"{router_prefix}/event-findings/bulk-delete")' in source
    assert '@app.post(f"{router_prefix}/event-findings/delete-old")' in source
    assert 'Depends(require_admin)' in source
