import sqlite3
from pathlib import Path
from app.remediation import ensure_schema, record_device_diagnostic, monitor_result_findings, suggested_fix, scanner_event_findings
from app.intelligence import ensure_schema as ensure_intelligence


def make_db(tmp_path: Path):
    c=sqlite3.connect(tmp_path/'r.sqlite'); c.row_factory=sqlite3.Row
    c.executescript("""
    CREATE TABLE devices(id INTEGER PRIMARY KEY,mac TEXT UNIQUE,ip TEXT,hostname TEXT,vendor TEXT,name TEXT,device_type TEXT,status TEXT,first_seen TEXT,last_seen TEXT,trusted INTEGER DEFAULT 0,notes TEXT DEFAULT '',offline_escalated_at TEXT,classification TEXT DEFAULT 'new',missed_scans INTEGER DEFAULT 0);
    CREATE TABLE events(id INTEGER PRIMARY KEY,mac TEXT,event_type TEXT,ip TEXT,created_at TEXT,details TEXT DEFAULT '',severity TEXT DEFAULT 'info');
    CREATE TABLE integration_checks(id INTEGER PRIMARY KEY,kind TEXT,target TEXT,status TEXT,latency_ms REAL,details TEXT,last_checked TEXT,monitor_id INTEGER);
    """)
    ensure_intelligence(c); ensure_schema(c); return c

def test_repeated_packet_loss_creates_finding(tmp_path):
    c=make_db(tmp_path); ts='2026-09-09T12:00:00+00:00'; c.execute("INSERT INTO devices(id,mac,ip,hostname,status,first_seen,last_seen) VALUES(1,'aa:bb:cc:dd:ee:ff','192.168.1.20','dev.local','online',?,?)",(ts,ts)); d=c.execute('SELECT * FROM devices WHERE id=1').fetchone()
    record_device_diagnostic(c,d,{'ok':True,'packet_loss_percent':25},{'ok':True}); record_device_diagnostic(c,d,{'ok':True,'packet_loss_percent':20},{'ok':True})
    assert c.execute("SELECT 1 FROM network_issues WHERE issue_type='packet_loss' AND status='open'").fetchone()

def test_repeated_dns_failure_creates_finding(tmp_path):
    c=make_db(tmp_path); ts='2026-09-09T12:00:00+00:00'; c.execute("INSERT INTO devices(id,mac,ip,hostname,status,first_seen,last_seen) VALUES(1,'aa:bb:cc:dd:ee:ff','192.168.1.20','bad.local','online',?,?)",(ts,ts)); d=c.execute('SELECT * FROM devices WHERE id=1').fetchone()
    record_device_diagnostic(c,d,{'ok':True,'packet_loss_percent':0},{'ok':False}); record_device_diagnostic(c,d,{'ok':True,'packet_loss_percent':0},{'ok':False})
    assert c.execute("SELECT 1 FROM network_issues WHERE issue_type='dns_problem' AND status='open'").fetchone()

def test_monitor_failure_and_recovery(tmp_path):
    c=make_db(tmp_path); setting={'id':7,'name':'Camera API','kind':'website','target':'192.168.1.30'}
    for n in range(2):
        c.execute("INSERT INTO integration_checks(kind,target,status,latency_ms,details,last_checked,monitor_id) VALUES(?,?,?,?,?,?,?)",('website',setting['target'],'down',10,'{}',f'2026-09-09T12:00:0{n}+00:00',7)); monitor_result_findings(c,setting,{'ok':False},'down',10)
    assert c.execute("SELECT 1 FROM network_issues WHERE issue_type='service_failure' AND status='open'").fetchone()
    c.execute("INSERT INTO integration_checks(kind,target,status,latency_ms,details,last_checked,monitor_id) VALUES(?,?,?,?,?,?,?)",('website',setting['target'],'up',10,'{}','2026-09-09T12:01:00+00:00',7)); monitor_result_findings(c,setting,{'ok':True},'up',10)
    assert not c.execute("SELECT 1 FROM network_issues WHERE issue_type='service_failure' AND status='open'").fetchone()

def test_scanner_events_open_offline_and_ip_change(tmp_path):
    c=make_db(tmp_path); events=[{'mac':'aa:bb:cc:dd:ee:ff','ip':'192.168.1.20','event_type':'disconnected','details':'offline'},{'mac':'aa:bb:cc:dd:ee:ff','ip':'192.168.1.21','event_type':'ip_changed','details':'changed'}]; scanner_event_findings(c,events)
    assert c.execute("SELECT 1 FROM network_issues WHERE issue_type='offline_device'").fetchone(); assert c.execute("SELECT 1 FROM network_issues WHERE issue_type='ip_changed'").fetchone()

def test_suggested_fix_has_actions():
    r=suggested_fix({'id':1,'issue_type':'packet_loss','title':'Loss','evidence':'{}','recommendation':'Check path'}); assert r['actions'] and r['recommendation']=='Check path'
