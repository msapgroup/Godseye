import sqlite3
from pathlib import Path

from app.device_intelligence import build_device_intelligence
from app.intelligence import ensure_schema, correlate_device, open_issue


def test_device_intelligence_aggregates_evidence(tmp_path: Path):
    db = tmp_path / "intel.sqlite"
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE devices(
      id INTEGER PRIMARY KEY, mac TEXT UNIQUE, ip TEXT, hostname TEXT, vendor TEXT,
      name TEXT, device_type TEXT, status TEXT, first_seen TEXT, last_seen TEXT,
      trusted INTEGER DEFAULT 0, notes TEXT DEFAULT '', offline_escalated_at TEXT,
      classification TEXT DEFAULT 'new', missed_scans INTEGER DEFAULT 0
    );
    CREATE TABLE events(
      id INTEGER PRIMARY KEY, mac TEXT, event_type TEXT, ip TEXT, created_at TEXT,
      details TEXT DEFAULT '', severity TEXT DEFAULT 'info'
    );
    """)
    ensure_schema(c)
    ts = "2026-09-09T12:00:00+00:00"
    c.execute("""INSERT INTO devices(id,mac,ip,hostname,vendor,name,device_type,status,first_seen,last_seen,classification)
                 VALUES(1,'aa:bb:cc:dd:ee:ff','192.168.1.20','tv','Example','Living Room TV','TV','online',?,?, 'known')""", (ts, ts))
    c.execute("INSERT INTO events(mac,event_type,ip,created_at,details,severity) VALUES(?,?,?,?,?,?)",
              ('aa:bb:cc:dd:ee:ff','ip_changed','192.168.1.20',ts,'IP changed','info'))
    correlate_device(c, 'aa:bb:cc:dd:ee:ff', '192.168.1.20', 'tv', 'Example', source='arp-scan')
    open_issue(c, 'service_slow', 'warning', 'aa:bb:cc:dd:ee:ff', 'Service response slow', {'latency': 900}, 'Check the local link.')
    c.commit()

    report = build_device_intelligence(c, 1)
    assert report is not None
    assert report['device']['name'] == 'Living Room TV'
    assert report['summary']['source_count'] >= 1
    assert report['summary']['open_issue_count'] == 1
    assert report['events'][0]['event_type'] == 'ip_changed'
    assert report['recommendations']
    c.close()
