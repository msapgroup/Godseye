import sqlite3
from pathlib import Path

from app.integration_reporting import ensure_schema, build_network_report, generate_report, next_report_time, prometheus_metrics, safe_config


def make_db(tmp_path):
    p=tmp_path/'t.db'
    c=sqlite3.connect(p)
    c.row_factory=sqlite3.Row
    c.executescript('''
    CREATE TABLE devices(id INTEGER PRIMARY KEY,mac TEXT UNIQUE,ip TEXT,hostname TEXT,vendor TEXT,name TEXT,device_type TEXT,status TEXT,first_seen TEXT,last_seen TEXT,trusted INTEGER DEFAULT 0,notes TEXT DEFAULT '',offline_escalated_at TEXT,classification TEXT DEFAULT 'new',missed_scans INTEGER DEFAULT 0);
    CREATE TABLE network_issues(id INTEGER PRIMARY KEY,issue_type TEXT,severity TEXT,target TEXT,title TEXT,evidence TEXT,recommendation TEXT,status TEXT,first_seen TEXT,last_seen TEXT,resolved_at TEXT);
    CREATE TABLE integration_checks(id INTEGER PRIMARY KEY,kind TEXT,target TEXT,status TEXT,latency_ms REAL,details TEXT,last_checked TEXT,monitor_id INTEGER);
    CREATE TABLE integration_settings(id INTEGER PRIMARY KEY,name TEXT,kind TEXT,target TEXT,enabled INTEGER,interval_seconds INTEGER,options_json TEXT,created_at TEXT,updated_at TEXT);
    CREATE TABLE topology_links(id INTEGER PRIMARY KEY,parent TEXT,child TEXT,link_type TEXT,details TEXT,last_seen TEXT,UNIQUE(parent,child,link_type));
    CREATE TABLE device_sources(id INTEGER PRIMARY KEY,mac TEXT,source TEXT,ip TEXT,hostname TEXT,vendor TEXT,details TEXT,first_seen TEXT,last_seen TEXT,UNIQUE(mac,source));
    CREATE TABLE device_ip_history(id INTEGER PRIMARY KEY,mac TEXT,ip TEXT,source TEXT,first_seen TEXT,last_seen TEXT,UNIQUE(mac,ip,source));
    ''')
    ensure_schema(c)
    return c


def test_schema_masks_secrets(tmp_path):
    c=make_db(tmp_path)
    c.execute("INSERT INTO integration_configs(kind,enabled,target,username,secret,verify_tls,sync_interval_seconds,options_json,created_at,updated_at) VALUES('unifi',1,'https://gw','admin','secret',1,300,'{}','x','x')")
    row=c.execute("SELECT * FROM integration_configs WHERE kind='unifi'").fetchone()
    cfg=safe_config(row)
    assert cfg['has_secret'] is True
    assert 'secret' not in cfg


def test_report_and_prometheus(tmp_path):
    c=make_db(tmp_path)
    c.execute("INSERT INTO devices(mac,ip,status,first_seen,last_seen,classification) VALUES('aa:bb:cc:dd:ee:ff','192.168.1.2','online','x','x','known')")
    c.execute("INSERT INTO network_issues(issue_type,severity,target,title,evidence,recommendation,status,first_seen,last_seen) VALUES('offline','critical','x','Test','{}','Fix','open','x','x')")
    c.commit()
    summary,body=build_network_report(c)
    assert summary['devices']==1 and summary['online']==1 and summary['critical_findings']==1
    assert 'GODSEYE Network Summary' in body
    rep=generate_report(c)
    assert rep['summary']['devices']==1
    metrics=prometheus_metrics(c)
    assert 'godseye_devices_total 1' in metrics
    assert 'godseye_findings_open 1' in metrics


def test_next_report_time():
    import datetime as dt
    after=dt.datetime(2026,9,9,13,30,tzinfo=dt.timezone.utc)
    assert next_report_time('daily',12,0,after).startswith('2026-09-10T12:00:00')
    assert next_report_time('hourly',12,0,after).startswith('2026-09-09T14:00:00')
