import sqlite3
from pathlib import Path

import app.appliance_hardening as ah


def db(tmp_path):
    p=tmp_path/'g.db'; c=sqlite3.connect(p); c.row_factory=sqlite3.Row
    c.executescript('''
    CREATE TABLE events(id INTEGER PRIMARY KEY,created_at TEXT,mac TEXT,ip TEXT,event_type TEXT,details TEXT);
    CREATE TABLE audit_log(id INTEGER PRIMARY KEY,created_at TEXT);
    CREATE TABLE generated_reports(id INTEGER PRIMARY KEY,generated_at TEXT);
    CREATE TABLE integration_sync_runs(id INTEGER PRIMARY KEY,started_at TEXT);
    CREATE TABLE analytics_snapshots(id INTEGER PRIMARY KEY,captured_at TEXT);
    CREATE TABLE notification_deliveries(id INTEGER PRIMARY KEY,created_at TEXT);
    CREATE TABLE devices(id INTEGER PRIMARY KEY,mac TEXT,ip TEXT,name TEXT,hostname TEXT,last_seen TEXT);
    ''')
    ah.ensure_schema(c); c.commit(); return p,c


def test_secret_encryption_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(ah,'KEY_PATH',tmp_path/'secret.key')
    encrypted=ah.encrypt_secret('super-secret')
    assert encrypted.startswith('enc:v1:')
    assert 'super-secret' not in encrypted
    assert ah.decrypt_secret(encrypted)=='super-secret'
    assert (tmp_path/'secret.key').stat().st_mode & 0o777 == 0o600


def test_prometheus_key_is_hashed(tmp_path):
    p,c=db(tmp_path)
    key=ah.generate_prometheus_key(c)
    row=c.execute('SELECT prometheus_key_hash FROM appliance_settings WHERE id=1').fetchone()
    assert key not in row['prometheus_key_hash']
    assert ah.verify_prometheus_key(c,key)
    assert not ah.verify_prometheus_key(c,key+'x')


def test_retention_prunes_old_rows(tmp_path):
    p,c=db(tmp_path)
    c.execute("INSERT INTO traffic_samples(captured_at,interface,rx_bytes,tx_bytes,rx_bps,tx_bps) VALUES('2000-01-01T00:00:00+00:00','eth0',1,1,0,0)")
    c.execute("INSERT INTO events(created_at) VALUES('2000-01-01T00:00:00+00:00')"); c.commit()
    deleted=ah.apply_retention(c)
    assert deleted['traffic_samples']==1
    assert deleted['events']==1


def test_backup_restore_and_exports(tmp_path, monkeypatch):
    p,c=db(tmp_path); c.execute("CREATE TABLE marker(value TEXT)"); c.execute("INSERT INTO marker VALUES('before')"); c.commit(); c.close()
    monkeypatch.setattr(ah,'BACKUP_DIR',tmp_path/'backups')
    backup=ah.create_backup(p)
    c=sqlite3.connect(p); c.execute("UPDATE marker SET value='after'"); c.commit(); c.close()
    ah.restore_backup(p,backup.name)
    c=sqlite3.connect(p); assert c.execute('SELECT value FROM marker').fetchone()[0]=='before'; c.close()
    report={'title':'GODSEYE Test','generated_at':'2026-09-09T00:00:00+00:00','summary':{'devices':4,'online':3}}
    assert b'Metric,Value' in ah.report_csv_bytes(report)
    assert ah.report_pdf_bytes(report).startswith(b'%PDF')
