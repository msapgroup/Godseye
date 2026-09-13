import io, json, sqlite3, zipfile
from pathlib import Path
import app.production_management as pm
import app.appliance_hardening as ah
import app.integration_reporting as ir

def make_db(tmp_path):
    p=tmp_path/'g.db'; c=sqlite3.connect(p); c.row_factory=sqlite3.Row
    c.executescript('''
    CREATE TABLE audit_log(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT,details TEXT DEFAULT '',ip TEXT,created_at TEXT NOT NULL);
    CREATE TABLE rules(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,rule_type TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,params TEXT NOT NULL DEFAULT '{}',severity TEXT NOT NULL DEFAULT 'critical',created_at TEXT NOT NULL,last_triggered_at TEXT);
    CREATE TABLE integration_settings(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,target TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1,interval_seconds INTEGER NOT NULL DEFAULT 300,options_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
    CREATE TABLE events(id INTEGER PRIMARY KEY,created_at TEXT,mac TEXT,ip TEXT,event_type TEXT,details TEXT);
    CREATE TABLE devices(id INTEGER PRIMARY KEY,mac TEXT,ip TEXT,name TEXT,hostname TEXT,last_seen TEXT,status TEXT);
    CREATE TABLE network_issues(id INTEGER PRIMARY KEY,status TEXT,severity TEXT);
    CREATE TABLE device_sources(id INTEGER PRIMARY KEY,source TEXT,mac TEXT,last_seen TEXT);
    ''')
    ir.ensure_schema(c); ah.ensure_schema(c); pm.ensure_schema(c); c.commit(); return p,c

def test_config_export_excludes_secrets(tmp_path):
    _,c=make_db(tmp_path)
    c.execute("INSERT INTO integration_configs(kind,enabled,target,username,secret,verify_tls,sync_interval_seconds,options_json,created_at,updated_at) VALUES('pihole',1,'http://pi','','secret-token',1,300,'{}','x','x')")
    c.commit(); d=pm.config_export(c)
    raw=json.dumps(d)
    assert d['secrets_included'] is False
    assert 'secret-token' not in raw
    assert d['integrations'][0]['target']=='http://pi'

def test_config_import_roundtrip_nonsecret(tmp_path):
    _,c=make_db(tmp_path)
    payload=pm.config_export(c)
    payload['rules']=[{'name':'Imported','rule_type':'new_device_burst','enabled':1,'params':'{}','severity':'warning'}]
    result=pm.config_import(c,payload)
    assert result['ok']
    assert c.execute("SELECT COUNT(*) FROM rules WHERE name='Imported'").fetchone()[0]==1

def test_audit_search_and_csv(tmp_path):
    _,c=make_db(tmp_path)
    c.execute("INSERT INTO audit_log(actor,action,target,details,ip,created_at) VALUES('admin','backup_created','x','ok','127.0.0.1','2026-09-09T00:00:00+00:00')");c.commit()
    rows=pm.audit_query(c,actor='admin',action='backup')
    assert len(rows)==1
    assert b'backup_created' in pm.audit_csv(rows)

def test_update_preflight(tmp_path,monkeypatch):
    monkeypatch.setattr(pm,'UPDATE_DIR',tmp_path/'updates')
    bio=io.BytesIO()
    with zipfile.ZipFile(bio,'w') as z:
        z.writestr('app/main.py','x=1')
        z.writestr('install.sh','#!/bin/sh')
        z.writestr('requirements.txt','')
        z.writestr('VERSION','9.9.9-test')
    p,sha,pf=pm.stage_update_bytes(bio.getvalue(),'release.zip')
    assert len(sha)==64 and p.exists()
    assert pf['ok'] and pf['version']=='9.9.9-test'

def test_production_settings(tmp_path):
    _,c=make_db(tmp_path)
    r=pm.save_settings(c,{'auto_backup_enabled':0,'backup_hour_utc':5,'backup_keep_count':7})
    assert r['auto_backup_enabled']==0 and r['backup_hour_utc']==5 and r['backup_keep_count']==7
