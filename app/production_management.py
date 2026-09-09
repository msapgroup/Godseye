from __future__ import annotations
import datetime as dt, hashlib, json, os, re, shutil, sqlite3, subprocess, threading, time, urllib.request, urllib.parse
from pathlib import Path

VERSION='1.6.0-production-management'
DATA_DIR=Path(os.environ.get('GODSEYE_DATA_DIR','/var/lib/godseye'))
UPDATE_DIR=DATA_DIR/'updates'; CONFIG_DIR=DATA_DIR/'config-exports'

def utcnow(): return dt.datetime.now(dt.timezone.utc).isoformat()

def ensure_schema(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS production_settings(
      id INTEGER PRIMARY KEY CHECK(id=1), auto_backup_enabled INTEGER NOT NULL DEFAULT 1,
      backup_cadence TEXT NOT NULL DEFAULT 'daily', backup_hour_utc INTEGER NOT NULL DEFAULT 3,
      backup_keep_count INTEGER NOT NULL DEFAULT 14, https_mode TEXT NOT NULL DEFAULT 'off',
      https_hostname TEXT NOT NULL DEFAULT '', update_channel TEXT NOT NULL DEFAULT 'stable', updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS update_runs(
      id INTEGER PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL, version TEXT,
      status TEXT NOT NULL, preflight_json TEXT NOT NULL DEFAULT '{}', started_at TEXT,
      completed_at TEXT, actor TEXT, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS config_transfers(
      id INTEGER PRIMARY KEY, direction TEXT NOT NULL, actor TEXT, status TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS remediation_actions(
      id INTEGER PRIMARY KEY, action_type TEXT NOT NULL, target TEXT NOT NULL, requested_by TEXT NOT NULL,
      confirmation TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, completed_at TEXT);
    ''')
    c.execute("INSERT OR IGNORE INTO production_settings(id,updated_at) VALUES(1,?)",(utcnow(),))
    # Extend delivery rows so retries can reproduce the original notification.
    cols={r['name'] for r in c.execute('PRAGMA table_info(notification_deliveries)').fetchall()}
    for name,ddl in [('title','title TEXT NOT NULL DEFAULT \'\''),('body','body TEXT NOT NULL DEFAULT \'\''),('attempts','attempts INTEGER NOT NULL DEFAULT 1'),('last_attempt_at','last_attempt_at TEXT')]:
        if name not in cols: c.execute(f'ALTER TABLE notification_deliveries ADD COLUMN {ddl}')
    c.commit()

def settings(c): ensure_schema(c); return dict(c.execute('SELECT * FROM production_settings WHERE id=1').fetchone())

def save_settings(c, values):
    ensure_schema(c); allowed={'auto_backup_enabled','backup_cadence','backup_hour_utc','backup_keep_count','https_mode','https_hostname','update_channel'}
    clean={k:v for k,v in values.items() if k in allowed}
    if clean:
        c.execute('UPDATE production_settings SET '+','.join(f'{k}=?' for k in clean)+',updated_at=? WHERE id=1',(*clean.values(),utcnow())); c.commit()
    return settings(c)

def config_export(c):
    ensure_schema(c)
    def rows(sql): return [dict(r) for r in c.execute(sql).fetchall()]
    integrations=[]
    for r in rows('SELECT kind,enabled,target,username,verify_tls,sync_interval_seconds,options_json FROM integration_configs ORDER BY kind'):
        try:r['options']=json.loads(r.pop('options_json') or '{}')
        except:r['options']={}
        integrations.append(r)
    notif=dict(c.execute('SELECT webhook_enabled,webhook_url,ntfy_enabled,ntfy_server,ntfy_topic,smtp_enabled,smtp_host,smtp_port,smtp_user,smtp_from,smtp_to,min_severity FROM notification_configs WHERE id=1').fetchone())
    retention=dict(c.execute('SELECT traffic_retention_days,event_retention_days,audit_retention_days,report_retention_days,sync_retention_days,notification_retention_days FROM appliance_settings WHERE id=1').fetchone())
    return {'schema_version':1,'exported_at':utcnow(),'secrets_included':False,'integrations':integrations,'monitoring':rows('SELECT name,kind,target,enabled,interval_seconds,options_json FROM integration_settings ORDER BY id'),'rules':rows('SELECT name,rule_type,enabled,params,severity FROM rules ORDER BY id'),'report_schedules':rows('SELECT name,report_type,enabled,cadence,hour_utc,weekday,notify FROM report_schedules ORDER BY id'),'notifications':notif,'retention':retention,'production':settings(c)}

def config_import(c, payload):
    ensure_schema(c)
    if int(payload.get('schema_version',0))!=1: raise ValueError('Unsupported configuration schema version')
    # non-secret, additive/upsert import
    for r in payload.get('integrations',[]):
        if r.get('kind') not in {'pihole','unifi','snmp'}: continue
        ts=utcnow(); c.execute('''INSERT INTO integration_configs(kind,enabled,target,username,secret,verify_tls,sync_interval_seconds,options_json,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(kind) DO UPDATE SET enabled=excluded.enabled,target=excluded.target,username=excluded.username,verify_tls=excluded.verify_tls,sync_interval_seconds=excluded.sync_interval_seconds,options_json=excluded.options_json,updated_at=excluded.updated_at''',(r['kind'],int(bool(r.get('enabled'))),r.get('target',''),r.get('username',''),'',int(bool(r.get('verify_tls',True))),max(30,int(r.get('sync_interval_seconds',300))),json.dumps(r.get('options',{})),ts,ts))
    for r in payload.get('monitoring',[]):
        name=(r.get('name') or 'Imported monitor').strip(); kind=r.get('kind','website')
        opts=r.get('options_json','{}') if isinstance(r.get('options_json','{}'),str) else json.dumps(r.get('options_json') or {})
        c.execute('''INSERT INTO integration_settings(name,kind,target,enabled,interval_seconds,options_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)
          ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,target=excluded.target,enabled=excluded.enabled,interval_seconds=excluded.interval_seconds,options_json=excluded.options_json,updated_at=excluded.updated_at''',(name,kind,r.get('target',''),int(bool(r.get('enabled',1))),max(30,int(r.get('interval_seconds',300))),opts,utcnow(),utcnow()))
    for r in payload.get('rules',[]):
        c.execute('INSERT OR IGNORE INTO rules(name,rule_type,enabled,params,severity,created_at) VALUES(?,?,?,?,?,?)',(r.get('name','Imported rule'),r.get('rule_type','new_device_burst'),int(bool(r.get('enabled',1))),r.get('params','{}'),r.get('severity','critical'),utcnow()))
    for r in payload.get('report_schedules',[]):
        c.execute('''INSERT INTO report_schedules(name,report_type,enabled,cadence,hour_utc,weekday,notify,next_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(name) DO UPDATE SET report_type=excluded.report_type,enabled=excluded.enabled,cadence=excluded.cadence,hour_utc=excluded.hour_utc,weekday=excluded.weekday,notify=excluded.notify,updated_at=excluded.updated_at''',(r.get('name','Imported report'),r.get('report_type','network_summary'),int(bool(r.get('enabled',1))),r.get('cadence','daily'),int(r.get('hour_utc',12)),int(r.get('weekday',0)),int(bool(r.get('notify',1))),None,utcnow(),utcnow()))
    n=payload.get('notifications') or {}
    if n:
        fields=['webhook_enabled','webhook_url','ntfy_enabled','ntfy_server','ntfy_topic','smtp_enabled','smtp_host','smtp_port','smtp_user','smtp_from','smtp_to','min_severity']
        vals=[n.get(k) for k in fields]
        c.execute('UPDATE notification_configs SET '+','.join(f'{k}=?' for k in fields)+',updated_at=? WHERE id=1',(*vals,utcnow()))
    ret=payload.get('retention') or {}
    if ret:
        fields=['traffic_retention_days','event_retention_days','audit_retention_days','report_retention_days','sync_retention_days','notification_retention_days']
        vals=[max(1,min(3650,int(ret.get(k,90)))) for k in fields]
        c.execute('UPDATE appliance_settings SET '+','.join(f'{k}=?' for k in fields)+',updated_at=? WHERE id=1',(*vals,utcnow()))
    prod=payload.get('production') or {}; save_settings(c,prod)
    c.commit(); return {'ok':True,'note':'Secrets are intentionally not imported; re-enter integration and SMTP credentials.'}

def audit_query(c, *, actor='', action='', target='', start='', end='', limit=200):
    sql='SELECT * FROM audit_log WHERE 1=1'; args=[]
    for col,val,op in [('actor',actor,'='),('action',action,'LIKE'),('target',target,'LIKE')]:
        if val: sql+=f' AND {col} {op} ?'; args.append(val if op=='=' else f'%{val}%')
    if start: sql+=' AND created_at>=?'; args.append(start)
    if end: sql+=' AND created_at<=?'; args.append(end)
    sql+=' ORDER BY id DESC LIMIT ?'; args.append(max(1,min(int(limit),2000)))
    return [dict(r) for r in c.execute(sql,args).fetchall()]

def audit_csv(rows):
    import csv,io
    s=io.StringIO(); w=csv.DictWriter(s,fieldnames=['id','created_at','actor','action','target','details','ip']);w.writeheader();w.writerows(rows);return s.getvalue().encode()

def preflight_update(path: Path):
    import zipfile
    result={'ok':False,'filename':path.name,'size_bytes':path.stat().st_size,'required':{},'version':''}
    if path.suffix.lower()!='.zip': result['error']='Update package must be a ZIP'; return result
    try:
        with zipfile.ZipFile(path) as z:
            names=set(z.namelist()); roots={n.split('/')[0] for n in names if '/' in n}
            def has(s): return s in names or any(n.endswith('/'+s) for n in names)
            for req in ['app/main.py','install.sh','requirements.txt','VERSION']: result['required'][req]=has(req)
            if not all(result['required'].values()): result['error']='Package is missing required GODSEYE files'; return result
            v=[n for n in names if n=='VERSION' or n.endswith('/VERSION')][0]; result['version']=z.read(v).decode('utf-8','replace').strip()[:100]
            bad=z.testzip();
            if bad: result['error']='ZIP integrity failure'; return result
        result['ok']=True; return result
    except Exception as e: result['error']=str(e); return result

def stage_update_bytes(data: bytes, filename: str):
    UPDATE_DIR.mkdir(parents=True,exist_ok=True); safe=re.sub(r'[^A-Za-z0-9._-]','_',Path(filename).name)
    if not safe.endswith('.zip'): raise ValueError('Update filename must end in .zip')
    if len(data)>100*1024*1024: raise ValueError('Update package exceeds 100 MB limit')
    p=UPDATE_DIR/safe; p.write_bytes(data); os.chmod(p,0o640)
    return p,hashlib.sha256(data).hexdigest(),preflight_update(p)

def apply_staged_update(c, filename, expected_sha256, actor):
    ensure_schema(c); p=(UPDATE_DIR/Path(filename).name)
    if not p.exists(): raise FileNotFoundError('Staged update not found')
    actual=hashlib.sha256(p.read_bytes()).hexdigest()
    if not expected_sha256 or actual.lower()!=expected_sha256.lower(): raise ValueError('SHA-256 confirmation does not match staged package')
    pf=preflight_update(p)
    if not pf.get('ok'): raise ValueError(pf.get('error','Update preflight failed'))
    cur=c.execute('INSERT INTO update_runs(filename,sha256,version,status,preflight_json,started_at,actor,created_at) VALUES(?,?,?,?,?,?,?,?)',(p.name,actual,pf.get('version'),'ready',json.dumps(pf),utcnow(),actor,utcnow())); c.commit()
    # Actual privileged replacement is intentionally delegated to a fixed root helper.
    helper='/usr/local/sbin/godseye-apply-update'
    if not os.path.exists(helper):
        c.execute('UPDATE update_runs SET status=?,details=?,completed_at=? WHERE id=?',('staged','Privileged update helper is not installed; package remains staged.',utcnow(),cur.lastrowid)); c.commit()
        return {'ok':True,'status':'staged','restart_required':False,'message':'Preflight passed; privileged helper not installed.'}
    cp=subprocess.run(['sudo',helper,str(p),actual],capture_output=True,text=True,timeout=180)
    status='applied' if cp.returncode==0 else 'failed'; details=(cp.stdout+'\n'+cp.stderr)[-8000:]
    c.execute('UPDATE update_runs SET status=?,details=?,completed_at=? WHERE id=?',(status,details,utcnow(),cur.lastrowid));c.commit()
    return {'ok':cp.returncode==0,'status':status,'restart_required':cp.returncode==0,'details':details}

class ProductionManager:
    def __init__(self, db_factory, backup_func): self.db_factory=db_factory; self.backup_func=backup_func; self.stop_event=threading.Event(); self.thread=None
    def start(self):
        if self.thread and self.thread.is_alive(): return
        self.thread=threading.Thread(target=self._loop,name='godseye-production-manager',daemon=True);self.thread.start()
    def stop(self): self.stop_event.set(); self.thread and self.thread.join(timeout=3)
    def _loop(self):
        last_day=''
        while not self.stop_event.wait(60):
            try:
                with self.db_factory() as c: cfg=settings(c)
                now=dt.datetime.now(dt.timezone.utc)
                if cfg['auto_backup_enabled'] and cfg['backup_cadence']=='daily' and now.hour==int(cfg['backup_hour_utc']) and now.date().isoformat()!=last_day:
                    self.backup_func('scheduled'); last_day=now.date().isoformat(); self._trim(int(cfg['backup_keep_count']))
            except Exception as e: print('[GODSEYE] production manager:',e)
    def _trim(self, keep):
        bdir=DATA_DIR/'backups'
        files=sorted(bdir.glob('godseye-*.db'),key=lambda p:p.stat().st_mtime,reverse=True)
        for p in files[max(1,keep):]:
            try:
                key=p.with_suffix(p.suffix+'.key'); p.unlink(); key.exists() and key.unlink()
            except Exception: pass

def https_status():
    cert=DATA_DIR/'tls'/'godseye.crt'; key=DATA_DIR/'tls'/'godseye.key'
    return {'configured':cert.exists() and key.exists(),'certificate':str(cert),'key':str(key),'helper':'sudo godseye-https-setup <hostname> [self-signed|letsencrypt]'}
