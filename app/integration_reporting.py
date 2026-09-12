from __future__ import annotations

import datetime as dt
import json
import smtplib
import ssl
import threading
import time
import urllib.request
from email.message import EmailMessage

from .appliance_hardening import decrypt_secret, apply_retention
from .integrations import pihole_auth, pihole_json

from .discovery_intelligence import (
    ingest_observations,
    pihole_client_observations,
    unifi_client_observations,
    snmp_neighbor_observations,
    build_live_topology,
)


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def ensure_schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS integration_configs (
        id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 0,
        target TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        secret TEXT NOT NULL DEFAULT '',
        verify_tls INTEGER NOT NULL DEFAULT 1,
        sync_interval_seconds INTEGER NOT NULL DEFAULT 300,
        options_json TEXT NOT NULL DEFAULT '{}',
        last_sync_at TEXT,
        last_sync_status TEXT NOT NULL DEFAULT 'never',
        last_sync_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS integration_sync_runs (
        id INTEGER PRIMARY KEY,
        integration_kind TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL,
        observations INTEGER NOT NULL DEFAULT 0,
        analytics_json TEXT NOT NULL DEFAULT '{}',
        error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_sync_runs_kind ON integration_sync_runs(integration_kind,id DESC);
    CREATE TABLE IF NOT EXISTS analytics_snapshots (
        id INTEGER PRIMARY KEY,
        source TEXT NOT NULL,
        captured_at TEXT NOT NULL,
        data_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_analytics_source ON analytics_snapshots(source,id DESC);
    CREATE TABLE IF NOT EXISTS report_schedules (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        report_type TEXT NOT NULL DEFAULT 'network_summary',
        enabled INTEGER NOT NULL DEFAULT 1,
        cadence TEXT NOT NULL DEFAULT 'daily',
        hour_utc INTEGER NOT NULL DEFAULT 12,
        weekday INTEGER NOT NULL DEFAULT 0,
        notify INTEGER NOT NULL DEFAULT 1,
        last_run_at TEXT,
        next_run_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS generated_reports (
        id INTEGER PRIMARY KEY,
        schedule_id INTEGER,
        report_type TEXT NOT NULL,
        title TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        body_text TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_reports_generated ON generated_reports(generated_at DESC);
    CREATE TABLE IF NOT EXISTS notification_configs (
        id INTEGER PRIMARY KEY CHECK(id=1),
        webhook_enabled INTEGER NOT NULL DEFAULT 0,
        webhook_url TEXT NOT NULL DEFAULT '',
        ntfy_enabled INTEGER NOT NULL DEFAULT 0,
        ntfy_server TEXT NOT NULL DEFAULT 'https://ntfy.sh',
        ntfy_topic TEXT NOT NULL DEFAULT '',
        smtp_enabled INTEGER NOT NULL DEFAULT 0,
        smtp_host TEXT NOT NULL DEFAULT '',
        smtp_port INTEGER NOT NULL DEFAULT 587,
        smtp_user TEXT NOT NULL DEFAULT '',
        smtp_password TEXT NOT NULL DEFAULT '',
        smtp_from TEXT NOT NULL DEFAULT '',
        smtp_to TEXT NOT NULL DEFAULT '',
        min_severity TEXT NOT NULL DEFAULT 'warning',
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notification_deliveries (
        id INTEGER PRIMARY KEY,
        dedupe_key TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        target TEXT,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );
    """)
    c.execute("""INSERT OR IGNORE INTO notification_configs(id,updated_at) VALUES(1,?)""", (utcnow(),))


def safe_config(row):
    if not row:
        return None
    d = dict(row)
    d['has_secret'] = bool(d.get('secret'))
    d['has_password'] = bool(d.get('secret'))
    d.pop('secret', None)
    return d


def _json_load(value, default=None):
    try:
        return json.loads(value or '{}')
    except Exception:
        return {} if default is None else default


def _http_json(url, headers=None, timeout=8):
    req = urllib.request.Request(url, headers=headers or {'User-Agent':'GODSEYE/1.4'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8','replace'))


def pihole_analytics(base_url, token=None, verify_tls=True):
    auth = pihole_auth(base_url, token, verify_tls=verify_tls) if token else None
    errors=[]
    candidates=['/api/stats/summary','/api/summary','/admin/api.php?summaryRaw']
    for path in candidates:
        try:
            data, used=pihole_json(base_url, path, token, verify_tls=verify_tls, session=auth)
            if isinstance(data, dict):
                queries = data.get('queries') or data.get('dns_queries_today') or data.get('total_queries')
                blocked = data.get('blocked') or data.get('ads_blocked_today') or data.get('blocked_queries')
                clients = data.get('clients') or data.get('unique_clients')
                # v6 summary payloads may nest counters under queries/clients objects.
                if isinstance(queries, dict):
                    queries = queries.get('total') or queries.get('queries') or queries.get('cached')
                if isinstance(blocked, dict):
                    blocked = blocked.get('total') or blocked.get('blocked')
                if isinstance(clients, dict):
                    clients = clients.get('active') or clients.get('total') or clients.get('clients')
                return {'ok':True,'queries':queries,'blocked':blocked,'clients':clients,'raw':data,'endpoint':path,'auth_mode':used.get('request_mode') or used.get('mode')}
        except Exception as exc:
            errors.append(f'{path}: {exc}')
    return {'ok':False,'error':'; '.join(errors)[-2000:]}


def sync_integration(c, kind: str):
    ensure_schema(c)
    row=c.execute("SELECT * FROM integration_configs WHERE kind=?",(kind,)).fetchone()
    if not row:
        raise KeyError(kind)
    cfg=dict(row); cfg['secret']=decrypt_secret(cfg.get('secret')); started=utcnow()
    run_id=c.execute("INSERT INTO integration_sync_runs(integration_kind,started_at,status) VALUES(?,?,'running')",(kind,started)).lastrowid
    c.commit()
    options=_json_load(cfg.get('options_json'))
    try:
        devices_before=c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        if kind=='pihole':
            result=pihole_client_observations(cfg['target'], cfg.get('secret') or None, verify_tls=bool(cfg.get('verify_tls')))
            observations=result.get('observations',[])
            count=ingest_observations(c,'pihole',observations)
            analytics=pihole_analytics(cfg['target'],cfg.get('secret') or None, verify_tls=bool(cfg.get('verify_tls')))
        elif kind=='unifi':
            result=unifi_client_observations(cfg['target'],cfg.get('username',''),cfg.get('secret',''),bool(cfg.get('verify_tls')),options.get('site','default'))
            observations=result.get('observations',[])
            count=ingest_observations(c,'unifi',observations)
            wifi=sum(1 for o in observations if o.get('access_point_id'))
            analytics={'ok':result.get('ok',False),'active_clients':len(observations),'wifi_clients':wifi,'site':options.get('site','default')}
        elif kind=='snmp':
            result=snmp_neighbor_observations(cfg['target'],cfg.get('secret') or 'public')
            observations=result.get('observations',[])
            count=ingest_observations(c,'snmp',observations)
            analytics={'ok':result.get('ok',False),'neighbors':len(observations),'host':cfg['target']}
        else:
            raise ValueError('Unsupported integration type')
        devices_after=c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        new_devices=max(0,devices_after-devices_before)
        analytics=dict(analytics or {})
        analytics['new_devices']=new_devices
        analytics['device_total_after_sync']=devices_after
        ok=bool(result.get('ok') or (kind=='pihole' and analytics.get('ok')))
        status='success' if ok else 'failed'
        err=(result.get('error') or analytics.get('error')) if not ok else None
        if kind=='pihole' and analytics.get('auth_mode'):
            analytics['authentication']=analytics.get('auth_mode')
        completed=utcnow()
        c.execute("UPDATE integration_configs SET last_sync_at=?,last_sync_status=?,last_sync_error=? WHERE id=?",(completed,status,err,cfg['id']))
        c.execute("UPDATE integration_sync_runs SET completed_at=?,status=?,observations=?,analytics_json=?,error=? WHERE id=?",(completed,status,count,json.dumps(analytics)[:20000],err,run_id))
        c.execute("INSERT INTO analytics_snapshots(source,captured_at,data_json) VALUES(?,?,?)",(kind,completed,json.dumps(analytics)[:50000]))
        c.commit()
        if ok and new_devices:
            send_notification(c,'topology_change','warning',f'GODSEYE Topology: {new_devices} new device(s)',f'{kind} synchronization added {new_devices} previously unknown device(s) to the topology.',kind,f'topology:{kind}:{run_id}')
        return {'ok':ok,'kind':kind,'observations':count,'new_devices':new_devices,'analytics':analytics,'error':err,'completed_at':completed}
    except Exception as exc:
        completed=utcnow(); err=str(exc)
        c.execute("UPDATE integration_configs SET last_sync_at=?,last_sync_status='failed',last_sync_error=? WHERE id=?",(completed,err,cfg['id']))
        c.execute("UPDATE integration_sync_runs SET completed_at=?,status='failed',error=? WHERE id=?",(completed,err,run_id)); c.commit()
        return {'ok':False,'kind':kind,'observations':0,'analytics':{},'error':err,'completed_at':completed}


def build_network_report(c):
    ensure_schema(c)
    devices=c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online=c.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]
    offline=c.execute("SELECT COUNT(*) FROM devices WHERE status='offline'").fetchone()[0]
    new=c.execute("SELECT COUNT(*) FROM devices WHERE classification='new'").fetchone()[0]
    open_issues=c.execute("SELECT COUNT(*) FROM network_issues WHERE status='open'").fetchone()[0]
    critical=c.execute("SELECT COUNT(*) FROM network_issues WHERE status='open' AND severity='critical'").fetchone()[0]
    checks=c.execute("SELECT COUNT(*) FROM integration_checks WHERE status='down'").fetchone()[0]
    topology=build_live_topology(c)
    syncs=[dict(r) for r in c.execute("SELECT kind,last_sync_at,last_sync_status,last_sync_error FROM integration_configs ORDER BY kind")]
    summary={'devices':devices,'online':online,'offline':offline,'new':new,'open_findings':open_issues,'critical_findings':critical,'monitors_down':checks,'topology_nodes':len(topology.get('nodes',[])),'topology_links':len(topology.get('links',[])),'integrations':syncs}
    body=(f"GODSEYE Network Summary\nGenerated: {utcnow()}\n\n"
          f"Devices: {devices} total, {online} online, {offline} offline, {new} new\n"
          f"Findings: {open_issues} open, {critical} critical\n"
          f"Monitor checks currently down: {checks}\n"
          f"Topology: {summary['topology_nodes']} nodes, {summary['topology_links']} links\n")
    return summary,body


def generate_report(c, report_type='network_summary', schedule_id=None, title=None):
    if report_type!='network_summary':
        raise ValueError('Unsupported report type')
    summary,body=build_network_report(c)
    generated=utcnow(); title=title or 'GODSEYE Network Summary'
    rid=c.execute("INSERT INTO generated_reports(schedule_id,report_type,title,generated_at,summary_json,body_text) VALUES(?,?,?,?,?,?)",(schedule_id,report_type,title,generated,json.dumps(summary),body)).lastrowid
    c.commit()
    return {'id':rid,'report_type':report_type,'title':title,'generated_at':generated,'summary':summary,'body_text':body}


def next_report_time(cadence, hour_utc=12, weekday=0, after=None):
    cur=after or dt.datetime.now(dt.timezone.utc)
    base=cur.replace(hour=max(0,min(23,int(hour_utc))),minute=0,second=0,microsecond=0)
    if cadence=='hourly':
        return (cur.replace(minute=0,second=0,microsecond=0)+dt.timedelta(hours=1)).isoformat()
    if cadence=='weekly':
        target=int(weekday)%7
        days=(target-base.weekday())%7
        cand=base+dt.timedelta(days=days)
        if cand<=cur: cand+=dt.timedelta(days=7)
        return cand.isoformat()
    cand=base
    if cand<=cur: cand+=dt.timedelta(days=1)
    return cand.isoformat()


SEVERITY={'info':0,'warning':1,'critical':2}

def _notify_config(c):
    ensure_schema(c)
    return dict(c.execute("SELECT * FROM notification_configs WHERE id=1").fetchone())


def send_notification(c, event_type, severity, title, body, target=None, dedupe_key=None, force=False):
    cfg=_notify_config(c)
    if (not force) and SEVERITY.get(severity,0) < SEVERITY.get(cfg.get('min_severity','warning'),1):
        return {'sent':0,'skipped':'below threshold'}
    if dedupe_key:
        if c.execute("SELECT 1 FROM notification_deliveries WHERE dedupe_key=?",(dedupe_key,)).fetchone():
            return {'sent':0,'skipped':'duplicate'}
    sent=0; errors=[]
    payload=json.dumps({'source':'GODSEYE','event_type':event_type,'severity':severity,'title':title,'body':body,'target':target,'created_at':utcnow()}).encode()
    if cfg.get('webhook_enabled') and cfg.get('webhook_url'):
        try:
            req=urllib.request.Request(cfg['webhook_url'],data=payload,headers={'Content-Type':'application/json','User-Agent':'GODSEYE/1.4'},method='POST')
            urllib.request.urlopen(req,timeout=8).read(256); sent+=1
        except Exception as exc: errors.append('webhook: '+str(exc))
    if cfg.get('ntfy_enabled') and cfg.get('ntfy_topic'):
        try:
            url=cfg.get('ntfy_server','https://ntfy.sh').rstrip('/')+'/'+cfg['ntfy_topic']
            req=urllib.request.Request(url,data=body.encode(),headers={'Title':title,'Priority':'urgent' if severity=='critical' else 'default'},method='POST')
            urllib.request.urlopen(req,timeout=8).read(256); sent+=1
        except Exception as exc: errors.append('ntfy: '+str(exc))
    if cfg.get('smtp_enabled') and cfg.get('smtp_host') and cfg.get('smtp_from') and cfg.get('smtp_to'):
        try:
            msg=EmailMessage(); msg['Subject']=title; msg['From']=cfg['smtp_from']; msg['To']=cfg['smtp_to']; msg.set_content(body)
            with smtplib.SMTP(cfg['smtp_host'],int(cfg.get('smtp_port') or 587),timeout=10) as s:
                s.starttls(context=ssl.create_default_context())
                if cfg.get('smtp_user'): s.login(cfg['smtp_user'],decrypt_secret(cfg.get('smtp_password','')))
                s.send_message(msg); sent+=1
        except Exception as exc: errors.append('smtp: '+str(exc))
    # Only commit the dedupe key after at least one channel succeeds. This
    # allows a temporarily broken or not-yet-configured channel to retry on
    # the next background pass instead of permanently suppressing the alert.
    if dedupe_key and sent:
        
        cols={r['name'] for r in c.execute('PRAGMA table_info(notification_deliveries)').fetchall()}
        if {'title','body','attempts','last_attempt_at'} <= cols:
            c.execute("INSERT OR IGNORE INTO notification_deliveries(dedupe_key,event_type,target,severity,status,details,created_at,title,body,attempts,last_attempt_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(dedupe_key,event_type,target,severity,'sent','; '.join(errors)[:4000],utcnow(),title,body,1,utcnow()))
        else:
            c.execute("INSERT OR IGNORE INTO notification_deliveries(dedupe_key,event_type,target,severity,status,details,created_at) VALUES(?,?,?,?,?,?,?)",(dedupe_key,event_type,target,severity,'sent','; '.join(errors)[:4000],utcnow()))
        c.commit()
    return {'sent':sent,'errors':errors}


def prometheus_metrics(c):
    ensure_schema(c)
    vals={
      'godseye_devices_total':c.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
      'godseye_devices_online':c.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0],
      'godseye_devices_offline':c.execute("SELECT COUNT(*) FROM devices WHERE status='offline'").fetchone()[0],
      'godseye_findings_open':c.execute("SELECT COUNT(*) FROM network_issues WHERE status='open'").fetchone()[0],
      'godseye_findings_critical':c.execute("SELECT COUNT(*) FROM network_issues WHERE status='open' AND severity='critical'").fetchone()[0],
      'godseye_monitors_total':c.execute("SELECT COUNT(*) FROM integration_settings").fetchone()[0],
      'godseye_integrations_enabled':c.execute("SELECT COUNT(*) FROM integration_configs WHERE enabled=1").fetchone()[0],
    }
    lines=['# HELP godseye_info GODSEYE appliance information','# TYPE godseye_info gauge','godseye_info{version="1.4.0"} 1']
    for k,v in vals.items():
        lines += [f'# TYPE {k} gauge',f'{k} {v}']
    for row in c.execute("SELECT kind,last_sync_status FROM integration_configs"):
        ok=1 if row['last_sync_status']=='success' else 0
        lines.append(f'godseye_integration_sync_ok{{integration="{row["kind"]}"}} {ok}')
    return '\n'.join(lines)+'\n'


class IntegrationReportingManager:
    def __init__(self, db_factory, poll_seconds=15):
        self.db_factory=db_factory; self.poll_seconds=poll_seconds; self._stop=threading.Event(); self._thread=None; self._last_retention=0
    def start(self):
        if self._thread and self._thread.is_alive(): return
        self._stop.clear(); self._thread=threading.Thread(target=self._loop,name='godseye-integrations',daemon=True); self._thread.start()
    def stop(self):
        self._stop.set()
        if self._thread: self._thread.join(timeout=3)
    def run_sync(self, kind):
        with self.db_factory() as c: return sync_integration(c,kind)
    def _loop(self):
        while not self._stop.wait(self.poll_seconds):
            try:
                with self.db_factory() as c:
                    ensure_schema(c); now_dt=dt.datetime.now(dt.timezone.utc)
                    rows=c.execute("SELECT * FROM integration_configs WHERE enabled=1").fetchall()
                    due=[]
                    for r in rows:
                        if not r['last_sync_at']: due.append(r['kind']); continue
                        try: last=dt.datetime.fromisoformat(r['last_sync_at'])
                        except Exception: due.append(r['kind']); continue
                        if (now_dt-last).total_seconds()>=max(30,int(r['sync_interval_seconds'])): due.append(r['kind'])
                for kind in due: self.run_sync(kind)
                with self.db_factory() as c:
                    ensure_schema(c)
                    due_reports=c.execute("SELECT * FROM report_schedules WHERE enabled=1 AND (next_run_at IS NULL OR next_run_at<=?)",(utcnow(),)).fetchall()
                    for r in due_reports:
                        rep=generate_report(c,r['report_type'],r['id'],r['name'])
                        if r['notify']:
                            send_notification(c,'scheduled_report','info',rep['title'],rep['body_text'],dedupe_key=f'report:{rep["id"]}',force=True)
                        nxt=next_report_time(r['cadence'],r['hour_utc'],r['weekday'])
                        c.execute("UPDATE report_schedules SET last_run_at=?,next_run_at=? WHERE id=?",(rep['generated_at'],nxt,r['id'])); c.commit()
                    issues=c.execute("SELECT * FROM network_issues WHERE status='open' ORDER BY id DESC LIMIT 100").fetchall()
                    for issue in issues:
                        send_notification(c,'finding',issue['severity'],f"GODSEYE Finding: {issue['title']}",issue['recommendation'] or issue['title'],issue['target'],f'finding:{issue["id"]}')
                    # Apply retention automatically at most once per hour.
                    if time.time()-self._last_retention >= 3600:
                        apply_retention(c); self._last_retention=time.time()
            except Exception as exc:
                print('[GODSEYE] integration/reporting background error:',exc)
