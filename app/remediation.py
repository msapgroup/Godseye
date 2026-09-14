"""GODSEYE findings/remediation engine.

Findings are evidence-based. Suggested Fix is advisory; Recheck performs only
read-only diagnostics/monitor checks; Resolve records operator acknowledgement.
"""
from __future__ import annotations
import datetime as dt, json

def now(): return dt.datetime.now(dt.timezone.utc).isoformat()

def ensure_schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS diagnostic_runs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, mac TEXT, ip TEXT,
      ping_ok INTEGER, packet_loss REAL, dns_ok INTEGER, details TEXT DEFAULT '{}',
      created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_diag_device_created ON diagnostic_runs(device_id,created_at DESC);
    """)

def _loads(v, default=None):
    try: return json.loads(v) if isinstance(v,str) else (v if v is not None else default)
    except Exception: return default

def resolve_device(c,target):
    if not target: return None
    return c.execute("SELECT * FROM devices WHERE lower(mac)=lower(?) OR ip=? ORDER BY id LIMIT 1",(target,target)).fetchone()

def open_or_update_issue(c,issue_type,severity,target,title,evidence,recommendation):
    from .intelligence import ensure_schema as ensure_intel
    ensure_intel(c); ensure_schema(c); ts=now(); target=target or 'unknown'
    row=c.execute("SELECT id FROM network_issues WHERE issue_type=? AND target=? AND status='open' ORDER BY id DESC LIMIT 1",(issue_type,target)).fetchone()
    payload=json.dumps(evidence or {},separators=(',',':'))[:10000]
    if row:
        c.execute("UPDATE network_issues SET severity=?,title=?,evidence=?,recommendation=?,last_seen=? WHERE id=?",(severity,title,payload,recommendation,ts,row['id']))
        return row['id']
    cur=c.execute("INSERT INTO network_issues(issue_type,severity,target,title,evidence,recommendation,status,first_seen,last_seen) VALUES(?,?,?,?,?,?,'open',?,?)",(issue_type,severity,target,title,payload,recommendation,ts,ts))
    return cur.lastrowid

def resolve_matching(c,issue_type,target):
    ts=now(); cur=c.execute("UPDATE network_issues SET status='resolved',resolved_at=?,last_seen=? WHERE issue_type=? AND target=? AND status='open'",(ts,ts,issue_type,target))
    return cur.rowcount

def scanner_event_findings(c,events):
    out=[]
    for event in events or []:
        e=dict(event); kind=e.get('event_type'); mac=(e.get('mac') or '').lower(); ip=e.get('ip')
        if kind=='disconnected' and mac:
            out.append(open_or_update_issue(c,'offline_device','high',mac,'Device is offline',{'event':e},'Run Recheck. If still unreachable, verify power, Ethernet/Wi-Fi association, switch/AP status, DHCP lease, and firewall policy.'))
        elif kind=='connected' and mac:
            resolve_matching(c,'offline_device',mac)
        elif kind=='ip_changed' and mac:
            out.append(open_or_update_issue(c,'ip_changed','low',mac,'Device IP address changed',{'current_ip':ip,'event':e},'Confirm the new address is expected. Use a DHCP reservation when a stable address is required.'))
    return out

def record_device_diagnostic(c,device,ping_result,dns_result=None):
    ensure_schema(c); d=dict(device); did=d.get('id'); mac=(d.get('mac') or '').lower(); ip=d.get('ip'); target=mac or ip
    loss=ping_result.get('packet_loss_percent'); ping_ok=1 if ping_result.get('ok') else 0; dns_ok=None if dns_result is None else (1 if dns_result.get('ok') else 0)
    c.execute("INSERT INTO diagnostic_runs(device_id,mac,ip,ping_ok,packet_loss,dns_ok,details,created_at) VALUES(?,?,?,?,?,?,?,?)",(did,mac,ip,ping_ok,loss,dns_ok,json.dumps({'ping':ping_result,'dns':dns_result})[:10000],now()))
    recent=[dict(r) for r in c.execute("SELECT * FROM diagnostic_runs WHERE device_id=? ORDER BY id DESC LIMIT 3",(did,)).fetchall()]
    if len(recent)>=2 and all(r['ping_ok']==0 for r in recent[:2]):
        open_or_update_issue(c,'offline_device','high',target,'Repeated reachability failure',{'checks':recent[:2]},'The device failed two consecutive reachability checks. Verify power, link, DHCP state, AP/switch health, and firewall policy, then use Recheck.')
    elif ping_ok: resolve_matching(c,'offline_device',target)
    if len(recent)>=2:
        losses=[r['packet_loss'] for r in recent[:2]]
        if all(v is not None and v>=10 for v in losses):
            open_or_update_issue(c,'packet_loss','medium',target,'Repeated packet loss detected',{'loss_percent':losses},'Check Wi-Fi signal/interference, Ethernet cabling, switch/AP errors, and congestion. Recheck after correcting the path.')
        elif loss is not None and loss<10: resolve_matching(c,'packet_loss',target)
        if dns_result is not None and all(r['dns_ok']==0 for r in recent[:2]):
            open_or_update_issue(c,'dns_problem','medium',target,'Repeated DNS resolution failure',{'hostname':d.get('hostname'),'checks':recent[:2]},'Verify hostname, DHCP DNS/search-domain settings, and the local resolver/Pi-hole. Recheck after correcting DNS.')
        elif dns_ok==1: resolve_matching(c,'dns_problem',target)

def monitor_result_findings(c,setting,result,status,latency_ms):
    sid=setting.get('id'); target=setting.get('target') or '(auto)'; name=setting.get('name') or setting.get('kind')
    dev=resolve_device(c,target); issue_target=(dev['mac'].lower() if dev else f'monitor:{sid}')
    rows=[dict(r) for r in c.execute("SELECT * FROM integration_checks WHERE monitor_id=? ORDER BY id DESC LIMIT 2",(sid,)).fetchall()]
    if len(rows)>=2 and all(r['status']=='down' for r in rows[:2]):
        return open_or_update_issue(c,'service_failure','high',issue_target,f'{name} monitor is failing',{'monitor_id':sid,'name':name,'kind':setting.get('kind'),'target':target,'checks':rows[:2],'latest':result},'Run Recheck. Verify target reachability, service availability, credentials, and TLS/API settings.')
    if status=='up': resolve_matching(c,'service_failure',issue_target)
    return None

def suggested_fix(issue):
    i=dict(issue); typ=i.get('issue_type'); evidence=_loads(i.get('evidence'),{}) or {}
    actions={
      'offline_device':['Run Recheck to confirm current reachability.','Verify power and Ethernet/Wi-Fi link.','Confirm DHCP/address state.','Check switch/AP and firewall policy.'],
      'packet_loss':['Run Recheck after a short interval.','Check Wi-Fi RSSI/interference or Ethernet cabling.','Inspect switch/AP errors and congestion.','Compare gateway loss to isolate the affected segment.'],
      'dns_problem':['Verify the recorded hostname.','Test the configured DNS resolver/Pi-hole.','Check DHCP DNS/search-domain settings.','Recheck after resolver changes.'],
      'service_failure':['Run the monitor again.','Confirm host/port reachability.','Verify credentials/API token.','Check TLS settings and service logs.'],
      'ip_changed':['Confirm the new IP belongs to the expected device.','Create a DHCP reservation if stability is required.','Resolve if the change was expected.'],
      'public_ip_change':['Confirm the WAN change with the router/ISP.','Update DNS/allowlists if necessary.','Resolve if expected.']
    }.get(typ,['Review the evidence.','Run Recheck.','Correct the underlying issue, then resolve the finding.'])
    return {'issue_id':i.get('id'),'type':typ,'title':i.get('title'),'recommendation':i.get('recommendation') or '','evidence':evidence,'actions':actions}
