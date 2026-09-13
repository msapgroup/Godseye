"""GODSEYE device intelligence: correlate discovery/integration data into one inventory."""
from __future__ import annotations
import datetime as dt, json, re, subprocess, shutil

VENDOR_PREFIXES = {
    "b827eb":"Raspberry Pi Foundation","dc:a6:32":"Raspberry Pi","e4:5f:01":"Raspberry Pi",
    "f0:9f:c2":"Ubiquiti","44:d9:e7":"Ubiquiti","b4:fb:e4":"Ubiquiti",
    "3c:5a:b4":"Amazon","a4:77:33":"Amazon","ac:bc:32":"Apple",
    "f0:18:98":"Apple","d8:96:95":"Google","3c:5a:b4":"Amazon",
    "00:1c:42":"Parallels","00:50:56":"VMware","08:00:27":"VirtualBox",
}

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def ensure_schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS device_sources(
      id INTEGER PRIMARY KEY, mac TEXT NOT NULL, source TEXT NOT NULL,
      ip TEXT, hostname TEXT, vendor TEXT, details TEXT DEFAULT '',
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
      UNIQUE(mac,source)
    );
    CREATE TABLE IF NOT EXISTS device_ip_history(
      id INTEGER PRIMARY KEY, mac TEXT NOT NULL, ip TEXT NOT NULL,
      source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
      UNIQUE(mac,ip,source)
    );
    CREATE TABLE IF NOT EXISTS topology_links(
      id INTEGER PRIMARY KEY, parent TEXT NOT NULL, child TEXT NOT NULL,
      link_type TEXT NOT NULL, details TEXT DEFAULT '', last_seen TEXT NOT NULL,
      UNIQUE(parent,child,link_type)
    );
    CREATE TABLE IF NOT EXISTS network_issues(
      id INTEGER PRIMARY KEY, issue_type TEXT NOT NULL, severity TEXT NOT NULL,
      target TEXT, title TEXT NOT NULL, evidence TEXT DEFAULT '{}',
      recommendation TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'open',
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_sources_mac ON device_sources(mac);
    CREATE INDEX IF NOT EXISTS idx_ip_history_mac ON device_ip_history(mac);
    CREATE INDEX IF NOT EXISTS idx_issues_status ON network_issues(status,last_seen);
    """)

def vendor_for_mac(mac):
    key = mac.lower().replace("-",":")
    prefix = key[:8]
    return VENDOR_PREFIXES.get(prefix) or VENDOR_PREFIXES.get(prefix.replace(":",""))

def record_source(c, source, mac, ip=None, hostname=None, vendor=None, details=None):
    if not mac: return
    mac=mac.lower()
    ts=now()
    ensure_schema(c)
    c.execute("""INSERT INTO device_sources(mac,source,ip,hostname,vendor,details,first_seen,last_seen)
      VALUES(?,?,?,?,?,?,?,?)
      ON CONFLICT(mac,source) DO UPDATE SET ip=excluded.ip,hostname=excluded.hostname,
      vendor=COALESCE(excluded.vendor,device_sources.vendor),details=excluded.details,last_seen=excluded.last_seen""",
      (mac,source,ip,hostname,vendor,json.dumps(details or {})[:4000],ts,ts))
    if ip:
        c.execute("""INSERT INTO device_ip_history(mac,ip,source,first_seen,last_seen) VALUES(?,?,?,?,?)
          ON CONFLICT(mac,ip,source) DO UPDATE SET last_seen=excluded.last_seen""",
          (mac,ip,source,ts,ts))

def correlate_device(c, mac, ip=None, hostname=None, vendor=None, source="unknown", details=None):
    if not mac: return
    mac=mac.lower()
    record_source(c,source,mac,ip,hostname,vendor,details)
    row=c.execute("SELECT * FROM devices WHERE mac=?",(mac,)).fetchone()
    ts=now()
    detected_vendor=vendor or vendor_for_mac(mac)
    if row:
        updates=[]; vals=[]
        for col,val in [("ip",ip),("hostname",hostname),("vendor",detected_vendor)]:
            if val and not row[col]:
                updates.append(f"{col}=?"); vals.append(val)
        if updates:
            vals.append(mac); c.execute(f"UPDATE devices SET {','.join(updates)} WHERE mac=?",vals)
    else:
        # Source records can precede ARP discovery; create a useful inventory row.
        c.execute("""INSERT OR IGNORE INTO devices
          (mac,ip,hostname,vendor,status,first_seen,last_seen,classification,missed_scans)
          VALUES(?,?,?,?,?,?,?,?,?)""",
          (mac,ip,hostname,detected_vendor,"online",ts,ts,"new",0))
        c.execute("INSERT INTO events(mac,event_type,ip,created_at,details,severity) VALUES(?,?,?,?,?,?)",
                  (mac,"device_discovered",ip,ts,f"source={source}","info"))

def ingest_dhcp(c, leases):
    count=0
    for lease in leases or []:
        mac=lease.get("mac"); ip=lease.get("ip"); host=lease.get("hostname")
        if not mac: continue
        correlate_device(c,mac,ip,host,source="dhcp",details=lease)
        count+=1
    return count

def ingest_nmap(c, hosts):
    count=0
    for host in hosts or []:
        mac=host.get("mac")
        if not mac: continue
        correlate_device(c,mac,host.get("ip"),host.get("hostname"),source="nmap",details=host)
        count+=1
    return count

def ingest_neighbors(c, neighbors):
    count=0
    for n in neighbors or []:
        mac=n.get("lladdr") or n.get("mac")
        ip=n.get("dst") or n.get("ip")
        if not mac or not ip: continue
        correlate_device(c,mac,ip,source="neighbor",details=n)
        count+=1
    return count

def open_issue(c, issue_type, severity, target, title, evidence, recommendation):
    ts=now()
    existing=c.execute("""SELECT id FROM network_issues WHERE issue_type=? AND target=? AND status='open'
                          ORDER BY id DESC LIMIT 1""",(issue_type,target)).fetchone()
    if existing:
        c.execute("""UPDATE network_issues SET evidence=?,recommendation=?,last_seen=? WHERE id=?""",
                  (json.dumps(evidence)[:10000],recommendation,ts,existing["id"]))
        return existing["id"]
    cur=c.execute("""INSERT INTO network_issues(issue_type,severity,target,title,evidence,recommendation,first_seen,last_seen)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (issue_type,severity,target,title,json.dumps(evidence)[:10000],recommendation,ts,ts))
    return cur.lastrowid

def correlate_public_ip(c, current_ip):
    if not current_ip: return None
    ensure_schema(c)
    row=c.execute("""SELECT target FROM network_issues WHERE issue_type='public_ip_change'
                     ORDER BY id DESC LIMIT 1""").fetchone()
    # Store latest observation as a source record keyed to a synthetic identity.
    record_source(c,"public_ip","public",current_ip,details={"ip":current_ip})
    if row and row["target"] != current_ip:
        return open_issue(c,"public_ip_change","warning",current_ip,"Public IP changed",
                          {"previous":row["target"],"current":current_ip},
                          "Verify whether the WAN address change was expected.")
    return None
