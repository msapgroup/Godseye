"""SQLite persistence for GODSEYE network intelligence."""
from __future__ import annotations
import sqlite3, json, time
SCHEMA = """
CREATE TABLE IF NOT EXISTS intelligence_devices (
 device_id TEXT PRIMARY KEY, mac TEXT, ip TEXT, hostname TEXT, vendor TEXT,
 device_type TEXT, sources_json TEXT NOT NULL DEFAULT '[]', ips_json TEXT NOT NULL DEFAULT '[]',
 hostnames_json TEXT NOT NULL DEFAULT '[]', first_seen REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS intelligence_observations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL, source TEXT NOT NULL,
 observed_at REAL NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS intelligence_findings (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, kind TEXT NOT NULL, severity TEXT NOT NULL,
 title TEXT NOT NULL, recommendation TEXT, evidence_json TEXT NOT NULL DEFAULT '{}',
 status TEXT NOT NULL DEFAULT 'open', created_at REAL NOT NULL, resolved_at REAL);
CREATE TABLE IF NOT EXISTS topology_links (
 id INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL, target_id TEXT NOT NULL,
 relation TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', first_seen REAL NOT NULL,
 last_seen REAL NOT NULL, UNIQUE(source_id,target_id,relation));
"""
class IntelligenceStore:
    def __init__(self,path): self.path=str(path); self._init()
    def _connect(self):
        c=sqlite3.connect(self.path); c.row_factory=sqlite3.Row; return c
    def _init(self):
        with self._connect() as c: c.executescript(SCHEMA)
    def upsert_device(self,d):
        now=time.time()
        with self._connect() as c:
            row=c.execute("SELECT first_seen FROM intelligence_devices WHERE device_id=?",(d["id"],)).fetchone()
            first=row["first_seen"] if row else now
            c.execute("""INSERT INTO intelligence_devices
            (device_id,mac,ip,hostname,vendor,device_type,sources_json,ips_json,hostnames_json,first_seen,last_seen)
            VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET
            mac=excluded.mac,ip=excluded.ip,hostname=excluded.hostname,vendor=excluded.vendor,
            device_type=excluded.device_type,sources_json=excluded.sources_json,ips_json=excluded.ips_json,
            hostnames_json=excluded.hostnames_json,last_seen=excluded.last_seen""",
            (d["id"],d.get("mac"),d.get("ip"),d.get("hostname"),d.get("vendor"),d.get("device_type"),
             json.dumps(d.get("sources",[])),json.dumps(d.get("ips",[])),json.dumps(d.get("hostnames",[])),first,now))
    def add_observation(self,device_id,source,payload):
        with self._connect() as c:
            c.execute("INSERT INTO intelligence_observations(device_id,source,observed_at,payload_json) VALUES(?,?,?,?)",(device_id,source,time.time(),json.dumps(payload)))
    def add_finding(self,device_id,f):
        with self._connect() as c:
            c.execute("""INSERT INTO intelligence_findings(device_id,kind,severity,title,recommendation,evidence_json,created_at)
                         VALUES(?,?,?,?,?,?,?)""",(device_id,f.get("type","unknown"),f.get("severity","info"),f.get("title","Finding"),f.get("recommendation",""),json.dumps(f.get("evidence",{})),time.time()))
    def findings(self,status="open"):
        with self._connect() as c: return [dict(r) for r in c.execute("SELECT * FROM intelligence_findings WHERE status=? ORDER BY created_at DESC",(status,))]
    def resolve_finding(self,finding_id):
        with self._connect() as c: c.execute("UPDATE intelligence_findings SET status='resolved',resolved_at=? WHERE id=?",(time.time(),finding_id))
    def upsert_link(self,source_id,target_id,relation,evidence=None):
        now=time.time()
        with self._connect() as c:
            c.execute("""INSERT INTO topology_links(source_id,target_id,relation,evidence_json,first_seen,last_seen)
            VALUES(?,?,?,?,?,?) ON CONFLICT(source_id,target_id,relation) DO UPDATE SET evidence_json=excluded.evidence_json,last_seen=excluded.last_seen""",(source_id,target_id,relation,json.dumps(evidence or {}),now,now))
    def topology(self):
        with self._connect() as c: return [dict(r) for r in c.execute("SELECT * FROM topology_links ORDER BY last_seen DESC")]
    def devices(self):
        with self._connect() as c: return [dict(r) for r in c.execute("SELECT * FROM intelligence_devices ORDER BY last_seen DESC")]
