"""Persistent native monitoring collectors for GODSEYE.

Collectors are intentionally lightweight and Docker-free. Credentials remain in
options/environment and are never written to integration_checks.
"""
from __future__ import annotations
import json, threading, time, os, urllib.request, re
from .integrations import website_check, pihole_test, snmp_test, unifi_login
from .intelligence import ensure_schema, ingest_dhcp, correlate_public_ip


def dhcp_leases(path=None):
    """Read common dnsmasq lease files without requiring a DHCP daemon."""
    paths=[path] if path else [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
    ]
    for candidate in paths:
        if not candidate or not os.path.exists(candidate):
            continue
        leases=[]
        try:
            for line in open(candidate, encoding="utf-8", errors="replace"):
                parts=line.split()
                if len(parts)>=4:
                    leases.append({"expires":parts[0],"mac":parts[1].lower(),
                                   "ip":parts[2],"hostname":parts[3]})
            return {"ok":True,"path":candidate,"leases":leases}
        except Exception as exc:
            return {"ok":False,"error":str(exc)}
    return {"ok":False,"error":"No dnsmasq lease file found"}

def public_ip(timeout=5):
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=timeout) as r:
            data=json.loads(r.read().decode())
        return {"ok":True,"ip":data.get("ip")}
    except Exception as exc:
        return {"ok":False,"error":str(exc)}

class CollectorManager:
    def __init__(self, db_factory, now_fn):
        self.db_factory=db_factory
        self.now=now_fn
        self.stop_event=threading.Event()
        self.thread=None

    def _settings(self):
        with self.db_factory() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM integration_settings WHERE enabled=1 ORDER BY id"
            ).fetchall()]

    def _run(self, setting):
        kind,target=setting["kind"],setting["target"]
        opts=json.loads(setting.get("options_json") or "{}")
        started=time.monotonic()
        try:
            if kind=="website":
                result=website_check(target)
            elif kind=="dhcp":
                result=dhcp_leases(target or None)
            elif kind=="public_ip":
                result=public_ip()
            elif kind=="pihole":
                result=pihole_test(target)
            elif kind=="snmp":
                result=snmp_test(target, opts.get("community"))
            elif kind=="unifi":
                result=unifi_login(target, opts.get("username",""), opts.get("password",""),
                                   bool(opts.get("verify_tls", True)))
            else:
                result={"ok":False,"error":"Unsupported monitor"}
        except Exception as exc:
            result={"ok":False,"error":str(exc)}
        latency=(time.monotonic()-started)*1000
        status="up" if result.get("ok") else "down"
        with self.db_factory() as c:
            ensure_schema(c)
            c.execute(
                "INSERT INTO integration_checks(kind,target,status,latency_ms,details,last_checked) VALUES(?,?,?,?,?,?)",
                (kind,target,status,round(latency,1),json.dumps(result)[:10000],self.now())
            )
            # Feed integration observations into the shared device intelligence layer.
            if kind == "dhcp" and result.get("ok"):
                ingest_dhcp(c, result.get("leases", []))
            elif kind == "public_ip" and result.get("ok"):
                correlate_public_ip(c, result.get("ip"))
            c.execute("""DELETE FROM integration_checks WHERE id NOT IN
                         (SELECT id FROM integration_checks ORDER BY last_checked DESC LIMIT 500)""")
        return {"name":setting["name"],"kind":kind,"target":target,"status":status,
                "latency_ms":round(latency,1),"details":result}

    def run_all(self):
        return {"results":[self._run(s) for s in self._settings()]}

    def _loop(self):
        while not self.stop_event.wait(30):
            now=time.time()
            for setting in self._settings():
                # Use last successful/check timestamp for a simple bounded scheduler.
                with self.db_factory() as c:
                    row=c.execute(
                        "SELECT last_checked FROM integration_checks WHERE kind=? AND target=? ORDER BY id DESC LIMIT 1",
                        (setting["kind"],setting["target"])).fetchone()
                due=True
                if row:
                    try:
                        import datetime as dt
                        last=dt.datetime.fromisoformat(row["last_checked"]).timestamp()
                        due=(now-last)>=setting["interval_seconds"]
                    except Exception:
                        due=True
                if due:
                    self._run(setting)

    def start(self):
        self.thread=threading.Thread(target=self._loop,name="godseye-collectors",daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
