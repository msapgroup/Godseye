"""Safe, bounded defensive checks for the GODSEYE Cyber Tools console."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

TOOLS={"network_exposure","endpoint_posture","web_tls","malware_ioc","dns_email","linux_audit","threat_detection","evidence_capture"}
SCHEDULABLE_TOOLS=TOOLS-{"malware_ioc","evidence_capture"}
PROFILES={"quick","standard","deep"}
DOMAIN_RE=re.compile(r"(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

def utcnow(): return dt.datetime.now(dt.timezone.utc).isoformat()

def ensure_schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS cyber_tool_runs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,tool TEXT NOT NULL,target TEXT NOT NULL DEFAULT '',profile TEXT NOT NULL DEFAULT 'standard',
      status TEXT NOT NULL,summary TEXT NOT NULL DEFAULT '',result_json TEXT NOT NULL DEFAULT '{}',requested_by TEXT NOT NULL,
      scheduled_id INTEGER,finding_id INTEGER,ticket_id INTEGER,started_at TEXT NOT NULL,completed_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_cyber_runs_time ON cyber_tool_runs(completed_at DESC,id DESC);
    CREATE TABLE IF NOT EXISTS cyber_tool_schedules(
      id INTEGER PRIMARY KEY AUTOINCREMENT,tool TEXT NOT NULL,target TEXT NOT NULL DEFAULT '',profile TEXT NOT NULL DEFAULT 'standard',
      options_json TEXT NOT NULL DEFAULT '{}',interval_minutes INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,updated_at TEXT NOT NULL,last_run_at TEXT,next_run_at TEXT NOT NULL,last_status TEXT NOT NULL DEFAULT 'never',last_error TEXT NOT NULL DEFAULT '');
    CREATE INDEX IF NOT EXISTS idx_cyber_schedules_due ON cyber_tool_schedules(enabled,next_run_at);
    """)

def _run(cmd,timeout=30):
    started=time.monotonic()
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,check=False)
        return p.returncode,(p.stdout or "")[-12000:],(p.stderr or "")[-12000:],round((time.monotonic()-started)*1000,1)
    except subprocess.TimeoutExpired as exc:
        return 124,str(exc.stdout or "")[-12000:],"Command timed out",round((time.monotonic()-started)*1000,1)
    except Exception as exc:
        return 1,"",str(exc),round((time.monotonic()-started)*1000,1)

def capabilities(data_dir):
    eve=Path(os.environ.get("GODSEYE_SURICATA_EVE","/var/log/suricata/eve.json"))
    helper=Path("/usr/local/sbin/godseye-evidence-capture")
    engines=[name for name,binary in (("ClamAV","clamscan"),("YARA","yara")) if shutil.which(binary)]
    try: interfaces=sorted(n for _,n in socket.if_nameindex())
    except OSError: interfaces=[]
    return {
      "network_exposure":{"available":bool(shutil.which("nmap")),"engine":"Nmap"},
      "endpoint_posture":{"available":True,"engine":"GODSEYE Agent"},
      "web_tls":{"available":True,"engine":"TLS/HTTP"},
      "malware_ioc":{"available":bool(engines),"engine":" + ".join(engines) or "Install ClamAV/YARA"},
      "dns_email":{"available":bool(shutil.which("dig")),"engine":"BIND dig"},
      "linux_audit":{"available":bool(shutil.which("lynis")),"engine":"Lynis"},
      "threat_detection":{"available":eve.is_file(),"engine":"Suricata EVE","source":str(eve)},
      "evidence_capture":{"available":bool(shutil.which("tcpdump")) and (os.geteuid()==0 or helper.is_file()),"engine":"tcpdump","interfaces":interfaces},
    }

def _private_target(value,allow_network=False):
    value=(value or "").strip()
    if not value or len(value)>253: raise ValueError("A private host or network is required")
    if "/" in value:
        if not allow_network: raise ValueError("This check requires one host")
        try: net=ipaddress.ip_network(value,strict=False)
        except ValueError as exc: raise ValueError("Target is not a valid network") from exc
        if not(net.is_private or net.is_link_local): raise ValueError("Only private/link-local targets are allowed")
        if net.num_addresses>256: raise ValueError("Network scans are limited to 256 addresses")
        return str(net)
    try: ip=ipaddress.ip_address(value)
    except ValueError:
        try: ip=ipaddress.ip_address(socket.gethostbyname(value))
        except Exception as exc: raise ValueError(f"Unable to resolve target: {exc}") from exc
    if not(ip.is_private or ip.is_link_local): raise ValueError("Only private/link-local targets are allowed")
    return str(ip)

def _nmap_hosts(raw):
    try: root=ET.fromstring(raw)
    except ET.ParseError: return []
    out=[]
    for node in root.findall("host"):
        state=node.find("status");addresses={a.get("addrtype","address"):a.get("addr","") for a in node.findall("address")};ports=[]
        for p in node.findall("./ports/port"):
            s=p.find("state");svc=p.find("service")
            ports.append({"port":int(p.get("portid","0")),"protocol":p.get("protocol","tcp"),"state":s.get("state","unknown") if s is not None else "unknown","service":svc.get("name","") if svc is not None else "","product":svc.get("product","") if svc is not None else "","version":svc.get("version","") if svc is not None else ""})
        out.append({"status":state.get("state","unknown") if state is not None else "unknown","addresses":addresses,"ports":ports})
    return out

def network_exposure(target,profile):
    binary=shutil.which("nmap")
    if not binary:return{"ok":False,"error":"Nmap is not installed"}
    target=_private_target(target,True);is_net="/" in target
    if profile=="quick" or is_net: args=[binary,"-sn","-n","-T3","-oX","-",target];timeout=45
    elif profile=="deep": args=[binary,"-Pn","-n","-sT","-sV","--version-light","--top-ports","100","--open","-T3","-oX","-",target];timeout=90
    else: args=[binary,"-Pn","-n","-sT","--open","-T3","-p","22,25,53,80,110,135,139,143,443,445,587,993,995,1433,3306,3389,5432,8080,8443","-oX","-",target];timeout=60
    code,out,err,elapsed=_run(args,timeout);hosts=_nmap_hosts(out)
    return{"ok":code==0,"target":target,"profile":profile,"hosts":hosts,"host_count":len(hosts),"open_port_count":sum(p["state"]=="open" for h in hosts for p in h["ports"]),"elapsed_ms":elapsed,"error":err if code else ""}

def endpoint_posture(c):
    now=dt.datetime.now(dt.timezone.utc);agents=[]
    for row in c.execute("SELECT * FROM windows_agents WHERE enabled=1 AND revoked_at IS NULL ORDER BY computer_name,id"):
        online=False
        try:
            hb=dt.datetime.fromisoformat(row["last_heartbeat_at"] or "");hb=hb if hb.tzinfo else hb.replace(tzinfo=dt.timezone.utc)
            online=(now-hb).total_seconds()<=max(180,int(row["poll_interval_seconds"] or 60)*3)
        except ValueError: pass
        checks={}
        for kind in ("scan_windows_updates","clamav_scan"):
            cmd=c.execute("SELECT status,completed_at,result_json FROM windows_agent_commands WHERE agent_id=? AND command_type=? ORDER BY id DESC LIMIT 1",(row["id"],kind)).fetchone()
            if cmd:
                try: result=json.loads(cmd["result_json"] or "{}")
                except json.JSONDecodeError: result={}
                checks[kind]={"status":cmd["status"],"completed_at":cmd["completed_at"],"result":result}
        agents.append({"id":row["id"],"computer_name":row["computer_name"],"ip_address":row["ip_address"],"os_version":row["os_version"],"agent_version":row["agent_version"],"online":online,"last_heartbeat_at":row["last_heartbeat_at"],"last_error":row["last_error"],"checks":checks})
    return{"ok":True,"agents":agents,"agent_count":len(agents),"online_count":sum(a["online"] for a in agents),"offline_count":sum(not a["online"] for a in agents)}

def web_tls(target):
    value=(target or "").strip()
    if "://" not in value:value="https://"+value
    u=urllib.parse.urlparse(value)
    if u.scheme not in{"http","https"} or not u.hostname or u.username or u.password: raise ValueError("Enter an HTTP or HTTPS URL without embedded credentials")
    started=time.monotonic();req=urllib.request.Request(u.geturl(),method="HEAD",headers={"User-Agent":"GODSEYE-Defensive-Audit/1.0"})
    try:
        with urllib.request.urlopen(req,timeout=10) as resp: status=resp.status;final=resp.url;headers={k.lower():v for k,v in resp.headers.items()}
    except urllib.error.HTTPError as exc: status=exc.code;final=exc.url;headers={k.lower():v for k,v in exc.headers.items()}
    except Exception as exc:return{"ok":False,"target":value,"error":str(exc),"elapsed_ms":round((time.monotonic()-started)*1000,1)}
    wanted={"strict-transport-security":"HSTS","content-security-policy":"Content-Security-Policy","x-content-type-options":"X-Content-Type-Options","x-frame-options":"X-Frame-Options","referrer-policy":"Referrer-Policy","permissions-policy":"Permissions-Policy"}
    security={label:headers.get(key,"") for key,label in wanted.items()};tls=None;tls_error=""
    if u.scheme=="https":
        try:
            with socket.create_connection((u.hostname,u.port or 443),timeout=8) as raw:
                with ssl.create_default_context().wrap_socket(raw,server_hostname=u.hostname) as s:
                    cert=s.getpeercert();tls={"version":s.version(),"cipher":s.cipher()[0],"expires":cert.get("notAfter","")}
        except Exception as exc:tls_error=str(exc)
    return{"ok":True,"target":value,"final_url":final,"status_code":status,"tls":tls,"tls_error":tls_error,"security_headers":security,"missing_headers":[k for k,v in security.items() if not v],"elapsed_ms":round((time.monotonic()-started)*1000,1)}

def _dig(name,kind):
    binary=shutil.which("dig")
    if not binary:raise ValueError("BIND dig is not installed")
    code,out,_,_=_run([binary,"+time=3","+tries=1","+short",name,kind],8)
    return[l.strip().strip('"') for l in out.splitlines() if l.strip()] if code==0 else[]

def dns_email(target,options):
    domain=(target or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):raise ValueError("Enter a valid domain name")
    selector=str((options or {}).get("selector") or "default")[:63];records={k:_dig(domain,k) for k in("A","AAAA","MX","TXT","CAA")}
    spf=[x for x in records["TXT"] if x.lower().startswith("v=spf1")];dmarc=[x for x in _dig("_dmarc."+domain,"TXT") if x.lower().startswith("v=dmarc1")];dkim=[x for x in _dig(f"{selector}._domainkey.{domain}","TXT") if "p=" in x.lower()]
    checks={"has_mx":bool(records["MX"]),"spf":bool(spf),"dmarc":bool(dmarc),"dkim_selector":bool(dkim),"dnssec_dnskey":bool(_dig(domain,"DNSKEY"))}
    return{"ok":True,"domain":domain,"selector":selector,"records":records,"spf":spf,"dmarc":dmarc,"dkim":dkim,"checks":checks,"passed":sum(checks.values()),"total":len(checks)}

def malware_ioc(target,options,data_dir):
    options=options or {};indicator=(target or "").strip();file64=str(options.get("file_base64") or "");result={"ok":True,"indicator":indicator,"indicator_type":"unknown"}
    if re.fullmatch(r"[A-Fa-f0-9]{64}",indicator):result["indicator_type"]="sha256"
    elif re.fullmatch(r"[A-Fa-f0-9]{32}",indicator):result["indicator_type"]="md5"
    else:
        try:ipaddress.ip_address(indicator);result["indicator_type"]="ip"
        except ValueError:
            if DOMAIN_RE.fullmatch(indicator):
                result["indicator_type"]="domain"
                try:result["resolved_addresses"]=sorted({x[4][0] for x in socket.getaddrinfo(indicator,None)})
                except Exception as exc:result["resolution_error"]=str(exc)
    if not file64:result["message"]="Indicator classified locally. Attach a file for ClamAV and YARA scanning.";return result
    try:payload=base64.b64decode(file64,validate=True)
    except Exception as exc:raise ValueError("Attached file is not valid base64") from exc
    if not payload or len(payload)>10*1024*1024:raise ValueError("Attached file must be between 1 byte and 10 MB")
    root=Path(data_dir)/"cyber-scan-temp";root.mkdir(parents=True,exist_ok=True);filename=Path(str(options.get("filename") or "sample.bin")).name[:180]
    with tempfile.TemporaryDirectory(prefix="scan-",dir=root) as temp:
        path=Path(temp)/filename;path.write_bytes(payload);result.update({"filename":filename,"size_bytes":len(payload),"sha256":hashlib.sha256(payload).hexdigest(),"md5":hashlib.md5(payload,usedforsecurity=False).hexdigest()})
        clam=shutil.which("clamscan")
        if clam:
            code,out,err,elapsed=_run([clam,"--no-summary","--infected",str(path)],120);result["clamav"]={"available":True,"clean":code==0,"threat_found":code==1,"output":out or err,"elapsed_ms":elapsed}
        else:result["clamav"]={"available":False,"error":"ClamAV is not installed"}
        yara=shutil.which("yara");rules=Path(os.environ.get("GODSEYE_YARA_RULES",str(Path(__file__).parent/"yara_rules"/"godseye-baseline.yar")))
        if yara and rules.exists():
            code,out,err,elapsed=_run([yara,"-r",str(rules),str(path)],60);matches=[x.split()[0] for x in out.splitlines() if x.strip()];result["yara"]={"available":True,"clean":code==0 and not matches,"matches":matches,"output":out or err,"elapsed_ms":elapsed}
        else:result["yara"]={"available":False,"error":"YARA or rules are not installed"}
    result["ok"]=not result.get("clamav",{}).get("threat_found") and not result.get("yara",{}).get("matches");return result

def linux_audit():
    binary=shutil.which("lynis")
    if not binary:return{"ok":False,"error":"Lynis is not installed"}
    code,out,err,elapsed=_run([binary,"audit","system","--quick","--no-colors","--quiet"],180);text=out+"\n"+err;warnings=[l.strip(" -[]") for l in text.splitlines() if "warning" in l.lower()][:50];suggestions=[l.strip(" -[]") for l in text.splitlines() if "suggestion" in l.lower()][:100];m=re.search(r"Hardening index\s*:\s*(\d+)",text,re.I)
    return{"ok":code in{0,1},"hardening_index":int(m.group(1)) if m else None,"warnings":warnings,"suggestions":suggestions,"warning_count":len(warnings),"suggestion_count":len(suggestions),"elapsed_ms":elapsed,"error":err if code not in{0,1}else""}

def threat_detection(profile):
    path=Path(os.environ.get("GODSEYE_SURICATA_EVE","/var/log/suricata/eve.json"))
    if not path.is_file():return{"ok":False,"error":f"Suricata EVE log is not available at {path}"}
    limit={"quick":25,"standard":100,"deep":250}[profile]
    try:
        with path.open("rb") as f:size=path.stat().st_size;f.seek(max(0,size-2_000_000));f.readline() if size>2_000_000 else None;lines=f.readlines()
    except OSError as exc:return{"ok":False,"error":f"Unable to read Suricata EVE log: {exc}"}
    alerts=[]
    for raw in reversed(lines):
        try:e=json.loads(raw)
        except Exception:continue
        if e.get("event_type")!="alert":continue
        a=e.get("alert") or {};alerts.append({"timestamp":e.get("timestamp"),"src_ip":e.get("src_ip"),"src_port":e.get("src_port"),"dest_ip":e.get("dest_ip"),"dest_port":e.get("dest_port"),"signature":a.get("signature"),"category":a.get("category"),"severity":a.get("severity")})
        if len(alerts)>=limit:break
    return{"ok":True,"source":str(path),"alerts":alerts,"alert_count":len(alerts),"high_priority_count":sum(int(a.get("severity") or 99)<=2 for a in alerts)}

def evidence_capture(target,options,data_dir):
    options=options or {}
    try:interfaces={n for _,n in socket.if_nameindex()}
    except OSError:interfaces=set()
    interface=str(options.get("interface") or "")
    if interface not in interfaces:raise ValueError("Choose an available network interface")
    host=str(ipaddress.ip_address(target.strip())) if target.strip() else "";count=max(1,min(int(options.get("packet_count") or 100),500));seconds=max(1,min(int(options.get("seconds") or 10),15));root=Path(data_dir)/"cyber-evidence";root.mkdir(parents=True,exist_ok=True);name="capture-"+dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+os.urandom(4).hex()+".pcap";path=root/name;helper=Path("/usr/local/sbin/godseye-evidence-capture")
    if os.geteuid()==0:
        cmd=[shutil.which("tcpdump") or "tcpdump","-i",interface,"-c",str(count),"-w",str(path)]+(["host",host] if host else[])
    elif helper.is_file():cmd=["sudo","-n",str(helper),interface,str(count),str(seconds),str(path),host or "-"]
    else:return{"ok":False,"error":"The validated evidence-capture helper is not installed"}
    code,out,err,elapsed=_run(cmd,seconds+8)
    if not path.exists():return{"ok":False,"error":err or out or "No capture file was produced","elapsed_ms":elapsed}
    return{"ok":code in{0,124},"filename":name,"interface":interface,"host_filter":host,"packet_limit":count,"duration_limit_seconds":seconds,"size_bytes":path.stat().st_size,"download_url":f"/api/v1/cyber-tools/evidence/{name}","elapsed_ms":elapsed,"details":err or out}

def execute(tool,target,profile,options,data_dir,connection=None):
    if tool not in TOOLS:raise ValueError("Unknown Cyber Tool")
    if profile not in PROFILES:raise ValueError("Profile must be quick, standard, or deep")
    if tool=="network_exposure":return network_exposure(target,profile)
    if tool=="endpoint_posture":return endpoint_posture(connection)
    if tool=="web_tls":return web_tls(target)
    if tool=="malware_ioc":return malware_ioc(target,options,data_dir)
    if tool=="dns_email":return dns_email(target,options)
    if tool=="linux_audit":return linux_audit()
    if tool=="threat_detection":return threat_detection(profile)
    return evidence_capture(target,options,data_dir)

def summarize(tool,r):
    if not r.get("ok"):return str(r.get("error") or "Check did not complete")[:300]
    return {"network_exposure":f"{r.get('host_count',0)} host(s), {r.get('open_port_count',0)} open port(s)","endpoint_posture":f"{r.get('online_count',0)}/{r.get('agent_count',0)} endpoint(s) online","web_tls":f"HTTP {r.get('status_code')}; {len(r.get('missing_headers') or [])} header(s) missing","malware_ioc":"No local malware rule matches detected","dns_email":f"{r.get('passed',0)}/{r.get('total',0)} controls detected","linux_audit":f"{r.get('warning_count',0)} warning(s), {r.get('suggestion_count',0)} suggestion(s)","threat_detection":f"{r.get('alert_count',0)} alert(s); {r.get('high_priority_count',0)} high priority","evidence_capture":f"Captured {r.get('size_bytes',0)} bytes on {r.get('interface','')}"}.get(tool,"Completed")

def public_run(row):
    d=dict(row)
    try:d["result"]=json.loads(d.pop("result_json") or "{}")
    except json.JSONDecodeError:d["result"]={}
    return d

def record_run(c,tool,target,profile,result,user,started,scheduled_id=None):
    summary=summarize(tool,result);encoded=json.dumps(result,separators=(",",":"),default=str)
    if len(encoded)>200000:encoded=json.dumps({"ok":result.get("ok",False),"summary":summary,"truncated":True})
    rid=c.execute("INSERT INTO cyber_tool_runs(tool,target,profile,status,summary,result_json,requested_by,scheduled_id,started_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(tool,target[:2048],profile,"completed" if result.get("ok") else"failed",summary,encoded,user,scheduled_id,started,utcnow())).lastrowid
    return public_run(c.execute("SELECT * FROM cyber_tool_runs WHERE id=?",(rid,)).fetchone())

class CyberScheduleManager:
    def __init__(self,db_factory,data_dir):
        import threading
        self.db_factory=db_factory;self.data_dir=Path(data_dir);self.stop_event=threading.Event();self.thread=threading.Thread(target=self._loop,daemon=True,name="godseye-cyber-schedules")
    def start(self):self.thread.start()
    def stop(self):self.stop_event.set();self.thread.join(timeout=5)
    def _loop(self):
        while not self.stop_event.wait(30):
            try:self.run_due()
            except Exception:pass
    def run_due(self):
        with self.db_factory() as c:ensure_schema(c);due=[dict(r) for r in c.execute("SELECT * FROM cyber_tool_schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT 5",(utcnow(),))]
        for s in due:
            try:
                with self.db_factory() as c:
                    result=execute(s["tool"],s["target"],s["profile"],json.loads(s["options_json"] or "{}"),self.data_dir,c);record_run(c,s["tool"],s["target"],s["profile"],result,s["created_by"],utcnow(),s["id"]);nxt=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=s["interval_minutes"])).isoformat();c.execute("UPDATE cyber_tool_schedules SET last_run_at=?,next_run_at=?,last_status=?,last_error='',updated_at=? WHERE id=?",(utcnow(),nxt,"completed" if result.get("ok") else"failed",utcnow(),s["id"]))
            except Exception as exc:
                with self.db_factory() as c:nxt=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=s["interval_minutes"])).isoformat();c.execute("UPDATE cyber_tool_schedules SET last_run_at=?,next_run_at=?,last_status='failed',last_error=?,updated_at=? WHERE id=?",(utcnow(),nxt,str(exc)[:1000],utcnow(),s["id"]))
