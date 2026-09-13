from __future__ import annotations

import base64
import json
from typing import Any

STORAGE_IDS={7,11,15,51,55,98,129,153,157}
WHEA_IDS={1,17,18,19,20,46,47}
POWER_IDS={41,6008}
UPDATE_IDS={20,25,31,34}
DEFENDER_IDS={1116,1117,1118,1119}
VSS_IDS={25,27,36}
SERVICE_IDS=set(range(7000,7046))

def _norm(value: Any) -> str:
    return str(value or "").strip()

def classify_windows_event(event: dict) -> dict:
    provider=_norm(event.get("provider") or event.get("ProviderName"))
    channel=_norm(event.get("channel") or event.get("LogName"))
    event_id=int(event.get("event_id") or event.get("Id") or 0)
    level=_norm(event.get("level") or event.get("LevelDisplayName") or "Error")
    p=provider.lower()
    severity="high" if level.lower() in {"critical","error"} else "medium"
    category="Windows"
    title=f"{provider or channel} Event {event_id}"
    recommendation="Review the Windows event details, recent changes, and the affected component before making changes."
    actions=[
        "Review the complete Windows event message and surrounding events.",
        "Check whether the condition is still occurring.",
        "Review recent Windows updates, driver changes, and configuration changes.",
        "Recheck the finding after corrective work.",
    ]

    if event_id in STORAGE_IDS or any(x in p for x in ("disk","storahci","stornvme","ntfs","partmgr")):
        category="Storage"
        severity="critical" if event_id in {7,55,157} else "high"
        title=f"Storage / disk reliability warning on {event.get('computer_name') or event.get('MachineName') or 'Windows host'}"
        recommendation="Treat repeated disk, controller, timeout, or NTFS events as a possible storage reliability problem."
        actions=[
            "Back up important data before stressing or repairing the disk.",
            "Check SMART / vendor diagnostics and storage-controller health.",
            "Inspect SATA/SAS/NVMe cabling, backplane, controller, and power connections where applicable.",
            "Run CHKDSK only after backup if filesystem corruption is indicated.",
            "Review firmware and storage-driver updates from the system or controller vendor.",
            "Replace a failing disk or controller component if diagnostics confirm hardware failure.",
        ]
    elif event_id in WHEA_IDS or "whea" in p:
        category="Hardware"
        severity="critical" if event_id in {18,46} else "high"
        title="Windows hardware error (WHEA)"
        recommendation="WHEA events can indicate CPU, memory, PCIe, motherboard, firmware, or power instability."
        actions=[
            "Review the WHEA event details for the reported component or error source.",
            "Check BIOS/UEFI, chipset, storage, NIC, and device firmware levels.",
            "Run vendor hardware diagnostics and memory testing.",
            "Check temperatures, power supply, overclocking, and physical seating of components.",
            "Escalate repeated uncorrectable WHEA errors as a hardware-reliability incident.",
        ]
    elif event_id in POWER_IDS or "kernel-power" in p:
        category="Power / Shutdown"
        severity="high"
        title="Unexpected shutdown or power-loss event"
        recommendation="Determine whether the host lost power, crashed, reset, or was forced off."
        actions=[
            "Check UPS, power supply, PDU, and facility power history.",
            "Review bugcheck / crash dump information around the same time.",
            "Check thermal events and hardware-management logs.",
            "Review recent driver, firmware, and Windows updates.",
            "Confirm the issue does not repeat after corrective work.",
        ]
    elif event_id in SERVICE_IDS or "service control manager" in p:
        category="Service"
        severity="medium" if level.lower()=="warning" else "high"
        title="Windows service failure"
        recommendation="A Windows service failed to start, stopped unexpectedly, or reported a control error."
        actions=[
            "Open Services and verify the affected service state and startup type.",
            "Check dependent services and the service account permissions.",
            "Review the executable path, configuration, and recent application updates.",
            "Check adjacent Service Control Manager and application events.",
            "Restart or repair the service only after identifying the failure cause.",
        ]
    elif event_id in UPDATE_IDS or "windowsupdate" in p or "windows update" in p:
        category="Windows Update"
        severity="medium"
        title="Windows Update failure"
        recommendation="Windows Update reported a failed installation, scan, or download."
        actions=[
            "Review the update KB/error code in the event message.",
            "Confirm free disk space, network access, proxy, and time synchronization.",
            "Run Windows Update troubleshooting and component-store health checks.",
            "Review DISM /RestoreHealth and SFC results if servicing corruption is suspected.",
            "Retry the update after the underlying cause is corrected.",
        ]
    elif event_id in DEFENDER_IDS or "windows defender" in p or "microsoft-windows-windows defender" in p:
        category="Security"
        severity="critical" if event_id in {1116,1117} else "high"
        title="Microsoft Defender security event"
        recommendation="Review the detected threat or Defender failure and verify remediation completed successfully."
        actions=[
            "Review the threat name, path, user, and remediation action in Microsoft Defender.",
            "Isolate the host if an active threat or lateral movement is suspected.",
            "Run an updated Defender scan and review protection history.",
            "Check persistence locations and related security events.",
            "Recheck the finding only after Defender reports the issue remediated.",
        ]
    elif event_id in VSS_IDS or "volsnap" in p or "vss" in p:
        category="Backup / VSS"
        severity="high"
        title="Volume Shadow Copy / backup error"
        recommendation="VSS or volume snapshot errors can make backups incomplete or unusable."
        actions=[
            "Check VSS writers with `vssadmin list writers`.",
            "Check free space and shadow-copy storage allocation.",
            "Review backup application logs and recent snapshot failures.",
            "Restart or repair the failing VSS writer/service if appropriate.",
            "Run a new backup and verify recovery data after correction.",
        ]
    elif "application error" in p or "application hang" in p:
        category="Application"
        title="Application crash or hang"
        recommendation="An application reported a crash or hang that may require application, runtime, or OS remediation."
        actions=[
            "Identify the faulting application and module in the event.",
            "Review application logs and recent application changes.",
            "Check runtime/framework and application updates.",
            "Check memory, disk, and resource pressure around the failure time.",
            "Reproduce and recheck after repair or update.",
        ]

    return {"category":category,"severity":severity,"title":title,"recommendation":recommendation,"actions":actions}

def finding_key(event: dict) -> str:
    computer=_norm(event.get("computer_name") or event.get("MachineName")).lower()
    channel=_norm(event.get("channel") or event.get("LogName")).lower()
    provider=_norm(event.get("provider") or event.get("ProviderName")).lower()
    event_id=int(event.get("event_id") or event.get("Id") or 0)
    return f"{computer}|{channel}|{provider}|{event_id}"

def winrm_powershell_query(channels: list[str], bookmarks: dict[str,int], max_events: int=250) -> str:
    payload=base64.b64encode(json.dumps({"channels":channels,"bookmarks":bookmarks,"max_events":max(10,min(max_events,500))}).encode()).decode()
    script = r'''
$ErrorActionPreference = "SilentlyContinue"
$cfgJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("__PAYLOAD__"))
$cfg = $cfgJson | ConvertFrom-Json
$out = @()
foreach ($channel in $cfg.channels) {
  $last = 0
  if ($cfg.bookmarks.PSObject.Properties.Name -contains $channel) { $last = [int64]$cfg.bookmarks.$channel }
  $filter = @{LogName=$channel; Level=1,2,3}
  if ($last -le 0) { $filter.StartTime=(Get-Date).AddDays(-1) }
  $items = Get-WinEvent -FilterHashtable $filter -MaxEvents ([int]$cfg.max_events) |
    Where-Object { [int64]$_.RecordId -gt $last } |
    Sort-Object RecordId
  foreach ($e in $items) {
    $out += [pscustomobject]@{
      computer_name = $e.MachineName
      channel = $e.LogName
      provider = $e.ProviderName
      event_id = [int]$e.Id
      level = $e.LevelDisplayName
      record_id = [int64]$e.RecordId
      event_time = if ($e.TimeCreated) { $e.TimeCreated.ToUniversalTime().ToString("o") } else { "" }
      message = $e.Message
    }
  }
}
$out | ConvertTo-Json -Compress -Depth 4
'''.strip()
    return script.replace("__PAYLOAD__",payload)

def parse_winrm_json(raw: bytes | str) -> list[dict]:
    if isinstance(raw,bytes): raw=raw.decode("utf-8","replace")
    raw=(raw or "").strip()
    if not raw: return []
    data=json.loads(raw)
    if isinstance(data,dict): return [data]
    return [x for x in data if isinstance(x,dict)]

def ingest_event(c, source_id: int | None, event: dict, now_iso: str) -> tuple[int,bool]:
    computer=_norm(event.get("computer_name") or event.get("MachineName") or "Unknown Windows host")
    channel=_norm(event.get("channel") or event.get("LogName") or "System")
    provider=_norm(event.get("provider") or event.get("ProviderName") or "Windows")
    event_id=int(event.get("event_id") or event.get("Id") or 0)
    level=_norm(event.get("level") or event.get("LevelDisplayName") or "Error")
    record_id=int(event.get("record_id") or event.get("RecordId") or 0)
    event_time=_norm(event.get("event_time") or event.get("TimeCreated") or now_iso)
    message=_norm(event.get("message") or event.get("Message"))[:12000]
    key=finding_key({**event,"computer_name":computer,"channel":channel,"provider":provider,"event_id":event_id})
    rule=classify_windows_event({**event,"computer_name":computer,"channel":channel,"provider":provider,"event_id":event_id,"level":level,"message":message})
    existing=c.execute("SELECT * FROM event_findings WHERE finding_key=?",(key,)).fetchone()
    created=False
    if existing:
        new_status="open" if existing["status"]=="resolved" else existing["status"]
        c.execute("""UPDATE event_findings SET source_id=COALESCE(?,source_id),level=?,category=?,severity=?,title=?,message=?,record_id=?,event_time=?,
                     recommendation=?,suggested_actions_json=?,status=?,occurrence_count=occurrence_count+1,last_seen=?,resolved_at=CASE WHEN ?='open' THEN NULL ELSE resolved_at END
                     WHERE id=?""",
                  (source_id,level,rule["category"],rule["severity"],rule["title"],message,record_id,event_time,rule["recommendation"],json.dumps(rule["actions"]),
                   new_status,now_iso,new_status,existing["id"]))
        finding_id=existing["id"]
    else:
        cur=c.execute("""INSERT INTO event_findings(source_id,computer_name,channel,provider,event_id,level,category,severity,title,message,record_id,event_time,
                         finding_key,recommendation,suggested_actions_json,status,occurrence_count,first_seen,last_seen)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open',1,?,?)""",
                      (source_id,computer,channel,provider,event_id,level,rule["category"],rule["severity"],rule["title"],message,record_id,event_time,key,
                       rule["recommendation"],json.dumps(rule["actions"]),now_iso,now_iso))
        finding_id=cur.lastrowid
        created=True
    return finding_id,created

def poll_windows_source(c, source: dict, now_iso: str) -> dict:
    try:
        import winrm
    except Exception as exc:
        raise RuntimeError("pywinrm is not installed; run the GODSEYE installer/upgrade") from exc
    channels=json.loads(source.get("channels_json") or '["System","Application"]')
    bookmarks=json.loads(source.get("last_record_json") or "{}")
    endpoint=f"https://{source['hostname']}:{int(source['port'])}/wsman"
    password=source.get("_password_plain") or ""
    transport=(source.get("transport") or "ntlm").lower()
    cert_validation="validate" if source.get("verify_tls") else "ignore"
    session=winrm.Session(endpoint,auth=(source.get("username") or "",password),transport=transport,server_cert_validation=cert_validation)
    result=session.run_ps(winrm_powershell_query(channels,bookmarks))
    if result.status_code not in (0,None):
        err=(result.std_err or b"").decode("utf-8","replace")
        raise RuntimeError(err[:2000] or f"WinRM PowerShell returned {result.status_code}")
    events=parse_winrm_json(result.std_out)
    created=0; newest=dict(bookmarks); finding_ids=[]
    for event in events:
        fid,is_new=ingest_event(c,source["id"],event,now_iso)
        finding_ids.append(fid)
        if is_new: created+=1
        ch=_norm(event.get("channel") or "System")
        rid=int(event.get("record_id") or 0)
        newest[ch]=max(int(newest.get(ch,0) or 0),rid)
    return {"events":len(events),"new_findings":created,"finding_ids":finding_ids,"bookmarks":newest}
