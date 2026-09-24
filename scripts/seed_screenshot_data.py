from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3

os.environ.setdefault("GODSEYE_DB", "/tmp/godseye-ui-capture.db")

from app import main
from app.intelligence import ensure_schema as ensure_intelligence_schema


def iso(minutes_ago: int = 0) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago)).isoformat()


def seed() -> None:
    path = str(main.DB_PATH)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass

    main.init_db()

    devices = [
        ("00:16:3e:10:00:01","192.168.1.10","dc01","Microsoft","DC01","Server","server","online","managed",1),
        ("00:16:3e:10:00:02","192.168.1.11","fs01","Microsoft","File Server","Server","server","online","managed",1),
        ("00:16:3e:10:00:03","192.168.1.20","nas01","Synology","NAS-01","NAS","nas","online","known",1),
        ("f0:9f:c2:10:00:04","192.168.1.1","gateway","Ubiquiti","Main Gateway","Router","router","online","managed",1),
        ("44:d9:e7:10:00:05","192.168.1.2","core-switch","Ubiquiti","Core Switch","Switch","switch","online","managed",1),
        ("b4:fb:e4:10:00:06","192.168.1.3","office-ap","Ubiquiti","Office AP","Access Point","access-point","online","managed",1),
        ("00:50:56:10:00:07","192.168.1.50","pc-07","Dell","PC-07","PC","pc","online","known",1),
        ("00:50:56:10:00:08","192.168.1.51","pc-08","Dell","PC-08","PC","pc","online","known",1),
        ("ac:bc:32:10:00:09","192.168.1.60","macbook-pro","Apple","Design MacBook","Laptop","laptop","online","known",1),
        ("3c:5a:b4:10:00:0a","192.168.1.70","front-camera","Amazon","Front Camera","Camera","camera","online","investigate",0),
        ("08:00:27:10:00:0b","192.168.1.77","lab-device","Unknown","New Lab Device","Other","other","online","new",0),
        ("00:1c:42:10:00:0c","192.168.1.88","old-printer","HP","Office Printer","Printer","printer","offline","known",1),
    ]

    monitors = [
        ("Internet Gateway","website","https://example.com",1,60),
        ("Client VPN","website","https://vpn.example.local",1,120),
        ("DNS Resolver","pihole","192.168.1.53",1,60),
        ("File Server","website","https://192.168.1.11",1,120),
        ("Backup Service","website","https://192.168.1.20",1,300),
    ]

    tickets = [
        ("TKT-00001","Review unmanaged lab device","Investigate newly discovered device","open","high","Alex","New Lab Device",10),
        ("TKT-00002","Backup warning on NAS-01","Verify backup schedule and last successful job","in_progress","high","Jordan","NAS-01",24),
        ("TKT-00003","Printer offline","Confirm power and network connection","waiting","medium","Sam","Office Printer",42),
        ("TKT-00004","TLS certificate review","Renew expiring internal certificate","open","medium","","Main Gateway",70),
    ]

    network_issues = [
        ("offline_device","high","00:1c:42:10:00:0c","Device is offline",{"ip":"192.168.1.88"},"Verify power, network link, DHCP state, and switch port, then run Recheck.",5),
        ("service_failure","critical","monitor:5","Backup service monitor is failing",{"monitor_id":5},"Verify the backup service, credentials, and target reachability.",11),
        ("ip_changed","medium","00:50:56:10:00:07","Device IP address changed",{"current_ip":"192.168.1.50"},"Confirm the address change is expected and consider a DHCP reservation.",31),
        ("packet_loss","medium","b4:fb:e4:10:00:06","Repeated packet loss detected",{"loss_percent":[18,14]},"Check Wi-Fi interference, cabling, switch/AP errors, and congestion.",47),
    ]

    event_findings = [
        ("DC01","System","Microsoft-Windows-DistributedCOM",10016,"Warning","Permissions","medium","DCOM permission warning","The application-specific permission settings do not grant Local Activation permission.","dcom-10016-dc01","Review the affected COM server permissions and validate the application identity.",["Confirm the CLSID and APPID from the event.","Review Component Services permissions.","Apply only the minimum required activation permission.","Recheck the event log after remediation."],6),
        ("PC-07","System","Service Control Manager",7031,"Error","Service","high","Windows service terminated unexpectedly","The Windows service terminated unexpectedly and will be restarted.","scm-7031-pc07","Identify the service, review its dependencies, and inspect related application logs.",["Identify the failing service name.","Review recent service and application errors.","Confirm dependencies are running.","Restart the service after correcting the root cause."],12),
        ("FS01","System","Disk",153,"Warning","Storage","high","Disk I/O operation retried","The I/O operation at a logical block address was retried.","disk-153-fs01","Review storage health, controller logs, cabling, and disk diagnostics.",["Review SMART/storage health.","Check controller and system logs.","Verify cabling or virtual storage health.","Plan maintenance if errors continue."],28),
    ]

    with sqlite3.connect(path) as c:
        c.row_factory = sqlite3.Row
        ensure_intelligence_schema(c)

        for i, d in enumerate(devices):
            mac, ip, hostname, vendor, name, dtype, icon, status, classification, trusted = d
            c.execute(
                """INSERT INTO devices(mac,ip,hostname,vendor,name,device_type,icon_key,status,first_seen,last_seen,trusted,notes,classification,missed_scans)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (mac, ip, hostname, vendor, name, dtype, icon, status, iso(1440 + i*30), iso(i*3), trusted, "", classification),
            )
            c.execute(
                "INSERT INTO events(mac,event_type,ip,created_at,details,severity) VALUES(?,?,?,?,?,?)",
                (mac, "device_seen" if status == "online" else "disconnected", ip, iso(i*7), f"{name} inventory update", "info" if status == "online" else "warning"),
            )

        c.execute(
            """INSERT OR REPLACE INTO scanner_heartbeat(id,last_run_at,last_success_at,last_error,devices_found,scan_duration_ms)
               VALUES(1,?,?,?,?,?)""",
            (iso(1), iso(1), "", len(devices), 1280),
        )

        for idx, (name, kind, target, enabled, interval) in enumerate(monitors, 1):
            ts = iso(idx)
            c.execute(
                """INSERT INTO integration_settings(id,name,kind,target,enabled,interval_seconds,options_json,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (idx, name, kind, target, enabled, interval, "{}", iso(1440), ts),
            )
            state = "down" if name == "Backup Service" else "up"
            latency = 220.0 if state == "down" else 8.0 + idx * 2
            c.execute(
                """INSERT INTO integration_checks(kind,target,status,latency_ms,details,last_checked,monitor_id)
                   VALUES(?,?,?,?,?,?,?)""",
                (kind, target, state, latency, "Screenshot capture data", ts, idx),
            )

        for num, title, desc, status, priority, assignee, device, mins in tickets:
            c.execute(
                """INSERT INTO tickets(ticket_number,title,description,status,priority,assignee,device_name,created_by,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (num, title, desc, status, priority, assignee, device, "admin", iso(mins+30), iso(mins)),
            )

        for issue_type, severity, target, title, evidence, recommendation, mins in network_issues:
            c.execute(
                """INSERT INTO network_issues(issue_type,severity,target,title,evidence,recommendation,status,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,'open',?,?)""",
                (issue_type, severity, target, title, json.dumps(evidence), recommendation, iso(mins+60), iso(mins)),
            )

        for computer, channel, provider, event_id, level, category, severity, title, message, key, rec, actions, mins in event_findings:
            c.execute(
                """INSERT INTO event_findings(computer_name,channel,provider,event_id,level,category,severity,title,message,event_time,finding_key,recommendation,suggested_actions_json,status,occurrence_count,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'open',1,?,?)""",
                (computer, channel, provider, event_id, level, category, severity, title, message, iso(mins+10), key, rec, json.dumps(actions), iso(mins+120), iso(mins)),
            )

        c.commit()


if __name__ == "__main__":
    seed()
    print(f"Seeded live screenshot database at {main.DB_PATH}")
