"""Full multi-source discovery and topology intelligence for GODSEYE.

The pipeline is deliberately best-effort: a missing optional tool or an
unconfigured integration never breaks the primary ARP scan. Every observation
is normalized into the shared device intelligence model and contributes
explainable topology evidence.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import urllib.request
import urllib.parse
from http.cookiejar import CookieJar
from pathlib import Path

from .intelligence import correlate_device, ensure_schema, now
from .discovery import nmap_discover, ip_neighbors
from .collectors import dhcp_leases
from .integrations import pihole_auth, pihole_json

MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")


def _run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or p.stderr or "").strip()
    except Exception as exc:
        return 1, str(exc)


def normalize_mac(value):
    if not value:
        return None
    raw = re.sub(r"[^0-9a-fA-F]", "", str(value)).lower()
    if len(raw) != 12:
        return None
    return ":".join(raw[i:i+2] for i in range(0, 12, 2))


def default_gateway():
    code, out = _run(["ip", "route", "show", "default"], 5)
    if code != 0:
        return None
    m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def mdns_observations(timeout=5):
    """Discover mDNS services with avahi-browse when available."""
    binary = shutil.which("avahi-browse")
    if not binary:
        return {"ok": False, "installed": False, "observations": [], "error": "avahi-browse not installed"}
    code, out = _run([binary, "-artp"], timeout)
    obs = []
    seen = set()
    # parsable format: =;iface;IPv4;name;_service._tcp;local;host.local;1.2.3.4;port;...
    for line in out.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 9:
            continue
        ip = parts[7].replace("\\032", " ")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        hostname = parts[6].replace("\\032", " ").rstrip(".") or None
        service = parts[4]
        key = (ip, hostname, service)
        if key in seen:
            continue
        seen.add(key)
        obs.append({"ip": ip, "hostname": hostname, "service": service})
    return {"ok": code == 0, "installed": True, "observations": obs, "raw": out[-4000:]}


def netbios_observations(network=None, timeout=12):
    binary = shutil.which("nbtscan")
    if not binary:
        return {"ok": False, "installed": False, "observations": [], "error": "nbtscan not installed"}
    target = network or "192.168.1.0/24"
    code, out = _run([binary, "-s", ":", str(target)], timeout)
    obs = []
    for line in out.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 2:
            continue
        ip, hostname = parts[0].strip(), parts[1].strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        obs.append({"ip": ip, "hostname": hostname})
    return {"ok": code == 0, "installed": True, "observations": obs, "raw": out[-4000:]}


def pihole_client_observations(base_url, token=None, timeout=8, verify_tls=True):
    """Best-effort Pi-hole client/network discovery with v6 authentication.

    ``token`` is treated as a Pi-hole v6 application password/web password
    first. GODSEYE exchanges it for a short-lived SID at /api/auth, then uses
    that SID for protected endpoints. Older static API tokens and existing SIDs
    are retried automatically for backward compatibility.
    """
    if not base_url:
        return {"ok": False, "observations": [], "error": "Pi-hole URL not configured"}
    errors = []
    auth = pihole_auth(base_url, token, timeout=timeout, verify_tls=verify_tls) if token else None
    for path in ("/api/network/devices", "/api/clients", "/api/stats/top_clients"):
        try:
            data, used = pihole_json(base_url, path, token, timeout=timeout, verify_tls=verify_tls, session=auth)
            rows = data.get("devices") if isinstance(data, dict) else data
            if rows is None and isinstance(data, dict):
                rows = data.get("clients") or data.get("data") or []
            # Some Pi-hole endpoints return a mapping of client -> count.
            if isinstance(rows, dict):
                rows = [{"ip": k, "queries": v} for k, v in rows.items()]
            obs = []
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                mac = normalize_mac(row.get("hwaddr") or row.get("mac") or row.get("mac_address"))
                ip = row.get("ip") or row.get("ip_address") or row.get("address") or row.get("client")
                host = row.get("name") or row.get("hostname") or row.get("host")
                if mac or ip:
                    obs.append({"mac": mac, "ip": ip, "hostname": host, "details": row})
            return {"ok": True, "observations": obs, "endpoint": path, "auth_mode": used.get('request_mode') or used.get('mode')}
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    return {"ok": False, "observations": [], "error": "; ".join(errors)[-3000:]}


def unifi_client_observations(base_url, username, password, verify_tls=True, site="default", timeout=10):
    """Fetch active UniFi clients with a cookie-preserving login."""
    if not (base_url and username and password):
        return {"ok": False, "observations": [], "error": "UniFi URL/username/password not configured"}
    import ssl
    context = None if verify_tls else ssl._create_unverified_context()
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=context))
    base = base_url.rstrip("/")
    login_variants = [
        ("/api/auth/login", {"username": username, "password": password}),
        ("/api/login", {"username": username, "password": password}),
    ]
    logged = False
    last_error = None
    for path, payload in login_variants:
        try:
            req = urllib.request.Request(base + path, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json","User-Agent":"GODSEYE/1.3"}, method="POST")
            with opener.open(req, timeout=timeout) as r:
                logged = 200 <= r.status < 300
            if logged:
                break
        except Exception as exc:
            last_error = str(exc)
    if not logged:
        return {"ok": False, "observations": [], "error": last_error or "UniFi login failed"}
    endpoints = [
        f"/proxy/network/api/s/{urllib.parse.quote(site)}/stat/sta",
        f"/api/s/{urllib.parse.quote(site)}/stat/sta",
    ]
    errors = []
    for path in endpoints:
        try:
            req = urllib.request.Request(base + path, headers={"User-Agent":"GODSEYE/1.3"})
            with opener.open(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            rows = data.get("data", []) if isinstance(data, dict) else []
            obs = []
            for row in rows:
                mac = normalize_mac(row.get("mac"))
                if not mac:
                    continue
                obs.append({
                    "mac": mac, "ip": row.get("ip"),
                    "hostname": row.get("hostname") or row.get("name"),
                    "access_point_id": normalize_mac(row.get("ap_mac") or row.get("bssid")),
                    "parent_id": normalize_mac(row.get("sw_mac")),
                    "ssid": row.get("essid"), "signal": row.get("signal"),
                    "details": row,
                })
            return {"ok": True, "observations": obs, "endpoint": path}
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    return {"ok": False, "observations": [], "error": "; ".join(errors)[-3000:]}


def snmp_neighbor_observations(host, community="public", timeout=12):
    """Read IPv4 ARP/neighbor table from a router/switch using SNMPv2c."""
    binary = shutil.which("snmpwalk")
    if not binary:
        return {"ok": False, "installed": False, "observations": [], "error": "snmpwalk not installed"}
    # ipNetToMediaPhysAddress (legacy but widely supported): 1.3.6.1.2.1.4.22.1.2
    oid = "1.3.6.1.2.1.4.22.1.2"
    code, out = _run([binary, "-v2c", "-c", community, "-On", host, oid], timeout)
    obs = []
    for line in out.splitlines():
        m_ip = re.search(r"\.(\d+\.\d+\.\d+\.\d+)\s+=", line)
        m_mac = MAC_RE.search(line.replace(" ", ":")) or MAC_RE.search(line)
        if m_ip and m_mac:
            obs.append({"ip": m_ip.group(1), "mac": normalize_mac(m_mac.group(0)), "parent_id": host})
        else:
            # Hex-STRING: AA BB CC DD EE FF
            m_hex = re.search(r"Hex-STRING:\s*((?:[0-9A-Fa-f]{2}\s+){5}[0-9A-Fa-f]{2})", line)
            if m_ip and m_hex:
                obs.append({"ip": m_ip.group(1), "mac": normalize_mac(m_hex.group(1)), "parent_id": host})
    return {"ok": code == 0, "installed": True, "observations": obs, "raw": out[-4000:]}


def _source_by_ip(c):
    result = {}
    for r in c.execute("SELECT mac,ip FROM devices WHERE ip IS NOT NULL"):
        result[r["ip"]] = r["mac"]
    return result


def _link(c, parent, child, link_type, details=None):
    if not parent or not child or str(parent).lower() == str(child).lower():
        return
    ensure_schema(c)
    c.execute("""INSERT INTO topology_links(parent,child,link_type,details,last_seen)
                 VALUES(?,?,?,?,?) ON CONFLICT(parent,child,link_type)
                 DO UPDATE SET details=excluded.details,last_seen=excluded.last_seen""",
              (str(parent).lower(), str(child).lower(), link_type, json.dumps(details or {})[:4000], now()))


def ingest_observations(c, source, observations, gateway=None):
    """Normalize and correlate arbitrary observations. Returns count."""
    ensure_schema(c)
    ip_map = _source_by_ip(c)
    count = 0
    for item in observations or []:
        mac = normalize_mac(item.get("mac"))
        ip = item.get("ip")
        if not mac and ip:
            mac = ip_map.get(ip)
        if not mac:
            continue
        hostname = item.get("hostname")
        vendor = item.get("vendor")
        details = dict(item)
        correlate_device(c, mac, ip, hostname, vendor, source=source, details=details)
        parent = normalize_mac(item.get("parent_id")) or item.get("parent_id")
        ap = normalize_mac(item.get("access_point_id")) or item.get("access_point_id")
        if ap:
            _link(c, ap, mac, "wifi_client", {"source": source, "ssid": item.get("ssid"), "signal": item.get("signal")})
        elif parent:
            _link(c, parent, mac, "attached", {"source": source})
        elif gateway:
            _link(c, gateway, mac, "gateway_path", {"source": source})
        count += 1
    return count


def build_live_topology(c):
    """Return nodes + links suitable for the GODSEYE Network Map."""
    ensure_schema(c)
    gateway = default_gateway()
    nodes = [{"id":"internet","label":"Internet","type":"internet","status":"online"}]
    gateway_id = gateway or "gateway"
    nodes.append({"id":gateway_id,"label":"Gateway / Router","type":"gateway","ip":gateway,"status":"online"})
    links = [{"parent":"internet","child":gateway_id,"link_type":"wan","details":{}}]
    devs = [dict(r) for r in c.execute("SELECT * FROM devices ORDER BY status DESC,last_seen DESC")]
    known_ids = {"internet", gateway_id}
    for d in devs:
        node_id = d.get("mac") or d.get("ip") or f"device:{d['id']}"
        known_ids.add(node_id)
        nodes.append({"id":node_id,"device_id":d["id"],"label":d.get("name") or d.get("hostname") or d.get("vendor") or "Device",
                      "type":d.get("device_type") or "device","ip":d.get("ip"),"mac":d.get("mac"),"vendor":d.get("vendor"),"status":d.get("status"),
                      "classification":d.get("classification"),"icon_key":d.get("icon_key") or "auto","icon_data":d.get("icon_data")})
    persisted = [dict(r) for r in c.execute("SELECT * FROM topology_links ORDER BY last_seen DESC")]
    children = set()
    for row in persisted:
        parent, child = row["parent"], row["child"]
        if child not in known_ids:
            continue
        if parent not in known_ids:
            nodes.append({"id":parent,"label":parent,"type":"infrastructure","status":"unknown"})
            known_ids.add(parent)
        try: details = json.loads(row.get("details") or "{}")
        except Exception: details = {}
        links.append({"parent":parent,"child":child,"link_type":row["link_type"],"details":details,"last_seen":row["last_seen"]})
        children.add(child)
    # Give every otherwise-unattached device a conservative gateway path.
    for d in devs:
        node_id = d.get("mac") or d.get("ip") or f"device:{d['id']}"
        if node_id not in children and node_id != gateway_id:
            links.append({"parent":gateway_id,"child":node_id,"link_type":"gateway_path","details":{"source":"inferred"}})
    return {"generated_at":now(),"gateway":gateway,"nodes":nodes,"links":links}


def run_full_discovery(c, network=None, integration_settings=None, arp_observations=None):
    """Run all locally available discovery sources and configured integrations."""
    ensure_schema(c)
    gateway = default_gateway()
    summary = {"gateway": gateway, "sources": {}, "total_observations": 0}

    def add(source, result, observations=None):
        obs = observations if observations is not None else result.get("observations", [])
        n = ingest_observations(c, source, obs, gateway=gateway)
        summary["sources"][source] = {"ok": bool(result.get("ok")), "count": n, "error": result.get("error"), "installed": result.get("installed", True)}
        summary["total_observations"] += n

    if arp_observations:
        add("arp-scan", {"ok":True}, arp_observations)

    target = network or os.environ.get("GODSEYE_DISCOVERY_NETWORK")
    if target:
        nr = nmap_discover(target)
        add("nmap", nr, nr.get("hosts", []))

    neigh = ip_neighbors()
    add("neighbor", neigh, neigh.get("neighbors", []))

    md = mdns_observations()
    # mDNS lacks MAC; correlate by current IP where possible.
    add("mdns", md)

    if target:
        nb = netbios_observations(target)
        add("netbios", nb)

    dh = dhcp_leases()
    add("dhcp", dh, dh.get("leases", []))

    settings = integration_settings
    if settings is None:
        settings = [dict(r) for r in c.execute("SELECT * FROM integration_settings WHERE enabled=1 AND kind IN ('pihole','unifi','snmp')")]
    for setting in settings:
        try:
            opts = json.loads(setting.get("options_json") or "{}")
        except Exception:
            opts = {}
        kind = setting.get("kind")
        if kind == "pihole":
            result = pihole_client_observations(setting.get("target"), opts.get("token") or opts.get("api_token"), verify_tls=bool(setting.get("verify_tls", 1)))
            add("pihole", result)
        elif kind == "unifi":
            result = unifi_client_observations(setting.get("target"), opts.get("username",""), opts.get("password",""), bool(opts.get("verify_tls",True)), opts.get("site","default"))
            add("unifi", result)
        elif kind == "snmp":
            result = snmp_neighbor_observations(setting.get("target"), opts.get("community","public"))
            add("snmp", result)

    # Reverse DNS for unresolved inventory entries is cheap enough only after the
    # active sources have run, and only for entries still missing a hostname.
    rdns_obs = []
    for row in c.execute("SELECT mac,ip FROM devices WHERE ip IS NOT NULL AND (hostname IS NULL OR hostname='') LIMIT 64"):
        name = reverse_dns(row["ip"])
        if name:
            rdns_obs.append({"mac":row["mac"],"ip":row["ip"],"hostname":name})
    add("reverse_dns", {"ok":True}, rdns_obs)

    summary["topology"] = build_live_topology(c)
    return summary
