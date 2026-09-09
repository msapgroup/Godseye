"""Native, Docker-free integration helpers for GODSEYE.

These helpers never persist credentials. Integration secrets are supplied only
for an individual test call or through administrator-controlled environment
variables for local collectors.
"""
from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import json


def _urlopen(url: str, timeout: float = 8, verify_tls: bool = True, data: bytes | None = None, headers=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    context = None if verify_tls else ssl._create_unverified_context()
    return urllib.request.urlopen(req, timeout=timeout, context=context)


def website_check(url: str, timeout: float = 8) -> dict:
    started = time.monotonic()
    try:
        with _urlopen(url, timeout=timeout, headers={"User-Agent": "GODSEYE/1.0"}) as r:
            r.read(256)
            return {"ok": 200 <= r.status < 400, "status": r.status,
                    "final_url": r.geturl(), "elapsed_ms": round((time.monotonic()-started)*1000, 1)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_ms": round((time.monotonic()-started)*1000, 1)}


def pihole_test(base_url: str, timeout: float = 8) -> dict:
    url = base_url.rstrip("/") + "/api/info"
    try:
        with _urlopen(url, timeout=timeout, headers={"User-Agent": "GODSEYE/1.0"}) as r:
            data = r.read(8192).decode("utf-8", "replace")
            try: parsed = json.loads(data)
            except Exception: parsed = data[:4000]
            return {"ok": 200 <= r.status < 400, "status": r.status, "data": parsed}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def unifi_login(base_url: str, username: str, password: str, verify_tls: bool = True) -> dict:
    url = base_url.rstrip("/") + "/api/auth/login"
    payload = json.dumps({"username": username, "password": password}).encode()
    try:
        with _urlopen(url, timeout=10, verify_tls=verify_tls,
                      data=payload,
                      headers={"Content-Type": "application/json", "User-Agent": "GODSEYE/1.0"},
                      method="POST") as r:
            return {"ok": 200 <= r.status < 300, "status": r.status}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": "Controller rejected the login"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def snmp_test(host: str, community: str | None = None) -> dict:
    binary = shutil.which("snmpget") or shutil.which("snmpwalk")
    if not binary:
        return {"ok": False, "installed": False, "error": "SNMP tools are not installed"}
    community = community or os.environ.get("GODSEYE_SNMP_COMMUNITY", "public")
    oid = "1.3.6.1.2.1.1.1.0"
    try:
        cmd = [binary, "-v2c", "-c", community, "-On", host, oid]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {"ok": p.returncode == 0, "installed": True, "response": (p.stdout or p.stderr).strip()[-3000:]}
    except Exception as exc:
        return {"ok": False, "installed": True, "error": str(exc)}


def wake_on_lan(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> dict:
    raw = mac.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(raw) != 12 or any(ch not in "0123456789abcdef" for ch in raw):
        raise ValueError("Invalid MAC address")
    packet = bytes.fromhex("ff" * 6 + raw * 16)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sent = sock.sendto(packet, (broadcast, port))
    finally:
        sock.close()
    return {"ok": sent == 102, "bytes_sent": sent, "broadcast": broadcast, "port": port}
