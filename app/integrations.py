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
import urllib.parse
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


def _pihole_context(verify_tls: bool):
    return None if verify_tls else ssl._create_unverified_context()


def _pihole_open(req, timeout=8, verify_tls=True):
    return urllib.request.urlopen(req, timeout=timeout, context=_pihole_context(verify_tls))


def pihole_auth(base_url: str, credential: str | None, timeout: float = 8, verify_tls: bool = True) -> dict:
    """Authenticate to Pi-hole v6 and return a short-lived SID.

    Pi-hole v6 does not accept the old static API token as a bearer token. It
    expects the web password or an application password to be POSTed to
    /api/auth, which returns a session ID (SID). For backward compatibility we
    still allow callers to fall back to direct legacy-token/SID use when this
    v6 authentication attempt is not accepted by the server.
    """
    if not credential:
        return {"ok": True, "mode": "none", "sid": None, "csrf": None}
    url = base_url.rstrip('/') + '/api/auth'
    payload = json.dumps({"password": credential}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "GODSEYE/2.1"},
        method="POST",
    )
    try:
        with _pihole_open(req, timeout=timeout, verify_tls=verify_tls) as r:
            data = json.loads(r.read().decode('utf-8', 'replace'))
        session = data.get('session', {}) if isinstance(data, dict) else {}
        sid = session.get('sid')
        if session.get('valid') and sid:
            return {"ok": True, "mode": "v6_session", "sid": sid, "csrf": session.get('csrf'), "validity": session.get('validity')}
        return {"ok": False, "mode": "v6_session", "error": "Pi-hole did not return a valid session"}
    except urllib.error.HTTPError as exc:
        body = ''
        try:
            body = exc.read().decode('utf-8', 'replace')[:1000]
        except Exception:
            pass
        return {"ok": False, "mode": "v6_session", "status": exc.code, "error": body or str(exc)}
    except Exception as exc:
        return {"ok": False, "mode": "v6_session", "error": str(exc)}


def pihole_json(base_url: str, path: str, credential: str | None = None, timeout: float = 8,
                verify_tls: bool = True, session: dict | None = None) -> tuple[dict, dict]:
    """GET JSON from Pi-hole with v6 session auth and legacy compatibility.

    Returns ``(payload, auth_info)``. A configured credential is treated as a
    Pi-hole v6 application password/web password first. If /api/auth cannot
    establish a session, GODSEYE retries it as a direct SID/static legacy token
    for older Pi-hole releases and already-issued SIDs.
    """
    base = base_url.rstrip('/')
    auth = session or pihole_auth(base, credential, timeout=timeout, verify_tls=verify_tls)
    attempts = []
    if auth.get('ok') and auth.get('sid'):
        attempts.append((base + path, {"User-Agent":"GODSEYE/2.1", "X-FTL-SID": auth['sid']}, 'v6_session'))
    elif not credential:
        attempts.append((base + path, {"User-Agent":"GODSEYE/2.1"}, 'none'))
    if credential:
        # Already-issued v6 SID and Pi-hole v5/static-token compatibility.
        attempts.append((base + path, {"User-Agent":"GODSEYE/2.1", "X-FTL-SID": credential}, 'direct_sid'))
        sep = '&' if '?' in path else '?'
        attempts.append((base + path + sep + urllib.parse.urlencode({'auth': credential}), {"User-Agent":"GODSEYE/2.1"}, 'legacy_token'))
    errors=[]
    for url, headers, mode in attempts:
        try:
            req=urllib.request.Request(url, headers=headers)
            with _pihole_open(req, timeout=timeout, verify_tls=verify_tls) as r:
                data=json.loads(r.read().decode('utf-8','replace'))
            return data, {**auth, 'ok':True, 'request_mode':mode}
        except urllib.error.HTTPError as exc:
            detail=''
            try: detail=exc.read().decode('utf-8','replace')[:800]
            except Exception: pass
            errors.append(f'{mode}: HTTP {exc.code} {detail}'.strip())
        except Exception as exc:
            errors.append(f'{mode}: {exc}')
    auth_error = auth.get('error') if isinstance(auth, dict) else None
    if auth_error:
        errors.insert(0, 'v6 auth: '+str(auth_error))
    raise RuntimeError('; '.join(errors)[-3000:] or 'Pi-hole request failed')


def pihole_test(base_url: str, timeout: float = 8, credential: str | None = None, verify_tls: bool = True) -> dict:
    """Validate Pi-hole connectivity and authentication.

    v6 credentials should be an application password (recommended) or web
    password. Legacy API tokens and an already-issued SID are also accepted.
    """
    candidates = ['/api/info/version', '/api/dns/blocking', '/api/info']
    errors=[]
    auth = pihole_auth(base_url, credential, timeout=timeout, verify_tls=verify_tls) if credential else None
    for path in candidates:
        try:
            data, used = pihole_json(base_url, path, credential, timeout, verify_tls, session=auth)
            return {"ok": True, "status": 200, "endpoint": path, "auth_mode": used.get('request_mode') or used.get('mode'), "data": data}
        except Exception as exc:
            errors.append(f'{path}: {exc}')
    return {"ok": False, "error": '; '.join(errors)[-3000:]}


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
