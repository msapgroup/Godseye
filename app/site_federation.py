"""Paired GODSEYE installations on an existing private network.

The master talks to remote APIs server-to-server. No browser session, remote
database connection, or VPN management is shared between installations.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import secrets
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, field_validator


def ensure_schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS federation_identity (
        id INTEGER PRIMARY KEY CHECK(id=1), instance_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS federation_pairing_tokens (
        token_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL, used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS federation_peers (
        id INTEGER PRIMARY KEY, master_id TEXT NOT NULL UNIQUE,
        master_name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL, revoked_at TEXT
    );
    CREATE TABLE IF NOT EXISTS managed_sites (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, endpoint TEXT NOT NULL UNIQUE,
        remote_id TEXT NOT NULL UNIQUE, key_enc TEXT NOT NULL, ca_cert TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'checking', snapshot_json TEXT NOT NULL DEFAULT '{}',
        last_check TEXT, last_error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
    );
    """)
    c.execute("INSERT OR IGNORE INTO federation_identity(id,instance_id) VALUES(1,?)", (secrets.token_hex(16),))


def _identity(c) -> str:
    return c.execute("SELECT instance_id FROM federation_identity WHERE id=1").fetchone()[0]


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


def validate_endpoint(value: str) -> str:
    """Require a literal private VPN address: no DNS rebinding or public egress."""
    try:
        url = urlsplit(value.strip())
        address = ipaddress.ip_address(url.hostname or "")
        port = url.port
    except (ValueError, TypeError):
        raise HTTPException(400, "Enter an HTTPS URL with a private VPN IP address")
    is_cgnat = address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10")
    if not (address.is_private or is_cgnat) or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        raise HTTPException(400, "The site address must be a private VPN IP")
    if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise HTTPException(400, "Use only the remote GODSEYE origin, without a path or credentials")
    if url.scheme != "https":
        # A lab override is intentionally explicit. Production pairing requires TLS.
        if url.scheme != "http" or os.environ.get("GODSEYE_SITE_ALLOW_HTTP_VPN") != "1":
            raise HTTPException(400, "Remote GODSEYE requires HTTPS over the existing VPN")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"{url.scheme}://{host}" + (f":{port}" if port else "")


def remote_call(endpoint: str, path: str, token: str | None = None,
                data: dict | None = None, method: str = "GET", ca_cert: str = "") -> Any:
    if not path.startswith("/api/v1/federation/"):
        raise ValueError("Not a federation API path")
    payload = json.dumps(data).encode() if data is not None else None
    headers = {"Accept": "application/json", "User-Agent": "GODSEYE-Sites/1"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    context = ssl.create_default_context(cadata=ca_cert or None)
    request = urllib.request.Request(endpoint + path, data=payload, headers=headers, method=method)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise urllib.error.HTTPError(req.full_url, code, "Remote redirect refused", headers, fp)

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise HTTPException(502, "Remote response is too large")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        raise HTTPException(502, f"Remote GODSEYE returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, ValueError) as exc:
        raise HTTPException(502, "Remote GODSEYE could not be reached or verified") from exc


class PairRequest(BaseModel):
    token: str
    master_id: str
    master_name: str = "Master GODSEYE"


class LinkSite(BaseModel):
    name: str
    endpoint: str
    pairing_token: str
    ca_cert: str = ""

    @field_validator("name")
    @classmethod
    def site_name(cls, value):
        value = value.strip()
        if not 2 <= len(value) <= 120:
            raise ValueError("Site name must be 2–120 characters")
        return value

    @field_validator("ca_cert")
    @classmethod
    def ca_limit(cls, value):
        if len(value) > 16_000:
            raise ValueError("CA certificate is too large")
        return value


class SiteName(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def name_limit(cls, value):
        value = value.strip()
        if not 2 <= len(value) <= 120:
            raise ValueError("Site name must be 2–120 characters")
        return value


class RemoteDeviceEdit(BaseModel):
    name: str | None = None
    classification: str | None = None
    notes: str | None = None


class RemoteTicket(BaseModel):
    title: str
    description: str = ""
    priority: str = "medium"


class CloseTicket(BaseModel):
    note: str = "Closed from master GODSEYE"


def register_routes(app, core):
    """Install routes after main.py's normal dependencies have been defined."""
    prefix = "/api/v1"

    def peer(request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer ") or len(auth) > 256:
            raise HTTPException(401, "Site authentication required")
        with core.db() as c:
            row = c.execute("SELECT * FROM federation_peers WHERE key_hash=? AND revoked_at IS NULL",
                            (_digest(auth[7:].strip()),)).fetchone()
        if not row:
            raise HTTPException(401, "Site authentication failed")
        return dict(row)

    def local_site(site_id: int):
        with core.db() as c:
            row = c.execute("SELECT * FROM managed_sites WHERE id=?", (site_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Site not found")
        return dict(row)

    def call_site(row, path, method="GET", data=None):
        return remote_call(row["endpoint"], path, core.decrypt_secret(row["key_enc"]), data, method, row["ca_cert"])

    def public_site(row):
        value = {k: row[k] for k in ("id", "name", "endpoint", "remote_id", "status", "last_check", "last_error", "created_at")}
        value["snapshot"] = json.loads(row["snapshot_json"] or "{}")
        return value

    @app.post(prefix + "/federation/pairing-tokens")
    def pairing_token(request: Request, user=Depends(core.require_admin)):
        token = secrets.token_urlsafe(32)
        expiry = _utcnow() + dt.timedelta(minutes=15)
        with core.db() as c:
            c.execute("DELETE FROM federation_pairing_tokens WHERE expires_at < ?", (core.now(),))
            c.execute("INSERT INTO federation_pairing_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)",
                      (_digest(token), core.now(), expiry.isoformat()))
            core.audit(c, user["username"], "site_pairing_token_created", ip=core.client_ip(request))
        return {"pairing_token": token, "expires_at": expiry.isoformat()}

    @app.post(prefix + "/federation/pair")
    def pair_remote(payload: PairRequest, request: Request):
        if not payload.master_id or len(payload.master_id) > 80 or len(payload.master_name) > 120:
            raise HTTPException(400, "Invalid master identity")
        with core.db() as c:
            own_id = _identity(c)
            if payload.master_id == own_id:
                raise HTTPException(400, "An installation cannot pair with itself")
            active = c.execute("SELECT id FROM federation_peers WHERE revoked_at IS NULL").fetchone()
            if active:
                raise HTTPException(409, "This installation is already paired. Revoke its master before linking another")
            token = c.execute("SELECT * FROM federation_pairing_tokens WHERE token_hash=? AND used_at IS NULL",
                              (_digest(payload.token),)).fetchone()
            if not token or token["expires_at"] < core.now():
                raise HTTPException(401, "Pairing token is invalid or expired")
            key = secrets.token_urlsafe(48)
            c.execute("UPDATE federation_pairing_tokens SET used_at=? WHERE token_hash=?", (core.now(), _digest(payload.token)))
            c.execute("INSERT INTO federation_peers(master_id,master_name,key_hash,created_at) VALUES(?,?,?,?)",
                      (payload.master_id, payload.master_name[:120], _digest(key), core.now()))
            core.audit(c, "site-pairing", "site_master_paired", payload.master_id, ip=core.client_ip(request))
        return {"instance_id": own_id, "api_key": key, "version": core.APP_VERSION}

    @app.get(prefix + "/federation/peers")
    def peers(user=Depends(core.require_admin)):
        with core.db() as c:
            return [dict(r) for r in c.execute("SELECT id,master_name,created_at,revoked_at FROM federation_peers ORDER BY id DESC")]

    @app.post(prefix + "/federation/peers/{peer_id}/revoke")
    def revoke_peer(peer_id: int, request: Request, user=Depends(core.require_admin)):
        with core.db() as c:
            cur = c.execute("UPDATE federation_peers SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (core.now(), peer_id))
            if not cur.rowcount:
                raise HTTPException(404, "Active master not found")
            core.audit(c, user["username"], "site_master_revoked", str(peer_id), ip=core.client_ip(request))
        return {"ok": True}

    @app.get(prefix + "/federation/summary")
    def federation_summary(master=Depends(peer)):
        with core.db() as c:
            devices = c.execute("SELECT count(*) AS total, count(*) FILTER (WHERE status='offline') AS offline FROM devices").fetchone()
            issues = c.execute("SELECT count(*) FROM network_issues WHERE status='open'").fetchone()[0]
            tickets = c.execute("SELECT count(*) FROM tickets WHERE status NOT IN ('closed','resolved')").fetchone()[0]
            scanner = c.execute("SELECT last_success_at FROM scanner_heartbeat WHERE id=1").fetchone()
            return {"instance_id": _identity(c), "version": core.APP_VERSION, "devices": devices["total"],
                    "offline": devices["offline"], "open_findings": issues, "open_tickets": tickets,
                    "scanner_last_success": scanner[0] if scanner else None, "checked_at": core.now()}

    @app.get(prefix + "/federation/devices")
    def federation_devices(master=Depends(peer)):
        with core.db() as c:
            return [dict(r) for r in c.execute("SELECT id,name,hostname,ip,status,classification,device_type,last_seen FROM devices ORDER BY last_seen DESC LIMIT 300")]

    @app.patch(prefix + "/federation/devices/{device_id}")
    def federation_device_edit(device_id: int, payload: RemoteDeviceEdit, request: Request, master=Depends(peer)):
        fields = payload.model_dump(exclude_unset=True)
        if not fields:
            raise HTTPException(400, "Enter a change")
        if fields.get("classification") is not None and fields["classification"] not in core.VALID_CLASSIFICATIONS:
            raise HTTPException(400, "Invalid classification")
        return core.update_device(device_id, core.DeviceUpdate(**fields), request,
                                  admin={"username": "site-master:" + master["master_name"]})

    @app.get(prefix + "/federation/issues")
    def federation_issues(master=Depends(peer)):
        with core.db() as c:
            return [dict(r) for r in c.execute("SELECT id,title,severity,target,status,last_seen FROM network_issues WHERE status='open' ORDER BY last_seen DESC LIMIT 200")]

    @app.post(prefix + "/federation/issues/{issue_id}/resolve")
    def federation_issue_resolve(issue_id: int, request: Request, master=Depends(peer)):
        return core.resolve_intelligence_issue(issue_id, request, user={"username": "site-master:" + master["master_name"]})

    @app.post(prefix + "/federation/issues/{issue_id}/create-ticket")
    def federation_issue_ticket(issue_id: int, request: Request, master=Depends(peer)):
        return core.network_finding_create_ticket(issue_id, request, user={"username": "site-master:" + master["master_name"]})

    @app.get(prefix + "/federation/tickets")
    def federation_tickets(master=Depends(peer)):
        with core.db() as c:
            return [dict(r) for r in c.execute("SELECT id,ticket_number,title,status,priority,updated_at FROM tickets ORDER BY updated_at DESC LIMIT 200")]

    @app.post(prefix + "/federation/tickets")
    def federation_create_ticket(payload: RemoteTicket, request: Request, master=Depends(peer)):
        if not payload.title.strip() or payload.priority not in {"low", "medium", "high", "critical"}:
            raise HTTPException(400, "Enter a title and valid priority")
        return core.ticket_create(core.TicketCreateRequest(title=payload.title, description=payload.description,
                                 priority=payload.priority), request, user={"username": "site-master:" + master["master_name"]})

    @app.post(prefix + "/federation/tickets/{ticket_id}/close")
    def federation_close_ticket(ticket_id: int, payload: CloseTicket, request: Request, master=Depends(peer)):
        return core.ticket_close(ticket_id, core.TicketCloseRequest(note=payload.note), request,
                                 user={"username": "site-master:" + master["master_name"]})

    @app.get(prefix + "/sites")
    def list_sites(user=Depends(core.get_current_user)):
        with core.db() as c:
            return [public_site(dict(r)) for r in c.execute("SELECT * FROM managed_sites ORDER BY name")]

    @app.post(prefix + "/sites")
    def link_site(payload: LinkSite, request: Request, user=Depends(core.require_admin)):
        endpoint = validate_endpoint(payload.endpoint)
        if not 20 <= len(payload.pairing_token) <= 256:
            raise HTTPException(400, "Invalid pairing token")
        with core.db() as c:
            own_id = _identity(c)
            if c.execute("SELECT 1 FROM managed_sites WHERE endpoint=?", (endpoint,)).fetchone():
                raise HTTPException(409, "This site is already linked")
        response = remote_call(endpoint, prefix + "/federation/pair", data={"token": payload.pairing_token,
                               "master_id": own_id, "master_name": "Master GODSEYE"}, method="POST", ca_cert=payload.ca_cert)
        remote_id = response.get("instance_id", "")
        if not remote_id or remote_id == own_id or not response.get("api_key"):
            raise HTTPException(502, "Remote GODSEYE returned an invalid pairing response")
        snapshot = remote_call(endpoint, prefix + "/federation/summary", response["api_key"], ca_cert=payload.ca_cert)
        if snapshot.get("instance_id") != remote_id:
            raise HTTPException(502, "Remote identity changed during pairing")
        with core.db() as c:
            try:
                cur = c.execute("INSERT INTO managed_sites(name,endpoint,remote_id,key_enc,ca_cert,status,snapshot_json,last_check,created_at) VALUES(?,?,?,?,?,'connected',?,?,?)",
                                (payload.name, endpoint, remote_id, core.encrypt_secret(response["api_key"]), payload.ca_cert,
                                 json.dumps(snapshot), core.now(), core.now()))
            except Exception as exc:
                if isinstance(exc, __import__('sqlite3').IntegrityError):
                    raise HTTPException(409, "This installation is already linked") from exc
                raise
            core.audit(c, user["username"], "site_linked", payload.name, endpoint, core.client_ip(request))
            row = c.execute("SELECT * FROM managed_sites WHERE id=?", (cur.lastrowid,)).fetchone()
        return public_site(dict(row))

    @app.patch(prefix + "/sites/{site_id}")
    def rename_site(site_id: int, payload: SiteName, request: Request, user=Depends(core.require_admin)):
        local_site(site_id)
        with core.db() as c:
            c.execute("UPDATE managed_sites SET name=? WHERE id=?", (payload.name, site_id))
            core.audit(c, user["username"], "site_renamed", str(site_id), payload.name, core.client_ip(request))
            return public_site(dict(c.execute("SELECT * FROM managed_sites WHERE id=?", (site_id,)).fetchone()))

    @app.delete(prefix + "/sites/{site_id}")
    def unlink_site(site_id: int, request: Request, user=Depends(core.require_admin)):
        row = local_site(site_id)
        with core.db() as c:
            c.execute("DELETE FROM managed_sites WHERE id=?", (site_id,))
            core.audit(c, user["username"], "site_unlinked", row["name"], ip=core.client_ip(request))
        return {"ok": True, "message": "Link removed. Revoke the master key on the remote installation too."}

    @app.post(prefix + "/sites/{site_id}/refresh")
    def refresh_site(site_id: int, user=Depends(core.get_current_user)):
        row = local_site(site_id)
        try:
            snapshot = call_site(row, prefix + "/federation/summary")
            if snapshot.get("instance_id") != row["remote_id"]:
                raise HTTPException(502, "Remote identity does not match the paired site")
            with core.db() as c:
                c.execute("UPDATE managed_sites SET status='connected',snapshot_json=?,last_check=?,last_error='' WHERE id=?",
                          (json.dumps(snapshot), core.now(), site_id))
        except Exception as exc:
            with core.db() as c:
                c.execute("UPDATE managed_sites SET status='offline',last_check=?,last_error=? WHERE id=?",
                          (core.now(), str(getattr(exc, "detail", "Remote site unavailable"))[:200], site_id))
            raise
        return snapshot

    @app.get(prefix + "/sites/{site_id}/workspace")
    def site_workspace(site_id: int, user=Depends(core.get_current_user)):
        row = local_site(site_id)
        results = {"site": public_site(row)}
        for name, path in (("devices", "/devices"), ("issues", "/issues"), ("tickets", "/tickets")):
            results[name] = call_site(row, prefix + "/federation" + path)
        return results

    @app.patch(prefix + "/sites/{site_id}/devices/{device_id}")
    def site_device_edit(site_id: int, device_id: int, payload: RemoteDeviceEdit, request: Request,
                         user=Depends(core.require_admin)):
        result = call_site(local_site(site_id), f"{prefix}/federation/devices/{device_id}", "PATCH", payload.model_dump(exclude_unset=True))
        with core.db() as c:
            core.audit(c, user["username"], "remote_device_updated", f"{site_id}:{device_id}", ip=core.client_ip(request))
        return result

    @app.post(prefix + "/sites/{site_id}/issues/{issue_id}/{action}")
    def site_issue_action(site_id: int, issue_id: int, action: str, request: Request,
                          user=Depends(core.require_permission("operate"))):
        if action not in {"resolve", "create-ticket"}:
            raise HTTPException(404, "Unknown action")
        result = call_site(local_site(site_id), f"{prefix}/federation/issues/{issue_id}/{action}", "POST", {})
        with core.db() as c:
            core.audit(c, user["username"], "remote_issue_" + action, f"{site_id}:{issue_id}", ip=core.client_ip(request))
        return result

    @app.post(prefix + "/sites/{site_id}/tickets")
    def site_new_ticket(site_id: int, payload: RemoteTicket, request: Request,
                        user=Depends(core.require_permission("operate"))):
        result = call_site(local_site(site_id), prefix + "/federation/tickets", "POST", payload.model_dump())
        with core.db() as c:
            core.audit(c, user["username"], "remote_ticket_created", str(site_id), ip=core.client_ip(request))
        return result

    @app.post(prefix + "/sites/{site_id}/tickets/{ticket_id}/close")
    def site_close_ticket(site_id: int, ticket_id: int, payload: CloseTicket, request: Request,
                          user=Depends(core.require_permission("operate"))):
        result = call_site(local_site(site_id), f"{prefix}/federation/tickets/{ticket_id}/close", "POST", payload.model_dump())
        with core.db() as c:
            core.audit(c, user["username"], "remote_ticket_closed", f"{site_id}:{ticket_id}", ip=core.client_ip(request))
        return result
