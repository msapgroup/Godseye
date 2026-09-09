from __future__ import annotations
import datetime as dt
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

from .auth import generate_totp_secret, hash_password, new_token, totp_provisioning_uri, verify_password, verify_totp
from .diagnostics import diagnose_device, recommendations
from .diagnostic_rules import analyze as analyze_diagnostic
from .plugins import manifest as plugin_manifest
from .discovery import nmap_discover, ip_neighbors, mdns_name
from .integrations import website_check, pihole_test, unifi_login, snmp_test
from .collectors import CollectorManager
from .integration_reporting import IntegrationReportingManager, ensure_schema as ensure_ir_schema, safe_config, sync_integration, build_network_report, generate_report, next_report_time, send_notification, prometheus_metrics
from .appliance_hardening import (TrafficCollector, ensure_schema as ensure_hardening_schema, encrypt_secret, decrypt_secret, migrate_plaintext_secrets, traffic_history, client_bandwidth_estimates, generate_prometheus_key, verify_prometheus_key, retention_config, save_retention, apply_retention, create_backup, list_backups, restore_backup, appliance_health, report_csv_bytes, report_pdf_bytes)
from .production_management import (ProductionManager, ensure_schema as ensure_production_schema, settings as production_settings, save_settings as save_production_settings, config_export, config_import, audit_query, audit_csv, stage_update_bytes, apply_staged_update, preflight_update, https_status)

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("GODSEYE_DB", BASE_DIR / "data" / "godseye.db"))

# A scanner that hasn't reported a successful run in this many seconds is
# treated as unhealthy even if the systemd unit still shows "active" -
# otherwise GODSEYE can look fine on the dashboard while silently doing
# nothing (see /api/v1/health).
HEARTBEAT_STALE_AFTER = int(os.environ.get("GODSEYE_HEARTBEAT_STALE_AFTER", "180"))

VALID_CLASSIFICATIONS = {"new", "known", "ignored", "investigate"}
VALID_ROLES = {"admin", "operator", "auditor", "readonly"}
VALID_RULE_TYPES = {"new_device_burst", "offline_duration"}
VALID_SEVERITIES = {"info", "warning", "critical"}

SESSION_COOKIE = "godseye_session"
CSRF_COOKIE = "godseye_csrf"
SESSION_TTL_SECONDS = int(os.environ.get("GODSEYE_SESSION_TTL", str(60 * 60 * 24 * 7)))  # 7 days absolute cap
IDLE_TIMEOUT_SECONDS = int(os.environ.get("GODSEYE_IDLE_TIMEOUT", "900"))  # 15 min inactivity
COOKIE_SECURE = os.environ.get("GODSEYE_COOKIE_SECURE", "false").lower() == "true"

# Account lockout (NIST 800-63B / DISA STIG AC-7 style: lock the account after
# repeated failures rather than let a client hammer the login endpoint).
MAX_FAILED_ATTEMPTS = int(os.environ.get("GODSEYE_MAX_FAILED_ATTEMPTS", "5"))
LOCKOUT_SECONDS = int(os.environ.get("GODSEYE_LOCKOUT_SECONDS", "900"))  # 15 min

MIN_PASSWORD_LENGTH = int(os.environ.get("GODSEYE_MIN_PASSWORD_LENGTH", "12"))
MAX_PASSWORD_LENGTH = 128  # sane upper bound; not a NIST requirement, just avoids hashing-cost abuse
WEAK_PASSWORDS = {
    "godseye", "password", "password123", "admin", "administrator", "changeme",
    "letmein", "welcome", "qwerty123456", "123456789012", "raspberry", "raspberrypi",
}

# Mandatory periodic password rotation. NIST SP 800-63B section 5.1.1.2
# recommends AGAINST forcing periodic rotation of user-chosen passwords -
# it tends to produce weaker, more predictable passwords ("Summer2024!" ->
# "Summer2025!") without a clear security benefit, and instead recommends
# rotation only on evidence of compromise. Default here is therefore 0
# (disabled). Set to 30 / 90 / 180 if your organization's policy requires
# it regardless (common in older compliance baselines still used in some
# legal and healthcare contexts).
PASSWORD_MAX_AGE_DAYS = int(os.environ.get("GODSEYE_PASSWORD_MAX_AGE_DAYS", "0"))

# When an admin sets someone's password for them (initial seed, a new user
# created by an admin, or an admin-issued reset), the account isn't locked
# out of everything until they change it - they get a grace period during
# which the app works normally with just a reminder banner, and the change
# is only truly enforced once the deadline passes. 0 means enforce
# immediately with no grace period (the old, stricter behavior).
PASSWORD_CHANGE_GRACE_DAYS = int(os.environ.get("GODSEYE_PASSWORD_CHANGE_GRACE_DAYS", "2"))
PASSWORD_HISTORY_COUNT = int(os.environ.get("GODSEYE_PASSWORD_HISTORY_COUNT", "5"))

MFA_PENDING_TTL_SECONDS = int(os.environ.get("GODSEYE_MFA_PENDING_TTL", "300"))  # 5 min to enter a code after password
MFA_BACKUP_CODE_COUNT = 10

# Optional consent/warning banner shown above the login form. Off by default -
# set this to your organization's actual approved banner text if one is required;
# GODSEYE does not ship banner text of its own since that's an organizational
# policy decision, not something a project can supply on your behalf.
LOGIN_BANNER = os.environ.get("GODSEYE_LOGIN_BANNER", "")

EYE_LOGO = """<svg class=\"eye-logo\" viewBox=\"0 0 120 72\" role=\"img\" aria-label=\"GODSEYE\"><path d=\"M8 36 C26 7 94 7 112 36 C94 65 26 65 8 36 Z\" fill=\"#eef7ff\" stroke=\"#8eb9df\" stroke-width=\"3\"/><ellipse cx=\"60\" cy=\"36\" rx=\"25\" ry=\"25\" fill=\"#168fe5\" stroke=\"#07355d\" stroke-width=\"4\"/><circle cx=\"60\" cy=\"36\" r=\"10\" fill=\"#07101c\"/><circle cx=\"65\" cy=\"31\" r=\"4\" fill=\"white\"/></svg>"""

# Only used to seed the very first admin account on a fresh install. Change
# these via env vars before first boot if you don't want the well-known
# default - either way, first login forces a password change (see login()).
ADMIN_DEFAULT_USER = "admin"
# Fresh installs do not ship a usable password. The first-login setup creates it.
ADMIN_DEFAULT_PASSWORD = ""


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def audit(c, actor, action, target=None, details="", ip=None):
    c.execute(
        "INSERT INTO audit_log(actor,action,target,details,ip,created_at) VALUES(?,?,?,?,?,?)",
        (actor, action, target, details, ip, now()),
    )


def check_password_strength(password: str, username: str | None = None):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    if password.lower() in WEAK_PASSWORDS:
        raise ValueError("This password is too common - choose something less guessable")
    if username and password.lower() == username.lower():
        raise ValueError("Password cannot be the same as the username")


def is_password_expired(password_changed_at: str | None) -> bool:
    if PASSWORD_MAX_AGE_DAYS <= 0 or not password_changed_at:
        return False
    age_days = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(password_changed_at)).total_seconds() / 86400
    return age_days >= PASSWORD_MAX_AGE_DAYS


def must_change_deadline() -> str | None:
    """Returns the ISO timestamp an admin-set password must be changed by,
    or None if grace periods are disabled (enforce immediately)."""
    if PASSWORD_CHANGE_GRACE_DAYS <= 0:
        return None
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=PASSWORD_CHANGE_GRACE_DAYS)).isoformat()


def must_change_now(must_change_flag, must_change_by: str | None) -> bool:
    """Whether an admin-set password change is actually enforced yet.
    A flag with no deadline (grace disabled, or a legacy row from before
    grace periods existed) enforces immediately. A flag with a future
    deadline doesn't block access until that deadline passes."""
    if not must_change_flag:
        return False
    if not must_change_by:
        return True
    return dt.datetime.now(dt.timezone.utc) >= dt.datetime.fromisoformat(must_change_by)


def days_until(deadline: str | None) -> int | None:
    if not deadline:
        return None
    remaining = dt.datetime.fromisoformat(deadline) - dt.datetime.now(dt.timezone.utc)
    return max(0, math.ceil(remaining.total_seconds() / 86400))


def check_password_reuse(c, user_id: int, new_password: str, current_salt: str, current_hash: str):
    """Rejects a new password that matches the current one or any of the last
    PASSWORD_HISTORY_COUNT passwords for this account."""
    if verify_password(new_password, current_salt, current_hash):
        raise HTTPException(400, "New password must be different from your current password")
    if PASSWORD_HISTORY_COUNT <= 0:
        return
    history = c.execute(
        "SELECT password_salt, password_hash FROM password_history WHERE user_id=? ORDER BY changed_at DESC LIMIT ?",
        (user_id, PASSWORD_HISTORY_COUNT),
    ).fetchall()
    for h in history:
        if verify_password(new_password, h["password_salt"], h["password_hash"]):
            raise HTTPException(
                400, f"That password was used recently - choose one you haven't used in your last {PASSWORD_HISTORY_COUNT} changes"
            )


def record_password_history(c, user_id: int, old_salt: str, old_hash: str):
    c.execute(
        "INSERT INTO password_history(user_id,password_hash,password_salt,changed_at) VALUES(?,?,?,?)",
        (user_id, old_hash, old_salt, now()),
    )
    if PASSWORD_HISTORY_COUNT > 0:
        c.execute(
            "DELETE FROM password_history WHERE user_id=? AND id NOT IN "
            "(SELECT id FROM password_history WHERE user_id=? ORDER BY changed_at DESC LIMIT ?)",
            (user_id, user_id, PASSWORD_HISTORY_COUNT),
        )


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    return c


def _add_column_if_missing(c, table, column, ddl):
    cols = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db():
    # Mirrors app/scanner.py's init_db(). Both services run this on startup
    # so either one can bootstrap a fresh database; see README's privilege
    # separation note for why the schema isn't owned by a single service.
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY,
            mac TEXT NOT NULL UNIQUE,
            ip TEXT,
            hostname TEXT,
            vendor TEXT,
            name TEXT,
            device_type TEXT,
            status TEXT NOT NULL DEFAULT 'unknown',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            trusted INTEGER NOT NULL DEFAULT 0,
            notes TEXT DEFAULT '',
            offline_escalated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            mac TEXT,
            event_type TEXT NOT NULL,
            ip TEXT,
            created_at TEXT NOT NULL,
            details TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS scanner_heartbeat (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_run_at TEXT,
            last_success_at TEXT,
            last_error TEXT,
            devices_found INTEGER,
            scan_duration_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS scan_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requested_at TEXT NOT NULL,
            requested_by TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            devices_found INTEGER,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scan_requests_status ON scan_requests(status, id);
        CREATE TABLE IF NOT EXISTS integration_checks (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown',
            latency_ms REAL,
            details TEXT DEFAULT '',
            last_checked TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS integration_settings (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            target TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            interval_seconds INTEGER NOT NULL DEFAULT 300,
            options_json TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_sources (
            id INTEGER PRIMARY KEY, mac TEXT NOT NULL, source TEXT NOT NULL,
            ip TEXT, hostname TEXT, vendor TEXT, details TEXT DEFAULT '',
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(mac,source)
        );
        CREATE TABLE IF NOT EXISTS device_ip_history (
            id INTEGER PRIMARY KEY, mac TEXT NOT NULL, ip TEXT NOT NULL,
            source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            UNIQUE(mac,ip,source)
        );
        CREATE TABLE IF NOT EXISTS topology_links (
            id INTEGER PRIMARY KEY, parent TEXT NOT NULL, child TEXT NOT NULL,
            link_type TEXT NOT NULL, details TEXT DEFAULT '', last_seen TEXT NOT NULL,
            UNIQUE(parent,child,link_type)
        );
        CREATE TABLE IF NOT EXISTS network_issues (
            id INTEGER PRIMARY KEY, issue_type TEXT NOT NULL, severity TEXT NOT NULL,
            target TEXT, title TEXT NOT NULL, evidence TEXT DEFAULT '{}',
            recommendation TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'open',
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'readonly',
            must_change_password INTEGER NOT NULL DEFAULT 0,
            must_change_password_by TEXT,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            password_changed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            changed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT DEFAULT '',
            ip TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mfa_secrets (
            user_id INTEGER PRIMARY KEY,
            secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            confirmed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS mfa_backup_codes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            code_salt TEXT NOT NULL,
            used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS mfa_pending (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            params TEXT NOT NULL DEFAULT '{}',
            severity TEXT NOT NULL DEFAULT 'critical',
            created_at TEXT NOT NULL,
            last_triggered_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_pwhistory_user ON password_history(user_id);
        CREATE INDEX IF NOT EXISTS idx_backupcodes_user ON mfa_backup_codes(user_id);
        """)
        _add_column_if_missing(c, "users", "failed_attempts", "failed_attempts INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(c, "users", "locked_until", "locked_until TEXT")
        _add_column_if_missing(c, "users", "password_changed_at", "password_changed_at TEXT")
        _add_column_if_missing(c, "users", "must_change_password_by", "must_change_password_by TEXT")
        _add_column_if_missing(c, "devices", "offline_escalated_at", "offline_escalated_at TEXT")
        _add_column_if_missing(c, "sessions", "last_seen_at", "last_seen_at TEXT")
        # Backfill so enabling GODSEYE_PASSWORD_MAX_AGE_DAYS after upgrading doesn't
        # instantly treat every existing account as already expired.
        c.execute("UPDATE users SET password_changed_at=? WHERE password_changed_at IS NULL", (now(),))
        _add_column_if_missing(c, "devices", "classification", "classification TEXT NOT NULL DEFAULT 'new'")
        _add_column_if_missing(c, "devices", "missed_scans", "missed_scans INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(c, "events", "severity", "severity TEXT NOT NULL DEFAULT 'info'")
        _add_column_if_missing(c, "integration_checks", "monitor_id", "monitor_id INTEGER")
        c.execute("UPDATE devices SET classification='known' WHERE trusted=1 AND classification='new'")

        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            # Fresh install: create the administrator identity with no usable password.
            # The browser first-login setup endpoint assigns the password.
            c.execute(
                "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,"
                "must_change_password_by,created_at,password_changed_at) "
                "VALUES(?,?,?,'admin',1,NULL,?,?)",
                (ADMIN_DEFAULT_USER, "", "", now(), now()),
            )
            print("[GODSEYE] Fresh install: admin account created; first-login password setup is required.")


@asynccontextmanager
async def lifespan(app):
    init_db()
    collector_manager = CollectorManager(db, now)
    app.state.collector_manager = collector_manager
    collector_manager.start()
    with db() as c:
        ensure_ir_schema(c)
        ensure_hardening_schema(c)
        ensure_production_schema(c)
        migrate_plaintext_secrets(c)
    traffic_collector = TrafficCollector(db, int(os.environ.get('GODSEYE_TRAFFIC_SAMPLE_SECONDS','10')))
    app.state.traffic_collector = traffic_collector
    traffic_collector.start()
    integration_reporting_manager = IntegrationReportingManager(db)
    app.state.integration_reporting_manager = integration_reporting_manager
    integration_reporting_manager.start()
    def _scheduled_backup(note):
        path=create_backup(DB_PATH,note)
        with db() as c:
            ensure_hardening_schema(c)
            c.execute("INSERT OR IGNORE INTO backup_runs(filename,created_at,size_bytes,status,note) VALUES(?,?,?,?,?)",(path.name,now(),path.stat().st_size,'complete',note)); c.commit()
        return path
    production_manager=ProductionManager(db,_scheduled_backup)
    app.state.production_manager=production_manager
    production_manager.start()
    yield
    production_manager.stop()
    integration_reporting_manager.stop()
    traffic_collector.stop()
    collector_manager.stop()


app = FastAPI(title="GODSEYE", version="1.6.0", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


router_prefix = "/api/v1"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_len(cls, v):
        check_password_strength(v)
        return v


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "readonly"

    @field_validator("role")
    @classmethod
    def check_role(cls, v):
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
        return v

    @field_validator("password")
    @classmethod
    def check_pw(cls, v, info):
        check_password_strength(v, info.data.get("username"))
        return v


class ResetPasswordRequest(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_len(cls, v):
        check_password_strength(v)
        return v


class MfaVerifyRequest(BaseModel):
    pending_token: str
    code: str


class MfaConfirmRequest(BaseModel):
    code: str


class MfaDisableRequest(BaseModel):
    current_password: str
    code: str


ALLOWED_WHILE_PASSWORD_RESET_REQUIRED = {
    f"{router_prefix}/auth/change-password",
    f"{router_prefix}/auth/logout",
    f"{router_prefix}/auth/me",
}


def get_current_user(request: Request):
    """Auth dependency for every /api/v1 route except /auth/login.

    Uses the double-submit cookie CSRF pattern: the session cookie is
    httponly, the CSRF cookie is not (so the dashboard JS can read it) and
    every mutating request must echo it back in an X-CSRF-Token header. A
    cross-site request can ride the session cookie automatically but can't
    read the CSRF cookie's value to put in that header.

    Also enforces an idle timeout (GODSEYE_IDLE_TIMEOUT) independent of the
    session's absolute expiry, so a forgotten-open tab doesn't stay valid
    indefinitely just because it's within the 7-day absolute window.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Not authenticated")
    with db() as c:
        row = c.execute(
            "SELECT u.id AS id, u.username, u.role, u.must_change_password, u.must_change_password_by, "
            "u.password_changed_at, s.expires_at, s.last_seen_at "
            "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?",
            (token,),
        ).fetchone()
        if not row:
            raise HTTPException(401, "Session expired")
        nowdt = dt.datetime.now(dt.timezone.utc)
        if dt.datetime.fromisoformat(row["expires_at"]) < nowdt:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            raise HTTPException(401, "Session expired")
        if row["last_seen_at"] and (nowdt - dt.datetime.fromisoformat(row["last_seen_at"])).total_seconds() > IDLE_TIMEOUT_SECONDS:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            raise HTTPException(401, "Session timed out due to inactivity")
        c.execute("UPDATE sessions SET last_seen_at=? WHERE token=?", (now(), token))
    password_reset_needed = must_change_now(row["must_change_password"], row["must_change_password_by"]) \
        or is_password_expired(row["password_changed_at"])
    if password_reset_needed and request.url.path not in ALLOWED_WHILE_PASSWORD_RESET_REQUIRED:
        # Enforced here, not just hidden behind the dashboard's modal, so a
        # direct API call can't skip the forced (or expired) password change either.
        raise HTTPException(403, "Password change required before continuing")
    if request.method in {"POST", "PATCH", "DELETE", "PUT"}:
        header = request.headers.get("x-csrf-token")
        cookie = request.cookies.get(CSRF_COOKIE)
        if not header or not cookie or not hmac.compare_digest(header, cookie):
            raise HTTPException(403, "CSRF token missing or invalid")
    return row


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required")
    return user

ROLE_PERMISSIONS = {
    "admin": {"*"},
    "operator": {"operate", "findings.resolve", "reports.generate", "notifications.retry", "integrations.sync"},
    "auditor": {"audit.read", "reports.read"},
    "readonly": set(),
}

def require_permission(permission: str):
    def dep(user=Depends(get_current_user)):
        perms=ROLE_PERMISSIONS.get(user["role"], set())
        if "*" not in perms and permission not in perms:
            raise HTTPException(403, f"Permission required: {permission}")
        return user
    return dep


def _issue_session(c, user_id: int) -> tuple[str, str]:
    """Creates a session row and returns (session_token, csrf_token). Caller
    is responsible for setting the cookies via _set_session_cookies."""
    token, csrf_token = new_token(), new_token()
    expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()
    c.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))  # opportunistic cleanup
    c.execute(
        "INSERT INTO sessions(token,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)",
        (token, user_id, now(), expires_at, now()),
    )
    return token, csrf_token


def _set_session_cookies(response: Response, token: str, csrf_token: str):
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", secure=COOKIE_SECURE, max_age=SESSION_TTL_SECONDS, path="/")
    response.set_cookie(CSRF_COOKIE, csrf_token, httponly=False, samesite="lax", secure=COOKIE_SECURE, max_age=SESSION_TTL_SECONDS, path="/")


def _login_response(user) -> dict:
    hard_blocked = must_change_now(user["must_change_password"], user["must_change_password_by"]) \
        or is_password_expired(user["password_changed_at"])
    resp = {
        "ok": True,
        "username": user["username"],
        "role": user["role"],
        "must_change_password": hard_blocked,
    }
    if user["must_change_password"] and not hard_blocked:
        # Still in the grace period - not blocked, but the dashboard should
        # show a reminder rather than stay silent about it.
        resp["password_change_reminder_days"] = days_until(user["must_change_password_by"])
    return resp


@app.get(f"{router_prefix}/auth/csrf")
def csrf_bootstrap(response: Response):
    """Issue a CSRF cookie before the browser makes authenticated mutations."""
    token = new_token()
    response.set_cookie(CSRF_COOKIE, token, httponly=False, samesite="lax", secure=COOKIE_SECURE, max_age=SESSION_TTL_SECONDS, path="/")
    return {"ok": True}


@app.get(f"{router_prefix}/auth/setup/status")
def setup_status():
    with db() as c:
        user = c.execute("SELECT id,username,password_hash FROM users WHERE username=?", ("admin",)).fetchone()
    return {"setup_required": bool(user and not user["password_hash"]), "username": "admin"}


@app.post(f"{router_prefix}/auth/setup")
def initial_setup(payload: ChangePasswordRequest, request: Request):
    # One-time bootstrap. No session exists yet, so this endpoint is intentionally
    # limited to an admin row whose password is still blank.
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE username=?", ("admin",)).fetchone()
        if not user or user["password_hash"]:
            raise HTTPException(409, "Initial setup has already been completed")
        check_password_strength(payload.new_password, "admin")
        salt, hashed = hash_password(payload.new_password)
        c.execute("UPDATE users SET password_hash=?,password_salt=?,must_change_password=0,must_change_password_by=NULL,password_changed_at=? WHERE id=?",
                  (hashed, salt, now(), user["id"]))
        audit(c, "system", "initial_admin_password_set", target="admin", ip=client_ip(request))
    return {"ok": True, "username": "admin"}


@app.post(f"{router_prefix}/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    ip = client_ip(request)
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE username=?", (payload.username,)).fetchone()

        if user and user["locked_until"]:
            if dt.datetime.fromisoformat(user["locked_until"]) > dt.datetime.now(dt.timezone.utc):
                audit(c, payload.username, "login_blocked_locked", ip=ip)
                raise HTTPException(423, "Account locked due to repeated failed logins. Try again later.")
            c.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?", (user["id"],))

        if not user or not verify_password(payload.password, user["password_salt"], user["password_hash"]):
            if user:
                attempts = user["failed_attempts"] + 1
                if attempts >= MAX_FAILED_ATTEMPTS:
                    locked_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=LOCKOUT_SECONDS)).isoformat()
                    c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", (attempts, locked_until, user["id"]))
                    audit(c, payload.username, "account_locked", details=f"{attempts} failed attempts", ip=ip)
                else:
                    c.execute("UPDATE users SET failed_attempts=? WHERE id=?", (attempts, user["id"]))
            audit(c, payload.username, "login_failed", ip=ip)
            # Same generic message whether the username exists or not, so this
            # endpoint doesn't double as a username-enumeration oracle.
            raise HTTPException(401, "Invalid username or password")

        mfa = c.execute("SELECT 1 FROM mfa_secrets WHERE user_id=? AND enabled=1", (user["id"],)).fetchone()
        if mfa:
            # Password is correct, but a second factor is still required - don't
            # issue a session yet. A short-lived pending token carries the user
            # through to /auth/mfa/verify without exposing a real session cookie.
            pending_token = new_token()
            expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=MFA_PENDING_TTL_SECONDS)).isoformat()
            c.execute("DELETE FROM mfa_pending WHERE expires_at < ?", (now(),))
            c.execute(
                "INSERT INTO mfa_pending(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                (pending_token, user["id"], now(), expires_at),
            )
            c.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
            audit(c, user["username"], "login_password_ok_awaiting_mfa", ip=ip)
            return {"ok": True, "mfa_required": True, "pending_token": pending_token}

        token, csrf_token = _issue_session(c, user["id"])
        c.execute("UPDATE users SET last_login_at=?, failed_attempts=0, locked_until=NULL WHERE id=?", (now(), user["id"]))
        audit(c, user["username"], "login_success", ip=ip)
    _set_session_cookies(response, token, csrf_token)
    return _login_response(user)


@app.post(f"{router_prefix}/auth/mfa/verify")
def mfa_verify(payload: MfaVerifyRequest, request: Request, response: Response):
    ip = client_ip(request)
    with db() as c:
        pending = c.execute("SELECT * FROM mfa_pending WHERE token=?", (payload.pending_token,)).fetchone()
        if not pending:
            raise HTTPException(401, "MFA session expired - please log in again")
        if dt.datetime.fromisoformat(pending["expires_at"]) < dt.datetime.now(dt.timezone.utc):
            c.execute("DELETE FROM mfa_pending WHERE token=?", (payload.pending_token,))
            raise HTTPException(401, "MFA session expired - please log in again")

        user = c.execute("SELECT * FROM users WHERE id=?", (pending["user_id"],)).fetchone()
        mfa = c.execute("SELECT secret FROM mfa_secrets WHERE user_id=? AND enabled=1", (user["id"],)).fetchone()

        code = payload.code.strip()
        code_ok = bool(mfa) and verify_totp(mfa["secret"], code)
        backup_used = False
        if not code_ok:
            candidates = c.execute(
                "SELECT id, code_hash, code_salt FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL",
                (user["id"],),
            ).fetchall()
            for cand in candidates:
                if verify_password(code, cand["code_salt"], cand["code_hash"]):
                    c.execute("UPDATE mfa_backup_codes SET used_at=? WHERE id=?", (now(), cand["id"]))
                    code_ok, backup_used = True, True
                    break

        if not code_ok:
            audit(c, user["username"], "mfa_verify_failed", ip=ip)
            raise HTTPException(401, "Invalid authentication code")

        c.execute("DELETE FROM mfa_pending WHERE token=?", (payload.pending_token,))
        token, csrf_token = _issue_session(c, user["id"])
        c.execute("UPDATE users SET last_login_at=? WHERE id=?", (now(), user["id"]))
        remaining = None
        if backup_used:
            remaining = c.execute(
                "SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL", (user["id"],)
            ).fetchone()[0]
        audit(c, user["username"], "mfa_backup_code_used" if backup_used else "login_success_mfa", ip=ip)
    _set_session_cookies(response, token, csrf_token)
    resp = _login_response(user)
    if backup_used:
        resp["backup_codes_remaining"] = remaining
    return resp


@app.post(f"{router_prefix}/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with db() as c:
            row = c.execute(
                "SELECT u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (token,)
            ).fetchone()
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            if row:
                audit(c, row["username"], "logout", ip=client_ip(request))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"ok": True}


@app.get(f"{router_prefix}/auth/me")
def me(user=Depends(get_current_user)):
    with db() as c:
        mfa = c.execute("SELECT enabled FROM mfa_secrets WHERE user_id=?", (user["id"],)).fetchone()
    hard_blocked = must_change_now(user["must_change_password"], user["must_change_password_by"]) \
        or is_password_expired(user["password_changed_at"])
    resp = {
        "username": user["username"],
        "role": user["role"],
        "must_change_password": hard_blocked,
        "mfa_enabled": bool(mfa and mfa["enabled"]),
    }
    if user["must_change_password"] and not hard_blocked:
        resp["password_change_reminder_days"] = days_until(user["must_change_password_by"])
    if PASSWORD_MAX_AGE_DAYS > 0 and user["password_changed_at"]:
        age_days = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(user["password_changed_at"])).total_seconds() / 86400
        resp["password_expires_in_days"] = max(0, round(PASSWORD_MAX_AGE_DAYS - age_days))
    return resp


@app.post(f"{router_prefix}/auth/change-password")
def change_password(payload: ChangePasswordRequest, request: Request, user=Depends(get_current_user)):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(payload.current_password, row["password_salt"], row["password_hash"]):
            audit(c, user["username"], "password_change_failed", ip=client_ip(request))
            raise HTTPException(401, "Current password is incorrect")
        check_password_reuse(c, user["id"], payload.new_password, row["password_salt"], row["password_hash"])
        record_password_history(c, user["id"], row["password_salt"], row["password_hash"])
        salt, hashed = hash_password(payload.new_password)
        c.execute(
            "UPDATE users SET password_hash=?,password_salt=?,must_change_password=0,"
            "must_change_password_by=NULL,password_changed_at=? WHERE id=?",
            (hashed, salt, now(), user["id"]),
        )
        # Invalidate every session for this account, including the current one - if the
        # old password had leaked, this makes sure it can't keep a session alive.
        # The dashboard re-prompts for login with the new password right after this call.
        c.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        audit(c, user["username"], "password_changed", ip=client_ip(request))
    return {"ok": True}


@app.post(f"{router_prefix}/auth/mfa/setup")
def mfa_setup(request: Request, user=Depends(get_current_user)):
    with db() as c:
        existing = c.execute("SELECT enabled FROM mfa_secrets WHERE user_id=?", (user["id"],)).fetchone()
        if existing and existing["enabled"]:
            raise HTTPException(400, "MFA is already enabled on this account - disable it before setting up a new device")
        secret = generate_totp_secret()
        c.execute(
            "INSERT OR REPLACE INTO mfa_secrets(user_id,secret,enabled,created_at) VALUES(?,?,0,?)",
            (user["id"], secret, now()),
        )
        audit(c, user["username"], "mfa_setup_started", ip=client_ip(request))
    grouped_secret = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return {"ok": True, "secret": grouped_secret, "otpauth_uri": totp_provisioning_uri(secret, user["username"])}


@app.post(f"{router_prefix}/auth/mfa/confirm")
def mfa_confirm(payload: MfaConfirmRequest, request: Request, user=Depends(get_current_user)):
    with db() as c:
        row = c.execute("SELECT secret FROM mfa_secrets WHERE user_id=? AND enabled=0", (user["id"],)).fetchone()
        if not row:
            raise HTTPException(400, "No pending MFA setup found - call /auth/mfa/setup first")
        if not verify_totp(row["secret"], payload.code.strip()):
            audit(c, user["username"], "mfa_confirm_failed", ip=client_ip(request))
            raise HTTPException(401, "Incorrect code - check your authenticator app and try again")
        c.execute("UPDATE mfa_secrets SET enabled=1, confirmed_at=? WHERE user_id=?", (now(), user["id"]))
        c.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user["id"],))
        codes = []
        for _ in range(MFA_BACKUP_CODE_COUNT):
            raw = secrets.token_hex(5)
            code = f"{raw[:5]}-{raw[5:]}"
            codes.append(code)
            salt, hashed = hash_password(code)
            c.execute(
                "INSERT INTO mfa_backup_codes(user_id,code_hash,code_salt,used_at) VALUES(?,?,?,NULL)",
                (user["id"], hashed, salt),
            )
        audit(c, user["username"], "mfa_enabled", ip=client_ip(request))
    return {"ok": True, "backup_codes": codes}


@app.post(f"{router_prefix}/auth/mfa/disable")
def mfa_disable(payload: MfaDisableRequest, request: Request, user=Depends(get_current_user)):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(payload.current_password, row["password_salt"], row["password_hash"]):
            raise HTTPException(401, "Current password is incorrect")
        mfa = c.execute("SELECT secret FROM mfa_secrets WHERE user_id=? AND enabled=1", (user["id"],)).fetchone()
        if not mfa:
            raise HTTPException(400, "MFA is not enabled on this account")
        code = payload.code.strip()
        code_ok = verify_totp(mfa["secret"], code)
        if not code_ok:
            candidates = c.execute(
                "SELECT id, code_hash, code_salt FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL",
                (user["id"],),
            ).fetchall()
            code_ok = any(verify_password(code, cand["code_salt"], cand["code_hash"]) for cand in candidates)
        if not code_ok:
            raise HTTPException(401, "Invalid authentication code")
        c.execute("DELETE FROM mfa_secrets WHERE user_id=?", (user["id"],))
        c.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user["id"],))
        audit(c, user["username"], "mfa_disabled", ip=client_ip(request))
    return {"ok": True}


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------

@app.get(f"{router_prefix}/users")
def list_users(admin=Depends(require_admin)):
    with db() as c:
        rows = c.execute(
            "SELECT u.id,u.username,u.role,u.must_change_password,u.must_change_password_by,"
            "u.created_at,u.last_login_at,u.password_changed_at, "
            "COALESCE((SELECT enabled FROM mfa_secrets m WHERE m.user_id=u.id), 0) AS mfa_enabled "
            "FROM users u ORDER BY u.id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post(f"{router_prefix}/users")
def create_user(payload: CreateUserRequest, request: Request, admin=Depends(require_admin)):
    salt, hashed = hash_password(payload.password)
    with db() as c:
        try:
            c.execute(
                "INSERT INTO users(username,password_hash,password_salt,role,must_change_password,"
                "must_change_password_by,created_at,password_changed_at) "
                "VALUES(?,?,?,?,1,?,?,?)",
                (payload.username, hashed, salt, payload.role, must_change_deadline(), now(), now()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username already exists")
        audit(c, admin["username"], "user_created", target=payload.username, details=f"role={payload.role}", ip=client_ip(request))
    return {"ok": True}


@app.post(f"{router_prefix}/users/{{user_id}}/reset-password")
def admin_reset_password(user_id: int, payload: ResetPasswordRequest, request: Request, admin=Depends(require_admin)):
    with db() as c:
        target = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        check_password_reuse(c, user_id, payload.new_password, target["password_salt"], target["password_hash"])
        record_password_history(c, user_id, target["password_salt"], target["password_hash"])
        salt, hashed = hash_password(payload.new_password)
        c.execute(
            "UPDATE users SET password_hash=?,password_salt=?,must_change_password=1,"
            "must_change_password_by=?,failed_attempts=0,locked_until=NULL,password_changed_at=? WHERE id=?",
            (hashed, salt, must_change_deadline(), now(), user_id),
        )
        c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit(c, admin["username"], "password_reset_by_admin", target=target["username"] if target else str(user_id), ip=client_ip(request))
    return {"ok": True}


@app.delete(f"{router_prefix}/users/{{user_id}}")
def delete_user(user_id: int, request: Request, admin=Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(400, "Cannot delete the account you're currently logged in as")
    with db() as c:
        target = c.execute("SELECT username, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        if target["role"] == "admin":
            remaining_admins = c.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND id != ?", (user_id,)
            ).fetchone()[0]
            if remaining_admins == 0:
                raise HTTPException(400, "Cannot delete the last admin account")
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit(c, admin["username"], "user_deleted", target=target["username"], ip=client_ip(request))
    return {"ok": True}


@app.post(f"{router_prefix}/users/{{user_id}}/mfa/reset")
def admin_reset_mfa(user_id: int, request: Request, admin=Depends(require_admin)):
    # For lost-device recovery: an admin can turn MFA off for another account
    # (never on - enrollment requires access to that person's own authenticator
    # app), after which the user re-enrolls a new device themselves.
    with db() as c:
        target = c.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        c.execute("DELETE FROM mfa_secrets WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user_id,))
        audit(c, admin["username"], "mfa_reset_by_admin", target=target["username"], ip=client_ip(request))
    return {"ok": True}


@app.get(f"{router_prefix}/audit")
def audit_log(limit: int = 200, admin=Depends(require_permission("audit.read"))):
    limit = min(max(limit, 1), 1000)
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]


# ---------------------------------------------------------------------------
# Devices / events / health (any authenticated user can view; admin-only to mutate)
# ---------------------------------------------------------------------------

class DeviceUpdate(BaseModel):
    name: str | None = None
    classification: str | None = None
    notes: str | None = None
    device_type: str | None = None

    @field_validator("classification")
    @classmethod
    def check_classification(cls, v):
        if v is not None and v not in VALID_CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {sorted(VALID_CLASSIFICATIONS)}")
        return v


@app.get(f"{router_prefix}/health")
def health(user=Depends(get_current_user)):
    with db() as c:
        total = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = c.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]
        needs_review = c.execute(
            "SELECT COUNT(*) FROM devices WHERE classification IN ('new','investigate')"
        ).fetchone()[0]
        events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        hb = c.execute("SELECT * FROM scanner_heartbeat WHERE id=1").fetchone()

    scanner_ok = False
    scanner_detail = "scanner has not reported in yet"
    if hb and hb["last_success_at"]:
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(hb["last_success_at"])).total_seconds()
        scanner_ok = age <= HEARTBEAT_STALE_AFTER
        scanner_detail = f"last successful scan {int(age)}s ago" if scanner_ok else \
            f"no successful scan in {int(age)}s (stale, threshold {HEARTBEAT_STALE_AFTER}s)"

    return {
        "ok": True,
        "total": total,
        "online": online,
        "unknown": needs_review,  # kept for backward compatibility with the existing dashboard
        "needs_review": needs_review,
        "events": events,
        "scanner": {
            "healthy": scanner_ok,
            "detail": scanner_detail,
            "last_run_at": hb["last_run_at"] if hb else None,
            "last_success_at": hb["last_success_at"] if hb else None,
            "last_error": hb["last_error"] if hb else None,
            "devices_found": hb["devices_found"] if hb else None,
            "scan_duration_ms": hb["scan_duration_ms"] if hb else None,
        },
    }


@app.get(f"{router_prefix}/devices")
def devices(search: str | None = None, status: str | None = None, classification: str | None = None,
            user=Depends(get_current_user)):
    query = "SELECT * FROM devices WHERE 1=1"
    values = []
    if search:
        query += " AND (mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ? OR name LIKE ?)"
        term = f"%{search}%"
        values += [term] * 5
    if status in {"online", "suspected_offline", "offline"}:
        query += " AND status=?"
        values.append(status)
    if classification in VALID_CLASSIFICATIONS:
        query += " AND classification=?"
        values.append(classification)
    query += " ORDER BY CASE status WHEN 'online' THEN 0 WHEN 'suspected_offline' THEN 1 ELSE 2 END, " \
             "CASE classification WHEN 'new' THEN 0 WHEN 'investigate' THEN 1 ELSE 2 END, last_seen DESC"
    with db() as c:
        return [dict(r) for r in c.execute(query, values)]


@app.patch(f"{router_prefix}/devices/{{device_id}}")
def update_device(device_id: int, payload: DeviceUpdate, request: Request, admin=Depends(require_admin)):
    fields, values = [], []
    for field in ("name", "classification", "notes", "device_type"):
        value = getattr(payload, field)
        if value is not None:
            fields.append(f"{field}=?")
            values.append(value)
    if not fields:
        return {"ok": True}
    values.append(device_id)
    with db() as c:
        cur = c.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(404, "Device not found")
        device = c.execute("SELECT mac FROM devices WHERE id=?", (device_id,)).fetchone()
        audit(c, admin["username"], "device_updated", target=device["mac"] if device else str(device_id),
              details=", ".join(fields), ip=client_ip(request))
    return {"ok": True}


@app.get(f"{router_prefix}/events")
def events(limit: int = 100, severity: str | None = None, user=Depends(get_current_user)):
    limit = min(max(limit, 1), 500)
    query = "SELECT * FROM events WHERE 1=1"
    values = []
    if severity in {"info", "warning", "critical"}:
        query += " AND severity=?"
        values.append(severity)
    query += " ORDER BY id DESC LIMIT ?"
    values.append(limit)
    with db() as c:
        return [dict(r) for r in c.execute(query, values)]


@app.get(f"{router_prefix}/devices/{{device_id}}/events")
def device_events(device_id: int, limit: int = 200, user=Depends(get_current_user)):
    limit = min(max(limit, 1), 500)
    with db() as c:
        device = c.execute("SELECT mac FROM devices WHERE id=?", (device_id,)).fetchone()
        if not device:
            raise HTTPException(404, "Device not found")
        return [dict(r) for r in c.execute(
            "SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT ?", (device["mac"], limit)
        )]


@app.get(f"{router_prefix}/devices/{{device_id}}")
def device_detail(device_id: int, user=Depends(get_current_user)):
    with db() as c:
        row = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Device not found")
        return dict(row)


@app.get(f"{router_prefix}/devices/{{device_id}}/intelligence")
def device_intelligence_report(device_id: int, user=Depends(get_current_user)):
    from .device_intelligence import build_device_intelligence
    with db() as c:
        report = build_device_intelligence(c, device_id)
    if report is None:
        raise HTTPException(404, "Device not found")
    return report


@app.post(f"{router_prefix}/devices/{{device_id}}/diagnose")
def device_diagnose(device_id: int, user=Depends(require_permission("operate"))):
    from .tools import ping, device_info
    with db() as c:
        row = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Device not found")
    if not row["ip"]:
        raise HTTPException(400, "Device does not currently have an IP address")
    p = ping(row["ip"], 4)
    info = device_info(row["ip"])
    from .tools import dns
    dns_result = dns(row["hostname"]) if row["hostname"] else None
    with db() as c:
        from .remediation import record_device_diagnostic
        record_device_diagnostic(c,row,p,dns_result)
    recs = []
    if not p.get("ok"):
        recs.append("The device did not answer ping. Check power, network association, DHCP state, and local firewall policy.")
    elif (p.get("packet_loss_percent") or 0) >= 10:
        recs.append("Packet loss is elevated. Check Wi-Fi signal, cabling, AP/switch health, and congestion.")
    if not recs:
        recs.append("Basic reachability looks healthy. Use Port Scan or Traceroute for deeper investigation if needed.")
    return {"ok": bool(p.get("ok")), "device_id": device_id, "target": row["ip"], "ping": p, "dns": dns_result, "device_info": info, "recommendations": recs}


@app.post(f"{router_prefix}/devices/{{device_id}}/recheck")
def device_recheck(device_id: int, request: Request, admin=Depends(require_permission("operate"))):
    from .tools import ping
    with db() as c:
        row = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Device not found")
        if not row["ip"]:
            raise HTTPException(400, "Device does not currently have an IP address")
        result = ping(row["ip"], 2)
        from .remediation import record_device_diagnostic
        record_device_diagnostic(c,row,result,None)
        ts = now()
        if result.get("ok"):
            c.execute("UPDATE devices SET status='online',last_seen=?,missed_scans=0,offline_escalated_at=NULL WHERE id=?", (ts, device_id))
            event_type, details, severity = "device_recheck_ok", "Manual recheck confirmed the device is reachable", "info"
        else:
            event_type, details, severity = "device_recheck_failed", "Manual recheck could not confirm device reachability", "warning"
        c.execute("INSERT INTO events(mac,event_type,ip,created_at,details,severity) VALUES(?,?,?,?,?,?)",
                  (row["mac"], event_type, row["ip"], ts, details, severity))
        audit(c, admin["username"], "device_rechecked", target=row["mac"], details=details, ip=client_ip(request))
    return {"ok": bool(result.get("ok")), "device_id": device_id, "result": result}


@app.post(f"{router_prefix}/scan")
def manual_scan(request: Request, admin=Depends(require_permission("operate"))):
    # Queue a scan in SQLite. The privileged scanner service polls this table
    # every second between normal scan cycles, so Scan Now does not depend on
    # a filesystem flag or a 60-second polling boundary.
    with db() as c:
        cur = c.execute(
            "INSERT INTO scan_requests(requested_at,requested_by,status) VALUES(?,?, 'pending')",
            (now(), admin["username"]),
        )
        request_id = cur.lastrowid
        audit(c, admin["username"], "manual_scan_requested", target=str(request_id), ip=client_ip(request))
    return {"ok": True, "request_id": request_id, "message": "Scan queued"}


@app.get(f"{router_prefix}/scan/status")
def scan_status(user=Depends(get_current_user)):
    with db() as c:
        row = c.execute("SELECT * FROM scan_requests ORDER BY id DESC LIMIT 1").fetchone()
        hb = c.execute("SELECT * FROM scanner_heartbeat WHERE id=1").fetchone()
    return {"request": dict(row) if row else None, "heartbeat": dict(hb) if hb else None}


class DeviceCreate(BaseModel):
    name: str
    ip: str | None = None
    mac: str
    vendor: str | None = None
    device_type: str | None = None
    classification: str = "known"
    notes: str = ""

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, v):
        if v not in VALID_CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {sorted(VALID_CLASSIFICATIONS)}")
        return v

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, v):
        value = v.strip().lower().replace("-", ":")
        if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", value):
            raise ValueError("MAC address must look like AA:BB:CC:DD:EE:FF")
        return value


@app.post(f"{router_prefix}/devices")
def create_device(payload: DeviceCreate, request: Request, admin=Depends(require_admin)):
    timestamp = now()
    with db() as c:
        existing = c.execute("SELECT id FROM devices WHERE mac=?", (payload.mac,)).fetchone()
        if existing:
            raise HTTPException(409, "A device with that MAC address already exists")
        c.execute(
            "INSERT INTO devices(mac,ip,hostname,vendor,name,device_type,status,first_seen,last_seen,classification,notes,missed_scans) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,0)",
            (payload.mac, payload.ip, None, payload.vendor, payload.name, payload.device_type or "unknown",
             "online" if payload.ip else "unknown", timestamp, timestamp, payload.classification, payload.notes),
        )
        from .intelligence import correlate_device
        correlate_device(c, payload.mac, payload.ip, None, payload.vendor, source="manual", details={"name": payload.name, "device_type": payload.device_type})
        audit(c, admin["username"], "device_added", target=payload.mac, details=payload.name, ip=client_ip(request))
    return {"ok": True, "message": "Device added", "mac": payload.mac}


# ---------------------------------------------------------------------------
# Alert rules (admin only to manage; the scanner service evaluates them)
# ---------------------------------------------------------------------------

class RuleCreate(BaseModel):
    name: str
    rule_type: str
    params: dict
    severity: str = "critical"
    enabled: bool = True

    @field_validator("rule_type")
    @classmethod
    def check_type(cls, v):
        if v not in VALID_RULE_TYPES:
            raise ValueError(f"rule_type must be one of {sorted(VALID_RULE_TYPES)}")
        return v

    @field_validator("severity")
    @classmethod
    def check_sev(cls, v):
        if v not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        return v

    @field_validator("params")
    @classmethod
    def check_params(cls, v, info):
        rule_type = info.data.get("rule_type")
        if rule_type == "new_device_burst":
            if "count" not in v or "window_minutes" not in v:
                raise ValueError("new_device_burst params need 'count' and 'window_minutes'")
            if not (isinstance(v["count"], (int, float)) and v["count"] > 0):
                raise ValueError("'count' must be a positive number")
            if not (isinstance(v["window_minutes"], (int, float)) and v["window_minutes"] > 0):
                raise ValueError("'window_minutes' must be a positive number")
        elif rule_type == "offline_duration":
            if "minutes" not in v:
                raise ValueError("offline_duration params need 'minutes'")
            if not (isinstance(v["minutes"], (int, float)) and v["minutes"] > 0):
                raise ValueError("'minutes' must be a positive number")
            classes = v.get("classifications")
            if classes is not None:
                if not isinstance(classes, list) or not set(classes).issubset(VALID_CLASSIFICATIONS):
                    raise ValueError(f"'classifications' must be a list drawn from {sorted(VALID_CLASSIFICATIONS)}")
        return v


class RuleUpdate(BaseModel):
    enabled: bool | None = None


@app.get(f"{router_prefix}/rules")
def list_rules(user=Depends(get_current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM rules ORDER BY id").fetchall()
    return [dict(r) for r in rows]


@app.post(f"{router_prefix}/rules")
def create_rule(payload: RuleCreate, request: Request, admin=Depends(require_admin)):
    with db() as c:
        c.execute(
            "INSERT INTO rules(name,rule_type,enabled,params,severity,created_at) VALUES(?,?,?,?,?,?)",
            (payload.name, payload.rule_type, int(payload.enabled), json.dumps(payload.params), payload.severity, now()),
        )
        audit(c, admin["username"], "rule_created", target=payload.name,
              details=f"type={payload.rule_type}", ip=client_ip(request))
    return {"ok": True}


@app.patch(f"{router_prefix}/rules/{{rule_id}}")
def update_rule(rule_id: int, payload: RuleUpdate, request: Request, admin=Depends(require_admin)):
    if payload.enabled is None:
        return {"ok": True}
    with db() as c:
        cur = c.execute("UPDATE rules SET enabled=? WHERE id=?", (int(payload.enabled), rule_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Rule not found")
        audit(c, admin["username"], "rule_toggled", target=str(rule_id),
              details=f"enabled={payload.enabled}", ip=client_ip(request))
    return {"ok": True}


@app.delete(f"{router_prefix}/rules/{{rule_id}}")
def delete_rule(rule_id: int, request: Request, admin=Depends(require_admin)):
    with db() as c:
        rule = c.execute("SELECT name FROM rules WHERE id=?", (rule_id,)).fetchone()
        if not rule:
            raise HTTPException(404, "Rule not found")
        c.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        audit(c, admin["username"], "rule_deleted", target=rule["name"], ip=client_ip(request))
    return {"ok": True}



@app.get(f"{router_prefix}/plugins")
def plugins(user=Depends(get_current_user)):
    """Return the installed GODSEYE capability/plugin manifest."""
    return plugin_manifest()


class DiagnosticRequest(BaseModel):
    host: str
    count: int = 4

    @field_validator("host")
    @classmethod
    def validate_host(cls, value):
        value = value.strip()
        if not value or len(value) > 253:
            raise ValueError("Invalid host")
        return value


@app.post(f"{router_prefix}/diagnostics/host")
def diagnostic_host(req: DiagnosticRequest, user=Depends(require_permission("operate"))):
    try:
        result = diagnose_device(req.host)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    result["analysis"] = analyze_diagnostic({
        "ping": next((x for x in result["tests"] if x["test"] == "ping"), {}),
        "dns": {"ok": True},
        "recommendations": [],
    })
    result["recommendations"] = recommendations(result)
    return result


@app.get(f"{router_prefix}/diagnostics/gateway")
def diagnostic_gateway(user=Depends(get_current_user)):
    from .tools import gateway
    return gateway()


@app.get(f"{router_prefix}/diagnostics/internet")
def diagnostic_internet(user=Depends(get_current_user)):
    from .tools import internet
    return internet()


@app.get(f"{router_prefix}/discovery/neighbors")
def discovery_neighbors(user=Depends(get_current_user)):
    return ip_neighbors()


@app.get(f"{router_prefix}/discovery/nmap")
def discovery_nmap(target: str = "192.168.1.0/24", user=Depends(require_permission("operate"))):
    # Keep the built-in UI focused on local networks. A caller must provide a
    # private/link-local IPv4/IPv6 network rather than accidentally scanning
    # public Internet address space from the Pi.
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise HTTPException(400, "target must be a valid IP network")
    if not (network.is_private or network.is_link_local):
        raise HTTPException(400, "GODSEYE Nmap discovery is limited to private/link-local networks")
    return nmap_discover(str(network))


@app.get(f"{router_prefix}/discovery/name")
def discovery_name(ip: str, user=Depends(get_current_user)):
    return mdns_name(ip)




# ---------------------------------------------------------------------------
# Device intelligence / correlation
# ---------------------------------------------------------------------------
@app.get(f"{router_prefix}/intelligence/devices/{{mac}}/sources")
def device_sources(mac: str, user=Depends(get_current_user)):
    with db() as c:
        rows=c.execute("SELECT * FROM device_sources WHERE mac=? ORDER BY source",(mac.lower(),)).fetchall()
    return [dict(r) for r in rows]

@app.get(f"{router_prefix}/intelligence/devices/{{mac}}/ip-history")
def device_ip_history(mac: str, user=Depends(get_current_user)):
    with db() as c:
        rows=c.execute("SELECT * FROM device_ip_history WHERE mac=? ORDER BY last_seen DESC",(mac.lower(),)).fetchall()
    return [dict(r) for r in rows]

@app.get(f"{router_prefix}/intelligence/issues")
def intelligence_issues(status: str = "open", user=Depends(get_current_user)):
    with db() as c:
        if status == "all":
            rows=c.execute("SELECT * FROM network_issues ORDER BY last_seen DESC LIMIT 200").fetchall()
        else:
            rows=c.execute("SELECT * FROM network_issues WHERE status=? ORDER BY last_seen DESC LIMIT 200",(status,)).fetchall()
    return [dict(r) for r in rows]

@app.get(f"{router_prefix}/intelligence/issues/{{issue_id}}/suggested-fix")
def issue_suggested_fix(issue_id: int, user=Depends(get_current_user)):
    from .remediation import suggested_fix
    with db() as c: row=c.execute("SELECT * FROM network_issues WHERE id=?",(issue_id,)).fetchone()
    if not row: raise HTTPException(404,"Issue not found")
    return suggested_fix(dict(row))

@app.post(f"{router_prefix}/intelligence/issues/{{issue_id}}/recheck")
def recheck_intelligence_issue(issue_id: int, request: Request, admin=Depends(require_permission("operate"))):
    from .remediation import suggested_fix, record_device_diagnostic
    from .tools import ping, dns
    with db() as c:
        row=c.execute("SELECT * FROM network_issues WHERE id=?",(issue_id,)).fetchone()
        if not row: raise HTTPException(404,"Issue not found")
        issue=dict(row); typ=issue["issue_type"]; target=issue.get("target"); evidence=json.loads(issue.get("evidence") or '{}')
        if typ=="service_failure":
            mid=evidence.get("monitor_id"); manager=getattr(app.state,"collector_manager",None)
            if manager is None: raise HTTPException(503,"Collector manager is not running")
            if not mid: raise HTTPException(400,"Finding is missing monitor evidence")
            result=manager.run_one(int(mid)); result["issue_id"]=issue_id
        elif typ in {"offline_device","packet_loss","dns_problem"}:
            dev=c.execute("SELECT * FROM devices WHERE lower(mac)=lower(?) OR ip=? ORDER BY id LIMIT 1",(target,target)).fetchone()
            if not dev: raise HTTPException(404,"Associated device not found")
            pr=ping(dev["ip"],4) if dev["ip"] else {"ok":False,"error":"No current IP"}; dr=dns(dev["hostname"]) if dev["hostname"] else None
            record_device_diagnostic(c,dev,pr,dr); result={"ok":bool(pr.get("ok")),"issue_id":issue_id,"ping":pr,"dns":dr}
        elif typ=="ip_changed":
            dev=c.execute("SELECT * FROM devices WHERE lower(mac)=lower(?) OR ip=? ORDER BY id LIMIT 1",(target,target)).fetchone(); result={"ok":bool(dev),"issue_id":issue_id,"current_ip":dev["ip"] if dev else None}
        else: result={"ok":False,"issue_id":issue_id,"message":"No automated recheck is defined for this finding type.","suggested_fix":suggested_fix(issue)}
        audit(c,admin["username"],"finding_rechecked",target=str(issue_id),details=json.dumps(result)[:2000],ip=client_ip(request))
    return result

@app.post(f"{router_prefix}/intelligence/issues/{{issue_id}}/resolve")
def resolve_intelligence_issue(issue_id: int, request: Request, user=Depends(require_permission("findings.resolve"))):
    with db() as c:
        row=c.execute("SELECT * FROM network_issues WHERE id=? AND status='open'",(issue_id,)).fetchone()
        if not row: raise HTTPException(404,"Issue not found or already resolved")
        c.execute("UPDATE network_issues SET status='resolved',resolved_at=?,last_seen=? WHERE id=?",(now(),now(),issue_id))
        audit(c,user["username"],"finding_resolved",target=str(issue_id),details=row["title"],ip=client_ip(request))
    return {"ok":True}

@app.get(f"{router_prefix}/intelligence/topology")
def intelligence_topology(user=Depends(get_current_user)):
    with db() as c:
        rows=c.execute("SELECT * FROM topology_links ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]

@app.get(f"{router_prefix}/intelligence/topology/live")
def intelligence_topology_live(user=Depends(get_current_user)):
    from .discovery_intelligence import build_live_topology
    with db() as c:
        return build_live_topology(c)

@app.get(f"{router_prefix}/discovery/status")
def discovery_status(user=Depends(get_current_user)):
    from .intelligence import ensure_schema
    with db() as c:
        ensure_schema(c)
        rows=c.execute("SELECT source,COUNT(*) AS devices,MAX(last_seen) AS last_seen FROM device_sources GROUP BY source ORDER BY source").fetchall()
        links=c.execute("SELECT link_type,COUNT(*) AS links,MAX(last_seen) AS last_seen FROM topology_links GROUP BY link_type ORDER BY link_type").fetchall()
    return {"sources":[dict(r) for r in rows],"topology":[dict(r) for r in links]}

@app.post(f"{router_prefix}/discovery/full")
def discovery_full(request: Request, admin=Depends(require_permission("operate"))):
    from .discovery_intelligence import run_full_discovery
    from .scanner import local_subnet
    with db() as c:
        result=run_full_discovery(c, str(local_subnet()) if local_subnet() else None)
        audit(c,admin["username"],"full_discovery",details=json.dumps({"sources":result.get("sources"),"total":result.get("total_observations")})[:2000],ip=client_ip(request))
    return result

@app.post(f"{router_prefix}/intelligence/enrich")
def intelligence_enrich(user=Depends(require_admin)):
    from .intelligence import ensure_schema, correlate_device
    count=0
    with db() as c:
        ensure_schema(c)
        rows=c.execute("SELECT mac,ip,hostname,vendor FROM devices").fetchall()
        for r in rows:
            correlate_device(c,r["mac"],r["ip"],r["hostname"],r["vendor"],source="inventory")
            count += 1
    return {"ok":True,"devices_processed":count}

# ---------------------------------------------------------------------------
# Monitoring / collectors
# ---------------------------------------------------------------------------

class MonitorCreate(BaseModel):
    kind: str
    name: str
    target: str = ""
    interval_seconds: int = 300
    enabled: bool = True
    options: dict = {}

class MonitorUpdate(BaseModel):
    kind: str | None = None
    name: str | None = None
    target: str | None = None
    interval_seconds: int | None = None
    enabled: bool | None = None
    options: dict | None = None

@app.get(f"{router_prefix}/monitoring/checks")
def monitoring_checks(user=Depends(get_current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM integration_checks ORDER BY last_checked DESC LIMIT 200").fetchall()
    return [dict(r) for r in rows]

@app.get(f"{router_prefix}/monitoring/settings")
def monitoring_settings(user=Depends(get_current_user)):
    with db() as c:
        rows = c.execute("SELECT * FROM integration_settings ORDER BY name").fetchall()
    return [dict(r) for r in rows]

@app.post(f"{router_prefix}/monitoring/settings")
def create_monitoring_setting(req: MonitorCreate, user=Depends(require_admin)):
    allowed = {"website", "dhcp", "pihole", "unifi", "snmp", "public_ip"}
    if req.kind not in allowed:
        raise HTTPException(400, "Unsupported monitor type")
    if not req.name.strip():
        raise HTTPException(400, "Name is required")
    if req.kind != "public_ip" and not req.target.strip():
        raise HTTPException(400, "Target is required for this monitor type")
    interval = max(30, min(req.interval_seconds, 86400))
    ts = now()
    with db() as c:
        try:
            c.execute(
                "INSERT INTO integration_settings(name,kind,target,enabled,interval_seconds,options_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (req.name.strip(), req.kind, req.target.strip() or "(auto)", 1 if req.enabled else 0, interval, json.dumps(req.options), ts, ts)
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "A monitor with that name already exists")
    return {"ok": True}

@app.put(f"{router_prefix}/monitoring/settings/{{monitor_id}}")
def update_monitoring_setting(monitor_id: int, req: MonitorUpdate, user=Depends(require_admin)):
    allowed={"website","dhcp","pihole","unifi","snmp","public_ip"}
    with db() as c:
        row=c.execute("SELECT * FROM integration_settings WHERE id=?",(monitor_id,)).fetchone()
        if not row: raise HTTPException(404,"Monitor not found")
        data=dict(row); updates=req.model_dump(exclude_unset=True)
        kind=updates.get("kind",data["kind"]); name=(updates.get("name",data["name"]) or "").strip(); target=(updates.get("target",data["target"]) or "").strip()
        if kind not in allowed: raise HTTPException(400,"Unsupported monitor type")
        if not name: raise HTTPException(400,"Name is required")
        if kind!="public_ip" and not target: raise HTTPException(400,"Target is required for this monitor type")
        interval=max(30,min(int(updates.get("interval_seconds",data["interval_seconds"])),86400)); enabled=1 if bool(updates.get("enabled",data["enabled"])) else 0
        opts=updates.get("options"); options_json=data["options_json"] if opts is None else json.dumps(opts)
        try: c.execute("UPDATE integration_settings SET name=?,kind=?,target=?,enabled=?,interval_seconds=?,options_json=?,updated_at=? WHERE id=?",(name,kind,target or "(auto)",enabled,interval,options_json,now(),monitor_id))
        except sqlite3.IntegrityError: raise HTTPException(409,"A monitor with that name already exists")
    return {"ok":True,"id":monitor_id}

@app.post(f"{router_prefix}/monitoring/settings/{{monitor_id}}/run")
def run_monitoring_setting(monitor_id: int, user=Depends(require_permission("operate"))):
    manager=getattr(app.state,"collector_manager",None)
    if manager is None: raise HTTPException(503,"Collector manager is not running")
    try: return manager.run_one(monitor_id)
    except KeyError: raise HTTPException(404,"Monitor not found")

@app.delete(f"{router_prefix}/monitoring/settings/{{monitor_id}}")
def delete_monitoring_setting(monitor_id: int, user=Depends(require_admin)):
    with db() as c:
        cur=c.execute("DELETE FROM integration_settings WHERE id=?",(monitor_id,))
        if not cur.rowcount: raise HTTPException(404,"Monitor not found")
        c.execute("DELETE FROM integration_checks WHERE monitor_id=?",(monitor_id,))
    return {"ok":True}

@app.post(f"{router_prefix}/monitoring/run")
def run_monitoring(user=Depends(require_permission("operate"))):
    manager = getattr(app.state, "collector_manager", None)
    if manager is None:
        raise HTTPException(503, "Collector manager is not running")
    return manager.run_all()


@app.get("/monitoring", response_class=HTMLResponse)
def monitoring_page(request: Request):
    get_current_user(request)
    page = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GODSEYE — Monitoring</title><style>
body{margin:0;background:#070b12;color:#e8eef7;font-family:system-ui}.wrap{max-width:1100px;margin:auto;padding:28px}
a{color:#8ab4ff}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}.card{background:#0d141f;border:1px solid #1d2a3d;border-radius:14px;padding:18px}
input,select,button{background:#0b121c;color:#e8eef7;border:1px solid #2b3a52;border-radius:8px;padding:10px}button{background:#2563eb;cursor:pointer}
pre{white-space:pre-wrap;background:#080e16;padding:12px;border-radius:8px}.muted{color:#8290a6;font-size:13px}

/* GODSEYE screenshot-matched visual system */
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033}
body{background:#f3f6fa;color:#172033}
.sidebar{background:#07101c;border-right:1px solid #18283b;box-shadow:8px 0 24px rgba(15,34,58,.08)}
.sidebar .brand{padding:18px 20px 20px}.sidebar .brand b{font-size:18px;color:#fff}.sidebar .brand .muted{color:#7890ad;font-size:9px;letter-spacing:.08em}
.eye{width:42px;height:42px;border-radius:50%;background:radial-gradient(circle at 50% 50%,#fff 0 26%,#2d9bea 27% 48%,#0c2f58 49% 62%,#dbeeff 63% 68%,transparent 69%);border:2px solid #5caaf0;box-shadow:0 0 0 3px rgba(55,153,238,.12);font-size:0}
.navsection{color:#637991;padding-top:17px}.navitem{color:#a7b9ce;border-left:3px solid transparent;padding:10px 18px;gap:11px}.navicon{width:20px;text-align:center;color:#9eb4ca;font-size:15px}.navitem:hover{background:#0d1b2b}.navitem.active{background:linear-gradient(90deg,#12335d,#0d223d);border-left-color:#1d8cf5;color:#fff}.navitem.active .navicon{color:#fff}.navitem .badge{background:#b4233d;color:#fff}
.content{background:#f3f6fa}.wrap{max-width:1560px;padding:28px 30px}.hero h1{font-size:25px;font-weight:700;color:#172033}.hero .muted{font-size:12px}.headerbar{display:flex;justify-content:space-between;align-items:center;background:#fff;border-bottom:1px solid #e4eaf1;padding:12px 30px;min-height:58px}.status-chip{display:inline-flex;align-items:center;gap:6px;background:#ecfdf5;color:#11845b;border-radius:999px;padding:5px 10px;font-size:11px;font-weight:700}.status-dot{width:7px;height:7px;background:#14b87a;border-radius:50%}
.cards{grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.card{border:1px solid #e2e8f0;border-radius:9px;box-shadow:0 2px 7px rgba(25,45,70,.04);padding:16px}.statcard{display:flex;align-items:center;gap:13px}.staticon{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;background:#e8f4ff;color:#1685e7;font-weight:800}.staticon.green{background:#e8faf2;color:#0e9f68}.staticon.red{background:#fff0f2;color:#ed4561}.staticon.purple{background:#f1edff;color:#7756d9}.statmeta{font-size:10px;color:#72819a;text-transform:none;letter-spacing:0}.statnum{font-size:27px;font-weight:750;margin-top:2px}.trend{font-size:10px;margin-left:auto;color:#18a26f}.panel{border-radius:9px;box-shadow:0 2px 7px rgba(25,45,70,.04);border:1px solid #e1e7ef;margin-top:16px}.panel h2{font-size:14px;padding:14px 16px}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(320px,.8fr);gap:16px;margin-top:16px}.traffic{height:245px;padding:14px 16px}.traffic svg{width:100%;height:180px}.activity-list{padding:4px 16px 14px}.activity-row{display:grid;grid-template-columns:18px 1fr auto;gap:9px;align-items:center;padding:10px 0;border-bottom:1px solid #eef2f6;font-size:11px}.activity-row:last-child{border-bottom:0}.activity-dot{width:10px;height:10px;border-radius:50%;border:2px solid #1685e7}.activity-dot.green{border-color:#12b77a}.activity-dot.orange{border-color:#f59e0b}.activity-title{font-weight:650}.activity-sub{font-size:10px;color:#7c8ba0;margin-top:2px}.activity-time{font-size:9px;color:#8996a8}
.toolbar{margin:16px 0 12px}.input,.filter{border:1px solid #d8e0e9;border-radius:7px;background:#fff;color:#25334a}.primary{background:#0f7df0!important;border-color:#0f7df0!important;color:#fff!important}.primary:hover{background:#096fd8!important}.secondary{background:#fff!important;border:1px solid #d8e0e9!important;color:#35506f!important}.secondary:hover{background:#f6f9fc!important}.primary:disabled{opacity:.6;cursor:wait}.modal{position:fixed;inset:0;background:rgba(4,13,24,.55);display:grid;place-items:center;z-index:1000;padding:20px}.modal-card{width:min(560px,100%);background:#fff;border-radius:12px;box-shadow:0 24px 70px rgba(0,0,0,.25);padding:22px}.modal-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}.modal-head h2{margin:0 0 5px;font-size:18px}.modal-form{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:18px}.modal-form label{display:flex;flex-direction:column;gap:6px;font-size:11px;color:#52657b}.modal-form label:nth-child(1),.modal-form label:nth-child(7){grid-column:1/-1}.modal-form textarea{resize:vertical}.modal-actions{grid-column:1/-1;display:flex;justify-content:flex-end;gap:8px;margin-top:4px}.err{color:#c83b50;font-size:11px;min-height:16px}@media(max-width:600px){.modal-form{grid-template-columns:1fr}.modal-form label:nth-child(1),.modal-form label:nth-child(7){grid-column:auto}}.table-head{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid #e8edf3}.table-head h2{padding:0;border:0}.table-head .muted{font-size:11px}
th,td{padding:11px 12px;font-size:11px}th{font-size:9px;color:#78889e;background:#fbfcfe}tr:hover{background:#f7fbff}.device-name{display:flex;align-items:center;gap:8px}.device-icon{width:23px;height:23px;border-radius:7px;background:#e8f4ff;color:#0879d9;display:grid;place-items:center;font-size:11px}.status-badge{display:inline-flex;padding:3px 7px;border-radius:999px;background:#e9fbf3;color:#0b9a63;font-size:9px;font-weight:700}.severity-high{background:#fff0f2;color:#dc3f58}.severity-medium{background:#fff7e7;color:#b77900}.severity-low{background:#eef7ff;color:#2478b9}
.map-card{min-height:460px;position:relative;overflow:hidden;background:linear-gradient(#fff,#fbfdff)}.map-canvas{min-height:410px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px}.map-node{min-width:110px;text-align:center}.map-circle{width:44px;height:44px;border-radius:50%;margin:auto;display:grid;place-items:center;background:#1592e8;color:#fff;box-shadow:0 5px 16px rgba(21,146,232,.2)}.map-label{font-size:10px;font-weight:700;margin-top:4px}.map-sub{font-size:9px;color:#8190a2}.map-line{width:2px;height:28px;background:#8fd4fa}.map-children{display:flex;gap:45px;position:relative}.map-children:before{content:"";position:absolute;top:-15px;left:15%;right:15%;height:2px;background:#54b5eb}.map-children .map-node{position:relative}.map-children .map-node:before{content:"";position:absolute;top:-15px;left:50%;width:2px;height:15px;background:#54b5eb}
.tool-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.tool-card{background:#fff;border:1px solid #e1e7ef;border-radius:9px;padding:17px;min-height:145px;box-shadow:0 2px 7px rgba(25,45,70,.04)}.tool-card h3{font-size:13px;margin:10px 0 4px}.tool-card p{font-size:10px;color:#77879b;min-height:30px}.tool-card .tool-icon{width:35px;height:35px;border-radius:9px;background:#edf6ff;color:#1685e7;display:grid;place-items:center;font-size:17px}.tool-card button{font-size:10px;padding:6px 10px}
.integration-tabs{display:flex;gap:4px;border-bottom:1px solid #e2e8f0;padding:0 16px}.integration-tab{padding:11px 14px;border:0;border-bottom:2px solid transparent;background:none;color:#72819a}.integration-tab.active{color:#0f7df0;border-bottom-color:#0f7df0}.integration-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;padding:18px}.checklist{padding:16px;background:#f8fafc;border-radius:8px}.check{font-size:11px;margin:10px 0;color:#52647a}.check:before{content:'✓';color:#13a36e;font-weight:800;margin-right:8px}
.intel-modal-card{width:min(980px,96vw);max-height:90vh;overflow:auto}.intel-hero{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:14px 0 4px}.intel-title{display:flex;align-items:center;gap:12px}.intel-big-icon{width:48px;height:48px;border-radius:12px;background:#e8f4ff;color:#0f7df0;display:grid;place-items:center;font-size:22px}.intel-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}.intel-stat{border:1px solid #e2e8f0;border-radius:9px;padding:12px;background:#fbfdff}.intel-stat .k{font-size:9px;color:#7b899b;text-transform:uppercase;letter-spacing:.05em}.intel-stat .v{font-size:17px;font-weight:750;margin-top:4px}.intel-sections{display:grid;grid-template-columns:1fr 1fr;gap:14px}.intel-section{border:1px solid #e2e8f0;border-radius:9px;background:#fff;overflow:hidden}.intel-section h3{font-size:12px;padding:11px 13px;border-bottom:1px solid #edf1f5;margin:0}.intel-body{padding:12px 13px}.intel-kv{display:grid;grid-template-columns:120px 1fr;gap:7px 10px;font-size:11px}.intel-kv .k{color:#78879a}.intel-actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.intel-list{margin:0;padding-left:18px;font-size:11px;color:#4f6278}.intel-list li{margin:7px 0}.timeline{max-height:220px;overflow:auto}.timeline-row{padding:8px 0;border-bottom:1px solid #eef2f6;font-size:10px}.timeline-row:last-child{border-bottom:0}.risk-low{color:#0b9a63}.risk-med{color:#c27a00}.risk-high{color:#d83c55}@media(max-width:800px){.intel-grid{grid-template-columns:repeat(2,1fr)}.intel-sections{grid-template-columns:1fr}}
.top-actions{display:flex;align-items:center;gap:12px}.top-actions .icon-btn{border:0;background:none;color:#52657b;font-size:14px;padding:4px}.user-chip{display:flex;align-items:center;gap:7px;font-size:11px;color:#53657a}.avatar{width:24px;height:24px;border-radius:50%;background:#e7f1ff;color:#1768b5;display:grid;place-items:center;font-size:10px;font-weight:800}
@media(max-width:1050px){.dashboard-grid,.integration-grid{grid-template-columns:1fr}.tool-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:820px){.wrap{padding:18px 14px}.cards{grid-template-columns:repeat(2,1fr)}.dashboard-grid{grid-template-columns:1fr}.tool-grid{grid-template-columns:1fr}.headerbar{padding:10px 14px}.map-children{gap:12px;flex-wrap:wrap;justify-content:center}.sidebar .brand{display:flex}.sidebar{position:sticky}.top-actions .user-chip{display:none}}
</style></head><body><div class="wrap"><a href="/">← GODSEYE Dashboard</a><h1>Monitoring & Collectors</h1>
<p class="muted">Create persistent checks. GODSEYE runs them locally without Docker and stores recent results.</p>
<div class="card"><h2>Add monitor</h2><div class="grid">
<div><label>Name<br><input id="name" placeholder="Home website"></label></div>
<div><label>Type<br><select id="kind"><option value="website">Website</option><option value="dhcp">DHCP leases</option><option value="pihole">Pi-hole</option><option value="unifi">UniFi</option><option value="snmp">SNMP</option><option value="public_ip">Public IP</option></select></label></div>
<div><label>Target<br><input id="target" placeholder="https://example.com"></label></div>
<div><label>Interval seconds<br><input id="interval" type="number" value="300" min="30"></label></div>
</div><p><button onclick="addMonitor()">Add monitor</button> <button onclick="runNow()">Run all now</button></p><pre id="out">Ready.</pre></div>
<div class="card"><h2>Recent results</h2><button onclick="load()">Refresh</button><pre id="results">Loading…</pre></div>
<script>
async function req(u,o={}){o=o||{};o.headers=o.headers||{};if(o.method&&['POST','PUT','PATCH','DELETE'].includes(o.method.toUpperCase())){const m=document.cookie.match('(?:^|; )godseye_csrf=([^;]*)');const token=m?decodeURIComponent(m[1]):'';if(token)o.headers['X-CSRF-Token']=token}let r=await fetch(u,o);let t=await r.text();if(!r.ok)throw Error(t);return t?JSON.parse(t):{}}
async function load(){try{document.getElementById('results').textContent=JSON.stringify(await req('/api/v1/monitoring/checks'),null,2)}catch(e){document.getElementById('results').textContent=e}}
async function addMonitor(){try{let body={name:name.value,kind:kind.value,target:target.value,interval_seconds:+interval.value,options:{}};document.getElementById('out').textContent=JSON.stringify(await req('/api/v1/monitoring/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),null,2);load()}catch(e){out.textContent=e}}
async function runNow(){try{out.textContent=JSON.stringify(await req('/api/v1/monitoring/run',{method:'POST'}),null,2);load()}catch(e){out.textContent=e}}
load()
</script></div></body></html>"""
    return HTMLResponse(page.replace("__EYE_LOGO__", EYE_LOGO))

@app.get("/tools", response_class=HTMLResponse)
def tools_page(request: Request):
    get_current_user(request)
    page = '''<!doctype html>
<html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GODSEYE — Network Tools</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033}*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#172033}.layout{display:flex;min-height:100vh}.side{width:216px;background:#07101c;border-right:1px solid #18283b;position:sticky;top:0;height:100vh;display:flex;flex-direction:column}.brand{padding:20px 18px;border-bottom:1px solid #18283b;display:flex;align-items:center;gap:10px}.brand b{display:block;color:#fff;letter-spacing:.1em;font-size:18px}.brand small{display:block;color:#7890ad;font-size:9px;letter-spacing:.08em;margin-top:2px}.eye-logo{width:48px;height:31px;display:block}.nav{padding:12px 0;flex:1}.nav-title{color:#637991;font-size:10px;text-transform:uppercase;letter-spacing:.12em;padding:12px 18px 6px}.nav a{display:flex;align-items:center;gap:10px;padding:10px 16px;color:#a7b9ce;text-decoration:none;font-size:12px;border-left:3px solid transparent}.nav a:hover{background:#0d1b2b;color:#fff}.nav a.active{background:linear-gradient(90deg,#12335d,#0d223d);border-left-color:#1d8cf5;color:#fff}.navicon{width:18px;text-align:center}.side-footer{padding:14px 12px;border-top:1px solid #18283b}.back{display:block;text-align:center;background:#0f7df0;color:#fff;text-decoration:none;border-radius:7px;padding:9px;font-size:11px}.main{flex:1;min-width:0}.headerbar{height:58px;background:#fff;border-bottom:1px solid #e4eaf1;display:flex;justify-content:flex-end;align-items:center;padding:0 30px;gap:16px}.online{display:inline-flex;align-items:center;gap:6px;background:#ecfdf5;color:#11845b;border-radius:999px;padding:5px 10px;font-size:11px;font-weight:700}.online i{width:7px;height:7px;background:#14b87a;border-radius:50%}.user{font-size:12px;color:#35506f}.wrap{max-width:1450px;margin:auto;padding:28px 30px}.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin-bottom:20px}.hero h1{margin:0;font-size:26px}.hero p{margin:5px 0 0;color:#72819a;font-size:12px}.tool-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.tool-card{background:#fff;border:1px solid #e1e7ef;border-radius:10px;box-shadow:0 2px 7px rgba(25,45,70,.04);padding:18px}.tool-card h2{font-size:15px;margin:0 0 5px}.tool-card p{font-size:11px;color:#72819a;min-height:30px;margin:0 0 14px}.tool-icon{width:34px;height:34px;border-radius:9px;background:#e8f4ff;color:#0f7df0;display:grid;place-items:center;font-weight:800;margin-bottom:10px}.full{grid-column:1/-1}.panel{background:#fff;border:1px solid #e1e7ef;border-radius:10px;box-shadow:0 2px 7px rgba(25,45,70,.04);padding:18px;margin-top:16px}.panel h2{font-size:15px;margin:0 0 5px}.muted{color:#72819a;font-size:11px}.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px}.input{border:1px solid #d8e0e9;border-radius:7px;background:#fff;color:#25334a;padding:9px 10px;min-width:180px}.input.grow{flex:1}.btn{border:1px solid #0f7df0;background:#0f7df0;color:#fff;border-radius:7px;padding:9px 12px;cursor:pointer;font-size:11px}.btn.secondary{background:#fff;color:#35506f;border-color:#d8e0e9}.btn.warn{background:#c83b50;border-color:#c83b50}.result{margin-top:12px;background:#f7f9fc;border:1px solid #e5eaf1;border-radius:8px;padding:12px;min-height:45px;white-space:pre-wrap;word-break:break-word;font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#33465e}.result.ok{border-color:#b9ead5}.result.err{border-color:#f1c2ca;color:#a52e43}.status{font-size:10px;color:#72819a;margin-left:auto;align-self:center}.security-note{background:#f0f7ff;border:1px solid #cfe5fb;color:#365979;padding:10px 12px;border-radius:8px;font-size:10px;margin-top:14px}@media(max-width:1050px){.tool-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.layout{display:block}.side{width:100%;height:auto;position:sticky;top:0;z-index:20}.brand{display:none}.nav{display:flex;overflow:auto;padding:0}.nav-title{display:none}.nav a{white-space:nowrap;border-left:0;border-bottom:3px solid transparent}.nav a.active{border-left:0;border-bottom-color:#1d8cf5}.side-footer{display:none}.headerbar{height:48px;padding:0 14px}.wrap{padding:20px 14px}.tool-grid{grid-template-columns:1fr}.full{grid-column:auto}}
</style></head><body><div class="layout">
<aside class="side"><div class="brand">__EYE_LOGO__<div><b>GODSEYE</b><small>NETWORK INTELLIGENCE</small></div></div><nav class="nav">
<div class="nav-title">Overview</div><a href="/">◉ <span>Dashboard</span></a><a href="/#devices">▣ <span>Devices</span></a><a href="/#network">⌘ <span>Network Map</span></a><a href="/monitoring">◔ <span>Monitoring</span></a><a href="/#findings">⚠ <span>Findings</span></a>
<div class="nav-title">Management</div><a class="active" href="/tools">⚒ <span>Tools</span></a><a href="/#integrations">⌘ <span>Integrations</span></a><a href="/#reports">▤ <span>Reports</span></a><a href="/#settings">⚙ <span>Settings</span></a></nav><div class="side-footer"><a class="back" href="/">Dashboard</a></div></aside>
<main class="main"><header class="headerbar"><span class="online"><i></i>Online</span><span class="user">admin ▾</span></header><div class="wrap">
<div class="hero"><div><h1>Network Tools</h1><p>Diagnostics and management tools for your local network.</p></div><span class="status">GODSEYE native tools</span></div>
<div class="tool-grid">
<section class="tool-card"><div class="tool-icon">↗</div><h2>Ping</h2><p>Test reachability, packet loss, and latency.</p><div class="row"><input class="input grow" id="pingHost" value="192.168.1.1" placeholder="Private IP or hostname"><button class="btn" onclick="runPing()">Run Ping</button></div><div class="result" id="pingOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">⌁</div><h2>Traceroute</h2><p>Show the local route toward a private network device.</p><div class="row"><input class="input grow" id="traceHost" value="192.168.1.1" placeholder="Private IP or hostname"><button class="btn" onclick="runTrace()">Trace Route</button></div><div class="result" id="traceOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">◎</div><h2>DNS Lookup</h2><p>Resolve a hostname and show its addresses.</p><div class="row"><input class="input grow" id="dnsHost" value="google.com" placeholder="Hostname"><button class="btn" onclick="runDns()">Lookup</button></div><div class="result" id="dnsOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">◉</div><h2>Port Scan</h2><p>Check selected TCP ports on a private LAN target using Nmap.</p><div class="row"><input class="input grow" id="portHost" value="192.168.1.1" placeholder="Private IP or hostname"><input class="input" id="ports" value="22,53,80,443,445,3389,8080,8443" title="Comma-separated ports or ranges"><button class="btn" onclick="runPorts()">Scan Ports</button></div><div class="result" id="portOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">▣</div><h2>Device Information</h2><p>Collect reverse DNS, neighbor-table data, and reachability.</p><div class="row"><input class="input grow" id="infoHost" value="192.168.1.1" placeholder="Private IP or hostname"><button class="btn" onclick="runInfo()">Get Info</button></div><div class="result" id="infoOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">⟳</div><h2>Network Discovery</h2><p>Discover active hosts with Nmap or inspect the Linux neighbor table.</p><div class="row"><input class="input grow" id="discoverTarget" value="192.168.1.0/24" placeholder="Private network CIDR"><button class="btn" onclick="runNmap()">Discover</button><button class="btn secondary" onclick="runNeighbors()">Neighbors</button></div><div class="result" id="discoverOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">⚡</div><h2>Wake on LAN</h2><p>Send a magic packet to a device. Administrator access is required.</p><div class="row"><input class="input grow" id="wolMac" placeholder="AA:BB:CC:DD:EE:FF"><input class="input" id="wolBroadcast" value="255.255.255.255"><button class="btn warn" onclick="runWol()">Wake Device</button></div><div class="result" id="wolOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">✓</div><h2>Gateway & Internet</h2><p>Test the Raspberry Pi's default gateway and Internet path.</p><div class="row"><button class="btn" onclick="runGet('/api/v1/diagnostics/gateway','gatewayOut')">Test Gateway</button><button class="btn secondary" onclick="runGet('/api/v1/diagnostics/internet','gatewayOut')">Test Internet</button></div><div class="result" id="gatewayOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">◇</div><h2>Website Monitor Test</h2><p>Check HTTP/HTTPS availability and response time.</p><div class="row"><input class="input grow" id="webUrl" value="https://example.com" placeholder="https://host-or-service"><button class="btn" onclick="runWebsite()">Test Website</button></div><div class="result" id="webOut">Ready.</div></section>
<section class="panel full"><h2>Tool safety</h2><div class="muted">GODSEYE limits active network diagnostics to private or link-local targets. Port scans use TCP connect mode and a bounded port list. Wake-on-LAN is an administrator-only state-changing action.</div><div class="security-note">The fresh installer includes the native Linux programs required by these tools, including Nmap, traceroute, DNS utilities, iproute2, ping, and Wake-on-LAN.</div></section>
</div></div></main></div>
<script>
async function ensureCsrf(){if(document.cookie.includes('godseye_csrf='))return;await fetch('/api/v1/auth/csrf')}
async function req(url,opt={}){await ensureCsrf();opt=opt||{};opt.headers=opt.headers||{};if(opt.method&&['POST','PUT','PATCH','DELETE'].includes(opt.method.toUpperCase())){const m=document.cookie.match('(?:^|; )godseye_csrf=([^;]*)');if(m)opt.headers['X-CSRF-Token']=decodeURIComponent(m[1])}const r=await fetch(url,opt);const t=await r.text();let data={};try{data=t?JSON.parse(t):{}}catch{data={detail:t}}if(!r.ok)throw new Error(data.detail||t||('HTTP '+r.status));return data}
function show(id,data){const el=document.getElementById(id);el.textContent=typeof data==='string'?data:JSON.stringify(data,null,2);el.className='result '+(data&&data.ok?'ok':data&&data.detail?'err':'')}
async function post(url,body,id){try{show(id,await req(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}))}catch(e){show(id,'Error: '+e.message);document.getElementById(id).className='result err'}}
async function runGet(url,id){try{show(id,await req(url))}catch(e){show(id,'Error: '+e.message);document.getElementById(id).className='result err'}}
function val(id){return document.getElementById(id).value.trim()}
function runPing(){post('/api/v1/tools/ping',{host:val('pingHost')},'pingOut')}
function runTrace(){post('/api/v1/tools/traceroute',{host:val('traceHost'),max_hops:12},'traceOut')}
function runDns(){post('/api/v1/tools/dns',{host:val('dnsHost')},'dnsOut')}
function runPorts(){post('/api/v1/tools/port-scan',{host:val('portHost'),ports:val('ports')},'portOut')}
function runInfo(){post('/api/v1/tools/device-info',{host:val('infoHost')},'infoOut')}
function runNmap(){runGet('/api/v1/discovery/nmap?target='+encodeURIComponent(val('discoverTarget')),'discoverOut')}
function runNeighbors(){runGet('/api/v1/discovery/neighbors','discoverOut')}
function runWol(){post('/api/v1/tools/wol',{mac:val('wolMac'),broadcast:val('wolBroadcast')},'wolOut')}
function runWebsite(){post('/api/v1/monitor/website',{url:val('webUrl')},'webOut')}
</script></body></html>'''
    return HTMLResponse(page.replace("__EYE_LOGO__", EYE_LOGO))


@app.get("/", response_class=HTMLResponse)
def dashboard():
    banner_html = LOGIN_BANNER.replace("<", "&lt;").replace(">", "&gt;") if LOGIN_BANNER else ""
    html = DASHBOARD.replace("__LOGIN_BANNER__", banner_html)
    html = html.replace("__LOGIN_BANNER_DISPLAY__", "" if LOGIN_BANNER else "display:none")
    html = html.replace("__MIN_PASSWORD_LENGTH__", str(MIN_PASSWORD_LENGTH))
    html = html.replace("__EYE_LOGO__", EYE_LOGO)
    return HTMLResponse(html)


DASHBOARD = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GODSEYE — Network Monitor</title>
<style>
:root{color-scheme:dark;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172033}header{position:sticky;top:0;z-index:5;background:rgba(255,255,255,.96);backdrop-filter:blur(14px);border-bottom:1px solid #e5eaf1;padding:16px 4%;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.brand{display:flex;gap:12px;align-items:center}.eye{width:38px;height:38px;border-radius:12px;background:#182338;display:grid;place-items:center;font-size:21px}.brand b{font-size:20px;letter-spacing:.08em} .muted{color:#6b778c;font-size:12px}button,.filter{border:1px solid #d7dee8;background:#fff;color:#24324a;border-radius:9px;padding:9px 13px;cursor:pointer}button.primary{background:#2563eb;border-color:#2563eb}button.danger{background:#3a1522;border-color:#5c2436;color:#ff8194}button.link{background:none;border:none;color:#7f9fd8;padding:4px 6px}.headerRight{display:flex;gap:10px;align-items:center}.wrap{max-width:1500px;margin:auto;padding:28px 4%}.hero{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:22px}.hero h1{font-size:32px;margin:0 0 5px}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:18px}.label{color:#8090a7;font-size:12px;text-transform:uppercase;letter-spacing:.1em}.num{font-size:32px;font-weight:750;margin-top:7px}.green{color:#50e3a4}.yellow{color:#f7c948}.red{color:#ff6b81}.toolbar{display:flex;gap:9px;margin:22px 0;flex-wrap:wrap}.toolbar input{flex:1;min-width:220px}.input{background:#fff;border:1px solid #d7dee8;border-radius:9px;padding:10px;color:#172033}.panel{background:#fff;border:1px solid #e2e8f0;border-radius:14px;overflow:hidden;margin-top:18px}.panel h2{font-size:16px;margin:0;padding:16px 18px;border-bottom:1px solid #e7ebf1;display:flex;justify-content:space-between;align-items:center}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #edf0f5;font-size:13px}th{color:#72819a;font-size:11px;text-transform:uppercase;letter-spacing:.08em}tr:hover{background:#f7f9fc}.dot{font-size:10px}.online{color:#50e3a4}.offline{color:#68758a}.suspected_offline{color:#f7c948}.pill{border:1px solid #31415a;border-radius:999px;padding:3px 8px;font-size:11px;color:#9eb0c8;cursor:pointer;background:none}.known{color:#50e3a4;border-color:#245c49}.new{color:#f7c948;border-color:#6d5a24}.investigate{color:#ff8194;border-color:#6d2e3c}.ignored{color:#72819a}.admin{color:#f7c948;border-color:#6d5a24}.readonly{color:#7f9fd8;border-color:#28406d}.critical{color:#ff8194;border-color:#6d2e3c}.warning{color:#f7c948;border-color:#6d5a24}.info{color:#7f9fd8;border-color:#28406d}.name{font-weight:650}.empty{padding:35px;text-align:center;color:#72819a}.healthbar{font-size:12px;padding:8px 4%;border-bottom:1px solid #e5eaf1;background:#fff}.healthbar.ok{color:#50e3a4}.healthbar.bad{color:#ff8194}
.overlay{position:fixed;inset:0;background:#070b12;display:grid;place-items:center;z-index:50;padding:20px}.authcard{width:100%;max-width:360px;background:#101927;border:1px solid #1d2a3d;border-radius:16px;padding:28px}.authcard h2{margin:0 0 6px}.authcard form{display:flex;flex-direction:column;gap:11px;margin-top:18px}.authcard .input{width:100%}.err{color:#ff8194;font-size:13px;min-height:18px}.formRow{display:flex;gap:9px}.userForm{display:flex;gap:8px;padding:14px 18px;flex-wrap:wrap;border-bottom:1px solid #182335}.userForm .input{flex:1;min-width:120px}
.shell{display:flex;align-items:flex-start}.sidebar{width:230px;flex-shrink:0;background:#0a0f18;border-right:1px solid #1d2838;padding:18px 0;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}.sidebar .brand{padding:0 18px 16px;margin-bottom:8px;border-bottom:1px solid #1d2838}.navsection{padding:13px 18px 6px;color:#586a84;font-size:10px;font-weight:800;letter-spacing:.13em;text-transform:uppercase}.navlist{display:flex;flex-direction:column}.navitem{display:flex;align-items:center;gap:10px;padding:9px 18px;color:#9eb0c8;background:none;border:none;border-left:3px solid transparent;text-align:left;cursor:pointer;font-size:13px;width:100%;text-decoration:none}.navitem:hover{background:#111a28;color:#e8eef7}.navitem.active{background:#111a28;color:#e8eef7;border-left-color:#2563eb}.navitem .badge{margin-left:auto;min-width:20px;padding:2px 6px;border-radius:999px;background:#3a1522;color:#ff8194;font-size:10px;text-align:center}.sidebar-footer{margin-top:auto;padding:14px 18px 4px;border-top:1px solid #1d2838;display:flex;flex-direction:column;gap:8px}.content{flex:1;min-width:0}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){display:none}}@media(max-width:600px){.cards{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}th:nth-child(4),td:nth-child(4){display:none}.wrap{padding:20px 3%}}
@media(max-width:820px){.shell{flex-direction:column}.sidebar{width:100%;height:auto;position:sticky;top:0;flex-direction:column;overflow:visible;border-right:none;border-bottom:1px solid #1d2838;padding:8px 0;z-index:6}.sidebar .brand{display:none}.navlist{flex-direction:row;overflow-x:auto;padding:0 4%;align-items:center}.navsection{display:none}.navitem{width:auto;white-space:nowrap;border-left:none;border-bottom:3px solid transparent;padding:8px 12px}.navitem.active{border-left:none;border-bottom-color:#2563eb}.sidebar-footer{margin-top:8px;flex-direction:row;border-top:1px solid #1d2838;padding:8px 4% 0;gap:10px;align-items:center;flex-wrap:wrap}.sidebar-footer #whoami{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sidebar-footer #scanBtn{width:auto!important;margin-bottom:0!important}}
.eye-logo{width:48px;height:30px;display:block}.login-brand{display:flex;flex-direction:column;align-items:center;text-align:center;margin-bottom:18px}.login-brand .eye-logo{width:132px;height:79px}.login-brand b{font-size:28px;letter-spacing:.12em}.login-brand .muted{font-size:11px}.authcard{box-shadow:0 24px 60px rgba(0,0,0,.35)}.user-chip{border:0!important;background:transparent!important;padding:4px!important;display:flex;align-items:center;gap:7px;font-size:11px;color:#53657a}.user-menu{position:absolute;right:4%;top:58px;background:#fff;border:1px solid #dfe6ef;border-radius:10px;box-shadow:0 12px 30px rgba(15,34,58,.14);padding:6px;z-index:20}.user-menu button{display:block;width:100%;border:0;text-align:left;background:#fff;padding:9px 12px}.user-menu button:hover{background:#f3f6fa}
</style></head>
<body>
<div id="authOverlay" class="overlay" style="display:none">
  <div class="authcard">
    <div class="login-brand">__EYE_LOGO__<b>GODSEYE</b><div class="muted">Network Intelligence &amp; Security</div></div>
    <div id="loginBanner" class="muted" style="white-space:pre-wrap;margin-bottom:14px;__LOGIN_BANNER_DISPLAY__">__LOGIN_BANNER__</div>
    <h2>Welcome Back</h2>
    <div class="muted">Sign in to your GODSEYE account</div>
    <form id="loginForm" onsubmit="return doLogin(event)">
      <input class="input" id="loginUser" placeholder="Username" autocomplete="username" required>
      <input class="input" id="loginPass" type="password" placeholder="Password" autocomplete="current-password" required>
      <div class="err" id="loginErr"></div>
      <button class="primary" type="submit">Sign in</button>
    </form>
  </div>
</div>
<div id="setupOverlay" class="overlay" style="display:none">
  <div class="authcard">
    <div class="brand" style="margin-bottom:18px"><div class="eye">__EYE_LOGO__</div><div><b>GODSEYE</b><div class="muted">NETWORK INTELLIGENCE & SECURITY</div></div></div>
    <h2>Create your administrator password</h2>
    <div class="muted">Fresh installation complete. Choose a password for the <b>admin</b> account.</div>
    <form id="setupForm" onsubmit="return doInitialSetup(event)">
      <input class="input" value="admin" readonly>
      <input class="input" id="setupPass" type="password" placeholder="Create password (min __MIN_PASSWORD_LENGTH__ characters)" autocomplete="new-password" required minlength="__MIN_PASSWORD_LENGTH__">
      <input class="input" id="setupPass2" type="password" placeholder="Confirm password" autocomplete="new-password" required minlength="__MIN_PASSWORD_LENGTH__">
      <div class="err" id="setupErr"></div>
      <button class="primary" type="submit">Create Password & Continue</button>
    </form>
  </div>
</div>
<div id="pwOverlay" class="overlay" style="display:none">
  <div class="authcard">
    <h2>Set a new password</h2>
    <div class="muted">This account is using a password that must be changed before continuing.</div>
    <form id="pwForm" onsubmit="return doChangePassword(event)">
      <input class="input" id="curPass" type="password" placeholder="Current password" autocomplete="current-password" required>
      <input class="input" id="newPass" type="password" placeholder="New password (min __MIN_PASSWORD_LENGTH__ characters)" autocomplete="new-password" required minlength="__MIN_PASSWORD_LENGTH__">
      <div class="err" id="pwErr"></div>
      <button class="primary" type="submit">Set password</button>
    </form>
  </div>
</div>
<div id="mfaLoginOverlay" class="overlay" style="display:none">
  <div class="authcard">
    <h2>Two-factor authentication</h2>
    <div class="muted">Enter the 6-digit code from your authenticator app, or a backup code.</div>
    <form id="mfaLoginForm" onsubmit="return doMfaVerify(event)">
      <input class="input" id="mfaCode" placeholder="123456 or backup code" autocomplete="one-time-code" required>
      <div class="err" id="mfaLoginErr"></div>
      <button class="primary" type="submit">Verify</button>
    </form>
  </div>
</div>
<div id="app" style="display:none">
<div class="healthbar" id="healthbar"></div>
<div class="healthbar" id="pwReminderBar" style="display:none;color:#f7c948;cursor:pointer" onclick="openChangePassword()"></div>
<div class="shell">
<nav class="sidebar">
<div class="brand"><div class="eye">__EYE_LOGO__</div><div><b>GODSEYE</b><div class="muted">LOCAL NETWORK INTELLIGENCE</div></div></div>
<div class="navlist">
<div class="navsection">Overview</div>
<button type="button" class="navitem active" data-view="overview"><span class="navicon">⌂</span><span>Dashboard</span></button>
<button type="button" class="navitem" data-view="devices"><span class="navicon">▣</span><span>Devices</span></button>
<button type="button" class="navitem" data-view="network"><span class="navicon">⌁</span><span>Network Map</span></button>
<button type="button" class="navitem" data-view="monitoring"><span class="navicon">◔</span><span>Monitoring</span></button>
<button type="button" class="navitem" data-view="findings"><span class="navicon">!</span><span>Findings</span><span class="badge" id="findingBadge">0</span></button>

<div class="navsection">Management</div>
<button type="button" class="navitem" data-view="tools"><span class="navicon">⚒</span><span>Tools</span></button>
<button type="button" class="navitem" data-view="integrations"><span class="navicon">⌘</span><span>Integrations</span></button>
<button type="button" class="navitem" data-view="reports"><span class="navicon">▤</span><span>Reports</span></button>
<button type="button" class="navitem" data-view="health"><span class="navicon">♥</span><span>System Health</span></button>
<button type="button" class="navitem" data-view="security"><span class="navicon">▣</span><span>Settings</span></button>

<div class="navsection">Administration</div>
<button type="button" class="navitem" data-view="rules" id="navRules"><span class="navicon">⚑</span><span>Alert Rules</span></button>
<button type="button" class="navitem" id="navUsers" data-view="users"><span class="navicon">♙</span><span>Users</span></button>
<button type="button" class="navitem" id="navAudit" data-view="audit"><span class="navicon">▥</span><span>Audit Log</span></button>
</div>
<div class="sidebar-footer">
<button id="scanBtn" class="primary" onclick="scan()">⟳ Scan Now</button>
<div class="muted" id="whoami"></div>
<button class="link" onclick="openChangePassword()">Change password</button>
<button class="link" onclick="logout()">Log out</button>
</div>
</nav>
<main class="content"><div class="headerbar"><div class="muted">Network Intelligence & Security</div><div class="top-actions"><span class="status-chip"><span class="status-dot"></span> Online</span><button class="icon-btn" title="Notifications">♧</button><button class="user-chip" type="button" onclick="toggleUserMenu()"><span class="avatar">A</span><span id="topUser">admin</span><span aria-hidden="true">⌄</span></button><div id="userMenu" class="user-menu" style="display:none"><button onclick="openChangePassword();toggleUserMenu()">Change password</button><button onclick="logout()">Sign out</button></div></div></div><div class="wrap">

<div class="view" id="view-overview">
<div class="hero"><div><h1>Dashboard</h1><div class="muted">Network overview and system status</div></div></div>
<div class="cards">
<div class="card statcard"><div class="staticon">▣</div><div><div class="statmeta">Total Devices</div><div class="statnum" id="total">—</div></div><span class="trend">↑ 2 new</span></div>
<div class="card statcard"><div class="staticon green">✓</div><div><div class="statmeta">Online</div><div class="statnum" id="online">—</div></div><span class="trend" id="onlineTrend">—</span></div>
<div class="card statcard"><div class="staticon red">!</div><div><div class="statmeta">Issues</div><div class="statnum" id="unknown">—</div></div><span class="trend" style="color:#df5064">↓ 2 resolved</span></div>
<div class="card statcard"><div class="staticon purple">◔</div><div><div class="statmeta">Monitors</div><div class="statnum">6</div></div><span class="trend">5 healthy</span></div>
</div>
<div class="dashboard-grid">
<section class="panel traffic"><div class="table-head"><h2>Live Network Traffic</h2><div class="muted"><span style="color:#1976e8">●</span> Download &nbsp;&nbsp; <span style="color:#16a36d">●</span> Upload <span id="trafficNow" style="margin-left:12px">collecting…</span></div></div>
<svg id="trafficSvg" viewBox="0 0 760 190" preserveAspectRatio="none" aria-label="Live network traffic chart"><g stroke="#e8edf3" stroke-width="1"><line x1="45" y1="25" x2="745" y2="25"/><line x1="45" y1="65" x2="745" y2="65"/><line x1="45" y1="105" x2="745" y2="105"/><line x1="45" y1="145" x2="745" y2="145"/></g><polyline id="trafficRx" points="" fill="none" stroke="#1976e8" stroke-width="2.2"/><polyline id="trafficTx" points="" fill="none" stroke="#16a36d" stroke-width="2"/></svg></section>
<section class="panel"><div class="table-head"><h2>Recent Activity</h2><button class="link" onclick="showView('activity')">View all</button></div><div class="activity-list" id="activityList"><div class="activity-row"><span class="activity-dot green"></span><div><div class="activity-title">Loading activity…</div><div class="activity-sub">GODSEYE is checking the network</div></div><span class="activity-time">now</span></div></div></section>
</div>
<section class="panel"><div class="table-head"><h2>Client Activity</h2><div class="muted" id="clientMetricNote">Observed activity by device</div></div><div id="clientBars" style="padding:16px"><div class="empty">Collecting client evidence…</div></div></section>
<section class="panel"><div class="table-head"><h2>Devices</h2><button class="link" onclick="showView('devices')">View all devices →</button></div><div style="overflow:auto"><table><thead><tr><th>Status</th><th>Device</th><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Type</th><th>Last Seen</th></tr></thead><tbody id="devices"></tbody></table></div></section>
<div class="toolbar" style="display:none"><input id="search" class="input"><select id="status" class="filter"><option value="">All</option></select><select id="classification" class="filter"><option value="">All</option></select></div>
</div>

<div class="view" id="view-devices" style="display:none">
<div class="hero"><div><h1>Device Inventory</h1><div class="muted">All discovered devices on your network</div></div><button class="primary" onclick="openAddDevice()">＋ Add Device</button><button class="secondary" onclick="scan()">⟳ Discover Network</button></div>
<div class="toolbar"><input id="inventorySearch" class="input" placeholder="Search devices…" oninput="loadInventory()"><select id="inventoryStatus" class="filter" onchange="loadInventory()"><option value="">All statuses</option><option value="online">Online</option><option value="offline">Offline</option></select></div>
<section class="panel"><div class="table-head"><h2>Discovered Devices</h2><div class="muted" id="inventoryCount">—</div></div><div style="overflow:auto"><table><thead><tr><th>Name</th><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Type</th><th>Last Seen</th><th>Status</th><th>Actions</th></tr></thead><tbody id="inventoryRows"></tbody></table></div></section>
</div>
<div class="view" id="view-network" style="display:none">
<div class="hero"><div><h1>Network Map</h1><div class="muted">Visual view of your network topology</div></div><div><button class="primary" onclick="runFullDiscovery()">⟳ Full Discovery</button> <button class="secondary" onclick="loadNetwork()">↻ Refresh Map</button></div></div>
<section class="panel map-card"><div class="table-head"><h2>Live Network Topology</h2><div class="muted">Based on discovered devices and relationships</div></div><div class="map-canvas" id="networkCanvas"><div class="map-node"><div class="map-circle">☁</div><div class="map-label">Internet</div><div class="map-sub">External</div></div><div class="map-line"></div><div class="map-node"><div class="map-circle">▣</div><div class="map-label">Gateway / Router</div><div class="map-sub">192.168.1.1</div></div><div class="map-line"></div><div class="map-node"><div class="map-circle">▦</div><div class="map-label">Network</div><div class="map-sub">Discovering topology…</div></div></div></section>
</div>
<div class="view" id="view-monitoring" style="display:none">
<div class="hero"><div><h1>Monitors</h1><div class="muted">Configure, run, and remediate network monitoring</div></div><div class="actions"><button class="secondary" onclick="runMonitors()">▶ Run All</button><button class="primary" onclick="openMonitorEditor()">＋ Add Monitor</button></div></div>
<section class="panel"><div class="table-head"><h2>Monitoring Services</h2><div class="muted">Repeated failures automatically create Findings.</div></div><div style="overflow:auto"><table><thead><tr><th>Name</th><th>Type</th><th>Target</th><th>Interval</th><th>Status</th><th>Last Check</th><th>Response</th><th>Actions</th></tr></thead><tbody id="monitorRows"></tbody></table></div></section>
</div>
<div class="view" id="view-findings" style="display:none">
<div class="hero"><div><h1>Network Findings</h1><div class="muted">Issues and notable events detected by GODSEYE</div></div></div>
<div class="cards"><div class="card"><div class="label">Open</div><div class="num red" id="findingOpen">—</div></div><div class="card"><div class="label">Resolved</div><div class="num green" id="findingResolved">—</div></div><div class="card"><div class="label">All Findings</div><div class="num" id="findingAll">—</div></div><div class="card"><div class="label">Critical</div><div class="num red" id="findingCritical">—</div></div></div>
<section class="panel"><div class="table-head"><h2>Findings / Issues</h2><div class="muted">Explainable recommendations</div></div><div style="overflow:auto"><table><thead><tr><th>Severity</th><th>Title</th><th>Device</th><th>Detected</th><th>Status</th><th>Action</th></tr></thead><tbody id="findingRows"></tbody></table></div></section>
</div>
<div class="view" id="view-tools" style="display:none">
<div class="hero"><div><h1>Network Tools</h1><div class="muted">Diagnostics and management tools</div></div></div>
<div class="tool-grid">
<div class="tool-card"><div class="tool-icon">↗</div><h3>Ping</h3><p>Test connectivity to a host.</p><a class="primary" href="/tools#diagnostics" style="display:inline-block;text-decoration:none;border-radius:7px;padding:6px 10px;font-size:10px">Open</a></div>
<div class="tool-card"><div class="tool-icon">⌁</div><h3>Traceroute</h3><p>Trace the network route.</p><a class="primary" href="/tools#diagnostics" style="display:inline-block;text-decoration:none;border-radius:7px;padding:6px 10px;font-size:10px">Open</a></div>
<div class="tool-card"><div class="tool-icon">◎</div><h3>DNS Lookup</h3><p>Resolve domain names.</p><a class="primary" href="/tools#hostname" style="display:inline-block;text-decoration:none;border-radius:7px;padding:6px 10px;font-size:10px">Open</a></div>
<div class="tool-card"><div class="tool-icon">◉</div><h3>Port Scan</h3><p>Check open ports on a device.</p><a class="primary" href="/tools#nmap" style="display:inline-block;text-decoration:none;border-radius:7px;padding:6px 10px;font-size:10px">Open</a></div>
<div class="tool-card"><div class="tool-icon">⏻</div><h3>Wake on LAN</h3><p>Power on a device remotely.</p><a class="primary" href="/tools#wol" style="display:inline-block;text-decoration:none;border-radius:7px;padding:6px 10px;font-size:10px">Open</a></div>
<div class="tool-card"><div class="tool-icon">▣</div><h3>Device Info</h3><p>Get device and discovery details.</p><button class="primary" onclick="showView('devices')">Open</button></div>
</div></div>
<div class="view" id="view-integrations" style="display:none">
<div class="hero"><div><h1>Integrations</h1><div class="muted">Saved Pi-hole, UniFi and SNMP collectors with background synchronization</div></div><div class="actions"><a class="secondary" href="/metrics" target="_blank" style="text-decoration:none">Prometheus Metrics</a></div></div>
<div class="tool-grid">
<div class="tool-card"><div class="tool-icon">π</div><h3>Pi-hole</h3><input id="piTarget" class="input" placeholder="http://192.168.1.3" style="width:100%;margin:5px 0"><input id="piSecret" class="input" type="password" placeholder="API token / SID (leave blank to keep saved)" style="width:100%;margin:5px 0"><input id="piInterval" class="input" type="number" min="30" value="300" style="width:100%;margin:5px 0"><p><button class="primary" onclick="saveIntegration('pihole')">Save</button> <button class="secondary" onclick="syncIntegration('pihole')">Sync Now</button></p><div id="piStatus" class="muted">Not configured</div></div>
<div class="tool-card"><div class="tool-icon">U</div><h3>UniFi</h3><input id="uniTarget" class="input" placeholder="https://192.168.1.1" style="width:100%;margin:5px 0"><input id="uniUser" class="input" placeholder="Controller username" style="width:100%;margin:5px 0"><input id="uniSecret" class="input" type="password" placeholder="Password (leave blank to keep saved)" style="width:100%;margin:5px 0"><input id="uniSite" class="input" value="default" placeholder="Site" style="width:100%;margin:5px 0"><p><label class="muted"><input id="uniTls" type="checkbox" checked> Verify TLS</label></p><p><button class="primary" onclick="saveIntegration('unifi')">Save</button> <button class="secondary" onclick="syncIntegration('unifi')">Sync Now</button></p><div id="uniStatus" class="muted">Not configured</div></div>
<div class="tool-card"><div class="tool-icon">S</div><h3>SNMP</h3><input id="snmpTarget" class="input" placeholder="192.168.1.1" style="width:100%;margin:5px 0"><input id="snmpSecret" class="input" type="password" placeholder="Community (leave blank to keep saved)" style="width:100%;margin:5px 0"><input id="snmpInterval" class="input" type="number" min="30" value="300" style="width:100%;margin:5px 0"><p><button class="primary" onclick="saveIntegration('snmp')">Save</button> <button class="secondary" onclick="syncIntegration('snmp')">Sync Now</button></p><div id="snmpStatus" class="muted">Not configured</div></div>
</div>
<section class="panel"><div class="table-head"><h2>Client & Query Analytics</h2><div class="muted">Latest synchronized evidence</div></div><div id="integrationAnalytics" style="padding:16px" class="muted">Load integrations to view analytics.</div></section>
<section class="panel"><div class="table-head"><h2>Notifications</h2><div class="muted">Webhook, ntfy and SMTP delivery for findings, topology changes and scheduled reports</div></div><div style="padding:16px" class="grid"><input id="notifyWebhook" class="input" placeholder="Webhook URL"><input id="notifyNtfyServer" class="input" value="https://ntfy.sh" placeholder="ntfy server"><input id="notifyNtfy" class="input" placeholder="ntfy topic"><input id="notifySmtpHost" class="input" placeholder="SMTP host"><input id="notifySmtpPort" class="input" type="number" value="587" placeholder="SMTP port"><input id="notifySmtpUser" class="input" placeholder="SMTP username"><input id="notifySmtpPass" class="input" type="password" placeholder="SMTP password (blank keeps saved)"><input id="notifySmtpFrom" class="input" placeholder="From address"><input id="notifyEmail" class="input" placeholder="Recipient address"><select id="notifySeverity" class="filter"><option value="info">Info+</option><option value="warning" selected>Warning+</option><option value="critical">Critical only</option></select><div><button class="primary" onclick="saveNotifications()">Save Notifications</button> <button class="secondary" onclick="testNotifications()">Send Test</button></div><div id="notifyOut" class="muted"></div></div></section>
</div>
<div class="view" id="view-reports" style="display:none">
<div class="hero"><div><h1>Reports</h1><div class="muted">Live network summaries and scheduled delivery</div></div><div class="actions"><button class="primary" onclick="generateReport()">Generate Now</button></div></div>
<section class="panel"><div class="table-head"><h2>Current Network Summary</h2></div><pre id="reportSummary" style="margin:16px;white-space:pre-wrap">Loading…</pre></section>
<section class="panel"><div class="table-head"><h2>Schedule a Report</h2></div><div style="padding:16px" class="grid"><input id="reportName" class="input" placeholder="Daily network summary"><select id="reportCadence" class="filter"><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="hourly">Hourly</option></select><input id="reportHour" class="input" type="number" min="0" max="23" value="12" title="UTC hour"><button class="primary" onclick="addReportSchedule()">Add Schedule</button></div><div style="overflow:auto"><table><thead><tr><th>Name</th><th>Cadence</th><th>Next Run</th><th>Last Run</th><th></th></tr></thead><tbody id="reportSchedules"></tbody></table></div></section>
<section class="panel"><div class="table-head"><h2>Report History</h2></div><div style="overflow:auto"><table><thead><tr><th>Generated</th><th>Title</th><th>Devices</th><th>Findings</th><th>Export</th></tr></thead><tbody id="reportHistory"></tbody></table></div></section>
</div>


<div class="view" id="view-health" style="display:none">
<div class="hero"><div><h1>Raspberry Pi Health</h1><div class="muted">Appliance diagnostics, backups, retention and metrics security</div></div><div class="actions"><button class="secondary" onclick="loadHealth()">↻ Refresh</button><button class="primary" onclick="createBackup()">Create Backup</button></div></div>
<div class="cards"><div class="card"><div class="label">Overall</div><div class="num" id="healthOverall">—</div></div><div class="card"><div class="label">Hostname</div><div class="num" id="healthHost" style="font-size:16px">—</div></div><div class="card"><div class="label">Kernel</div><div class="num" id="healthKernel" style="font-size:16px">—</div></div></div>
<section class="panel"><div class="table-head"><h2>Self Diagnostics</h2><div class="muted">CPU, temperature, memory, disk, database, services and network interface</div></div><div style="overflow:auto"><table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody id="healthChecks"></tbody></table></div></section>
<section class="panel"><div class="table-head"><h2>Encrypted Secrets & Prometheus</h2><div class="muted">Integration credentials are encrypted at rest with the appliance key</div></div><div style="padding:16px"><button class="primary" onclick="rotateMetricsKey()">Generate / Rotate Metrics API Key</button><pre id="metricsKeyOut" style="white-space:pre-wrap;margin-top:12px"></pre><div class="muted">Prometheus can authenticate with Authorization: Bearer &lt;key&gt; or X-API-Key. Browser sessions can also open /metrics.</div></div></section>
<section class="panel"><div class="table-head"><h2>Retention Policies</h2><div class="muted">Days to retain local operational history</div></div><div style="padding:16px" class="grid"><label>Traffic <input id="retTraffic" class="input" type="number" min="1"></label><label>Events <input id="retEvents" class="input" type="number" min="1"></label><label>Audit <input id="retAudit" class="input" type="number" min="1"></label><label>Reports <input id="retReports" class="input" type="number" min="1"></label><label>Sync history <input id="retSync" class="input" type="number" min="1"></label><label>Notifications <input id="retNotify" class="input" type="number" min="1"></label><div><button class="primary" onclick="saveRetention()">Save & Prune</button></div></div></section>
<section class="panel"><div class="table-head"><h2>Database Backups</h2><div class="muted">SQLite online backups with integrity checks. Restore automatically creates a pre-restore safety backup.</div></div><div style="overflow:auto"><table><thead><tr><th>Created</th><th>Filename</th><th>Size</th><th>Note</th><th>Action</th></tr></thead><tbody id="backupRows"></tbody></table></div></section>
<section class="panel"><div class="table-head"><h2>Production Appliance Management</h2><div class="muted">Automatic backups, HTTPS, configuration portability and controlled updates</div></div><div style="padding:16px" class="grid"><label>Automatic backup <select id="prodAutoBackup" class="filter"><option value="1">Enabled</option><option value="0">Disabled</option></select></label><label>Backup UTC hour <input id="prodBackupHour" class="input" type="number" min="0" max="23" value="3"></label><label>Backups to keep <input id="prodBackupKeep" class="input" type="number" min="1" max="100" value="14"></label><label>Update channel <select id="prodUpdateChannel" class="filter"><option value="stable">Stable</option><option value="beta">Beta</option></select></label><div><button class="primary" onclick="saveProductionSettings()">Save Appliance Settings</button> <a class="secondary" href="/api/v1/config/export" style="text-decoration:none">Export Config</a></div><div id="httpsOut" class="muted"></div></div></section>
<section class="panel"><div class="table-head"><h2>Controlled Software Update</h2><div class="muted">Stage a GODSEYE ZIP, verify package structure and SHA-256, then explicitly confirm application.</div></div><div style="padding:16px"><input id="updateFile" type="file" accept=".zip" class="input"> <button class="primary" onclick="stageUpdate()">Stage & Preflight</button><pre id="updateOut" class="result">No update staged.</pre><button class="danger" id="applyUpdateBtn" style="display:none" onclick="applyUpdate()">Apply Staged Update</button></div></section>
<section class="panel"><div class="table-head"><h2>HTTPS / TLS</h2><div class="muted">Nginx reverse proxy with a self-signed certificate or Let's Encrypt.</div></div><div style="padding:16px"><div id="tlsStatus" class="muted">Checking…</div><pre class="result">Run on the Raspberry Pi as root:
sudo godseye-https-setup godseye.local self-signed

Or for a public DNS name:
sudo godseye-https-setup godseye.example.com letsencrypt</pre></div></section>
<section class="panel"><div class="table-head"><h2>Notification Delivery History</h2><div class="muted">Review and retry prior deliveries.</div></div><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Status</th><th>Attempts</th><th>Action</th></tr></thead><tbody id="notificationHistoryRows"></tbody></table></div></section>
<section class="panel"><div class="table-head"><h2>Controlled Remediation</h2><div class="muted">Actions are restricted to configured Pi-hole/UniFi integrations and require exact administrator confirmation.</div></div><div style="padding:16px" class="grid"><select id="remediationAction" class="filter"><option value="pihole_block_domain">Pi-hole: Block Domain</option><option value="unifi_quarantine">UniFi: Quarantine Client</option></select><input id="remediationTarget" class="input" placeholder="example.com or AA:BB:CC:DD:EE:FF"><button class="danger" onclick="runRemediation()">Review & Execute</button><div id="remediationOut" class="muted"></div></div></section>
</div>
<div class="view" id="view-activity" style="display:none">
<section class="panel"><h2>Recent Activity</h2><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Event</th><th>Device</th><th>IP</th><th>Details</th></tr></thead><tbody id="events"></tbody></table></div></section>
</div>

<div class="view" id="view-security" style="display:none">
<section class="panel"><h2>Two-Factor Authentication</h2><div id="mfaStatus" style="padding:16px 18px"></div></section>
</div>

<div class="view" id="view-rules" style="display:none">
<section class="panel" id="rulesPanel"><h2>Alert Rules</h2>
<form class="userForm" onsubmit="return createRule(event)" style="flex-wrap:wrap">
<input class="input" id="ruleName" placeholder="Rule name" required style="flex:1;min-width:160px">
<select class="filter" id="ruleType" onchange="updateRuleFields()"><option value="new_device_burst">New device burst</option><option value="offline_duration">Offline duration</option></select>
<span id="ruleFieldsBurst" style="display:flex;gap:6px;align-items:center"><input class="input" id="ruleBurstCount" type="number" min="1" value="10" style="width:80px" title="Count"><span class="muted">new devices in</span><input class="input" id="ruleBurstWindow" type="number" min="1" value="5" style="width:80px" title="Window (minutes)"><span class="muted">min</span></span>
<span id="ruleFieldsOffline" style="display:none;gap:6px;align-items:center"><span class="muted">offline</span><input class="input" id="ruleOfflineMinutes" type="number" min="1" value="30" style="width:80px" title="Minutes"><span class="muted">min, classes:</span><input class="input" id="ruleOfflineClasses" placeholder="known,investigate (blank=any)" style="width:190px"></span>
<select class="filter" id="ruleSeverity"><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select>
<button class="primary" type="submit">Add rule</button>
</form>
<div style="overflow:auto"><table><thead><tr><th>Name</th><th>Type</th><th>Condition</th><th>Severity</th><th>Last triggered</th><th>Enabled</th><th></th></tr></thead><tbody id="rules"></tbody></table></div>
</section>
</div>

<div class="view" id="view-users" style="display:none">
<section class="panel" id="usersPanel"><h2>Users</h2>
<form class="userForm" onsubmit="return createUser(event)"><input class="input" id="newUsername" placeholder="Username" required><input class="input" id="newUserPassword" type="password" placeholder="Password (min __MIN_PASSWORD_LENGTH__ chars)" required minlength="__MIN_PASSWORD_LENGTH__"><select class="filter" id="newUserRole"><option value="readonly">Read-only</option><option value="auditor">Auditor</option><option value="operator">Operator</option><option value="admin">Admin</option></select><button class="primary" type="submit">Add user</button></form>
<div style="overflow:auto"><table><thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Last login</th><th>Password changed</th><th>Must change PW</th><th>MFA</th><th></th></tr></thead><tbody id="users"></tbody></table></div>
</section>
</div>

<div class="view" id="view-audit" style="display:none">
<section class="panel" id="auditPanel"><h2>Audit Log</h2>
<div style="overflow:auto"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead><tbody id="auditRows"></tbody></table></div>
</section>
</div>

</div></main>
</div>
</div>
<div id="deviceModal" class="modal" style="display:none">
  <div class="modal-card">
    <div class="modal-head"><div><h2>Add Device</h2><div class="muted">Add a known device manually, or use Discover Network for automatic discovery.</div></div><button class="icon-btn" onclick="closeAddDevice()">×</button></div>
    <form onsubmit="return submitAddDevice(event)" class="modal-form">
      <label>Name<input class="input" id="deviceName" required placeholder="Living Room TV"></label>
      <label>IP address<input class="input" id="deviceIp" placeholder="192.168.1.50"></label>
      <label>MAC address<input class="input" id="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label>
      <label>Vendor<input class="input" id="deviceVendor" placeholder="Samsung"></label>
      <label>Type<input class="input" id="deviceType" placeholder="TV, Router, Computer…"></label>
      <label>Classification<select class="filter" id="deviceClass"><option value="known">Known</option><option value="new">New</option><option value="investigate">Investigate</option><option value="ignored">Ignored</option></select></label>
      <label>Notes<textarea class="input" id="deviceNotes" rows="3" placeholder="Optional notes"></textarea></label>
      <div class="err" id="deviceAddErr"></div>
      <div class="modal-actions"><button type="button" class="secondary" onclick="closeAddDevice()">Cancel</button><button type="submit" class="primary">Add Device</button></div>
    </form>
  </div>
</div>
<div id="monitorModal" class="modal" style="display:none"><div class="modal-card" style="max-width:620px"><div class="modal-head"><div><h2 id="monitorModalTitle">Add Monitor</h2><div class="muted">Persistent Raspberry Pi-native monitoring.</div></div><button class="icon-btn" onclick="closeMonitorEditor()">×</button></div><div class="modal-form"><label>Name<input class="input" id="monName" placeholder="Gateway health"></label><label>Type<select class="filter" id="monKind"><option value="website">Website / HTTP</option><option value="dhcp">DHCP leases</option><option value="public_ip">Public IP</option><option value="pihole">Pi-hole</option><option value="unifi">UniFi</option><option value="snmp">SNMP</option></select></label><label>Target<input class="input" id="monTarget" placeholder="https://example.com or 192.168.1.1"></label><label>Interval (seconds)<input class="input" id="monInterval" type="number" min="30" value="300"></label><label>Enabled<select class="filter" id="monEnabled"><option value="1">Enabled</option><option value="0">Disabled</option></select></label><label>Options JSON<textarea class="input" id="monOptions" rows="4">{}</textarea></label><div class="err" id="monitorEditorOut"></div><div class="modal-actions"><button class="secondary" onclick="closeMonitorEditor()" type="button">Cancel</button><button class="primary" onclick="saveMonitor()" type="button">Save Monitor</button></div></div></div></div>
<div id="deviceIntelModal" class="modal" style="display:none">
  <div class="modal-card intel-modal-card">
    <div class="modal-head"><div><h2>Device Intelligence</h2><div class="muted">Identity, history, diagnostics, findings, and recommended actions.</div></div><button class="icon-btn" onclick="closeDeviceIntel()">×</button></div>
    <div id="deviceIntelContent"><div class="empty">Loading device intelligence…</div></div>
  </div>
</div>

<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const CLASS_CYCLE={new:'known',known:'ignored',ignored:'investigate',investigate:'new'};
const CLASS_LABEL={new:'New',known:'Known',ignored:'Ignored',investigate:'Investigate'};
let ME=null;
let PENDING_MFA_TOKEN=null;
function getCookie(name){const m=document.cookie.match('(?:^|; )'+name+'=([^;]*)');return m?decodeURIComponent(m[1]):null}
async function json(url,opt={}){opt.headers=opt.headers||{};if(opt.method&&opt.method!=='GET'){let csrf=getCookie('godseye_csrf');if(!csrf){await fetch('/api/v1/auth/csrf');csrf=getCookie('godseye_csrf')}opt.headers['X-CSRF-Token']=csrf||''}let r=await fetch(url,opt);if(r.status===401){showLogin();throw new Error('unauthenticated')}if(!r.ok){let t=await r.text();throw new Error(t)}return r.status===204?null:r.json()}
function toggleUserMenu(){const m=document.getElementById("userMenu");if(m)m.style.display=m.style.display==="none"?"block":"none"}
function showLogin(){document.getElementById('app').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('setupOverlay').style.display='none';document.getElementById('authOverlay').style.display='grid'}
async function checkInitialSetup(){try{let r=await fetch('/api/v1/auth/setup/status');let d=await r.json();if(d.setup_required){document.getElementById('authOverlay').style.display='none';document.getElementById('setupOverlay').style.display='grid';return true}}catch(e){}return false}
async function doInitialSetup(e){e.preventDefault();const err=document.getElementById('setupErr');err.textContent='';if(setupPass.value!==setupPass2.value){err.textContent='Passwords do not match';return false}try{let r=await fetch('/api/v1/auth/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:'',new_password:setupPass.value})});if(!r.ok){let t=await r.json().catch(()=>({}));err.textContent=t.detail||'Could not create password';return false}document.getElementById('setupOverlay').style.display='none';document.getElementById('authOverlay').style.display='grid';loginUser.value='admin';loginPass.value='';loginPass.focus()}catch(e){err.textContent='Setup failed'}return false}
function showApp(){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('app').style.display='block'}
const VIEW_LOADERS={
  devices:()=>loadDevices(),
  network:()=>loadNetwork(),
  monitoring:()=>loadMonitoring(),
  findings:()=>loadFindings(),
  integrations:()=>loadIntegrations(),
  reports:()=>loadReports(),
  health:()=>loadHealth(),
  users:()=>loadUsers(),
  audit:()=>loadAudit(),
  rules:()=>loadRules(),
  security:()=>loadSecurity(),
  activity:()=>load()
};
function showView(name,updateHash=true){
  const target=document.getElementById('view-'+name);
  if(!target){console.error('GODSEYE navigation target missing:',name);return false}
  document.querySelectorAll('.view').forEach(v=>{v.style.display='none';v.setAttribute('aria-hidden','true')});
  target.style.display='block';target.setAttribute('aria-hidden','false');
  document.querySelectorAll('.navitem[data-view]').forEach(b=>{b.classList.remove('active');b.removeAttribute('aria-current')});
  const btn=document.querySelector('.navitem[data-view="'+name+'"]');
  if(btn){btn.classList.add('active');btn.setAttribute('aria-current','page')}
  if(updateHash && location.hash!=='#'+name){history.replaceState(null,'','#'+name)}
  const loader=VIEW_LOADERS[name];
  if(loader){Promise.resolve().then(loader).catch(e=>console.error('GODSEYE view load failed:',name,e))}
  return true
}
window.showView=showView;
function installSidebarNavigation(){
  const nav=document.querySelector('.navlist');
  if(!nav)return;
  nav.addEventListener('click',e=>{
    const btn=e.target.closest('.navitem[data-view]');
    if(!btn || !nav.contains(btn))return;
    e.preventDefault();e.stopPropagation();showView(btn.dataset.view,true);
  });
  window.addEventListener('hashchange',()=>{
    const name=(location.hash||'#overview').slice(1);
    if(document.getElementById('view-'+name))showView(name,false);
  });
}
installSidebarNavigation();
async function doLogin(e){e.preventDefault();const err=document.getElementById('loginErr');err.textContent='';try{let r=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:loginUser.value,password:loginPass.value})});if(r.status===423){err.textContent='Account temporarily locked due to repeated failed logins. Try again later.';return false}if(!r.ok){err.textContent='Invalid username or password';return false}let data=await r.json();if(data.mfa_required){PENDING_MFA_TOKEN=data.pending_token;document.getElementById('authOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='grid';return false}if(data.must_change_password){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='grid';return false}await boot()}catch(e){err.textContent='Sign-in failed'}return false}
async function doMfaVerify(e){e.preventDefault();const err=document.getElementById('mfaLoginErr');err.textContent='';try{let r=await fetch('/api/v1/auth/mfa/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pending_token:PENDING_MFA_TOKEN,code:mfaCode.value.trim()})});if(!r.ok){err.textContent='Invalid code';return false}let data=await r.json();PENDING_MFA_TOKEN=null;if(data.must_change_password){document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('pwOverlay').style.display='grid';return false}await boot()}catch(e){err.textContent='Verification failed'}return false}
function openChangePassword(){document.getElementById('pwOverlay').style.display='grid'}
async function doChangePassword(e){e.preventDefault();const err=document.getElementById('pwErr');err.textContent='';try{await json('/api/v1/auth/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:curPass.value,new_password:newPass.value})});await boot()}catch(e){err.textContent='Could not change password — check your current password'}return false}
async function logout(){await fetch('/api/v1/auth/logout',{method:'POST',headers:{'X-CSRF-Token':getCookie('godseye_csrf')||''}});showLogin()}
async function loadDevices(){let q=new URLSearchParams();if(search.value)q.set('search',search.value);if(status.value)q.set('status',status.value);if(classification.value)q.set('classification',classification.value);let d=await json('/api/v1/devices?'+q);const canEdit=ME&&ME.role==='admin';devices.innerHTML=d.length?d.map(x=>`<tr><td class="${esc(x.status)}"><span class="dot">●</span> ${esc(x.status).replace('_',' ')}</td><td><div class="name">${esc(x.name||x.hostname||'Unknown device')}</div><div class="muted">${esc(x.device_type||'Unclassified')}</div></td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td><td>${esc(x.vendor||'—')}</td><td><button class="pill ${esc(x.classification)}" ${canEdit?`onclick="cycleClass(${x.id},'${x.classification}')"`:'disabled'}>${CLASS_LABEL[x.classification]||x.classification}</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">No devices match this filter.</td></tr>'}
async function loadUsers(){if(!ME||ME.role!=='admin'){usersPanel.style.display='none';return}usersPanel.style.display='block';let u=await json('/api/v1/users');users.innerHTML=u.map(x=>{let mustChange=x.must_change_password?(x.must_change_password_by?`yes, by ${esc(new Date(x.must_change_password_by).toLocaleDateString())}`:'yes'):'no';return `<tr><td>${esc(x.username)}</td><td><span class="pill ${esc(x.role)}">${esc(x.role)}</span></td><td>${esc(new Date(x.created_at).toLocaleDateString())}</td><td>${x.last_login_at?esc(new Date(x.last_login_at).toLocaleString()):'never'}</td><td>${x.password_changed_at?esc(new Date(x.password_changed_at).toLocaleDateString()):'—'}</td><td>${mustChange}</td><td>${x.mfa_enabled?'yes':'no'}</td><td>${x.username===ME.username?'':`<button class="link" onclick="removeUser(${x.id},'${esc(x.username)}')">Remove</button>${x.mfa_enabled?` <button class="link" onclick="resetUserMfa(${x.id},'${esc(x.username)}')">Reset MFA</button>`:''}`}</td></tr>`}).join('')}
async function loadAudit(){if(!ME||!['admin','auditor'].includes(ME.role)){auditPanel.style.display='none';return}auditPanel.style.display='block';let a=await json('/api/v1/audit?limit=50');auditRows.innerHTML=a.length?a.map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td>${esc(x.actor)}</td><td><span class="pill">${esc(x.action)}</span></td><td>${esc(x.target||'—')}</td><td>${esc(x.details||'')}</td><td>${esc(x.ip||'—')}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No audit entries yet.</td></tr>'}
async function loadSecurity(){const el=document.getElementById('mfaStatus');if(ME.mfa_enabled){el.innerHTML=`<div class="muted">Two-factor authentication is <b style="color:#50e3a4">enabled</b> on this account.</div><button class="link" style="margin-top:10px" onclick="startMfaDisable()">Disable MFA</button>`}else{el.innerHTML=`<div class="muted">Two-factor authentication is <b style="color:#f7c948">not enabled</b>. Add it for a second layer of protection beyond your password.</div><button class="primary" style="margin-top:10px" onclick="startMfaSetup()">Set up MFA</button>`}}
function updateRuleFields(){const t=document.getElementById('ruleType').value;document.getElementById('ruleFieldsBurst').style.display=t==='new_device_burst'?'flex':'none';document.getElementById('ruleFieldsOffline').style.display=t==='offline_duration'?'flex':'none'}
async function loadRules(){if(!ME||ME.role!=='admin'){rulesPanel.style.display='none';return}rulesPanel.style.display='block';let r=await json('/api/v1/rules');rules.innerHTML=r.length?r.map(x=>{let p;try{p=JSON.parse(x.params)}catch(e){p={}}let cond=x.rule_type==='new_device_burst'?`${p.count}+ new devices in ${p.window_minutes}m`:`offline ${p.minutes}m+ (${(p.classifications&&p.classifications.length?p.classifications:['any']).join(', ')})`;return `<tr><td>${esc(x.name)}</td><td>${esc(x.rule_type)}</td><td>${esc(cond)}</td><td><span class="pill ${esc(x.severity)}">${esc(x.severity)}</span></td><td>${x.last_triggered_at?esc(new Date(x.last_triggered_at).toLocaleString()):'never'}</td><td><input type="checkbox" ${x.enabled?'checked':''} onchange="toggleRule(${x.id},this.checked)"></td><td><button class="link" onclick="removeRule(${x.id},'${esc(x.name)}')">Remove</button></td></tr>`}).join(''):'<tr><td colspan="7" class="empty">No rules configured yet.</td></tr>'}
async function createRule(e){e.preventDefault();const type=document.getElementById('ruleType').value;let params;if(type==='new_device_burst'){params={count:parseInt(ruleBurstCount.value,10),window_minutes:parseFloat(ruleBurstWindow.value)}}else{params={minutes:parseFloat(ruleOfflineMinutes.value)};const raw=ruleOfflineClasses.value.trim();if(raw)params.classifications=raw.split(',').map(s=>s.trim()).filter(Boolean)}try{await json('/api/v1/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:ruleName.value,rule_type:type,params:params,severity:ruleSeverity.value})});ruleName.value='';await loadRules()}catch(e){alert('Could not create rule: '+e.message)}return false}
async function toggleRule(id,enabled){await json('/api/v1/rules/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:enabled})});await loadRules()}
async function removeRule(id,name){if(!confirm('Remove rule "'+name+'"?'))return;await json('/api/v1/rules/'+id,{method:'DELETE'});await loadRules()}
async function startMfaSetup(){let data=await json('/api/v1/auth/mfa/setup',{method:'POST'});const el=document.getElementById('mfaStatus');el.innerHTML=`<div class="muted">In Google Authenticator (or any TOTP app), choose "Enter a setup key" and type this in:</div><div style="font-family:monospace;font-size:16px;background:#0d141f;border:1px solid #2b3a52;border-radius:8px;padding:10px;margin:10px 0;word-break:break-all">${esc(data.secret)}</div><div class="muted" style="font-size:11px;word-break:break-all">${esc(data.otpauth_uri)}</div><form onsubmit="return confirmMfaSetup(event)" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap"><input class="input" id="mfaConfirmCode" placeholder="Enter 6-digit code to confirm" required style="flex:1;min-width:180px"><button class="primary" type="submit">Confirm</button></form><div class="err" id="mfaSetupErr"></div>`}
async function confirmMfaSetup(e){e.preventDefault();const err=document.getElementById('mfaSetupErr');err.textContent='';try{let data=await json('/api/v1/auth/mfa/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:mfaConfirmCode.value.trim()})});const el=document.getElementById('mfaStatus');el.innerHTML=`<div class="muted" style="color:#50e3a4">MFA enabled. Save these one-time backup codes somewhere safe — each works once if you lose access to your authenticator app:</div><div style="font-family:monospace;background:#0d141f;border:1px solid #2b3a52;border-radius:8px;padding:10px;margin:10px 0">${data.backup_codes.map(esc).join('<br>')}</div><button class="primary" onclick="boot()">Done</button>`;ME=await json('/api/v1/auth/me')}catch(e){err.textContent='Incorrect code — try again'}return false}
async function startMfaDisable(){const el=document.getElementById('mfaStatus');el.innerHTML=`<form onsubmit="return confirmMfaDisable(event)" style="display:flex;flex-direction:column;gap:8px;max-width:320px"><input class="input" id="mfaDisablePw" type="password" placeholder="Current password" required><input class="input" id="mfaDisableCode" placeholder="6-digit code or backup code" required><button class="danger" type="submit">Disable MFA</button><div class="err" id="mfaDisableErr"></div></form>`}
async function confirmMfaDisable(e){e.preventDefault();const err=document.getElementById('mfaDisableErr');err.textContent='';try{await json('/api/v1/auth/mfa/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:mfaDisablePw.value,code:mfaDisableCode.value.trim()})});ME=await json('/api/v1/auth/me');loadSecurity()}catch(e){err.textContent='Could not disable MFA — check password and code'}return false}
async function resetUserMfa(id,username){if(!confirm('Reset MFA for "'+username+'"? They will need to set it up again.'))return;await json('/api/v1/users/'+id+'/mfa/reset',{method:'POST'});await loadUsers()}
async function createUser(e){e.preventDefault();try{await json('/api/v1/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:newUsername.value,password:newUserPassword.value,role:newUserRole.value})});newUsername.value='';newUserPassword.value='';await loadUsers()}catch(e){alert('Could not create user: '+e.message)}return false}
async function removeUser(id,username){if(!confirm('Remove user "'+username+'"?'))return;await json('/api/v1/users/'+id,{method:'DELETE'});await loadUsers()}
async function load(){let h=await json('/api/v1/health');total.textContent=h.total;online.textContent=h.online;unknown.textContent=h.needs_review;const badge=document.getElementById('needsReviewBadge');if(badge)badge.textContent=h.needs_review;eventsCount.textContent=h.events;updated.textContent='Last refreshed '+new Date().toLocaleTimeString();lastScan.textContent=h.scanner.detail;const hb=document.getElementById('healthbar');if(!h.scanner.healthy){hb.className='healthbar bad';hb.textContent='⚠ Scanner unhealthy — '+h.scanner.detail;hb.style.display='block'}else{hb.style.display='none'}await loadDevices();loadTraffic().catch(()=>{});let e=await json('/api/v1/events?limit=30');events.innerHTML=e.length?e.map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td><span class="pill">${esc(x.event_type)}</span></td><td>${esc(x.mac)}</td><td>${esc(x.ip)}</td><td>${esc(x.details)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No activity yet.</td></tr>';const al=document.getElementById('activityList');if(al)al.innerHTML=e.slice(0,5).map((x,i)=>`<div class="activity-row"><span class="activity-dot ${i%2?'':'green'}"></span><div><div class="activity-title">${esc(x.event_type||'Network activity')}</div><div class="activity-sub">${esc(x.mac||x.ip||'Network event')} ${x.details?'· '+esc(x.details):''}</div></div><span class="activity-time">${esc(new Date(x.created_at).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'}))}</span></div>`).join('')||'<div class="empty">No recent activity.</div>';const tr=document.getElementById('onlineTrend');if(tr&&h.total)tr.textContent=Math.round((h.online/h.total)*100)+'%';}
async function cycleClass(id,current){await json('/api/v1/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({classification:CLASS_CYCLE[current]||'new'})});load()}
async function scan(){
  const btn=document.getElementById('scanBtn');
  if(btn){btn.disabled=true;btn.textContent='⟳ Scanning…'}
  try{
    const r=await json('/api/v1/scan',{method:'POST'});
    updated.textContent='Scan queued — waiting for scanner…';
    let attempts=0;
    const poll=async()=>{
      attempts++;
      try{
        const st=await json('/api/v1/scan/status');
        const req=st.request;
        if(req && req.id===r.request_id && req.status==='completed'){
          updated.textContent='Scan complete — '+(req.devices_found??0)+' devices found';
          await load();
          if(btn){btn.disabled=false;btn.textContent='⟳ Scan Now'}
          return;
        }
        if(req && req.id===r.request_id && req.status==='failed'){
          updated.textContent='Scan failed: '+(req.error||'unknown scanner error');
          if(btn){btn.disabled=false;btn.textContent='⟳ Scan Now'}
          return;
        }
      }catch(e){}
      if(attempts<30)setTimeout(poll,1000);
      else{updated.textContent='Scan is still queued. Check scanner health for details.';if(btn){btn.disabled=false;btn.textContent='⟳ Scan Now'}}
    };
    poll();
  }catch(e){
    updated.textContent='Unable to queue scan: '+e.message;
    if(btn){btn.disabled=false;btn.textContent='⟳ Scan Now'}
  }
}
function openAddDevice(){document.getElementById('deviceModal').style.display='grid'}
function closeAddDevice(){document.getElementById('deviceModal').style.display='none'}
async function submitAddDevice(e){e.preventDefault();const err=document.getElementById('deviceAddErr');err.textContent='';try{await json('/api/v1/devices',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:deviceName.value.trim(),ip:deviceIp.value.trim()||null,mac:deviceMac.value.trim(),vendor:deviceVendor.value.trim()||null,device_type:deviceType.value.trim()||'unknown',classification:deviceClass.value,notes:deviceNotes.value.trim()})});closeAddDevice();e.target.reset();deviceClass.value='known';await load();if(document.getElementById('view-devices').style.display!=='none')await loadInventory()}catch(e){err.textContent='Could not add device: '+e.message}return false}

async function loadInventory(){try{let q=new URLSearchParams();if(inventorySearch.value)q.set('search',inventorySearch.value);if(inventoryStatus.value)q.set('status',inventoryStatus.value);let d=await json('/api/v1/devices?'+q);inventoryCount.textContent=d.length+' devices';inventoryRows.innerHTML=d.length?d.map(x=>`<tr><td><div class="device-name"><span class="device-icon">●</span><div><button class="link name" onclick="openDeviceIntel(${x.id})">${esc(x.name||x.hostname||'Unknown device')}</button><div class="muted">${esc(x.device_type||'Unclassified')}</div></div></div></td><td>${esc(x.ip||'—')}</td><td>${esc(x.mac)}</td><td>${esc(x.vendor||'—')}</td><td>${esc(x.device_type||'—')}</td><td>${x.last_seen?esc(new Date(x.last_seen).toLocaleString()):'—'}</td><td><span class="status-badge">${esc(x.status||'unknown')}</span></td><td><button class="secondary" onclick="openDeviceIntel(${x.id})">Details</button></td></tr>`).join(''):'<tr><td colspan="8" class="empty">No devices discovered yet. Click Scan Now to discover the network.</td></tr>'}catch(e){inventoryRows.innerHTML='<tr><td colspan="8" class="empty">Unable to load devices.</td></tr>'}}
let ACTIVE_DEVICE_ID=null;
function closeDeviceIntel(){document.getElementById('deviceIntelModal').style.display='none';ACTIVE_DEVICE_ID=null}
function fmtAgo(seconds){if(seconds===null||seconds===undefined)return '—';if(seconds<60)return seconds+' sec ago';if(seconds<3600)return Math.floor(seconds/60)+' min ago';if(seconds<86400)return Math.floor(seconds/3600)+' hr ago';return Math.floor(seconds/86400)+' days ago'}
async function openDeviceIntel(id){ACTIVE_DEVICE_ID=id;const modal=document.getElementById('deviceIntelModal');const box=document.getElementById('deviceIntelContent');modal.style.display='grid';box.innerHTML='<div class="empty">Loading device intelligence…</div>';try{const r=await json('/api/v1/devices/'+id+'/intelligence');renderDeviceIntel(r)}catch(e){box.innerHTML='<div class="err">Unable to load device intelligence: '+esc(e.message)+'</div>'}}
function renderDeviceIntel(r){const d=r.device,s=r.summary||{},risk=s.risk_score||0,riskClass=risk>=50?'risk-high':risk>=20?'risk-med':'risk-low';const events=(r.events||[]).slice(0,12);const ips=(r.ip_history||[]).slice(0,10);const issues=(r.issues||[]).filter(x=>x.status==='open');const sources=(r.sources||[]);document.getElementById('deviceIntelContent').innerHTML=`<div class="intel-hero"><div class="intel-title"><div class="intel-big-icon">◉</div><div><h2 style="margin:0">${esc(d.name||d.hostname||'Unknown device')}</h2><div class="muted">${esc(d.ip||'No IP')} · ${esc(d.mac)} · ${esc(d.vendor||'Unknown vendor')}</div></div></div><span class="status-badge">${esc(d.status||'unknown')}</span></div><div class="intel-grid"><div class="intel-stat"><div class="k">Risk score</div><div class="v ${riskClass}">${risk}/100</div></div><div class="intel-stat"><div class="k">Evidence sources</div><div class="v">${s.source_count||0}</div></div><div class="intel-stat"><div class="k">Known IPs</div><div class="v">${s.known_ip_count||0}</div></div><div class="intel-stat"><div class="k">Last seen</div><div class="v" style="font-size:13px">${fmtAgo(s.seconds_since_seen)}</div></div></div><div class="intel-actions"><button class="primary" onclick="diagnoseActiveDevice()">🩺 Diagnose</button><button class="secondary" onclick="recheckActiveDevice()">↻ Recheck</button>${d.ip?`<a class="secondary" href="/tools#ports" style="text-decoration:none">Port Scan</a>`:''}${d.ip?`<a class="secondary" href="/tools#diagnostics" style="text-decoration:none">Network Tools</a>`:''}</div><div id="deviceDiagOut"></div><div class="intel-sections"><section class="intel-section"><h3>Identity</h3><div class="intel-body intel-kv"><div class="k">Name</div><div>${esc(d.name||'—')}</div><div class="k">Hostname</div><div>${esc(d.hostname||'—')}</div><div class="k">IP address</div><div>${esc(d.ip||'—')}</div><div class="k">MAC address</div><div>${esc(d.mac)}</div><div class="k">Vendor</div><div>${esc(d.vendor||'—')}</div><div class="k">Type</div><div>${esc(d.device_type||'—')}</div><div class="k">Classification</div><div>${esc(d.classification||'—')}</div><div class="k">First seen</div><div>${d.first_seen?esc(new Date(d.first_seen).toLocaleString()):'—'}</div></div></section><section class="intel-section"><h3>GODSEYE Recommendations</h3><div class="intel-body"><ul class="intel-list">${(r.recommendations||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div></section><section class="intel-section"><h3>Evidence Sources</h3><div class="intel-body">${sources.length?sources.map(x=>`<div class="timeline-row"><b>${esc(x.source)}</b> · ${esc(x.ip||'—')}<div class="muted">Last seen ${x.last_seen?esc(new Date(x.last_seen).toLocaleString()):'—'}</div></div>`).join(''):'<div class="muted">Inventory evidence only.</div>'}</div></section><section class="intel-section"><h3>IP History</h3><div class="intel-body timeline">${ips.length?ips.map(x=>`<div class="timeline-row"><b>${esc(x.ip)}</b> · ${esc(x.source)}<div class="muted">${x.first_seen?esc(new Date(x.first_seen).toLocaleString()):'—'} → ${x.last_seen?esc(new Date(x.last_seen).toLocaleString()):'—'}</div></div>`).join(''):'<div class="muted">No IP history recorded yet.</div>'}</div></section><section class="intel-section"><h3>Recent Events</h3><div class="intel-body timeline">${events.length?events.map(x=>`<div class="timeline-row"><b>${esc(x.event_type)}</b> · ${esc(x.ip||'—')}<div class="muted">${x.created_at?esc(new Date(x.created_at).toLocaleString()):'—'} · ${esc(x.details||'')}</div></div>`).join(''):'<div class="muted">No device events recorded yet.</div>'}</div></section><section class="intel-section"><h3>Open Findings</h3><div class="intel-body">${issues.length?issues.map(x=>`<div class="timeline-row"><b>${esc(x.title)}</b> <span class="status-badge severity-${esc((x.severity||'info').toLowerCase())}">${esc(x.severity||'info')}</span><div class="muted">${esc(x.recommendation||'')}</div></div>`).join(''):'<div class="muted">No open findings for this device.</div>'}</div></section></div>`}
async function diagnoseActiveDevice(){if(!ACTIVE_DEVICE_ID)return;const out=document.getElementById('deviceDiagOut');out.innerHTML='<div class="panel" style="padding:12px">Running diagnostics…</div>';try{const r=await json('/api/v1/devices/'+ACTIVE_DEVICE_ID+'/diagnose',{method:'POST'});out.innerHTML=`<div class="panel" style="padding:12px"><b>${r.ok?'✓ Reachable':'⚠ Reachability problem'}</b><div class="muted" style="margin-top:5px">Packet loss: ${esc(r.ping?.packet_loss_percent??'—')}% · Target: ${esc(r.target||'—')}</div><ul class="intel-list">${(r.recommendations||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div>`}catch(e){out.innerHTML='<div class="err">Diagnostics failed: '+esc(e.message)+'</div>'}}
async function recheckActiveDevice(){if(!ACTIVE_DEVICE_ID)return;const out=document.getElementById('deviceDiagOut');out.innerHTML='<div class="panel" style="padding:12px">Rechecking device…</div>';try{const r=await json('/api/v1/devices/'+ACTIVE_DEVICE_ID+'/recheck',{method:'POST'});out.innerHTML=`<div class="panel" style="padding:12px"><b>${r.ok?'✓ Device is reachable':'⚠ Device is still unreachable'}</b></div>`;await openDeviceIntel(ACTIVE_DEVICE_ID);await loadInventory();await load()}catch(e){out.innerHTML='<div class="err">Recheck failed: '+esc(e.message)+'</div>'}}

async function loadNetwork(){try{const t=await json('/api/v1/intelligence/topology/live');const nodes=t.nodes||[],links=t.links||[];const byId={};nodes.forEach(n=>byId[n.id]=n);const gateway=t.gateway||'gateway';const childLinks={};links.forEach(l=>{(childLinks[l.parent]||(childLinks[l.parent]=[])).push(l)});const icon=n=>n.type==='internet'?'☁':n.type==='gateway'?'▣':String(n.type||'').toLowerCase().includes('wifi')?'◉':String(n.type||'').toLowerCase().includes('switch')?'▦':'●';const card=(n,link)=>`<div class="map-node" title="${esc((link?.link_type||'node')+(link?.details?.source?' · '+link.details.source:''))}"><div class="map-circle">${icon(n)}</div><div class="map-label">${esc(n.label||n.id)}</div><div class="map-sub">${esc(n.ip||n.mac||n.type||'—')}</div><div class="map-sub">${esc(n.vendor||'')} ${esc(n.status||'')}</div>${link?`<div class="pill" style="margin-top:5px">${esc(link.link_type||'link')}${link.details?.source?' · '+esc(link.details.source):''}</div>`:''}</div>`;const renderBranch=(link,depth=0)=>{const n=byId[link.child];if(!n)return'';const kids=(childLinks[n.id]||[]).filter(x=>x.child!==gateway).slice(0,12);return `<div style="display:flex;flex-direction:column;align-items:center;gap:6px">${card(n,link)}${kids.length&&depth<2?`<div class="map-line" style="height:18px"></div><div class="map-children">${kids.map(k=>renderBranch(k,depth+1)).join('')}</div>`:''}</div>`};const roots=(childLinks[gateway]||[]).filter(l=>byId[l.child]);const attached=new Set();links.forEach(l=>attached.add(l.child));const extra=nodes.filter(n=>!['internet',gateway].includes(n.id)&&!attached.has(n.id)).map(n=>({parent:gateway,child:n.id,link_type:'unattached',details:{source:'inventory'}}));const branches=[...roots,...extra].slice(0,40).map(l=>renderBranch(l)).join('');networkCanvas.innerHTML=`${card(byId.internet||{id:'internet',label:'Internet',type:'internet'})}<div class="map-line"></div>${card(byId[gateway]||{id:gateway,label:'Gateway / Router',type:'gateway',ip:t.gateway},(childLinks.internet||[])[0])}<div class="map-line"></div><div class="map-children">${branches||'<div class="map-node"><div class="map-circle">?</div><div class="map-label">No devices</div><div class="map-sub">Run Full Discovery</div></div>'}</div><div class="muted" style="margin-top:18px;text-align:center">${nodes.length} nodes · ${links.length} links · gateway ${esc(t.gateway||'unknown')} · relationship badges show topology evidence</div>`}catch(e){networkCanvas.innerHTML='<div class="empty">Topology is not available yet: '+esc(e.message)+'</div>'}}
async function runFullDiscovery(){networkCanvas.innerHTML='<div class="empty">Running ARP, Nmap, neighbors, mDNS, NetBIOS, DHCP and configured integration discovery…</div>';try{const r=await json('/api/v1/discovery/full',{method:'POST'});await loadNetwork();const parts=Object.entries(r.sources||{}).map(([k,v])=>k+': '+v.count).join(' · ');alert('Full discovery complete. '+r.total_observations+' correlated observations.\n'+parts)}catch(e){networkCanvas.innerHTML='<div class="empty">Full discovery failed: '+esc(e.message)+'</div>'}}
let MONITORS=[];let EDIT_MONITOR_ID=null;
async function loadMonitoring(){try{const [settings,checks]=await Promise.all([json('/api/v1/monitoring/settings'),json('/api/v1/monitoring/checks')]);MONITORS=settings;const latest={};for(const c of checks){if(c.monitor_id&&!latest[c.monitor_id])latest[c.monitor_id]=c}monitorRows.innerHTML=settings.length?settings.map(x=>{const c=latest[x.id];const st=c?c.status:(x.enabled?'unknown':'disabled');return `<tr><td><div class="name">${esc(x.name)}</div></td><td>${esc(x.kind)}</td><td>${esc(x.target||'—')}</td><td>${esc(x.interval_seconds)} sec</td><td><span class="status-badge ${st==='down'?'severity-high':''}">${esc(st)}</span></td><td>${c?esc(new Date(c.last_checked).toLocaleString()):'—'}</td><td>${c&&c.latency_ms!=null?esc(c.latency_ms)+' ms':'—'}</td><td><button class="link" onclick="runMonitor(${x.id})">Run</button> <button class="link" onclick="openMonitorEditor(${x.id})">Edit</button> <button class="link" onclick="deleteMonitor(${x.id})">Delete</button></td></tr>`}).join(''):'<tr><td colspan="8" class="empty">No monitors configured yet. Click Add Monitor.</td></tr>'}catch(e){monitorRows.innerHTML='<tr><td colspan="8" class="empty">Monitoring data unavailable: '+esc(e.message)+'</td></tr>'}}
async function runMonitors(){try{await json('/api/v1/monitoring/run',{method:'POST'});await loadMonitoring();await loadFindings()}catch(e){alert('Could not run monitors: '+e.message)}}
async function runMonitor(id){try{await json('/api/v1/monitoring/settings/'+id+'/run',{method:'POST'});await loadMonitoring();await loadFindings()}catch(e){alert('Monitor failed: '+e.message)}}
function openMonitorEditor(id=null){EDIT_MONITOR_ID=id;const x=id?MONITORS.find(m=>m.id===id):null;monitorModalTitle.textContent=x?'Edit Monitor':'Add Monitor';monName.value=x?.name||'';monKind.value=x?.kind||'website';monTarget.value=x?.target==='(auto)'?'':(x?.target||'');monInterval.value=x?.interval_seconds||300;monEnabled.value=x?(x.enabled?'1':'0'):'1';try{monOptions.value=JSON.stringify(JSON.parse(x?.options_json||'{}'),null,2)}catch(_){monOptions.value='{}'}monitorEditorOut.textContent='';monitorModal.style.display='grid'}
function closeMonitorEditor(){monitorModal.style.display='none'}
async function saveMonitor(){try{let options={};try{options=JSON.parse(monOptions.value||'{}')}catch(_){throw new Error('Options must be valid JSON')}const body={name:monName.value.trim(),kind:monKind.value,target:monTarget.value.trim(),interval_seconds:+monInterval.value,enabled:monEnabled.value==='1',options};const url=EDIT_MONITOR_ID?'/api/v1/monitoring/settings/'+EDIT_MONITOR_ID:'/api/v1/monitoring/settings';await json(url,{method:EDIT_MONITOR_ID?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});closeMonitorEditor();await loadMonitoring()}catch(e){monitorEditorOut.textContent=e.message}}
async function deleteMonitor(id){if(!confirm('Delete this monitor and its check history?'))return;try{await json('/api/v1/monitoring/settings/'+id,{method:'DELETE'});await loadMonitoring()}catch(e){alert('Could not delete monitor: '+e.message)}}
async function loadFindings(){try{let open=await json('/api/v1/intelligence/issues?status=open');let resolved=await json('/api/v1/intelligence/issues?status=resolved');let all=open.concat(resolved);findingOpen.textContent=open.length;findingResolved.textContent=resolved.length;findingAll.textContent=all.length;findingCritical.textContent=all.filter(x=>['critical','high'].includes((x.severity||'').toLowerCase())).length;let badge=document.getElementById('findingBadge');if(badge)badge.textContent=open.length;findingRows.innerHTML=all.length?all.map(x=>`<tr><td><span class="status-badge severity-${esc((x.severity||'info').toLowerCase())}">${esc(x.severity||'Info')}</span></td><td><div class="name">${esc(x.title||x.issue_type||'Finding')}</div><div class="muted">${esc(x.recommendation||'')}</div></td><td>${esc(x.target||'—')}</td><td>${x.first_seen?esc(new Date(x.first_seen).toLocaleString()):'—'}</td><td><span class="status-badge">${esc(x.status||'open')}</span></td><td>${x.status==='open'?`<button class="link" onclick="showSuggestedFix(${x.id})">Suggested Fix</button> <button class="link" onclick="recheckFinding(${x.id})">Recheck</button> <button class="link" onclick="resolveFinding(${x.id})">Resolve</button>`:'—'}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No findings yet.</td></tr>'}catch(e){findingRows.innerHTML='<tr><td colspan="6" class="empty">Findings unavailable: '+esc(e.message)+'</td></tr>'}}
async function showSuggestedFix(id){try{const r=await json('/api/v1/intelligence/issues/'+id+'/suggested-fix');alert(r.title+'\n\n'+(r.recommendation||'')+'\n\n'+(r.actions||[]).map((x,i)=>(i+1)+'. '+x).join('\n'))}catch(e){alert('Could not load suggested fix: '+e.message)}}
async function recheckFinding(id){try{const r=await json('/api/v1/intelligence/issues/'+id+'/recheck',{method:'POST'});alert(r.ok?'Recheck completed successfully.':'Recheck completed; the condition may still be present.');await loadFindings();await loadMonitoring();await loadInventory()}catch(e){alert('Could not recheck finding: '+e.message)}}
async function resolveFinding(id){if(!confirm('Mark this finding resolved?'))return;try{await json('/api/v1/intelligence/issues/'+id+'/resolve',{method:'POST'});await loadFindings()}catch(e){alert('Could not resolve finding: '+e.message)}}

async function loadIntegrations(){try{const [r,a,n]=await Promise.all([json('/api/v1/integrations/configs'),json('/api/v1/analytics/clients'),json('/api/v1/notifications/config').catch(()=>null)]);for(const c of r.configs||[]){if(c.kind==='pihole'){piTarget.value=c.target||'';piInterval.value=c.sync_interval_seconds||300;piStatus.textContent=(c.last_sync_status||'never')+' · '+(c.last_sync_at?new Date(c.last_sync_at).toLocaleString():'never synced')+(c.has_secret?' · credential saved':'')}if(c.kind==='unifi'){uniTarget.value=c.target||'';uniUser.value=c.username||'';uniTls.checked=!!c.verify_tls;try{uniSite.value=JSON.parse(c.options_json||'{}').site||'default'}catch(_){ }uniStatus.textContent=(c.last_sync_status||'never')+' · '+(c.last_sync_at?new Date(c.last_sync_at).toLocaleString():'never synced')+(c.has_secret?' · credential saved':'')}if(c.kind==='snmp'){snmpTarget.value=c.target||'';snmpInterval.value=c.sync_interval_seconds||300;snmpStatus.textContent=(c.last_sync_status||'never')+' · '+(c.last_sync_at?new Date(c.last_sync_at).toLocaleString():'never synced')+(c.has_secret?' · community saved':'')}}integrationAnalytics.innerHTML='<b>Discovery evidence:</b> '+(a.by_source||[]).map(x=>esc(x.source)+': '+x.devices+' devices').join(' · ')+'<br><br><b>Integration analytics:</b><pre style="white-space:pre-wrap">'+esc(JSON.stringify(a.integration_analytics||{},null,2))+'</pre>';if(n){notifyWebhook.value=n.webhook_url||'';notifyNtfyServer.value=n.ntfy_server||'https://ntfy.sh';notifyNtfy.value=n.ntfy_topic||'';notifySmtpHost.value=n.smtp_host||'';notifySmtpPort.value=n.smtp_port||587;notifySmtpUser.value=n.smtp_user||'';notifySmtpFrom.value=n.smtp_from||'';notifyEmail.value=n.smtp_to||'';notifySmtpPass.placeholder=n.has_smtp_password?'SMTP password saved — blank keeps it':'SMTP password';notifySeverity.value=n.min_severity||'warning'}}catch(e){integrationAnalytics.textContent='Integrations unavailable: '+e.message}}
async function saveIntegration(kind){try{let body;if(kind==='pihole')body={enabled:true,target:piTarget.value.trim(),secret:piSecret.value||null,sync_interval_seconds:+piInterval.value,verify_tls:true,options:{}};if(kind==='unifi')body={enabled:true,target:uniTarget.value.trim(),username:uniUser.value.trim(),secret:uniSecret.value||null,sync_interval_seconds:300,verify_tls:uniTls.checked,options:{site:uniSite.value.trim()||'default'}};if(kind==='snmp')body={enabled:true,target:snmpTarget.value.trim(),secret:snmpSecret.value||null,sync_interval_seconds:+snmpInterval.value,verify_tls:true,options:{}};await json('/api/v1/integrations/configs/'+kind,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});piSecret.value='';uniSecret.value='';snmpSecret.value='';await loadIntegrations()}catch(e){alert('Could not save integration: '+e.message)}}
async function syncIntegration(kind){try{const r=await json('/api/v1/integrations/configs/'+kind+'/sync',{method:'POST'});alert((r.ok?'Sync complete':'Sync failed')+' · '+r.observations+' observations'+(r.error?'\n'+r.error:''));await loadIntegrations();if(r.ok)await loadNetwork()}catch(e){alert('Sync failed: '+e.message)}}
async function saveNotifications(){try{const body={webhook_enabled:!!notifyWebhook.value.trim(),webhook_url:notifyWebhook.value.trim(),ntfy_enabled:!!notifyNtfy.value.trim(),ntfy_server:notifyNtfyServer.value.trim()||'https://ntfy.sh',ntfy_topic:notifyNtfy.value.trim(),smtp_enabled:!!(notifySmtpHost.value.trim()&&notifySmtpFrom.value.trim()&&notifyEmail.value.trim()),smtp_host:notifySmtpHost.value.trim(),smtp_port:+notifySmtpPort.value||587,smtp_user:notifySmtpUser.value.trim(),smtp_password:notifySmtpPass.value||null,smtp_from:notifySmtpFrom.value.trim(),smtp_to:notifyEmail.value.trim(),min_severity:notifySeverity.value};await json('/api/v1/notifications/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});notifySmtpPass.value='';notifyOut.textContent='Saved.'}catch(e){notifyOut.textContent=e.message}}
async function testNotifications(){try{const r=await json('/api/v1/notifications/test',{method:'POST'});notifyOut.textContent='Test attempted: '+r.sent+' channel(s) sent'+(r.errors?.length?' · '+r.errors.join('; '):'')}catch(e){notifyOut.textContent=e.message}}
async function loadReports(){try{const [s,sc,h]=await Promise.all([json('/api/v1/reports/summary'),json('/api/v1/reports/schedules'),json('/api/v1/reports/history')]);reportSummary.textContent=s.body_text;reportSchedules.innerHTML=sc.length?sc.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.cadence)}</td><td>${x.next_run_at?esc(new Date(x.next_run_at).toLocaleString()):'—'}</td><td>${x.last_run_at?esc(new Date(x.last_run_at).toLocaleString()):'—'}</td><td><button class="link" onclick="deleteReportSchedule(${x.id})">Delete</button></td></tr>`).join(''):'<tr><td colspan="5" class="empty">No scheduled reports.</td></tr>';reportHistory.innerHTML=h.length?h.map(x=>`<tr><td>${esc(new Date(x.generated_at).toLocaleString())}</td><td>${esc(x.title)}</td><td>${x.summary?.devices??'—'}</td><td>${x.summary?.open_findings??'—'}</td><td><a class="link" href="/api/v1/reports/${x.id}/export.pdf">PDF</a> · <a class="link" href="/api/v1/reports/${x.id}/export.csv">CSV</a></td></tr>`).join(''):'<tr><td colspan="5" class="empty">No reports generated yet.</td></tr>'}catch(e){reportSummary.textContent='Reports unavailable: '+e.message}}
async function generateReport(){try{await json('/api/v1/reports/generate',{method:'POST'});await loadReports()}catch(e){alert('Could not generate report: '+e.message)}}
async function addReportSchedule(){try{await json('/api/v1/reports/schedules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:reportName.value.trim(),report_type:'network_summary',enabled:true,cadence:reportCadence.value,hour_utc:+reportHour.value,weekday:0,notify:true})});reportName.value='';await loadReports()}catch(e){alert('Could not add report schedule: '+e.message)}}
async function deleteReportSchedule(id){if(!confirm('Delete this report schedule?'))return;try{await json('/api/v1/reports/schedules/'+id,{method:'DELETE'});await loadReports()}catch(e){alert(e.message)}}

function fmtBits(v){v=Number(v||0);if(v>=1e9)return (v/1e9).toFixed(1)+' Gbps';if(v>=1e6)return (v/1e6).toFixed(1)+' Mbps';if(v>=1e3)return (v/1e3).toFixed(1)+' Kbps';return Math.round(v)+' bps'}
async function loadTraffic(){const r=await json('/api/v1/analytics/traffic?minutes=60');const a=r.samples||[];if(a.length){const max=Math.max(1,...a.flatMap(x=>[+x.rx_bps||0,+x.tx_bps||0]));const pts=(key)=>a.map((x,i)=>{const xx=45+(700*(i/Math.max(1,a.length-1)));const yy=170-(140*((+x[key]||0)/max));return xx.toFixed(1)+','+yy.toFixed(1)}).join(' ');trafficRx.setAttribute('points',pts('rx_bps'));trafficTx.setAttribute('points',pts('tx_bps'));const last=a[a.length-1];trafficNow.textContent=fmtBits(last.rx_bps)+' ↓ · '+fmtBits(last.tx_bps)+' ↑ · '+esc(last.interface)}else trafficNow.textContent='waiting for samples';const c=r.clients||{};clientMetricNote.textContent=c.note||'Observed activity';const rows=c.clients||[];const mx=Math.max(1,...rows.map(x=>+x.activity_events||0));clientBars.innerHTML=rows.length?rows.slice(0,10).map(x=>`<div style="display:grid;grid-template-columns:minmax(120px,220px) 1fr 52px;gap:10px;align-items:center;margin:8px 0"><div>${esc(x.label||x.ip||x.mac)}</div><div style="height:9px;background:#edf2f7;border-radius:9px;overflow:hidden"><div style="height:100%;width:${Math.max(2,(+x.activity_events||0)/mx*100)}%;background:#1976e8"></div></div><div class="muted">${x.activity_events}</div></div>`).join(''):'<div class="empty">No client activity evidence yet.</div>'}
async function loadHealth(){try{const [h,r,b,p,tls,nh]=await Promise.all([json('/api/v1/appliance/health'),json('/api/v1/appliance/retention').catch(()=>null),json('/api/v1/appliance/backups').catch(()=>[]),json('/api/v1/appliance/production-settings').catch(()=>null),json('/api/v1/appliance/https').catch(()=>null),json('/api/v1/notifications/history').catch(()=>[])]);healthOverall.textContent=(h.overall||'unknown').toUpperCase();healthHost.textContent=h.hostname||'—';healthKernel.textContent=h.kernel||'—';healthChecks.innerHTML=(h.checks||[]).map(x=>`<tr><td>${esc(x.name)}</td><td><span class="pill ${x.status==='ok'?'online':x.status==='critical'?'offline':''}">${esc(x.status)}</span></td><td>${esc(x.detail)}</td></tr>`).join('');if(r){retTraffic.value=r.traffic_retention_days;retEvents.value=r.event_retention_days;retAudit.value=r.audit_retention_days;retReports.value=r.report_retention_days;retSync.value=r.sync_retention_days;retNotify.value=r.notification_retention_days}backupRows.innerHTML=(b||[]).map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td>${esc(x.filename)}</td><td>${(x.size_bytes/1024/1024).toFixed(2)} MB</td><td>${esc(x.note||'')}</td><td><button class="link" onclick="restoreBackup('${esc(x.filename)}')">Restore</button></td></tr>`).join('')||'<tr><td colspan="5" class="empty">No backups yet.</td></tr>';if(p){prodAutoBackup.value=p.auto_backup_enabled?'1':'0';prodBackupHour.value=p.backup_hour_utc;prodBackupKeep.value=p.backup_keep_count;prodUpdateChannel.value=p.update_channel||'stable'}if(tls){tlsStatus.textContent=tls.configured?'HTTPS certificate is installed on this appliance.':'HTTPS certificate is not configured yet.';httpsOut.textContent=tls.helper||''}notificationHistoryRows.innerHTML=(nh||[]).map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td>${esc(x.event_type)}</td><td>${esc(x.severity)}</td><td>${esc(x.status)}</td><td>${x.attempts||1}</td><td><button class="link" onclick="retryNotification(${x.id})">Retry</button></td></tr>`).join('')||'<tr><td colspan="6" class="empty">No notification history.</td></tr>'}catch(e){healthChecks.innerHTML='<tr><td colspan="3">'+esc(e.message)+'</td></tr>'}}
async function createBackup(){try{await json('/api/v1/appliance/backups',{method:'POST'});await loadHealth()}catch(e){alert('Backup failed: '+e.message)}}
async function restoreBackup(name){if(!confirm('Restore '+name+'? GODSEYE will create a safety backup first. A service restart is recommended after restore.'))return;try{const r=await json('/api/v1/appliance/backups/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:name})});alert('Restore complete. Safety backup: '+r.safety_backup+'\nRestart GODSEYE services when convenient.');await loadHealth()}catch(e){alert('Restore failed: '+e.message)}}
async function rotateMetricsKey(){if(!confirm('Rotate the Prometheus API key? Any existing Prometheus configuration will stop working until updated.'))return;try{const r=await json('/api/v1/appliance/prometheus-key',{method:'POST'});metricsKeyOut.textContent='API key (shown once):\n'+r.api_key+'\n\nPrometheus header:\nAuthorization: Bearer '+r.api_key}catch(e){alert(e.message)}}

let STAGED_UPDATE=null;
async function saveProductionSettings(){try{await json('/api/v1/appliance/production-settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({auto_backup_enabled:prodAutoBackup.value==='1',backup_cadence:'daily',backup_hour_utc:+prodBackupHour.value,backup_keep_count:+prodBackupKeep.value,https_mode:'off',https_hostname:'',update_channel:prodUpdateChannel.value})});alert('Production appliance settings saved.');await loadHealth()}catch(e){alert(e.message)}}
async function stageUpdate(){const f=updateFile.files[0];if(!f){alert('Choose a GODSEYE ZIP package first.');return}updateOut.textContent='Uploading and running preflight…';try{const r=await fetch('/api/v1/updates/stage',{method:'POST',headers:{'X-CSRF-Token':csrfToken(),'X-Filename':f.name},body:await f.arrayBuffer()});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Stage failed');STAGED_UPDATE=d;updateOut.textContent=JSON.stringify(d,null,2);applyUpdateBtn.style.display=d.preflight?.ok?'inline-block':'none'}catch(e){updateOut.textContent=e.message}}
async function applyUpdate(){if(!STAGED_UPDATE)return;const text=prompt('This creates a safety backup before applying the staged release. Type exactly: APPLY GODSEYE UPDATE');if(text!=='APPLY GODSEYE UPDATE')return;try{const r=await json('/api/v1/updates/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:STAGED_UPDATE.filename,sha256:STAGED_UPDATE.sha256,confirm:text})});updateOut.textContent=JSON.stringify(r,null,2)}catch(e){updateOut.textContent=e.message}}
async function retryNotification(id){try{const r=await json('/api/v1/notifications/retry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({delivery_id:id})});alert('Retry complete: '+JSON.stringify(r));await loadHealth()}catch(e){alert(e.message)}}
async function runRemediation(){const action=remediationAction.value,target=remediationTarget.value.trim();if(!target){alert('Enter a target.');return}const confirmText='CONFIRM '+action.toUpperCase()+' '+target;const typed=prompt('This changes your configured network service. Type exactly:\n'+confirmText);if(typed!==confirmText)return;try{const r=await json('/api/v1/remediation/execute',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,target,confirm:typed})});remediationOut.textContent=r.ok?'Action completed.':'Action failed: '+(r.error||'unknown error')}catch(e){remediationOut.textContent=e.message}}
async function saveRetention(){try{const body={traffic_retention_days:+retTraffic.value,event_retention_days:+retEvents.value,audit_retention_days:+retAudit.value,report_retention_days:+retReports.value,sync_retention_days:+retSync.value,notification_retention_days:+retNotify.value};const r=await json('/api/v1/appliance/retention',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});alert('Retention saved. Pruned: '+JSON.stringify(r.deleted));await loadHealth()}catch(e){alert(e.message)}}
showView=function(name){originalShowView(name);if(name==='devices')loadInventory();if(name==='network')loadNetwork();if(name==='monitoring')loadMonitoring();if(name==='findings')loadFindings();if(name==='tools'){}if(name==='integrations')loadIntegrations();if(name==='reports')loadReports();if(name==='health')loadHealth();if(name==='security')loadSecurity();if(name==='users'&&ME&&ME.role==='admin')loadUsers();if(name==='audit'&&ME&&['admin','auditor'].includes(ME.role))loadAudit()}
async function boot(){try{if(!getCookie('godseye_csrf'))await fetch('/api/v1/auth/csrf');ME=await json('/api/v1/auth/me')}catch(e){showLogin();return}whoami.textContent=ME.username+' ('+ME.role+')';const tu=document.getElementById('topUser');if(tu)tu.textContent=ME.username;scanBtn.style.display=['admin','operator'].includes(ME.role)?'inline-block':'none';['navRules','navUsers'].forEach(id=>{document.getElementById(id).style.display=ME.role==='admin'?'':'none'});document.getElementById('navAudit').style.display=['admin','auditor'].includes(ME.role)?'':'none';const pwBar=document.getElementById('pwReminderBar');if(ME.password_change_reminder_days!==undefined){pwBar.textContent='⚠ Set a new password within '+ME.password_change_reminder_days+' day(s) — click here to do it now.';pwBar.style.display='block'}else{pwBar.style.display='none'}showApp();await load();await loadUsers();await loadAudit();await loadSecurity();await loadRules();await loadFindings();const initialView=(location.hash||'#overview').slice(1);showView(document.getElementById('view-'+initialView)?initialView:'overview',false);setInterval(load,10000)}
checkInitialSetup().then(required=>{if(!required)boot()});
</script></body></html>'''


# --- Network tool endpoints ------------------------------------------------
class ToolTargetRequest(BaseModel):
    host: str

class PortScanRequest(BaseModel):
    host: str
    ports: str = "22,53,80,443,445,3389,8080,8443"

class TraceRequest(BaseModel):
    host: str
    max_hops: int = 12

@app.post(f"{router_prefix}/tools/ping")
def tool_ping(req: ToolTargetRequest, user=Depends(require_permission("operate"))):
    from .tools import ping
    return ping(req.host)

@app.post(f"{router_prefix}/tools/traceroute")
def tool_traceroute(req: TraceRequest, user=Depends(require_permission("operate"))):
    from .tools import traceroute
    try:
        return traceroute(req.host, req.max_hops)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@app.post(f"{router_prefix}/tools/dns")
def tool_dns(req: ToolTargetRequest, user=Depends(get_current_user)):
    from .tools import dns
    return dns(req.host)

@app.post(f"{router_prefix}/tools/port-scan")
def tool_port_scan(req: PortScanRequest, user=Depends(require_permission("operate"))):
    from .tools import port_scan
    try:
        return port_scan(req.host, req.ports)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@app.post(f"{router_prefix}/tools/device-info")
def tool_device_info(req: ToolTargetRequest, user=Depends(require_permission("operate"))):
    from .tools import device_info
    try:
        return device_info(req.host)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

# --- Native integration endpoints -----------------------------------------
# These are intentionally implemented in the same FastAPI process so GODSEYE
# remains a simple Raspberry Pi appliance. Credentials are never persisted.
class IntegrationURLRequest(BaseModel):
    url: str
    timeout: float = 8
    verify_tls: bool = True

class UniFiRequest(BaseModel):
    url: str
    username: str
    password: str
    verify_tls: bool = True

class SNMPRequest(BaseModel):
    host: str
    community: str | None = None

class WOLRequest(BaseModel):
    mac: str
    broadcast: str = "255.255.255.255"
    port: int = 9

@app.post(f"{router_prefix}/monitor/website")
def monitor_website(req: IntegrationURLRequest, user=Depends(require_permission("operate"))):
    from .integrations import website_check
    return website_check(req.url, req.timeout)

@app.post(f"{router_prefix}/integrations/pihole/test")
def integration_pihole(req: IntegrationURLRequest, admin=Depends(require_admin)):
    from .integrations import pihole_test
    return pihole_test(req.url, req.timeout)

@app.post(f"{router_prefix}/integrations/unifi/test")
def integration_unifi(req: UniFiRequest, admin=Depends(require_admin)):
    from .integrations import unifi_login
    return unifi_login(req.url, req.username, req.password, req.verify_tls)

@app.post(f"{router_prefix}/integrations/snmp/test")
def integration_snmp(req: SNMPRequest, admin=Depends(require_admin)):
    from .integrations import snmp_test
    return snmp_test(req.host, req.community)

@app.post(f"{router_prefix}/tools/wol")
def integration_wol(req: WOLRequest, admin=Depends(require_admin)):
    from .integrations import wake_on_lan
    try:
        return wake_on_lan(req.mac, req.broadcast, req.port)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

# --- Integrations + Reporting v1.4 ----------------------------------------
class SavedIntegrationRequest(BaseModel):
    enabled: bool = True
    target: str
    username: str = ""
    secret: str | None = None
    verify_tls: bool = True
    sync_interval_seconds: int = 300
    options: dict = {}

class ReportScheduleRequest(BaseModel):
    name: str
    report_type: str = "network_summary"
    enabled: bool = True
    cadence: str = "daily"
    hour_utc: int = 12
    weekday: int = 0
    notify: bool = True

class NotificationConfigRequest(BaseModel):
    webhook_enabled: bool = False
    webhook_url: str = ""
    ntfy_enabled: bool = False
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str | None = None
    smtp_from: str = ""
    smtp_to: str = ""
    min_severity: str = "warning"

@app.get(f"{router_prefix}/integrations/configs")
def get_saved_integrations(user=Depends(get_current_user)):
    with db() as c:
        ensure_ir_schema(c)
        rows=c.execute("SELECT * FROM integration_configs ORDER BY kind").fetchall()
        latest={r['source']: json.loads(r['data_json']) for r in c.execute("SELECT a.* FROM analytics_snapshots a JOIN (SELECT source,MAX(id) mid FROM analytics_snapshots GROUP BY source) x ON a.id=x.mid")}
    return {"configs":[safe_config(r) for r in rows],"analytics":latest}

@app.put(f"{router_prefix}/integrations/configs/{{kind}}")
def save_integration(kind: str, req: SavedIntegrationRequest, request: Request, user=Depends(require_admin)):
    kind=kind.lower()
    if kind not in {"pihole","unifi","snmp"}: raise HTTPException(400,"Supported integrations are pihole, unifi, snmp")
    if not req.target.strip(): raise HTTPException(400,"Target is required")
    if req.sync_interval_seconds < 30: raise HTTPException(400,"Sync interval must be at least 30 seconds")
    with db() as c:
        ensure_ir_schema(c); existing=c.execute("SELECT * FROM integration_configs WHERE kind=?",(kind,)).fetchone(); stamp=now()
        secret=encrypt_secret(req.secret) if req.secret is not None else (existing['secret'] if existing else '')
        c.execute("""INSERT INTO integration_configs(kind,enabled,target,username,secret,verify_tls,sync_interval_seconds,options_json,created_at,updated_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(kind) DO UPDATE SET enabled=excluded.enabled,target=excluded.target,username=excluded.username,secret=excluded.secret,verify_tls=excluded.verify_tls,sync_interval_seconds=excluded.sync_interval_seconds,options_json=excluded.options_json,updated_at=excluded.updated_at""",
                  (kind,int(req.enabled),req.target.strip(),req.username.strip(),secret,int(req.verify_tls),req.sync_interval_seconds,json.dumps(req.options),stamp,stamp))
        audit(c,user['username'],'integration_config_saved',kind,f'enabled={req.enabled}; target={req.target}',client_ip(request))
        row=c.execute("SELECT * FROM integration_configs WHERE kind=?",(kind,)).fetchone()
    return safe_config(row)

@app.delete(f"{router_prefix}/integrations/configs/{{kind}}")
def delete_integration(kind: str, request: Request, user=Depends(require_admin)):
    with db() as c:
        ensure_ir_schema(c); cur=c.execute("DELETE FROM integration_configs WHERE kind=?",(kind.lower(),))
        if not cur.rowcount: raise HTTPException(404,"Integration not configured")
        audit(c,user['username'],'integration_config_deleted',kind,'',client_ip(request))
    return {"ok":True}

@app.post(f"{router_prefix}/integrations/configs/{{kind}}/sync")
def sync_saved_integration(kind: str, request: Request, user=Depends(require_permission("integrations.sync"))):
    manager=getattr(app.state,'integration_reporting_manager',None)
    if manager is None: raise HTTPException(503,"Integration manager is not running")
    try: result=manager.run_sync(kind.lower())
    except KeyError: raise HTTPException(404,"Integration not configured")
    with db() as c: audit(c,user['username'],'integration_sync',kind,json.dumps({k:v for k,v in result.items() if k!='analytics'})[:1000],client_ip(request))
    return result

@app.get(f"{router_prefix}/integrations/sync-runs")
def integration_sync_runs(limit: int=50, user=Depends(get_current_user)):
    with db() as c:
        ensure_ir_schema(c); rows=c.execute("SELECT * FROM integration_sync_runs ORDER BY id DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall()
    return [dict(r) for r in rows]

@app.get(f"{router_prefix}/analytics/clients")
def client_analytics(user=Depends(get_current_user)):
    with db() as c:
        ensure_ir_schema(c)
        by_source=[dict(r) for r in c.execute("SELECT source,COUNT(DISTINCT mac) devices,MAX(last_seen) last_seen FROM device_sources GROUP BY source ORDER BY devices DESC")]
        top=[dict(r) for r in c.execute("SELECT mac,COALESCE(name,hostname,vendor,mac) label,ip,status,last_seen FROM devices ORDER BY last_seen DESC LIMIT 50")]
        snapshots={r['source']:json.loads(r['data_json']) for r in c.execute("SELECT a.* FROM analytics_snapshots a JOIN (SELECT source,MAX(id) mid FROM analytics_snapshots GROUP BY source) x ON a.id=x.mid")}
    return {"by_source":by_source,"clients":top,"integration_analytics":snapshots}

def _metrics_authorized(request: Request, c):
    auth=request.headers.get("authorization","")
    key=request.headers.get("x-api-key") or (auth[7:] if auth.lower().startswith("bearer ") else "")
    if verify_prometheus_key(c,key): return True
    token=request.cookies.get(SESSION_COOKIE)
    if token:
        row=c.execute("SELECT s.expires_at,u.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",(token,)).fetchone()
        if row:
            try: return dt.datetime.fromisoformat(row['expires_at'])>dt.datetime.now(dt.timezone.utc)
            except Exception: pass
    return False

@app.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request):
    with db() as c:
        ensure_hardening_schema(c)
        if not _metrics_authorized(request,c):
            raise HTTPException(401,"Metrics authentication required")
        return PlainTextResponse(prometheus_metrics(c),media_type="text/plain; version=0.0.4; charset=utf-8")

@app.get(f"{router_prefix}/reports/summary")
def report_summary(user=Depends(get_current_user)):
    with db() as c:
        summary,body=build_network_report(c)
    return {"generated_at":now(),"summary":summary,"body_text":body}

@app.post(f"{router_prefix}/reports/generate")
def report_generate(request: Request, user=Depends(require_permission("reports.generate"))):
    with db() as c:
        rep=generate_report(c)
        audit(c,user['username'],'report_generated',str(rep['id']),rep['title'],client_ip(request))
    return rep

@app.get(f"{router_prefix}/reports/history")
def report_history(limit: int=50, user=Depends(get_current_user)):
    with db() as c:
        ensure_ir_schema(c); rows=c.execute("SELECT id,schedule_id,report_type,title,generated_at,summary_json,body_text FROM generated_reports ORDER BY id DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall()
    out=[]
    for r in rows:
        d=dict(r); d['summary']=json.loads(d.pop('summary_json') or '{}'); out.append(d)
    return out

@app.get(f"{router_prefix}/reports/schedules")
def report_schedules(user=Depends(get_current_user)):
    with db() as c:
        ensure_ir_schema(c); return [dict(r) for r in c.execute("SELECT * FROM report_schedules ORDER BY name")]

@app.post(f"{router_prefix}/reports/schedules")
def create_report_schedule(req: ReportScheduleRequest, request: Request, user=Depends(require_admin)):
    if req.cadence not in {'hourly','daily','weekly'}: raise HTTPException(400,"Cadence must be hourly, daily, or weekly")
    if req.report_type!='network_summary': raise HTTPException(400,"Unsupported report type")
    with db() as c:
        ensure_ir_schema(c); stamp=now(); nxt=next_report_time(req.cadence,req.hour_utc,req.weekday)
        try: rid=c.execute("INSERT INTO report_schedules(name,report_type,enabled,cadence,hour_utc,weekday,notify,next_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(req.name,req.report_type,int(req.enabled),req.cadence,max(0,min(23,req.hour_utc)),req.weekday%7,int(req.notify),nxt,stamp,stamp)).lastrowid
        except sqlite3.IntegrityError: raise HTTPException(409,"A report schedule with that name already exists")
        audit(c,user['username'],'report_schedule_created',str(rid),req.name,client_ip(request))
        return dict(c.execute("SELECT * FROM report_schedules WHERE id=?",(rid,)).fetchone())

@app.delete(f"{router_prefix}/reports/schedules/{{schedule_id}}")
def delete_report_schedule(schedule_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        ensure_ir_schema(c); cur=c.execute("DELETE FROM report_schedules WHERE id=?",(schedule_id,))
        if not cur.rowcount: raise HTTPException(404,"Schedule not found")
        audit(c,user['username'],'report_schedule_deleted',str(schedule_id),'',client_ip(request))
    return {"ok":True}


# --- Dashboard visualization + appliance hardening v1.5 -------------------
class RetentionRequest(BaseModel):
    traffic_retention_days: int = 7
    event_retention_days: int = 90
    audit_retention_days: int = 365
    report_retention_days: int = 365
    sync_retention_days: int = 90
    notification_retention_days: int = 90

class BackupRestoreRequest(BaseModel):
    filename: str

@app.get(f"{router_prefix}/analytics/traffic")
def traffic_analytics(minutes: int=60, user=Depends(get_current_user)):
    with db() as c:
        return {"samples":traffic_history(c,minutes),"clients":client_bandwidth_estimates(c)}

@app.get(f"{router_prefix}/appliance/health")
def get_appliance_health(user=Depends(get_current_user)):
    return appliance_health(DB_PATH)

@app.get(f"{router_prefix}/appliance/retention")
def get_retention(user=Depends(require_admin)):
    with db() as c: return retention_config(c)

@app.put(f"{router_prefix}/appliance/retention")
def put_retention(req: RetentionRequest, request: Request, user=Depends(require_admin)):
    with db() as c:
        cfg=save_retention(c,req.model_dump()); deleted=apply_retention(c)
        audit(c,user['username'],'retention_policy_saved','appliance',json.dumps(deleted),client_ip(request))
        return {"config":cfg,"deleted":deleted}

@app.post(f"{router_prefix}/appliance/retention/run")
def run_retention(request: Request, user=Depends(require_admin)):
    with db() as c:
        deleted=apply_retention(c); audit(c,user['username'],'retention_run','appliance',json.dumps(deleted),client_ip(request)); return {"deleted":deleted}

@app.get(f"{router_prefix}/appliance/backups")
def backups(user=Depends(require_admin)):
    with db() as c: return list_backups(c)

@app.post(f"{router_prefix}/appliance/backups")
def make_backup(request: Request, user=Depends(require_admin)):
    path=create_backup(DB_PATH,'manual')
    with db() as c:
        ensure_hardening_schema(c)
        c.execute("INSERT OR IGNORE INTO backup_runs(filename,created_at,size_bytes,status,note) VALUES(?,?,?,?,?)",(path.name,now(),path.stat().st_size,'complete','manual'))
        audit(c,user['username'],'backup_created',path.name,str(path.stat().st_size),client_ip(request)); c.commit()
    return {"ok":True,"filename":path.name,"size_bytes":path.stat().st_size}

@app.post(f"{router_prefix}/appliance/backups/restore")
def restore_existing_backup(req: BackupRestoreRequest, request: Request, user=Depends(require_admin)):
    # Create a safety backup immediately before a restore so the operation is reversible.
    safety=create_backup(DB_PATH,'pre-restore')
    try: result=restore_backup(DB_PATH,req.filename)
    except (ValueError,FileNotFoundError,RuntimeError) as exc: raise HTTPException(400,str(exc))
    with db() as c:
        ensure_ir_schema(c); ensure_hardening_schema(c); migrate_plaintext_secrets(c)
        audit(c,user['username'],'backup_restored',req.filename,f'pre-restore={safety.name}',client_ip(request)); c.commit()
    return {**result,"safety_backup":safety.name,"restart_recommended":True}

@app.post(f"{router_prefix}/appliance/prometheus-key")
def rotate_prometheus_key(request: Request, user=Depends(require_admin)):
    with db() as c:
        key=generate_prometheus_key(c); audit(c,user['username'],'prometheus_key_rotated','metrics','',client_ip(request))
    return {"api_key":key,"warning":"This key is shown once. Store it in your Prometheus configuration."}

@app.get(f"{router_prefix}/reports/{{report_id}}/export.csv")
def export_report_csv(report_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT * FROM generated_reports WHERE id=?",(report_id,)).fetchone()
        if not row: raise HTTPException(404,"Report not found")
        d=dict(row); d['summary']=json.loads(d.get('summary_json') or '{}')
    return Response(content=report_csv_bytes(d),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="godseye-report-{report_id}.csv"'})

@app.get(f"{router_prefix}/reports/{{report_id}}/export.pdf")
def export_report_pdf(report_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT * FROM generated_reports WHERE id=?",(report_id,)).fetchone()
        if not row: raise HTTPException(404,"Report not found")
        d=dict(row); d['summary']=json.loads(d.get('summary_json') or '{}')
    return Response(content=report_pdf_bytes(d),media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="godseye-report-{report_id}.pdf"'})

@app.get(f"{router_prefix}/notifications/config")
def get_notification_config(user=Depends(require_admin)):
    with db() as c:
        ensure_ir_schema(c); d=dict(c.execute("SELECT * FROM notification_configs WHERE id=1").fetchone())
    d['has_smtp_password']=bool(d.get('smtp_password')); d.pop('smtp_password',None); return d

@app.put(f"{router_prefix}/notifications/config")
def save_notification_config(req: NotificationConfigRequest, request: Request, user=Depends(require_admin)):
    if req.min_severity not in VALID_SEVERITIES: raise HTTPException(400,"Invalid minimum severity")
    with db() as c:
        ensure_ir_schema(c); old=c.execute("SELECT smtp_password FROM notification_configs WHERE id=1").fetchone(); pw=encrypt_secret(req.smtp_password) if req.smtp_password is not None else (old['smtp_password'] if old else '')
        c.execute("""UPDATE notification_configs SET webhook_enabled=?,webhook_url=?,ntfy_enabled=?,ntfy_server=?,ntfy_topic=?,smtp_enabled=?,smtp_host=?,smtp_port=?,smtp_user=?,smtp_password=?,smtp_from=?,smtp_to=?,min_severity=?,updated_at=? WHERE id=1""",
                  (int(req.webhook_enabled),req.webhook_url,int(req.ntfy_enabled),req.ntfy_server,req.ntfy_topic,int(req.smtp_enabled),req.smtp_host,req.smtp_port,req.smtp_user,pw,req.smtp_from,req.smtp_to,req.min_severity,now()))
        audit(c,user['username'],'notification_config_saved','notifications','',client_ip(request))
    return {"ok":True}

@app.post(f"{router_prefix}/notifications/test")
def test_notification(request: Request, user=Depends(require_admin)):
    with db() as c:
        result=send_notification(c,'test','warning','GODSEYE Test Notification','Your GODSEYE notification configuration is working.',dedupe_key=None)
        audit(c,user['username'],'notification_test','notifications',json.dumps(result),client_ip(request))
    return result


# --- Production appliance management + automated response v1.6 -----------
class ProductionSettingsRequest(BaseModel):
    auto_backup_enabled: bool=True
    backup_cadence: str='daily'
    backup_hour_utc: int=3
    backup_keep_count: int=14
    https_mode: str='off'
    https_hostname: str=''
    update_channel: str='stable'

class ConfigImportRequest(BaseModel):
    config: dict

class UpdateApplyRequest(BaseModel):
    filename: str
    sha256: str
    confirm: str

class NotificationRetryRequest(BaseModel):
    delivery_id: int

class RemediationRequest(BaseModel):
    action: str
    target: str
    confirm: str

@app.get(f"{router_prefix}/auth/permissions")
def permissions(user=Depends(get_current_user)):
    perms=ROLE_PERMISSIONS.get(user['role'],set())
    return {'role':user['role'],'permissions':sorted(perms)}

@app.get(f"{router_prefix}/appliance/production-settings")
def get_production_settings(user=Depends(require_admin)):
    with db() as c:return production_settings(c)

@app.put(f"{router_prefix}/appliance/production-settings")
def put_production_settings(req: ProductionSettingsRequest, request: Request, user=Depends(require_admin)):
    if req.backup_cadence not in {'daily'}: raise HTTPException(400,'Only daily automatic backup is currently supported')
    if req.https_mode not in {'off','self-signed','letsencrypt'}: raise HTTPException(400,'Invalid HTTPS mode')
    if req.update_channel not in {'stable','beta'}: raise HTTPException(400,'Invalid update channel')
    with db() as c:
        r=save_production_settings(c,{**req.model_dump(),'auto_backup_enabled':int(req.auto_backup_enabled),'backup_hour_utc':max(0,min(23,req.backup_hour_utc)),'backup_keep_count':max(1,min(100,req.backup_keep_count))})
        audit(c,user['username'],'production_settings_saved','appliance','',client_ip(request));return r

@app.get(f"{router_prefix}/appliance/https")
def get_https_status(user=Depends(get_current_user)): return https_status()

@app.get(f"{router_prefix}/config/export")
def export_configuration(request: Request, user=Depends(require_admin)):
    with db() as c:
        payload=config_export(c); audit(c,user['username'],'config_exported','configuration','secrets excluded',client_ip(request))
    return Response(content=json.dumps(payload,indent=2),media_type='application/json',headers={'Content-Disposition':'attachment; filename="godseye-config.json"'})

@app.post(f"{router_prefix}/config/import")
def import_configuration(req: ConfigImportRequest, request: Request, user=Depends(require_admin)):
    with db() as c:
        try:r=config_import(c,req.config)
        except ValueError as e: raise HTTPException(400,str(e))
        audit(c,user['username'],'config_imported','configuration',r.get('note',''),client_ip(request));return r

@app.get(f"{router_prefix}/audit/search")
def search_audit(actor:str='',action:str='',target:str='',start:str='',end:str='',limit:int=200,user=Depends(require_permission('audit.read'))):
    with db() as c:return audit_query(c,actor=actor,action=action,target=target,start=start,end=end,limit=limit)

@app.get(f"{router_prefix}/audit/export.csv")
def export_audit(actor:str='',action:str='',target:str='',start:str='',end:str='',limit:int=2000,user=Depends(require_permission('audit.read'))):
    with db() as c: rows=audit_query(c,actor=actor,action=action,target=target,start=start,end=end,limit=limit)
    return Response(content=audit_csv(rows),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="godseye-audit.csv"'})

@app.get(f"{router_prefix}/notifications/history")
def notification_history(limit:int=100,user=Depends(require_permission('notifications.retry'))):
    with db() as c:
        ensure_production_schema(c); return [dict(r) for r in c.execute('SELECT * FROM notification_deliveries ORDER BY id DESC LIMIT ?',(max(1,min(limit,500)),)).fetchall()]

@app.post(f"{router_prefix}/notifications/retry")
def notification_retry(req: NotificationRetryRequest, request: Request, user=Depends(require_permission('notifications.retry'))):
    with db() as c:
        ensure_production_schema(c); row=c.execute('SELECT * FROM notification_deliveries WHERE id=?',(req.delivery_id,)).fetchone()
        if not row: raise HTTPException(404,'Notification delivery not found')
        d=dict(row); result=send_notification(c,d['event_type'],d['severity'],d.get('title') or 'GODSEYE notification retry',d.get('body') or d.get('details') or '',target=d.get('target'),dedupe_key=None,force=True)
        c.execute('UPDATE notification_deliveries SET attempts=attempts+1,last_attempt_at=? WHERE id=?',(now(),req.delivery_id)); audit(c,user['username'],'notification_retried',str(req.delivery_id),json.dumps(result)[:1000],client_ip(request));c.commit();return result

@app.post(f"{router_prefix}/updates/stage")
async def stage_update(request: Request, user=Depends(require_admin)):
    filename=request.headers.get('x-filename','godseye-update.zip'); data=await request.body()
    try:p,sha,pf=stage_update_bytes(data,filename)
    except ValueError as e: raise HTTPException(400,str(e))
    with db() as c:
        ensure_production_schema(c); c.execute('INSERT INTO update_runs(filename,sha256,version,status,preflight_json,actor,created_at) VALUES(?,?,?,?,?,?,?)',(p.name,sha,pf.get('version'),'preflight_passed' if pf.get('ok') else 'preflight_failed',json.dumps(pf),user['username'],now())); audit(c,user['username'],'update_staged',p.name,sha,client_ip(request));c.commit()
    return {'filename':p.name,'sha256':sha,'preflight':pf}

@app.get(f"{router_prefix}/updates/history")
def update_history(limit:int=50,user=Depends(require_admin)):
    with db() as c:
        ensure_production_schema(c);return [dict(r) for r in c.execute('SELECT * FROM update_runs ORDER BY id DESC LIMIT ?',(max(1,min(limit,200)),)).fetchall()]

@app.post(f"{router_prefix}/updates/apply")
def apply_update(req: UpdateApplyRequest, request: Request, user=Depends(require_admin)):
    if req.confirm!='APPLY GODSEYE UPDATE': raise HTTPException(400,'Exact confirmation text required: APPLY GODSEYE UPDATE')
    safety=create_backup(DB_PATH,'pre-update')
    with db() as c:
        try:r=apply_staged_update(c,req.filename,req.sha256,user['username'])
        except (ValueError,FileNotFoundError) as e: raise HTTPException(400,str(e))
        audit(c,user['username'],'update_apply_requested',req.filename,f'safety_backup={safety.name}; status={r.get("status")}',client_ip(request));return {**r,'safety_backup':safety.name}

@app.post(f"{router_prefix}/remediation/execute")
def execute_remediation(req: RemediationRequest, request: Request, user=Depends(require_admin)):
    action=req.action.lower(); target=req.target.strip()
    expected=f'CONFIRM {action.upper()} {target}'
    if req.confirm!=expected: raise HTTPException(400,f'Exact confirmation required: {expected}')
    if action not in {'unifi_quarantine','pihole_block_domain'}: raise HTTPException(400,'Unsupported remediation action')
    with db() as c:
        ensure_production_schema(c); cfg=c.execute('SELECT * FROM integration_configs WHERE kind=?',('unifi' if action=='unifi_quarantine' else 'pihole',)).fetchone()
        if not cfg: raise HTTPException(409,'Required integration is not configured')
        rid=c.execute('INSERT INTO remediation_actions(action_type,target,requested_by,confirmation,status,created_at) VALUES(?,?,?,?,?,?)',(action,target,user['username'],req.confirm,'requested',now())).lastrowid
        # Deliberately call only the configured local controller/Pi-hole. No arbitrary endpoint is accepted here.
        result={'ok':False,'action':action,'target':target}
        try:
            if action=='pihole_block_domain':
                if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}',target): raise ValueError('Target must be a valid domain name')
                secret=decrypt_secret(cfg['secret']) if cfg['secret'] else ''
                base=cfg['target'].rstrip('/'); body=json.dumps({'type':'deny','kind':'exact','comment':'Blocked by GODSEYE administrator'}).encode(); headers={'Content-Type':'application/json','User-Agent':'GODSEYE/1.6'}
                if secret: headers['X-FTL-SID']=secret; headers['Authorization']='Bearer '+secret
                errors=[]; sent=False
                # Pi-hole v6 API variants first, then the legacy v5 admin API.
                for url,method,data in [
                    (base+'/api/domains/deny/exact/'+urllib.parse.quote(target,safe=''),'POST',body),
                    (base+'/api/domains/'+urllib.parse.quote(target,safe=''),'POST',body),
                    (base+'/admin/api.php?'+urllib.parse.urlencode({'list':'black','add':target,'auth':secret}),'GET',None),
                ]:
                    try:
                        rq=urllib.request.Request(url,data=data,headers=headers,method=method); urllib.request.urlopen(rq,timeout=8).read(); sent=True; break
                    except Exception as ex: errors.append(str(ex))
                if not sent: raise RuntimeError('Pi-hole block request failed: '+'; '.join(errors)[-2000:])
                result={'ok':True,'action':action,'target':target}
            else:
                if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',target): raise ValueError('UniFi quarantine target must be a MAC address')
                # Cookie-preserving UniFi login, supporting both UniFi OS and legacy controller paths.
                import ssl as _ssl
                from http.cookiejar import CookieJar
                base=cfg['target'].rstrip('/'); site=json.loads(cfg['options_json'] or '{}').get('site','default'); password=decrypt_secret(cfg['secret']) if cfg['secret'] else ''; username=cfg['username'] or ''
                context=None if cfg['verify_tls'] else _ssl._create_unverified_context(); jar=CookieJar(); opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),urllib.request.HTTPSHandler(context=context))
                logged=False; last_error=''
                for login_path in ['/api/auth/login','/api/login']:
                    try:
                        lr=urllib.request.Request(base+login_path,data=json.dumps({'username':username,'password':password}).encode(),headers={'Content-Type':'application/json','User-Agent':'GODSEYE/1.6'},method='POST'); opener.open(lr,timeout=10).read(); logged=True; break
                    except Exception as ex: last_error=str(ex)
                if not logged: raise RuntimeError('UniFi login failed: '+last_error)
                payload=json.dumps({'cmd':'block-sta','mac':target.lower()}).encode(); sent=False; errors=[]
                for path in [f'/proxy/network/api/s/{urllib.parse.quote(site)}/cmd/stamgr',f'/api/s/{urllib.parse.quote(site)}/cmd/stamgr']:
                    try:
                        rq=urllib.request.Request(base+path,data=payload,headers={'Content-Type':'application/json','User-Agent':'GODSEYE/1.6'},method='POST'); opener.open(rq,timeout=10).read(); sent=True; break
                    except Exception as ex: errors.append(str(ex))
                if not sent: raise RuntimeError('UniFi quarantine request failed: '+'; '.join(errors)[-2000:])
                result={'ok':True,'action':action,'target':target}
        except Exception as e: result={'ok':False,'action':action,'target':target,'error':str(e)}
        c.execute('UPDATE remediation_actions SET status=?,result_json=?,completed_at=? WHERE id=?',('completed' if result['ok'] else 'failed',json.dumps(result),now(),rid)); audit(c,user['username'],'remediation_'+action,target,json.dumps(result)[:1000],client_ip(request));c.commit();return result

@app.get(f"{router_prefix}/remediation/history")
def remediation_history(limit:int=100,user=Depends(require_admin)):
    with db() as c:
        ensure_production_schema(c); return [dict(r) for r in c.execute('SELECT * FROM remediation_actions ORDER BY id DESC LIMIT ?',(max(1,min(limit,500)),)).fetchall()]
