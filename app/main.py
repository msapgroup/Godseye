from __future__ import annotations
import datetime as dt
import hmac
import ipaddress
import json
import math
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

from .auth import generate_totp_secret, hash_password, new_token, totp_provisioning_uri, verify_password, verify_totp
from .diagnostics import diagnose_device, recommendations
from .diagnostic_rules import analyze as analyze_diagnostic
from .plugins import manifest as plugin_manifest
from .discovery import nmap_discover, ip_neighbors, mdns_name
from .integrations import website_check, pihole_test, unifi_login, snmp_test
from .collectors import CollectorManager

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("GODSEYE_DB", BASE_DIR / "data" / "godseye.db"))

# A scanner that hasn't reported a successful run in this many seconds is
# treated as unhealthy even if the systemd unit still shows "active" -
# otherwise GODSEYE can look fine on the dashboard while silently doing
# nothing (see /api/v1/health).
HEARTBEAT_STALE_AFTER = int(os.environ.get("GODSEYE_HEARTBEAT_STALE_AFTER", "180"))

VALID_CLASSIFICATIONS = {"new", "known", "ignored", "investigate"}
VALID_ROLES = {"admin", "readonly"}
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
    yield
    collector_manager.stop()


app = FastAPI(title="GODSEYE", version="1.0.0", lifespan=lifespan)


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
def audit_log(limit: int = 200, admin=Depends(require_admin)):
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


@app.post(f"{router_prefix}/scan")
def manual_scan(request: Request, admin=Depends(require_admin)):
    # Scanning is deliberately isolated into the privileged godseye-scanner service.
    # Touching this endpoint asks that service to scan on its next cycle.
    flag = DB_PATH.parent / "scan-now"
    flag.touch()
    with db() as c:
        audit(c, admin["username"], "manual_scan_requested", ip=client_ip(request))
    return {"ok": True, "message": "Scan requested"}


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
def diagnostic_host(req: DiagnosticRequest, user=Depends(get_current_user)):
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
def discovery_nmap(target: str = "192.168.1.0/24", user=Depends(get_current_user)):
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

@app.post(f"{router_prefix}/intelligence/issues/{{issue_id}}/resolve")
def resolve_intelligence_issue(issue_id: int, user=Depends(require_admin)):
    with db() as c:
        cur=c.execute("UPDATE network_issues SET status='resolved',resolved_at=? WHERE id=? AND status='open'",(now(),issue_id))
        if not cur.rowcount: raise HTTPException(404,"Issue not found or already resolved")
    return {"ok":True}

@app.get(f"{router_prefix}/intelligence/topology")
def intelligence_topology(user=Depends(get_current_user)):
    with db() as c:
        rows=c.execute("SELECT * FROM topology_links ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]

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
    target: str
    interval_seconds: int = 300
    options: dict = {}

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
    if not req.name.strip() or not req.target.strip():
        raise HTTPException(400, "Name and target are required")
    interval = max(30, min(req.interval_seconds, 86400))
    ts = now()
    with db() as c:
        try:
            c.execute(
                "INSERT INTO integration_settings(name,kind,target,enabled,interval_seconds,options_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (req.name.strip(), req.kind, req.target.strip(), 1, interval, json.dumps(req.options), ts, ts)
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "A monitor with that name already exists")
    return {"ok": True}

@app.delete(f"{router_prefix}/monitoring/settings/{{monitor_id}}")
def delete_monitoring_setting(monitor_id: int, user=Depends(require_admin)):
    with db() as c:
        c.execute("DELETE FROM integration_settings WHERE id=?", (monitor_id,))
    return {"ok": True}

@app.post(f"{router_prefix}/monitoring/run")
def run_monitoring(user=Depends(require_admin)):
    manager = getattr(app.state, "collector_manager", None)
    if manager is None:
        raise HTTPException(503, "Collector manager is not running")
    return manager.run_all()


@app.get("/monitoring", response_class=HTMLResponse)
def monitoring_page(request: Request):
    get_current_user(request)
    return HTMLResponse("""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
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
.toolbar{margin:16px 0 12px}.input,.filter{border:1px solid #d8e0e9;border-radius:7px;background:#fff;color:#25334a}.primary{background:#0f7df0!important;border-color:#0f7df0!important;color:#fff!important}.primary:hover{background:#096fd8!important}.table-head{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid #e8edf3}.table-head h2{padding:0;border:0}.table-head .muted{font-size:11px}
th,td{padding:11px 12px;font-size:11px}th{font-size:9px;color:#78889e;background:#fbfcfe}tr:hover{background:#f7fbff}.device-name{display:flex;align-items:center;gap:8px}.device-icon{width:23px;height:23px;border-radius:7px;background:#e8f4ff;color:#0879d9;display:grid;place-items:center;font-size:11px}.status-badge{display:inline-flex;padding:3px 7px;border-radius:999px;background:#e9fbf3;color:#0b9a63;font-size:9px;font-weight:700}.severity-high{background:#fff0f2;color:#dc3f58}.severity-medium{background:#fff7e7;color:#b77900}.severity-low{background:#eef7ff;color:#2478b9}
.map-card{min-height:460px;position:relative;overflow:hidden;background:linear-gradient(#fff,#fbfdff)}.map-canvas{min-height:410px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px}.map-node{min-width:110px;text-align:center}.map-circle{width:44px;height:44px;border-radius:50%;margin:auto;display:grid;place-items:center;background:#1592e8;color:#fff;box-shadow:0 5px 16px rgba(21,146,232,.2)}.map-label{font-size:10px;font-weight:700;margin-top:4px}.map-sub{font-size:9px;color:#8190a2}.map-line{width:2px;height:28px;background:#8fd4fa}.map-children{display:flex;gap:45px;position:relative}.map-children:before{content:"";position:absolute;top:-15px;left:15%;right:15%;height:2px;background:#54b5eb}.map-children .map-node{position:relative}.map-children .map-node:before{content:"";position:absolute;top:-15px;left:50%;width:2px;height:15px;background:#54b5eb}
.tool-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.tool-card{background:#fff;border:1px solid #e1e7ef;border-radius:9px;padding:17px;min-height:145px;box-shadow:0 2px 7px rgba(25,45,70,.04)}.tool-card h3{font-size:13px;margin:10px 0 4px}.tool-card p{font-size:10px;color:#77879b;min-height:30px}.tool-card .tool-icon{width:35px;height:35px;border-radius:9px;background:#edf6ff;color:#1685e7;display:grid;place-items:center;font-size:17px}.tool-card button{font-size:10px;padding:6px 10px}
.integration-tabs{display:flex;gap:4px;border-bottom:1px solid #e2e8f0;padding:0 16px}.integration-tab{padding:11px 14px;border:0;border-bottom:2px solid transparent;background:none;color:#72819a}.integration-tab.active{color:#0f7df0;border-bottom-color:#0f7df0}.integration-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;padding:18px}.checklist{padding:16px;background:#f8fafc;border-radius:8px}.check{font-size:11px;margin:10px 0;color:#52647a}.check:before{content:'✓';color:#13a36e;font-weight:800;margin-right:8px}
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
</script></div></body></html>""")

@app.get("/tools", response_class=HTMLResponse)
def tools_page(request: Request):
    get_current_user(request)
    return HTMLResponse("""<!doctype html>
<html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GODSEYE — Tools</title>
<style>
:root{color-scheme:dark;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172033}.layout{display:flex;min-height:100vh}.side{width:240px;background:#0a0f18;border-right:1px solid #1d2838;padding:20px 0;position:sticky;top:0;height:100vh}.brand{padding:0 20px 18px;border-bottom:1px solid #1d2838;font-weight:800;letter-spacing:.08em}.brand small{display:block;color:#66758b;font-size:10px;letter-spacing:.12em;margin-top:4px}.nav{padding:14px 0}.nav a{display:block;padding:10px 20px;color:#9eb0c8;text-decoration:none;font-size:13px;border-left:3px solid transparent}.nav a:hover{background:#111a28;color:#fff;border-left-color:#2563eb}.main{flex:1;max-width:1100px;padding:28px 4%;margin:auto}.hero{display:flex;justify-content:space-between;gap:15px;align-items:end} .muted{color:#6b778c;font-size:12px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:20px}.section{background:#0d141f;border:1px solid #1d2a3d;border-radius:14px;padding:20px;scroll-margin-top:20px}.section h2{margin:0 0 8px;font-size:17px}.row{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.input,button{background:#0b121c;color:#e8eef7;border:1px solid #2b3a52;border-radius:8px;padding:10px 12px}.input{flex:1;min-width:190px}button{cursor:pointer;background:#2563eb;border-color:#2563eb}button.secondary{background:#111a28}button.warn{background:#3a1522;border-color:#5c2436}pre{white-space:pre-wrap;word-break:break-word;background:#080e16;border:1px solid #1d2a3d;border-radius:9px;padding:12px;min-height:42px}.full{grid-column:1/-1}.status{color:#50e3a4}.planned{color:#f7c948}@media(max-width:800px){.layout{display:block}.side{position:sticky;width:100%;height:auto;z-index:10;border-right:0;border-bottom:1px solid #1d2838;padding:10px 0}.brand{display:none}.nav{display:flex;overflow:auto;padding:0}.nav a{white-space:nowrap;border-left:0;border-bottom:3px solid transparent;padding:9px 12px}.grid{grid-template-columns:1fr}}
</style></head><body><div class="layout">
<aside class="side"><div class="brand">◉ GODSEYE<small>NETWORK INTELLIGENCE</small></div><nav class="nav">
<a href="/">📡 Dashboard</a><a href="#discovery">🔎 Discovery</a><a href="#diagnostics">🩺 Diagnostics</a><a href="#integrations">🔌 Integrations</a><a href="#monitoring">🌐 Monitoring</a><a href="#wol">⚡ Wake-on-LAN</a><a href="#plugins">🧩 Plugins</a>
</nav></aside>
<main class="main"><div class="hero"><div><h1>GODSEYE Tools</h1><div class="muted">Discovery, diagnostics and safe network utilities. Actions that change network state require administrator access.</div></div><a href="/" style="color:#7fb0ff">← Dashboard</a></div>
<div class="grid">
<section class="section" id="discovery"><h2>🔎 Discovery</h2><div class="muted">Find devices and local network neighbors.</div><div class="row"><input class="input" id="target" value="192.168.1.0/24" placeholder="Private network CIDR"><button onclick="nmap()">Run Nmap</button><button class="secondary" onclick="get('/api/v1/discovery/neighbors','discoveryOut')">Neighbors</button></div><pre id="discoveryOut">Ready.</pre></section>
<section class="section" id="diagnostics"><h2>🩺 Diagnostics</h2><div class="muted">Evidence-based host troubleshooting.</div><div class="row"><input class="input" id="host" value="192.168.1.1" placeholder="IP or hostname"><button onclick="diag()">Diagnose Host</button></div><pre id="diagOut">Ready.</pre></section>
<section class="section" id="gateway"><h2>🌐 Gateway / Internet</h2><div class="row"><button onclick="get('/api/v1/diagnostics/gateway','gatewayOut')">Test Gateway</button><button onclick="get('/api/v1/diagnostics/internet','gatewayOut')">Test Internet</button></div><pre id="gatewayOut">Ready.</pre></section>
<section class="section" id="monitoring"><h2>🔗 Website / Service Monitor</h2><div class="row"><input class="input" id="url" value="https://example.com" placeholder="https://host-or-service"><button onclick="website()">Test Website</button></div><pre id="websiteOut">Ready.</pre></section>
<section class="section" id="integrations"><h2>🔌 Integrations</h2><div class="muted">Native integration connectivity tests. Credentials are not persisted by these test actions.</div><div class="row"><input class="input" id="pihole" placeholder="Pi-hole URL"><button onclick="piholeTest()">Test Pi-hole</button><input class="input" id="snmp" placeholder="SNMP host"><button onclick="snmpTest()">Test SNMP</button></div><pre id="integrationOut">Ready.</pre><div class="muted planned">DHCP, UniFi collectors, router collectors, MQTT/Home Assistant and additional integrations are being added to the plugin collector layer.</div></section>
<section class="section" id="wol"><h2>⚡ Wake-on-LAN</h2><div class="muted">Administrator-only. Sends a magic packet on the selected broadcast network.</div><div class="row"><input class="input" id="mac" placeholder="AA:BB:CC:DD:EE:FF"><input class="input" id="broadcast" value="255.255.255.255" placeholder="Broadcast"><button class="warn" onclick="wol()">Wake Device</button></div><pre id="wolOut">Ready.</pre></section>
<section class="section full" id="plugins"><h2>🧩 GODSEYE Plugins</h2><div class="row"><button onclick="get('/api/v1/plugins','pluginOut')">Refresh Capability Manifest</button></div><pre id="pluginOut">Ready.</pre></section>
<section class="section full" id="ask"><h2>🧠 Ask GODSEYE</h2><div class="muted">Run a host diagnosis and GODSEYE will turn the evidence into likely causes and recommended next steps.</div><div class="row"><input class="input" id="askHost" value="192.168.1.1" placeholder="Device IP or hostname"><button onclick="ask()">Analyze</button></div><pre id="askOut">Ready.</pre></section>
</div></main></div>
<script>
async function req(url,opt={}){opt=opt||{};opt.headers=opt.headers||{};if(opt.method&&['POST','PUT','PATCH','DELETE'].includes(opt.method.toUpperCase())){const m=document.cookie.match('(?:^|; )godseye_csrf=([^;]*)');const token=m?decodeURIComponent(m[1]):'';if(token)opt.headers['X-CSRF-Token']=token}let r=await fetch(url,opt);let t=await r.text();if(!r.ok)throw new Error(t);return t?JSON.parse(t):{}}
async function get(url,id){try{document.getElementById(id).textContent=JSON.stringify(await req(url),null,2)}catch(e){document.getElementById(id).textContent=e}}
async function nmap(){try{document.getElementById('discoveryOut').textContent=JSON.stringify(await req('/api/v1/discovery/nmap?target='+encodeURIComponent(document.getElementById('target').value)),null,2)}catch(e){document.getElementById('discoveryOut').textContent=e}}
async function diag(){try{document.getElementById('diagOut').textContent=JSON.stringify(await req('/api/v1/diagnostics/host',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:document.getElementById('host').value})}),null,2)}catch(e){document.getElementById('diagOut').textContent=e}}
async function ask(){try{document.getElementById('askOut').textContent=JSON.stringify(await req('/api/v1/diagnostics/host',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:document.getElementById('askHost').value})}),null,2)}catch(e){document.getElementById('askOut').textContent=e}}
async function website(){try{document.getElementById('websiteOut').textContent=JSON.stringify(await req('/api/v1/monitor/website',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:document.getElementById('url').value})}),null,2)}catch(e){document.getElementById('websiteOut').textContent=e}}
async function piholeTest(){try{document.getElementById('integrationOut').textContent=JSON.stringify(await req('/api/v1/integrations/pihole/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:document.getElementById('pihole').value})}),null,2)}catch(e){document.getElementById('integrationOut').textContent=e}}
async function snmpTest(){try{document.getElementById('integrationOut').textContent=JSON.stringify(await req('/api/v1/integrations/snmp/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:document.getElementById('snmp').value})}),null,2)}catch(e){document.getElementById('integrationOut').textContent=e}}
async function wol(){try{document.getElementById('wolOut').textContent=JSON.stringify(await req('/api/v1/tools/wol',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:document.getElementById('mac').value,broadcast:document.getElementById('broadcast').value})}),null,2)}catch(e){document.getElementById('wolOut').textContent=e}}
</script></body></html>""")

@app.get("/", response_class=HTMLResponse)
def dashboard():
    banner_html = LOGIN_BANNER.replace("<", "&lt;").replace(">", "&gt;") if LOGIN_BANNER else ""
    html = DASHBOARD.replace("__LOGIN_BANNER__", banner_html)
    html = html.replace("__LOGIN_BANNER_DISPLAY__", "" if LOGIN_BANNER else "display:none")
    html = html.replace("__MIN_PASSWORD_LENGTH__", str(MIN_PASSWORD_LENGTH))
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
</style></head>
<body>
<div id="authOverlay" class="overlay" style="display:none">
  <div class="authcard">
    <div id="loginBanner" class="muted" style="white-space:pre-wrap;margin-bottom:14px;__LOGIN_BANNER_DISPLAY__">__LOGIN_BANNER__</div>
    <h2>GODSEYE</h2>
    <div class="muted">Sign in to continue</div>
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
    <div class="brand" style="margin-bottom:18px"><div class="eye">◉</div><div><b>GODSEYE</b><div class="muted">NETWORK INTELLIGENCE & SECURITY</div></div></div>
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
<div class="brand"><div class="eye">◉</div><div><b>GODSEYE</b><div class="muted">LOCAL NETWORK INTELLIGENCE</div></div></div>
<div class="navlist">
<div class="navsection">Overview</div>
<button class="navitem active" data-view="overview" onclick="showView('overview')"><span class="navicon">⌂</span><span>Dashboard</span></button>
<button class="navitem" data-view="devices" onclick="showView('devices')"><span class="navicon">▣</span><span>Devices</span></button>
<button class="navitem" data-view="network" onclick="showView('network')"><span class="navicon">⌁</span><span>Network Map</span></button>
<button class="navitem" data-view="monitoring" onclick="showView('monitoring')"><span class="navicon">◔</span><span>Monitoring</span></button>
<button class="navitem" data-view="findings" onclick="showView('findings')"><span class="navicon">!</span><span>Findings</span><span class="badge" id="findingBadge">0</span></button>

<div class="navsection">Management</div>
<button class="navitem" data-view="tools" onclick="showView('tools')"><span class="navicon">⚒</span><span>Tools</span></button>
<button class="navitem" data-view="integrations" onclick="showView('integrations')"><span class="navicon">⌘</span><span>Integrations</span></button>
<button class="navitem" data-view="reports" onclick="showView('reports')"><span class="navicon">▤</span><span>Reports</span></button>
<button class="navitem" data-view="security" onclick="showView('security')"><span class="navicon">▣</span><span>Settings</span></button>

<div class="navsection">Administration</div>
<button class="navitem" data-view="rules" id="navRules" onclick="showView('rules')"><span class="navicon">⚑</span><span>Alert Rules</span></button>
<button class="navitem" id="navUsers" data-view="users" onclick="showView('users')"><span class="navicon">♙</span><span>Users</span></button>
<button class="navitem" id="navAudit" data-view="audit" onclick="showView('audit')"><span class="navicon">▥</span><span>Audit Log</span></button>
</div>
<div class="sidebar-footer">
<button id="scanBtn" class="primary" onclick="scan()">⟳ Scan Now</button>
<div class="muted" id="whoami"></div>
<button class="link" onclick="openChangePassword()">Change password</button>
<button class="link" onclick="logout()">Log out</button>
</div>
</nav>
<main class="content"><div class="headerbar"><div class="muted">Network Intelligence & Security</div><div class="top-actions"><span class="status-chip"><span class="status-dot"></span> Online</span><button class="icon-btn" title="Notifications">♧</button><span class="user-chip"><span class="avatar">A</span><span id="topUser">admin</span>⌄</span></div></div><div class="wrap">

<div class="view" id="view-overview">
<div class="hero"><div><h1>Dashboard</h1><div class="muted">Network overview and system status</div></div></div>
<div class="cards">
<div class="card statcard"><div class="staticon">▣</div><div><div class="statmeta">Total Devices</div><div class="statnum" id="total">—</div></div><span class="trend">↑ 2 new</span></div>
<div class="card statcard"><div class="staticon green">✓</div><div><div class="statmeta">Online</div><div class="statnum" id="online">—</div></div><span class="trend" id="onlineTrend">—</span></div>
<div class="card statcard"><div class="staticon red">!</div><div><div class="statmeta">Issues</div><div class="statnum" id="unknown">—</div></div><span class="trend" style="color:#df5064">↓ 2 resolved</span></div>
<div class="card statcard"><div class="staticon purple">◔</div><div><div class="statmeta">Monitors</div><div class="statnum">6</div></div><span class="trend">5 healthy</span></div>
</div>
<div class="dashboard-grid">
<section class="panel traffic"><div class="table-head"><h2>Network Traffic</h2><div class="muted"><span style="color:#1976e8">●</span> Download &nbsp;&nbsp; <span style="color:#16a36d">●</span> Upload</div></div>
<svg viewBox="0 0 760 190" preserveAspectRatio="none" aria-label="Network traffic chart"><g stroke="#e8edf3" stroke-width="1"><line x1="45" y1="25" x2="745" y2="25"/><line x1="45" y1="65" x2="745" y2="65"/><line x1="45" y1="105" x2="745" y2="105"/><line x1="45" y1="145" x2="745" y2="145"/></g><g fill="#8492a6" font-size="9"><text x="4" y="28">100 Mbps</text><text x="8" y="68">75 Mbps</text><text x="8" y="108">50 Mbps</text><text x="8" y="148">25 Mbps</text><text x="20" y="183">0 Mbps</text></g><path d="M45 150 L75 142 L105 146 L135 128 L165 136 L195 116 L225 125 L255 92 L285 105 L315 82 L345 110 L375 96 L405 52 L435 82 L465 68 L495 36 L525 75 L555 60 L585 96 L615 80 L645 108 L675 94 L705 115 L745 100 L745 170 L45 170 Z" fill="rgba(25,118,232,.12)"/><polyline points="45,150 75,142 105,146 135,128 165,136 195,116 225,125 255,92 285,105 315,82 345,110 375,96 405,52 435,82 465,68 495,36 525,75 555,60 585,96 615,80 645,108 675,94 705,115 745,100" fill="none" stroke="#1976e8" stroke-width="2.2"/><polyline points="45,166 75,160 105,162 135,154 165,158 195,148 225,154 255,139 285,145 315,132 345,147 375,139 405,120 435,136 465,127 495,111 525,131 555,122 585,143 615,134 645,150 675,141 705,153 745,145" fill="none" stroke="#16a36d" stroke-width="2"/></svg></section>
<section class="panel"><div class="table-head"><h2>Recent Activity</h2><button class="link" onclick="showView('activity')">View all</button></div><div class="activity-list" id="activityList"><div class="activity-row"><span class="activity-dot green"></span><div><div class="activity-title">Loading activity…</div><div class="activity-sub">GODSEYE is checking the network</div></div><span class="activity-time">now</span></div></div></section>
</div>
<section class="panel"><div class="table-head"><h2>Devices</h2><button class="link" onclick="showView('devices')">View all devices →</button></div><div style="overflow:auto"><table><thead><tr><th>Status</th><th>Device</th><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Type</th><th>Last Seen</th></tr></thead><tbody id="devices"></tbody></table></div></section>
<div class="toolbar" style="display:none"><input id="search" class="input"><select id="status" class="filter"><option value="">All</option></select><select id="classification" class="filter"><option value="">All</option></select></div>
</div>

<div class="view" id="view-devices" style="display:none">
<div class="hero"><div><h1>Device Inventory</h1><div class="muted">All discovered devices on your network</div></div><button class="primary" onclick="scan()">＋ Add / Discover Device</button></div>
<div class="toolbar"><input id="inventorySearch" class="input" placeholder="Search devices…" oninput="loadInventory()"><select id="inventoryStatus" class="filter" onchange="loadInventory()"><option value="">All statuses</option><option value="online">Online</option><option value="offline">Offline</option></select></div>
<section class="panel"><div class="table-head"><h2>Discovered Devices</h2><div class="muted" id="inventoryCount">—</div></div><div style="overflow:auto"><table><thead><tr><th>Name</th><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Type</th><th>Last Seen</th><th>Status</th></tr></thead><tbody id="inventoryRows"></tbody></table></div></section>
</div>
<div class="view" id="view-network" style="display:none">
<div class="hero"><div><h1>Network Map</h1><div class="muted">Visual view of your network topology</div></div><div><button class="primary" onclick="loadNetwork()">↻ Refresh Map</button></div></div>
<section class="panel map-card"><div class="table-head"><h2>Live Network Topology</h2><div class="muted">Based on discovered devices and relationships</div></div><div class="map-canvas" id="networkCanvas"><div class="map-node"><div class="map-circle">☁</div><div class="map-label">Internet</div><div class="map-sub">External</div></div><div class="map-line"></div><div class="map-node"><div class="map-circle">▣</div><div class="map-label">Gateway / Router</div><div class="map-sub">192.168.1.1</div></div><div class="map-line"></div><div class="map-node"><div class="map-circle">▦</div><div class="map-label">Network</div><div class="map-sub">Discovering topology…</div></div></div></section>
</div>
<div class="view" id="view-monitoring" style="display:none">
<div class="hero"><div><h1>Monitors</h1><div class="muted">Configure and manage network monitoring</div></div><button class="primary" onclick="runMonitors()">▶ Run All</button></div>
<section class="panel"><div class="table-head"><h2>Monitoring Services</h2><button class="primary" onclick="showView('integrations')">＋ Add Monitor</button></div><div style="overflow:auto"><table><thead><tr><th>Name</th><th>Type</th><th>Target</th><th>Interval</th><th>Status</th><th>Last Check</th><th>Response</th></tr></thead><tbody id="monitorRows"></tbody></table></div></section>
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
<div class="hero"><div><h1>Integrations</h1><div class="muted">Configure external services and integrations</div></div></div>
<section class="panel"><div class="integration-tabs"><button class="integration-tab active">Pi-hole</button><button class="integration-tab">UniFi</button><button class="integration-tab">SNMP</button><button class="integration-tab">Other</button></div><div class="integration-grid"><div><h3 style="font-size:14px;margin-top:0">Pi-hole</h3><div class="muted" style="margin-bottom:12px">Integrate with your Pi-hole instance for DNS and blocking analytics.</div><input id="piholeUrl" class="input" style="width:100%;margin-bottom:9px" placeholder="Pi-hole URL, e.g. http://192.168.1.3"><button class="primary" onclick="testPihole()">Save Configuration & Test</button><div id="integrationResult" class="muted" style="margin-top:10px"></div></div><div class="checklist"><div style="font-size:12px;font-weight:700">Features (when configured)</div><div class="check">Client device correlation</div><div class="check">Blocked domain tracking</div><div class="check">Query analytics</div><div class="check">Device enrichment</div></div></div></section>
</div>
<div class="view" id="view-reports" style="display:none">
<div class="hero"><div><h1>Reports</h1><div class="muted">Network status, findings and audit summaries</div></div></div>
<div class="tool-grid"><div class="tool-card"><div class="tool-icon">▤</div><h3>Network Summary</h3><p>Current devices, health and scanner status.</p><button class="primary" onclick="load()">Refresh</button></div><div class="tool-card"><div class="tool-icon">!</div><h3>Findings Report</h3><p>Open and resolved intelligence findings.</p><button class="primary" onclick="showView('findings')">Open</button></div><div class="tool-card"><div class="tool-icon">▥</div><h3>Audit Report</h3><p>Administrator actions and security events.</p><button class="primary" onclick="showView('audit')">Open</button></div></div></div>

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
<form class="userForm" onsubmit="return createUser(event)"><input class="input" id="newUsername" placeholder="Username" required><input class="input" id="newUserPassword" type="password" placeholder="Password (min __MIN_PASSWORD_LENGTH__ chars)" required minlength="__MIN_PASSWORD_LENGTH__"><select class="filter" id="newUserRole"><option value="readonly">Read-only</option><option value="admin">Admin</option></select><button class="primary" type="submit">Add user</button></form>
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
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const CLASS_CYCLE={new:'known',known:'ignored',ignored:'investigate',investigate:'new'};
const CLASS_LABEL={new:'New',known:'Known',ignored:'Ignored',investigate:'Investigate'};
let ME=null;
let PENDING_MFA_TOKEN=null;
function getCookie(name){const m=document.cookie.match('(?:^|; )'+name+'=([^;]*)');return m?decodeURIComponent(m[1]):null}
async function json(url,opt={}){opt.headers=opt.headers||{};if(opt.method&&opt.method!=='GET'){let csrf=getCookie('godseye_csrf');if(!csrf){await fetch('/api/v1/auth/csrf');csrf=getCookie('godseye_csrf')}opt.headers['X-CSRF-Token']=csrf||''}let r=await fetch(url,opt);if(r.status===401){showLogin();throw new Error('unauthenticated')}if(!r.ok){let t=await r.text();throw new Error(t)}return r.status===204?null:r.json()}
function showLogin(){document.getElementById('app').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('setupOverlay').style.display='none';document.getElementById('authOverlay').style.display='grid'}
async function checkInitialSetup(){try{let r=await fetch('/api/v1/auth/setup/status');let d=await r.json();if(d.setup_required){document.getElementById('authOverlay').style.display='none';document.getElementById('setupOverlay').style.display='grid';return true}}catch(e){}return false}
async function doInitialSetup(e){e.preventDefault();const err=document.getElementById('setupErr');err.textContent='';if(setupPass.value!==setupPass2.value){err.textContent='Passwords do not match';return false}try{let r=await fetch('/api/v1/auth/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:'',new_password:setupPass.value})});if(!r.ok){let t=await r.json().catch(()=>({}));err.textContent=t.detail||'Could not create password';return false}document.getElementById('setupOverlay').style.display='none';document.getElementById('authOverlay').style.display='grid';loginUser.value='admin';loginPass.value='';loginPass.focus()}catch(e){err.textContent='Setup failed'}return false}
function showApp(){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('app').style.display='block'}
function showView(name){document.querySelectorAll('.view').forEach(v=>v.style.display='none');const target=document.getElementById('view-'+name);if(target)target.style.display='';document.querySelectorAll('.navitem').forEach(b=>b.classList.remove('active'));const btn=document.querySelector('.navitem[data-view="'+name+'"]');if(btn)btn.classList.add('active');if(name==='users'&&ME&&ME.role==='admin')loadUsers();if(name==='audit'&&ME&&ME.role==='admin')loadAudit();if(name==='rules')loadRules();if(name==='security')loadSecurity()}
async function doLogin(e){e.preventDefault();const err=document.getElementById('loginErr');err.textContent='';try{let r=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:loginUser.value,password:loginPass.value})});if(r.status===423){err.textContent='Account temporarily locked due to repeated failed logins. Try again later.';return false}if(!r.ok){err.textContent='Invalid username or password';return false}let data=await r.json();if(data.mfa_required){PENDING_MFA_TOKEN=data.pending_token;document.getElementById('authOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='grid';return false}if(data.must_change_password){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='grid';return false}await boot()}catch(e){err.textContent='Sign-in failed'}return false}
async function doMfaVerify(e){e.preventDefault();const err=document.getElementById('mfaLoginErr');err.textContent='';try{let r=await fetch('/api/v1/auth/mfa/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pending_token:PENDING_MFA_TOKEN,code:mfaCode.value.trim()})});if(!r.ok){err.textContent='Invalid code';return false}let data=await r.json();PENDING_MFA_TOKEN=null;if(data.must_change_password){document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('pwOverlay').style.display='grid';return false}await boot()}catch(e){err.textContent='Verification failed'}return false}
function openChangePassword(){document.getElementById('pwOverlay').style.display='grid'}
async function doChangePassword(e){e.preventDefault();const err=document.getElementById('pwErr');err.textContent='';try{await json('/api/v1/auth/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:curPass.value,new_password:newPass.value})});await boot()}catch(e){err.textContent='Could not change password — check your current password'}return false}
async function logout(){await fetch('/api/v1/auth/logout',{method:'POST',headers:{'X-CSRF-Token':getCookie('godseye_csrf')||''}});showLogin()}
async function loadDevices(){let q=new URLSearchParams();if(search.value)q.set('search',search.value);if(status.value)q.set('status',status.value);if(classification.value)q.set('classification',classification.value);let d=await json('/api/v1/devices?'+q);const canEdit=ME&&ME.role==='admin';devices.innerHTML=d.length?d.map(x=>`<tr><td class="${esc(x.status)}"><span class="dot">●</span> ${esc(x.status).replace('_',' ')}</td><td><div class="name">${esc(x.name||x.hostname||'Unknown device')}</div><div class="muted">${esc(x.device_type||'Unclassified')}</div></td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td><td>${esc(x.vendor||'—')}</td><td><button class="pill ${esc(x.classification)}" ${canEdit?`onclick="cycleClass(${x.id},'${x.classification}')"`:'disabled'}>${CLASS_LABEL[x.classification]||x.classification}</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">No devices match this filter.</td></tr>'}
async function loadUsers(){if(!ME||ME.role!=='admin'){usersPanel.style.display='none';return}usersPanel.style.display='block';let u=await json('/api/v1/users');users.innerHTML=u.map(x=>{let mustChange=x.must_change_password?(x.must_change_password_by?`yes, by ${esc(new Date(x.must_change_password_by).toLocaleDateString())}`:'yes'):'no';return `<tr><td>${esc(x.username)}</td><td><span class="pill ${esc(x.role)}">${esc(x.role)}</span></td><td>${esc(new Date(x.created_at).toLocaleDateString())}</td><td>${x.last_login_at?esc(new Date(x.last_login_at).toLocaleString()):'never'}</td><td>${x.password_changed_at?esc(new Date(x.password_changed_at).toLocaleDateString()):'—'}</td><td>${mustChange}</td><td>${x.mfa_enabled?'yes':'no'}</td><td>${x.username===ME.username?'':`<button class="link" onclick="removeUser(${x.id},'${esc(x.username)}')">Remove</button>${x.mfa_enabled?` <button class="link" onclick="resetUserMfa(${x.id},'${esc(x.username)}')">Reset MFA</button>`:''}`}</td></tr>`}).join('')}
async function loadAudit(){if(!ME||ME.role!=='admin'){auditPanel.style.display='none';return}auditPanel.style.display='block';let a=await json('/api/v1/audit?limit=50');auditRows.innerHTML=a.length?a.map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td>${esc(x.actor)}</td><td><span class="pill">${esc(x.action)}</span></td><td>${esc(x.target||'—')}</td><td>${esc(x.details||'')}</td><td>${esc(x.ip||'—')}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No audit entries yet.</td></tr>'}
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
async function load(){let h=await json('/api/v1/health');total.textContent=h.total;online.textContent=h.online;unknown.textContent=h.needs_review;const badge=document.getElementById('needsReviewBadge');if(badge)badge.textContent=h.needs_review;eventsCount.textContent=h.events;updated.textContent='Last refreshed '+new Date().toLocaleTimeString();lastScan.textContent=h.scanner.detail;const hb=document.getElementById('healthbar');if(!h.scanner.healthy){hb.className='healthbar bad';hb.textContent='⚠ Scanner unhealthy — '+h.scanner.detail;hb.style.display='block'}else{hb.style.display='none'}await loadDevices();let e=await json('/api/v1/events?limit=30');events.innerHTML=e.length?e.map(x=>`<tr><td>${esc(new Date(x.created_at).toLocaleString())}</td><td><span class="pill">${esc(x.event_type)}</span></td><td>${esc(x.mac)}</td><td>${esc(x.ip)}</td><td>${esc(x.details)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No activity yet.</td></tr>';const al=document.getElementById('activityList');if(al)al.innerHTML=e.slice(0,5).map((x,i)=>`<div class="activity-row"><span class="activity-dot ${i%2?'':'green'}"></span><div><div class="activity-title">${esc(x.event_type||'Network activity')}</div><div class="activity-sub">${esc(x.mac||x.ip||'Network event')} ${x.details?'· '+esc(x.details):''}</div></div><span class="activity-time">${esc(new Date(x.created_at).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'}))}</span></div>`).join('')||'<div class="empty">No recent activity.</div>';const tr=document.getElementById('onlineTrend');if(tr&&h.total)tr.textContent=Math.round((h.online/h.total)*100)+'%';}
async function cycleClass(id,current){await json('/api/v1/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({classification:CLASS_CYCLE[current]||'new'})});load()}
async function scan(){await json('/api/v1/scan',{method:'POST'});updated.textContent='Scan requested…';setTimeout(load,3000)}

async function loadInventory(){try{let q=new URLSearchParams();if(inventorySearch.value)q.set('search',inventorySearch.value);if(inventoryStatus.value)q.set('status',inventoryStatus.value);let d=await json('/api/v1/devices?'+q);inventoryCount.textContent=d.length+' devices';inventoryRows.innerHTML=d.length?d.map(x=>`<tr><td><div class="device-name"><span class="device-icon">●</span><div><div class="name">${esc(x.name||x.hostname||'Unknown device')}</div><div class="muted">${esc(x.device_type||'Unclassified')}</div></div></div></td><td>${esc(x.ip||'—')}</td><td>${esc(x.mac)}</td><td>${esc(x.vendor||'—')}</td><td>${esc(x.device_type||'—')}</td><td>${x.last_seen?esc(new Date(x.last_seen).toLocaleString()):'—'}</td><td><span class="status-badge">${esc(x.status||'unknown')}</span></td></tr>`).join(''):'<tr><td colspan="7" class="empty">No devices discovered yet. Click Scan Now to discover the network.</td></tr>'}catch(e){inventoryRows.innerHTML='<tr><td colspan="7" class="empty">Unable to load devices.</td></tr>'}}
async function loadNetwork(){try{let links=await json('/api/v1/intelligence/topology');let devs=await json('/api/v1/devices');let nodes=devs.slice(0,8).map(x=>`<div class="map-node"><div class="map-circle">●</div><div class="map-label">${esc(x.name||x.hostname||'Device')}</div><div class="map-sub">${esc(x.ip||'—')}</div></div>`).join('');networkCanvas.innerHTML=`<div class="map-node"><div class="map-circle">☁</div><div class="map-label">Internet</div><div class="map-sub">External</div></div><div class="map-line"></div><div class="map-node"><div class="map-circle">▣</div><div class="map-label">Gateway / Router</div><div class="map-sub">192.168.1.1</div></div><div class="map-line"></div><div class="map-children">${nodes||'<div class="map-node"><div class="map-circle">?</div><div class="map-label">No devices</div><div class="map-sub">Run a scan to build topology</div></div>'}</div>`}catch(e){networkCanvas.innerHTML='<div class="empty">Topology is not available yet. Run a network scan first.</div>'}}
async function loadMonitoring(){try{let d=await json('/api/v1/monitoring/settings');monitorRows.innerHTML=d.length?d.map(x=>`<tr><td>${esc(x.name||'Monitor')}</td><td>${esc(x.kind||x.type||'Monitor')}</td><td>${esc(x.target||'—')}</td><td>${esc(x.interval_seconds||300)} sec</td><td><span class="status-badge">Healthy</span></td><td>—</td><td>—</td></tr>`).join(''):'<tr><td colspan="7" class="empty">No monitors configured yet.</td></tr>'}catch(e){monitorRows.innerHTML='<tr><td colspan="7" class="empty">Monitoring data unavailable.</td></tr>'}}
async function runMonitors(){try{await json('/api/v1/monitoring/run',{method:'POST'});await loadMonitoring();alert('Monitoring run requested.')}catch(e){alert('Could not run monitors: '+e.message)}}
async function loadFindings(){try{let open=await json('/api/v1/intelligence/issues?status=open');let resolved=await json('/api/v1/intelligence/issues?status=resolved');let all=open.concat(resolved);findingOpen.textContent=open.length;findingResolved.textContent=resolved.length;findingAll.textContent=all.length;findingCritical.textContent=all.filter(x=>(x.severity||'').toLowerCase()==='critical').length;let badge=document.getElementById('findingBadge');if(badge)badge.textContent=open.length;findingRows.innerHTML=all.length?all.map(x=>`<tr><td><span class="status-badge severity-${esc((x.severity||'info').toLowerCase())}">${esc(x.severity||'Info')}</span></td><td><div class="name">${esc(x.title||x.kind||'Finding')}</div><div class="muted">${esc(x.recommendation||'')}</div></td><td>${esc(x.device_id||'—')}</td><td>${x.created_at?esc(new Date(x.created_at).toLocaleString()):'—'}</td><td><span class="status-badge">${esc(x.status||'open')}</span></td><td>${x.status==='open'?`<button class="link" onclick="resolveFinding(${x.id})">Resolve</button>`:'—'}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No findings yet.</td></tr>'}catch(e){findingRows.innerHTML='<tr><td colspan="6" class="empty">Findings unavailable.</td></tr>'}}
async function resolveFinding(id){try{await json('/api/v1/intelligence/issues/'+id+'/resolve',{method:'POST'});await loadFindings()}catch(e){alert('Could not resolve finding: '+e.message)}}
async function testPihole(){try{let r=await json('/api/v1/integrations/pihole/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:piholeUrl.value.trim(),timeout:8,verify_tls:true})});integrationResult.textContent=r.ok?'Pi-hole connection successful.':'Pi-hole test completed: '+(r.detail||'not reachable')}catch(e){integrationResult.textContent='Pi-hole test failed: '+e.message}}
const originalShowView=showView;
showView=function(name){originalShowView(name);if(name==='devices')loadInventory();if(name==='network')loadNetwork();if(name==='monitoring')loadMonitoring();if(name==='findings')loadFindings();if(name==='tools'){}if(name==='integrations'){}if(name==='reports'){}if(name==='security')loadSecurity();if(name==='users'&&ME&&ME.role==='admin')loadUsers();if(name==='audit'&&ME&&ME.role==='admin')loadAudit()}
async function boot(){try{if(!getCookie('godseye_csrf'))await fetch('/api/v1/auth/csrf');ME=await json('/api/v1/auth/me')}catch(e){showLogin();return}whoami.textContent=ME.username+' ('+ME.role+')';const tu=document.getElementById('topUser');if(tu)tu.textContent=ME.username+(ME.password_expires_in_days!==undefined?' · password expires in '+ME.password_expires_in_days+'d':'');scanBtn.style.display=ME.role==='admin'?'inline-block':'none';['navRules','navUsers','navAudit'].forEach(id=>{document.getElementById(id).style.display=ME.role==='admin'?'':'none'});const pwBar=document.getElementById('pwReminderBar');if(ME.password_change_reminder_days!==undefined){pwBar.textContent='⚠ Set a new password within '+ME.password_change_reminder_days+' day(s) — click here to do it now.';pwBar.style.display='block'}else{pwBar.style.display='none'}showApp();await load();await loadUsers();await loadAudit();await loadSecurity();await loadRules();await loadFindings();setInterval(load,10000)}
checkInitialSetup().then(required=>{if(!required)boot()});
</script></body></html>'''

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
def monitor_website(req: IntegrationURLRequest, user=Depends(get_current_user)):
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
