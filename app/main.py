Warning: truncated output (original token count: 193767)
Total output lines: 8832

from __future__ import annotations
import base64
import datetime as dt
import hmac
import mimetypes
import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from contextlib import asynccontextmanager
from pathlib import Path
from email.message import EmailMessage
from email.utils import formatdate

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse, RedirectResponse
from pydantic import BaseModel, field_validator

from .auth import generate_totp_secret, hash_password, new_token, totp_provisioning_uri, verify_password, verify_totp
from .diagnostics import diagnose_device, recommendations
from .diagnostic_rules import analyze as analyze_diagnostic
from .plugins import manifest as plugin_manifest
from .discovery import nmap_discover, ip_neighbors, mdns_name
from .integrations import website_check, pihole_test, unifi_login, snmp_test
from .collectors import CollectorManager
from .integration_reporting import IntegrationReportingManager, ensure_schema as ensure_ir_schema, safe_config, sync_integration, build_network_report, build_report, generate_report, next_report_time, send_notification, prometheus_metrics, REPORT_TYPES
from .appliance_hardening import (TrafficCollector, ensure_schema as ensure_hardening_schema, encrypt_secret, decrypt_secret, migrate_plaintext_secrets, traffic_history, client_bandwidth_estimates, generate_prometheus_key, verify_prometheus_key, retention_config, save_retention, apply_retention, create_backup, list_backups, restore_backup, appliance_health, report_csv_bytes, report_pdf_bytes)
from .production_management import (ProductionManager, ensure_schema as ensure_production_schema, settings as production_settings, save_settings as save_production_settings, config_export, config_import, audit_query, audit_csv, stage_update_bytes, apply_staged_update, preflight_update, https_status)
from .traffic_intelligence import (TrafficIntelligenceCollector, ensure_schema as ensure_device_traffic_schema, get_settings as traffic_collection_settings, save_settings as save_traffic_collection_settings, collect_once as collect_device_traffic_once, device_usage as device_traffic_usage, list_interfaces as traffic_interfaces, ingest_samples as ingest_device_traffic_samples, mode_capabilities as traffic_mode_capabilities, TRAFFIC_MODES)

BASE_DIR = Path(__file__).resolve().parent.parent

def _read_app_version() -> str:
    """Read the installed release version from VERSION at runtime.

    Keeping the login-screen version sourced from the release VERSION file
    prevents stale hard-coded UI version strings after in-place upgrades.
    """
    try:
        value = (BASE_DIR / "VERSION").read_text(encoding="utf-8").strip()
        return value or "unknown"
    except OSError:
        return "unknown"

APP_VERSION = _read_app_version()
DB_PATH = Path(os.environ.get("GODSEYE_DB", BASE_DIR / "data" / "godseye.db"))

# A scanner that hasn't reported a successful run in this many seconds is
# treated as unhealthy even if the systemd unit still shows "active" -
# otherwise GODSEYE can look fine on the dashboard while silently doing
# nothing (see /api/v1/health).
HEARTBEAT_STALE_AFTER = int(os.environ.get("GODSEYE_HEARTBEAT_STALE_AFTER", "180"))

VALID_CLASSIFICATIONS = {"new", "investigate", "known", "managed", "ignored"}
VALID_DEVICE_ICONS = {"auto", "router", "switch", "access-point", "firewall", "modem", "pc", "laptop", "server", "nas", "network-storage", "camera", "printer", "phone", "voip-phone", "tablet", "tv", "game-console", "iot", "patch-panel", "other"}
DEVICE_ICON_DIR = BASE_DIR / "app" / "assets" / "device-icons"
VALID_ROLES = {"admin", "operator", "auditor", "readonly"}
VALID_RULE_TYPES = {"new_device_burst", "offline_duration", "ip_change_burst", "reconnect_burst", "offline_count", "scanner_stale", "classification_count"}
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
            icon_key TEXT NOT NULL DEFAULT 'auto',
            icon_data TEXT,
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
        CREATE TABLE IF NOT EXISTS windows_event_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            hostname TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 5986,
            transport TEXT NOT NULL DEFAULT 'ntlm',
            username TEXT NOT NULL DEFAULT '',
            password_enc TEXT NOT NULL DEFAULT '',
            verify_tls INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            poll_interval_minutes INTEGER NOT NULL DEFAULT 5,
            channels_json TEXT NOT NULL DEFAULT '["System","Application"]',
            last_record_json TEXT NOT NULL DEFAULT '{}',
            last_poll_at TEXT,
            last_status TEXT NOT NULL DEFAULT 'never',
            last_error TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS event_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            computer_name TEXT NOT NULL,
            channel TEXT NOT NULL,
            provider TEXT NOT NULL,
            event_id INTEGER NOT NULL,
            level TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT DEFAULT '',
            record_id INTEGER,
            event_time TEXT,
            finding_key TEXT NOT NULL UNIQUE,
            recommendation TEXT DEFAULT '',
            suggested_actions_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'open',
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolved_at TEXT,
            last_recheck_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_event_findings_status ON event_findings(status,severity,last_seen);
        CREATE INDEX IF NOT EXISTS idx_event_findings_computer ON event_findings(computer_name,last_seen);
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_number TEXT UNIQUE,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            priority TEXT NOT NULL DEFAULT 'medium',
            assignee TEXT DEFAULT '',
            linked_type TEXT DEFAULT '',
            linked_id INTEGER,
            device_name TEXT DEFAULT '',
            due_at TEXT,
            calendar_event_id INTEGER,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT,
            closed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status,priority,updated_at);
        CREATE TABLE IF NOT EXISTS ticket_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ticket_notes_ticket ON ticket_notes(ticket_id,created_at);
        CREATE TABLE IF NOT EXISTS windows_agent_enrollment_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            label TEXT DEFAULT '',
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_windows_agent_enrollment_expires ON windows_agent_enrollment_tokens(expires_at);
        CREATE TABLE IF NOT EXISTS windows_agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_uuid TEXT NOT NULL UNIQUE,
            api_key_hash TEXT NOT NULL UNIQUE,
            computer_name TEXT NOT NULL,
            machine_guid TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            os_version TEXT DEFAULT '',
            architecture TEXT DEFAULT '',
            agent_version TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'enrolled',
            enabled INTEGER NOT NULL DEFAULT 1,
            channels_json TEXT NOT NULL DEFAULT '["System","Application"]',
            poll_interval_seconds INTEGER NOT NULL DEFAULT 60,
            last_heartbeat_at TEXT,
            last_event_at TEXT,
            last_error TEXT DEFAULT '',
            enrolled_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_windows_agents_heartbeat ON windows_agents(enabled,last_heartbeat_at);
        CREATE TABLE IF NOT EXISTS windows_agent_rechecks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            finding_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            requested_by TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            delivered_at TEXT,
            completed_at TEXT,
            result_json TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_windows_agent_rechecks_agent ON windows_agent_rechecks(agent_id,status,requested_at);
        CREATE TABLE IF NOT EXISTS windows_agent_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            command_type TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            requested_by TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            delivered_at TEXT,
            completed_at TEXT,
            result_json TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_windows_agent_commands_agent ON windows_agent_commands(agent_id,status,requested_at);
        CREATE TABLE IF NOT EXISTS windows_remote_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'connecting',
            requested_by TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            connected_at TEXT,
            ended_at TEXT,
            last_frame_at TEXT,
            last_width INTEGER NOT NULL DEFAULT 0,
            last_height INTEGER NOT NULL DEFAULT 0,
            last_error TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_windows_remote_sessions_agent ON windows_remote_sessions(agent_id,status,requested_at);
        CREATE TABLE IF NOT EXISTS windows_remote_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            event_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            delivered_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_windows_remote_events_session ON windows_remote_events(session_id,id);
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL DEFAULT '',
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
        CREATE TABLE IF NOT EXISTS ui_layouts (
            page_key TEXT PRIMARY KEY,
            layout_json TEXT NOT NULL DEFAULT '{}',
            updated_by TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS calendar_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            location TEXT DEFAULT '',
            start_at TEXT NOT NULL,
            end_at TEXT NOT NULL,
            all_day INTEGER NOT NULL DEFAULT 0,
            color TEXT NOT NULL DEFAULT 'blue',
            source TEXT NOT NULL DEFAULT 'local',
            external_uid TEXT,
            external_readonly INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(source, external_uid)
        );
        CREATE INDEX IF NOT EXISTS idx_calendar_events_start ON calendar_events(start_at);
        CREATE INDEX IF NOT EXISTS idx_calendar_events_source ON calendar_events(source);
        CREATE TABLE IF NOT EXISTS calendar_integrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            name TEXT NOT NULL,
            account_email TEXT DEFAULT '',
            calendar_name TEXT DEFAULT '',
            auth_mode TEXT NOT NULL DEFAULT 'ics',
            remote_calendar_id TEXT DEFAULT '',
            ics_url_enc TEXT DEFAULT '',
            client_id TEXT DEFAULT '',
            client_secret_enc TEXT DEFAULT '',
            access_token_enc TEXT DEFAULT '',
            refresh_token_enc TEXT DEFAULT '',
            token_expires_at TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            sync_interval_minutes INTEGER NOT NULL DEFAULT 30,
            last_sync_at TEXT,
            last_status TEXT NOT NULL DEFAULT 'not_synced',
            last_error TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS calendar_oauth_states (
            state TEXT PRIMARY KEY,
            integration_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            created_by TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS email_integrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            name TEXT NOT NULL,
            account_email TEXT DEFAULT '',
            client_id TEXT NOT NULL,
            client_secret_enc TEXT NOT NULL,
            access_token_enc TEXT DEFAULT '',
            refresh_token_enc TEXT DEFAULT '',
            token_expires_at TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_status TEXT NOT NULL DEFAULT 'needs_authorization',
            last_error TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS email_oauth_states (
            state TEXT PRIMARY KEY,
            integration_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            created_by TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_email_oauth_states_expires ON email_oauth_states(expires_at);
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
        _add_column_if_missing(c, "users", "display_name", "display_name TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(c, "devices", "offline_escalated_at", "offline_escalated_at TEXT")
        _add_column_if_missing(c, "sessions", "last_seen_at", "last_seen_at TEXT")
        _add_column_if_missing(c, "calendar_integrations", "auth_mode", "auth_mode TEXT NOT NULL DEFAULT 'ics'")
        _add_column_if_missing(c, "calendar_integrations", "remote_calendar_id", "remote_calendar_id TEXT DEFAULT ''")
        _add_column_if_missing(c, "calendar_integrations", "client_id", "client_id TEXT DEFAULT ''")
        _add_column_if_missing(c, "calendar_integrations", "client_secret_enc", "client_secret_enc TEXT DEFAULT ''")
        _add_column_if_missing(c, "calendar_integrations", "access_token_enc", "access_token_enc TEXT DEFAULT ''")
        _add_column_if_missing(c, "calendar_integrations", "refresh_token_enc", "refresh_token_enc TEXT DEFAULT ''")
        _add_column_if_missing(c, "calendar_integrations", "token_expires_at", "token_expires_at TEXT")
        _add_column_if_missing(c, "audit_log", "protected_until", "protected_until TEXT")
        _add_column_if_missing(c, "event_findings", "agent_id", "agent_id INTEGER")
        # Backfill so enabling GODSEYE_PASSWORD_MAX_AGE_DAYS after upgrading doesn't
        # instantly treat every existing account as already expired.
        c.execute("UPDATE users SET password_changed_at=? WHERE password_changed_at IS NULL", (now(),))
        _add_column_if_missing(c, "devices", "classification", "classification TEXT NOT NULL DEFAULT 'new'")
        _add_column_if_missing(c, "devices", "icon_key", "icon_key TEXT NOT NULL DEFAULT 'auto'")
        _add_column_if_missing(c, "devices", "icon_data", "icon_data TEXT")
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



class CalendarSyncManager:
    def __init__(self, db_factory):
        self.db_factory=db_factory
        self._stop=threading.Event()
        self._thread=None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread=threading.Thread(target=self._loop,name="godseye-calendar-sync",daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        while not self._stop.wait(60):
            try:
                with self.db_factory() as c:
                    rows=c.execute("SELECT * FROM calendar_integrations WHERE enabled=1").fetchall()
                    now_dt=dt.datetime.now(dt.timezone.utc)
                    for row in rows:
                        due=True
                        if row["last_sync_at"]:
                            try:
                                last=dt.datetime.fromisoformat(row["last_sync_at"])
                                if last.tzinfo is None:
                                    last=last.replace(tzinfo=dt.timezone.utc)
                                due=(now_dt-last).total_seconds() >= max(5,int(row["sync_interval_minutes"]))*60
                            except Exception:
                                due=True
                        if not due:
                            continue
                        try:
                            _sync_calendar_integration(c,row)
                        except Exception as exc:
                            ts=now()
                            c.execute("UPDATE calendar_integrations SET last_sync_at=?,last_status='error',last_error=?,updated_at=? WHERE id=?",
                                      (ts,str(exc)[:500],ts,row["id"]))
                    c.commit()
            except Exception:
                pass


class WindowsEventCollectorManager:
    def __init__(self, db_factory):
        self.db_factory=db_factory
        self._stop=threading.Event()
        self._thread=None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread=threading.Thread(target=self._loop,name="godseye-windows-events",daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _due(self,row,now_dt):
        if not row["last_poll_at"]:
            return True
        try:
            last=dt.datetime.fromisoformat(row["last_poll_at"])
            if last.tzinfo is None:
                last=last.replace(tzinfo=dt.timezone.utc)
            return (now_dt-last).total_seconds() >= max(1,int(row["poll_interval_minutes"]))*60
        except Exception:
            return True

    def _poll_one(self,c,row):
        from .event_ticketing import poll_windows_source
        source=dict(row)
        source["_password_plain"]=decrypt_secret(source.get("password_enc"))
        ts=now()
        try:
            result=poll_windows_source(c,source,ts)
            c.execute("""UPDATE windows_event_sources SET last_record_json=?,last_poll_at=?,last_status='ok',last_error='',updated_at=? WHERE id=?""",
                      (json.dumps(result["bookmarks"]),ts,ts,row["id"]))
            return result
        except Exception as exc:
            c.execute("""UPDATE windows_event_sources SET last_poll_at=?,last_status='error',last_error=?,updated_at=? WHERE id=?""",
                      (ts,str(exc)[:1000],ts,row["id"]))
            raise

    def poll_source(self,source_id:int):
        with self.db_factory() as c:
            row=c.execute("SELECT * FROM windows_event_sources WHERE id=?",(source_id,)).fetchone()
            if not row:
                raise KeyError("Windows event source not found")
            result=self._poll_one(c,row)
            c.commit()
            return result

    def _loop(self):
        while not self._stop.wait(60):
            try:
                with self.db_factory() as c:
                    rows=c.execute("SELECT * FROM windows_event_sources WHERE enabled=1 ORDER BY id").fetchall()
                    now_dt=dt.datetime.now(dt.timezone.utc)
                    for row in rows:
                        if not self._due(row,now_dt):
                            continue
                        try:
                            self._poll_one(c,row)
                        except Exception:
                            pass
                    c.commit()
            except Exception:
                pass

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
        ensure_device_traffic_schema(c)
        migrate_plaintext_secrets(c)
    traffic_collector = TrafficCollector(db, int(os.environ.get('GODSEYE_TRAFFIC_SAMPLE_SECONDS','10')))
    app.state.traffic_collector = traffic_collector
    traffic_collector.start()
    device_traffic_collector = TrafficIntelligenceCollector(db)
    app.state.device_traffic_collector = device_traffic_collector
    device_traffic_collector.start()
    integration_reporting_manager = IntegrationReportingManager(db)
    app.state.integration_reporting_manager = integration_reporting_manager
    integration_reporting_manager.start()
    calendar_sync_manager = CalendarSyncManager(db)
    app.state.calendar_sync_manager = calendar_sync_manager
    calendar_sync_manager.start()
    windows_event_manager = WindowsEventCollectorManager(db)
    app.state.windows_event_manager = windows_event_manager
    windows_event_manager.start()
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
    windows_event_manager.stop()
    calendar_sync_manager.stop()
    integration_reporting_manager.stop()
    device_traffic_collector.stop()
    traffic_collector.stop()
    collector_manager.stop()


app = FastAPI(title="GODSEYE", version=APP_VERSION, lifespan=lifespan)

@app.get("/assets/login-bg.jpg", include_in_schema=False)
def login_background():
    return FileResponse(BASE_DIR / "app" / "assets" / "login-bg.jpg", media_type="image/jpeg", headers={"Cache-Control":"no-cache, max-age=0, must-revalidate"})

@app.get("/assets/device-icons/{icon_name}.svg", include_in_schema=False)
def device_icon_asset(icon_name: str):
    if icon_name not in VALID_DEVICE_ICONS - {"auto"}:
        raise HTTPException(404, "Device icon not found")
    path = DEVICE_ICON_DIR / f"{icon_name}.svg"
    if not path.exists():
        raise HTTPException(404, "Device icon not found")
    return FileResponse(path, media_type="image/svg+xml", headers={"Cache-Control":"no-cache, max-age=0, must-revalidate"})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Opti…173767 tokens truncated…trip()
        if len(reason) < 5:
            raise HTTPException(400, "A reason of at least 5 characters is required")
        if len(reason) > 500:
            raise HTTPException(400, "Reason must be 500 characters or fewer")
        return reason

@app.post(f"{router_prefix}/monitor/website")
def monitor_website(req: IntegrationURLRequest, user=Depends(require_permission("operate"))):
    from .integrations import website_check
    return website_check(req.url, req.timeout)

@app.post(f"{router_prefix}/integrations/pihole/test")
def integration_pihole(req: IntegrationURLRequest, admin=Depends(require_admin)):
    from .integrations import pihole_test
    return pihole_test(req.url, req.timeout, req.credential, req.verify_tls)

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
    name: str = ""
    kind: str = "pihole"
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

class TrafficCollectionRequest(BaseModel):
    enabled: bool = False
    mode: str = "unifi"
    integration_id: int | None = None
    interface: str = ""
    sample_interval_seconds: int = 30
    options: dict = {}

class TrafficSampleRequest(BaseModel):
    mac: str = ""
    ip: str = ""
    rx_bytes: int = 0
    tx_bytes: int = 0
    interval_seconds: float | None = None
    confidence: str = "measured"
    details: dict = {}

class TrafficIngestRequest(BaseModel):
    mode: str
    source_ref: str = ""
    captured_at: str | None = None
    counter_mode: str = "delta"
    samples: list[TrafficSampleRequest] = []


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
        rows=c.execute("SELECT * FROM integration_configs ORDER BY kind,name,id").fetchall()
        latest={}
        for r in c.execute("SELECT a.* FROM analytics_snapshots a JOIN (SELECT integration_id,MAX(id) mid FROM analytics_snapshots WHERE integration_id IS NOT NULL GROUP BY integration_id) x ON a.id=x.mid"):
            latest[str(r['integration_id'])]=json.loads(r['data_json'])
    return {"configs":[safe_config(r) for r in rows],"analytics":latest}

def _save_integration_instance(c, req, user, request, integration_id=None):
    kind=req.kind.lower()
    if integration_id is not None:
        existing=c.execute("SELECT * FROM integration_configs WHERE id=?",(integration_id,)).fetchone()
        if not existing: raise HTTPException(404,"Integration not configured")
        kind=existing['kind']
    else:
        kind=(kind or req.kind or '').lower()
    if kind not in {"pihole","unifi","snmp"}: raise HTTPException(400,"Supported integrations are pihole, unifi, snmp")
    if not req.target.strip(): raise HTTPException(400,"Target is required")
    if req.sync_interval_seconds < 30: raise HTTPException(400,"Sync interval must be at least 30 seconds")
    stamp=now(); name=(req.name or '').strip()
    if not name:
        n=c.execute("SELECT COUNT(*) FROM integration_configs WHERE kind=?",(kind,)).fetchone()[0]+1
        name=f"{kind.replace('pihole','Pi-hole').replace('unifi','UniFi').replace('snmp','SNMP')} {n}"
    dup=c.execute("SELECT id FROM integration_configs WHERE lower(name)=lower(?) AND (? IS NULL OR id<>?)",(name,integration_id,integration_id)).fetchone()
    if dup: raise HTTPException(409,"An integration with that name already exists")
    old=c.execute("SELECT secret FROM integration_configs WHERE id=?",(integration_id,)).fetchone() if integration_id else None
    secret=encrypt_secret(req.secret) if req.secret is not None else (old['secret'] if old else '')
    options=dict(req.options or {})
    if integration_id:
        c.execute("""UPDATE integration_configs SET name=?,enabled=?,target=?,username=?,secret=?,verify_tls=?,sync_interval_seconds=?,options_json=?,updated_at=? WHERE id=?""",(name,int(req.enabled),req.target.strip(),req.username.strip(),secret,int(req.verify_tls),req.sync_interval_seconds,json.dumps(options),stamp,integration_id))
        iid=integration_id
    else:
        iid=c.execute("""INSERT INTO integration_configs(name,kind,enabled,target,username,secret,verify_tls,sync_interval_seconds,options_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(name,kind,int(req.enabled),req.target.strip(),req.username.strip(),secret,int(req.verify_tls),req.sync_interval_seconds,json.dumps(options),stamp,stamp)).lastrowid
    audit(c,user['username'],'integration_config_saved',str(iid),f'{kind}; name={name}; enabled={req.enabled}; target={req.target}',client_ip(request))
    return safe_config(c.execute("SELECT * FROM integration_configs WHERE id=?",(iid,)).fetchone())

@app.post(f"{router_prefix}/integrations/configs")
def create_integration(req: SavedIntegrationRequest, request: Request, user=Depends(require_admin)):
    with db() as c:
        ensure_ir_schema(c); return _save_integration_instance(c,req,user,request,None)

@app.put(f"{router_prefix}/integrations/configs/{{integration_id}}")
def update_integration(integration_id: int, req: SavedIntegrationRequest, request: Request, user=Depends(require_admin)):
    with db() as c:
        ensure_ir_schema(c); return _save_integration_instance(c,req,user,request,integration_id)

@app.delete(f"{router_prefix}/integrations/configs/{{integration_id}}")
def delete_integration(integration_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        ensure_ir_schema(c); row=c.execute("SELECT name,kind FROM integration_configs WHERE id=?",(integration_id,)).fetchone()
        if not row: raise HTTPException(404,"Integration not configured")
        analytics_deleted=c.execute("DELETE FROM analytics_snapshots WHERE integration_id=?",(integration_id,)).rowcount
        sync_runs_deleted=c.execute("DELETE FROM integration_sync_runs WHERE integration_id=?",(integration_id,)).rowcount
        c.execute("DELETE FROM integration_configs WHERE id=?",(integration_id,))
        audit(c,user['username'],'integration_config_deleted',str(integration_id),f"{row['kind']} {row['name']}; analytics_deleted={analytics_deleted}; sync_runs_deleted={sync_runs_deleted}",client_ip(request))
    return {"ok":True,"analytics_deleted":analytics_deleted,"sync_runs_deleted":sync_runs_deleted}

@app.post(f"{router_prefix}/integrations/configs/{{integration_id}}/sync")
def sync_saved_integration(integration_id: int, request: Request, user=Depends(require_permission("integrations.sync"))):
    manager=getattr(app.state,'integration_reporting_manager',None)
    if manager is None: raise HTTPException(503,"Integration manager is not running")
    try: result=manager.run_sync(integration_id)
    except KeyError: raise HTTPException(404,"Integration not configured")
    with db() as c: audit(c,user['username'],'integration_sync',str(integration_id),json.dumps({k:v for k,v in result.items() if k!='analytics'})[:1000],client_ip(request))
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
        snapshots=[]
        for r in c.execute("""SELECT a.* FROM analytics_snapshots a JOIN (SELECT integration_id,MAX(id) mid FROM analytics_snapshots WHERE integration_id IS NOT NULL GROUP BY integration_id) x ON a.id=x.mid ORDER BY a.id DESC"""):
            d=dict(r); d['analytics']=json.loads(d.pop('data_json') or '{}'); snapshots.append(d)
    return {"by_source":by_source,"clients":top,"integration_analytics":snapshots}

@app.post(f"{router_prefix}/analytics/clear/{{integration_id}}")
def clear_integration_analytics(integration_id: int, req: ClearReasonRequest, request: Request, user=Depends(require_admin)):
    reason=req.clean_reason()
    with db() as c:
        ensure_ir_schema(c)
        cfg=c.execute("SELECT name,kind FROM integration_configs WHERE id=?",(integration_id,)).fetchone()
        label=(cfg['name'] if cfg else f'integration {integration_id}')
        count=c.execute("SELECT COUNT(*) FROM analytics_snapshots WHERE integration_id=?",(integration_id,)).fetchone()[0]
        c.execute("DELETE FROM analytics_snapshots WHERE integration_id=?",(integration_id,))
        audit(c,user['username'],'integration_analytics_cleared',str(integration_id),f'name={label}; deleted={count}; reason={reason}',client_ip(request))
    return {"ok":True,"deleted":count,"cleared_by":user['username'],"integration_id":integration_id,"name":label}

@app.post(f"{router_prefix}/analytics/clear")
def clear_client_query_analytics(req: ClearReasonRequest, request: Request, user=Depends(require_admin)):
    reason=req.clean_reason()
    with db() as c:
        ensure_ir_schema(c)
        count=c.execute("SELECT COUNT(*) FROM analytics_snapshots").fetchone()[0]
        c.execute("DELETE FROM analytics_snapshots")
        audit(c,user['username'],'client_query_analytics_cleared','analytics',f'reason={reason}; deleted={count}',client_ip(request))
    return {"ok":True,"deleted":count,"cleared_by":user['username'],"reason":reason}

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

@app.get(f"{router_prefix}/traffic/config")
def get_traffic_collection_config(user=Depends(get_current_user)):
    with db() as c:
        ensure_device_traffic_schema(c)
        cfg=traffic_collection_settings(c)
        integrations=[safe_config(r) for r in c.execute(
            "SELECT * FROM integration_configs WHERE kind IN ('unifi','snmp') ORDER BY kind,name"
        ).fetchall()]
    return {"config":cfg,"modes":TRAFFIC_MODES,"mode_capabilities":{k:traffic_mode_capabilities(k) for k in TRAFFIC_MODES},"integrations":integrations,"interfaces":traffic_interfaces()}

@app.put(f"{router_prefix}/traffic/config")
def put_traffic_collection_config(req: TrafficCollectionRequest, request: Request, user=Depends(require_admin)):
    with db() as c:
        ensure_device_traffic_schema(c)
        try:
            cfg=save_traffic_collection_settings(c,req.model_dump())
        except ValueError as exc:
            raise HTTPException(400,str(exc))
        audit(c,user['username'],'traffic_collection_config_updated',cfg['mode'],
              f"enabled={cfg['enabled']}; integration_id={cfg.get('integration_id')}; interface={cfg.get('interface')}; interval={cfg['sample_interval_seconds']}",
              client_ip(request))
    return cfg

@app.post(f"{router_prefix}/traffic/ingest")
def traffic_ingest(req: TrafficIngestRequest, request: Request, user=Depends(require_admin)):
    mode=req.mode.lower()
    if mode not in {"span","inline","unifi","snmp"}:
        raise HTTPException(400,"Unsupported traffic source mode")
    if req.counter_mode not in {"delta","cumulative"}:
        raise HTTPException(400,"counter_mode must be delta or cumulative")
    with db() as c:
        ensure_device_traffic_schema(c)
        current=traffic_collection_settings(c)
        if mode in {"span","inline"} and current["mode"]!=mode:
            raise HTTPException(409,f"Traffic collection is configured for {current['mode']}, not {mode}")
        count=ingest_device_traffic_samples(
            c,mode,[x.model_dump() for x in req.samples],
            source_ref=req.source_ref,captured_at=req.captured_at,
            counter_mode=req.counter_mode,confidence="measured",
        )
        stamp=now()
        c.execute("UPDATE traffic_collection_settings SET last_collected_at=?,last_status='success',last_error='',updated_at=? WHERE id=1",(stamp,stamp))
        c.commit()
        audit(c,user['username'],'traffic_samples_ingested',mode,
              f"source_ref={req.source_ref}; counter_mode={req.counter_mode}; samples={count}",client_ip(request))
    return {"ok":True,"mode":mode,"samples_ingested":count}

@app.post(f"{router_prefix}/traffic/collect-now")
def traffic_collect_now(request: Request, user=Depends(require_admin)):
    with db() as c:
        result=collect_device_traffic_once(c)
        audit(c,user['username'],'traffic_collection_run',result.get('mode',''),
              f"status={result.get('status')}; devices_sampled={result.get('devices_sampled',0)}; error={result.get('error') or result.get('note','')}",
              client_ip(request))
    return result

@app.get(f"{router_prefix}/traffic/devices")
def traffic_devices(hours: int=24, limit: int=100, user=Depends(get_current_user)):
    with db() as c:
        return device_traffic_usage(c,hours,limit)

@app.get(f"{router_prefix}/reports/summary")
def report_summary(user=Depends(get_current_user)):
    with db() as c:
        summary,body=build_network_report(c)
    return {"generated_at":now(),"summary":summary,"body_text":body}

@app.post(f"{router_prefix}/reports/generate")
def report_generate(request: Request, report_type: str = "network_summary", user=Depends(require_permission("reports.generate"))):
    if report_type not in REPORT_TYPES: raise HTTPException(400,"Unsupported report type")
    with db() as c:
        rep=generate_report(c,report_type)
        audit(c,user['username'],'report_generated',str(rep['id']),rep['title'],client_ip(request))
    return rep

class ReportBulkDeleteRequest(BaseModel):
    report_ids: list[int]

@app.get(f"{router_prefix}/reports/history")
def report_history(limit: int=50, user=Depends(get_current_user)):
    with db() as c:
        ensure_ir_schema(c); rows=c.execute("SELECT id,schedule_id,report_type,title,generated_at,summary_json,body_text FROM generated_reports ORDER BY id DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall()
    out=[]
    for r in rows:
        d=dict(r); d['summary']=json.loads(d.pop('summary_json') or '{}'); out.append(d)
    return out

@app.delete(f"{router_prefix}/reports/{{report_id}}")
def report_delete(report_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        ensure_ir_schema(c)
        row=c.execute("SELECT id,title,report_type FROM generated_reports WHERE id=?",(report_id,)).fetchone()
        if not row:
            raise HTTPException(404,"Report not found")
        c.execute("DELETE FROM generated_reports WHERE id=?",(report_id,))
        audit(c,user["username"],"report_deleted",str(report_id),json.dumps({"title":row["title"],"report_type":row["report_type"]}),client_ip(request))
    return {"ok":True,"deleted":1}

@app.post(f"{router_prefix}/reports/bulk-delete")
def report_bulk_delete(req: ReportBulkDeleteRequest, request: Request, user=Depends(require_admin)):
    ids=sorted({int(x) for x in req.report_ids if int(x)>0})
    if not ids:
        raise HTTPException(400,"No reports selected")
    if len(ids)>200:
        raise HTTPException(400,"Too many reports selected")
    placeholders=",".join("?" for _ in ids)
    with db() as c:
        ensure_ir_schema(c)
        rows=c.execute(f"SELECT id,title,report_type FROM generated_reports WHERE id IN ({placeholders})",ids).fetchall()
        if not rows:
            raise HTTPException(404,"No selected reports were found")
        found=[r["id"] for r in rows]
        ph=",".join("?" for _ in found)
        c.execute(f"DELETE FROM generated_reports WHERE id IN ({ph})",found)
        audit(c,user["username"],"reports_bulk_deleted","reports",json.dumps({"report_ids":found,"count":len(found)}),client_ip(request))
    return {"ok":True,"deleted":len(found),"report_ids":found}

@app.get(f"{router_prefix}/reports/schedules")
def report_schedules(user=Depends(get_current_user)):
    with db() as c:
        ensure_ir_schema(c); return [dict(r) for r in c.execute("SELECT * FROM report_schedules ORDER BY name")]

@app.post(f"{router_prefix}/reports/schedules")
def create_report_schedule(req: ReportScheduleRequest, request: Request, user=Depends(require_admin)):
    if req.cadence not in {'hourly','daily','weekly'}: raise HTTPException(400,"Cadence must be hourly, daily, or weekly")
    if req.report_type not in REPORT_TYPES: raise HTTPException(400,"Unsupported report type")
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
        return {
            "samples":traffic_history(c,minutes),
            "clients":client_bandwidth_estimates(c),
            "device_usage":device_traffic_usage(c,max(1,(minutes+59)//60),100),
        }

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

@app.post(f"{router_prefix}/audit/clear")
def clear_audit_log(req: ClearReasonRequest, request: Request, user=Depends(require_admin)):
    reason=req.clean_reason()
    stamp=dt.datetime.now(dt.timezone.utc)
    protected_until=(stamp+dt.timedelta(days=7)).isoformat()
    with db() as c:
        # Preserve any protected audit-clear markers that are still inside their 7-day hold window.
        preserved=c.execute("SELECT COUNT(*) FROM audit_log WHERE protected_until IS NOT NULL AND protected_until > ?",(stamp.isoformat(),)).fetchone()[0]
        deleted=c.execute("DELETE FROM audit_log WHERE protected_until IS NULL OR protected_until <= ?",(stamp.isoformat(),)).rowcount
        c.execute("INSERT INTO audit_log(actor,action,target,details,ip,created_at,protected_until) VALUES(?,?,?,?,?,?,?)",
                  (user['username'],'audit_log_cleared','audit_log',f'reason={reason}; deleted={deleted}; preserved_protected={preserved}',client_ip(request),stamp.isoformat(),protected_until))
    return {"ok":True,"deleted":deleted,"preserved_protected":preserved,"cleared_by":user['username'],"reason":reason,"protected_until":protected_until}

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
        ensure_production_schema(c); cfg=c.execute('SELECT * FROM integration_configs WHERE kind=? AND enabled=1 ORDER BY id LIMIT 1',('unifi' if action=='unifi_quarantine' else 'pihole',)).fetchone()
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
