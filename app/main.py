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
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:"
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
    display_name: str = ""
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


class UILayoutRequest(BaseModel):
    layout: dict[str, list[str]]

    @field_validator("layout")
    @classmethod
    def validate_layout(cls, value):
        if len(value) > 80:
            raise ValueError("Too many layout zones")
        cleaned = {}
        for zone, items in value.items():
            if not isinstance(zone, str) or not zone or len(zone) > 120:
                raise ValueError("Invalid layout zone")
            if len(items) > 100:
                raise ValueError("Too many cards in a layout zone")
            cleaned[zone] = [str(item)[:160] for item in items if str(item)]
        return cleaned


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


@app.get(f"{router_prefix}/ui/layouts")
def get_ui_layouts(user=Depends(get_current_user)):
    with db() as c:
        rows = c.execute("SELECT page_key,layout_json,updated_by,updated_at FROM ui_layouts ORDER BY page_key").fetchall()
    layouts = {}
    for row in rows:
        try:
            layouts[row["page_key"]] = {"layout": json.loads(row["layout_json"]), "updated_by": row["updated_by"], "updated_at": row["updated_at"]}
        except Exception:
            continue
    return {"layouts": layouts}


@app.put(f"{router_prefix}/ui/layouts/{{page_key}}")
def save_ui_layout(page_key: str, payload: UILayoutRequest, request: Request, admin=Depends(require_admin)):
    if not re.fullmatch(r"[a-z0-9_-]{1,80}", page_key):
        raise HTTPException(400, "Invalid page key")
    encoded = json.dumps(payload.layout, separators=(",", ":"), sort_keys=True)
    if len(encoded) > 50000:
        raise HTTPException(413, "Layout is too large")
    stamp = now()
    with db() as c:
        c.execute(
            "INSERT INTO ui_layouts(page_key,layout_json,updated_by,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(page_key) DO UPDATE SET layout_json=excluded.layout_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
            (page_key, encoded, admin["username"], stamp),
        )
        audit(c, admin["username"], "ui_layout_saved", target=page_key, details=f"zones={len(payload.layout)}", ip=client_ip(request))
    return {"ok": True, "page_key": page_key, "updated_at": stamp}


@app.delete(f"{router_prefix}/ui/layouts/{{page_key}}")
def reset_ui_layout(page_key: str, request: Request, admin=Depends(require_admin)):
    if not re.fullmatch(r"[a-z0-9_-]{1,80}", page_key):
        raise HTTPException(400, "Invalid page key")
    with db() as c:
        c.execute("DELETE FROM ui_layouts WHERE page_key=?", (page_key,))
        audit(c, admin["username"], "ui_layout_reset", target=page_key, ip=client_ip(request))
    return {"ok": True, "page_key": page_key}


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
            "SELECT u.id,u.username,u.display_name,u.role,u.must_change_password,u.must_change_password_by,"
            "u.created_at,u.last_login_at,u.password_changed_at, "
            "COALESCE((SELECT enabled FROM mfa_secrets m WHERE m.user_id=u.id), 0) AS mfa_enabled "
            "FROM users u ORDER BY u.id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.get(f"{router_prefix}/ticket-assignees")
def ticket_assignees(user=Depends(get_current_user)):
    """Small, non-sensitive user directory used by the Ticket Portal assignee picker."""
    with db() as c:
        rows=c.execute(
            "SELECT id,username,display_name,role FROM users ORDER BY "
            "CASE WHEN trim(display_name)<>'' THEN lower(display_name) ELSE lower(username) END, lower(username)"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post(f"{router_prefix}/users")
def create_user(payload: CreateUserRequest, request: Request, admin=Depends(require_admin)):
    salt, hashed = hash_password(payload.password)
    with db() as c:
        try:
            c.execute(
                "INSERT INTO users(username,display_name,password_hash,password_salt,role,must_change_password,"
                "must_change_password_by,created_at,password_changed_at) "
                "VALUES(?,?,?,?,?,1,?,?,?)",
                (payload.username, payload.display_name.strip()[:160], hashed, salt, payload.role, must_change_deadline(), now(), now()),
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
    hostname: str | None = None
    classification: str | None = None
    notes: str | None = None
    device_type: str | None = None
    icon_key: str | None = None
    icon_data: str | None = None

    @field_validator("name")
    @classmethod
    def check_name(cls, v):
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("name cannot be blank")
        if len(v) > 120:
            raise ValueError("name must be 120 characters or fewer")
        return v

    @field_validator("hostname")
    @classmethod
    def check_hostname(cls, v):
        if v is None:
            return v
        v = v.strip()
        if len(v) > 253:
            raise ValueError("hostname must be 253 characters or fewer")
        return v

    @field_validator("device_type")
    @classmethod
    def check_device_type(cls, v):
        if v is None:
            return v
        v = v.strip()
        if len(v) > 80:
            raise ValueError("device type must be 80 characters or fewer")
        return v

    @field_validator("icon_key")
    @classmethod
    def check_icon_key(cls, v):
        if v is not None and v not in VALID_DEVICE_ICONS:
            raise ValueError(f"icon_key must be one of {sorted(VALID_DEVICE_ICONS)}")
        return v

    @field_validator("icon_data")
    @classmethod
    def check_icon_data(cls, v):
        if v is None or v == "":
            return None
        if not re.fullmatch(r"data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/=\r\n]+", v):
            raise ValueError("custom icon must be a PNG, JPEG, or WebP image")
        try:
            raw = base64.b64decode(v.split(",", 1)[1], validate=True)
        except Exception as exc:
            raise ValueError("custom icon contains invalid base64 data") from exc
        if len(raw) > 262144:
            raise ValueError("custom icon must be 256 KB or smaller")
        return v

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
    for field in ("name", "hostname", "classification", "notes", "device_type", "icon_key", "icon_data"):
        value = getattr(payload, field)
        if value is not None or (field == "icon_data" and field in payload.model_fields_set):
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


class DeviceDeleteRequest(BaseModel):
    reason: str

    @field_validator("reason")
    @classmethod
    def check_reason(cls, v):
        value = (v or "").strip()
        if len(value) < 3:
            raise ValueError("reason must be at least 3 characters")
        if len(value) > 500:
            raise ValueError("reason must be 500 characters or fewer")
        return value


class DeviceCleanupRequest(BaseModel):
    mode: str
    older_than_days: int = 30
    reason: str

    @field_validator("mode")
    @classmethod
    def check_mode(cls, v):
        if v not in {"offline", "old"}:
            raise ValueError("mode must be offline or old")
        return v

    @field_validator("older_than_days")
    @classmethod
    def check_days(cls, v):
        if not 1 <= v <= 3650:
            raise ValueError("older_than_days must be between 1 and 3650")
        return v

    @field_validator("reason")
    @classmethod
    def check_reason(cls, v):
        value = (v or "").strip()
        if len(value) < 3:
            raise ValueError("reason must be at least 3 characters")
        if len(value) > 500:
            raise ValueError("reason must be 500 characters or fewer")
        return value

def _delete_device_record(c, device_id: int):
    row = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not row:
        return None
    mac = row["mac"]
    # Delete device-owned evidence/history while intentionally preserving the audit log.
    c.execute("DELETE FROM device_sources WHERE mac=?", (mac,))
    c.execute("DELETE FROM device_ip_history WHERE mac=?", (mac,))
    c.execute("DELETE FROM events WHERE mac=?", (mac,))
    try:
        c.execute("DELETE FROM diagnostic_runs WHERE device_id=?", (device_id,))
    except Exception:
        pass
    # Remove topology relationships that directly reference this device identity.
    c.execute("DELETE FROM topology_links WHERE parent IN (?,?) OR child IN (?,?)", (mac, row["ip"], mac, row["ip"]))
    c.execute("DELETE FROM network_issues WHERE target IN (?,?)", (mac, row["ip"]))
    c.execute("DELETE FROM devices WHERE id=?", (device_id,))
    return dict(row)


@app.delete(f"{router_prefix}/devices/{{device_id}}")
def delete_device(device_id: int, payload: DeviceDeleteRequest, request: Request, admin=Depends(require_admin)):
    with db() as c:
        row = _delete_device_record(c, device_id)
        if not row:
            raise HTTPException(404, "Device not found")
        audit(c, admin["username"], "device_deleted", target=row["mac"],
              details=f"reason={payload.reason}; name={row.get('name') or row.get('hostname') or ''}; status={row.get('status')}; classification={row.get('classification')}; last_seen={row.get('last_seen')}",
              ip=client_ip(request))
    return {"ok": True, "deleted": 1}


@app.post(f"{router_prefix}/devices/cleanup")
def cleanup_devices(payload: DeviceCleanupRequest, request: Request, admin=Depends(require_admin)):
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=payload.older_than_days)).isoformat()
    with db() as c:
        if payload.mode == "offline":
            where = "status='offline'"
            values = []
        else:
            # v3.5: no classification/status safety filters; the admin-selected age cutoff is authoritative.
            where = "last_seen < ?"
            values = [cutoff]
        rows = c.execute(f"SELECT id FROM devices WHERE {where} ORDER BY last_seen ASC", values).fetchall()
        deleted = 0
        for r in rows:
            if _delete_device_record(c, int(r["id"])):
                deleted += 1
        audit(c, admin["username"], "device_cleanup", target=payload.mode,
              details=f"reason={payload.reason}; deleted={deleted}; older_than_days={payload.older_than_days}; safety_filters=disabled",
              ip=client_ip(request))
    return {"ok": True, "deleted": deleted, "mode": payload.mode}


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
        elif rule_type in {"ip_change_burst", "reconnect_burst"}:
            if "count" not in v or "window_minutes" not in v:
                raise ValueError(f"{rule_type} params need 'count' and 'window_minutes'")
            if not (isinstance(v["count"], (int, float)) and v["count"] > 0):
                raise ValueError("'count' must be a positive number")
            if not (isinstance(v["window_minutes"], (int, float)) and v["window_minutes"] > 0):
                raise ValueError("'window_minutes' must be a positive number")
        elif rule_type == "offline_count":
            if not (isinstance(v.get("count"), (int, float)) and v["count"] > 0):
                raise ValueError("offline_count params need a positive 'count'")
            if not (isinstance(v.get("cooldown_minutes", 15), (int, float)) and v.get("cooldown_minutes", 15) > 0):
                raise ValueError("'cooldown_minutes' must be a positive number")
        elif rule_type == "scanner_stale":
            if not (isinstance(v.get("minutes"), (int, float)) and v["minutes"] > 0):
                raise ValueError("scanner_stale params need a positive 'minutes'")
        elif rule_type == "classification_count":
            if not (isinstance(v.get("count"), (int, float)) and v["count"] > 0):
                raise ValueError("classification_count params need a positive 'count'")
            classes = v.get("classifications") or []
            if not isinstance(classes, list) or not classes or not set(classes).issubset(VALID_CLASSIFICATIONS):
                raise ValueError(f"'classifications' must be a non-empty list drawn from {sorted(VALID_CLASSIFICATIONS)}")
            if not (isinstance(v.get("cooldown_minutes", 15), (int, float)) and v.get("cooldown_minutes", 15) > 0):
                raise ValueError("'cooldown_minutes' must be a positive number")
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

@app.post(f"{router_prefix}/intelligence/issues/{{issue_id}}/create-ticket")
def network_finding_create_ticket(issue_id: int, request: Request, user=Depends(require_permission("operate"))):
    with db() as c:
        issue=c.execute("SELECT * FROM network_issues WHERE id=?",(issue_id,)).fetchone()
        if not issue: raise HTTPException(404,"Network Finding not found")
        existing=c.execute("SELECT * FROM tickets WHERE linked_type='network_finding' AND linked_id=? AND status NOT IN ('closed','resolved') ORDER BY id DESC LIMIT 1",(issue_id,)).fetchone()
        if existing: return dict(existing)
        ts=now()
        priority="critical" if issue["severity"]=="critical" else ("high" if issue["severity"]=="high" else "medium")
        cur=c.execute("""INSERT INTO tickets(title,description,status,priority,assignee,linked_type,linked_id,device_name,created_by,created_at,updated_at)
                         VALUES(?,?,'open',?,'','network_finding',?,?,?, ?,?)""",
                      (issue["title"],issue["recommendation"],priority,issue_id,issue["target"] or "",user["username"],ts,ts))
        tid=cur.lastrowid;number=f"TKT-{tid:05d}";c.execute("UPDATE tickets SET ticket_number=? WHERE id=?",(number,tid))
        audit(c,user["username"],"ticket_created_from_network_finding",number,json.dumps({"issue_id":issue_id,"target":issue["target"]}),client_ip(request))
        row=c.execute("SELECT * FROM tickets WHERE id=?",(tid,)).fetchone()
    return dict(row)

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
# Calendar
# ---------------------------------------------------------------------------

class CalendarEventRequest(BaseModel):
    title: str
    description: str = ""
    location: str = ""
    start_at: str
    end_at: str
    all_day: bool = False
    color: str = "blue"
    calendar_integration_id: int | None = None

class CalendarIntegrationRequest(BaseModel):
    provider: str
    name: str
    account_email: str = ""
    calendar_name: str = ""
    auth_mode: str = "oauth"
    remote_calendar_id: str = ""
    ics_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    enabled: bool = True
    sync_interval_minutes: int = 30

GOOGLE_CALENDAR_SCOPE="https://www.googleapis.com/auth/calendar"
MICROSOFT_CALENDAR_SCOPE="offline_access User.Read Calendars.ReadWrite"

def _calendar_event_row(r):
    d=dict(r)
    d["all_day"]=bool(d.get("all_day"))
    d["external_readonly"]=bool(d.get("external_readonly"))
    d["ticket_id"]=int(d["external_uid"]) if d.get("source")=="ticket" and str(d.get("external_uid") or "").isdigit() else None
    return d

def _calendar_parse_iso(value: str, field: str):
    try:
        parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    except Exception:
        raise HTTPException(400, f"Invalid {field}")
    if parsed.tzinfo is None:
        parsed=parsed.replace(tzinfo=dt.timezone.utc)
    return parsed

def _calendar_validate_event(req: CalendarEventRequest):
    title=req.title.strip()
    if not title or len(title)>160:
        raise HTTPException(400,"Title is required and must be 160 characters or fewer")
    start_dt=_calendar_parse_iso(req.start_at,"start time")
    end_dt=_calendar_parse_iso(req.end_at,"end time")
    if end_dt < start_dt:
        raise HTTPException(400,"End time must be after start time")
    if req.color not in {"blue","green","purple","orange","red"}:
        raise HTTPException(400,"Unsupported calendar color")
    return title,start_dt,end_dt

def _calendar_http_json(url: str, method="GET", headers=None, data=None, form=None, timeout=15):
    headers=dict(headers or {})
    body=None
    if form is not None:
        body=urllib.parse.urlencode(form).encode()
        headers.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif data is not None:
        body=json.dumps(data).encode()
        headers.setdefault("Content-Type","application/json")
    req=urllib.request.Request(url,data=body,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=timeout) as resp:
            raw=resp.read(4_000_001)
            if len(raw)>4_000_000:
                raise RuntimeError("Calendar provider response is too large")
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8","replace"))
    except urllib.error.HTTPError as exc:
        detail=exc.read(8192).decode("utf-8","replace")
        raise RuntimeError(f"Calendar provider HTTP {exc.code}: {detail[:1200]}") from exc

def _calendar_refresh_token(c, integration):
    provider=integration["provider"]
    refresh=decrypt_secret(integration["refresh_token_enc"])
    client_secret=decrypt_secret(integration["client_secret_enc"])
    if not refresh:
        raise RuntimeError("Calendar connection requires authorization")
    if provider=="google":
        form={"client_id":integration["client_id"],"client_secret":client_secret,"refresh_token":refresh,"grant_type":"refresh_token"}
        token=_calendar_http_json("https://oauth2.googleapis.com/token",method="POST",form=form)
    else:
        form={"client_id":integration["client_id"],"client_secret":client_secret,"refresh_token":refresh,"grant_type":"refresh_token","scope":MICROSOFT_CALENDAR_SCOPE}
        token=_calendar_http_json("https://login.microsoftonline.com/common/oauth2/v2.0/token",method="POST",form=form)
    access=token.get("access_token")
    if not access:
        raise RuntimeError("Calendar provider did not return an access token")
    expires=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=max(60,int(token.get("expires_in",3600))))
    new_refresh=token.get("refresh_token") or refresh
    c.execute("""UPDATE calendar_integrations SET access_token_enc=?,refresh_token_enc=?,token_expires_at=?,last_status='connected',last_error='',updated_at=? WHERE id=?""",
              (encrypt_secret(access),encrypt_secret(new_refresh),expires.isoformat(),now(),integration["id"]))
    return access

def _calendar_access_token(c, integration):
    token=decrypt_secret(integration["access_token_enc"])
    expires=integration["token_expires_at"]
    valid=False
    if token and expires:
        try:
            exp=dt.datetime.fromisoformat(expires)
            if exp.tzinfo is None: exp=exp.replace(tzinfo=dt.timezone.utc)
            valid=exp > dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=90)
        except Exception:
            valid=False
    return token if valid else _calendar_refresh_token(c,integration)

def _calendar_google_event_payload(req: CalendarEventRequest):
    start=_calendar_parse_iso(req.start_at,"start time")
    end=_calendar_parse_iso(req.end_at,"end time")
    payload={"summary":req.title.strip(),"description":req.description.strip()[:4000],"location":req.location.strip()[:300]}
    if req.all_day:
        payload["start"]={"date":start.date().isoformat()}
        payload["end"]={"date":max(end.date(),start.date()+dt.timedelta(days=1)).isoformat()}
    else:
        payload["start"]={"dateTime":start.isoformat()}
        payload["end"]={"dateTime":end.isoformat()}
    return payload

def _calendar_ms_dt(value: str):
    parsed=_calendar_parse_iso(value,"calendar time").astimezone(dt.timezone.utc).replace(tzinfo=None)
    return parsed.isoformat(timespec="seconds")

def _calendar_ms_event_payload(req: CalendarEventRequest):
    payload={
        "subject":req.title.strip(),
        "body":{"contentType":"text","content":req.description.strip()[:4000]},
        "location":{"displayName":req.location.strip()[:300]},
        "start":{"dateTime":_calendar_ms_dt(req.start_at),"timeZone":"UTC"},
        "end":{"dateTime":_calendar_ms_dt(req.end_at),"timeZone":"UTC"},
        "isAllDay":bool(req.all_day),
    }
    return payload

def _calendar_remote_base(integration):
    remote=(integration["remote_calendar_id"] or "").strip()
    if integration["provider"]=="google":
        cid=remote or "primary"
        return f"https://www.googleapis.com/calendar/v3/calendars/{urllib.parse.quote(cid,safe='')}/events"
    if remote and remote!="default":
        return f"https://graph.microsoft.com/v1.0/me/calendars/{urllib.parse.quote(remote,safe='')}/events"
    return "https://graph.microsoft.com/v1.0/me/events"

def _calendar_remote_create(c, integration, req: CalendarEventRequest):
    token=_calendar_access_token(c,integration)
    headers={"Authorization":f"Bearer {token}"}
    if integration["provider"]=="google":
        result=_calendar_http_json(_calendar_remote_base(integration),method="POST",headers=headers,data=_calendar_google_event_payload(req))
        return result.get("id")
    result=_calendar_http_json(_calendar_remote_base(integration),method="POST",headers=headers,data=_calendar_ms_event_payload(req))
    return result.get("id")

def _calendar_remote_update(c, integration, remote_id: str, req: CalendarEventRequest):
    token=_calendar_access_token(c,integration)
    headers={"Authorization":f"Bearer {token}"}
    url=_calendar_remote_base(integration)+"/"+urllib.parse.quote(remote_id,safe="")
    payload=_calendar_google_event_payload(req) if integration["provider"]=="google" else _calendar_ms_event_payload(req)
    _calendar_http_json(url,method="PATCH",headers=headers,data=payload)

def _calendar_remote_delete(c, integration, remote_id: str):
    token=_calendar_access_token(c,integration)
    headers={"Authorization":f"Bearer {token}"}
    url=_calendar_remote_base(integration)+"/"+urllib.parse.quote(remote_id,safe="")
    req=urllib.request.Request(url,headers=headers,method="DELETE")
    try:
        with urllib.request.urlopen(req,timeout=15):
            return
    except urllib.error.HTTPError as exc:
        if exc.code==404:
            return
        detail=exc.read(4096).decode("utf-8","replace")
        raise RuntimeError(f"Calendar provider HTTP {exc.code}: {detail[:1000]}") from exc

def _calendar_google_to_local(item):
    start=item.get("start") or {}; end=item.get("end") or {}
    all_day="date" in start
    if all_day:
        start_at=dt.datetime.fromisoformat(start["date"]).replace(tzinfo=dt.timezone.utc).isoformat()
        end_at=dt.datetime.fromisoformat(end.get("date") or start["date"]).replace(tzinfo=dt.timezone.utc).isoformat()
    else:
        start_at=(start.get("dateTime") or "").replace("Z","+00:00")
        end_at=(end.get("dateTime") or start.get("dateTime") or "").replace("Z","+00:00")
    return {
        "uid":item.get("id"),"title":item.get("summary") or "(Untitled)",
        "description":item.get("description") or "","location":item.get("location") or "",
        "start_at":start_at,"end_at":end_at,"all_day":1 if all_day else 0,
    }

def _calendar_ms_to_local(item):
    start=(item.get("start") or {}).get("dateTime") or ""
    end=(item.get("end") or {}).get("dateTime") or start
    def utc_iso(v):
        if not v: return now()
        parsed=dt.datetime.fromisoformat(v.replace("Z","+00:00"))
        if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat()
    body=item.get("body") or {}
    location=item.get("location") or {}
    return {
        "uid":item.get("id"),"title":item.get("subject") or "(Untitled)",
        "description":body.get("content") or "","location":location.get("displayName") or "",
        "start_at":utc_iso(start),"end_at":utc_iso(end),"all_day":1 if item.get("isAllDay") else 0,
    }

def _sync_calendar_oauth(c, integration):
    token=_calendar_access_token(c,integration)
    headers={"Authorization":f"Bearer {token}"}
    start=dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=90)
    end=dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=365)
    if integration["provider"]=="google":
        cid=(integration["remote_calendar_id"] or "primary").strip() or "primary"
        query=urllib.parse.urlencode({"timeMin":start.isoformat().replace("+00:00","Z"),"timeMax":end.isoformat().replace("+00:00","Z"),"singleEvents":"true","maxResults":"2500"})
        url=f"https://www.googleapis.com/calendar/v3/calendars/{urllib.parse.quote(cid,safe='')}/events?{query}"
        data=_calendar_http_json(url,headers=headers)
        items=data.get("items") or []
        convert=_calendar_google_to_local
    else:
        remote=(integration["remote_calendar_id"] or "").strip()
        base=f"https://graph.microsoft.com/v1.0/me/calendars/{urllib.parse.quote(remote,safe='')}/calendarView" if remote and remote!="default" else "https://graph.microsoft.com/v1.0/me/calendarView"
        query=urllib.parse.urlencode({"startDateTime":start.isoformat(),"endDateTime":end.isoformat(),"$top":"1000"})
        data=_calendar_http_json(base+"?"+query,headers=headers)
        items=data.get("value") or []
        convert=_calendar_ms_to_local
    source=f"calendar:{integration['id']}"
    seen=[];ts=now()
    for item in items[:2500]:
        event=convert(item)
        if not event["uid"] or not event["start_at"]:
            continue
        seen.append(event["uid"])
        c.execute("""INSERT INTO calendar_events(title,description,location,start_at,end_at,all_day,color,source,external_uid,external_readonly,created_by,created_at,updated_at)
                     VALUES(?,?,?,?,?,?,'purple',?,?,0,'external',?,?)
                     ON CONFLICT(source,external_uid) DO UPDATE SET
                       title=excluded.title,description=excluded.description,location=excluded.location,start_at=excluded.start_at,end_at=excluded.end_at,
                       all_day=excluded.all_day,external_readonly=0,updated_at=excluded.updated_at""",
                  (event["title"][:160],event["description"][:4000],event["location"][:300],event["start_at"],event["end_at"],event["all_day"],source,event["uid"],ts,ts))
    if seen:
        placeholders=",".join("?" for _ in seen)
        c.execute(f"""DELETE FROM calendar_events WHERE source=? AND start_at<=? AND end_at>=? AND external_uid NOT IN ({placeholders})""",
                  [source,end.isoformat(),start.isoformat(),*seen])
    c.execute("UPDATE calendar_integrations SET last_sync_at=?,last_status='connected',last_error='',updated_at=? WHERE id=?",(ts,ts,integration["id"]))
    return len(seen)

def _ics_unfold(text: str) -> list[str]:
    lines=text.replace("\r\n","\n").replace("\r","\n").split("\n")
    out=[]
    for line in lines:
        if line.startswith((" ","\t")) and out:
            out[-1]+=line[1:]
        else:
            out.append(line)
    return out

def _ics_value(lines: list[str], key: str) -> str:
    prefix=key.upper()
    for line in lines:
        left,sep,right=line.partition(":")
        if sep and left.split(";",1)[0].upper()==prefix:
            return right.strip()
    return ""

def _ics_dt(value: str) -> str:
    v=value.strip()
    if re.fullmatch(r"\d{8}",v):
        return dt.datetime.strptime(v,"%Y%m%d").replace(tzinfo=dt.timezone.utc).isoformat()
    if v.endswith("Z"):
        for fmt in ("%Y%m%dT%H%M%SZ","%Y%m%dT%H%MZ"):
            try: return dt.datetime.strptime(v,fmt).replace(tzinfo=dt.timezone.utc).isoformat()
            except ValueError: pass
    for fmt in ("%Y%m%dT%H%M%S","%Y%m%dT%H%M"):
        try: return dt.datetime.strptime(v,fmt).replace(tzinfo=dt.timezone.utc).isoformat()
        except ValueError: pass
    raise ValueError("Unsupported ICS date")

def _sync_calendar_ics(c, integration):
    url=decrypt_secret(integration["ics_url_enc"])
    req=urllib.request.Request(url,headers={"User-Agent":"GODSEYE/Calendar"})
    with urllib.request.urlopen(req,timeout=12) as resp:
        raw=resp.read(2_000_001)
    if len(raw)>2_000_000:
        raise ValueError("Calendar feed is too large")
    lines=_ics_unfold(raw.decode("utf-8","replace"));blocks=[];current=None
    for line in lines:
        if line.upper()=="BEGIN:VEVENT": current=[]
        elif line.upper()=="END:VEVENT" and current is not None: blocks.append(current);current=None
        elif current is not None: current.append(line)
    source=f"calendar:{integration['id']}";seen=[];ts=now()
    for item in blocks[:2000]:
        uid=_ics_value(item,"UID") or secrets.token_hex(12)
        start_raw=_ics_value(item,"DTSTART")
        if not start_raw: continue
        try:
            start_at=_ics_dt(start_raw)
            end_raw=_ics_value(item,"DTEND")
            end_at=_ics_dt(end_raw) if end_raw else (dt.datetime.fromisoformat(start_at)+dt.timedelta(hours=1)).isoformat()
        except Exception:
            continue
        c.execute("""INSERT INTO calendar_events(title,description,location,start_at,end_at,all_day,color,source,external_uid,external_readonly,created_by,created_at,updated_at)
                     VALUES(?,?,?,?,?,?,'purple',?,?,1,'external',?,?)
                     ON CONFLICT(source,external_uid) DO UPDATE SET
                       title=excluded.title,description=excluded.description,location=excluded.location,start_at=excluded.start_at,end_at=excluded.end_at,
                       all_day=excluded.all_day,external_readonly=1,updated_at=excluded.updated_at""",
                  ((_ics_value(item,"SUMMARY") or "External calendar event")[:160],_ics_value(item,"DESCRIPTION")[:4000],_ics_value(item,"LOCATION")[:300],
                   start_at,end_at,1 if re.fullmatch(r"\d{8}",start_raw.strip()) else 0,source,uid,ts,ts))
        seen.append(uid)
    if seen:
        placeholders=",".join("?" for _ in seen)
        c.execute(f"DELETE FROM calendar_events WHERE source=? AND external_uid NOT IN ({placeholders})",[source,*seen])
    c.execute("UPDATE calendar_integrations SET last_sync_at=?,last_status='ok',last_error='',updated_at=? WHERE id=?",(ts,ts,integration["id"]))
    return len(seen)

def _sync_calendar_integration(c, integration):
    if integration["auth_mode"]=="oauth":
        return _sync_calendar_oauth(c,integration)
    return _sync_calendar_ics(c,integration)

@app.get(f"{router_prefix}/calendar/events")
def calendar_events(start: str | None = None, end: str | None = None, user=Depends(get_current_user)):
    with db() as c:
        q="SELECT * FROM calendar_events WHERE 1=1";params=[]
        if start: q+=" AND end_at>=?";params.append(start)
        if end: q+=" AND start_at<=?";params.append(end)
        q+=" ORDER BY start_at,id"
        rows=c.execute(q,params).fetchall()
    return [_calendar_event_row(r) for r in rows]

@app.post(f"{router_prefix}/calendar/events")
def calendar_event_create(req: CalendarEventRequest, request: Request, user=Depends(require_admin)):
    title,_,_=_calendar_validate_event(req);ts=now()
    with db() as c:
        source="local";remote_id=None
        if req.calendar_integration_id:
            integration=c.execute("SELECT * FROM calendar_integrations WHERE id=?",(req.calendar_integration_id,)).fetchone()
            if not integration or integration["auth_mode"]!="oauth":
                raise HTTPException(409,"Two-way calendar connection is required to create this event remotely")
            remote_id=_calendar_remote_create(c,integration,req)
            if not remote_id: raise HTTPException(502,"Calendar provider did not return an event ID")
            source=f"calendar:{integration['id']}"
        cur=c.execute("""INSERT INTO calendar_events(title,description,location,start_at,end_at,all_day,color,source,external_uid,external_readonly,created_by,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,0,?,?,?)""",
                      (title,req.description.strip()[:4000],req.location.strip()[:300],req.start_at,req.end_at,1 if req.all_day else 0,req.color,source,remote_id,user["username"],ts,ts))
        event_id=cur.lastrowid
        audit(c,user["username"],"calendar_event_created",str(event_id),json.dumps({"title":title,"source":source,"start_at":req.start_at}),client_ip(request))
        row=c.execute("SELECT * FROM calendar_events WHERE id=?",(event_id,)).fetchone()
    return _calendar_event_row(row)

@app.put(f"{router_prefix}/calendar/events/{{event_id}}")
def calendar_event_update(event_id: int, req: CalendarEventRequest, request: Request, user=Depends(require_admin)):
    title,_,_=_calendar_validate_event(req)
    with db() as c:
        existing=c.execute("SELECT * FROM calendar_events WHERE id=?",(event_id,)).fetchone()
        if not existing: raise HTTPException(404,"Calendar event not found")
        if existing["external_readonly"]: raise HTTPException(409,"ICS subscription events are read-only")
        if existing["source"].startswith("calendar:") and existing["external_uid"]:
            integration_id=int(existing["source"].split(":",1)[1])
            integration=c.execute("SELECT * FROM calendar_integrations WHERE id=?",(integration_id,)).fetchone()
            if not integration or integration["auth_mode"]!="oauth":
                raise HTTPException(409,"Two-way calendar connection is unavailable")
            _calendar_remote_update(c,integration,existing["external_uid"],req)
        c.execute("""UPDATE calendar_events SET title=?,description=?,location=?,start_at=?,end_at=?,all_day=?,color=?,updated_at=? WHERE id=?""",
                  (title,req.description.strip()[:4000],req.location.strip()[:300],req.start_at,req.end_at,1 if req.all_day else 0,req.color,now(),event_id))
        if existing["source"]=="ticket" and str(existing["external_uid"] or "").isdigit():
            c.execute("UPDATE tickets SET due_at=?,updated_at=? WHERE id=?",(req.end_at,now(),int(existing["external_uid"])))
        audit(c,user["username"],"calendar_event_updated",str(event_id),json.dumps({"title":title,"source":existing["source"],"start_at":req.start_at}),client_ip(request))
        row=c.execute("SELECT * FROM calendar_events WHERE id=?",(event_id,)).fetchone()
    return _calendar_event_row(row)

@app.delete(f"{router_prefix}/calendar/events/{{event_id}}")
def calendar_event_delete(event_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        existing=c.execute("SELECT * FROM calendar_events WHERE id=?",(event_id,)).fetchone()
        if not existing: raise HTTPException(404,"Calendar event not found")
        if existing["external_readonly"]: raise HTTPException(409,"ICS subscription events are read-only")
        if existing["source"].startswith("calendar:") and existing["external_uid"]:
            integration_id=int(existing["source"].split(":",1)[1])
            integration=c.execute("SELECT * FROM calendar_integrations WHERE id=?",(integration_id,)).fetchone()
            if integration and integration["auth_mode"]=="oauth":
                _calendar_remote_delete(c,integration,existing["external_uid"])
        if existing["source"]=="ticket" and str(existing["external_uid"] or "").isdigit():
            c.execute("UPDATE tickets SET calendar_event_id=NULL,due_at=NULL,updated_at=? WHERE id=?",(now(),int(existing["external_uid"])))
        c.execute("DELETE FROM calendar_events WHERE id=?",(event_id,))
        audit(c,user["username"],"calendar_event_deleted",str(event_id),json.dumps({"title":existing["title"],"source":existing["source"]}),client_ip(request))
    return {"ok":True}

@app.get(f"{router_prefix}/calendar/integrations")
def calendar_integrations(user=Depends(get_current_user)):
    with db() as c:
        rows=c.execute("""SELECT id,provider,name,account_email,calendar_name,auth_mode,remote_calendar_id,enabled,sync_interval_minutes,last_sync_at,last_status,last_error,created_at,updated_at,
                         CASE WHEN ics_url_enc!='' THEN 1 ELSE 0 END AS has_subscription_url,
                         CASE WHEN refresh_token_enc!='' THEN 1 ELSE 0 END AS connected
                         FROM calendar_integrations ORDER BY name""").fetchall()
    return [dict(r) for r in rows]

def _validate_calendar_subscription_url(provider: str, url: str):
    parsed=urllib.parse.urlparse(url)
    if parsed.scheme!="https" or not parsed.hostname:
        raise HTTPException(400,"Calendar subscription URL must use HTTPS")
    host=parsed.hostname.lower().rstrip(".")
    allowed={"google":("calendar.google.com","googleusercontent.com"),
             "microsoft365":("outlook.office365.com","outlook.live.com","outlook.office.com","office.com")}.get(provider,())
    if not any(host==d or host.endswith("."+d) for d in allowed):
        raise HTTPException(400,"Calendar subscription URL does not match the selected provider")

@app.post(f"{router_prefix}/calendar/integrations")
def calendar_integration_create(req: CalendarIntegrationRequest, request: Request, user=Depends(require_admin)):
    provider=req.provider.strip().lower()
    if provider not in {"google","microsoft365"}: raise HTTPException(400,"Provider must be google or microsoft365")
    mode=req.auth_mode.strip().lower()
    if mode not in {"oauth","ics"}: raise HTTPException(400,"Authentication mode must be oauth or ics")
    name=req.name.strip()
    if not name: raise HTTPException(400,"Integration name is required")
    ics_enc=client_secret_enc=""
    status="not_synced"
    if mode=="ics":
        if not req.ics_url.strip(): raise HTTPException(400,"Calendar subscription (ICS) URL is required")
        _validate_calendar_subscription_url(provider,req.ics_url.strip())
        ics_enc=encrypt_secret(req.ics_url.strip())
    else:
        if not req.client_id.strip() or not req.client_secret.strip():
            raise HTTPException(400,"OAuth client ID and client secret are required")
        client_secret_enc=encrypt_secret(req.client_secret.strip())
        status="needs_authorization"
    remote=req.remote_calendar_id.strip() or ("primary" if provider=="google" else "default")
    ts=now()
    with db() as c:
        cur=c.execute("""INSERT INTO calendar_integrations(provider,name,account_email,calendar_name,auth_mode,remote_calendar_id,ics_url_enc,client_id,client_secret_enc,
                         enabled,sync_interval_minutes,last_status,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (provider,name,req.account_email.strip()[:254],req.calendar_name.strip()[:200],mode,remote,ics_enc,req.client_id.strip()[:500],client_secret_enc,
                       1 if req.enabled else 0,max(5,min(req.sync_interval_minutes,1440)),status,ts,ts))
        iid=cur.lastrowid
        audit(c,user["username"],"calendar_integration_created",str(iid),json.dumps({"provider":provider,"name":name,"auth_mode":mode}),client_ip(request))
    return {"ok":True,"id":iid,"auth_mode":mode,"needs_authorization":mode=="oauth"}

@app.post(f"{router_prefix}/calendar/integrations/{{integration_id}}/oauth/start")
def calendar_oauth_start(integration_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        row=c.execute("SELECT * FROM calendar_integrations WHERE id=?",(integration_id,)).fetchone()
        if not row or row["auth_mode"]!="oauth": raise HTTPException(404,"OAuth calendar integration not found")
        state=secrets.token_urlsafe(32)
        public_base=os.environ.get("GODSEYE_PUBLIC_URL","").strip().rstrip("/") or str(request.base_url).rstrip("/")
        redirect_uri=f"{public_base}{router_prefix}/calendar/oauth/{row['provider']}/callback"
        expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=10)).isoformat()
        c.execute("DELETE FROM calendar_oauth_states WHERE expires_at<?",(now(),))
        c.execute("INSERT INTO calendar_oauth_states(state,integration_id,provider,redirect_uri,created_by,expires_at) VALUES(?,?,?,?,?,?)",
                  (state,integration_id,row["provider"],redirect_uri,user["username"],expires))
    if row["provider"]=="google":
        query=urllib.parse.urlencode({"client_id":row["client_id"],"redirect_uri":redirect_uri,"response_type":"code","scope":GOOGLE_CALENDAR_SCOPE,
                                     "access_type":"offline","prompt":"consent","state":state})
        auth_url="https://accounts.google.com/o/oauth2/v2/auth?"+query
    else:
        query=urllib.parse.urlencode({"client_id":row["client_id"],"redirect_uri":redirect_uri,"response_type":"code","response_mode":"query",
                                     "scope":MICROSOFT_CALENDAR_SCOPE,"state":state})
        auth_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"+query
    return {"authorization_url":auth_url}

@app.get(f"{router_prefix}/calendar/oauth/{{provider}}/callback")
def calendar_oauth_callback(provider: str, state: str, code: str | None = None, error: str | None = None):
    with db() as c:
        saved=c.execute("SELECT * FROM calendar_oauth_states WHERE state=? AND provider=?",(state,provider)).fetchone()
        if not saved: return HTMLResponse("<h2>Calendar authorization failed</h2><p>Invalid or expired OAuth state.</p>",status_code=400)
        c.execute("DELETE FROM calendar_oauth_states WHERE state=?",(state,))
        if saved["expires_at"]<now(): return HTMLResponse("<h2>Calendar authorization failed</h2><p>The authorization request expired.</p>",status_code=400)
        if error or not code: return HTMLResponse(f"<h2>Calendar authorization was not completed</h2><p>{error or 'No authorization code was returned.'}</p>",status_code=400)
        row=c.execute("SELECT * FROM calendar_integrations WHERE id=?",(saved["integration_id"],)).fetchone()
        secret=decrypt_secret(row["client_secret_enc"])
        if provider=="google":
            token=_calendar_http_json("https://oauth2.googleapis.com/token",method="POST",form={"client_id":row["client_id"],"client_secret":secret,"code":code,
                                      "grant_type":"authorization_code","redirect_uri":saved["redirect_uri"]})
        else:
            token=_calendar_http_json("https://login.microsoftonline.com/common/oauth2/v2.0/token",method="POST",form={"client_id":row["client_id"],"client_secret":secret,
                                      "code":code,"grant_type":"authorization_code","redirect_uri":saved["redirect_uri"],"scope":MICROSOFT_CALENDAR_SCOPE})
        access=token.get("access_token");refresh=token.get("refresh_token")
        if not access or not refresh: return HTMLResponse("<h2>Calendar authorization failed</h2><p>The provider did not return reusable credentials.</p>",status_code=502)
        expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=max(60,int(token.get("expires_in",3600))))).isoformat()
        c.execute("""UPDATE calendar_integrations SET access_token_enc=?,refresh_token_enc=?,token_expires_at=?,last_status='connected',last_error='',updated_at=? WHERE id=?""",
                  (encrypt_secret(access),encrypt_secret(refresh),expires,now(),row["id"]))
        audit(c,saved["created_by"],"calendar_oauth_connected",str(row["id"]),json.dumps({"provider":provider}),None)
        try: _sync_calendar_oauth(c,c.execute("SELECT * FROM calendar_integrations WHERE id=?",(row["id"],)).fetchone())
        except Exception as exc:
            c.execute("UPDATE calendar_integrations SET last_error=? WHERE id=?",(str(exc)[:500],row["id"]))
    safe_provider="Google Calendar" if provider=="google" else "Microsoft 365 Calendar"
    html="<!doctype html><html><body style=\"font-family:system-ui;background:#0b1119;color:#fff;padding:40px\"><h2>"+safe_provider+" connected</h2><p>You can close this window and return to GODSEYE.</p><script>if(window.opener)window.opener.postMessage({type:'godseye-calendar-connected'},window.location.origin);setTimeout(()=>window.close(),900);</script></body></html>"
    return HTMLResponse(html)

@app.post(f"{router_prefix}/calendar/integrations/{{integration_id}}/sync")
def calendar_integration_sync(integration_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        integration=c.execute("SELECT * FROM calendar_integrations WHERE id=?",(integration_id,)).fetchone()
        if not integration: raise HTTPException(404,"Calendar integration not found")
        try:
            imported=_sync_calendar_integration(c,integration)
            audit(c,user["username"],"calendar_integration_synced",str(integration_id),json.dumps({"imported":imported,"auth_mode":integration["auth_mode"]}),client_ip(request))
            return {"ok":True,"imported":imported}
        except Exception as exc:
            ts=now()
            c.execute("UPDATE calendar_integrations SET last_sync_at=?,last_status='error',last_error=?,updated_at=? WHERE id=?",(ts,str(exc)[:500],ts,integration_id))
            raise HTTPException(502,f"Calendar sync failed: {exc}")

@app.delete(f"{router_prefix}/calendar/integrations/{{integration_id}}")
def calendar_integration_delete(integration_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        row=c.execute("SELECT * FROM calendar_integrations WHERE id=?",(integration_id,)).fetchone()
        if not row: raise HTTPException(404,"Calendar integration not found")
        source=f"calendar:{integration_id}"
        c.execute("DELETE FROM calendar_events WHERE source=?",(source,))
        c.execute("DELETE FROM calendar_integrations WHERE id=?",(integration_id,))
        c.execute("DELETE FROM calendar_oauth_states WHERE integration_id=?",(integration_id,))
        audit(c,user["username"],"calendar_integration_deleted",str(integration_id),json.dumps({"provider":row["provider"],"name":row["name"]}),client_ip(request))
    return {"ok":True}


# ---------------------------------------------------------------------------
# Email client
# ---------------------------------------------------------------------------

GMAIL_MAIL_SCOPE="https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send"
MICROSOFT_MAIL_SCOPE="offline_access User.Read Mail.ReadWrite Mail.Send"

class EmailIntegrationRequest(BaseModel):
    provider: str
    name: str
    account_email: str = ""
    client_id: str
    client_secret: str

class EmailAttachmentRequest(BaseModel):
    name: str
    content_type: str = "application/octet-stream"
    content_b64: str

class EmailComposeRequest(BaseModel):
    integration_id: int
    to: list[str] = []
    cc: list[str] = []
    bcc: list[str] = []
    subject: str = ""
    body: str = ""
    attachments: list[EmailAttachmentRequest] = []

class EmailMessageActionRequest(BaseModel):
    integration_id: int
    body: str = ""
    to: list[str] = []

class EmailMessageStateRequest(BaseModel):
    integration_id: int
    is_read: bool | None = None
    starred: bool | None = None

class EmailReportRequest(BaseModel):
    integration_id: int
    report_id: int
    to: list[str]
    cc: list[str] = []
    subject: str = ""
    body: str = ""
    format: str = "pdf"

def _email_integration_row(c, integration_id: int):
    row=c.execute("SELECT * FROM email_integrations WHERE id=? AND enabled=1",(integration_id,)).fetchone()
    if not row:
        raise HTTPException(404,"Email integration not found")
    return row

def _email_access_token(c, integration):
    token=decrypt_secret(integration["access_token_enc"])
    expires=integration["token_expires_at"]
    valid=False
    if token and expires:
        try:
            exp=dt.datetime.fromisoformat(expires)
            if exp.tzinfo is None: exp=exp.replace(tzinfo=dt.timezone.utc)
            valid=exp > dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=90)
        except Exception:
            valid=False
    if valid:
        return token
    refresh=decrypt_secret(integration["refresh_token_enc"])
    secret=decrypt_secret(integration["client_secret_enc"])
    if not refresh:
        raise HTTPException(409,"Email connection requires authorization")
    if integration["provider"]=="gmail":
        tok=_calendar_http_json("https://oauth2.googleapis.com/token",method="POST",form={
            "client_id":integration["client_id"],"client_secret":secret,"refresh_token":refresh,"grant_type":"refresh_token"})
    else:
        tok=_calendar_http_json("https://login.microsoftonline.com/common/oauth2/v2.0/token",method="POST",form={
            "client_id":integration["client_id"],"client_secret":secret,"refresh_token":refresh,"grant_type":"refresh_token","scope":MICROSOFT_MAIL_SCOPE})
    access=tok.get("access_token")
    if not access:
        raise HTTPException(502,"Email provider did not return an access token")
    new_refresh=tok.get("refresh_token") or refresh
    exp=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=max(60,int(tok.get("expires_in",3600))))
    c.execute("""UPDATE email_integrations SET access_token_enc=?,refresh_token_enc=?,token_expires_at=?,last_status='connected',last_error='',updated_at=? WHERE id=?""",
              (encrypt_secret(access),encrypt_secret(new_refresh),exp.isoformat(),now(),integration["id"]))
    return access

def _email_headers(integration, token):
    return {"Authorization":f"Bearer {token}","Accept":"application/json"}

def _gmail_decode(data: str) -> bytes:
    if not data: return b""
    pad="="*((4-len(data)%4)%4)
    return base64.urlsafe_b64decode((data+pad).encode())

def _mail_plain(text: str) -> str:
    if not text: return ""
    text=re.sub(r"(?is)<(script|style).*?>.*?</\1>","",text)
    text=re.sub(r"(?i)<br\s*/?>","\n",text)
    text=re.sub(r"(?i)</p\s*>","\n\n",text)
    text=re.sub(r"(?s)<[^>]+>","",text)
    text=text.replace("&nbsp;"," ").replace("&lt;","<").replace("&gt;",">").replace("&amp;","&")
    return re.sub(r"\n{3,}","\n\n",text).strip()

def _gmail_headers_map(msg):
    return {h.get("name","").lower():h.get("value","") for h in (msg.get("payload") or {}).get("headers",[])}

def _gmail_body(payload):
    if not payload: return ""
    mime=payload.get("mimeType","")
    data=(payload.get("body") or {}).get("data")
    if data and mime=="text/plain":
        return _gmail_decode(data).decode("utf-8","replace")
    plain="";html=""
    for part in payload.get("parts") or []:
        found=_gmail_body(part)
        if found:
            if part.get("mimeType")=="text/plain": plain=found
            elif not html: html=found
    if plain: return plain
    if data:
        raw=_gmail_decode(data).decode("utf-8","replace")
        return _mail_plain(raw) if mime=="text/html" else raw
    return _mail_plain(html)

def _gmail_attachments(payload):
    out=[]
    def walk(part):
        body=part.get("body") or {}
        name=part.get("filename") or ""
        if name and body.get("attachmentId"):
            out.append({"id":body["attachmentId"],"name":name,"content_type":part.get("mimeType") or "application/octet-stream","size":body.get("size") or 0})
        for child in part.get("parts") or []: walk(child)
    walk(payload or {})
    return out

def _gmail_message_normalize(msg, full=False):
    h=_gmail_headers_map(msg)
    labels=set(msg.get("labelIds") or [])
    out={
        "id":msg.get("id"),"thread_id":msg.get("threadId"),"subject":h.get("subject") or "(No subject)",
        "from":h.get("from") or "","to":h.get("to") or "","cc":h.get("cc") or "",
        "date":h.get("date") or "","snippet":msg.get("snippet") or "",
        "is_read":"UNREAD" not in labels,"starred":"STARRED" in labels,"has_attachments":bool(_gmail_attachments(msg.get("payload") or {})),
        "provider":"gmail",
    }
    if full:
        out["body"]=_gmail_body(msg.get("payload") or {})
        out["attachments"]=_gmail_attachments(msg.get("payload") or {})
        out["message_id_header"]=h.get("message-id") or ""
        out["references"]=h.get("references") or ""
    return out

def _email_addresses(values):
    clean=[]
    for v in values or []:
        v=(v or "").strip()
        if v and "@" in v and len(v)<=254: clean.append(v)
    return clean[:100]

def _build_mime(req: EmailComposeRequest, account_email="", reply_headers=None):
    msg=EmailMessage()
    msg["Date"]=formatdate(localtime=True)
    if account_email: msg["From"]=account_email
    msg["To"]=", ".join(_email_addresses(req.to))
    if req.cc: msg["Cc"]=", ".join(_email_addresses(req.cc))
    if req.bcc: msg["Bcc"]=", ".join(_email_addresses(req.bcc))
    msg["Subject"]=req.subject[:500]
    if reply_headers:
        if reply_headers.get("message_id"): msg["In-Reply-To"]=reply_headers["message_id"]
        refs=(reply_headers.get("references") or "").strip()
        mid=(reply_headers.get("message_id") or "").strip()
        if refs or mid: msg["References"]=" ".join(x for x in [refs,mid] if x)
    msg.set_content(req.body or "")
    total=0
    for a in req.attachments[:20]:
        try: raw=base64.b64decode(a.content_b64,validate=True)
        except Exception: raise HTTPException(400,f"Invalid attachment data for {a.name}")
        total+=len(raw)
        if total>18*1024*1024: raise HTTPException(413,"Attachments exceed the 18 MB GODSEYE compose limit")
        ctype=(a.content_type or mimetypes.guess_type(a.name)[0] or "application/octet-stream")
        maintype,_,subtype=ctype.partition("/")
        msg.add_attachment(raw,maintype=maintype or "application",subtype=subtype or "octet-stream",filename=Path(a.name).name[:200])
    return msg

def _gmail_send_or_draft(c, integration, req: EmailComposeRequest, draft=False, thread_id=None, reply_headers=None):
    token=_email_access_token(c,integration)
    mime=_build_mime(req,integration["account_email"],reply_headers)
    payload={"raw":base64.urlsafe_b64encode(mime.as_bytes()).decode().rstrip("=")}
    if thread_id: payload["threadId"]=thread_id
    headers=_email_headers(integration,token)
    if draft:
        return _calendar_http_json("https://gmail.googleapis.com/gmail/v1/users/me/drafts",method="POST",headers=headers,data={"message":payload})
    return _calendar_http_json("https://gmail.googleapis.com/gmail/v1/users/me/messages/send",method="POST",headers=headers,data=payload)

def _ms_recipients(values):
    return [{"emailAddress":{"address":x}} for x in _email_addresses(values)]

def _ms_message_payload(req: EmailComposeRequest):
    attachments=[]
    total=0
    for a in req.attachments[:20]:
        try: raw=base64.b64decode(a.content_b64,validate=True)
        except Exception: raise HTTPException(400,f"Invalid attachment data for {a.name}")
        total+=len(raw)
        if total>3*1024*1024: raise HTTPException(413,"Microsoft direct-send attachments are limited to 3 MB in this GODSEYE build")
        attachments.append({"@odata.type":"#microsoft.graph.fileAttachment","name":Path(a.name).name[:200],"contentType":a.content_type or "application/octet-stream","contentBytes":base64.b64encode(raw).decode()})
    msg={"subject":req.subject[:500],"body":{"contentType":"Text","content":req.body or ""},"toRecipients":_ms_recipients(req.to),"ccRecipients":_ms_recipients(req.cc),"bccRecipients":_ms_recipients(req.bcc)}
    if attachments: msg["attachments"]=attachments
    return msg

def _email_send_compose(c, integration, req: EmailComposeRequest, draft=False):
    token=_email_access_token(c,integration);headers=_email_headers(integration,token)
    if integration["provider"]=="gmail":
        return _gmail_send_or_draft(c,integration,req,draft=draft)
    if draft:
        return _calendar_http_json("https://graph.microsoft.com/v1.0/me/messages",method="POST",headers=headers,data=_ms_message_payload(req))
    return _calendar_http_json("https://graph.microsoft.com/v1.0/me/sendMail",method="POST",headers=headers,data={"message":_ms_message_payload(req),"saveToSentItems":True})

@app.get(f"{router_prefix}/email/integrations")
def email_integrations(user=Depends(require_permission("operate"))):
    with db() as c:
        rows=c.execute("""SELECT id,provider,name,account_email,enabled,last_status,last_error,created_at,updated_at,
                         CASE WHEN refresh_token_enc<>'' THEN 1 ELSE 0 END AS connected
                         FROM email_integrations ORDER BY name""").fetchall()
    return [dict(r) for r in rows]

@app.post(f"{router_prefix}/email/integrations")
def email_integration_create(req: EmailIntegrationRequest, request: Request, user=Depends(require_admin)):
    provider=req.provider.strip().lower()
    if provider not in {"gmail","microsoft365"}: raise HTTPException(400,"Provider must be gmail or microsoft365")
    if not req.name.strip() or not req.client_id.strip() or not req.client_secret.strip():
        raise HTTPException(400,"Name, OAuth client ID, and client secret are required")
    ts=now()
    with db() as c:
        iid=c.execute("""INSERT INTO email_integrations(provider,name,account_email,client_id,client_secret_enc,enabled,last_status,created_at,updated_at)
                         VALUES(?,?,?,?,?,1,'needs_authorization',?,?)""",
                      (provider,req.name.strip()[:160],req.account_email.strip()[:254],req.client_id.strip()[:500],encrypt_secret(req.client_secret.strip()),ts,ts)).lastrowid
        audit(c,user["username"],"email_integration_created",str(iid),json.dumps({"provider":provider,"name":req.name.strip()}),client_ip(request))
    return {"ok":True,"id":iid,"needs_authorization":True}

@app.post(f"{router_prefix}/email/integrations/{{integration_id}}/oauth/start")
def email_oauth_start(integration_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        row=_email_integration_row(c,integration_id)
        state=secrets.token_urlsafe(32)
        base=os.environ.get("GODSEYE_PUBLIC_URL","").strip().rstrip("/") or str(request.base_url).rstrip("/")
        redirect=f"{base}{router_prefix}/email/oauth/{row['provider']}/callback"
        expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=10)).isoformat()
        c.execute("DELETE FROM email_oauth_states WHERE expires_at<?",(now(),))
        c.execute("INSERT INTO email_oauth_states(state,integration_id,provider,redirect_uri,created_by,expires_at) VALUES(?,?,?,?,?,?)",
                  (state,integration_id,row["provider"],redirect,user["username"],expires))
    if row["provider"]=="gmail":
        q=urllib.parse.urlencode({"client_id":row["client_id"],"redirect_uri":redirect,"response_type":"code","scope":GMAIL_MAIL_SCOPE,"access_type":"offline","prompt":"consent","state":state})
        url="https://accounts.google.com/o/oauth2/v2/auth?"+q
    else:
        q=urllib.parse.urlencode({"client_id":row["client_id"],"redirect_uri":redirect,"response_type":"code","response_mode":"query","scope":MICROSOFT_MAIL_SCOPE,"state":state})
        url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"+q
    return {"authorization_url":url}

@app.get(f"{router_prefix}/email/oauth/{{provider}}/callback")
def email_oauth_callback(provider: str, state: str, code: str | None=None, error: str | None=None):
    with db() as c:
        saved=c.execute("SELECT * FROM email_oauth_states WHERE state=? AND provider=?",(state,provider)).fetchone()
        if not saved: return HTMLResponse("<h2>Email authorization failed</h2><p>Invalid or expired OAuth state.</p>",status_code=400)
        c.execute("DELETE FROM email_oauth_states WHERE state=?",(state,))
        if saved["expires_at"]<now(): return HTMLResponse("<h2>Email authorization failed</h2><p>The request expired.</p>",status_code=400)
        if error or not code: return HTMLResponse("<h2>Email authorization was not completed</h2>",status_code=400)
        row=c.execute("SELECT * FROM email_integrations WHERE id=?",(saved["integration_id"],)).fetchone()
        secret=decrypt_secret(row["client_secret_enc"])
        if provider=="gmail":
            tok=_calendar_http_json("https://oauth2.googleapis.com/token",method="POST",form={"client_id":row["client_id"],"client_secret":secret,"code":code,"grant_type":"authorization_code","redirect_uri":saved["redirect_uri"]})
        else:
            tok=_calendar_http_json("https://login.microsoftonline.com/common/oauth2/v2.0/token",method="POST",form={"client_id":row["client_id"],"client_secret":secret,"code":code,"grant_type":"authorization_code","redirect_uri":saved["redirect_uri"],"scope":MICROSOFT_MAIL_SCOPE})
        access=tok.get("access_token");refresh=tok.get("refresh_token")
        if not access or not refresh: return HTMLResponse("<h2>Email authorization failed</h2><p>The provider did not return reusable credentials.</p>",status_code=502)
        exp=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=max(60,int(tok.get("expires_in",3600))))).isoformat()
        c.execute("""UPDATE email_integrations SET access_token_enc=?,refresh_token_enc=?,token_expires_at=?,last_status='connected',last_error='',updated_at=? WHERE id=?""",
                  (encrypt_secret(access),encrypt_secret(refresh),exp,now(),row["id"]))
        audit(c,saved["created_by"],"email_oauth_connected",str(row["id"]),json.dumps({"provider":provider}),None)
    name="Gmail" if provider=="gmail" else "Microsoft 365"
    html="<!doctype html><html><body style=\"font-family:system-ui;background:#0b1119;color:#fff;padding:40px\"><h2>"+name+" connected</h2><p>You can close this window and return to GODSEYE.</p><script>if(window.opener)window.opener.postMessage({type:'godseye-email-connected'},window.location.origin);setTimeout(()=>window.close(),900);</script></body></html>"
    return HTMLResponse(html)

@app.delete(f"{router_prefix}/email/integrations/{{integration_id}}")
def email_integration_delete(integration_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        row=c.execute("SELECT provider,name FROM email_integrations WHERE id=?",(integration_id,)).fetchone()
        if not row: raise HTTPException(404,"Email integration not found")
        c.execute("DELETE FROM email_oauth_states WHERE integration_id=?",(integration_id,))
        c.execute("DELETE FROM email_integrations WHERE id=?",(integration_id,))
        audit(c,user["username"],"email_integration_deleted",str(integration_id),json.dumps(dict(row)),client_ip(request))
    return {"ok":True}

@app.get(f"{router_prefix}/email/folders")
def email_folders(integration_id: int, user=Depends(require_permission("operate"))):
    with db() as c:
        integration=_email_integration_row(c,integration_id);token=_email_access_token(c,integration);headers=_email_headers(integration,token)
        if integration["provider"]=="gmail":
            data=_calendar_http_json("https://gmail.googleapis.com/gmail/v1/users/me/labels",headers=headers)
            wanted={"INBOX":"Inbox","SENT":"Sent","DRAFT":"Drafts","TRASH":"Trash","STARRED":"Starred","SPAM":"Spam"}
            out=[]
            for x in data.get("labels") or []:
                if x.get("id") in wanted:
                    out.append({"id":x["id"].lower(),"name":wanted[x["id"]],"unread":x.get("messagesUnread",0),"total":x.get("messagesTotal",0)})
            order={"inbox":0,"starred":1,"sent":2,"draft":3,"trash":4,"spam":5}
            return sorted(out,key=lambda x:order.get(x["id"],99))
        data=_calendar_http_json("https://graph.microsoft.com/v1.0/me/mailFolders?$top=100&$select=id,displayName,unreadItemCount,totalItemCount",headers=headers)
        norm=[]
        for x in data.get("value") or []:
            norm.append({"id":x.get("id"),"name":x.get("displayName"),"unread":x.get("unreadItemCount",0),"total":x.get("totalItemCount",0)})
        return norm

@app.get(f"{router_prefix}/email/messages")
def email_messages(integration_id: int, folder: str="inbox", q: str="", limit: int=40, user=Depends(require_permission("operate"))):
    limit=max(1,min(limit,60))
    with db() as c:
        integration=_email_integration_row(c,integration_id);token=_email_access_token(c,integration);headers=_email_headers(integration,token)
        if integration["provider"]=="gmail":
            label=folder.upper()
            if label=="DRAFTS": label="DRAFT"
            params={"maxResults":limit}
            if label not in {"ALL",""}: params["labelIds"]=label
            if q.strip(): params["q"]=q.strip()[:500]
            data=_calendar_http_json("https://gmail.googleapis.com/gmail/v1/users/me/messages?"+urllib.parse.urlencode(params),headers=headers)
            out=[]
            for item in (data.get("messages") or [])[:limit]:
                msg=_calendar_http_json(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{urllib.parse.quote(item['id'])}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Cc&metadataHeaders=Date",headers=headers)
                out.append(_gmail_message_normalize(msg))
            return {"messages":out,"next_page_token":data.get("nextPageToken")}
        if folder in {"inbox","sentitems","drafts","deleteditems","archive","junkemail"}:
            base=f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages"
        else:
            base=f"https://graph.microsoft.com/v1.0/me/mailFolders/{urllib.parse.quote(folder,safe='')}/messages"
        params={"$top":limit,"$select":"id,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,hasAttachments,bodyPreview,flag"}
        if q.strip(): params["$search"]=f'"{q.strip()[:200]}"'
        else: params["$orderby"]="receivedDateTime desc"
        data=_calendar_http_json(base+"?"+urllib.parse.urlencode(params),headers={**headers,"ConsistencyLevel":"eventual"})
        out=[]
        for m in data.get("value") or []:
            out.append({"id":m.get("id"),"subject":m.get("subject") or "(No subject)","from":((m.get("from") or {}).get("emailAddress") or {}).get("address",""),
                        "to":", ".join((((x or {}).get("emailAddress") or {}).get("address","")) for x in m.get("toRecipients") or []),
                        "cc":", ".join((((x or {}).get("emailAddress") or {}).get("address","")) for x in m.get("ccRecipients") or []),
                        "date":m.get("receivedDateTime") or "","snippet":m.get("bodyPreview") or "","is_read":bool(m.get("isRead")),
                        "starred":((m.get("flag") or {}).get("flagStatus")=="flagged"),"has_attachments":bool(m.get("hasAttachments")),"provider":"microsoft365"})
        return {"messages":out,"next_link":data.get("@odata.nextLink")}

@app.get(f"{router_prefix}/email/messages/{{message_id}}")
def email_message_get(message_id: str, integration_id: int, user=Depends(require_permission("operate"))):
    with db() as c:
        integration=_email_integration_row(c,integration_id);token=_email_access_token(c,integration);headers=_email_headers(integration,token)
        mid=urllib.parse.quote(message_id,safe="")
        if integration["provider"]=="gmail":
            msg=_calendar_http_json(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}?format=full",headers=headers)
            return _gmail_message_normalize(msg,full=True)
        msg=_calendar_http_json(f"https://graph.microsoft.com/v1.0/me/messages/{mid}?$expand=attachments&$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,hasAttachments,body,bodyPreview,flag,internetMessageId",headers=headers)
        return {"id":msg.get("id"),"subject":msg.get("subject") or "(No subject)","from":((msg.get("from") or {}).get("emailAddress") or {}).get("address",""),
                "to":", ".join((((x or {}).get("emailAddress") or {}).get("address","")) for x in msg.get("toRecipients") or []),
                "cc":", ".join((((x or {}).get("emailAddress") or {}).get("address","")) for x in msg.get("ccRecipients") or []),
                "date":msg.get("receivedDateTime") or "","snippet":msg.get("bodyPreview") or "","body":_mail_plain((msg.get("body") or {}).get("content") or ""),
                "is_read":bool(msg.get("isRead")),"starred":((msg.get("flag") or {}).get("flagStatus")=="flagged"),"has_attachments":bool(msg.get("hasAttachments")),
                "attachments":[{"id":a.get("id"),"name":a.get("name"),"content_type":a.get("contentType"),"size":a.get("size",0)} for a in msg.get("attachments") or [] if a.get("@odata.type")=="#microsoft.graph.fileAttachment"],
                "provider":"microsoft365","message_id_header":msg.get("internetMessageId") or ""}

@app.post(f"{router_prefix}/email/send")
def email_send(req: EmailComposeRequest, request: Request, user=Depends(require_permission("operate"))):
    if not _email_addresses(req.to): raise HTTPException(400,"At least one valid recipient is required")
    with db() as c:
        integration=_email_integration_row(c,req.integration_id)
        result=_email_send_compose(c,integration,req,draft=False)
        audit(c,user["username"],"email_sent",str(req.integration_id),json.dumps({"to":_email_addresses(req.to),"subject":req.subject[:200]}),client_ip(request))
    return {"ok":True,"provider_result":result}

@app.post(f"{router_prefix}/email/drafts")
def email_draft(req: EmailComposeRequest, request: Request, user=Depends(require_permission("operate"))):
    with db() as c:
        integration=_email_integration_row(c,req.integration_id)
        result=_email_send_compose(c,integration,req,draft=True)
        audit(c,user["username"],"email_draft_saved",str(req.integration_id),json.dumps({"subject":req.subject[:200]}),client_ip(request))
    return {"ok":True,"provider_result":result}

@app.post(f"{router_prefix}/email/messages/{{message_id}}/trash")
def email_message_trash(message_id: str, req: EmailMessageActionRequest, request: Request, user=Depends(require_permission("operate"))):
    with db() as c:
        integration=_email_integration_row(c,req.integration_id);token=_email_access_token(c,integration);headers=_email_headers(integration,token);mid=urllib.parse.quote(message_id,safe="")
        if integration["provider"]=="gmail":
            _calendar_http_json(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}/trash",method="POST",headers=headers,data={})
        else:
            try:
                request_obj=urllib.request.Request(f"https://graph.microsoft.com/v1.0/me/messages/{mid}",headers=headers,method="DELETE")
                with urllib.request.urlopen(request_obj,timeout=15): pass
            except urllib.error.HTTPError as exc:
                raise HTTPException(502,f"Microsoft mail delete failed: HTTP {exc.code}")
        audit(c,user["username"],"email_message_trashed",message_id,json.dumps({"integration_id":req.integration_id}),client_ip(request))
    return {"ok":True}

@app.post(f"{router_prefix}/email/messages/{{message_id}}/{{action}}")
def email_message_action(message_id: str, action: str, req: EmailMessageActionRequest, request: Request, user=Depends(require_permission("operate"))):
    if action not in {"reply","reply-all","forward"}: raise HTTPException(400,"Unsupported message action")
    with db() as c:
        integration=_email_integration_row(c,req.integration_id);token=_email_access_token(c,integration);headers=_email_headers(integration,token);mid=urllib.parse.quote(message_id,safe="")
        if integration["provider"]=="microsoft365":
            endpoint={"reply":"reply","reply-all":"replyAll","forward":"forward"}[action]
            payload={"comment":req.body or ""}
            if action=="forward":
                recipients=_ms_recipients(req.to)
                if not recipients: raise HTTPException(400,"Forward requires at least one recipient")
                payload["toRecipients"]=recipients
            _calendar_http_json(f"https://graph.microsoft.com/v1.0/me/messages/{mid}/{endpoint}",method="POST",headers=headers,data=payload)
        else:
            original=_calendar_http_json(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}?format=full",headers=headers)
            normalized=_gmail_message_normalize(original,full=True)
            if action=="reply":
                recipients=[normalized["from"]]
                subject=normalized["subject"] if normalized["subject"].lower().startswith("re:") else "Re: "+normalized["subject"]
            elif action=="reply-all":
                recipients=[normalized["from"]]+[x.strip() for x in normalized["to"].split(",") if x.strip()]
                subject=normalized["subject"] if normalized["subject"].lower().startswith("re:") else "Re: "+normalized["subject"]
            else:
                recipients=_email_addresses(req.to)
                if not recipients: raise HTTPException(400,"Forward requires at least one recipient")
                subject=normalized["subject"] if normalized["subject"].lower().startswith("fwd:") else "Fwd: "+normalized["subject"]
            action_body=req.body or ""
            if action=="forward":
                action_body += "\n\n---------- Forwarded message ----------\nFrom: "+normalized.get("from","")+"\nDate: "+normalized.get("date","")+"\nSubject: "+normalized.get("subject","")+"\nTo: "+normalized.get("to","")+"\n\n"+normalized.get("body","")
            compose=EmailComposeRequest(integration_id=req.integration_id,to=recipients,subject=subject,body=action_body,attachments=[])
            _gmail_send_or_draft(c,integration,compose,draft=False,thread_id=original.get("threadId") if action!="forward" else None,
                                 reply_headers={"message_id":normalized.get("message_id_header"),"references":normalized.get("references")} if action!="forward" else None)
        audit(c,user["username"],f"email_{action.replace('-','_')}",message_id,json.dumps({"integration_id":req.integration_id}),client_ip(request))
    return {"ok":True}

@app.post(f"{router_prefix}/email/messages/{{message_id}}/state")
def email_message_state(message_id: str, req: EmailMessageStateRequest, request: Request, user=Depends(require_permission("operate"))):
    with db() as c:
        integration=_email_integration_row(c,req.integration_id);token=_email_access_token(c,integration);headers=_email_headers(integration,token);mid=urllib.parse.quote(message_id,safe="")
        if integration["provider"]=="gmail":
            add=[];remove=[]
            if req.is_read is not None:
                (remove if req.is_read else add).append("UNREAD")
            if req.starred is not None:
                (add if req.starred else remove).append("STARRED")
            _calendar_http_json(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}/modify",method="POST",headers=headers,data={"addLabelIds":add,"removeLabelIds":remove})
        else:
            patch={}
            if req.is_read is not None: patch["isRead"]=req.is_read
            if req.starred is not None: patch["flag"]={"flagStatus":"flagged" if req.starred else "notFlagged"}
            if patch: _calendar_http_json(f"https://graph.microsoft.com/v1.0/me/messages/{mid}",method="PATCH",headers=headers,data=patch)
        audit(c,user["username"],"email_message_state_changed",message_id,json.dumps({"integration_id":req.integration_id,"is_read":req.is_read,"starred":req.starred}),client_ip(request))
    return {"ok":True}

@app.get(f"{router_prefix}/email/messages/{{message_id}}/attachments/{{attachment_id}}")
def email_attachment_download(message_id: str, attachment_id: str, integration_id: int, user=Depends(require_permission("operate"))):
    with db() as c:
        integration=_email_integration_row(c,integration_id);token=_email_access_token(c,integration);headers=_email_headers(integration,token)
        mid=urllib.parse.quote(message_id,safe="");aid=urllib.parse.quote(attachment_id,safe="")
        if integration["provider"]=="gmail":
            data=_calendar_http_json(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}/attachments/{aid}",headers=headers)
            raw=_gmail_decode(data.get("data") or "")
            name="attachment.bin";ctype="application/octet-stream"
            full=_calendar_http_json(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}?format=full",headers=headers)
            for a in _gmail_attachments((full.get("payload") or {})):
                if a["id"]==attachment_id: name=a["name"];ctype=a["content_type"];break
        else:
            data=_calendar_http_json(f"https://graph.microsoft.com/v1.0/me/messages/{mid}/attachments/{aid}",headers=headers)
            raw=base64.b64decode(data.get("contentBytes") or "")
            name=data.get("name") or "attachment.bin";ctype=data.get("contentType") or "application/octet-stream"
        safe_name=re.sub(r"[^A-Za-z0-9._ -]","_",Path(name).name)[:180] or "attachment.bin"
        return Response(content=raw,media_type=ctype,headers={"Content-Disposition":f'attachment; filename="{safe_name}"'})

@app.post(f"{router_prefix}/email/report")
def email_report(req: EmailReportRequest, request: Request, user=Depends(require_permission("reports.generate"))):
    fmt=req.format.lower()
    if fmt not in {"pdf","csv"}: raise HTTPException(400,"Report format must be pdf or csv")
    with db() as c:
        integration=_email_integration_row(c,req.integration_id)
        row=c.execute("SELECT * FROM generated_reports WHERE id=?",(req.report_id,)).fetchone()
        if not row: raise HTTPException(404,"Report not found")
        d=dict(row);d["summary"]=json.loads(d.get("summary_json") or "{}")
        raw=report_pdf_bytes(d) if fmt=="pdf" else report_csv_bytes(d)
        ctype="application/pdf" if fmt=="pdf" else "text/csv"
        subject=req.subject.strip() or f"GODSEYE Report: {row['title']}"
        compose=EmailComposeRequest(integration_id=req.integration_id,to=req.to,cc=req.cc,subject=subject,body=req.body or "Attached is a GODSEYE report.",
                                   attachments=[EmailAttachmentRequest(name=f"godseye-report-{req.report_id}.{fmt}",content_type=ctype,content_b64=base64.b64encode(raw).decode())])
        _email_send_compose(c,integration,compose,draft=False)
        audit(c,user["username"],"report_emailed",str(req.report_id),json.dumps({"integration_id":req.integration_id,"format":fmt,"to":req.to}),client_ip(request))
    return {"ok":True}

# ---------------------------------------------------------------------------
# GODSEYE Windows Agent
# ---------------------------------------------------------------------------

class WindowsAgentEnrollRequest(BaseModel):
    enrollment_token: str
    agent_uuid: str
    computer_name: str
    machine_guid: str = ""
    hostname: str = ""
    os_version: str = ""
    architecture: str = "x64"
    agent_version: str = ""

class WindowsAgentHeartbeatRequest(BaseModel):
    computer_name: str = ""
    hostname: str = ""
    os_version: str = ""
    architecture: str = "x64"
    agent_version: str = ""
    last_error: str = ""

class WindowsAgentEvent(BaseModel):
    computer_name: str = ""
    channel: str
    provider: str
    event_id: int
    level: str
    record_id: int = 0
    event_time: str = ""
    message: str = ""

class WindowsAgentEventBatch(BaseModel):
    events: list[WindowsAgentEvent]

class WindowsAgentRecheckResult(BaseModel):
    seen_again: bool
    details: str = ""
    checked_at: str = ""

class WindowsAgentCommandResult(BaseModel):
    ok: bool = True
    events: int = 0
    new_findings: int = 0
    details: str = ""
    completed_at: str = ""

class WindowsAgentConfigRequest(BaseModel):
    channels: list[str] = ["System", "Application"]
    poll_interval_seconds: int = 60
    enabled: bool = True

class WindowsAgentEnrollmentRequest(BaseModel):
    label: str = "Windows Agent"
    expires_minutes: int = 30

class WindowsRemoteStartRequest(BaseModel):
    agent_id: int

class WindowsRemoteInputRequest(BaseModel):
    kind: str
    action: str = ""
    x: float | None = None
    y: float | None = None
    button: str = "left"
    vk: int = 0
    delta: int = 0

class WindowsRemoteFrameRequest(BaseModel):
    image_base64: str
    width: int = 0
    height: int = 0

class WindowsRemoteStateRequest(BaseModel):
    status: str
    error: str = ""


def _agent_auth(request: Request):
    from .windows_agent import token_hash
    header=(request.headers.get("authorization") or "").strip()
    if not header.lower().startswith("bearer "):
        raise HTTPException(401,"Windows Agent authentication required")
    key=header[7:].strip()
    if not key:
        raise HTTPException(401,"Windows Agent authentication required")
    digest=token_hash(key)
    with db() as c:
        row=c.execute("SELECT * FROM windows_agents WHERE api_key_hash=? AND enabled=1 AND revoked_at IS NULL",(digest,)).fetchone()
    if not row:
        raise HTTPException(401,"Invalid or revoked Windows Agent key")
    return row


@app.post(f"{router_prefix}/windows-agents/enrollment-tokens")
def windows_agent_create_enrollment(req: WindowsAgentEnrollmentRequest, request: Request, user=Depends(require_admin)):
    from .windows_agent import new_enrollment_token, token_hash
    minutes=max(5,min(int(req.expires_minutes or 30),1440))
    token=new_enrollment_token(); created=dt.datetime.now(dt.timezone.utc); expires=created+dt.timedelta(minutes=minutes)
    with db() as c:
        c.execute("INSERT INTO windows_agent_enrollment_tokens(token_hash,label,expires_at,created_by,created_at) VALUES(?,?,?,?,?)",
                  (token_hash(token),req.label.strip()[:160],expires.isoformat(),user["username"],created.isoformat()))
        audit(c,user["username"],"windows_agent_enrollment_created",req.label.strip()[:160],json.dumps({"expires_at":expires.isoformat()}),client_ip(request))
    return {"enrollment_token":token,"expires_at":expires.isoformat(),"label":req.label.strip()[:160]}


@app.post(f"{router_prefix}/windows-agents/enroll")
def windows_agent_enroll(req: WindowsAgentEnrollRequest, request: Request):
    from .windows_agent import token_hash, new_agent_key
    if not req.enrollment_token or not req.agent_uuid.strip() or not req.computer_name.strip():
        raise HTTPException(400,"Enrollment token, agent UUID, and computer name are required")
    nowdt=dt.datetime.now(dt.timezone.utc); digest=token_hash(req.enrollment_token)
    with db() as c:
        token=c.execute("SELECT * FROM windows_agent_enrollment_tokens WHERE token_hash=?",(digest,)).fetchone()
        if not token or token["used_at"]:
            raise HTTPException(401,"Enrollment token is invalid or has already been used")
        try: expires=dt.datetime.fromisoformat(token["expires_at"])
        except Exception: raise HTTPException(401,"Enrollment token is invalid")
        if expires.tzinfo is None: expires=expires.replace(tzinfo=dt.timezone.utc)
        if expires < nowdt:
            raise HTTPException(401,"Enrollment token has expired")
        existing=c.execute("SELECT * FROM windows_agents WHERE agent_uuid=?",(req.agent_uuid.strip(),)).fetchone()
        if existing and existing["revoked_at"] is None:
            raise HTTPException(409,"This Windows Agent is already enrolled")
        api_key=new_agent_key(); api_hash=token_hash(api_key); ts=nowdt.isoformat()
        if existing:
            c.execute("""UPDATE windows_agents SET api_key_hash=?,computer_name=?,machine_guid=?,hostname=?,ip_address=?,os_version=?,architecture=?,agent_version=?,status='online',enabled=1,last_heartbeat_at=?,last_error='',updated_at=?,revoked_at=NULL WHERE id=?""",
                      (api_hash,req.computer_name.strip()[:255],req.machine_guid.strip()[:255],req.hostname.strip()[:255],client_ip(request)[:120],req.os_version.strip()[:300],req.architecture.strip()[:80],req.agent_version.strip()[:80],ts,ts,existing["id"]))
            agent_id=existing["id"]
        else:
            agent_id=c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,machine_guid,hostname,ip_address,os_version,architecture,agent_version,status,enabled,channels_json,poll_interval_seconds,last_heartbeat_at,enrolled_at,updated_at)
                                  VALUES(?,?,?,?,?,?,?,?,?,'online',1,'[\"System\",\"Application\"]',60,?,?,?)""",
                               (req.agent_uuid.strip()[:255],api_hash,req.computer_name.strip()[:255],req.machine_guid.strip()[:255],req.hostname.strip()[:255],client_ip(request)[:120],req.os_version.strip()[:300],req.architecture.strip()[:80],req.agent_version.strip()[:80],ts,ts,ts)).lastrowid
        c.execute("UPDATE windows_agent_enrollment_tokens SET used_at=? WHERE id=?",(ts,token["id"]))
        audit(c,"windows-agent","windows_agent_enrolled",str(agent_id),json.dumps({"computer_name":req.computer_name,"ip":client_ip(request),"agent_version":req.agent_version})[:2000],client_ip(request))
        row=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
    return {"agent_id":agent_id,"api_key":api_key,"server_time":ts,"channels":json.loads(row["channels_json"]),"poll_interval_seconds":row["poll_interval_seconds"]}


@app.post(f"{router_prefix}/windows-agents/heartbeat")
def windows_agent_heartbeat(req: WindowsAgentHeartbeatRequest, request: Request, agent=Depends(_agent_auth)):
    ts=now(); aid=agent["id"]
    with db() as c:
        c.execute("""UPDATE windows_agents SET computer_name=CASE WHEN ?<>'' THEN ? ELSE computer_name END,hostname=CASE WHEN ?<>'' THEN ? ELSE hostname END,
                     ip_address=?,os_version=CASE WHEN ?<>'' THEN ? ELSE os_version END,architecture=CASE WHEN ?<>'' THEN ? ELSE architecture END,
                     agent_version=CASE WHEN ?<>'' THEN ? ELSE agent_version END,status='online',last_heartbeat_at=?,last_error=?,updated_at=? WHERE id=?""",
                  (req.computer_name,req.computer_name[:255],req.hostname,req.hostname[:255],client_ip(request)[:120],req.os_version,req.os_version[:300],req.architecture,req.architecture[:80],req.agent_version,req.agent_version[:80],ts,req.last_error[:1000],ts,aid))
        pending=c.execute("SELECT * FROM windows_agent_rechecks WHERE agent_id=? AND status IN ('pending','delivered') ORDER BY id LIMIT 20",(aid,)).fetchall()
        if pending:
            ids=[r["id"] for r in pending if r["status"]=="pending"]
            if ids:
                marks=','.join('?' for _ in ids)
                c.execute(f"UPDATE windows_agent_rechecks SET status='delivered',delivered_at=? WHERE id IN ({marks})",[ts]+ids)
        pending_commands=c.execute("SELECT * FROM windows_agent_commands WHERE agent_id=? AND status IN ('pending','delivered') ORDER BY id LIMIT 20",(aid,)).fetchall()
        if pending_commands:
            ids=[r["id"] for r in pending_commands if r["status"]=="pending"]
            if ids:
                marks=','.join('?' for _ in ids)
                c.execute(f"UPDATE windows_agent_commands SET status='delivered',delivered_at=? WHERE id IN ({marks})",[ts]+ids)
        fresh=c.execute("SELECT * FROM windows_agents WHERE id=?",(aid,)).fetchone()
        rechecks=[]
        for r in pending:
            finding=c.execute("SELECT id,computer_name,channel,provider,event_id,record_id,last_seen FROM event_findings WHERE id=?",(r["finding_id"],)).fetchone()
            if finding:
                rechecks.append({"recheck_id":r["id"],"finding":dict(finding)})
        agent_commands=[]
        for r in pending_commands:
            try: payload=json.loads(r["payload_json"] or "{}")
            except Exception: payload={}
            agent_commands.append({"command_id":r["id"],"type":r["command_type"],"payload":payload})
    return {"ok":True,"server_time":ts,"channels":json.loads(fresh["channels_json"]),"poll_interval_seconds":fresh["poll_interval_seconds"],"enabled":bool(fresh["enabled"]),"rechecks":rechecks,"commands":agent_commands}


@app.post(f"{router_prefix}/windows-agents/events")
def windows_agent_events(req: WindowsAgentEventBatch, request: Request, agent=Depends(_agent_auth)):
    from .event_ticketing import ingest_event
    if len(req.events)>500:
        raise HTTPException(400,"A Windows Agent batch cannot exceed 500 events")
    created=0; finding_ids=[]; ts=now()
    with db() as c:
        for item in req.events:
            event=item.model_dump()
            event["computer_name"]=agent["computer_name"]
            fid,is_new=ingest_event(c,None,event,ts,agent_id=agent["id"])
            finding_ids.append(fid); created += 1 if is_new else 0
        c.execute("UPDATE windows_agents SET status='online',ip_address=?,last_heartbeat_at=?,last_event_at=?,last_error='',updated_at=? WHERE id=?",
                  (client_ip(request)[:120],ts,ts if req.events else agent["last_event_at"],ts,agent["id"]))
    return {"ok":True,"events":len(req.events),"new_findings":created,"finding_ids":finding_ids}


@app.post(f"{router_prefix}/windows-agents/rechecks/{{recheck_id}}/result")
def windows_agent_recheck_result(recheck_id: int, req: WindowsAgentRecheckResult, request: Request, agent=Depends(_agent_auth)):
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_agent_rechecks WHERE id=? AND agent_id=?",(recheck_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Recheck request not found")
        result={"seen_again":bool(req.seen_again),"details":req.details[:4000],"checked_at":req.checked_at or ts}
        c.execute("UPDATE windows_agent_rechecks SET status='completed',completed_at=?,result_json=? WHERE id=?",(ts,json.dumps(result),recheck_id))
        c.execute("UPDATE event_findings SET last_recheck_at=? WHERE id=?",(ts,row["finding_id"]))
        c.execute("UPDATE windows_agents SET status='online',last_heartbeat_at=?,updated_at=? WHERE id=?",(ts,ts,agent["id"]))
        audit(c,"windows-agent","event_finding_agent_recheck_completed",str(row["finding_id"]),json.dumps(result)[:2000],client_ip(request))
    return {"ok":True}


@app.post(f"{router_prefix}/windows-agents/commands/{{command_id}}/result")
def windows_agent_command_result(command_id: int, req: WindowsAgentCommandResult, request: Request, agent=Depends(_agent_auth)):
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_agent_commands WHERE id=? AND agent_id=?",(command_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Windows Agent command not found")
        result={"ok":bool(req.ok),"events":max(0,int(req.events or 0)),"new_findings":max(0,int(req.new_findings or 0)),"details":req.details[:4000],"completed_at":req.completed_at or ts}
        c.execute("UPDATE windows_agent_commands SET status=?,completed_at=?,result_json=? WHERE id=?",('completed' if req.ok else 'failed',ts,json.dumps(result),command_id))
        c.execute("UPDATE windows_agents SET status='online',last_heartbeat_at=?,last_error=?,updated_at=? WHERE id=?",(ts,'' if req.ok else req.details[:1000],ts,agent["id"]))
        audit(c,"windows-agent","windows_agent_command_completed",str(command_id),json.dumps({"agent_id":agent["id"],"command_type":row["command_type"],**result})[:2000],client_ip(request))
    return {"ok":True}


def _agent_version_tuple(value: str):
    try:
        parts=[int(x) for x in re.findall(r"\d+",value or "")[:3]]
        return tuple((parts+[0,0,0])[:3])
    except Exception:
        return (0,0,0)


def _windows_agent_update_manifest():
    from .windows_agent import load_update_manifest
    path=BASE_DIR / "windows" / "agent-x64" / "update-manifest.json"
    try:
        return load_update_manifest(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(503,f"Windows Agent update manifest is unavailable: {exc}")


@app.get(f"{router_prefix}/windows-agents/update-info")
def windows_agent_update_info(user=Depends(get_current_user)):
    manifest=_windows_agent_update_manifest()
    return {"ok":True,**manifest,"self_update_baseline":"2.1.0"}


@app.post(f"{router_prefix}/windows-agents/{{agent_id}}/upgrade")
def windows_agent_upgrade(agent_id: int, request: Request, user=Depends(require_admin)):
    manifest=_windows_agent_update_manifest(); ts=now()
    target=manifest["version"]
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not agent: raise HTTPException(404,"Windows Agent not found")
        if not agent["enabled"] or agent["revoked_at"]: raise HTTPException(409,"Windows Agent is disabled or revoked")
        installed=agent["agent_version"] or "0.0.0"
        if _agent_version_tuple(installed) >= _agent_version_tuple(target):
            return {"ok":True,"queued":False,"update_available":False,"installed_version":installed,"available_version":target,"message":"This Windows Agent is already up to date."}
        if _agent_version_tuple(installed) < (2,1,0):
            raise HTTPException(409,f"Windows Agent {installed} requires one manual upgrade to 2.1.0 or newer before self-update is available. Download and run the current x64 installer once; enrollment is preserved.")
        existing=c.execute("SELECT * FROM windows_agent_commands WHERE agent_id=? AND command_type='upgrade_agent' AND status IN ('pending','delivered') ORDER BY id DESC LIMIT 1",(agent_id,)).fetchone()
        if existing:
            return {"ok":True,"queued":True,"command_id":existing["id"],"status":existing["status"],"installed_version":installed,"available_version":target,"message":"An Agent upgrade is already queued."}
        payload=json.dumps({"version":target,"sha256":manifest["sha256"]},separators=(",",":"))
        cur=c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'upgrade_agent',?,'pending',?,?)",(agent_id,payload,user["username"],ts))
        cid=cur.lastrowid
        audit(c,user["username"],"windows_agent_upgrade_requested",str(agent_id),json.dumps({"command_id":cid,"computer_name":agent["computer_name"],"installed_version":installed,"target_version":target}),client_ip(request))
    return {"ok":True,"queued":True,"command_id":cid,"status":"pending","installed_version":installed,"available_version":target,"message":f"Upgrade to Windows Agent {target} queued. The agent will verify the MSI and launch Windows Installer on its next heartbeat."}


@app.post(f"{router_prefix}/windows-agents/{{agent_id}}/pull-now")
def windows_agent_pull_now(agent_id: int, request: Request, user=Depends(require_permission("operate"))):
    ts=now()
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not agent: raise HTTPException(404,"Windows Agent not found")
        if not agent["enabled"] or agent["revoked_at"]: raise HTTPException(409,"Windows Agent is disabled or revoked")
        if _agent_version_tuple(agent["agent_version"]) < (1,1,0):
            raise HTTPException(409,"Windows Agent 1.1.0 or newer is required for Pull Events Now. Download and update the agent package.")
        existing=c.execute("SELECT * FROM windows_agent_commands WHERE agent_id=? AND command_type='pull_events' AND status IN ('pending','delivered') ORDER BY id DESC LIMIT 1",(agent_id,)).fetchone()
        if existing:
            return {"ok":True,"queued":True,"command_id":existing["id"],"status":existing["status"],"message":"A Pull Events Now request is already queued for this agent."}
        cur=c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'pull_events','{}','pending',?,?)",(agent_id,user["username"],ts))
        cid=cur.lastrowid
        audit(c,user["username"],"windows_agent_pull_requested",str(agent_id),json.dumps({"command_id":cid,"computer_name":agent["computer_name"]}),client_ip(request))
    return {"ok":True,"queued":True,"command_id":cid,"status":"pending","message":"Pull Events Now queued. The agent will receive it on its next heartbeat."}


@app.get(f"{router_prefix}/windows-agents")
def windows_agent_list(user=Depends(get_current_user)):
    from .windows_agent import public_agent
    nowdt=dt.datetime.now(dt.timezone.utc); out=[]
    try: update_manifest=_windows_agent_update_manifest()
    except HTTPException: update_manifest=None
    with db() as c:
        rows=c.execute("SELECT * FROM windows_agents ORDER BY computer_name,id").fetchall()
        for row in rows:
            d=public_agent(row); status=d.get("status") or "enrolled"
            if d.get("revoked_at"): status="revoked"
            elif d.get("enabled") and d.get("last_heartbeat_at"):
                try:
                    hb=dt.datetime.fromisoformat(d["last_heartbeat_at"]); hb=hb if hb.tzinfo else hb.replace(tzinfo=dt.timezone.utc)
                    if (nowdt-hb).total_seconds()>max(180,int(d.get("poll_interval_seconds") or 60)*3): status="offline"
                except Exception: pass
            d["status"]=status
            d["open_findings"]=c.execute("SELECT COUNT(*) FROM event_findings WHERE agent_id=? AND status='open'",(row["id"],)).fetchone()[0]
            pull=c.execute("SELECT * FROM windows_agent_commands WHERE agent_id=? AND command_type='pull_events' ORDER BY id DESC LIMIT 1",(row["id"],)).fetchone()
            installed_version=d.get("agent_version") or "0.0.0"
            d["pull_now_supported"]=_agent_version_tuple(installed_version) >= (1,1,0)
            d["upgrade_supported"]=_agent_version_tuple(installed_version) >= (2,1,0)
            d["remote_supported"]=_agent_version_tuple(installed_version) >= (2,2,0)
            d["available_version"]=update_manifest["version"] if update_manifest else None
            d["update_available"]=bool(update_manifest and _agent_version_tuple(installed_version) < _agent_version_tuple(update_manifest["version"]))
            if pull:
                d["last_pull_status"]=pull["status"]; d["last_pull_requested_at"]=pull["requested_at"]; d["last_pull_completed_at"]=pull["completed_at"]
                try: d["last_pull_result"]=json.loads(pull["result_json"] or "{}")
                except Exception: d["last_pull_result"]={}
            else:
                d["last_pull_status"]="never"; d["last_pull_requested_at"]=None; d["last_pull_completed_at"]=None; d["last_pull_result"]={}
            out.append(d)
    return out


def _remote_frame_path(session_id: int):
    root=BASE_DIR / "data" / "remote-frames"
    root.mkdir(parents=True,exist_ok=True)
    return root / f"session-{int(session_id)}.jpg"


def _remote_session_public(row):
    if not row: return None
    d=dict(row)
    d["frame_url"]=f"{router_prefix}/remote-access/sessions/{d['id']}/frame"
    return d


@app.post(f"{router_prefix}/remote-access/sessions")
def windows_remote_start(req: WindowsRemoteStartRequest, request: Request, user=Depends(require_admin)):
    ts=now(); nowdt=dt.datetime.now(dt.timezone.utc)
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(req.agent_id,)).fetchone()
        if not agent: raise HTTPException(404,"Windows Agent not found")
        if not agent["enabled"] or agent["revoked_at"]: raise HTTPException(409,"Windows Agent is disabled or revoked")
        if _agent_version_tuple(agent["agent_version"] or "") < (2,2,0):
            raise HTTPException(409,"Windows Agent 2.2.0 or newer is required for Remote Access. Upgrade this computer first.")
        if not agent["last_heartbeat_at"]: raise HTTPException(409,"Windows Agent is offline")
        try:
            hb=dt.datetime.fromisoformat(agent["last_heartbeat_at"]); hb=hb if hb.tzinfo else hb.replace(tzinfo=dt.timezone.utc)
            if (nowdt-hb).total_seconds()>180: raise HTTPException(409,"Windows Agent is offline")
        except HTTPException: raise
        except Exception: raise HTTPException(409,"Windows Agent heartbeat is invalid")
        existing=c.execute("SELECT * FROM windows_remote_sessions WHERE agent_id=? AND status IN ('connecting','active') ORDER BY id DESC LIMIT 1",(req.agent_id,)).fetchone()
        if existing: return {"ok":True,"session":_remote_session_public(existing),"message":"A remote support session is already open for this computer."}
        cur=c.execute("INSERT INTO windows_remote_sessions(agent_id,status,requested_by,requested_at) VALUES(?,'connecting',?,?)",(req.agent_id,user["username"],ts))
        sid=cur.lastrowid
        payload=json.dumps({"session_id":sid,"requested_by":user["username"]},separators=(",",":"))
        c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'remote_session_start',?,'pending',?,?)",(req.agent_id,payload,user["username"],ts))
        audit(c,user["username"],"windows_remote_session_requested",str(sid),json.dumps({"agent_id":req.agent_id,"computer_name":agent["computer_name"]}),client_ip(request))
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(sid,)).fetchone()
    return {"ok":True,"session":_remote_session_public(row),"message":"Remote support request sent. The signed-in Windows user must approve the connection."}


@app.get(f"{router_prefix}/remote-access/sessions/{{session_id}}")
def windows_remote_session(session_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT s.*,a.computer_name,a.hostname,a.ip_address,a.os_version,a.agent_version FROM windows_remote_sessions s JOIN windows_agents a ON a.id=s.agent_id WHERE s.id=?",(session_id,)).fetchone()
    if not row: raise HTTPException(404,"Remote support session not found")
    return _remote_session_public(row)


@app.post(f"{router_prefix}/remote-access/sessions/{{session_id}}/stop")
def windows_remote_stop(session_id: int, request: Request, user=Depends(require_admin)):
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] not in ("ended","failed"):
            c.execute("UPDATE windows_remote_sessions SET status='ended',ended_at=? WHERE id=?",(ts,session_id))
            c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'remote_session_stop',?,'pending',?,?)",(row["agent_id"],json.dumps({"session_id":session_id}),user["username"],ts))
            audit(c,user["username"],"windows_remote_session_stopped",str(session_id),"",client_ip(request))
    return {"ok":True}


@app.get(f"{router_prefix}/remote-access/sessions/{{session_id}}/frame")
def windows_remote_frame(session_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT id FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
    if not row: raise HTTPException(404,"Remote support session not found")
    path=_remote_frame_path(session_id)
    if not path.exists(): return Response(status_code=204,headers={"Cache-Control":"no-store"})
    return Response(content=path.read_bytes(),media_type="image/jpeg",headers={"Cache-Control":"no-store, max-age=0"})


@app.post(f"{router_prefix}/remote-access/sessions/{{session_id}}/input")
def windows_remote_input(session_id: int, req: WindowsRemoteInputRequest, request: Request, user=Depends(require_admin)):
    kind=(req.kind or "").lower(); action=(req.action or "").lower(); event={"kind":kind}
    if kind=="pointer":
        if action not in {"move","click","down","up"}: raise HTTPException(400,"Unsupported pointer action")
        if req.x is None or req.y is None: raise HTTPException(400,"Pointer coordinates are required")
        if req.button not in {"left","right","middle"}: raise HTTPException(400,"Unsupported pointer button")
        event.update({"action":action,"x":max(0.0,min(float(req.x),1.0)),"y":max(0.0,min(float(req.y),1.0)),"button":req.button})
    elif kind=="keyboard":
        if action not in {"down","up"} or not (8 <= int(req.vk) <= 255): raise HTTPException(400,"Unsupported keyboard event")
        event.update({"action":action,"vk":int(req.vk)})
    elif kind=="wheel":
        event.update({"delta":max(-1200,min(int(req.delta),1200))})
    else: raise HTTPException(400,"Unsupported remote input type")
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] not in {"connecting","active"}: raise HTTPException(409,"Remote support session is not active")
        c.execute("INSERT INTO windows_remote_events(session_id,event_json,created_at) VALUES(?,?,?)",(session_id,json.dumps(event,separators=(",",":")),now()))
    return {"ok":True}


@app.post(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/frame")
def windows_remote_agent_frame(session_id: int, req: WindowsRemoteFrameRequest, agent=Depends(_agent_auth)):
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] not in {"connecting","active"}: raise HTTPException(409,"Remote support session is closed")
        try: raw=base64.b64decode(req.image_base64,validate=True)
        except Exception: raise HTTPException(400,"Invalid remote frame encoding")
        if len(raw)<4 or len(raw)>5*1024*1024 or not raw.startswith(b"\xff\xd8"): raise HTTPException(400,"Invalid remote JPEG frame")
        path=_remote_frame_path(session_id); tmp=path.with_suffix('.tmp'); tmp.write_bytes(raw); tmp.replace(path)
        ts=now(); connected=row["connected_at"] or ts
        c.execute("UPDATE windows_remote_sessions SET status='active',connected_at=?,last_frame_at=?,last_width=?,last_height=?,last_error='' WHERE id=?",(connected,ts,max(0,min(req.width,10000)),max(0,min(req.height,10000)),session_id))
    return {"ok":True}


@app.get(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/events")
def windows_remote_agent_events(session_id: int, after: int=0, agent=Depends(_agent_auth)):
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        active=row["status"] in {"connecting","active"}
        events=c.execute("SELECT * FROM windows_remote_events WHERE session_id=? AND id>? ORDER BY id LIMIT 100",(session_id,max(0,int(after)))).fetchall() if active else []
        if events:
            ids=[r["id"] for r in events]; marks=','.join('?' for _ in ids)
            c.execute(f"UPDATE windows_remote_events SET delivered_at=? WHERE id IN ({marks})",[now()]+ids)
        out=[]
        for r in events:
            try: ev=json.loads(r["event_json"])
            except Exception: ev={}
            out.append({"event_id":r["id"],"event":ev})
    return {"ok":True,"active":active,"status":row["status"],"events":out}


@app.post(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/state")
def windows_remote_agent_state(session_id: int, req: WindowsRemoteStateRequest, agent=Depends(_agent_auth)):
    status=(req.status or "").lower()
    if status not in {"active","failed","ended"}: raise HTTPException(400,"Invalid remote support state")
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if status=="active": c.execute("UPDATE windows_remote_sessions SET status='active',connected_at=COALESCE(connected_at,?),last_error='' WHERE id=?",(ts,session_id))
        else: c.execute("UPDATE windows_remote_sessions SET status=?,ended_at=?,last_error=? WHERE id=?",(status,ts,req.error[:1000],session_id))
    return {"ok":True}


@app.put(f"{router_prefix}/windows-agents/{{agent_id}}")
def windows_agent_update(agent_id: int, req: WindowsAgentConfigRequest, request: Request, user=Depends(require_admin)):
    from .windows_agent import normalize_channels, public_agent
    channels=normalize_channels(req.channels); interval=max(30,min(int(req.poll_interval_seconds or 60),3600)); ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not row: raise HTTPException(404,"Windows Agent not found")
        c.execute("UPDATE windows_agents SET channels_json=?,poll_interval_seconds=?,enabled=?,updated_at=? WHERE id=?",(json.dumps(channels),interval,1 if req.enabled else 0,ts,agent_id))
        audit(c,user["username"],"windows_agent_config_updated",str(agent_id),json.dumps({"channels":channels,"poll_interval_seconds":interval,"enabled":req.enabled}),client_ip(request))
        out=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
    return public_agent(out)


@app.delete(f"{router_prefix}/windows-agents/{{agent_id}}")
def windows_agent_revoke(agent_id: int, request: Request, user=Depends(require_admin)):
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not row: raise HTTPException(404,"Windows Agent not found")
        c.execute("UPDATE windows_agents SET enabled=0,status='revoked',revoked_at=?,updated_at=? WHERE id=?",(ts,ts,agent_id))
        c.execute("UPDATE windows_agent_rechecks SET status='failed',completed_at=?,result_json=? WHERE agent_id=? AND status IN ('pending','delivered')",(ts,json.dumps({"error":"Agent revoked"}),agent_id))
        c.execute("UPDATE windows_agent_commands SET status='failed',completed_at=?,result_json=? WHERE agent_id=? AND status IN ('pending','delivered')",(ts,json.dumps({"error":"Agent revoked"}),agent_id))
        audit(c,user["username"],"windows_agent_revoked",str(agent_id),row["computer_name"],client_ip(request))
    return {"ok":True}


@app.delete(f"{router_prefix}/windows-agents/{{agent_id}}/purge")
def windows_agent_purge(agent_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        row=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not row: raise HTTPException(404,"Windows Agent not found")
        if not row["revoked_at"] and row["status"] != "revoked":
            raise HTTPException(409,"Revoke the Windows Agent before removing it permanently")
        sessions=[r[0] for r in c.execute("SELECT id FROM windows_remote_sessions WHERE agent_id=?",(agent_id,)).fetchall()]
        finding_ids=[r[0] for r in c.execute("SELECT id FROM event_findings WHERE agent_id=?",(agent_id,)).fetchall()]
        if sessions:
            marks=",".join("?" for _ in sessions)
            c.execute(f"DELETE FROM windows_remote_events WHERE session_id IN ({marks})",sessions)
        c.execute("DELETE FROM windows_remote_sessions WHERE agent_id=?",(agent_id,))
        c.execute("DELETE FROM windows_agent_rechecks WHERE agent_id=?",(agent_id,))
        c.execute("DELETE FROM windows_agent_commands WHERE agent_id=?",(agent_id,))
        findings_deleted=0
        if finding_ids:
            findings_deleted=len(_delete_event_findings(c,finding_ids))
        c.execute("DELETE FROM windows_agents WHERE id=?",(agent_id,))
        audit(c,user["username"],"windows_agent_purged",str(agent_id),json.dumps({"computer_name":row["computer_name"],"findings_deleted":findings_deleted,"remote_sessions_deleted":len(sessions)}),client_ip(request))
    return {"ok":True,"computer_name":row["computer_name"],"findings_deleted":findings_deleted,"remote_sessions_deleted":len(sessions)}

@app.get(f"{router_prefix}/windows-agents/package/msi")
def windows_agent_msi_package(agent=Depends(_agent_auth)):
    manifest=_windows_agent_update_manifest()
    path=BASE_DIR / "windows" / "agent-x64" / manifest["filename"]
    if not path.exists(): raise HTTPException(404,"Windows Agent x64 MSI is not installed")
    return FileResponse(path,media_type="application/octet-stream",filename=manifest["filename"],headers={"X-GODSEYE-Agent-Version":manifest["version"],"X-GODSEYE-SHA256":manifest["sha256"]})


@app.get(f"{router_prefix}/windows-agents/package")
def windows_agent_package(user=Depends(require_admin)):
    path=BASE_DIR / "windows" / "agent-x64" / "GODSEYE-Windows-Agent-x64-Setup.exe"
    if not path.exists(): raise HTTPException(404,"Windows Agent x64 installer is not installed")
    return FileResponse(path,media_type="application/vnd.microsoft.portable-executable",filename="GODSEYE-Windows-Agent-x64-Setup.exe")


@app.get(f"{router_prefix}/windows-agents/package/legacy")
def windows_agent_legacy_package(user=Depends(require_admin)):
    path=BASE_DIR / "windows" / "agent" / "GODSEYE-Windows-Agent.zip"
    if not path.exists(): raise HTTPException(404,"Legacy Windows Agent package is not installed")
    return FileResponse(path,media_type="application/zip",filename="GODSEYE-Windows-Agent-Legacy.zip")


# ---------------------------------------------------------------------------
# Windows Event Findings + Ticket Portal
# ---------------------------------------------------------------------------

class WindowsEventSourceRequest(BaseModel):
    name: str
    hostname: str
    port: int = 5986
    transport: str = "ntlm"
    username: str = ""
    password: str = ""
    verify_tls: bool = True
    enabled: bool = True
    poll_interval_minutes: int = 5
    channels: list[str] = ["System","Application"]

class TicketCreateRequest(BaseModel):
    title: str
    description: str = ""
    priority: str = "medium"
    assignee: str = ""
    linked_type: str = ""
    linked_id: int | None = None
    device_name: str = ""
    due_at: str | None = None

class TicketUpdateRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    priority: str | None = None
    assignee: str | None = None
    due_at: str | None = None

class TicketNoteRequest(BaseModel):
    note: str

class TicketScheduleRequest(BaseModel):
    start_at: str
    end_at: str
    all_day: bool = False

class TicketCloseRequest(BaseModel):
    note: str = ""
    resolve_linked_finding: bool = False

class TicketBulkDeleteRequest(BaseModel):
    ticket_ids: list[int]

class TicketDeleteOldRequest(BaseModel):
    older_than_days: int = 90

def _windows_source_public(row):
    d=dict(row)
    d["verify_tls"]=bool(d.get("verify_tls"))
    d["enabled"]=bool(d.get("enabled"))
    d["has_password"]=bool(d.pop("password_enc",""))
    try: d["channels"]=json.loads(d.pop("channels_json") or "[]")
    except Exception: d["channels"]=[]
    try: d["bookmarks"]=json.loads(d.pop("last_record_json") or "{}")
    except Exception: d["bookmarks"]={}
    return d

def _event_finding_public(row):
    d=dict(row)
    try: d["suggested_actions"]=json.loads(d.pop("suggested_actions_json") or "[]")
    except Exception: d["suggested_actions"]=[]
    return d

@app.get(f"{router_prefix}/windows-event-sources")
def windows_event_sources(user=Depends(require_permission("operate"))):
    with db() as c:
        rows=c.execute("SELECT * FROM windows_event_sources ORDER BY name,id").fetchall()
    return [_windows_source_public(r) for r in rows]

@app.post(f"{router_prefix}/windows-event-sources")
def windows_event_source_create(req: WindowsEventSourceRequest, request: Request, user=Depends(require_admin)):
    name=req.name.strip();host=req.hostname.strip()
    if not name or not host: raise HTTPException(400,"Name and hostname are required")
    if not req.username.strip() or not req.password:
        raise HTTPException(400,"A dedicated Windows Event Log reader username and password are required")
    if req.transport not in {"ntlm","basic"}: raise HTTPException(400,"Unsupported WinRM transport")
    if not (1 <= req.port <= 65535): raise HTTPException(400,"Invalid WinRM port")
    channels=[x.strip() for x in req.channels if x and x.strip()][:20]
    if not channels: channels=["System","Application"]
    ts=now()
    with db() as c:
        sid=c.execute("""INSERT INTO windows_event_sources(name,hostname,port,transport,username,password_enc,verify_tls,enabled,poll_interval_minutes,channels_json,last_status,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,'never',?,?)""",
                      (name[:160],host[:255],req.port,req.transport,req.username.strip()[:300],encrypt_secret(req.password),1 if req.verify_tls else 0,
                       1 if req.enabled else 0,max(1,min(req.poll_interval_minutes,1440)),json.dumps(channels),ts,ts)).lastrowid
        audit(c,user["username"],"windows_event_source_created",str(sid),json.dumps({"name":name,"hostname":host,"channels":channels}),client_ip(request))
        row=c.execute("SELECT * FROM windows_event_sources WHERE id=?",(sid,)).fetchone()
    return _windows_source_public(row)

@app.put(f"{router_prefix}/windows-event-sources/{{source_id}}")
def windows_event_source_update(source_id: int, req: WindowsEventSourceRequest, request: Request, user=Depends(require_admin)):
    if not req.name.strip() or not req.hostname.strip(): raise HTTPException(400,"Name and hostname are required")
    if req.transport not in {"ntlm","basic"}: raise HTTPException(400,"Unsupported WinRM transport")
    if not (1 <= req.port <= 65535): raise HTTPException(400,"Invalid WinRM port")
    channels=[x.strip() for x in req.channels if x and x.strip()][:20] or ["System","Application"]
    with db() as c:
        old=c.execute("SELECT * FROM windows_event_sources WHERE id=?",(source_id,)).fetchone()
        if not old: raise HTTPException(404,"Windows event source not found")
        password_enc=encrypt_secret(req.password) if req.password else old["password_enc"]
        c.execute("""UPDATE windows_event_sources SET name=?,hostname=?,port=?,transport=?,username=?,password_enc=?,verify_tls=?,enabled=?,poll_interval_minutes=?,channels_json=?,updated_at=? WHERE id=?""",
                  (req.name.strip()[:160],req.hostname.strip()[:255],req.port,req.transport,req.username.strip()[:300],password_enc,1 if req.verify_tls else 0,
                   1 if req.enabled else 0,max(1,min(req.poll_interval_minutes,1440)),json.dumps(channels),now(),source_id))
        audit(c,user["username"],"windows_event_source_updated",str(source_id),json.dumps({"hostname":req.hostname,"channels":channels}),client_ip(request))
        row=c.execute("SELECT * FROM windows_event_sources WHERE id=?",(source_id,)).fetchone()
    return _windows_source_public(row)

@app.delete(f"{router_prefix}/windows-event-sources/{{source_id}}")
def windows_event_source_delete(source_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        row=c.execute("SELECT * FROM windows_event_sources WHERE id=?",(source_id,)).fetchone()
        if not row: raise HTTPException(404,"Windows event source not found")
        c.execute("UPDATE event_findings SET source_id=NULL WHERE source_id=?",(source_id,))
        c.execute("DELETE FROM windows_event_sources WHERE id=?",(source_id,))
        audit(c,user["username"],"windows_event_source_deleted",str(source_id),json.dumps({"name":row["name"],"hostname":row["hostname"]}),client_ip(request))
    return {"ok":True}

@app.post(f"{router_prefix}/windows-event-sources/{{source_id}}/poll")
def windows_event_source_poll(source_id: int, request: Request, user=Depends(require_permission("operate"))):
    manager=getattr(app.state,"windows_event_manager",None)
    if manager is None: raise HTTPException(503,"Windows Event collector is not running")
    try:
        result=manager.poll_source(source_id)
    except KeyError: raise HTTPException(404,"Windows event source not found")
    except Exception as exc: raise HTTPException(502,f"Windows Event pull failed: {exc}")
    with db() as c:
        audit(c,user["username"],"windows_event_source_polled",str(source_id),json.dumps(result)[:2000],client_ip(request))
    return result

class EventFindingBulkDeleteRequest(BaseModel):
    finding_ids: list[int]

class EventFindingOldDeleteRequest(BaseModel):
    older_than_days: int = 30

@app.get(f"{router_prefix}/event-findings")
def event_findings(status: str | None=None, severity: str | None=None, computer: str | None=None, q: str | None=None, limit: int=500, user=Depends(get_current_user)):
    with db() as c:
        sql="SELECT * FROM event_findings WHERE 1=1";params=[]
        if status: sql+=" AND status=?";params.append(status)
        if severity: sql+=" AND severity=?";params.append(severity)
        if computer: sql+=" AND lower(computer_name) LIKE ?";params.append("%"+computer.lower()+"%")
        if q and q.strip():
            like="%"+q.strip().lower()+"%"
            sql+=" AND (lower(computer_name) LIKE ? OR lower(provider) LIKE ? OR lower(title) LIKE ? OR lower(message) LIKE ? OR lower(category) LIKE ? OR CAST(event_id AS TEXT) LIKE ?)"
            params.extend([like,like,like,like,like,like])
        sql+=" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,last_seen DESC LIMIT ?"
        params.append(max(1,min(limit,2000)))
        rows=c.execute(sql,params).fetchall()
    return [_event_finding_public(r) for r in rows]

def _delete_event_findings(c, ids: list[int]):
    ids=sorted({int(x) for x in ids if int(x)>0})
    if not ids:
        return []
    marks=",".join("?" for _ in ids)
    rows=c.execute(f"SELECT id,title,computer_name,event_id,status FROM event_findings WHERE id IN ({marks})",ids).fetchall()
    found=[int(r["id"]) for r in rows]
    if not found:
        return []
    fmarks=",".join("?" for _ in found)
    # Keep ticket history but mark its source as a deleted Event Finding.
    c.execute(f"UPDATE tickets SET linked_type='event_finding_deleted' WHERE linked_type='event_finding' AND linked_id IN ({fmarks})",found)
    c.execute(f"DELETE FROM windows_agent_rechecks WHERE finding_id IN ({fmarks})",found)
    c.execute(f"DELETE FROM event_findings WHERE id IN ({fmarks})",found)
    return [dict(r) for r in rows]

@app.delete(f"{router_prefix}/event-findings/{{finding_id}}")
def event_finding_delete(finding_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        rows=_delete_event_findings(c,[finding_id])
        if not rows: raise HTTPException(404,"Event Finding not found")
        row=rows[0]
        audit(c,user["username"],"event_finding_deleted",str(finding_id),json.dumps({"title":row["title"],"computer_name":row["computer_name"],"event_id":row["event_id"],"status":row["status"]}),client_ip(request))
    return {"ok":True,"deleted":1}

@app.post(f"{router_prefix}/event-findings/bulk-delete")
def event_findings_bulk_delete(req: EventFindingBulkDeleteRequest, request: Request, user=Depends(require_admin)):
    ids=sorted({int(x) for x in req.finding_ids if int(x)>0})
    if not ids: raise HTTPException(400,"Select at least one Event Finding")
    if len(ids)>200: raise HTTPException(400,"A maximum of 200 Event Findings can be deleted at once")
    with db() as c:
        rows=_delete_event_findings(c,ids)
        audit(c,user["username"],"event_findings_bulk_deleted",details=json.dumps({"requested":len(ids),"deleted":len(rows),"ids":[r["id"] for r in rows]})[:4000],ip=client_ip(request))
    return {"ok":True,"deleted":len(rows)}

@app.post(f"{router_prefix}/event-findings/delete-old")
def event_findings_delete_old(req: EventFindingOldDeleteRequest, request: Request, user=Depends(require_admin)):
    days=int(req.older_than_days)
    if days not in {7,30,90,180,365}: raise HTTPException(400,"Unsupported retention age")
    cutoff=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).isoformat()
    with db() as c:
        ids=[int(r["id"]) for r in c.execute("SELECT id FROM event_findings WHERE status='resolved' AND COALESCE(resolved_at,last_seen) < ? ORDER BY id",(cutoff,)).fetchall()]
        rows=_delete_event_findings(c,ids)
        audit(c,user["username"],"event_findings_old_deleted",details=json.dumps({"older_than_days":days,"deleted":len(rows)})[:2000],ip=client_ip(request))
    return {"ok":True,"deleted":len(rows),"older_than_days":days}

@app.get(f"{router_prefix}/event-findings/{{finding_id}}")
def event_finding_detail(finding_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT * FROM event_findings WHERE id=?",(finding_id,)).fetchone()
        if not row: raise HTTPException(404,"Event Finding not found")
        tickets=c.execute("SELECT id,ticket_number,title,status,priority FROM tickets WHERE linked_type='event_finding' AND linked_id=? ORDER BY id DESC",(finding_id,)).fetchall()
    out=_event_finding_public(row);out["tickets"]=[dict(x) for x in tickets];return out

@app.get(f"{router_prefix}/event-findings/{{finding_id}}/suggested-fix")
def event_finding_suggested_fix(finding_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT * FROM event_findings WHERE id=?",(finding_id,)).fetchone()
        if not row: raise HTTPException(404,"Event Finding not found")
    d=_event_finding_public(row)
    return {"id":finding_id,"title":d["title"],"recommendation":d["recommendation"],"actions":d["suggested_actions"],"event_id":d["event_id"],"provider":d["provider"],"computer_name":d["computer_name"]}

@app.post(f"{router_prefix}/event-findings/{{finding_id}}/recheck")
def event_finding_recheck(finding_id: int, request: Request, user=Depends(require_permission("operate"))):
    with db() as c:
        row=c.execute("SELECT * FROM event_findings WHERE id=?",(finding_id,)).fetchone()
        if not row: raise HTTPException(404,"Event Finding not found")
        before=row["occurrence_count"];source_id=row["source_id"];agent_id=row["agent_id"]
        if agent_id:
            agent=c.execute("SELECT * FROM windows_agents WHERE id=? AND enabled=1 AND revoked_at IS NULL",(agent_id,)).fetchone()
            if not agent: raise HTTPException(409,"The Windows Agent linked to this finding is unavailable or revoked")
            existing=c.execute("SELECT * FROM windows_agent_rechecks WHERE agent_id=? AND finding_id=? AND status IN ('pending','delivered') ORDER BY id DESC LIMIT 1",(agent_id,finding_id)).fetchone()
            if existing:
                return {"ok":False,"pending":True,"recheck_id":existing["id"],"message":"A Windows Agent recheck is already queued for this finding."}
            ts=now(); rid=c.execute("INSERT INTO windows_agent_rechecks(agent_id,finding_id,status,requested_by,requested_at) VALUES(?,?,'pending',?,?)",(agent_id,finding_id,user["username"],ts)).lastrowid
            c.execute("UPDATE event_findings SET last_recheck_at=? WHERE id=?",(ts,finding_id))
            audit(c,user["username"],"event_finding_agent_recheck_queued",str(finding_id),json.dumps({"agent_id":agent_id,"recheck_id":rid}),client_ip(request))
            return {"ok":False,"pending":True,"recheck_id":rid,"message":"Recheck queued for the Windows Agent. The agent will run it on its next heartbeat."}
    poll=None
    if source_id:
        manager=getattr(app.state,"windows_event_manager",None)
        if manager is None: raise HTTPException(503,"Windows Event collector is not running")
        try: poll=manager.poll_source(int(source_id))
        except Exception as exc: raise HTTPException(502,f"Recheck pull failed: {exc}")
    with db() as c:
        current=c.execute("SELECT * FROM event_findings WHERE id=?",(finding_id,)).fetchone()
        c.execute("UPDATE event_findings SET last_recheck_at=? WHERE id=?",(now(),finding_id))
        new_occurrence=current["occurrence_count"]>before
        result={"ok":not new_occurrence,"new_occurrence":new_occurrence,"occurrence_count":current["occurrence_count"],"status":current["status"],"poll":poll,
                "message":"No new matching Windows event was found during recheck." if not new_occurrence else "The Windows error occurred again during recheck."}
        audit(c,user["username"],"event_finding_rechecked",str(finding_id),json.dumps(result)[:2000],client_ip(request))
    return result

@app.post(f"{router_prefix}/event-findings/{{finding_id}}/resolve")
def event_finding_resolve(finding_id: int, request: Request, user=Depends(require_permission("findings.resolve"))):
    with db() as c:
        row=c.execute("SELECT * FROM event_findings WHERE id=? AND status='open'",(finding_id,)).fetchone()
        if not row: raise HTTPException(404,"Event Finding not found or already resolved")
        c.execute("UPDATE event_findings SET status='resolved',resolved_at=?,last_seen=last_seen WHERE id=?",(now(),finding_id))
        audit(c,user["username"],"event_finding_resolved",str(finding_id),row["title"],client_ip(request))
    return {"ok":True}

@app.post(f"{router_prefix}/event-findings/{{finding_id}}/create-ticket")
def event_finding_create_ticket(finding_id: int, request: Request, user=Depends(require_permission("operate"))):
    with db() as c:
        finding=c.execute("SELECT * FROM event_findings WHERE id=?",(finding_id,)).fetchone()
        if not finding: raise HTTPException(404,"Event Finding not found")
        existing=c.execute("SELECT * FROM tickets WHERE linked_type='event_finding' AND linked_id=? AND status NOT IN ('closed','resolved') ORDER BY id DESC LIMIT 1",(finding_id,)).fetchone()
        if existing: return dict(existing)
        ts=now()
        cur=c.execute("""INSERT INTO tickets(title,description,status,priority,assignee,linked_type,linked_id,device_name,created_by,created_at,updated_at)
                         VALUES(?,?,'open',?,'','event_finding',?,?,?, ?,?)""",
                      (finding["title"],finding["recommendation"],"critical" if finding["severity"]=="critical" else ("high" if finding["severity"]=="high" else "medium"),
                       finding_id,finding["computer_name"],user["username"],ts,ts))
        tid=cur.lastrowid;number=f"TKT-{tid:05d}"
        c.execute("UPDATE tickets SET ticket_number=? WHERE id=?",(number,tid))
        audit(c,user["username"],"ticket_created_from_event_finding",number,json.dumps({"finding_id":finding_id,"computer":finding["computer_name"]}),client_ip(request))
        row=c.execute("SELECT * FROM tickets WHERE id=?",(tid,)).fetchone()
    return dict(row)

def _ticket_public(c,row,include_notes=False):
    d=dict(row)
    if include_notes:
        d["notes"]=[dict(x) for x in c.execute("SELECT * FROM ticket_notes WHERE ticket_id=? ORDER BY created_at,id",(row["id"],)).fetchall()]
        if d.get("linked_type")=="event_finding" and d.get("linked_id"):
            finding=c.execute("SELECT id,title,severity,status,computer_name,event_id,provider FROM event_findings WHERE id=?",(d["linked_id"],)).fetchone()
            d["linked_finding"]=dict(finding) if finding else None
        elif d.get("linked_type")=="network_finding" and d.get("linked_id"):
            finding=c.execute("SELECT id,title,severity,status,target,issue_type FROM network_issues WHERE id=?",(d["linked_id"],)).fetchone()
            d["linked_network_finding"]=dict(finding) if finding else None
    return d

@app.get(f"{router_prefix}/tickets")
def tickets(status: str | None=None, priority: str | None=None, limit: int=500, user=Depends(get_current_user)):
    with db() as c:
        q="SELECT * FROM tickets WHERE 1=1";params=[]
        if status: q+=" AND status=?";params.append(status)
        if priority: q+=" AND priority=?";params.append(priority)
        q+=" ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'assigned' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'waiting' THEN 3 ELSE 4 END, CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,updated_at DESC LIMIT ?"
        params.append(max(1,min(limit,2000)))
        rows=c.execute(q,params).fetchall()
        return [_ticket_public(c,r) for r in rows]

@app.get(f"{router_prefix}/tickets/{{ticket_id}}")
def ticket_detail(ticket_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT * FROM tickets WHERE id=?",(ticket_id,)).fetchone()
        if not row: raise HTTPException(404,"Ticket not found")
        return _ticket_public(c,row,True)

def _validate_ticket_assignee(c, username: str, allow_legacy: str | None = None) -> str:
    username=(username or "").strip()
    if not username:
        return ""
    if allow_legacy is not None and username==allow_legacy:
        return username
    row=c.execute("SELECT username FROM users WHERE username=?",(username,)).fetchone()
    if not row:
        raise HTTPException(400,"Ticket assignee must be an existing GODSEYE user")
    return row["username"]


@app.post(f"{router_prefix}/tickets")
def ticket_create(req: TicketCreateRequest, request: Request, user=Depends(require_permission("operate"))):
    if not req.title.strip(): raise HTTPException(400,"Ticket title is required")
    if req.priority not in {"low","medium","high","critical"}: raise HTTPException(400,"Invalid priority")
    ts=now()
    with db() as c:
        assignee=_validate_ticket_assignee(c,req.assignee)
        cur=c.execute("""INSERT INTO tickets(title,description,status,priority,assignee,linked_type,linked_id,device_name,due_at,created_by,created_at,updated_at)
                         VALUES(?,?,'open',?,?,?,?,?,?,?,?,?)""",
                      (req.title.strip()[:240],req.description.strip()[:8000],req.priority,assignee,req.linked_type.strip()[:40],
                       req.linked_id,req.device_name.strip()[:255],req.due_at,user["username"],ts,ts))
        tid=cur.lastrowid;number=f"TKT-{tid:05d}";c.execute("UPDATE tickets SET ticket_number=? WHERE id=?",(number,tid))
        audit(c,user["username"],"ticket_created",number,json.dumps({"title":req.title,"priority":req.priority}),client_ip(request))
        row=c.execute("SELECT * FROM tickets WHERE id=?",(tid,)).fetchone()
    return dict(row)

@app.put(f"{router_prefix}/tickets/{{ticket_id}}")
def ticket_update(ticket_id: int, req: TicketUpdateRequest, request: Request, user=Depends(require_permission("operate"))):
    with db() as c:
        row=c.execute("SELECT * FROM tickets WHERE id=?",(ticket_id,)).fetchone()
        if not row: raise HTTPException(404,"Ticket not found")
        d=dict(row)
        title=req.title.strip()[:240] if req.title is not None else d["title"]
        description=req.description.strip()[:8000] if req.description is not None else d["description"]
        status=req.status if req.status is not None else d["status"]
        priority=req.priority if req.priority is not None else d["priority"]
        assignee=_validate_ticket_assignee(c,req.assignee,d["assignee"]) if req.assignee is not None else d["assignee"]
        due_at=req.due_at if req.due_at is not None else d["due_at"]
        if status not in {"open","assigned","in_progress","waiting","resolved","closed"}: raise HTTPException(400,"Invalid ticket status")
        if priority not in {"low","medium","high","critical"}: raise HTTPException(400,"Invalid priority")
        resolved=d["resolved_at"];closed=d["closed_at"];ts=now()
        if status=="resolved" and not resolved: resolved=ts
        if status=="closed" and not closed: closed=ts
        c.execute("""UPDATE tickets SET title=?,description=?,status=?,priority=?,assignee=?,due_at=?,resolved_at=?,closed_at=?,updated_at=? WHERE id=?""",
                  (title,description,status,priority,assignee,due_at,resolved,closed,ts,ticket_id))
        if d.get("calendar_event_id"):
            calendar_title=(f"✓ {d['ticket_number']} · {title}" if status in {"resolved","closed"} else f"{d['ticket_number']} · {title}")
            calendar_color="green" if status in {"resolved","closed"} else {"critical":"red","high":"orange","medium":"blue","low":"green"}.get(priority,"blue")
            c.execute("UPDATE calendar_events SET title=?,description=?,color=?,updated_at=? WHERE id=?",(calendar_title,description,calendar_color,ts,d["calendar_event_id"]))
        audit(c,user["username"],"ticket_updated",d["ticket_number"],json.dumps({"status":status,"priority":priority,"assignee":assignee}),client_ip(request))
        out=c.execute("SELECT * FROM tickets WHERE id=?",(ticket_id,)).fetchone()
    return dict(out)

@app.post(f"{router_prefix}/tickets/{{ticket_id}}/notes")
def ticket_add_note(ticket_id: int, req: TicketNoteRequest, request: Request, user=Depends(require_permission("operate"))):
    note=req.note.strip()
    if not note: raise HTTPException(400,"Ticket note cannot be empty")
    with db() as c:
        ticket=c.execute("SELECT * FROM tickets WHERE id=?",(ticket_id,)).fetchone()
        if not ticket: raise HTTPException(404,"Ticket not found")
        c.execute("INSERT INTO ticket_notes(ticket_id,note,author,created_at) VALUES(?,?,?,?)",(ticket_id,note[:12000],user["username"],now()))
        c.execute("UPDATE tickets SET updated_at=? WHERE id=?",(now(),ticket_id))
        audit(c,user["username"],"ticket_note_added",ticket["ticket_number"],note[:500],client_ip(request))
    return {"ok":True}

@app.post(f"{router_prefix}/tickets/{{ticket_id}}/schedule")
def ticket_schedule(ticket_id: int, req: TicketScheduleRequest, request: Request, user=Depends(require_permission("operate"))):
    start=_calendar_parse_iso(req.start_at,"start time");end=_calendar_parse_iso(req.end_at,"end time")
    if end<start: raise HTTPException(400,"End time must be after start time")
    with db() as c:
        ticket=c.execute("SELECT * FROM tickets WHERE id=?",(ticket_id,)).fetchone()
        if not ticket: raise HTTPException(404,"Ticket not found")
        color={"critical":"red","high":"orange","medium":"blue","low":"green"}.get(ticket["priority"],"blue")
        ts=now()
        if ticket["calendar_event_id"]:
            c.execute("""UPDATE calendar_events SET title=?,description=?,start_at=?,end_at=?,all_day=?,color=?,updated_at=? WHERE id=?""",
                      (f"{ticket['ticket_number']} · {ticket['title']}",ticket["description"],req.start_at,req.end_at,1 if req.all_day else 0,color,ts,ticket["calendar_event_id"]))
            eid=ticket["calendar_event_id"]
        else:
            cur=c.execute("""INSERT INTO calendar_events(title,description,location,start_at,end_at,all_day,color,source,external_uid,external_readonly,created_by,created_at,updated_at)
                             VALUES(?,?,?,?,?,?,?,'ticket',?,0,?,?,?)""",
                          (f"{ticket['ticket_number']} · {ticket['title']}",ticket["description"],ticket["device_name"],req.start_at,req.end_at,1 if req.all_day else 0,color,str(ticket_id),user["username"],ts,ts))
            eid=cur.lastrowid
            c.execute("UPDATE tickets SET calendar_event_id=?,due_at=?,updated_at=? WHERE id=?",(eid,req.end_at,ts,ticket_id))
        audit(c,user["username"],"ticket_scheduled",ticket["ticket_number"],json.dumps({"calendar_event_id":eid,"start_at":req.start_at,"end_at":req.end_at}),client_ip(request))
    return {"ok":True,"calendar_event_id":eid}

def _delete_ticket_rows(c, ticket_ids: list[int]) -> list[dict]:
    clean=sorted({int(x) for x in ticket_ids if int(x)>0})
    if not clean:
        return []
    marks=','.join('?' for _ in clean)
    rows=[dict(r) for r in c.execute(f"SELECT * FROM tickets WHERE id IN ({marks})",clean).fetchall()]
    if not rows:
        return []
    event_ids=[int(r['calendar_event_id']) for r in rows if r.get('calendar_event_id')]
    if event_ids:
        emarks=','.join('?' for _ in event_ids)
        c.execute(f"DELETE FROM calendar_events WHERE id IN ({emarks})",event_ids)
    actual=[int(r['id']) for r in rows]
    tmarks=','.join('?' for _ in actual)
    c.execute(f"DELETE FROM ticket_notes WHERE ticket_id IN ({tmarks})",actual)
    c.execute(f"DELETE FROM tickets WHERE id IN ({tmarks})",actual)
    return rows

@app.delete(f"{router_prefix}/tickets/{{ticket_id}}")
def ticket_delete(ticket_id: int, request: Request, user=Depends(require_admin)):
    with db() as c:
        rows=_delete_ticket_rows(c,[ticket_id])
        if not rows: raise HTTPException(404,"Ticket not found")
        row=rows[0]
        audit(c,user["username"],"ticket_deleted",row.get("ticket_number") or str(ticket_id),json.dumps({"title":row.get("title"),"status":row.get("status")})[:1000],client_ip(request))
    return {"ok":True,"deleted":1}

@app.post(f"{router_prefix}/tickets/bulk-delete")
def ticket_bulk_delete(req: TicketBulkDeleteRequest, request: Request, user=Depends(require_admin)):
    ids=sorted({int(x) for x in req.ticket_ids if int(x)>0})
    if not ids: raise HTTPException(400,"Select at least one ticket")
    if len(ids)>200: raise HTTPException(400,"A maximum of 200 tickets can be deleted at once")
    with db() as c:
        rows=_delete_ticket_rows(c,ids)
        audit(c,user["username"],"tickets_bulk_deleted",details=json.dumps({"requested":len(ids),"deleted":len(rows),"ticket_numbers":[r.get("ticket_number") for r in rows]})[:2000],ip=client_ip(request))
    return {"ok":True,"deleted":len(rows)}

@app.post(f"{router_prefix}/tickets/delete-old")
def ticket_delete_old(req: TicketDeleteOldRequest, request: Request, user=Depends(require_admin)):
    days=max(1,min(int(req.older_than_days),3650))
    cutoff=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).isoformat()
    with db() as c:
        rows=c.execute("""SELECT * FROM tickets
                          WHERE status IN ('resolved','closed')
                            AND COALESCE(closed_at,resolved_at,updated_at) < ?
                          ORDER BY id""",(cutoff,)).fetchall()
        ids=[int(r['id']) for r in rows]
        deleted=_delete_ticket_rows(c,ids) if ids else []
        audit(c,user["username"],"old_tickets_deleted",details=json.dumps({"older_than_days":days,"cutoff":cutoff,"deleted":len(deleted),"ticket_numbers":[r.get("ticket_number") for r in deleted]})[:2000],ip=client_ip(request))
    return {"ok":True,"deleted":len(deleted),"older_than_days":days,"cutoff":cutoff}

@app.post(f"{router_prefix}/tickets/{{ticket_id}}/close")
def ticket_close(ticket_id: int, req: TicketCloseRequest, request: Request, user=Depends(require_permission("operate"))):
    with db() as c:
        ticket=c.execute("SELECT * FROM tickets WHERE id=?",(ticket_id,)).fetchone()
        if not ticket: raise HTTPException(404,"Ticket not found")
        ts=now()
        if req.note.strip():
            c.execute("INSERT INTO ticket_notes(ticket_id,note,author,created_at) VALUES(?,?,?,?)",(ticket_id,req.note.strip()[:12000],user["username"],ts))
        c.execute("UPDATE tickets SET status='closed',closed_at=?,updated_at=? WHERE id=?",(ts,ts,ticket_id))
        if ticket["calendar_event_id"]:
            c.execute("UPDATE calendar_events SET title=?,color='green',updated_at=? WHERE id=?",(f"✓ {ticket['ticket_number']} · {ticket['title']}",ts,ticket["calendar_event_id"]))
        if req.resolve_linked_finding and ticket["linked_type"]=="event_finding" and ticket["linked_id"]:
            c.execute("UPDATE event_findings SET status='resolved',resolved_at=? WHERE id=?",(ts,ticket["linked_id"]))
        if req.resolve_linked_finding and ticket["linked_type"]=="network_finding" and ticket["linked_id"]:
            c.execute("UPDATE network_issues SET status='resolved',resolved_at=?,last_seen=last_seen WHERE id=?",(ts,ticket["linked_id"]))
        audit(c,user["username"],"ticket_closed",ticket["ticket_number"],json.dumps({"resolve_linked_finding":req.resolve_linked_finding,"note":req.note[:500]}),client_ip(request))
    return {"ok":True}

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
<title>GODSEYE — Monitoring</title><script>(function(){try{const saved=localStorage.getItem('godseye_theme');const dark=saved==='dark'||(!saved&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=dark?'dark':'light'}catch(e){document.documentElement.dataset.theme='light'}})();</script><style>
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


/* v3.9 — polished per-device traffic collection */
.traffic-collection-panel{overflow:visible}
.traffic-collection-head{padding:18px 20px;align-items:flex-start;background:linear-gradient(180deg,#fff,#fbfdff)}
.traffic-title-row{display:flex;align-items:center;gap:11px}
.traffic-title-icon{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;background:#eaf4ff;color:#1378de;font-size:18px;box-shadow:inset 0 0 0 1px #d7eafe}
.traffic-collection-head h2{font-size:15px;margin:0 0 4px}
.traffic-state{display:inline-flex;align-items:center;gap:7px;border:1px solid #dce5ef;background:#f7fafc;color:#53667c;border-radius:999px;padding:6px 10px;font-size:10px;font-weight:800;letter-spacing:.03em;white-space:nowrap}
.traffic-state:before{content:"";width:7px;height:7px;border-radius:50%;background:#94a3b8}
.traffic-state.success{background:#ecfdf5;border-color:#caefdf;color:#0d865b}.traffic-state.success:before{background:#13a36e}
.traffic-state.failed{background:#fff1f2;border-color:#ffd7dc;color:#c53b52}.traffic-state.failed:before{background:#e64760}
.traffic-state.waiting_profile,.traffic-state.awaiting_sensor,.traffic-state.configured{background:#fff8e8;border-color:#f6e2aa;color:#9a6906}.traffic-state.waiting_profile:before,.traffic-state.awaiting_sensor:before,.traffic-state.configured:before{background:#e9a314}
.traffic-summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;padding:16px 20px 0}
.traffic-summary-card{border:1px solid #e2e9f1;border-radius:10px;padding:13px 14px;background:#fff;min-width:0}
.traffic-summary-card .k{font-size:9px;color:#7a899d;text-transform:uppercase;letter-spacing:.065em}
.traffic-summary-card .v{font-size:20px;font-weight:760;color:#1d2c40;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.traffic-summary-card .sub{font-size:10px;color:#8a98aa;margin-top:3px}
.traffic-setup{padding:18px 20px 20px}
.traffic-section-label{font-size:10px;font-weight:800;color:#5e7087;text-transform:uppercase;letter-spacing:.07em;margin:0 0 10px}
.traffic-source-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.traffic-source-card{appearance:none;text-align:left;border:1px solid #dce5ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:14px;padding:15px;cursor:pointer;transition:.16s ease;min-height:222px;color:#31445c;box-shadow:0 5px 18px rgba(24,53,82,.055);position:relative;overflow:hidden}
.traffic-source-card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:transparent;transition:.16s ease}
.traffic-source-card:hover{border-color:#9cc8f8;background:#fff;transform:translateY(-2px);box-shadow:0 10px 26px rgba(24,73,119,.1)}
.traffic-source-card.active{border-color:#2789f4;background:linear-gradient(180deg,#f7fbff,#f0f7ff);box-shadow:0 0 0 2px rgba(22,124,240,.09),0 10px 24px rgba(24,91,153,.09)}
.traffic-source-card.active:before{background:#167cf0}
.traffic-source-top{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:9px}
.traffic-source-icon{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:#eef6ff;color:#167cf0;font-size:17px;border:1px solid #dcecff}
.traffic-source-card.active .traffic-source-icon{background:#167cf0;color:#fff;border-color:#167cf0}
.traffic-source-kind{font-size:8px;font-weight:800;letter-spacing:.075em;color:#91a0b2}
.traffic-source-name{font-size:13px;font-weight:780;color:#20354d;margin-top:13px}
.traffic-source-desc{font-size:10px;color:#718399;line-height:1.48;margin-top:5px;min-height:44px}
.traffic-source-divider{height:1px;background:#edf2f7;margin:12px 0 10px}
.traffic-source-meta{display:grid;gap:5px;font-size:9px;color:#6f8196;line-height:1.35}
.traffic-source-meta span{display:flex;justify-content:space-between;gap:8px}.traffic-source-meta b{color:#41566f;font-weight:750}
.traffic-source-foot{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:12px;color:#8a99aa;font-size:8px}
.traffic-source-tag{display:inline-flex;align-items:center;border:1px solid #dce6f0;background:#f5f8fb;color:#60758d;border-radius:999px;padding:4px 7px;font-weight:800}
.traffic-source-tag.recommended{background:#eaf7f1;border-color:#ccebdc;color:#23815d}.traffic-source-tag.advanced{background:#fff6e8;border-color:#f0ddb7;color:#9b6b18}
.traffic-selected-check{display:none;width:20px;height:20px;border-radius:50%;background:#167cf0;color:#fff;place-items:center;font-size:10px;font-weight:900}
.traffic-source-card.active .traffic-selected-check{display:grid}
.traffic-config-shell{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(260px,.9fr);gap:14px;margin-top:15px}
.traffic-config-card,.traffic-help-card{border:1px solid #e3eaf2;border-radius:10px;background:#fbfdff;padding:14px}
.traffic-config-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.traffic-config-grid label{display:flex;flex-direction:column;gap:6px;font-size:10px;color:#64758a;font-weight:650}
.traffic-config-grid .full{grid-column:1/-1}
.traffic-config-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:13px}
.traffic-help-card{background:linear-gradient(180deg,#f8fbff,#f4f8fc)}
.traffic-help-title{display:flex;align-items:center;gap:8px;font-size:11px;font-weight:760;color:#30465f}
.traffic-help-copy{font-size:10px;line-height:1.55;color:#66788d;margin-top:8px}
.traffic-help-require{margin-top:9px;padding:9px 10px;border-radius:8px;background:#fff;border:1px solid #e1e9f2;font-size:9px;line-height:1.45;color:#5f7288}
.traffic-usage-head{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:13px 20px;border-top:1px solid #e8eef5;border-bottom:1px solid #edf2f7;background:#fcfdff}
.traffic-usage-head h3{font-size:12px;margin:0;color:#2b3f57}
.traffic-usage-head .muted{font-size:10px}
.traffic-table-wrap{overflow:auto}
.traffic-table-wrap table th{white-space:nowrap}
.traffic-device-name{font-weight:700;color:#2e435c}
.traffic-source-chip{display:inline-flex;align-items:center;gap:5px;border-radius:999px;background:#eef5fd;color:#326493;padding:4px 7px;font-size:9px;font-weight:700}
.traffic-empty{padding:32px 20px!important}
.traffic-empty-icon{font-size:22px;display:block;margin-bottom:7px;opacity:.65}
@media(max-width:1100px){.traffic-source-grid{grid-template-columns:repeat(2,1fr)}.traffic-summary-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:760px){.traffic-config-shell{grid-template-columns:1fr}.traffic-config-grid{grid-template-columns:1fr}.traffic-config-grid .full{grid-column:auto}.traffic-source-grid{grid-template-columns:1fr 1fr}.traffic-collection-head{flex-direction:column;gap:10px}.traffic-summary-grid{grid-template-columns:1fr 1fr}}
@media(max-width:480px){.traffic-source-grid,.traffic-summary-grid{grid-template-columns:1fr}}
.device-link{background:none!important;border:0!important;padding:0!important;color:#1565c0!important;font-weight:700;cursor:pointer;text-align:left}.device-link:hover{text-decoration:underline}.device-page-head{display:flex;align-items:center;gap:12px}.back-btn{display:inline-flex;align-items:center;gap:7px;border:1px solid #d8e0e9!important;background:#fff!important;color:#2d4665!important}.device-detail-shell{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(300px,.65fr);gap:16px}.device-hero-card{padding:18px}.kpi-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:14px}.kpi{border:1px solid #e4eaf1;border-radius:10px;padding:12px;background:#fafcff}.kpi .k{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#7b889a}.kpi .v{font-size:17px;font-weight:750;margin-top:4px}.stack{display:grid;gap:16px}.chart-empty{height:160px;display:grid;place-items:center;color:#7c8ba0}.dashboard-table tbody tr{cursor:pointer}.dashboard-table tbody tr:hover{background:#f4f8fd}.panel-subtle{padding:12px 16px;border-top:1px solid #eef2f6;font-size:11px;color:#738197}.traffic-axis{font-size:9px;fill:#8795a8}.activity-row button{all:unset;cursor:pointer}.activity-row button:hover .activity-title{text-decoration:underline}.intel-modal-card{display:none!important}.dashboard-statusline{display:flex;gap:14px;align-items:center;flex-wrap:wrap;font-size:11px;color:#748197}.status-pill{display:inline-flex;align-items:center;gap:6px}.status-pill::before{content:"";width:7px;height:7px;border-radius:50%;background:#22a06b}.status-pill.warn::before{background:#f59e0b}
.sortable-head{cursor:pointer;user-select:none;position:relative;padding-right:24px!important}.sortable-head:hover{color:#235f9f;background:#f7faff}.sortable-head::after{content:"↕";position:absolute;right:8px;opacity:.35;font-size:10px}.sortable-head.sort-asc::after{content:"↑";opacity:1}.sortable-head.sort-desc::after{content:"↓";opacity:1}.protected-audit{background:#fff8e8}.protected-audit td:first-child{box-shadow:inset 3px 0 0 #f2a51a}.admin-only{display:none}.admin-visible{display:inline-flex}
@media(max-width:1000px){.device-detail-shell{grid-template-columns:1fr}.kpi-row{grid-template-columns:repeat(2,1fr)}}

.device-icon{width:38px;height:38px;display:inline-flex;align-items:center;justify-content:center;flex:0 0 38px}.device-icon img{width:36px;height:36px;object-fit:contain;display:block;filter:drop-shadow(0 2px 2px rgba(18,38,63,.18))}.device-icon-modal{position:fixed!important;inset:0!important;z-index:5000!important;place-items:center!important;background:rgba(7,16,28,.62)!important;padding:24px!important;overflow:auto!important}.device-icon-dialog{width:min(720px,calc(100vw - 32px))!important;max-width:720px!important;max-height:calc(100vh - 48px)!important;overflow:auto!important;padding:0!important;border:1px solid #d8e3ef;border-radius:13px!important;box-shadow:0 26px 90px rgba(2,12,27,.34)!important}.device-icon-dialog .modal-head{padding:18px 20px 12px;border-bottom:1px solid #edf2f7}.device-icon-dialog .modal-form{display:block;margin:0;padding:0 20px 18px}.device-icon-summary{display:flex;align-items:center;gap:14px;padding:14px 0}.device-icon-summary-art{width:72px;height:64px;border:1px solid #dce6f1;border-radius:10px;background:linear-gradient(180deg,#fff,#f6f9fc);display:grid;place-items:center}.device-icon-summary-art img{width:58px;height:58px;object-fit:contain;filter:drop-shadow(0 3px 3px rgba(17,39,64,.2))}.device-icon-summary-name{font-size:16px;font-weight:750;color:#0b6ddd}.device-icon-summary-meta{font-size:12px;color:#64768d;line-height:1.5}.device-icon-tabs{display:flex;gap:24px;border-bottom:1px solid #e5edf5;margin-bottom:14px;overflow:auto}.device-icon-tab{border:0;background:transparent;padding:10px 2px 9px;color:#61738b;font-size:11px;white-space:nowrap;cursor:pointer;border-bottom:2px solid transparent}.device-icon-tab.active{color:#0d74f5;border-bottom-color:#0d74f5;font-weight:700}.device-icon-picker{display:grid;grid-template-columns:repeat(5,minmax(96px,1fr));gap:10px;max-height:390px;overflow:auto;padding:2px}.device-icon-choice{position:relative;border:1px solid #d8e3ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:9px;padding:9px 6px 8px;cursor:pointer;text-align:center;color:#30445e;font-size:10px;min-height:92px}.device-icon-choice:hover{border-color:#86bdfb;background:#f7fbff}.device-icon-choice.selected{border:2px solid #0d74f5;padding:8px 5px 7px;box-shadow:0 0 0 2px rgba(13,116,245,.09)}.device-icon-choice.selected:after{content:'✓';position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%;background:#0d74f5;color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.device-icon-choice img{width:66px;height:58px;display:block;object-fit:contain;margin:0 auto 5px;filter:drop-shadow(0 3px 3px rgba(18,38,63,.2))}.device-icon-custom{border-top:1px solid #e4ebf3;margin-top:14px;padding-top:13px}.custom-icon-preview{width:58px;height:58px;object-fit:contain;border:1px solid #d8e3ef;border-radius:8px;background:#fff;padding:4px}.icon-upload-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.device-icon-dialog .modal-actions{display:flex;justify-content:flex-end;gap:8px;border-top:1px solid #edf2f7;padding-top:14px;margin-top:14px}@media(max-width:700px){.device-icon-modal{padding:10px!important;align-items:center!important}.device-icon-dialog{max-height:calc(100vh - 20px)!important}.device-icon-picker{grid-template-columns:repeat(3,1fr)}.device-icon-tabs{gap:14px}.device-icon-summary-art{width:60px;height:56px}.device-icon-summary-art img{width:48px;height:48px}}

/* standalone dark surfaces v4.1 */

[data-theme="dark"]{color-scheme:dark}
[data-theme="dark"] body{background:#0b1119!important;color:#f1f6fc!important}
[data-theme="dark"] .main,[data-theme="dark"] .wrap{background:#0b1119!important;color:#f1f6fc!important}
[data-theme="dark"] .headerbar,[data-theme="dark"] .top{background:#0c131d!important;border-color:#263244!important;color:#f1f6fc!important}
[data-theme="dark"] h1,[data-theme="dark"] h2,[data-theme="dark"] h3,[data-theme="dark"] strong,[data-theme="dark"] b{color:#fbfdff!important}
[data-theme="dark"] .muted,[data-theme="dark"] p{color:#bdcada!important}
[data-theme="dark"] .tool-card,[data-theme="dark"] .panel,[data-theme="dark"] .card,[data-theme="dark"] .modal-card,
[data-theme="dark"] .monitor-summary-card,[data-theme="dark"] .detail-card{
 background:#111a25!important;border-color:#2b3a4e!important;color:#f1f6fc!important;box-shadow:0 5px 18px rgba(0,0,0,.16)!important
}
[data-theme="dark"] .tool-card:hover,[data-theme="dark"] .card:hover{background:#172334!important;border-color:#405772!important}
[data-theme="dark"] .tool-card h2,[data-theme="dark"] .tool-card h3{color:#fbfdff!important}
[data-theme="dark"] .tool-card p{color:#bdcada!important}
[data-theme="dark"] .tool-icon{background:#132d49!important;color:#7dc2ff!important}
[data-theme="dark"] .input,[data-theme="dark"] input,[data-theme="dark"] textarea,[data-theme="dark"] select,[data-theme="dark"] .filter{
 background:#0d1621!important;border-color:#304056!important;color:#f1f6fc!important
}
[data-theme="dark"] .btn,[data-theme="dark"] button{background:#152131!important;border-color:#304056!important;color:#f1f6fc!important}
[data-theme="dark"] .btn:hover,[data-theme="dark"] button:hover{background:#1a293b!important}
[data-theme="dark"] .btn.warn,[data-theme="dark"] .primary{background:#167cf0!important;color:#fff!important;border-color:#167cf0!important}
[data-theme="dark"] .result,[data-theme="dark"] pre,[data-theme="dark"] code{background:#09121c!important;border-color:#2a3a4f!important;color:#edf5fc!important}
[data-theme="dark"] table{color:#f1f6fc!important}
[data-theme="dark"] th{color:#b7c5d6!important;background:#0f1823!important}
[data-theme="dark"] td{color:#f0f5fb!important;border-color:#263244!important}
[data-theme="dark"] .security-note{background:#11243a!important;border-color:#274866!important;color:#cfe5f8!important}
[data-theme="dark"] .back-btn,[data-theme="dark"] .back{background:#152131!important;border-color:#304056!important;color:#e7eff8!important}
[data-theme="dark"] .identity-input,[data-theme="dark"] .identity-select{background:#0d1621!important;border-color:#304056!important;color:#f1f6fc!important}
[data-theme="dark"] .detail-device-icon,[data-theme="dark"] .custom-icon-preview{background:#111a25!important;border-color:#2b3a4e!important}

/* v4.8 standalone monitoring Pi-hole blue */
html[data-theme="dark"] .monitor-summary-card .k,
html[data-theme="dark"] .monitor-summary-card:not(.good):not(.bad) .v,
html[data-theme="dark"] .monitor-target,
html[data-theme="dark"] .monitor-type-badge{color:#9cc9f5!important}
html[data-theme="dark"] .monitor-type-badge{background:#142438!important;border-color:#2e4d70!important}
html[data-theme="dark"] .monitor-summary-card.good .v{color:#35d391!important}
html[data-theme="dark"] .monitor-summary-card.bad .v{color:#ff6278!important}
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
<title>GODSEYE — Network Tools</title><div id="standaloneToolsHelp" class="standalone-help-pop" style="display:none"><div class="standalone-help-card"><div class="standalone-help-head"><span>Network Tools</span><button type="button" onclick="document.getElementById('standaloneToolsHelp').style.display='none'" aria-label="Close help">×</button></div><div class="standalone-help-body">Diagnostics and management tools for your local network.</div></div></div><script>(function(){try{const saved=localStorage.getItem('godseye_theme');const dark=saved==='dark'||(!saved&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=dark?'dark':'light'}catch(e){document.documentElement.dataset.theme='light'}})();</script>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033}*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#172033}.layout{display:flex;min-height:100vh}.side{width:216px;background:#07101c;border-right:1px solid #18283b;position:sticky;top:0;height:100vh;display:flex;flex-direction:column}.brand{padding:20px 18px;border-bottom:1px solid #18283b;display:flex;align-items:center;gap:10px}.brand b{display:block;color:#fff;letter-spacing:.1em;font-size:18px}.brand small{display:block;color:#7890ad;font-size:9px;letter-spacing:.08em;margin-top:2px}.eye-logo{width:48px;height:31px;display:block}.nav{padding:12px 0;flex:1}.nav-title{color:#637991;font-size:10px;text-transform:uppercase;letter-spacing:.12em;padding:12px 18px 6px}.nav a{display:flex;align-items:center;gap:10px;padding:10px 16px;color:#a7b9ce;text-decoration:none;font-size:12px;border-left:3px solid transparent}.nav a:hover{background:#0d1b2b;color:#fff}.nav a.active{background:linear-gradient(90deg,#12335d,#0d223d);border-left-color:#1d8cf5;color:#fff}.navicon{width:18px;text-align:center}.side-footer{padding:14px 12px;border-top:1px solid #18283b}.back{display:block;text-align:center;background:#0f7df0;color:#fff;text-decoration:none;border-radius:7px;padding:9px;font-size:11px}.main{flex:1;min-width:0}.headerbar{height:58px;background:#fff;border-bottom:1px solid #e4eaf1;display:flex;justify-content:flex-end;align-items:center;padding:0 30px;gap:16px}.online{display:inline-flex;align-items:center;gap:6px;background:#ecfdf5;color:#11845b;border-radius:999px;padding:5px 10px;font-size:11px;font-weight:700}.online i{width:7px;height:7px;background:#14b87a;border-radius:50%}.user{font-size:12px;color:#35506f}.wrap{max-width:1450px;margin:auto;padding:28px 30px}.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin-bottom:20px}.hero h1{margin:0;font-size:26px}.hero p{margin:5px 0 0;color:#72819a;font-size:12px}.tool-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.tool-card{background:#fff;border:1px solid #e1e7ef;border-radius:10px;box-shadow:0 2px 7px rgba(25,45,70,.04);padding:18px}.tool-card h2{font-size:15px;margin:0 0 5px}.tool-card p{font-size:11px;color:#72819a;min-height:30px;margin:0 0 14px}.tool-icon{width:34px;height:34px;border-radius:9px;background:#e8f4ff;color:#0f7df0;display:grid;place-items:center;font-weight:800;margin-bottom:10px}.full{grid-column:1/-1}.panel{background:#fff;border:1px solid #e1e7ef;border-radius:10px;box-shadow:0 2px 7px rgba(25,45,70,.04);padding:18px;margin-top:16px}.panel h2{font-size:15px;margin:0 0 5px}.muted{color:#72819a;font-size:11px}.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px}.input{border:1px solid #d8e0e9;border-radius:7px;background:#fff;color:#25334a;padding:9px 10px;min-width:180px}.input.grow{flex:1}.btn{border:1px solid #0f7df0;background:#0f7df0;color:#fff;border-radius:7px;padding:9px 12px;cursor:pointer;font-size:11px}.btn.secondary{background:#fff;color:#35506f;border-color:#d8e0e9}.btn.warn{background:#c83b50;border-color:#c83b50}.result{margin-top:12px;background:#f7f9fc;border:1px solid #e5eaf1;border-radius:8px;padding:12px;min-height:45px;white-space:pre-wrap;word-break:break-word;font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#33465e}.result.ok{border-color:#b9ead5}.result.err{border-color:#f1c2ca;color:#a52e43}.status{font-size:10px;color:#72819a;margin-left:auto;align-self:center}.security-note{background:#f0f7ff;border:1px solid #cfe5fb;color:#365979;padding:10px 12px;border-radius:8px;font-size:10px;margin-top:14px}@media(max-width:1050px){.tool-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.layout{display:block}.side{width:100%;height:auto;position:sticky;top:0;z-index:20}.brand{display:none}.nav{display:flex;overflow:auto;padding:0}.nav-title{display:none}.nav a{white-space:nowrap;border-left:0;border-bottom:3px solid transparent}.nav a.active{border-left:0;border-bottom-color:#1d8cf5}.side-footer{display:none}.headerbar{height:48px;padding:0 14px}.wrap{padding:20px 14px}.tool-grid{grid-template-columns:1fr}.full{grid-column:auto}}

.device-link{background:none!important;border:0!important;padding:0!important;color:#1565c0!important;font-weight:700;cursor:pointer;text-align:left}.device-link:hover{text-decoration:underline}.device-page-head{display:flex;align-items:center;gap:12px}.back-btn{display:inline-flex;align-items:center;gap:7px;border:1px solid #d8e0e9!important;background:#fff!important;color:#2d4665!important}.device-detail-shell{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(300px,.65fr);gap:16px}.device-hero-card{padding:18px}.kpi-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:14px}.kpi{border:1px solid #e4eaf1;border-radius:10px;padding:12px;background:#fafcff}.kpi .k{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#7b889a}.kpi .v{font-size:17px;font-weight:750;margin-top:4px}.stack{display:grid;gap:16px}.chart-empty{height:160px;display:grid;place-items:center;color:#7c8ba0}.dashboard-table tbody tr{cursor:pointer}.dashboard-table tbody tr:hover{background:#f4f8fd}.panel-subtle{padding:12px 16px;border-top:1px solid #eef2f6;font-size:11px;color:#738197}.traffic-axis{font-size:9px;fill:#8795a8}.activity-row button{all:unset;cursor:pointer}.activity-row button:hover .activity-title{text-decoration:underline}.intel-modal-card{display:none!important}.dashboard-statusline{display:flex;gap:14px;align-items:center;flex-wrap:wrap;font-size:11px;color:#748197}.status-pill{display:inline-flex;align-items:center;gap:6px}.status-pill::before{content:"";width:7px;height:7px;border-radius:50%;background:#22a06b}.status-pill.warn::before{background:#f59e0b}
@media(max-width:1000px){.device-detail-shell{grid-template-columns:1fr}.kpi-row{grid-template-columns:repeat(2,1fr)}}

.device-icon{width:38px;height:38px;display:inline-flex;align-items:center;justify-content:center;flex:0 0 38px}.device-icon img{width:36px;height:36px;object-fit:contain;display:block;filter:drop-shadow(0 2px 2px rgba(18,38,63,.18))}.device-icon-modal{position:fixed!important;inset:0!important;z-index:5000!important;place-items:center!important;background:rgba(7,16,28,.62)!important;padding:24px!important;overflow:auto!important}.device-icon-dialog{width:min(720px,calc(100vw - 32px))!important;max-width:720px!important;max-height:calc(100vh - 48px)!important;overflow:auto!important;padding:0!important;border:1px solid #d8e3ef;border-radius:13px!important;box-shadow:0 26px 90px rgba(2,12,27,.34)!important}.device-icon-dialog .modal-head{padding:18px 20px 12px;border-bottom:1px solid #edf2f7}.device-icon-dialog .modal-form{display:block;margin:0;padding:0 20px 18px}.device-icon-summary{display:flex;align-items:center;gap:14px;padding:14px 0}.device-icon-summary-art{width:72px;height:64px;border:1px solid #dce6f1;border-radius:10px;background:linear-gradient(180deg,#fff,#f6f9fc);display:grid;place-items:center}.device-icon-summary-art img{width:58px;height:58px;object-fit:contain;filter:drop-shadow(0 3px 3px rgba(17,39,64,.2))}.device-icon-summary-name{font-size:16px;font-weight:750;color:#0b6ddd}.device-icon-summary-meta{font-size:12px;color:#64768d;line-height:1.5}.device-icon-tabs{display:flex;gap:24px;border-bottom:1px solid #e5edf5;margin-bottom:14px;overflow:auto}.device-icon-tab{border:0;background:transparent;padding:10px 2px 9px;color:#61738b;font-size:11px;white-space:nowrap;cursor:pointer;border-bottom:2px solid transparent}.device-icon-tab.active{color:#0d74f5;border-bottom-color:#0d74f5;font-weight:700}.device-icon-picker{display:grid;grid-template-columns:repeat(5,minmax(96px,1fr));gap:10px;max-height:390px;overflow:auto;padding:2px}.device-icon-choice{position:relative;border:1px solid #d8e3ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:9px;padding:9px 6px 8px;cursor:pointer;text-align:center;color:#30445e;font-size:10px;min-height:92px}.device-icon-choice:hover{border-color:#86bdfb;background:#f7fbff}.device-icon-choice.selected{border:2px solid #0d74f5;padding:8px 5px 7px;box-shadow:0 0 0 2px rgba(13,116,245,.09)}.device-icon-choice.selected:after{content:'✓';position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%;background:#0d74f5;color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.device-icon-choice img{width:66px;height:58px;display:block;object-fit:contain;margin:0 auto 5px;filter:drop-shadow(0 3px 3px rgba(18,38,63,.2))}.device-icon-custom{border-top:1px solid #e4ebf3;margin-top:14px;padding-top:13px}.custom-icon-preview{width:58px;height:58px;object-fit:contain;border:1px solid #d8e3ef;border-radius:8px;background:#fff;padding:4px}.icon-upload-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.device-icon-dialog .modal-actions{display:flex;justify-content:flex-end;gap:8px;border-top:1px solid #edf2f7;padding-top:14px;margin-top:14px}@media(max-width:700px){.device-icon-modal{padding:10px!important;align-items:center!important}.device-icon-dialog{max-height:calc(100vh - 20px)!important}.device-icon-picker{grid-template-columns:repeat(3,1fr)}.device-icon-tabs{gap:14px}.device-icon-summary-art{width:60px;height:56px}.device-icon-summary-art img{width:48px;height:48px}}

/* standalone dark surfaces v4.1 */

[data-theme="dark"]{color-scheme:dark}
[data-theme="dark"] body{background:#0b1119!important;color:#f1f6fc!important}
[data-theme="dark"] .main,[data-theme="dark"] .wrap{background:#0b1119!important;color:#f1f6fc!important}
[data-theme="dark"] .headerbar,[data-theme="dark"] .top{background:#0c131d!important;border-color:#263244!important;color:#f1f6fc!important}
[data-theme="dark"] h1,[data-theme="dark"] h2,[data-theme="dark"] h3,[data-theme="dark"] strong,[data-theme="dark"] b{color:#fbfdff!important}
[data-theme="dark"] .muted,[data-theme="dark"] p{color:#bdcada!important}
[data-theme="dark"] .tool-card,[data-theme="dark"] .panel,[data-theme="dark"] .card,[data-theme="dark"] .modal-card,
[data-theme="dark"] .monitor-summary-card,[data-theme="dark"] .detail-card{
 background:#111a25!important;border-color:#2b3a4e!important;color:#f1f6fc!important;box-shadow:0 5px 18px rgba(0,0,0,.16)!important
}
[data-theme="dark"] .tool-card:hover,[data-theme="dark"] .card:hover{background:#172334!important;border-color:#405772!important}
[data-theme="dark"] .tool-card h2,[data-theme="dark"] .tool-card h3{color:#fbfdff!important}
[data-theme="dark"] .tool-card p{color:#bdcada!important}
[data-theme="dark"] .tool-icon{background:#132d49!important;color:#7dc2ff!important}
[data-theme="dark"] .input,[data-theme="dark"] input,[data-theme="dark"] textarea,[data-theme="dark"] select,[data-theme="dark"] .filter{
 background:#0d1621!important;border-color:#304056!important;color:#f1f6fc!important
}
[data-theme="dark"] .btn,[data-theme="dark"] button{background:#152131!important;border-color:#304056!important;color:#f1f6fc!important}
[data-theme="dark"] .btn:hover,[data-theme="dark"] button:hover{background:#1a293b!important}
[data-theme="dark"] .btn.warn,[data-theme="dark"] .primary{background:#167cf0!important;color:#fff!important;border-color:#167cf0!important}
[data-theme="dark"] .result,[data-theme="dark"] pre,[data-theme="dark"] code{background:#09121c!important;border-color:#2a3a4f!important;color:#edf5fc!important}
[data-theme="dark"] table{color:#f1f6fc!important}
[data-theme="dark"] th{color:#b7c5d6!important;background:#0f1823!important}
[data-theme="dark"] td{color:#f0f5fb!important;border-color:#263244!important}
[data-theme="dark"] .security-note{background:#11243a!important;border-color:#274866!important;color:#cfe5f8!important}
[data-theme="dark"] .back-btn,[data-theme="dark"] .back{background:#152131!important;border-color:#304056!important;color:#e7eff8!important}
[data-theme="dark"] .identity-input,[data-theme="dark"] .identity-select{background:#0d1621!important;border-color:#304056!important;color:#f1f6fc!important}
[data-theme="dark"] .detail-device-icon,[data-theme="dark"] .custom-icon-preview{background:#111a25!important;border-color:#2b3a4e!important}
\n/* v4.9 standalone tools arrangement */\n.tools-layout-bar{display:none;gap:7px;align-items:center}.tools-layout-bar.show{display:flex}.tool-card.arrange-card{position:relative}.tools-arranging .tool-card{cursor:grab;outline:1px dashed rgba(156,201,245,.25)}.tools-arranging .tool-card:before{content:'⋮⋮';position:absolute;right:8px;top:8px;width:24px;height:21px;border-radius:7px;background:#0f7df0;color:#fff;display:grid;place-items:center;z-index:10}.tool-card.dragging{opacity:.42}.tool-card.drop-target{box-shadow:0 0 0 2px #0f7df0!important}@media(min-width:1051px){.tool-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important}}\n
/* v4.10 standalone header help */
.hero > div > p{display:none!important}
.standalone-help-btn{width:21px;height:21px;border-radius:50%;border:1px solid #4f91c9;background:#102c49;color:#9cc9f5;display:inline-grid;place-items:center;font-weight:900;font-size:11px;cursor:pointer;margin-left:7px}
.standalone-help-pop{position:fixed;inset:0;z-index:9999;background:rgba(2,7,12,.68);display:grid;place-items:start center;padding:84px 18px}
.standalone-help-card{width:min(520px,calc(100vw - 28px));background:#101923;border:1px solid #31445c;border-radius:13px;color:#f7fbff;box-shadow:0 26px 90px rgba(0,0,0,.52)}
.standalone-help-head{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid #29394d;font-weight:800}
.standalone-help-head button{width:29px;height:29px;border:1px solid #344960;border-radius:8px;background:#142131;color:#eef5fc;cursor:pointer}
.standalone-help-body{padding:16px;color:#d2dce8;font-size:11px;line-height:1.65}
</style></head><body><div class="layout">
<aside class="side"><div class="brand">__EYE_LOGO__<div><b>GODSEYE</b><small>NETWORK INTELLIGENCE</small></div></div><nav class="nav">
<div class="nav-title">Overview</div><a href="/">◉ <span>Dashboard</span></a><a href="/#devices">▣ <span>Devices</span></a><a href="/#network">⌘ <span>Network Map</span></a><a href="/monitoring">◔ <span>Monitoring</span></a><a href="/#findings">⚠ <span>Findings</span></a>
<div class="nav-title">Management</div><a class="active" href="/tools">⚒ <span>Tools</span></a><a href="/#integrations">⌘ <span>Integrations</span></a><a href="/#reports">▤ <span>Reports</span></a><a href="/#settings">⚙ <span>Settings</span></a></nav><div class="side-footer"><a class="back" href="/">Dashboard</a></div></aside>
<main class="main"><header class="headerbar"><span class="online"><i></i>Online</span><span class="user">admin ▾</span></header><div class="wrap">
<div class="hero"><div><div style="display:flex;align-items:center"><h1>Network Tools</h1><button type="button" class="standalone-help-btn" onclick="document.getElementById('standaloneToolsHelp').style.display='grid'" aria-label="More information about Network Tools">?</button></div><p>Diagnostics and management tools for your local network.</p></div><div style="display:flex;gap:9px;align-items:center"><span class="status">GODSEYE native tools</span><div id="toolsLayoutBar" class="tools-layout-bar"><button class="btn secondary" onclick="toggleStandaloneToolsArrange()">↕ Arrange Cards</button></div></div></div>
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
let toolsArrange=false,toolsDragged=null;
async function initStandaloneToolsLayout(){try{const me=await req('/api/v1/auth/me');if(me.role==='admin')document.getElementById('toolsLayoutBar')?.classList.add('show');const r=await req('/api/v1/ui/layouts');const order=r.layouts?.tools_standalone?.layout?.cards||[];const grid=document.querySelector('.tool-grid');const cards=[...grid.querySelectorAll(':scope > .tool-card')];cards.forEach((c,i)=>{c.dataset.layoutKey=(c.querySelector('h2')?.textContent||'tool-'+i).toLowerCase().replace(/[^a-z0-9]+/g,'-');c.classList.add('arrange-card')});const map=new Map(cards.map(c=>[c.dataset.layoutKey,c]));order.forEach(k=>{if(map.has(k))grid.appendChild(map.get(k))})}catch(e){}}
function toggleStandaloneToolsArrange(){toolsArrange=!toolsArrange;document.body.classList.toggle('tools-arranging',toolsArrange);document.querySelectorAll('.tool-card').forEach(c=>c.draggable=toolsArrange);const b=document.querySelector('#toolsLayoutBar button');if(b)b.textContent=toolsArrange?'✓ Done Arranging':'↕ Arrange Cards'}
document.addEventListener('dragstart',e=>{if(!toolsArrange)return;const c=e.target.closest('.tool-card');if(!c)return;toolsDragged=c;c.classList.add('dragging');e.dataTransfer.setData('text/plain',c.dataset.layoutKey)});
document.addEventListener('dragover',e=>{if(!toolsDragged)return;const c=e.target.closest('.tool-card');if(!c||c===toolsDragged)return;e.preventDefault();document.querySelectorAll('.drop-target').forEach(x=>x.classList.remove('drop-target'));c.classList.add('drop-target')});
document.addEventListener('drop',async e=>{if(!toolsDragged)return;const c=e.target.closest('.tool-card');if(!c||c===toolsDragged)return;e.preventDefault();const r=c.getBoundingClientRect();c.parentNode.insertBefore(toolsDragged,(e.clientY<r.top+r.height/2||e.clientX<r.left+r.width/2)?c:c.nextSibling);document.querySelectorAll('.drop-target').forEach(x=>x.classList.remove('drop-target'));const cards=[...document.querySelectorAll('.tool-grid > .tool-card')].map(x=>x.dataset.layoutKey);try{await req('/api/v1/ui/layouts/tools_standalone',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({layout:{cards}})})}catch(err){}});
document.addEventListener('dragend',()=>{toolsDragged?.classList.remove('dragging');toolsDragged=null;document.querySelectorAll('.drop-target').forEach(x=>x.classList.remove('drop-target'))});
setTimeout(initStandaloneToolsLayout,0);
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



DEVICE_DETAIL_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GODSEYE — Device</title><script>(function(){try{const saved=localStorage.getItem('godseye_theme');const dark=saved==='dark'||(!saved&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=dark?'dark':'light'}catch(e){document.documentElement.dataset.theme='light'}})();</script><style>
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;background:#f5f9fd;color:#17263c}.shell{min-height:100vh;display:grid;grid-template-columns:188px 1fr}.side{background:#07101c;color:#dce8f5;min-height:100vh;position:fixed;left:0;top:0;width:188px;padding:24px 8px}.brand{text-align:center;margin-bottom:34px}.brand svg{width:76px;height:46px}.brand b{display:block;color:#fff;letter-spacing:.16em;font-size:15px}.nav a{display:block;color:#c8d5e5;text-decoration:none;padding:10px 12px;border-radius:6px;font-size:12px;margin:3px 0}.nav a:hover,.nav a.active{background:#0d74f5;color:#fff}.main{grid-column:2;min-width:0}.top{height:58px;background:#fff;border-bottom:1px solid #e2eaf3;display:flex;justify-content:flex-end;align-items:center;padding:0 28px;gap:16px;font-size:12px}.online{background:#eaf9f2;color:#0c9562;border-radius:999px;padding:5px 10px}.wrap{padding:26px 24px 40px;max-width:1380px}.back{display:inline-flex;align-items:center;gap:7px;color:#0d66cf;text-decoration:none;font-weight:650;font-size:13px;margin-bottom:14px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;margin-bottom:16px}.hero h1{font-size:26px;margin:0}.muted{color:#73849a;font-size:12px}.status{border-radius:999px;padding:5px 10px;background:#eaf9f2;color:#07955e;font-size:11px}.grid{display:grid;grid-template-columns:minmax(0,2fr) minmax(280px,1fr);gap:14px}.stack{display:flex;flex-direction:column;gap:14px}.panel{background:#fff;border:1px solid #dce6f1;border-radius:7px;box-shadow:0 2px 8px rgba(27,64,102,.04);overflow:hidden}.panel-head{padding:13px 15px;border-bottom:1px solid #e6edf5;display:flex;justify-content:space-between;align-items:center}.panel-head h2{font-size:14px;margin:0}.panel-body{padding:15px}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.kpi{padding:12px;border:1px solid #e4ebf3;border-radius:6px}.kpi .v{font-size:21px;font-weight:760;margin-top:4px}.kv{display:grid;grid-template-columns:110px 1fr;gap:10px 14px;font-size:12px}.kv .k{color:#71839a}table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;border-bottom:1px solid #edf2f7;text-align:left;font-size:12px}th{font-size:10px;color:#72839a;text-transform:uppercase;background:#fbfdff}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{border:1px solid #ccd9e8;background:#fff;color:#24405f;padding:8px 11px;border-radius:6px;cursor:pointer}.btn.primary{background:#0d74f5;border-color:#0d74f5;color:#fff}.detail-device-icon{width:54px;height:54px;object-fit:contain;border:1px solid #dce6f1;border-radius:10px;background:#fff;padding:6px}.identity-input,.identity-select{width:100%;min-width:0;border:1px solid #d8e0e9;border-radius:6px;background:#fff;color:#25334a;padding:8px 9px;font:inherit}.identity-input:focus,.identity-select:focus{outline:2px solid #d9ecff;border-color:#0d74f5}.empty{padding:24px;color:#8090a4;text-align:center}.timeline{padding:12px 15px;border-bottom:1px solid #edf2f7;font-size:12px}.error{padding:14px;background:#fff1f1;color:#b52d3d;border:1px solid #ffd0d4;border-radius:6px}@media(max-width:900px){.shell{display:block}.side{position:relative;width:100%;min-height:auto}.main{grid-column:auto}.grid{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}}

.device-icon{width:38px;height:38px;display:inline-flex;align-items:center;justify-content:center;flex:0 0 38px}.device-icon img{width:36px;height:36px;object-fit:contain;display:block;filter:drop-shadow(0 2px 2px rgba(18,38,63,.18))}.device-icon-modal{position:fixed!important;inset:0!important;z-index:5000!important;place-items:center!important;background:rgba(7,16,28,.62)!important;padding:24px!important;overflow:auto!important}.device-icon-dialog{width:min(720px,calc(100vw - 32px))!important;max-width:720px!important;max-height:calc(100vh - 48px)!important;overflow:auto!important;padding:0!important;border:1px solid #d8e3ef;border-radius:13px!important;box-shadow:0 26px 90px rgba(2,12,27,.34)!important}.device-icon-dialog .modal-head{padding:18px 20px 12px;border-bottom:1px solid #edf2f7}.device-icon-dialog .modal-form{display:block;margin:0;padding:0 20px 18px}.device-icon-summary{display:flex;align-items:center;gap:14px;padding:14px 0}.device-icon-summary-art{width:72px;height:64px;border:1px solid #dce6f1;border-radius:10px;background:linear-gradient(180deg,#fff,#f6f9fc);display:grid;place-items:center}.device-icon-summary-art img{width:58px;height:58px;object-fit:contain;filter:drop-shadow(0 3px 3px rgba(17,39,64,.2))}.device-icon-summary-name{font-size:16px;font-weight:750;color:#0b6ddd}.device-icon-summary-meta{font-size:12px;color:#64768d;line-height:1.5}.device-icon-tabs{display:flex;gap:24px;border-bottom:1px solid #e5edf5;margin-bottom:14px;overflow:auto}.device-icon-tab{border:0;background:transparent;padding:10px 2px 9px;color:#61738b;font-size:11px;white-space:nowrap;cursor:pointer;border-bottom:2px solid transparent}.device-icon-tab.active{color:#0d74f5;border-bottom-color:#0d74f5;font-weight:700}.device-icon-picker{display:grid;grid-template-columns:repeat(5,minmax(96px,1fr));gap:10px;max-height:390px;overflow:auto;padding:2px}.device-icon-choice{position:relative;border:1px solid #d8e3ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:9px;padding:9px 6px 8px;cursor:pointer;text-align:center;color:#30445e;font-size:10px;min-height:92px}.device-icon-choice:hover{border-color:#86bdfb;background:#f7fbff}.device-icon-choice.selected{border:2px solid #0d74f5;padding:8px 5px 7px;box-shadow:0 0 0 2px rgba(13,116,245,.09)}.device-icon-choice.selected:after{content:'✓';position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%;background:#0d74f5;color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.device-icon-choice img{width:66px;height:58px;display:block;object-fit:contain;margin:0 auto 5px;filter:drop-shadow(0 3px 3px rgba(18,38,63,.2))}.device-icon-custom{border-top:1px solid #e4ebf3;margin-top:14px;padding-top:13px}.custom-icon-preview{width:58px;height:58px;object-fit:contain;border:1px solid #d8e3ef;border-radius:8px;background:#fff;padding:4px}.icon-upload-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.device-icon-dialog .modal-actions{display:flex;justify-content:flex-end;gap:8px;border-top:1px solid #edf2f7;padding-top:14px;margin-top:14px}@media(max-width:700px){.device-icon-modal{padding:10px!important;align-items:center!important}.device-icon-dialog{max-height:calc(100vh - 20px)!important}.device-icon-picker{grid-template-columns:repeat(3,1fr)}.device-icon-tabs{gap:14px}.device-icon-summary-art{width:60px;height:56px}.device-icon-summary-art img{width:48px;height:48px}}

/* standalone dark surfaces v4.1 */

[data-theme="dark"]{color-scheme:dark}
[data-theme="dark"] body{background:#0b1119!important;color:#f1f6fc!important}
[data-theme="dark"] .main,[data-theme="dark"] .wrap{background:#0b1119!important;color:#f1f6fc!important}
[data-theme="dark"] .headerbar,[data-theme="dark"] .top{background:#0c131d!important;border-color:#263244!important;color:#f1f6fc!important}
[data-theme="dark"] h1,[data-theme="dark"] h2,[data-theme="dark"] h3,[data-theme="dark"] strong,[data-theme="dark"] b{color:#fbfdff!important}
[data-theme="dark"] .muted,[data-theme="dark"] p{color:#bdcada!important}
[data-theme="dark"] .tool-card,[data-theme="dark"] .panel,[data-theme="dark"] .card,[data-theme="dark"] .modal-card,
[data-theme="dark"] .monitor-summary-card,[data-theme="dark"] .detail-card{
 background:#111a25!important;border-color:#2b3a4e!important;color:#f1f6fc!important;box-shadow:0 5px 18px rgba(0,0,0,.16)!important
}
[data-theme="dark"] .tool-card:hover,[data-theme="dark"] .card:hover{background:#172334!important;border-color:#405772!important}
[data-theme="dark"] .tool-card h2,[data-theme="dark"] .tool-card h3{color:#fbfdff!important}
[data-theme="dark"] .tool-card p{color:#bdcada!important}
[data-theme="dark"] .tool-icon{background:#132d49!important;color:#7dc2ff!important}
[data-theme="dark"] .input,[data-theme="dark"] input,[data-theme="dark"] textarea,[data-theme="dark"] select,[data-theme="dark"] .filter{
 background:#0d1621!important;border-color:#304056!important;color:#f1f6fc!important
}
[data-theme="dark"] .btn,[data-theme="dark"] button{background:#152131!important;border-color:#304056!important;color:#f1f6fc!important}
[data-theme="dark"] .btn:hover,[data-theme="dark"] button:hover{background:#1a293b!important}
[data-theme="dark"] .btn.warn,[data-theme="dark"] .primary{background:#167cf0!important;color:#fff!important;border-color:#167cf0!important}
[data-theme="dark"] .result,[data-theme="dark"] pre,[data-theme="dark"] code{background:#09121c!important;border-color:#2a3a4f!important;color:#edf5fc!important}
[data-theme="dark"] table{color:#f1f6fc!important}
[data-theme="dark"] th{color:#b7c5d6!important;background:#0f1823!important}
[data-theme="dark"] td{color:#f0f5fb!important;border-color:#263244!important}
[data-theme="dark"] .security-note{background:#11243a!important;border-color:#274866!important;color:#cfe5f8!important}
[data-theme="dark"] .back-btn,[data-theme="dark"] .back{background:#152131!important;border-color:#304056!important;color:#e7eff8!important}
[data-theme="dark"] .identity-input,[data-theme="dark"] .identity-select{background:#0d1621!important;border-color:#304056!important;color:#f1f6fc!important}
[data-theme="dark"] .detail-device-icon,[data-theme="dark"] .custom-icon-preview{background:#111a25!important;border-color:#2b3a4e!important}
</style></head><body><div class="shell"><aside class="side"><div class="brand">__EYE_LOGO__<b>GODSEYE</b><div class="muted">LOCAL NETWORK INTELLIGENCE</div></div><nav class="nav"><a href="/#overview">⌂ &nbsp; Dashboard</a><a class="active" href="/#devices">▣ &nbsp; Devices</a><a href="/#network">⌘ &nbsp; Network Map</a><a href="/#monitoring">◷ &nbsp; Monitoring</a><a href="/#findings">! &nbsp; Findings</a><a href="/#tools">⌁ &nbsp; Tools</a><a href="/#integrations">⌘ &nbsp; Integrations</a><a href="/#reports">▤ &nbsp; Reports</a><a href="/#security">⚙ &nbsp; Settings</a></nav></aside><main class="main"><header class="top"><span class="online">● Online</span><span id="who">admin</span></header><div class="wrap"><a class="back" href="/#devices">← Back to Devices</a><div class="hero"><div style="display:flex;align-items:center;gap:12px"><img id="detailDeviceIcon" class="detail-device-icon" src="/assets/device-icons/other.svg" alt="Device icon"><div><h1 id="title">Device</h1><div class="muted" id="subtitle">Loading device intelligence…</div></div></div><div class="actions"><button class="btn" id="renameBtn" onclick="renameCurrentDevice()">Rename Device</button><span class="status" id="state">Loading</span></div></div><div id="content"><div class="panel"><div class="empty">Loading device intelligence…</div></div></div></div></main></div><datalist id="deviceTypeChoices"><option value="Router"><option value="PC"><option value="Laptop"><option value="Camera"><option value="Switch"><option value="Access Point"><option value="Phone"><option value="Tablet"><option value="Printer"><option value="Server"><option value="NAS"><option value="TV / Media"><option value="IoT"><option value="Smart Home"><option value="Game Console"><option value="Other"></datalist><script>
const DEVICE_ID=__DEVICE_ID__;const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const DEVICE_ICON_ASSET_VERSION='27';function deviceIconAsset(key){return '/assets/device-icons/'+String(key||'other')+'.svg?v='+DEVICE_ICON_ASSET_VERSION}
async function api(url,opt={}){const r=await fetch(url,opt);if(r.status===401){location.href='/#devices';throw new Error('Sign in required')}if(!r.ok)throw new Error(await r.text());return r.json()}function dt(v){try{return v?new Date(v).toLocaleString():'—'}catch(_){return '—'}}
function effectiveDetailIcon(d){const key=d&&d.icon_key;if(key&&key!=='auto')return key;const t=String(d&&d.device_type||'').toLowerCase();if(t.includes('firewall'))return'firewall';if(t.includes('modem'))return'modem';if(t.includes('patch panel'))return'patch-panel';if(t.includes('voip'))return'voip-phone';if(t.includes('router')||t.includes('gateway'))return'router';if(t.includes('switch'))return'switch';if(t.includes('access point')||t==='ap'||t.includes('wifi'))return'access-point';if(t.includes('laptop'))return'laptop';if(t==='pc'||t.includes('desktop')||t.includes('computer'))return'pc';if(t.includes('camera'))return'camera';if(t.includes('printer'))return'printer';if(t.includes('phone'))return'phone';if(t.includes('tablet'))return'tablet';if(t.includes('server'))return'server';if(t.includes('network storage'))return'network-storage';if(t.includes('nas')||t.includes('storage'))return'nas';if(t.includes('tv')||t.includes('media'))return'tv';if(t.includes('game')||t.includes('console'))return'game-console';if(t.includes('iot')||t.includes('smart')||t.includes('sensor')||t.includes('light'))return'iot';return'other'}
let CURRENT_DEVICE=null;async function load(){try{const me=await api('/api/v1/auth/me');document.getElementById('who').textContent=me.username;const r=await api('/api/v1/devices/'+DEVICE_ID+'/intelligence'),d=r.device||{};CURRENT_DEVICE=d;const detailIcon=document.getElementById('detailDeviceIcon');if(detailIcon)detailIcon.src=d.icon_data||deviceIconAsset(effectiveDetailIcon(d));const s=r.summary||{},events=(r.events||[]).slice(0,30),ips=(r.ip_history||[]).slice(0,20),sources=r.sources||[],issues=(r.issues||[]).filter(x=>x.status==='open');document.getElementById('title').textContent=d.name||d.hostname||'Unknown device';document.getElementById('subtitle').textContent=[d.ip||'No IP',d.mac||'No MAC',d.vendor||'Unknown vendor'].join(' · ');document.getElementById('state').textContent=d.status||'unknown';document.getElementById('content').innerHTML=`<div class="grid"><div class="stack"><section class="panel"><div class="panel-head"><h2>Device Overview</h2><div class="actions"><button class="btn primary" onclick="diagnose()">Diagnose</button><button class="btn" onclick="recheck()">Recheck</button></div></div><div class="panel-body"><div class="kpis"><div class="kpi"><div class="muted">Risk score</div><div class="v">${Number(s.risk_score||0)}/100</div></div><div class="kpi"><div class="muted">Evidence sources</div><div class="v">${Number(s.source_count||0)}</div></div><div class="kpi"><div class="muted">Known IPs</div><div class="v">${Number(s.known_ip_count||0)}</div></div><div class="kpi"><div class="muted">Open findings</div><div class="v">${Number(s.open_issue_count||0)}</div></div></div><div id="diag" class="muted" style="margin-top:12px"></div></div></section><section class="panel"><div class="panel-head"><h2>Recent Activity</h2></div><table><thead><tr><th>Time</th><th>Event</th><th>IP</th><th>Details</th></tr></thead><tbody>${events.length?events.map(x=>`<tr><td>${esc(dt(x.created_at))}</td><td>${esc(x.event_type||'event')}</td><td>${esc(x.ip||'—')}</td><td>${esc(x.details||'')}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">No activity recorded.</td></tr>'}</tbody></table></section><section class="panel"><div class="panel-head"><h2>IP History</h2></div><table><thead><tr><th>IP</th><th>Source</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>${ips.length?ips.map(x=>`<tr><td>${esc(x.ip||'—')}</td><td>${esc(x.source||'—')}</td><td>${esc(dt(x.first_seen))}</td><td>${esc(dt(x.last_seen))}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">No IP history yet.</td></tr>'}</tbody></table></section></div><div class="stack"><section class="panel"><div class="panel-head"><h2>Identity</h2><div class="actions"><a class="btn" href="/#devices">Change Icon in Inventory</a><button class="btn primary" id="saveIdentityBtn" onclick="saveIdentity()">Save Identity</button></div></div><div class="panel-body kv"><div class="k">Hostname</div><div><input id="identityHostname" class="identity-input" maxlength="253" value="${esc(d.hostname||'')}" placeholder="Enter hostname"></div><div class="k">IP address</div><div>${esc(d.ip||'—')}</div><div class="k">MAC address</div><div>${esc(d.mac||'—')}</div><div class="k">Vendor</div><div>${esc(d.vendor||'—')}</div><div class="k">Type</div><div><input id="identityType" class="identity-input" maxlength="80" list="deviceTypeChoices" value="${esc(d.device_type||'')}" placeholder="Router, PC, Camera, Switch…"></div><div class="k">Classification</div><div><select id="identityClassification" class="identity-select"><option value="new" ${d.classification==='new'?'selected':''}>New</option><option value="investigate" ${d.classification==='investigate'?'selected':''}>Investigate</option><option value="known" ${d.classification==='known'?'selected':''}>Known</option><option value="managed" ${d.classification==='managed'?'selected':''}>Managed</option><option value="ignored" ${d.classification==='ignored'?'selected':''}>Ignored</option></select></div><div class="k">First seen</div><div>${esc(dt(d.first_seen))}</div><div class="k">Last seen</div><div>${esc(dt(d.last_seen))}</div><div class="k">Update status</div><div id="identitySaveStatus" class="muted">Edit the fields above, then Save Identity.</div></div></section><section class="panel"><div class="panel-head"><h2>Evidence Sources</h2></div>${sources.length?sources.map(x=>`<div class="timeline"><b>${esc(x.source||'source')}</b><div class="muted">${esc(x.ip||'')} · ${esc(dt(x.last_seen))}</div></div>`).join(''):'<div class="empty">Inventory evidence only.</div>'}</section><section class="panel"><div class="panel-head"><h2>Open Findings</h2></div>${issues.length?issues.map(x=>`<div class="timeline"><b>${esc(x.title||x.issue_type||'Finding')}</b><div class="muted">${esc(x.recommendation||'')}</div></div>`).join(''):'<div class="empty">No open findings.</div>'}</section><section class="panel"><div class="panel-head"><h2>Recommendations</h2></div><div class="panel-body">${(r.recommendations||[]).map(x=>`<div class="timeline">${esc(x)}</div>`).join('')||'<div class="empty">No recommendations.</div>'}</div></section></div></div>`}catch(e){document.getElementById('content').innerHTML='<div class="error">Unable to load device: '+esc(e.message)+'</div>';document.getElementById('state').textContent='Unavailable'}}
function csrf(){const raw=(document.cookie.match('(?:^|; )godseye_csrf=([^;]*)')||[])[1]||'';return decodeURIComponent(raw)}async function saveIdentity(){const status=document.getElementById('identitySaveStatus'),btn=document.getElementById('saveIdentityBtn');const hostname=(document.getElementById('identityHostname')?.value||'').trim(),device_type=(document.getElementById('identityType')?.value||'').trim(),classification=document.getElementById('identityClassification')?.value||'new';if(btn)btn.disabled=true;if(status)status.textContent='Saving identity…';try{const r=await fetch('/api/v1/devices/'+DEVICE_ID,{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({hostname,device_type,classification})});const t=await r.text();if(!r.ok)throw new Error(t);if(status)status.textContent='Identity saved.';await load()}catch(e){if(status)status.textContent='Could not save identity: '+e.message}finally{if(btn)btn.disabled=false}}async function mutate(path){const r=await fetch(path,{method:'POST',headers:{'X-CSRF-Token':csrf()}});const t=await r.text();if(!r.ok)throw new Error(t);return t?JSON.parse(t):{}}async function renameCurrentDevice(){const old=(CURRENT_DEVICE&&CURRENT_DEVICE.name)||'';const name=prompt(old?'Rename this device:':'Name this device:',old||(CURRENT_DEVICE&&CURRENT_DEVICE.hostname)||'');if(name===null)return;const clean=name.trim();if(!clean){alert('Device name cannot be blank.');return}try{const r=await fetch('/api/v1/devices/'+DEVICE_ID,{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({name:clean})});const t=await r.text();if(!r.ok)throw new Error(t);await load()}catch(e){alert('Could not rename device: '+e.message)}}async function diagnose(){const el=document.getElementById('diag');el.textContent='Running diagnostics…';try{const r=await mutate('/api/v1/devices/'+DEVICE_ID+'/diagnose');el.textContent='Diagnostics complete: '+JSON.stringify(r)}catch(e){el.textContent='Diagnostics failed: '+e.message}}async function recheck(){const el=document.getElementById('diag');el.textContent='Rechecking device…';try{await mutate('/api/v1/devices/'+DEVICE_ID+'/recheck');el.textContent='Recheck complete. Refreshing…';await load()}catch(e){el.textContent='Recheck failed: '+e.message}}load();
</script></body></html>'''

@app.get("/device/{device_id}", response_class=HTMLResponse, include_in_schema=False)
def device_detail_page(device_id: int):
    html = DEVICE_DETAIL_PAGE.replace("__DEVICE_ID__", str(device_id)).replace("__EYE_LOGO__", EYE_LOGO)
    return HTMLResponse(html, headers={"Cache-Control":"no-store, no-cache, must-revalidate", "Pragma":"no-cache"})

@app.get("/", response_class=HTMLResponse)
def dashboard():
    banner_html = LOGIN_BANNER.replace("<", "&lt;").replace(">", "&gt;") if LOGIN_BANNER else ""
    html = DASHBOARD.replace("__LOGIN_BANNER__", banner_html)
    html = html.replace("__LOGIN_BANNER_DISPLAY__", "" if LOGIN_BANNER else "display:none")
    html = html.replace("__MIN_PASSWORD_LENGTH__", str(MIN_PASSWORD_LENGTH))
    html = html.replace("__APP_VERSION__", APP_VERSION)
    html = html.replace("__EYE_LOGO__", EYE_LOGO)
    return HTMLResponse(html, headers={"Cache-Control":"no-store, no-cache, must-revalidate", "Pragma":"no-cache"})


DASHBOARD = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GODSEYE — Network Monitor</title>
<script>
(function(){
  try{
    const saved=localStorage.getItem('godseye_theme');
    const dark=saved==='dark'||(!saved&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.dataset.theme=dark?'dark':'light';
  }catch(e){document.documentElement.dataset.theme='light'}
})();
</script>
<style>
:root{color-scheme:light;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}[data-theme="dark"]{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172033}header{position:sticky;top:0;z-index:5;background:rgba(255,255,255,.96);backdrop-filter:blur(14px);border-bottom:1px solid #e5eaf1;padding:16px 4%;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.brand{display:flex;gap:12px;align-items:center}.eye{width:38px;height:38px;border-radius:12px;background:#182338;display:grid;place-items:center;font-size:21px}.brand b{font-size:20px;letter-spacing:.08em} .muted{color:#6b778c;font-size:12px}button,.filter{border:1px solid #d7dee8;background:#fff;color:#24324a;border-radius:9px;padding:9px 13px;cursor:pointer}button.primary{background:#2563eb;border-color:#2563eb}button.danger{background:#3a1522;border-color:#5c2436;color:#ff8194}button.link{background:none;border:none;color:#7f9fd8;padding:4px 6px}.headerRight{display:flex;gap:10px;align-items:center}.wrap{max-width:1500px;margin:auto;padding:28px 4%}.hero{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:22px}.hero h1{font-size:32px;margin:0 0 5px}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:18px}.label{color:#8090a7;font-size:12px;text-transform:uppercase;letter-spacing:.1em}.num{font-size:32px;font-weight:750;margin-top:7px}.green{color:#50e3a4}.yellow{color:#f7c948}.red{color:#ff6b81}.toolbar{display:flex;gap:9px;margin:22px 0;flex-wrap:wrap}.toolbar input{flex:1;min-width:220px}.input{background:#fff;border:1px solid #d7dee8;border-radius:9px;padding:10px;color:#172033}.panel{background:#fff;border:1px solid #e2e8f0;border-radius:14px;overflow:hidden;margin-top:18px}.panel h2{font-size:16px;margin:0;padding:16px 18px;border-bottom:1px solid #e7ebf1;display:flex;justify-content:space-between;align-items:center}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #edf0f5;font-size:13px}th{color:#72819a;font-size:11px;text-transform:uppercase;letter-spacing:.08em}tr:hover{background:#f7f9fc}.dot{font-size:10px}.online{color:#50e3a4}.offline{color:#68758a}.suspected_offline{color:#f7c948}.pill{border:1px solid #31415a;border-radius:999px;padding:3px 8px;font-size:11px;color:#9eb0c8;cursor:pointer;background:none}.known{color:#50e3a4;border-color:#245c49}.new{color:#f7c948;border-color:#6d5a24}.investigate{color:#ff8194;border-color:#6d2e3c}.ignored{color:#72819a}.admin{color:#f7c948;border-color:#6d5a24}.readonly{color:#7f9fd8;border-color:#28406d}.critical{color:#ff8194;border-color:#6d2e3c}.warning{color:#f7c948;border-color:#6d5a24}.info{color:#7f9fd8;border-color:#28406d}.name{font-weight:650}.empty{padding:35px;text-align:center;color:#72819a}.healthbar{font-size:12px;padding:8px 4%;border-bottom:1px solid #e5eaf1;background:#fff}.healthbar.ok{color:#50e3a4}.healthbar.bad{color:#ff8194}
.overlay{position:fixed;inset:0;background:#070b12;display:grid;place-items:center;z-index:50;padding:20px}.authcard{width:100%;max-width:360px;background:#101927;border:1px solid #1d2a3d;border-radius:16px;padding:28px}.authcard h2{margin:0 0 6px}.authcard form{display:flex;flex-direction:column;gap:11px;margin-top:18px}.authcard .input{width:100%}.err{color:#ff8194;font-size:13px;min-height:18px}.formRow{display:flex;gap:9px}.userForm{display:flex;gap:8px;padding:14px 18px;flex-wrap:wrap;border-bottom:1px solid #182335}.userForm .input{flex:1;min-width:120px}
.shell{display:flex;align-items:flex-start}.sidebar{width:230px;flex-shrink:0;background:#0a0f18;border-right:1px solid #1d2838;padding:18px 0;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}.sidebar .brand{padding:0 18px 16px;margin-bottom:8px;border-bottom:1px solid #1d2838}.navsection{padding:13px 18px 6px;color:#586a84;font-size:10px;font-weight:800;letter-spacing:.13em;text-transform:uppercase}.navlist{display:flex;flex-direction:column}.navitem{display:flex;align-items:center;gap:10px;padding:9px 18px;color:#9eb0c8;background:none;border:none;border-left:3px solid transparent;text-align:left;cursor:pointer;font-size:13px;width:100%;text-decoration:none}.navitem:hover{background:#111a28;color:#e8eef7}.navitem.active{background:#111a28;color:#e8eef7;border-left-color:#2563eb}.navitem .badge{margin-left:auto;min-width:20px;padding:2px 6px;border-radius:999px;background:#3a1522;color:#ff8194;font-size:10px;text-align:center}.sidebar-footer{margin-top:auto;padding:14px 18px 4px;border-top:1px solid #1d2838;display:flex;flex-direction:column;gap:8px}.content{flex:1;min-width:0}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){display:none}}@media(max-width:600px){.cards{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}th:nth-child(4),td:nth-child(4){display:none}.wrap{padding:20px 3%}}
@media(max-width:820px){.shell{flex-direction:column}.sidebar{width:100%;height:auto;position:sticky;top:0;flex-direction:column;overflow:visible;border-right:none;border-bottom:1px solid #1d2838;padding:8px 0;z-index:6}.sidebar .brand{display:none}.navlist{flex-direction:row;overflow-x:auto;padding:0 4%;align-items:center}.navsection{display:none}.navitem{width:auto;white-space:nowrap;border-left:none;border-bottom:3px solid transparent;padding:8px 12px}.navitem.active{border-left:none;border-bottom-color:#2563eb}.sidebar-footer{margin-top:8px;flex-direction:row;border-top:1px solid #1d2838;padding:8px 4% 0;gap:10px;align-items:center;flex-wrap:wrap}.sidebar-footer #whoami{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sidebar-footer #scanBtn{width:auto!important;margin-bottom:0!important}}
.eye-logo{width:48px;height:30px;display:block}.login-brand{display:flex;flex-direction:column;align-items:center;text-align:center;margin-bottom:18px}.login-brand .eye-logo{width:132px;height:79px}.login-brand b{font-size:28px;letter-spacing:.12em}.login-brand .muted{font-size:11px}.authcard{box-shadow:0 24px 60px rgba(0,0,0,.35)}.user-chip{border:0!important;background:transparent!important;padding:4px!important;display:flex;align-items:center;gap:7px;font-size:11px;color:#53657a}.user-menu{position:absolute;right:4%;top:58px;background:#fff;border:1px solid #dfe6ef;border-radius:10px;box-shadow:0 12px 30px rgba(15,34,58,.14);padding:6px;z-index:20}.user-menu button{display:block;width:100%;border:0;text-align:left;background:#fff;padding:9px 12px}.user-menu button:hover{background:#f3f6fa}

.device-link{background:none!important;border:0!important;padding:0!important;color:#1565c0!important;font-weight:700;cursor:pointer;text-align:left}.device-link:hover{text-decoration:underline}.device-page-head{display:flex;align-items:center;gap:12px}.back-btn{display:inline-flex;align-items:center;gap:7px;border:1px solid #d8e0e9!important;background:#fff!important;color:#2d4665!important}.device-detail-shell{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(300px,.65fr);gap:16px}.device-hero-card{padding:18px}.kpi-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:14px}.kpi{border:1px solid #e4eaf1;border-radius:10px;padding:12px;background:#fafcff}.kpi .k{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#7b889a}.kpi .v{font-size:17px;font-weight:750;margin-top:4px}.stack{display:grid;gap:16px}.chart-empty{height:160px;display:grid;place-items:center;color:#7c8ba0}.dashboard-table tbody tr{cursor:pointer}.dashboard-table tbody tr:hover{background:#f4f8fd}.panel-subtle{padding:12px 16px;border-top:1px solid #eef2f6;font-size:11px;color:#738197}.traffic-axis{font-size:9px;fill:#8795a8}.activity-row button{all:unset;cursor:pointer}.activity-row button:hover .activity-title{text-decoration:underline}.intel-modal-card{display:none!important}.dashboard-statusline{display:flex;gap:14px;align-items:center;flex-wrap:wrap;font-size:11px;color:#748197}.status-pill{display:inline-flex;align-items:center;gap:6px}.status-pill::before{content:"";width:7px;height:7px;border-radius:50%;background:#22a06b}.status-pill.warn::before{background:#f59e0b}
.sortable-head{cursor:pointer;user-select:none;position:relative;padding-right:24px!important}.sortable-head:hover{color:#235f9f;background:#f7faff}.sortable-head::after{content:"↕";position:absolute;right:8px;opacity:.35;font-size:10px}.sortable-head.sort-asc::after{content:"↑";opacity:1}.sortable-head.sort-desc::after{content:"↓";opacity:1}.protected-audit{background:#fff8e8}.protected-audit td:first-child{box-shadow:inset 3px 0 0 #f2a51a}.admin-only{display:none}.admin-visible{display:inline-flex}
@media(max-width:1000px){.device-detail-shell{grid-template-columns:1fr}.kpi-row{grid-template-columns:repeat(2,1fr)}}
/* GODSEYE v1.9 screenshot-matched UI + stability pass */
:root{color-scheme:light;--navy:#07101c;--navy-2:#0b1728;--blue:#0d74f5;--blue-2:#1b84ff;--ink:#17263c;--muted:#6f8097;--line:#dce6f1;--surface:#ffffff;--canvas:#f5f9fd;--green:#11a86b;--red:#ef4f5f;--amber:#f2a51a;--purple:#6d5bd0}
html,body{min-height:100%;background:var(--canvas);color:var(--ink)}
body{font-size:14px}.shell{min-height:100vh;background:var(--canvas)}
.sidebar{width:188px;background:linear-gradient(180deg,#07101c 0%,#081522 100%);border-right:0;box-shadow:8px 0 28px rgba(18,43,72,.08);padding:20px 0 16px}
.sidebar .brand{padding:2px 18px 22px;margin:0 0 8px;border-bottom:0;justify-content:center;flex-direction:column;text-align:center;gap:5px}.sidebar .brand .eye{background:transparent;width:74px;height:48px;border-radius:0}.sidebar .brand .eye-logo{width:72px;height:44px}.sidebar .brand b{font-size:15px;color:#fff;letter-spacing:.12em}.sidebar .brand .muted{font-size:8px;letter-spacing:.08em;color:#7790ab}.navsection{color:#58708c;padding:15px 18px 5px;font-size:9px}.navitem{padding:10px 15px;color:#d1d9e5;border-left:0;border-radius:6px;margin:1px 8px;width:calc(100% - 16px);font-size:12px}.navitem:hover{background:#0f2238;color:#fff}.navitem.active{background:linear-gradient(90deg,#0a67d9,#0e7cf8);color:#fff;border-left:0;box-shadow:0 5px 14px rgba(0,112,242,.22)}.navicon{width:18px;text-align:center;color:inherit}.navitem .badge{background:#ec4d5c;color:#fff;border:1px solid rgba(255,255,255,.25)}
.sidebar-footer{border-top:1px solid #13243a;margin-top:auto;padding:14px 14px 0}.sidebar-footer .primary{width:100%;margin-bottom:4px}.sidebar-footer .muted{color:#7690ad}.sidebar-footer .link{color:#99abc0;text-align:left}
.content{background:var(--canvas);min-height:100vh}.headerbar{height:58px;background:#fff;border-bottom:1px solid #e6edf5;display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:10}.headerbar>.muted{font-size:11px}.top-actions{display:flex;align-items:center;gap:8px}.status-chip{display:inline-flex;align-items:center;gap:6px;background:#e9fbf2;color:#128451;border-radius:999px;padding:5px 9px;font-size:10px}.status-dot{width:6px;height:6px;border-radius:50%;background:#12aa69}.icon-btn{width:32px;height:32px;border:0;background:transparent;padding:0;display:grid;place-items:center}.avatar{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;background:#e7f1ff;color:#0d74f5;font-weight:800}
.wrap{max-width:none;margin:0;padding:22px 24px 42px}.hero{margin-bottom:18px;align-items:center}.hero h1{font-size:23px;letter-spacing:-.025em;margin:0 0 3px}.hero .muted{font-size:11px}.actions{display:flex;gap:8px;align-items:center}.dashboard-statusline{margin-top:5px!important}.cards{grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card,.panel,.tool-card,.integration-card{border:1px solid #dbe5f0;border-radius:8px;background:#fff;box-shadow:0 2px 9px rgba(29,58,90,.035)}.card{padding:14px 15px;min-height:92px}.statcard{display:grid;grid-template-columns:34px 1fr auto;gap:10px;align-items:start}.stat-action{width:100%;text-align:left;color:inherit;font:inherit;cursor:pointer;transition:transform .14s ease,box-shadow .14s ease,border-color .14s ease}.stat-action:hover{transform:translateY(-2px);box-shadow:0 8px 22px rgba(22,73,125,.11);border-color:#bcd7f3}.stat-action:focus-visible{outline:3px solid rgba(13,116,245,.18);outline-offset:2px}.stat-action .statmeta:after{content:'  →';color:#0d74f5;font-weight:800}.dashboard-return{display:none;align-items:center;gap:6px;margin-bottom:10px;padding:0!important;border:0!important;background:transparent!important;color:#0d74f5!important;font-weight:700;font-size:11px!important;box-shadow:none!important}.dashboard-return:hover{text-decoration:underline}.staticon{width:28px;height:28px;border-radius:7px;display:grid;place-items:center;background:#eaf6ff;color:#0874d7;font-weight:900}.staticon.green{background:#e9f9f2;color:#0d9c65}.staticon.red{background:#fff0f1;color:#ef4f5f}.staticon.purple{background:#f1efff;color:#6a5bd5}.statmeta{font-size:10px;color:#61738a}.statnum{font-size:25px;line-height:1.1;font-weight:800;margin-top:3px}.trend{font-size:9px;color:#0ca763;align-self:end;white-space:nowrap}.panel{margin-top:14px}.panel h2,.table-head{font-size:13px}.table-head{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;border-bottom:1px solid #e8eef5}.table-head h2,.panel .table-head h2{padding:0;border:0;font-size:13px}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(310px,.8fr);gap:12px}.traffic{min-height:310px}#trafficSvg{display:block;width:100%;height:230px;padding:8px 12px 0}.activity-list{padding:5px 14px 12px}.activity-row{display:grid;grid-template-columns:18px 1fr auto;gap:9px;align-items:center;padding:9px 0;border-bottom:1px solid #edf2f7}.activity-row:last-child{border-bottom:0}.activity-dot{width:9px;height:9px;border-radius:50%;background:#1677ee}.activity-dot.green{background:#0fb26d}.activity-title{font-weight:700;font-size:11px}.activity-sub,.activity-time{font-size:9px;color:#8391a5}.panel-subtle{font-size:10px;background:#fbfdff}.client-row{display:grid;grid-template-columns:minmax(120px,200px) 1fr 56px;gap:10px;align-items:center;margin:9px 0}.client-bar{height:8px;background:#edf2f7;border-radius:8px;overflow:hidden}.client-bar>span{display:block;height:100%;background:linear-gradient(90deg,#0d74f5,#4ba4ff);border-radius:8px}
button,.filter,.input{border-radius:6px;border-color:#d8e3ee;background:#fff;color:#24364f;font-size:11px}button{padding:7px 10px}button.primary,.primary{background:#0d74f5!important;border-color:#0d74f5!important;color:#fff!important;box-shadow:none}button.primary:hover,.primary:hover{background:#0969de!important}button.secondary,.secondary{background:#fff!important;border:1px solid #d5e1ed!important;color:#38516d!important}.input,.filter{padding:8px 10px}.toolbar{margin:12px 0}.panel table{background:#fff}th,td{padding:10px 11px;border-bottom:1px solid #e9eef5;font-size:10px}th{font-size:9px;color:#5c7088;background:#fbfdff;text-transform:none;letter-spacing:0;font-weight:700}tr:hover{background:#f5faff}.status-badge,.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 7px;font-size:9px;border:1px solid #cfe7db;background:#eafaf2;color:#0a8c57}.status-badge.severity-high,.status-badge.severity-critical{background:#fff0f1;border-color:#ffd4d8;color:#db3044}.status-badge.severity-medium,.status-badge.severity-warning{background:#fff7e6;border-color:#f8deb0;color:#b87500}.status-badge.severity-low{background:#fffbe7;border-color:#f1e6aa;color:#92750a}.device-icon{display:grid;place-items:center;width:24px;height:24px;border-radius:50%;background:#e9f5ff;color:#0675dd}.device-name{display:flex;align-items:center;gap:8px}.device-link{color:#0b68c9!important}.map-card{min-height:560px}.map-canvas{padding:24px;min-height:520px}.map-node{background:#fff}.tool-grid{gap:12px}.tool-card{padding:18px}.tool-icon{width:34px;height:34px;border-radius:50%;background:#10a9ba;color:#fff;display:grid;place-items:center;font-size:17px}.tool-card:nth-child(2) .tool-icon,.tool-card:nth-child(3) .tool-icon{background:#176fe8}.tool-card:nth-child(4) .tool-icon{background:#7457da}.tool-card:nth-child(5) .tool-icon{background:#13a564}.tool-card:nth-child(6) .tool-icon{background:#126cd9}.tool-card h3{font-size:13px;margin-bottom:4px}.tool-card p{font-size:10px;color:#718198}.tool-card .primary{display:inline-block;margin-top:10px}
.map-shell{display:grid;grid-template-columns:minmax(0,1fr) 230px;gap:14px;margin-top:14px}.map-main{min-width:0}.map-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:12px}.map-summary-card{border:1px solid #e0e9f2;background:#fff;border-radius:8px;padding:11px 12px}.map-summary-label{font-size:9px;color:#718198}.map-summary-value{font-size:16px;font-weight:800;color:#1d3048;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.map-toolbar2{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 12px;border-bottom:1px solid #e7eef5;background:#fbfdff}.map-toolbar2 .input{min-width:190px;flex:1}.map-viewport{position:relative;min-height:545px;overflow:auto;background-color:#f8fbff;background-image:radial-gradient(#d6e5f4 1px,transparent 1px);background-size:20px 20px}.map-stage{min-width:760px;min-height:515px;padding:34px 44px 58px;transform-origin:top center;transition:transform .15s ease}.map-canvas{padding:0!important;min-height:auto!important;justify-content:flex-start!important}.map-node{min-width:142px;max-width:180px;padding:10px 9px 9px;border:1px solid #dce7f1;border-radius:10px;background:#fff!important;box-shadow:0 4px 14px rgba(33,66,100,.07);cursor:default;transition:box-shadow .15s ease,border-color .15s ease,transform .15s ease}.map-node.device-clickable{cursor:pointer}.map-node.device-clickable:hover{border-color:#91c6f4;box-shadow:0 8px 20px rgba(13,116,245,.14);transform:translateY(-2px)}.map-circle{width:38px!important;height:38px!important;box-shadow:none!important}.map-node.offline-node .map-circle{background:#8b98a9!important}.map-node.issue-node .map-circle{background:#ef5b67!important}.map-node.infrastructure-node .map-circle{background:#725bd7!important}.map-label{font-size:10px!important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.map-sub{font-size:9px!important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.map-link-badge{display:inline-flex;margin-top:6px;padding:2px 6px;border-radius:999px;background:#eef6ff;color:#1769b4;font-size:8px;border:1px solid #d7eafc}.map-side{display:flex;flex-direction:column;gap:12px}.map-side-card{border:1px solid #dce7f1;background:#fff;border-radius:8px;padding:13px}.map-side-card h3{font-size:11px;margin:0 0 9px;color:#253a54}.map-legend-row{display:flex;align-items:center;gap:8px;font-size:9px;color:#61738a;margin:7px 0}.map-legend-dot{width:10px;height:10px;border-radius:50%;background:#1592e8;flex:0 0 auto}.map-legend-dot.green{background:#0da66a}.map-legend-dot.gray{background:#8b98a9}.map-legend-dot.purple{background:#725bd7}.map-legend-dot.red{background:#ef5b67}.map-tip{font-size:9px;line-height:1.5;color:#75859a}.map-zoom{display:flex;gap:5px}.map-zoom button{min-width:31px;padding:6px 8px}.map-empty{padding:80px 20px;text-align:center;color:#75859a}.map-children{align-items:flex-start;justify-content:center;flex-wrap:wrap;row-gap:28px}.map-children:before{left:6%;right:6%}@media(max-width:1100px){.map-shell{grid-template-columns:1fr}.map-side{display:grid;grid-template-columns:repeat(2,1fr)}.map-summary{grid-template-columns:repeat(2,1fr)}}@media(max-width:700px){.map-side{grid-template-columns:1fr}.map-summary{grid-template-columns:1fr 1fr}.map-stage{min-width:660px;padding-left:24px;padding-right:24px}}
.device-detail-shell{grid-template-columns:minmax(0,1.45fr) minmax(300px,.55fr)}.device-hero-card{border-top:3px solid #0d74f5}.back-btn{font-weight:700}.intel-kv{display:grid;grid-template-columns:120px 1fr;gap:8px 12px;font-size:11px}.intel-kv .k{color:#72839a}.timeline-row{padding:9px 0;border-bottom:1px solid #edf2f7;font-size:11px}.timeline-row:last-child{border-bottom:0}
/* Login and setup screens — match the reference mountain composition. */
.overlay{background-image:linear-gradient(rgba(3,17,32,.18),rgba(3,17,32,.42)),url('/assets/login-bg.jpg');background-size:cover;background-position:center;position:fixed;inset:0}.authcard{max-width:350px;background:rgba(255,255,255,.97);border:1px solid rgba(255,255,255,.62);box-shadow:0 24px 60px rgba(0,15,34,.42);color:#16253a;border-radius:7px;padding:24px 26px}.authcard h2{text-align:center;font-size:20px;margin:2px 0 4px}.authcard> .muted,.authcard .login-brand+.muted{text-align:center}.login-brand{margin-bottom:13px;color:#fff;position:absolute;top:7%;left:50%;transform:translateX(-50%);text-shadow:0 2px 10px rgba(0,0,0,.45)}.login-brand .eye-logo{width:86px;height:52px}.login-brand b{font-size:28px;color:#fff}.login-brand .muted{color:#fff;font-size:10px}.authcard .input{background:#fff;color:#17263c;border:1px solid #cfddeb;height:38px}.authcard button.primary{height:38px}.authcard .err{color:#d73545}.login-scene-footer{position:absolute;bottom:20px;left:50%;transform:translateX(-50%);text-align:center;color:rgba(255,255,255,.8);font-size:9px;line-height:1.7;text-shadow:0 1px 3px rgba(0,0,0,.7)}
#setupOverlay .login-brand,#pwOverlay .login-brand,#mfaLoginOverlay .login-brand{position:static;transform:none;color:#16253a;text-shadow:none}#setupOverlay .login-brand b,#pwOverlay .login-brand b,#mfaLoginOverlay .login-brand b{color:#16253a}
.scan-status{min-height:18px;color:#86a0bc;font-size:9px;line-height:1.35;padding:2px 2px 6px}.scan-status.ok{color:#70d9a8}.scan-status.bad{color:#ff8290}.scan-status.busy{color:#9ac6ff}
@media(max-width:1100px){.cards{grid-template-columns:repeat(2,1fr)}.dashboard-grid{grid-template-columns:1fr}.sidebar{width:174px}.wrap{padding:18px}}
@media(max-width:820px){.sidebar{width:100%;height:auto;padding:8px 0}.sidebar .brand{display:none}.wrap{padding:14px}.headerbar{padding:0 12px}.cards{grid-template-columns:repeat(2,1fr)}.dashboard-grid{grid-template-columns:1fr}.authcard{margin-top:100px}.login-brand{top:3%}}
@media(max-width:560px){.cards{grid-template-columns:1fr 1fr}.card{padding:11px}.statnum{font-size:22px}.wrap{padding:10px}.hero h1{font-size:21px}.client-row{grid-template-columns:110px 1fr 42px}.login-brand b{font-size:24px}}


/* v2.5 realistic device icon picker */
.device-name .device-icon{width:42px;height:42px;border-radius:0;background:transparent;display:inline-grid;place-items:center;flex:0 0 42px}.device-name .device-icon img{width:40px;height:38px;object-fit:contain;filter:drop-shadow(0 2px 2px rgba(18,38,63,.22))}.device-icon-modal{position:fixed!important;inset:0!important;z-index:5000!important;place-items:center!important;background:rgba(7,16,28,.62)!important;padding:24px!important;overflow:auto!important}.device-icon-dialog{width:min(720px,calc(100vw - 32px))!important;max-width:720px!important;max-height:calc(100vh - 48px)!important;overflow:auto!important;padding:0!important;border:1px solid #d8e3ef!important;border-radius:13px!important;box-shadow:0 26px 90px rgba(2,12,27,.34)!important}.device-icon-dialog .modal-head{padding:18px 20px 12px;border-bottom:1px solid #edf2f7}.device-icon-dialog .modal-form{display:block!important;margin:0!important;padding:0 20px 18px!important}.device-icon-summary{display:flex;align-items:center;gap:14px;padding:14px 0}.device-icon-summary-art{width:72px;height:64px;border:1px solid #dce6f1;border-radius:10px;background:linear-gradient(180deg,#fff,#f6f9fc);display:grid;place-items:center}.device-icon-summary-art img{width:58px;height:58px;object-fit:contain;filter:drop-shadow(0 3px 3px rgba(17,39,64,.2))}.device-icon-summary-name{font-size:16px;font-weight:750;color:#0b6ddd}.device-icon-summary-meta{font-size:12px;color:#64768d;line-height:1.5}.device-icon-tabs{display:flex;gap:24px;border-bottom:1px solid #e5edf5;margin-bottom:14px;overflow:auto}.device-icon-tab{border:0;background:transparent;padding:10px 2px 9px;color:#61738b;font-size:11px;white-space:nowrap;cursor:pointer;border-bottom:2px solid transparent;border-radius:0}.device-icon-tab.active{color:#0d74f5;border-bottom-color:#0d74f5;font-weight:700}.device-icon-picker{display:grid;grid-template-columns:repeat(5,minmax(96px,1fr));gap:10px;max-height:390px;overflow:auto;padding:2px}.device-icon-choice{position:relative;border:1px solid #d8e3ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:9px;padding:9px 6px 8px;cursor:pointer;text-align:center;color:#30445e;font-size:10px;min-height:92px}.device-icon-choice:hover{border-color:#86bdfb;background:#f7fbff}.device-icon-choice.selected{border:2px solid #0d74f5;padding:8px 5px 7px;box-shadow:0 0 0 2px rgba(13,116,245,.09)}.device-icon-choice.selected:after{content:'✓';position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%;background:#0d74f5;color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.device-icon-choice img{width:66px;height:58px;display:block;object-fit:contain;margin:0 auto 5px;filter:drop-shadow(0 3px 3px rgba(18,38,63,.2))}.device-icon-custom{border-top:1px solid #e4ebf3;margin-top:14px;padding-top:13px}.custom-icon-preview{width:58px;height:58px;object-fit:contain;border:1px solid #d8e3ef;border-radius:8px;background:#fff;padding:4px}.icon-upload-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.device-icon-dialog .modal-actions{display:flex!important;justify-content:flex-end!important;gap:8px;border-top:1px solid #edf2f7;padding-top:14px;margin-top:14px}.device-icon-dialog .err{margin-top:8px}@media(max-width:700px){.device-icon-modal{padding:10px!important;align-items:center!important}.device-icon-dialog{max-height:calc(100vh - 20px)!important}.device-icon-picker{grid-template-columns:repeat(3,1fr)}.device-icon-tabs{gap:14px}.device-icon-summary-art{width:60px;height:56px}.device-icon-summary-art img{width:48px;height:48px}}


/* v3.0 centered form modals + monitoring cleanup */
.modal{position:fixed!important;inset:0!important;z-index:4800!important;display:grid;place-items:center;background:rgba(7,16,28,.58);backdrop-filter:blur(2px);padding:24px;overflow:auto}
.modal[style*="display:none"]{display:none!important}
.modal-card{width:min(620px,calc(100vw - 36px));max-height:calc(100vh - 48px);overflow:auto;background:#fff;border:1px solid #d8e4ef;border-radius:14px;box-shadow:0 28px 90px rgba(2,12,27,.34);padding:0}
.modal-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:18px 20px 14px;border-bottom:1px solid #edf2f7;background:linear-gradient(180deg,#fff,#fbfdff);position:sticky;top:0;z-index:2}
.modal-head h2{margin:0 0 4px;font-size:18px;color:#182b43}.modal-head .muted{font-size:10px}.modal-head .icon-btn{border:1px solid #dde7f1;background:#fff!important;border-radius:8px;color:#526980;font-size:18px;line-height:1}.modal-head .icon-btn:hover{background:#f4f8fc!important;color:#172b43}
.modal-form{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:18px 20px 20px;margin:0}.modal-form label{display:flex;flex-direction:column;gap:6px;font-size:10px;font-weight:700;color:#536981}.modal-form label .input,.modal-form label .filter{width:100%;box-sizing:border-box}.modal-form textarea{resize:vertical;min-height:82px}.modal-form label:first-child,.modal-form label:last-of-type:has(textarea){grid-column:1/-1}.modal-form>.err,.modal-form>.muted{grid-column:1/-1}.modal-actions{grid-column:1/-1;display:flex;justify-content:flex-end;gap:8px;padding-top:14px;margin-top:2px;border-top:1px solid #edf2f7}.modal-card .primary,.modal-card .secondary{min-width:104px}.form-hint{font-size:9px;color:#7c8ea3;font-weight:400;margin-top:-2px}.modal-section-title{grid-column:1/-1;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#7a8ca1;font-weight:800;margin-top:2px}
.monitor-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:12px 0 2px}.monitor-summary-card{border:1px solid #dce7f1;background:#fff;border-radius:10px;padding:12px 13px}.monitor-summary-card .k{font-size:9px;color:#718299}.monitor-summary-card .v{font-size:20px;font-weight:800;color:#182d47;margin-top:3px}.monitor-summary-card.good .v{color:#0b995e}.monitor-summary-card.bad .v{color:#d63b4f}.monitor-summary-card.off .v{color:#75869a}.monitor-table-wrap{overflow:auto}.monitor-type-badge{display:inline-flex;align-items:center;border-radius:999px;padding:3px 7px;background:#eef5ff;color:#216cc5;border:1px solid #d6e7fb;font-size:9px;font-weight:700}.monitor-target{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9px;color:#435a72}.monitor-empty{padding:36px 18px;text-align:center;color:#7a8ca0}.monitor-empty b{display:block;color:#30475f;font-size:12px;margin-bottom:5px}.monitor-actions{display:flex;gap:5px;flex-wrap:wrap}.monitor-actions .link{border:1px solid #dce6ef!important;border-radius:6px!important;padding:5px 7px!important;background:#fff!important;color:#2f5e92!important;text-decoration:none!important}.monitor-actions .link:hover{background:#f5f9fd!important}

.integration-toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin:0 0 14px}.integration-list{display:grid;grid-template-columns:repeat(3,minmax(240px,1fr));gap:14px}.integration-card{border:1px solid #dfe8f1;border-radius:12px;background:#fff;padding:15px;box-shadow:0 4px 14px rgba(27,53,79,.05)}.integration-card-head{display:flex;align-items:center;justify-content:space-between;gap:10px}.integration-badge{font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.07em;padding:4px 7px;border-radius:999px;background:#edf5ff;color:#1872d7}.integration-state{font-size:10px;padding:4px 7px;border-radius:999px;background:#f2f5f8;color:#5c7087}.integration-state.success{background:#e8f8ef;color:#198754}.integration-state.failed{background:#fff0f1;color:#c73c50}.integration-meta{display:grid;gap:6px;margin:12px 0;color:#64768d;font-size:10px}.integration-actions{display:flex;gap:7px;flex-wrap:wrap}.integration-remove{margin-left:auto;background:#fff5f6!important;border:1px solid #f2c7cd!important;color:#be3448!important}.integration-remove:hover{background:#ffe9ec!important;border-color:#e69aa5!important}.remove-summary{margin:14px 20px 0;padding:13px 14px;border:1px solid #f0d3d7;border-radius:10px;background:#fff7f8;color:#5d2630;font-size:11px;line-height:1.5}.remove-summary b{color:#a8293d}.analytics-grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:12px;padding:16px}.analytics-card{border:1px solid #dfe8f1;border-radius:11px;padding:14px;background:linear-gradient(180deg,#fff,#fbfdff);cursor:pointer;text-align:left}.analytics-card:hover{border-color:#91bef2;box-shadow:0 5px 18px rgba(28,84,140,.08)}.analytics-card .metric{font-size:24px;font-weight:800;color:#1872d7}.analytics-card .sub{font-size:10px;color:#1872d7;margin-top:4px}.notify-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;padding:16px}.notify-card{border:1px solid #dfe8f1;border-radius:12px;padding:15px;background:#fff}.notify-card h3{margin:0 0 4px;font-size:14px}.notify-desc{font-size:10px;color:#71869d;min-height:32px;margin-bottom:12px}.notify-fields{display:grid;gap:9px}.notify-footer{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:0 16px 16px;flex-wrap:wrap}.integration-kind-fields{display:grid;grid-template-columns:1fr 1fr;gap:12px;grid-column:1/-1}.analytics-dialog pre{background:#07101c;color:#dbe9f6;border-radius:9px;padding:14px;max-height:420px;overflow:auto;font-size:10px}.analytics-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}.analytics-summary div{border:1px solid #e0e8f0;border-radius:9px;padding:10px}.analytics-summary b{display:block;font-size:18px;color:#19324d}.analytics-summary span{font-size:9px;color:#7b8da2}@media(max-width:1000px){.integration-list,.analytics-grid,.notify-grid{grid-template-columns:1fr 1fr}}@media(max-width:680px){.integration-list,.analytics-grid,.notify-grid{grid-template-columns:1fr}.integration-kind-fields{grid-template-columns:1fr}}
@media(max-width:720px){.modal{padding:10px}.modal-card{width:100%;max-height:calc(100vh - 20px)}.modal-form{grid-template-columns:1fr}.modal-form label:first-child,.modal-form label:last-of-type:has(textarea){grid-column:auto}.monitor-summary{grid-template-columns:repeat(2,1fr)}}

/* v2.6 realistic topology map */
.network-hero{align-items:flex-start}.network-hero .actions{align-items:center;flex-wrap:wrap}.network-search{width:240px!important}.network-filter-row{display:flex;gap:8px;align-items:center;margin:8px 0 12px;flex-wrap:wrap}.network-filter{border:1px solid #d8e4ef;background:#f6f9fc;color:#38516d;border-radius:9px;padding:8px 14px;font-size:10px;font-weight:700}.network-filter.active{background:#0d74f5;color:#fff;border-color:#0d74f5}.network-filter.online:not(.active){background:#ecfaf3;color:#0b8f5a;border-color:#ccebdc}.network-filter.offline:not(.active){background:#fff0f1;color:#cb2f40;border-color:#f8ccd1}.network-filter.unknown:not(.active){background:#f1f5f9;color:#62748a}.network-filter span{margin-left:4px}.network-generated{font-size:9px;color:#788ba1;margin-left:auto}.network-map-layout{display:grid;grid-template-columns:minmax(0,1fr) 290px;gap:12px}.network-topology-panel{position:relative;border:1px solid #dce7f1;background:#fff;border-radius:10px;overflow:hidden;min-width:0}.realistic-map-viewport{height:665px;min-height:665px;overflow:auto;background-color:#f8fbff;background-image:radial-gradient(#d8e6f3 1px,transparent 1px);background-size:18px 18px}.realistic-map-stage{position:relative;width:1100px;height:720px;min-width:1100px;min-height:720px;padding:0!important;transform-origin:top left;transition:transform .15s ease}.realistic-map-canvas{position:absolute;inset:0;padding:0!important;min-height:0!important;display:block!important}.map-edge-layer{position:absolute;inset:0;width:1100px;height:720px;overflow:visible;pointer-events:none}.topology-edge{fill:none;stroke:#327fe7;stroke-width:2;opacity:.82}.topology-edge.wireless{stroke:#0d74f5;stroke-dasharray:6 5}.topology-edge.inferred{stroke:#91a9c1;opacity:.62}.topology-node{position:absolute;width:126px;transform:translate(-50%,-50%);text-align:center;cursor:pointer;border-radius:10px;padding:4px 5px 7px;transition:background .15s ease,box-shadow .15s ease,opacity .15s ease}.topology-node:hover,.topology-node.selected{background:rgba(255,255,255,.94);box-shadow:0 8px 24px rgba(26,60,98,.13)}.topology-node.selected{outline:2px solid rgba(13,116,245,.35)}.topology-node .topology-art{height:66px;display:flex;align-items:flex-end;justify-content:center;position:relative}.topology-node .topology-art img{width:76px;height:62px;object-fit:contain;filter:drop-shadow(0 5px 5px rgba(21,42,65,.18))}.topology-node.internet .topology-art{align-items:center}.topology-node.internet .topology-art .internet-globe{font-size:54px;line-height:1;filter:drop-shadow(0 5px 5px rgba(21,42,65,.18))}.topology-status-dot{position:absolute;right:13px;bottom:3px;width:10px;height:10px;border-radius:50%;border:2px solid #fff;background:#8b98a9;box-shadow:0 1px 3px rgba(0,0,0,.16)}.topology-status-dot.online{background:#12ad67}.topology-status-dot.offline{background:#ef5966}.topology-name{font-size:10px;font-weight:800;color:#1c2f47;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:3px}.topology-ip,.topology-vendor{font-size:9px;color:#607790;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.35}.topology-node.dimmed{opacity:.14;filter:grayscale(.6)}.network-map-footer{position:absolute;left:14px;right:14px;bottom:10px;display:flex;justify-content:space-between;align-items:center;pointer-events:none}.network-map-footer>*{pointer-events:auto}.network-map-footer .map-zoom{padding:4px;background:rgba(255,255,255,.94);border:1px solid #dbe6ef;border-radius:8px;box-shadow:0 4px 15px rgba(25,55,88,.08)}.network-map-legend{display:flex;align-items:center;gap:14px;padding:7px 10px;background:rgba(255,255,255,.94);border:1px solid #dbe6ef;border-radius:8px;font-size:8px;color:#657a91}.network-map-legend span{display:flex;gap:5px;align-items:center}.legend-line{width:24px;height:0;border-top:2px solid #327fe7}.legend-line.wireless{border-top-style:dashed}.legend-status{width:9px;height:9px;border-radius:50%;background:#8b98a9}.legend-status.online{background:#12ad67}.legend-status.offline{background:#ef5966}.network-detail-column{display:flex;flex-direction:column;gap:10px}.network-device-card,.network-connected-card,.network-controls-card{border:1px solid #dce7f1;background:#fff;border-radius:10px;padding:13px}.network-device-card{min-height:244px}.network-device-head{display:flex;gap:11px;align-items:center;padding-bottom:11px;border-bottom:1px solid #e7eef5}.network-device-head img{width:70px;height:58px;object-fit:contain}.network-device-head .internet-globe{font-size:48px}.network-device-title{font-size:13px;font-weight:800;color:#0870e6}.network-device-sub{font-size:9px;color:#6d8198;margin-top:3px}.network-kv{display:grid;grid-template-columns:92px 1fr;gap:8px 8px;padding:12px 2px;font-size:9px}.network-kv .k{color:#70849c}.network-kv .v{color:#142b46;overflow:hidden;text-overflow:ellipsis}.network-device-actions{display:flex;gap:5px;flex-wrap:wrap}.network-device-actions button{font-size:9px;padding:6px 8px}.network-connected-card h3,.network-controls-card h3{font-size:11px;margin:0 0 9px;color:#203650}.connected-device-row{display:grid;grid-template-columns:38px 9px minmax(0,1fr) auto;gap:6px;align-items:center;border-top:1px solid #edf2f6;padding:7px 0;cursor:pointer}.connected-device-row:first-child{border-top:0}.connected-device-row img{width:34px;height:27px;object-fit:contain}.connected-device-row .dot{width:8px;height:8px;border-radius:50%;background:#8b98a9}.connected-device-row .dot.online{background:#12ad67}.connected-device-row .dot.offline{background:#ef5966}.connected-device-row .connected-name{font-size:9px;font-weight:800;color:#0870e6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.connected-device-row .connected-type,.connected-device-row .connected-ip{font-size:8px;color:#6f8298}.network-empty-side{font-size:9px;color:#7a8da3;padding:18px 4px;text-align:center}.map-layout-btn{display:block;width:100%;text-align:left;margin:5px 0;background:#fff;border:1px solid #d8e4ef;color:#2d4663;border-radius:7px}.map-layout-btn.active{background:#0d74f5!important;color:#fff!important;border-color:#0d74f5!important}.map-evidence-note{font-size:8px;line-height:1.45;color:#75879b;margin-top:9px;padding-top:9px;border-top:1px solid #edf2f6}@media(max-width:1150px){.network-map-layout{grid-template-columns:1fr}.network-detail-column{display:grid;grid-template-columns:repeat(3,1fr)}.realistic-map-viewport{height:590px;min-height:590px}}@media(max-width:760px){.network-detail-column{grid-template-columns:1fr}.network-search{width:100%!important}.network-generated{width:100%;margin-left:0}.network-map-legend{display:none}}

/* v4.0 — full dashboard dark mode */
.theme-toggle{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-width:36px;height:34px;padding:0 10px;border:1px solid #dbe3ec;border-radius:9px;background:#fff;color:#40536b;font-size:12px;font-weight:700;cursor:pointer}
.theme-toggle:hover{background:#f5f8fb;border-color:#cbd8e5}
.theme-toggle .theme-icon{font-size:15px;line-height:1}
[data-theme="dark"] body{background:#0b1119;color:#dce6f2}
[data-theme="dark"] .content{background:#0b1119}
[data-theme="dark"] .headerbar{background:rgba(12,19,29,.96)!important;border-bottom-color:#263244!important;box-shadow:0 1px 0 rgba(255,255,255,.015)}
[data-theme="dark"] .wrap{color:#dce6f2}
[data-theme="dark"] h1,[data-theme="dark"] h2,[data-theme="dark"] h3,[data-theme="dark"] h4,[data-theme="dark"] .name,[data-theme="dark"] .statnum,[data-theme="dark"] .kpi .v{color:#eef5fc}
[data-theme="dark"] .muted,[data-theme="dark"] .dashboard-statusline,[data-theme="dark"] .chart-empty,[data-theme="dark"] .empty{color:#91a2b7!important}
[data-theme="dark"] .card,[data-theme="dark"] .panel,[data-theme="dark"] .kpi,[data-theme="dark"] .modal-card,[data-theme="dark"] .device-hero-card,[data-theme="dark"] .integration-card,[data-theme="dark"] .notification-card,[data-theme="dark"] .security-card,[data-theme="dark"] .report-card{background:#111a25!important;border-color:#273548!important;color:#dce6f2}
[data-theme="dark"] .card:hover,[data-theme="dark"] .dashboard-table tbody tr:hover,[data-theme="dark"] tr:hover{background:#152131!important}
[data-theme="dark"] .label,[data-theme="dark"] th,[data-theme="dark"] .statmeta,[data-theme="dark"] .kpi .k{color:#8ea0b6!important}
[data-theme="dark"] table{color:#d6e1ec}
[data-theme="dark"] th,[data-theme="dark"] td{border-bottom-color:#263244!important}
[data-theme="dark"] thead{background:#0f1823}
[data-theme="dark"] .input,[data-theme="dark"] input,[data-theme="dark"] textarea,[data-theme="dark"] select,[data-theme="dark"] .filter{background:#0d1621!important;border-color:#304056!important;color:#e6eef7!important}
[data-theme="dark"] input::placeholder,[data-theme="dark"] textarea::placeholder{color:#71839a!important}
[data-theme="dark"] button:not(.primary):not(.danger):not(.navitem):not(.link):not(.traffic-source-card):not(.theme-toggle){background:#152131;border-color:#304056;color:#dce6f2}
[data-theme="dark"] button:not(.primary):not(.danger):not(.navitem):not(.link):not(.traffic-source-card):not(.theme-toggle):hover{background:#1a293b}
[data-theme="dark"] .theme-toggle{background:#152131;border-color:#304056;color:#e7eef7}
[data-theme="dark"] .theme-toggle:hover{background:#1b2a3d;border-color:#3a4d66}
[data-theme="dark"] .user-chip{color:#bdcad9!important}
[data-theme="dark"] .user-menu{background:#111a25;border-color:#2a394d;box-shadow:0 18px 45px rgba(0,0,0,.45)}
[data-theme="dark"] .user-menu button{background:#111a25!important;color:#dce6f2!important}
[data-theme="dark"] .user-menu button:hover{background:#182536!important}
[data-theme="dark"] .avatar{background:#1a2b40!important;color:#dce9f8!important}
[data-theme="dark"] .status-chip{background:#102419!important;border-color:#224c35!important;color:#75d8aa!important}
[data-theme="dark"] .panel-subtle{background:#0e1722;border-top-color:#273548;color:#91a2b7}
[data-theme="dark"] .device-link{color:#6ab0ff!important}
[data-theme="dark"] .back-btn{background:#111a25!important;border-color:#304056!important;color:#cfe2f7!important}
[data-theme="dark"] .healthbar{background:#0e1722;border-bottom-color:#263244}
[data-theme="dark"] .modal{background:rgba(2,7,13,.76)}
[data-theme="dark"] .modal-card h2,[data-theme="dark"] .modal-card h3{color:#eef5fc}
[data-theme="dark"] .userForm{border-bottom-color:#273548}
[data-theme="dark"] .pill{background:#101a26;border-color:#35465e;color:#a9b9cb}
[data-theme="dark"] .trend{color:#8fa4bc}
[data-theme="dark"] .activity-row,[data-theme="dark"] .finding-row,[data-theme="dark"] .setting-row{border-color:#273548!important}
[data-theme="dark"] .activity-title{color:#dce6f2}
[data-theme="dark"] pre,[data-theme="dark"] code{background:#09111a!important;color:#d7e6f6!important;border-color:#26374b!important}
[data-theme="dark"] .traffic-collection-head{background:linear-gradient(180deg,#111a25,#0f1822)!important}
[data-theme="dark"] .traffic-title-icon{background:#102a45;color:#66b4ff;box-shadow:inset 0 0 0 1px #1c4267}
[data-theme="dark"] .traffic-summary-card{background:#101925;border-color:#29384b}
[data-theme="dark"] .traffic-summary-card .k{color:#8fa1b7}
[data-theme="dark"] .traffic-summary-card .v{color:#edf5fd}
[data-theme="dark"] .traffic-summary-card .sub{color:#8396ad}
[data-theme="dark"] .traffic-section-label{color:#9badc1}
[data-theme="dark"] .traffic-source-card{background:#0f1823;border-color:#2b3b50;color:#ced9e6}
[data-theme="dark"] .traffic-source-card:hover{background:#142033;border-color:#45729e}
[data-theme="dark"] .traffic-source-card.active{background:#10243a;border-color:#2587f6;box-shadow:0 0 0 2px rgba(37,135,246,.13)}
[data-theme="dark"] .traffic-source-icon{background:#152d47;color:#71bbff}
[data-theme="dark"] .traffic-source-name{color:#e2ecf6}
[data-theme="dark"] .traffic-source-desc{color:#90a2b7}
[data-theme="dark"] .traffic-source-kind{color:#74879e}
[data-theme="dark"] .traffic-source-divider{background:#263548}
[data-theme="dark"] .traffic-source-meta{color:#8ea1b8}
[data-theme="dark"] .traffic-source-meta b{color:#c2d2e3}
[data-theme="dark"] .traffic-source-foot{color:#7f92aa}
[data-theme="dark"] .traffic-source-tag{background:#151f2c;border-color:#304157;color:#a8b9cb}
[data-theme="dark"] .traffic-source-tag.recommended{background:#10281e;border-color:#24523c;color:#72d0a3}
[data-theme="dark"] .traffic-source-tag.advanced{background:#2a2313;border-color:#5d4d22;color:#ebc65e}

[data-theme="dark"] .traffic-config-card,[data-theme="dark"] .traffic-help-card{background:#0e1722;border-color:#29384b}
[data-theme="dark"] .traffic-config-grid label{color:#9badc1}
[data-theme="dark"] .traffic-help-card{background:linear-gradient(180deg,#101b29,#0d1621)}
[data-theme="dark"] .traffic-help-title{color:#d9e7f5}
[data-theme="dark"] .traffic-help-copy{color:#9aacbf}
[data-theme="dark"] .traffic-help-require{background:#111c29;border-color:#2a3a4f;color:#9eb1c6}
[data-theme="dark"] .traffic-usage-head{background:#0e1722;border-color:#263548}
[data-theme="dark"] .traffic-usage-head h3{color:#dce8f4}
[data-theme="dark"] .traffic-device-name{color:#dce8f4}
[data-theme="dark"] .traffic-source-chip{background:#142a40;color:#83bdf3}
[data-theme="dark"] .traffic-state{background:#101925;border-color:#304056;color:#a9b9cb}
[data-theme="dark"] .traffic-state.success{background:#10271d;border-color:#26553e;color:#73d3a6}
[data-theme="dark"] .traffic-state.failed{background:#2a1419;border-color:#62303b;color:#ff8596}
[data-theme="dark"] .traffic-state.waiting_profile,[data-theme="dark"] .traffic-state.awaiting_sensor,[data-theme="dark"] .traffic-state.configured{background:#2a2413;border-color:#665825;color:#f2c95d}
[data-theme="dark"] .integration-card .muted,[data-theme="dark"] .notification-card .muted{color:#8fa1b7!important}
[data-theme="dark"] .integration-badge,[data-theme="dark"] .type-badge{background:#142438!important;color:#9cc9f5!important;border-color:#2e4d70!important}
[data-theme="dark"] .analytics-card,[data-theme="dark"] .monitor-summary-card{background:#101925!important;border-color:#29384b!important}
[data-theme="dark"] .monitor-summary-card strong,[data-theme="dark"] .analytics-card strong{color:#eef5fc!important}
[data-theme="dark"] .report-summary,[data-theme="dark"] #reportSummary{background:#0a121c!important;color:#d8e6f5!important;border-color:#27384b!important}
[data-theme="dark"] .security-grid .card,[data-theme="dark"] .settings-grid .card{background:#111a25!important}
[data-theme="dark"] .toast{background:#152131!important;border-color:#34465e!important;color:#e6eef7!important}

/* v4.1 — complete dark-surface coverage, brighter typography, report workspace */
[data-theme="dark"] body,[data-theme="dark"] .wrap,[data-theme="dark"] .content,[data-theme="dark"] table{color:#f1f6fc!important}
[data-theme="dark"] h1,[data-theme="dark"] h2,[data-theme="dark"] h3,[data-theme="dark"] h4,[data-theme="dark"] h5,
[data-theme="dark"] .name,[data-theme="dark"] .statnum,[data-theme="dark"] .num,[data-theme="dark"] .kpi .v,[data-theme="dark"] strong,[data-theme="dark"] b{color:#fbfdff!important}
[data-theme="dark"] .muted,[data-theme="dark"] .dashboard-statusline,[data-theme="dark"] .chart-empty,[data-theme="dark"] .empty,
[data-theme="dark"] .activity-sub,[data-theme="dark"] .activity-time,[data-theme="dark"] .map-sub,[data-theme="dark"] .network-generated{color:#bdcada!important}
[data-theme="dark"] th,[data-theme="dark"] .label,[data-theme="dark"] .statmeta,[data-theme="dark"] .kpi .k{color:#b7c5d6!important}
[data-theme="dark"] td{color:#f0f5fb!important}
[data-theme="dark"] a,[data-theme="dark"] button.link,[data-theme="dark"] .device-link{color:#8fcbff!important}

/* eliminate white cards across dashboard views */
[data-theme="dark"] .tool-card,
[data-theme="dark"] .map-card,
[data-theme="dark"] .map-summary-card,
[data-theme="dark"] .map-side-card,
[data-theme="dark"] .network-topology-panel,
[data-theme="dark"] .network-device-card,
[data-theme="dark"] .network-connected-card,
[data-theme="dark"] .network-controls-card,
[data-theme="dark"] .notify-card,
[data-theme="dark"] .remove-summary,
[data-theme="dark"] .intel-stat,
[data-theme="dark"] .intel-section,
[data-theme="dark"] .device-icon-summary-art,
[data-theme="dark"] .device-icon-choice,
[data-theme="dark"] .custom-icon-preview,
[data-theme="dark"] .analytics-card,
[data-theme="dark"] .monitor-summary-card,
[data-theme="dark"] .map-node,
[data-theme="dark"] .cards .card,
[data-theme="dark"] .settings-card,
[data-theme="dark"] .security-card{
 background:#111a25!important;border-color:#2b3a4e!important;color:#f1f6fc!important;box-shadow:0 5px 18px rgba(0,0,0,.16)!important
}
[data-theme="dark"] .tool-card:hover,[data-theme="dark"] .map-summary-card:hover,[data-theme="dark"] .map-side-card:hover,
[data-theme="dark"] .network-device-card:hover,[data-theme="dark"] .network-connected-card:hover,[data-theme="dark"] .network-controls-card:hover,
[data-theme="dark"] .notify-card:hover,[data-theme="dark"] .analytics-card:hover,[data-theme="dark"] .monitor-summary-card:hover{
 background:#172334!important;border-color:#405772!important
}
[data-theme="dark"] .tool-card h2,[data-theme="dark"] .tool-card h3,[data-theme="dark"] .network-device-card h3,
[data-theme="dark"] .network-connected-card h3,[data-theme="dark"] .network-controls-card h3,[data-theme="dark"] .notify-card h3,
[data-theme="dark"] .intel-section h3{color:#fbfdff!important}
[data-theme="dark"] .tool-card p,[data-theme="dark"] .notify-desc,[data-theme="dark"] .intel-kv .k,[data-theme="dark"] .intel-list,
[data-theme="dark"] .connected-device-row .connected-type,[data-theme="dark"] .connected-device-row .connected-ip,
[data-theme="dark"] .network-empty-side,[data-theme="dark"] .map-evidence-note{color:#bdcada!important}
[data-theme="dark"] .tool-card .tool-icon,[data-theme="dark"] .network-device-card .tool-icon{background:#132d49!important;color:#7dc2ff!important}
[data-theme="dark"] .map-layout-btn{background:#101925!important;border-color:#304158!important;color:#f2f7fc!important}
[data-theme="dark"] .map-layout-btn:hover{background:#18273a!important}
[data-theme="dark"] .network-filter{background:#111a25!important;border-color:#2b3a4e!important;color:#e7eff8!important}
[data-theme="dark"] .network-filter.active{background:#17365b!important;border-color:#388ee9!important;color:#fff!important}
[data-theme="dark"] .network-filter.offline:not(.active){background:#111a25!important;color:#e7eff8!important}
[data-theme="dark"] .network-map-footer,[data-theme="dark"] .map-toolbar,[data-theme="dark"] .network-map-header{background:#0e1722!important;border-color:#2a394d!important}
[data-theme="dark"] .connected-device-row{border-color:#27374a!important}
[data-theme="dark"] .connected-device-row .connected-name{color:#91ccff!important}
[data-theme="dark"] .intel-section h3,[data-theme="dark"] .timeline-row{border-color:#29384b!important}
[data-theme="dark"] .device-icon-choice:hover{background:#172538!important;border-color:#49759f!important}
[data-theme="dark"] .device-icon-choice.selected{background:#122947!important;border-color:#2c8df5!important}
[data-theme="dark"] .device-icon-summary-name{color:#8bc9ff!important}
[data-theme="dark"] .device-icon-summary-meta{color:#bdcada!important}
[data-theme="dark"] .device-icon-tabs{border-color:#29384b!important}
[data-theme="dark"] .device-icon-tab{color:#b7c5d6!important}
[data-theme="dark"] .device-icon-tab.active{color:#8fcbff!important;border-bottom-color:#3598ff!important}
[data-theme="dark"] .protected-audit{background:#2a2414!important}
[data-theme="dark"] .sortable-head:hover{background:#142033!important;color:#e6f2ff!important}

/* report page visually matches approved preview */
.report-workspace{display:grid;gap:16px}
.report-hero{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;padding:0 0 2px}
.report-hero-copy{display:flex;align-items:center;gap:12px}
.report-hero-icon{width:42px;height:42px;border-radius:11px;display:grid;place-items:center;background:#eaf4ff;color:#1479e6;font-size:18px;font-weight:800}
.report-generate-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.report-kpi-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.report-kpi{background:#fff;border:1px solid #e2e9f1;border-radius:11px;padding:13px 14px;box-shadow:0 3px 12px rgba(25,45,70,.045)}
.report-kpi .k{font-size:9px;letter-spacing:.07em;text-transform:uppercase;color:#7f8fa3;font-weight:800}
.report-kpi .v{font-size:21px;font-weight:780;color:#20354d;margin-top:5px}
.report-kpi .sub{font-size:9px;color:#8b9aac;margin-top:3px}
.report-grid-two{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(360px,.85fr);gap:16px}
.report-section-card{background:#fff;border:1px solid #e1e8f0;border-radius:12px;overflow:hidden;box-shadow:0 3px 12px rgba(25,45,70,.045)}
.report-section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px;border-bottom:1px solid #e8eef5;background:#fcfdff}
.report-section-title{display:flex;align-items:center;gap:9px}
.report-section-icon{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;background:#edf6ff;color:#1479e6;font-size:13px}
.report-section-head h2{margin:0;padding:0;border:0;font-size:13px}
.report-section-body{padding:15px 16px}
.report-summary-box{margin:0;white-space:pre-wrap;min-height:170px;max-height:310px;overflow:auto;background:#f7f9fc;border:1px solid #e4eaf1;border-radius:9px;padding:13px;font:10px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;color:#31465f}
.report-schedule-form{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.report-schedule-form .full{grid-column:1/-1}
.report-schedule-form label{display:flex;flex-direction:column;gap:5px;font-size:9px;font-weight:750;color:#63758a}
.report-history-wrap{overflow:auto}
.report-history-wrap table th{white-space:nowrap}
[data-theme="dark"] .report-hero-icon{background:#102a45;color:#79c1ff}
[data-theme="dark"] .report-kpi,[data-theme="dark"] .report-section-card{background:#111a25!important;border-color:#29384b!important;box-shadow:0 5px 18px rgba(0,0,0,.16)!important}
[data-theme="dark"] .report-kpi .k{color:#b8c6d7!important}
[data-theme="dark"] .report-kpi .v{color:#fbfdff!important}
[data-theme="dark"] .report-kpi .sub{color:#bdcada!important}
[data-theme="dark"] .report-section-head{background:#0e1722!important;border-color:#29384b!important}
[data-theme="dark"] .report-section-icon{background:#132d49;color:#7dc2ff}
[data-theme="dark"] .report-section-head h2{color:#fbfdff!important}
[data-theme="dark"] .report-section-body{background:#111a25!important}
[data-theme="dark"] .report-summary-box{background:#09121c!important;border-color:#2a3a4f!important;color:#f2f7fc!important}
[data-theme="dark"] .report-schedule-form label{color:#c0ccda!important}
@media(max-width:1100px){.report-kpi-grid{grid-template-columns:repeat(2,1fr)}.report-grid-two{grid-template-columns:1fr}}
@media(max-width:650px){.report-kpi-grid{grid-template-columns:1fr 1fr}.report-hero{align-items:flex-start;flex-direction:column}.report-generate-bar{width:100%}.report-generate-bar .filter{flex:1}.report-schedule-form{grid-template-columns:1fr}}
@media(max-width:440px){.report-kpi-grid{grid-template-columns:1fr}}

/* v4.2 — final dark-mode surface layer; intentionally last in stylesheet */
html[data-theme="dark"] body,
html[data-theme="dark"] .content,
html[data-theme="dark"] .wrap{background:#080e16!important;color:#f5f9ff!important}
html[data-theme="dark"] h1,html[data-theme="dark"] h2,html[data-theme="dark"] h3,html[data-theme="dark"] h4,
html[data-theme="dark"] h5,html[data-theme="dark"] h6,html[data-theme="dark"] strong,html[data-theme="dark"] b,
html[data-theme="dark"] .name,html[data-theme="dark"] .num,html[data-theme="dark"] .statnum{color:#ffffff!important}
html[data-theme="dark"] .muted,html[data-theme="dark"] p,html[data-theme="dark"] small,
html[data-theme="dark"] .activity-sub,html[data-theme="dark"] .activity-time,
html[data-theme="dark"] .device-icon-summary-meta,html[data-theme="dark"] .network-device-sub,
html[data-theme="dark"] .topology-ip,html[data-theme="dark"] .topology-vendor{color:#c8d4e3!important}
html[data-theme="dark"] th{color:#c3d0df!important;background:#0c1520!important}
html[data-theme="dark"] td{color:#f3f7fc!important}
html[data-theme="dark"] .headerbar{background:#0b121c!important;border-color:#253244!important}
/* Safety net: any card-style surface inside a dashboard view is dark before hover. */
html[data-theme="dark"] .view [class$="-card"],
html[data-theme="dark"] .view [class*="-card "],
html[data-theme="dark"] .view section.card{
 background:#101923!important;border-color:#2a394d!important;color:#f5f9ff!important
}
html[data-theme="dark"] .card,
html[data-theme="dark"] .panel,
html[data-theme="dark"] .tool-card,
html[data-theme="dark"] .intel-stat,
html[data-theme="dark"] .intel-section,
html[data-theme="dark"] .integration-card,
html[data-theme="dark"] .analytics-card,
html[data-theme="dark"] .notify-card,
html[data-theme="dark"] .monitor-summary-card,
html[data-theme="dark"] .notification-card,
html[data-theme="dark"] .security-card,
html[data-theme="dark"] .settings-card,
html[data-theme="dark"] .modal-card,
html[data-theme="dark"] .device-hero-card,
html[data-theme="dark"] .device-icon-summary-art,
html[data-theme="dark"] .device-icon-choice,
html[data-theme="dark"] .network-topology-panel,
html[data-theme="dark"] .network-device-card,
html[data-theme="dark"] .network-connected-card,
html[data-theme="dark"] .network-controls-card,
html[data-theme="dark"] .map-summary-card,
html[data-theme="dark"] .map-side-card,
html[data-theme="dark"] .map-node,
html[data-theme="dark"] .report-kpi,
html[data-theme="dark"] .report-section-card,
html[data-theme="dark"] .traffic-summary-card,
html[data-theme="dark"] .traffic-source-card,
html[data-theme="dark"] .traffic-config-card,
html[data-theme="dark"] .traffic-help-card{
 background:#101923!important;
 border-color:#2a394d!important;
 color:#f5f9ff!important;
 box-shadow:0 5px 18px rgba(0,0,0,.22)!important
}
html[data-theme="dark"] .tool-card:hover,
html[data-theme="dark"] .card:hover,
html[data-theme="dark"] .network-device-card:hover,
html[data-theme="dark"] .network-connected-card:hover,
html[data-theme="dark"] .network-controls-card:hover,
html[data-theme="dark"] .map-summary-card:hover,
html[data-theme="dark"] .analytics-card:hover,
html[data-theme="dark"] .monitor-summary-card:hover{
 background:#172435!important;border-color:#405976!important
}
html[data-theme="dark"] .tool-icon,
html[data-theme="dark"] .report-section-icon,
html[data-theme="dark"] .report-hero-icon,
html[data-theme="dark"] .traffic-title-icon{
 background:#122d49!important;color:#83c8ff!important;border-color:#21496f!important
}
html[data-theme="dark"] input,
html[data-theme="dark"] textarea,
html[data-theme="dark"] select,
html[data-theme="dark"] .input,
html[data-theme="dark"] .filter{
 background:#0a131e!important;border-color:#33465e!important;color:#f7fbff!important
}
html[data-theme="dark"] input::placeholder,html[data-theme="dark"] textarea::placeholder{color:#8fa1b7!important}
html[data-theme="dark"] .secondary,
html[data-theme="dark"] .back-btn,
html[data-theme="dark"] .map-layout-btn,
html[data-theme="dark"] .network-filter:not(.active),
html[data-theme="dark"] button:not(.primary):not(.danger):not(.navitem):not(.link):not(.traffic-source-card):not(.theme-toggle){
 background:#142131!important;border-color:#33465e!important;color:#f4f8fd!important
}
html[data-theme="dark"] .secondary:hover,
html[data-theme="dark"] button:not(.primary):not(.danger):not(.navitem):not(.link):not(.traffic-source-card):not(.theme-toggle):hover{
 background:#1b2a3d!important
}
html[data-theme="dark"] .realistic-map-viewport{
 background-color:#0a121c!important;
 background-image:radial-gradient(#26384b 1px,transparent 1px)!important
}
html[data-theme="dark"] .topology-node:hover,html[data-theme="dark"] .topology-node.selected{
 background:rgba(18,30,44,.98)!important
}
html[data-theme="dark"] .topology-name,
html[data-theme="dark"] .network-device-title,
html[data-theme="dark"] .network-kv .v{color:#f8fbff!important}
html[data-theme="dark"] .network-map-footer .map-zoom,
html[data-theme="dark"] .network-map-legend{
 background:rgba(12,22,33,.97)!important;border-color:#304158!important;color:#c8d4e3!important
}
html[data-theme="dark"] .panel-subtle,
html[data-theme="dark"] .report-section-head,
html[data-theme="dark"] .traffic-collection-head,
html[data-theme="dark"] .traffic-usage-head,
html[data-theme="dark"] .table-head{
 background:#0d1621!important;border-color:#28384c!important;color:#f7fbff!important
}
html[data-theme="dark"] .report-summary-box,
html[data-theme="dark"] #reportSummary,
html[data-theme="dark"] pre,
html[data-theme="dark"] code,
html[data-theme="dark"] .result{
 background:#07101a!important;border-color:#293c52!important;color:#f5f9ff!important
}
html[data-theme="dark"] .traffic-source-card:hover{background:#172538!important}
html[data-theme="dark"] .traffic-source-card.active{background:#102842!important;border-color:#2f91ff!important}
html[data-theme="dark"] .traffic-source-name,html[data-theme="dark"] .traffic-device-name,
html[data-theme="dark"] .traffic-help-title{color:#ffffff!important}
html[data-theme="dark"] .traffic-source-desc,html[data-theme="dark"] .traffic-help-copy,
html[data-theme="dark"] .traffic-config-grid label,html[data-theme="dark"] .traffic-source-meta{color:#c5d2e1!important}

/* Login follows selected appearance too */
html[data-theme="dark"] .overlay{
 background-image:linear-gradient(rgba(2,7,12,.55),rgba(2,7,12,.78)),url('/assets/login-bg.jpg')!important;
 background-color:#050a10!important
}
html[data-theme="dark"] .login-scene{background-color:#060b12!important}
html[data-theme="dark"] .login-scene:before{background:linear-gradient(180deg,rgba(4,9,15,.22),rgba(4,9,15,.68))!important}
html[data-theme="dark"] .authcard{
 background:rgba(13,22,33,.96)!important;
 border:1px solid #304158!important;
 color:#f7fbff!important;
 box-shadow:0 26px 80px rgba(0,0,0,.52)!important
}
html[data-theme="dark"] .authcard h1,html[data-theme="dark"] .authcard h2{color:#ffffff!important}
html[data-theme="dark"] .authcard .muted,html[data-theme="dark"] .login-scene-footer{color:#c7d3e2!important}
html[data-theme="dark"] .authcard input{
 background:#08111b!important;border-color:#344960!important;color:#ffffff!important
}
html[data-theme="dark"] .authcard input::placeholder{color:#91a5bc!important}
html[data-theme="dark"] .authcard label{color:#d9e3ee!important}
html[data-theme="dark"] .authcard .secondary{background:#132030!important;color:#f5f9ff!important;border-color:#344960!important}

/* report-type cards */
.report-type-section{margin-top:4px}
.report-type-label{font-size:9px;font-weight:850;letter-spacing:.08em;text-transform:uppercase;color:#718399;margin-bottom:9px}
.report-type-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.report-type-card{appearance:none;text-align:left;background:#fff;border:1px solid #e0e7ef;border-radius:12px;padding:13px;min-height:128px;cursor:pointer;transition:.15s ease;position:relative;box-shadow:0 3px 12px rgba(24,53,82,.045);color:#2d435d}
.report-type-card:hover{transform:translateY(-1px);border-color:#a6cef6;box-shadow:0 8px 22px rgba(24,73,119,.09)}
.report-type-card.active{background:#f2f8ff;border-color:#2587f6;box-shadow:0 0 0 2px rgba(37,135,246,.09),0 8px 22px rgba(24,73,119,.08)}
.report-type-card.active:before{content:"";position:absolute;left:0;top:12px;bottom:12px;width:3px;background:#167cf0;border-radius:0 3px 3px 0}
.report-type-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.report-type-icon{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;background:#edf6ff;color:#1479e6;font-size:15px;font-weight:800}
.report-type-card.active .report-type-icon{background:#167cf0;color:#fff}
.report-type-check{display:none;width:18px;height:18px;border-radius:50%;background:#167cf0;color:#fff;place-items:center;font-size:9px;font-weight:900}
.report-type-card.active .report-type-check{display:grid}
.report-type-name{font-size:11px;font-weight:800;color:#22384f;margin-top:10px}
.report-type-desc{font-size:9px;line-height:1.45;color:#74869a;margin-top:4px}
.report-type-foot{font-size:8px;color:#8b99a9;margin-top:9px;padding-top:8px;border-top:1px solid #edf2f6}
html[data-theme="dark"] .report-type-label{color:#bdcada}
html[data-theme="dark"] .report-type-card{background:#101923!important;border-color:#2a394d!important;color:#f5f9ff!important;box-shadow:0 5px 18px rgba(0,0,0,.18)!important}
html[data-theme="dark"] .report-type-card:hover{background:#172435!important;border-color:#46617f!important}
html[data-theme="dark"] .report-type-card.active{background:#102842!important;border-color:#2f91ff!important}
html[data-theme="dark"] .report-type-icon{background:#122d49!important;color:#83c8ff!important}
html[data-theme="dark"] .report-type-card.active .report-type-icon{background:#167cf0!important;color:#fff!important}
html[data-theme="dark"] .report-type-name{color:#ffffff!important}
html[data-theme="dark"] .report-type-desc,html[data-theme="dark"] .report-type-foot{color:#c5d2e1!important}
html[data-theme="dark"] .report-type-foot{border-color:#29384b!important}
@media(max-width:1100px){.report-type-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.report-type-grid{grid-template-columns:1fr}}

/* v4.3 — hard dark-surface normalization. KEEP LAST. */
html[data-theme="dark"],
html[data-theme="dark"] body{
  --gs-bg:#080e16;
  --gs-surface:#101923;
  --gs-surface-2:#0d1621;
  --gs-surface-hover:#172435;
  --gs-border:#2a394d;
  --gs-border-strong:#3a506a;
  --gs-text:#f8fbff;
  --gs-text-soft:#cbd7e5;
  --gs-blue:#83c8ff;
  background:var(--gs-bg)!important;
  color:var(--gs-text)!important;
}
html[data-theme="dark"] .content,
html[data-theme="dark"] .wrap,
html[data-theme="dark"] .view,
html[data-theme="dark"] main{background:var(--gs-bg)!important;color:var(--gs-text)!important}

/* Explicitly neutralize every remaining light structural surface. */
html[data-theme="dark"] .card,
html[data-theme="dark"] .panel,
html[data-theme="dark"] .tool-card,
html[data-theme="dark"] .integration-card,
html[data-theme="dark"] .modal-card,
html[data-theme="dark"] .monitor-summary-card,
html[data-theme="dark"] .map-node,
html[data-theme="dark"] .map-summary-card,
html[data-theme="dark"] .map-side-card,
html[data-theme="dark"] .network-topology-panel,
html[data-theme="dark"] .network-device-card,
html[data-theme="dark"] .network-connected-card,
html[data-theme="dark"] .network-controls-card,
html[data-theme="dark"] .custom-icon-preview,
html[data-theme="dark"] .remove-summary,
html[data-theme="dark"] .notify-card,
html[data-theme="dark"] .report-kpi,
html[data-theme="dark"] .report-section-card,
html[data-theme="dark"] .report-type-card,
html[data-theme="dark"] .traffic-shell-card,
html[data-theme="dark"] .traffic-stat-card,
html[data-theme="dark"] .traffic-source-card,
html[data-theme="dark"] .traffic-config-card,
html[data-theme="dark"] .traffic-help-card,
html[data-theme="dark"] .traffic-usage-card,
html[data-theme="dark"] .healthbar,
html[data-theme="dark"] .user-menu,
html[data-theme="dark"] .back-btn,
html[data-theme="dark"] .protected-audit{
  background:var(--gs-surface)!important;
  background-image:none!important;
  border-color:var(--gs-border)!important;
  color:var(--gs-text)!important;
  box-shadow:0 5px 18px rgba(0,0,0,.22)!important;
}

/* Any future component named card/panel/surface also defaults dark. */
html[data-theme="dark"] .view [class~="card"],
html[data-theme="dark"] .view [class$="-card"],
html[data-theme="dark"] .view [class*="-card "],
html[data-theme="dark"] .view [class$="-panel"],
html[data-theme="dark"] .view [class*="-panel "],
html[data-theme="dark"] .view [class$="-surface"],
html[data-theme="dark"] .view [class*="-surface "]{
  background-color:var(--gs-surface)!important;
  border-color:var(--gs-border)!important;
  color:var(--gs-text)!important;
}
/* Catch legacy inline white backgrounds in SPA views. */
html[data-theme="dark"] .view [style*="background:#fff"],
html[data-theme="dark"] .view [style*="background: #fff"],
html[data-theme="dark"] .view [style*="background:white"],
html[data-theme="dark"] .view [style*="background: white"],
html[data-theme="dark"] .view [style*="background-color:#fff"],
html[data-theme="dark"] .view [style*="background-color: #fff"]{
  background:var(--gs-surface)!important;
  background-image:none!important;
  color:var(--gs-text)!important;
}

/* Rest/hover states must both remain dark. */
html[data-theme="dark"] .card:hover,
html[data-theme="dark"] .panel:hover,
html[data-theme="dark"] .tool-card:hover,
html[data-theme="dark"] .integration-card:hover,
html[data-theme="dark"] .monitor-summary-card:hover,
html[data-theme="dark"] .map-node:hover,
html[data-theme="dark"] .map-summary-card:hover,
html[data-theme="dark"] .map-side-card:hover,
html[data-theme="dark"] .network-device-card:hover,
html[data-theme="dark"] .network-connected-card:hover,
html[data-theme="dark"] .network-controls-card:hover,
html[data-theme="dark"] .report-kpi:hover,
html[data-theme="dark"] .report-section-card:hover,
html[data-theme="dark"] .report-type-card:hover,
html[data-theme="dark"] .traffic-source-card:hover,
html[data-theme="dark"] .traffic-stat-card:hover{
  background:var(--gs-surface-hover)!important;
  border-color:var(--gs-border-strong)!important;
  color:var(--gs-text)!important;
}

/* Light-form and table rules that previously leaked through on some views. */
html[data-theme="dark"] .panel table,
html[data-theme="dark"] table,
html[data-theme="dark"] tbody,
html[data-theme="dark"] tr{background:transparent!important;color:var(--gs-text)!important}
html[data-theme="dark"] thead,
html[data-theme="dark"] th{background:var(--gs-surface-2)!important;color:#d4dfeb!important}
html[data-theme="dark"] td{background:transparent!important;color:#f5f9ff!important;border-color:#26374a!important}
html[data-theme="dark"] button,
html[data-theme="dark"] .filter,
html[data-theme="dark"] .input,
html[data-theme="dark"] input,
html[data-theme="dark"] textarea,
html[data-theme="dark"] select{
  border-color:#344960!important;
}
html[data-theme="dark"] .filter,
html[data-theme="dark"] .input,
html[data-theme="dark"] input,
html[data-theme="dark"] textarea,
html[data-theme="dark"] select{
  background:#09131e!important;color:#f8fbff!important;
}
html[data-theme="dark"] button.secondary,
html[data-theme="dark"] .secondary,
html[data-theme="dark"] .map-layout-btn,
html[data-theme="dark"] .monitor-actions .link,
html[data-theme="dark"] .modal-head .icon-btn,
html[data-theme="dark"] .integration-remove{
  background:#142131!important;color:#f7fbff!important;border-color:#344960!important;
}

/* No white status/removal chips in dark mode. */
html[data-theme="dark"] .status-badge.severity-high,
html[data-theme="dark"] .status-badge.severity-critical{background:#35151b!important;color:#ff9baa!important;border-color:#6b2c38!important}
html[data-theme="dark"] .status-badge.severity-medium,
html[data-theme="dark"] .status-badge.severity-warning{background:#322711!important;color:#ffd56a!important;border-color:#6f5924!important}
html[data-theme="dark"] .status-badge.severity-low{background:#102a43!important;color:#8ac9ff!important;border-color:#29567f!important}
html[data-theme="dark"] .integration-state.failed{background:#35151b!important;color:#ff9baa!important}
html[data-theme="dark"] .network-filter.offline:not(.active){background:#142131!important;color:#eef5fc!important}

/* Bright text. */
html[data-theme="dark"] h1,
html[data-theme="dark"] h2,
html[data-theme="dark"] h3,
html[data-theme="dark"] h4,
html[data-theme="dark"] h5,
html[data-theme="dark"] h6,
html[data-theme="dark"] strong,
html[data-theme="dark"] b,
html[data-theme="dark"] .traffic-source-name,
html[data-theme="dark"] .traffic-stat-value,
html[data-theme="dark"] .report-type-name{color:#ffffff!important}
html[data-theme="dark"] .muted,
html[data-theme="dark"] p,
html[data-theme="dark"] small,
html[data-theme="dark"] .traffic-source-desc,
html[data-theme="dark"] .traffic-stat-sub,
html[data-theme="dark"] .report-type-desc{color:var(--gs-text-soft)!important}
html[data-theme="dark"] .analytics-card .metric,
html[data-theme="dark"] .analytics-card .sub{color:#9cc9f5!important}
html[data-theme="dark"] a,
html[data-theme="dark"] .device-link,
html[data-theme="dark"] button.link{color:var(--gs-blue)!important}

/* Login must follow dark mode from first paint. */
html[data-theme="dark"] .overlay{
  background-image:linear-gradient(rgba(2,7,12,.64),rgba(2,7,12,.84)),url('/assets/login-bg.jpg')!important;
  background-color:#04090f!important;
}
html[data-theme="dark"] .authcard{
  background:#0d1722!important;
  background-image:none!important;
  border-color:#344960!important;
  color:#f8fbff!important;
  box-shadow:0 28px 90px rgba(0,0,0,.58)!important;
}
html[data-theme="dark"] .authcard input{
  background:#07111b!important;color:#fff!important;border-color:#3a5069!important
}
html[data-theme="dark"] .authcard label,
html[data-theme="dark"] .authcard h1,
html[data-theme="dark"] .authcard h2{color:#fff!important}
html[data-theme="dark"] .authcard .muted,
html[data-theme="dark"] .login-scene-footer{color:#cbd7e5!important}

/* Per-device traffic collection is a real card workspace. */
.traffic-card-workspace{display:grid;gap:14px}
.traffic-card-heading{display:flex;align-items:center;justify-content:space-between;gap:14px}
.traffic-card-heading-copy{display:flex;align-items:center;gap:11px}
.traffic-card-heading h2{margin:0;font-size:15px}
.traffic-card-heading .muted{margin-top:3px}
.traffic-stat-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.traffic-stat-card{background:#fff;border:1px solid #e1e8f0;border-radius:12px;padding:14px;box-shadow:0 3px 12px rgba(25,45,70,.045);min-height:91px}
.traffic-stat-icon{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;background:#edf6ff;color:#1479e6;font-size:13px;float:right}
.traffic-stat-label{font-size:8px;font-weight:850;letter-spacing:.075em;text-transform:uppercase;color:#7d8da0}
.traffic-stat-value{font-size:20px;font-weight:800;color:#20354d;margin-top:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.traffic-stat-sub{font-size:8px;color:#8b9aac;margin-top:3px}
.traffic-source-section-card,.traffic-config-section-card,.traffic-usage-card{background:#fff;border:1px solid #e1e8f0;border-radius:12px;box-shadow:0 3px 12px rgba(25,45,70,.045);overflow:hidden}
.traffic-card-section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 15px;border-bottom:1px solid #e8eef5;background:#fcfdff}
.traffic-card-section-title{display:flex;align-items:center;gap:9px}
.traffic-card-section-title .traffic-section-icon{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;background:#edf6ff;color:#1479e6;font-size:13px}
.traffic-card-section-title h3{margin:0;font-size:12px}
.traffic-card-section-body{padding:14px}
.traffic-config-card-grid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(300px,.85fr);gap:12px}
.traffic-mini-card{background:#f9fbfd;border:1px solid #e4eaf1;border-radius:10px;padding:13px}
.traffic-mini-card h4{margin:0 0 10px;font-size:11px;color:#30465f}
.traffic-config-fields{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.traffic-config-fields label{display:flex;flex-direction:column;gap:5px;font-size:9px;font-weight:750;color:#63758a}
.traffic-config-actions-card{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:11px}
html[data-theme="dark"] .traffic-source-section-card,
html[data-theme="dark"] .traffic-config-section-card,
html[data-theme="dark"] .traffic-usage-card,
html[data-theme="dark"] .traffic-mini-card{background:#101923!important;border-color:#2a394d!important;color:#f8fbff!important}
html[data-theme="dark"] .traffic-card-section-head{background:#0d1621!important;border-color:#29394d!important}
html[data-theme="dark"] .traffic-card-section-title .traffic-section-icon,
html[data-theme="dark"] .traffic-stat-icon{background:#122d49!important;color:#83c8ff!important}
html[data-theme="dark"] .traffic-mini-card h4{color:#fff!important}
html[data-theme="dark"] .traffic-config-fields label{color:#cbd7e5!important}
@media(max-width:1100px){.traffic-stat-grid{grid-template-columns:repeat(2,1fr)}.traffic-config-card-grid{grid-template-columns:1fr}}
@media(max-width:600px){.traffic-stat-grid{grid-template-columns:1fr}.traffic-config-fields{grid-template-columns:1fr}}

/* v4.5 — integration card Pi-hole blue supporting text */
.integration-card .integration-meta,
.integration-card .integration-meta .muted{
  color:#1872d7!important;
}
html[data-theme="dark"] .integration-card .integration-meta,
html[data-theme="dark"] .integration-card .integration-meta .muted{
  color:#9cc9f5!important;
}

/* v4.6 — calmer traffic source cards + unified Pi-hole blue in dark mode */
.traffic-source-grid{grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.traffic-source-card[data-clean="1"]{
  min-height:160px!important;padding:15px!important;display:flex!important;flex-direction:column!important;
  justify-content:space-between!important;text-align:left!important;border-radius:12px!important;
}
.traffic-source-card-head{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:10px}
.traffic-source-card[data-clean="1"] .traffic-source-name{margin:0!important;font-size:12px!important;line-height:1.25}
.traffic-source-card[data-clean="1"] .traffic-source-kind{margin-top:2px;font-size:8px!important;font-weight:800;letter-spacing:.04em!important;text-transform:uppercase}
.traffic-source-card[data-clean="1"] .traffic-source-desc{margin-top:13px!important;min-height:42px!important;font-size:9px!important;line-height:1.55!important}
.traffic-source-card[data-clean="1"] .traffic-source-divider,
.traffic-source-card[data-clean="1"] .traffic-source-meta{display:none!important}
.traffic-source-card[data-clean="1"] .traffic-source-foot{
  display:flex!important;align-items:center!important;justify-content:space-between!important;gap:10px!important;
  margin-top:13px!important;padding-top:10px!important;border-top:1px solid #e9eef4!important;font-size:8px!important;
}
.traffic-source-card[data-clean="1"] .traffic-source-foot>span:last-child{color:#8a99aa;white-space:nowrap}
.traffic-source-card[data-clean="1"] .traffic-source-icon{width:34px!important;height:34px!important;border-radius:9px!important;font-size:15px!important}
.traffic-source-card[data-clean="1"] .traffic-selected-check{width:19px!important;height:19px!important}
html[data-theme="dark"]{--gs-blue:#9cc9f5!important}
html[data-theme="dark"] a,
html[data-theme="dark"] .device-link,
html[data-theme="dark"] button.link,
html[data-theme="dark"] .integration-badge,
html[data-theme="dark"] .type-badge,
html[data-theme="dark"] .analytics-card .metric,
html[data-theme="dark"] .analytics-card .sub,
html[data-theme="dark"] .integration-card .integration-meta,
html[data-theme="dark"] .integration-card .integration-meta .muted,
html[data-theme="dark"] .traffic-source-kind,
html[data-theme="dark"] .traffic-source-icon,
html[data-theme="dark"] .traffic-section-icon,
html[data-theme="dark"] .traffic-stat-icon,
html[data-theme="dark"] .report-section-icon,
html[data-theme="dark"] .report-hero-icon,
html[data-theme="dark"] .report-type-icon,
html[data-theme="dark"] .device-icon-summary-name,
html[data-theme="dark"] .connected-device-row .connected-name{color:#9cc9f5!important}
html[data-theme="dark"] .traffic-source-card[data-clean="1"] .traffic-source-foot{border-top-color:#29394c!important}
html[data-theme="dark"] .traffic-source-card[data-clean="1"] .traffic-source-foot>span:last-child{color:#b5c3d3!important}
html[data-theme="dark"] .traffic-source-card[data-clean="1"] .traffic-source-desc{color:#d1dbe7!important}
html[data-theme="dark"] .traffic-source-card[data-clean="1"] .traffic-source-name{color:#ffffff!important}
html[data-theme="dark"] .traffic-source-card[data-clean="1"].active .traffic-source-icon{background:#173654!important;border-color:#2e5f8b!important;color:#9cc9f5!important}
html[data-theme="dark"] .traffic-source-card[data-clean="1"].active{border-color:#4a83b8!important;box-shadow:0 0 0 1px rgba(156,201,245,.14),0 8px 20px rgba(0,0,0,.2)!important}
@media(max-width:1200px){.traffic-source-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:650px){.traffic-source-grid{grid-template-columns:1fr}}

/* v4.7 — traffic source cards: fixed 2x2 equal-size grid */
.traffic-source-grid{
  display:grid!important;
  grid-template-columns:repeat(2,minmax(0,1fr))!important;
  gap:14px!important;
  width:100%!important;
  max-width:760px!important;
  align-items:stretch!important;
}
.traffic-source-card[data-clean="1"]{
  width:100%!important;
  min-width:0!important;
  height:184px!important;
  min-height:184px!important;
  max-height:184px!important;
  box-sizing:border-box!important;
  margin:0!important;
}
.traffic-source-card[data-clean="1"] .traffic-source-desc{
  min-height:44px!important;
}
@media(max-width:650px){
  .traffic-source-grid{grid-template-columns:1fr!important;max-width:100%!important}
  .traffic-source-card[data-clean="1"]{
    height:184px!important;min-height:184px!important;max-height:184px!important;
  }
}

/* v4.8 — monitoring Pi-hole blue + compact 2x3 Tools launcher */
html[data-theme="dark"] #view-monitoring .monitor-summary-card .k,
html[data-theme="dark"] #view-monitoring .monitor-summary-card:not(.good):not(.bad) .v,
html[data-theme="dark"] #view-monitoring .monitor-target,
html[data-theme="dark"] #view-monitoring .monitor-type-badge,
html[data-theme="dark"] #view-monitoring td:nth-child(3),
html[data-theme="dark"] #view-monitoring td:nth-child(7){
  color:#9cc9f5!important;
}
html[data-theme="dark"] #view-monitoring .monitor-type-badge{
  background:#142438!important;
  border-color:#2e4d70!important;
}
html[data-theme="dark"] #view-monitoring .monitor-summary-card.good .k,
html[data-theme="dark"] #view-monitoring .monitor-summary-card.bad .k{
  color:#9cc9f5!important;
}
/* keep semantic health values green/red */
html[data-theme="dark"] #view-monitoring .monitor-summary-card.good .v{color:#35d391!important}
html[data-theme="dark"] #view-monitoring .monitor-summary-card.bad .v{color:#ff6278!important}
html[data-theme="dark"] #view-monitoring .status-badge{font-weight:800}

/* exactly six launcher cards: two rows of three */
#view-tools .tool-grid{
  display:grid!important;
  grid-template-columns:repeat(3,minmax(0,1fr))!important;
  gap:12px!important;
  align-items:stretch!important;
}
#view-tools .tool-card{
  min-height:122px!important;
  padding:14px!important;
  display:flex!important;
  flex-direction:column!important;
  justify-content:flex-start!important;
}
#view-tools .tool-card .tool-icon{
  width:30px!important;
  height:30px!important;
  font-size:14px!important;
  margin-bottom:7px!important;
}
#view-tools .tool-card h3{
  margin:3px 0 3px!important;
  font-size:12px!important;
}
#view-tools .tool-card p{
  margin:0!important;
  min-height:28px!important;
  font-size:9px!important;
  line-height:1.4!important;
}
#view-tools .tool-card .primary{
  margin-top:auto!important;
  align-self:flex-start!important;
  padding:5px 9px!important;
  font-size:9px!important;
}
html[data-theme="dark"] #view-tools .tool-icon{color:#9cc9f5!important}
@media(max-width:1000px){
  #view-tools .tool-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:650px){
  #view-tools .tool-grid{grid-template-columns:1fr!important}
}
\n/* v4.9 — admin card arrangement */\n.layout-admin-tools{display:none;align-items:center;gap:7px;margin-left:auto}\n.layout-admin-tools.admin-visible{display:flex}\n.layout-arrange-btn,.layout-reset-btn{display:inline-flex!important;align-items:center;gap:6px;white-space:nowrap}\n.layout-reset-btn{display:none!important}\nbody.layout-editing .layout-reset-btn{display:inline-flex!important}\n.layout-zone{position:relative}\nbody.layout-editing .layout-zone{outline:1px dashed rgba(15,125,240,.28);outline-offset:5px;border-radius:10px}\n.layout-movable{position:relative}\nbody.layout-editing .layout-movable{cursor:grab!important;user-select:none;transition:transform .14s ease,box-shadow .14s ease,border-color .14s ease}\nbody.layout-editing .layout-movable::before{content:'⋮⋮';position:absolute;z-index:40;right:8px;top:7px;width:25px;height:22px;border-radius:7px;background:#0f7df0;color:#fff;display:grid;place-items:center;font-size:13px;letter-spacing:-2px;box-shadow:0 4px 12px rgba(15,125,240,.24);pointer-events:none}\nbody.layout-editing .layout-movable:hover{border-color:#5da9ef!important;box-shadow:0 8px 24px rgba(15,80,145,.14)!important}\n.layout-movable.layout-dragging{opacity:.42!important;transform:scale(.985)!important;border:1px dashed #64b4ff!important}\n.layout-movable.layout-drop-target{box-shadow:0 0 0 2px #0f7df0,0 12px 28px rgba(15,125,240,.20)!important;transform:translateY(-2px)!important}\n.layout-save-state{font-size:9px;color:#6f8298;min-width:42px}\nhtml[data-theme="dark"] .layout-save-state{color:#9cc9f5!important}\nhtml[data-theme="dark"] body.layout-editing .layout-zone{outline-color:rgba(156,201,245,.34)}\nhtml[data-theme="dark"] body.layout-editing .layout-movable:hover{border-color:#4d86ba!important}\n@media(max-width:720px){.layout-admin-tools{width:100%;margin-top:8px}.layout-save-state{display:none}}\n
/* v4.10 — compact header help pop-outs */
.hero h1 + .muted,
.hero h1 + p,
.table-head h2 + .muted,
.table-head h2 + p,
.table-head > .muted{
  display:none!important;
}
.header-help-extra{display:none!important}
.header-help-title{
  display:inline-flex;
  align-items:center;
  gap:8px;
  min-width:0;
}
.header-help-btn{
  appearance:none;
  width:21px;
  height:21px;
  min-width:21px;
  border-radius:50%;
  border:1px solid #78b9f3!important;
  background:#e9f5ff!important;
  color:#0d74d9!important;
  display:inline-grid;
  place-items:center;
  padding:0!important;
  font-size:11px!important;
  line-height:1!important;
  font-weight:900!important;
  cursor:pointer;
  box-shadow:none!important;
}
.header-help-btn:hover{
  background:#d8eeff!important;
  border-color:#3f98eb!important;
  transform:none!important;
}
.header-help-modal{
  position:fixed;
  inset:0;
  z-index:12000;
  display:grid;
  place-items:start center;
  padding:84px 18px 18px;
  background:rgba(4,11,19,.48);
  backdrop-filter:blur(2px);
}
.header-help-dialog{
  width:min(560px,calc(100vw - 28px));
  border-radius:13px;
  border:1px solid #d9e4ef;
  background:#fff;
  color:#263b53;
  box-shadow:0 24px 70px rgba(5,19,36,.28);
  overflow:hidden;
}
.header-help-modal-head{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:14px;
  padding:14px 16px;
  border-bottom:1px solid #e6edf4;
}
.header-help-modal-title{
  display:flex;
  align-items:center;
  gap:9px;
  font-size:13px;
  font-weight:800;
  color:#1f344c;
}
.header-help-modal-icon{
  width:25px;
  height:25px;
  border-radius:50%;
  display:grid;
  place-items:center;
  background:#e9f5ff;
  border:1px solid #78b9f3;
  color:#0d74d9;
  font-weight:900;
}
.header-help-close{
  width:29px;
  height:29px;
  border:1px solid #dbe4ee!important;
  border-radius:8px!important;
  background:#f7f9fc!important;
  color:#52667c!important;
  display:grid!important;
  place-items:center!important;
  padding:0!important;
  font-size:16px!important;
  cursor:pointer;
}
.header-help-close:hover{background:#edf2f7!important;color:#1f344c!important}
.header-help-body{
  padding:16px;
  font-size:11px;
  line-height:1.65;
  white-space:pre-line;
  color:#52677f;
}
html[data-theme="dark"] .header-help-btn{
  background:#102c49!important;
  border-color:#4f91c9!important;
  color:#9cc9f5!important;
}
html[data-theme="dark"] .header-help-btn:hover{
  background:#173a5e!important;
  border-color:#6aaee5!important;
}
html[data-theme="dark"] .header-help-modal{background:rgba(2,7,12,.68)}
html[data-theme="dark"] .header-help-dialog{
  background:#101923!important;
  border-color:#31445c!important;
  color:#f7fbff!important;
  box-shadow:0 26px 90px rgba(0,0,0,.52)!important;
}
html[data-theme="dark"] .header-help-modal-head{border-color:#29394d!important}
html[data-theme="dark"] .header-help-modal-title{color:#fff!important}
html[data-theme="dark"] .header-help-modal-icon{
  background:#102c49!important;
  border-color:#4f91c9!important;
  color:#9cc9f5!important;
}
html[data-theme="dark"] .header-help-close{
  background:#142131!important;
  border-color:#344960!important;
  color:#eef5fc!important;
}
html[data-theme="dark"] .header-help-close:hover{background:#1b2b3e!important}
html[data-theme="dark"] .header-help-body{color:#d2dce8!important}

/* v4.12 — complete dark-mode modal normalization */
html[data-theme="dark"] .modal{
  background:rgba(2,7,12,.72)!important;
}
html[data-theme="dark"] .modal .modal-card,
html[data-theme="dark"] .modal-card,
html[data-theme="dark"] .intel-modal-card{
  background:#101923!important;
  background-image:none!important;
  border:1px solid #31445c!important;
  color:#f7fbff!important;
  box-shadow:0 28px 90px rgba(0,0,0,.56)!important;
}
html[data-theme="dark"] .modal .modal-head,
html[data-theme="dark"] .modal-head{
  background:#0d1621!important;
  background-image:none!important;
  border-bottom-color:#2b3b50!important;
  color:#f7fbff!important;
}
html[data-theme="dark"] .modal .modal-head h1,
html[data-theme="dark"] .modal .modal-head h2,
html[data-theme="dark"] .modal .modal-head h3,
html[data-theme="dark"] .modal-head h1,
html[data-theme="dark"] .modal-head h2,
html[data-theme="dark"] .modal-head h3{
  color:#ffffff!important;
}
html[data-theme="dark"] .modal .modal-head .muted,
html[data-theme="dark"] .modal-head .muted{
  color:#b9c8d9!important;
}
html[data-theme="dark"] .modal .modal-head .icon-btn,
html[data-theme="dark"] .modal-head .icon-btn{
  background:#142131!important;
  border-color:#3a4f68!important;
  color:#f7fbff!important;
}
html[data-theme="dark"] .modal .modal-head .icon-btn:hover,
html[data-theme="dark"] .modal-head .icon-btn:hover{
  background:#1d2e42!important;
  border-color:#4f6b8b!important;
  color:#ffffff!important;
}
html[data-theme="dark"] .modal .analytics-summary div,
html[data-theme="dark"] .analytics-summary div{
  background:#111d2a!important;
  border-color:#38506a!important;
  color:#f7fbff!important;
}
html[data-theme="dark"] .modal .analytics-summary b,
html[data-theme="dark"] .analytics-summary b{
  color:#ffffff!important;
}
html[data-theme="dark"] .modal .analytics-summary span,
html[data-theme="dark"] .analytics-summary span{
  color:#9cc9f5!important;
}
html[data-theme="dark"] .modal pre,
html[data-theme="dark"] .modal code,
html[data-theme="dark"] .modal .result,
html[data-theme="dark"] #analyticsDetail{
  background:#07111b!important;
  border-color:#293d53!important;
  color:#f2f7fc!important;
}
html[data-theme="dark"] .modal .modal-form,
html[data-theme="dark"] .modal .modal-actions,
html[data-theme="dark"] .modal .admin-only,
html[data-theme="dark"] .modal [style*="border-top:1px solid #edf2f7"],
html[data-theme="dark"] .modal [style*="border-top: 1px solid #edf2f7"]{
  border-color:#2b3b50!important;
}
html[data-theme="dark"] .modal label,
html[data-theme="dark"] .modal .muted{
  color:#c7d4e3!important;
}
html[data-theme="dark"] .modal input,
html[data-theme="dark"] .modal textarea,
html[data-theme="dark"] .modal select,
html[data-theme="dark"] .modal .input,
html[data-theme="dark"] .modal .filter{
  background:#09131e!important;
  border-color:#3a5069!important;
  color:#ffffff!important;
}
html[data-theme="dark"] .modal input::placeholder,
html[data-theme="dark"] .modal textarea::placeholder{
  color:#91a5bc!important;
}
html[data-theme="dark"] .modal .secondary{
  background:#142131!important;
  border-color:#3a5069!important;
  color:#f7fbff!important;
}
html[data-theme="dark"] .modal .secondary:hover{
  background:#1d2e42!important;
}
html[data-theme="dark"] .modal .danger{
  background:#35151d!important;
  border-color:#6a2d3b!important;
  color:#ff9bab!important;
}
html[data-theme="dark"] .modal .danger:hover{
  background:#451b26!important;
  border-color:#864055!important;
}
/* Prevent inline white backgrounds from leaking into any modal in dark mode. */
html[data-theme="dark"] .modal [style*="background:#fff"],
html[data-theme="dark"] .modal [style*="background: #fff"],
html[data-theme="dark"] .modal [style*="background:white"],
html[data-theme="dark"] .modal [style*="background: white"],
html[data-theme="dark"] .modal [style*="background-color:#fff"],
html[data-theme="dark"] .modal [style*="background-color: #fff"]{
  background:#101923!important;
  background-image:none!important;
  color:#f7fbff!important;
}

/* v4.13 — management calendar */
.calendar-page{display:grid;gap:16px}
.calendar-hero{display:flex;justify-content:space-between;align-items:center;gap:16px}
.calendar-hero-copy{display:flex;align-items:center;gap:12px}
.calendar-hero-copy h1{margin:0 0 4px}
.calendar-hero-icon{width:42px;height:42px;border-radius:11px;display:grid;place-items:center;background:#eaf4ff;color:#1479e6;font-size:18px;font-weight:800}
.calendar-actions{display:flex;gap:8px;flex-wrap:wrap}
.calendar-shell{display:grid;grid-template-columns:250px minmax(0,1fr);gap:14px;align-items:start}
.calendar-side,.calendar-main-card{background:#fff;border:1px solid #e1e8f0;border-radius:12px;box-shadow:0 3px 12px rgba(25,45,70,.045)}
.calendar-side{padding:14px}
.calendar-create{width:100%;border:0;border-radius:12px;background:#fff;box-shadow:0 2px 8px rgba(25,45,70,.11);padding:11px 12px;font-weight:800;color:#23415f;cursor:pointer;border:1px solid #e5ebf2}
.calendar-create:hover{background:#f8fbff}
.calendar-side-block{margin-top:18px}
.calendar-side-title{font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.075em;color:#7c8ca0;margin-bottom:8px}
.calendar-filter{display:flex;align-items:center;gap:8px;font-size:10px;color:#42566e;padding:5px 0}
.calendar-dot{width:9px;height:9px;border-radius:3px;display:inline-block}.calendar-dot.blue{background:#1a73e8}.calendar-dot.purple{background:#8e67d4}
.calendar-upcoming{display:grid;gap:7px}.calendar-upcoming-item{border-left:3px solid #1a73e8;padding:7px 8px;background:#f8fafc;border-radius:0 7px 7px 0}
.calendar-upcoming-item b{display:block;font-size:9px;color:#253c55}.calendar-upcoming-item span{font-size:8px;color:#7f90a4}
.calendar-main-card{overflow:hidden}
.calendar-toolbar{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:13px 15px;border-bottom:1px solid #e6edf4;background:#fcfdff}
.calendar-nav-actions{display:flex;align-items:center;gap:7px}.calendar-nav-actions h2{margin:0 0 0 7px;font-size:15px}
.calendar-view-chip{border:1px solid #dce5ef;border-radius:999px;padding:5px 9px;font-size:9px;color:#56708b;background:#fff}
.calendar-week-head{display:grid;grid-template-columns:repeat(7,1fr);border-bottom:1px solid #e6edf4;background:#f8fafc}
.calendar-week-head span{text-align:center;padding:8px 0;font-size:8px;font-weight:800;color:#74869a;text-transform:uppercase}
.calendar-grid{display:grid;grid-template-columns:repeat(7,1fr);grid-auto-rows:minmax(112px,1fr)}
.calendar-day{border-right:1px solid #e9eef4;border-bottom:1px solid #e9eef4;padding:7px;min-width:0;background:#fff;position:relative}
.calendar-day:nth-child(7n){border-right:0}.calendar-day.outside{background:#fbfcfd}.calendar-day.today{background:#f4f9ff}
.calendar-day-num{font-size:9px;font-weight:800;color:#5e7085;margin-bottom:5px}.calendar-day.today .calendar-day-num{width:24px;height:24px;border-radius:50%;display:grid;place-items:center;background:#1a73e8;color:#fff;margin-top:-2px}
.calendar-event-chip{display:block;width:100%;border:0;border-radius:5px;padding:4px 6px;margin-top:3px;text-align:left;font-size:8px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer;background:#eaf2ff;color:#195eb7}
.calendar-event-chip.green{background:#e8f7ef;color:#28774f}.calendar-event-chip.purple{background:#f0eafd;color:#6b4aab}.calendar-event-chip.orange{background:#fff1df;color:#a96313}.calendar-event-chip.red{background:#ffe7eb;color:#ad3247}
.calendar-event-chip.external:before{content:"↗ ";opacity:.75}
.calendar-more{font-size:8px;color:#657d97;margin-top:4px}
.calendar-event-form,.calendar-integration-form{display:grid;grid-template-columns:1fr 1fr;gap:11px;padding:17px 20px}
.calendar-event-form label,.calendar-integration-form label{display:flex;flex-direction:column;gap:5px;font-size:9px;font-weight:750;color:#60748b}
.calendar-event-form .full,.calendar-integration-form .full{grid-column:1/-1}
.calendar-check{flex-direction:row!important;align-items:center!important}
.calendar-integration-body{padding:16px 20px 20px}
.calendar-provider-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.calendar-provider{appearance:none;text-align:left;border:1px solid #dce5ef;border-radius:11px;padding:12px;background:#fff;color:#2b4059;cursor:pointer;display:grid;grid-template-columns:auto 1fr;column-gap:10px;align-items:center}
.calendar-provider:hover{background:#f8fbff}.calendar-provider.active{border-color:#1a73e8;background:#f2f7ff}
.calendar-provider-icon{grid-row:1/3;width:34px;height:34px;border-radius:9px;background:#eaf3ff;color:#1a73e8;display:grid;place-items:center;font-weight:900}
.calendar-provider b{font-size:10px}.calendar-provider small{font-size:8px;color:#7e90a5;margin-top:2px}
.calendar-integration-note{font-size:9px;color:#72859b;background:#f7f9fc;border:1px solid #e4eaf1;border-radius:8px;padding:10px;line-height:1.5}
.calendar-connected-title{font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.07em;color:#77899e;margin:5px 0 8px}
.calendar-integration-list{display:grid;gap:8px}
.calendar-integration-row{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;border:1px solid #e1e8f0;border-radius:9px;padding:10px}
.calendar-integration-row .calendar-provider-icon{width:30px;height:30px}.calendar-integration-row b{font-size:10px;color:#2b4059}.calendar-integration-row small{display:block;font-size:8px;color:#7d8fa4;margin-top:2px}
.calendar-integration-row .actions{display:flex;gap:6px}
.calendar-integration-dialog{width:min(720px,calc(100vw - 36px))!important}
.calendar-event-dialog{width:min(620px,calc(100vw - 36px))!important}
html[data-theme="dark"] .calendar-hero-icon{background:#102c49;color:#9cc9f5}
html[data-theme="dark"] .calendar-side,html[data-theme="dark"] .calendar-main-card{background:#101923!important;border-color:#2a394d!important}
html[data-theme="dark"] .calendar-create{background:#142131;color:#fff;border-color:#344960;box-shadow:none}
html[data-theme="dark"] .calendar-create:hover{background:#1b2b3e}
html[data-theme="dark"] .calendar-side-title,html[data-theme="dark"] .calendar-week-head span{color:#aebdd0}
html[data-theme="dark"] .calendar-filter{color:#d3deea}
html[data-theme="dark"] .calendar-upcoming-item{background:#0d1722}
html[data-theme="dark"] .calendar-upcoming-item b{color:#fff}html[data-theme="dark"] .calendar-upcoming-item span{color:#aebdd0}
html[data-theme="dark"] .calendar-toolbar{background:#0d1621;border-color:#2b3b50}
html[data-theme="dark"] .calendar-view-chip{background:#142131;border-color:#344960;color:#dce8f4}
html[data-theme="dark"] .calendar-week-head{background:#0c1520;border-color:#29394d}
html[data-theme="dark"] .calendar-day{background:#101923;border-color:#26374a}html[data-theme="dark"] .calendar-day.outside{background:#0c151f}html[data-theme="dark"] .calendar-day.today{background:#102238}
html[data-theme="dark"] .calendar-day-num{color:#bdcada}
html[data-theme="dark"] .calendar-event-chip{background:#16355a;color:#a7d2ff}
html[data-theme="dark"] .calendar-event-chip.green{background:#153426;color:#8bd3ab}
html[data-theme="dark"] .calendar-event-chip.purple{background:#2a2345;color:#c7b4ff}
html[data-theme="dark"] .calendar-event-chip.orange{background:#3a2a14;color:#ffd18b}
html[data-theme="dark"] .calendar-event-chip.red{background:#3a1820;color:#ff9bab}
html[data-theme="dark"] .calendar-provider{background:#101923;border-color:#31445c;color:#f7fbff}
html[data-theme="dark"] .calendar-provider:hover{background:#172435}html[data-theme="dark"] .calendar-provider.active{background:#102842;border-color:#4a83b8}
html[data-theme="dark"] .calendar-provider-icon{background:#102c49;color:#9cc9f5}
html[data-theme="dark"] .calendar-provider small,html[data-theme="dark"] .calendar-integration-row small{color:#afbdd0}
html[data-theme="dark"] .calendar-integration-note{background:#0d1722;border-color:#2b3b50;color:#cbd7e5}
html[data-theme="dark"] .calendar-connected-title{color:#b7c5d6}
html[data-theme="dark"] .calendar-integration-row{background:#101923;border-color:#31445c}
html[data-theme="dark"] .calendar-integration-row b{color:#fff}
@media(max-width:1050px){.calendar-shell{grid-template-columns:1fr}.calendar-side{display:grid;grid-template-columns:220px 1fr;gap:16px}.calendar-side-block{margin-top:0}.calendar-upcoming{grid-template-columns:repeat(2,1fr)}}
@media(max-width:760px){.calendar-hero{align-items:flex-start;flex-direction:column}.calendar-side{display:block}.calendar-side-block{margin-top:16px}.calendar-grid{grid-auto-rows:minmax(90px,1fr)}.calendar-event-form,.calendar-integration-form{grid-template-columns:1fr}.calendar-event-form .full,.calendar-integration-form .full{grid-column:auto}.calendar-provider-grid{grid-template-columns:1fr}}


/* v4.15 — direct date interaction */
.calendar-day{cursor:default}
.calendar-day:hover{outline:1px solid #9cc9f5;outline-offset:-1px;background:#f7fbff}
.calendar-day:hover .calendar-day-num{text-decoration:underline;text-decoration-style:dotted}
html[data-theme="dark"] .calendar-day:hover{background:#132235!important;outline-color:#4f769e}
html[data-theme="dark"] .calendar-day.outside:hover{background:#101d2b!important}
/* v4.14 — two-way calendar connection controls */
.calendar-mode-tabs{display:flex;gap:7px;margin:13px 0 2px;padding:4px;background:#f4f7fa;border:1px solid #e1e8f0;border-radius:10px}
.calendar-mode-tab{appearance:none;flex:1;border:0;border-radius:7px;background:transparent;padding:8px 10px;font-size:9px;font-weight:800;color:#64778d;cursor:pointer}
.calendar-mode-tab.active{background:#fff;color:#176fc8;box-shadow:0 1px 5px rgba(23,64,105,.11)}
.calendar-event-chip.synced{box-shadow:inset 3px 0 0 rgba(156,201,245,.8)}
.calendar-sync-mark{font-weight:900}
html[data-theme="dark"] .calendar-mode-tabs{background:#0b141f;border-color:#2d4056}
html[data-theme="dark"] .calendar-mode-tab{color:#b8c6d7}
html[data-theme="dark"] .calendar-mode-tab.active{background:#17304b;color:#9cc9f5;box-shadow:none}
html[data-theme="dark"] .calendar-integration-note code{color:#9cc9f5}
html[data-theme="dark"] .calendar-event-chip.synced{box-shadow:inset 3px 0 0 #9cc9f5}

/* v4.16 — email client */
.operate-only{display:none!important}.operate-only.operate-visible{display:inline-flex!important}.ticket-hidden{display:none!important}
.email-page{display:grid;gap:16px}.email-hero{display:flex;justify-content:space-between;align-items:center;gap:16px}
.email-hero-copy{display:flex;gap:12px;align-items:center}.email-hero-copy h1{margin:0 0 4px}.email-hero-icon{width:42px;height:42px;border-radius:11px;display:grid;place-items:center;background:#eaf4ff;color:#1479e6;font-size:18px;font-weight:800}
.email-hero-actions{display:flex;gap:8px;flex-wrap:wrap}
.email-shell{display:grid;grid-template-columns:220px 360px minmax(0,1fr);min-height:650px;background:#fff;border:1px solid #e1e8f0;border-radius:12px;overflow:hidden;box-shadow:0 3px 12px rgba(25,45,70,.045)}
.email-folders{padding:14px;border-right:1px solid #e7edf4;background:#fbfcfe}.email-compose-btn{width:100%;padding:11px 12px;border:1px solid #dbe6f1;border-radius:12px;background:#fff;font-weight:800;color:#23415f;cursor:pointer;box-shadow:0 2px 8px rgba(25,45,70,.08)}
.email-account-select{width:100%;margin:12px 0}.email-folder-list{display:grid;gap:3px}.email-folder-btn{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;border:0;background:transparent;color:#4e6177;border-radius:7px;padding:8px 9px;text-align:left;cursor:pointer;font-size:10px}
.email-folder-btn:hover,.email-folder-btn.active{background:#eaf2fc;color:#176fc8}.email-folder-count{font-size:8px;min-width:18px;text-align:center;padding:2px 5px;border-radius:999px;background:#edf1f5;color:#6b7c8e}
.email-list-pane{border-right:1px solid #e7edf4;min-width:0}.email-toolbar{display:flex;align-items:center;gap:8px;padding:12px;border-bottom:1px solid #e7edf4;background:#fcfdff}.email-search-wrap{display:flex;gap:6px;flex:1}.email-search-wrap .input{min-width:0;flex:1}
.email-list-meta{padding:8px 12px;border-bottom:1px solid #eef2f6;font-size:9px}.email-message-list{max-height:620px;overflow:auto}
.email-message-row{display:grid;grid-template-columns:22px 1fr;gap:8px;padding:11px 12px;border-bottom:1px solid #edf1f5;cursor:pointer;background:#fff}.email-message-row:hover,.email-message-row.active{background:#f4f8fd}.email-message-row.unread{background:#eef5ff}
.email-message-star{border:0;background:none;padding:0;color:#93a1b1;font-size:14px;cursor:pointer}.email-message-star.starred{color:#d79516}
.email-message-from{display:flex;justify-content:space-between;gap:8px;font-size:9px;color:#52677d}.email-message-row.unread .email-message-from{font-weight:850;color:#22384f}.email-message-date{font-size:8px;white-space:nowrap;color:#8796a8}
.email-message-subject{font-size:10px;font-weight:750;color:#24384e;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.email-message-snippet{font-size:8px;color:#77899d;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.email-reader-pane{min-width:0;background:#fff}.email-reader-empty{height:100%;display:grid;place-items:center;align-content:center;gap:8px;color:#8493a6;text-align:center}.email-reader-empty-icon{font-size:34px;color:#b5c4d4}.email-reader-empty b{color:#53677d}
.email-reader{padding:18px 20px}.email-reader-head{display:flex;justify-content:space-between;gap:15px;border-bottom:1px solid #e8edf3;padding-bottom:14px}.email-reader-title h2{margin:0 0 6px;font-size:17px}.email-reader-meta{font-size:9px;color:#72859a;line-height:1.5}.email-reader-actions{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.email-reader-body{white-space:pre-wrap;font-family:inherit;font-size:11px;line-height:1.65;color:#324960;margin:18px 0}.email-attachments{display:flex;gap:8px;flex-wrap:wrap;border-top:1px solid #e8edf3;padding-top:12px}.email-attachment-chip{font-size:9px;padding:7px 9px;border:1px solid #dbe5ef;border-radius:8px;background:#f8fafc;color:#3d5a75;text-decoration:none}
.email-compose-dialog{width:min(760px,calc(100vw - 36px))!important}.email-compose-form,.email-integration-form,.email-report-form{display:grid;grid-template-columns:1fr 1fr;gap:11px;padding:17px 20px}
.email-compose-form label,.email-integration-form label,.email-report-form label{display:flex;flex-direction:column;gap:5px;font-size:9px;font-weight:750;color:#60748b}.email-compose-form .full,.email-integration-form .full,.email-report-form .full{grid-column:1/-1}.email-compose-body{resize:vertical;min-height:180px}.email-attachment-picker input{padding:8px 0}.email-integration-body{padding:16px 20px 20px}.email-integration-dialog{width:min(720px,calc(100vw - 36px))!important}.email-quick-dialog{width:min(620px,calc(100vw - 36px))!important}.danger-link{color:#cf4459!important}
html[data-theme="dark"] .email-hero-icon{background:#102c49;color:#9cc9f5}
html[data-theme="dark"] .email-shell{background:#101923;border-color:#2a394d}html[data-theme="dark"] .email-folders{background:#0c151f;border-color:#2b3a4d}
html[data-theme="dark"] .email-compose-btn{background:#142131;color:#fff;border-color:#344960;box-shadow:none}
html[data-theme="dark"] .email-folder-btn{color:#cad5e2}html[data-theme="dark"] .email-folder-btn:hover,html[data-theme="dark"] .email-folder-btn.active{background:#132943;color:#9cc9f5}html[data-theme="dark"] .email-folder-count{background:#1a2837;color:#bdcada}
html[data-theme="dark"] .email-list-pane,html[data-theme="dark"] .email-reader-pane{background:#101923;border-color:#2b3a4d}
html[data-theme="dark"] .email-toolbar{background:#0d1621;border-color:#2b3a4d}html[data-theme="dark"] .email-list-meta{border-color:#273749}
html[data-theme="dark"] .email-message-row{background:#101923;border-color:#26374a}html[data-theme="dark"] .email-message-row:hover,html[data-theme="dark"] .email-message-row.active{background:#142438}html[data-theme="dark"] .email-message-row.unread{background:#10263e}
html[data-theme="dark"] .email-message-from,html[data-theme="dark"] .email-message-row.unread .email-message-from{color:#e2eaf3}html[data-theme="dark"] .email-message-subject{color:#fff}html[data-theme="dark"] .email-message-snippet{color:#aebdd0}html[data-theme="dark"] .email-message-date{color:#9bacc0}
html[data-theme="dark"] .email-reader-head,html[data-theme="dark"] .email-attachments{border-color:#2b3a4d}html[data-theme="dark"] .email-reader-title h2{color:#fff}html[data-theme="dark"] .email-reader-meta{color:#adbed0}html[data-theme="dark"] .email-reader-body{color:#e0e8f1}
html[data-theme="dark"] .email-attachment-chip{background:#132131;border-color:#344960;color:#9cc9f5}
@media(max-width:1100px){.email-shell{grid-template-columns:200px minmax(280px,360px) minmax(420px,1fr)}}@media(max-width:850px){.email-shell{grid-template-columns:1fr}.email-folders,.email-list-pane{border-right:0;border-bottom:1px solid #e7edf4}.email-message-list{max-height:420px}.email-reader-pane{min-height:420px}.email-compose-form,.email-integration-form,.email-report-form{grid-template-columns:1fr}.email-compose-form .full,.email-integration-form .full,.email-report-form .full{grid-column:auto}}

/* v4.17 — Event Findings + Ticket Portal */
.event-findings-page,.ticket-page{display:grid;gap:14px}.event-findings-hero,.ticket-hero{align-items:flex-start}
.event-filter-row{display:flex;gap:7px;flex-wrap:wrap}.windows-source-dialog,.event-finding-dialog,.ticket-dialog{width:min(880px,calc(100vw - 36px))!important}
.windows-source-body{padding:16px 20px 20px}.windows-source-form,.ticket-editor-grid{display:grid;grid-template-columns:1fr 1fr;gap:11px}
.windows-source-form label,.ticket-editor-grid label{display:flex;flex-direction:column;gap:5px;font-size:9px;font-weight:750;color:#60748b}.windows-source-form .full,.ticket-editor-grid .full{grid-column:1/-1}.windows-check{flex-direction:row!important;align-items:center!important}
.windows-source-list{display:grid;gap:8px}.windows-source-row{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:10px;padding:10px;border:1px solid #e1e8f0;border-radius:9px}.windows-source-icon{width:34px;height:34px;border-radius:8px;display:grid;place-items:center;background:#eaf4ff;color:#176fc8;font-weight:900}.windows-source-row b{font-size:10px}.windows-source-row small{display:block;color:#788ba1;font-size:8px;margin-top:3px}.windows-source-row .actions{display:flex;gap:6px;flex-wrap:wrap}
.event-finding-detail{padding:18px 20px;display:grid;gap:14px}.event-detail-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.event-detail-cell{background:#f8fafc;border:1px solid #e2e9f0;border-radius:8px;padding:9px}.event-detail-cell .k{font-size:8px;color:#7a8ca0;text-transform:uppercase;font-weight:800}.event-detail-cell .v{font-size:10px;color:#2b4057;margin-top:4px}.event-message-box{white-space:pre-wrap;background:#f7f9fc;border:1px solid #e1e8ef;border-radius:8px;padding:12px;font-size:10px;line-height:1.5;max-height:240px;overflow:auto}.event-fix-list{display:grid;gap:7px}.event-fix-item{display:flex;gap:8px;padding:8px 10px;border-radius:8px;background:#f7f9fc;border:1px solid #e3e9f0;font-size:9px}.event-fix-num{width:20px;height:20px;display:grid;place-items:center;border-radius:50%;background:#e7f2ff;color:#176fc8;font-weight:800;flex:none}
.ticket-editor-grid{padding:18px 20px}.ticket-section{border-top:1px solid #e5ebf2;padding-top:12px}.ticket-section h3{margin:0 0 9px;font-size:11px}.ticket-schedule-grid{display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:end}.ticket-notes-list{display:grid;gap:7px;max-height:190px;overflow:auto}.ticket-note{padding:9px 10px;border:1px solid #e2e8ef;background:#f8fafc;border-radius:8px}.ticket-note b{font-size:8px}.ticket-note small{font-size:8px;color:#8292a5;margin-left:6px}.ticket-note p{font-size:9px;margin:5px 0 0;white-space:pre-wrap}.ticket-note-add{display:grid;grid-template-columns:1fr auto;gap:8px;margin-top:8px;align-items:end}
.calendar-ticket-actions{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px;border:1px solid #bfdcff;background:#f1f7ff;border-radius:9px}.calendar-ticket-actions b{font-size:10px}.calendar-ticket-actions .actions{display:flex;gap:6px;flex-wrap:wrap}
.agent-recommendation{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:11px 14px;border:1px solid #b9d8f6;background:#f2f8ff;border-radius:9px}.agent-recommendation b{display:block;font-size:10px;color:#1e4f80}.agent-recommendation span{display:block;font-size:8px;color:#637d98;margin-top:3px}.agent-summary{font-size:9px;font-weight:800;color:#176fc8;white-space:nowrap}.windows-agent-dialog{width:min(920px,calc(100vw - 36px))!important}.windows-agent-body{padding:16px 20px 20px;display:grid;gap:14px}.agent-onboarding{display:flex;justify-content:space-between;gap:14px;align-items:center;padding:12px;border:1px solid #d7e4f0;background:#f7fbff;border-radius:9px}.agent-onboarding b{font-size:11px}.agent-onboarding .muted{font-size:8px;margin-top:3px;max-width:560px}.agent-enrollment-result{padding:12px;border:1px solid #a9cff5;background:#eef7ff;border-radius:9px;display:grid;gap:8px}.agent-token-head,.agent-token-row{display:flex;justify-content:space-between;align-items:center;gap:8px}.agent-token-row code{display:block;overflow:auto;padding:8px 10px;background:#fff;border:1px solid #cbdbea;border-radius:7px;font-size:9px;flex:1}.agent-command{white-space:pre-wrap;word-break:break-word;padding:10px;background:#07101c;color:#dcecff;border-radius:7px;font-size:8px;line-height:1.45;margin:0}.windows-agent-list{display:grid;gap:8px}.windows-agent-row{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:10px;padding:11px;border:1px solid #dde6ef;border-radius:9px}.windows-agent-icon{width:38px;height:38px;border-radius:9px;background:#e8f3ff;color:#176fc8;display:grid;place-items:center;font-weight:900}.windows-agent-row b{font-size:10px}.windows-agent-row small{display:block;color:#75899f;font-size:8px;margin-top:3px}.agent-status{display:inline-flex;align-items:center;gap:5px;font-size:8px;font-weight:800}.agent-status-dot{width:7px;height:7px;border-radius:50%;background:#8a99aa}.agent-status.online .agent-status-dot{background:#43b581}.agent-status.offline .agent-status-dot{background:#e1a23b}.agent-status.revoked .agent-status-dot{background:#df5d70}html[data-theme="dark"] .agent-recommendation,html[data-theme="dark"] .agent-onboarding,html[data-theme="dark"] .agent-enrollment-result{background:#10253b;border-color:#345b80}html[data-theme="dark"] .agent-recommendation b,html[data-theme="dark"] .agent-summary{color:#9cc9f5}html[data-theme="dark"] .agent-recommendation span{color:#aebdd0}html[data-theme="dark"] .windows-agent-row{background:#101923;border-color:#31445c}html[data-theme="dark"] .windows-agent-icon{background:#102c49;color:#9cc9f5}html[data-theme="dark"] .windows-agent-row b{color:#f7fbff}html[data-theme="dark"] .windows-agent-row small{color:#aebdd0}html[data-theme="dark"] .agent-token-row code{background:#09131e;border-color:#3b5875;color:#f7fbff}
.ticket-number{font-weight:850;color:#176fc8}.ticket-due{font-size:8px;color:#73869c}.status-ticket-open{background:#eaf2ff;color:#176fc8}.status-ticket-in_progress{background:#fff1dc;color:#9a5d10}.status-ticket-waiting{background:#f2ecff;color:#7651b1}.status-ticket-resolved,.status-ticket-closed{background:#e9f7ef;color:#2c8053}
html[data-theme="dark"] .windows-source-row,html[data-theme="dark"] .event-detail-cell,html[data-theme="dark"] .event-message-box,html[data-theme="dark"] .event-fix-item,html[data-theme="dark"] .ticket-note{background:#101923;border-color:#31445c}
html[data-theme="dark"] .windows-source-icon,html[data-theme="dark"] .event-fix-num{background:#102c49;color:#9cc9f5}html[data-theme="dark"] .windows-source-row b,html[data-theme="dark"] .event-detail-cell .v,html[data-theme="dark"] .event-message-box,html[data-theme="dark"] .ticket-note p{color:#f7fbff}
html[data-theme="dark"] .windows-source-row small,html[data-theme="dark"] .event-detail-cell .k,html[data-theme="dark"] .ticket-note small{color:#aebdd0}
html[data-theme="dark"] .ticket-section{border-color:#2d4056}html[data-theme="dark"] .calendar-ticket-actions{background:#10253b;border-color:#3d6288}html[data-theme="dark"] .ticket-number{color:#9cc9f5}
html[data-theme="dark"] .status-ticket-open{background:#142e4b;color:#9cc9f5}html[data-theme="dark"] .status-ticket-in_progress{background:#3c2b14;color:#ffd18b}html[data-theme="dark"] .status-ticket-waiting{background:#2d2446;color:#c7b4ff}html[data-theme="dark"] .status-ticket-resolved,html[data-theme="dark"] .status-ticket-closed{background:#173425;color:#8bd3ab}
@media(max-width:800px){.windows-source-form,.ticket-editor-grid,.event-detail-grid,.ticket-schedule-grid{grid-template-columns:1fr}.windows-source-form .full,.ticket-editor-grid .full{grid-column:auto}.ticket-note-add{grid-template-columns:1fr}.calendar-ticket-actions{align-items:flex-start;flex-direction:column}}

/* v4.19 Event Finding cleanup */
.event-finding-bulkbar{display:flex;align-items:center;gap:10px;padding:10px 14px;border-top:1px solid #e2e8ef;border-bottom:1px solid #e2e8ef;flex-wrap:wrap}.event-select-all{display:flex;align-items:center;gap:6px;font-size:9px;font-weight:750}.event-old-delete{margin-left:auto;display:flex;gap:7px;align-items:center}.event-finding-search{min-width:210px;width:260px}.event-finding-footer{padding:10px 14px;border-top:1px solid #e2e8ef}.event-finding-check{width:16px;height:16px}.event-findings-panel .danger:disabled{opacity:.45;cursor:not-allowed}.event-findings-panel td:first-child,.event-findings-panel th:first-child{text-align:center}.event-findings-panel td.admin-only.admin-visible,.event-findings-panel th.admin-only.admin-visible{display:table-cell}.event-findings-panel .event-finding-bulkbar.admin-visible{display:flex}.event-findings-panel .delete-link{color:#ff657b!important}.event-findings-panel .delete-link:hover{text-decoration:underline}
html[data-theme="dark"] .event-finding-bulkbar,html[data-theme="dark"] .event-finding-footer{border-color:#2c4055;background:#0d1722}html[data-theme="dark"] .event-select-all{color:#edf5ff}
@media(max-width:900px){.event-old-delete{margin-left:0}.event-finding-search{width:100%;min-width:150px}}

/* v4.20 — Ticket cleanup */
.ticket-cleanup-bar{display:flex;align-items:center;gap:10px;padding:10px 14px;border-top:1px solid #e2e8ef;border-bottom:1px solid #e2e8ef;flex-wrap:wrap}.ticket-select-all{display:flex;align-items:center;gap:6px;font-size:9px;font-weight:750}.ticket-old-delete{margin-left:auto;display:flex;gap:7px;align-items:center}.ticket-cleanup-panel .danger:disabled{opacity:.45;cursor:not-allowed}.ticket-cleanup-panel td:first-child,.ticket-cleanup-panel th:first-child{text-align:center}.ticket-cleanup-panel td.admin-only.admin-visible,.ticket-cleanup-panel th.admin-only.admin-visible{display:table-cell}.ticket-cleanup-panel .ticket-cleanup-bar.admin-visible{display:flex}.ticket-check{width:16px;height:16px}.ticket-delete-link{color:#ff657b!important}.ticket-delete-link:hover{text-decoration:underline}html[data-theme="dark"] .ticket-cleanup-bar{border-color:#31445c}

/* v4.23.1 — consent-aware Windows Agent Remote Access */
.remote-hero{align-items:center}.remote-stats{display:flex;gap:9px;flex-wrap:wrap}.remote-stats span{min-width:98px;padding:10px 13px;border:1px solid #dce6f0;border-radius:10px;background:#fff;color:#52677f;font-size:10px}.remote-stats b{font-size:18px;color:#1f344c;margin-right:5px}.remote-layout{display:grid;grid-template-columns:minmax(280px,38%) minmax(0,1fr);gap:14px}.remote-computers,.remote-session-panel{min-height:610px}.remote-filter{padding:0 14px 10px}.remote-agent-list{padding:0 8px 12px;display:grid;gap:5px}.remote-agent-row{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:10px;border:1px solid #e3eaf2;border-radius:9px;padding:9px 10px;background:#fff}.remote-agent-main{min-width:0}.remote-agent-name{font-weight:800;font-size:11px;color:#20364e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.remote-agent-sub{font-size:9px;color:#778ba1;margin-top:3px}.remote-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;background:#9ba9b7}.remote-dot.online{background:#27c76f}.remote-dot.offline{background:#e34b5e}.remote-session-head{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:0 0 12px}.remote-session-head h2{margin:0 0 3px}.remote-screen-wrap{height:500px;border-radius:9px;border:1px solid #cfdbe7;background:#06101b;display:grid;place-items:center;overflow:hidden;outline:none;position:relative}.remote-screen-wrap:focus{box-shadow:0 0 0 2px rgba(15,125,240,.35)}.remote-screen{width:100%;height:100%;object-fit:contain;user-select:none;cursor:default}.remote-screen-empty{display:flex;flex-direction:column;align-items:center;gap:7px;color:#9fb0c2;font-size:10px}.remote-screen-empty b{font-size:13px;color:#dfe9f4}.remote-monitor-icon{font-size:42px;color:#2388f2}.remote-session-meta{display:flex;gap:18px;flex-wrap:wrap;padding-top:11px;font-size:9px;color:#71869d}.remote-session-meta b{color:#263b53}.remote-connect{min-width:72px}.remote-waiting{color:#f0b94b!important}
html[data-theme="dark"] .remote-stats span,html[data-theme="dark"] .remote-agent-row{background:#101923!important;border-color:#2d4056!important;color:#d8e3ef!important}html[data-theme="dark"] .remote-stats b,html[data-theme="dark"] .remote-agent-name,html[data-theme="dark"] .remote-session-meta b{color:#fff!important}html[data-theme="dark"] .remote-agent-sub,html[data-theme="dark"] .remote-session-meta{color:#98abc0!important}html[data-theme="dark"] .remote-screen-wrap{border-color:#31465e!important;background:#02070d!important}
@media(max-width:1000px){.remote-layout{grid-template-columns:1fr}.remote-computers,.remote-session-panel{min-height:auto}.remote-screen-wrap{height:min(62vw,500px)}}
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
  <div class="login-scene-footer">GODSEYE v__APP_VERSION__<br>Network Intelligence · Device Correlation · Smart Alerts</div>
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
<button type="button" class="navitem" data-view="calendar"><span class="navicon">▦</span><span>Calendar</span></button>
<button type="button" class="navitem operate-only" data-view="email"><span class="navicon">✉</span><span>Email</span></button>
<button type="button" class="navitem" data-view="event-findings"><span class="navicon">⚠</span><span>Event Findings</span><span class="badge" id="eventFindingBadge">0</span></button>
<button type="button" class="navitem admin-only" data-view="remote-access"><span class="navicon">▰</span><span>Remote Access</span></button>
<button type="button" class="navitem" data-view="tickets"><span class="navicon">▧</span><span>Ticket Portal</span><span class="badge" id="ticketBadge">0</span></button>
<button type="button" class="navitem" data-view="health"><span class="navicon">♥</span><span>System Health</span></button>
<button type="button" class="navitem" data-view="security"><span class="navicon">▣</span><span>Settings</span></button>

<div class="navsection">Administration</div>
<button type="button" class="navitem" data-view="rules" id="navRules"><span class="navicon">⚑</span><span>Alert Rules</span></button>
<button type="button" class="navitem" id="navUsers" data-view="users"><span class="navicon">♙</span><span>Users</span></button>
<button type="button" class="navitem" id="navAudit" data-view="audit"><span class="navicon">▥</span><span>Audit Log</span></button>
</div>
<div class="sidebar-footer">
<button id="scanBtn" class="primary" type="button" onclick="scan()">⟳ Scan Now</button><div id="scanStatus" class="scan-status" aria-live="polite">Ready to scan</div>
<div class="muted" id="whoami"></div>
<button class="link" onclick="openChangePassword()">Change password</button>
<button class="link" onclick="logout()">Log out</button>
</div>
</nav>
<main class="content"><div class="headerbar"><div class="muted">Network Intelligence & Security</div><div class="top-actions"><span class="status-chip"><span class="status-dot"></span> Online</span><button id="themeToggle" class="theme-toggle" type="button" onclick="toggleTheme()" title="Switch appearance" aria-label="Switch between light and dark mode"><span class="theme-icon" id="themeIcon">☾</span><span id="themeLabel">Dark</span></button><button class="icon-btn" title="Notifications">♧</button><button class="user-chip" type="button" onclick="toggleUserMenu()"><span class="avatar">A</span><span id="topUser">admin</span><span aria-hidden="true">⌄</span></button><div id="userMenu" class="user-menu" style="display:none"><button onclick="openChangePassword();toggleUserMenu()">Change password</button><button onclick="logout()">Sign out</button></div></div></div><div class="wrap">

<div class="view" id="view-overview">
<div class="hero"><div><h1>Dashboard</h1><div class="muted">Network overview and system status</div><div class="dashboard-statusline" style="margin-top:8px"><span class="status-pill" id="dashScannerState">Scanner checking…</span><span id="dashRefreshState">Waiting for first refresh</span></div></div></div>
<div class="cards">
<button type="button" class="card statcard stat-action" onclick="openDashboardSummary('devices')" aria-label="Open all devices"><div class="staticon">▣</div><div><div class="statmeta">Total Devices</div><div class="statnum" id="total">—</div></div><span class="trend">View all</span></button>
<button type="button" class="card statcard stat-action" onclick="openDashboardSummary('online')" aria-label="Open online devices"><div class="staticon green">✓</div><div><div class="statmeta">Online</div><div class="statnum" id="online">—</div></div><span class="trend" id="onlineTrend">—</span></button>
<button type="button" class="card statcard stat-action" onclick="openDashboardSummary('issues')" aria-label="Open network findings"><div class="staticon red">!</div><div><div class="statmeta">Issues</div><div class="statnum" id="unknown">—</div></div><span class="trend" style="color:#df5064">Review →</span></button>
<button type="button" class="card statcard stat-action" onclick="openDashboardSummary('monitors')" aria-label="Open monitors"><div class="staticon purple">◔</div><div><div class="statmeta">Monitors</div><div class="statnum" id="monitorCount">—</div></div><span class="trend" id="monitorTrend">—</span></button>
</div>
<div class="dashboard-grid">
<section class="panel traffic"><div class="table-head"><h2>Live Network Traffic</h2><div class="muted"><span style="color:#1976e8">●</span> Download &nbsp;&nbsp; <span style="color:#16a36d">●</span> Upload <span id="trafficNow" style="margin-left:12px">collecting…</span></div></div>
<svg id="trafficSvg" viewBox="0 0 760 190" preserveAspectRatio="none" aria-label="Live network traffic chart"><g stroke="#e8edf3" stroke-width="1"><line x1="45" y1="25" x2="745" y2="25"/><line x1="45" y1="65" x2="745" y2="65"/><line x1="45" y1="105" x2="745" y2="105"/><line x1="45" y1="145" x2="745" y2="145"/></g><g id="trafficLabels"></g><polyline id="trafficRx" points="" fill="none" stroke="#1976e8" stroke-width="2.2"/><polyline id="trafficTx" points="" fill="none" stroke="#16a36d" stroke-width="2"/></svg><div class="panel-subtle" id="trafficFoot">Traffic collector is warming up…</div></section>
<section class="panel"><div class="table-head"><h2>Recent Activity</h2><button class="link" onclick="showView('activity')">View all</button></div><div class="activity-list" id="activityList"><div class="activity-row"><span class="activity-dot green"></span><div><div class="activity-title">Loading activity…</div><div class="activity-sub">GODSEYE is checking the network</div></div><span class="activity-time">now</span></div></div></section>
</div>
<section class="panel"><div class="table-head"><h2>Client Activity</h2><div class="muted" id="clientMetricNote">Observed activity by device</div></div><div id="clientBars" style="padding:16px"><div class="empty">Collecting client evidence…</div></div></section>
<section class="panel"><div class="table-head"><h2>Devices</h2><button class="link" onclick="showView('devices')">View all devices →</button></div><div style="overflow:auto"><table class="dashboard-table"><thead><tr><th>Status</th><th>Device</th><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Type</th><th>Last Seen</th></tr></thead><tbody id="devices"></tbody></table></div></section>
<div class="toolbar" style="display:none"><input id="search" class="input"><select id="status" class="filter"><option value="">All</option></select><select id="classification" class="filter"><option value="">All</option></select></div>
</div>

<div class="view" id="view-devices" style="display:none">
<button type="button" class="dashboard-return" data-dashboard-return onclick="backToDashboard()">← Back to Dashboard</button>
<div class="hero"><div><h1>Device Inventory</h1><div class="muted" id="deviceInventorySubtitle">All discovered devices on your network</div></div><div class="actions"><button class="primary" onclick="openAddDevice()">＋ Add Device</button><button class="secondary" onclick="scan()">⟳ Discover Network</button></div></div>
<div class="toolbar"><input id="inventorySearch" class="input" placeholder="Search devices…" oninput="loadInventory()"><select id="inventoryStatus" class="filter" onchange="loadInventory()"><option value="">All statuses</option><option value="online">Online</option><option value="offline">Offline</option></select><button type="button" class="danger admin-only" onclick="openDeviceCleanup()">Clean Up Devices</button></div>
<section class="panel"><div class="table-head"><h2>Discovered Devices</h2><div class="muted" id="inventoryCount">—</div></div><div style="overflow:auto"><table><thead><tr><th>Name</th><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Type</th><th>Classification</th><th>Last Seen</th><th>Status</th><th>Actions</th></tr></thead><tbody id="inventoryRows"></tbody></table></div></section>
</div>

<div class="view" id="view-network" style="display:none">
<div class="hero network-hero"><div><h1>Network Map</h1><div class="muted">Visual view of your network and connected devices</div></div><div class="actions"><input id="mapSearch" class="input network-search" placeholder="⌕  Search devices…" oninput="filterMapNodes()"><button class="secondary" onclick="setNetworkLayout('auto')">⟳ Auto Layout</button><button class="primary" onclick="runFullDiscovery()">＋ Discover Network</button><button class="secondary" title="Fit map" onclick="fitNetworkMap()">⛶</button></div></div>
<div class="network-filter-row"><button type="button" class="network-filter active" data-map-filter="all" onclick="setMapFilter('all')">All <span id="mapAllCount">0</span></button><button type="button" class="network-filter online" data-map-filter="online" onclick="setMapFilter('online')">● Online <span id="mapOnlineCount">0</span></button><button type="button" class="network-filter offline" data-map-filter="offline" onclick="setMapFilter('offline')">● Offline <span id="mapOfflineCount">0</span></button><button type="button" class="network-filter unknown" data-map-filter="unknown" onclick="setMapFilter('unknown')">● Unknown <span id="mapUnknownCount">0</span></button><span class="network-generated" id="mapStatus">Loading topology…</span></div>
<div class="map-summary map-summary-compat" style="display:none"><span id="mapGateway"></span><span id="mapNodes"></span><span id="mapLinks"></span><span id="mapUpdated"></span></div>
<div class="network-map-layout">
  <section class="network-topology-panel">
    <div class="map-viewport realistic-map-viewport" id="networkViewport"><div class="map-stage realistic-map-stage" id="networkStage"><svg class="map-edge-layer" id="mapEdgeLayer" aria-hidden="true"></svg><div class="map-canvas realistic-map-canvas" id="networkCanvas"><div class="map-empty">Building your network map…</div></div></div></div>
    <div class="network-map-footer"><div class="map-zoom"><button type="button" title="Zoom in" onclick="zoomNetwork(0.1)">＋</button><button type="button" title="Zoom out" onclick="zoomNetwork(-0.1)">−</button><button type="button" title="Fit map" onclick="fitNetworkMap()">⛶</button><button type="button" title="Center selected" onclick="centerSelectedMapNode()">◎</button></div><div class="network-map-legend"><span><i class="legend-line wired"></i>Wired Connection</span><span><i class="legend-line wireless"></i>Wireless Connection</span><span><i class="legend-status online"></i>Online</span><span><i class="legend-status offline"></i>Offline</span><span><i class="legend-status unknown"></i>Unknown</span></div></div>
  </section>
  <aside class="network-detail-column">
    <section class="network-device-card" id="mapSelectedPanel"><div class="network-empty-side">Select a device on the map to view its details.</div></section>
    <section class="network-connected-card"><h3>Connected Devices <span id="mapConnectedCount">0</span></h3><div id="mapConnectedDevices"><div class="network-empty-side">No device selected.</div></div></section>
    <section class="network-controls-card"><h3>Map Controls</h3><button type="button" class="map-layout-btn active" data-layout="auto" onclick="setNetworkLayout('auto')">⌁ &nbsp; Auto Layout</button><button type="button" class="map-layout-btn" data-layout="hierarchical" onclick="setNetworkLayout('hierarchical')">⌘ &nbsp; Hierarchical</button><button type="button" class="map-layout-btn" data-layout="circular" onclick="setNetworkLayout('circular')">◌ &nbsp; Circular</button><div class="map-evidence-note" id="mapEvidence">Relationship evidence appears here after discovery.</div></section>
  </aside>
</div>
</div>

<div class="view" id="view-monitoring" style="display:none">
<button type="button" class="dashboard-return" data-dashboard-return onclick="backToDashboard()">← Back to Dashboard</button>
<div class="hero"><div><h1>Monitors</h1><div class="muted">Clean, continuous health checks for important network services and infrastructure.</div></div><div class="actions"><button class="secondary" onclick="runMonitors()">▶ Run All</button><button class="primary" onclick="openMonitorEditor()">＋ Add Monitor</button></div></div>
<div class="monitor-summary"><div class="monitor-summary-card"><div class="k">Total Monitors</div><div class="v" id="monitorTotalSummary">—</div></div><div class="monitor-summary-card good"><div class="k">Healthy</div><div class="v" id="monitorHealthySummary">—</div></div><div class="monitor-summary-card bad"><div class="k">Needs Attention</div><div class="v" id="monitorFailingSummary">—</div></div><div class="monitor-summary-card off"><div class="k">Disabled</div><div class="v" id="monitorDisabledSummary">—</div></div></div>
<section class="panel"><div class="table-head"><div><h2>Monitoring Services</h2><div class="muted">Repeated failures automatically create Findings.</div></div><div class="muted">Use Add Monitor to create a check without leaving this page.</div></div><div class="monitor-table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Target</th><th>Interval</th><th>Status</th><th>Last Check</th><th>Response</th><th>Actions</th></tr></thead><tbody id="monitorRows"></tbody></table></div></section>
</div>
<div class="view" id="view-findings" style="display:none">
<button type="button" class="dashboard-return" data-dashboard-return onclick="backToDashboard()">← Back to Dashboard</button>
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
<div class="hero"><div><h1>Integrations</h1><div class="muted">Manage multiple Pi-hole, UniFi and SNMP collectors from one place.</div></div><div class="actions"><button class="primary admin-only" onclick="openIntegrationModal()">+ Add Integration</button></div></div>
<div class="integration-toolbar"><div class="muted" id="integrationSummary">Loading integrations…</div><button class="secondary" onclick="loadIntegrations()">↻ Refresh</button></div>
<div id="integrationList" class="integration-list"><div class="panel empty">Loading integrations…</div></div>
<section class="panel" style="margin-top:16px"><div class="table-head"><div><h2>Client & Query Analytics</h2><div class="muted">Open any analytics card for a focused view and clear only that integration's retained analytics when finished.</div></div><button type="button" class="danger admin-only" onclick="openClearData('analytics')">Clear All Analytics</button></div><div id="integrationAnalytics" class="analytics-grid"><div class="empty">Run an integration sync to collect analytics.</div></div></section>
<section class="panel"><div class="table-head"><div><h2>Notifications</h2><div class="muted">Choose how GODSEYE delivers findings, topology changes and scheduled reports.</div></div><span class="integration-badge">Delivery Channels</span></div>
<div class="notify-grid">
<div class="notify-card"><h3>Webhook</h3><div class="notify-desc">Send structured GODSEYE events to an automation platform, SIEM, or custom HTTP endpoint.</div><div class="notify-fields"><label class="muted">Webhook URL<input id="notifyWebhook" class="input" placeholder="https://example.com/hooks/godseye"></label></div></div>
<div class="notify-card"><h3>ntfy Push</h3><div class="notify-desc">Send lightweight push notifications to an ntfy topic for quick mobile alerts.</div><div class="notify-fields"><label class="muted">Server<input id="notifyNtfyServer" class="input" value="https://ntfy.sh" placeholder="ntfy server"></label><label class="muted">Topic<input id="notifyNtfy" class="input" placeholder="godseye-alerts"></label></div></div>
<div class="notify-card"><h3>Email / SMTP</h3><div class="notify-desc">Email alerts and scheduled report notifications through your SMTP server.</div><div class="notify-fields"><input id="notifySmtpHost" class="input" placeholder="SMTP host"><div style="display:grid;grid-template-columns:1fr 110px;gap:8px"><input id="notifySmtpUser" class="input" placeholder="Username"><input id="notifySmtpPort" class="input" type="number" value="587" placeholder="Port"></div><input id="notifySmtpPass" class="input" type="password" placeholder="Password (blank keeps saved)"><input id="notifySmtpFrom" class="input" placeholder="From address"><input id="notifyEmail" class="input" placeholder="Recipient address"></div></div>
</div><div class="notify-footer"><label class="muted">Minimum alert severity <select id="notifySeverity" class="filter"><option value="info">Info and above</option><option value="warning" selected>Warning and critical</option><option value="critical">Critical only</option></select></label><div><button class="primary" onclick="saveNotifications()">Save Notification Settings</button> <button class="secondary" onclick="testNotifications()">Send Test</button></div><div id="notifyOut" class="muted" style="width:100%"></div></div></section>
</div>
<div class="view" id="view-calendar" style="display:none">
<div class="calendar-page">
  <div class="calendar-hero">
    <div class="calendar-hero-copy"><div class="calendar-hero-icon">▦</div><div><h1>Calendar</h1><div class="muted">Plan maintenance, appointments, reviews and network-security work from one shared appliance calendar.</div></div></div>
    <div class="calendar-actions"><button class="secondary" onclick="openCalendarIntegrationModal()">⌘ Calendar Integrations</button><button class="primary admin-only" onclick="openCalendarEventModal()">＋ Create</button></div>
  </div>
  <div class="calendar-shell">
    <aside class="calendar-side">
      <button class="calendar-create admin-only" onclick="openCalendarEventModal()">＋ Create appointment</button>
      <div class="calendar-side-block"><div class="calendar-side-title">Calendars</div>
        <label class="calendar-filter"><input type="checkbox" checked onchange="toggleCalendarSource('local',this.checked)"><span class="calendar-dot blue"></span>GODSEYE</label>
        <div id="calendarExternalFilters"></div>
      </div>
      <div class="calendar-side-block"><div class="calendar-side-title">Upcoming</div><div id="calendarUpcoming" class="calendar-upcoming"><div class="empty">No upcoming appointments.</div></div></div>
    </aside>
    <section class="calendar-main-card">
      <div class="calendar-toolbar">
        <div class="calendar-nav-actions"><button class="secondary" onclick="calendarToday()">Today</button><button class="icon-btn" onclick="calendarStep(-1)" title="Previous month">‹</button><button class="icon-btn" onclick="calendarStep(1)" title="Next month">›</button><h2 id="calendarMonthLabel">Month</h2></div>
        <div class="calendar-view-chip">Month</div>
      </div>
      <div class="calendar-week-head"><span>Sun</span><span>Mon</span><span>Tue</span><span>Wed</span><span>Thu</span><span>Fri</span><span>Sat</span></div>
      <div id="calendarGrid" class="calendar-grid"></div>
    </section>
  </div>
</div>
</div>

<div id="calendarEventModal" class="modal" style="display:none" onclick="if(event.target===this)closeCalendarEventModal()">
 <div class="modal-card calendar-event-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2 id="calendarEventModalTitle">Create appointment</h2><div class="muted">Add an appointment, maintenance window, review or reminder.</div></div><button class="icon-btn" onclick="closeCalendarEventModal()">×</button></div>
  <form class="calendar-event-form" onsubmit="return saveCalendarEvent(event)">
   <input type="hidden" id="calendarEventId">
   <label class="full">Title<input class="input" id="calendarEventTitle" maxlength="160" required placeholder="Example: Firewall maintenance"></label>
   <label>Start<input class="input" id="calendarEventStart" type="datetime-local" required></label>
   <label>End<input class="input" id="calendarEventEnd" type="datetime-local" required></label>
   <label>Location<input class="input" id="calendarEventLocation" maxlength="300" placeholder="Server room / Teams / Office"></label>
   <label>Calendar<select class="filter" id="calendarEventTarget"><option value="">GODSEYE local calendar</option></select></label>
   <label>Color<select class="filter" id="calendarEventColor"><option value="blue">Blue</option><option value="green">Green</option><option value="purple">Purple</option><option value="orange">Orange</option><option value="red">Red</option></select></label>
   <label class="calendar-check"><input type="checkbox" id="calendarEventAllDay"> All-day event</label>
   <label class="full">Notes<textarea class="input" id="calendarEventDescription" rows="4" maxlength="4000" placeholder="Add details, agenda, ticket number or maintenance notes"></textarea></label>
   <div id="calendarTicketActions" class="calendar-ticket-actions full" style="display:none"><div><b id="calendarTicketLabel">Linked ticket</b><div class="muted">Work and close the linked ticket directly from Calendar.</div></div><div class="actions"><button type="button" class="secondary" onclick="openCalendarLinkedTicket()">Open Ticket</button><button type="button" class="secondary operate-only" onclick="addCalendarTicketNote()">Add Work Note</button><button type="button" class="secondary operate-only" onclick="resolveCalendarTicket()">Resolve</button><button type="button" class="danger operate-only" onclick="closeCalendarTicket()">Close Ticket</button></div></div>
   <div id="calendarEventErr" class="err full"></div>
   <div class="modal-actions full"><button type="button" id="calendarDeleteBtn" class="danger" style="display:none;margin-right:auto" onclick="deleteCalendarEvent()">Delete</button><button type="button" class="secondary" onclick="closeCalendarEventModal()">Cancel</button><button type="submit" class="primary">Save</button></div>
  </form>
 </div>
</div>

<div id="calendarIntegrationModal" class="modal" style="display:none" onclick="if(event.target===this)closeCalendarIntegrationModal()">
 <div class="modal-card calendar-integration-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2>Calendar Integrations</h2><div class="muted">Connect Google Calendar or Microsoft 365 for full two-way editing, or keep ICS as a read-only fallback.</div></div><button class="icon-btn" onclick="closeCalendarIntegrationModal()">×</button></div>
  <div class="calendar-integration-body">
   <div class="calendar-provider-grid">
    <button type="button" class="calendar-provider active" data-provider="google" onclick="selectCalendarProvider('google')"><span class="calendar-provider-icon">G</span><b>Google Calendar</b><small>OAuth · two-way</small></button>
    <button type="button" class="calendar-provider" data-provider="microsoft365" onclick="selectCalendarProvider('microsoft365')"><span class="calendar-provider-icon">M</span><b>Microsoft 365</b><small>OAuth · two-way</small></button>
   </div>
   <input type="hidden" id="calendarProvider" value="google">
   <div class="calendar-mode-tabs">
    <button type="button" class="calendar-mode-tab active" data-mode="oauth" onclick="selectCalendarAuthMode('oauth')">Two-way OAuth</button>
    <button type="button" class="calendar-mode-tab" data-mode="ics" onclick="selectCalendarAuthMode('ics')">ICS read-only fallback</button>
   </div>
   <input type="hidden" id="calendarAuthMode" value="oauth">
   <div class="calendar-integration-form">
    <label>Name<input class="input" id="calendarIntegrationName" placeholder="Work Calendar"></label>
    <label>Account email<input class="input" id="calendarIntegrationEmail" type="email" placeholder="name@example.com"></label>
    <label>Calendar name<input class="input" id="calendarIntegrationCalendar" placeholder="Primary / Security Team"></label>
    <label>Remote calendar ID<input class="input" id="calendarIntegrationRemoteId" placeholder="primary"></label>
    <label>Sync every<select class="filter" id="calendarIntegrationInterval"><option value="15">15 minutes</option><option value="30" selected>30 minutes</option><option value="60">1 hour</option><option value="180">3 hours</option></select></label>
    <label id="calendarClientIdWrap">OAuth client ID<input class="input" id="calendarIntegrationClientId" placeholder="OAuth client ID"></label>
    <label id="calendarClientSecretWrap">OAuth client secret<input class="input" id="calendarIntegrationClientSecret" type="password" placeholder="OAuth client secret"></label>
    <label class="full" id="calendarIcsWrap" style="display:none">Private ICS subscription URL<input class="input" id="calendarIntegrationIcs" type="url" placeholder="https://.../calendar.ics"></label>
    <div class="calendar-integration-note full" id="calendarIntegrationModeNote">Two-way OAuth lets GODSEYE create, edit and delete events in the connected calendar. OAuth credentials and refresh tokens are encrypted at rest.</div>
    <div class="calendar-integration-note full">OAuth redirect URL: <code id="calendarOAuthRedirectHint">this GODSEYE URL + /api/v1/calendar/oauth/provider/callback</code>. If GODSEYE is behind HTTPS/reverse proxy, set <code>GODSEYE_PUBLIC_URL</code> to the externally reachable base URL.</div>
    <div id="calendarIntegrationErr" class="err full"></div>
    <div class="modal-actions full"><button type="button" class="secondary" onclick="closeCalendarIntegrationModal()">Close</button><button type="button" class="primary admin-only" onclick="saveCalendarIntegration()">Save Integration</button></div>
   </div>
   <div class="calendar-connected-title">Connected calendars</div>
   <div id="calendarIntegrationList" class="calendar-integration-list"><div class="empty">No external calendar integrations configured.</div></div>
  </div>
 </div>
</div>

<div class="view" id="view-email" style="display:none">
<div class="email-page">
  <div class="email-hero">
    <div class="email-hero-copy"><div class="email-hero-icon">✉</div><div><h1>Email</h1><div class="muted">Gmail and Microsoft 365 mail inside GODSEYE for operational communication, alerts, and report delivery.</div></div></div>
    <div class="email-hero-actions"><button class="secondary admin-only" onclick="openEmailIntegrationModal()">⚙ Mail Accounts</button><button class="primary operate-only" onclick="openEmailCompose()">＋ Compose</button></div>
  </div>
  <div class="email-shell">
    <aside class="email-folders">
      <button class="email-compose-btn operate-only" onclick="openEmailCompose()">＋ Compose</button>
      <select id="emailAccountSelect" class="filter email-account-select" onchange="selectEmailAccount(this.value)"></select>
      <div id="emailFolderList" class="email-folder-list"><div class="empty">Connect a mail account to begin.</div></div>
    </aside>
    <section class="email-list-pane">
      <div class="email-toolbar">
        <div class="email-search-wrap"><input id="emailSearch" class="input" placeholder="Search mail" onkeydown="if(event.key==='Enter')loadEmailMessages()"><button class="secondary" onclick="loadEmailMessages()">Search</button></div>
        <button class="icon-btn" onclick="loadEmailMessages()" title="Refresh">↻</button>
      </div>
      <div id="emailListMeta" class="email-list-meta muted">No mailbox selected.</div>
      <div id="emailMessageList" class="email-message-list"><div class="empty">No messages.</div></div>
    </section>
    <section class="email-reader-pane" id="emailReaderPane">
      <div class="email-reader-empty"><div class="email-reader-empty-icon">✉</div><b>Select a message</b><span>Choose a message from the list to read it here.</span></div>
    </section>
  </div>
</div>
</div>

<div id="emailComposeModal" class="modal" style="display:none" onclick="if(event.target===this)closeEmailCompose()">
 <div class="modal-card email-compose-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2 id="emailComposeTitle">New message</h2><div class="muted">Send from a connected Gmail or Microsoft 365 mailbox.</div></div><button class="icon-btn" onclick="closeEmailCompose()">×</button></div>
  <form class="email-compose-form" onsubmit="return sendEmailCompose(event)">
    <label>From<select class="filter" id="emailComposeAccount" required></select></label>
    <label>To<input class="input" id="emailComposeTo" placeholder="name@example.com" required></label>
    <label>CC<input class="input" id="emailComposeCc" placeholder="Optional"></label>
    <label>BCC<input class="input" id="emailComposeBcc" placeholder="Optional"></label>
    <label class="full">Subject<input class="input" id="emailComposeSubject" maxlength="500"></label>
    <label class="full">Message<textarea class="input email-compose-body" id="emailComposeBody" rows="10" placeholder="Write your message"></textarea></label>
    <label class="full email-attachment-picker">Attachments<input id="emailComposeFiles" type="file" multiple onchange="renderEmailAttachmentList()"><span id="emailAttachmentList" class="muted">No attachments selected.</span></label>
    <div id="emailComposeErr" class="err full"></div>
    <div class="modal-actions full"><button type="button" class="secondary" onclick="saveEmailDraft()">Save Draft</button><button type="button" class="secondary" onclick="closeEmailCompose()">Cancel</button><button type="submit" class="primary">Send</button></div>
  </form>
 </div>
</div>

<div id="emailIntegrationModal" class="modal" style="display:none" onclick="if(event.target===this)closeEmailIntegrationModal()">
 <div class="modal-card email-integration-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2>Mail Accounts</h2><div class="muted">Connect Gmail or Microsoft 365 with OAuth. Passwords are never stored.</div></div><button class="icon-btn" onclick="closeEmailIntegrationModal()">×</button></div>
  <div class="email-integration-body">
    <div class="calendar-provider-grid">
      <button type="button" class="calendar-provider active" data-email-provider="gmail" onclick="selectEmailProvider('gmail')"><span class="calendar-provider-icon">G</span><b>Gmail</b><small>Gmail API · OAuth</small></button>
      <button type="button" class="calendar-provider" data-email-provider="microsoft365" onclick="selectEmailProvider('microsoft365')"><span class="calendar-provider-icon">M</span><b>Microsoft 365</b><small>Microsoft Graph · OAuth</small></button>
    </div>
    <input type="hidden" id="emailProvider" value="gmail">
    <div class="email-integration-form">
      <label>Name<input class="input" id="emailIntegrationName" placeholder="Operations Mail"></label>
      <label>Account email<input class="input" id="emailIntegrationAddress" type="email" placeholder="name@example.com"></label>
      <label>OAuth client ID<input class="input" id="emailIntegrationClientId" placeholder="OAuth client ID"></label>
      <label>OAuth client secret<input class="input" id="emailIntegrationClientSecret" type="password" placeholder="OAuth client secret"></label>
      <div class="calendar-integration-note full">Gmail uses Gmail API OAuth access. Microsoft 365 uses Microsoft Graph with delegated Mail.ReadWrite and Mail.Send. Client secrets and OAuth tokens are encrypted at rest.</div>
      <div class="calendar-integration-note full">Redirect URL: this GODSEYE URL + <code>/api/v1/email/oauth/provider/callback</code>. Set <code>GODSEYE_PUBLIC_URL</code> when the appliance is behind HTTPS or a reverse proxy.</div>
      <div id="emailIntegrationErr" class="err full"></div>
      <div class="modal-actions full"><button type="button" class="secondary" onclick="closeEmailIntegrationModal()">Close</button><button type="button" class="primary admin-only" onclick="saveEmailIntegration()">Save &amp; Connect</button></div>
    </div>
    <div class="calendar-connected-title">Connected mailboxes</div>
    <div id="emailIntegrationList" class="calendar-integration-list"><div class="empty">No mail accounts connected.</div></div>
  </div>
 </div>
</div>

<div id="emailQuickActionModal" class="modal" style="display:none" onclick="if(event.target===this)closeEmailQuickAction()">
 <div class="modal-card email-quick-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2 id="emailQuickActionTitle">Reply</h2><div class="muted" id="emailQuickActionSubtitle"></div></div><button class="icon-btn" onclick="closeEmailQuickAction()">×</button></div>
  <div style="padding:18px 20px"><label id="emailQuickActionToWrap" style="display:none;flex-direction:column;gap:6px;margin-bottom:10px;font-size:10px;font-weight:750">To<input id="emailQuickActionTo" class="input" placeholder="name@example.com"></label><textarea id="emailQuickActionBody" class="input" rows="9" style="width:100%" placeholder="Write your message"></textarea><div id="emailQuickActionErr" class="err" style="margin-top:8px"></div><div class="modal-actions"><button class="secondary" onclick="closeEmailQuickAction()">Cancel</button><button class="primary" onclick="sendEmailQuickAction()">Send</button></div></div>
 </div>
</div>

<div id="emailReportModal" class="modal" style="display:none" onclick="if(event.target===this)closeEmailReportModal()">
 <div class="modal-card email-quick-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2>Email Report</h2><div class="muted" id="emailReportTitleLabel">Send a generated report directly from GODSEYE.</div></div><button class="icon-btn" onclick="closeEmailReportModal()">×</button></div>
  <div class="email-report-form">
    <input type="hidden" id="emailReportId">
    <label>From<select class="filter" id="emailReportAccount"></select></label>
    <label>Format<select class="filter" id="emailReportFormat"><option value="pdf">PDF</option><option value="csv">CSV</option></select></label>
    <label class="full">To<input class="input" id="emailReportTo" placeholder="name@example.com"></label>
    <label class="full">Subject<input class="input" id="emailReportSubject"></label>
    <label class="full">Message<textarea class="input" id="emailReportBody" rows="5">Attached is a GODSEYE report.</textarea></label>
    <div id="emailReportErr" class="err full"></div>
    <div class="modal-actions full"><button class="secondary" onclick="closeEmailReportModal()">Cancel</button><button class="primary" onclick="sendEmailReport()">Send Report</button></div>
  </div>
 </div>
</div>

<div class="view" id="view-event-findings" style="display:none">
<div class="event-findings-page">
  <div class="hero event-findings-hero"><div><h1>Event Findings</h1><div class="muted">Windows Critical, Error, and Warning events converted into explainable findings with remediation guidance.</div></div><div class="actions"><button class="primary operate-only" onclick="openWindowsAgentModal()">▣ Windows Agents</button><button class="secondary operate-only" onclick="pullAllWindowsAgentsNow()">⟳ Pull Events Now (Agents)</button><button class="secondary admin-only" onclick="openWindowsSourceModal()">⚙ WinRM Sources</button><button class="secondary operate-only" onclick="pollAllWindowsSources()">⟳ Pull Events Now (WinRM)</button></div></div>
  <div class="agent-recommendation"><div><b>Windows Agent is the recommended collection method.</b><span>Outbound HTTPS only · no inbound WinRM port · local Event Log bookmarks · offline queue · targeted rechecks.</span></div><div id="agentSummary" class="agent-summary">Agents: —</div></div>
  <div class="cards"><div class="card"><div class="label">Open</div><div class="num red" id="eventFindingOpen">—</div></div><div class="card"><div class="label">Critical</div><div class="num red" id="eventFindingCritical">—</div></div><div class="card"><div class="label">Storage / Hardware</div><div class="num" id="eventFindingHardware">—</div></div><div class="card"><div class="label">Resolved</div><div class="num green" id="eventFindingResolved">—</div></div></div>
  <section class="panel event-findings-panel"><div class="table-head"><div><h2>Windows Event Findings</h2><div class="muted">Only selected Warning, Error, and Critical events are retained as findings.</div></div><div class="event-filter-row"><select id="eventFindingStatusFilter" class="filter" onchange="loadEventFindings()"><option value="">All status</option><option value="open" selected>Open</option><option value="resolved">Resolved</option></select><select id="eventFindingSeverityFilter" class="filter" onchange="loadEventFindings()"><option value="">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select><input id="eventFindingSearch" class="input event-finding-search" placeholder="Search findings…" onkeydown="if(event.key==='Enter')loadEventFindings()"><button class="secondary" onclick="loadEventFindings()">↻ Refresh</button></div></div>
  <div class="event-finding-bulkbar admin-only"><label class="event-select-all"><input id="eventFindingSelectAll" type="checkbox" onchange="toggleAllEventFindings(this.checked)"> Select All <span id="eventFindingVisibleCount"></span></label><button id="eventFindingDeleteSelected" class="danger" onclick="deleteSelectedEventFindings()" disabled>🗑 Delete Selected</button><span id="eventFindingSelectedCount" class="muted">0 selected</span><div class="event-old-delete"><select id="eventFindingOldDays" class="filter"><option value="7">Resolved &gt; 7 days</option><option value="30" selected>Resolved &gt; 30 days</option><option value="90">Resolved &gt; 90 days</option><option value="180">Resolved &gt; 180 days</option><option value="365">Resolved &gt; 1 year</option></select><button class="danger" onclick="deleteOldEventFindings()">🗑 Delete Old Findings</button></div></div>
  <div style="overflow:auto"><table><thead><tr><th class="admin-only"><input type="checkbox" aria-label="Select all visible findings" onchange="toggleAllEventFindings(this.checked)"></th><th>Severity</th><th>Computer</th><th>Finding</th><th>Event</th><th>Occurrences</th><th>Last Seen</th><th>Status</th><th>Actions</th></tr></thead><tbody id="eventFindingRows"></tbody></table></div><div class="event-finding-footer"><span id="eventFindingFooterText" class="muted">No findings loaded.</span></div></section>
</div>
</div>

<div id="windowsAgentModal" class="modal" style="display:none" onclick="if(event.target===this)closeWindowsAgentModal()">
 <div class="modal-card windows-agent-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2>Windows Agents</h2><div class="muted">Recommended Event Findings collection for 64-bit Windows computers and Windows Server.</div></div><button class="icon-btn" onclick="closeWindowsAgentModal()">×</button></div>
  <div class="windows-agent-body">
    <div class="agent-onboarding">
      <div><b>Agent enrollment</b><div class="muted">Generate a one-time token, download the permanent x64 Windows installer, and run Setup as Administrator. Future agent upgrades preserve enrollment automatically.</div></div>
      <div class="actions"><button class="secondary" type="button" onclick="checkWindowsAgentUpdates()">↻ Check for Updates</button><button class="primary operate-only" type="button" onclick="pullAllWindowsAgentsNow()">⟳ Pull All Online</button><button class="secondary admin-only" type="button" onclick="downloadWindowsAgentPackage()">↓ Download x64 Installer</button><button class="primary admin-only" type="button" onclick="createWindowsAgentEnrollment()">＋ Create Enrollment Token</button></div>
    </div>
    <div id="windowsAgentEnrollment" class="agent-enrollment-result" style="display:none">
      <div class="agent-token-head"><b>One-time enrollment token</b><span id="windowsAgentEnrollmentExpiry" class="muted"></span></div>
      <div class="agent-token-row"><code id="windowsAgentEnrollmentToken"></code><button class="secondary" onclick="copyAgentEnrollmentToken()">Copy Token</button></div>
      <div class="muted">Installer setup:</div><pre id="windowsAgentInstallCommand" class="agent-command"></pre>
      <div class="calendar-integration-note">The token is shown only here and expires automatically. The Windows agent exchanges it for a unique machine API key and protects that key with Windows DPAPI.</div>
    </div>
    <div class="calendar-connected-title">Enrolled Windows agents</div>
    <div id="windowsAgentList" class="windows-agent-list"><div class="empty">No Windows Agents enrolled.</div></div>
    <div class="calendar-integration-note">WinRM remains available as an agentless fallback. Agent collection does not require inbound TCP 5986 on Windows.</div>
  </div>
 </div>
</div>

<div id="windowsSourceModal" class="modal" style="display:none" onclick="if(event.target===this)closeWindowsSourceModal()">
 <div class="modal-card windows-source-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2>Windows Event Sources</h2><div class="muted">Agentless WinRM HTTPS pull for 64-bit Windows computers and Windows Server.</div></div><button class="icon-btn" onclick="closeWindowsSourceModal()">×</button></div>
  <div class="windows-source-body">
    <div class="windows-source-form">
      <input type="hidden" id="windowsSourceId">
      <label>Name<input id="windowsSourceName" class="input" placeholder="FILESERVER01"></label>
      <label>Hostname / IP<input id="windowsSourceHost" class="input" placeholder="fileserver01.example.local"></label>
      <label>WinRM HTTPS port<input id="windowsSourcePort" class="input" type="number" value="5986"></label>
      <label>Transport<select id="windowsSourceTransport" class="filter"><option value="ntlm">NTLM</option><option value="basic">Basic over HTTPS</option></select></label>
      <label>Username<input id="windowsSourceUsername" class="input" placeholder="DOMAIN\\godseye-reader"></label>
      <label>Password<input id="windowsSourcePassword" class="input" type="password" placeholder="Leave blank when editing to keep current"></label>
      <label>Poll every<select id="windowsSourceInterval" class="filter"><option value="1">1 minute</option><option value="5" selected>5 minutes</option><option value="15">15 minutes</option><option value="30">30 minutes</option><option value="60">1 hour</option></select></label>
      <label class="windows-check"><input type="checkbox" id="windowsSourceVerifyTls" checked> Verify WinRM TLS certificate</label>
      <label class="full">Event channels<input id="windowsSourceChannels" class="input" value="System, Application" placeholder="System, Application"></label>
      <div class="calendar-integration-note full">GODSEYE queries only Windows event levels 1, 2, and 3 (Critical, Error, Warning), stores a per-channel record bookmark, and requests only newer records on later polls. Use WinRM over HTTPS and a dedicated least-privilege account with Event Log Readers access.</div>
      <div id="windowsSourceErr" class="err full"></div>
      <div class="modal-actions full"><button class="secondary" onclick="resetWindowsSourceForm()" type="button">New</button><button class="secondary" onclick="closeWindowsSourceModal()" type="button">Close</button><button class="primary admin-only" onclick="saveWindowsSource()" type="button">Save Source</button></div>
    </div>
    <div class="calendar-connected-title">Configured Windows hosts</div>
    <div id="windowsSourceList" class="windows-source-list"><div class="empty">No Windows Event sources configured.</div></div>
  </div>
 </div>
</div>

<div id="eventFindingModal" class="modal" style="display:none" onclick="if(event.target===this)closeEventFindingModal()">
 <div class="modal-card event-finding-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2 id="eventFindingModalTitle">Event Finding</h2><div class="muted" id="eventFindingModalSubtitle"></div></div><button class="icon-btn" onclick="closeEventFindingModal()">×</button></div>
  <div id="eventFindingModalBody" class="event-finding-detail"></div>
 </div>
</div>

<div class="view" id="view-tickets" style="display:none">
<div class="ticket-page">
  <div class="hero ticket-hero"><div><h1>Ticket Portal</h1><div class="muted">Track network, Windows, monitoring, and manual issues from discovery through scheduled work and closure.</div></div><div class="actions"><button class="primary operate-only" onclick="openTicketEditor()">＋ New Ticket</button></div></div>
  <div class="cards"><div class="card"><div class="label">Open</div><div class="num red" id="ticketOpen">—</div></div><div class="card"><div class="label">In Progress</div><div class="num" id="ticketInProgress">—</div></div><div class="card"><div class="label">Due / Scheduled</div><div class="num" id="ticketScheduled">—</div></div><div class="card"><div class="label">Closed</div><div class="num green" id="ticketClosed">—</div></div></div>
  <section class="panel ticket-cleanup-panel"><div class="table-head"><div><h2>Tickets</h2><div class="muted">Open a ticket to add notes, change status, schedule it on Calendar, or clean up completed ticket history.</div></div><div><select id="ticketStatusFilter" class="filter" onchange="loadTickets()"><option value="">All status</option><option value="open">Open</option><option value="assigned">Assigned</option><option value="in_progress">In Progress</option><option value="waiting">Waiting</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select></div></div>
  <div class="ticket-cleanup-bar admin-only"><label class="ticket-select-all"><input id="ticketSelectAll" type="checkbox" onchange="toggleAllTickets(this.checked)"> Select All <span id="ticketVisibleCount"></span></label><button id="ticketDeleteSelected" class="danger" onclick="deleteSelectedTickets()" disabled>🗑 Delete Selected</button><span id="ticketSelectedCount" class="muted">0 selected</span><div class="ticket-old-delete"><select id="ticketOldDays" class="filter"><option value="7">Closed / resolved &gt; 7 days</option><option value="30">Closed / resolved &gt; 30 days</option><option value="90" selected>Closed / resolved &gt; 90 days</option><option value="180">Closed / resolved &gt; 180 days</option><option value="365">Closed / resolved &gt; 1 year</option></select><button class="danger" onclick="deleteOldTickets()">🗑 Delete Old Tickets</button></div></div>
  <div style="overflow:auto"><table><thead><tr><th class="admin-only"><input id="ticketHeaderSelectAll" type="checkbox" onchange="toggleAllTickets(this.checked)" aria-label="Select all visible tickets"></th><th>Ticket</th><th>Priority</th><th>Title</th><th>Affected</th><th>Assignee</th><th>Status</th><th>Due / Calendar</th><th>Updated</th><th>Action</th></tr></thead><tbody id="ticketRows"></tbody></table></div></section>
</div>
</div>

<div id="ticketEditorModal" class="modal" style="display:none" onclick="if(event.target===this)closeTicketEditor()">
 <div class="modal-card ticket-dialog" role="dialog" aria-modal="true">
  <div class="modal-head"><div><h2 id="ticketEditorTitle">New Ticket</h2><div class="muted" id="ticketEditorSubtitle">Create and track operational work.</div></div><button class="icon-btn" onclick="closeTicketEditor()">×</button></div>
  <div class="ticket-editor-grid">
    <input type="hidden" id="ticketEditorId">
    <label class="full">Title<input id="ticketTitle" class="input" maxlength="240"></label>
    <label>Priority<select id="ticketPriority" class="filter"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
    <label>Status<select id="ticketStatus" class="filter"><option value="open">Open</option><option value="assigned">Assigned</option><option value="in_progress">In Progress</option><option value="waiting">Waiting</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select></label>
    <label>Assignee<select id="ticketAssignee" class="filter"><option value="">Unassigned</option></select></label>
    <label>Device / System<input id="ticketDevice" class="input" placeholder="FILESERVER01"></label>
    <label class="full">Description<textarea id="ticketDescription" class="input" rows="5"></textarea></label>
    <div id="ticketLinkedInfo" class="calendar-integration-note full" style="display:none"></div>
    <div class="ticket-section full" id="ticketScheduleSection" style="display:none"><h3>Schedule on Calendar</h3><div class="ticket-schedule-grid"><label>Start<input id="ticketScheduleStart" class="input" type="datetime-local"></label><label>End<input id="ticketScheduleEnd" class="input" type="datetime-local"></label><button class="secondary" type="button" onclick="scheduleCurrentTicket()">Save to Calendar</button></div></div>
    <div class="ticket-section full" id="ticketNotesSection" style="display:none"><h3>Work Notes</h3><div id="ticketNotesList" class="ticket-notes-list"></div><div class="ticket-note-add"><textarea id="ticketNoteText" class="input" rows="3" placeholder="Add work performed, parts replaced, test results, or follow-up notes"></textarea><button class="secondary" type="button" onclick="addTicketNote()">Add Note</button></div></div>
    <div id="ticketEditorErr" class="err full"></div>
    <div class="modal-actions full"><button id="ticketDeleteBtn" class="danger admin-only ticket-hidden" type="button" style="margin-right:8px" onclick="deleteCurrentTicket()">Delete Ticket</button><button id="ticketCloseBtn" class="danger operate-only" type="button" style="display:none;margin-right:auto" onclick="closeCurrentTicket()">Close Ticket</button><button class="secondary" type="button" onclick="closeTicketEditor()">Cancel</button><button class="primary operate-only" type="button" onclick="saveTicket()">Save Ticket</button></div>
  </div>
 </div>
</div>

<div class="view" id="view-reports" style="display:none">
<div class="report-workspace">
<div class="report-hero"><div class="report-hero-copy"><div class="report-hero-icon">▤</div><div><h1 style="margin:0 0 4px">Reports</h1><div class="muted">Choose a report card, then generate it now or schedule it below.</div></div></div><div class="report-generate-bar"><select id="reportGenerateType" class="filter" style="display:none"><option value="network_summary">Network Summary</option><option value="device_inventory">Device Inventory</option><option value="security_findings">Security Findings</option><option value="availability_monitoring">Availability &amp; Monitoring</option><option value="integrations_health">Integrations Health</option><option value="traffic_usage">Traffic Usage</option><option value="audit_activity">Audit Activity</option><option value="device_changes">Device Changes</option></select><button class="primary" onclick="generateReport()">＋ Generate Selected Report</button></div></div>
<div class="report-type-section"><div class="report-type-label">Choose report type</div><div class="report-type-grid">
<button type="button" class="report-type-card active" data-report-type="network_summary" onclick="selectReportType('network_summary')"><div class="report-type-top"><span class="report-type-icon">⌂</span><span class="report-type-check">✓</span></div><div class="report-type-name">Network Summary</div><div class="report-type-desc">Overall devices, findings, monitors, topology and integration health.</div><div class="report-type-foot">Best for daily operational review</div></button>
<button type="button" class="report-type-card" data-report-type="device_inventory" onclick="selectReportType('device_inventory')"><div class="report-type-top"><span class="report-type-icon">▣</span><span class="report-type-check">✓</span></div><div class="report-type-name">Device Inventory</div><div class="report-type-desc">Device identity, IP/MAC, status, type, classification and last seen.</div><div class="report-type-foot">Best for asset inventory</div></button>
<button type="button" class="report-type-card" data-report-type="security_findings" onclick="selectReportType('security_findings')"><div class="report-type-top"><span class="report-type-icon">⚠</span><span class="report-type-check">✓</span></div><div class="report-type-name">Security Findings</div><div class="report-type-desc">Open findings, severity, affected targets and remediation guidance.</div><div class="report-type-foot">Best for security review</div></button>
<button type="button" class="report-type-card" data-report-type="availability_monitoring" onclick="selectReportType('availability_monitoring')"><div class="report-type-top"><span class="report-type-icon">◔</span><span class="report-type-check">✓</span></div><div class="report-type-name">Availability & Monitoring</div><div class="report-type-desc">Monitor states, targets, latency and the latest availability checks.</div><div class="report-type-foot">Best for service uptime</div></button>
<button type="button" class="report-type-card" data-report-type="integrations_health" onclick="selectReportType('integrations_health')"><div class="report-type-top"><span class="report-type-icon">⌘</span><span class="report-type-check">✓</span></div><div class="report-type-name">Integrations Health</div><div class="report-type-desc">Pi-hole, UniFi and SNMP sync status, errors and last collection.</div><div class="report-type-foot">Best for collector health</div></button>
<button type="button" class="report-type-card" data-report-type="traffic_usage" onclick="selectReportType('traffic_usage')"><div class="report-type-top"><span class="report-type-icon">⇅</span><span class="report-type-check">✓</span></div><div class="report-type-name">Traffic Usage</div><div class="report-type-desc">Measured per-device download, upload, rates, source and confidence.</div><div class="report-type-foot">Best for bandwidth review</div></button>
<button type="button" class="report-type-card" data-report-type="audit_activity" onclick="selectReportType('audit_activity')"><div class="report-type-top"><span class="report-type-icon">◎</span><span class="report-type-check">✓</span></div><div class="report-type-name">Audit Activity</div><div class="report-type-desc">Administrative and user actions from the retained security audit trail.</div><div class="report-type-foot">Best for accountability</div></button>
<button type="button" class="report-type-card" data-report-type="device_changes" onclick="selectReportType('device_changes')"><div class="report-type-top"><span class="report-type-icon">↻</span><span class="report-type-check">✓</span></div><div class="report-type-name">Device Changes</div><div class="report-type-desc">New devices, reconnects, online/offline transitions and IP changes.</div><div class="report-type-foot">Best for change tracking</div></button>
</div></div>
<div class="report-kpi-grid">
<div class="report-kpi"><div class="k">Generated Reports</div><div class="v" id="reportGeneratedCount">—</div><div class="sub">Retained report history</div></div>
<div class="report-kpi"><div class="k">Scheduled</div><div class="v" id="reportScheduleCount">—</div><div class="sub">Automated report jobs</div></div>
<div class="report-kpi"><div class="k">Latest Report</div><div class="v" id="reportLatestType" style="font-size:15px">—</div><div class="sub" id="reportLatestTime">Nothing generated yet</div></div>
<div class="report-kpi"><div class="k">Export Formats</div><div class="v" style="font-size:15px">PDF · CSV</div><div class="sub">Download any generated report</div></div>
</div>
<div class="traffic-card-workspace">
<div class="traffic-card-heading"><div class="traffic-card-heading-copy"><div class="traffic-title-icon">⇅</div><div><h2>Per-Device Traffic Collection</h2><div class="muted">Measured traffic intelligence with a clearly defined source, status and confidence.</div></div></div><span id="trafficCollectionState" class="traffic-state">LOADING</span></div>

<div class="traffic-stat-grid">
<div class="traffic-stat-card"><span class="traffic-stat-icon">⌘</span><div class="traffic-stat-label">Active Source</div><div class="traffic-stat-value" id="trafficSourceLabel">—</div><div class="traffic-stat-sub" id="trafficSourceSub">Not configured</div></div>
<div class="traffic-stat-card"><span class="traffic-stat-icon">↓</span><div class="traffic-stat-label">24h Download</div><div class="traffic-stat-value" id="traffic24Rx">0 B</div><div class="traffic-stat-sub">Measured per-device traffic</div></div>
<div class="traffic-stat-card"><span class="traffic-stat-icon">↑</span><div class="traffic-stat-label">24h Upload</div><div class="traffic-stat-value" id="traffic24Tx">0 B</div><div class="traffic-stat-sub">Measured per-device traffic</div></div>
<div class="traffic-stat-card"><span class="traffic-stat-icon">▣</span><div class="traffic-stat-label">Devices Measured</div><div class="traffic-stat-value" id="trafficDeviceCount">0</div><div class="traffic-stat-sub" id="trafficLastSample">No samples yet</div></div>
</div>

<section class="traffic-source-section-card">
<div class="traffic-card-section-head"><div class="traffic-card-section-title"><span class="traffic-section-icon">1</span><div><h3>1. Choose traffic source</h3><div class="muted">Select the source that can actually observe device traffic.</div></div></div></div>
<div class="traffic-card-section-body">
<select id="trafficMode" class="filter" onchange="renderTrafficModeFields()" style="display:none"><option value="unifi">UniFi / Controller</option><option value="snmp">SNMP</option><option value="span">SPAN / Mirror</option><option value="inline">Inline / Gateway</option></select>
<div class="traffic-source-grid">
<button type="button" class="traffic-source-card" data-traffic-mode="unifi" data-clean="1" onclick="selectTrafficMode('unifi')">
  <div class="traffic-source-card-head"><span class="traffic-source-icon">◉</span><div><div class="traffic-source-name">UniFi / Controller</div><div class="traffic-source-kind">Controller API</div></div><span class="traffic-selected-check">✓</span></div>
  <div class="traffic-source-desc">Use device counters already collected by your UniFi controller.</div>
  <div class="traffic-source-divider"></div><div class="traffic-source-meta"><span>UniFi networks</span></div>
  <div class="traffic-source-foot"><span class="traffic-source-tag recommended">Recommended</span><span>Select an integration</span></div>
</button>
<button type="button" class="traffic-source-card" data-traffic-mode="snmp" data-clean="1" onclick="selectTrafficMode('snmp')">
  <div class="traffic-source-card-head"><span class="traffic-source-icon">⌁</span><div><div class="traffic-source-name">SNMP</div><div class="traffic-source-kind">Counter profile</div></div><span class="traffic-selected-check">✓</span></div>
  <div class="traffic-source-desc">Read mapped traffic counters from supported routers and switches.</div>
  <div class="traffic-source-divider"></div><div class="traffic-source-meta"><span>Managed networks</span></div>
  <div class="traffic-source-foot"><span class="traffic-source-tag">Flexible</span><span>OID profile required</span></div>
</button>
<button type="button" class="traffic-source-card" data-traffic-mode="span" data-clean="1" onclick="selectTrafficMode('span')">
  <div class="traffic-source-card-head"><span class="traffic-source-icon">⇄</span><div><div class="traffic-source-name">SPAN / Mirror</div><div class="traffic-source-kind">Packet sensor</div></div><span class="traffic-selected-check">✓</span></div>
  <div class="traffic-source-desc">Observe mirrored traffic without placing GODSEYE in the gateway path.</div>
  <div class="traffic-source-divider"></div><div class="traffic-source-meta"><span>Passive visibility</span></div>
  <div class="traffic-source-foot"><span class="traffic-source-tag advanced">Advanced</span><span>Mirror port + NIC</span></div>
</button>
<button type="button" class="traffic-source-card" data-traffic-mode="inline" data-clean="1" onclick="selectTrafficMode('inline')">
  <div class="traffic-source-card-head"><span class="traffic-source-icon">↔</span><div><div class="traffic-source-name">Inline / Gateway</div><div class="traffic-source-kind">Inline sensor</div></div><span class="traffic-selected-check">✓</span></div>
  <div class="traffic-source-desc">Measure traffic that actually passes through the GODSEYE appliance.</div>
  <div class="traffic-source-divider"></div><div class="traffic-source-meta"><span>Full-path visibility</span></div>
  <div class="traffic-source-foot"><span class="traffic-source-tag advanced">Advanced</span><span>Full-path visibility</span></div>
</button>
</div>
</div>
</section>

<section class="traffic-config-section-card">
<div class="traffic-card-section-head"><div class="traffic-card-section-title"><span class="traffic-section-icon">2</span><div><h3>2. Configure source</h3><div class="muted">Collection settings and requirements are separated into their own cards.</div></div></div></div>
<div class="traffic-card-section-body">
<div class="traffic-config-card-grid">
<div class="traffic-mini-card"><h4>Source Configuration</h4><div class="traffic-config-fields">
<label id="trafficIntegrationWrap">Source integration<select id="trafficIntegration" class="filter"></select></label>
<label id="trafficInterfaceWrap" style="display:none">Capture interface<select id="trafficInterface" class="filter"></select></label>
<label>Sample interval<input id="trafficInterval" class="input" type="number" min="10" max="3600" value="30"><span class="muted">Seconds between collection cycles</span></label>
<label>Collection state<select id="trafficEnabled" class="filter"><option value="0">Disabled</option><option value="1">Enabled</option></select></label>
</div><div class="traffic-config-actions-card"><button class="primary" data-admin-only onclick="saveTrafficCollection()">Save Configuration</button><button class="secondary" data-admin-only onclick="collectTrafficNow()">Run Collection Now</button><span class="muted" id="trafficCollectionMeta"></span></div></div>
<div class="traffic-mini-card"><h4 id="trafficModeHelpTitle">Source Requirements</h4><div id="trafficModeHelp" class="traffic-help-copy">Select a traffic source to see its requirements.</div><div id="trafficModeRequire" class="traffic-help-require">GODSEYE records the measurement source and confidence with every device sample.</div></div>
</div>
</div>
</section>

<section class="traffic-usage-card">
<div class="traffic-card-section-head"><div class="traffic-card-section-title"><span class="traffic-section-icon">3</span><div><h3>Top Device Usage · Last 24 Hours</h3><div class="muted">Only real measured per-device counters are displayed.</div></div></div><button class="secondary" onclick="loadReports()">↻ Refresh</button></div>
<div class="traffic-table-wrap"><table><thead><tr><th>Device</th><th>Source</th><th>Download</th><th>Upload</th><th>Peak Download</th><th>Peak Upload</th><th>Last Sample</th></tr></thead><tbody id="trafficDeviceRows"><tr><td colspan="7" class="empty traffic-empty"><span class="traffic-empty-icon">⇅</span>No per-device traffic samples yet.</td></tr></tbody></table></div>
</section>
</div>
<div class="report-grid-two">
<section class="report-section-card"><div class="report-section-head"><div class="report-section-title"><span class="report-section-icon">≡</span><div><h2>Current Network Summary</h2><div class="muted">Live report-ready network snapshot</div></div></div><button class="secondary" onclick="loadReports()">↻ Refresh</button></div><div class="report-section-body"><pre id="reportSummary" class="report-summary-box">Loading…</pre></div></section>
<section class="report-section-card"><div class="report-section-head"><div class="report-section-title"><span class="report-section-icon">◷</span><div><h2>Schedule a Report</h2><div class="muted">Automate recurring report generation</div></div></div></div><div class="report-section-body"><div class="report-schedule-form"><label class="full">Schedule name<input id="reportName" class="input" placeholder="Weekly security review"></label><label>Report type<select id="reportScheduleType" class="filter"><option value="network_summary">Network Summary</option><option value="device_inventory">Device Inventory</option><option value="security_findings">Security Findings</option><option value="availability_monitoring">Availability &amp; Monitoring</option><option value="integrations_health">Integrations Health</option><option value="traffic_usage">Traffic Usage</option><option value="audit_activity">Audit Activity</option><option value="device_changes">Device Changes</option></select></label><label>Cadence<select id="reportCadence" class="filter"><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="hourly">Hourly</option></select></label><label>UTC hour<input id="reportHour" class="input" type="number" min="0" max="23" value="12"></label><div style="display:flex;align-items:end"><button class="primary" style="width:100%" onclick="addReportSchedule()">＋ Add Schedule</button></div></div></div></section>
</div>
<section class="report-section-card"><div class="report-section-head"><div class="report-section-title"><span class="report-section-icon">▦</span><div><h2>Scheduled Reports</h2><div class="muted">Upcoming automated report jobs</div></div></div></div><div class="report-history-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Cadence</th><th>Next Run</th><th>Last Run</th><th></th></tr></thead><tbody id="reportSchedules"></tbody></table></div></section>
<section class="report-section-card"><div class="report-section-head"><div class="report-section-title"><span class="report-section-icon">⇩</span><div><h2>Report History</h2><div class="muted">Generated reports, export formats, email delivery, and cleanup</div></div></div><div class="actions admin-only"><button class="danger" id="deleteSelectedReportsBtn" onclick="deleteSelectedReports()" disabled>Delete Selected</button></div></div><div class="report-history-wrap"><table><thead><tr><th><input type="checkbox" id="reportSelectAll" onchange="toggleAllReports(this.checked)" aria-label="Select all reports"></th><th>Generated</th><th>Type</th><th>Title</th><th>Key Metrics</th><th>Export</th><th>Actions</th></tr></thead><tbody id="reportHistory"></tbody></table></div></section>
</div>
</div>


<div class="view" id="view-remote-access" style="display:none">
<div class="hero remote-hero"><div><h1>Remote Access</h1><div class="muted">Secure remote support for computers running GODSEYE Windows Agent 2.2.0 or newer. The signed-in Windows user must approve each session.</div></div><div class="remote-stats"><span><b id="remoteOnlineCount">0</b> Online</span><span><b id="remoteOfflineCount">0</b> Offline</span><span><b id="remoteTotalCount">0</b> Agents</span></div></div>
<div class="remote-layout">
<section class="panel remote-computers"><div class="table-head"><h2>Agent Computers</h2><button class="secondary" type="button" onclick="loadRemoteAccess()">↻ Refresh</button></div><div class="remote-filter"><input id="remoteSearch" class="input" placeholder="Search computers…" oninput="renderRemoteAgents()"></div><div id="remoteAgentList" class="remote-agent-list"><div class="empty">Loading Windows Agents…</div></div></section>
<section class="panel remote-session-panel">
<div class="remote-session-head"><div><h2 id="remoteSessionTitle">Remote Session</h2><div class="muted" id="remoteSessionStatus">Select an online computer to begin.</div></div><div class="actions"><button id="remoteScreenshotBtn" class="secondary" type="button" onclick="openRemoteScreenshot()" disabled>Take Screenshot</button><button id="remoteDisconnectBtn" class="danger" type="button" onclick="stopRemoteSession()" disabled>Disconnect</button></div></div>
<div id="remoteScreenWrap" class="remote-screen-wrap" tabindex="0"><div id="remoteEmpty" class="remote-screen-empty"><div class="remote-monitor-icon">▰</div><b>No active remote session</b><span>Select a computer and click Connect.</span></div><img id="remoteScreen" class="remote-screen" alt="Remote Windows desktop" draggable="false" style="display:none"></div>
<div id="remoteSessionMeta" class="remote-session-meta"><span>Computer: <b>—</b></span><span>User approval: <b>Required</b></span><span>Agent: <b>—</b></span><span>Status: <b>Idle</b></span></div>
</section></div></div>

<div class="view" id="view-health" style="display:none">
<div class="hero"><div><h1>Raspberry Pi Health</h1><div class="muted">Appliance diagnostics, backups, retention and metrics security</div></div><div class="actions"><button class="secondary" onclick="loadHealth()">↻ Refresh</button><button class="primary" onclick="createBackup()">Create Backup</button></div></div>
<div class="cards"><div class="card"><div class="label">Overall</div><div class="num" id="healthOverall">—</div></div><div class="card"><div class="label">Hostname</div><div class="num" id="healthHost" style="font-size:16px">—</div></div><div class="card"><div class="label">Kernel</div><div class="num" id="healthKernel" style="font-size:16px">—</div></div></div>
<section class="panel"><div class="table-head"><h2>Self Diagnostics</h2><div class="muted">CPU, temperature, memory, disk, database, services and network interface</div></div><div style="overflow:auto"><table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody id="healthChecks"></tbody></table></div></section>
<section class="panel"><div class="table-head"><h2>Encrypted Secrets & Prometheus</h2><div class="muted">Integration credentials are encrypted at rest with the appliance key</div></div><div style="padding:16px"><button class="primary" onclick="rotateMetricsKey()">Generate / Rotate Metrics API Key</button><pre id="metricsKeyOut" style="white-space:pre-wrap;margin-top:12px"></pre><div class="muted header-help-extra">Prometheus can authenticate with Authorization: Bearer &lt;key&gt; or X-API-Key. Browser sessions can also open /metrics.</div></div></section>
<section class="panel"><div class="table-head"><h2>Retention Policies</h2><div class="muted">Days to retain local operational history</div></div><div style="padding:16px" class="grid"><label>Traffic <input id="retTraffic" class="input" type="number" min="1"></label><label>Events <input id="retEvents" class="input" type="number" min="1"></label><label>Audit <input id="retAudit" class="input" type="number" min="1"></label><label>Reports <input id="retReports" class="input" type="number" min="1"></label><label>Sync history <input id="retSync" class="input" type="number" min="1"></label><label>Notifications <input id="retNotify" class="input" type="number" min="1"></label><div><button class="primary" onclick="saveRetention()">Save & Prune</button></div></div></section>
<section class="panel"><div class="table-head"><h2>Database Backups</h2><div class="muted">SQLite online backups with integrity checks. Restore automatically creates a pre-restore safety backup.</div></div><div style="overflow:auto"><table><thead><tr><th>Created</th><th>Filename</th><th>Size</th><th>Note</th><th>Action</th></tr></thead><tbody id="backupRows"></tbody></table></div></section>
<section class="panel"><div class="table-head"><h2>Production Appliance Management</h2><div class="muted">Automatic backups, HTTPS, configuration portability and controlled updates</div></div><div style="padding:16px" class="grid"><label>Automatic backup <select id="prodAutoBackup" class="filter"><option value="1">Enabled</option><option value="0">Disabled</option></select></label><label>Backup UTC hour <input id="prodBackupHour" class="input" type="number" min="0" max="23" value="3"></label><label>Backups to keep <input id="prodBackupKeep" class="input" type="number" min="1" max="100" value="14"></label><label>Update channel <select id="prodUpdateChannel" class="filter"><option value="stable">Stable</option><option value="beta">Beta</option></select></label><div><button class="primary" onclick="saveProductionSettings()">Save Appliance Settings</button> <a class="secondary" href="/api/v1/config/export" style="text-decoration:none">Export Config</a></div><div id="httpsOut" class="muted header-help-extra"></div></div></section>
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
<select class="filter" id="ruleType" onchange="updateRuleFields()"><option value="new_device_burst">New device burst</option><option value="offline_duration">Offline duration</option><option value="ip_change_burst">IP address changes</option><option value="reconnect_burst">Device reconnects</option><option value="offline_count">Offline device count</option><option value="scanner_stale">Scanner not reporting</option><option value="classification_count">Classification count</option></select>
<span id="ruleFieldsBurst" style="display:flex;gap:6px;align-items:center"><input class="input" id="ruleBurstCount" type="number" min="1" value="10" style="width:80px" title="Count"><span class="muted">new devices in</span><input class="input" id="ruleBurstWindow" type="number" min="1" value="5" style="width:80px" title="Window (minutes)"><span class="muted">min</span></span>
<span id="ruleFieldsOffline" style="display:none;gap:6px;align-items:center"><span class="muted">offline</span><input class="input" id="ruleOfflineMinutes" type="number" min="1" value="30" style="width:80px" title="Minutes"><span class="muted">min, classes:</span><input class="input" id="ruleOfflineClasses" placeholder="known,managed,investigate (blank=any)" style="width:190px"></span>
<span id="ruleFieldsEventBurst" style="display:none;gap:6px;align-items:center"><input class="input" id="ruleEventCount" type="number" min="1" value="3" style="width:80px"><span class="muted">events in</span><input class="input" id="ruleEventWindow" type="number" min="1" value="10" style="width:80px"><span class="muted">min</span></span>
<span id="ruleFieldsOfflineCount" style="display:none;gap:6px;align-items:center"><span class="muted">at least</span><input class="input" id="ruleOfflineCount" type="number" min="1" value="5" style="width:80px"><span class="muted">offline devices · cooldown</span><input class="input" id="ruleOfflineCountCooldown" type="number" min="1" value="15" style="width:80px"><span class="muted">min</span></span>
<span id="ruleFieldsScanner" style="display:none;gap:6px;align-items:center"><span class="muted">no successful scan for</span><input class="input" id="ruleScannerMinutes" type="number" min="1" value="10" style="width:80px"><span class="muted">min</span></span>
<span id="ruleFieldsClassification" style="display:none;gap:6px;align-items:center"><span class="muted">at least</span><input class="input" id="ruleClassCount" type="number" min="1" value="1" style="width:70px"><span class="muted">devices in classes</span><input class="input" id="ruleClasses" value="new,investigate" style="width:180px"><span class="muted">cooldown</span><input class="input" id="ruleClassCooldown" type="number" min="1" value="15" style="width:70px"><span class="muted">min</span></span>
<select class="filter" id="ruleSeverity"><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select>
<button class="primary" type="submit">Add rule</button>
</form>
<div style="overflow:auto"><table><thead><tr><th>Name</th><th>Type</th><th>Condition</th><th>Severity</th><th>Last triggered</th><th>Enabled</th><th></th></tr></thead><tbody id="rules"></tbody></table></div>
</section>
</div>

<div class="view" id="view-users" style="display:none">
<section class="panel" id="usersPanel"><h2>Users</h2>
<form class="userForm" onsubmit="return createUser(event)"><input class="input" id="newUserDisplayName" placeholder="Display name"><input class="input" id="newUsername" placeholder="Username" required><input class="input" id="newUserPassword" type="password" placeholder="Password (min __MIN_PASSWORD_LENGTH__ chars)" required minlength="__MIN_PASSWORD_LENGTH__"><select class="filter" id="newUserRole"><option value="readonly">Read-only</option><option value="auditor">Auditor</option><option value="operator">Operator</option><option value="admin">Admin</option></select><button class="primary" type="submit">Add user</button></form>
<div style="overflow:auto"><table><thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Created</th><th>Last login</th><th>Password changed</th><th>Must change PW</th><th>MFA</th><th></th></tr></thead><tbody id="users"></tbody></table></div>
</section>
</div>

<div class="view" id="view-audit" style="display:none">
<section class="panel" id="auditPanel"><div class="table-head"><h2>Audit Log</h2><div style="display:flex;align-items:center;gap:10px"><div class="muted">Security and administrative history</div><button type="button" class="danger admin-only" id="clearAuditBtn" onclick="openClearData('audit')">Clear Audit Log</button></div></div>
<div style="overflow:auto"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead><tbody id="auditRows"></tbody></table></div>
</section>
</div>

</div></main>
</div>
</div>
<div id="deviceCleanupModal" class="modal" style="display:none" onclick="if(event.target===this)closeDeviceCleanup()">
  <div class="modal-card">
    <div class="modal-head"><div><h2>Clean Up Devices</h2><div class="muted">Remove stale inventory entries. Audit history is preserved.</div></div><button class="icon-btn" onclick="closeDeviceCleanup()">×</button></div>
    <form onsubmit="return submitDeviceCleanup(event)" class="modal-form">
      <label>Cleanup mode<select class="filter" id="deviceCleanupMode" onchange="updateDeviceCleanupFields()"><option value="offline">Delete all offline devices</option><option value="old">Delete old devices</option></select></label>
      <label id="deviceCleanupDaysLabel" style="display:none">Older than<input class="input" id="deviceCleanupDays" type="number" min="1" max="3650" value="30"><span class="muted">days since last seen. Old-device cleanup can remove any device older than this cutoff, including online, Known, or Managed devices.</span></label>
      <label>Reason for deletion<textarea class="input" id="deviceCleanupReason" rows="3" maxlength="500" required placeholder="Example: Retiring stale inventory after network replacement"></textarea></label>
      <div class="muted">No safety exclusions are applied. Matching devices and their device-owned event/source/IP history are removed. The reason, actor, mode, and deleted count are preserved in the Audit Log.</div>
      <div class="err" id="deviceCleanupErr"></div>
      <div class="modal-actions"><button type="button" class="secondary" onclick="closeDeviceCleanup()">Cancel</button><button type="submit" class="danger">Delete Matching Devices</button></div>
    </form>
  </div>
</div>
<div id="deviceDeleteModal" class="modal" style="display:none" onclick="if(event.target===this)closeDeleteDevice()">
  <div class="modal-card">
    <div class="modal-head"><div><h2>Delete Device</h2><div class="muted" id="deviceDeleteIdentity">Remove this device from inventory.</div></div><button class="icon-btn" onclick="closeDeleteDevice()">×</button></div>
    <form onsubmit="return submitDeleteDevice(event)" class="modal-form">
      <input type="hidden" id="deviceDeleteId">
      <label>Reason for deletion<textarea class="input" id="deviceDeleteReason" rows="3" maxlength="500" required placeholder="Example: Device retired and removed from the network"></textarea></label>
      <div class="muted">Deletion is allowed regardless of device status or classification. The reason and device details are written to the Audit Log.</div>
      <div class="err" id="deviceDeleteErr"></div>
      <div class="modal-actions"><button type="button" class="secondary" onclick="closeDeleteDevice()">Cancel</button><button type="submit" class="danger">Delete Device</button></div>
    </form>
  </div>
</div>
<div id="deviceModal" class="modal" style="display:none" onclick="if(event.target===this)closeAddDevice()">
  <div class="modal-card">
    <div class="modal-head"><div><h2>Add Device</h2><div class="muted">Add a known device manually, or use Discover Network for automatic discovery.</div></div><button class="icon-btn" onclick="closeAddDevice()">×</button></div>
    <form onsubmit="return submitAddDevice(event)" class="modal-form">
      <label>Name<input class="input" id="deviceName" required placeholder="Living Room TV"></label>
      <label>IP address<input class="input" id="deviceIp" placeholder="192.168.1.50"></label>
      <label>MAC address<input class="input" id="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label>
      <label>Vendor<input class="input" id="deviceVendor" placeholder="Samsung"></label>
      <label>Type<input class="input" id="deviceType" placeholder="TV, Router, Computer…"></label>
      <label>Classification<select class="filter" id="deviceClass"><option value="known">Known</option><option value="managed">Managed</option><option value="new">New</option><option value="investigate">Investigate</option><option value="ignored">Ignored</option></select></label>
      <label>Notes<textarea class="input" id="deviceNotes" rows="3" placeholder="Optional notes"></textarea></label>
      <div class="err" id="deviceAddErr"></div>
      <div class="modal-actions"><button type="button" class="secondary" onclick="closeAddDevice()">Cancel</button><button type="submit" class="primary">Add Device</button></div>
    </form>
  </div>
</div>
<div id="renameDeviceModal" class="modal" style="display:none">
  <div class="modal-card" style="max-width:500px">
    <div class="modal-head"><div><h2>Name Device</h2><div class="muted">Give discovered devices a friendly name, or rename a known device at any time.</div></div><button class="icon-btn" onclick="closeRenameDevice()">×</button></div>
    <form onsubmit="return submitRenameDevice(event)" class="modal-form">
      <input type="hidden" id="renameDeviceId">
      <label>Device name<input class="input" id="renameDeviceName" required maxlength="120" placeholder="Living Room TV"></label>
      <div class="muted" id="renameDeviceIdentity"></div>
      <div class="err" id="renameDeviceErr"></div>
      <div class="modal-actions"><button type="button" class="secondary" onclick="closeRenameDevice()">Cancel</button><button type="submit" class="primary">Save Name</button></div>
    </form>
  </div>
</div>
<div id="classifyDeviceModal" class="modal" style="display:none">
  <div class="modal-card" style="max-width:520px">
    <div class="modal-head"><div><h2>Classify Device</h2><div class="muted">Set what the device is and how GODSEYE should manage it.</div></div><button class="icon-btn" onclick="closeClassifyDevice()">×</button></div>
    <form onsubmit="return submitClassifyDevice(event)" class="modal-form">
      <input type="hidden" id="classifyDeviceId">
      <label>Device type<input class="input" id="classifyDeviceType" maxlength="80" list="inventoryDeviceTypeChoices" placeholder="Router, PC, Camera, Switch…"></label>
      <datalist id="inventoryDeviceTypeChoices"><option value="Router"><option value="PC"><option value="Laptop"><option value="Camera"><option value="Switch"><option value="Access Point"><option value="Phone"><option value="Tablet"><option value="Printer"><option value="Server"><option value="NAS"><option value="TV / Media"><option value="IoT"><option value="Smart Home"><option value="Game Console"><option value="Other"></datalist>
      <label>Classification<select class="filter" id="classifyDeviceClass"><option value="new">New</option><option value="investigate">Investigate</option><option value="known">Known</option><option value="managed">Managed</option><option value="ignored">Ignored</option></select></label>
      <div class="muted" id="classifyDeviceIdentity"></div>
      <div class="err" id="classifyDeviceErr"></div>
      <div class="modal-actions"><button type="button" class="secondary" onclick="closeClassifyDevice()">Cancel</button><button type="submit" class="primary">Save Classification</button></div>
    </form>
  </div>
</div>
<div id="deviceIconModal" class="modal device-icon-modal" style="display:none" onclick="if(event.target===this)closeDeviceIcon()">
  <div class="modal-card device-icon-dialog" role="dialog" aria-modal="true" aria-labelledby="deviceIconTitle">
    <div class="modal-head"><div><h2 id="deviceIconTitle">Select Device Icon</h2><div class="muted">Choose a realistic device picture or upload your own.</div></div><button class="icon-btn" aria-label="Close icon picker" onclick="closeDeviceIcon()">×</button></div>
    <form onsubmit="return submitDeviceIcon(event)" class="modal-form">
      <input type="hidden" id="deviceIconId"><input type="hidden" id="deviceIconKey" value="auto"><input type="hidden" id="deviceIconData">
      <div class="device-icon-summary"><div class="device-icon-summary-art"><img id="deviceIconCurrentPreview" src="/assets/device-icons/other.svg?v=27" alt="Selected device icon"></div><div><div class="device-icon-summary-name" id="deviceIconName">Device</div><div class="device-icon-summary-meta" id="deviceIconIdentity"></div></div></div>
      <div class="device-icon-tabs" id="deviceIconTabs"><button type="button" class="device-icon-tab active" data-icon-category="all" onclick="setDeviceIconCategory('all')">All Icons</button><button type="button" class="device-icon-tab" data-icon-category="network" onclick="setDeviceIconCategory('network')">Network Devices</button><button type="button" class="device-icon-tab" data-icon-category="computers" onclick="setDeviceIconCategory('computers')">Computers &amp; Mobile</button><button type="button" class="device-icon-tab" data-icon-category="security" onclick="setDeviceIconCategory('security')">Security</button><button type="button" class="device-icon-tab" data-icon-category="home" onclick="setDeviceIconCategory('home')">Home &amp; IoT</button><button type="button" class="device-icon-tab" data-icon-category="other" onclick="setDeviceIconCategory('other')">Other</button></div>
      <div class="device-icon-picker" id="deviceIconPicker"></div>
      <div class="device-icon-custom"><b style="font-size:12px">Custom Icon</b><div class="muted" style="margin:4px 0 9px">PNG, JPEG, or WebP. Maximum 256 KB.</div><div class="icon-upload-row"><input id="deviceIconFile" type="file" accept="image/png,image/jpeg,image/webp" onchange="previewCustomDeviceIcon(this)"><img id="deviceIconPreview" class="custom-icon-preview" alt="Custom icon preview" style="display:none"></div></div>
      <div class="err" id="deviceIconErr"></div>
      <div class="modal-actions"><button type="button" class="secondary" onclick="closeDeviceIcon()">Cancel</button><button type="submit" class="primary">Save Icon</button></div>
    </form>
  </div>
</div>
<div class="modal" id="integrationModal" style="display:none" onclick="if(event.target===this)closeIntegrationModal()"><div class="modal-card" role="dialog" aria-modal="true"><div class="modal-head"><div><h2 id="integrationModalTitle">Add Integration</h2><div class="muted">Each saved collector runs independently and keeps its own sync history and analytics.</div></div><button class="icon-btn" onclick="closeIntegrationModal()">×</button></div><form class="modal-form" onsubmit="return submitIntegration(event)"><input id="integrationId" type="hidden"><label>Name<input id="integrationName" class="input" required placeholder="Home Pi-hole"></label><label>Type<select id="integrationKind" class="filter" onchange="updateIntegrationFields()"><option value="pihole">Pi-hole</option><option value="unifi">UniFi</option><option value="snmp">SNMP</option></select></label><label style="grid-column:1/-1">Target<input id="integrationTarget" class="input" required placeholder="https://pi.hole or 192.168.1.1"></label><div class="integration-kind-fields"><label id="integrationUserWrap">Username<input id="integrationUser" class="input" placeholder="Controller username"></label><label>Credential<input id="integrationSecret" class="input" type="password" placeholder="Blank keeps saved credential"></label><label id="integrationSiteWrap">UniFi Site<input id="integrationSite" class="input" value="default"></label><label>Sync interval (seconds)<input id="integrationInterval" class="input" type="number" min="30" value="300"></label></div><label style="flex-direction:row;align-items:center"><input id="integrationEnabled" type="checkbox" checked> Enabled</label><label style="flex-direction:row;align-items:center"><input id="integrationTls" type="checkbox" checked> Verify TLS certificate</label><div id="integrationErr" class="err"></div><div class="modal-actions"><button type="button" class="secondary" onclick="closeIntegrationModal()">Cancel</button><button class="primary" type="submit">Save Integration</button></div></form></div></div>
<div class="modal" id="deleteIntegrationModal" style="display:none" onclick="if(event.target===this)closeDeleteIntegrationModal()"><div class="modal-card" style="max-width:520px" role="dialog" aria-modal="true" aria-labelledby="deleteIntegrationTitle"><div class="modal-head"><div><h2 id="deleteIntegrationTitle">Remove Integration</h2><div class="muted">Remove an integration that is retired, replaced, or no longer reachable.</div></div><button class="icon-btn" onclick="closeDeleteIntegrationModal()">×</button></div><div id="deleteIntegrationSummary" class="remove-summary"></div><div style="padding:14px 20px 0"><label class="muted" style="display:block;margin-bottom:6px">Type REMOVE to confirm</label><input id="deleteIntegrationConfirm" class="input" style="width:100%;box-sizing:border-box" autocomplete="off" placeholder="REMOVE"><div id="deleteIntegrationErr" class="err" style="margin-top:7px"></div></div><div class="modal-actions" style="padding:16px 20px 20px"><button class="secondary" onclick="closeDeleteIntegrationModal()">Cancel</button><button class="danger" id="deleteIntegrationBtn" onclick="confirmDeleteIntegration()">Remove Integration</button></div></div></div>
<div class="modal" id="analyticsModal" style="display:none" onclick="if(event.target===this)closeAnalyticsModal()"><div class="modal-card analytics-dialog" style="width:min(760px,calc(100vw - 36px))" role="dialog" aria-modal="true"><div class="modal-head"><div><h2 id="analyticsTitle">Analytics</h2><div class="muted" id="analyticsSubtitle"></div></div><button class="icon-btn" onclick="closeAnalyticsModal()">×</button></div><div style="padding:18px 20px"><div id="analyticsSummary" class="analytics-summary"></div><pre id="analyticsDetail"></pre><div class="admin-only" style="border-top:1px solid #edf2f7;padding-top:13px;margin-top:13px"><label class="muted" style="display:block;margin-bottom:6px">Reason required to clear this analytics snapshot history</label><textarea id="analyticsClearReason" class="input" style="width:100%;min-height:66px;box-sizing:border-box" placeholder="Example: Reviewed DNS query statistics and exported the findings."></textarea><div id="analyticsClearErr" class="err"></div></div><div class="modal-actions"><button class="danger admin-only" id="clearOneAnalyticsBtn" onclick="clearCurrentAnalytics()">Clear This Analytics</button><button class="secondary" onclick="closeAnalyticsModal()">Done</button></div></div></div></div>
<div id="clearDataModal" class="modal" style="display:none">
  <div class="modal-card" style="max-width:540px">
    <div class="modal-head"><div><h2 id="clearDataTitle">Clear data</h2><div class="muted" id="clearDataHelp">A reason is required and will be written to the audit log.</div></div><button class="icon-btn" onclick="closeClearData()">×</button></div>
    <form onsubmit="return submitClearData(event)" class="modal-form">
      <input type="hidden" id="clearDataKind">
      <label>Reason<textarea class="input" id="clearDataReason" rows="4" required minlength="5" maxlength="500" placeholder="Example: Reviewed incident findings and no longer need the retained analytics history."></textarea></label>
      <div class="muted" id="clearDataWarning"></div>
      <div class="err" id="clearDataErr"></div>
      <div class="modal-actions"><button type="button" class="secondary" onclick="closeClearData()">Cancel</button><button type="submit" class="danger" id="clearDataConfirm">Clear Data</button></div>
    </form>
  </div>
</div>
<div id="monitorModal" class="modal" style="display:none" onclick="if(event.target===this)closeMonitorEditor()">
  <div class="modal-card" style="max-width:660px" role="dialog" aria-modal="true" aria-labelledby="monitorModalTitle">
    <div class="modal-head"><div><h2 id="monitorModalTitle">Add Monitor</h2><div class="muted">Create a persistent Raspberry Pi-native health check.</div></div><button class="icon-btn" aria-label="Close monitor editor" onclick="closeMonitorEditor()">×</button></div>
    <div class="modal-form">
      <div class="modal-section-title">Monitor Details</div>
      <label>Name<input class="input" id="monName" placeholder="Gateway health"><span class="form-hint">A clear label shown in Monitoring and Findings.</span></label>
      <label>Type<select class="filter" id="monKind"><option value="website">Website / HTTP</option><option value="dhcp">DHCP leases</option><option value="public_ip">Public IP</option><option value="pihole">Pi-hole</option><option value="unifi">UniFi</option><option value="snmp">SNMP</option></select><span class="form-hint">Choose what GODSEYE should check.</span></label>
      <label>Target<input class="input" id="monTarget" placeholder="https://example.com or 192.168.1.1"><span class="form-hint">Public IP monitors determine the target automatically.</span></label>
      <label>Check every<input class="input" id="monInterval" type="number" min="30" value="300"><span class="form-hint">Interval in seconds (minimum 30).</span></label>
      <label>Status<select class="filter" id="monEnabled"><option value="1">Enabled</option><option value="0">Disabled</option></select></label>
      <label>Advanced Options<textarea class="input" id="monOptions" rows="4">{}</textarea><span class="form-hint">Optional JSON settings for this monitor.</span></label>
      <div class="err" id="monitorEditorOut"></div>
      <div class="modal-actions"><button class="secondary" onclick="closeMonitorEditor()" type="button">Cancel</button><button class="primary" onclick="saveMonitor()" type="button">Save Monitor</button></div>
    </div>
  </div>
</div>

<div id="headerHelpModal" class="header-help-modal" style="display:none" role="dialog" aria-modal="true" aria-labelledby="headerHelpModalTitle">
  <div class="header-help-dialog">
    <div class="header-help-modal-head">
      <div class="header-help-modal-title"><span class="header-help-modal-icon">?</span><span id="headerHelpModalTitle">Information</span></div>
      <button type="button" class="header-help-close" aria-label="Close help" onclick="closeHeaderHelp()">×</button>
    </div>
    <div id="headerHelpModalBody" class="header-help-body"></div>
  </div>
</div>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const CLASS_CYCLE={new:'investigate',investigate:'known',known:'managed',managed:'ignored',ignored:'new'};
const CLASS_LABEL={new:'New',investigate:'Investigate',known:'Known',managed:'Managed',ignored:'Ignored'};
const DEVICE_ICON_LABELS={auto:'Auto',router:'Router',switch:'Switch','access-point':'Access Point',firewall:'Firewall',modem:'Modem',pc:'PC',laptop:'Laptop',server:'Server',nas:'NAS','network-storage':'Network Storage',camera:'Camera',printer:'Printer',phone:'Phone','voip-phone':'VoIP Phone',tablet:'Tablet',tv:'TV','game-console':'Game Console',iot:'IoT','patch-panel':'Patch Panel',other:'Other'};
const DEVICE_ICON_CATEGORIES={auto:'all',router:'network',switch:'network','access-point':'network',firewall:'network',modem:'network',nas:'network','network-storage':'network','patch-panel':'network',pc:'computers',laptop:'computers',server:'computers',printer:'computers',phone:'computers','voip-phone':'computers',tablet:'computers',camera:'security',tv:'home','game-console':'home',iot:'home',other:'other'};
let ACTIVE_DEVICE_ICON_CATEGORY='all';
const DEVICE_ICON_KEYS=Object.keys(DEVICE_ICON_LABELS);
const DEVICE_ICON_ASSET_VERSION='27';
function deviceIconAsset(key){return '/assets/device-icons/'+key+'.svg?v='+DEVICE_ICON_ASSET_VERSION}
function inferredDeviceIcon(type){const t=String(type||'').toLowerCase();if(t.includes('firewall'))return'firewall';if(t.includes('modem'))return'modem';if(t.includes('patch panel'))return'patch-panel';if(t.includes('voip'))return'voip-phone';if(t.includes('router')||t.includes('gateway'))return'router';if(t.includes('switch'))return'switch';if(t.includes('access point')||t==='ap'||t.includes('wifi'))return'access-point';if(t.includes('laptop')||t.includes('notebook'))return'laptop';if(t==='pc'||t.includes('desktop')||t.includes('computer')||t.includes('workstation'))return'pc';if(t.includes('camera')||t.includes('nvr'))return'camera';if(t.includes('printer'))return'printer';if(t.includes('phone')||t.includes('iphone')||t.includes('android'))return'phone';if(t.includes('tablet')||t.includes('ipad'))return'tablet';if(t.includes('server'))return'server';if(t.includes('network storage'))return'network-storage';if(t.includes('nas')||t.includes('storage'))return'nas';if(t.includes('tv')||t.includes('media')||t.includes('stream'))return'tv';if(t.includes('game')||t.includes('console')||t.includes('xbox')||t.includes('playstation'))return'game-console';if(t.includes('iot')||t.includes('smart')||t.includes('sensor')||t.includes('light'))return'iot';return'other'}
function effectiveDeviceIcon(d){return(d&&d.icon_key&&d.icon_key!=='auto')?d.icon_key:inferredDeviceIcon(d&&d.device_type)}
function deviceIconSrc(d){if(d&&d.icon_data)return d.icon_data;return deviceIconAsset(effectiveDeviceIcon(d))}
function deviceIconHtml(d){return `<span class="device-icon"><img src="${esc(deviceIconSrc(d))}" alt="${esc(DEVICE_ICON_LABELS[effectiveDeviceIcon(d)]||'Device')} icon"></span>`}
let ME=null;
let PENDING_MFA_TOKEN=null;
function getCookie(name){const m=document.cookie.match('(?:^|; )'+name+'=([^;]*)');return m?decodeURIComponent(m[1]):null}
async function json(url,opt={}){opt.headers=opt.headers||{};if(opt.method&&opt.method!=='GET'){let csrf=getCookie('godseye_csrf');if(!csrf){await fetch('/api/v1/auth/csrf');csrf=getCookie('godseye_csrf')}opt.headers['X-CSRF-Token']=csrf||''}let r=await fetch(url,opt);if(r.status===401){showLogin();throw new Error('unauthenticated')}if(!r.ok){let t=await r.text();throw new Error(t)}return r.status===204?null:r.json()}
function toggleUserMenu(){const m=document.getElementById("userMenu");if(m)m.style.display=m.style.display==="none"?"block":"none"}
function showLogin(){document.getElementById('app').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('setupOverlay').style.display='none';document.getElementById('authOverlay').style.display='grid'}
async function checkInitialSetup(){try{let r=await fetch('/api/v1/auth/setup/status');let d=await r.json();if(d.setup_required){document.getElementById('authOverlay').style.display='none';document.getElementById('setupOverlay').style.display='grid';return true}}catch(e){}return false}
async function doInitialSetup(e){e.preventDefault();const err=document.getElementById('setupErr');err.textContent='';if(setupPass.value!==setupPass2.value){err.textContent='Passwords do not match';return false}try{let r=await fetch('/api/v1/auth/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:'',new_password:setupPass.value})});if(!r.ok){let t=await r.json().catch(()=>({}));err.textContent=t.detail||'Could not create password';return false}document.getElementById('setupOverlay').style.display='none';document.getElementById('authOverlay').style.display='grid';loginUser.value='admin';loginPass.value='';loginPass.focus()}catch(e){err.textContent='Setup failed'}return false}
function showApp(){document.getElementById('authOverlay').style.display='none';document.getElementById('pwOverlay').style.display='none';document.getElementById('mfaLoginOverlay').style.display='none';document.getElementById('app').style.display='block'}


let CALENDAR_DATE=new Date();
let CALENDAR_EVENTS=[];
let CALENDAR_INTEGRATIONS=[];
let CALENDAR_SOURCE_VISIBILITY={local:true};
let CALENDAR_ACTIVE_TICKET_ID=null;

function calendarIsoLocal(d){
 const pad=n=>String(n).padStart(2,'0');
 return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function calendarMonthRange(d){
 const start=new Date(d.getFullYear(),d.getMonth(),1);
 start.setDate(start.getDate()-start.getDay());
 start.setHours(0,0,0,0);
 const end=new Date(start);end.setDate(end.getDate()+42);end.setMilliseconds(-1);
 return {start,end};
}
function calendarIntegrationForSource(source){
 if(!source||!source.startsWith('calendar:'))return null;
 const id=Number(source.split(':')[1]);
 return CALENDAR_INTEGRATIONS.find(x=>x.id===id)||null;
}
function calendarTargetOptions(selected=''){
 const writable=CALENDAR_INTEGRATIONS.filter(x=>x.auth_mode==='oauth'&&x.connected);
 const opts=['<option value="">GODSEYE local calendar</option>',...writable.map(i=>`<option value="${i.id}">${esc(i.name)} · ${i.provider==='google'?'Google':'Microsoft 365'}</option>`)];
 calendarEventTarget.innerHTML=opts.join('');
 calendarEventTarget.value=selected||'';
}
async function loadCalendar(){
 const range=calendarMonthRange(CALENDAR_DATE);
 const [events,integrations]=await Promise.all([
   json(`/api/v1/calendar/events?start=${encodeURIComponent(range.start.toISOString())}&end=${encodeURIComponent(range.end.toISOString())}`),
   json('/api/v1/calendar/integrations')
 ]);
 CALENDAR_EVENTS=events||[];CALENDAR_INTEGRATIONS=integrations||[];
 CALENDAR_INTEGRATIONS.forEach(x=>{const k='calendar:'+x.id;if(CALENDAR_SOURCE_VISIBILITY[k]===undefined)CALENDAR_SOURCE_VISIBILITY[k]=true});
 renderCalendar();
 renderCalendarIntegrations();
 calendarTargetOptions();
 applyRoleVisibility();
}
function calendarToday(){CALENDAR_DATE=new Date();loadCalendar()}
function calendarStep(delta){CALENDAR_DATE=new Date(CALENDAR_DATE.getFullYear(),CALENDAR_DATE.getMonth()+delta,1);loadCalendar()}
function installCalendarDateInteractions(){
 const grid=document.getElementById('calendarGrid');
 if(!grid||grid.dataset.dblclickReady==='1')return;
 grid.dataset.dblclickReady='1';
 grid.addEventListener('dblclick',e=>{
   if(e.target.closest('.calendar-event-chip'))return;
   const day=e.target.closest('.calendar-day[data-calendar-date]');
   if(!day||!grid.contains(day))return;
   e.preventDefault();
   openCalendarEventModal(null,day.dataset.calendarDate);
 });
}
function toggleCalendarSource(source,visible){CALENDAR_SOURCE_VISIBILITY[source]=visible;renderCalendar()}
function renderCalendarFilters(){
 const root=document.getElementById('calendarExternalFilters');if(!root)return;
 root.innerHTML=CALENDAR_INTEGRATIONS.map(i=>`<label class="calendar-filter"><input type="checkbox" ${CALENDAR_SOURCE_VISIBILITY['calendar:'+i.id]!==false?'checked':''} onchange="toggleCalendarSource('calendar:${i.id}',this.checked)"><span class="calendar-dot ${i.provider==='google'?'blue':'purple'}"></span>${esc(i.name)}</label>`).join('');
}
function renderCalendar(){
 const label=document.getElementById('calendarMonthLabel'),grid=document.getElementById('calendarGrid');if(!label||!grid)return;
 label.textContent=CALENDAR_DATE.toLocaleDateString(undefined,{month:'long',year:'numeric'});
 renderCalendarFilters();
 const range=calendarMonthRange(CALENDAR_DATE),today=new Date();today.setHours(0,0,0,0);
 let html='';
 for(let i=0;i<42;i++){
  const day=new Date(range.start);day.setDate(day.getDate()+i);
  const dayStart=new Date(day);dayStart.setHours(0,0,0,0);
  const dayEnd=new Date(day);dayEnd.setHours(23,59,59,999);
  const events=CALENDAR_EVENTS.filter(e=>{
    if(CALENDAR_SOURCE_VISIBILITY[e.source]===false)return false;
    const st=new Date(e.start_at),en=new Date(e.end_at);
    return st<=dayEnd&&en>=dayStart;
  });
  const sameMonth=day.getMonth()===CALENDAR_DATE.getMonth();
  const isToday=dayStart.getTime()===today.getTime();
  const createAt=calendarIsoLocal(new Date(day.getFullYear(),day.getMonth(),day.getDate(),9,0));
  html+=`<div class="calendar-day ${sameMonth?'':'outside'} ${isToday?'today':''}" data-calendar-date="${createAt}" title="Double-click to create an appointment"><div class="calendar-day-num">${day.getDate()}</div>`;
  events.slice(0,4).forEach(e=>{
    const integration=calendarIntegrationForSource(e.source);
    const synced=integration?' synced':'';
    const readonly=e.external_readonly?' readonly':'';
    const start=e.all_day?'':new Date(e.start_at).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'})+' ';
    const marker=e.ticket_id?'<span class="calendar-sync-mark">▧</span> ':(integration?'<span class="calendar-sync-mark">↻</span> ':'');
    html+=`<button class="calendar-event-chip ${esc(e.color||'blue')}${synced}${readonly}" title="${esc(e.title)}" onclick="event.stopPropagation();openCalendarEventModal(${e.id})" ondblclick="event.stopPropagation();openCalendarEventModal(${e.id})">${marker}${esc(start+e.title)}</button>`;
  });
  if(events.length>4)html+=`<div class="calendar-more">+${events.length-4} more</div>`;
  html+='</div>';
 }
 grid.innerHTML=html;
 installCalendarDateInteractions();
 const upcoming=CALENDAR_EVENTS.filter(e=>new Date(e.end_at)>=new Date()&&CALENDAR_SOURCE_VISIBILITY[e.source]!==false).sort((a,b)=>new Date(a.start_at)-new Date(b.start_at)).slice(0,5);
 const up=document.getElementById('calendarUpcoming');
 up.innerHTML=upcoming.length?upcoming.map(e=>{
   const integration=calendarIntegrationForSource(e.source);
   return `<div class="calendar-upcoming-item"><b>${esc(e.title)}</b><span>${new Date(e.start_at).toLocaleString()}${integration?' · '+esc(integration.name):''}</span></div>`;
 }).join(''):'<div class="empty">No upcoming appointments.</div>';
}
function openCalendarEventModal(id=null,startValue=null){
 const modal=document.getElementById('calendarEventModal');
 const event=id?CALENDAR_EVENTS.find(x=>x.id===Number(id)):null;
 if(event&&event.external_readonly){alert('This appointment comes from an ICS subscription. Connect the provider with OAuth if you want two-way editing.');return}
 calendarEventId.value=event?event.id:'';
 calendarEventModalTitle.textContent=event?'Edit appointment':'Create appointment';
 calendarEventTitle.value=event?event.title:'';
 calendarEventLocation.value=event?event.location||'':'';
 calendarEventDescription.value=event?event.description||'':'';
 calendarEventColor.value=event?event.color||'blue':'blue';
 calendarEventAllDay.checked=!!event?.all_day;
 const integration=event?calendarIntegrationForSource(event.source):null;
 calendarTargetOptions(integration?String(integration.id):'');
 calendarEventTarget.disabled=!!event;
 CALENDAR_ACTIVE_TICKET_ID=event?.ticket_id||null;
 calendarTicketActions.style.display=CALENDAR_ACTIVE_TICKET_ID?'flex':'none';
 if(CALENDAR_ACTIVE_TICKET_ID){
   calendarTicketLabel.textContent='Linked Ticket #'+CALENDAR_ACTIVE_TICKET_ID;
   calendarEventTitle.readOnly=true;calendarEventLocation.readOnly=true;calendarEventDescription.readOnly=true;calendarEventColor.disabled=true;
 }else{
   calendarEventTitle.readOnly=false;calendarEventLocation.readOnly=false;calendarEventDescription.readOnly=false;calendarEventColor.disabled=false;
 }
 let start=event?new Date(event.start_at):(startValue?new Date(startValue):new Date());
 if(!event){start.setSeconds(0,0);start.setMinutes(Math.ceil(start.getMinutes()/30)*30)}
 let end=event?new Date(event.end_at):new Date(start.getTime()+60*60*1000);
 calendarEventStart.value=calendarIsoLocal(start);calendarEventEnd.value=calendarIsoLocal(end);
 calendarDeleteBtn.style.display=event&&!CALENDAR_ACTIVE_TICKET_ID?'inline-flex':'none';
 calendarEventErr.textContent='';
 modal.style.display='grid';document.body.style.overflow='hidden';
 setTimeout(()=>calendarEventTitle.focus(),20);
}
function closeCalendarEventModal(){calendarEventModal.style.display='none';document.body.style.overflow='';calendarEventTarget.disabled=false;calendarEventTitle.readOnly=false;calendarEventLocation.readOnly=false;calendarEventDescription.readOnly=false;calendarEventColor.disabled=false;CALENDAR_ACTIVE_TICKET_ID=null;calendarTicketActions.style.display='none'}
async function openCalendarLinkedTicket(){
 if(!CALENDAR_ACTIVE_TICKET_ID)return;
 closeCalendarEventModal();showView('tickets',true);await loadTickets();openTicketEditor(CALENDAR_ACTIVE_TICKET_ID);
}
async function addCalendarTicketNote(){
 if(!CALENDAR_ACTIVE_TICKET_ID)return;
 const note=prompt('Add a work note to this ticket:');if(!note||!note.trim())return;
 try{await json('/api/v1/tickets/'+CALENDAR_ACTIVE_TICKET_ID+'/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note:note.trim()})});alert('Work note added.')}catch(e){alert('Could not add note: '+e.message)}
}
async function resolveCalendarTicket(){
 if(!CALENDAR_ACTIVE_TICKET_ID)return;
 try{await json('/api/v1/tickets/'+CALENDAR_ACTIVE_TICKET_ID,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'resolved'})});alert('Ticket marked resolved.');await loadCalendar()}catch(e){alert('Could not resolve ticket: '+e.message)}
}
async function closeCalendarTicket(){
 if(!CALENDAR_ACTIVE_TICKET_ID)return;
 const note=prompt('Closing work note (optional):')||'';
 const resolveLinked=confirm('Also resolve the linked Event Finding, if this ticket came from one?');
 try{await json('/api/v1/tickets/'+CALENDAR_ACTIVE_TICKET_ID+'/close',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note,resolve_linked_finding:resolveLinked})});alert('Ticket closed.');closeCalendarEventModal();await loadCalendar()}catch(e){alert('Could not close ticket: '+e.message)}
}
async function saveCalendarEvent(e){
 e.preventDefault();calendarEventErr.textContent='';
 const id=calendarEventId.value;
 const body={title:calendarEventTitle.value.trim(),description:calendarEventDescription.value.trim(),location:calendarEventLocation.value.trim(),
   start_at:new Date(calendarEventStart.value).toISOString(),end_at:new Date(calendarEventEnd.value).toISOString(),
   all_day:calendarEventAllDay.checked,color:calendarEventColor.value,
   calendar_integration_id:calendarEventTarget.value?Number(calendarEventTarget.value):null};
 try{
  await json(id?'/api/v1/calendar/events/'+id:'/api/v1/calendar/events',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  closeCalendarEventModal();await loadCalendar();
 }catch(err){calendarEventErr.textContent='Could not save appointment: '+err.message}
 return false;
}
async function deleteCalendarEvent(){
 const id=calendarEventId.value;if(!id)return;
 if(!confirm('Delete this appointment? Connected calendar events will also be deleted from the provider.'))return;
 try{await json('/api/v1/calendar/events/'+id,{method:'DELETE'});closeCalendarEventModal();await loadCalendar()}catch(err){calendarEventErr.textContent='Could not delete appointment: '+err.message}
}
function selectCalendarProvider(provider){
 calendarProvider.value=provider;
 document.querySelectorAll('.calendar-provider').forEach(x=>x.classList.toggle('active',x.dataset.provider===provider));
 calendarIntegrationRemoteId.placeholder=provider==='google'?'primary':'default';
}
function selectCalendarAuthMode(mode){
 calendarAuthMode.value=mode;
 document.querySelectorAll('.calendar-mode-tab').forEach(x=>x.classList.toggle('active',x.dataset.mode===mode));
 const oauth=mode==='oauth';
 calendarClientIdWrap.style.display=oauth?'flex':'none';
 calendarClientSecretWrap.style.display=oauth?'flex':'none';
 calendarIcsWrap.style.display=oauth?'none':'flex';
 calendarIntegrationRemoteId.parentElement.style.display=oauth?'flex':'none';
 calendarIntegrationModeNote.textContent=oauth
   ?'Two-way OAuth lets GODSEYE create, edit and delete events in the connected calendar. OAuth credentials and refresh tokens are encrypted at rest.'
   :'ICS remains available as a read-only fallback. To edit provider events from GODSEYE, use Two-way OAuth.';
}
function openCalendarIntegrationModal(){
 selectCalendarAuthMode('oauth');
 calendarIntegrationModal.style.display='grid';document.body.style.overflow='hidden';renderCalendarIntegrations()
}
function closeCalendarIntegrationModal(){calendarIntegrationModal.style.display='none';document.body.style.overflow=''}
async function saveCalendarIntegration(){
 calendarIntegrationErr.textContent='';
 const mode=calendarAuthMode.value;
 const body={provider:calendarProvider.value,name:calendarIntegrationName.value.trim(),account_email:calendarIntegrationEmail.value.trim(),
 calendar_name:calendarIntegrationCalendar.value.trim(),auth_mode:mode,remote_calendar_id:calendarIntegrationRemoteId.value.trim(),
 ics_url:calendarIntegrationIcs.value.trim(),client_id:calendarIntegrationClientId.value.trim(),client_secret:calendarIntegrationClientSecret.value,
 enabled:true,sync_interval_minutes:Number(calendarIntegrationInterval.value||30)};
 try{
  const result=await json('/api/v1/calendar/integrations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  calendarIntegrationIcs.value='';calendarIntegrationClientSecret.value='';calendarIntegrationName.value='';calendarIntegrationCalendar.value='';
  await loadCalendar();
  if(result.needs_authorization)await connectCalendarIntegration(result.id);
  else await syncCalendarIntegration(result.id);
 }catch(err){calendarIntegrationErr.textContent='Could not save calendar integration: '+err.message}
}
async function connectCalendarIntegration(id){
 try{
  const result=await json('/api/v1/calendar/integrations/'+id+'/oauth/start',{method:'POST'});
  const popup=window.open(result.authorization_url,'godseyeCalendarOAuth','width=620,height=760,resizable=yes,scrollbars=yes');
  if(!popup)throw new Error('Browser blocked the authorization window');
 }catch(err){alert('Could not start calendar authorization: '+err.message)}
}
window.addEventListener('message',async event=>{
 if(event.origin!==window.location.origin||event.data?.type!=='godseye-calendar-connected')return;
 await loadCalendar();
 renderCalendarIntegrations();
});
async function syncCalendarIntegration(id){
 try{
  await json('/api/v1/calendar/integrations/'+id+'/sync',{method:'POST'});
  await loadCalendar();
 }catch(err){alert('Calendar sync failed: '+err.message)}
}
async function removeCalendarIntegration(id){
 if(!confirm('Remove this calendar integration and its synchronized appointments?'))return;
 await json('/api/v1/calendar/integrations/'+id,{method:'DELETE'});await loadCalendar();
}
function renderCalendarIntegrations(){
 const root=document.getElementById('calendarIntegrationList');if(!root)return;
 root.innerHTML=CALENDAR_INTEGRATIONS.length?CALENDAR_INTEGRATIONS.map(i=>{
  const oauth=i.auth_mode==='oauth';
  const provider=i.provider==='google'?'Google Calendar':'Microsoft 365 / Outlook';
  const status=oauth?(i.connected?'Two-way connected':'Authorization required'):'ICS read-only';
  return `<div class="calendar-integration-row">
   <span class="calendar-provider-icon">${i.provider==='google'?'G':'M'}</span>
   <div><b>${esc(i.name)}</b><small>${provider} · ${status} · ${esc(i.calendar_name||i.account_email||i.remote_calendar_id||'Calendar')}${i.last_sync_at?' · '+new Date(i.last_sync_at).toLocaleString():''}</small></div>
   <div class="actions admin-only">${oauth&&!i.connected?`<button class="primary" onclick="connectCalendarIntegration(${i.id})">Connect</button>`:''}<button class="secondary" onclick="syncCalendarIntegration(${i.id})">Sync</button><button class="danger" onclick="removeCalendarIntegration(${i.id})">Remove</button></div>
  </div>`;
 }).join(''):'<div class="empty">No external calendar integrations configured.</div>';
}

let EMAIL_INTEGRATIONS=[];
let EMAIL_FOLDERS=[];
let EMAIL_MESSAGES=[];
let EMAIL_SELECTED_INTEGRATION=null;
let EMAIL_SELECTED_FOLDER=null;
let EMAIL_SELECTED_MESSAGE=null;
let EMAIL_QUICK_ACTION={id:null,action:null};

function emailSplitAddresses(value){
 return String(value||'').split(/[;,]/).map(x=>x.trim()).filter(Boolean);
}
function emailConnectedIntegrations(){
 return EMAIL_INTEGRATIONS.filter(x=>x.connected);
}
function renderEmailAccountSelects(){
 const connected=emailConnectedIntegrations();
 const options=connected.map(x=>`<option value="${x.id}">${esc(x.name)} · ${x.provider==='gmail'?'Gmail':'Microsoft 365'}</option>`).join('');
 [document.getElementById('emailAccountSelect'),document.getElementById('emailComposeAccount'),document.getElementById('emailReportAccount')].forEach(el=>{
   if(!el)return;
   const current=el.value;
   el.innerHTML=options||'<option value="">No connected mailbox</option>';
   if(current&&connected.some(x=>String(x.id)===String(current)))el.value=current;
   else if(EMAIL_SELECTED_INTEGRATION)el.value=String(EMAIL_SELECTED_INTEGRATION);
 });
}
async function loadEmail(){
 try{
  EMAIL_INTEGRATIONS=await json('/api/v1/email/integrations');
  renderEmailIntegrations();
  renderEmailAccountSelects();
  const connected=emailConnectedIntegrations();
  if(!connected.length){
    EMAIL_SELECTED_INTEGRATION=null;EMAIL_SELECTED_FOLDER=null;EMAIL_MESSAGES=[];
    emailFolderList.innerHTML='<div class="empty">No connected mail account. Use Mail Accounts to connect Gmail or Microsoft 365.</div>';
    emailMessageList.innerHTML='<div class="empty">No mailbox connected.</div>';
    emailListMeta.textContent='No mailbox selected.';
    emailReaderPane.innerHTML='<div class="email-reader-empty"><div class="email-reader-empty-icon">✉</div><b>Connect a mail account</b><span>Gmail and Microsoft 365 are supported through OAuth.</span></div>';
    applyRoleVisibility();return;
  }
  if(!EMAIL_SELECTED_INTEGRATION||!connected.some(x=>x.id===EMAIL_SELECTED_INTEGRATION))EMAIL_SELECTED_INTEGRATION=connected[0].id;
  emailAccountSelect.value=String(EMAIL_SELECTED_INTEGRATION);
  await loadEmailFolders();
  applyRoleVisibility();
 }catch(e){
  emailFolderList.innerHTML='<div class="empty">Email unavailable: '+esc(e.message)+'</div>';
 }
}
async function selectEmailAccount(value){
 EMAIL_SELECTED_INTEGRATION=Number(value)||null;EMAIL_SELECTED_FOLDER=null;EMAIL_SELECTED_MESSAGE=null;
 await loadEmailFolders();
}
async function loadEmailFolders(){
 if(!EMAIL_SELECTED_INTEGRATION)return;
 EMAIL_FOLDERS=await json('/api/v1/email/folders?integration_id='+EMAIL_SELECTED_INTEGRATION);
 const inbox=EMAIL_FOLDERS.find(x=>String(x.name||'').toLowerCase()==='inbox'||String(x.id||'').toLowerCase()==='inbox');
 if(!EMAIL_SELECTED_FOLDER||!EMAIL_FOLDERS.some(x=>String(x.id)===String(EMAIL_SELECTED_FOLDER)))EMAIL_SELECTED_FOLDER=inbox?.id||EMAIL_FOLDERS[0]?.id||'inbox';
 renderEmailFolders();
 await loadEmailMessages();
}
function renderEmailFolders(){
 emailFolderList.innerHTML=EMAIL_FOLDERS.length?EMAIL_FOLDERS.map(f=>`<button class="email-folder-btn ${String(f.id)===String(EMAIL_SELECTED_FOLDER)?'active':''}" onclick="selectEmailFolder('${esc(String(f.id)).replace(/'/g,"&#39;")}')"><span>${esc(f.name||f.id)}</span><span class="email-folder-count">${Number(f.unread||0)}</span></button>`).join(''):'<div class="empty">No mail folders returned.</div>';
}
async function selectEmailFolder(folder){
 EMAIL_SELECTED_FOLDER=folder;EMAIL_SELECTED_MESSAGE=null;renderEmailFolders();await loadEmailMessages();
}
function emailDateLabel(value){
 if(!value)return '';
 const d=new Date(value);
 return Number.isNaN(d.getTime())?value:d.toLocaleString();
}
async function loadEmailMessages(){
 if(!EMAIL_SELECTED_INTEGRATION||!EMAIL_SELECTED_FOLDER)return;
 const q=(document.getElementById('emailSearch')?.value||'').trim();
 emailListMeta.textContent='Loading messages…';
 try{
  const data=await json('/api/v1/email/messages?integration_id='+EMAIL_SELECTED_INTEGRATION+'&folder='+encodeURIComponent(EMAIL_SELECTED_FOLDER)+'&q='+encodeURIComponent(q));
  EMAIL_MESSAGES=data.messages||[];
  const folder=EMAIL_FOLDERS.find(x=>String(x.id)===String(EMAIL_SELECTED_FOLDER));
  emailListMeta.textContent=(folder?.name||'Mailbox')+' · '+EMAIL_MESSAGES.length+' message'+(EMAIL_MESSAGES.length===1?'':'s')+(q?' · search: '+q:'');
  emailMessageList.innerHTML=EMAIL_MESSAGES.length?EMAIL_MESSAGES.map(m=>`<div class="email-message-row ${m.is_read?'':'unread'} ${EMAIL_SELECTED_MESSAGE===m.id?'active':''}" onclick="openEmailMessage('${esc(String(m.id)).replace(/'/g,"&#39;")}')">
   <button class="email-message-star ${m.starred?'starred':''} operate-only" onclick="event.stopPropagation();toggleEmailStar('${esc(String(m.id)).replace(/'/g,"&#39;")}',${m.starred?'false':'true'})" title="${m.starred?'Unstar':'Star'}">${m.starred?'★':'☆'}</button>
   <div><div class="email-message-from"><span>${esc(m.from||'Unknown sender')}</span><span class="email-message-date">${esc(emailDateLabel(m.date))}</span></div><div class="email-message-subject">${esc(m.subject||'(No subject)')}</div><div class="email-message-snippet">${m.has_attachments?'📎 ':''}${esc(m.snippet||'')}</div></div>
  </div>`).join(''):'<div class="empty">No messages in this folder.</div>';
  applyRoleVisibility();
 }catch(e){
  emailListMeta.textContent='Could not load messages';
  emailMessageList.innerHTML='<div class="empty">'+esc(e.message)+'</div>';
 }
}
async function openEmailMessage(id){
 EMAIL_SELECTED_MESSAGE=id;await loadEmailMessages();
 try{
  const m=await json('/api/v1/email/messages/'+encodeURIComponent(id)+'?integration_id='+EMAIL_SELECTED_INTEGRATION);
  const attachments=(m.attachments||[]).map(a=>`<a class="email-attachment-chip" href="/api/v1/email/messages/${encodeURIComponent(id)}/attachments/${encodeURIComponent(a.id)}?integration_id=${EMAIL_SELECTED_INTEGRATION}">📎 ${esc(a.name||'Attachment')} ${a.size?`(${Math.ceil(a.size/1024)} KB)`:''}</a>`).join('');
  emailReaderPane.innerHTML=`<div class="email-reader">
   <div class="email-reader-head"><div class="email-reader-title"><h2>${esc(m.subject||'(No subject)')}</h2><div class="email-reader-meta"><b>From:</b> ${esc(m.from||'')}<br><b>To:</b> ${esc(m.to||'')}${m.cc?'<br><b>CC:</b> '+esc(m.cc):''}<br>${esc(emailDateLabel(m.date))}</div></div>
   <div class="email-reader-actions operate-only"><button class="secondary" onclick="openEmailQuickAction('reply','${esc(String(id)).replace(/'/g,"&#39;")}')">Reply</button><button class="secondary" onclick="openEmailQuickAction('reply-all','${esc(String(id)).replace(/'/g,"&#39;")}')">Reply All</button><button class="secondary" onclick="openEmailQuickAction('forward','${esc(String(id)).replace(/'/g,"&#39;")}')">Forward</button><button class="secondary" onclick="setEmailReadState('${esc(String(id)).replace(/'/g,"&#39;")}',${m.is_read?'false':'true'})">${m.is_read?'Mark Unread':'Mark Read'}</button><button class="secondary" onclick="toggleEmailStar('${esc(String(id)).replace(/'/g,"&#39;")}',${m.starred?'false':'true'})">${m.starred?'Unstar':'Star'}</button><button class="danger" onclick="trashEmailMessage('${esc(String(id)).replace(/'/g,"&#39;")}')">Trash</button></div></div>
   <pre class="email-reader-body">${esc(m.body||m.snippet||'')}</pre>
   ${attachments?'<div class="email-attachments">'+attachments+'</div>':''}
  </div>`;
  applyRoleVisibility();
 }catch(e){emailReaderPane.innerHTML='<div class="email-reader-empty"><b>Could not open message</b><span>'+esc(e.message)+'</span></div>'}
}
async function setEmailReadState(id,isRead){
 try{await json('/api/v1/email/messages/'+encodeURIComponent(id)+'/state',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({integration_id:EMAIL_SELECTED_INTEGRATION,is_read:isRead})});await loadEmailMessages();if(EMAIL_SELECTED_MESSAGE===id)await openEmailMessage(id)}catch(e){alert(e.message)}
}
async function toggleEmailStar(id,starred){
 try{await json('/api/v1/email/messages/'+encodeURIComponent(id)+'/state',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({integration_id:EMAIL_SELECTED_INTEGRATION,starred})});await loadEmailMessages();if(EMAIL_SELECTED_MESSAGE===id)await openEmailMessage(id)}catch(e){alert(e.message)}
}
async function trashEmailMessage(id){
 if(!confirm('Move this message to Trash / Deleted Items?'))return;
 try{await json('/api/v1/email/messages/'+encodeURIComponent(id)+'/trash',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({integration_id:EMAIL_SELECTED_INTEGRATION})});EMAIL_SELECTED_MESSAGE=null;emailReaderPane.innerHTML='<div class="email-reader-empty"><div class="email-reader-empty-icon">✉</div><b>Message moved to Trash</b></div>';await loadEmailFolders()}catch(e){alert(e.message)}
}
function openEmailQuickAction(action,id){
 EMAIL_QUICK_ACTION={action,id};
 emailQuickActionTitle.textContent=action==='reply'?'Reply':action==='reply-all'?'Reply All':'Forward';
 emailQuickActionSubtitle.textContent=action==='forward'?'Enter a recipient and message.':'Write your response.';
 emailQuickActionToWrap.style.display=action==='forward'?'flex':'none';
 emailQuickActionTo.value='';emailQuickActionBody.value='';emailQuickActionErr.textContent='';
 emailQuickActionModal.style.display='grid';document.body.style.overflow='hidden';
 setTimeout(()=>action==='forward'?emailQuickActionTo.focus():emailQuickActionBody.focus(),20);
}
function closeEmailQuickAction(){emailQuickActionModal.style.display='none';document.body.style.overflow=''}
async function sendEmailQuickAction(){
 const {action,id}=EMAIL_QUICK_ACTION;if(!action||!id)return;
 const body={integration_id:EMAIL_SELECTED_INTEGRATION,body:emailQuickActionBody.value,to:action==='forward'?emailSplitAddresses(emailQuickActionTo.value):[]};
 emailQuickActionErr.textContent='';
 try{await json('/api/v1/email/messages/'+encodeURIComponent(id)+'/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});closeEmailQuickAction();await loadEmailMessages()}catch(e){emailQuickActionErr.textContent=e.message}
}
function openEmailCompose(){
 const connected=emailConnectedIntegrations();if(!connected.length){alert('Connect a Gmail or Microsoft 365 account first.');openEmailIntegrationModal();return}
 renderEmailAccountSelects();
 emailComposeAccount.value=String(EMAIL_SELECTED_INTEGRATION||connected[0].id);
 emailComposeTo.value='';emailComposeCc.value='';emailComposeBcc.value='';emailComposeSubject.value='';emailComposeBody.value='';emailComposeFiles.value='';emailComposeErr.textContent='';renderEmailAttachmentList();
 emailComposeModal.style.display='grid';document.body.style.overflow='hidden';setTimeout(()=>emailComposeTo.focus(),20);
}
function closeEmailCompose(){emailComposeModal.style.display='none';document.body.style.overflow=''}
function renderEmailAttachmentList(){
 const files=[...(emailComposeFiles.files||[])];
 emailAttachmentList.textContent=files.length?files.map(f=>`${f.name} (${Math.ceil(f.size/1024)} KB)`).join(' · '):'No attachments selected.';
}
function fileToBase64(file){
 return new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result).split(',')[1]||'');r.onerror=reject;r.readAsDataURL(file)});
}
async function buildEmailComposePayload(){
 const files=[...(emailComposeFiles.files||[])];
 const attachments=[];
 for(const file of files.slice(0,20))attachments.push({name:file.name,content_type:file.type||'application/octet-stream',content_b64:await fileToBase64(file)});
 return {integration_id:Number(emailComposeAccount.value),to:emailSplitAddresses(emailComposeTo.value),cc:emailSplitAddresses(emailComposeCc.value),bcc:emailSplitAddresses(emailComposeBcc.value),subject:emailComposeSubject.value,body:emailComposeBody.value,attachments};
}
async function sendEmailCompose(e){
 e.preventDefault();emailComposeErr.textContent='';
 try{const body=await buildEmailComposePayload();await json('/api/v1/email/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});closeEmailCompose();await loadEmailMessages()}catch(err){emailComposeErr.textContent='Could not send email: '+err.message}
 return false;
}
async function saveEmailDraft(){
 emailComposeErr.textContent='';
 try{const body=await buildEmailComposePayload();await json('/api/v1/email/drafts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});closeEmailCompose();await loadEmailFolders()}catch(err){emailComposeErr.textContent='Could not save draft: '+err.message}
}
function selectEmailProvider(provider){
 emailProvider.value=provider;
 document.querySelectorAll('[data-email-provider]').forEach(x=>x.classList.toggle('active',x.dataset.emailProvider===provider));
}
function openEmailIntegrationModal(){emailIntegrationModal.style.display='grid';document.body.style.overflow='hidden';renderEmailIntegrations()}
function closeEmailIntegrationModal(){emailIntegrationModal.style.display='none';document.body.style.overflow=''}
async function saveEmailIntegration(){
 emailIntegrationErr.textContent='';
 const body={provider:emailProvider.value,name:emailIntegrationName.value.trim(),account_email:emailIntegrationAddress.value.trim(),client_id:emailIntegrationClientId.value.trim(),client_secret:emailIntegrationClientSecret.value};
 try{
  const result=await json('/api/v1/email/integrations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  emailIntegrationClientSecret.value='';emailIntegrationName.value='';
  await loadEmail();
  await connectEmailIntegration(result.id);
 }catch(e){emailIntegrationErr.textContent='Could not save mail account: '+e.message}
}
async function connectEmailIntegration(id){
 try{const result=await json('/api/v1/email/integrations/'+id+'/oauth/start',{method:'POST'});const popup=window.open(result.authorization_url,'godseyeEmailOAuth','width=620,height=760,resizable=yes,scrollbars=yes');if(!popup)throw new Error('Browser blocked the authorization window')}catch(e){alert('Could not start mail authorization: '+e.message)}
}
async function removeEmailIntegration(id){
 if(!confirm('Remove this connected mail account from GODSEYE?'))return;
 try{await json('/api/v1/email/integrations/'+id,{method:'DELETE'});if(EMAIL_SELECTED_INTEGRATION===id){EMAIL_SELECTED_INTEGRATION=null;EMAIL_SELECTED_FOLDER=null}await loadEmail()}catch(e){alert(e.message)}
}
function renderEmailIntegrations(){
 const root=document.getElementById('emailIntegrationList');if(!root)return;
 root.innerHTML=EMAIL_INTEGRATIONS.length?EMAIL_INTEGRATIONS.map(i=>`<div class="calendar-integration-row"><span class="calendar-provider-icon">${i.provider==='gmail'?'G':'M'}</span><div><b>${esc(i.name)}</b><small>${i.provider==='gmail'?'Gmail':'Microsoft 365'} · ${i.connected?'Connected':'Authorization required'} · ${esc(i.account_email||'Mailbox')}</small></div><div class="actions admin-only">${!i.connected?`<button class="primary" onclick="connectEmailIntegration(${i.id})">Connect</button>`:''}<button class="danger" onclick="removeEmailIntegration(${i.id})">Remove</button></div></div>`).join(''):'<div class="empty">No mail accounts configured.</div>';
 applyRoleVisibility();
}
window.addEventListener('message',async event=>{
 if(event.origin!==window.location.origin||event.data?.type!=='godseye-email-connected')return;
 await loadEmail();renderEmailIntegrations();
});
function openEmailReportModal(id,title){
 const connected=emailConnectedIntegrations();
 if(!connected.length){alert('Connect a Gmail or Microsoft 365 account first.');openEmailIntegrationModal();return}
 renderEmailAccountSelects();emailReportId.value=id;emailReportAccount.value=String(EMAIL_SELECTED_INTEGRATION||connected[0].id);emailReportTitleLabel.textContent=title||'Generated report';
 emailReportTo.value='';emailReportSubject.value='GODSEYE Report: '+(title||'Report');emailReportBody.value='Attached is a GODSEYE report.';emailReportErr.textContent='';emailReportModal.style.display='grid';document.body.style.overflow='hidden';
}
function closeEmailReportModal(){emailReportModal.style.display='none';document.body.style.overflow=''}
async function sendEmailReport(){
 emailReportErr.textContent='';
 const body={integration_id:Number(emailReportAccount.value),report_id:Number(emailReportId.value),to:emailSplitAddresses(emailReportTo.value),cc:[],subject:emailReportSubject.value,body:emailReportBody.value,format:emailReportFormat.value};
 if(!body.to.length){emailReportErr.textContent='Enter at least one recipient.';return}
 try{await json('/api/v1/email/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});closeEmailReportModal()}catch(e){emailReportErr.textContent='Could not email report: '+e.message}
}

let WINDOWS_SOURCES=[];
let WINDOWS_AGENTS=[];
let EVENT_FINDINGS=[];
let TICKETS=[];
let TICKET_ASSIGNEES=[];
let CURRENT_EVENT_FINDING=null;
let CURRENT_TICKET=null;

function openWindowsAgentModal(){windowsAgentModal.style.display='grid';document.body.style.overflow='hidden';loadWindowsAgents()}
function closeWindowsAgentModal(){windowsAgentModal.style.display='none';document.body.style.overflow=''}
async function loadWindowsAgents(){
 try{
   WINDOWS_AGENTS=await json('/api/v1/windows-agents');
   renderWindowsAgents();
   const online=WINDOWS_AGENTS.filter(x=>x.status==='online').length,offline=WINDOWS_AGENTS.filter(x=>x.status==='offline').length;
   const summary=document.getElementById('agentSummary');if(summary)summary.textContent=`Agents: ${online} online${offline?' · '+offline+' offline':''} · ${WINDOWS_AGENTS.length} enrolled`;
 }catch(e){WINDOWS_AGENTS=[];renderWindowsAgents();const summary=document.getElementById('agentSummary');if(summary)summary.textContent='Agents unavailable'}
}
function renderWindowsAgents(){
 const root=document.getElementById('windowsAgentList');if(!root)return;
 root.innerHTML=WINDOWS_AGENTS.length?WINDOWS_AGENTS.map(x=>{
   const pull=x.last_pull_status&&x.last_pull_status!=='never'?` · Pull: ${esc(x.last_pull_status)}${x.last_pull_completed_at?' '+esc(new Date(x.last_pull_completed_at).toLocaleTimeString()):''}`:'';
   const pullBtn=x.revoked_at?'':(x.pull_now_supported?`<button class="primary operate-only" onclick="pullWindowsAgentNow(${x.id})">⟳ Pull Events Now</button>`:`<button class="secondary" disabled title="Install the permanent x64 agent (v2.0.0 or newer)">Update Agent for Pull Now</button>`);
   let updateBtn='';
   if(!x.revoked_at&&x.update_available){
     updateBtn=x.upgrade_supported?`<button class="primary admin-only" onclick="upgradeWindowsAgent(${x.id})">↑ Upgrade to ${esc(x.available_version)}</button>`:`<button class="secondary admin-only" onclick="downloadWindowsAgentPackage()" title="Agent 2.0.x needs one manual baseline upgrade; enrollment is preserved.">↓ Manual Update to ${esc(x.available_version)}</button>`;
   }else if(!x.revoked_at&&x.available_version){updateBtn=`<button class="secondary" disabled>✓ Up to date</button>`}
   const updateText=x.available_version?(x.update_available?` · Update available: ${esc(x.available_version)}${x.upgrade_supported?'':' (one manual baseline update required)'}`:` · Latest: ${esc(x.available_version)}`):'';
   return `<div class="windows-agent-row"><span class="windows-agent-icon">W</span><div><b>${esc(x.computer_name||x.hostname||'Windows Agent')}</b><small><span class="agent-status ${esc(x.status||'enrolled')}"><span class="agent-status-dot"></span>${esc(x.status||'enrolled')}</span> · ${esc(x.ip_address||'no IP')} · ${esc(x.os_version||'Windows')} · Agent ${esc(x.agent_version||'—')} · ${x.open_findings||0} open finding(s)${updateText}</small><small>Last heartbeat: ${x.last_heartbeat_at?esc(new Date(x.last_heartbeat_at).toLocaleString()):'never'} · Channels: ${(x.channels||[]).map(esc).join(', ')} · every ${x.poll_interval_seconds||60}s${pull}${x.last_error?' · '+esc(x.last_error):''}</small></div><div class="actions">${updateBtn}${pullBtn}${x.revoked_at?`<button class="danger admin-only" onclick="purgeWindowsAgent(${x.id})">Remove Permanently</button>`:`<button class="secondary admin-only" onclick="configureWindowsAgent(${x.id})">Configure</button><button class="danger admin-only" onclick="revokeWindowsAgent(${x.id})">Revoke</button>`}</div></div>`
 }).join(''):'<div class="empty">No Windows Agents enrolled.</div>';
 applyRoleVisibility();
}
async function checkWindowsAgentUpdates(){
 try{
   const info=await json('/api/v1/windows-agents/update-info');await loadWindowsAgents();
   const updates=WINDOWS_AGENTS.filter(x=>x.update_available),automatic=updates.filter(x=>x.upgrade_supported),manual=updates.filter(x=>!x.upgrade_supported);
   alert(`Latest Windows Agent: ${info.version}. ${updates.length} enrolled agent${updates.length===1?'':'s'} need an update.${automatic.length?' '+automatic.length+' can upgrade directly from GODSEYE.':''}${manual.length?' '+manual.length+' need the one-time 2.1.0 baseline installer first.':''}`);
 }catch(e){alert('Could not check Windows Agent updates: '+e.message)}
}
async function upgradeWindowsAgent(id){
 const x=WINDOWS_AGENTS.find(a=>a.id===id);if(!x)return;
 if(!confirm(`Upgrade ${x.computer_name||'this Windows Agent'} from ${x.agent_version||'unknown'} to ${x.available_version||'the latest version'}? Enrollment, API key, bookmarks, queue, and configuration will be preserved.`))return;
 try{
   const r=await json('/api/v1/windows-agents/'+id+'/upgrade',{method:'POST'});alert(r.message||'Windows Agent upgrade queued.');await loadWindowsAgents();
   setTimeout(loadWindowsAgents,15000);
 }catch(e){alert('Could not upgrade Windows Agent: '+e.message)}
}
async function createWindowsAgentEnrollment(){
 const label=prompt('Enrollment label (for example FILESERVER01):','Windows Agent');if(label===null)return;
 try{
   const r=await json('/api/v1/windows-agents/enrollment-tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:label.trim()||'Windows Agent',expires_minutes:30})});
   windowsAgentEnrollment.style.display='grid';windowsAgentEnrollmentToken.textContent=r.enrollment_token;windowsAgentEnrollmentExpiry.textContent='Expires '+new Date(r.expires_at).toLocaleString();
   windowsAgentInstallCommand.textContent=`1. Click Download x64 Installer above.\n2. Run GODSEYE-Windows-Agent-x64-Setup.exe as Administrator.\n3. GODSEYE URL: ${location.origin}\n4. Paste the one-time token shown above.\n\nExisting enrolled agents can run newer Setup versions without a new token.`;
 }catch(e){alert('Could not create enrollment token: '+e.message)}
}
function copyAgentEnrollmentToken(){const value=windowsAgentEnrollmentToken.textContent||'';if(!value)return;navigator.clipboard?.writeText(value).then(()=>alert('Enrollment token copied.')).catch(()=>prompt('Copy this enrollment token:',value))}
function downloadWindowsAgentPackage(){window.location.href='/api/v1/windows-agents/package'}
async function pullWindowsAgentNow(id){
 const x=WINDOWS_AGENTS.find(a=>a.id===id);if(!x)return;
 try{
   const r=await json('/api/v1/windows-agents/'+id+'/pull-now',{method:'POST'});
   alert(r.message||`Pull Events Now queued for ${x.computer_name||'Windows Agent'}.`);
   await loadWindowsAgents();
   setTimeout(async()=>{await loadWindowsAgents();await loadEventFindings()},12000);
 }catch(e){alert('Could not request agent event pull: '+e.message)}
}
async function pullAllWindowsAgentsNow(){
 await loadWindowsAgents();
 const targets=WINDOWS_AGENTS.filter(x=>!x.revoked_at&&x.enabled&&x.pull_now_supported&&x.status!=='offline');
 if(!targets.length){alert('No compatible online Windows Agents are available. Install or upgrade to the permanent x64 agent if needed.');return}
 let queued=0,failed=0;
 for(const x of targets){try{await json('/api/v1/windows-agents/'+x.id+'/pull-now',{method:'POST'});queued++}catch(e){failed++}}
 alert(`Pull Events Now queued for ${queued} Windows Agent${queued===1?'':'s'}${failed?`; ${failed} failed`:''}. Agents check for commands every 10 seconds.`);
 await loadWindowsAgents();setTimeout(async()=>{await loadWindowsAgents();await loadEventFindings()},12000);
}
async function configureWindowsAgent(id){
 const x=WINDOWS_AGENTS.find(a=>a.id===id);if(!x)return;
 const channels=prompt('Event Log channels, comma separated:',(x.channels||['System','Application']).join(', '));if(channels===null)return;
 const interval=prompt('Collection interval in seconds (30-3600):',String(x.poll_interval_seconds||60));if(interval===null)return;
 try{await json('/api/v1/windows-agents/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({channels:channels.split(',').map(v=>v.trim()).filter(Boolean),poll_interval_seconds:Number(interval||60),enabled:true})});await loadWindowsAgents()}catch(e){alert('Could not update Windows Agent: '+e.message)}
}
async function revokeWindowsAgent(id){
 const x=WINDOWS_AGENTS.find(a=>a.id===id);if(!confirm(`Revoke ${x?.computer_name||'this Windows Agent'}? The installed agent will no longer be able to upload events.`))return;
 try{await json('/api/v1/windows-agents/'+id,{method:'DELETE'});await loadWindowsAgents()}catch(e){alert('Could not revoke Windows Agent: '+e.message)}
}

async function purgeWindowsAgent(id){
 const x=WINDOWS_AGENTS.find(a=>a.id===id);if(!x)return;
 if(!x.revoked_at&&x.status!=='revoked'){alert('Revoke this Windows Agent before removing it permanently.');return}
 if(!confirm(`Permanently remove ${x.computer_name||x.hostname||'this computer'} from GODSEYE?\n\nThis removes the revoked agent record, its Event Findings, remote-session history, queued commands, and rechecks. Linked tickets remain as history. This cannot be undone.`))return;
 try{const r=await json('/api/v1/windows-agents/'+id+'/purge',{method:'DELETE'});alert(`Removed ${r.computer_name||'computer'} from GODSEYE. ${r.findings_deleted||0} Event Finding(s) removed.`);await loadWindowsAgents();await loadEventFindings();if(typeof loadRemoteAccess==='function')await loadRemoteAccess()}catch(e){alert('Could not permanently remove Windows Agent: '+e.message)}
}

async function loadWindowsSources(){
 try{WINDOWS_SOURCES=await json('/api/v1/windows-event-sources');renderWindowsSources()}catch(e){WINDOWS_SOURCES=[];renderWindowsSources()}
}
async function loadEventFindings(){
 const status=document.getElementById('eventFindingStatusFilter')?.value||'';
 const severity=document.getElementById('eventFindingSeverityFilter')?.value||'';
 const q=document.getElementById('eventFindingSearch')?.value.trim()||'';
 try{
   const [rows,allOpen,resolved]=await Promise.all([
     json('/api/v1/event-findings?'+new URLSearchParams({status,severity,q}).toString()),
     json('/api/v1/event-findings?status=open'),
     json('/api/v1/event-findings?status=resolved')
   ]);
   EVENT_FINDINGS=rows||[];
   eventFindingOpen.textContent=allOpen.length;
   eventFindingResolved.textContent=resolved.length;
   eventFindingCritical.textContent=allOpen.filter(x=>x.severity==='critical').length;
   eventFindingHardware.textContent=allOpen.filter(x=>['Storage','Hardware'].includes(x.category)).length;
   const badge=document.getElementById('eventFindingBadge');if(badge)badge.textContent=allOpen.length;
   eventFindingRows.innerHTML=EVENT_FINDINGS.length?EVENT_FINDINGS.map(x=>`<tr>
     <td class="admin-only"><input class="event-finding-check" type="checkbox" value="${x.id}" onchange="updateEventFindingDeleteSelection()" aria-label="Select finding ${x.id}"></td>
     <td><span class="status-badge severity-${esc(x.severity||'info')}">${esc(x.severity||'Info')}</span></td>
     <td><div class="name">${esc(x.computer_name)}</div><div class="muted">${esc(x.channel)}</div></td>
     <td><div class="name">${esc(x.title)}</div><div class="muted">${esc(x.category)} · ${esc(x.recommendation||'')}</div></td>
     <td><b>${esc(x.provider)}</b><div class="muted">Event ${x.event_id} · ${esc(x.level)}</div></td>
     <td>${x.occurrence_count}</td>
     <td>${x.last_seen?esc(new Date(x.last_seen).toLocaleString()):'—'}</td>
     <td><span class="status-badge">${esc(x.status)}</span></td>
     <td><button class="link" onclick="openEventFinding(${x.id})">Open</button>${x.status==='open'?` <button class="link operate-only" onclick="recheckEventFinding(${x.id})">Recheck</button> <button class="link operate-only" onclick="createTicketFromEventFinding(${x.id})">Create Ticket</button>`:''} <button class="link delete-link admin-only" onclick="deleteEventFinding(${x.id})">Delete</button></td>
   </tr>`).join(''):'<tr><td colspan="9" class="empty">No Event Findings match this filter.</td></tr>';
   const vc=document.getElementById('eventFindingVisibleCount');if(vc)vc.textContent=`(${EVENT_FINDINGS.length})`;
   const ft=document.getElementById('eventFindingFooterText');if(ft)ft.textContent=`Showing ${EVENT_FINDINGS.length} finding${EVENT_FINDINGS.length===1?'':'s'}`;
   document.querySelectorAll('#view-event-findings thead input[type=checkbox],#eventFindingSelectAll').forEach(x=>x.checked=false);
   updateEventFindingDeleteSelection();
   applyRoleVisibility();
   await Promise.all([loadWindowsAgents(),loadWindowsSources()]);
 }catch(e){eventFindingRows.innerHTML='<tr><td colspan="9" class="empty">Event Findings unavailable: '+esc(e.message)+'</td></tr>'}
}
function selectedEventFindingIds(){return [...document.querySelectorAll('.event-finding-check:checked')].map(x=>Number(x.value)).filter(Boolean)}
function updateEventFindingDeleteSelection(){const ids=selectedEventFindingIds();const btn=document.getElementById('eventFindingDeleteSelected');const count=document.getElementById('eventFindingSelectedCount');if(btn)btn.disabled=!ids.length;if(count)count.textContent=`${ids.length} selected`}
function toggleAllEventFindings(checked){document.querySelectorAll('.event-finding-check').forEach(x=>x.checked=!!checked);document.querySelectorAll('#view-event-findings thead input[type=checkbox],#eventFindingSelectAll').forEach(x=>x.checked=!!checked);updateEventFindingDeleteSelection()}
async function deleteEventFinding(id){const x=EVENT_FINDINGS.find(v=>v.id===id);if(!confirm(`Delete this Windows Event Finding?\n\n${x?.title||'Finding #'+id}\n\nLinked tickets will be preserved as historical tickets. This cannot be undone.`))return;try{await json('/api/v1/event-findings/'+id,{method:'DELETE'});if(CURRENT_EVENT_FINDING?.id===id)closeEventFindingModal();await loadEventFindings()}catch(e){alert('Could not delete Event Finding: '+e.message)}}
async function deleteSelectedEventFindings(){const ids=selectedEventFindingIds();if(!ids.length)return;if(!confirm(`Delete ${ids.length} selected Windows Event Finding${ids.length===1?'':'s'}?\n\nLinked tickets will be preserved. This cannot be undone.`))return;try{const r=await json('/api/v1/event-findings/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({finding_ids:ids})});alert(`Deleted ${r.deleted} Event Finding${r.deleted===1?'':'s'}.`);await loadEventFindings()}catch(e){alert('Could not delete selected Event Findings: '+e.message)}}
async function deleteOldEventFindings(){const days=Number(document.getElementById('eventFindingOldDays')?.value||30);if(!confirm(`Delete resolved Windows Event Findings older than ${days} days?\n\nOpen findings will not be deleted. Linked tickets will be preserved.`))return;try{const r=await json('/api/v1/event-findings/delete-old',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({older_than_days:days})});alert(`Deleted ${r.deleted} old resolved Event Finding${r.deleted===1?'':'s'}.`);await loadEventFindings()}catch(e){alert('Could not delete old Event Findings: '+e.message)}}
async function openEventFinding(id){
 try{
   CURRENT_EVENT_FINDING=await json('/api/v1/event-findings/'+id);
   const x=CURRENT_EVENT_FINDING;
   eventFindingModalTitle.textContent=x.title;
   eventFindingModalSubtitle.textContent=`${x.computer_name} · ${x.provider} · Event ${x.event_id}`;
   const actions=(x.suggested_actions||[]).map((a,i)=>`<div class="event-fix-item"><span class="event-fix-num">${i+1}</span><span>${esc(a)}</span></div>`).join('');
   const linked=(x.tickets||[]).map(t=>`<button class="secondary" onclick="closeEventFindingModal();showView('tickets',true);setTimeout(()=>openTicketEditor(${t.id}),50)">${esc(t.ticket_number)} · ${esc(t.status)}</button>`).join(' ');
   eventFindingModalBody.innerHTML=`<div class="event-detail-grid">
      <div class="event-detail-cell"><div class="k">Severity</div><div class="v">${esc(x.severity)}</div></div>
      <div class="event-detail-cell"><div class="k">Category</div><div class="v">${esc(x.category)}</div></div>
      <div class="event-detail-cell"><div class="k">Occurrences</div><div class="v">${x.occurrence_count}</div></div>
      <div class="event-detail-cell"><div class="k">Computer</div><div class="v">${esc(x.computer_name)}</div></div>
      <div class="event-detail-cell"><div class="k">Channel</div><div class="v">${esc(x.channel)}</div></div>
      <div class="event-detail-cell"><div class="k">Last Seen</div><div class="v">${x.last_seen?esc(new Date(x.last_seen).toLocaleString()):'—'}</div></div>
      <div class="event-detail-cell"><div class="k">Collection</div><div class="v">${x.agent_id?'Windows Agent':(x.source_id?'WinRM':'Imported')}</div></div>
    </div>
    <div><h3>Windows Event Message</h3><div class="event-message-box">${esc(x.message||'No event message returned.')}</div></div>
    <div><h3>Suggested Fix</h3><p class="muted">${esc(x.recommendation||'')}</p><div class="event-fix-list">${actions}</div></div>
    ${linked?'<div><h3>Linked Tickets</h3><div class="actions">'+linked+'</div></div>':''}
    <div class="modal-actions"><button class="secondary operate-only" onclick="recheckEventFinding(${x.id})">Recheck</button><button class="primary operate-only" onclick="createTicketFromEventFinding(${x.id})">Create Ticket</button>${x.status==='open'?`<button class="danger operate-only" onclick="resolveEventFinding(${x.id})">Resolve</button>`:''}<button class="danger admin-only" onclick="deleteEventFinding(${x.id})">Delete</button><button class="secondary" onclick="closeEventFindingModal()">Close</button></div>`;
   eventFindingModal.style.display='grid';document.body.style.overflow='hidden';applyRoleVisibility();
 }catch(e){alert('Could not open Event Finding: '+e.message)}
}
function closeEventFindingModal(){eventFindingModal.style.display='none';document.body.style.overflow=''}
async function recheckEventFinding(id){
 try{const r=await json('/api/v1/event-findings/'+id+'/recheck',{method:'POST'});alert(r.message||'Recheck completed.');await loadEventFindings();if(document.getElementById('eventFindingModal').style.display==='grid')await openEventFinding(id)}catch(e){alert('Could not recheck Event Finding: '+e.message)}
}
async function resolveEventFinding(id){
 if(!confirm('Mark this Event Finding resolved?'))return;
 try{await json('/api/v1/event-findings/'+id+'/resolve',{method:'POST'});closeEventFindingModal();await loadEventFindings()}catch(e){alert('Could not resolve Event Finding: '+e.message)}
}
async function createTicketFromEventFinding(id){
 try{
   const ticket=await json('/api/v1/event-findings/'+id+'/create-ticket',{method:'POST'});
   closeEventFindingModal();showView('tickets',true);await loadTickets();openTicketEditor(ticket.id);
 }catch(e){alert('Could not create ticket: '+e.message)}
}
function openWindowsSourceModal(){windowsSourceModal.style.display='grid';document.body.style.overflow='hidden';resetWindowsSourceForm();loadWindowsSources()}
function closeWindowsSourceModal(){windowsSourceModal.style.display='none';document.body.style.overflow=''}
function resetWindowsSourceForm(){
 windowsSourceId.value='';windowsSourceName.value='';windowsSourceHost.value='';windowsSourcePort.value='5986';windowsSourceTransport.value='ntlm';windowsSourceUsername.value='';windowsSourcePassword.value='';windowsSourceInterval.value='5';windowsSourceVerifyTls.checked=true;windowsSourceChannels.value='System, Application';windowsSourceErr.textContent='';
}
function editWindowsSource(id){
 const x=WINDOWS_SOURCES.find(s=>s.id===id);if(!x)return;
 windowsSourceId.value=x.id;windowsSourceName.value=x.name;windowsSourceHost.value=x.hostname;windowsSourcePort.value=x.port;windowsSourceTransport.value=x.transport;windowsSourceUsername.value=x.username||'';windowsSourcePassword.value='';windowsSourceInterval.value=String(x.poll_interval_minutes||5);windowsSourceVerifyTls.checked=!!x.verify_tls;windowsSourceChannels.value=(x.channels||[]).join(', ');windowsSourceErr.textContent='';
}
async function saveWindowsSource(){
 const id=windowsSourceId.value;
 const body={name:windowsSourceName.value.trim(),hostname:windowsSourceHost.value.trim(),port:Number(windowsSourcePort.value||5986),transport:windowsSourceTransport.value,username:windowsSourceUsername.value.trim(),password:windowsSourcePassword.value,verify_tls:windowsSourceVerifyTls.checked,enabled:true,poll_interval_minutes:Number(windowsSourceInterval.value||5),channels:windowsSourceChannels.value.split(',').map(x=>x.trim()).filter(Boolean)};
 windowsSourceErr.textContent='';
 try{await json(id?'/api/v1/windows-event-sources/'+id:'/api/v1/windows-event-sources',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});resetWindowsSourceForm();await loadWindowsSources()}catch(e){windowsSourceErr.textContent=e.message}
}
async function pollWindowsSource(id){
 try{const r=await json('/api/v1/windows-event-sources/'+id+'/poll',{method:'POST'});alert(`Pulled ${r.events} matching Windows event(s); ${r.new_findings} new Event Finding(s).`);await loadWindowsSources();await loadEventFindings()}catch(e){alert('Windows Event pull failed: '+e.message)}
}
async function pollAllWindowsSources(){
 await loadWindowsSources();
 if(!WINDOWS_SOURCES.length){alert('Configure at least one Windows Event source first.');openWindowsSourceModal();return}
 let ok=0,failed=0,total=0;
 for(const x of WINDOWS_SOURCES.filter(x=>x.enabled)){try{const r=await json('/api/v1/windows-event-sources/'+x.id+'/poll',{method:'POST'});ok++;total+=r.events||0}catch(e){failed++}}
 alert(`Windows Event pull complete: ${ok} host(s) succeeded, ${failed} failed, ${total} event(s) processed.`);await loadEventFindings();
}
async function removeWindowsSource(id){
 if(!confirm('Remove this Windows Event source? Existing Event Findings will be kept.'))return;
 try{await json('/api/v1/windows-event-sources/'+id,{method:'DELETE'});await loadWindowsSources()}catch(e){alert(e.message)}
}
function renderWindowsSources(){
 const root=document.getElementById('windowsSourceList');if(!root)return;
 root.innerHTML=WINDOWS_SOURCES.length?WINDOWS_SOURCES.map(x=>`<div class="windows-source-row"><span class="windows-source-icon">W</span><div><b>${esc(x.name)}</b><small>${esc(x.hostname)}:${x.port} · ${esc(x.transport.toUpperCase())} · every ${x.poll_interval_minutes} min · ${esc(x.last_status||'never')}${x.last_poll_at?' · '+new Date(x.last_poll_at).toLocaleString():''}${x.last_error?' · '+esc(x.last_error):''}</small></div><div class="actions"><button class="secondary" onclick="pollWindowsSource(${x.id})">Pull Now</button><button class="secondary admin-only" onclick="editWindowsSource(${x.id})">Edit</button><button class="danger admin-only" onclick="removeWindowsSource(${x.id})">Remove</button></div></div>`).join(''):'<div class="empty">No Windows Event sources configured.</div>';
 applyRoleVisibility();
}

function selectedTicketIds(){return [...document.querySelectorAll('.ticket-row-check:checked')].map(x=>Number(x.value)).filter(Boolean)}
function updateTicketDeleteSelection(){
 const ids=selectedTicketIds(),btn=document.getElementById('ticketDeleteSelected'),count=document.getElementById('ticketSelectedCount');
 if(btn){btn.disabled=!ids.length;btn.textContent=ids.length?`🗑 Delete Selected (${ids.length})`:'🗑 Delete Selected'}
 if(count)count.textContent=`${ids.length} selected`;
 const boxes=[...document.querySelectorAll('.ticket-row-check')];
 const all=boxes.length>0&&boxes.every(x=>x.checked);
 ['ticketSelectAll','ticketHeaderSelectAll'].forEach(id=>{const el=document.getElementById(id);if(el){el.checked=all;el.indeterminate=ids.length>0&&!all}});
}
function toggleAllTickets(checked){document.querySelectorAll('.ticket-row-check').forEach(x=>x.checked=checked);updateTicketDeleteSelection()}
async function loadTicketAssignees(selected=''){
 try{
  TICKET_ASSIGNEES=await json('/api/v1/ticket-assignees');
 }catch(e){TICKET_ASSIGNEES=[]}
 const el=document.getElementById('ticketAssignee');if(!el)return;
 const current=selected||el.value||'';
 const options=['<option value="">Unassigned</option>',...TICKET_ASSIGNEES.map(u=>{
   const label=(u.display_name||'').trim()?`${u.display_name} (${u.username})`:u.username;
   return `<option value="${esc(u.username)}">${esc(label)} · ${esc(u.role)}</option>`;
 })];
 if(current && !TICKET_ASSIGNEES.some(u=>u.username===current)){
   options.push(`<option value="${esc(current)}">${esc(current)} · legacy assignment</option>`);
 }
 el.innerHTML=options.join('');el.value=current;
}
function ticketAssigneeLabel(username){
 if(!username)return 'Unassigned';
 const u=TICKET_ASSIGNEES.find(x=>x.username===username);
 return u&&u.display_name?`${u.display_name} (${u.username})`:username;
}
async function loadTickets(){
 try{
  await loadTicketAssignees('');
  const all=await json('/api/v1/tickets');
  TICKETS=all||[];
  const selected=document.getElementById('ticketStatusFilter')?.value||'';
  const rows=selected?TICKETS.filter(x=>x.status===selected):TICKETS;
  ticketOpen.textContent=TICKETS.filter(x=>['open','assigned','waiting'].includes(x.status)).length;
  ticketInProgress.textContent=TICKETS.filter(x=>x.status==='in_progress').length;
  ticketScheduled.textContent=TICKETS.filter(x=>x.calendar_event_id&& !['closed'].includes(x.status)).length;
  ticketClosed.textContent=TICKETS.filter(x=>x.status==='closed').length;
  const badge=document.getElementById('ticketBadge');if(badge)badge.textContent=TICKETS.filter(x=>!['resolved','closed'].includes(x.status)).length;
  const visible=document.getElementById('ticketVisibleCount');if(visible)visible.textContent=`(${rows.length})`;
  ticketRows.innerHTML=rows.length?rows.map(t=>`<tr><td class="admin-only"><input class="ticket-row-check ticket-check" type="checkbox" value="${t.id}" onchange="updateTicketDeleteSelection()" aria-label="Select ${esc(t.ticket_number||'ticket')}"></td><td><span class="ticket-number">${esc(t.ticket_number||'TKT')}</span></td><td><span class="status-badge severity-${t.priority==='critical'?'critical':t.priority==='high'?'high':'medium'}">${esc(t.priority)}</span></td><td><div class="name">${esc(t.title)}</div><div class="muted">${esc((t.description||'').slice(0,120))}</div></td><td>${esc(t.device_name||'—')}</td><td>${esc(ticketAssigneeLabel(t.assignee))}</td><td><span class="status-badge status-ticket-${esc(t.status)}">${esc(t.status.replace('_',' '))}</span></td><td>${t.calendar_event_id?`<span class="ticket-due">▦ ${t.due_at?esc(new Date(t.due_at).toLocaleString()):'Scheduled'}</span>`:(t.due_at?esc(new Date(t.due_at).toLocaleString()):'—')}</td><td>${esc(new Date(t.updated_at).toLocaleString())}</td><td><button class="link" onclick="openTicketEditor(${t.id})">Open</button> <button class="link ticket-delete-link admin-only" onclick="deleteTicket(${t.id})">Delete</button></td></tr>`).join(''):'<tr><td colspan="10" class="empty">No tickets match this filter.</td></tr>';
  applyRoleVisibility();updateTicketDeleteSelection();
 }catch(e){ticketRows.innerHTML='<tr><td colspan="10" class="empty">Ticket Portal unavailable: '+esc(e.message)+'</td></tr>'}
}
async function deleteTicket(id){
 const t=TICKETS.find(x=>x.id===id)||CURRENT_TICKET;
 if(!confirm(`Delete this ticket?\n\n${t?.ticket_number||'Ticket #'+id} · ${t?.title||''}\n\nWork notes and its linked GODSEYE calendar appointment will also be deleted. The original finding, if any, will be preserved. This cannot be undone.`))return;
 try{await json('/api/v1/tickets/'+id,{method:'DELETE'});if(CURRENT_TICKET?.id===id)closeTicketEditor();await loadTickets();await loadCalendar()}catch(e){alert('Could not delete ticket: '+e.message)}
}
async function deleteSelectedTickets(){
 const ids=selectedTicketIds();if(!ids.length)return;
 if(!confirm(`Delete ${ids.length} selected ticket${ids.length===1?'':'s'}?\n\nTheir work notes and linked GODSEYE calendar appointments will also be deleted. Linked findings will be preserved. This cannot be undone.`))return;
 try{const r=await json('/api/v1/tickets/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket_ids:ids})});alert(`Deleted ${r.deleted} ticket${r.deleted===1?'':'s'}.`);await loadTickets();await loadCalendar()}catch(e){alert('Could not delete selected tickets: '+e.message)}
}
async function deleteOldTickets(){
 const days=Number(document.getElementById('ticketOldDays')?.value||90);
 if(!confirm(`Delete closed and resolved tickets older than ${days} days?\n\nOpen, assigned, in-progress, and waiting tickets will NOT be deleted. Work notes and linked GODSEYE calendar appointments for deleted tickets will also be removed.`))return;
 try{const r=await json('/api/v1/tickets/delete-old',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({older_than_days:days})});alert(`Deleted ${r.deleted} old completed ticket${r.deleted===1?'':'s'}.`);await loadTickets();await loadCalendar()}catch(e){alert('Could not delete old tickets: '+e.message)}
}
function defaultTicketSchedule(){
 const start=new Date();start.setSeconds(0,0);start.setMinutes(Math.ceil(start.getMinutes()/30)*30);
 const end=new Date(start.getTime()+60*60*1000);
 ticketScheduleStart.value=calendarIsoLocal(start);ticketScheduleEnd.value=calendarIsoLocal(end);
}
async function openTicketEditor(id=null){
 ticketEditorErr.textContent='';CURRENT_TICKET=null;ticketEditorId.value=id||'';
 await loadTicketAssignees('');
 if(!id){
   ticketEditorTitle.textContent='New Ticket';ticketEditorSubtitle.textContent='Create and track operational work.';ticketTitle.value='';ticketDescription.value='';ticketPriority.value='medium';ticketStatus.value='open';ticketAssignee.value='';ticketDevice.value='';ticketLinkedInfo.style.display='none';ticketScheduleSection.style.display='none';ticketNotesSection.style.display='none';ticketCloseBtn.classList.add('ticket-hidden');ticketDeleteBtn.classList.add('ticket-hidden');defaultTicketSchedule();
 }else{
   try{
    const t=await json('/api/v1/tickets/'+id);CURRENT_TICKET=t;ticketEditorTitle.textContent=t.ticket_number+' · '+t.title;ticketEditorSubtitle.textContent='Created '+new Date(t.created_at).toLocaleString()+' · Last updated '+new Date(t.updated_at).toLocaleString();ticketTitle.value=t.title;ticketDescription.value=t.description||'';ticketPriority.value=t.priority;ticketStatus.value=t.status;ticketAssignee.value=t.assignee||'';ticketDevice.value=t.device_name||'';ticketScheduleSection.style.display='block';ticketNotesSection.style.display='block';ticketCloseBtn.classList.toggle('ticket-hidden',t.status==='closed');ticketDeleteBtn.classList.remove('ticket-hidden');
    if(t.linked_finding){ticketLinkedInfo.style.display='block';ticketLinkedInfo.innerHTML=`Linked Event Finding: <b>${esc(t.linked_finding.title)}</b> · ${esc(t.linked_finding.computer_name)} · Event ${t.linked_finding.event_id} · ${esc(t.linked_finding.status)}`}
    else if(t.linked_network_finding){ticketLinkedInfo.style.display='block';ticketLinkedInfo.innerHTML=`Linked Network Finding: <b>${esc(t.linked_network_finding.title)}</b> · ${esc(t.linked_network_finding.target||'')} · ${esc(t.linked_network_finding.status)}`}
    else ticketLinkedInfo.style.display='none';
    ticketNotesList.innerHTML=(t.notes||[]).length?(t.notes||[]).map(n=>`<div class="ticket-note"><b>${esc(n.author)}</b><small>${esc(new Date(n.created_at).toLocaleString())}</small><p>${esc(n.note)}</p></div>`).join(''):'<div class="empty">No work notes yet.</div>';
    if(t.due_at){const end=new Date(t.due_at);ticketScheduleEnd.value=calendarIsoLocal(end);const start=new Date(end.getTime()-60*60*1000);ticketScheduleStart.value=calendarIsoLocal(start)}else defaultTicketSchedule();
   }catch(e){alert('Could not load ticket: '+e.message);return}
 }
 ticketEditorModal.style.display='grid';document.body.style.overflow='hidden';applyRoleVisibility();
}
function closeTicketEditor(){ticketEditorModal.style.display='none';document.body.style.overflow='';CURRENT_TICKET=null;ticketDeleteBtn.classList.add('ticket-hidden')}
async function deleteCurrentTicket(){const id=Number(ticketEditorId.value);if(id)await deleteTicket(id)}
async function saveTicket(){
 const id=ticketEditorId.value;
 ticketEditorErr.textContent='';
 try{
  if(id){
    const body={title:ticketTitle.value.trim(),description:ticketDescription.value.trim(),status:ticketStatus.value,priority:ticketPriority.value,assignee:ticketAssignee.value.trim(),due_at:CURRENT_TICKET?.due_at||null};
    await json('/api/v1/tickets/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});await loadTickets();await openTicketEditor(Number(id));
  }else{
    const body={title:ticketTitle.value.trim(),description:ticketDescription.value.trim(),priority:ticketPriority.value,assignee:ticketAssignee.value.trim(),device_name:ticketDevice.value.trim()};
    const t=await json('/api/v1/tickets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});await loadTickets();await openTicketEditor(t.id);
  }
 }catch(e){ticketEditorErr.textContent=e.message}
}
async function scheduleCurrentTicket(){
 const id=Number(ticketEditorId.value);if(!id)return;
 try{await json('/api/v1/tickets/'+id+'/schedule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({start_at:new Date(ticketScheduleStart.value).toISOString(),end_at:new Date(ticketScheduleEnd.value).toISOString(),all_day:false})});await loadTickets();await loadCalendar();await openTicketEditor(id);alert('Ticket scheduled on Calendar.')}catch(e){ticketEditorErr.textContent='Could not schedule ticket: '+e.message}
}
async function addTicketNote(){
 const id=Number(ticketEditorId.value),note=ticketNoteText.value.trim();if(!id||!note)return;
 try{await json('/api/v1/tickets/'+id+'/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note})});ticketNoteText.value='';await openTicketEditor(id)}catch(e){ticketEditorErr.textContent=e.message}
}
async function closeCurrentTicket(){
 const id=Number(ticketEditorId.value);if(!id)return;
 const note=prompt('Closing note (optional):')||'';
 const resolveLinked=!!(CURRENT_TICKET?.linked_finding||CURRENT_TICKET?.linked_network_finding)&&confirm('Also resolve the linked finding?');
 try{await json('/api/v1/tickets/'+id+'/close',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note,resolve_linked_finding:resolveLinked})});closeTicketEditor();await loadTickets();await loadEventFindings();await loadCalendar()}catch(e){ticketEditorErr.textContent=e.message}
}
const VIEW_LOADERS={
  overview:()=>loadDashboard(),
  devices:()=>loadInventory(),
  network:()=>loadNetwork(),
  monitoring:()=>loadMonitoring(),
  findings:()=>loadFindings(),
  integrations:()=>loadIntegrations(),
  reports:()=>loadReports(),
  calendar:()=>loadCalendar(),
  email:()=>loadEmail(),
  'event-findings':()=>loadEventFindings(),
  tickets:()=>loadTickets(),
  health:()=>loadHealth(),
  users:()=>loadUsers(),
  audit:()=>loadAudit(),
  rules:()=>loadRules(),
  security:()=>loadSecurity(),
  activity:()=>loadEvents()
};
let DASHBOARD_DRILLDOWN=false;
let NETWORK_ZOOM=1;
function setDashboardReturnVisible(show){document.querySelectorAll('[data-dashboard-return]').forEach(b=>b.style.display=show?'inline-flex':'none')}
function openDashboardSummary(kind){
  DASHBOARD_DRILLDOWN=true;setDashboardReturnVisible(true);
  const status=document.getElementById('inventoryStatus'),subtitle=document.getElementById('deviceInventorySubtitle');
  if(kind==='online'){if(status)status.value='online';if(subtitle)subtitle.textContent='Devices currently online on your network';showView('devices',true);return}
  if(kind==='devices'){if(status)status.value='';if(subtitle)subtitle.textContent='All discovered devices on your network';showView('devices',true);return}
  if(kind==='issues'){showView('findings',true);return}
  if(kind==='monitors'){showView('monitoring',true);return}
}
function backToDashboard(){
  DASHBOARD_DRILLDOWN=false;setDashboardReturnVisible(false);
  const status=document.getElementById('inventoryStatus'),subtitle=document.getElementById('deviceInventorySubtitle');if(status)status.value='';if(subtitle)subtitle.textContent='All discovered devices on your network';
  showView('overview',true);
}
window.openDashboardSummary=openDashboardSummary;window.backToDashboard=backToDashboard;
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
    e.preventDefault();e.stopPropagation();DASHBOARD_DRILLDOWN=false;setDashboardReturnVisible(false);showView(btn.dataset.view,true);
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
function csrfToken(){return getCookie('godseye_csrf')||''}
async function loadUsers(){
  const panel=document.getElementById('usersPanel'),tbody=document.getElementById('users');
  if(!ME||ME.role!=='admin'){if(panel)panel.style.display='none';return}
  if(panel)panel.style.display='block';
  try{
    const rows=await json('/api/v1/users');
    if(tbody)tbody.innerHTML=rows.length?rows.map(x=>{
      const deadline=x.must_change_password?(x.must_change_password_by?`Yes, by ${esc(new Date(x.must_change_password_by).toLocaleDateString())}`:'Yes'):'No';
      return `<tr><td>${esc(x.display_name||'—')}</td><td>${esc(x.username)}</td><td><span class="pill">${esc(x.role)}</span></td><td>${x.created_at?esc(new Date(x.created_at).toLocaleDateString()):'—'}</td><td>${x.last_login_at?esc(new Date(x.last_login_at).toLocaleString()):'Never'}</td><td>${x.password_changed_at?esc(new Date(x.password_changed_at).toLocaleDateString()):'—'}</td><td>${deadline}</td><td>${x.mfa_enabled?'Yes':'No'}</td><td>${x.username===ME.username?'':`<button class="link" onclick="removeUser(${x.id},'${esc(x.username)}')">Remove</button>${x.mfa_enabled?` <button class="link" onclick="resetUserMfa(${x.id},'${esc(x.username)}')">Reset MFA</button>`:''}`}</td></tr>`;
    }).join(''):'<tr><td colspan="9" class="empty">No users found.</td></tr>';
  }catch(e){if(tbody)tbody.innerHTML='<tr><td colspan="9" class="empty">Unable to load users.</td></tr>'}
}
async function loadAudit(){
  const panel=document.getElementById('auditPanel'),tbody=document.getElementById('auditRows');
  if(!ME||!['admin','auditor'].includes(ME.role)){if(panel)panel.style.display='none';return}
  if(panel)panel.style.display='block';
  try{
    const rows=await json('/api/v1/audit?limit=50');
    if(tbody)tbody.innerHTML=rows.length?rows.map(x=>{const protectedNow=x.protected_until&&new Date(x.protected_until)>new Date();return `<tr class="${protectedNow?'protected-audit':''}"><td>${x.created_at?esc(new Date(x.created_at).toLocaleString()):'—'}</td><td>${esc(x.actor)}</td><td><span class="pill">${esc(x.action)}</span>${protectedNow?' <span class="pill warning">Protected 7 days</span>':''}</td><td>${esc(x.target||'—')}</td><td>${esc(x.details||'')}</td><td>${esc(x.ip||'—')}</td></tr>`}).join(''):'<tr><td colspan="6" class="empty">No audit entries yet.</td></tr>';
  }catch(e){if(tbody)tbody.innerHTML='<tr><td colspan="6" class="empty">Unable to load audit log.</td></tr>'}
}
async function loadSecurity(){
  const el=document.getElementById('mfaStatus');if(!el||!ME)return;
  if(ME.mfa_enabled){
    el.innerHTML=`<div class="muted">Two-factor authentication is <b style="color:#0a8c57">enabled</b> on this account.</div><button class="link" style="margin-top:10px" onclick="startMfaDisable()">Disable MFA</button>`;
  }else{
    el.innerHTML=`<div class="muted">Two-factor authentication is <b style="color:#b87500">not enabled</b>. Add it for a second layer of protection.</div><button class="primary" style="margin-top:10px" onclick="startMfaSetup()">Set up MFA</button>`;
  }
}
function updateRuleFields(){
  const type=document.getElementById('ruleType')?.value;
  const groups={ruleFieldsBurst:type==='new_device_burst',ruleFieldsOffline:type==='offline_duration',ruleFieldsEventBurst:['ip_change_burst','reconnect_burst'].includes(type),ruleFieldsOfflineCount:type==='offline_count',ruleFieldsScanner:type==='scanner_stale',ruleFieldsClassification:type==='classification_count'};
  Object.entries(groups).forEach(([id,show])=>{const el=document.getElementById(id);if(el)el.style.display=show?'flex':'none'});
}
function ruleCondition(type,p){
  if(type==='new_device_burst')return `${p.count||0}+ new devices in ${p.window_minutes||0}m`;
  if(type==='offline_duration')return `Offline ${p.minutes||0}m+ (${((p.classifications&&p.classifications.length)?p.classifications:['any']).join(', ')})`;
  if(type==='ip_change_burst')return `${p.count||0}+ IP changes in ${p.window_minutes||0}m`;
  if(type==='reconnect_burst')return `${p.count||0}+ reconnects in ${p.window_minutes||0}m`;
  if(type==='offline_count')return `${p.count||0}+ devices offline (cooldown ${p.cooldown_minutes||15}m)`;
  if(type==='scanner_stale')return `No successful scan for ${p.minutes||0}m`;
  if(type==='classification_count')return `${p.count||0}+ devices classified ${((p.classifications||[]).join(', ')||'selected')} (cooldown ${p.cooldown_minutes||15}m)`;
  return JSON.stringify(p||{});
}
async function loadRules(){
  const panel=document.getElementById('rulesPanel'),tbody=document.getElementById('rules');
  if(!ME||ME.role!=='admin'){if(panel)panel.style.display='none';return}
  if(panel)panel.style.display='block';
  try{
    const rows=await json('/api/v1/rules');
    if(tbody)tbody.innerHTML=rows.length?rows.map(x=>{
      let params={};try{params=JSON.parse(x.params||'{}')}catch(_){}
      const condition=ruleCondition(x.rule_type,params);
      return `<tr><td>${esc(x.name)}</td><td>${esc(x.rule_type)}</td><td>${esc(condition)}</td><td><span class="pill">${esc(x.severity)}</span></td><td>${x.last_triggered_at?esc(new Date(x.last_triggered_at).toLocaleString()):'Never'}</td><td><input type="checkbox" ${x.enabled?'checked':''} onchange="toggleRule(${x.id},this.checked)"></td><td><button class="link" onclick="removeRule(${x.id},'${esc(x.name)}')">Remove</button></td></tr>`;
    }).join(''):'<tr><td colspan="7" class="empty">No rules configured yet.</td></tr>';
  }catch(e){if(tbody)tbody.innerHTML='<tr><td colspan="7" class="empty">Unable to load alert rules.</td></tr>'}
}
async function createRule(e){
  e.preventDefault();
  const type=document.getElementById('ruleType').value;
  const name=document.getElementById('ruleName').value.trim();
  const severity=document.getElementById('ruleSeverity').value;
  let params;
  if(type==='new_device_burst'){
    params={count:+document.getElementById('ruleBurstCount').value,window_minutes:+document.getElementById('ruleBurstWindow').value};
  }else if(type==='offline_duration'){
    params={minutes:+document.getElementById('ruleOfflineMinutes').value};
    const raw=document.getElementById('ruleOfflineClasses').value.trim();
    if(raw)params.classifications=raw.split(',').map(v=>v.trim()).filter(Boolean);
  }else if(['ip_change_burst','reconnect_burst'].includes(type)){
    params={count:+document.getElementById('ruleEventCount').value,window_minutes:+document.getElementById('ruleEventWindow').value};
  }else if(type==='offline_count'){
    params={count:+document.getElementById('ruleOfflineCount').value,cooldown_minutes:+document.getElementById('ruleOfflineCountCooldown').value};
  }else if(type==='scanner_stale'){
    params={minutes:+document.getElementById('ruleScannerMinutes').value};
  }else if(type==='classification_count'){
    params={count:+document.getElementById('ruleClassCount').value,classifications:document.getElementById('ruleClasses').value.split(',').map(v=>v.trim()).filter(Boolean),cooldown_minutes:+document.getElementById('ruleClassCooldown').value};
  }
  try{
    await json('/api/v1/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,rule_type:type,params,severity})});
    document.getElementById('ruleName').value='';await loadRules();
  }catch(err){alert('Could not create rule: '+err.message)}
  return false;
}
async function toggleRule(id,enabled){try{await json('/api/v1/rules/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});await loadRules()}catch(e){alert(e.message)}}
async function removeRule(id,name){if(!confirm('Remove rule "'+name+'"?'))return;try{await json('/api/v1/rules/'+id,{method:'DELETE'});await loadRules()}catch(e){alert(e.message)}}
async function startMfaSetup(){
  try{
    const data=await json('/api/v1/auth/mfa/setup',{method:'POST'}),el=document.getElementById('mfaStatus');
    el.innerHTML=`<div class="muted">Enter this setup key in your TOTP authenticator:</div><div style="font-family:monospace;font-size:15px;background:#f6f9fc;border:1px solid #dce6f1;border-radius:6px;padding:10px;margin:10px 0;word-break:break-all">${esc(data.secret)}</div><div class="muted" style="font-size:10px;word-break:break-all">${esc(data.otpauth_uri)}</div><form onsubmit="return confirmMfaSetup(event)" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap"><input class="input" id="mfaConfirmCode" placeholder="Enter 6-digit code" required style="flex:1;min-width:180px"><button class="primary" type="submit">Confirm</button></form><div class="err" id="mfaSetupErr"></div>`;
  }catch(e){alert('Could not start MFA setup: '+e.message)}
}
async function confirmMfaSetup(e){
  e.preventDefault();const err=document.getElementById('mfaSetupErr');if(err)err.textContent='';
  try{
    const code=document.getElementById('mfaConfirmCode').value.trim();
    const data=await json('/api/v1/auth/mfa/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
    const el=document.getElementById('mfaStatus');
    el.innerHTML=`<div class="muted" style="color:#0a8c57">MFA enabled. Save these backup codes somewhere safe:</div><div style="font-family:monospace;background:#f6f9fc;border:1px solid #dce6f1;border-radius:6px;padding:10px;margin:10px 0">${(data.backup_codes||[]).map(esc).join('<br>')}</div><button class="primary" onclick="boot()">Done</button>`;
    ME=await json('/api/v1/auth/me');
  }catch(ex){if(err)err.textContent='Incorrect code — try again'}
  return false;
}
function startMfaDisable(){
  const el=document.getElementById('mfaStatus');
  el.innerHTML=`<form onsubmit="return confirmMfaDisable(event)" style="display:flex;flex-direction:column;gap:8px;max-width:320px"><input class="input" id="mfaDisablePw" type="password" placeholder="Current password" required><input class="input" id="mfaDisableCode" placeholder="6-digit code or backup code" required><button class="danger" type="submit">Disable MFA</button><div class="err" id="mfaDisableErr"></div></form>`;
}
async function confirmMfaDisable(e){
  e.preventDefault();const err=document.getElementById('mfaDisableErr');if(err)err.textContent='';
  try{
    await json('/api/v1/auth/mfa/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:document.getElementById('mfaDisablePw').value,code:document.getElementById('mfaDisableCode').value.trim()})});
    ME=await json('/api/v1/auth/me');await loadSecurity();
  }catch(ex){if(err)err.textContent='Could not disable MFA — check password and code'}
  return false;
}
async function resetUserMfa(id,username){if(!confirm('Reset MFA for "'+username+'"?'))return;try{await json('/api/v1/users/'+id+'/mfa/reset',{method:'POST'});await loadUsers()}catch(e){alert(e.message)}}
async function createUser(e){
  e.preventDefault();
  try{
    await json('/api/v1/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      display_name:document.getElementById('newUserDisplayName').value.trim(),
      username:document.getElementById('newUsername').value.trim(),
      password:document.getElementById('newUserPassword').value,
      role:document.getElementById('newUserRole').value
    })});
    document.getElementById('newUserDisplayName').value='';document.getElementById('newUsername').value='';document.getElementById('newUserPassword').value='';await loadUsers();
  }catch(err){alert('Could not create user: '+err.message)}
  return false;
}
async function removeUser(id,username){if(!confirm('Remove user "'+username+'"?'))return;try{await json('/api/v1/users/'+id,{method:'DELETE'});await loadUsers()}catch(e){alert(e.message)}}
async function loadDevices(){
  const tbody=document.getElementById('devices');if(!tbody)return;
  try{const q=new URLSearchParams(),se=document.getElementById('search'),st=document.getElementById('status'),cl=document.getElementById('classification');if(se?.value)q.set('search',se.value);if(st?.value)q.set('status',st.value);if(cl?.value)q.set('classification',cl.value);const response=await json('/api/v1/devices?'+q.toString()),d=Array.isArray(response)?response:[],rows=d.slice(0,12);tbody.innerHTML=rows.length?rows.map(x=>`<tr onclick="goDevice(${x.id})" style="cursor:pointer"><td class="${esc(x.status)}"><span class="dot">●</span> ${esc((x.status||'unknown').replace('_',' '))}</td><td><div class="device-name">${deviceIconHtml(x)}<div><button class="device-link" onclick="event.stopPropagation();goDevice(${x.id})">${esc(x.name||x.hostname||'Unknown device')}</button><div class="muted">${esc(x.device_type||'Unclassified')}</div></div></div></td><td>${esc(x.ip||'—')}</td><td>${esc(x.mac||'—')}</td><td>${esc(x.vendor||'—')}</td><td>${esc(x.device_type||'—')}</td><td>${x.last_seen?esc(new Date(x.last_seen).toLocaleString()):'—'}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">No devices discovered yet. Click Scan Now to discover the network.</td></tr>';applyRoleVisibility()}catch(e){tbody.innerHTML='<tr><td colspan="7" class="empty">Unable to load devices: '+esc(e.message)+'</td></tr>'}
}
async function cycleClass(id,current){await json('/api/v1/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({classification:CLASS_CYCLE[current]||'new'})});load()}
function setScanStatus(message,state=''){
  const el=document.getElementById('scanStatus');
  if(el){el.textContent=message||'';el.className='scan-status'+(state?' '+state:'')}
  const dash=document.getElementById('dashRefreshState');if(dash&&message)dash.textContent=message;
}
function formatEventTime(value){try{return new Date(value).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'})}catch(_){return '—'}}
async function loadEvents(){
  const table=document.getElementById('events'),list=document.getElementById('activityList');
  try{
    const rows=await json('/api/v1/events?limit=30');
    if(table)table.innerHTML=rows.length?rows.map(x=>`<tr><td>${x.created_at?esc(new Date(x.created_at).toLocaleString()):'—'}</td><td><span class="pill">${esc(x.event_type||'event')}</span></td><td>${esc(x.mac||'—')}</td><td>${esc(x.ip||'—')}</td><td>${esc(x.details||'')}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No activity yet.</td></tr>';
    if(list)list.innerHTML=rows.slice(0,6).map((x,i)=>`<div class="activity-row"><span class="activity-dot ${i%3===0?'green':''}"></span><div><div class="activity-title">${esc((x.event_type||'Network activity').replaceAll('_',' '))}</div><div class="activity-sub">${esc(x.ip||x.mac||'Network')} ${x.details?'· '+esc(x.details):''}</div></div><span class="activity-time">${formatEventTime(x.created_at)}</span></div>`).join('')||'<div class="empty">No recent activity.</div>';
    return rows;
  }catch(e){
    if(table)table.innerHTML='<tr><td colspan="5" class="empty">Unable to load activity.</td></tr>';
    if(list)list.innerHTML='<div class="empty">Unable to load recent activity.</div>';
    return [];
  }
}
async function loadDashboard(){
  const refresh=document.getElementById('dashRefreshState');if(refresh)refresh.textContent='Refreshing…';
  const tasks=await Promise.allSettled([
    json('/api/v1/health'),
    loadDevices(),
    loadTraffic(),
    loadEvents(),
    json('/api/v1/monitoring/settings').catch(()=>[]),
    json('/api/v1/monitoring/checks').catch(()=>[])
  ]);
  const healthResult=tasks[0];
  if(healthResult.status==='fulfilled'){
    const h=healthResult.value;
    const totalEl=document.getElementById('total'),onlineEl=document.getElementById('online'),issueEl=document.getElementById('unknown');
    if(totalEl)totalEl.textContent=h.total??0;
    if(onlineEl)onlineEl.textContent=h.online??0;
    if(issueEl)issueEl.textContent=h.needs_review??h.unknown??0;
    const tr=document.getElementById('onlineTrend');if(tr)tr.textContent=h.total?Math.round((h.online/h.total)*100)+'%':'0%';
    const scanner=document.getElementById('dashScannerState');
    if(scanner){scanner.textContent=h.scanner?.healthy?'Scanner healthy':(h.scanner?.detail||'Scanner waiting');scanner.classList.toggle('warn',!h.scanner?.healthy)}
    const hb=document.getElementById('healthbar');
    if(hb){if(h.scanner?.healthy){hb.style.display='none'}else{hb.style.display='block';hb.className='healthbar bad';hb.textContent='⚠ Scanner: '+(h.scanner?.detail||'not reporting')}}
  }else{
    const scanner=document.getElementById('dashScannerState');if(scanner){scanner.textContent='Dashboard API unavailable';scanner.classList.add('warn')}
  }
  const settings=tasks[4].status==='fulfilled'?(tasks[4].value||[]):[];
  const checks=tasks[5].status==='fulfilled'?(tasks[5].value||[]):[];
  const mc=document.getElementById('monitorCount'),mt=document.getElementById('monitorTrend');
  if(mc)mc.textContent=settings.length;
  if(mt){
    const latest={};for(const c of checks){if(c.monitor_id&&!latest[c.monitor_id])latest[c.monitor_id]=c}
    const healthy=settings.filter(m=>!m.enabled || !latest[m.id] || latest[m.id].status==='up').length;
    mt.textContent=settings.length?healthy+' healthy':'No monitors';
  }
  if(refresh)refresh.textContent='Last refreshed '+new Date().toLocaleTimeString();
}
async function load(){return loadDashboard()}
async function scan(){
  const btn=document.getElementById('scanBtn');
  if(btn){btn.disabled=true;btn.textContent='⟳ Scanning…'}
  setScanStatus('Queuing scan…','busy');
  try{
    const r=await json('/api/v1/scan',{method:'POST'});
    setScanStatus('Scan queued — waiting for scanner…','busy');
    let attempts=0;
    const poll=async()=>{
      attempts++;
      try{
        const st=await json('/api/v1/scan/status');const req=st.request;
        if(req && req.id===r.request_id && req.status==='completed'){
          setScanStatus('Scan complete — '+(req.devices_found??0)+' devices found','ok');
          if(btn){btn.disabled=false;btn.textContent='⟳ Scan Now'}
          await Promise.allSettled([loadDashboard(),loadInventory()]);
          return;
        }
        if(req && req.id===r.request_id && req.status==='failed'){
          setScanStatus('Scan failed: '+(req.error||'unknown scanner error'),'bad');
          if(btn){btn.disabled=false;btn.textContent='⟳ Scan Now'}
          return;
        }
      }catch(e){console.warn('scan status poll failed',e)}
      if(attempts<45){setTimeout(poll,1000)}
      else{
        setScanStatus('Scan is still queued — check System Health if this persists.','bad');
        if(btn){btn.disabled=false;btn.textContent='⟳ Scan Now'}
      }
    };
    poll();
  }catch(e){
    setScanStatus('Unable to queue scan: '+e.message,'bad');
    if(btn){btn.disabled=false;btn.textContent='⟳ Scan Now'}
  }
}

function goDevice(id){if(!id)return;window.location.assign('/device/'+encodeURIComponent(id))}
function openClearData(kind){if(!ME||ME.role!=='admin')return;const modal=document.getElementById('clearDataModal');if(!modal)return;clearDataKind.value=kind;clearDataReason.value='';clearDataErr.textContent='';if(kind==='audit'){clearDataTitle.textContent='Clear Audit Log';clearDataHelp.textContent='A reason is mandatory. GODSEYE will create a new audit event naming you as the user who cleared the log.';clearDataWarning.textContent='The new audit_log_cleared event is protected and cannot be removed for 7 days.';clearDataConfirm.textContent='Clear Audit Log'}else{clearDataTitle.textContent='Clear Client & Query Analytics';clearDataHelp.textContent='A reason is mandatory and will be written to the audit log with your username.';clearDataWarning.textContent='This removes retained integration analytics snapshots. Device inventory and discovery records are not deleted.';clearDataConfirm.textContent='Clear Analytics'}modal.style.display='grid';setTimeout(()=>clearDataReason.focus(),20)}
function closeClearData(){const modal=document.getElementById('clearDataModal');if(modal)modal.style.display='none'}
async function submitClearData(e){e.preventDefault();const kind=clearDataKind.value,reason=clearDataReason.value.trim();clearDataErr.textContent='';if(reason.length<5){clearDataErr.textContent='Please enter a reason of at least 5 characters.';return false}const path=kind==='audit'?'/api/v1/audit/clear':'/api/v1/analytics/clear';try{const result=await json(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})});closeClearData();if(kind==='audit')await loadAudit();else await loadIntegrations();alert((kind==='audit'?'Audit log':'Analytics')+' cleared by '+result.cleared_by+'. '+result.deleted+' record(s) removed.')}catch(err){clearDataErr.textContent='Could not clear data: '+err.message}return false}
function sortValue(text){const v=(text||'').trim();const ip=v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);if(ip)return {kind:'num',value:ip.slice(1).reduce((n,x)=>n*256+Number(x),0)};const n=Number(v.replace(/,/g,''));if(v!==''&&Number.isFinite(n))return {kind:'num',value:n};const t=Date.parse(v);if(/[-/:]|am|pm/i.test(v)&&Number.isFinite(t))return {kind:'num',value:t};return {kind:'text',value:v.toLowerCase()}}
function sortTableByHeader(th){const table=th.closest('table'),tbody=table&&table.tBodies&&table.tBodies[0];if(!tbody)return;const idx=Array.from(th.parentElement.children).indexOf(th);const rows=Array.from(tbody.rows).filter(r=>!r.querySelector('.empty'));if(rows.length<2)return;const asc=!th.classList.contains('sort-asc');th.parentElement.querySelectorAll('th').forEach(h=>h.classList.remove('sort-asc','sort-desc'));th.classList.add(asc?'sort-asc':'sort-desc');rows.sort((a,b)=>{const av=sortValue(a.cells[idx]?.innerText||''),bv=sortValue(b.cells[idx]?.innerText||'');let cmp;if(av.kind==='num'&&bv.kind==='num')cmp=av.value-bv.value;else cmp=String(av.value).localeCompare(String(bv.value),undefined,{numeric:true,sensitivity:'base'});return asc?cmp:-cmp});rows.forEach(r=>tbody.appendChild(r))}
function enableSortableTables(){if(!window.__godseyeSortableBound){document.addEventListener('click',e=>{const th=e.target.closest('th.sortable-head');if(th)sortTableByHeader(th)});window.__godseyeSortableBound=true}document.querySelectorAll('table thead th').forEach(th=>{const label=(th.textContent||'').trim().toLowerCase();if(!['action','actions',''].includes(label)){th.classList.add('sortable-head');th.title='Click to sort'}})}
function openRenameDevice(id,currentName,identity){const m=document.getElementById('renameDeviceModal');if(!m)return;renameDeviceId.value=id;renameDeviceName.value=currentName||'';renameDeviceIdentity.textContent=identity||'';renameDeviceErr.textContent='';m.style.display='grid';setTimeout(()=>{renameDeviceName.focus();renameDeviceName.select()},20)}
function openRenameDeviceFromButton(btn){openRenameDevice(Number(btn.dataset.renameId),btn.dataset.renameName||'',btn.dataset.renameIdentity||'')}
function closeRenameDevice(){const m=document.getElementById('renameDeviceModal');if(m)m.style.display='none'}
async function submitRenameDevice(e){e.preventDefault();const id=Number(renameDeviceId.value),name=renameDeviceName.value.trim();renameDeviceErr.textContent='';if(!id||!name){renameDeviceErr.textContent='Enter a device name.';return false}try{await json('/api/v1/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});closeRenameDevice();await Promise.allSettled([loadInventory(),loadDevices(),loadDashboard()])}catch(err){renameDeviceErr.textContent='Could not save device name: '+err.message}return false}
function openClassifyDevice(id,type,classification,identity){classifyDeviceId.value=id;classifyDeviceType.value=type||'';classifyDeviceClass.value=classification||'new';classifyDeviceIdentity.textContent=identity||'';classifyDeviceErr.textContent='';classifyDeviceModal.style.display='grid';setTimeout(()=>classifyDeviceType.focus(),20)}
function openClassifyDeviceFromButton(btn){openClassifyDevice(Number(btn.dataset.classifyId),btn.dataset.classifyType||'',btn.dataset.classifyClass||'new',btn.dataset.classifyIdentity||'')}
function closeClassifyDevice(){classifyDeviceModal.style.display='none'}
async function submitClassifyDevice(e){e.preventDefault();const id=Number(classifyDeviceId.value),device_type=classifyDeviceType.value.trim(),classification=classifyDeviceClass.value;classifyDeviceErr.textContent='';if(!id){classifyDeviceErr.textContent='Device is missing.';return false}try{await json('/api/v1/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_type,classification})});closeClassifyDevice();await Promise.allSettled([loadInventory(),loadDevices(),loadDashboard()])}catch(err){classifyDeviceErr.textContent='Could not save classification: '+err.message}return false}
function renderDeviceIconPicker(selected){const p=document.getElementById('deviceIconPicker');if(!p)return;const keys=DEVICE_ICON_KEYS.filter(k=>ACTIVE_DEVICE_ICON_CATEGORY==='all'||DEVICE_ICON_CATEGORIES[k]===ACTIVE_DEVICE_ICON_CATEGORY);p.innerHTML=keys.map(k=>`<button type="button" class="device-icon-choice ${k===selected?'selected':''}" data-icon-key="${k}" onclick="selectDeviceIcon('${k}')"><img src="${deviceIconAsset(k==='auto'?'other':k)}" alt="${esc(DEVICE_ICON_LABELS[k])} icon" onerror="this.src='${deviceIconAsset('other')}'"><span>${esc(DEVICE_ICON_LABELS[k])}</span></button>`).join('')}
function setDeviceIconCategory(category){ACTIVE_DEVICE_ICON_CATEGORY=category;document.querySelectorAll('#deviceIconTabs .device-icon-tab').forEach(b=>b.classList.toggle('active',b.dataset.iconCategory===category));renderDeviceIconPicker(deviceIconKey.value)}
function updateDeviceIconSummary(){const key=deviceIconKey.value||'auto';const img=document.getElementById('deviceIconCurrentPreview');if(!img)return;img.src=deviceIconData.value||deviceIconAsset(key==='auto'?'other':key)}
function selectDeviceIcon(key){deviceIconKey.value=key;deviceIconData.value='';deviceIconPreview.style.display='none';deviceIconFile.value='';renderDeviceIconPicker(key);updateDeviceIconSummary()}
function openDeviceIconFromButton(btn){deviceIconId.value=btn.dataset.iconId;deviceIconKey.value=btn.dataset.iconKey||'auto';deviceIconData.value='';deviceIconName.textContent=btn.dataset.iconName||'Device';deviceIconIdentity.textContent=[btn.dataset.iconIp,btn.dataset.iconType].filter(Boolean).join(' · ');deviceIconErr.textContent='';deviceIconFile.value='';deviceIconPreview.style.display='none';const selected=deviceIconKey.value;ACTIVE_DEVICE_ICON_CATEGORY='all';document.querySelectorAll('#deviceIconTabs .device-icon-tab').forEach(b=>b.classList.toggle('active',b.dataset.iconCategory===ACTIVE_DEVICE_ICON_CATEGORY));renderDeviceIconPicker(selected);updateDeviceIconSummary();deviceIconModal.style.display='grid';document.body.style.overflow='hidden'}
function closeDeviceIcon(){deviceIconModal.style.display='none';document.body.style.overflow=''}
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&deviceIconModal&&deviceIconModal.style.display!=='none')closeDeviceIcon()})
function previewCustomDeviceIcon(input){const f=input.files&&input.files[0];deviceIconErr.textContent='';if(!f)return;if(!['image/png','image/jpeg','image/webp'].includes(f.type)){deviceIconErr.textContent='Choose a PNG, JPEG, or WebP image.';input.value='';return}if(f.size>262144){deviceIconErr.textContent='Custom icon must be 256 KB or smaller.';input.value='';return}const r=new FileReader();r.onload=()=>{deviceIconData.value=String(r.result||'');deviceIconKey.value='other';deviceIconPreview.src=deviceIconData.value;deviceIconPreview.style.display='block';updateDeviceIconSummary();renderDeviceIconPicker('__custom__')};r.onerror=()=>{deviceIconErr.textContent='Could not read the image.'};r.readAsDataURL(f)}
async function submitDeviceIcon(e){e.preventDefault();const id=Number(deviceIconId.value),icon_key=deviceIconKey.value||'auto',icon_data=deviceIconData.value||null;deviceIconErr.textContent='';if(!id){deviceIconErr.textContent='Device is missing.';return false}try{await json('/api/v1/devices/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({icon_key,icon_data})});closeDeviceIcon();await Promise.allSettled([loadInventory(),loadDevices(),loadDashboard()])}catch(err){deviceIconErr.textContent='Could not save device icon: '+err.message}return false}
function openAddDevice(){const m=document.getElementById('deviceModal');m.style.display='grid';document.body.style.overflow='hidden';setTimeout(()=>document.getElementById('deviceName')?.focus(),0)}
function closeAddDevice(){document.getElementById('deviceModal').style.display='none';document.body.style.overflow=''}
async function submitAddDevice(e){e.preventDefault();const err=document.getElementById('deviceAddErr');err.textContent='';try{await json('/api/v1/devices',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:deviceName.value.trim(),ip:deviceIp.value.trim()||null,mac:deviceMac.value.trim(),vendor:deviceVendor.value.trim()||null,device_type:deviceType.value.trim()||'unknown',classification:deviceClass.value,notes:deviceNotes.value.trim()})});closeAddDevice();e.target.reset();deviceClass.value='known';await load();if(document.getElementById('view-devices').style.display!=='none')await loadInventory()}catch(e){err.textContent='Could not add device: '+e.message}return false}

document.addEventListener('keydown',e=>{if(e.key!=='Escape')return;if(document.getElementById('deviceCleanupModal')?.style.display==='grid')closeDeviceCleanup();if(document.getElementById('deviceDeleteModal')?.style.display==='grid')closeDeleteDevice()});
function openDeviceCleanup(){const m=document.getElementById('deviceCleanupModal');if(!m)return;document.getElementById('deviceCleanupReason').value='';document.getElementById('deviceCleanupErr').textContent='';m.style.display='grid';document.body.style.overflow='hidden';updateDeviceCleanupFields();setTimeout(()=>document.getElementById('deviceCleanupMode')?.focus(),0)}
function closeDeviceCleanup(){const m=document.getElementById('deviceCleanupModal');if(m)m.style.display='none';document.body.style.overflow=''}
function updateDeviceCleanupFields(){const old=document.getElementById('deviceCleanupMode')?.value==='old';const row=document.getElementById('deviceCleanupDaysLabel');if(row)row.style.display=old?'grid':'none'}
async function submitDeviceCleanup(e){e.preventDefault();const mode=document.getElementById('deviceCleanupMode').value,older_than_days=+document.getElementById('deviceCleanupDays').value,reason=document.getElementById('deviceCleanupReason').value.trim(),err=document.getElementById('deviceCleanupErr');if(err)err.textContent='';if(reason.length<3){err.textContent='Enter a reason for this cleanup.';document.getElementById('deviceCleanupReason').focus();return false}try{const r=await json('/api/v1/devices/cleanup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode,older_than_days,reason})});closeDeviceCleanup();await Promise.allSettled([loadInventory(),loadDashboard(),loadNetwork(),loadAudit()]);alert(`Deleted ${r.deleted||0} device(s). The action was recorded in the Audit Log.`)}catch(ex){if(err)err.textContent='Cleanup failed: '+ex.message}return false}
function deleteInventoryDevice(id,name,status){const m=document.getElementById('deviceDeleteModal');if(!m)return;document.getElementById('deviceDeleteId').value=String(id);document.getElementById('deviceDeleteIdentity').textContent=`${name||'Device'} · ${status||'unknown'} status`;document.getElementById('deviceDeleteReason').value='';document.getElementById('deviceDeleteErr').textContent='';m.style.display='grid';document.body.style.overflow='hidden';setTimeout(()=>document.getElementById('deviceDeleteReason')?.focus(),0)}
function openDeleteDeviceFromButton(btn){if(!btn)return;deleteInventoryDevice(Number(btn.dataset.deleteId),btn.dataset.deleteName||'Device',btn.dataset.deleteStatus||'unknown')}
function closeDeleteDevice(){const m=document.getElementById('deviceDeleteModal');if(m)m.style.display='none';document.body.style.overflow=''}
async function submitDeleteDevice(e){e.preventDefault();const id=Number(document.getElementById('deviceDeleteId').value),reason=document.getElementById('deviceDeleteReason').value.trim(),err=document.getElementById('deviceDeleteErr');err.textContent='';if(!id){err.textContent='Device is missing.';return false}if(reason.length<3){err.textContent='Enter a reason for deleting this device.';document.getElementById('deviceDeleteReason').focus();return false}try{await json('/api/v1/devices/'+id,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})});closeDeleteDevice();await Promise.allSettled([loadInventory(),loadDashboard(),loadNetwork(),loadAudit()]);alert('Device deleted. The reason and administrator were recorded in the Audit Log.')}catch(ex){err.textContent='Could not delete device: '+ex.message}return false}

async function loadInventory(){
  const se=document.getElementById('inventorySearch'),st=document.getElementById('inventoryStatus'),ce=document.getElementById('inventoryCount'),tbody=document.getElementById('inventoryRows');if(!tbody)return;
  try{const q=new URLSearchParams();if(se?.value)q.set('search',se.value);if(st?.value)q.set('status',st.value);const response=await json('/api/v1/devices?'+q.toString()),d=Array.isArray(response)?response:[];if(ce)ce.textContent=d.length+' devices';tbody.innerHTML=d.length?d.map(x=>`<tr onclick="goDevice(${x.id})" style="cursor:pointer"><td><div class="device-name">${deviceIconHtml(x)}<div><button class="link name" onclick="event.stopPropagation();goDevice(${x.id})">${esc(x.name||x.hostname||'Unknown device')}</button><div class="muted">${esc(x.device_type||'Unclassified')}</div></div></div></td><td>${esc(x.ip||'—')}</td><td>${esc(x.mac||'—')}</td><td>${esc(x.vendor||'—')}</td><td>${esc(x.device_type||'—')}</td><td><span class="status-badge">${esc(CLASS_LABEL[x.classification]||x.classification||'new')}</span></td><td>${x.last_seen?esc(new Date(x.last_seen).toLocaleString()):'—'}</td><td><span class="status-badge">${esc(x.status||'unknown')}</span></td><td><button class="secondary" data-rename-id="${x.id}" data-rename-name="${esc(x.name||'')}" data-rename-identity="${esc([x.hostname,x.ip,x.mac].filter(Boolean).join(' · '))}" onclick="event.stopPropagation();openRenameDeviceFromButton(this)">${x.name?'Rename':'Name'}</button> <button class="secondary" data-classify-id="${x.id}" data-classify-type="${esc(x.device_type||'')}" data-classify-class="${esc(x.classification||'new')}" data-classify-identity="${esc([x.name||x.hostname,x.ip,x.mac].filter(Boolean).join(' · '))}" onclick="event.stopPropagation();openClassifyDeviceFromButton(this)">Classify</button> <button class="secondary" data-icon-id="${x.id}" data-icon-key="${esc(x.icon_key||'auto')}" data-icon-name="${esc(x.name||x.hostname||'Unknown device')}" data-icon-ip="${esc(x.ip||x.mac||'')}" data-icon-type="${esc(x.device_type||'Unclassified')}" onclick="event.stopPropagation();openDeviceIconFromButton(this)">Icon</button> <button class="secondary" onclick="event.stopPropagation();goDevice(${x.id})">Details</button> <button class="danger admin-only" data-delete-id="${x.id}" data-delete-name="${esc(x.name||x.hostname||x.mac||'Device')}" data-delete-status="${esc(x.status||'unknown')}" onclick="event.stopPropagation();openDeleteDeviceFromButton(this)">Delete</button></td></tr>`).join(''):'<tr><td colspan="9" class="empty">No devices discovered yet. Click Scan Now to discover the network.</td></tr>';applyRoleVisibility()}catch(e){tbody.innerHTML='<tr><td colspan="9" class="empty">Unable to load devices: '+esc(e.message)+'</td></tr>'}
}


let NETWORK_DATA={nodes:[],links:[],byId:{}};let NETWORK_LAYOUT='auto';let NETWORK_FILTER='all';let SELECTED_MAP_INDEX=-1;
function mapNodeClass(n){const status=String(n.status||'').toLowerCase();if(status.includes('offline'))return'offline';if(status.includes('online'))return'online';return'unknown'}
function mapDeviceIconKey(n){if(n&&n.icon_key&&n.icon_key!=='auto')return n.icon_key;const t=String(n&&n.type||'').toLowerCase();if(t==='internet')return'internet';return inferredDeviceIcon(t)}
function mapDeviceIconSrc(n){if(n&&n.icon_data)return n.icon_data;const key=mapDeviceIconKey(n);return key==='internet'?'':deviceIconAsset(key)}
function isInfrastructureNode(n){const t=String(n?.type||'').toLowerCase();return /gateway|router|switch|access|wifi|firewall|modem|nas|storage|server|patch/.test(t)}
function isWirelessLink(l){const x=(String(l?.link_type||'')+' '+String(l?.details?.source||'')).toLowerCase();return /wifi|wireless|wlan/.test(x)}
function computeNetworkPositions(nodes,links,layout){const W=1100,H=720,pos={};const byId=NETWORK_DATA.byId;const internet=nodes.find(n=>n.id==='internet'),gateway=nodes.find(n=>n.id===(NETWORK_DATA.gateway||'gateway'))||nodes.find(n=>String(n.type).toLowerCase()==='gateway');if(layout==='circular'){const center=gateway||internet||nodes[0];if(center)pos[center.id]={x:550,y:350};const ring=nodes.filter(n=>!center||n.id!==center.id);ring.forEach((n,i)=>{const a=(Math.PI*2*i/Math.max(1,ring.length))-Math.PI/2;pos[n.id]={x:550+390*Math.cos(a),y:350+270*Math.sin(a)}});if(internet&&center&&internet.id!==center.id)pos[internet.id]={x:550,y:70};return pos}
  const children={};links.forEach(l=>(children[l.parent]||(children[l.parent]=[])).push(l.child));const root=internet?.id||gateway?.id||nodes[0]?.id;const depth={},q=root?[root]:[];if(root)depth[root]=0;while(q.length){const id=q.shift();for(const ch of children[id]||[]){if(depth[ch]===undefined){depth[ch]=depth[id]+1;q.push(ch)}}}nodes.forEach(n=>{if(depth[n.id]===undefined)depth[n.id]=gateway&&n.id!==gateway.id?2:1});if(layout==='auto'&&internet&&gateway){pos[internet.id]={x:550,y:65};pos[gateway.id]={x:550,y:245};const remaining=nodes.filter(n=>n.id!==internet.id&&n.id!==gateway.id);const infra=remaining.filter(isInfrastructureNode),clients=remaining.filter(n=>!isInfrastructureNode(n));infra.forEach((n,i)=>{const slots=Math.max(1,infra.length);pos[n.id]={x:180+(740*(i+.5)/slots),y:410}});clients.forEach((n,i)=>{const cols=Math.min(7,Math.max(1,clients.length));const row=Math.floor(i/cols),col=i%cols;pos[n.id]={x:95+(910*(col+.5)/cols),y:575+row*112}});return pos}
  const levels={};nodes.forEach(n=>(levels[depth[n.id]]||(levels[depth[n.id]]=[])).push(n));Object.keys(levels).map(Number).sort((a,b)=>a-b).forEach(d=>{const a=levels[d],y=70+d*145;a.forEach((n,i)=>pos[n.id]={x:85+(930*(i+.5)/a.length),y})});return pos}
function edgePath(a,b){const mid=(a.y+b.y)/2;return`M ${a.x} ${a.y+26} C ${a.x} ${mid}, ${b.x} ${mid}, ${b.x} ${b.y-32}`}
function mapNodeVisible(n){const st=mapNodeClass(n);return NETWORK_FILTER==='all'||NETWORK_FILTER===st}
function renderNetworkGraph(){const canvas=document.getElementById('networkCanvas'),svg=document.getElementById('mapEdgeLayer');if(!canvas||!svg)return;const nodes=NETWORK_DATA.nodes||[],links=NETWORK_DATA.links||[],pos=computeNetworkPositions(nodes,links,NETWORK_LAYOUT);const visible=new Set(nodes.filter(mapNodeVisible).map(n=>n.id));svg.innerHTML=links.filter(l=>pos[l.parent]&&pos[l.child]&&visible.has(l.parent)&&visible.has(l.child)).map(l=>`<path class="topology-edge ${isWirelessLink(l)?'wireless':''} ${l.details?.source==='inferred'?'inferred':''}" d="${edgePath(pos[l.parent],pos[l.child])}"></path>`).join('');canvas.innerHTML=nodes.filter(mapNodeVisible).map((n,i)=>{const p=pos[n.id]||{x:550,y:350},st=mapNodeClass(n),icon=n.type==='internet'?'<div class="internet-globe">🌐</div>':`<img src="${esc(mapDeviceIconSrc(n))}" alt="${esc(n.type||'Device')} icon">`;const originalIndex=nodes.indexOf(n);return`<div class="topology-node device-clickable ${n.type==='internet'?'internet':''} ${originalIndex===SELECTED_MAP_INDEX?'selected':''}" data-map-index="${originalIndex}" data-search="${esc([n.label,n.ip,n.mac,n.vendor,n.type,n.classification].filter(Boolean).join(' ').toLowerCase())}" style="left:${p.x}px;top:${p.y}px" onclick="selectMapNodeByIndex(${originalIndex})"><div class="topology-art">${icon}<span class="topology-status-dot ${st}"></span></div><div class="topology-name">${esc(n.label||n.id)}</div><div class="topology-ip">${esc(n.ip||n.type||'')}</div><div class="topology-vendor">${esc(n.vendor||'')}</div></div>`}).join('')||'<div class="map-empty">No devices match this filter.</div>';filterMapNodes();renderSelectedMapPanel();setTimeout(()=>{const stage=document.getElementById('networkStage');if(stage){const maxY=Math.max(720,...Object.values(pos).map(p=>p.y+110));stage.style.height=maxY+'px';svg.setAttribute('height',maxY);svg.style.height=maxY+'px'}},0)}
function setMapFilter(filter){NETWORK_FILTER=filter;document.querySelectorAll('.network-filter').forEach(b=>b.classList.toggle('active',b.dataset.mapFilter===filter));renderNetworkGraph()}
function setNetworkLayout(layout){NETWORK_LAYOUT=layout;document.querySelectorAll('.map-layout-btn').forEach(b=>b.classList.toggle('active',b.dataset.layout===layout));renderNetworkGraph();setTimeout(fitNetworkMap,30)}
function filterMapNodes(){const q=(document.getElementById('mapSearch')?.value||'').trim().toLowerCase();document.querySelectorAll('#networkCanvas .topology-node[data-search]').forEach(n=>{const match=!q||n.dataset.search.includes(q);n.classList.toggle('dimmed',!match)})}
function applyNetworkZoom(){const stage=document.getElementById('networkStage');if(stage)stage.style.transform='scale('+NETWORK_ZOOM+')'}
function zoomNetwork(delta){NETWORK_ZOOM=Math.max(.55,Math.min(1.45,Math.round((NETWORK_ZOOM+delta)*10)/10));applyNetworkZoom()}
function fitNetworkMap(){const vp=document.getElementById('networkViewport'),stage=document.getElementById('networkStage');if(!vp||!stage)return;NETWORK_ZOOM=Math.max(.55,Math.min(1,(vp.clientWidth-18)/1100));applyNetworkZoom();vp.scrollTo({left:0,top:0,behavior:'smooth'})}
function centerSelectedMapNode(){const vp=document.getElementById('networkViewport'),node=document.querySelector('.topology-node.selected');if(!vp||!node)return;vp.scrollTo({left:Math.max(0,node.offsetLeft*NETWORK_ZOOM-vp.clientWidth/2),top:Math.max(0,node.offsetTop*NETWORK_ZOOM-vp.clientHeight/2),behavior:'smooth'})}
function selectMapNodeByIndex(i){SELECTED_MAP_INDEX=Number(i);renderNetworkGraph();setTimeout(centerSelectedMapNode,10)}
function connectedNodesFor(n){if(!n)return[];const ids=[];for(const l of NETWORK_DATA.links||[]){if(l.parent===n.id)ids.push(l.child);else if(l.child===n.id)ids.push(l.parent)}return[...new Set(ids)].map(id=>NETWORK_DATA.byId[id]).filter(Boolean)}
function renderSelectedMapPanel(){const panel=document.getElementById('mapSelectedPanel'),list=document.getElementById('mapConnectedDevices'),count=document.getElementById('mapConnectedCount');if(!panel||!list)return;const n=(NETWORK_DATA.nodes||[])[SELECTED_MAP_INDEX];if(!n){panel.innerHTML='<div class="network-empty-side">Select a device on the map to view its details.</div>';list.innerHTML='<div class="network-empty-side">No device selected.</div>';if(count)count.textContent='0';return}const icon=n.type==='internet'?'<div class="internet-globe">🌐</div>':`<img src="${esc(mapDeviceIconSrc(n))}" alt="">`;panel.innerHTML=`<div class="network-device-head">${icon}<div><div class="network-device-title">${esc(n.label||n.id)}</div><div class="status-badge">● ${esc(mapNodeClass(n))}</div><div class="network-device-sub">${esc(n.vendor||n.type||'Network node')}</div></div></div><div class="network-kv"><div class="k">IP Address</div><div class="v">${esc(n.ip||'—')}</div><div class="k">MAC Address</div><div class="v">${esc(n.mac||'—')}</div><div class="k">Type</div><div class="v">${esc(n.type||'—')}</div><div class="k">Classification</div><div class="v">${esc(n.classification||'—')}</div><div class="k">Status</div><div class="v">${esc(n.status||'unknown')}</div></div><div class="network-device-actions">${n.device_id?`<button class="primary" onclick="goDevice(${Number(n.device_id)})">View Details</button><button class="secondary" onclick="showView('devices')">Edit Device</button>`:''}<a class="secondary" href="/tools#diagnostics" style="text-decoration:none">Ping</a></div>`;const connected=connectedNodesFor(n).filter(x=>x.id!=='internet');if(count)count.textContent=String(connected.length);list.innerHTML=connected.length?connected.slice(0,12).map(x=>{const st=mapNodeClass(x),src=x.type==='internet'?'':mapDeviceIconSrc(x);return`<div class="connected-device-row" onclick="selectMapNodeByIndex(${NETWORK_DATA.nodes.indexOf(x)})"><div>${x.type==='internet'?'🌐':`<img src="${esc(src)}" alt="">`}</div><span class="dot ${st}"></span><div><div class="connected-name">${esc(x.label||x.id)}</div><div class="connected-type">${esc(x.type||'Device')}</div></div><div class="connected-ip">${esc(x.ip||'')}</div></div>`}).join(''):'<div class="network-empty-side">No directly connected devices.</div>'}
/* legacy navigation contract: goDevice(${Number(n.device_id)}) */
window.filterMapNodes=filterMapNodes;window.zoomNetwork=zoomNetwork;window.fitNetworkMap=fitNetworkMap;window.setMapFilter=setMapFilter;window.setNetworkLayout=setNetworkLayout;window.selectMapNodeByIndex=selectMapNodeByIndex;window.centerSelectedMapNode=centerSelectedMapNode;
async function loadNetwork(){const canvas=document.getElementById('networkCanvas');if(!canvas)return;const status=document.getElementById('mapStatus');if(status)status.textContent='Refreshing topology…';try{const t=await json('/api/v1/intelligence/topology/live'),nodes=t.nodes||[],links=t.links||[],byId={};nodes.forEach(n=>byId[n.id]=n);NETWORK_DATA={...t,nodes,links,byId,gateway:t.gateway||'gateway'};const gw=document.getElementById('mapGateway'),nc=document.getElementById('mapNodes'),lc=document.getElementById('mapLinks'),up=document.getElementById('mapUpdated');if(gw)gw.textContent=t.gateway||'Unknown';if(nc)nc.textContent=nodes.filter(n=>n.type!=='internet').length;if(lc)lc.textContent=links.length;if(up)up.textContent=new Date(t.generated_at||Date.now()).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'});const all=nodes.filter(n=>n.type!=='internet'),online=all.filter(n=>mapNodeClass(n)==='online').length,offline=all.filter(n=>mapNodeClass(n)==='offline').length,unknown=Math.max(0,all.length-online-offline);document.getElementById('mapAllCount').textContent=all.length;document.getElementById('mapOnlineCount').textContent=online;document.getElementById('mapOfflineCount').textContent=offline;document.getElementById('mapUnknownCount').textContent=unknown;if(status)status.textContent=nodes.length+' nodes · '+links.length+' relationships · '+new Date(t.generated_at||Date.now()).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'});const evidence=document.getElementById('mapEvidence');if(evidence){const sources=[...new Set(links.map(l=>l.details?.source).filter(Boolean))];evidence.textContent=sources.length?'Evidence sources: '+sources.join(', ')+'. Solid paths are wired/unspecified; dashed paths are wireless.':'Paths without direct controller evidence are shown conservatively.'}if(SELECTED_MAP_INDEX<0||SELECTED_MAP_INDEX>=nodes.length)SELECTED_MAP_INDEX=Math.max(0,nodes.findIndex(n=>n.id===t.gateway||String(n.type).toLowerCase()==='gateway'));renderNetworkGraph();setTimeout(fitNetworkMap,40)}catch(e){canvas.innerHTML='<div class="map-empty">Topology is not available yet.<br><span class="muted">'+esc(e.message)+'</span><br><br><button class="primary" onclick="runFullDiscovery()">Run Full Discovery</button></div>';if(status)status.textContent='Topology unavailable'}}
async function runFullDiscovery(){networkCanvas.innerHTML='<div class="empty">Running ARP, Nmap, neighbors, mDNS, NetBIOS, DHCP and configured integration discovery…</div>';try{const r=await json('/api/v1/discovery/full',{method:'POST'});await loadNetwork();const parts=Object.entries(r.sources||{}).map(([k,v])=>k+': '+v.count).join(' · ');alert('Full discovery complete. '+r.total_observations+' correlated observations.\n'+parts)}catch(e){networkCanvas.innerHTML='<div class="empty">Full discovery failed: '+esc(e.message)+'</div>'}}
let MONITORS=[];let EDIT_MONITOR_ID=null;
async function loadMonitoring(){try{const [settings,checks]=await Promise.all([json('/api/v1/monitoring/settings'),json('/api/v1/monitoring/checks')]);MONITORS=settings;const latest={};for(const c of checks){if(c.monitor_id&&!latest[c.monitor_id])latest[c.monitor_id]=c}let healthy=0,failing=0,disabled=0;for(const x of settings){if(!x.enabled){disabled++;continue}const c=latest[x.id];const st=c?String(c.status||'unknown').toLowerCase():'unknown';if(['up','ok','healthy','online','success'].includes(st))healthy++;else if(['down','failed','error','offline'].includes(st))failing++}const setText=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v};setText('monitorTotalSummary',settings.length);setText('monitorHealthySummary',healthy);setText('monitorFailingSummary',failing);setText('monitorDisabledSummary',disabled);monitorRows.innerHTML=settings.length?settings.map(x=>{const c=latest[x.id];const st=c?c.status:(x.enabled?'unknown':'disabled');return `<tr><td><div class="name">${esc(x.name)}</div></td><td><span class="monitor-type-badge">${esc(String(x.kind||'').replace('_',' '))}</span></td><td><span class="monitor-target">${esc(x.target||'—')}</span></td><td>${esc(x.interval_seconds)} sec</td><td><span class="status-badge ${st==='down'||st==='failed'||st==='error'?'severity-high':''}">${esc(st)}</span></td><td>${c?esc(new Date(c.last_checked).toLocaleString()):'—'}</td><td>${c&&c.latency_ms!=null?esc(c.latency_ms)+' ms':'—'}</td><td><div class="monitor-actions"><button class="link" onclick="runMonitor(${x.id})">Run</button><button class="link" onclick="openMonitorEditor(${x.id})">Edit</button><button class="link" onclick="deleteMonitor(${x.id})">Delete</button></div></td></tr>`}).join(''):'<tr><td colspan="8"><div class="monitor-empty"><b>No monitors configured yet</b>Click Add Monitor to create your first network health check.</div></td></tr>'}catch(e){monitorRows.innerHTML='<tr><td colspan="8" class="empty">Monitoring data unavailable: '+esc(e.message)+'</td></tr>'}}
async function runMonitors(){try{await json('/api/v1/monitoring/run',{method:'POST'});await loadMonitoring();await loadFindings()}catch(e){alert('Could not run monitors: '+e.message)}}
async function runMonitor(id){try{await json('/api/v1/monitoring/settings/'+id+'/run',{method:'POST'});await loadMonitoring();await loadFindings()}catch(e){alert('Monitor failed: '+e.message)}}
function openMonitorEditor(id=null){EDIT_MONITOR_ID=id;const x=id?MONITORS.find(m=>m.id===id):null;monitorModalTitle.textContent=x?'Edit Monitor':'Add Monitor';monName.value=x?.name||'';monKind.value=x?.kind||'website';monTarget.value=x?.target==='(auto)'?'':(x?.target||'');monInterval.value=x?.interval_seconds||300;monEnabled.value=x?(x.enabled?'1':'0'):'1';try{monOptions.value=JSON.stringify(JSON.parse(x?.options_json||'{}'),null,2)}catch(_){monOptions.value='{}'}monitorEditorOut.textContent='';monitorModal.style.display='grid';document.body.style.overflow='hidden';setTimeout(()=>monName?.focus(),0)}
function closeMonitorEditor(){monitorModal.style.display='none';document.body.style.overflow=''}
async function saveMonitor(){try{let options={};try{options=JSON.parse(monOptions.value||'{}')}catch(_){throw new Error('Options must be valid JSON')}const body={name:monName.value.trim(),kind:monKind.value,target:monTarget.value.trim(),interval_seconds:+monInterval.value,enabled:monEnabled.value==='1',options};const url=EDIT_MONITOR_ID?'/api/v1/monitoring/settings/'+EDIT_MONITOR_ID:'/api/v1/monitoring/settings';await json(url,{method:EDIT_MONITOR_ID?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});closeMonitorEditor();await loadMonitoring()}catch(e){monitorEditorOut.textContent=e.message}}
async function deleteMonitor(id){if(!confirm('Delete this monitor and its check history?'))return;try{await json('/api/v1/monitoring/settings/'+id,{method:'DELETE'});await loadMonitoring()}catch(e){alert('Could not delete monitor: '+e.message)}}
async function loadFindings(){try{let open=await json('/api/v1/intelligence/issues?status=open');let resolved=await json('/api/v1/intelligence/issues?status=resolved');let all=open.concat(resolved);findingOpen.textContent=open.length;findingResolved.textContent=resolved.length;findingAll.textContent=all.length;findingCritical.textContent=all.filter(x=>['critical','high'].includes((x.severity||'').toLowerCase())).length;let badge=document.getElementById('findingBadge');if(badge)badge.textContent=open.length;findingRows.innerHTML=all.length?all.map(x=>`<tr><td><span class="status-badge severity-${esc((x.severity||'info').toLowerCase())}">${esc(x.severity||'Info')}</span></td><td><div class="name">${esc(x.title||x.issue_type||'Finding')}</div><div class="muted">${esc(x.recommendation||'')}</div></td><td>${esc(x.target||'—')}</td><td>${x.first_seen?esc(new Date(x.first_seen).toLocaleString()):'—'}</td><td><span class="status-badge">${esc(x.status||'open')}</span></td><td>${x.status==='open'?`<button class="link" onclick="showSuggestedFix(${x.id})">Suggested Fix</button> <button class="link" onclick="recheckFinding(${x.id})">Recheck</button> <button class="link operate-only" onclick="createTicketFromNetworkFinding(${x.id})">Create Ticket</button> <button class="link" onclick="resolveFinding(${x.id})">Resolve</button>`:'—'}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No findings yet.</td></tr>'}catch(e){findingRows.innerHTML='<tr><td colspan="6" class="empty">Findings unavailable: '+esc(e.message)+'</td></tr>'}}
async function showSuggestedFix(id){try{const r=await json('/api/v1/intelligence/issues/'+id+'/suggested-fix');alert(r.title+'\n\n'+(r.recommendation||'')+'\n\n'+(r.actions||[]).map((x,i)=>(i+1)+'. '+x).join('\n'))}catch(e){alert('Could not load suggested fix: '+e.message)}}
async function recheckFinding(id){try{const r=await json('/api/v1/intelligence/issues/'+id+'/recheck',{method:'POST'});alert(r.ok?'Recheck completed successfully.':'Recheck completed; the condition may still be present.');await loadFindings();await loadMonitoring();await loadInventory()}catch(e){alert('Could not recheck finding: '+e.message)}}
async function resolveFinding(id){if(!confirm('Mark this finding resolved?'))return;try{await json('/api/v1/intelligence/issues/'+id+'/resolve',{method:'POST'});await loadFindings()}catch(e){alert('Could not resolve finding: '+e.message)}}
async function createTicketFromNetworkFinding(id){try{const ticket=await json('/api/v1/intelligence/issues/'+id+'/create-ticket',{method:'POST'});showView('tickets',true);await loadTickets();openTicketEditor(ticket.id)}catch(e){alert('Could not create ticket: '+e.message)}}


let INTEGRATIONS=[],ANALYTICS_ITEMS=[],CURRENT_ANALYTICS=null;
function integrationKindLabel(k){return k==='pihole'?'Pi-hole':k==='unifi'?'UniFi':'SNMP'}
function integrationIcon(k){return k==='pihole'?'π':k==='unifi'?'U':'S'}
function integrationCard(c){const state=c.last_sync_status||'never';return `<div class="integration-card"><div class="integration-card-head"><div style="display:flex;gap:9px;align-items:center"><div class="tool-icon" style="width:34px;height:34px;margin:0">${integrationIcon(c.kind)}</div><div><b>${esc(c.name||integrationKindLabel(c.kind))}</b><div><span class="integration-badge">${integrationKindLabel(c.kind)}</span></div></div></div><span class="integration-state ${state}">${esc(state)}</span></div><div class="integration-meta"><div><b>Target:</b> ${esc(c.target||'—')}</div><div><b>Last sync:</b> ${c.last_sync_at?new Date(c.last_sync_at).toLocaleString():'Never'}</div>${c.last_sync_error?`<div style="color:#c73c50">${esc(c.last_sync_error)}</div>`:''}<div>${c.enabled?'● Enabled':'○ Disabled'} · every ${c.sync_interval_seconds||300}s ${c.has_secret?'· credential saved':''}</div></div><div class="integration-actions"><button class="secondary" onclick="syncIntegration(${c.id})">Test & Sync</button><button class="secondary admin-only" onclick="openIntegrationModal(${c.id})">Edit</button><button class="integration-remove admin-only" onclick="openDeleteIntegrationModal(${c.id})" title="Remove this integration">Remove</button></div></div>`}
function analyticsCard(a){const d=a.analytics||{};let main='—',label='Latest snapshot';if(a.source==='pihole'){main=d.queries??d.total_queries??'—';label='DNS queries'}else if(a.source==='unifi'){main=d.active_clients??'—';label='Active clients'}else if(a.source==='snmp'){main=d.neighbors??'—';label='Neighbors'}return `<button class="analytics-card" onclick="openAnalytics(${a.integration_id})"><div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(a.integration_name||integrationKindLabel(a.source))}</b><span class="integration-badge">${integrationKindLabel(a.source)}</span></div><div class="metric">${esc(main)}</div><div class="sub">${label} · ${a.captured_at?new Date(a.captured_at).toLocaleString():'No timestamp'}</div><div class="sub">Click for full analytics</div></button>`}
function applyRoleVisibility(){
 document.querySelectorAll('.admin-only').forEach(el=>el.classList.toggle('admin-visible',!!ME&&ME.role==='admin'));
 document.querySelectorAll('.operate-only').forEach(el=>el.classList.toggle('operate-visible',!!ME&&['admin','operator'].includes(ME.role)));
}
async function loadIntegrations(){try{const [r,a,n]=await Promise.all([json('/api/v1/integrations/configs'),json('/api/v1/analytics/clients'),json('/api/v1/notifications/config').catch(()=>null)]);INTEGRATIONS=r.configs||[];ANALYTICS_ITEMS=a.integration_analytics||[];integrationSummary.textContent=INTEGRATIONS.length+' configured integration'+(INTEGRATIONS.length===1?'':'s')+' · '+INTEGRATIONS.filter(x=>x.enabled).length+' enabled';integrationList.innerHTML=INTEGRATIONS.length?INTEGRATIONS.map(integrationCard).join(''):'<div class="panel empty" style="grid-column:1/-1">No integrations configured. Add your first Pi-hole, UniFi, or SNMP collector.</div>';integrationAnalytics.innerHTML=ANALYTICS_ITEMS.length?ANALYTICS_ITEMS.map(analyticsCard).join(''):'<div class="empty" style="grid-column:1/-1">No retained client/query analytics. Run an integration sync to collect analytics.</div>';applyRoleVisibility();if(n){notifyWebhook.value=n.webhook_url||'';notifyNtfyServer.value=n.ntfy_server||'https://ntfy.sh';notifyNtfy.value=n.ntfy_topic||'';notifySmtpHost.value=n.smtp_host||'';notifySmtpPort.value=n.smtp_port||587;notifySmtpUser.value=n.smtp_user||'';notifySmtpFrom.value=n.smtp_from||'';notifyEmail.value=n.smtp_to||'';notifySmtpPass.placeholder=n.has_smtp_password?'SMTP password saved — blank keeps it':'SMTP password';notifySeverity.value=n.min_severity||'warning'}}catch(e){integrationList.innerHTML='<div class="panel empty" style="grid-column:1/-1">Integrations unavailable: '+esc(e.message)+'</div>'}}
function updateIntegrationFields(){const k=integrationKind.value;integrationUserWrap.style.display=k==='unifi'?'flex':'none';integrationSiteWrap.style.display=k==='unifi'?'flex':'none';integrationTls.parentElement.style.display=k==='snmp'?'none':'flex';integrationSecret.placeholder=k==='pihole'?'Application password / API credential':k==='unifi'?'Controller password':'SNMP community'}
function openIntegrationModal(id=null){const c=id?INTEGRATIONS.find(x=>x.id===id):null;integrationId.value=c?.id||'';integrationModalTitle.textContent=c?'Edit Integration':'Add Integration';integrationName.value=c?.name||'';integrationKind.value=c?.kind||'pihole';integrationKind.disabled=!!c;integrationTarget.value=c?.target||'';integrationUser.value=c?.username||'';integrationSecret.value='';integrationSite.value='default';try{if(c?.options_json)integrationSite.value=JSON.parse(c.options_json).site||'default'}catch(_){}integrationInterval.value=c?.sync_interval_seconds||300;integrationEnabled.checked=c?!!c.enabled:true;integrationTls.checked=c?!!c.verify_tls:true;integrationErr.textContent='';updateIntegrationFields();integrationModal.style.display='grid';document.body.style.overflow='hidden';setTimeout(()=>integrationName.focus(),20)}
function closeIntegrationModal(){integrationModal.style.display='none';document.body.style.overflow='';integrationKind.disabled=false}
async function submitIntegration(e){e.preventDefault();const id=integrationId.value;const kind=integrationKind.value;const body={name:integrationName.value.trim(),kind,enabled:integrationEnabled.checked,target:integrationTarget.value.trim(),username:integrationUser.value.trim(),secret:integrationSecret.value||null,verify_tls:integrationTls.checked,sync_interval_seconds:+integrationInterval.value||300,options:{site:integrationSite.value.trim()||'default'}};try{await json(id?'/api/v1/integrations/configs/'+id:'/api/v1/integrations/configs',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});closeIntegrationModal();await loadIntegrations()}catch(err){integrationErr.textContent=err.message}return false}
let DELETE_INTEGRATION_ID=null;
function openDeleteIntegrationModal(id){const c=INTEGRATIONS.find(x=>x.id===id);if(!c)return;DELETE_INTEGRATION_ID=id;deleteIntegrationConfirm.value='';deleteIntegrationErr.textContent='';deleteIntegrationSummary.innerHTML='<b>'+esc(c.name||integrationKindLabel(c.kind))+'</b><br>'+esc(integrationKindLabel(c.kind))+' · '+esc(c.target||'No target')+'<br><br>This removes the saved integration, its sync history, and its retained analytics. Device inventory and the audit log are preserved.';deleteIntegrationModal.style.display='grid';document.body.style.overflow='hidden';setTimeout(()=>deleteIntegrationConfirm.focus(),20)}
function closeDeleteIntegrationModal(){deleteIntegrationModal.style.display='none';DELETE_INTEGRATION_ID=null;deleteIntegrationConfirm.value='';deleteIntegrationErr.textContent='';document.body.style.overflow=''}
async function confirmDeleteIntegration(){if(!DELETE_INTEGRATION_ID)return;if(deleteIntegrationConfirm.value.trim()!=='REMOVE'){deleteIntegrationErr.textContent='Type REMOVE exactly to continue.';deleteIntegrationConfirm.focus();return}deleteIntegrationErr.textContent='';deleteIntegrationBtn.disabled=true;deleteIntegrationBtn.textContent='Removing…';try{await json('/api/v1/integrations/configs/'+DELETE_INTEGRATION_ID,{method:'DELETE'});closeDeleteIntegrationModal();await loadIntegrations()}catch(e){deleteIntegrationErr.textContent='Could not remove integration: '+e.message}finally{deleteIntegrationBtn.disabled=false;deleteIntegrationBtn.textContent='Remove Integration'}}
async function syncIntegration(id){try{const r=await json('/api/v1/integrations/configs/'+id+'/sync',{method:'POST'});alert((r.ok?'Sync complete':'Sync failed')+' · '+r.observations+' observations'+(r.error?'\n'+r.error:''));await loadIntegrations();if(r.ok)await loadNetwork()}catch(e){alert('Sync failed: '+e.message)}}
function openAnalytics(id){CURRENT_ANALYTICS=ANALYTICS_ITEMS.find(x=>x.integration_id===id);if(!CURRENT_ANALYTICS)return;const d=CURRENT_ANALYTICS.analytics||{};analyticsTitle.textContent=CURRENT_ANALYTICS.integration_name||integrationKindLabel(CURRENT_ANALYTICS.source);analyticsSubtitle.textContent=integrationKindLabel(CURRENT_ANALYTICS.source)+' · captured '+(CURRENT_ANALYTICS.captured_at?new Date(CURRENT_ANALYTICS.captured_at).toLocaleString():'unknown');const metrics=[];if(d.queries!=null)metrics.push(['Queries',d.queries]);if(d.blocked!=null)metrics.push(['Blocked',d.blocked]);if(d.clients!=null)metrics.push(['Clients',d.clients]);if(d.active_clients!=null)metrics.push(['Active clients',d.active_clients]);if(d.wifi_clients!=null)metrics.push(['Wi-Fi clients',d.wifi_clients]);if(d.neighbors!=null)metrics.push(['Neighbors',d.neighbors]);analyticsSummary.innerHTML=(metrics.slice(0,3).map(x=>`<div><b>${esc(x[1])}</b><span>${esc(x[0])}</span></div>`).join('')||'<div><b>✓</b><span>Analytics snapshot</span></div>');analyticsDetail.textContent=JSON.stringify(d,null,2);analyticsClearReason.value='';analyticsClearErr.textContent='';analyticsModal.style.display='grid';document.body.style.overflow='hidden'}
function closeAnalyticsModal(){analyticsModal.style.display='none';document.body.style.overflow='';CURRENT_ANALYTICS=null}
function clearCurrentAnalytics(){if(!CURRENT_ANALYTICS)return;const reason=analyticsClearReason.value.trim();analyticsClearErr.textContent='';if(reason.length<5){analyticsClearErr.textContent='Please provide a reason of at least 5 characters.';analyticsClearReason.focus();return}clearOneAnalyticsBtn.disabled=true;json('/api/v1/analytics/clear/'+CURRENT_ANALYTICS.integration_id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})}).then(r=>{closeAnalyticsModal();loadIntegrations();alert('Analytics cleared by '+r.cleared_by+'. '+r.deleted+' record(s) removed.')}).catch(e=>{analyticsClearErr.textContent='Could not clear analytics: '+e.message}).finally(()=>{clearOneAnalyticsBtn.disabled=false})}
async function saveNotifications(){try{const body={webhook_enabled:!!notifyWebhook.value.trim(),webhook_url:notifyWebhook.value.trim(),ntfy_enabled:!!notifyNtfy.value.trim(),ntfy_server:notifyNtfyServer.value.trim()||'https://ntfy.sh',ntfy_topic:notifyNtfy.value.trim(),smtp_enabled:!!(notifySmtpHost.value.trim()&&notifySmtpFrom.value.trim()&&notifyEmail.value.trim()),smtp_host:notifySmtpHost.value.trim(),smtp_port:+notifySmtpPort.value||587,smtp_user:notifySmtpUser.value.trim(),smtp_password:notifySmtpPass.value||null,smtp_from:notifySmtpFrom.value.trim(),smtp_to:notifyEmail.value.trim(),min_severity:notifySeverity.value};await json('/api/v1/notifications/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});notifySmtpPass.value='';notifyOut.textContent='Saved.'}catch(e){notifyOut.textContent=e.message}}
async function testNotifications(){try{const r=await json('/api/v1/notifications/test',{method:'POST'});notifyOut.textContent='Test attempted: '+r.sent+' channel(s) sent'+(r.errors?.length?' · '+r.errors.join('; '):'')}catch(e){notifyOut.textContent=e.message}}
function fmtBytes(v){v=Number(v||0);if(v<1024)return v+' B';if(v<1048576)return (v/1024).toFixed(1)+' KB';if(v<1073741824)return (v/1048576).toFixed(1)+' MB';return (v/1073741824).toFixed(2)+' GB'}
function fmtRate(v){v=Number(v||0);if(v<1000)return Math.round(v)+' bps';if(v<1000000)return (v/1000).toFixed(1)+' Kbps';if(v<1000000000)return (v/1000000).toFixed(1)+' Mbps';return (v/1000000000).toFixed(2)+' Gbps'}
let trafficConfigPayload=null;
function selectTrafficMode(mode){
 trafficMode.value=mode;
 const ints=(trafficConfigPayload?.integrations||[]).filter(x=>x.kind===mode);
 trafficIntegration.innerHTML=ints.map(x=>`<option value="${x.id}">${esc(x.name)} — ${esc(x.target)}</option>`).join('')||'<option value="">No matching integration configured</option>';
 renderTrafficModeFields();
}
function renderTrafficModeFields(){
 const mode=trafficMode.value;
 document.querySelectorAll('.traffic-source-card').forEach(el=>el.classList.toggle('active',el.dataset.trafficMode===mode));
 trafficIntegrationWrap.style.display=(mode==='unifi'||mode==='snmp')?'':'none';
 trafficInterfaceWrap.style.display=(mode==='span'||mode==='inline')?'':'none';
 if(trafficConfigPayload){
  const cap=trafficConfigPayload.mode_capabilities?.[mode]||{};
  const label=trafficConfigPayload.modes?.[mode]||mode;
  trafficModeHelpTitle.textContent=label;
  trafficModeHelp.textContent=cap.description||'No source description available.';
  trafficModeRequire.textContent=(cap.requires?'Requires: '+cap.requires+' ':'')+'GODSEYE records this source and confidence with every device sample.';
 }
}
function renderTrafficCollection(payload,usage){
 trafficConfigPayload=payload;const c=payload.config||{};trafficMode.value=c.mode||'unifi';trafficEnabled.value=c.enabled?'1':'0';trafficInterval.value=c.sample_interval_seconds||30;
 const ints=(payload.integrations||[]).filter(x=>x.kind===trafficMode.value);trafficIntegration.innerHTML=ints.map(x=>`<option value="${x.id}">${esc(x.name)} — ${esc(x.target)}</option>`).join('')||'<option value="">No matching integration configured</option>';if(c.integration_id)trafficIntegration.value=String(c.integration_id);
 trafficInterface.innerHTML=(payload.interfaces||[]).map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('')||'<option value="">No interfaces found</option>';if(c.interface)trafficInterface.value=c.interface;
 const state=c.enabled?(c.last_status||'configured'):'disabled';
 trafficCollectionState.textContent=state.replaceAll('_',' ').toUpperCase();trafficCollectionState.className='traffic-state '+state;
 trafficSourceLabel.textContent=payload.modes?.[c.mode]||c.mode||'Not configured';
 trafficSourceSub.textContent=c.enabled?'Collection enabled':'Collection disabled';
 traffic24Rx.textContent=fmtBytes(usage.total_rx_bytes||0);traffic24Tx.textContent=fmtBytes(usage.total_tx_bytes||0);
 const rows=usage.devices||[];trafficDeviceCount.textContent=String(rows.length);
 const latest=rows.map(x=>x.last_sample).filter(Boolean).sort().at(-1);
 trafficLastSample.textContent=latest?'Latest '+new Date(latest).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):'No samples yet';
 trafficCollectionMeta.textContent=c.last_collected_at?'Last run '+new Date(c.last_collected_at).toLocaleString():(c.last_error||'');
 renderTrafficModeFields();
 trafficDeviceRows.innerHTML=rows.length?rows.map(x=>`<tr><td><span class="traffic-device-name">${esc(x.label)}</span><div class="muted">${esc(x.ip||x.mac||'')}</div></td><td><span class="traffic-source-chip">${esc(x.source_mode)} · ${esc(x.confidence)}</span></td><td><strong>${fmtBytes(x.rx_bytes)}</strong></td><td><strong>${fmtBytes(x.tx_bytes)}</strong></td><td>${fmtRate(x.peak_rx_bps)}</td><td>${fmtRate(x.peak_tx_bps)}</td><td>${x.last_sample?esc(new Date(x.last_sample).toLocaleString()):'—'}</td></tr>`).join(''):'<tr><td colspan="7" class="empty traffic-empty"><span class="traffic-empty-icon">⇅</span>No measured per-device traffic yet.<br><span class="muted">Choose a source above and run a collection cycle.</span></td></tr>';
 applyRoleVisibility();
}
async function saveTrafficCollection(){try{const body={enabled:trafficEnabled.value==='1',mode:trafficMode.value,integration_id:(trafficMode.value==='unifi'||trafficMode.value==='snmp')?(+trafficIntegration.value||null):null,interface:(trafficMode.value==='span'||trafficMode.value==='inline')?trafficInterface.value:'',sample_interval_seconds:+trafficInterval.value,options:{}};await json('/api/v1/traffic/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});await loadReports()}catch(e){alert('Could not save traffic source: '+e.message)}}
async function collectTrafficNow(){try{const r=await json('/api/v1/traffic/collect-now',{method:'POST'});alert('Traffic collection: '+(r.status||'unknown')+(r.devices_sampled!=null?' · '+r.devices_sampled+' device(s) sampled':'')+(r.note?' · '+r.note:'')+(r.error?' · '+r.error:''));await loadReports()}catch(e){alert('Traffic collection failed: '+e.message)}}
trafficMode?.addEventListener?.('change',()=>selectTrafficMode(trafficMode.value));
function selectReportType(type){
 const sel=document.getElementById('reportGenerateType');if(sel)sel.value=type;
 document.querySelectorAll('.report-type-card').forEach(el=>el.classList.toggle('active',el.dataset.reportType===type));
}
function reportTypeLabel(t){return ({network_summary:'Network Summary',device_inventory:'Device Inventory',security_findings:'Security Findings',availability_monitoring:'Availability & Monitoring',integrations_health:'Integrations Health',traffic_usage:'Traffic Usage',audit_activity:'Audit Activity',device_changes:'Device Changes'})[t]||t||'Report'}
function reportMetricText(x){const s=x.summary||{};return Object.entries(s).filter(([k,v])=>!Array.isArray(v)&&typeof v!=='object').slice(0,3).map(([k,v])=>k.replaceAll('_',' ')+': '+v).join(' · ')||'—'}
async function loadReports(){try{selectReportType(reportGenerateType?.value||'network_summary');const [s,sc,h,tc,tu]=await Promise.all([json('/api/v1/reports/summary'),json('/api/v1/reports/schedules'),json('/api/v1/reports/history'),json('/api/v1/traffic/config'),json('/api/v1/traffic/devices?hours=24&limit=25')]);renderTrafficCollection(tc,tu);reportSummary.textContent=s.body_text;
reportGeneratedCount.textContent=String(h.length||0);
reportScheduleCount.textContent=String(sc.length||0);
if(h.length){reportLatestType.textContent=reportTypeLabel(h[0].report_type);reportLatestTime.textContent=new Date(h[0].generated_at).toLocaleString()}else{reportLatestType.textContent='—';reportLatestTime.textContent='Nothing generated yet'};reportSchedules.innerHTML=sc.length?sc.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(reportTypeLabel(x.report_type))}</td><td>${esc(x.cadence)}</td><td>${x.next_run_at?esc(new Date(x.next_run_at).toLocaleString()):'—'}</td><td>${x.last_run_at?esc(new Date(x.last_run_at).toLocaleString()):'—'}</td><td><button class="link" onclick="deleteReportSchedule(${x.id})">Delete</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">No scheduled reports.</td></tr>';reportHistory.innerHTML=h.length?h.map(x=>`<tr data-report-id="${x.id}"><td class="admin-only"><input type="checkbox" class="report-select" value="${x.id}" onchange="updateReportDeleteSelection()" aria-label="Select ${esc(x.title)}"></td><td>${esc(new Date(x.generated_at).toLocaleString())}</td><td>${esc(reportTypeLabel(x.report_type))}</td><td>${esc(x.title)}</td><td>${esc(reportMetricText(x))}</td><td><a class="link" href="/api/v1/reports/${x.id}/export.pdf">PDF</a> · <a class="link" href="/api/v1/reports/${x.id}/export.csv">CSV</a></td><td><button class="link operate-only" onclick="openEmailReportModal(${x.id},'${esc(x.title).replace(/'/g,"&#39;")}')">Email</button> <span class="admin-only">· <button class="link danger-link" onclick="deleteReport(${x.id},'${esc(x.title).replace(/'/g,"&#39;")}')">Delete</button></span></td></tr>`).join(''):'<tr><td colspan="7" class="empty">No reports generated yet.</td></tr>';updateReportDeleteSelection()}catch(e){reportSummary.textContent='Reports unavailable: '+e.message}}
async function generateReport(){try{await json('/api/v1/reports/generate?report_type='+encodeURIComponent(reportGenerateType.value),{method:'POST'});await loadReports()}catch(e){alert('Could not generate report: '+e.message)}}
async function addReportSchedule(){try{await json('/api/v1/reports/schedules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:reportName.value.trim(),report_type:reportScheduleType.value,enabled:true,cadence:reportCadence.value,hour_utc:+reportHour.value,weekday:0,notify:true})});reportName.value='';await loadReports()}catch(e){alert('Could not add report schedule: '+e.message)}}
async function deleteReportSchedule(id){if(!confirm('Delete this report schedule?'))return;try{await json('/api/v1/reports/schedules/'+id,{method:'DELETE'});await loadReports()}catch(e){alert(e.message)}}
function updateReportDeleteSelection(){
 const boxes=[...document.querySelectorAll('.report-select')];
 const selected=boxes.filter(x=>x.checked);
 const btn=document.getElementById('deleteSelectedReportsBtn');
 if(btn){btn.disabled=selected.length===0;btn.textContent=selected.length?`Delete Selected (${selected.length})`:'Delete Selected'}
 const all=document.getElementById('reportSelectAll');
 if(all){all.checked=boxes.length>0&&selected.length===boxes.length;all.indeterminate=selected.length>0&&selected.length<boxes.length}
}
function toggleAllReports(checked){
 document.querySelectorAll('.report-select').forEach(x=>x.checked=checked);
 updateReportDeleteSelection();
}
async function deleteReport(id,title){
 if(!confirm(`Delete "${title}" from Report History? This cannot be undone.`))return;
 try{await json('/api/v1/reports/'+id,{method:'DELETE'});await loadReports()}catch(e){alert('Could not delete report: '+e.message)}
}
async function deleteSelectedReports(){
 const ids=[...document.querySelectorAll('.report-select:checked')].map(x=>Number(x.value));
 if(!ids.length)return;
 if(!confirm(`Delete ${ids.length} selected report${ids.length===1?'':'s'}? This cannot be undone.`))return;
 try{
   await json('/api/v1/reports/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({report_ids:ids})});
   await loadReports();
 }catch(e){alert('Could not delete selected reports: '+e.message)}
}

function fmtBits(v){v=Number(v||0);if(v>=1e9)return (v/1e9).toFixed(1)+' Gbps';if(v>=1e6)return (v/1e6).toFixed(1)+' Mbps';if(v>=1e3)return (v/1e3).toFixed(1)+' Kbps';return Math.round(v)+' bps'}
async function loadTraffic(){
  const nowEl=document.getElementById('trafficNow'),foot=document.getElementById('trafficFoot'),labels=document.getElementById('trafficLabels'),rx=document.getElementById('trafficRx'),tx=document.getElementById('trafficTx'),client=document.getElementById('clientBars'),note=document.getElementById('clientMetricNote');
  try{
    const r=await json('/api/v1/analytics/traffic?minutes=60');const a=r.samples||[];
    if(a.length){const max=Math.max(1,...a.flatMap(x=>[Number(x.rx_bps)||0,Number(x.tx_bps)||0]));const pts=(key)=>a.map((x,i)=>{const xx=45+(700*(i/Math.max(1,a.length-1)));const yy=165-(135*((Number(x[key])||0)/max));return xx.toFixed(1)+','+yy.toFixed(1)}).join(' ');rx.setAttribute('points',pts('rx_bps'));tx.setAttribute('points',pts('tx_bps'));const last=a[a.length-1];nowEl.textContent=fmtBits(last.rx_bps)+' ↓ · '+fmtBits(last.tx_bps)+' ↑';foot.textContent=(last.interface||'interface')+' · '+a.length+' samples · last '+new Date(last.captured_at).toLocaleTimeString();if(labels)labels.innerHTML=`<text x="4" y="29" class="traffic-axis">${esc(fmtBits(max))}</text><text x="16" y="168" class="traffic-axis">0</text>`}
    else{rx.setAttribute('points','');tx.setAttribute('points','');nowEl.textContent='waiting for traffic samples';foot.textContent='No samples yet. The collector records a baseline first, then calculates rates on the next sample.'}
    const c=r.clients||{};note.textContent=c.note||'Observed activity by device';const rows=c.clients||[],mx=Math.max(1,...rows.map(x=>Number(x.activity_events)||0));client.innerHTML=rows.length?rows.slice(0,10).map(x=>`<div class="client-row"><button class="device-link" onclick="goDevice(${x.id})">${esc(x.label||x.ip||x.mac||'Unknown')}</button><div class="client-bar"><span style="width:${Math.max(2,(Number(x.activity_events)||0)/mx*100)}%"></span></div><div class="muted">${Number(x.activity_events)||0}</div></div>`).join(''):'<div class="empty">No client activity has been observed yet.</div>';
  }catch(e){if(nowEl)nowEl.textContent='traffic unavailable';if(foot)foot.textContent=e.message;if(client)client.innerHTML='<div class="empty">Unable to load client activity.</div>'}
}
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


let UI_LAYOUTS={};
let LAYOUT_EDITING=false;
let LAYOUT_DRAGGED=null;
let LAYOUT_SAVE_TIMER=null;
const LAYOUT_ZONE_SELECTORS=['.cards','.tool-grid','.report-type-grid','.traffic-source-grid','.analytics-grid','.notify-grid','.monitor-summary','.map-summary','.integration-list','.traffic-stat-grid','.intel-grid','.connected-grid','.report-history-grid','.health-grid'];
function layoutSlug(value){return String(value||'item').trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,80)||'item'}
function currentLayoutPage(){const visible=[...document.querySelectorAll('.view')].find(v=>v.style.display!=='none');return visible?.id?.replace(/^view-/,'')||'overview'}
function layoutItemKey(el,index){if(el.dataset.layoutKey)return el.dataset.layoutKey;let key=el.id||el.dataset.reportType||el.dataset.trafficMode||el.dataset.integrationId||el.querySelector('h1,h2,h3,.report-type-name,.traffic-source-name,.analytics-title,.label,.k')?.textContent||('card-'+index);key=layoutSlug(key);el.dataset.layoutKey=key;return key}
function registerLayoutZones(){
 document.querySelectorAll('.view').forEach(view=>{
  const page=view.id.replace(/^view-/,'');let zoneIndex=0;
  LAYOUT_ZONE_SELECTORS.forEach(selector=>view.querySelectorAll(selector).forEach(zone=>{
   if(zone.closest('.modal'))return;
   zone.classList.add('layout-zone');zone.dataset.layoutZone=zone.dataset.layoutZone||`${page}-${layoutSlug(selector)}-${zoneIndex++}`;
   [...zone.children].forEach((el,i)=>{if(el.matches('.empty,script,style'))return;el.classList.add('layout-movable');layoutItemKey(el,i)});
  }));
  const directPanels=[...view.children].filter(el=>el.classList.contains('panel'));
  if(directPanels.length>1){directPanels.forEach((el,i)=>{el.classList.add('layout-movable');layoutItemKey(el,i)});view.dataset.layoutLooseZone=`${page}-panels`;view.classList.add('layout-loose-zone')}
  ensureLayoutToolbar(view,page);
 });
 applyAllSavedLayouts();
 syncLayoutDraggable();
}
function ensureLayoutToolbar(view,page){
 let hero=view.querySelector(':scope > .hero');if(!hero||hero.querySelector('.layout-admin-tools'))return;
 let tools=document.createElement('div');tools.className='layout-admin-tools admin-only';tools.innerHTML=`<button type="button" class="secondary layout-arrange-btn" onclick="toggleLayoutEditing(event)">↕ Arrange Cards</button><button type="button" class="secondary layout-reset-btn" onclick="resetPageLayout(event)">Reset</button><span class="layout-save-state" data-layout-state></span>`;hero.appendChild(tools);applyRoleVisibility();
}
function zoneForElement(el){return el.closest('.layout-zone')||el.closest('.layout-loose-zone')}
function zoneKey(zone){return zone.dataset.layoutZone||zone.dataset.layoutLooseZone}
function movableChildren(zone){return zone.classList.contains('layout-loose-zone')?[...zone.children].filter(x=>x.classList.contains('layout-movable')):[...zone.children].filter(x=>x.classList.contains('layout-movable'))}
function applyZoneOrder(zone,order){if(!Array.isArray(order)||!order.length)return;const items=movableChildren(zone),map=new Map(items.map((el,i)=>[layoutItemKey(el,i),el]));order.forEach(key=>{const el=map.get(key);if(el)zone.appendChild(el)})}
function applyAllSavedLayouts(){document.querySelectorAll('.layout-zone,.layout-loose-zone').forEach(zone=>{const page=(zone.closest('.view')?.id||'view-overview').replace(/^view-/,'');const order=UI_LAYOUTS[page]?.layout?.[zoneKey(zone)];applyZoneOrder(zone,order)})}
function pageLayoutSnapshot(page){const view=document.getElementById('view-'+page);const out={};if(!view)return out;view.querySelectorAll('.layout-zone,.layout-loose-zone').forEach(zone=>{const key=zoneKey(zone);if(key)out[key]=movableChildren(zone).map((el,i)=>layoutItemKey(el,i))});return out}
async function loadUILayouts(){try{const r=await json('/api/v1/ui/layouts');UI_LAYOUTS=r.layouts||{}}catch(e){UI_LAYOUTS={}}registerLayoutZones()}
function syncLayoutDraggable(){document.querySelectorAll('.layout-movable').forEach(el=>{el.draggable=!!(LAYOUT_EDITING&&ME?.role==='admin')})}
function toggleLayoutEditing(event){event?.preventDefault();if(!ME||ME.role!=='admin')return;LAYOUT_EDITING=!LAYOUT_EDITING;document.body.classList.toggle('layout-editing',LAYOUT_EDITING);document.querySelectorAll('.layout-arrange-btn').forEach(b=>b.innerHTML=LAYOUT_EDITING?'✓ Done Arranging':'↕ Arrange Cards');document.querySelectorAll('.layout-save-state').forEach(x=>x.textContent=LAYOUT_EDITING?'Drag cards to move':'' );registerLayoutZones();syncLayoutDraggable()}
function layoutDropIndex(zone,x,y,dragged){const items=movableChildren(zone).filter(el=>el!==dragged);if(!items.length)return null;let best=null,bestDistance=Infinity;for(const el of items){const r=el.getBoundingClientRect(),cx=r.left+r.width/2,cy=r.top+r.height/2,d=Math.hypot(x-cx,y-cy);if(d<bestDistance){bestDistance=d;best={el,before:(Math.abs(y-cy)>Math.abs(x-cx))?y<cy:x<cx}}}return best}
function clearLayoutTargets(){document.querySelectorAll('.layout-drop-target').forEach(x=>x.classList.remove('layout-drop-target'))}
document.addEventListener('dragstart',e=>{const el=e.target.closest?.('.layout-movable');if(!LAYOUT_EDITING||!el||ME?.role!=='admin')return;e.stopPropagation();LAYOUT_DRAGGED=el;el.classList.add('layout-dragging');e.dataTransfer.effectAllowed='move';e.dataTransfer.setData('text/plain',el.dataset.layoutKey||'card')});
document.addEventListener('dragover',e=>{if(!LAYOUT_DRAGGED)return;const zone=zoneForElement(e.target);if(!zone||zone!==zoneForElement(LAYOUT_DRAGGED))return;e.preventDefault();e.dataTransfer.dropEffect='move';clearLayoutTargets();const hit=layoutDropIndex(zone,e.clientX,e.clientY,LAYOUT_DRAGGED);hit?.el.classList.add('layout-drop-target')});
document.addEventListener('drop',e=>{if(!LAYOUT_DRAGGED)return;const zone=zoneForElement(e.target);if(!zone||zone!==zoneForElement(LAYOUT_DRAGGED))return;e.preventDefault();const hit=layoutDropIndex(zone,e.clientX,e.clientY,LAYOUT_DRAGGED);if(hit?.el)zone.insertBefore(LAYOUT_DRAGGED,hit.before?hit.el:hit.el.nextSibling);clearLayoutTargets();queueLayoutSave(currentLayoutPage())});
document.addEventListener('dragend',()=>{if(LAYOUT_DRAGGED)LAYOUT_DRAGGED.classList.remove('layout-dragging');LAYOUT_DRAGGED=null;clearLayoutTargets()});
document.addEventListener('click',e=>{if(LAYOUT_EDITING&&e.target.closest('.layout-movable')&&!e.target.closest('.layout-admin-tools')){e.preventDefault();e.stopPropagation()}},true);
function queueLayoutSave(page){clearTimeout(LAYOUT_SAVE_TIMER);document.querySelectorAll('[data-layout-state]').forEach(x=>x.textContent='Saving…');LAYOUT_SAVE_TIMER=setTimeout(()=>savePageLayout(page),250)}
async function savePageLayout(page){if(!ME||ME.role!=='admin')return;const layout=pageLayoutSnapshot(page);try{const r=await json('/api/v1/ui/layouts/'+encodeURIComponent(page),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({layout})});UI_LAYOUTS[page]={layout,updated_by:ME.username,updated_at:r.updated_at};document.querySelectorAll('[data-layout-state]').forEach(x=>x.textContent='Saved')}catch(e){document.querySelectorAll('[data-layout-state]').forEach(x=>x.textContent='Save failed')}}
async function resetPageLayout(event){event?.preventDefault();const page=currentLayoutPage();if(!ME||ME.role!=='admin')return;if(!confirm('Reset card positions on this page to the GODSEYE default layout?'))return;try{await json('/api/v1/ui/layouts/'+encodeURIComponent(page),{method:'DELETE'});delete UI_LAYOUTS[page];location.reload()}catch(e){alert(e.message)}}
const layoutObserver=new MutationObserver(()=>{if(!LAYOUT_EDITING){clearTimeout(window.__layoutRefresh);window.__layoutRefresh=setTimeout(registerLayoutZones,120)}});
document.addEventListener('DOMContentLoaded',()=>{const app=document.getElementById('app');if(app)layoutObserver.observe(app,{childList:true,subtree:true})});

function applyTheme(theme,persist=true){
 const next=theme==='dark'?'dark':'light';
 document.documentElement.dataset.theme=next;
 document.body?.setAttribute('data-theme',next);
 const icon=document.getElementById('themeIcon'),label=document.getElementById('themeLabel'),button=document.getElementById('themeToggle');
 if(icon)icon.textContent=next==='dark'?'☀':'☾';
 if(label)label.textContent=next==='dark'?'Light':'Dark';
 if(button){
  button.title=next==='dark'?'Switch to light mode':'Switch to dark mode';
  button.setAttribute('aria-label',button.title);
  button.setAttribute('aria-pressed',next==='dark'?'true':'false');
 }
 if(persist){try{localStorage.setItem('godseye_theme',next)}catch(e){}}
}
function toggleTheme(){applyTheme(document.documentElement.dataset.theme==='dark'?'light':'dark')}
function initializeTheme(){
 let saved=null;
 try{saved=localStorage.getItem('godseye_theme')}catch(e){}
 if(saved!=='dark'&&saved!=='light'){
  saved=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
 }
 applyTheme(saved,false);
}

function headerHelpTextFor(container){
  const nodes=[];
  if(container.classList.contains('hero')){
    container.querySelectorAll(':scope > div > .muted, :scope > div > p').forEach(n=>nodes.push(n));
  }else{
    container.querySelectorAll(':scope > .muted, :scope > div > .muted, :scope > div > p').forEach(n=>nodes.push(n));
  }
  const texts=[];
  nodes.forEach(n=>{
    const text=(n.textContent||'').trim();
    if(text&&!texts.includes(text))texts.push(text);
    n.classList.add('header-help-copy');
    n.style.display='none';
  });
  return texts.join('\n\n');
}
function decorateHeaderHelp(){
  document.querySelectorAll('.view .hero, .view .table-head').forEach(container=>{
    if(container.dataset.headerHelpReady==='1')return;
    const heading=container.querySelector('h1,h2');
    if(!heading)return;
    const text=headerHelpTextFor(container);
    if(!text)return;
    const wrapper=document.createElement('span');
    wrapper.className='header-help-title';
    heading.parentNode.insertBefore(wrapper,heading);
    wrapper.appendChild(heading);
    const btn=document.createElement('button');
    btn.type='button';
    btn.className='header-help-btn';
    btn.textContent='?';
    btn.title='More information';
    btn.setAttribute('aria-label','More information about '+(heading.textContent||'this section').trim());
    btn.addEventListener('click',event=>{
      event.preventDefault();
      event.stopPropagation();
      const extras=[...(container.closest('.panel')?.querySelectorAll('.header-help-extra')||[])]
        .map(n=>(n.textContent||'').trim()).filter(Boolean);
      const helpText=[text,...extras].filter(Boolean).join('\n\n');
      openHeaderHelp((heading.textContent||'Information').trim(),helpText);
    });
    wrapper.appendChild(btn);
    container.dataset.headerHelpReady='1';
  });
}
function openHeaderHelp(title,text){
  const modal=document.getElementById('headerHelpModal');
  if(!modal)return;
  document.getElementById('headerHelpModalTitle').textContent=title||'Information';
  document.getElementById('headerHelpModalBody').textContent=text||'';
  modal.style.display='grid';
  modal.querySelector('.header-help-close')?.focus();
}
function closeHeaderHelp(){
  const modal=document.getElementById('headerHelpModal');
  if(modal)modal.style.display='none';
}
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeHeaderHelp()});
document.addEventListener('click',event=>{
  const modal=document.getElementById('headerHelpModal');
  if(modal&&modal.style.display!=='none'&&event.target===modal)closeHeaderHelp();
});
async function boot(){decorateHeaderHelp();
 initializeTheme();
  try{
    if(!getCookie('godseye_csrf'))await fetch('/api/v1/auth/csrf');
    ME=await json('/api/v1/auth/me');
  }catch(e){showLogin();return}
  const who=document.getElementById('whoami');if(who)who.textContent=ME.username+' ('+ME.role+')';
  const tu=document.getElementById('topUser');if(tu)tu.textContent=ME.username;
  const sb=document.getElementById('scanBtn');if(sb)sb.style.display=['admin','operator'].includes(ME.role)?'inline-block':'none';
  ['navRules','navUsers'].forEach(id=>{const n=document.getElementById(id);if(n)n.style.display=ME.role==='admin'?'':'none'});
  const auditNav=document.getElementById('navAudit');if(auditNav)auditNav.style.display=['admin','auditor'].includes(ME.role)?'':'none';
  applyRoleVisibility();
  await loadUILayouts();
  enableSortableTables();
  const pwBar=document.getElementById('pwReminderBar');
  if(pwBar){
    if(ME.password_change_reminder_days!==undefined){
      pwBar.textContent='⚠ Set a new password within '+ME.password_change_reminder_days+' day(s) — click here to do it now.';
      pwBar.style.display='block';
    }else pwBar.style.display='none';
  }
  showApp();
  const rawHash=(location.hash||'#overview').slice(1);
  showView(document.getElementById('view-'+rawHash)?rawHash:'overview',false);
  Promise.allSettled([
    loadFindings(),
    ME.role==='admin'?loadUsers():Promise.resolve(),
    ['admin','auditor'].includes(ME.role)?loadAudit():Promise.resolve(),
    loadSecurity(),
    ME.role==='admin'?loadRules():Promise.resolve()
  ]);
  setInterval(()=>{
    const ov=document.getElementById('view-overview');
    if(ov&&ov.style.display!=='none')loadDashboard();
  },10000);
}
checkInitialSetup().then(required=>{if(!required)boot()});

document.addEventListener('keydown',e=>{if(e.key!=='Escape')return;const im=document.getElementById('integrationModal'),am=document.getElementById('analyticsModal'),rim=document.getElementById('deleteIntegrationModal'),dm=document.getElementById('deviceModal'),mm=document.getElementById('monitorModal');if(rim&&rim.style.display!=='none'){closeDeleteIntegrationModal();return}if(am&&am.style.display!=='none'){closeAnalyticsModal();return}if(im&&im.style.display!=='none'){closeIntegrationModal();return}if(mm&&mm.style.display!=='none'){closeMonitorEditor();return}if(dm&&dm.style.display!=='none'){closeAddDevice();return}});

const headerHelpObserver=new MutationObserver(()=>decorateHeaderHelp());
document.addEventListener('DOMContentLoaded',()=>{
  decorateHeaderHelp();
  const appRoot=document.getElementById('app');
  if(appRoot)headerHelpObserver.observe(appRoot,{childList:true,subtree:true});
});

let REMOTE_AGENTS=[];
let REMOTE_SESSION=null;
let REMOTE_POLL_TIMER=null;
let REMOTE_MOVE_AT=0;

function remoteCsrf(){const raw=(document.cookie.match('(?:^|; )godseye_csrf=([^;]*)')||[])[1]||'';return decodeURIComponent(raw)}
async function remoteApi(url,opt={}){
 const options={...opt};options.headers={Accept:'application/json',...(opt.headers||{})};const method=String(options.method||'GET').toUpperCase();
 if(method!=='GET'&&method!=='HEAD'){options.headers['X-CSRF-Token']=remoteCsrf();if(options.body&&!options.headers['Content-Type'])options.headers['Content-Type']='application/json'}
 const r=await fetch(url,options);const text=await r.text();if(r.status===401){location.reload();throw new Error('Sign in required')}if(!r.ok)throw new Error(text||('Request failed: '+r.status));if(!text)return{};try{return JSON.parse(text)}catch(_){return{text}}
}

async function loadRemoteAccess(){
 try{REMOTE_AGENTS=await remoteApi('/api/v1/windows-agents');renderRemoteAgents();}
 catch(e){const root=document.getElementById('remoteAgentList');if(root)root.innerHTML=`<div class="empty">${esc(e.message||e)}</div>`;}
}
function renderRemoteAgents(){
 const root=document.getElementById('remoteAgentList');if(!root)return;
 const q=(document.getElementById('remoteSearch')?.value||'').trim().toLowerCase();
 const rows=REMOTE_AGENTS.filter(a=>!q||String(a.computer_name||'').toLowerCase().includes(q)||String(a.hostname||'').toLowerCase().includes(q)||String(a.ip_address||'').toLowerCase().includes(q));
 const online=REMOTE_AGENTS.filter(a=>a.status==='online').length;
 const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v};set('remoteOnlineCount',online);set('remoteOfflineCount',Math.max(0,REMOTE_AGENTS.length-online));set('remoteTotalCount',REMOTE_AGENTS.length);
 root.innerHTML=rows.length?rows.map(a=>{const on=a.status==='online';const supported=!!a.remote_supported;let action='';if(on&&supported)action=`<button class="primary remote-connect" type="button" onclick="startRemoteSession(${a.id})">Connect</button>`;else if(!supported)action=`<button class="secondary remote-connect" type="button" disabled title="Upgrade to Agent 2.2.0 or newer">Upgrade Agent</button>`;else action=`<button class="secondary remote-connect" type="button" disabled>Offline</button>`;if(a.revoked_at||a.status==='revoked')action=`<button class="danger admin-only" type="button" onclick="purgeWindowsAgent(${a.id})">Remove</button>`;return `<div class="remote-agent-row"><div class="remote-agent-main"><div class="remote-agent-name"><span class="remote-dot ${on?'online':'offline'}"></span>${esc(a.computer_name||a.hostname||('Agent '+a.id))}</div><div class="remote-agent-sub">${esc(a.ip_address||'No IP')} · Agent ${esc(a.agent_version||'unknown')} · ${esc(a.os_version||'Windows')}</div></div>${action}</div>`}).join(''):`<div class="empty">No matching Windows Agents.</div>`;
}
async function startRemoteSession(agentId){
 try{
  const r=await remoteApi('/api/v1/remote-access/sessions',{method:'POST',body:JSON.stringify({agent_id:agentId})});REMOTE_SESSION=r.session;
  const a=REMOTE_AGENTS.find(x=>x.id===agentId)||{};document.getElementById('remoteSessionTitle').textContent='Remote Session — '+(a.computer_name||'Windows Agent');
  document.getElementById('remoteSessionStatus').textContent='Waiting for the signed-in Windows user to approve access…';document.getElementById('remoteSessionStatus').classList.add('remote-waiting');
  document.getElementById('remoteDisconnectBtn').disabled=false;document.getElementById('remoteScreenWrap').focus();pollRemoteSession();
 }catch(e){alert(e.message||e);}
}
async function pollRemoteSession(){
 if(!REMOTE_SESSION)return;clearTimeout(REMOTE_POLL_TIMER);
 try{
  const s=await remoteApi(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}`);REMOTE_SESSION=s;
  const status=document.getElementById('remoteSessionStatus');const img=document.getElementById('remoteScreen');const empty=document.getElementById('remoteEmpty');
  status.classList.toggle('remote-waiting',s.status==='connecting');
  if(s.status==='active'){
   status.textContent='Connected · interactive support session active';empty.style.display='none';img.style.display='block';img.src=`${s.frame_url}?t=${Date.now()}`;document.getElementById('remoteScreenshotBtn').disabled=false;
  }else if(s.status==='connecting'){status.textContent='Waiting for local user approval…';}
  else{status.textContent=(s.status==='failed'?'Connection failed: '+(s.last_error||'user declined or desktop unavailable'):'Session ended');img.style.display='none';empty.style.display='flex';document.getElementById('remoteDisconnectBtn').disabled=true;document.getElementById('remoteScreenshotBtn').disabled=true;REMOTE_SESSION=null;return;}
  const meta=document.getElementById('remoteSessionMeta');if(meta)meta.innerHTML=`<span>Computer: <b>${esc(s.computer_name||'—')}</b></span><span>User approval: <b>${s.connected_at?'Approved':'Pending'}</b></span><span>Agent: <b>${esc(s.agent_version||'—')}</b></span><span>Status: <b>${esc(s.status)}</b></span>`;
 }catch(e){}
 if(REMOTE_SESSION)REMOTE_POLL_TIMER=setTimeout(pollRemoteSession,650);
}
async function stopRemoteSession(){if(!REMOTE_SESSION)return;try{await remoteApi(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/stop`,{method:'POST',body:'{}'});}catch(e){}clearTimeout(REMOTE_POLL_TIMER);REMOTE_SESSION=null;const img=document.getElementById('remoteScreen');img.style.display='none';document.getElementById('remoteEmpty').style.display='flex';document.getElementById('remoteDisconnectBtn').disabled=true;document.getElementById('remoteScreenshotBtn').disabled=true;document.getElementById('remoteSessionStatus').textContent='Session ended';}
function openRemoteScreenshot(){if(REMOTE_SESSION)window.open(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/frame?t=${Date.now()}`,'_blank');}
async function sendRemoteInput(payload){if(!REMOTE_SESSION||REMOTE_SESSION.status!=='active')return;try{await remoteApi(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/input`,{method:'POST',body:JSON.stringify(payload)});}catch(e){}}
function remotePointerPayload(ev,action){const img=document.getElementById('remoteScreen');if(!img||img.style.display==='none')return null;const r=img.getBoundingClientRect();if(!r.width||!r.height)return null;const b=ev.button===2?'right':ev.button===1?'middle':'left';return {kind:'pointer',action,x:Math.max(0,Math.min(1,(ev.clientX-r.left)/r.width)),y:Math.max(0,Math.min(1,(ev.clientY-r.top)/r.height)),button:b};}
(function(){
 const bind=()=>{const wrap=document.getElementById('remoteScreenWrap');const img=document.getElementById('remoteScreen');if(!wrap||!img||wrap.dataset.remoteBound)return;wrap.dataset.remoteBound='1';wrap.addEventListener('contextmenu',e=>e.preventDefault());img.addEventListener('mousemove',e=>{const n=Date.now();if(n-REMOTE_MOVE_AT<80)return;REMOTE_MOVE_AT=n;const p=remotePointerPayload(e,'move');if(p)sendRemoteInput(p)});img.addEventListener('mousedown',e=>{e.preventDefault();wrap.focus();const p=remotePointerPayload(e,'down');if(p)sendRemoteInput(p)});img.addEventListener('mouseup',e=>{e.preventDefault();const p=remotePointerPayload(e,'up');if(p)sendRemoteInput(p)});wrap.addEventListener('wheel',e=>{if(!REMOTE_SESSION)return;e.preventDefault();sendRemoteInput({kind:'wheel',delta:e.deltaY<0?120:-120})},{passive:false});wrap.addEventListener('keydown',e=>{if(!REMOTE_SESSION||REMOTE_SESSION.status!=='active')return;if([116,123].includes(e.keyCode))return;e.preventDefault();sendRemoteInput({kind:'keyboard',action:'down',vk:e.keyCode})});wrap.addEventListener('keyup',e=>{if(!REMOTE_SESSION||REMOTE_SESSION.status!=='active')return;e.preventDefault();sendRemoteInput({kind:'keyboard',action:'up',vk:e.keyCode})});};
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bind);else setTimeout(bind,0);
 document.addEventListener('click',e=>{const nav=e.target.closest&&e.target.closest('[data-view="remote-access"]');if(nav)setTimeout(loadRemoteAccess,0)});
})();
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
    credential: str | None = None

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

class ClearReasonRequest(BaseModel):
    reason: str

    def clean_reason(self) -> str:
        reason = (self.reason or "").strip()
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
