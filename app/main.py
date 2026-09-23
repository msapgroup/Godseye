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
import imaplib
import smtplib
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from contextlib import asynccontextmanager
from pathlib import Path
from email.message import EmailMessage
from email.utils import formatdate

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse, RedirectResponse
from pydantic import BaseModel, field_validator
from PIL import Image, UnidentifiedImageError

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
from .cyber_tools import (CyberScheduleManager, SCHEDULABLE_TOOLS, capabilities as cyber_capabilities,
                          ensure_schema as ensure_cyber_schema, execute as execute_cyber_tool,
                          public_run as public_cyber_run, record_run as record_cyber_run,
                          utcnow as cyber_utcnow)

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

EYE_LOGO = '<svg class="eye-logo godseye-g-mark" viewBox="0 0 72 72" role="img" aria-label="GODSEYE sideways G logo"><path d="M59 13H29L10 36l19 23h30V39H42" fill="none" stroke="#27b5ff" stroke-width="11" stroke-linecap="square" stroke-linejoin="miter"/><path d="M59 59V39H42" fill="none" stroke="#736dff" stroke-width="11" stroke-linecap="square" stroke-linejoin="miter"/><path d="M55 19H32L18 36" fill="none" stroke="#c4f5ff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" opacity=".78"/></svg>'

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
            last_state_at TEXT,
            connected_at TEXT,
            ended_at TEXT,
            last_frame_at TEXT,
            last_width INTEGER NOT NULL DEFAULT 0,
            last_height INTEGER NOT NULL DEFAULT 0,
            frame_seq INTEGER NOT NULL DEFAULT 0,
            control_status TEXT NOT NULL DEFAULT 'view_only',
            control_requested_at TEXT,
            control_decided_at TEXT,
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
        CREATE TABLE IF NOT EXISTS ui_user_layouts (
            user_id INTEGER NOT NULL,
            page_key TEXT NOT NULL,
            layout_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            PRIMARY KEY(user_id, page_key)
        );
        CREATE INDEX IF NOT EXISTS idx_ui_user_layouts_user ON ui_user_layouts(user_id,page_key);
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
        _add_column_if_missing(c, "calendar_integrations", "auth_username", "auth_username TEXT DEFAULT ''")
        _add_column_if_missing(c, "calendar_integrations", "auth_password_enc", "auth_password_enc TEXT DEFAULT ''")
        _add_column_if_missing(c, "calendar_integrations", "server_host", "server_host TEXT DEFAULT ''")
        _add_column_if_missing(c, "calendar_integrations", "server_port", "server_port INTEGER DEFAULT 443")
        _add_column_if_missing(c, "tickets", "requester_name", "requester_name TEXT DEFAULT ''")
        _add_column_if_missing(c, "tickets", "requester_department", "requester_department TEXT DEFAULT ''")
        _add_column_if_missing(c, "tickets", "requester_phone", "requester_phone TEXT DEFAULT ''")
        _add_column_if_missing(c, "tickets", "requester_email", "requester_email TEXT DEFAULT ''")
        _add_column_if_missing(c, "tickets", "agent_request_id", "agent_request_id TEXT DEFAULT ''")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tickets_agent_request ON tickets(agent_request_id) WHERE agent_request_id <> ''")
        _add_column_if_missing(c, "email_integrations", "auth_mode", "auth_mode TEXT NOT NULL DEFAULT 'oauth'")
        _add_column_if_missing(c, "email_integrations", "password_enc", "password_enc TEXT DEFAULT ''")
        _add_column_if_missing(c, "email_integrations", "imap_host", "imap_host TEXT DEFAULT ''")
        _add_column_if_missing(c, "email_integrations", "imap_port", "imap_port INTEGER DEFAULT 993")
        _add_column_if_missing(c, "email_integrations", "smtp_host", "smtp_host TEXT DEFAULT ''")
        _add_column_if_missing(c, "email_integrations", "smtp_port", "smtp_port INTEGER DEFAULT 587")
        _add_column_if_missing(c, "audit_log", "protected_until", "protected_until TEXT")
        _add_column_if_missing(c, "event_findings", "agent_id", "agent_id INTEGER")
        _add_column_if_missing(c, "windows_remote_sessions", "frame_seq", "frame_seq INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(c, "windows_remote_sessions", "control_status", "control_status TEXT NOT NULL DEFAULT 'view_only'")
        _add_column_if_missing(c, "windows_remote_sessions", "control_requested_at", "control_requested_at TEXT")
        _add_column_if_missing(c, "windows_remote_sessions", "control_decided_at", "control_decided_at TEXT")
        _add_column_if_missing(c, "windows_remote_sessions", "last_state_at", "last_state_at TEXT")
        c.execute("UPDATE windows_remote_sessions SET last_state_at=COALESCE(last_state_at,last_frame_at,connected_at,requested_at)")
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
        ensure_cyber_schema(c)
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
    cyber_schedule_manager=CyberScheduleManager(db,DB_PATH.parent)
    app.state.cyber_schedule_manager=cyber_schedule_manager
    cyber_schedule_manager.start()
    yield
    cyber_schedule_manager.stop()
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

@app.get("/assets/dashboard-map-reference.png", include_in_schema=False)
def dashboard_map_reference():
    return FileResponse(BASE_DIR / "app" / "assets" / "dashboard-map-reference.png", media_type="image/png", headers={"Cache-Control":"public, max-age=86400"})

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
    """Return effective layouts: appliance defaults plus this user's overrides."""
    with db() as c:
        defaults = c.execute("SELECT page_key,layout_json,updated_by,updated_at FROM ui_layouts ORDER BY page_key").fetchall()
        personal = c.execute("SELECT page_key,layout_json,updated_at FROM ui_user_layouts WHERE user_id=? ORDER BY page_key", (user["id"],)).fetchall()
    layouts = {}
    for row in defaults:
        try:
            layouts[row["page_key"]] = {"layout": json.loads(row["layout_json"]), "updated_by": row["updated_by"], "updated_at": row["updated_at"], "scope": "default"}
        except Exception:
            continue
    for row in personal:
        try:
            layouts[row["page_key"]] = {"layout": json.loads(row["layout_json"]), "updated_by": user["username"], "updated_at": row["updated_at"], "scope": "personal"}
        except Exception:
            continue
    return {"layouts": layouts}


@app.put(f"{router_prefix}/ui/layouts/{{page_key}}/personal")
def save_personal_ui_layout(page_key: str, payload: UILayoutRequest, request: Request, user=Depends(get_current_user)):
    if not re.fullmatch(r"[a-z0-9_-]{1,80}", page_key):
        raise HTTPException(400, "Invalid page key")
    encoded = json.dumps(payload.layout, separators=(",", ":"), sort_keys=True)
    if len(encoded) > 50000:
        raise HTTPException(413, "Layout is too large")
    stamp = now()
    with db() as c:
        c.execute(
            "INSERT INTO ui_user_layouts(user_id,page_key,layout_json,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(user_id,page_key) DO UPDATE SET layout_json=excluded.layout_json,updated_at=excluded.updated_at",
            (user["id"], page_key, encoded, stamp),
        )
        audit(c, user["username"], "ui_personal_layout_saved", target=page_key, details=f"zones={len(payload.layout)}", ip=client_ip(request))
    return {"ok": True, "page_key": page_key, "updated_at": stamp, "scope": "personal"}


@app.delete(f"{router_prefix}/ui/layouts/{{page_key}}/personal")
def reset_personal_ui_layout(page_key: str, request: Request, user=Depends(get_current_user)):
    if not re.fullmatch(r"[a-z0-9_-]{1,80}", page_key):
        raise HTTPException(400, "Invalid page key")
    with db() as c:
        c.execute("DELETE FROM ui_user_layouts WHERE user_id=? AND page_key=?", (user["id"], page_key))
        audit(c, user["username"], "ui_personal_layout_reset", target=page_key, ip=client_ip(request))
    return {"ok": True, "page_key": page_key, "scope": "personal"}


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
    auth_username: str = ""
    auth_password: str = ""
    server_host: str = ""
    server_port: int = 443
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
    headers={"User-Agent":"GODSEYE/Calendar"}
    if integration["auth_mode"]=="basic" and integration["auth_username"]:
        import base64
        headers["Authorization"]="Basic "+base64.b64encode((integration["auth_username"]+":"+decrypt_secret(integration["auth_password_enc"])).encode()).decode()
    req=urllib.request.Request(url,headers=headers)
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
    if mode not in {"oauth","ics","basic"}: raise HTTPException(400,"Authentication mode must be oauth, app-password, or ics")
    name=req.name.strip()
    if not name: raise HTTPException(400,"Integration name is required")
    ics_enc=client_secret_enc=""
    status="not_synced"
    auth_username=auth_password_enc=""
    if mode in {"ics","basic"}:
        if not req.ics_url.strip(): raise HTTPException(400,"Calendar subscription (ICS) URL is required")
        _validate_calendar_subscription_url(provider,req.ics_url.strip())
        ics_enc=encrypt_secret(req.ics_url.strip())
        if mode=="basic":
            if not req.auth_username.strip() or not req.auth_password: raise HTTPException(400,"Email address and app password are required")
            auth_username=req.auth_username.strip()[:254];auth_password_enc=encrypt_secret(req.auth_password)
    else:
        if not req.client_id.strip() or not req.client_secret.strip():
            raise HTTPException(400,"OAuth client ID and client secret are required")
        client_secret_enc=encrypt_secret(req.client_secret.strip())
        status="needs_authorization"
    remote=req.remote_calendar_id.strip() or ("primary" if provider=="google" else "default")
    ts=now()
    with db() as c:
        cur=c.execute("""INSERT INTO calendar_integrations(provider,name,account_email,calendar_name,auth_mode,remote_calendar_id,ics_url_enc,client_id,client_secret_enc,auth_username,auth_password_enc,server_host,server_port,
                         enabled,sync_interval_minutes,last_status,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (provider,name,req.account_email.strip()[:254],req.calendar_name.strip()[:200],mode,remote,ics_enc,req.client_id.strip()[:500],client_secret_enc,auth_username,auth_password_enc,req.server_host.strip()[:255],max(1,min(req.server_port,65535)),
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

# Request calendar access at the same time as mail access.  This keeps the
# Outlook/Gmail-style one-account setup: once mail OAuth completes, the same
# delegated grant can be used by the linked calendar integration.
GMAIL_MAIL_SCOPE="https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/calendar"
MICROSOFT_MAIL_SCOPE="offline_access User.Read Mail.ReadWrite Mail.Send Calendars.ReadWrite"

class EmailIntegrationRequest(BaseModel):
    provider: str
    name: str
    account_email: str = ""
    auth_mode: str = "oauth"
    client_id: str = ""
    client_secret: str = ""
    username: str = ""
    password: str = ""
    imap_host: str = ""
    imap_port: int = 993
    smtp_host: str = ""
    smtp_port: int = 587

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

def _mailbox_password(integration):
    return decrypt_secret(integration["password_enc"] or "")

def _mailbox_connect(integration, folder="INBOX"):
    host=(integration["imap_host"] or "").strip()
    if not host: raise HTTPException(409,"IMAP server is not configured")
    try:
        client=imaplib.IMAP4_SSL(host,int(integration["imap_port"] or 993),timeout=15)
        client.login(integration["account_email"] or integration["name"],_mailbox_password(integration));client.select(folder,readonly=False)
        return client
    except Exception as exc: raise HTTPException(502,f"IMAP connection failed: {exc}")

def _mailbox_decode(value):
    try:
        return "".join((part.decode(enc or "utf-8", "replace") if isinstance(part,bytes) else part) for part,enc in decode_header(value or ""))
    except Exception: return str(value or "")

def _mailbox_message(msg, uid, full=False):
    get=lambda key:_mailbox_decode(msg.get(key,""))
    body=""
    if full:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type()=="text/plain" and not part.get_filename(): body=part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8","replace");break
        else: body=(msg.get_payload(decode=True) or b"").decode(msg.get_content_charset() or "utf-8","replace")
    return {"id":str(uid),"thread_id":str(uid),"subject":get("Subject") or "(No subject)","from":get("From"),"to":get("To"),"cc":get("Cc"),"date":get("Date"),"snippet":body[:240],"body":body,"is_read":True,"starred":False,"has_attachments":any(bool(p.get_filename()) for p in msg.walk()) if msg.is_multipart() else False,"provider":"imap_smtp"}

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
    if integration["provider"]=="imap_smtp":
        msg=EmailMessage();msg["From"]=integration["account_email"];msg["To"]=", ".join(_email_addresses(req.to));msg["Cc"]=", ".join(_email_addresses(req.cc));msg["Subject"]=req.subject[:500];msg.set_content(req.body or "")
        try:
            with smtplib.SMTP(integration["smtp_host"],int(integration["smtp_port"] or 587),timeout=15) as smtp:
                smtp.starttls();smtp.login(integration["account_email"],_mailbox_password(integration));smtp.send_message(msg)
        except Exception as exc: raise HTTPException(502,f"SMTP send failed: {exc}")
        return {"ok":True,"provider":"imap_smtp"}
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

def _email_autodiscover(account_email: str):
    """Return Outlook/Gmail-compatible IMAP/SMTP defaults for app-password mail.

    Explicit server fields still win; these defaults make the common Outlook
    setup work from just an email address and provider app password.
    """
    domain=account_email.rsplit("@",1)[-1].lower().strip() if "@" in account_email else ""
    if domain in {"outlook.com","hotmail.com","live.com","msn.com"} or domain.endswith(".onmicrosoft.com"):
        return ("outlook.office365.com",993,"smtp.office365.com",587)
    if domain in {"gmail.com","googlemail.com"}:
        return ("imap.gmail.com",993,"smtp.gmail.com",587)
    return (f"imap.{domain}",993,f"smtp.{domain}",587) if domain else ("",993,"",587)

@app.post(f"{router_prefix}/email/integrations")
def email_integration_create(req: EmailIntegrationRequest, request: Request, user=Depends(require_admin)):
    provider=req.provider.strip().lower()
    mode=req.auth_mode.strip().lower()
    if provider not in {"gmail","microsoft365","imap_smtp"}: raise HTTPException(400,"Provider must be gmail, microsoft365, or standard mailbox")
    if not req.name.strip(): raise HTTPException(400,"Mailbox name is required")
    if provider=="imap_smtp" or mode=="password":
        provider="imap_smtp";mode="password"
        # Standard mailboxes authenticate with the full email address as the
        # username and an app password (never the normal account password).
        mail_username=(req.username.strip() or req.account_email.strip())
        discovered_imap,discovered_imap_port,discovered_smtp,discovered_smtp_port=_email_autodiscover(mail_username)
        imap_host=(req.imap_host.strip() or discovered_imap)
        smtp_host=(req.smtp_host.strip() or discovered_smtp)
        imap_port=req.imap_port or discovered_imap_port
        smtp_port=req.smtp_port or discovered_smtp_port
        if "@" not in mail_username or not req.password or not imap_host or not smtp_host:
            raise HTTPException(400,"Email username, app password, IMAP server, and SMTP server are required")
        status="connected"
    else:
        mode="oauth"
        if not req.client_id.strip() or not req.client_secret.strip(): raise HTTPException(400,"OAuth client ID and client secret are required")
        status="needs_authorization"
    ts=now()
    with db() as c:
        iid=c.execute("""INSERT INTO email_integrations(provider,name,account_email,client_id,client_secret_enc,auth_mode,password_enc,imap_host,imap_port,smtp_host,smtp_port,enabled,last_status,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)""",
                      (provider,req.name.strip()[:160],(mail_username if provider=="imap_smtp" else req.account_email.strip())[:254],req.client_id.strip()[:500],encrypt_secret(req.client_secret.strip()),mode,encrypt_secret(req.password) if req.password else "",(imap_host if provider=="imap_smtp" else req.imap_host.strip())[:255],max(1,min((imap_port if provider=="imap_smtp" else req.imap_port),65535)),(smtp_host if provider=="imap_smtp" else req.smtp_host.strip())[:255],max(1,min((smtp_port if provider=="imap_smtp" else req.smtp_port),65535)),status,ts,ts)).lastrowid
        audit(c,user["username"],"email_integration_created",str(iid),json.dumps({"provider":provider,"name":req.name.strip()}),client_ip(request))
    return {"ok":True,"id":iid,"needs_authorization":status!="connected","auth_mode":mode}

def _ensure_calendar_for_email(c, email_row, username=""):
    """Create/update the provider calendar that belongs to a connected mailbox.

    Mail and calendar are one account from the operator's perspective. Keep
    the calendar row separate (the sync worker expects that table), but reuse
    the OAuth client and delegated tokens so no second setup wizard is needed.
    """
    provider=email_row["provider"]
    if provider not in {"gmail","microsoft365"} or not email_row["refresh_token_enc"]:
        return None
    existing=c.execute("SELECT * FROM calendar_integrations WHERE provider=? AND account_email=? ORDER BY id LIMIT 1",
                       (provider,email_row["account_email"] or "")).fetchone()
    ts=now()
    remote="primary" if provider=="gmail" else "default"
    if existing:
        c.execute("""UPDATE calendar_integrations SET client_id=?,client_secret_enc=?,access_token_enc=?,
                     refresh_token_enc=?,token_expires_at=?,auth_mode='oauth',remote_calendar_id=?,
                     enabled=1,last_status='connected',last_error='',updated_at=? WHERE id=?""",
                  (email_row["client_id"],email_row["client_secret_enc"],email_row["access_token_enc"],
                   email_row["refresh_token_enc"],email_row["token_expires_at"],remote,ts,existing["id"]))
        return existing["id"]
    name=("Gmail Calendar" if provider=="gmail" else "Microsoft 365 Calendar")
    cur=c.execute("""INSERT INTO calendar_integrations(provider,name,account_email,calendar_name,auth_mode,
                 remote_calendar_id,client_id,client_secret_enc,access_token_enc,refresh_token_enc,
                 token_expires_at,enabled,sync_interval_minutes,last_status,created_at,updated_at)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (provider,name,email_row["account_email"] or "",name,"oauth",remote,email_row["client_id"],
                   email_row["client_secret_enc"],email_row["access_token_enc"],email_row["refresh_token_enc"],
                   email_row["token_expires_at"],1,30,"connected",ts,ts))
    return cur.lastrowid

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
        connected_row=c.execute("SELECT * FROM email_integrations WHERE id=?",(row["id"],)).fetchone()
        _ensure_calendar_for_email(c,connected_row,saved["created_by"])
        audit(c,saved["created_by"],"email_oauth_connected",str(row["id"]),json.dumps({"provider":provider,"calendar_auto_setup":True}),None)
    name="Gmail" if provider=="gmail" else "Microsoft 365"
    html="<!doctype html><html><body style=\"font-family:system-ui;background:#0b1119;color:#fff;padding:40px\"><h2>"+name+" connected</h2><p>Your calendar was set up automatically. You can close this window and return to GODSEYE.</p><script>if(window.opener)window.opener.postMessage({type:'godseye-email-connected',calendarConnected:true},window.location.origin);setTimeout(()=>window.close(),900);</script></body></html>"
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
        integration=_email_integration_row(c,integration_id)
        if integration["provider"]=="imap_smtp":
            client=_mailbox_connect(integration);_,boxes=client.list();client.logout();return [{"id":(b.decode(errors="replace").split(' "/" ')[-1].strip('"') if isinstance(b,bytes) else str(b)),"name":(b.decode(errors="replace").split(' "/" ')[-1].strip('"') if isinstance(b,bytes) else str(b)),"unread":0,"total":0} for b in (boxes or [])]
        token=_email_access_token(c,integration);headers=_email_headers(integration,token)
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
        integration=_email_integration_row(c,integration_id)
        if integration["provider"]=="imap_smtp":
            client=_mailbox_connect(integration,folder.upper() if folder else "INBOX");criteria=f'(TEXT "{q.strip()[:120]}")' if q.strip() else 'ALL';_,data=client.uid('search',None,criteria);uids=(data[0].split() if data and data[0] else [])[-limit:][::-1];out=[]
            for uid in uids:
                _,parts=client.uid('fetch',uid,b'(RFC822)');raw=next((p[1] for p in parts if isinstance(p,tuple)),b'');out.append(_mailbox_message(BytesParser(policy=policy).parsebytes(raw),uid.decode()))
            client.logout();return {"messages":out,"next_page_token":None}
        token=_email_access_token(c,integration);headers=_email_headers(integration,token)
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
    updates: list[dict] = []
    installed_update_ids: list[str] = []

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

class WindowsRemoteControlDecisionRequest(BaseModel):
    approved: bool = False

class WindowsAgentTicketRequest(BaseModel):
    request_id: str
    requester_name: str
    requester_department: str = ""
    requester_phone: str = ""
    requester_email: str = ""
    category: str = "Other"
    issue_notes: str


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
        result={"ok":bool(req.ok),"events":max(0,int(req.events or 0)),"new_findings":max(0,int(req.new_findings or 0)),"details":req.details[:4000],"completed_at":req.completed_at or ts,"updates":req.updates[:500],"installed_update_ids":req.installed_update_ids[:500]}
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
    except (OSError, ValueError, json.JSONDecodeError):
        # Release packages are stored as GitHub Release assets rather than in
        # the server repository. Keep managed updates available on fresh
        # server installs even when the optional local MSI is absent.
        return {"version":"2.4.4","sha256":"C9C513F5020FDBD1D9309578F7610EBC3D8605E542D700791673AC4CE6E04299","filename":"GODSEYE-Windows-Agent-x64.msi","url":"https://github.com/msapgroup/Godseye/releases/download/v4.31.0-agent-2.4.4/GODSEYE-Windows-Agent-x64.msi"}


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

@app.post(f"{router_prefix}/windows-agents/{{agent_id}}/windows-updates/scan")
def windows_agent_windows_updates_scan(agent_id: int, request: Request, user=Depends(require_permission("operate"))):
    ts=now()
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not agent or not agent["enabled"] or agent["revoked_at"]: raise HTTPException(404,"Windows Agent not found or disabled")
        cur=c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'scan_windows_updates','{}','pending',?,?)",(agent_id,user["username"],ts))
        cid=cur.lastrowid
    return {"ok":True,"command_id":cid,"status":"pending","message":"Microsoft Windows Update scan queued."}

@app.post(f"{router_prefix}/windows-agents/{{agent_id}}/windows-updates/install")
def windows_agent_windows_updates_install(agent_id: int, payload: dict, request: Request, user=Depends(require_permission("operate"))):
    ids=[str(x)[:300] for x in (payload.get("update_ids") or []) if str(x).strip()][:200]
    if not ids: raise HTTPException(400,"Select at least one Windows update")
    ts=now()
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not agent or not agent["enabled"] or agent["revoked_at"]: raise HTTPException(404,"Windows Agent not found or disabled")
        cur=c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'install_windows_updates',?,'pending',?,?)",(agent_id,json.dumps({"update_ids":ids},separators=(",",":")),user["username"],ts))
        cid=cur.lastrowid
    return {"ok":True,"command_id":cid,"status":"pending","message":"Microsoft Windows Update installation queued."}

@app.get(f"{router_prefix}/windows-agents/commands/{{command_id}}")
def windows_agent_command_status(command_id: int, user=Depends(require_permission("operate"))):
    with db() as c:
        row=c.execute("SELECT id,agent_id,command_type,status,result_json,requested_at,completed_at FROM windows_agent_commands WHERE id=?",(command_id,)).fetchone()
        if not row: raise HTTPException(404,"Windows Agent command not found")
    out=dict(row)
    try: out["result"]=json.loads(out.pop("result_json") or "{}")
    except Exception: out["result"]={}
    return out

@app.post(f"{router_prefix}/windows-agents/{{agent_id}}/clamav-scan")
def windows_agent_clamav_scan(agent_id: int, request: Request, user=Depends(require_permission("operate"))):
    ts=now()
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not agent: raise HTTPException(404,"Windows Agent not found")
        if not agent["enabled"] or agent["revoked_at"]: raise HTTPException(409,"Windows Agent is disabled or revoked")
        cur=c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'clamav_scan','{}','pending',?,?)",(agent_id,user["username"],ts))
        cid=cur.lastrowid
        audit(c,user["username"],"windows_agent_clamav_scan_requested",str(agent_id),json.dumps({"command_id":cid,"computer_name":agent["computer_name"]}),client_ip(request))
    return {"ok":True,"queued":True,"command_id":cid,"status":"pending","message":"ClamAV scan queued. The agent will run clamscan when it next checks in."}


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
            d["remote_supported"]=_agent_version_tuple(installed_version) >= (2,4,0)
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
    # Production installs keep application files read-only. The database parent
    # is the configured writable GODSEYE data directory (normally /var/lib/godseye).
    root=DB_PATH.parent / "remote-frames"
    root.mkdir(parents=True,exist_ok=True)
    return root / f"session-{int(session_id)}.jpg"


def _remote_session_public(row):
    if not row: return None
    d=dict(row)
    d["frame_url"]=f"{router_prefix}/remote-access/sessions/{d['id']}/frame"
    return d


def _expire_stale_remote_session(c, row):
    if not row or row["status"] in {"ended","failed","denied"}:
        return row
    current=dt.datetime.now(dt.timezone.utc)
    try:
        stamp=row["last_frame_at"] if row["status"]=="active" else (row["last_state_at"] or row["requested_at"])
        changed=dt.datetime.fromisoformat(stamp)
        if changed.tzinfo is None: changed=changed.replace(tzinfo=dt.timezone.utc)
        age=(current-changed).total_seconds()
    except Exception:
        age=0
    limits={"waiting_for_user":300,"approved":90,"capture_started":45,"active":30}
    limit=limits.get(row["status"],120)
    if age <= limit:
        return row
    if row["status"]=="active":
        error="Remote screen frames stopped arriving. Start a new remote session."
    elif row["status"] in {"approved","capture_started"}:
        error="Remote screen capture did not start after approval. Start a new session; Agent 2.4.4 fixes writable frame storage."
    else:
        error=f"Remote session timed out while {row['status'].replace('_',' ')}. Start a new remote session."
    ts=now()
    c.execute("UPDATE windows_remote_sessions SET status='failed',ended_at=?,last_state_at=?,last_error=? WHERE id=?",(ts,ts,error,row["id"]))
    for command in c.execute("SELECT id,payload_json FROM windows_agent_commands WHERE agent_id=? AND command_type='remote_session_start' AND status IN ('pending','delivered')",(row["agent_id"],)).fetchall():
        try: command_session_id=int(json.loads(command["payload_json"] or "{}").get("session_id") or 0)
        except (TypeError,ValueError,json.JSONDecodeError): command_session_id=0
        if command_session_id==int(row["id"]):
            c.execute("UPDATE windows_agent_commands SET status='failed',completed_at=?,result_json=? WHERE id=?",(ts,json.dumps({"ok":False,"details":error}),command["id"]))
    return c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(row["id"],)).fetchone()


@app.post(f"{router_prefix}/remote-access/sessions")
def windows_remote_start(req: WindowsRemoteStartRequest, request: Request, user=Depends(require_admin)):
    ts=now(); nowdt=dt.datetime.now(dt.timezone.utc)
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(req.agent_id,)).fetchone()
        if not agent: raise HTTPException(404,"Windows Agent not found")
        if not agent["enabled"] or agent["revoked_at"]: raise HTTPException(409,"Windows Agent is disabled or revoked")
        if _agent_version_tuple(agent["agent_version"] or "") < (2,4,0):
            raise HTTPException(409,"Windows Agent 2.4.0 or newer is required for v4.31 Remote Access. Upgrade this computer first.")
        if not agent["last_heartbeat_at"]: raise HTTPException(409,"Windows Agent is offline")
        try:
            hb=dt.datetime.fromisoformat(agent["last_heartbeat_at"]); hb=hb if hb.tzinfo else hb.replace(tzinfo=dt.timezone.utc)
            if (nowdt-hb).total_seconds()>180: raise HTTPException(409,"Windows Agent is offline")
        except HTTPException: raise
        except Exception: raise HTTPException(409,"Windows Agent heartbeat is invalid")
        existing=c.execute("SELECT * FROM windows_remote_sessions WHERE agent_id=? AND status IN ('requested','waiting_for_tray','tray_ready','waiting_for_user','approved','capture_started','active') ORDER BY id DESC LIMIT 1",(req.agent_id,)).fetchone()
        existing=_expire_stale_remote_session(c,existing)
        if existing and existing["status"] not in {"ended","failed","denied"}: return {"ok":True,"session":_remote_session_public(existing),"message":"A remote support session is already open for this computer."}
        cur=c.execute("INSERT INTO windows_remote_sessions(agent_id,status,requested_by,requested_at,last_state_at) VALUES(?,'requested',?,?,?)",(req.agent_id,user["username"],ts,ts))
        sid=cur.lastrowid
        payload=json.dumps({"session_id":sid,"requested_by":user["username"]},separators=(",",":"))
        c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'remote_session_start',?,'pending',?,?)",(req.agent_id,payload,user["username"],ts))
        audit(c,user["username"],"windows_remote_session_requested",str(sid),json.dumps({"agent_id":req.agent_id,"computer_name":agent["computer_name"]}),client_ip(request))
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(sid,)).fetchone()
    return {"ok":True,"session":_remote_session_public(row),"message":"Remote support request sent. The signed-in Windows user must approve the connection."}


@app.get(f"{router_prefix}/remote-access/sessions/{{session_id}}")
def windows_remote_session(session_id: int, user=Depends(get_current_user)):
    with db() as c:
        session=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
        _expire_stale_remote_session(c,session)
        row=c.execute("SELECT s.*,a.computer_name,a.hostname,a.ip_address,a.os_version,a.agent_version FROM windows_remote_sessions s JOIN windows_agents a ON a.id=s.agent_id WHERE s.id=?",(session_id,)).fetchone()
    if not row: raise HTTPException(404,"Remote support session not found")
    return _remote_session_public(row)


@app.post(f"{router_prefix}/remote-access/sessions/{{session_id}}/stop")
def windows_remote_stop(session_id: int, request: Request, user=Depends(require_admin)):
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] not in ("ended","failed","denied"):
            c.execute("UPDATE windows_remote_sessions SET status='ended',ended_at=?,last_state_at=? WHERE id=?",(ts,ts,session_id))
            c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'remote_session_stop',?,'pending',?,?)",(row["agent_id"],json.dumps({"session_id":session_id}),user["username"],ts))
            audit(c,user["username"],"windows_remote_session_stopped",str(session_id),"",client_ip(request))
    return {"ok":True}


@app.get(f"{router_prefix}/remote-access/sessions/{{session_id}}/frame")
def windows_remote_frame(session_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT id,frame_seq FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
    if not row: raise HTTPException(404,"Remote support session not found")
    path=_remote_frame_path(session_id)
    if not path.exists(): return Response(status_code=204,headers={"Cache-Control":"no-store"})
    return Response(content=path.read_bytes(),media_type="image/jpeg",headers={"Cache-Control":"no-store, max-age=0","X-GODSEYE-Frame-Sequence":str(int(row["frame_seq"] or 0))})


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
        if row["status"] != "active": raise HTTPException(409,"Remote support session is not active")
        if row["control_status"] != "approved": raise HTTPException(409,"The signed-in Windows user has not approved remote control")
        if kind=="pointer" and action=="move":
            stale_ids=[]
            for pending in c.execute("SELECT id,event_json FROM windows_remote_events WHERE session_id=? AND delivered_at IS NULL",(session_id,)).fetchall():
                try:
                    pending_event=json.loads(pending["event_json"] or "{}")
                except (TypeError,ValueError,json.JSONDecodeError):
                    pending_event={}
                if pending_event.get("kind")=="pointer" and pending_event.get("action")=="move": stale_ids.append(int(pending["id"]))
            if stale_ids:
                marks=",".join("?" for _ in stale_ids)
                c.execute(f"DELETE FROM windows_remote_events WHERE id IN ({marks})",stale_ids)
        c.execute("INSERT INTO windows_remote_events(session_id,event_json,created_at) VALUES(?,?,?)",(session_id,json.dumps(event,separators=(",",":")),now()))
    return {"ok":True}


@app.post(f"{router_prefix}/remote-access/sessions/{{session_id}}/control/request")
def windows_remote_control_request(session_id: int, request: Request, user=Depends(require_admin)):
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] != "active": raise HTTPException(409,"Screen sharing must be active before requesting control")
        if row["control_status"] not in {"view_only","denied"}: return {"ok":True,"control_status":row["control_status"]}
        c.execute("UPDATE windows_remote_sessions SET control_status='requested',control_requested_at=?,control_decided_at=NULL WHERE id=?",(ts,session_id))
        audit(c,user["username"],"windows_remote_control_requested",str(session_id),"",client_ip(request))
    return {"ok":True,"control_status":"requested"}


@app.post(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/frame")
def windows_remote_agent_frame(session_id: int, req: WindowsRemoteFrameRequest, agent=Depends(_agent_auth)):
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] not in {"capture_started","active"}:
            raise HTTPException(409,"Remote support session is not ready to accept screen frames")
        try:
            raw=base64.b64decode(req.image_base64,validate=True)
        except Exception:
            raise HTTPException(400,"Invalid remote frame encoding")
        if len(raw)<128 or len(raw)>5*1024*1024 or not (raw.startswith(b"\xff\xd8") and raw.endswith(b"\xff\xd9")):
            raise HTTPException(400,"Invalid remote JPEG frame")
        try:
            import io
            with Image.open(io.BytesIO(raw)) as image:
                if image.format != "JPEG": raise HTTPException(400,"Remote frame must be JPEG")
                image.verify()
            with Image.open(io.BytesIO(raw)) as image:
                actual_width,actual_height=image.size
        except HTTPException:
            raise
        except (UnidentifiedImageError,OSError,ValueError):
            raise HTTPException(400,"Remote JPEG frame failed image validation")
        if actual_width<1 or actual_height<1 or actual_width>10000 or actual_height>10000:
            raise HTTPException(400,"Remote JPEG dimensions are invalid")
        path=_remote_frame_path(session_id);tmp=path.with_suffix('.tmp');tmp.write_bytes(raw);tmp.replace(path)
        ts=now();connected=row["connected_at"] or ts;new_seq=int(row["frame_seq"] or 0)+1
        c.execute("UPDATE windows_remote_sessions SET status='active',connected_at=?,last_frame_at=?,last_state_at=?,last_width=?,last_height=?,frame_seq=?,last_error='' WHERE id=?",(connected,ts,ts,actual_width,actual_height,new_seq,session_id))
    return {"ok":True,"status":"active","width":actual_width,"height":actual_height,"sequence":new_seq}


@app.get(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/events")
def windows_remote_agent_events(session_id: int, after: int=0, agent=Depends(_agent_auth)):
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        active=row["status"] in {"capture_started","active"}
        control_allowed=row["control_status"] == "approved"
        events=c.execute("SELECT * FROM windows_remote_events WHERE session_id=? AND id>? AND delivered_at IS NULL ORDER BY id LIMIT 100",(session_id,max(0,int(after)))).fetchall() if active and control_allowed else []
        if events:
            ids=[r["id"] for r in events]; marks=','.join('?' for _ in ids)
            c.execute(f"UPDATE windows_remote_events SET delivered_at=? WHERE id IN ({marks})",[now()]+ids)
        out=[]
        for r in events:
            try: ev=json.loads(r["event_json"])
            except Exception: ev={}
            out.append({"event_id":r["id"],"event":ev})
    return {"ok":True,"active":active,"status":row["status"],"control_status":row["control_status"],"events":out}


@app.post(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/control/decision")
def windows_remote_agent_control_decision(session_id: int, req: WindowsRemoteControlDecisionRequest, agent=Depends(_agent_auth)):
    decision="approved" if req.approved else "denied"
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] != "active" or row["control_status"] != "requested":
            raise HTTPException(409,"Remote control permission is not awaiting a user decision")
        c.execute("UPDATE windows_remote_sessions SET control_status=?,control_decided_at=? WHERE id=?",(decision,now(),session_id))
    return {"ok":True,"control_status":decision}


@app.post(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/state")
def windows_remote_agent_state(session_id: int, req: WindowsRemoteStateRequest, agent=Depends(_agent_auth)):
    requested=(req.status or "").lower().strip()
    # Pre-v2.3 agents used `active` to mean that capture had started. Keep
    # compatibility with that signal, but the server never becomes active until
    # the frame endpoint validates a complete JPEG.
    status="capture_started" if requested=="active" else requested
    allowed={"waiting_for_tray","tray_ready","waiting_for_user","approved","capture_started","denied","failed","ended"}
    if status not in allowed: raise HTTPException(400,"Invalid remote support state")
    transitions={
        "requested":{"waiting_for_tray","failed","ended"},
        "waiting_for_tray":{"tray_ready","failed","ended"},
        "tray_ready":{"waiting_for_user","failed","ended"},
        "waiting_for_user":{"approved","denied","failed","ended"},
        "approved":{"capture_started","failed","ended"},
        "capture_started":{"failed","ended"},
        "active":{"failed","ended"},
        "denied":set(),"failed":set(),"ended":set(),
    }
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        current=(row["status"] or "").lower()
        if status!=current and status not in transitions.get(current,set()):
            raise HTTPException(409,f"Invalid remote support transition: {current} -> {status}")
        if status in {"denied","failed","ended"}:
            c.execute("UPDATE windows_remote_sessions SET status=?,ended_at=?,last_state_at=?,last_error=? WHERE id=?",(status,ts,ts,req.error[:1000],session_id))
        else:
            c.execute("UPDATE windows_remote_sessions SET status=?,last_state_at=?,last_error=? WHERE id=?",(status,ts,req.error[:1000],session_id))
    return {"ok":True,"status":status}


@app.post(f"{router_prefix}/windows-agents/tickets")
def windows_agent_submit_ticket(req: WindowsAgentTicketRequest, agent=Depends(_agent_auth)):
    request_id=(req.request_id or "").strip()
    name=(req.requester_name or "").strip()
    notes=(req.issue_notes or "").strip()
    categories={x.lower():x for x in ("Email","Internet","Phone","Hardware","Software","Security","Other")}
    category=categories.get((req.category or "").strip().lower())
    if not request_id or len(request_id)>100: raise HTTPException(400,"A valid ticket request ID is required")
    if not name: raise HTTPException(400,"Requester name is required")
    if not notes: raise HTTPException(400,"Issue notes are required")
    if not category: raise HTTPException(400,"Invalid ticket category")
    email=(req.requester_email or "").strip()
    if email and ("@" not in email or len(email)>254): raise HTTPException(400,"Invalid requester email")
    ts=now()
    with db() as c:
        existing=c.execute("SELECT * FROM tickets WHERE agent_request_id=?",(request_id,)).fetchone()
        if existing: return {"ok":True,"ticket_id":existing["id"],"ticket_number":existing["ticket_number"],"duplicate":True}
        computer=(agent["computer_name"] or agent["hostname"] or f"Agent {agent['id']}").strip()
        title=f"{category} support request ‚Äî {computer}"
        priority="high" if category=="Security" else "medium"
        cur=c.execute("""INSERT INTO tickets(title,description,status,priority,assignee,linked_type,linked_id,device_name,requester_name,requester_department,requester_phone,requester_email,agent_request_id,created_by,created_at,updated_at)
                         VALUES(?,?,'open',?,'','windows_agent',?,?,?,?,?,?,?,?,?,?)""",
                      (title[:240],notes[:8000],priority,agent["id"],computer[:255],name[:160],(req.requester_department or "").strip()[:160],(req.requester_phone or "").strip()[:60],email,request_id,f"windows-agent:{computer}"[:160],ts,ts))
        ticket_id=cur.lastrowid; ticket_number=f"TKT-{ticket_id:05d}"
        c.execute("UPDATE tickets SET ticket_number=? WHERE id=?",(ticket_number,ticket_id))
        audit(c,f"windows-agent:{computer}","ticket_created_from_windows_agent",ticket_number,json.dumps({"agent_id":agent["id"],"category":category}))
    return {"ok":True,"ticket_id":ticket_id,"ticket_number":ticket_number,"duplicate":False}


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
    if not path.exists():
        return RedirectResponse(manifest["url"], status_code=302)
    return FileResponse(path,media_type="application/octet-stream",filename=manifest["filename"],headers={"X-GODSEYE-Agent-Version":manifest["version"],"X-GODSEYE-SHA256":manifest["sha256"]})


@app.get(f"{router_prefix}/windows-agents/package")
def windows_agent_package(user=Depends(require_admin)):
    version="2.4.4"
    versioned_name=f"GODSEYE-Windows-Agent-x64-Setup-{version}.exe"
    path=BASE_DIR / "windows" / "agent-x64" / versioned_name
    if not path.is_file():
        path=BASE_DIR / "windows" / "agent-x64" / "GODSEYE-Windows-Agent-x64-Setup.exe"
    if path.is_file():
        return FileResponse(path,media_type="application/vnd.microsoft.portable-executable",filename=versioned_name,headers={"Cache-Control":"no-store, no-cache, must-revalidate, max-age=0","Pragma":"no-cache","Expires":"0","X-GODSEYE-Agent-Version":version})
    # Release builds are published as GitHub Release assets because the installer
    # exceeds GitHub's repository file-size limit. Fresh installs use that asset.
    return RedirectResponse(
        "https://github.com/msapgroup/Godseye/releases/download/v4.31.0-agent-2.4.4/GODSEYE-Windows-Agent-x64-Setup-2.4.4.exe",
        status_code=302,
        headers={"Cache-Control":"no-store, no-cache, must-revalidate, max-age=0","Pragma":"no-cache","Expires":"0","X-GODSEYE-Agent-Version":version},
    )


@app.get(f"{router_prefix}/windows-agents/package-status")
def windows_agent_package_status(user=Depends(require_admin)):
    setup=BASE_DIR / "windows" / "agent-x64" / "GODSEYE-Windows-Agent-x64-Setup.exe"
    msi=BASE_DIR / "windows" / "agent-x64" / "GODSEYE-Windows-Agent-x64.msi"
    manifest={"version":"2.4.4","status":"pending_build"}
    manifest_path=BASE_DIR / "windows" / "agent-x64" / "update-manifest.json"
    try:
        if manifest_path.is_file(): manifest.update(json.loads(manifest_path.read_text(encoding="utf-8")))
    except (OSError,ValueError,json.JSONDecodeError): pass
    return {
        "available":True,
        "msi_available":msi.is_file(),
        "version":manifest.get("version","2.4.4"),
        "status":manifest.get("status","ready"),
        "message":"Windows Agent 2.4.4 installer is ready from the local package or GitHub Release."
    }


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
    requester_name: str = ""
    requester_department: str = ""
    requester_phone: str = ""
    requester_email: str = ""

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
        cur=c.execute("""INSERT INTO tickets(title,description,status,priority,assignee,linked_type,linked_id,device_name,due_at,requester_name,requester_department,requester_phone,requester_email,created_by,created_at,updated_at)
                         VALUES(?,?,'open',?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (req.title.strip()[:240],req.description.strip()[:8000],req.priority,assignee,req.linked_type.strip()[:40],
                       req.linked_id,req.device_name.strip()[:255],req.due_at,req.requester_name.strip()[:160],req.requester_department.strip()[:160],req.requester_phone.strip()[:60],req.requester_email.strip()[:254],user["username"],ts,ts))
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
            calendar_title=(f"‚úì {d['ticket_number']} ¬∑ {title}" if status in {"resolved","closed"} else f"{d['ticket_number']} ¬∑ {title}")
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
                      (f"{ticket['ticket_number']} ¬∑ {ticket['title']}",ticket["description"],req.start_at,req.end_at,1 if req.all_day else 0,color,ts,ticket["calendar_event_id"]))
            eid=ticket["calendar_event_id"]
        else:
            cur=c.execute("""INSERT INTO calendar_events(title,description,location,start_at,end_at,all_day,color,source,external_uid,external_readonly,created_by,created_at,updated_at)
                             VALUES(?,?,?,?,?,?,?,'ticket',?,0,?,?,?)""",
                          (f"{ticket['ticket_number']} ¬∑ {ticket['title']}",ticket["description"],ticket["device_name"],req.start_at,req.end_at,1 if req.all_day else 0,color,str(ticket_id),user["username"],ts,ts))
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
            c.execute("UPDATE calendar_events SET title=?,color='green',updated_at=? WHERE id=?",(f"‚úì {ticket['ticket_number']} ¬∑ {ticket['title']}",ts,ticket["calendar_event_id"]))
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
<title>GODSEYE ‚Äî Monitoring</title><script>(function(){try{const saved=localStorage.getItem('godseye_theme');const dark=saved!=='light';document.documentElement.dataset.theme=dark?'dark':'light'}catch(e){document.documentElement.dataset.theme='light'}})();</script><style>
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
.integration-tabs{display:flex;gap:4px;border-bottom:1px solid #e2e8f0;padding:0 16px}.integration-tab{padding:11px 14px;border:0;border-bottom:2px solid transparent;background:none;color:#72819a}.integration-tab.active{color:#0f7df0;border-bottom-color:#0f7df0}.integration-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;padding:18px}.checklist{padding:16px;background:#f8fafc;border-radius:8px}.check{font-size:11px;margin:10px 0;color:#52647a}.check:before{content:'‚úì';color:#13a36e;font-weight:800;margin-right:8px}
.intel-modal-card{width:min(980px,96vw);max-height:90vh;overflow:auto}.intel-hero{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:14px 0 4px}.intel-title{display:flex;align-items:center;gap:12px}.intel-big-icon{width:48px;height:48px;border-radius:12px;background:#e8f4ff;color:#0f7df0;display:grid;place-items:center;font-size:22px}.intel-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}.intel-stat{border:1px solid #e2e8f0;border-radius:9px;padding:12px;background:#fbfdff}.intel-stat .k{font-size:9px;color:#7b899b;text-transform:uppercase;letter-spacing:.05em}.intel-stat .v{font-size:17px;font-weight:750;margin-top:4px}.intel-sections{display:grid;grid-template-columns:1fr 1fr;gap:14px}.intel-section{border:1px solid #e2e8f0;border-radius:9px;background:#fff;overflow:hidden}.intel-section h3{font-size:12px;padding:11px 13px;border-bottom:1px solid #edf1f5;margin:0}.intel-body{padding:12px 13px}.intel-kv{display:grid;grid-template-columns:120px 1fr;gap:7px 10px;font-size:11px}.intel-kv .k{color:#78879a}.intel-actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.intel-list{margin:0;padding-left:18px;font-size:11px;color:#4f6278}.intel-list li{margin:7px 0}.timeline{max-height:220px;overflow:auto}.timeline-row{padding:8px 0;border-bottom:1px solid #eef2f6;font-size:10px}.timeline-row:last-child{border-bottom:0}.risk-low{color:#0b9a63}.risk-med{color:#c27a00}.risk-high{color:#d83c55}@media(max-width:800px){.intel-grid{grid-template-columns:repeat(2,1fr)}.intel-sections{grid-template-columns:1fr}}
.top-actions{display:flex;align-items:center;gap:12px}.top-actions .icon-btn{border:0;background:none;color:#52657b;font-size:14px;padding:4px}.user-chip{display:flex;align-items:center;gap:7px;font-size:11px;color:#53657a}.avatar{width:24px;height:24px;border-radius:50%;background:#e7f1ff;color:#1768b5;display:grid;place-items:center;font-size:10px;font-weight:800}
@media(max-width:1050px){.dashboard-grid,.integration-grid{grid-template-columns:1fr}.tool-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:820px){.wrap{padding:18px 14px}.cards{grid-template-columns:repeat(2,1fr)}.dashboard-grid{grid-template-columns:1fr}.tool-grid{grid-template-columns:1fr}.headerbar{padding:10px 14px}.map-children{gap:12px;flex-wrap:wrap;justify-content:center}.sidebar .brand{display:flex}.sidebar{position:sticky}.top-actions .user-chip{display:none}}


/* v3.9 ‚Äî polished per-device traffic collection */
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
.sortable-head{cursor:pointer;user-select:none;position:relative;padding-right:24px!important}.sortable-head:hover{color:#235f9f;background:#f7faff}.sortable-head::after{content:"‚Üï";position:absolute;right:8px;opacity:.35;font-size:10px}.sortable-head.sort-asc::after{content:"‚Üë";opacity:1}.sortable-head.sort-desc::after{content:"‚Üì";opacity:1}.protected-audit{background:#fff8e8}.protected-audit td:first-child{box-shadow:inset 3px 0 0 #f2a51a}.admin-only{display:none}.admin-visible{display:inline-flex}
@media(max-width:1000px){.device-detail-shell{grid-template-columns:1fr}.kpi-row{grid-template-columns:repeat(2,1fr)}}

.device-icon{width:38px;height:38px;display:inline-flex;align-items:center;justify-content:center;flex:0 0 38px}.device-icon img{width:36px;height:36px;object-fit:contain;display:block;filter:drop-shadow(0 2px 2px rgba(18,38,63,.18))}.device-icon-modal{position:fixed!important;inset:0!important;z-index:5000!important;place-items:center!important;background:rgba(7,16,28,.62)!important;padding:24px!important;overflow:auto!important}.device-icon-dialog{width:min(720px,calc(100vw - 32px))!important;max-width:720px!important;max-height:calc(100vh - 48px)!important;overflow:auto!important;padding:0!important;border:1px solid #d8e3ef;border-radius:13px!important;box-shadow:0 26px 90px rgba(2,12,27,.34)!important}.device-icon-dialog .modal-head{padding:18px 20px 12px;border-bottom:1px solid #edf2f7}.device-icon-dialog .modal-form{display:block;margin:0;padding:0 20px 18px}.device-icon-summary{display:flex;align-items:center;gap:14px;padding:14px 0}.device-icon-summary-art{width:72px;height:64px;border:1px solid #dce6f1;border-radius:10px;background:linear-gradient(180deg,#fff,#f6f9fc);display:grid;place-items:center}.device-icon-summary-art img{width:58px;height:58px;object-fit:contain;filter:drop-shadow(0 3px 3px rgba(17,39,64,.2))}.device-icon-summary-name{font-size:16px;font-weight:750;color:#0b6ddd}.device-icon-summary-meta{font-size:12px;color:#64768d;line-height:1.5}.device-icon-tabs{display:flex;gap:24px;border-bottom:1px solid #e5edf5;margin-bottom:14px;overflow:auto}.device-icon-tab{border:0;background:transparent;padding:10px 2px 9px;color:#61738b;font-size:11px;white-space:nowrap;cursor:pointer;border-bottom:2px solid transparent}.device-icon-tab.active{color:#0d74f5;border-bottom-color:#0d74f5;font-weight:700}.device-icon-picker{display:grid;grid-template-columns:repeat(5,minmax(96px,1fr));gap:10px;max-height:390px;overflow:auto;padding:2px}.device-icon-choice{position:relative;border:1px solid #d8e3ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:9px;padding:9px 6px 8px;cursor:pointer;text-align:center;color:#30445e;font-size:10px;min-height:92px}.device-icon-choice:hover{border-color:#86bdfb;background:#f7fbff}.device-icon-choice.selected{border:2px solid #0d74f5;padding:8px 5px 7px;box-shadow:0 0 0 2px rgba(13,116,245,.09)}.device-icon-choice.selected:after{content:'‚úì';position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%;background:#0d74f5;color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.device-icon-choice img{width:66px;height:58px;display:block;object-fit:contain;margin:0 auto 5px;filter:drop-shadow(0 3px 3px rgba(18,38,63,.2))}.device-icon-custom{border-top:1px solid #e4ebf3;margin-top:14px;padding-top:13px}.custom-icon-preview{width:58px;height:58px;object-fit:contain;border:1px solid #d8e3ef;border-radius:8px;background:#fff;padding:4px}.icon-upload-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.device-icon-dialog .modal-actions{display:flex;justify-content:flex-end;gap:8px;border-top:1px solid #edf2f7;padding-top:14px;margin-top:14px}@media(max-width:700px){.device-icon-modal{padding:10px!important;align-items:center!important}.device-icon-dialog{max-height:calc(100vh - 20px)!important}.device-icon-picker{grid-template-columns:repeat(3,1fr)}.device-icon-tabs{gap:14px}.device-icon-summary-art{width:60px;height:56px}.device-icon-summary-art img{width:48px;height:48px}}

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
</style></head><body><div class="wrap"><a href="/">‚Üê GODSEYE Dashboard</a><h1>Monitoring & Collectors</h1>
<p class="muted">Create persistent checks. GODSEYE runs them locally without Docker and stores recent results.</p>
<div class="card"><h2>Add monitor</h2><div class="grid">
<div><label>Name<br><input id="name" placeholder="Home website"></label></div>
<div><label>Type<br><select id="kind"><option value="website">Website</option><option value="dhcp">DHCP leases</option><option value="pihole">Pi-hole</option><option value="unifi">UniFi</option><option value="snmp">SNMP</option><option value="public_ip">Public IP</option></select></label></div>
<div><label>Target<br><input id="target" placeholder="https://example.com"></label></div>
<div><label>Interval seconds<br><input id="interval" type="number" value="300" min="30"></label></div>
</div><p><button onclick="addMonitor()">Add monitor</button> <button onclick="runNow()">Run all now</button></p><pre id="out">Ready.</pre></div>
<div class="card"><h2>Recent results</h2><button onclick="load()">Refresh</button><pre id="results">Loading‚Ä¶</pre></div>
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
<title>GODSEYE ‚Äî Network Tools</title><div id="standaloneToolsHelp" class="standalone-help-pop" style="display:none"><div class="standalone-help-card"><div class="standalone-help-head"><span>Network Tools</span><button type="button" onclick="document.getElementById('standaloneToolsHelp').style.display='none'" aria-label="Close help">√ó</button></div><div class="standalone-help-body">Diagnostics and management tools for your local network.</div></div></div><script>(function(){try{const saved=localStorage.getItem('godseye_theme');const dark=saved!=='light';document.documentElement.dataset.theme=dark?'dark':'light'}catch(e){document.documentElement.dataset.theme='light'}})();</script>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033}*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#172033}.layout{display:flex;min-height:100vh}.side{width:216px;background:#07101c;border-right:1px solid #18283b;position:sticky;top:0;height:100vh;display:flex;flex-direction:column}.brand{padding:20px 18px;border-bottom:1px solid #18283b;display:flex;align-items:center;gap:10px}.brand b{display:block;color:#fff;letter-spacing:.1em;font-size:18px}.brand small{display:block;color:#7890ad;font-size:9px;letter-spacing:.08em;margin-top:2px}.eye-logo{width:48px;height:31px;display:block}.nav{padding:12px 0;flex:1}.nav-title{color:#637991;font-size:10px;text-transform:uppercase;letter-spacing:.12em;padding:12px 18px 6px}.nav a{display:flex;align-items:center;gap:10px;padding:10px 16px;color:#a7b9ce;text-decoration:none;font-size:12px;border-left:3px solid transparent}.nav a:hover{background:#0d1b2b;color:#fff}.nav a.active{background:linear-gradient(90deg,#12335d,#0d223d);border-left-color:#1d8cf5;color:#fff}.navicon{width:18px;text-align:center}.side-footer{padding:14px 12px;border-top:1px solid #18283b}.back{display:block;text-align:center;background:#0f7df0;color:#fff;text-decoration:none;border-radius:7px;padding:9px;font-size:11px}.main{flex:1;min-width:0}.headerbar{height:58px;background:#fff;border-bottom:1px solid #e4eaf1;display:flex;justify-content:flex-end;align-items:center;padding:0 30px;gap:16px}.online{display:inline-flex;align-items:center;gap:6px;background:#ecfdf5;color:#11845b;border-radius:999px;padding:5px 10px;font-size:11px;font-weight:700}.online i{width:7px;height:7px;background:#14b87a;border-radius:50%}.user{font-size:12px;color:#35506f}.wrap{max-width:1450px;margin:auto;padding:28px 30px}.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin-bottom:20px}.hero h1{margin:0;font-size:26px}.hero p{margin:5px 0 0;color:#72819a;font-size:12px}.tool-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.tool-card{background:#fff;border:1px solid #e1e7ef;border-radius:10px;box-shadow:0 2px 7px rgba(25,45,70,.04);padding:18px}.tool-card h2{font-size:15px;margin:0 0 5px}.tool-card p{font-size:11px;color:#72819a;min-height:30px;margin:0 0 14px}.tool-icon{width:34px;height:34px;border-radius:9px;background:#e8f4ff;color:#0f7df0;display:grid;place-items:center;font-weight:800;margin-bottom:10px}.full{grid-column:1/-1}.panel{background:#fff;border:1px solid #e1e7ef;border-radius:10px;box-shadow:0 2px 7px rgba(25,45,70,.04);padding:18px;margin-top:16px}.panel h2{font-size:15px;margin:0 0 5px}.muted{color:#72819a;font-size:11px}.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px}.input{border:1px solid #d8e0e9;border-radius:7px;background:#fff;color:#25334a;padding:9px 10px;min-width:180px}.input.grow{flex:1}.btn{border:1px solid #0f7df0;background:#0f7df0;color:#fff;border-radius:7px;padding:9px 12px;cursor:pointer;font-size:11px}.btn.secondary{background:#fff;color:#35506f;border-color:#d8e0e9}.btn.warn{background:#c83b50;border-color:#c83b50}.result{margin-top:12px;background:#f7f9fc;border:1px solid #e5eaf1;border-radius:8px;padding:12px;min-height:45px;white-space:pre-wrap;word-break:break-word;font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#33465e}.result.ok{border-color:#b9ead5}.result.err{border-color:#f1c2ca;color:#a52e43}.status{font-size:10px;color:#72819a;margin-left:auto;align-self:center}.security-note{background:#f0f7ff;border:1px solid #cfe5fb;color:#365979;padding:10px 12px;border-radius:8px;font-size:10px;margin-top:14px}@media(max-width:1050px){.tool-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.layout{display:block}.side{width:100%;height:auto;position:sticky;top:0;z-index:20}.brand{display:none}.nav{display:flex;overflow:auto;padding:0}.nav-title{display:none}.nav a{white-space:nowrap;border-left:0;border-bottom:3px solid transparent}.nav a.active{border-left:0;border-bottom-color:#1d8cf5}.side-footer{display:none}.headerbar{height:48px;padding:0 14px}.wrap{padding:20px 14px}.tool-grid{grid-template-columns:1fr}.full{grid-column:auto}}

.device-link{background:none!important;border:0!important;padding:0!important;color:#1565c0!important;font-weight:700;cursor:pointer;text-align:left}.device-link:hover{text-decoration:underline}.device-page-head{display:flex;align-items:center;gap:12px}.back-btn{display:inline-flex;align-items:center;gap:7px;border:1px solid #d8e0e9!important;background:#fff!important;color:#2d4665!important}.device-detail-shell{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(300px,.65fr);gap:16px}.device-hero-card{padding:18px}.kpi-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:14px}.kpi{border:1px solid #e4eaf1;border-radius:10px;padding:12px;background:#fafcff}.kpi .k{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#7b889a}.kpi .v{font-size:17px;font-weight:750;margin-top:4px}.stack{display:grid;gap:16px}.chart-empty{height:160px;display:grid;place-items:center;color:#7c8ba0}.dashboard-table tbody tr{cursor:pointer}.dashboard-table tbody tr:hover{background:#f4f8fd}.panel-subtle{padding:12px 16px;border-top:1px solid #eef2f6;font-size:11px;color:#738197}.traffic-axis{font-size:9px;fill:#8795a8}.activity-row button{all:unset;cursor:pointer}.activity-row button:hover .activity-title{text-decoration:underline}.intel-modal-card{display:none!important}.dashboard-statusline{display:flex;gap:14px;align-items:center;flex-wrap:wrap;font-size:11px;color:#748197}.status-pill{display:inline-flex;align-items:center;gap:6px}.status-pill::before{content:"";width:7px;height:7px;border-radius:50%;background:#22a06b}.status-pill.warn::before{background:#f59e0b}
@media(max-width:1000px){.device-detail-shell{grid-template-columns:1fr}.kpi-row{grid-template-columns:repeat(2,1fr)}}

.device-icon{width:38px;height:38px;display:inline-flex;align-items:center;justify-content:center;flex:0 0 38px}.device-icon img{width:36px;height:36px;object-fit:contain;display:block;filter:drop-shadow(0 2px 2px rgba(18,38,63,.18))}.device-icon-modal{position:fixed!important;inset:0!important;z-index:5000!important;place-items:center!important;background:rgba(7,16,28,.62)!important;padding:24px!important;overflow:auto!important}.device-icon-dialog{width:min(720px,calc(100vw - 32px))!important;max-width:720px!important;max-height:calc(100vh - 48px)!important;overflow:auto!important;padding:0!important;border:1px solid #d8e3ef;border-radius:13px!important;box-shadow:0 26px 90px rgba(2,12,27,.34)!important}.device-icon-dialog .modal-head{padding:18px 20px 12px;border-bottom:1px solid #edf2f7}.device-icon-dialog .modal-form{display:block;margin:0;padding:0 20px 18px}.device-icon-summary{display:flex;align-items:center;gap:14px;padding:14px 0}.device-icon-summary-art{width:72px;height:64px;border:1px solid #dce6f1;border-radius:10px;background:linear-gradient(180deg,#fff,#f6f9fc);display:grid;place-items:center}.device-icon-summary-art img{width:58px;height:58px;object-fit:contain;filter:drop-shadow(0 3px 3px rgba(17,39,64,.2))}.device-icon-summary-name{font-size:16px;font-weight:750;color:#0b6ddd}.device-icon-summary-meta{font-size:12px;color:#64768d;line-height:1.5}.device-icon-tabs{display:flex;gap:24px;border-bottom:1px solid #e5edf5;margin-bottom:14px;overflow:auto}.device-icon-tab{border:0;background:transparent;padding:10px 2px 9px;color:#61738b;font-size:11px;white-space:nowrap;cursor:pointer;border-bottom:2px solid transparent}.device-icon-tab.active{color:#0d74f5;border-bottom-color:#0d74f5;font-weight:700}.device-icon-picker{display:grid;grid-template-columns:repeat(5,minmax(96px,1fr));gap:10px;max-height:390px;overflow:auto;padding:2px}.device-icon-choice{position:relative;border:1px solid #d8e3ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:9px;padding:9px 6px 8px;cursor:pointer;text-align:center;color:#30445e;font-size:10px;min-height:92px}.device-icon-choice:hover{border-color:#86bdfb;background:#f7fbff}.device-icon-choice.selected{border:2px solid #0d74f5;padding:8px 5px 7px;box-shadow:0 0 0 2px rgba(13,116,245,.09)}.device-icon-choice.selected:after{content:'‚úì';position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%;background:#0d74f5;color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.device-icon-choice img{width:66px;height:58px;display:block;object-fit:contain;margin:0 auto 5px;filter:drop-shadow(0 3px 3px rgba(18,38,63,.2))}.device-icon-custom{border-top:1px solid #e4ebf3;margin-top:14px;padding-top:13px}.custom-icon-preview{width:58px;height:58px;object-fit:contain;border:1px solid #d8e3ef;border-radius:8px;background:#fff;padding:4px}.icon-upload-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.device-icon-dialog .modal-actions{display:flex;justify-content:flex-end;gap:8px;border-top:1px solid #edf2f7;padding-top:14px;margin-top:14px}@media(max-width:700px){.device-icon-modal{padding:10px!important;align-items:center!important}.device-icon-dialog{max-height:calc(100vh - 20px)!important}.device-icon-picker{grid-template-columns:repeat(3,1fr)}.device-icon-tabs{gap:14px}.device-icon-summary-art{width:60px;height:56px}.device-icon-summary-art img{width:48px;height:48px}}

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
\n/* v4.9 standalone tools arrangement */\n.tools-layout-bar{display:none;gap:7px;align-items:center}.tools-layout-bar.show{display:flex}.tool-card.arrange-card{position:relative}.tools-arranging .tool-card{cursor:grab;outline:1px dashed rgba(156,201,245,.25)}.tools-arranging .tool-card:before{content:'‚ãÆ‚ãÆ';position:absolute;right:8px;top:8px;width:24px;height:21px;border-radius:7px;background:#0f7df0;color:#fff;display:grid;place-items:center;z-index:10}.tool-card.dragging{opacity:.42}.tool-card.drop-target{box-shadow:0 0 0 2px #0f7df0!important}@media(min-width:1051px){.tool-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important}}\n
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
<div class="nav-title">Overview</div><a href="/">‚óâ <span>Dashboard</span></a><a href="/#devices">‚ñ£ <span>Devices</span></a><a href="/#network">‚åò <span>Network Map</span></a><a href="/monitoring">‚óî <span>Monitoring</span></a><a href="/#findings">‚ö† <span>Findings</span></a>
<div class="nav-title">Management</div><a class="active" href="/tools">‚öí <span>Tools</span></a><a href="/#integrations">‚åò <span>Integrations</span></a><a href="/#reports">‚ñ§ <span>Reports</span></a><a href="/#settings">‚öô <span>Settings</span></a></nav><div class="side-footer"><a class="back" href="/">Dashboard</a></div></aside>
<main class="main"><header class="headerbar"><span class="online"><i></i>Online</span><span class="user">admin ‚ñæ</span></header><div class="wrap">
<div class="hero"><div><div style="display:flex;align-items:center"><h1>Network Tools</h1><button type="button" class="standalone-help-btn" onclick="document.getElementById('standaloneToolsHelp').style.display='grid'" aria-label="More information about Network Tools">?</button></div><p>Diagnostics and management tools for your local network.</p></div><div style="display:flex;gap:9px;align-items:center"><span class="status">GODSEYE native tools</span><div id="toolsLayoutBar" class="tools-layout-bar"><button class="btn secondary" onclick="toggleStandaloneToolsArrange()">üîì Unlock Layout</button></div></div></div>
<div class="tool-grid">
<section class="tool-card"><div class="tool-icon">‚Üó</div><h2>Ping</h2><p>Test reachability, packet loss, and latency.</p><div class="row"><input class="input grow" id="pingHost" value="192.168.1.1" placeholder="Private IP or hostname"><button class="btn" onclick="runPing()">Run Ping</button></div><div class="result" id="pingOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">‚åÅ</div><h2>Traceroute</h2><p>Show the local route toward a private network device.</p><div class="row"><input class="input grow" id="traceHost" value="192.168.1.1" placeholder="Private IP or hostname"><button class="btn" onclick="runTrace()">Trace Route</button></div><div class="result" id="traceOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">‚óé</div><h2>DNS Lookup</h2><p>Resolve a hostname and show its addresses.</p><div class="row"><input class="input grow" id="dnsHost" value="google.com" placeholder="Hostname"><button class="btn" onclick="runDns()">Lookup</button></div><div class="result" id="dnsOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">‚óâ</div><h2>Port Scan</h2><p>Check selected TCP ports on a private LAN target using Nmap.</p><div class="row"><input class="input grow" id="portHost" value="192.168.1.1" placeholder="Private IP or hostname"><input class="input" id="ports" value="22,53,80,443,445,3389,8080,8443" title="Comma-separated ports or ranges"><button class="btn" onclick="runPorts()">Scan Ports</button></div><div class="result" id="portOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">‚ñ£</div><h2>Device Information</h2><p>Collect reverse DNS, neighbor-table data, and reachability.</p><div class="row"><input class="input grow" id="infoHost" value="192.168.1.1" placeholder="Private IP or hostname"><button class="btn" onclick="runInfo()">Get Info</button></div><div class="result" id="infoOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">‚ü≥</div><h2>Network Discovery</h2><p>Discover active hosts with Nmap or inspect the Linux neighbor table.</p><div class="row"><input class="input grow" id="discoverTarget" value="192.168.1.0/24" placeholder="Private network CIDR"><button class="btn" onclick="runNmap()">Discover</button><button class="btn secondary" onclick="runNeighbors()">Neighbors</button></div><div class="result" id="discoverOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">‚ö°</div><h2>Wake on LAN</h2><p>Send a magic packet to a device. Administrator access is required.</p><div class="row"><input class="input grow" id="wolMac" placeholder="AA:BB:CC:DD:EE:FF"><input class="input" id="wolBroadcast" value="255.255.255.255"><button class="btn warn" onclick="runWol()">Wake Device</button></div><div class="result" id="wolOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">‚úì</div><h2>Gateway & Internet</h2><p>Test the Raspberry Pi's default gateway and Internet path.</p><div class="row"><button class="btn" onclick="runGet('/api/v1/diagnostics/gateway','gatewayOut')">Test Gateway</button><button class="btn secondary" onclick="runGet('/api/v1/diagnostics/internet','gatewayOut')">Test Internet</button></div><div class="result" id="gatewayOut">Ready.</div></section>
<section class="tool-card"><div class="tool-icon">‚óá</div><h2>Website Monitor Test</h2><p>Check HTTP/HTTPS availability and response time.</p><div class="row"><input class="input grow" id="webUrl" value="https://example.com" placeholder="https://host-or-service"><button class="btn" onclick="runWebsite()">Test Website</button></div><div class="result" id="webOut">Ready.</div></section>
<section class="panel full"><h2>Tool safety</h2><div class="muted">GODSEYE limits active network diagnostics to private or link-local targets. Port scans use TCP connect mode and a bounded port list. Wake-on-LAN is an administrator-only state-changing action.</div><div class="security-note">The fresh installer includes the native Linux programs required by these tools, including Nmap, traceroute, DNS utilities, iproute2, ping, and Wake-on-LAN.</div></section>
</div></div></main></div>
<script>
let toolsArrange=false,toolsDragged=null;
async function initStandaloneToolsLayout(){try{const me=await req('/api/v1/auth/me');document.getElementById('toolsLayoutBar')?.classList.add('show');const r=await req('/api/v1/ui/layouts');const order=r.layouts?.tools_standalone?.layout?.cards||[];const grid=document.querySelector('.tool-grid');const cards=[...grid.querySelectorAll(':scope > .tool-card')];cards.forEach((c,i)=>{c.dataset.layoutKey=(c.querySelector('h2')?.textContent||'tool-'+i).toLowerCase().replace(/[^a-z0-9]+/g,'-');c.classList.add('arrange-card')});const map=new Map(cards.map(c=>[c.dataset.layoutKey,c]));order.forEach(k=>{if(map.has(k))grid.appendChild(map.get(k))})}catch(e){}}
function toggleStandaloneToolsArrange(){toolsArrange=!toolsArrange;document.body.classList.toggle('tools-arranging',toolsArrange);document.querySelectorAll('.tool-card').forEach(c=>c.draggable=toolsArrange);const b=document.querySelector('#toolsLayoutBar button');if(b)b.textContent=toolsArrange?'üîí Lock Layout':'üîì Unlock Layout'}
document.addEventListener('dragstart',e=>{if(!toolsArrange)return;const c=e.target.closest('.tool-card');if(!c)return;toolsDragged=c;c.classList.add('dragging');e.dataTransfer.setData('text/plain',c.dataset.layoutKey)});
document.addEventListener('dragover',e=>{if(!toolsDragged)return;const c=e.target.closest('.tool-card');if(!c||c===toolsDragged)return;e.preventDefault();document.querySelectorAll('.drop-target').forEach(x=>x.classList.remove('drop-target'));c.classList.add('drop-target')});
document.addEventListener('drop',async e=>{if(!toolsDragged)return;const c=e.target.closest('.tool-card');if(!c||c===toolsDragged)return;e.preventDefault();const r=c.getBoundingClientRect();c.parentNode.insertBefore(toolsDragged,(e.clientY<r.top+r.height/2||e.clientX<r.left+r.width/2)?c:c.nextSibling);document.querySelectorAll('.drop-target').forEach(x=>x.classList.remove('drop-target'));const cards=[...document.querySelectorAll('.tool-grid > .tool-card')].map(x=>x.dataset.layoutKey);try{await req('/api/v1/ui/layouts/tools_standalone/personal',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({layout:{cards}})})}catch(err){}});
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



DEVICE_DETAIL_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GODSEYE ‚Äî Device</title><script>(function(){try{const saved=localStorage.getItem('godseye_theme');const dark=saved==='dark'||(!saved&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=dark?'dark':'light'}catch(e){document.documentElement.dataset.theme='light'}})();</script><style>
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;background:#f5f9fd;color:#17263c}.shell{min-height:100vh;display:grid;grid-template-columns:188px 1fr}.side{background:#07101c;color:#dce8f5;min-height:100vh;position:fixed;left:0;top:0;width:188px;padding:24px 8px}.brand{text-align:center;margin-bottom:34px}.brand svg{width:76px;height:46px}.brand b{display:block;color:#fff;letter-spacing:.16em;font-size:15px}.nav a{display:block;color:#c8d5e5;text-decoration:none;padding:10px 12px;border-radius:6px;font-size:12px;margin:3px 0}.nav a:hover,.nav a.active{background:#0d74f5;color:#fff}.main{grid-column:2;min-width:0}.top{height:58px;background:#fff;border-bottom:1px solid #e2eaf3;display:flex;justify-content:flex-end;align-items:center;padding:0 28px;gap:16px;font-size:12px}.online{background:#eaf9f2;color:#0c9562;border-radius:999px;padding:5px 10px}.wrap{padding:26px 24px 40px;max-width:1380px}.back{display:inline-flex;align-items:center;gap:7px;color:#0d66cf;text-decoration:none;font-weight:650;font-size:13px;margin-bottom:14px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;margin-bottom:16px}.hero h1{font-size:26px;margin:0}.muted{color:#73849a;font-size:12px}.status{border-radius:999px;padding:5px 10px;background:#eaf9f2;color:#07955e;font-size:11px}.grid{display:grid;grid-template-columns:minmax(0,2fr) minmax(280px,1fr);gap:14px}.stack{display:flex;flex-direction:column;gap:14px}.panel{background:#fff;border:1px solid #dce6f1;border-radius:7px;box-shadow:0 2px 8px rgba(27,64,102,.04);overflow:hidden}.panel-head{padding:13px 15px;border-bottom:1px solid #e6edf5;display:flex;justify-content:space-between;align-items:center}.panel-head h2{font-size:14px;margin:0}.panel-body{padding:15px}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.kpi{padding:12px;border:1px solid #e4ebf3;border-radius:6px}.kpi .v{font-size:21px;font-weight:760;margin-top:4px}.kv{display:grid;grid-template-columns:110px 1fr;gap:10px 14px;font-size:12px}.kv .k{color:#71839a}table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;border-bottom:1px solid #edf2f7;text-align:left;font-size:12px}th{font-size:10px;color:#72839a;text-transform:uppercase;background:#fbfdff}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{border:1px solid #ccd9e8;background:#fff;color:#24405f;padding:8px 11px;border-radius:6px;cursor:pointer}.btn.primary{background:#0d74f5;border-color:#0d74f5;color:#fff}.detail-device-icon{width:54px;height:54px;object-fit:contain;border:1px solid #dce6f1;border-radius:10px;background:#fff;padding:6px}.identity-input,.identity-select{width:100%;min-width:0;border:1px solid #d8e0e9;border-radius:6px;background:#fff;color:#25334a;padding:8px 9px;font:inherit}.identity-input:focus,.identity-select:focus{outline:2px solid #d9ecff;border-color:#0d74f5}.empty{padding:24px;color:#8090a4;text-align:center}.timeline{padding:12px 15px;border-bottom:1px solid #edf2f7;font-size:12px}.error{padding:14px;background:#fff1f1;color:#b52d3d;border:1px solid #ffd0d4;border-radius:6px}@media(max-width:900px){.shell{display:block}.side{position:relative;width:100%;min-height:auto}.main{grid-column:auto}.grid{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}}

.device-icon{width:38px;height:38px;display:inline-flex;align-items:center;justify-content:center;flex:0 0 38px}.device-icon img{width:36px;height:36px;object-fit:contain;display:block;filter:drop-shadow(0 2px 2px rgba(18,38,63,.18))}.device-icon-modal{position:fixed!important;inset:0!important;z-index:5000!important;place-items:center!important;background:rgba(7,16,28,.62)!important;padding:24px!important;overflow:auto!important}.device-icon-dialog{width:min(720px,calc(100vw - 32px))!important;max-width:720px!important;max-height:calc(100vh - 48px)!important;overflow:auto!important;padding:0!important;border:1px solid #d8e3ef;border-radius:13px!important;box-shadow:0 26px 90px rgba(2,12,27,.34)!important}.device-icon-dialog .modal-head{padding:18px 20px 12px;border-bottom:1px solid #edf2f7}.device-icon-dialog .modal-form{display:block;margin:0;padding:0 20px 18px}.device-icon-summary{display:flex;align-items:center;gap:14px;padding:14px 0}.device-icon-summary-art{width:72px;height:64px;border:1px solid #dce6f1;border-radius:10px;background:linear-gradient(180deg,#fff,#f6f9fc);display:grid;place-items:center}.device-icon-summary-art img{width:58px;height:58px;object-fit:contain;filter:drop-shadow(0 3px 3px rgba(17,39,64,.2))}.device-icon-summary-name{font-size:16px;font-weight:750;color:#0b6ddd}.device-icon-summary-meta{font-size:12px;color:#64768d;line-height:1.5}.device-icon-tabs{display:flex;gap:24px;border-bottom:1px solid #e5edf5;margin-bottom:14px;overflow:auto}.device-icon-tab{border:0;background:transparent;padding:10px 2px 9px;color:#61738b;font-size:11px;white-space:nowrap;cursor:pointer;border-bottom:2px solid transparent}.device-icon-tab.active{color:#0d74f5;border-bottom-color:#0d74f5;font-weight:700}.device-icon-picker{display:grid;grid-template-columns:repeat(5,minmax(96px,1fr));gap:10px;max-height:390px;overflow:auto;padding:2px}.device-icon-choice{position:relative;border:1px solid #d8e3ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:9px;padding:9px 6px 8px;cursor:pointer;text-align:center;color:#30445e;font-size:10px;min-height:92px}.device-icon-choice:hover{border-color:#86bdfb;background:#f7fbff}.device-icon-choice.selected{border:2px solid #0d74f5;padding:8px 5px 7px;box-shadow:0 0 0 2px rgba(13,116,245,.09)}.device-icon-choice.selected:after{content:'‚úì';position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%;background:#0d74f5;color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.device-icon-choice img{width:66px;height:58px;display:block;object-fit:contain;margin:0 auto 5px;filter:drop-shadow(0 3px 3px rgba(18,38,63,.2))}.device-icon-custom{border-top:1px solid #e4ebf3;margin-top:14px;padding-top:13px}.custom-icon-preview{width:58px;height:58px;object-fit:contain;border:1px solid #d8e3ef;border-radius:8px;background:#fff;padding:4px}.icon-upload-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.device-icon-dialog .modal-actions{display:flex;justify-content:flex-end;gap:8px;border-top:1px solid #edf2f7;padding-top:14px;margin-top:14px}@media(max-width:700px){.device-icon-modal{padding:10px!important;align-items:center!important}.device-icon-dialog{max-height:calc(100vh - 20px)!important}.device-icon-picker{grid-template-columns:repeat(3,1fr)}.device-icon-tabs{gap:14px}.device-icon-summary-art{width:60px;height:56px}.device-icon-summary-art img{width:48px;height:48px}}

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
</style></head><body><div class="shell"><aside class="side"><div class="brand">__EYE_LOGO__<b>GODSEYE</b><div class="muted">LOCAL NETWORK INTELLIGENCE</div></div><nav class="nav"><a href="/#overview">‚åÇ &nbsp; Dashboard</a><a class="active" href="/#devices">‚ñ£ &nbsp; Devices</a><a href="/#network">‚åò &nbsp; Network Map</a><a href="/#monitoring">‚ó∑ &nbsp; Monitoring</a><a href="/#findings">! &nbsp; Findings</a><a href="/#tools">‚åÅ &nbsp; Tools</a><a href="/#integrations">‚åò &nbsp; Integrations</a><a href="/#reports">‚ñ§ &nbsp; Reports</a><a href="/#security">‚öô &nbsp; Settings</a></nav></aside><main class="main"><header class="top"><span class="online">‚óè Online</span><span id="who">admin</span></header><div class="wrap"><button type="button" class="back" onclick="if(document.referrer.startsWith(location.origin))history.back();else location.assign('/#devices')">‚Üê Close Device Details and Return</button><div class="hero"><div style="display:flex;align-items:center;gap:12px"><img id="detailDeviceIcon" class="detail-device-icon" src="/assets/device-icons/other.svg" alt="Device icon"><div><h1 id="title">Device</h1><div class="muted" id="subtitle">Loading device intelligence‚Ä¶</div></div></div><div class="actions"><button class="btn" id="renameBtn" onclick="renameCurrentDevice()">Rename Device</button><span class="status" id="state">Loading</span></div></div><div id="content"><div class="panel"><div class="empty">Loading device intelligence‚Ä¶</div></div></div></div></main></div><datalist id="deviceTypeChoices"><option value="Router"><option value="PC"><option value="Laptop"><option value="Camera"><option value="Switch"><option value="Access Point"><option value="Phone"><option value="Tablet"><option value="Printer"><option value="Server"><option value="NAS"><option value="TV / Media"><option value="IoT"><option value="Smart Home"><option value="Game Console"><option value="Other"></datalist><script>
const DEVICE_ID=__DEVICE_ID__;const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const DEVICE_ICON_ASSET_VERSION='27';function deviceIconAsset(key){return '/assets/device-icons/'+String(key||'other')+'.svg?v='+DEVICE_ICON_ASSET_VERSION}
async function api(url,opt={}){const r=await fetch(url,opt);if(r.status===401){location.href='/#devices';throw new Error('Sign in required')}if(!r.ok)throw new Error(await r.text());return r.json()}function dt(v){try{return v?new Date(v).toLocaleString():'‚Äî'}catch(_){return '‚Äî'}}
function effectiveDetailIcon(d){const key=d&&d.icon_key;if(key&&key!=='auto')return key;const t=String(d&&d.device_type||'').toLowerCase();if(t.includes('firewall'))return'firewall';if(t.includes('modem'))return'modem';if(t.includes('patch panel'))return'patch-panel';if(t.includes('voip'))return'voip-phone';if(t.includes('router')||t.includes('gateway'))return'router';if(t.includes('switch'))return'switch';if(t.includes('access point')||t==='ap'||t.includes('wifi'))return'access-point';if(t.includes('laptop'))return'laptop';if(t==='pc'||t.includes('desktop')||t.includes('computer'))return'pc';if(t.includes('camera'))return'camera';if(t.includes('printer'))return'printer';if(t.includes('phone'))return'phone';if(t.includes('tablet'))return'tablet';if(t.includes('server'))return'server';if(t.includes('network storage'))return'network-storage';if(t.includes('nas')||t.includes('storage'))return'nas';if(t.includes('tv')||t.includes('media'))return'tv';if(t.includes('game')||t.includes('console'))return'game-console';if(t.includes('iot')||t.includes('smart')||t.includes('sensor')||t.includes('light'))return'iot';return'other'}
let CURRENT_DEVICE=null;async function load(){try{const me=await api('/api/v1/auth/me');document.getElementById('who').textContent=me.username;const r=await api('/api/v1/devices/'+DEVICE_ID+'/intelligence'),d=r.device||{};CURRENT_DEVICE=d;const detailIcon=document.getElementById('detailDeviceIcon');if(detailIcon)detailIcon.src=d.icon_data||deviceIconAsset(effectiveDetailIcon(d));const s=r.summary||{},events=(r.events||[]).slice(0,30),ips=(r.ip_history||[]).slice(0,20),sources=r.sources||[],issues=(r.issues||[]).filter(x=>x.status==='open');document.getElementById('title').textContent=d.name||d.hostname||'Unknown device';document.getElementById('subtitle').textContent=[d.ip||'No IP',d.mac||'No MAC',d.vendor||'Unknown vendor'].join(' ¬∑ ');document.getElementById('state').textContent=d.status||'unknown';document.getElementById('content').innerHTML=`<div class="grid"><div class="stack"><section class="panel"><div class="panel-head"><h2>Device Overview</h2><div class="actions"><button class="btn primary" onclick="diagnose()">Diagnose</button><button class="btn" onclick="recheck()">Recheck</button></div></div><div class="panel-body"><div class="kpis"><div class="kpi"><div class="muted">Risk score</div><div class="v">${Number(s.risk_score||0)}/100</div></div><div class="kpi"><div class="muted">Evidence sources</div><div class="v">${Number(s.source_count||0)}</div></div><div class="kpi"><div class="muted">Known IPs</div><div class="v">${Number(s.known_ip_count||0)}</div></div><div class="kpi"><div class="muted">Open findings</div><div class="v">${Number(s.open_issue_count||0)}</div></div></div><div id="diag" class="muted" style="margin-top:12px"></div></div></section><section class="panel"><div class="panel-head"><h2>Recent Activity</h2></div><table><thead><tr><th>Time</th><th>Event</th><th>IP</th><th>Details</th></tr></thead><tbody>${events.length?events.map(x=>`<tr><td>${esc(dt(x.created_at))}</td><td>${esc(x.event_type||'event')}</td><td>${esc(x.ip||'‚Äî')}</td><td>${esc(x.details||'')}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">No activity recorded.</td></tr>'}</tbody></table></section><section class="panel"><div class="panel-head"><h2>IP History</h2></div><table><thead><tr><th>IP</th><th>Source</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>${ips.length?ips.map(x=>`<tr><td>${esc(x.ip||'‚Äî')}</td><td>${esc(x.source||'‚Äî')}</td><td>${esc(dt(x.first_seen))}</td><td>${esc(dt(x.last_seen))}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">No IP history yet.</td></tr>'}</tbody></table></section></div><div class="stack"><section class="panel"><div class="panel-head"><h2>Identity</h2><div class="actions"><a class="btn" href="/#devices">Change Icon in Inventory</a><button class="btn primary" id="saveIdentityBtn" onclick="saveIdentity()">Save Identity</button></div></div><div class="panel-body kv"><div class="k">Hostname</div><div><input id="identityHostname" class="identity-input" maxlength="253" value="${esc(d.hostname||'')}" placeholder="Enter hostname"></div><div class="k">IP address</div><div>${esc(d.ip||'‚Äî')}</div><div class="k">MAC address</div><div>${esc(d.mac||'‚Äî')}</div><div class="k">Vendor</div><div>${esc(d.vendor||'‚Äî')}</div><div class="k">Type</div><div><input id="identityType" class="identity-input" maxlength="80" list="deviceTypeChoices" value="${esc(d.device_type||'')}" placeholder="Router, PC, Camera, Switch‚Ä¶"></div><div class="k">Classification</div><div><select id="identityClassification" class="identity-select"><option value="new" ${d.classification==='new'?'selected':''}>New</option><option value="investigate" ${d.classification==='investigate'?'selected':''}>Investigate</option><option value="known" ${d.classification==='known'?'selected':''}>Known</option><option value="managed" ${d.classification==='managed'?'selected':''}>Managed</option><option value="ignored" ${d.classification==='ignored'?'selected':''}>Ignored</option></select></div><div class="k">First seen</div><div>${esc(dt(d.first_seen))}</div><div class="k">Last seen</div><div>${esc(dt(d.last_seen))}</div><div class="k">Update status</div><div id="identitySaveStatus" class="muted">Edit the fields above, then Save Identity.</div></div></section><section class="panel"><div class="panel-head"><h2>Evidence Sources</h2></div>${sources.length?sources.map(x=>`<div class="timeline"><b>${esc(x.source||'source')}</b><div class="muted">${esc(x.ip||'')} ¬∑ ${esc(dt(x.last_seen))}</div></div>`).join(''):'<div class="empty">Inventory evidence only.</div>'}</section><section class="panel"><div class="panel-head"><h2>Open Findings</h2></div>${issues.length?issues.map(x=>`<div class="timeline"><b>${esc(x.title||x.issue_type||'Finding')}</b><div class="muted">${esc(x.recommendation||'')}</div></div>`).join(''):'<div class="empty">No open findings.</div>'}</section><section class="panel"><div class="panel-head"><h2>Recommendations</h2></div><div class="panel-body">${(r.recommendations||[]).map(x=>`<div class="timeline">${esc(x)}</div>`).join('')||'<div class="empty">No recommendations.</div>'}</div></section></div></div>`}catch(e){document.getElementById('content').innerHTML='<div class="error">Unable to load device: '+esc(e.message)+'</div>';document.getElementById('state').textContent='Unavailable'}}
function csrf(){const raw=(document.cookie.match('(?:^|; )godseye_csrf=([^;]*)')||[])[1]||'';return decodeURIComponent(raw)}async function saveIdentity(){const status=document.getElementById('identitySaveStatus'),btn=document.getElementById('saveIdentityBtn');const hostname=(document.getElementById('identityHostname')?.value||'').trim(),device_type=(document.getElementById('identityType')?.value||'').trim(),classification=document.getElementById('identityClassification')?.value||'new';if(btn)btn.disabled=true;if(status)status.textContent='Saving identity‚Ä¶';try{const r=await fetch('/api/v1/devices/'+DEVICE_ID,{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({hostname,device_type,classification})});const t=await r.text();if(!r.ok)throw new Error(t);if(status)status.textContent='Identity saved.';await load()}catch(e){if(status)status.textContent='Could not save identity: '+e.message}finally{if(btn)btn.disabled=false}}async function mutate(path){const r=await fetch(path,{method:'POST',headers:{'X-CSRF-Token':csrf()}});const t=await r.text();if(!r.ok)throw new Error(t);return t?JSON.parse(t):{}}async function renameCurrentDevice(){const old=(CURRENT_DEVICE&&CURRENT_DEVICE.name)||'';const name=prompt(old?'Rename this device:':'Name this device:',old||(CURRENT_DEVICE&&CURRENT_DEVICE.hostname)||'');if(name===null)return;const clean=name.trim();if(!clean){alert('Device name cannot be blank.');return}try{const r=await fetch('/api/v1/devices/'+DEVICE_ID,{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify({name:clean})});const t=await r.text();if(!r.ok)throw new Error(t);await load()}catch(e){alert('Could not rename device: '+e.message)}}async function diagnose(){const el=document.getElementById('diag');el.textContent='Running diagnostics‚Ä¶';try{const r=await mutate('/api/v1/devices/'+DEVICE_ID+'/diagnose');el.textContent='Diagnostics complete: '+JSON.stringify(r)}catch(e){el.textContent='Diagnostics failed: '+e.message}}async function recheck(){const el=document.getElementById('diag');el.textContent='Rechecking device‚Ä¶';try{await mutate('/api/v1/devices/'+DEVICE_ID+'/recheck');el.textContent='Recheck complete. Refreshing‚Ä¶';await load()}catch(e){el.textContent='Recheck failed: '+e.message}}load();
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
<title>GODSEYE ‚Äî Network Monitor</title>
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
.sortable-head{cursor:pointer;user-select:none;position:relative;padding-right:24px!important}.sortable-head:hover{color:#235f9f;background:#f7faff}.sortable-head::after{content:"‚Üï";position:absolute;right:8px;opacity:.35;font-size:10px}.sortable-head.sort-asc::after{content:"‚Üë";opacity:1}.sortable-head.sort-desc::after{content:"‚Üì";opacity:1}.protected-audit{background:#fff8e8}.protected-audit td:first-child{box-shadow:inset 3px 0 0 #f2a51a}.admin-only{display:none}.admin-visible{display:inline-flex}
@media(max-width:1000px){.device-detail-shell{grid-template-columns:1fr}.kpi-row{grid-template-columns:repeat(2,1fr)}}
/* GODSEYE v1.9 screenshot-matched UI + stability pass */
:root{color-scheme:light;--navy:#07101c;--navy-2:#0b1728;--blue:#0d74f5;--blue-2:#1b84ff;--ink:#17263c;--muted:#6f8097;--line:#dce6f1;--surface:#ffffff;--canvas:#f5f9fd;--green:#11a86b;--red:#ef4f5f;--amber:#f2a51a;--purple:#6d5bd0}
html,body{min-height:100%;background:var(--canvas);color:var(--ink)}
body{font-size:14px}.shell{min-height:100vh;background:var(--canvas)}
.sidebar{width:188px;background:linear-gradient(180deg,#07101c 0%,#081522 100%);border-right:0;box-shadow:8px 0 28px rgba(18,43,72,.08);padding:20px 0 16px}
.sidebar .brand{padding:2px 18px 22px;margin:0 0 8px;border-bottom:0;justify-content:center;flex-direction:column;text-align:center;gap:5px}.sidebar .brand .eye{background:transparent;width:74px;height:48px;border-radius:0}.sidebar .brand .eye-logo{width:72px;height:44px}.sidebar .brand b{font-size:15px;color:#fff;letter-spacing:.12em}.sidebar .brand .muted{font-size:8px;letter-spacing:.08em;color:#7790ab}.navsection{color:#58708c;padding:15px 18px 5px;font-size:9px}.navitem{padding:10px 15px;color:#d1d9e5;border-left:0;border-radius:6px;margin:1px 8px;width:calc(100% - 16px);font-size:12px}.navitem:hover{background:#0f2238;color:#fff}.navitem.active{background:linear-gradient(90deg,#0a67d9,#0e7cf8);color:#fff;border-left:0;box-shadow:0 5px 14px rgba(0,112,242,.22)}.navicon{width:18px;text-align:center;color:inherit}.navitem .badge{background:#ec4d5c;color:#fff;border:1px solid rgba(255,255,255,.25)}
.sidebar-footer{border-top:1px solid #13243a;margin-top:auto;padding:14px 14px 0}.sidebar-footer .primary{width:100%;margin-bottom:4px}.sidebar-footer .muted{color:#7690ad}.sidebar-footer .link{color:#99abc0;text-align:left}
.content{background:var(--canvas);min-height:100vh}.headerbar{height:58px;background:#fff;border-bottom:1px solid #e6edf5;display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:10}.headerbar>.muted{font-size:11px}.top-actions{display:flex;align-items:center;gap:8px}.status-chip{display:inline-flex;align-items:center;gap:6px;background:#e9fbf2;color:#128451;border-radius:999px;padding:5px 9px;font-size:10px}.status-dot{width:6px;height:6px;border-radius:50%;background:#12aa69}.icon-btn{width:32px;height:32px;border:0;background:transparent;padding:0;display:grid;place-items:center}.avatar{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;background:#e7f1ff;color:#0d74f5;font-weight:800}
.wrap{max-width:none;margin:0;padding:22px 24px 42px}.hero{margin-bottom:18px;align-items:center}.hero h1{font-size:23px;letter-spacing:-.025em;margin:0 0 3px}.hero .muted{font-size:11px}.actions{display:flex;gap:8px;align-items:center}.dashboard-statusline{margin-top:5px!important}.cards{grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card,.panel,.tool-card,.integration-card{border:1px solid #dbe5f0;border-radius:8px;background:#fff;box-shadow:0 2px 9px rgba(29,58,90,.035)}.card{padding:14px 15px;min-height:92px}.statcard{display:grid;grid-template-columns:34px 1fr auto;gap:10px;align-items:start}.stat-action{width:100%;text-align:left;color:inherit;font:inherit;cursor:pointer;transition:transform .14s ease,box-shadow .14s ease,border-color .14s ease}.stat-action:hover{transform:translateY(-2px);box-shadow:0 8px 22px rgba(22,73,125,.11);border-color:#bcd7f3}.stat-action:focus-visible{outline:3px solid rgba(13,116,245,.18);outline-offset:2px}.stat-action .statmeta:after{content:'  ‚Üí';color:#0d74f5;font-weight:800}.dashboard-return{display:none;align-items:center;gap:6px;margin-bottom:10px;padding:0!important;border:0!important;background:transparent!important;color:#0d74f5!important;font-weight:700;font-size:11px!important;box-shadow:none!important}.dashboard-return:hover{text-decoration:underline}.staticon{width:28px;height:28px;border-radius:7px;display:grid;place-items:center;background:#eaf6ff;color:#0874d7;font-weight:900}.staticon.green{background:#e9f9f2;color:#0d9c65}.staticon.red{background:#fff0f1;color:#ef4f5f}.staticon.purple{background:#f1efff;color:#6a5bd5}.statmeta{font-size:10px;color:#61738a}.statnum{font-size:25px;line-height:1.1;font-weight:800;margin-top:3px}.trend{font-size:9px;color:#0ca763;align-self:end;white-space:nowrap}.panel{margin-top:14px}.panel h2,.table-head{font-size:13px}.table-head{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;border-bottom:1px solid #e8eef5}.table-head h2,.panel .table-head h2{padding:0;border:0;font-size:13px}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(310px,.8fr);gap:12px}.traffic{min-height:310px}#trafficSvg{display:block;width:100%;height:230px;padding:8px 12px 0}.activity-list{padding:5px 14px 12px}.activity-row{display:grid;grid-template-columns:18px 1fr auto;gap:9px;align-items:center;padding:9px 0;border-bottom:1px solid #edf2f7}.activity-row:last-child{border-bottom:0}.activity-dot{width:9px;height:9px;border-radius:50%;background:#1677ee}.activity-dot.green{background:#0fb26d}.activity-title{font-weight:700;font-size:11px}.activity-sub,.activity-time{font-size:9px;color:#8391a5}.panel-subtle{font-size:10px;background:#fbfdff}.client-row{display:grid;grid-template-columns:minmax(120px,200px) 1fr 56px;gap:10px;align-items:center;margin:9px 0}.client-bar{height:8px;background:#edf2f7;border-radius:8px;overflow:hidden}.client-bar>span{display:block;height:100%;background:linear-gradient(90deg,#0d74f5,#4ba4ff);border-radius:8px}
button,.filter,.input{border-radius:6px;border-color:#d8e3ee;background:#fff;color:#24364f;font-size:11px}button{padding:7px 10px}button.primary,.primary{background:#0d74f5!important;border-color:#0d74f5!important;color:#fff!important;box-shadow:none}button.primary:hover,.primary:hover{background:#0969de!important}button.secondary,.secondary{background:#fff!important;border:1px solid #d5e1ed!important;color:#38516d!important}.input,.filter{padding:8px 10px}.toolbar{margin:12px 0}.panel table{background:#fff}th,td{padding:10px 11px;border-bottom:1px solid #e9eef5;font-size:10px}th{font-size:9px;color:#5c7088;background:#fbfdff;text-transform:none;letter-spacing:0;font-weight:700}tr:hover{background:#f5faff}.status-badge,.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 7px;font-size:9px;border:1px solid #cfe7db;background:#eafaf2;color:#0a8c57}.status-badge.severity-high,.status-badge.severity-critical{background:#fff0f1;border-color:#ffd4d8;color:#db3044}.status-badge.severity-medium,.status-badge.severity-warning{background:#fff7e6;border-color:#f8deb0;color:#b87500}.status-badge.severity-low{background:#fffbe7;border-color:#f1e6aa;color:#92750a}.device-icon{display:grid;place-items:center;width:24px;height:24px;border-radius:50%;background:#e9f5ff;color:#0675dd}.device-name{display:flex;align-items:center;gap:8px}.device-link{color:#0b68c9!important}.map-card{min-height:560px}.map-canvas{padding:24px;min-height:520px}.map-node{background:#fff}.tool-grid{gap:12px}.tool-card{padding:18px}.tool-icon{width:34px;height:34px;border-radius:50%;background:#10a9ba;color:#fff;display:grid;place-items:center;font-size:17px}.tool-card:nth-child(2) .tool-icon,.tool-card:nth-child(3) .tool-icon{background:#176fe8}.tool-card:nth-child(4) .tool-icon{background:#7457da}.tool-card:nth-child(5) .tool-icon{background:#13a564}.tool-card:nth-child(6) .tool-icon{background:#126cd9}.tool-card h3{font-size:13px;margin-bottom:4px}.tool-card p{font-size:10px;color:#718198}.tool-card .primary{display:inline-block;margin-top:10px}
.map-shell{display:grid;grid-template-columns:minmax(0,1fr) 230px;gap:14px;margin-top:14px}.map-main{min-width:0}.map-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:12px}.map-summary-card{border:1px solid #e0e9f2;background:#fff;border-radius:8px;padding:11px 12px}.map-summary-label{font-size:9px;color:#718198}.map-summary-value{font-size:16px;font-weight:800;color:#1d3048;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.map-toolbar2{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 12px;border-bottom:1px solid #e7eef5;background:#fbfdff}.map-toolbar2 .input{min-width:190px;flex:1}.map-viewport{position:relative;min-height:545px;overflow:auto;background-color:#f8fbff;background-image:radial-gradient(#d6e5f4 1px,transparent 1px);background-size:20px 20px}.map-stage{min-width:760px;min-height:515px;padding:34px 44px 58px;transform-origin:top center;transition:transform .15s ease}.map-canvas{padding:0!important;min-height:auto!important;justify-content:flex-start!important}.map-node{min-width:142px;max-width:180px;padding:10px 9px 9px;border:1px solid #dce7f1;border-radius:10px;background:#fff!important;box-shadow:0 4px 14px rgba(33,66,100,.07);cursor:default;transition:box-shadow .15s ease,border-color .15s ease,transform .15s ease}.map-node.device-clickable{cursor:pointer}.map-node.device-clickable:hover{border-color:#91c6f4;box-shadow:0 8px 20px rgba(13,116,245,.14);transform:translateY(-2px)}.map-circle{width:38px!important;height:38px!important;box-shadow:none!important}.map-node.offline-node .map-circle{background:#8b98a9!important}.map-node.issue-node .map-circle{background:#ef5b67!important}.map-node.infrastructure-node .map-circle{background:#725bd7!important}.map-label{font-size:10px!important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.map-sub{font-size:9px!important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.map-link-badge{display:inline-flex;margin-top:6px;padding:2px 6px;border-radius:999px;background:#eef6ff;color:#1769b4;font-size:8px;border:1px solid #d7eafc}.map-side{display:flex;flex-direction:column;gap:12px}.map-side-card{border:1px solid #dce7f1;background:#fff;border-radius:8px;padding:13px}.map-side-card h3{font-size:11px;margin:0 0 9px;color:#253a54}.map-legend-row{display:flex;align-items:center;gap:8px;font-size:9px;color:#61738a;margin:7px 0}.map-legend-dot{width:10px;height:10px;border-radius:50%;background:#1592e8;flex:0 0 auto}.map-legend-dot.green{background:#0da66a}.map-legend-dot.gray{background:#8b98a9}.map-legend-dot.purple{background:#725bd7}.map-legend-dot.red{background:#ef5b67}.map-tip{font-size:9px;line-height:1.5;color:#75859a}.map-zoom{display:flex;gap:5px}.map-zoom button{min-width:31px;padding:6px 8px}.map-empty{padding:80px 20px;text-align:center;color:#75859a}.map-children{align-items:flex-start;justify-content:center;flex-wrap:wrap;row-gap:28px}.map-children:before{left:6%;right:6%}@media(max-width:1100px){.map-shell{grid-template-columns:1fr}.map-side{display:grid;grid-template-columns:repeat(2,1fr)}.map-summary{grid-template-columns:repeat(2,1fr)}}@media(max-width:700px){.map-side{grid-template-columns:1fr}.map-summary{grid-template-columns:1fr 1fr}.map-stage{min-width:660px;padding-left:24px;padding-right:24px}}
.device-detail-shell{grid-template-columns:minmax(0,1.45fr) minmax(300px,.55fr)}.device-hero-card{border-top:3px solid #0d74f5}.back-btn{font-weight:700}.intel-kv{display:grid;grid-template-columns:120px 1fr;gap:8px 12px;font-size:11px}.intel-kv .k{color:#72839a}.timeline-row{padding:9px 0;border-bottom:1px solid #edf2f7;font-size:11px}.timeline-row:last-child{border-bottom:0}
/* Login and setup screens ‚Äî match the reference mountain composition. */
.overlay{background-image:linear-gradient(rgba(3,17,32,.18),rgba(3,17,32,.42)),url('/assets/login-bg.jpg');background-size:cover;background-position:center;position:fixed;inset:0}.authcard{max-width:350px;background:rgba(255,255,255,.97);border:1px solid rgba(255,255,255,.62);box-shadow:0 24px 60px rgba(0,15,34,.42);color:#16253a;border-radius:7px;padding:24px 26px}.authcard h2{text-align:center;font-size:20px;margin:2px 0 4px}.authcard> .muted,.authcard .login-brand+.muted{text-align:center}.login-brand{margin-bottom:13px;color:#fff;position:absolute;top:7%;left:50%;transform:translateX(-50%);text-shadow:0 2px 10px rgba(0,0,0,.45)}.login-brand .eye-logo{width:86px;height:52px}.login-brand b{font-size:28px;color:#fff}.login-brand .muted{color:#fff;font-size:10px}.authcard .input{background:#fff;color:#17263c;border:1px solid #cfddeb;height:38px}.authcard button.primary{height:38px}.authcard .err{color:#d73545}.login-scene-footer{position:absolute;bottom:20px;left:50%;transform:translateX(-50%);text-align:center;color:rgba(255,255,255,.8);font-size:9px;line-height:1.7;text-shadow:0 1px 3px rgba(0,0,0,.7)}
#setupOverlay .login-brand,#pwOverlay .login-brand,#mfaLoginOverlay .login-brand{position:static;transform:none;color:#16253a;text-shadow:none}#setupOverlay .login-brand b,#pwOverlay .login-brand b,#mfaLoginOverlay .login-brand b{color:#16253a}
.scan-status{min-height:18px;color:#86a0bc;font-size:9px;line-height:1.35;padding:2px 2px 6px}.scan-status.ok{color:#70d9a8}.scan-status.bad{color:#ff8290}.scan-status.busy{color:#9ac6ff}
@media(max-width:1100px){.cards{grid-template-columns:repeat(2,1fr)}.dashboard-grid{grid-template-columns:1fr}.sidebar{width:174px}.wrap{padding:18px}}
@media(max-width:820px){.sidebar{width:100%;height:auto;padding:8px 0}.sidebar .brand{display:none}.wrap{padding:14px}.headerbar{padding:0 12px}.cards{grid-template-columns:repeat(2,1fr)}.dashboard-grid{grid-template-columns:1fr}.authcard{margin-top:100px}.login-brand{top:3%}}
@media(max-width:560px){.cards{grid-template-columns:1fr 1fr}.card{padding:11px}.statnum{font-size:22px}.wrap{padding:10px}.hero h1{font-size:21px}.client-row{grid-template-columns:110px 1fr 42px}.login-brand b{font-size:24px}}


/* v2.5 realistic device icon picker */
.device-name .device-icon{width:42px;height:42px;border-radius:0;background:transparent;display:inline-grid;place-items:center;flex:0 0 42px}.device-name .device-icon img{width:40px;height:38px;object-fit:contain;filter:drop-shadow(0 2px 2px rgba(18,38,63,.22))}.device-icon-modal{position:fixed!important;inset:0!important;z-index:5000!important;place-items:center!important;background:rgba(7,16,28,.62)!important;padding:24px!important;overflow:auto!important}.device-icon-dialog{width:min(720px,calc(100vw - 32px))!important;max-width:720px!important;max-height:calc(100vh - 48px)!important;overflow:auto!important;padding:0!important;border:1px solid #d8e3ef!important;border-radius:13px!important;box-shadow:0 26px 90px rgba(2,12,27,.34)!important}.device-icon-dialog .modal-head{padding:18px 20px 12px;border-bottom:1px solid #edf2f7}.device-icon-dialog .modal-form{display:block!important;margin:0!important;padding:0 20px 18px!important}.device-icon-summary{display:flex;align-items:center;gap:14px;padding:14px 0}.device-icon-summary-art{width:72px;height:64px;border:1px solid #dce6f1;border-radius:10px;background:linear-gradient(180deg,#fff,#f6f9fc);display:grid;place-items:center}.device-icon-summary-art img{width:58px;height:58px;object-fit:contain;filter:drop-shadow(0 3px 3px rgba(17,39,64,.2))}.device-icon-summary-name{font-size:16px;font-weight:750;color:#0b6ddd}.device-icon-summary-meta{font-size:12px;color:#64768d;line-height:1.5}.device-icon-tabs{display:flex;gap:24px;border-bottom:1px solid #e5edf5;margin-bottom:14px;overflow:auto}.device-icon-tab{border:0;background:transparent;padding:10px 2px 9px;color:#61738b;font-size:11px;white-space:nowrap;cursor:pointer;border-bottom:2px solid transparent;border-radius:0}.device-icon-tab.active{color:#0d74f5;border-bottom-color:#0d74f5;font-weight:700}.device-icon-picker{display:grid;grid-template-columns:repeat(5,minmax(96px,1fr));gap:10px;max-height:390px;overflow:auto;padding:2px}.device-icon-choice{position:relative;border:1px solid #d8e3ef;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:9px;padding:9px 6px 8px;cursor:pointer;text-align:center;color:#30445e;font-size:10px;min-height:92px}.device-icon-choice:hover{border-color:#86bdfb;background:#f7fbff}.device-icon-choice.selected{border:2px solid #0d74f5;padding:8px 5px 7px;box-shadow:0 0 0 2px rgba(13,116,245,.09)}.device-icon-choice.selected:after{content:'‚úì';position:absolute;top:5px;right:5px;width:18px;height:18px;border-radius:50%;background:#0d74f5;color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.device-icon-choice img{width:66px;height:58px;display:block;object-fit:contain;margin:0 auto 5px;filter:drop-shadow(0 3px 3px rgba(18,38,63,.2))}.device-icon-custom{border-top:1px solid #e4ebf3;margin-top:14px;padding-top:13px}.custom-icon-preview{width:58px;height:58px;object-fit:contain;border:1px solid #d8e3ef;border-radius:8px;background:#fff;padding:4px}.icon-upload-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.device-icon-dialog .modal-actions{display:flex!important;justify-content:flex-end!important;gap:8px;border-top:1px solid #edf2f7;padding-top:14px;margin-top:14px}.device-icon-dialog .err{margin-top:8px}@media(max-width:700px){.device-icon-modal{padding:10px!important;align-items:center!important}.device-icon-dialog{max-height:calc(100vh - 20px)!important}.device-icon-picker{grid-template-columns:repeat(3,1fr)}.device-icon-tabs{gap:14px}.device-icon-summary-art{width:60px;height:56px}.device-icon-summary-art img{width:48px;height:48px}}


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

/* v4.0 ‚Äî full dashboard dark mode */
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
[data-theme="dark"] .report-summary,[data-theme="dark"] #reportSummary{backgroun€ÆwÔfÚµÎ(ö+my÷W&Ê÷R#„∆ñÁWBñC“&Ê˜Fñgï6◊G˜'B"6∆73“&ñÁWB"GóS“&ÁV÷&W""f«VS“#SÉr"∆6VÜˆ∆FW#“%˜'B#„¬ˆFóc„∆ñÁWBñC“&Ê˜Fñgï6◊G72"6∆73“&ñÁWB"GóS“'77v˜&B"∆6VÜˆ∆FW#“%77v˜&BÜ&∆Ê≤∂VW26fVBí#„∆ñÁWBñC“&Ê˜Fñgï6◊Gg&ˆ“"6∆73“&ñÁWB"∆6VÜˆ∆FW#“$g&ˆ“FG&W72#„∆ñÁWBñC“&Ê˜FñgîV÷ñ¬"6∆73“&ñÁWB"∆6VÜˆ∆FW#“%&V6óñVÁBFG&W72#„¬ˆFóc„¬ˆFóc‡£¬ˆFóc„∆Fób6∆73“&Ê˜Fñgí÷fˆ˜FW"#„∆∆&V¬6∆73“&◊WFVB#‰÷ñÊñ◊V“∆W'B6WfW&óGí«6V∆V7BñC“&Ê˜Fñgï6WfW&óGí"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“&ñÊfÚ#‰ñÊfÚÊB&˜fS¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'v&ÊñÊr"6V∆V7FVCÂv&ÊñÊrÊB7&óFñ6√¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&7&óFñ6¬#‰7&óFñ6¬ˆÊ«ì¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√„∆Fóc„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'6fTÊ˜Fñfñ6FñˆÁ2Çí#Â6fRÊ˜Fñfñ6Fñˆ‚6WGFñÊw3¬ˆ'WGFˆ„‚∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'FW7DÊ˜Fñfñ6FñˆÁ2Çí#Â6VÊBFW7C¬ˆ'WGFˆ„„¬ˆFóc„∆FóbñC“&Ê˜Fñgî˜WB"6∆73“&◊WFVB"7Gñ∆S“'vñGFÉ£R#„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£∆Fób6∆73“'fñWr"ñC“'fñWr÷6∆VÊF""7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“&6∆VÊF"◊vR#‡¢∆Fób6∆73“&6∆VÊF"÷ÜW&Ú#‡¢∆Fób6∆73“&6∆VÊF"÷ÜW&Ú÷6˜í#„∆Fób6∆73“&6∆VÊF"÷ÜW&Ú÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«&V7BÉ“#2"ì“#R"vñGFÉ“#Ç"ÜVñváC“#b"'É“#""Û„«FÇC“$”r7cD”r7cD”2ÉÑ”rFÇ„”"FÇ„”rFÇ„”rÜÇ„”"ÜÇ„"Û„¬˜7fs„¬ˆFóc„∆Fóc„∆É‰6∆VÊF#¬ˆÉ„∆Fób6∆73“&◊WFVB#Â∆‚÷ñÁFVÊÊ6R¬ˆñÁF÷VÁG2¬&WfñWw2ÊBÊWGv˜&≤◊6V7W&óGív˜&≤g&ˆ“ˆÊR6Ü&VB∆ñÊ6R6∆VÊF"„¬ˆFóc„¬ˆFóc„¬ˆFóc‡¢¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"◊6ÜV∆¬#‡¢∆6ñFR6∆73“&6∆VÊF"◊6ñFR#‡¢∆Fób6∆73“&6∆VÊF"◊6ñFR÷&∆ˆ6≤#„∆Fób6∆73“&6∆VÊF"◊6ñFR◊FóF∆R#‰6∆VÊF"ñÁFVw&FñˆÁ2∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&˜V‰6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Çí#‰÷ÊvS¬ˆ'WGFˆ„„¬ˆFóc‡¢∆∆&V¬FF◊6˜W&6S“&∆ˆ6¬"6∆73“&6∆VÊF"÷fñ«FW"6∆VÊF"◊7vóF6Ç◊&˜r7FófR"ˆÊ6∆ñ6≥“'6V∆V7D6∆VÊF%6˜W&6RÇv∆ˆ6¬rí#„∆ñÁWBGóS“&6ÜV6∂&˜Ç"6ÜV6∂VBˆÊ6ÜÊvS“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∑Fˆvv∆T6∆VÊF%6˜W&6RÇv∆ˆ6¬r«FÜó2Ê6ÜV6∂VBí#„«7‚6∆73“&6∆VÊF"÷F˜B&«VR#„¬˜7„„«7„‰tÙE4UîS¬˜7„„¬ˆ∆&V√‡¢∆FóbñC“&6∆VÊF$WáFW&Êƒfñ«FW'2#„¬ˆFóc‡¢¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"◊6ñFR÷&∆ˆ6≤#„∆Fób6∆73“&6∆VÊF"◊6ñFR◊FóF∆R#ÂW6ˆ÷ñÊrWfVÁG3¬ˆFóc„∆FóbñC“&6∆VÊF%W6ˆ÷ñÊr"6∆73“&6∆VÊF"◊W6ˆ÷ñÊr#„∆Fób6∆73“&V◊Gí#‰ÊÚW6ˆ÷ñÊrˆñÁF÷VÁG2„¬ˆFóc„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"◊6ñFR÷&∆ˆ6≤cC3÷6∆VÊF"◊7FFó7Fñ72#„∆Fób6∆73“&6∆VÊF"◊6ñFR◊FóF∆R#‰6∆VÊF"7FFó7Fñ72«7„ÂFÜó2÷ˆÁFÉ¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3÷6∆VÊF"◊7FB÷w&ñB#„∆Fóc„∆"ñC“&6∆VÊF%7FEF˜F¬#„¬ˆ#„«6÷∆√ÂF˜F¬WfVÁG3¬˜6÷∆√„¬ˆFóc„∆Fóc„∆"ñC“&6∆VÊF%7FD÷ñÁFVÊÊ6R#„¬ˆ#„«6÷∆√‰÷ñÁFVÊÊ6S¬˜6÷∆√„¬ˆFóc„∆Fóc„∆"ñC“&6∆VÊF%7FEFñ6∂WG2#„¬ˆ#„«6÷∆√ÂFñ6∂WG3¬˜6÷∆√„¬ˆFóc„∆Fóc„∆"ñC“&6∆VÊF%7FD÷VWFñÊw2#„¬ˆ#„«6÷∆√‰÷VWFñÊw3¬˜6÷∆√„¬ˆFóc„¬ˆFóc„¬ˆFóc‡¢¬ˆ6ñFS‡¢«6V7Fñˆ‚6∆73“&6∆VÊF"÷÷ñ‚÷6&B#‡¢∆Fób6∆73“&6∆VÊF"◊Fˆˆ∆&"#‡¢∆Fób6∆73“&6∆VÊF"÷Êb÷7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆VÊF%FˆFíÇí#ÂFˆFì¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆VÊF%7FWÇ”í"FóF∆S“%&Wfñ˜W2÷ˆÁFÇ#Ó(ì¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆VÊF%7FWÉí"FóF∆S“$ÊWáB÷ˆÁFÇ#Ó(£¬ˆ'WGFˆ„„∆É"ñC“&6∆VÊF$÷ˆÁFÑ∆&V¬#‰÷ˆÁFÉ¬ˆÉ#„¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"◊fñWr◊7vóF6Ç"&ˆ∆S“&w&˜W"&ñ÷∆&V√“$6∆VÊF"fñWr#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&7FófR"FF÷6∆VÊF"÷÷ˆFS“&÷ˆÁFÇ"ˆÊ6∆ñ6≥“'6WD6∆VÊF%fñWt÷ˆFRÇv÷ˆÁFÇrí#‰÷ˆÁFÉ¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"FF÷6∆VÊF"÷÷ˆFS“'vVV≤"ˆÊ6∆ñ6≥“'6WD6∆VÊF%fñWt÷ˆFRÇwvVV≤rí#ÂvVV≥¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"FF÷6∆VÊF"÷÷ˆFS“&Fí"ˆÊ6∆ñ6≥“'6WD6∆VÊF%fñWt÷ˆFRÇvFírí#‰Fì¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"FF÷6∆VÊF"÷÷ˆFS“&∆ó7B"ˆÊ6∆ñ6≥“'6WD6∆VÊF%fñWt÷ˆFRÇv∆ó7Brí#‰∆ó7C¬ˆ'WGFˆ„„¬ˆFóc„∆'WGFˆ‚6∆73“'&ñ÷'íF÷ñ‚÷ˆÊ«í6∆VÊF"◊Fˆˆ∆&"÷7&VFR"ˆÊ6∆ñ6≥“&˜V‰6∆VÊF$WfVÁD÷ˆF¬Çí#Ó˚»≤7&VFRWfVÁC¬ˆ'WGFˆ„‡¢¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"◊vVV≤÷ÜVB#„«7„Â7V„¬˜7„„«7„‰÷ˆ„¬˜7„„«7„ÂGVS¬˜7„„«7„ÂvVC¬˜7„„«7„ÂFáS¬˜7„„«7„‰g&ì¬˜7„„«7„Â6C¬˜7„„¬ˆFóc‡¢∆FóbñC“&6∆VÊF$w&ñB"6∆73“&6∆VÊF"÷w&ñB#„¬ˆFóc‡¢¬˜6V7Fñˆ„‡¢¬ˆFóc‡£¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“&6∆VÊF$WfVÁD÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6T6∆VÊF$WfVÁD÷ˆF¬Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&B6∆VÊF"÷WfVÁB÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&6∆VÊF$WfVÁD÷ˆF≈FóF∆R#‰7&VFRˆñÁF÷VÁC¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰FB‚ˆñÁF÷VÁB¬÷ñÁFVÊÊ6RvñÊF˜r¬&WfñWr˜"&V÷ñÊFW"„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6T6∆VÊF$WfVÁD÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“6∆73“&6∆VÊF"÷WfVÁB÷f˜&“"ˆÁ7V&÷óC“'&WGW&‚6fT6∆VÊF$WfVÁBÜWfVÁBí#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&6∆VÊF$WfVÁDñB#‡¢∆∆&V¬6∆73“&gV∆¬#ÂFóF∆S∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$WfVÁEFóF∆R"÷Ü∆VÊwFÉ“#c"&WVó&VB∆6VÜˆ∆FW#“$WÜ◊∆S¢fó&Wv∆¬÷ñÁFVÊÊ6R#„¬ˆ∆&V√‡¢∆∆&V√Â7F'C∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$WfVÁE7F'B"GóS“&FFWFñ÷R÷∆ˆ6¬"&WVó&VC„¬ˆ∆&V√‡¢∆∆&V√‰VÊC∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$WfVÁDVÊB"GóS“&FFWFñ÷R÷∆ˆ6¬"&WVó&VC„¬ˆ∆&V√‡¢∆∆&V√‰∆ˆ6Fñˆ„∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$WfVÁD∆ˆ6Fñˆ‚"÷Ü∆VÊwFÉ“#3"∆6VÜˆ∆FW#“%6W'fW"&ˆˆ“ÚFV◊2Úˆffñ6R#„¬ˆ∆&V√‡¢∆∆&V√‰6∆VÊF#«6V∆V7B6∆73“&fñ«FW""ñC“&6∆VÊF$WfVÁEF&vWB#„∆˜Fñˆ‚f«VS“"#‰tÙE4UîR∆ˆ6¬6∆VÊF#¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√‰6ˆ∆˜#«6V∆V7B6∆73“&fñ«FW""ñC“&6∆VÊF$WfVÁD6ˆ∆˜"#„∆˜Fñˆ‚f«VS“&&«VR#‰&«VS¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&w&VV‚#‰w&VV„¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'W'∆R#ÂW'∆S¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&˜&ÊvR#‰˜&ÊvS¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'&VB#Â&VC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&6∆VÊF"÷6ÜV6≤#„∆ñÁWBGóS“&6ÜV6∂&˜Ç"ñC“&6∆VÊF$WfVÁD∆ƒFí#‚∆¬÷FíWfVÁC¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬#‰Ê˜FW3«FWáF&V6∆73“&ñÁWB"ñC“&6∆VÊF$WfVÁDFW67&óFñˆ‚"&˜w3“#B"÷Ü∆VÊwFÉ“#C"∆6VÜˆ∆FW#“$FBFWFñ«2¬vVÊF¬Fñ6∂WBÁV÷&W"˜"÷ñÁFVÊÊ6RÊ˜FW2#„¬˜FWáF&V„¬ˆ∆&V√‡¢∆FóbñC“&6∆VÊF%Fñ6∂WD7FñˆÁ2"6∆73“&6∆VÊF"◊Fñ6∂WB÷7FñˆÁ2gV∆¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#„∆Fóc„∆"ñC“&6∆VÊF%Fñ6∂WD∆&V¬#‰∆ñÊ∂VBFñ6∂WC¬ˆ#„∆Fób6∆73“&◊WFVB#Âv˜&≤ÊB6∆˜6RFÜR∆ñÊ∂VBFñ6∂WBFó&V7F«íg&ˆ“6∆VÊF"„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&˜V‰6∆VÊF$∆ñÊ∂VEFñ6∂WBÇí#‰˜V‚Fñ6∂WC¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&FD6∆VÊF%Fñ6∂WDÊ˜FRÇí#‰FBv˜&≤Ê˜FS¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“'&W6ˆ«fT6∆VÊF%Fñ6∂WBÇí#Â&W6ˆ«fS¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FÊvW"˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&6∆˜6T6∆VÊF%Fñ6∂WBÇí#‰6∆˜6RFñ6∂WC¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢∆FóbñC“&6∆VÊF$WfVÁDW'""6∆73“&W'"gV∆¬#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2gV∆¬#„∆'WGFˆ‚GóS“&'WGFˆ‚"ñC“&6∆VÊF$FV∆WFT'F‚"6∆73“&FÊvW""7Gñ∆S“&Fó7∆ì¶ÊˆÊS∂÷&vñ‚◊&ñváC¶WFÚ"ˆÊ6∆ñ6≥“&FV∆WFT6∆VÊF$WfVÁBÇí#‰FV∆WFS¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6T6∆VÊF$WfVÁD÷ˆF¬Çí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“'&ñ÷'í#Â6fS¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“&6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6T6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&B6∆VÊF"÷ñÁFVw&Fñˆ‚÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#‰6∆VÊF"ñÁFVw&FñˆÁ3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰6ˆÊÊV7Bvˆˆv∆R6∆VÊF"˜"÷ñ7&˜6ˆgB3cRf˜"gV∆¬GvÚ◊víVFóFñÊr¬˜"∂VWî522&VB÷ˆÊ«íf∆∆&6≤„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6T6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷&ˆGí#‡¢∆Fób6∆73“&6∆VÊF"◊&˜fñFW"÷w&ñB#‡¢∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&6∆VÊF"◊&˜fñFW"7FófR"FF◊&˜fñFW#“&÷ñ7&˜6ˆgC3cR"ˆÊ6∆ñ6≥“'6V∆V7D6∆VÊF%&˜fñFW"Çv÷ñ7&˜6ˆgC3cRrí#„«7‚6∆73“&6∆VÊF"◊&˜fñFW"÷ñ6ˆ‚#‰Û¬˜7„„∆#‰˜WF∆ˆˆ≤6∆VÊF#¬ˆ#„«6÷∆√‰WFˆ÷Fñ26WGWg&ˆ“˜WF∆ˆˆ≤÷ñ√¬˜6÷∆√„¬ˆ'WGFˆ„‡¢¬ˆFóc‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&6∆VÊF%&˜fñFW""f«VS“&÷ñ7&˜6ˆgC3cR#‡¢∆Fób6∆73“&6∆VÊF"÷÷ˆFR◊F'2#‡¢∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&6∆VÊF"÷÷ˆFR◊F"7FófR"FF÷÷ˆFS“&ˆWFÇ"ˆÊ6∆ñ6≥“'6V∆V7D6∆VÊF$WFÑ÷ˆFRÇvˆWFÇrí#ÂGvÚ◊víÙWFÉ¬ˆ'WGFˆ„‡¢∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&6∆VÊF"÷÷ˆFR◊F""FF÷÷ˆFS“&&6ñ2"ˆÊ6∆ñ6≥“'6V∆V7D6∆VÊF$WFÑ÷ˆFRÇv&6ñ2rí#‰◊77v˜&Bî53¬ˆ'WGFˆ„‡¢∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&6∆VÊF"÷÷ˆFR◊F""FF÷÷ˆFS“&ñ72"ˆÊ6∆ñ6≥“'6V∆V7D6∆VÊF$WFÑ÷ˆFRÇvñ72rí#‰î52&VB÷ˆÊ«íf∆∆&6≥¬ˆ'WGFˆ„‡¢¬ˆFóc‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&6∆VÊF$WFÑ÷ˆFR"f«VS“&ˆWFÇ#‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷f˜&“#‡¢∆∆&V√‰Ê÷S∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰Ê÷R"∆6VÜˆ∆FW#“%v˜&≤6∆VÊF"#„¬ˆ∆&V√‡¢∆∆&V√‰66˜VÁBV÷ñ√∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰V÷ñ¬"GóS“&V÷ñ¬"∆6VÜˆ∆FW#“&Ê÷TWÜ◊∆RÊ6ˆ“#„¬ˆ∆&V√‡¢∆∆&V√‰6∆VÊF"Ê÷S∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰6∆VÊF""∆6VÜˆ∆FW#“%&ñ÷'íÚ6V7W&óGíFV“#„¬ˆ∆&V√‡¢∆∆&V√Â&V÷˜FR6∆VÊF"îC∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$ñÁFVw&FñˆÂ&V÷˜FTñB"∆6VÜˆ∆FW#“'&ñ÷'í#„¬ˆ∆&V√‡¢∆∆&V√Â7ñÊ2WfW'ì«6V∆V7B6∆73“&fñ«FW""ñC“&6∆VÊF$ñÁFVw&Fñˆ‰ñÁFW'f¬#„∆˜Fñˆ‚f«VS“#R#„R÷ñÁWFW3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#3"6V∆V7FVC„3÷ñÁWFW3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#c#„Ü˜W#¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#É#„2Ü˜W'3¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰6∆ñVÁDñB"f«VS“"#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰6∆ñVÁE6V7&WB"f«VS“"#‡¢∆∆&V¬ñC“&6∆VÊF$&6ñ5W6W%w&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#ÂW6W&Ê÷RÚV÷ñ√∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰&6ñ5W6W""GóS“&V÷ñ¬"∆6VÜˆ∆FW#“&Ê÷TWÜ◊∆RÊ6ˆ“#„¬ˆ∆&V√‡¢∆∆&V¬ñC“&6∆VÊF$&6ñ577v˜&Ew&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‰77v˜&C∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰&6ñ577v˜&B"GóS“'77v˜&B"∆6VÜˆ∆FW#“$77v˜&B#„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬"ñC“&6∆VÊF$ñ75w&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#Â&ófFRî527V'67&óFñˆ‚U$√∆ñÁWB6∆73“&ñÁWB"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰ñ72"GóS“'W&¬"∆6VÜˆ∆FW#“&áGG3¢ÚÚ‚‚‚ˆ6∆VÊF"Êñ72#„¬ˆ∆&V√‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FRgV∆¬"ñC“&6∆VÊF$ñÁFVw&Fñˆ‰÷ˆFTÊ˜FR#ÂGvÚ◊víÙWFÇ∆WG2tÙE4UîR7&VFR¬VFóBÊBFV∆WFRWfVÁG2ñ‚FÜR6ˆÊÊV7FVB6∆VÊF"‚ñ˜W"77v˜&Bó2VÊ7'óFVBB&W7B„¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FRgV∆¬#ÂFÜR6∆VÊF"ó2∆ñÊ∂VBWFˆ÷Fñ6∆«ígFW"˜WF∆ˆˆ≤÷ñ¬6WGW„¬ˆFóc‡¢∆FóbñC“&6∆VÊF$ñÁFVw&Fñˆ‰W'""6∆73“&W'"gV∆¬#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2gV∆¬#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6T6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Çí#‰6∆˜6S¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&ñ÷'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“'6fT6∆VÊF$ñÁFVw&Fñˆ‚Çí#Â6fRñÁFVw&Fñˆ„¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"÷6ˆÊÊV7FVB◊FóF∆R#‰6ˆÊÊV7FVB6∆VÊF'3¬ˆFóc‡¢∆FóbñC“&6∆VÊF$ñÁFVw&Fñˆ‰∆ó7B"6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷∆ó7B#„∆Fób6∆73“&V◊Gí#‰ÊÚWáFW&Ê¬6∆VÊF"ñÁFVw&FñˆÁ26ˆÊfñwW&VB„¬ˆFóc„¬ˆFóc‡¢¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr÷V÷ñ¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“&V÷ñ¬◊vR#‡¢∆Fób6∆73“&V÷ñ¬÷ÜW&Ú#‡¢∆Fób6∆73“&V÷ñ¬÷ÜW&Ú÷6˜í#„∆Fób6∆73“&V÷ñ¬÷ÜW&Ú÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«&V7BÉ“#2"ì“#R"vñGFÉ“#Ç"ÜVñváC“#B"'É“#""Û„«FÇC“&”BrÇbÇ”b"Û„¬˜7fs„¬ˆFóc„∆Fóc„∆É‰V÷ñ√¬ˆÉ„∆Fób6∆73“&◊WFVB#‰÷ñ7&˜6ˆgB˜WF∆ˆˆ≤÷ñ¬ñÁ6ñFRtÙE4UîRf˜"˜W&FñˆÊ¬6ˆ÷◊VÊñ6Fñˆ‚¬∆W'G2¬ÊB&W˜'BFV∆ófW'í„¬ˆFóc„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&V÷ñ¬÷ÜW&Ú÷7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çí#Ó)©í÷ñ¬66˜VÁG3¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜V‰V÷ñƒ6ˆ◊˜6RÇí#Ó˚»≤6ˆ◊˜6S¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFóc‡¢∆FóbñC“&V÷ñƒ66˜VÁD6&G2"6∆73“'cC3÷V÷ñ¬÷66˜VÁB÷6&G2#„∆'WGFˆ‚6∆73“'cC3÷V÷ñ¬÷66˜VÁB÷6&B"ˆÊ6∆ñ6≥“&˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çí#„«7‚6∆73“'cC3÷÷ñ¬÷∆ˆvÚ#‰s¬˜7„„∆Fóc„∆#‰v÷ñ√¬ˆ#„«6÷∆√‰6ˆÊÊV7B÷ñ∆&˜É¬˜6÷∆√„¬ˆFóc„∆V”Ó˚»≥¬ˆV”„¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'cC3÷V÷ñ¬÷66˜VÁB÷6&B"ˆÊ6∆ñ6≥“&˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çí#„«7‚6∆73“'cC3÷÷ñ¬÷∆ˆvÚ◊2#‰Û¬˜7„„∆Fóc„∆#‰÷ñ7&˜6ˆgB3cS¬ˆ#„«6÷∆√‰6ˆÊÊV7B÷ñ∆&˜É¬˜6÷∆√„¬ˆFóc„∆V”Ó˚»≥¬ˆV”„¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'cC3÷V÷ñ¬÷66˜VÁB÷6&B&V∆í"ˆÊ6∆ñ6≥“&˜V‰6&EvRÇvñÁFVw&FñˆÁ2rí#„«7‚6∆73“'cC3÷÷ñ¬÷∆ˆvÚ#Ó)»ì¬˜7„„∆Fóc„∆#Â4’E&V∆ì¬ˆ#„«6÷∆√‰∆W'BFV∆ófW'ì¬˜6÷∆√„¬ˆFóc„∆V”Ó(£¬ˆV”„¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'cC3÷V÷ñ¬÷66˜VÁB÷6&B&V∆í"ˆÊ6∆ñ6≥“&˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çí#„«7‚6∆73“'cC3÷÷ñ¬÷∆ˆvÚ#Ó)©ì¬˜7„„∆Fóc„∆#‰÷ñ¬66˜VÁG3¬ˆ#„«6÷∆√‰ÙWFÇ6ˆÊÊV7FñˆÁ3¬˜6÷∆√„¬ˆFóc„∆V”Ó(£¬ˆV”„¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“&V÷ñ¬◊6ÜV∆¬#‡¢∆6ñFR6∆73“&V÷ñ¬÷fˆ∆FW'2#‡¢∆'WGFˆ‚6∆73“&V÷ñ¬÷6ˆ◊˜6R÷'F‚˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜V‰V÷ñƒ6ˆ◊˜6RÇí#Ó˚»≤6ˆ◊˜6S¬ˆ'WGFˆ„‡¢«6V∆V7BñC“&V÷ñƒ66˜VÁE6V∆V7B"6∆73“&fñ«FW"V÷ñ¬÷66˜VÁB◊6V∆V7B"ˆÊ6ÜÊvS“'6V∆V7DV÷ñƒ66˜VÁBáFÜó2Áf«VRí#„¬˜6V∆V7C‡¢∆FóbñC“&V÷ñƒfˆ∆FW$∆ó7B"6∆73“&V÷ñ¬÷fˆ∆FW"÷∆ó7B#„∆Fób6∆73“&V◊Gí#‰6ˆÊÊV7B÷ñ¬66˜VÁBFÚ&Vvñ‚„¬ˆFóc„¬ˆFóc‡¢¬ˆ6ñFS‡¢«6V7Fñˆ‚6∆73“&V÷ñ¬÷∆ó7B◊ÊR#‡¢∆Fób6∆73“&V÷ñ¬◊Fˆˆ∆&"#‡¢∆Fób6∆73“&V÷ñ¬◊6V&6Ç◊w&#„∆ñÁWBñC“&V÷ñ≈6V&6Ç"6∆73“&ñÁWB"∆6VÜˆ∆FW#“%6V&6Ç÷ñ¬"ˆÊ∂WñF˜v„“&ñbÜWfVÁBÊ∂Wì””“tVÁFW"rñ∆ˆDV÷ñƒ÷W76vW2Çí#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&∆ˆDV÷ñƒ÷W76vW2Çí#Â6V&6É¬ˆ'WGFˆ„„¬ˆFóc‡¢∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&∆ˆDV÷ñƒ÷W76vW2Çí"FóF∆S“%&Vg&W6Ç#Ó(k≥¬ˆ'WGFˆ„‡¢¬ˆFóc‡¢∆FóbñC“&V÷ñƒ∆ó7D÷WF"6∆73“&V÷ñ¬÷∆ó7B÷÷WF◊WFVB#‰ÊÚ÷ñ∆&˜Ç6V∆V7FVB„¬ˆFóc‡¢∆FóbñC“&V÷ñƒ÷W76vT∆ó7B"6∆73“&V÷ñ¬÷÷W76vR÷∆ó7B#„∆Fób6∆73“&V◊Gí#‰ÊÚ÷W76vW2„¬ˆFóc„¬ˆFóc‡¢¬˜6V7Fñˆ„‡¢«6V7Fñˆ‚6∆73“&V÷ñ¬◊&VFW"◊ÊR"ñC“&V÷ñ≈&VFW%ÊR#‡¢∆Fób6∆73“&V÷ñ¬◊&VFW"÷V◊Gí#„∆Fób6∆73“&V÷ñ¬◊&VFW"÷V◊Gí÷ñ6ˆ‚#Ó)»ì¬ˆFóc„∆#Â6V∆V7B÷W76vS¬ˆ#„«7„‰6Üˆ˜6R÷W76vRg&ˆ“FÜR∆ó7BFÚ&VBóBÜW&R„¬˜7„„¬ˆFóc‡¢¬˜6V7Fñˆ„‡¢¬ˆFóc‡£¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“&V÷ñƒ6ˆ◊˜6T÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TV÷ñƒ6ˆ◊˜6RÇí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BV÷ñ¬÷6ˆ◊˜6R÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&V÷ñƒ6ˆ◊˜6UFóF∆R#‰ÊWr÷W76vS¬ˆÉ#„∆Fób6∆73“&◊WFVB#Â6VÊBg&ˆ“6ˆÊÊV7FVBv÷ñ¬˜"÷ñ7&˜6ˆgB3cR÷ñ∆&˜Ç„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TV÷ñƒ6ˆ◊˜6RÇí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“6∆73“&V÷ñ¬÷6ˆ◊˜6R÷f˜&“"ˆÁ7V&÷óC“'&WGW&‚6VÊDV÷ñƒ6ˆ◊˜6RÜWfVÁBí#‡¢∆∆&V√‰g&ˆ”«6V∆V7B6∆73“&fñ«FW""ñC“&V÷ñƒ6ˆ◊˜6T66˜VÁB"&WVó&VC„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√ÂFÛ∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒ6ˆ◊˜6UFÚ"∆6VÜˆ∆FW#“&Ê÷TWÜ◊∆RÊ6ˆ“"&WVó&VC„¬ˆ∆&V√‡¢∆∆&V√‰43∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒ6ˆ◊˜6T62"∆6VÜˆ∆FW#“$˜FñˆÊ¬#„¬ˆ∆&V√‡¢∆∆&V√‰$43∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒ6ˆ◊˜6T&62"∆6VÜˆ∆FW#“$˜FñˆÊ¬#„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬#Â7V&¶V7C∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒ6ˆ◊˜6U7V&¶V7B"÷Ü∆VÊwFÉ“#S#„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬#‰÷W76vS«FWáF&V6∆73“&ñÁWBV÷ñ¬÷6ˆ◊˜6R÷&ˆGí"ñC“&V÷ñƒ6ˆ◊˜6T&ˆGí"&˜w3“#"∆6VÜˆ∆FW#“%w&óFRñ˜W"÷W76vR#„¬˜FWáF&V„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬V÷ñ¬÷GF6Ü÷VÁB◊ñ6∂W"#‰GF6Ü÷VÁG3∆ñÁWBñC“&V÷ñƒ6ˆ◊˜6Tfñ∆W2"GóS“&fñ∆R"◊V«Fó∆RˆÊ6ÜÊvS“'&VÊFW$V÷ñƒGF6Ü÷VÁD∆ó7BÇí#„«7‚ñC“&V÷ñƒGF6Ü÷VÁD∆ó7B"6∆73“&◊WFVB#‰ÊÚGF6Ü÷VÁG26V∆V7FVB„¬˜7„„¬ˆ∆&V√‡¢∆FóbñC“&V÷ñƒ6ˆ◊˜6TW'""6∆73“&W'"gV∆¬#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2gV∆¬#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'6fTV÷ñƒG&gBÇí#Â6fRG&gC¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TV÷ñƒ6ˆ◊˜6RÇí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“'&ñ÷'í#Â6VÊC¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“&V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TV÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BV÷ñ¬÷ñÁFVw&Fñˆ‚÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#‰÷ñ¬66˜VÁG3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰˜WF∆ˆˆ≤◊7Gñ∆RWFˆ÷Fñ26WGW¢VÁFW"ñ˜W"V÷ñ¬FG&W72ÊB&˜fñFW"77v˜&B‚tÙE4UîRFó66˜fW'2FÜR÷ñ∆&˜Ç6W'fW'2WFˆ÷Fñ6∆«í„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TV÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“&V÷ñ¬÷ñÁFVw&Fñˆ‚÷&ˆGí#‡¢∆Fób6∆73“&6∆VÊF"◊&˜fñFW"÷w&ñB#‡¢∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&6∆VÊF"◊&˜fñFW"7FófR"FF÷V÷ñ¬◊&˜fñFW#“&÷ñ7&˜6ˆgC3cR"ˆÊ6∆ñ6≥“'6V∆V7DV÷ñ≈&˜fñFW"Çv÷ñ7&˜6ˆgC3cRrí#„«7‚6∆73“&6∆VÊF"◊&˜fñFW"÷ñ6ˆ‚#‰”¬˜7„„∆#‰÷ñ7&˜6ˆgB˜WF∆ˆˆ≥¬ˆ#„«6÷∆√‰WFˆ÷Fñ26WGW+rÙWFÇÚ77v˜&C¬˜6÷∆√„¬ˆ'WGFˆ„‡¢¬ˆFóc‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&V÷ñ≈&˜fñFW""f«VS“&÷ñ7&˜6ˆgC3cR#‡¢∆Fób6∆73“&V÷ñ¬÷ñÁFVw&Fñˆ‚÷f˜&“#‡¢∆∆&V√‰Ê÷S∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒñÁFVw&Fñˆ‰Ê÷R"∆6VÜˆ∆FW#“$˜W&FñˆÁ2÷ñ¬#„¬ˆ∆&V√‡¢∆∆&V√‰66˜VÁBV÷ñ√∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒñÁFVw&Fñˆ‰FG&W72"GóS“&V÷ñ¬"∆6VÜˆ∆FW#“&Ê÷TWÜ◊∆RÊ6ˆ“#„¬ˆ∆&V√‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&V÷ñƒñÁFVw&Fñˆ‰6∆ñVÁDñB"f«VS“"#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&V÷ñƒñÁFVw&Fñˆ‰6∆ñVÁE6V7&WB"f«VS“"#‡¢∆∆&V¬ñC“&V÷ñƒ÷ñ∆&˜Ö77v˜&Ew&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‰77v˜&C∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒñÁFVw&FñˆÂ77v˜&B"GóS“'77v˜&B"∆6VÜˆ∆FW#“%W6Rñ˜W"&˜fñFW"77v˜&B#„¬ˆ∆&V√‡¢∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ñC“&V÷ñƒ÷ÁV≈6WGFñÊw5Fˆvv∆R"ˆÊ6∆ñ6≥“'Fˆvv∆TV÷ñƒ÷ÁV≈6WGFñÊw2Çí"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#ÂW6R÷ÁV¬6W'fW"6WGFñÊw3¬ˆ'WGFˆ„‡¢∆∆&V¬ñC“&V÷ñƒñ÷Ü˜7Ew&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‰î‘6W'fW#∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒñÁFVw&Fñˆ‰ñ÷Ü˜7B"∆6VÜˆ∆FW#“&ñ÷ÊWÜ◊∆RÊ6ˆ“#„¬ˆ∆&V√‡¢∆∆&V¬ñC“&V÷ñƒñ÷˜'Ew&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‰î‘˜'C∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒñÁFVw&Fñˆ‰ñ÷˜'B"GóS“&ÁV÷&W""f«VS“#ìì2#„¬ˆ∆&V√‡¢∆∆&V¬ñC“&V÷ñ≈6◊GÜ˜7Ew&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#Â4’E6W'fW#∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒñÁFVw&FñˆÂ6◊GÜ˜7B"∆6VÜˆ∆FW#“'6◊GÊWÜ◊∆RÊ6ˆ“#„¬ˆ∆&V√‡¢∆∆&V¬ñC“&V÷ñ≈6◊G˜'Ew&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#Â4’E˜'C∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñƒñÁFVw&FñˆÂ6◊G˜'B"GóS“&ÁV÷&W""f«VS“#SÉr#„¬ˆ∆&V√‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FRgV∆¬"ñC“&V÷ñƒñÁFVw&Fñˆ‰÷ˆFTÊ˜FR#‰÷ñ7&˜6ˆgB˜WF∆ˆˆ≤W6W2WFˆ÷Fñ2Fó66˜fW'íÊB÷ñ7&˜6ˆgBw&ÇvÜV‚FV∆VvFVB6∆VÊF"66W72ó2VÊ&∆VB‚6∆ñVÁB6V7&WG2ÊBÙWFÇFˆ∂VÁ2&RVÊ7'óFVBB&W7B„¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FRgV∆¬#Â&VFó&V7BU$√¢FÜó2tÙE4UîRU$¬≤∆6ˆFS‚ˆí˜cˆV÷ñ¬ˆˆWFÇ˜&˜fñFW"ˆ6∆∆&6≥¬ˆ6ˆFS‚‚6WB∆6ˆFS‰tÙE4UîUıT$ƒî5ıU$√¬ˆ6ˆFS‚vÜV‚FÜR∆ñÊ6Ró2&VÜñÊBÖEE2˜"&WfW'6R&˜áí„¬ˆFóc‡¢∆FóbñC“&V÷ñƒñÁFVw&Fñˆ‰W'""6∆73“&W'"gV∆¬#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2gV∆¬#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TV÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çí#‰6∆˜6S¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&ñ÷'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“'6fTV÷ñƒñÁFVw&Fñˆ‚Çí#Â6fRf◊≤6ˆÊÊV7C¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"÷6ˆÊÊV7FVB◊FóF∆R#‰6ˆÊÊV7FVB÷ñ∆&˜ÜW3¬ˆFóc‡¢∆FóbñC“&V÷ñƒñÁFVw&Fñˆ‰∆ó7B"6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷∆ó7B#„∆Fób6∆73“&V◊Gí#‰ÊÚ÷ñ¬66˜VÁG26ˆÊÊV7FVB„¬ˆFóc„¬ˆFóc‡¢¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“&V÷ñ≈Vñ6¥7Fñˆ‰÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TV÷ñ≈Vñ6¥7Fñˆ‚Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BV÷ñ¬◊Vñ6≤÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&V÷ñ≈Vñ6¥7FñˆÂFóF∆R#Â&W«ì¬ˆÉ#„∆Fób6∆73“&◊WFVB"ñC“&V÷ñ≈Vñ6¥7FñˆÂ7V'FóF∆R#„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TV÷ñ≈Vñ6¥7Fñˆ‚Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób7Gñ∆S“'FFñÊs£áÇ#Ç#„∆∆&V¬ñC“&V÷ñ≈Vñ6¥7FñˆÂFıw&"7Gñ∆S“&Fó7∆ì¶ÊˆÊS∂f∆WÇ÷Fó&V7Fñˆ„¶6ˆ«V÷„∂v£gÉ∂÷&vñ‚÷&˜GFˆ”£É∂fˆÁB◊6ó¶S£É∂fˆÁB◊vVñváC£sS#ÂFÛ∆ñÁWBñC“&V÷ñ≈Vñ6¥7FñˆÂFÚ"6∆73“&ñÁWB"∆6VÜˆ∆FW#“&Ê÷TWÜ◊∆RÊ6ˆ“#„¬ˆ∆&V√„«FWáF&VñC“&V÷ñ≈Vñ6¥7Fñˆ‰&ˆGí"6∆73“&ñÁWB"&˜w3“#í"7Gñ∆S“'vñGFÉ£R"∆6VÜˆ∆FW#“%w&óFRñ˜W"÷W76vR#„¬˜FWáF&V„∆FóbñC“&V÷ñ≈Vñ6¥7Fñˆ‰W'""6∆73“&W'""7Gñ∆S“&÷&vñ‚◊F˜£áÇ#„¬ˆFóc„∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TV÷ñ≈Vñ6¥7Fñˆ‚Çí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'6VÊDV÷ñ≈Vñ6¥7Fñˆ‚Çí#Â6VÊC¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“&V÷ñ≈&W˜'D÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TV÷ñ≈&W˜'D÷ˆF¬Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BV÷ñ¬◊Vñ6≤÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#‰V÷ñ¬&W˜'C¬ˆÉ#„∆Fób6∆73“&◊WFVB"ñC“&V÷ñ≈&W˜'EFóF∆T∆&V¬#Â6VÊBvVÊW&FVB&W˜'BFó&V7F«íg&ˆ“tÙE4UîR„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TV÷ñ≈&W˜'D÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“&V÷ñ¬◊&W˜'B÷f˜&“#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&V÷ñ≈&W˜'DñB#‡¢∆∆&V√‰g&ˆ”«6V∆V7B6∆73“&fñ«FW""ñC“&V÷ñ≈&W˜'D66˜VÁB#„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√‰f˜&÷C«6V∆V7B6∆73“&fñ«FW""ñC“&V÷ñ≈&W˜'Df˜&÷B#„∆˜Fñˆ‚f«VS“'Fb#ÂDc¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&77b#‰55c¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬#ÂFÛ∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñ≈&W˜'EFÚ"∆6VÜˆ∆FW#“&Ê÷TWÜ◊∆RÊ6ˆ“#„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬#Â7V&¶V7C∆ñÁWB6∆73“&ñÁWB"ñC“&V÷ñ≈&W˜'E7V&¶V7B#„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬#‰÷W76vS«FWáF&V6∆73“&ñÁWB"ñC“&V÷ñ≈&W˜'D&ˆGí"&˜w3“#R#‰GF6ÜVBó2tÙE4UîR&W˜'B„¬˜FWáF&V„¬ˆ∆&V√‡¢∆FóbñC“&V÷ñ≈&W˜'DW'""6∆73“&W'"gV∆¬#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2gV∆¬#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TV÷ñ≈&W˜'D÷ˆF¬Çí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'6VÊDV÷ñ≈&W˜'BÇí#Â6VÊB&W˜'C¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr◊vñÊF˜w2◊WFFW2"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“&ÜW&Ú#„∆Fóc„∆É‰÷ñ7&˜6ˆgBvñÊF˜w2WFFW3¬ˆÉ„∆Fób6∆73“&◊WFVB#Â66‚ÊBñÁ7F∆¬WFFW2&W˜'FVB'í÷ñ7&˜6ˆgBvñÊF˜w2WFFRˆ‚VÁ&ˆ∆∆VB6ˆ◊WFW'2„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&∆ˆD÷ñ7&˜6ˆgEvñÊF˜w5WFFW5fñWrÇí#Ó(k≤&Vg&W6É¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&˜VÂvñÊF˜w4vVÁD÷ˆF¬Çí#ÂvñÊF˜w2vVÁB6WGW¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆Fóc„∆É#ÂvñÊF˜w26ˆ◊WFW'3¬ˆÉ#„∆Fób6∆73“&◊WFVB#ÂFÜó2ó26W&FRg&ˆ“tÙE4UîRvVÁB6ˆgGv&RWw&FW2„¬ˆFóc„¬ˆFóc„¬ˆFóc„∆FóbñC“&÷ñ7&˜6ˆgEvñÊF˜w5WFFW4∆ó7B"6∆73“'vñÊF˜w2÷vVÁB÷∆ó7B#„∆Fób6∆73“&V◊Gí#‰∆ˆFñÊrvñÊF˜w26ˆ◊WFW'>(
c¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£∆Fób6∆73“'fñWr"ñC“'fñWr÷WfVÁB÷fñÊFñÊw2"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“&WfVÁB÷fñÊFñÊw2◊vR#‡¢∆Fób6∆73“&ÜW&ÚWfVÁB÷fñÊFñÊw2÷ÜW&Ú#„∆Fóc„∆É‰WfVÁBfñÊFñÊw3¬ˆÉ„∆Fób6∆73“&◊WFVB#ÂvñÊF˜w27&óFñ6¬¬W'&˜"¬ÊBv&ÊñÊrWfVÁG26ˆÁfW'FVBñÁFÚWá∆ñÊ&∆RfñÊFñÊw2vóFÇ&V÷VFñFñˆ‚wVñFÊ6R„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚6∆73“'&ñ÷'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜VÂvñÊF˜w4vVÁD÷ˆF¬Çí#Ó)j2vñÊF˜w2vVÁG3¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“'V∆ƒ∆≈vñÊF˜w4vVÁG4Ê˜rÇí#Ó)˚2V∆¬WfVÁG2Ê˜rÑvVÁG2ì¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜VÂvñÊF˜w56˜W&6T÷ˆF¬Çí#Ó)©ívñÂ$“6˜W&6W3¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“'ˆ∆ƒ∆≈vñÊF˜w56˜W&6W2Çí#Ó)˚2V∆¬WfVÁG2Ê˜rÖvñÂ$“ì¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&vVÁB◊&V6ˆ÷÷VÊFFñˆ‚#„∆Fóc„∆#ÂvñÊF˜w2vVÁBó2FÜR&V6ˆ÷÷VÊFVB6ˆ∆∆V7Fñˆ‚÷WFÜˆB„¬ˆ#„«7„‰˜WF&˜VÊBÖEE2ˆÊ«í+rÊÚñÊ&˜VÊBvñÂ$“˜'B+r∆ˆ6¬WfVÁB∆ˆr&ˆˆ∂÷&∑2+rˆff∆ñÊRVWVR+rF&vWFVB&V6ÜV6∑2„¬˜7„„¬ˆFóc„∆FóbñC“&vVÁE7V÷÷'í"6∆73“&vVÁB◊7V÷÷'í#‰vVÁG3¢(	C¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&6&G2#„∆Fób6∆73“&6&B#„∆Fób6∆73“&∆&V¬#‰˜V„¬ˆFóc„∆Fób6∆73“&ÁV“&VB"ñC“&WfVÁDfñÊFñÊt˜V‚#Ó(	C¬ˆFóc„¬ˆFóc„∆Fób6∆73“&6&B#„∆Fób6∆73“&∆&V¬#‰7&óFñ6√¬ˆFóc„∆Fób6∆73“&ÁV“&VB"ñC“&WfVÁDfñÊFñÊt7&óFñ6¬#Ó(	C¬ˆFóc„¬ˆFóc„∆Fób6∆73“&6&B#„∆Fób6∆73“&∆&V¬#Â7F˜&vRÚÜ&Gv&S¬ˆFóc„∆Fób6∆73“&ÁV“"ñC“&WfVÁDfñÊFñÊtÜ&Gv&R#Ó(	C¬ˆFóc„¬ˆFóc„∆Fób6∆73“&6&B#„∆Fób6∆73“&∆&V¬#Â&W6ˆ«fVC¬ˆFóc„∆Fób6∆73“&ÁV“w&VV‚"ñC“&WfVÁDfñÊFñÊu&W6ˆ«fVB#Ó(	C¬ˆFóc„¬ˆFóc„¬ˆFóc‡¢«6V7Fñˆ‚6∆73“'ÊV¬WfVÁB÷fñÊFñÊw2◊ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆Fóc„∆É#ÂvñÊF˜w2WfVÁBfñÊFñÊw3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰ˆÊ«í6V∆V7FVBv&ÊñÊr¬W'&˜"¬ÊB7&óFñ6¬WfVÁG2&R&WFñÊVB2fñÊFñÊw2„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&WfVÁB÷fñ«FW"◊&˜r#„«6V∆V7BñC“&WfVÁDfñÊFñÊu7FGW4fñ«FW""6∆73“&fñ«FW""ˆÊ6ÜÊvS“&∆ˆDWfVÁDfñÊFñÊw2Çí#„∆˜Fñˆ‚f«VS“"#‰∆¬7FGW3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&˜V‚"6V∆V7FVC‰˜V„¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'&W6ˆ«fVB#Â&W6ˆ«fVC¬ˆ˜Fñˆ„„¬˜6V∆V7C„«6V∆V7BñC“&WfVÁDfñÊFñÊu6WfW&óGîfñ«FW""6∆73“&fñ«FW""ˆÊ6ÜÊvS“&∆ˆDWfVÁDfñÊFñÊw2Çí#„∆˜Fñˆ‚f«VS“"#‰∆¬6WfW&óGì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&7&óFñ6¬#‰7&óFñ6√¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ÜñvÇ#‰ÜñvÉ¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&÷VFóV“#‰÷VFóV”¬ˆ˜Fñˆ„„¬˜6V∆V7C„∆ñÁWBñC“&WfVÁDfñÊFñÊu6V&6Ç"6∆73“&ñÁWBWfVÁB÷fñÊFñÊr◊6V&6Ç"∆6VÜˆ∆FW#“%6V&6ÇfñÊFñÊw>(
b"ˆÊ∂WñF˜v„“&ñbÜWfVÁBÊ∂Wì””“tVÁFW"rñ∆ˆDWfVÁDfñÊFñÊw2Çí#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&∆ˆDWfVÁDfñÊFñÊw2Çí#Ó(k≤&Vg&W6É¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&WfVÁB÷fñÊFñÊr÷'V∆∂&"F÷ñ‚÷ˆÊ«í#„∆∆&V¬6∆73“&WfVÁB◊6V∆V7B÷∆¬#„∆ñÁWBñC“&WfVÁDfñÊFñÊu6V∆V7D∆¬"GóS“&6ÜV6∂&˜Ç"ˆÊ6ÜÊvS“'Fˆvv∆T∆ƒWfVÁDfñÊFñÊw2áFÜó2Ê6ÜV6∂VBí#‚6V∆V7B∆¬«7‚ñC“&WfVÁDfñÊFñÊufó6ñ&∆T6˜VÁB#„¬˜7„„¬ˆ∆&V√„∆'WGFˆ‚ñC“&WfVÁDfñÊFñÊtFV∆WFU6V∆V7FVB"6∆73“&FÊvW""ˆÊ6∆ñ6≥“&FV∆WFU6V∆V7FVDWfVÁDfñÊFñÊw2Çí"Fó6&∆VCÔ	˘yFV∆WFR6V∆V7FVC¬ˆ'WGFˆ„„«7‚ñC“&WfVÁDfñÊFñÊu6V∆V7FVD6˜VÁB"6∆73“&◊WFVB#„6V∆V7FVC¬˜7„„∆Fób6∆73“&WfVÁB÷ˆ∆B÷FV∆WFR#„«6V∆V7BñC“&WfVÁDfñÊFñÊtˆ∆DFó2"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“#r#Â&W6ˆ«fVBfwC≤rFó3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#3"6V∆V7FVCÂ&W6ˆ«fVBfwC≤3Fó3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#ì#Â&W6ˆ«fVBfwC≤ìFó3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#É#Â&W6ˆ«fVBfwC≤ÉFó3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#3cR#Â&W6ˆ«fVBfwC≤ñV#¬ˆ˜Fñˆ„„¬˜6V∆V7C„∆'WGFˆ‚6∆73“&FÊvW""ˆÊ6∆ñ6≥“&FV∆WFTˆ∆DWfVÁDfñÊFñÊw2Çí#Ô	˘yFV∆WFRˆ∆BfñÊFñÊw3¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÚ#„«F&∆S„«FÜVC„«G#„«FÇ6∆73“&F÷ñ‚÷ˆÊ«í#„∆ñÁWBGóS“&6ÜV6∂&˜Ç"&ñ÷∆&V√“%6V∆V7B∆¬fó6ñ&∆RfñÊFñÊw2"ˆÊ6ÜÊvS“'Fˆvv∆T∆ƒWfVÁDfñÊFñÊw2áFÜó2Ê6ÜV6∂VBí#„¬˜FÉ„«FÉÂ6WfW&óGì¬˜FÉ„«FÉ‰6ˆ◊WFW#¬˜FÉ„«FÉ‰fñÊFñÊs¬˜FÉ„«FÉ‰WfVÁC¬˜FÉ„«FÉ‰ˆ67W'&VÊ6W3¬˜FÉ„«FÉ‰∆7B6VV„¬˜FÉ„«FÉÂ7FGW3¬˜FÉ„«FÉ‰7FñˆÁ3¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“&WfVÁDfñÊFñÊu&˜w2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc„∆Fób6∆73“&WfVÁB÷fñÊFñÊr÷fˆ˜FW"#„«7‚ñC“&WfVÁDfñÊFñÊtfˆ˜FW%FWáB"6∆73“&◊WFVB#‰ÊÚfñÊFñÊw2∆ˆFVB„¬˜7„„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“'vñÊF˜w4vVÁD÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6UvñÊF˜w4vVÁD÷ˆF¬Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BvñÊF˜w2÷vVÁB÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#ÂvñÊF˜w2vVÁG2f◊≤WFFW3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰ñÁ7F∆¬¬6ÜV6≤¬ÊB&V÷˜FV«í«í÷ó76ñÊrvñÊF˜w2vVÁBWFFW2ˆ‚VÁ&ˆ∆∆VB6ˆ◊WFW'2„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6UvñÊF˜w4vVÁD÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“'vñÊF˜w2÷vVÁB÷&ˆGí#‡¢∆Fób6∆73“&vVÁB÷ˆÊ&ˆ&FñÊr#‡¢∆Fóc„∆#‰vVÁBVÁ&ˆ∆∆÷VÁC¬ˆ#„∆Fób6∆73“&◊WFVB#‰vVÊW&FRˆÊR◊Fñ÷RFˆ∂V‚¬F˜vÊ∆ˆBFÜRW&÷ÊVÁBÉcBvñÊF˜w2ñÁ7F∆∆W"¬ÊB'V‚6WGW2F÷ñÊó7G&F˜"‚gWGW&RvVÁBWw&FW2&W6W'fRVÁ&ˆ∆∆÷VÁBWFˆ÷Fñ6∆«í„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“&6ÜV6µvñÊF˜w4vVÁEWFFW2Çí#Ó(k≤6ÜV6≤f˜"WFFW3¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'í˜W&FR÷ˆÊ«í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'V∆ƒ∆≈vñÊF˜w4vVÁG4Ê˜rÇí#Ó)˚2V∆¬∆¬ˆÊ∆ñÊS¬ˆ'WGFˆ„„∆'WGFˆ‚ñC“'vñÊF˜w4vVÁDF˜vÊ∆ˆD'F‚"6∆73“'6V6ˆÊF'íF÷ñ‚÷ˆÊ«í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“&F˜vÊ∆ˆEvñÊF˜w4vVÁE6∂vRÇí#Ó(i2F˜vÊ∆ˆBÉcBñÁ7F∆∆W#¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'íF÷ñ‚÷ˆÊ«í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“&7&VFUvñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁBÇí#Ó˚»≤7&VFRVÁ&ˆ∆∆÷VÁBFˆ∂V„¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFóc‡¢∆FóbñC“'vñÊF˜w4vVÁE6∂vU7FGW2"6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FR#‰6ÜV6∂ñÊrvVÁB"„B„BñÁ7F∆∆W"fñ∆&ñ∆óGû(
c¬ˆFóc‡¢∆FóbñC“'vñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁB"6∆73“&vVÁB÷VÁ&ˆ∆∆÷VÁB◊&W7V«B"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡¢∆Fób6∆73“&vVÁB◊Fˆ∂V‚÷ÜVB#„∆#‰ˆÊR◊Fñ÷RVÁ&ˆ∆∆÷VÁBFˆ∂V„¬ˆ#„«7‚ñC“'vñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁDWáó'í"6∆73“&◊WFVB#„¬˜7„„¬ˆFóc‡¢∆Fób6∆73“&vVÁB◊Fˆ∂V‚◊&˜r#„∆6ˆFRñC“'vñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁEFˆ∂V‚#„¬ˆ6ˆFS„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6˜îvVÁDVÁ&ˆ∆∆÷VÁEFˆ∂V‚Çí#‰6˜íFˆ∂V„¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“&◊WFVB#‰ñÁ7F∆∆W"6WGW£¬ˆFóc„«&RñC“'vñÊF˜w4vVÁDñÁ7F∆ƒ6ˆ÷÷ÊB"6∆73“&vVÁB÷6ˆ÷÷ÊB#„¬˜&S‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FR#ÂFÜRFˆ∂V‚ó26Ü˜v‚ˆÊ«íÜW&RÊBWáó&W2WFˆ÷Fñ6∆«í‚FÜRvñÊF˜w2vVÁBWÜ6ÜÊvW2óBf˜"VÊóVR÷6ÜñÊRí∂WíÊB&˜FV7G2FÜB∂WívóFÇvñÊF˜w2Eí„¬ˆFóc‡¢¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"÷6ˆÊÊV7FVB◊FóF∆R#‰VÁ&ˆ∆∆VBvñÊF˜w2vVÁG3¬ˆFóc‡¢∆FóbñC“'vñÊF˜w4vVÁD∆ó7B"6∆73“'vñÊF˜w2÷vVÁB÷∆ó7B#„∆Fób6∆73“&V◊Gí#‰ÊÚvñÊF˜w2vVÁG2VÁ&ˆ∆∆VB„¬ˆFóc„¬ˆFóc‡¢∆FóbñC“'vñÊF˜w5WFFW5ÊV¬"6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FR#„∆#‰÷ñ7&˜6ˆgBvñÊF˜w2WFFS¬ˆ#„∆FóbñC“'vñÊF˜w5WFFW5&W7V«G2"6∆73“&◊WFVB#Â6V∆V7B‚vVÁBÊB66‚f˜"÷ñ7&˜6ˆgBWFFW2„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FR#ÂvñÂ$“&V÷ñÁ2fñ∆&∆R2‚vVÁF∆W72f∆∆&6≤‚vVÁB6ˆ∆∆V7Fñˆ‚FˆW2Ê˜B&WVó&RñÊ&˜VÊBD5SìÉbˆ‚vñÊF˜w2„¬ˆFóc‡¢¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“'vñÊF˜w56˜W&6T÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6UvñÊF˜w56˜W&6T÷ˆF¬Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BvñÊF˜w2◊6˜W&6R÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#ÂvñÊF˜w2WfVÁB6˜W&6W3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰vVÁF∆W72vñÂ$“ÖEE2V∆¬f˜"cB÷&óBvñÊF˜w26ˆ◊WFW'2ÊBvñÊF˜w26W'fW"„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6UvñÊF˜w56˜W&6T÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“'vñÊF˜w2◊6˜W&6R÷&ˆGí#‡¢∆Fób6∆73“'vñÊF˜w2◊6˜W&6R÷f˜&“#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“'vñÊF˜w56˜W&6TñB#‡¢∆∆&V√‰Ê÷S∆ñÁWBñC“'vñÊF˜w56˜W&6TÊ÷R"6∆73“&ñÁWB"∆6VÜˆ∆FW#“$dîƒU4U%dU##„¬ˆ∆&V√‡¢∆∆&V√‰Ü˜7FÊ÷RÚï∆ñÁWBñC“'vñÊF˜w56˜W&6TÜ˜7B"6∆73“&ñÁWB"∆6VÜˆ∆FW#“&fñ∆W6W'fW#ÊWÜ◊∆RÊ∆ˆ6¬#„¬ˆ∆&V√‡¢∆∆&V√ÂvñÂ$“ÖEE2˜'C∆ñÁWBñC“'vñÊF˜w56˜W&6U˜'B"6∆73“&ñÁWB"GóS“&ÁV÷&W""f«VS“#SìÉb#„¬ˆ∆&V√‡¢∆∆&V√ÂG&Á7˜'C«6V∆V7BñC“'vñÊF˜w56˜W&6UG&Á7˜'B"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“&ÁF∆“#‰ÂDƒ”¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&&6ñ2#‰&6ñ2˜fW"ÖEE3¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√ÂW6W&Ê÷S∆ñÁWBñC“'vñÊF˜w56˜W&6UW6W&Ê÷R"6∆73“&ñÁWB"∆6VÜˆ∆FW#“$DÙ‘îÂ≈∆vˆG6WñR◊&VFW"#„¬ˆ∆&V√‡¢∆∆&V√Â77v˜&C∆ñÁWBñC“'vñÊF˜w56˜W&6U77v˜&B"6∆73“&ñÁWB"GóS“'77v˜&B"∆6VÜˆ∆FW#“$∆VfR&∆Ê≤vÜV‚VFóFñÊrFÚ∂VW7W'&VÁB#„¬ˆ∆&V√‡¢∆∆&V√Âˆ∆¬WfW'ì«6V∆V7BñC“'vñÊF˜w56˜W&6TñÁFW'f¬"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“##„÷ñÁWFS¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#R"6V∆V7FVC„R÷ñÁWFW3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#R#„R÷ñÁWFW3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#3#„3÷ñÁWFW3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#c#„Ü˜W#¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V¬6∆73“'vñÊF˜w2÷6ÜV6≤#„∆ñÁWBGóS“&6ÜV6∂&˜Ç"ñC“'vñÊF˜w56˜W&6UfW&ñgïF«2"6ÜV6∂VC‚fW&ñgívñÂ$“D≈26W'Fñfñ6FS¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬#‰WfVÁB6ÜÊÊV«3∆ñÁWBñC“'vñÊF˜w56˜W&6T6ÜÊÊV«2"6∆73“&ñÁWB"f«VS“%7ó7FV“¬∆ñ6Fñˆ‚"∆6VÜˆ∆FW#“%7ó7FV“¬∆ñ6Fñˆ‚#„¬ˆ∆&V√‡¢∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FRgV∆¬#‰tÙE4UîRVW&ñW2ˆÊ«ívñÊF˜w2WfVÁB∆WfV«2¬"¬ÊB2Ñ7&óFñ6¬¬W'&˜"¬v&ÊñÊrí¬7F˜&W2W"÷6ÜÊÊV¬&V6˜&B&ˆˆ∂÷&≤¬ÊB&WVW7G2ˆÊ«íÊWvW"&V6˜&G2ˆ‚∆FW"ˆ∆«2‚W6RvñÂ$“˜fW"ÖEE2ÊBFVFñ6FVB∆V7B◊&ófñ∆VvR66˜VÁBvóFÇWfVÁB∆ˆr&VFW'266W72„¬ˆFóc‡¢∆FóbñC“'vñÊF˜w56˜W&6TW'""6∆73“&W'"gV∆¬#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2gV∆¬#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'&W6WEvñÊF˜w56˜W&6Tf˜&“Çí"GóS“&'WGFˆ‚#‰ÊWs¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6UvñÊF˜w56˜W&6T÷ˆF¬Çí"GóS“&'WGFˆ‚#‰6∆˜6S¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“'6fUvñÊF˜w56˜W&6RÇí"GóS“&'WGFˆ‚#Â6fR6˜W&6S¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFóc‡¢∆Fób6∆73“&6∆VÊF"÷6ˆÊÊV7FVB◊FóF∆R#‰6ˆÊfñwW&VBvñÊF˜w2Ü˜7G3¬ˆFóc‡¢∆FóbñC“'vñÊF˜w56˜W&6T∆ó7B"6∆73“'vñÊF˜w2◊6˜W&6R÷∆ó7B#„∆Fób6∆73“&V◊Gí#‰ÊÚvñÊF˜w2WfVÁB6˜W&6W26ˆÊfñwW&VB„¬ˆFóc„¬ˆFóc‡¢¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“&WfVÁDfñÊFñÊt÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TWfVÁDfñÊFñÊt÷ˆF¬Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BWfVÁB÷fñÊFñÊr÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&WfVÁDfñÊFñÊt÷ˆF≈FóF∆R#‰WfVÁBfñÊFñÊs¬ˆÉ#„∆Fób6∆73“&◊WFVB"ñC“&WfVÁDfñÊFñÊt÷ˆF≈7V'FóF∆R#„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TWfVÁDfñÊFñÊt÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆FóbñC“&WfVÁDfñÊFñÊt÷ˆFƒ&ˆGí"6∆73“&WfVÁB÷fñÊFñÊr÷FWFñ¬#„¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr÷ÁFófó'W2"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“&ÜW&Ú#„∆Fóc„∆É‰ÁFófó'W3¬ˆÉ„∆Fób6∆73“&◊WFVB#‰6∆‘bó2g&VRÊB˜V‚6˜W&6R‚ñÁ7F∆¬6∆‘bˆ‚V6ÇvñÊF˜w26ˆ◊WFW"¬FÜV‚'V‚‚&˜fVB66‚g&ˆ“tÙE4UîR„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&∆ˆD6∆‘dvVÁG2Çí#Ó(k≤&Vg&W6É¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆Fóc„∆É#‰÷ÊvVBvñÊF˜w2&˜FV7Fñˆ„¬ˆÉ#„∆Fób6∆73“&◊WFVB#Â66Á2'V‚∆ˆ6∆«íˆ‚FÜRVÁ&ˆ∆∆VB6ˆ◊WFW"ÊB&WGW&‚&W7V«BFÚFÜRvVÁB˜'F¬„¬ˆFóc„¬ˆFóc„¬ˆFóc„∆FóbñC“&6∆÷dvVÁD∆ó7B"6∆73“&V◊Gí#‰∆ˆFñÊrvñÊF˜w2vVÁG>(
c¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr◊Fñ6∂WG2"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“'Fñ6∂WB◊vR#‡¢∆Fób6∆73“&ÜW&ÚFñ6∂WB÷ÜW&Ú#„∆Fóc„∆ÉÂFñ6∂WB˜'F√¬ˆÉ„∆Fób6∆73“&◊WFVB#ÂG&6≤ÊWGv˜&≤¬vñÊF˜w2¬÷ˆÊóF˜&ñÊr¬ÊB÷ÁV¬ó77VW2g&ˆ“Fó66˜fW'íFá&˜VvÇ66ÜVGV∆VBv˜&≤ÊB6∆˜7W&R„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚6∆73“'&ñ÷'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜VÂFñ6∂WDVFóF˜"Çí#Ó˚»≤ÊWrFñ6∂WC¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&6&G2#„∆Fób6∆73“&6&B#„∆Fób6∆73“&∆&V¬#‰˜V„¬ˆFóc„∆Fób6∆73“&ÁV“&VB"ñC“'Fñ6∂WD˜V‚#Ó(	C¬ˆFóc„¬ˆFóc„∆Fób6∆73“&6&B#„∆Fób6∆73“&∆&V¬#‰ñ‚&ˆw&W73¬ˆFóc„∆Fób6∆73“&ÁV“"ñC“'Fñ6∂WDñÂ&ˆw&W72#Ó(	C¬ˆFóc„¬ˆFóc„∆Fób6∆73“&6&B#„∆Fób6∆73“&∆&V¬#‰GVRÚ66ÜVGV∆VC¬ˆFóc„∆Fób6∆73“&ÁV“"ñC“'Fñ6∂WE66ÜVGV∆VB#Ó(	C¬ˆFóc„¬ˆFóc„∆Fób6∆73“&6&B#„∆Fób6∆73“&∆&V¬#‰6∆˜6VC¬ˆFóc„∆Fób6∆73“&ÁV“w&VV‚"ñC“'Fñ6∂WD6∆˜6VB#Ó(	C¬ˆFóc„¬ˆFóc„¬ˆFóc‡¢«6V7Fñˆ‚6∆73“'ÊV¬Fñ6∂WB÷6∆VÁW◊ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆Fóc„∆É#ÂFñ6∂WG3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰˜V‚Fñ6∂WBFÚFBÊ˜FW2¬6ÜÊvR7FGW2¬66ÜVGV∆RóBˆ‚6∆VÊF"¬˜"6∆V‚W6ˆ◊∆WFVBFñ6∂WBÜó7F˜'í„¬ˆFóc„¬ˆFóc„∆Fóc„«6V∆V7BñC“'Fñ6∂WE7FGW4fñ«FW""6∆73“&fñ«FW""ˆÊ6ÜÊvS“&∆ˆEFñ6∂WG2Çí#„∆˜Fñˆ‚f«VS“"#‰∆¬7FGW3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&˜V‚#‰˜V„¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&76ñvÊVB#‰76ñvÊVC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñÂ˜&ˆw&W72#‰ñ‚&ˆw&W73¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'vóFñÊr#ÂvóFñÊs¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'&W6ˆ«fVB#Â&W6ˆ«fVC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&6∆˜6VB#‰6∆˜6VC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“'Fñ6∂WB÷6∆VÁW÷&"F÷ñ‚÷ˆÊ«í#„∆∆&V¬6∆73“'Fñ6∂WB◊6V∆V7B÷∆¬#„∆ñÁWBñC“'Fñ6∂WE6V∆V7D∆¬"GóS“&6ÜV6∂&˜Ç"ˆÊ6ÜÊvS“'Fˆvv∆T∆≈Fñ6∂WG2áFÜó2Ê6ÜV6∂VBí#‚6V∆V7B∆¬«7‚ñC“'Fñ6∂WEfó6ñ&∆T6˜VÁB#„¬˜7„„¬ˆ∆&V√„∆'WGFˆ‚ñC“'Fñ6∂WDFV∆WFU6V∆V7FVB"6∆73“&FÊvW""ˆÊ6∆ñ6≥“&FV∆WFU6V∆V7FVEFñ6∂WG2Çí"Fó6&∆VCÔ	˘yFV∆WFR6V∆V7FVC¬ˆ'WGFˆ„„«7‚ñC“'Fñ6∂WE6V∆V7FVD6˜VÁB"6∆73“&◊WFVB#„6V∆V7FVC¬˜7„„∆Fób6∆73“'Fñ6∂WB÷ˆ∆B÷FV∆WFR#„«6V∆V7BñC“'Fñ6∂WDˆ∆DFó2"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“#r#‰6∆˜6VBÚ&W6ˆ«fVBfwC≤rFó3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#3#‰6∆˜6VBÚ&W6ˆ«fVBfwC≤3Fó3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#ì"6V∆V7FVC‰6∆˜6VBÚ&W6ˆ«fVBfwC≤ìFó3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#É#‰6∆˜6VBÚ&W6ˆ«fVBfwC≤ÉFó3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“#3cR#‰6∆˜6VBÚ&W6ˆ«fVBfwC≤ñV#¬ˆ˜Fñˆ„„¬˜6V∆V7C„∆'WGFˆ‚6∆73“&FÊvW""ˆÊ6∆ñ6≥“&FV∆WFTˆ∆EFñ6∂WG2Çí#Ô	˘yFV∆WFRˆ∆BFñ6∂WG3¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÚ#„«F&∆S„«FÜVC„«G#„«FÇ6∆73“&F÷ñ‚÷ˆÊ«í#„∆ñÁWBñC“'Fñ6∂WDÜVFW%6V∆V7D∆¬"GóS“&6ÜV6∂&˜Ç"ˆÊ6ÜÊvS“'Fˆvv∆T∆≈Fñ6∂WG2áFÜó2Ê6ÜV6∂VBí"&ñ÷∆&V√“%6V∆V7B∆¬fó6ñ&∆RFñ6∂WG2#„¬˜FÉ„«FÉÂFñ6∂WC¬˜FÉ„«FÉÂ&ñ˜&óGì¬˜FÉ„«FÉÂFóF∆S¬˜FÉ„«FÉ‰ffV7FVC¬˜FÉ„«FÉ‰76ñvÊVS¬˜FÉ„«FÉÂ7FGW3¬˜FÉ„«FÉ‰GVRÚ6∆VÊF#¬˜FÉ„«FÉÂWFFVC¬˜FÉ„«FÉ‰7Fñˆ„¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“'Fñ6∂WE&˜w2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“'Fñ6∂WDVFóF˜$÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6UFñ6∂WDVFóF˜"Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BFñ6∂WB÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“'Fñ6∂WDVFóF˜%FóF∆R#‰ÊWrFñ6∂WC¬ˆÉ#„∆Fób6∆73“&◊WFVB"ñC“'Fñ6∂WDVFóF˜%7V'FóF∆R#‰7&VFRÊBG&6≤˜W&FñˆÊ¬v˜&≤„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6UFñ6∂WDVFóF˜"Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“'Fñ6∂WB÷VFóF˜"÷w&ñB#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“'Fñ6∂WDVFóF˜$ñB#‡¢∆∆&V¬6∆73“&gV∆¬#‰ó77VRGóRÚFóF∆S«6V∆V7BñC“'Fñ6∂WDó77VUGóR"6∆73“&fñ«FW"#„∆˜Fñˆ„‰V÷ñ√¬ˆ˜Fñˆ„„∆˜Fñˆ„‰ñÁFW&ÊWC¬ˆ˜Fñˆ„„∆˜Fñˆ„ÂÜˆÊS¬ˆ˜Fñˆ„„∆˜Fñˆ„‰Ü&Gv&S¬ˆ˜Fñˆ„„∆˜Fñˆ„Â6ˆgGv&S¬ˆ˜Fñˆ„„∆˜Fñˆ„Â6V7W&óGì¬ˆ˜Fñˆ„„∆˜Fñˆ„‰˜FÜW#¬ˆ˜Fñˆ„„¬˜6V∆V7C„∆ñÁWBñC“'Fñ6∂WEFóF∆R"6∆73“&ñÁWB"÷Ü∆VÊwFÉ“##C"∆6VÜˆ∆FW#“$'&ñVf«íFW67&ñ&RFÜRó77VR#„¬ˆ∆&V√‡¢∆∆&V√Â&WVW7FW"Ê÷S∆ñÁWBñC“'Fñ6∂WE&WVW7FW$Ê÷R"6∆73“&ñÁWB"÷Ü∆VÊwFÉ“#c"∆6VÜˆ∆FW#“%ñ˜W"Ê÷R#„¬ˆ∆&V√‡¢∆∆&V√‰FW'F÷VÁC∆ñÁWBñC“'Fñ6∂WE&WVW7FW$FW'F÷VÁB"6∆73“&ñÁWB"÷Ü∆VÊwFÉ“#c"∆6VÜˆ∆FW#“$FW'F÷VÁB#„¬ˆ∆&V√‡¢∆∆&V√ÂÜˆÊRÁV÷&W#∆ñÁWBñC“'Fñ6∂WE&WVW7FW%ÜˆÊR"6∆73“&ñÁWB"÷Ü∆VÊwFÉ“#c"∆6VÜˆ∆FW#“#SSR”SSR”SSSR#„¬ˆ∆&V√‡¢∆∆&V√‰V÷ñ¬FG&W73∆ñÁWBñC“'Fñ6∂WE&WVW7FW$V÷ñ¬"6∆73“&ñÁWB"GóS“&V÷ñ¬"÷Ü∆VÊwFÉ“##SB"∆6VÜˆ∆FW#“'ñ˜TWÜ◊∆RÊ6ˆ“#„¬ˆ∆&V√‡¢∆∆&V√Â&ñ˜&óGì«6V∆V7BñC“'Fñ6∂WE&ñ˜&óGí"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“&∆˜r#‰∆˜s¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&÷VFóV“"6V∆V7FVC‰÷VFóV”¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ÜñvÇ#‰ÜñvÉ¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&7&óFñ6¬#‰7&óFñ6√¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√Â7FGW3«6V∆V7BñC“'Fñ6∂WE7FGW2"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“&˜V‚#‰˜V„¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&76ñvÊVB#‰76ñvÊVC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñÂ˜&ˆw&W72#‰ñ‚&ˆw&W73¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'vóFñÊr#ÂvóFñÊs¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'&W6ˆ«fVB#Â&W6ˆ«fVC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&6∆˜6VB#‰6∆˜6VC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√‰76ñvÊVS«6V∆V7BñC“'Fñ6∂WD76ñvÊVR"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“"#ÂVÊ76ñvÊVC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√‰FWfñ6RÚ7ó7FV”∆ñÁWBñC“'Fñ6∂WDFWfñ6R"6∆73“&ñÁWB"∆6VÜˆ∆FW#“$dîƒU4U%dU##„¬ˆ∆&V√‡¢∆∆&V¬6∆73“&gV∆¬#‰FW67&óFñˆ„«FWáF&VñC“'Fñ6∂WDFW67&óFñˆ‚"6∆73“&ñÁWB"&˜w3“#R#„¬˜FWáF&V„¬ˆ∆&V√‡¢∆FóbñC“'Fñ6∂WD∆ñÊ∂VDñÊfÚ"6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚÷Ê˜FRgV∆¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#„¬ˆFóc‡¢∆Fób6∆73“'Fñ6∂WB◊6V7Fñˆ‚gV∆¬"ñC“'Fñ6∂WE66ÜVGV∆U6V7Fñˆ‚"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#„∆É3Â66ÜVGV∆Rˆ‚6∆VÊF#¬ˆÉ3„∆Fób6∆73“'Fñ6∂WB◊66ÜVGV∆R÷w&ñB#„∆∆&V√Â7F'C∆ñÁWBñC“'Fñ6∂WE66ÜVGV∆U7F'B"6∆73“&ñÁWB"GóS“&FFWFñ÷R÷∆ˆ6¬#„¬ˆ∆&V√„∆∆&V√‰VÊC∆ñÁWBñC“'Fñ6∂WE66ÜVGV∆TVÊB"6∆73“&ñÁWB"GóS“&FFWFñ÷R÷∆ˆ6¬#„¬ˆ∆&V√„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'66ÜVGV∆T7W'&VÁEFñ6∂WBÇí#Â6fRFÚ6∆VÊF#¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“'Fñ6∂WB◊6V7Fñˆ‚gV∆¬"ñC“'Fñ6∂WDÊ˜FW56V7Fñˆ‚"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#„∆É3Âv˜&≤Ê˜FW3¬ˆÉ3„∆FóbñC“'Fñ6∂WDÊ˜FW4∆ó7B"6∆73“'Fñ6∂WB÷Ê˜FW2÷∆ó7B#„¬ˆFóc„∆Fób6∆73“'Fñ6∂WB÷Ê˜FR÷FB#„«FWáF&VñC“'Fñ6∂WDÊ˜FUFWáB"6∆73“&ñÁWB"&˜w3“#2"∆6VÜˆ∆FW#“$FBv˜&≤W&f˜&÷VB¬'G2&W∆6VB¬FW7B&W7V«G2¬˜"fˆ∆∆˜r◊WÊ˜FW2#„¬˜FWáF&V„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“&FEFñ6∂WDÊ˜FRÇí#‰FBÊ˜FS¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢∆FóbñC“'Fñ6∂WDVFóF˜$W'""6∆73“&W'"gV∆¬#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2gV∆¬#„∆'WGFˆ‚ñC“'Fñ6∂WDFV∆WFT'F‚"6∆73“&FÊvW"F÷ñ‚÷ˆÊ«íFñ6∂WB÷ÜñFFV‚"GóS“&'WGFˆ‚"7Gñ∆S“&÷&vñ‚◊&ñváC£áÇ"ˆÊ6∆ñ6≥“&FV∆WFT7W'&VÁEFñ6∂WBÇí#‰FV∆WFRFñ6∂WC¬ˆ'WGFˆ„„∆'WGFˆ‚ñC“'Fñ6∂WD6∆˜6T'F‚"6∆73“&FÊvW"˜W&FR÷ˆÊ«í"GóS“&'WGFˆ‚"7Gñ∆S“&Fó7∆ì¶ÊˆÊS∂÷&vñ‚◊&ñváC¶WFÚ"ˆÊ6∆ñ6≥“&6∆˜6T7W'&VÁEFñ6∂WBÇí#‰6∆˜6RFñ6∂WC¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“&6∆˜6UFñ6∂WDVFóF˜"Çí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'í˜W&FR÷ˆÊ«í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'6fUFñ6∂WBÇí#Â6fRFñ6∂WC¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr◊&W˜'G2"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“'&W˜'B◊v˜&∑76R#‡£∆Fób6∆73“'&W˜'B÷ÜW&Ú#„∆Fób6∆73“'&W˜'B÷ÜW&Ú÷6˜í#„∆Fób6∆73“'&W˜'B÷ÜW&Ú÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”b6Éñ√BGcDÉg§”R7cVÉT”í&Éd”ífÉb"Û„¬˜7fs„¬ˆFóc„∆Fóc„∆É7Gñ∆S“&÷&vñ„£GÇ#Â&W˜'G3¬ˆÉ„∆Fób6∆73“&◊WFVB#‰6Üˆ˜6R&W˜'B6&B¬FÜV‚vVÊW&FRóBÊ˜r˜"66ÜVGV∆RóB&V∆˜r„¬ˆFóc„¬ˆFóc„¬ˆFóc„∆Fób6∆73“'&W˜'B÷vVÊW&FR÷&"#„«6V∆V7BñC“'&W˜'DvVÊW&FUGóR"6∆73“&fñ«FW""7Gñ∆S“&Fó7∆ì¶ÊˆÊR#„∆˜Fñˆ‚f«VS“&ÊWGv˜&µ˜7V÷÷'í#‰ÊWGv˜&≤7V÷÷'ì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&FWfñ6UˆñÁfVÁF˜'í#‰FWfñ6RñÁfVÁF˜'ì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'6V7W&óGïˆfñÊFñÊw2#Â6V7W&óGífñÊFñÊw3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&fñ∆&ñ∆óGïˆ÷ˆÊóF˜&ñÊr#‰fñ∆&ñ∆óGíf◊≤÷ˆÊóF˜&ñÊs¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñÁFVw&FñˆÁ5ˆÜV«FÇ#‰ñÁFVw&FñˆÁ2ÜV«FÉ¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'G&ffñ5˜W6vR#ÂG&ffñ2W6vS¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&VFóEˆ7FófóGí#‰VFóB7FófóGì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&FWfñ6Uˆ6ÜÊvW2#‰FWfñ6R6ÜÊvW3¬ˆ˜Fñˆ„„¬˜6V∆V7C„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“&vVÊW&FU&W˜'BÇí#Ó˚»≤vVÊW&FR6V∆V7FVB&W˜'C¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'&W˜'B◊GóR◊6V7Fñˆ‚#„∆Fób6∆73“'&W˜'B◊GóR÷∆&V¬#‰6Üˆ˜6R&W˜'BGóS¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷w&ñB#‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&W˜'B◊GóR÷6&B7FófR"FF◊&W˜'B◊GóS“&ÊWGv˜&µ˜7V÷÷'í"ˆÊ6∆ñ6≥“'6V∆V7E&W˜'EGóRÇvÊWGv˜&µ˜7V÷÷'írí#„∆Fób6∆73“'&W˜'B◊GóR◊F˜#„«7‚6∆73“'&W˜'B◊GóR÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”2"F√ít”RcÉEc”í#b”fÉgcb"Û„¬˜7fs„¬˜7„„«7‚6∆73“'&W˜'B◊GóR÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷Ê÷R#‰ÊWGv˜&≤7V÷÷'ì¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷FW62#‰˜fW&∆¬FWfñ6W2¬fñÊFñÊw2¬÷ˆÊóF˜'2¬F˜ˆ∆ˆwíÊBñÁFVw&Fñˆ‚ÜV«FÇ„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷fˆ˜B#‰&W7Bf˜"Fñ«í˜W&FñˆÊ¬&WfñWs¬ˆFóc„¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&W˜'B◊GóR÷6&B"FF◊&W˜'B◊GóS“&FWfñ6UˆñÁfVÁF˜'í"ˆÊ6∆ñ6≥“'6V∆V7E&W˜'EGóRÇvFWfñ6UˆñÁfVÁF˜'írí#„∆Fób6∆73“'&W˜'B◊GóR◊F˜#„«7‚6∆73“'&W˜'B◊GóR÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«&V7BÉ“#2"ì“#B"vñGFÉ“#Ç"ÜVñváC“#b"'É“#"Û„«&V7BÉ“#2"ì“#B"vñGFÉ“#Ç"ÜVñváC“#b"'É“#"Û„«FÇC“$”rvÇ„”rvÇ„"Û„¬˜7fs„¬˜7„„«7‚6∆73“'&W˜'B◊GóR÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷Ê÷R#‰FWfñ6RñÁfVÁF˜'ì¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷FW62#‰FWfñ6RñFVÁFóGí¬ïÙ‘2¬7FGW2¬GóR¬6∆76ñfñ6Fñˆ‚ÊB∆7B6VV‚„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷fˆ˜B#‰&W7Bf˜"76WBñÁfVÁF˜'ì¬ˆFóc„¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&W˜'B◊GóR÷6&B"FF◊&W˜'B◊GóS“'6V7W&óGïˆfñÊFñÊw2"ˆÊ6∆ñ6≥“'6V∆V7E&W˜'EGóRÇw6V7W&óGïˆfñÊFñÊw2rí#„∆Fób6∆73“'&W˜'B◊GóR◊F˜#„«7‚6∆73“'&W˜'B◊GóR÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”"22„RñÉt√"5¢"Û„«FÇC“$”"ácT”"b„VÇ„"Û„¬˜7fs„¬˜7„„«7‚6∆73“'&W˜'B◊GóR÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷Ê÷R#Â6V7W&óGífñÊFñÊw3¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷FW62#‰˜V‚fñÊFñÊw2¬6WfW&óGí¬ffV7FVBF&vWG2ÊB&V÷VFñFñˆ‚wVñFÊ6R„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷fˆ˜B#‰&W7Bf˜"6V7W&óGí&WfñWs¬ˆFóc„¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&W˜'B◊GóR÷6&B"FF◊&W˜'B◊GóS“&fñ∆&ñ∆óGïˆ÷ˆÊóF˜&ñÊr"ˆÊ6∆ñ6≥“'6V∆V7E&W˜'EGóRÇvfñ∆&ñ∆óGïˆ÷ˆÊóF˜&ñÊrrí#„∆Fób6∆73“'&W˜'B◊GóR◊F˜#„«7‚6∆73“'&W˜'B◊GóR÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”2&ÉF√"”RB"”VÉb"Û„¬˜7fs„¬˜7„„«7‚6∆73“'&W˜'B◊GóR÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷Ê÷R#‰fñ∆&ñ∆óGíb÷ˆÊóF˜&ñÊs¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷FW62#‰÷ˆÊóF˜"7FFW2¬F&vWG2¬∆FVÊ7íÊBFÜR∆FW7Bfñ∆&ñ∆óGí6ÜV6∑2„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷fˆ˜B#‰&W7Bf˜"6W'fñ6RWFñ÷S¬ˆFóc„¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&W˜'B◊GóR÷6&B"FF◊&W˜'B◊GóS“&ñÁFVw&FñˆÁ5ˆÜV«FÇ"ˆÊ6∆ñ6≥“'6V∆V7E&W˜'EGóRÇvñÁFVw&FñˆÁ5ˆÜV«FÇrí#„∆Fób6∆73“'&W˜'B◊GóR◊F˜#„«7‚6∆73“'&W˜'B◊GóR÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”Ç7cD”b7cD”rvÉcFRR”cu§”"gcR"Û„¬˜7fs„¬˜7„„«7‚6∆73“'&W˜'B◊GóR÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷Ê÷R#‰ñÁFVw&FñˆÁ2ÜV«FÉ¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷FW62#Âí÷Üˆ∆R¬VÊîfíÊB4‰’7ñÊ27FGW2¬W'&˜'2ÊB∆7B6ˆ∆∆V7Fñˆ‚„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷fˆ˜B#‰&W7Bf˜"6ˆ∆∆V7F˜"ÜV«FÉ¬ˆFóc„¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&W˜'B◊GóR÷6&B"FF◊&W˜'B◊GóS“'G&ffñ5˜W6vR"ˆÊ6∆ñ6≥“'6V∆V7E&W˜'EGóRÇwG&ffñ5˜W6vRrí#„∆Fób6∆73“'&W˜'B◊GóR◊F˜#„«7‚6∆73“'&W˜'B◊GóR÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”ÇGcd”Rv√2”224”b#cD”2v√222”2"Û„¬˜7fs„¬˜7„„«7‚6∆73“'&W˜'B◊GóR÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷Ê÷R#ÂG&ffñ2W6vS¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷FW62#‰÷V7W&VBW"÷FWfñ6RF˜vÊ∆ˆB¬W∆ˆB¬&FW2¬6˜W&6RÊB6ˆÊfñFVÊ6R„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷fˆ˜B#‰&W7Bf˜"&ÊGvñGFÇ&WfñWs¬ˆFóc„¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&W˜'B◊GóR÷6&B"FF◊&W˜'B◊GóS“&VFóEˆ7FófóGí"ˆÊ6∆ñ6≥“'6V∆V7E&W˜'EGóRÇvVFóEˆ7FófóGírí#„∆Fób6∆73“'&W˜'B◊GóR◊F˜#„«7‚6∆73“'&W˜'B◊GóR÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„∆6ó&6∆R7É“#""7ì“#""#“#í"Û„«FÇC“$”"wcV√2""Û„¬˜7fs„¬˜7„„«7‚6∆73“'&W˜'B◊GóR÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷Ê÷R#‰VFóB7FófóGì¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷FW62#‰F÷ñÊó7G&FófRÊBW6W"7FñˆÁ2g&ˆ“FÜR&WFñÊVB6V7W&óGíVFóBG&ñ¬„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷fˆ˜B#‰&W7Bf˜"66˜VÁF&ñ∆óGì¬ˆFóc„¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'&W˜'B◊GóR÷6&B"FF◊&W˜'B◊GóS“&FWfñ6Uˆ6ÜÊvW2"ˆÊ6∆ñ6≥“'6V∆V7E&W˜'EGóRÇvFWfñ6Uˆ6ÜÊvW2rí#„∆Fób6∆73“'&W˜'B◊GóR◊F˜#„«7‚6∆73“'&W˜'B◊GóR÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”#gcVÇ”T”Báb”VÉR"Û„«FÇC“$”Çñrr”"”$”bVrr"""Û„¬˜7fs„¬˜7„„«7‚6∆73“'&W˜'B◊GóR÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷Ê÷R#‰FWfñ6R6ÜÊvW3¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷FW62#‰ÊWrFWfñ6W2¬&V6ˆÊÊV7G2¬ˆÊ∆ñÊRˆˆff∆ñÊRG&Á6óFñˆÁ2ÊBï6ÜÊvW2„¬ˆFóc„∆Fób6∆73“'&W˜'B◊GóR÷fˆ˜B#‰&W7Bf˜"6ÜÊvRG&6∂ñÊs¬ˆFóc„¬ˆ'WGFˆ„‡£¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'&W˜'B÷∑í÷w&ñB#‡£∆Fób6∆73“'&W˜'B÷∑í#„∆Fób6∆73“&≤#‰vVÊW&FVB&W˜'G3¬ˆFóc„∆Fób6∆73“'b"ñC“'&W˜'DvVÊW&FVD6˜VÁB#Ó(	C¬ˆFóc„∆Fób6∆73“'7V"#Â&WFñÊVB&W˜'BÜó7F˜'ì¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'&W˜'B÷∑í#„∆Fób6∆73“&≤#Â66ÜVGV∆VC¬ˆFóc„∆Fób6∆73“'b"ñC“'&W˜'E66ÜVGV∆T6˜VÁB#Ó(	C¬ˆFóc„∆Fób6∆73“'7V"#‰WFˆ÷FVB&W˜'B¶ˆ'3¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'&W˜'B÷∑í#„∆Fób6∆73“&≤#‰∆FW7B&W˜'C¬ˆFóc„∆Fób6∆73“'b"ñC“'&W˜'D∆FW7EGóR"7Gñ∆S“&fˆÁB◊6ó¶S£WÇ#Ó(	C¬ˆFóc„∆Fób6∆73“'7V""ñC“'&W˜'D∆FW7EFñ÷R#‰Ê˜FÜñÊrvVÊW&FVBñWC¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'&W˜'B÷∑í#„∆Fób6∆73“&≤#‰Wá˜'Bf˜&÷G3¬ˆFóc„∆Fób6∆73“'b"7Gñ∆S“&fˆÁB◊6ó¶S£WÇ#ÂDb+r55c¬ˆFóc„∆Fób6∆73“'7V"#‰F˜vÊ∆ˆBÁívVÊW&FVB&W˜'C¬ˆFóc„¬ˆFóc‡£¬ˆFóc‡£∆Fób6∆73“'G&ffñ2÷6&B◊v˜&∑76R#‡£∆Fób6∆73“'G&ffñ2÷6&B÷ÜVFñÊr#„∆Fób6∆73“'G&ffñ2÷6&B÷ÜVFñÊr÷6˜í#„∆Fób6∆73“'G&ffñ2◊FóF∆R÷ñ6ˆ‚#Ó(xS¬ˆFóc„∆Fóc„∆É#ÂW"‘FWfñ6RG&ffñ26ˆ∆∆V7Fñˆ„¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰÷V7W&VBG&ffñ2ñÁFV∆∆ñvVÊ6RvóFÇ6∆V&«íFVfñÊVB6˜W&6R¬7FGW2ÊB6ˆÊfñFVÊ6R„¬ˆFóc„¬ˆFóc„¬ˆFóc„«7‚ñC“'G&ffñ46ˆ∆∆V7FñˆÂ7FFR"6∆73“'G&ffñ2◊7FFR#‰ƒÙDî‰s¬˜7„„¬ˆFóc‡†£∆Fób6∆73“'G&ffñ2◊7FB÷w&ñB#‡£∆Fób6∆73“'G&ffñ2◊7FB÷6&B#„«7‚6∆73“'G&ffñ2◊7FB÷ñ6ˆ‚#Ó(…É¬˜7„„∆Fób6∆73“'G&ffñ2◊7FB÷∆&V¬#‰7FófR6˜W&6S¬ˆFóc„∆Fób6∆73“'G&ffñ2◊7FB◊f«VR"ñC“'G&ffñ56˜W&6T∆&V¬#Ó(	C¬ˆFóc„∆Fób6∆73“'G&ffñ2◊7FB◊7V""ñC“'G&ffñ56˜W&6U7V"#‰Ê˜B6ˆÊfñwW&VC¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'G&ffñ2◊7FB÷6&B#„«7‚6∆73“'G&ffñ2◊7FB÷ñ6ˆ‚#Ó(i3¬˜7„„∆Fób6∆73“'G&ffñ2◊7FB÷∆&V¬#„#FÇF˜vÊ∆ˆC¬ˆFóc„∆Fób6∆73“'G&ffñ2◊7FB◊f«VR"ñC“'G&ffñ3#E'Ç#„#¬ˆFóc„∆Fób6∆73“'G&ffñ2◊7FB◊7V"#‰÷V7W&VBW"÷FWfñ6RG&ffñ3¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'G&ffñ2◊7FB÷6&B#„«7‚6∆73“'G&ffñ2◊7FB÷ñ6ˆ‚#Ó(i¬˜7„„∆Fób6∆73“'G&ffñ2◊7FB÷∆&V¬#„#FÇW∆ˆC¬ˆFóc„∆Fób6∆73“'G&ffñ2◊7FB◊f«VR"ñC“'G&ffñ3#EGÇ#„#¬ˆFóc„∆Fób6∆73“'G&ffñ2◊7FB◊7V"#‰÷V7W&VBW"÷FWfñ6RG&ffñ3¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'G&ffñ2◊7FB÷6&B#„«7‚6∆73“'G&ffñ2◊7FB÷ñ6ˆ‚#Ó)j3¬˜7„„∆Fób6∆73“'G&ffñ2◊7FB÷∆&V¬#‰FWfñ6W2÷V7W&VC¬ˆFóc„∆Fób6∆73“'G&ffñ2◊7FB◊f«VR"ñC“'G&ffñ4FWfñ6T6˜VÁB#„¬ˆFóc„∆Fób6∆73“'G&ffñ2◊7FB◊7V""ñC“'G&ffñ4∆7E6◊∆R#‰ÊÚ6◊∆W2ñWC¬ˆFóc„¬ˆFóc‡£¬ˆFóc‡†£«6V7Fñˆ‚6∆73“'G&ffñ2◊6˜W&6R◊6V7Fñˆ‚÷6&B#‡£∆Fób6∆73“'G&ffñ2÷6&B◊6V7Fñˆ‚÷ÜVB#„∆Fób6∆73“'G&ffñ2÷6&B◊6V7Fñˆ‚◊FóF∆R#„«7‚6∆73“'G&ffñ2◊6V7Fñˆ‚÷ñ6ˆ‚#„¬˜7„„∆Fóc„∆É3„‚6Üˆ˜6RG&ffñ26˜W&6S¬ˆÉ3„∆Fób6∆73“&◊WFVB#Â6V∆V7BFÜR6˜W&6RFÜB6‚7GV∆«íˆ'6W'fRFWfñ6RG&ffñ2„¬ˆFóc„¬ˆFóc„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'G&ffñ2÷6&B◊6V7Fñˆ‚÷&ˆGí#‡£«6V∆V7BñC“'G&ffñ4÷ˆFR"6∆73“&fñ«FW""ˆÊ6ÜÊvS“'&VÊFW%G&ffñ4÷ˆFTfñV∆G2Çí"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#„∆˜Fñˆ‚f«VS“'VÊñfí#ÂVÊîfíÚ6ˆÁG&ˆ∆∆W#¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'6Ê◊#Â4‰’¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'7‚#Â5‚Ú÷ó'&˜#¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñÊ∆ñÊR#‰ñÊ∆ñÊRÚvFWvì¬ˆ˜Fñˆ„„¬˜6V∆V7C‡£∆Fób6∆73“'G&ffñ2◊6˜W&6R÷w&ñB#‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'G&ffñ2◊6˜W&6R÷6&B"FF◊G&ffñ2÷÷ˆFS“'VÊñfí"FF÷6∆V„“#"ˆÊ6∆ñ6≥“'6V∆V7EG&ffñ4÷ˆFRÇwVÊñfírí#‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷6&B÷ÜVB#„«7‚6∆73“'G&ffñ2◊6˜W&6R÷ñ6ˆ‚#Ó)xì¬˜7„„∆Fóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷Ê÷R#ÂVÊîfíÚ6ˆÁG&ˆ∆∆W#¬ˆFóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷∂ñÊB#‰6ˆÁG&ˆ∆∆W"ì¬ˆFóc„¬ˆFóc„«7‚6∆73“'G&ffñ2◊6V∆V7FVB÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷FW62#ÂW6RFWfñ6R6˜VÁFW'2«&VGí6ˆ∆∆V7FVB'íñ˜W"VÊîfí6ˆÁG&ˆ∆∆W"„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷FófñFW"#„¬ˆFóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷÷WF#„«7„ÂVÊîfíÊWGv˜&∑3¬˜7„„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷fˆ˜B#„«7‚6∆73“'G&ffñ2◊6˜W&6R◊Fr&V6ˆ÷÷VÊFVB#Â&V6ˆ÷÷VÊFVC¬˜7„„«7„Â6V∆V7B‚ñÁFVw&Fñˆ„¬˜7„„¬ˆFóc‡£¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'G&ffñ2◊6˜W&6R÷6&B"FF◊G&ffñ2÷÷ˆFS“'6Ê◊"FF÷6∆V„“#"ˆÊ6∆ñ6≥“'6V∆V7EG&ffñ4÷ˆFRÇw6Ê◊rí#‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷6&B÷ÜVB#„«7‚6∆73“'G&ffñ2◊6˜W&6R÷ñ6ˆ‚#Ó(»¬˜7„„∆Fóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷Ê÷R#Â4‰’¬ˆFóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷∂ñÊB#‰6˜VÁFW"&ˆfñ∆S¬ˆFóc„¬ˆFóc„«7‚6∆73“'G&ffñ2◊6V∆V7FVB÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷FW62#Â&VB÷VBG&ffñ26˜VÁFW'2g&ˆ“7W˜'FVB&˜WFW'2ÊB7vóF6ÜW2„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷FófñFW"#„¬ˆFóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷÷WF#„«7„‰÷ÊvVBÊWGv˜&∑3¬˜7„„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷fˆ˜B#„«7‚6∆73“'G&ffñ2◊6˜W&6R◊Fr#‰f∆WÜñ&∆S¬˜7„„«7„‰ÙîB&ˆfñ∆R&WVó&VC¬˜7„„¬ˆFóc‡£¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'G&ffñ2◊6˜W&6R÷6&B"FF◊G&ffñ2÷÷ˆFS“'7‚"FF÷6∆V„“#"ˆÊ6∆ñ6≥“'6V∆V7EG&ffñ4÷ˆFRÇw7‚rí#‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷6&B÷ÜVB#„«7‚6∆73“'G&ffñ2◊6˜W&6R÷ñ6ˆ‚#Ó(xC¬˜7„„∆Fóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷Ê÷R#Â5‚Ú÷ó'&˜#¬ˆFóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷∂ñÊB#Â6∂WB6VÁ6˜#¬ˆFóc„¬ˆFóc„«7‚6∆73“'G&ffñ2◊6V∆V7FVB÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷FW62#‰ˆ'6W'fR÷ó'&˜&VBG&ffñ2vóFÜ˜WB∆6ñÊrtÙE4UîRñ‚FÜRvFWvíFÇ„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷FófñFW"#„¬ˆFóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷÷WF#„«7„Â76ófRfó6ñ&ñ∆óGì¬˜7„„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷fˆ˜B#„«7‚6∆73“'G&ffñ2◊6˜W&6R◊FrGfÊ6VB#‰GfÊ6VC¬˜7„„«7„‰÷ó'&˜"˜'B≤‰î3¬˜7„„¬ˆFóc‡£¬ˆ'WGFˆ„‡£∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'G&ffñ2◊6˜W&6R÷6&B"FF◊G&ffñ2÷÷ˆFS“&ñÊ∆ñÊR"FF÷6∆V„“#"ˆÊ6∆ñ6≥“'6V∆V7EG&ffñ4÷ˆFRÇvñÊ∆ñÊRrí#‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷6&B÷ÜVB#„«7‚6∆73“'G&ffñ2◊6˜W&6R÷ñ6ˆ‚#Ó(iC¬˜7„„∆Fóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷Ê÷R#‰ñÊ∆ñÊRÚvFWvì¬ˆFóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷∂ñÊB#‰ñÊ∆ñÊR6VÁ6˜#¬ˆFóc„¬ˆFóc„«7‚6∆73“'G&ffñ2◊6V∆V7FVB÷6ÜV6≤#Ó)…3¬˜7„„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷FW62#‰÷V7W&RG&ffñ2FÜB7GV∆«í76W2Fá&˜VvÇFÜRtÙE4UîR∆ñÊ6R„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷FófñFW"#„¬ˆFóc„∆Fób6∆73“'G&ffñ2◊6˜W&6R÷÷WF#„«7„‰gV∆¬◊FÇfó6ñ&ñ∆óGì¬˜7„„¬ˆFóc‡¢∆Fób6∆73“'G&ffñ2◊6˜W&6R÷fˆ˜B#„«7‚6∆73“'G&ffñ2◊6˜W&6R◊FrGfÊ6VB#‰GfÊ6VC¬˜7„„«7„‰gV∆¬◊FÇfó6ñ&ñ∆óGì¬˜7„„¬ˆFóc‡£¬ˆ'WGFˆ„‡£¬ˆFóc‡£¬ˆFóc‡£¬˜6V7Fñˆ„‡†£«6V7Fñˆ‚6∆73“'G&ffñ2÷6ˆÊfñr◊6V7Fñˆ‚÷6&B#‡£∆Fób6∆73“'G&ffñ2÷6&B◊6V7Fñˆ‚÷ÜVB#„∆Fób6∆73“'G&ffñ2÷6&B◊6V7Fñˆ‚◊FóF∆R#„«7‚6∆73“'G&ffñ2◊6V7Fñˆ‚÷ñ6ˆ‚#„#¬˜7„„∆Fóc„∆É3„"‚6ˆÊfñwW&R6˜W&6S¬ˆÉ3„∆Fób6∆73“&◊WFVB#‰6ˆ∆∆V7Fñˆ‚6WGFñÊw2ÊB&WVó&V÷VÁG2&R6W&FVBñÁFÚFÜVó"˜v‚6&G2„¬ˆFóc„¬ˆFóc„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'G&ffñ2÷6&B◊6V7Fñˆ‚÷&ˆGí#‡£∆Fób6∆73“'G&ffñ2÷6ˆÊfñr÷6&B÷w&ñB#‡£∆Fób6∆73“'G&ffñ2÷÷ñÊí÷6&B#„∆ÉCÂ6˜W&6R6ˆÊfñwW&Fñˆ„¬ˆÉC„∆Fób6∆73“'G&ffñ2÷6ˆÊfñr÷fñV∆G2#‡£∆∆&V¬ñC“'G&ffñ4ñÁFVw&FñˆÂw&#Â6˜W&6RñÁFVw&Fñˆ„«6V∆V7BñC“'G&ffñ4ñÁFVw&Fñˆ‚"6∆73“&fñ«FW"#„¬˜6V∆V7C„¬ˆ∆&V√‡£∆∆&V¬ñC“'G&ffñ4ñÁFW&f6Uw&"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‰6GW&RñÁFW&f6S«6V∆V7BñC“'G&ffñ4ñÁFW&f6R"6∆73“&fñ«FW"#„¬˜6V∆V7C„¬ˆ∆&V√‡£∆∆&V√Â6◊∆RñÁFW'f√∆ñÁWBñC“'G&ffñ4ñÁFW'f¬"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“#"÷É“#3c"f«VS“#3#„«7‚6∆73“&◊WFVB#Â6V6ˆÊG2&WGvVV‚6ˆ∆∆V7Fñˆ‚7ñ6∆W3¬˜7„„¬ˆ∆&V√‡£∆∆&V√‰6ˆ∆∆V7Fñˆ‚7FFS«6V∆V7BñC“'G&ffñ4VÊ&∆VB"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“##‰Fó6&∆VC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“##‰VÊ&∆VC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡£¬ˆFóc„∆Fób6∆73“'G&ffñ2÷6ˆÊfñr÷7FñˆÁ2÷6&B#„∆'WGFˆ‚6∆73“'&ñ÷'í"FF÷F÷ñ‚÷ˆÊ«íˆÊ6∆ñ6≥“'6fUG&ffñ46ˆ∆∆V7Fñˆ‚Çí#Â6fR6ˆÊfñwW&Fñˆ„¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"FF÷F÷ñ‚÷ˆÊ«íˆÊ6∆ñ6≥“&6ˆ∆∆V7EG&ffñ4Ê˜rÇí#Â'V‚6ˆ∆∆V7Fñˆ‚Ê˜s¬ˆ'WGFˆ„„«7‚6∆73“&◊WFVB"ñC“'G&ffñ46ˆ∆∆V7Fñˆ‰÷WF#„¬˜7„„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'G&ffñ2÷÷ñÊí÷6&B#„∆ÉBñC“'G&ffñ4÷ˆFTÜV«FóF∆R#Â6˜W&6R&WVó&V÷VÁG3¬ˆÉC„∆FóbñC“'G&ffñ4÷ˆFTÜV«"6∆73“'G&ffñ2÷ÜV«÷6˜í#Â6V∆V7BG&ffñ26˜W&6RFÚ6VRóG2&WVó&V÷VÁG2„¬ˆFóc„∆FóbñC“'G&ffñ4÷ˆFU&WVó&R"6∆73“'G&ffñ2÷ÜV«◊&WVó&R#‰tÙE4UîR&V6˜&G2FÜR÷V7W&V÷VÁB6˜W&6RÊB6ˆÊfñFVÊ6RvóFÇWfW'íFWfñ6R6◊∆R„¬ˆFóc„¬ˆFóc‡£¬ˆFóc‡£¬ˆFóc‡£¬˜6V7Fñˆ„‡†£«6V7Fñˆ‚6∆73“'G&ffñ2◊W6vR÷6&B#‡£∆Fób6∆73“'G&ffñ2÷6&B◊6V7Fñˆ‚÷ÜVB#„∆Fób6∆73“'G&ffñ2÷6&B◊6V7Fñˆ‚◊FóF∆R#„«7‚6∆73“'G&ffñ2◊6V7Fñˆ‚÷ñ6ˆ‚#„3¬˜7„„∆Fóc„∆É3ÂF˜FWfñ6RW6vR+r∆7B#BÜ˜W'3¬ˆÉ3„∆Fób6∆73“&◊WFVB#‰ˆÊ«í&V¬÷V7W&VBW"÷FWfñ6R6˜VÁFW'2&RFó7∆ñVB„¬ˆFóc„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&∆ˆE&W˜'G2Çí#Ó(k≤&Vg&W6É¬ˆ'WGFˆ„„¬ˆFóc‡£∆Fób6∆73“'G&ffñ2◊F&∆R◊w&#„«F&∆S„«FÜVC„«G#„«FÉ‰FWfñ6S¬˜FÉ„«FÉÂ6˜W&6S¬˜FÉ„«FÉ‰F˜vÊ∆ˆC¬˜FÉ„«FÉÂW∆ˆC¬˜FÉ„«FÉÂV≤F˜vÊ∆ˆC¬˜FÉ„«FÉÂV≤W∆ˆC¬˜FÉ„«FÉ‰∆7B6◊∆S¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“'G&ffñ4FWfñ6U&˜w2#„«G#„«FB6ˆ«7„“#r"6∆73“&V◊GíG&ffñ2÷V◊Gí#„«7‚6∆73“'G&ffñ2÷V◊Gí÷ñ6ˆ‚#Ó(xS¬˜7„‰ÊÚW"÷FWfñ6RG&ffñ26◊∆W2ñWB„¬˜FC„¬˜G#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc‡£¬˜6V7Fñˆ„‡£¬ˆFóc‡£∆Fób6∆73“'&W˜'B÷w&ñB◊GvÚ#‡£«6V7Fñˆ‚6∆73“'&W˜'B◊6V7Fñˆ‚÷6&B#„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚÷ÜVB#„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚◊FóF∆R#„«7‚6∆73“'&W˜'B◊6V7Fñˆ‚÷ñ6ˆ‚#Ó(ö¬˜7„„∆Fóc„∆É#‰7W'&VÁBÊWGv˜&≤7V÷÷'ì¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰∆ófR&W˜'B◊&VGíÊWGv˜&≤6Ê6Ü˜C¬ˆFóc„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&∆ˆE&W˜'G2Çí#Ó(k≤&Vg&W6É¬ˆ'WGFˆ„„¬ˆFóc„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚÷&ˆGí#„«&RñC“'&W˜'E7V÷÷'í"6∆73“'&W˜'B◊7V÷÷'í÷&˜Ç#‰∆ˆFñÊ~(
c¬˜&S„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'&W˜'B◊6V7Fñˆ‚÷6&B#„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚÷ÜVB#„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚◊FóF∆R#„«7‚6∆73“'&W˜'B◊6V7Fñˆ‚÷ñ6ˆ‚#Ó){s¬˜7„„∆Fóc„∆É#Â66ÜVGV∆R&W˜'C¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰WFˆ÷FR&V7W'&ñÊr&W˜'BvVÊW&Fñˆ„¬ˆFóc„¬ˆFóc„¬ˆFóc„¬ˆFóc„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚÷&ˆGí#„∆Fób6∆73“'&W˜'B◊66ÜVGV∆R÷f˜&“#„∆∆&V¬6∆73“&gV∆¬#Â66ÜVGV∆RÊ÷S∆ñÁWBñC“'&W˜'DÊ÷R"6∆73“&ñÁWB"∆6VÜˆ∆FW#“%vVV∂«í6V7W&óGí&WfñWr#„¬ˆ∆&V√„∆∆&V√Â&W˜'BGóS«6V∆V7BñC“'&W˜'E66ÜVGV∆UGóR"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“&ÊWGv˜&µ˜7V÷÷'í#‰ÊWGv˜&≤7V÷÷'ì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&FWfñ6UˆñÁfVÁF˜'í#‰FWfñ6RñÁfVÁF˜'ì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'6V7W&óGïˆfñÊFñÊw2#Â6V7W&óGífñÊFñÊw3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&fñ∆&ñ∆óGïˆ÷ˆÊóF˜&ñÊr#‰fñ∆&ñ∆óGíf◊≤÷ˆÊóF˜&ñÊs¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñÁFVw&FñˆÁ5ˆÜV«FÇ#‰ñÁFVw&FñˆÁ2ÜV«FÉ¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'G&ffñ5˜W6vR#ÂG&ffñ2W6vS¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&VFóEˆ7FófóGí#‰VFóB7FófóGì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&FWfñ6Uˆ6ÜÊvW2#‰FWfñ6R6ÜÊvW3¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√„∆∆&V√‰6FVÊ6S«6V∆V7BñC“'&W˜'D6FVÊ6R"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“&Fñ«í#‰Fñ«ì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'vVV∂«í#ÂvVV∂«ì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&Ü˜W&«í#‰Ü˜W&«ì¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√„∆∆&V√ÂUD2Ü˜W#∆ñÁWBñC“'&W˜'DÜ˜W""6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“#"÷É“##2"f«VS“#"#„¬ˆ∆&V√„∆Fób7Gñ∆S“&Fó7∆ì¶f∆WÉ∂∆ñv‚÷óFV◊3¶VÊB#„∆'WGFˆ‚6∆73“'&ñ÷'í"7Gñ∆S“'vñGFÉ£R"ˆÊ6∆ñ6≥“&FE&W˜'E66ÜVGV∆RÇí#Ó˚»≤FB66ÜVGV∆S¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£«6V7Fñˆ‚6∆73“'&W˜'B◊6V7Fñˆ‚÷6&B#„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚÷ÜVB#„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚◊FóF∆R#„«7‚6∆73“'&W˜'B◊6V7Fñˆ‚÷ñ6ˆ‚#Ó)jc¬˜7„„∆Fóc„∆É#Â66ÜVGV∆VB&W˜'G3¬ˆÉ#„∆Fób6∆73“&◊WFVB#ÂW6ˆ÷ñÊrWFˆ÷FVB&W˜'B¶ˆ'3¬ˆFóc„¬ˆFóc„¬ˆFóc„¬ˆFóc„∆Fób6∆73“'&W˜'B÷Üó7F˜'í◊w&#„«F&∆S„«FÜVC„«G#„«FÉ‰Ê÷S¬˜FÉ„«FÉÂGóS¬˜FÉ„«FÉ‰6FVÊ6S¬˜FÉ„«FÉ‰ÊWáB'V„¬˜FÉ„«FÉ‰∆7B'V„¬˜FÉ„«FÉ„¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“'&W˜'E66ÜVGV∆W2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'&W˜'B◊6V7Fñˆ‚÷6&B#„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚÷ÜVB#„∆Fób6∆73“'&W˜'B◊6V7Fñˆ‚◊FóF∆R#„«7‚6∆73“'&W˜'B◊6V7Fñˆ‚÷ñ6ˆ‚#Ó(zì¬˜7„„∆Fóc„∆É#Â&W˜'BÜó7F˜'ì¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰vVÊW&FVB&W˜'G2¬Wá˜'Bf˜&÷G2¬V÷ñ¬FV∆ófW'í¬ÊB6∆VÁW¬ˆFóc„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2F÷ñ‚÷ˆÊ«í#„∆'WGFˆ‚6∆73“&FÊvW""ñC“&FV∆WFU6V∆V7FVE&W˜'G4'F‚"ˆÊ6∆ñ6≥“&FV∆WFU6V∆V7FVE&W˜'G2Çí"Fó6&∆VC‰FV∆WFR6V∆V7FVC¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc„∆Fób6∆73“'&W˜'B÷Üó7F˜'í◊w&#„«F&∆S„«FÜVC„«G#„«FÉ„∆ñÁWBGóS“&6ÜV6∂&˜Ç"ñC“'&W˜'E6V∆V7D∆¬"ˆÊ6ÜÊvS“'Fˆvv∆T∆≈&W˜'G2áFÜó2Ê6ÜV6∂VBí"&ñ÷∆&V√“%6V∆V7B∆¬&W˜'G2#„¬˜FÉ„«FÉ‰vVÊW&FVC¬˜FÉ„«FÉÂGóS¬˜FÉ„«FÉÂFóF∆S¬˜FÉ„«FÉ‰∂Wí÷WG&ñ73¬˜FÉ„«FÉ‰Wá˜'C¬˜FÉ„«FÉ‰7FñˆÁ3¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“'&W˜'DÜó7F˜'í#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£¬ˆFóc‡††£∆Fób6∆73“'fñWr"ñC“'fñWr◊&V÷˜FR÷66W72"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“&ÜW&Ú&V÷˜FR÷ÜW&Ú#„∆Fóc„∆ÉÂ&V÷˜FR66W73¬ˆÉ„∆Fób6∆73“&◊WFVB#ÂVñ6≤76ó7B◊7Gñ∆R7W˜'Bf˜"tÙE4UîRvñÊF˜w2vVÁB"„B„B‚67&VV‚6Ü&ñÊrÊB&V÷˜FR6ˆÁG&ˆ¬&WVó&R6W&FR&˜f¬„¬ˆFóc„¬ˆFóc„∆Fób6∆73“'&V÷˜FR◊7FG2#„«7„„∆"ñC“'&V÷˜FTˆÊ∆ñÊT6˜VÁB#„¬ˆ#‚ˆÊ∆ñÊS¬˜7„„«7„„∆"ñC“'&V÷˜FTˆff∆ñÊT6˜VÁB#„¬ˆ#‚ˆff∆ñÊS¬˜7„„«7„„∆"ñC“'&V÷˜FUF˜Fƒ6˜VÁB#„¬ˆ#‚vVÁG3¬˜7„„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'&V÷˜FR÷∆ñ˜WB#‡£«6V7Fñˆ‚6∆73“'ÊV¬&V÷˜FR÷6ˆ◊WFW'2#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰vVÁB6ˆ◊WFW'3¬ˆÉ#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“&∆ˆE&V÷˜FT66W72Çí#Ó(k≤&Vg&W6É¬ˆ'WGFˆ„„¬ˆFóc„∆Fób6∆73“'&V÷˜FR÷fñ«FW"#„∆ñÁWBñC“'&V÷˜FU6V&6Ç"6∆73“&ñÁWB"∆6VÜˆ∆FW#“%6V&6Ç6ˆ◊WFW'>(
b"ˆÊñÁWC“'&VÊFW%&V÷˜FTvVÁG2Çí#„¬ˆFóc„∆FóbñC“'&V÷˜FTvVÁD∆ó7B"6∆73“'&V÷˜FR÷vVÁB÷∆ó7B#„∆Fób6∆73“&V◊Gí#‰∆ˆFñÊrvñÊF˜w2vVÁG>(
c¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬&V÷˜FR◊6W76ñˆ‚◊ÊV¬#‡£∆Fób6∆73“'&V÷˜FR◊6W76ñˆ‚÷ÜVB#„∆Fóc„∆É"ñC“'&V÷˜FU6W76ñˆÂFóF∆R#Â&V÷˜FR6W76ñˆ„¬ˆÉ#„∆Fób6∆73“&◊WFVB"ñC“'&V÷˜FU6W76ñˆÂ7FGW2#Â6V∆V7B‚ˆÊ∆ñÊR6ˆ◊WFW"FÚ&Vvñ‚„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚ñC“'&V÷˜FT6ˆÁG&ˆƒ'F‚"6∆73“'&ñ÷'í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'&WVW7E&V÷˜FT6ˆÁG&ˆ¬Çí"Fó6&∆VCÂ&WVW7B6ˆÁG&ˆ√¬ˆ'WGFˆ„„∆'WGFˆ‚ñC“'&V÷˜FU67&VVÁ6Ü˜D'F‚"6∆73“'6V6ˆÊF'í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“&˜VÂ&V÷˜FU67&VVÁ6Ü˜BÇí"Fó6&∆VCÂF∂R67&VVÁ6Ü˜C¬ˆ'WGFˆ„„∆'WGFˆ‚ñC“'&V÷˜FTFó66ˆÊÊV7D'F‚"6∆73“&FÊvW""GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'7F˜&V÷˜FU6W76ñˆ‚Çí"Fó6&∆VC‰Fó66ˆÊÊV7C¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡£∆FóbñC“'&V÷˜FU67&VVÂw&"6∆73“'&V÷˜FR◊67&VV‚◊w&"F&ñÊFWÉ“##„∆FóbñC“'&V÷˜FTV◊Gí"6∆73“'&V÷˜FR◊67&VV‚÷V◊Gí#„∆Fób6∆73“'&V÷˜FR÷÷ˆÊóF˜"÷ñ6ˆ‚#Ó)k¬ˆFóc„∆#‰ÊÚ7FófR&V÷˜FR6W76ñˆ„¬ˆ#„«7„Â6V∆V7B6ˆ◊WFW"ÊB6∆ñ6≤6ˆÊÊV7B„¬˜7„„¬ˆFóc„∆ñ÷rñC“'&V÷˜FU67&VV‚"6∆73“'&V÷˜FR◊67&VV‚"«C“%&V÷˜FRvñÊF˜w2FW6∑F˜"G&vv&∆S“&f«6R"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#„¬ˆFóc‡£∆FóbñC“'&V÷˜FU6W76ñˆ‰÷WF"6∆73“'&V÷˜FR◊6W76ñˆ‚÷÷WF#„«7„‰6ˆ◊WFW#¢∆#Ó(	C¬ˆ#„¬˜7„„«7„Â67&VV‚6Ü&ñÊs¢∆#‰&˜f¬&WVó&VC¬ˆ#„¬˜7„„«7„‰6ˆÁG&ˆ√¢∆#ÂfñWrˆÊ«ì¬ˆ#„¬˜7„„«7„Â7FGW3¢∆#‰ñF∆S¬ˆ#„¬˜7„„¬ˆFóc‡£¬˜6V7Fñˆ„„¬ˆFóc„¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr÷ÜV«FÇ"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£∆Fób6∆73“&ÜW&Ú#„∆Fóc„∆ÉÂ7ó7FV“ÜV«FÉ¬ˆÉ„∆Fób6∆73“&◊WFVB#‰÷ˆÊóF˜"FÜRÜV«FÇÊBW&f˜&÷Ê6Rˆbñ˜W"tÙE4UîR7ó7FV“6ˆ◊ˆÊVÁG2„¬ˆFóc„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“'cC3÷ÜV«FÇ◊7FGW2÷w&ñB6&G2#‡£∆Fób6∆73“&6&BcC3÷ÜV«FÇ÷6&B#„«7‚6∆73“'cC3÷ÜV«FÇ÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«&V7BÉ“#2"ì“#B"vñGFÉ“#Ç"ÜVñváC“#b"'É“#"Û„«&V7BÉ“#2"ì“#B"vñGFÉ“#Ç"ÜVñváC“#b"'É“#"Û„«FÇC“$”rvÇ„”rvÇ„"Û„¬˜7fs„¬˜7„„∆Fóc„«6÷∆√‰∆ñÊ6RÜV«FÉ¬˜6÷∆√„∆"ñC“&ÜV«FÑ˜fW&∆¬#Ó(	C¬ˆ#„∆V”Â7ó7FV“7FGW3¬ˆV”„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“&6&BcC3÷ÜV«FÇ÷6&B#„«7‚6∆73“'cC3÷ÜV«FÇ÷ñ6ˆ‚w&VV‚#„«7frfñWt&˜É“##B#B#„∆6ó&6∆R7É“#""7ì“#""#“#í"Û„∆6ó&6∆R7É“#""7ì“#""#“#R"Û„∆6ó&6∆R7É“#""7ì“#""#“#"Û„¬˜7fs„¬˜7„„∆Fóc„«6÷∆√Â66ÊÊW"6W'fñ6S¬˜6÷∆√„∆"ñC“'cC3ÜV«FÖ66ÊÊW"#‰6ÜV6∂ñÊs¬ˆ#„∆V”‰ÊWGv˜&≤66ÊÊW#¬ˆV”„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“&6&BcC3÷ÜV«FÇ÷6&B#„«7‚6∆73“'cC3÷ÜV«FÇ÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„∆V∆∆ó6R7É“#""7ì“#R"'É“#Ç"'ì“#2"Û„«FÇC“$”BWcv3„r2„b2Ç73Ç”„2Ç”5cT”B'cv3„r2„b2Ç73Ç”„2Ç”7b”r"Û„¬˜7fs„¬˜7„„∆Fóc„«6÷∆√‰FF&6S¬˜6÷∆√„∆"ñC“'cC3ÜV«FÑF"#‰6ÜV6∂ñÊs¬ˆ#„∆V“ñC“&ÜV«FÑÜ˜7B#Ó(	C¬ˆV”„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“&6&BcC3÷ÜV«FÇ÷6&B#„«7‚6∆73“'cC3÷ÜV«FÇ÷ñ6ˆ‚w&VV‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”bñÉ&BB„r”r„îrrR„"í„ÇB„RB„Rbó¢"Û„¬˜7fs„¬˜7„„∆Fóc„«6÷∆√‰&6∑W3¬˜6÷∆√„∆"ñC“'cC3ÜV«FÑ&6∑W#‰6ÜV6∂ñÊs¬ˆ#„∆V”Â6fWGí6˜ñW3¬ˆV”„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“&6&BcC3÷ÜV«FÇ÷6&B#„«7‚6∆73“'cC3÷ÜV«FÇ÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”#wcVÇ”T”Bwb”VÉT”b„Ürr„R”√#$”B&√"„BVrr„R”"Û„¬˜7fs„¬˜7„„∆Fóc„«6÷∆√ÂWFFR6ÜÊÊV√¬˜6÷∆√„∆"ñC“'cC3ÜV«FÖWFFR#Â7F&∆S¬ˆ#„∆V”ÁeıÙıdU%4îÙÂıÛ¬ˆV”„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“&6&BcC3÷ÜV«FÇ÷6&B#„«7‚6∆73“'cC3÷ÜV«FÇ÷ñ6ˆ‚#„«7frfñWt&˜É“##B#B#„«FÇC“$”í6ÉgcF""BcVÇ”F""FÉGcTÉ7b”fÉF""”DÉ5cfÉg¢"Û„¬˜7fs„¬˜7„„∆Fóc„«6÷∆√‰ñÁFVw&FñˆÁ3¬˜6÷∆√„∆"ñC“'cC3ÜV«FÑñÁFVw&FñˆÁ2#‰ÜV«Fáì¬ˆ#„∆V“ñC“&ÜV«FÑ∂W&ÊV¬#Ó(	C¬ˆV”„¬ˆFóc„¬ˆFóc‡£¬ˆFóc‡£∆Fób6∆73“'cC3÷ÜV«FÇ÷÷WG&ñ72#‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰5RW6vS¬ˆÉ#„«7‚6∆73“&◊WFVB#‰∆7B#BÜ˜W'2(£¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷÷WG&ñ2#„∆Fób6∆73“'cC3◊&ñÊr#„∆"ñC“&ÜV«FÑ7R#Ó(	C¬ˆ#„«7„‰5S¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3◊7&≤#„∆í7Gñ∆S“&ÜVñváC£#BR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3bR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3R#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£CRR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£#ÇR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£S"R#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3RR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£C"R#„¬ˆì„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰÷V÷˜'íW6vS¬ˆÉ#„«7‚6∆73“&◊WFVB#‰∆7B#BÜ˜W'2(£¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷÷WG&ñ2#„∆Fób6∆73“'cC3◊&ñÊr÷V÷˜'í#„∆"ñC“&ÜV«FÑ÷V“#Ó(	C¬ˆ#„«7„‰÷V÷˜'ì¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3◊7&≤w&VV‚#„∆í7Gñ∆S“&ÜVñváC£CRR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£cBR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3íR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3BR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£C"R#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3"R#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3bR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3R#„¬ˆì„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰Fó6≤W6vS¬ˆÉ#„«7‚6∆73“&◊WFVB#‰∆7B#BÜ˜W'2(£¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷÷WG&ñ2#„∆Fób6∆73“'cC3◊&ñÊrFó6≤#„∆"ñC“&ÜV«FÑFó6≤#Ó(	C¬ˆ#„«7„‰Fó6≥¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3◊7&≤÷&W"#„∆í7Gñ∆S“&ÜVñváC£#ÇR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£32R#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£#RR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£C2R#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3R#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3bR#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£3R#„¬ˆì„∆í7Gñ∆S“&ÜVñváC£CRR#„¬ˆì„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£∆Fób6∆73“'cC3÷ÜV«FÇ◊6V6ˆÊF'í#‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#Â7F˜&vRw&˜wFÉ¬ˆÉ#„«7‚6∆73“&◊WFVB#‰7W'&VÁBW6vS¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷˜fW'fñWr#„«7G&ˆÊrñC“&ÜV«FÖ7F˜&vUW6vR#Ó(	C¬˜7G&ˆÊs„«7„ÂW6VB76Rˆ‚FÜR∆ñÊ6RFFFó6≥¬˜7„„∆Fób6∆73“'cC3÷÷WFW"#„∆íñC“&ÜV«FÖ7F˜&vT&"#„¬ˆì„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰ÊWGv˜&≤íÙÚÖ7ó7FV“ì¬ˆÉ#„«7‚6∆73“&◊WFVB#‰6ˆ∆∆V7F˜"6◊∆W3¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷˜fW'fñWr#„«7G&ˆÊrñC“&ÜV«FÑÊWGv˜&µ&FR#ÂvóFñÊrf˜"6◊∆W3¬˜7G&ˆÊs„«7‚ñC“&ÜV«FÑÊWGv˜&¥ñÁFW&f6R#‰ÊWGv˜&≤7FófóGívñ∆¬V"gFW"6ˆ∆∆V7Fñˆ‚„¬˜7„„∆Fób6∆73“'cC3÷÷WFW"#„∆íñC“&ÜV«FÑÊWGv˜&¥&"#„¬ˆì„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#ÂFV◊W&GW&Rf◊≤WFñ÷S¬ˆÉ#„¬ˆFóc„∆Fób6∆73“'cC3◊FV◊◊WFñ÷R#„∆Fóc„«7G&ˆÊrñC“&ÜV«FÖFV◊#Ó(	C¬˜7G&ˆÊs„«7„Â7ó7FV“FV◊W&GW&S¬˜7„„¬ˆFóc„∆Fóc„«7G&ˆÊrñC“&ÜV«FÖWFñ÷R#Ó(	C¬˜7G&ˆÊs„«7„Â7ó7FV“WFñ÷S¬˜7„„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£∆Fób6∆73“'cC3÷ÜV«FÇ÷˜W&FñˆÊ¬÷w&ñB#‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰&6∑Wf◊≤&W7F˜&R7FGW3¬ˆÉ#„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑGfÊ6VBríÊ˜V„◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv&6∑W&˜w2ríÁ67&ˆ∆ƒñÁFıfñWrÇí#ÂfñWr∆√¬ˆ'WGFˆ„„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷f7G2#„∆Fóc‰∆7B&6∑W∆"ñC“&ÜV«FÑ∆7D&6∑W#‰ÊÚ&6∑W2ñWC¬ˆ#„¬ˆFóc„∆FócÂ7F˜&VB6˜ñW2∆"ñC“&ÜV«FÑ&6∑W6˜VÁB#„¬ˆ#„¬ˆFóc„∆Fóc‰ÊWáB66ÜVGV∆VB&6∑W∆"ñC“&ÜV«FÑÊWáD&6∑W#Â6VR∆ñÊ6R6WGFñÊw3¬ˆ#„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#Â&WFVÁFñˆ‚f◊≤6∆VÁW¬ˆÉ#„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑGfÊ6VBríÊ˜V„◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&WEG&ffñ2ríÁ67&ˆ∆ƒñÁFıfñWrÇí#ÂfñWr∆√¬ˆ'WGFˆ„„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷f7G2#„∆FócÂG&ffñ2&WFVÁFñˆ‚∆"ñC“&ÜV«FÖG&ffñ5&WFVÁFñˆ‚#Ó(	C¬ˆ#„¬ˆFóc„∆Fóc‰WfVÁB&WFVÁFñˆ‚∆"ñC“&ÜV«FÑWfVÁE&WFVÁFñˆ‚#Ó(	C¬ˆ#„¬ˆFóc„∆Fóc‰&6∑W&WFVÁFñˆ‚∆"ñC“&ÜV«FÑ&6∑W&WFVÁFñˆ‚#Ó(	C¬ˆ#„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#Â7ó7FV“WFFW3¬ˆÉ#„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑGfÊ6VBríÊ˜V„◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwWFFTfñ∆RríÁ67&ˆ∆ƒñÁFıfñWrÇí#ÂfñWr∆√¬ˆ'WGFˆ„„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷f7G2#„∆Fóc‰7W'&VÁBfW'6ñˆ‚∆#ÁeıÙıdU%4îÙÂıÛ¬ˆ#„¬ˆFóc„∆FócÂWFFR6ÜÊÊV¬∆"ñC“&ÜV«FÖWFFT6ÜÊÊV¬#Â7F&∆S¬ˆ#„¬ˆFóc„∆FócÂ7FGW2∆"ñC“&ÜV«FÖWFFU7FGW2#‰ÊÚWFFR7FvVC¬ˆ#„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£∆Fób6∆73“'cC3÷ÜV«FÇ÷˜W&FñˆÊ¬÷w&ñB#‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#Â6W'fñ6R7FGW3¬ˆÉ#„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑGfÊ6VBríÊ˜V„◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑ6ÜV6∑2ríÁ67&ˆ∆ƒñÁFıfñWrÇí#ÂfñWr∆√¬ˆ'WGFˆ„„¬ˆFóc„∆FóbñC“&ÜV«FÖ6W'fñ6U7V÷÷'í"6∆73“'cC3÷ÜV«FÇ÷f7G2#„∆Fóc‰∆ˆFñÊrÜV«FÇ6ÜV6∑>(
c¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#Â&V6VÁB7ó7FV“WfVÁG3¬ˆÉ#„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&˜V‰6&EvRÇv7FófóGírí#ÂfñWr∆√¬ˆ'WGFˆ„„¬ˆFóc„∆FóbñC“&ÜV«FÑWfVÁE7V÷÷'í"6∆73“'cC3÷ÜV«FÇ÷f7G2#„∆Fóc‰ÊÚ&V6VÁB7ó7FV“WfVÁG2„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#ÂVñ6≤7FñˆÁ3¬ˆÉ#„¬ˆFóc„∆Fób6∆73“'cC3÷ÜV«FÇ÷7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&∆ˆDÜV«FÇÇí#Â'V‚ÜV«FÇ6ÜV6≥¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&7&VFT&6∑WÇí#‰7&VFR&6∑W¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑGfÊ6VBríÊ˜V„◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑ6ÜV6∑2ríÁ67&ˆ∆ƒñÁFıfñWrÇí#ÂfñWr∆ˆw3¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑGfÊ6VBríÊ˜V„◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwWFFTfñ∆RríÁ67&ˆ∆ƒñÁFıfñWrÇí#‰6ÜV6≤f˜"WFFW3¬ˆ'WGFˆ„„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£∆FWFñ«2ñC“&ÜV«FÑGfÊ6VB"6∆73“'cC3÷ÜV«FÇ÷GfÊ6VB#„«7V÷÷'ì‰GfÊ6VB∆ñÊ6R6WGFñÊw2ÊBFñvÊ˜7Fñ73¬˜7V÷÷'ì‡£∆Fób6∆73“'cC3÷ÜV«FÇ◊6V6ˆÊF'í#‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#Â6V∆bFñvÊ˜7Fñ73¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰5R¬FV◊W&GW&R¬÷V÷˜'í¬Fó6≤¬FF&6RÊB6W'fñ6W3¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÛ∂÷Ç÷ÜVñváC£##Ç#„«F&∆S„«FÜVC„«G#„«FÉ‰6ÜV6≥¬˜FÉ„«FÉÂ7FGW3¬˜FÉ„«FÉ‰FWFñ√¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“&ÜV«FÑ6ÜV6∑2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰VÊ7'óFVB6V7&WG2b&ˆ÷WFÜWW3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰ñÁFVw&Fñˆ‚7&VFVÁFñ«2&RVÊ7'óFVBB&W7BvóFÇFÜR∆ñÊ6R∂Wì¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“'FFñÊs£gÇ#„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'&˜FFT÷WG&ñ74∂WíÇí#‰vVÊW&FRÚ&˜FFR÷WG&ñ72í∂Wì¬ˆ'WGFˆ„„«&RñC“&÷WG&ñ74∂Wî˜WB"7Gñ∆S“'vÜóFR◊76Sß&R◊w&∂÷&vñ‚◊F˜£'Ç#„¬˜&S„∆Fób6∆73“&◊WFVBÜVFW"÷ÜV«÷WáG&#Â&ˆ÷WFÜWW26‚WFÜVÁFñ6FRvóFÇWFÜ˜&ó¶Fñˆ„¢&V&W"f«C∂∂WífwC≤˜"Ç‘í‘∂Wí‚'&˜w6W"6W76ñˆÁ26‚«6Ú˜V‚ˆ÷WG&ñ72„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#Â&WFVÁFñˆ‚ˆ∆ñ6ñW3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰Fó2FÚ&WFñ‚∆ˆ6¬˜W&FñˆÊ¬Üó7F˜'ì¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“'FFñÊs£gÇ"6∆73“&w&ñB#„∆∆&V√ÂG&ffñ2∆ñÁWBñC“'&WEG&ffñ2"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“##„¬ˆ∆&V√„∆∆&V√‰WfVÁG2∆ñÁWBñC“'&WDWfVÁG2"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“##„¬ˆ∆&V√„∆∆&V√‰VFóB∆ñÁWBñC“'&WDVFóB"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“##„¬ˆ∆&V√„∆∆&V√Â&W˜'G2∆ñÁWBñC“'&WE&W˜'G2"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“##„¬ˆ∆&V√„∆∆&V√Â7ñÊ2Üó7F˜'í∆ñÁWBñC“'&WE7ñÊ2"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“##„¬ˆ∆&V√„∆∆&V√‰Ê˜Fñfñ6FñˆÁ2∆ñÁWBñC“'&WDÊ˜Fñgí"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“##„¬ˆ∆&V√„∆Fóc„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'6fU&WFVÁFñˆ‚Çí#Â6fRb'VÊS¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰FF&6R&6∑W3¬ˆÉ#„∆Fób6∆73“&◊WFVB#Â5∆óFRˆÊ∆ñÊR&6∑W2vóFÇñÁFVw&óGí6ÜV6∑2‚&W7F˜&RWFˆ÷Fñ6∆«í7&VFW2&R◊&W7F˜&R6fWGí&6∑W„¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÚ#„«F&∆S„«FÜVC„«G#„«FÉ‰7&VFVC¬˜FÉ„«FÉ‰fñ∆VÊ÷S¬˜FÉ„«FÉÂ6ó¶S¬˜FÉ„«FÉ‰Ê˜FS¬˜FÉ„«FÉ‰7Fñˆ„¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“&&6∑W&˜w2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#Â&ˆGV7Fñˆ‚∆ñÊ6R÷ÊvV÷VÁC¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰WFˆ÷Fñ2&6∑W2¬ÖEE2¬6ˆÊfñwW&Fñˆ‚˜'F&ñ∆óGíÊB6ˆÁG&ˆ∆∆VBWFFW3¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“'FFñÊs£gÇ"6∆73“&w&ñB#„∆∆&V√‰WFˆ÷Fñ2&6∑W«6V∆V7BñC“'&ˆDWFÙ&6∑W"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“##‰VÊ&∆VC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“##‰Fó6&∆VC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√„∆∆&V√‰&6∑WUD2Ü˜W"∆ñÁWBñC“'&ˆD&6∑WÜ˜W""6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“#"÷É“##2"f«VS“#2#„¬ˆ∆&V√„∆∆&V√‰&6∑W2FÚ∂VW∆ñÁWBñC“'&ˆD&6∑W∂VW"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“#"÷É“#"f«VS“#B#„¬ˆ∆&V√„∆∆&V√ÂWFFR6ÜÊÊV¬«6V∆V7BñC“'&ˆEWFFT6ÜÊÊV¬"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“'7F&∆R#Â7F&∆S¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&&WF#‰&WF¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√„∆Fóc„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'6fU&ˆGV7FñˆÂ6WGFñÊw2Çí#Â6fR∆ñÊ6R6WGFñÊw3¬ˆ'WGFˆ„‚∆6∆73“'6V6ˆÊF'í"á&Vc“"ˆí˜cˆ6ˆÊfñrˆWá˜'B"7Gñ∆S“'FWáB÷FV6˜&Fñˆ„¶ÊˆÊR#‰Wá˜'B6ˆÊfñs¬ˆ„¬ˆFóc„∆FóbñC“&áGG4˜WB"6∆73“&◊WFVBÜVFW"÷ÜV«÷WáG&#„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰6ˆÁG&ˆ∆∆VB6ˆgGv&RWFFS¬ˆÉ#„∆Fób6∆73“&◊WFVB#Â7FvRtÙE4UîR§ï¬fW&ñgí6∂vR7G'V7GW&RÊB4Ñ”#Sb¬FÜV‚Wá∆ñ6óF«í6ˆÊfó&“∆ñ6Fñˆ‚„¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“'FFñÊs£gÇ#„∆ñÁWBñC“'WFFTfñ∆R"GóS“&fñ∆R"66WC“"Á¶ó"6∆73“&ñÁWB#‚∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'7FvUWFFRÇí#Â7FvRb&Vf∆ñváC¬ˆ'WGFˆ„„«&RñC“'WFFT˜WB"6∆73“'&W7V«B#‰ÊÚWFFR7FvVB„¬˜&S„∆'WGFˆ‚6∆73“&FÊvW""ñC“&«ïWFFT'F‚"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&«ïWFFRÇí#‰«í7FvVBWFFS¬ˆ'WGFˆ„„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰ÖEE2ÚD≈3¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰ÊvñÁÇ&WfW'6R&˜áívóFÇ6V∆b◊6ñvÊVB6W'Fñfñ6FR˜"∆WBw2VÊ7'óB„¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“'FFñÊs£gÇ#„∆FóbñC“'F«57FGW2"6∆73“&◊WFVB#‰6ÜV6∂ñÊ~(
c¬ˆFóc„«&R6∆73“'&W7V«B#Â'V‚ˆ‚FÜR&7&W''íí2&ˆ˜C†ß7VFÚvˆG6WñR÷áGG2◊6WGWvˆG6WñRÊ∆ˆ6¬6V∆b◊6ñvÊV@†§˜"f˜"V&∆ñ2DÂ2Ê÷S†ß7VFÚvˆG6WñR÷áGG2◊6WGWvˆG6WñRÊWÜ◊∆RÊ6ˆ“∆WG6VÊ7'óC¬˜&S„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰Ê˜Fñfñ6Fñˆ‚FV∆ófW'íÜó7F˜'ì¬ˆÉ#„∆Fób6∆73“&◊WFVB#Â&WfñWrÊB&WG'í&ñ˜"FV∆ófW&ñW2„¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÚ#„«F&∆S„«FÜVC„«G#„«FÉÂFñ÷S¬˜FÉ„«FÉÂGóS¬˜FÉ„«FÉÂ6WfW&óGì¬˜FÉ„«FÉÂ7FGW3¬˜FÉ„«FÉ‰GFV◊G3¬˜FÉ„«FÉ‰7Fñˆ„¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“&Ê˜Fñfñ6Fñˆ‰Üó7F˜'ï&˜w2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc„¬˜6V7Fñˆ„‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰6ˆÁG&ˆ∆∆VB&V÷VFñFñˆ„¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰7FñˆÁ2&R&W7G&ñ7FVBFÚ6ˆÊfñwW&VBí÷Üˆ∆RıVÊîfíñÁFVw&FñˆÁ2ÊB&WVó&RWÜ7BF÷ñÊó7G&F˜"6ˆÊfó&÷Fñˆ‚„¬ˆFóc„¬ˆFóc„∆Fób7Gñ∆S“'FFñÊs£gÇ"6∆73“&w&ñB#„«6V∆V7BñC“'&V÷VFñFñˆ‰7Fñˆ‚"6∆73“&fñ«FW"#„∆˜Fñˆ‚f«VS“'ñÜˆ∆Uˆ&∆ˆ6µˆFˆ÷ñ‚#Âí÷Üˆ∆S¢&∆ˆ6≤Fˆ÷ñ„¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'VÊñfï˜V&ÁFñÊR#ÂVÊîfì¢V&ÁFñÊR6∆ñVÁC¬ˆ˜Fñˆ„„¬˜6V∆V7C„∆ñÁWBñC“'&V÷VFñFñˆÂF&vWB"6∆73“&ñÁWB"∆6VÜˆ∆FW#“&WÜ◊∆RÊ6ˆ“˜"§$#§43§DC§TS§db#„∆'WGFˆ‚6∆73“&FÊvW""ˆÊ6∆ñ6≥“''VÂ&V÷VFñFñˆ‚Çí#Â&WfñWrbWÜV7WFS¬ˆ'WGFˆ„„∆FóbñC“'&V÷VFñFñˆ‰˜WB"6∆73“&◊WFVB#„¬ˆFóc„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFWFñ«3‡£¬ˆFóc‡£∆Fób6∆73“'fñWr"ñC“'fñWr÷7FófóGí"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆É#Â&V6VÁB7FófóGì¬ˆÉ#„∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÚ#„«F&∆S„«FÜVC„«G#„«FÉÂFñ÷S¬˜FÉ„«FÉ‰WfVÁC¬˜FÉ„«FÉ‰FWfñ6S¬˜FÉ„«FÉ‰ï¬˜FÉ„«FÉ‰FWFñ«3¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“&WfVÁG2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr◊6V7W&óGí"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£«6V7Fñˆ‚6∆73“'ÊV¬#„∆É#ÂGvÚ‘f7F˜"WFÜVÁFñ6Fñˆ„¬ˆÉ#„∆FóbñC“&÷f7FGW2"7Gñ∆S“'FFñÊs£gÇáÇ#„¬ˆFóc„¬˜6V7Fñˆ„‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr◊'V∆W2"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£«6V7Fñˆ‚6∆73“'ÊV¬"ñC“''V∆W5ÊV¬#„∆É#‰∆W'B'V∆W3¬ˆÉ#‡£∆f˜&“6∆73“'W6W$f˜&“"ˆÁ7V&÷óC“'&WGW&‚7&VFU'V∆RÜWfVÁBí"7Gñ∆S“&f∆WÇ◊w&ßw&#‡£∆ñÁWB6∆73“&ñÁWB"ñC“''V∆TÊ÷R"∆6VÜˆ∆FW#“%'V∆RÊ÷R"&WVó&VB7Gñ∆S“&f∆WÉ£∂÷ñ‚◊vñGFÉ£cÇ#‡£«6V∆V7B6∆73“&fñ«FW""ñC“''V∆UGóR"ˆÊ6ÜÊvS“'WFFU'V∆TfñV∆G2Çí#„∆˜Fñˆ‚f«VS“&ÊWuˆFWfñ6Uˆ'W'7B#‰ÊWrFWfñ6R'W'7C¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ˆff∆ñÊUˆGW&Fñˆ‚#‰ˆff∆ñÊRGW&Fñˆ„¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&óˆ6ÜÊvUˆ'W'7B#‰ïFG&W726ÜÊvW3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'&V6ˆÊÊV7Eˆ'W'7B#‰FWfñ6R&V6ˆÊÊV7G3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ˆff∆ñÊUˆ6˜VÁB#‰ˆff∆ñÊRFWfñ6R6˜VÁC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'66ÊÊW%˜7F∆R#Â66ÊÊW"Ê˜B&W˜'FñÊs¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&6∆76ñfñ6FñˆÂˆ6˜VÁB#‰6∆76ñfñ6Fñˆ‚6˜VÁC¬ˆ˜Fñˆ„„¬˜6V∆V7C‡£«7‚ñC“''V∆TfñV∆G4'W'7B"7Gñ∆S“&Fó7∆ì¶f∆WÉ∂v£gÉ∂∆ñv‚÷óFV◊3¶6VÁFW"#„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆T'W'7D6˜VÁB"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#"7Gñ∆S“'vñGFÉ£ÉÇ"FóF∆S“$6˜VÁB#„«7‚6∆73“&◊WFVB#ÊÊWrFWfñ6W2ñ„¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆T'W'7EvñÊF˜r"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#R"7Gñ∆S“'vñGFÉ£ÉÇ"FóF∆S“%vñÊF˜rÜ÷ñÁWFW2í#„«7‚6∆73“&◊WFVB#Ê÷ñ„¬˜7„„¬˜7„‡£«7‚ñC“''V∆TfñV∆G4ˆff∆ñÊR"7Gñ∆S“&Fó7∆ì¶ÊˆÊS∂v£gÉ∂∆ñv‚÷óFV◊3¶6VÁFW"#„«7‚6∆73“&◊WFVB#Êˆff∆ñÊS¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆Tˆff∆ñÊT÷ñÁWFW2"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#3"7Gñ∆S“'vñGFÉ£ÉÇ"FóF∆S“$÷ñÁWFW2#„«7‚6∆73“&◊WFVB#Ê÷ñ‚¬6∆76W3£¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆Tˆff∆ñÊT6∆76W2"∆6VÜˆ∆FW#“&∂Ê˜v‚∆÷ÊvVB∆ñÁfW7FñvFRÜ&∆Ê≥÷Áíí"7Gñ∆S“'vñGFÉ£ìÇ#„¬˜7„‡£«7‚ñC“''V∆TfñV∆G4WfVÁD'W'7B"7Gñ∆S“&Fó7∆ì¶ÊˆÊS∂v£gÉ∂∆ñv‚÷óFV◊3¶6VÁFW"#„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆TWfVÁD6˜VÁB"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#2"7Gñ∆S“'vñGFÉ£ÉÇ#„«7‚6∆73“&◊WFVB#ÊWfVÁG2ñ„¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆TWfVÁEvñÊF˜r"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#"7Gñ∆S“'vñGFÉ£ÉÇ#„«7‚6∆73“&◊WFVB#Ê÷ñ„¬˜7„„¬˜7„‡£«7‚ñC“''V∆TfñV∆G4ˆff∆ñÊT6˜VÁB"7Gñ∆S“&Fó7∆ì¶ÊˆÊS∂v£gÉ∂∆ñv‚÷óFV◊3¶6VÁFW"#„«7‚6∆73“&◊WFVB#ÊB∆V7C¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆Tˆff∆ñÊT6˜VÁB"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#R"7Gñ∆S“'vñGFÉ£ÉÇ#„«7‚6∆73“&◊WFVB#Êˆff∆ñÊRFWfñ6W2+r6ˆˆ∆F˜v„¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆Tˆff∆ñÊT6˜VÁD6ˆˆ∆F˜v‚"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#R"7Gñ∆S“'vñGFÉ£ÉÇ#„«7‚6∆73“&◊WFVB#Ê÷ñ„¬˜7„„¬˜7„‡£«7‚ñC“''V∆TfñV∆G566ÊÊW""7Gñ∆S“&Fó7∆ì¶ÊˆÊS∂v£gÉ∂∆ñv‚÷óFV◊3¶6VÁFW"#„«7‚6∆73“&◊WFVB#ÊÊÚ7V66W76gV¬66‚f˜#¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆U66ÊÊW$÷ñÁWFW2"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#"7Gñ∆S“'vñGFÉ£ÉÇ#„«7‚6∆73“&◊WFVB#Ê÷ñ„¬˜7„„¬˜7„‡£«7‚ñC“''V∆TfñV∆G46∆76ñfñ6Fñˆ‚"7Gñ∆S“&Fó7∆ì¶ÊˆÊS∂v£gÉ∂∆ñv‚÷óFV◊3¶6VÁFW"#„«7‚6∆73“&◊WFVB#ÊB∆V7C¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆T6∆746˜VÁB"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#"7Gñ∆S“'vñGFÉ£sÇ#„«7‚6∆73“&◊WFVB#ÊFWfñ6W2ñ‚6∆76W3¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆T6∆76W2"f«VS“&ÊWr∆ñÁfW7FñvFR"7Gñ∆S“'vñGFÉ£ÉÇ#„«7‚6∆73“&◊WFVB#Ê6ˆˆ∆F˜v„¬˜7„„∆ñÁWB6∆73“&ñÁWB"ñC“''V∆T6∆746ˆˆ∆F˜v‚"GóS“&ÁV÷&W""÷ñ„“#"f«VS“#R"7Gñ∆S“'vñGFÉ£sÇ#„«7‚6∆73“&◊WFVB#Ê÷ñ„¬˜7„„¬˜7„‡£«6V∆V7B6∆73“&fñ«FW""ñC“''V∆U6WfW&óGí#„∆˜Fñˆ‚f«VS“&7&óFñ6¬#‰7&óFñ6√¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'v&ÊñÊr#Âv&ÊñÊs¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñÊfÚ#‰ñÊfÛ¬ˆ˜Fñˆ„„¬˜6V∆V7C‡£∆'WGFˆ‚6∆73“'&ñ÷'í"GóS“'7V&÷óB#‰FB'V∆S¬ˆ'WGFˆ„‡£¬ˆf˜&”‡£∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÚ#„«F&∆S„«FÜVC„«G#„«FÉ‰Ê÷S¬˜FÉ„«FÉÂGóS¬˜FÉ„«FÉ‰6ˆÊFóFñˆ„¬˜FÉ„«FÉÂ6WfW&óGì¬˜FÉ„«FÉ‰∆7BG&ñvvW&VC¬˜FÉ„«FÉ‰VÊ&∆VC¬˜FÉ„«FÉ„¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“''V∆W2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc‡£¬˜6V7Fñˆ„‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr◊W6W'2"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£«6V7Fñˆ‚6∆73“'ÊV¬"ñC“'W6W'5ÊV¬#„∆É#ÂW6W'3¬ˆÉ#‡£∆f˜&“6∆73“'W6W$f˜&“"ˆÁ7V&÷óC“'&WGW&‚7&VFUW6W"ÜWfVÁBí#„∆ñÁWB6∆73“&ñÁWB"ñC“&ÊWuW6W$Fó7∆îÊ÷R"∆6VÜˆ∆FW#“$Fó7∆íÊ÷R#„∆ñÁWB6∆73“&ñÁWB"ñC“&ÊWuW6W&Ê÷R"∆6VÜˆ∆FW#“%W6W&Ê÷R"&WVó&VC„∆ñÁWB6∆73“&ñÁWB"ñC“&ÊWuW6W%77v˜&B"GóS“'77v˜&B"∆6VÜˆ∆FW#“%77v˜&BÜ÷ñ‚ıÙ‘îÂı55tı$EÙƒT‰uDÖıÚ6Ü'2í"&WVó&VB÷ñÊ∆VÊwFÉ“%ıÙ‘îÂı55tı$EÙƒT‰uDÖıÚ#„«6V∆V7B6∆73“&fñ«FW""ñC“&ÊWuW6W%&ˆ∆R#„∆˜Fñˆ‚f«VS“'&VFˆÊ«í#Â&VB÷ˆÊ«ì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&VFóF˜"#‰VFóF˜#¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&˜W&F˜"#‰˜W&F˜#¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&F÷ñ‚#‰F÷ñ„¬ˆ˜Fñˆ„„¬˜6V∆V7C„∆'WGFˆ‚6∆73“'&ñ÷'í"GóS“'7V&÷óB#‰FBW6W#¬ˆ'WGFˆ„„¬ˆf˜&”‡£∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÚ#„«F&∆S„«FÜVC„«G#„«FÉ‰Ê÷S¬˜FÉ„«FÉÂW6W&Ê÷S¬˜FÉ„«FÉÂ&ˆ∆S¬˜FÉ„«FÉ‰7&VFVC¬˜FÉ„«FÉ‰∆7B∆ˆvñ„¬˜FÉ„«FÉÂ77v˜&B6ÜÊvVC¬˜FÉ„«FÉ‰◊W7B6ÜÊvRs¬˜FÉ„«FÉ‰‘d¬˜FÉ„«FÉ„¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“'W6W'2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc‡£¬˜6V7Fñˆ„‡£¬ˆFóc‡†£∆Fób6∆73“'fñWr"ñC“'fñWr÷VFóB"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡£«6V7Fñˆ‚6∆73“'ÊV¬"ñC“&VFóEÊV¬#„∆Fób6∆73“'F&∆R÷ÜVB#„∆É#‰VFóB∆ˆs¬ˆÉ#„∆Fób7Gñ∆S“&Fó7∆ì¶f∆WÉ∂∆ñv‚÷óFV◊3¶6VÁFW#∂v£Ç#„∆Fób6∆73“&◊WFVB#Â6V7W&óGíÊBF÷ñÊó7G&FófRÜó7F˜'ì¬ˆFóc„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FÊvW"F÷ñ‚÷ˆÊ«í"ñC“&6∆V$VFóD'F‚"ˆÊ6∆ñ6≥“&˜V‰6∆V$FFÇvVFóBrí#‰6∆V"VFóB∆ˆs¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡£∆Fób7Gñ∆S“&˜fW&f∆˜s¶WFÚ#„«F&∆S„«FÜVC„«G#„«FÉÂFñ÷S¬˜FÉ„«FÉ‰7F˜#¬˜FÉ„«FÉ‰7Fñˆ„¬˜FÉ„«FÉÂF&vWC¬˜FÉ„«FÉ‰FWFñ«3¬˜FÉ„«FÉ‰ï¬˜FÉ„¬˜G#„¬˜FÜVC„«F&ˆGíñC“&VFóE&˜w2#„¬˜F&ˆGì„¬˜F&∆S„¬ˆFóc‡£¬˜6V7Fñˆ„‡£¬ˆFóc‡†£¬ˆFóc„¬ˆ÷ñ„‡£¬ˆFóc‡£¬ˆFóc‡£∆FóbñC“'cC36&Dfˆ7W2"6∆73“'cC3÷fˆ7W2÷˜fW&∆í"ÜñFFV‚&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR"&ñ÷∆&V∆∆VF'ì“'cC3fˆ7W5FóF∆R#‡¢∆Fób6∆73“'cC3÷fˆ7W2÷6ˆÁFVÁB#„∆ÜVFW#„∆Fóc„«6÷∆¬ñC“'cC3fˆ7W56˜W&6R#‰tÙE4UîS¬˜6÷∆√„∆ÉñC“'cC3fˆ7W5FóF∆R#‰FWFñ«3¬ˆÉ„¬ˆFóc„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6T6&Dfˆ7W2Çí#Ó(i&6≤FÚvS¬ˆ'WGFˆ„„¬ˆÜVFW#„∆FóbñC“'cC3fˆ7W4&ˆGí"6∆73“'cC3÷fˆ7W2÷&ˆGí#„¬ˆFóc„¬ˆFóc‡£¬ˆFóc‡£∆FóbñC“&FWfñ6T6∆VÁW÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TFWfñ6T6∆VÁWÇí#‡¢∆Fób6∆73“&÷ˆF¬÷6&B#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#‰6∆V‚WFWfñ6W3¬ˆÉ#„∆Fób6∆73“&◊WFVB#Â&V÷˜fR7F∆RñÁfVÁF˜'íVÁG&ñW2‚VFóBÜó7F˜'íó2&W6W'fVB„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TFWfñ6T6∆VÁWÇí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“ˆÁ7V&÷óC“'&WGW&‚7V&÷óDFWfñ6T6∆VÁWÜWfVÁBí"6∆73“&÷ˆF¬÷f˜&“#‡¢∆∆&V√‰6∆VÁW÷ˆFS«6V∆V7B6∆73“&fñ«FW""ñC“&FWfñ6T6∆VÁW÷ˆFR"ˆÊ6ÜÊvS“'WFFTFWfñ6T6∆VÁWfñV∆G2Çí#„∆˜Fñˆ‚f«VS“&ˆff∆ñÊR#‰FV∆WFR∆¬ˆff∆ñÊRFWfñ6W3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ˆ∆B#‰FV∆WFRˆ∆BFWfñ6W3¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V¬ñC“&FWfñ6T6∆VÁWFó4∆&V¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‰ˆ∆FW"FÜ„∆ñÁWB6∆73“&ñÁWB"ñC“&FWfñ6T6∆VÁWFó2"GóS“&ÁV÷&W""÷ñ„“#"÷É“#3cS"f«VS“#3#„«7‚6∆73“&◊WFVB#ÊFó26ñÊ6R∆7B6VV‚‚ˆ∆B÷FWfñ6R6∆VÁW6‚&V÷˜fRÁíFWfñ6Rˆ∆FW"FÜ‚FÜó27WFˆfb¬ñÊ6«VFñÊrˆÊ∆ñÊR¬∂Ê˜v‚¬˜"÷ÊvVBFWfñ6W2„¬˜7„„¬ˆ∆&V√‡¢∆∆&V√Â&V6ˆ‚f˜"FV∆WFñˆ„«FWáF&V6∆73“&ñÁWB"ñC“&FWfñ6T6∆VÁW&V6ˆ‚"&˜w3“#2"÷Ü∆VÊwFÉ“#S"&WVó&VB∆6VÜˆ∆FW#“$WÜ◊∆S¢&WFó&ñÊr7F∆RñÁfVÁF˜'ígFW"ÊWGv˜&≤&W∆6V÷VÁB#„¬˜FWáF&V„¬ˆ∆&V√‡¢∆Fób6∆73“&◊WFVB#‰ÊÚ6fWGíWÜ6«W6ñˆÁ2&R∆ñVB‚÷F6ÜñÊrFWfñ6W2ÊBFÜVó"FWfñ6R÷˜vÊVBWfVÁB˜6˜W&6RÙïÜó7F˜'í&R&V÷˜fVB‚FÜR&V6ˆ‚¬7F˜"¬÷ˆFR¬ÊBFV∆WFVB6˜VÁB&R&W6W'fVBñ‚FÜRVFóB∆ˆr„¬ˆFóc‡¢∆Fób6∆73“&W'""ñC“&FWfñ6T6∆VÁWW'"#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TFWfñ6T6∆VÁWÇí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“&FÊvW"#‰FV∆WFR÷F6ÜñÊrFWfñ6W3¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡£∆FóbñC“&FWfñ6TFV∆WFT÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TFV∆WFTFWfñ6RÇí#‡¢∆Fób6∆73“&÷ˆF¬÷6&B#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#‰FV∆WFRFWfñ6S¬ˆÉ#„∆Fób6∆73“&◊WFVB"ñC“&FWfñ6TFV∆WFTñFVÁFóGí#Â&V÷˜fRFÜó2FWfñ6Rg&ˆ“ñÁfVÁF˜'í„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TFV∆WFTFWfñ6RÇí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“ˆÁ7V&÷óC“'&WGW&‚7V&÷óDFV∆WFTFWfñ6RÜWfVÁBí"6∆73“&÷ˆF¬÷f˜&“#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&FWfñ6TFV∆WFTñB#‡¢∆∆&V√Â&V6ˆ‚f˜"FV∆WFñˆ„«FWáF&V6∆73“&ñÁWB"ñC“&FWfñ6TFV∆WFU&V6ˆ‚"&˜w3“#2"÷Ü∆VÊwFÉ“#S"&WVó&VB∆6VÜˆ∆FW#“$WÜ◊∆S¢FWfñ6R&WFó&VBÊB&V÷˜fVBg&ˆ“FÜRÊWGv˜&≤#„¬˜FWáF&V„¬ˆ∆&V√‡¢∆Fób6∆73“&◊WFVB#‰FV∆WFñˆ‚ó2∆∆˜vVB&Vv&F∆W72ˆbFWfñ6R7FGW2˜"6∆76ñfñ6Fñˆ‚‚FÜR&V6ˆ‚ÊBFWfñ6RFWFñ«2&Rw&óGFV‚FÚFÜRVFóB∆ˆr„¬ˆFóc‡¢∆Fób6∆73“&W'""ñC“&FWfñ6TFV∆WFTW'"#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TFV∆WFTFWfñ6RÇí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“&FÊvW"#‰FV∆WFRFWfñ6S¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡£∆FóbñC“&FWfñ6T÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TFDFWfñ6RÇí#‡¢∆Fób6∆73“&÷ˆF¬÷6&B#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#‰FBFWfñ6S¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰FB∂Ê˜v‚FWfñ6R÷ÁV∆«í¬˜"W6RFó66˜fW"ÊWGv˜&≤f˜"WFˆ÷Fñ2Fó66˜fW'í„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TFDFWfñ6RÇí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“ˆÁ7V&÷óC“'&WGW&‚7V&÷óDFDFWfñ6RÜWfVÁBí"6∆73“&÷ˆF¬÷f˜&“#‡¢∆∆&V√‰Ê÷S∆ñÁWB6∆73“&ñÁWB"ñC“&FWfñ6TÊ÷R"&WVó&VB∆6VÜˆ∆FW#“$∆ófñÊr&ˆˆ“Eb#„¬ˆ∆&V√‡¢∆∆&V√‰ïFG&W73∆ñÁWB6∆73“&ñÁWB"ñC“&FWfñ6Tó"∆6VÜˆ∆FW#“#ì"„cÇ„„S#„¬ˆ∆&V√‡¢∆∆&V√‰‘2FG&W73∆ñÁWB6∆73“&ñÁWB"ñC“&FWfñ6T÷2"&WVó&VB∆6VÜˆ∆FW#“$§$#§43§DC§TS§db#„¬ˆ∆&V√‡¢∆∆&V√ÂfVÊF˜#∆ñÁWB6∆73“&ñÁWB"ñC“&FWfñ6UfVÊF˜""∆6VÜˆ∆FW#“%6◊7VÊr#„¬ˆ∆&V√‡¢∆∆&V√ÂGóS∆ñÁWB6∆73“&ñÁWB"ñC“&FWfñ6UGóR"∆6VÜˆ∆FW#“%Eb¬&˜WFW"¬6ˆ◊WFW.(
b#„¬ˆ∆&V√‡¢∆∆&V√‰6∆76ñfñ6Fñˆ„«6V∆V7B6∆73“&fñ«FW""ñC“&FWfñ6T6∆72#„∆˜Fñˆ‚f«VS“&∂Ê˜v‚#‰∂Ê˜v„¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&÷ÊvVB#‰÷ÊvVC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ÊWr#‰ÊWs¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñÁfW7FñvFR#‰ñÁfW7FñvFS¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñvÊ˜&VB#‰ñvÊ˜&VC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√‰Ê˜FW3«FWáF&V6∆73“&ñÁWB"ñC“&FWfñ6TÊ˜FW2"&˜w3“#2"∆6VÜˆ∆FW#“$˜FñˆÊ¬Ê˜FW2#„¬˜FWáF&V„¬ˆ∆&V√‡¢∆Fób6∆73“&W'""ñC“&FWfñ6TFDW'"#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TFDFWfñ6RÇí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“'&ñ÷'í#‰FBFWfñ6S¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡£∆FóbñC“'&VÊ÷TFWfñ6T÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡¢∆Fób6∆73“&÷ˆF¬÷6&B"7Gñ∆S“&÷Ç◊vñGFÉ£SÇ#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#‰Ê÷RFWfñ6S¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰vófRFó66˜fW&VBFWfñ6W2g&ñVÊF«íÊ÷R¬˜"&VÊ÷R∂Ê˜v‚FWfñ6RBÁíFñ÷R„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6U&VÊ÷TFWfñ6RÇí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“ˆÁ7V&÷óC“'&WGW&‚7V&÷óE&VÊ÷TFWfñ6RÜWfVÁBí"6∆73“&÷ˆF¬÷f˜&“#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“'&VÊ÷TFWfñ6TñB#‡¢∆∆&V√‰FWfñ6RÊ÷S∆ñÁWB6∆73“&ñÁWB"ñC“'&VÊ÷TFWfñ6TÊ÷R"&WVó&VB÷Ü∆VÊwFÉ“##"∆6VÜˆ∆FW#“$∆ófñÊr&ˆˆ“Eb#„¬ˆ∆&V√‡¢∆Fób6∆73“&◊WFVB"ñC“'&VÊ÷TFWfñ6TñFVÁFóGí#„¬ˆFóc‡¢∆Fób6∆73“&W'""ñC“'&VÊ÷TFWfñ6TW'"#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6U&VÊ÷TFWfñ6RÇí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“'&ñ÷'í#Â6fRÊ÷S¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡£∆FóbñC“&6∆76ñgîFWfñ6T÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡¢∆Fób6∆73“&÷ˆF¬÷6&B"7Gñ∆S“&÷Ç◊vñGFÉ£S#Ç#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É#‰6∆76ñgíFWfñ6S¬ˆÉ#„∆Fób6∆73“&◊WFVB#Â6WBvÜBFÜRFWfñ6Ró2ÊBÜ˜rtÙE4UîR6Ü˜V∆B÷ÊvRóB„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6T6∆76ñgîFWfñ6RÇí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“ˆÁ7V&÷óC“'&WGW&‚7V&÷óD6∆76ñgîFWfñ6RÜWfVÁBí"6∆73“&÷ˆF¬÷f˜&“#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&6∆76ñgîFWfñ6TñB#‡¢∆∆&V√‰FWfñ6RGóS∆ñÁWB6∆73“&ñÁWB"ñC“&6∆76ñgîFWfñ6UGóR"÷Ü∆VÊwFÉ“#É"∆ó7C“&ñÁfVÁF˜'îFWfñ6UGóT6Üˆñ6W2"∆6VÜˆ∆FW#“%&˜WFW"¬2¬6÷W&¬7vóF6é(
b#„¬ˆ∆&V√‡¢∆FF∆ó7BñC“&ñÁfVÁF˜'îFWfñ6UGóT6Üˆñ6W2#„∆˜Fñˆ‚f«VS“%&˜WFW"#„∆˜Fñˆ‚f«VS“%2#„∆˜Fñˆ‚f«VS“$∆F˜#„∆˜Fñˆ‚f«VS“$6÷W&#„∆˜Fñˆ‚f«VS“%7vóF6Ç#„∆˜Fñˆ‚f«VS“$66W72ˆñÁB#„∆˜Fñˆ‚f«VS“%ÜˆÊR#„∆˜Fñˆ‚f«VS“%F&∆WB#„∆˜Fñˆ‚f«VS“%&ñÁFW"#„∆˜Fñˆ‚f«VS“%6W'fW"#„∆˜Fñˆ‚f«VS“$‰2#„∆˜Fñˆ‚f«VS“%EbÚ÷VFñ#„∆˜Fñˆ‚f«VS“$ñıB#„∆˜Fñˆ‚f«VS“%6÷'BÜˆ÷R#„∆˜Fñˆ‚f«VS“$v÷R6ˆÁ6ˆ∆R#„∆˜Fñˆ‚f«VS“$˜FÜW"#„¬ˆFF∆ó7C‡¢∆∆&V√‰6∆76ñfñ6Fñˆ„«6V∆V7B6∆73“&fñ«FW""ñC“&6∆76ñgîFWfñ6T6∆72#„∆˜Fñˆ‚f«VS“&ÊWr#‰ÊWs¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñÁfW7FñvFR#‰ñÁfW7FñvFS¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&∂Ê˜v‚#‰∂Ê˜v„¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&÷ÊvVB#‰÷ÊvVC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&ñvÊ˜&VB#‰ñvÊ˜&VC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆Fób6∆73“&◊WFVB"ñC“&6∆76ñgîFWfñ6TñFVÁFóGí#„¬ˆFóc‡¢∆Fób6∆73“&W'""ñC“&6∆76ñgîFWfñ6TW'"#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6T6∆76ñgîFWfñ6RÇí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“'&ñ÷'í#Â6fR6∆76ñfñ6Fñˆ„¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡£∆FóbñC“&FWfñ6Tñ6ˆ‰÷ˆF¬"6∆73“&÷ˆF¬FWfñ6R÷ñ6ˆ‚÷÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TFWfñ6Tñ6ˆ‚Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&BFWfñ6R÷ñ6ˆ‚÷Fñ∆ˆr"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR"&ñ÷∆&V∆∆VF'ì“&FWfñ6Tñ6ˆÂFóF∆R#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&FWfñ6Tñ6ˆÂFóF∆R#Â6V∆V7BFWfñ6Rñ6ˆ„¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰6Üˆ˜6R&V∆ó7Fñ2FWfñ6Rñ7GW&R˜"W∆ˆBñ˜W"˜v‚„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"&ñ÷∆&V√“$6∆˜6Rñ6ˆ‚ñ6∂W""ˆÊ6∆ñ6≥“&6∆˜6TFWfñ6Tñ6ˆ‚Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“ˆÁ7V&÷óC“'&WGW&‚7V&÷óDFWfñ6Tñ6ˆ‚ÜWfVÁBí"6∆73“&÷ˆF¬÷f˜&“#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&FWfñ6Tñ6ˆ‰ñB#„∆ñÁWBGóS“&ÜñFFV‚"ñC“&FWfñ6Tñ6ˆ‰∂Wí"f«VS“&WFÚ#„∆ñÁWBGóS“&ÜñFFV‚"ñC“&FWfñ6Tñ6ˆ‰FF#‡¢∆Fób6∆73“&FWfñ6R÷ñ6ˆ‚◊7V÷÷'í#„∆Fób6∆73“&FWfñ6R÷ñ6ˆ‚◊7V÷÷'í÷'B#„∆ñ÷rñC“&FWfñ6Tñ6ˆ‰7W'&VÁE&WfñWr"7&3“"ˆ76WG2ˆFWfñ6R÷ñ6ˆÁ2ˆ˜FÜW"Á7fs˜c”#r"«C“%6V∆V7FVBFWfñ6Rñ6ˆ‚#„¬ˆFóc„∆Fóc„∆Fób6∆73“&FWfñ6R÷ñ6ˆ‚◊7V÷÷'í÷Ê÷R"ñC“&FWfñ6Tñ6ˆ‰Ê÷R#‰FWfñ6S¬ˆFóc„∆Fób6∆73“&FWfñ6R÷ñ6ˆ‚◊7V÷÷'í÷÷WF"ñC“&FWfñ6Tñ6ˆ‰ñFVÁFóGí#„¬ˆFóc„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&FWfñ6R÷ñ6ˆ‚◊F'2"ñC“&FWfñ6Tñ6ˆÂF'2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FWfñ6R÷ñ6ˆ‚◊F"7FófR"FF÷ñ6ˆ‚÷6FVv˜'ì“&∆¬"ˆÊ6∆ñ6≥“'6WDFWfñ6Tñ6ˆ‰6FVv˜'íÇv∆¬rí#‰∆¬ñ6ˆÁ3¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FWfñ6R÷ñ6ˆ‚◊F""FF÷ñ6ˆ‚÷6FVv˜'ì“&ÊWGv˜&≤"ˆÊ6∆ñ6≥“'6WDFWfñ6Tñ6ˆ‰6FVv˜'íÇvÊWGv˜&≤rí#‰ÊWGv˜&≤FWfñ6W3¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FWfñ6R÷ñ6ˆ‚◊F""FF÷ñ6ˆ‚÷6FVv˜'ì“&6ˆ◊WFW'2"ˆÊ6∆ñ6≥“'6WDFWfñ6Tñ6ˆ‰6FVv˜'íÇv6ˆ◊WFW'2rí#‰6ˆ◊WFW'2f◊≤÷ˆ&ñ∆S¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FWfñ6R÷ñ6ˆ‚◊F""FF÷ñ6ˆ‚÷6FVv˜'ì“'6V7W&óGí"ˆÊ6∆ñ6≥“'6WDFWfñ6Tñ6ˆ‰6FVv˜'íÇw6V7W&óGírí#Â6V7W&óGì¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FWfñ6R÷ñ6ˆ‚◊F""FF÷ñ6ˆ‚÷6FVv˜'ì“&Üˆ÷R"ˆÊ6∆ñ6≥“'6WDFWfñ6Tñ6ˆ‰6FVv˜'íÇvÜˆ÷Rrí#‰Üˆ÷Rf◊≤ñıC¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FWfñ6R÷ñ6ˆ‚◊F""FF÷ñ6ˆ‚÷6FVv˜'ì“&˜FÜW""ˆÊ6∆ñ6≥“'6WDFWfñ6Tñ6ˆ‰6FVv˜'íÇv˜FÜW"rí#‰˜FÜW#¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“&FWfñ6R÷ñ6ˆ‚◊ñ6∂W""ñC“&FWfñ6Tñ6ˆÂñ6∂W"#„¬ˆFóc‡¢∆Fób6∆73“&FWfñ6R÷ñ6ˆ‚÷7W7Fˆ“#„∆"7Gñ∆S“&fˆÁB◊6ó¶S£'Ç#‰7W7Fˆ“ñ6ˆ„¬ˆ#„∆Fób6∆73“&◊WFVB"7Gñ∆S“&÷&vñ„£GÇóÇ#Â‰r¬•Tr¬˜"vV%‚÷Üñ◊V“#Sb¥"„¬ˆFóc„∆Fób6∆73“&ñ6ˆ‚◊W∆ˆB◊&˜r#„∆ñÁWBñC“&FWfñ6Tñ6ˆ‰fñ∆R"GóS“&fñ∆R"66WC“&ñ÷vR˜Êr∆ñ÷vRˆßVr∆ñ÷vR˜vV'"ˆÊ6ÜÊvS“'&WfñWt7W7Fˆ‘FWfñ6Tñ6ˆ‚áFÜó2í#„∆ñ÷rñC“&FWfñ6Tñ6ˆÂ&WfñWr"6∆73“&7W7Fˆ“÷ñ6ˆ‚◊&WfñWr"«C“$7W7Fˆ“ñ6ˆ‚&WfñWr"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#„¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&W'""ñC“&FWfñ6Tñ6ˆ‰W'"#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TFWfñ6Tñ6ˆ‚Çí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“'&ñ÷'í#Â6fRñ6ˆ„¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡£∆Fób6∆73“&÷ˆF¬"ñC“&ñÁFVw&Fñˆ‰÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TñÁFVw&Fñˆ‰÷ˆF¬Çí#„∆Fób6∆73“&÷ˆF¬÷6&B"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#„∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&ñÁFVw&Fñˆ‰÷ˆF≈FóF∆R#‰FBñÁFVw&Fñˆ„¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰V6Ç6fVB6ˆ∆∆V7F˜"'VÁ2ñÊFWVÊFVÁF«íÊB∂VW2óG2˜v‚7ñÊ2Üó7F˜'íÊBÊ«óFñ72„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TñÁFVw&Fñˆ‰÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc„∆f˜&“6∆73“&÷ˆF¬÷f˜&“"ˆÁ7V&÷óC“'&WGW&‚7V&÷óDñÁFVw&Fñˆ‚ÜWfVÁBí#„∆ñÁWBñC“&ñÁFVw&Fñˆ‰ñB"GóS“&ÜñFFV‚#„∆∆&V√‰Ê÷S∆ñÁWBñC“&ñÁFVw&Fñˆ‰Ê÷R"6∆73“&ñÁWB"&WVó&VB∆6VÜˆ∆FW#“$Üˆ÷Rí÷Üˆ∆R#„¬ˆ∆&V√„∆∆&V√ÂGóS«6V∆V7BñC“&ñÁFVw&Fñˆ‰∂ñÊB"6∆73“&fñ«FW""ˆÊ6ÜÊvS“'WFFTñÁFVw&Fñˆ‰fñV∆G2Çí#„∆˜Fñˆ‚f«VS“'ñÜˆ∆R#Âí÷Üˆ∆S¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'VÊñfí#ÂVÊîfì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'6Ê◊#Â4‰’¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√„∆∆&V¬7Gñ∆S“&w&ñB÷6ˆ«V÷„£Ú”#ÂF&vWC∆ñÁWBñC“&ñÁFVw&FñˆÂF&vWB"6∆73“&ñÁWB"&WVó&VB∆6VÜˆ∆FW#“&áGG3¢Ú˜íÊÜˆ∆R˜"ì"„cÇ„„#„¬ˆ∆&V√„∆Fób6∆73“&ñÁFVw&Fñˆ‚÷∂ñÊB÷fñV∆G2#„∆∆&V¬ñC“&ñÁFVw&FñˆÂW6W%w&#ÂW6W&Ê÷S∆ñÁWBñC“&ñÁFVw&FñˆÂW6W""6∆73“&ñÁWB"∆6VÜˆ∆FW#“$6ˆÁG&ˆ∆∆W"W6W&Ê÷R#„¬ˆ∆&V√„∆∆&V√‰7&VFVÁFñ√∆ñÁWBñC“&ñÁFVw&FñˆÂ6V7&WB"6∆73“&ñÁWB"GóS“'77v˜&B"∆6VÜˆ∆FW#“$&∆Ê≤∂VW26fVB7&VFVÁFñ¬#„¬ˆ∆&V√„∆∆&V¬ñC“&ñÁFVw&FñˆÂ6óFUw&#ÂVÊîfí6óFS∆ñÁWBñC“&ñÁFVw&FñˆÂ6óFR"6∆73“&ñÁWB"f«VS“&FVfV«B#„¬ˆ∆&V√„∆∆&V√Â7ñÊ2ñÁFW'f¬á6V6ˆÊG2ì∆ñÁWBñC“&ñÁFVw&Fñˆ‰ñÁFW'f¬"6∆73“&ñÁWB"GóS“&ÁV÷&W""÷ñ„“#3"f«VS“#3#„¬ˆ∆&V√„¬ˆFóc„∆∆&V¬7Gñ∆S“&f∆WÇ÷Fó&V7Fñˆ„ß&˜s∂∆ñv‚÷óFV◊3¶6VÁFW"#„∆ñÁWBñC“&ñÁFVw&Fñˆ‰VÊ&∆VB"GóS“&6ÜV6∂&˜Ç"6ÜV6∂VC‚VÊ&∆VC¬ˆ∆&V√„∆∆&V¬7Gñ∆S“&f∆WÇ÷Fó&V7Fñˆ„ß&˜s∂∆ñv‚÷óFV◊3¶6VÁFW"#„∆ñÁWBñC“&ñÁFVw&FñˆÂF«2"GóS“&6ÜV6∂&˜Ç"6ÜV6∂VC‚fW&ñgíD≈26W'Fñfñ6FS¬ˆ∆&V√„∆FóbñC“&ñÁFVw&Fñˆ‰W'""6∆73“&W'"#„¬ˆFóc„∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TñÁFVw&Fñˆ‰÷ˆF¬Çí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'í"GóS“'7V&÷óB#Â6fRñÁFVw&Fñˆ„¬ˆ'WGFˆ„„¬ˆFóc„¬ˆf˜&”„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“&÷ˆF¬"ñC“&FV∆WFTñÁFVw&Fñˆ‰÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TFV∆WFTñÁFVw&Fñˆ‰÷ˆF¬Çí#„∆Fób6∆73“&÷ˆF¬÷6&B"7Gñ∆S“&÷Ç◊vñGFÉ£S#Ç"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR"&ñ÷∆&V∆∆VF'ì“&FV∆WFTñÁFVw&FñˆÂFóF∆R#„∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&FV∆WFTñÁFVw&FñˆÂFóF∆R#Â&V÷˜fRñÁFVw&Fñˆ„¬ˆÉ#„∆Fób6∆73“&◊WFVB#Â&V÷˜fR‚ñÁFVw&Fñˆ‚FÜBó2&WFó&VB¬&W∆6VB¬˜"ÊÚ∆ˆÊvW"&V6Ü&∆R„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TFV∆WFTñÁFVw&Fñˆ‰÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc„∆FóbñC“&FV∆WFTñÁFVw&FñˆÂ7V÷÷'í"6∆73“'&V÷˜fR◊7V÷÷'í#„¬ˆFóc„∆Fób7Gñ∆S“'FFñÊs£GÇ#Ç#„∆∆&V¬6∆73“&◊WFVB"7Gñ∆S“&Fó7∆ì¶&∆ˆ6≥∂÷&vñ‚÷&˜GFˆ”£gÇ#ÂGóR$T‘ıdRFÚ6ˆÊfó&”¬ˆ∆&V√„∆ñÁWBñC“&FV∆WFTñÁFVw&Fñˆ‰6ˆÊfó&“"6∆73“&ñÁWB"7Gñ∆S“'vñGFÉ£S∂&˜Ç◊6ó¶ñÊs¶&˜&FW"÷&˜Ç"WFˆ6ˆ◊∆WFS“&ˆfb"∆6VÜˆ∆FW#“%$T‘ıdR#„∆FóbñC“&FV∆WFTñÁFVw&Fñˆ‰W'""6∆73“&W'""7Gñ∆S“&÷&vñ‚◊F˜£wÇ#„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2"7Gñ∆S“'FFñÊs£gÇ#Ç#Ç#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TFV∆WFTñÁFVw&Fñˆ‰÷ˆF¬Çí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&FÊvW""ñC“&FV∆WFTñÁFVw&Fñˆ‰'F‚"ˆÊ6∆ñ6≥“&6ˆÊfó&‘FV∆WFTñÁFVw&Fñˆ‚Çí#Â&V÷˜fRñÁFVw&Fñˆ„¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc„¬ˆFóc‡£∆Fób6∆73“&÷ˆF¬"ñC“&Ê«óFñ74÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6TÊ«óFñ74÷ˆF¬Çí#„∆Fób6∆73“&÷ˆF¬÷6&BÊ«óFñ72÷Fñ∆ˆr"7Gñ∆S“'vñGFÉ¶÷ñ‚ÉscÇ∆6∆2Égr“3gÇíí"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR#„∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&Ê«óFñ75FóF∆R#‰Ê«óFñ73¬ˆÉ#„∆Fób6∆73“&◊WFVB"ñC“&Ê«óFñ757V'FóF∆R#„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6TÊ«óFñ74÷ˆF¬Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc„∆Fób7Gñ∆S“'FFñÊs£áÇ#Ç#„∆FóbñC“&Ê«óFñ757V÷÷'í"6∆73“&Ê«óFñ72◊7V÷÷'í#„¬ˆFóc„«&RñC“&Ê«óFñ74FWFñ¬#„¬˜&S„∆Fób6∆73“&F÷ñ‚÷ˆÊ«í"7Gñ∆S“&&˜&FW"◊F˜£Ç6ˆ∆ñB6VFc&cs∑FFñÊr◊F˜£7É∂÷&vñ‚◊F˜£7Ç#„∆∆&V¬6∆73“&◊WFVB"7Gñ∆S“&Fó7∆ì¶&∆ˆ6≥∂÷&vñ‚÷&˜GFˆ”£gÇ#Â&V6ˆ‚&WVó&VBFÚ6∆V"FÜó2Ê«óFñ726Ê6Ü˜BÜó7F˜'ì¬ˆ∆&V√„«FWáF&VñC“&Ê«óFñ746∆V%&V6ˆ‚"6∆73“&ñÁWB"7Gñ∆S“'vñGFÉ£S∂÷ñ‚÷ÜVñváC£cgÉ∂&˜Ç◊6ó¶ñÊs¶&˜&FW"÷&˜Ç"∆6VÜˆ∆FW#“$WÜ◊∆S¢&WfñWvVBDÂ2VW'í7FFó7Fñ72ÊBWá˜'FVBFÜRfñÊFñÊw2‚#„¬˜FWáF&V„∆FóbñC“&Ê«óFñ746∆V$W'""6∆73“&W'"#„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚6∆73“&FÊvW"F÷ñ‚÷ˆÊ«í"ñC“&6∆V$ˆÊTÊ«óFñ74'F‚"ˆÊ6∆ñ6≥“&6∆V$7W'&VÁDÊ«óFñ72Çí#‰6∆V"FÜó2Ê«óFñ73¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TÊ«óFñ74÷ˆF¬Çí#‰FˆÊS¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc„¬ˆFóc„¬ˆFóc‡£∆FóbñC“&6∆V$FF÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR#‡¢∆Fób6∆73“&÷ˆF¬÷6&B"7Gñ∆S“&÷Ç◊vñGFÉ£SCÇ#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&6∆V$FFFóF∆R#‰6∆V"FF¬ˆÉ#„∆Fób6∆73“&◊WFVB"ñC“&6∆V$FFÜV«#‰&V6ˆ‚ó2&WVó&VBÊBvñ∆¬&Rw&óGFV‚FÚFÜRVFóB∆ˆr„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"ˆÊ6∆ñ6≥“&6∆˜6T6∆V$FFÇí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆f˜&“ˆÁ7V&÷óC“'&WGW&‚7V&÷óD6∆V$FFÜWfVÁBí"6∆73“&÷ˆF¬÷f˜&“#‡¢∆ñÁWBGóS“&ÜñFFV‚"ñC“&6∆V$FF∂ñÊB#‡¢∆∆&V√Â&V6ˆ„«FWáF&V6∆73“&ñÁWB"ñC“&6∆V$FF&V6ˆ‚"&˜w3“#B"&WVó&VB÷ñÊ∆VÊwFÉ“#R"÷Ü∆VÊwFÉ“#S"∆6VÜˆ∆FW#“$WÜ◊∆S¢&WfñWvVBñÊ6ñFVÁBfñÊFñÊw2ÊBÊÚ∆ˆÊvW"ÊVVBFÜR&WFñÊVBÊ«óFñ72Üó7F˜'í‚#„¬˜FWáF&V„¬ˆ∆&V√‡¢∆Fób6∆73“&◊WFVB"ñC“&6∆V$FFv&ÊñÊr#„¬ˆFóc‡¢∆Fób6∆73“&W'""ñC“&6∆V$FFW'"#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6T6∆V$FFÇí#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“'7V&÷óB"6∆73“&FÊvW""ñC“&6∆V$FF6ˆÊfó&“#‰6∆V"FF¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆf˜&”‡¢¬ˆFóc‡£¬ˆFóc‡£∆FóbñC“&÷ˆÊóF˜$÷ˆF¬"6∆73“&÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"ˆÊ6∆ñ6≥“&ñbÜWfVÁBÁF&vWC””◊FÜó2ñ6∆˜6T÷ˆÊóF˜$VFóF˜"Çí#‡¢∆Fób6∆73“&÷ˆF¬÷6&B"7Gñ∆S“&÷Ç◊vñGFÉ£ccÇ"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR"&ñ÷∆&V∆∆VF'ì“&÷ˆÊóF˜$÷ˆF≈FóF∆R#‡¢∆Fób6∆73“&÷ˆF¬÷ÜVB#„∆Fóc„∆É"ñC“&÷ˆÊóF˜$÷ˆF≈FóF∆R#‰FB÷ˆÊóF˜#¬ˆÉ#„∆Fób6∆73“&◊WFVB#‰7&VFRW'6ó7FVÁB&7&W''íí÷ÊFófRÜV«FÇ6ÜV6≤„¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&ñ6ˆ‚÷'F‚"&ñ÷∆&V√“$6∆˜6R÷ˆÊóF˜"VFóF˜""ˆÊ6∆ñ6≥“&6∆˜6T÷ˆÊóF˜$VFóF˜"Çí#Ï9s¬ˆ'WGFˆ„„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷f˜&“#‡¢∆Fób6∆73“&÷ˆF¬◊6V7Fñˆ‚◊FóF∆R#‰÷ˆÊóF˜"FWFñ«3¬ˆFóc‡¢∆∆&V√‰Ê÷S∆ñÁWB6∆73“&ñÁWB"ñC“&÷ˆ‰Ê÷R"∆6VÜˆ∆FW#“$vFWvíÜV«FÇ#„«7‚6∆73“&f˜&“÷ÜñÁB#‰6∆V"∆&V¬6Ü˜v‚ñ‚÷ˆÊóF˜&ñÊrÊBfñÊFñÊw2„¬˜7„„¬ˆ∆&V√‡¢∆∆&V√ÂGóS«6V∆V7B6∆73“&fñ«FW""ñC“&÷ˆ‰∂ñÊB#„∆˜Fñˆ‚f«VS“'vV'6óFR#ÂvV'6óFRÚÖEE¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“&FÜ7#‰DÑ5∆V6W3¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'V&∆ñ5ˆó#ÂV&∆ñ2ï¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'ñÜˆ∆R#Âí÷Üˆ∆S¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'VÊñfí#ÂVÊîfì¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“'6Ê◊#Â4‰’¬ˆ˜Fñˆ„„¬˜6V∆V7C„«7‚6∆73“&f˜&“÷ÜñÁB#‰6Üˆ˜6RvÜBtÙE4UîR6Ü˜V∆B6ÜV6≤„¬˜7„„¬ˆ∆&V√‡¢∆∆&V√ÂF&vWC∆ñÁWB6∆73“&ñÁWB"ñC“&÷ˆÂF&vWB"∆6VÜˆ∆FW#“&áGG3¢ÚˆWÜ◊∆RÊ6ˆ“˜"ì"„cÇ„„#„«7‚6∆73“&f˜&“÷ÜñÁB#ÂV&∆ñ2ï÷ˆÊóF˜'2FWFW&÷ñÊRFÜRF&vWBWFˆ÷Fñ6∆«í„¬˜7„„¬ˆ∆&V√‡¢∆∆&V√‰6ÜV6≤WfW'ì∆ñÁWB6∆73“&ñÁWB"ñC“&÷ˆ‰ñÁFW'f¬"GóS“&ÁV÷&W""÷ñ„“#3"f«VS“#3#„«7‚6∆73“&f˜&“÷ÜñÁB#‰ñÁFW'f¬ñ‚6V6ˆÊG2Ü÷ñÊñ◊V“3í„¬˜7„„¬ˆ∆&V√‡¢∆∆&V√Â7FGW3«6V∆V7B6∆73“&fñ«FW""ñC“&÷ˆ‰VÊ&∆VB#„∆˜Fñˆ‚f«VS“##‰VÊ&∆VC¬ˆ˜Fñˆ„„∆˜Fñˆ‚f«VS“##‰Fó6&∆VC¬ˆ˜Fñˆ„„¬˜6V∆V7C„¬ˆ∆&V√‡¢∆∆&V√‰GfÊ6VB˜FñˆÁ3«FWáF&V6∆73“&ñÁWB"ñC“&÷ˆ‰˜FñˆÁ2"&˜w3“#B#Á∑”¬˜FWáF&V„«7‚6∆73“&f˜&“÷ÜñÁB#‰˜FñˆÊ¬•4Ù‚6WGFñÊw2f˜"FÜó2÷ˆÊóF˜"„¬˜7„„¬ˆ∆&V√‡¢∆Fób6∆73“&W'""ñC“&÷ˆÊóF˜$VFóF˜$˜WB#„¬ˆFóc‡¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6T÷ˆÊóF˜$VFóF˜"Çí"GóS“&'WGFˆ‚#‰6Ê6V√¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'6fT÷ˆÊóF˜"Çí"GóS“&'WGFˆ‚#Â6fR÷ˆÊóF˜#¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡†£∆FóbñC“&ÜVFW$ÜV«÷ˆF¬"6∆73“&ÜVFW"÷ÜV«÷÷ˆF¬"7Gñ∆S“&Fó7∆ì¶ÊˆÊR"&ˆ∆S“&Fñ∆ˆr"&ñ÷÷ˆF√“'G'VR"&ñ÷∆&V∆∆VF'ì“&ÜVFW$ÜV«÷ˆF≈FóF∆R#‡¢∆Fób6∆73“&ÜVFW"÷ÜV«÷Fñ∆ˆr#‡¢∆Fób6∆73“&ÜVFW"÷ÜV«÷÷ˆF¬÷ÜVB#‡¢∆Fób6∆73“&ÜVFW"÷ÜV«÷÷ˆF¬◊FóF∆R#„«7‚6∆73“&ÜVFW"÷ÜV«÷÷ˆF¬÷ñ6ˆ‚#„Û¬˜7„„«7‚ñC“&ÜVFW$ÜV«÷ˆF≈FóF∆R#‰ñÊf˜&÷Fñˆ„¬˜7„„¬ˆFóc‡¢∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&ÜVFW"÷ÜV«÷6∆˜6R"&ñ÷∆&V√“$6∆˜6RÜV«"ˆÊ6∆ñ6≥“&6∆˜6TÜVFW$ÜV«Çí#Ï9s¬ˆ'WGFˆ„‡¢¬ˆFóc‡¢∆FóbñC“&ÜVFW$ÜV«÷ˆFƒ&ˆGí"6∆73“&ÜVFW"÷ÜV«÷&ˆGí#„¬ˆFóc‡¢¬ˆFóc‡£¬ˆFóc‡£«67&óC‡¶6ˆÁ7BW63◊3”Â7G&ñÊrá3ÛÚrríÁ&W∆6RÇı≤c√‚"u“ˆr∆””‚á≤rbs¢rf◊≤r¬s¬s¢rf«C≤r¬s‚s¢rfwC≤r¬r"s¢rgV˜C≤r¬"r#¢rb33ì≤w’∂’“íì∞¶6ˆÁ7B4ƒ55Ù5î4ƒS◊∂ÊWs¢vñÁfW7FñvFRr∆ñÁfW7FñvFS¢v∂Ê˜v‚r∆∂Ê˜v„¢v÷ÊvVBr∆÷ÊvVC¢vñvÊ˜&VBr∆ñvÊ˜&VC¢vÊWrw”∞¶6ˆÁ7B4ƒ55Ùƒ$T√◊∂ÊWs¢tÊWrr∆ñÁfW7FñvFS¢tñÁfW7FñvFRr∆∂Ê˜v„¢t∂Ê˜v‚r∆÷ÊvVC¢t÷ÊvVBr∆ñvÊ˜&VC¢tñvÊ˜&VBw”∞¶6ˆÁ7BDUdî4UÙî4ÙÂÙƒ$T≈3◊∂WFÛ¢tWFÚr«&˜WFW#¢u&˜WFW"r«7vóF6É¢u7vóF6Çr¬v66W72◊ˆñÁBs¢t66W72ˆñÁBr∆fó&Wv∆√¢tfó&Wv∆¬r∆÷ˆFV”¢t÷ˆFV“r«3¢u2r∆∆F˜¢t∆F˜r«6W'fW#¢u6W'fW"r∆Ê3¢t‰2r¬vÊWGv˜&≤◊7F˜&vRs¢tÊWGv˜&≤7F˜&vRr∆6÷W&¢t6÷W&r«&ñÁFW#¢u&ñÁFW"r«ÜˆÊS¢uÜˆÊRr¬wfˆó◊ÜˆÊRs¢ufÙïÜˆÊRr«F&∆WC¢uF&∆WBr«Gc¢uEbr¬vv÷R÷6ˆÁ6ˆ∆Rs¢tv÷R6ˆÁ6ˆ∆Rr∆ñ˜C¢tñıBr¬wF6Ç◊ÊV¬s¢uF6ÇÊV¬r∆˜FÜW#¢t˜FÜW"w”∞¶6ˆÁ7BDUdî4UÙî4ÙÂÙ4DTtı$îU3◊∂WFÛ¢v∆¬r«&˜WFW#¢vÊWGv˜&≤r«7vóF6É¢vÊWGv˜&≤r¬v66W72◊ˆñÁBs¢vÊWGv˜&≤r∆fó&Wv∆√¢vÊWGv˜&≤r∆÷ˆFV”¢vÊWGv˜&≤r∆Ê3¢vÊWGv˜&≤r¬vÊWGv˜&≤◊7F˜&vRs¢vÊWGv˜&≤r¬wF6Ç◊ÊV¬s¢vÊWGv˜&≤r«3¢v6ˆ◊WFW'2r∆∆F˜¢v6ˆ◊WFW'2r«6W'fW#¢v6ˆ◊WFW'2r«&ñÁFW#¢v6ˆ◊WFW'2r«ÜˆÊS¢v6ˆ◊WFW'2r¬wfˆó◊ÜˆÊRs¢v6ˆ◊WFW'2r«F&∆WC¢v6ˆ◊WFW'2r∆6÷W&¢w6V7W&óGír«Gc¢vÜˆ÷Rr¬vv÷R÷6ˆÁ6ˆ∆Rs¢vÜˆ÷Rr∆ñ˜C¢vÜˆ÷Rr∆˜FÜW#¢v˜FÜW"w”∞¶∆WB5DïdUÙDUdî4UÙî4ÙÂÙ4DTtı%ì“v∆¬s∞¶6ˆÁ7BDUdî4UÙî4ÙÂÙ¥Uï3‘ˆ&¶V7BÊ∂Wó2ÑDUdî4UÙî4ÙÂÙƒ$T≈2ì∞¶6ˆÁ7BDUdî4UÙî4ÙÂÙ54UEıdU%4îÙ„“s#rs∞¶gVÊ7Fñˆ‚FWfñ6Tñ6ˆ‰76WBÜ∂Wíó∑&WGW&‚rˆ76WG2ˆFWfñ6R÷ñ6ˆÁ2Úr∂∂Wí≤rÁ7fs˜c“r¥DUdî4UÙî4ÙÂÙ54UEıdU%4îÙÁ–¶gVÊ7Fñˆ‚ñÊfW'&VDFWfñ6Tñ6ˆ‚áGóRó∂6ˆÁ7BC’7G&ñÊráGóW«¬rríÁFÙ∆˜vW$66RÇì∂ñbáBÊñÊ6«VFW2Çvfó&Wv∆¬ríó&WGW&‚vfó&Wv∆¬s∂ñbáBÊñÊ6«VFW2Çv÷ˆFV“ríó&WGW&‚v÷ˆFV“s∂ñbáBÊñÊ6«VFW2ÇwF6ÇÊV¬ríó&WGW&‚wF6Ç◊ÊV¬s∂ñbáBÊñÊ6«VFW2Çwfˆóríó&WGW&‚wfˆó◊ÜˆÊRs∂ñbáBÊñÊ6«VFW2Çw&˜WFW"ró««BÊñÊ6«VFW2ÇvvFWvíríó&WGW&‚w&˜WFW"s∂ñbáBÊñÊ6«VFW2Çw7vóF6Çríó&WGW&‚w7vóF6Çs∂ñbáBÊñÊ6«VFW2Çv66W72ˆñÁBró««C””“vw««BÊñÊ6«VFW2Çwvñfíríó&WGW&‚v66W72◊ˆñÁBs∂ñbáBÊñÊ6«VFW2Çv∆F˜ró««BÊñÊ6«VFW2ÇvÊ˜FV&ˆˆ≤ríó&WGW&‚v∆F˜s∂ñbáC””“w2w««BÊñÊ6«VFW2ÇvFW6∑F˜ró««BÊñÊ6«VFW2Çv6ˆ◊WFW"ró««BÊñÊ6«VFW2Çwv˜&∑7FFñˆ‚ríó&WGW&‚w2s∂ñbáBÊñÊ6«VFW2Çv6÷W&ró««BÊñÊ6«VFW2ÇvÁg"ríó&WGW&‚v6÷W&s∂ñbáBÊñÊ6«VFW2Çw&ñÁFW"ríó&WGW&‚w&ñÁFW"s∂ñbáBÊñÊ6«VFW2ÇwÜˆÊRró««BÊñÊ6«VFW2ÇvóÜˆÊRró««BÊñÊ6«VFW2ÇvÊG&ˆñBríó&WGW&‚wÜˆÊRs∂ñbáBÊñÊ6«VFW2ÇwF&∆WBró««BÊñÊ6«VFW2ÇvóBríó&WGW&‚wF&∆WBs∂ñbáBÊñÊ6«VFW2Çw6W'fW"ríó&WGW&‚w6W'fW"s∂ñbáBÊñÊ6«VFW2ÇvÊWGv˜&≤7F˜&vRríó&WGW&‚vÊWGv˜&≤◊7F˜&vRs∂ñbáBÊñÊ6«VFW2ÇvÊ2ró««BÊñÊ6«VFW2Çw7F˜&vRríó&WGW&‚vÊ2s∂ñbáBÊñÊ6«VFW2ÇwGbró««BÊñÊ6«VFW2Çv÷VFñró««BÊñÊ6«VFW2Çw7G&V“ríó&WGW&‚wGbs∂ñbáBÊñÊ6«VFW2Çvv÷Rró««BÊñÊ6«VFW2Çv6ˆÁ6ˆ∆Rró««BÊñÊ6«VFW2ÇwÜ&˜Çró««BÊñÊ6«VFW2Çw∆ó7FFñˆ‚ríó&WGW&‚vv÷R÷6ˆÁ6ˆ∆Rs∂ñbáBÊñÊ6«VFW2Çvñ˜Bró««BÊñÊ6«VFW2Çw6÷'Bró««BÊñÊ6«VFW2Çw6VÁ6˜"ró««BÊñÊ6«VFW2Çv∆ñváBríó&WGW&‚vñ˜Bs∑&WGW&‚v˜FÜW"w–¶gVÊ7Fñˆ‚VffV7FófTFWfñ6Tñ6ˆ‚ÜBó∑&WGW&‚ÜBbfBÊñ6ˆÂˆ∂WíbfBÊñ6ˆÂˆ∂Wí”“vWFÚrìˆBÊñ6ˆÂˆ∂Wì¶ñÊfW'&VDFWfñ6Tñ6ˆ‚ÜBbfBÊFWfñ6U˜GóRó–¶gVÊ7Fñˆ‚FWfñ6Tñ6ˆÂ7&2ÜBó∂ñbÜBbfBÊñ6ˆÂˆFFó&WGW&‚BÊñ6ˆÂˆFF∑&WGW&‚FWfñ6Tñ6ˆ‰76WBÜVffV7FófTFWfñ6Tñ6ˆ‚ÜBíó–¶gVÊ7Fñˆ‚FWfñ6Tñ6ˆ‰áF÷¬ÜBó∑&WGW&‚«7‚6∆73“&FWfñ6R÷ñ6ˆ‚#„∆ñ÷r7&3“"G∂W62ÜFWfñ6Tñ6ˆÂ7&2ÜBíó“"«C“"G∂W62ÑDUdî4UÙî4ÙÂÙƒ$T≈5∂VffV7FófTFWfñ6Tñ6ˆ‚ÜBï◊«¬tFWfñ6Rró“ñ6ˆ‚#„¬˜7„Ê–¶∆WB‘S÷ÁV∆√∞¶∆WBT‰Dî‰uÙ‘dıDÙ¥T„÷ÁV∆√∞¶gVÊ7Fñˆ‚vWD6ˆˆ∂ñRÜÊ÷Ró∂6ˆÁ7B”÷Fˆ7V÷VÁBÊ6ˆˆ∂ñRÊ÷F6ÇÇrÉÛ•Á√≤ír∂Ê÷R≤s“Öµ„µ“¢írì∑&WGW&‚”ˆFV6ˆFUU$î6ˆ◊ˆÊVÁBÜ’≥“ì¶ÁV∆«–¶7ñÊ2gVÊ7Fñˆ‚ß6ˆ‚áW&¬∆˜C◊∑“ó∂˜BÊÜVFW'3÷˜BÊÜVFW'7««∑”∂ñbÜ˜BÊ÷WFÜˆBbf˜BÊ÷WFÜˆB”“ttUBró∂∆WB77&c÷vWD6ˆˆ∂ñRÇvvˆG6WñUˆ77&brì∂ñbÇ77&bó∂vóBfWF6ÇÇrˆí˜cˆWFÇˆ77&brì∂77&c÷vWD6ˆˆ∂ñRÇvvˆG6WñUˆ77&bró÷˜BÊÜVFW'5≤uÇ‘55$b’Fˆ∂V‚u”÷77&g«¬rw÷∆WB#÷vóBfWF6ÇáW&¬∆˜Bì∂ñbá"Á7FGW3”””Có∑6Ü˜t∆ˆvñ‚Çì∑Fá&˜rÊWrW'&˜"ÇwVÊWFÜVÁFñ6FVBró÷ñbÇ"Êˆ≤ó∂∆WBC÷vóB"ÁFWáBÇì∑Fá&˜rÊWrW'&˜"áBó◊&WGW&‚"Á7FGW3”””#CˆÁV∆√ß"Êß6ˆ‚Çó–¶gVÊ7Fñˆ‚Fˆvv∆UW6W$÷VÁRÇó∂6ˆÁ7B”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇ'W6W$÷VÁR"ì∂ñbÜ“ñ“Á7Gñ∆RÊFó7∆ì÷“Á7Gñ∆RÊFó7∆ì””“&ÊˆÊR#Ú&&∆ˆ6≤#¢&ÊˆÊR'–¶gVÊ7Fñˆ‚6Ü˜t∆ˆvñ‚Çó∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwt˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f∆ˆvñ‰˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw6WGW˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWFÑ˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vw&ñBw–¶7ñÊ2gVÊ7Fñˆ‚6ÜV6¥ñÊóFñ≈6WGWÇó∑G'ó∂∆WB#÷vóBfWF6ÇÇrˆí˜cˆWFÇ˜6WGW˜7FGW2rì∂∆WBC÷vóB"Êß6ˆ‚Çì∂ñbÜBÁ6WGW˜&WVó&VBó∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWFÑ˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw6WGW˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vw&ñBs∑&WGW&‚G'VW◊÷6F6ÇÜRó∑◊&WGW&‚f«6W–¶7ñÊ2gVÊ7Fñˆ‚FÙñÊóFñ≈6WGWÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BW'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw6WGWW'"rì∂W'"ÁFWáD6ˆÁFVÁC“rs∂ñbá6WGW72Áf«VR”◊6WGW73"Áf«VRó∂W'"ÁFWáD6ˆÁFVÁC“u77v˜&G2FÚÊ˜B÷F6Çs∑&WGW&‚f«6W◊G'ó∂∆WB#÷vóBfWF6ÇÇrˆí˜cˆWFÇ˜6WGWr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂7W'&VÁE˜77v˜&C¢rr∆ÊWu˜77v˜&Cß6WGW72Áf«VW“ó“ì∂ñbÇ"Êˆ≤ó∂∆WBC÷vóB"Êß6ˆ‚ÇíÊ6F6ÇÇÇì”‚á∑“íì∂W'"ÁFWáD6ˆÁFVÁC◊BÊFWFñ««¬t6˜V∆BÊ˜B7&VFR77v˜&Bs∑&WGW&‚f«6W÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw6WGW˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWFÑ˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vw&ñBs∂∆ˆvñÂW6W"Áf«VS“vF÷ñ‚s∂∆ˆvñÂ72Áf«VS“rs∂∆ˆvñÂ72Êfˆ7W2Çó÷6F6ÇÜRó∂W'"ÁFWáD6ˆÁFVÁC“u6WGWfñ∆VBw◊&WGW&‚f«6W–¶gVÊ7Fñˆ‚6Ü˜tÇó∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWFÑ˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwt˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f∆ˆvñ‰˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvríÁ7Gñ∆RÊFó7∆ì“v&∆ˆ6≤w–††¶∆WB4ƒT‰D%ÙDDS÷ÊWrFFRÇì∞¶∆WB4ƒT‰D%ÙUdTÂE3’µ”∞¶∆WB4ƒT‰D%ıdîUuÙ‘ÙDS“v÷ˆÁFÇs∞¶∆WB4ƒT‰D%ÙîÂDTu$DîÙÂ3’µ”∞¶∆WB4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEì◊∂∆ˆ6√ßG'VW”∞¶∆WB4ƒT‰D%Ù5DïdUı4ıU$4S“v∆ˆ6¬s∞¶∆WB4ƒT‰D%Ù5DïdUıDî4¥UEÙîC÷ÁV∆√∞†¶gVÊ7Fñˆ‚6∆VÊF$ó6Ù∆ˆ6¬ÜBó∞¢6ˆÁ7BC÷„”Â7G&ñÊrÜ‚íÁE7F'BÉ"¬srì∞¢&WGW&‚G∂BÊvWDgV∆≈ñV"Çó““G∑BÜBÊvWD÷ˆÁFÇÇí≥ó““G∑BÜBÊvWDFFRÇíó’BG∑BÜBÊvWDÜ˜W'2Çíó”¢G∑BÜBÊvWD÷ñÁWFW2Çíó÷∞ß–¶gVÊ7Fñˆ‚6∆VÊF$÷ˆÁFÖ&ÊvRÜBó∞¢6ˆÁ7B7F'C÷ÊWrFFRÜBÊvWDgV∆≈ñV"Çí∆BÊvWD÷ˆÁFÇÇí√ì∞¢7F'BÁ6WDFFRá7F'BÊvWDFFRÇí◊7F'BÊvWDFíÇíì∞¢7F'BÁ6WDÜ˜W'2É√√√ì∞¢6ˆÁ7BVÊC÷ÊWrFFRá7F'Bì∂VÊBÁ6WDFFRÜVÊBÊvWDFFRÇí≥C"ì∂VÊBÁ6WD÷ñ∆∆ó6V6ˆÊG2Ç”ì∞¢&WGW&‚∑7F'B∆VÊG”∞ß–¶gVÊ7Fñˆ‚6∆VÊF$ñÁFVw&Fñˆ‰f˜%6˜W&6Rá6˜W&6Ró∞¢ñbÇ6˜W&6W«¬6˜W&6RÁ7F'G5vóFÇÇv6∆VÊF#¢ríó&WGW&‚ÁV∆√∞¢6ˆÁ7BñC‘ÁV÷&W"á6˜W&6RÁ7∆óBÇs¢rï≥“ì∞¢&WGW&‚4ƒT‰D%ÙîÂDTu$DîÙÂ2ÊfñÊBáÉ”ÁÇÊñC””÷ñBó«∆ÁV∆√∞ß–¶gVÊ7Fñˆ‚6∆VÊF%F&vWD˜FñˆÁ2á6V∆V7FVC“rró∞¢6ˆÁ7Bw&óF&∆S‘4ƒT‰D%ÙîÂDTu$DîÙÂ2Êfñ«FW"áÉ”ÁÇÊWFÖˆ÷ˆFS””“vˆWFÇrbgÇÊ6ˆÊÊV7FVBì∞¢6ˆÁ7B˜G3’≤s∆˜Fñˆ‚f«VS“"#‰tÙE4UîR∆ˆ6¬6∆VÊF#¬ˆ˜Fñˆ„‚r¬‚‚Áw&óF&∆RÊ÷Üì”Ê∆˜Fñˆ‚f«VS“"G∂íÊñG“#‚G∂W62ÜíÊÊ÷Ró“+rG∂íÁ&˜fñFW#””“vvˆˆv∆RsÚtvˆˆv∆Rs¢t÷ñ7&˜6ˆgB3cRw”¬ˆ˜Fñˆ„Êï”∞¢6∆VÊF$WfVÁEF&vWBÊñÊÊW$ÖD‘√÷˜G2Ê¶ˆñ‚Çrrì∞¢6∆VÊF$WfVÁEF&vWBÁf«VS◊6V∆V7FVG«¬rs∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆD6∆VÊF"Çó∞¢6ˆÁ7B&ÊvS÷6∆VÊF$÷ˆÁFÖ&ÊvRÑ4ƒT‰D%ÙDDRì∞¢6ˆÁ7B∂WfVÁG2∆ñÁFVw&FñˆÁ5”÷vóB&ˆ÷ó6RÊ∆¬Ö∞¢ß6ˆ‚Üˆí˜cˆ6∆VÊF"ˆWfVÁG3˜7F'C“G∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBá&ÊvRÁ7F'BÁFÙï4ı7G&ñÊrÇíó“fVÊC“G∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBá&ÊvRÊVÊBÁFÙï4ı7G&ñÊrÇíó÷í¿¢ß6ˆ‚Çrˆí˜cˆ6∆VÊF"ˆñÁFVw&FñˆÁ2rê¢“ì∞¢4ƒT‰D%ÙUdTÂE3÷WfVÁG7«≈µ”¥4ƒT‰D%ÙîÂDTu$DîÙÂ3÷ñÁFVw&FñˆÁ7«≈µ”∞¢4ƒT‰D%ÙîÂDTu$DîÙÂ2Êf˜$V6ÇáÉ”Á∂6ˆÁ7B≥“v6∆VÊF#¢r∑ÇÊñC∂ñbÑ4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEï∂µ”””◊VÊFVfñÊVBî4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEï∂µ”◊G'VW“ì∞¢&VÊFW$6∆VÊF"Çì∞¢&VÊFW$6∆VÊF$ñÁFVw&FñˆÁ2Çì∞¢6∆VÊF%F&vWD˜FñˆÁ2Çì∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞ß–¶gVÊ7Fñˆ‚6∆VÊF%FˆFíÇó¥4ƒT‰D%ÙDDS÷ÊWrFFRÇì∂∆ˆD6∆VÊF"Çó–¶gVÊ7Fñˆ‚6∆VÊF%7FWÜFV«Fó∂ñbÑ4ƒT‰D%ıdîUuÙ‘ÙDS””“wvVV≤rî4ƒT‰D%ÙDDRÁ6WDFFRÑ4ƒT‰D%ÙDDRÊvWDFFRÇí∂FV«F£rì∂V«6RñbÑ4ƒT‰D%ıdîUuÙ‘ÙDS””“vFírî4ƒT‰D%ÙDDRÁ6WDFFRÑ4ƒT‰D%ÙDDRÊvWDFFRÇí∂FV«Fì∂V«6R4ƒT‰D%ÙDDS÷ÊWrFFRÑ4ƒT‰D%ÙDDRÊvWDgV∆≈ñV"Çíƒ4ƒT‰D%ÙDDRÊvWD÷ˆÁFÇÇí∂FV«F√ì∂∆ˆD6∆VÊF"Çó–¶gVÊ7Fñˆ‚6WD6∆VÊF%fñWt÷ˆFRÜ÷ˆFRó∂ñbÇ≤v÷ˆÁFÇr¬wvVV≤r¬vFír¬v∆ó7Bu“ÊñÊ6«VFW2Ü÷ˆFRíó&WGW&„¥4ƒT‰D%ıdîUuÙ‘ÙDS÷÷ˆFS∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂FF÷6∆VÊF"÷÷ˆFU“ríÊf˜$V6ÇÜ#”Á∂"Ê6∆74∆ó7BÁFˆvv∆RÇv7FófRr∆"ÊFF6WBÊ6∆VÊF$÷ˆFS””÷÷ˆFRì∂"Á6WDGG&ñ'WFRÇv&ñ◊&W76VBr≈7G&ñÊrÜ"ÊFF6WBÊ6∆VÊF$÷ˆFS””÷÷ˆFRíó“ì∑&VÊFW$6∆VÊF"Çó–¶gVÊ7Fñˆ‚ñÁ7F∆ƒ6∆VÊF$FFTñÁFW&7FñˆÁ2Çó∞¢6ˆÁ7Bw&ñC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆VÊF$w&ñBrì∞¢ñbÇw&ñG«∆w&ñBÊFF6WBÊF&∆6∆ñ6µ&VGì””“sró&WGW&„∞¢w&ñBÊFF6WBÊF&∆6∆ñ6µ&VGì“ss∞¢w&ñBÊFDWfVÁD∆ó7FVÊW"ÇvF&∆6∆ñ6≤r∆S”Á∞¢ñbÜRÁF&vWBÊ6∆˜6W7BÇrÊ6∆VÊF"÷WfVÁB÷6Üóríó&WGW&„∞¢6ˆÁ7BFì÷RÁF&vWBÊ6∆˜6W7BÇrÊ6∆VÊF"÷Fï∂FF÷6∆VÊF"÷FFU“rì∞¢ñbÇFó«¬w&ñBÊ6ˆÁFñÁ2ÜFííó&WGW&„∞¢RÁ&WfVÁDFVfV«BÇì∞¢˜V‰6∆VÊF$WfVÁD÷ˆF¬ÜÁV∆¬∆FíÊFF6WBÊ6∆VÊF$FFRì∞¢“ì∞ß–¶gVÊ7Fñˆ‚6V∆V7D6∆VÊF%6˜W&6Rá6˜W&6Ró∞¢4ƒT‰D%Ù5DïdUı4ıU$4S◊6˜W&6S∞¢4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEì◊∂∆ˆ6√ß6˜W&6S””“v∆ˆ6¬w”∞¢4ƒT‰D%ÙîÂDTu$DîÙÂ2Êf˜$V6ÇÜì”Á¥4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEï≤v6∆VÊF#¢r∂íÊñE”◊6˜W&6S””“v6∆VÊF#¢r∂íÊñG“ì∞¢&VÊFW$6∆VÊF$fñ«FW'2Çì∞¢&VÊFW$6∆VÊF"Çì∞ß–¶gVÊ7Fñˆ‚Fˆvv∆T6∆VÊF%6˜W&6Rá6˜W&6R«fó6ñ&∆Ró∞¢4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEï∑6˜W&6U”◊fó6ñ&∆S∞¢ñbáfó6ñ&∆Rî4ƒT‰D%Ù5DïdUı4ıU$4S◊6˜W&6S∞¢&VÊFW$6∆VÊF$fñ«FW'2Çì∞¢&VÊFW$6∆VÊF"Çì∞ß–¶gVÊ7Fñˆ‚&VÊFW$6∆VÊF$fñ«FW'2Çó∞¢6ˆÁ7B&ˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆VÊF$WáFW&Êƒfñ«FW'2rì∂ñbÇ&ˆ˜Bó&WGW&„∞¢&ˆ˜BÊñÊÊW$ÖD‘√‘4ƒT‰D%ÙîÂDTu$DîÙÂ2Ê∆VÊwFÉÙ4ƒT‰D%ÙîÂDTu$DîÙÂ2Ê÷Üì”Á∂6ˆÁ7B6˜W&6S“v6∆VÊF#¢r∂íÊñC∑&WGW&‚s∆∆&V¬FF◊6˜W&6S“"r∑6˜W&6R≤r"6∆73“&6∆VÊF"÷fñ«FW"6∆VÊF"◊7vóF6Ç◊&˜rcC3÷6∆VÊF"÷6ˆÊÊV7Fñˆ‚r≤Ñ4ƒT‰D%Ù5DïdUı4ıU$4S””◊6˜W&6SÚv7FófRs¢rrí≤r"ˆÊ6∆ñ6≥“'6V∆V7D6∆VÊF%6˜W&6RÖ¬rr∑6˜W&6R≤u¬rí#„∆ñÁWBGóS“&6ÜV6∂&˜Ç"r≤Ñ4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEï∑6˜W&6U“”÷f«6SÚv6ÜV6∂VBs¢rrí≤rˆÊ6ÜÊvS“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∑Fˆvv∆T6∆VÊF%6˜W&6RÖ¬rr∑6˜W&6R≤u¬r«FÜó2Ê6ÜV6∂VBí#„«7‚6∆73“'cC3◊&˜fñFW"÷v«óÇr≤ÜíÁ&˜fñFW#””“vvˆˆv∆RsÚvvˆˆv∆Rs¢v÷ñ7&˜6ˆgBrí≤r#‚r≤ÜíÁ&˜fñFW#””“vvˆˆv∆RsÚtrs¢tÚrí≤s¬˜7„„«7„„∆#‚r∂W62ÜíÊÊ÷Rí≤s¬ˆ#„«6÷∆√‚r∂W62ÜíÊ66˜VÁEˆV÷ñ««∆íÁ&˜fñFW"í≤s¬˜6÷∆√„¬˜7„„∆V”‚r≤ÜíÊVÊ&∆VCÚt6ˆÊÊV7FVBs¢uW6VBrí≤s¬ˆV”„¬ˆ∆&V√‚w“íÊ¶ˆñ‚Çrrì¢s∆'WGFˆ‚6∆73“&6∆VÊF"÷6ˆÊÊV7Fñˆ‚◊&ˆ◊B"ˆÊ6∆ñ6≥“&˜V‰6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Çì∑6V∆V7D6∆VÊF%&˜fñFW"Ö¬v÷ñ7&˜6ˆgC3cU¬rí#„«7‚6∆73“'cC3◊&˜fñFW"÷v«óÇ÷ñ7&˜6ˆgB#‰Û¬˜7„‰˜WF∆ˆˆ≤6∆VÊF"«6÷∆√‰6ˆÊÊV7C¬˜6÷∆√„¬ˆ'WGFˆ„‚s∞ß–¶gVÊ7Fñˆ‚&VÊFW$6∆VÊF"Çó∞¢6ˆÁ7B∆&V√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆VÊF$÷ˆÁFÑ∆&V¬rí∆w&ñC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆VÊF$w&ñBrì∂ñbÇ∆&V««¬w&ñBó&WGW&„∞¢∆&V¬ÁFWáD6ˆÁFVÁC‘4ƒT‰D%ıdîUuÙ‘ÙDS””“vFísÙ4ƒT‰D%ÙDDRÁFÙ∆ˆ6∆TFFU7G&ñÊráVÊFVfñÊVB«∂÷ˆÁFÉ¢v∆ˆÊrr∆Fì¢vÁV÷W&ñ2r«ñV#¢vÁV÷W&ñ2w“ì§4ƒT‰D%ÙDDRÁFÙ∆ˆ6∆TFFU7G&ñÊráVÊFVfñÊVB«∂÷ˆÁFÉ¢v∆ˆÊrr«ñV#¢vÁV÷W&ñ2w“ì∞¢&VÊFW$6∆VÊF$fñ«FW'2Çì∞¢6ˆÁ7B&ÊvS÷6∆VÊF$÷ˆÁFÖ&ÊvRÑ4ƒT‰D%ÙDDRí«FˆFì÷ÊWrFFRÇì∑FˆFíÁ6WDÜ˜W'2É√√√ì∞¢∆WBáF÷√“rs∞¢6ˆÁ7Bfó'7DFì÷ÊWrFFRÑ4ƒT‰D%ÙDDRÊvWDgV∆≈ñV"Çíƒ4ƒT‰D%ÙDDRÊvWD÷ˆÁFÇÇí√íÊvWDFíÇì∞¢6ˆÁ7BFó4ñ‰÷ˆÁFÉ÷ÊWrFFRÑ4ƒT‰D%ÙDDRÊvWDgV∆≈ñV"Çíƒ4ƒT‰D%ÙDDRÊvWD÷ˆÁFÇÇí≥√íÊvWDFFRÇì∞¢6ˆÁ7Bfó6ñ&∆TFó3‘4ƒT‰D%ıdîUuÙ‘ÙDS””“wvVV≤sÛs§4ƒT‰D%ıdîUuÙ‘ÙDS””“vFísÛ§÷FÇÊ6Vñ¬ÇÜfó'7DFí∂Fó4ñ‰÷ˆÁFÇíÛrí£s∞¢6ˆÁ7B7F'DFFS÷ÊWrFFRÑ4ƒT‰D%ıdîUuÙ‘ÙDS””“v÷ˆÁFÇs˜&ÊvRÁ7F'C§4ƒT‰D%ÙDDRì∞¢ñbÑ4ƒT‰D%ıdîUuÙ‘ÙDS””“wvVV≤ró7F'DFFRÁ6WDFFRá7F'DFFRÊvWDFFRÇí◊7F'DFFRÊvWDFíÇíì∞¢w&ñBÊ6∆74∆ó7BÁFˆvv∆RÇv6∆VÊF"÷∆ó7B÷÷ˆFRrƒ4ƒT‰D%ıdîUuÙ‘ÙDS””“v∆ó7Brì∂w&ñBÊ6∆74∆ó7BÁFˆvv∆RÇv6∆VÊF"÷Fí÷÷ˆFRrƒ4ƒT‰D%ıdîUuÙ‘ÙDS””“vFírì∞¢6ˆÁ7BvVV¥ÜVC÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜"Çr7fñWr÷6∆VÊF"Ê6∆VÊF"◊vVV≤÷ÜVBrì∂ñbávVV¥ÜVBóvVV¥ÜVBÊÜñFFV„’≤vFír¬v∆ó7Bu“ÊñÊ6«VFW2Ñ4ƒT‰D%ıdîUuÙ‘ÙDRì∞¢ñbÑ4ƒT‰D%ıdîUuÙ‘ÙDS””“v∆ó7Bró∞¢áF÷√‘4ƒT‰D%ÙUdTÂE2Êfñ«FW"ÜS”‰4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEï∂RÁ6˜W&6U“”÷f«6RíÁ6˜'BÇÜ∆"ì”ÊÊWrFFRÜÁ7F'EˆBí÷ÊWrFFRÜ"Á7F'EˆBííÊ÷ÜS”Ê∆'WGFˆ‚6∆73“&6∆VÊF"÷∆ó7B◊&˜r"ˆÊ6∆ñ6≥“&˜V‰6∆VÊF$WfVÁD÷ˆF¬ÇG¥ÁV÷&W"ÜRÊñBó“í#„«7„‚G∂W62ÜÊWrFFRÜRÁ7F'EˆBíÁFÙ∆ˆ6∆TFFU7G&ñÊrÇíó”¬˜7„„∆#‚G∂W62ÜRÁFóF∆W«¬tWfVÁBró”¬ˆ#„«7„‚G∂W62ÜÊWrFFRÜRÁ7F'EˆBíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“¬∂Ü˜W#¢vÁV÷W&ñ2r∆÷ñÁWFS¢s"÷FñvóBw“íó”¬˜7„„¬ˆ'WGFˆ„ÊíÊ¶ˆñ‚Çrró«¬s∆Fób6∆73“&V◊Gí#‰ÊÚWfVÁG2FÜó2÷ˆÁFÇ„¬ˆFóc‚s∞¢÷V«6Rf˜"Ü∆WBì”∂ì«fó6ñ&∆TFó3∂í≤≤ó∞¢6ˆÁ7BFì÷ÊWrFFRá7F'DFFRì∂FíÁ6WDFFRÜFíÊvWDFFRÇí∂íì∞¢6ˆÁ7BFï7F'C÷ÊWrFFRÜFíì∂Fï7F'BÁ6WDÜ˜W'2É√√√ì∞¢6ˆÁ7BFîVÊC÷ÊWrFFRÜFíì∂FîVÊBÁ6WDÜ˜W'2É#2√Sí√Sí√ììíì∞¢6ˆÁ7BWfVÁG3‘4ƒT‰D%ÙUdTÂE2Êfñ«FW"ÜS”Á∞¢ñbÑ4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEï∂RÁ6˜W&6U”””÷f«6Ró&WGW&‚f«6S∞¢6ˆÁ7B7C÷ÊWrFFRÜRÁ7F'EˆBí∆V„÷ÊWrFFRÜRÊVÊEˆBì∞¢&WGW&‚7C√÷FîVÊBbfV„„÷Fï7F'C∞¢“ì∞¢6ˆÁ7B6÷T÷ˆÁFÉ÷FíÊvWD÷ˆÁFÇÇì””‘4ƒT‰D%ÙDDRÊvWD÷ˆÁFÇÇì∞¢6ˆÁ7Bó5FˆFì÷Fï7F'BÊvWEFñ÷RÇì””◊FˆFíÊvWEFñ÷RÇì∞¢6ˆÁ7B7&VFTC÷6∆VÊF$ó6Ù∆ˆ6¬ÜÊWrFFRÜFíÊvWDgV∆≈ñV"Çí∆FíÊvWD÷ˆÁFÇÇí∆FíÊvWDFFRÇí√í√íì∞¢áF÷¬≥÷∆Fób6∆73“&6∆VÊF"÷FíG∑6÷T÷ˆÁFÉÚrs¢v˜WG6ñFRw“G∂ó5FˆFìÚwFˆFís¢rw“"FF÷6∆VÊF"÷FFS“"G∂7&VFTG“"FóF∆S“$F˜V&∆R÷6∆ñ6≤FÚ7&VFR‚ˆñÁF÷VÁB#„∆Fób6∆73“&6∆VÊF"÷Fí÷ÁV“#‚G∂FíÊvWDFFRÇó”¬ˆFócÊ∞¢WfVÁG2Á6∆ñ6RÉ√BíÊf˜$V6ÇÜS”Á∞¢6ˆÁ7BñÁFVw&Fñˆ„÷6∆VÊF$ñÁFVw&Fñˆ‰f˜%6˜W&6RÜRÁ6˜W&6Rì∞¢6ˆÁ7B7ñÊ6VC÷ñÁFVw&Fñˆ„Úr7ñÊ6VBs¢rs∞¢6ˆÁ7B&VFˆÊ«ì÷RÊWáFW&Ê≈˜&VFˆÊ«ìÚr&VFˆÊ«ís¢rs∞¢6ˆÁ7B7F'C÷RÊ∆≈ˆFìÚrs¶ÊWrFFRÜRÁ7F'EˆBíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“¬∂Ü˜W#¢vÁV÷W&ñ2r∆÷ñÁWFS¢s"÷FñvóBw“í≤rs∞¢6ˆÁ7B÷&∂W#÷RÁFñ6∂WEˆñCÚs«7‚6∆73“&6∆VÊF"◊7ñÊ2÷÷&≤#Ó)js¬˜7„‚s¢ÜñÁFVw&Fñˆ„Ús«7‚6∆73“&6∆VÊF"◊7ñÊ2÷÷&≤#Ó(k≥¬˜7„‚s¢rrì∞¢áF÷¬≥÷∆'WGFˆ‚6∆73“&6∆VÊF"÷WfVÁB÷6ÜóG∂W62ÜRÊ6ˆ∆˜'«¬v&«VRró“G∑7ñÊ6VG“G∑&VFˆÊ«ó“"FóF∆S“"G∂W62ÜRÁFóF∆Ró“"ˆÊ6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∂˜V‰6∆VÊF$WfVÁD÷ˆF¬ÇG∂RÊñG“í"ˆÊF&∆6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∂˜V‰6∆VÊF$WfVÁD÷ˆF¬ÇG∂RÊñG“í#‚G∂÷&∂W'“G∂W62á7F'B∂RÁFóF∆Ró”¬ˆ'WGFˆ„Ê∞¢“ì∞¢ñbÜWfVÁG2Ê∆VÊwFÉ„BñáF÷¬≥÷∆Fób6∆73“&6∆VÊF"÷÷˜&R#‚≤G∂WfVÁG2Ê∆VÊwFÇ”G“÷˜&S¬ˆFócÊ∞¢áF÷¬≥“s¬ˆFóc‚s∞¢–¢w&ñBÊñÊÊW$ÖD‘√÷áF÷√∞¢ñÁ7F∆ƒ6∆VÊF$FFTñÁFW&7FñˆÁ2Çì∞¢6ˆÁ7B÷ˆÁFÜ«ì‘4ƒT‰D%ÙUdTÂE2Êfñ«FW"ÜS”Á∂6ˆÁ7BC÷ÊWrFFRÜRÁ7F'EˆBì∑&WGW&‚BÊvWDgV∆≈ñV"Çì””‘4ƒT‰D%ÙDDRÊvWDgV∆≈ñV"ÇíbfBÊvWD÷ˆÁFÇÇì””‘4ƒT‰D%ÙDDRÊvWD÷ˆÁFÇÇó“ì∞¢6ˆÁ7B7FG3◊∂6∆VÊF%7FEF˜F√¶÷ˆÁFÜ«íÊ∆VÊwFÇ∆6∆VÊF%7FD÷ñÁFVÊÊ6S¶÷ˆÁFÜ«íÊfñ«FW"ÜS”‚ˆ÷ñÁFVÊÊ6W«Ww&FW«F6á∆&6∑W∆fó&◊v&RˆíÁFW7BÜRÁFóF∆W«¬rrííÊ∆VÊwFÇ∆6∆VÊF%7FEFñ6∂WG3¶÷ˆÁFÜ«íÊfñ«FW"ÜS”ÊRÁFñ6∂WEˆñG«¬˜Fñ6∂WG«F∑B“ˆíÁFW7BÜRÁFóF∆W«¬rrííÊ∆VÊwFÇ∆6∆VÊF%7FD÷VWFñÊw3¶÷ˆÁFÜ«íÊfñ«FW"ÜS”‚ˆ÷VWFñÊw«&WfñWw«7ñÊ2ˆíÁFW7BÜRÁFóF∆W«¬rrííÊ∆VÊwFá”∞¢ˆ&¶V7BÊVÁG&ñW2á7FG2íÊf˜$V6ÇÇÖ∂ñB∆6˜VÁE“ì”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬ÁFWáD6ˆÁFVÁC÷6˜VÁG“ì∞¢6ˆÁ7BW6ˆ÷ñÊs‘4ƒT‰D%ÙUdTÂE2Êfñ«FW"ÜS”ÊÊWrFFRÜRÊVÊEˆBì„÷ÊWrFFRÇíbd4ƒT‰D%ı4ıU$4Uıdï4î$îƒïEï∂RÁ6˜W&6U“”÷f«6RíÁ6˜'BÇÜ∆"ì”ÊÊWrFFRÜÁ7F'EˆBí÷ÊWrFFRÜ"Á7F'EˆBííÁ6∆ñ6RÉ√Rì∞¢6ˆÁ7BW÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆VÊF%W6ˆ÷ñÊrrì∞¢WÊñÊÊW$ÖD‘√◊W6ˆ÷ñÊrÊ∆VÊwFÉ˜W6ˆ÷ñÊrÊ÷ÜS”Á∞¢6ˆÁ7BñÁFVw&Fñˆ„÷6∆VÊF$ñÁFVw&Fñˆ‰f˜%6˜W&6RÜRÁ6˜W&6Rì∞¢&WGW&‚∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&6∆VÊF"◊W6ˆ÷ñÊr÷óFV“"ˆÊ6∆ñ6≥“&˜V‰6∆VÊF$WfVÁD÷ˆF¬ÇG¥ÁV÷&W"ÜRÊñBó“í#„∆#‚G∂W62ÜRÁFóF∆Ró”¬ˆ#„«7„‚G∂ÊWrFFRÜRÁ7F'EˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇó“G∂ñÁFVw&Fñˆ„Úr+rr∂W62ÜñÁFVw&Fñˆ‚ÊÊ÷Rì¢rw”¬˜7„„¬ˆ'WGFˆ„Ê∞¢“íÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚW6ˆ÷ñÊrˆñÁF÷VÁG2„¬ˆFóc‚s∞ß–¶gVÊ7Fñˆ‚˜V‰6∆VÊF$WfVÁD÷ˆF¬ÜñC÷ÁV∆¬«7F'Ef«VS÷ÁV∆¬ó∞¢6ˆÁ7B÷ˆF√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆VÊF$WfVÁD÷ˆF¬rì∞¢6ˆÁ7BWfVÁC÷ñCÙ4ƒT‰D%ÙUdTÂE2ÊfñÊBáÉ”ÁÇÊñC””‘ÁV÷&W"ÜñBíì¶ÁV∆√∞¢ñbÜWfVÁBbfWfVÁBÊWáFW&Ê≈˜&VFˆÊ«íó∂∆W'BÇuFÜó2ˆñÁF÷VÁB6ˆ÷W2g&ˆ“‚î527V'67&óFñˆ‚‚6ˆÊÊV7BFÜR&˜fñFW"vóFÇÙWFÇñbñ˜RvÁBGvÚ◊víVFóFñÊr‚rì∑&WGW&Á–¢6∆VÊF$WfVÁDñBÁf«VS÷WfVÁCˆWfVÁBÊñC¢rs∞¢6∆VÊF$WfVÁD÷ˆF≈FóF∆RÁFWáD6ˆÁFVÁC÷WfVÁCÚtVFóBˆñÁF÷VÁBs¢t7&VFRˆñÁF÷VÁBs∞¢6∆VÊF$WfVÁEFóF∆RÁf«VS÷WfVÁCˆWfVÁBÁFóF∆S¢rs∞¢6∆VÊF$WfVÁD∆ˆ6Fñˆ‚Áf«VS÷WfVÁCˆWfVÁBÊ∆ˆ6FñˆÁ«¬rs¢rs∞¢6∆VÊF$WfVÁDFW67&óFñˆ‚Áf«VS÷WfVÁCˆWfVÁBÊFW67&óFñˆÁ«¬rs¢rs∞¢6∆VÊF$WfVÁD6ˆ∆˜"Áf«VS÷WfVÁCˆWfVÁBÊ6ˆ∆˜'«¬v&«VRs¢v&«VRs∞¢6∆VÊF$WfVÁD∆ƒFíÊ6ÜV6∂VC“WfVÁCÚÊ∆≈ˆFì∞¢6ˆÁ7BñÁFVw&Fñˆ„÷WfVÁCˆ6∆VÊF$ñÁFVw&Fñˆ‰f˜%6˜W&6RÜWfVÁBÁ6˜W&6Rì¶ÁV∆√∞¢6∆VÊF%F&vWD˜FñˆÁ2ÜñÁFVw&Fñˆ„ı7G&ñÊrÜñÁFVw&Fñˆ‚ÊñBì¢rrì∞¢6∆VÊF$WfVÁEF&vWBÊFó6&∆VC“WfVÁC∞¢4ƒT‰D%Ù5DïdUıDî4¥UEÙîC÷WfVÁCÚÁFñ6∂WEˆñG«∆ÁV∆√∞¢6∆VÊF%Fñ6∂WD7FñˆÁ2Á7Gñ∆RÊFó7∆ì‘4ƒT‰D%Ù5DïdUıDî4¥UEÙîCÚvf∆WÇs¢vÊˆÊRs∞¢ñbÑ4ƒT‰D%Ù5DïdUıDî4¥UEÙîBó∞¢6∆VÊF%Fñ6∂WD∆&V¬ÁFWáD6ˆÁFVÁC“t∆ñÊ∂VBFñ6∂WB2r¥4ƒT‰D%Ù5DïdUıDî4¥UEÙîC∞¢6∆VÊF$WfVÁEFóF∆RÁ&VDˆÊ«ì◊G'VS∂6∆VÊF$WfVÁD∆ˆ6Fñˆ‚Á&VDˆÊ«ì◊G'VS∂6∆VÊF$WfVÁDFW67&óFñˆ‚Á&VDˆÊ«ì◊G'VS∂6∆VÊF$WfVÁD6ˆ∆˜"ÊFó6&∆VC◊G'VS∞¢÷V«6W∞¢6∆VÊF$WfVÁEFóF∆RÁ&VDˆÊ«ì÷f«6S∂6∆VÊF$WfVÁD∆ˆ6Fñˆ‚Á&VDˆÊ«ì÷f«6S∂6∆VÊF$WfVÁDFW67&óFñˆ‚Á&VDˆÊ«ì÷f«6S∂6∆VÊF$WfVÁD6ˆ∆˜"ÊFó6&∆VC÷f«6S∞¢–¢∆WB7F'C÷WfVÁCˆÊWrFFRÜWfVÁBÁ7F'EˆBì¢á7F'Ef«VSˆÊWrFFRá7F'Ef«VRì¶ÊWrFFRÇíì∞¢ñbÇWfVÁBó∑7F'BÁ6WE6V6ˆÊG2É√ì∑7F'BÁ6WD÷ñÁWFW2Ñ÷FÇÊ6Vñ¬á7F'BÊvWD÷ñÁWFW2ÇíÛ3í£3ó–¢∆WBVÊC÷WfVÁCˆÊWrFFRÜWfVÁBÊVÊEˆBì¶ÊWrFFRá7F'BÊvWEFñ÷RÇí≥c£c£ì∞¢6∆VÊF$WfVÁE7F'BÁf«VS÷6∆VÊF$ó6Ù∆ˆ6¬á7F'Bì∂6∆VÊF$WfVÁDVÊBÁf«VS÷6∆VÊF$ó6Ù∆ˆ6¬ÜVÊBì∞¢6∆VÊF$FV∆WFT'F‚Á7Gñ∆RÊFó7∆ì÷WfVÁBbb4ƒT‰D%Ù5DïdUıDî4¥UEÙîCÚvñÊ∆ñÊR÷f∆WÇs¢vÊˆÊRs∞¢6∆VÊF$WfVÁDW'"ÁFWáD6ˆÁFVÁC“rs∞¢÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∞¢6WEFñ÷V˜WBÇÇì”Ê6∆VÊF$WfVÁEFóF∆RÊfˆ7W2Çí√#ì∞ß–¶gVÊ7Fñˆ‚6∆˜6T6∆VÊF$WfVÁD÷ˆF¬Çó∂6∆VÊF$WfVÁD÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rs∂6∆VÊF$WfVÁEF&vWBÊFó6&∆VC÷f«6S∂6∆VÊF$WfVÁEFóF∆RÁ&VDˆÊ«ì÷f«6S∂6∆VÊF$WfVÁD∆ˆ6Fñˆ‚Á&VDˆÊ«ì÷f«6S∂6∆VÊF$WfVÁDFW67&óFñˆ‚Á&VDˆÊ«ì÷f«6S∂6∆VÊF$WfVÁD6ˆ∆˜"ÊFó6&∆VC÷f«6S¥4ƒT‰D%Ù5DïdUıDî4¥UEÙîC÷ÁV∆√∂6∆VÊF%Fñ6∂WD7FñˆÁ2Á7Gñ∆RÊFó7∆ì“vÊˆÊRw–¶7ñÊ2gVÊ7Fñˆ‚˜V‰6∆VÊF$∆ñÊ∂VEFñ6∂WBÇó∞¢ñbÇ4ƒT‰D%Ù5DïdUıDî4¥UEÙîBó&WGW&„∞¢6∆˜6T6∆VÊF$WfVÁD÷ˆF¬Çì∑6Ü˜ufñWrÇwFñ6∂WG2r«G'VRì∂vóB∆ˆEFñ6∂WG2Çì∂˜VÂFñ6∂WDVFóF˜"Ñ4ƒT‰D%Ù5DïdUıDî4¥UEÙîBì∞ß–¶7ñÊ2gVÊ7Fñˆ‚FD6∆VÊF%Fñ6∂WDÊ˜FRÇó∞¢ñbÇ4ƒT‰D%Ù5DïdUıDî4¥UEÙîBó&WGW&„∞¢6ˆÁ7BÊ˜FS◊&ˆ◊BÇtFBv˜&≤Ê˜FRFÚFÜó2Fñ6∂WC¢rì∂ñbÇÊ˜FW«¬Ê˜FRÁG&ñ“Çíó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr¥4ƒT‰D%Ù5DïdUıDî4¥UEÙîB≤rˆÊ˜FW2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂Ê˜FS¶Ê˜FRÁG&ñ“Çó“ó“ì∂∆W'BÇuv˜&≤Ê˜FRFFVB‚ró÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFBÊ˜FS¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚&W6ˆ«fT6∆VÊF%Fñ6∂WBÇó∞¢ñbÇ4ƒT‰D%Ù5DïdUıDî4¥UEÙîBó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr¥4ƒT‰D%Ù5DïdUıDî4¥UEÙîB«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑7FGW3¢w&W6ˆ«fVBw“ó“ì∂∆W'BÇuFñ6∂WB÷&∂VB&W6ˆ«fVB‚rì∂vóB∆ˆD6∆VÊF"Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B&W6ˆ«fRFñ6∂WC¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚6∆˜6T6∆VÊF%Fñ6∂WBÇó∞¢ñbÇ4ƒT‰D%Ù5DïdUıDî4¥UEÙîBó&WGW&„∞¢6ˆÁ7BÊ˜FS◊&ˆ◊BÇt6∆˜6ñÊrv˜&≤Ê˜FRÜ˜FñˆÊ¬ì¢ró«¬rs∞¢6ˆÁ7B&W6ˆ«fT∆ñÊ∂VC÷6ˆÊfó&“Çt«6Ú&W6ˆ«fRFÜR∆ñÊ∂VBWfVÁBfñÊFñÊr¬ñbFÜó2Fñ6∂WB6÷Rg&ˆ“ˆÊSÚrì∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr¥4ƒT‰D%Ù5DïdUıDî4¥UEÙîB≤rˆ6∆˜6Rr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂Ê˜FR«&W6ˆ«fUˆ∆ñÊ∂VEˆfñÊFñÊsß&W6ˆ«fT∆ñÊ∂VG“ó“ì∂∆W'BÇuFñ6∂WB6∆˜6VB‚rì∂6∆˜6T6∆VÊF$WfVÁD÷ˆF¬Çì∂vóB∆ˆD6∆VÊF"Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B6∆˜6RFñ6∂WC¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚6fT6∆VÊF$WfVÁBÜRó∞¢RÁ&WfVÁDFVfV«BÇì∂6∆VÊF$WfVÁDW'"ÁFWáD6ˆÁFVÁC“rs∞¢6ˆÁ7BñC÷6∆VÊF$WfVÁDñBÁf«VS∞¢6ˆÁ7B&ˆGì◊∑FóF∆S¶6∆VÊF$WfVÁEFóF∆RÁf«VRÁG&ñ“Çí∆FW67&óFñˆ„¶6∆VÊF$WfVÁDFW67&óFñˆ‚Áf«VRÁG&ñ“Çí∆∆ˆ6Fñˆ„¶6∆VÊF$WfVÁD∆ˆ6Fñˆ‚Áf«VRÁG&ñ“Çí¿¢7F'EˆC¶ÊWrFFRÜ6∆VÊF$WfVÁE7F'BÁf«VRíÁFÙï4ı7G&ñÊrÇí∆VÊEˆC¶ÊWrFFRÜ6∆VÊF$WfVÁDVÊBÁf«VRíÁFÙï4ı7G&ñÊrÇí¿¢∆≈ˆFì¶6∆VÊF$WfVÁD∆ƒFíÊ6ÜV6∂VB∆6ˆ∆˜#¶6∆VÊF$WfVÁD6ˆ∆˜"Áf«VR¿¢6∆VÊF%ˆñÁFVw&FñˆÂˆñC¶6∆VÊF$WfVÁEF&vWBÁf«VSÙÁV÷&W"Ü6∆VÊF$WfVÁEF&vWBÁf«VRì¶ÁV∆«”∞¢G'ó∞¢vóBß6ˆ‚ÜñCÚrˆí˜cˆ6∆VÊF"ˆWfVÁG2Úr∂ñC¢rˆí˜cˆ6∆VÊF"ˆWfVÁG2r«∂÷WFÜˆC¶ñCÚuUBs¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∞¢6∆˜6T6∆VÊF$WfVÁD÷ˆF¬Çì∂vóB∆ˆD6∆VÊF"Çì∞¢÷6F6ÇÜW'"ó∂6∆VÊF$WfVÁDW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6fRˆñÁF÷VÁC¢r∂W'"Ê÷W76vW–¢&WGW&‚f«6S∞ß–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFT6∆VÊF$WfVÁBÇó∞¢6ˆÁ7BñC÷6∆VÊF$WfVÁDñBÁf«VS∂ñbÇñBó&WGW&„∞¢ñbÇ6ˆÊfó&“ÇtFV∆WFRFÜó2ˆñÁF÷VÁCÚ6ˆÊÊV7FVB6∆VÊF"WfVÁG2vñ∆¬«6Ú&RFV∆WFVBg&ˆ“FÜR&˜fñFW"‚ríó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜cˆ6∆VÊF"ˆWfVÁG2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂6∆˜6T6∆VÊF$WfVÁD÷ˆF¬Çì∂vóB∆ˆD6∆VÊF"Çó÷6F6ÇÜW'"ó∂6∆VÊF$WfVÁDW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜BFV∆WFRˆñÁF÷VÁC¢r∂W'"Ê÷W76vW–ß–¶gVÊ7Fñˆ‚6V∆V7D6∆VÊF%&˜fñFW"á&˜fñFW"ó∞¢6∆VÊF%&˜fñFW"Áf«VS◊&˜fñFW#∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ6∆VÊF"◊&˜fñFW"ríÊf˜$V6ÇáÉ”ÁÇÊ6∆74∆ó7BÁFˆvv∆RÇv7FófRr«ÇÊFF6WBÁ&˜fñFW#””◊&˜fñFW"íì∞¢6∆VÊF$ñÁFVw&FñˆÂ&V÷˜FTñBÁ∆6VÜˆ∆FW#◊&˜fñFW#””“vvˆˆv∆RsÚw&ñ÷'ís¢vFVfV«Bs∞ß–¶gVÊ7Fñˆ‚6V∆V7D6∆VÊF$WFÑ÷ˆFRÜ÷ˆFRó∞¢6∆VÊF$WFÑ÷ˆFRÁf«VS÷÷ˆFS∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ6∆VÊF"÷÷ˆFR◊F"ríÊf˜$V6ÇáÉ”ÁÇÊ6∆74∆ó7BÁFˆvv∆RÇv7FófRr«ÇÊFF6WBÊ÷ˆFS””÷÷ˆFRíì∞¢6ˆÁ7BˆWFÉ÷÷ˆFS””“vˆWFÇs∞¢6∆VÊF$6∆ñVÁDñEw&Á7Gñ∆RÊFó7∆ì÷ˆWFÉÚvf∆WÇs¢vÊˆÊRs∞¢6∆VÊF$6∆ñVÁE6V7&WEw&Á7Gñ∆RÊFó7∆ì÷ˆWFÉÚvf∆WÇs¢vÊˆÊRs∞¢6∆VÊF$ñ75w&Á7Gñ∆RÊFó7∆ì÷ˆWFÉÚvÊˆÊRs¢vf∆WÇs∞¢6∆VÊF$&6ñ5W6W%w&Á7Gñ∆RÊFó7∆ì÷÷ˆFS””“v&6ñ2sÚvf∆WÇs¢vÊˆÊRs∂6∆VÊF$&6ñ577v˜&Ew&Á7Gñ∆RÊFó7∆ì÷÷ˆFS””“v&6ñ2sÚvf∆WÇs¢vÊˆÊRs∞¢6∆VÊF$ñÁFVw&FñˆÂ&V÷˜FTñBÁ&VÁDV∆V÷VÁBÁ7Gñ∆RÊFó7∆ì÷ˆWFÉÚvf∆WÇs¢vÊˆÊRs∞¢6∆VÊF$ñÁFVw&Fñˆ‰÷ˆFTÊ˜FRÁFWáD6ˆÁFVÁC÷ˆWFÄ¢ÚuGvÚ◊víÙWFÇ∆WG2tÙE4UîR7&VFR¬VFóBÊBFV∆WFRWfVÁG2ñ‚FÜR6ˆÊÊV7FVB6∆VÊF"‚ÙWFÇ7&VFVÁFñ«2ÊB&Vg&W6ÇFˆ∂VÁ2&RVÊ7'óFVBB&W7B‚p¢¶÷ˆFS””“v&6ñ2sÚuW6RFÜR÷ñ∆&˜ÇV÷ñ¬ÊB‚77v˜&BvVÊW&FVB'íñ˜W"&˜fñFW"‚tÙE4UîR6VÊG2&6ñ2WFÜVÁFñ6Fñˆ‚ˆÊ«íFÚFÜR&ófFRî526W'fW"ñ˜R7V6ñgì≤77v˜&G2&RVÊ7'óFVBB&W7B‚p¢¢tî52&V÷ñÁ2fñ∆&∆R2&VB÷ˆÊ«íf∆∆&6≤‚FÚVFóB&˜fñFW"WfVÁG2g&ˆ“tÙE4UîR¬W6RGvÚ◊víÙWFÇ‚s∞ß–¶gVÊ7Fñˆ‚˜V‰6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Çó∞¢6V∆V7D6∆VÊF$WFÑ÷ˆFRÇvˆWFÇrì∞¢6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑&VÊFW$6∆VÊF$ñÁFVw&FñˆÁ2Çêß–¶gVÊ7Fñˆ‚6∆˜6T6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Çó∂6∆VÊF$ñÁFVw&Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚6fT6∆VÊF$ñÁFVw&Fñˆ‚Çó∞¢6∆VÊF$ñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∞¢6ˆÁ7B÷ˆFS÷6∆VÊF$WFÑ÷ˆFRÁf«VS∞¢6ˆÁ7B&ˆGì◊∑&˜fñFW#¶6∆VÊF%&˜fñFW"Áf«VR∆Ê÷S¶6∆VÊF$ñÁFVw&Fñˆ‰Ê÷RÁf«VRÁG&ñ“Çí∆66˜VÁEˆV÷ñ√¶6∆VÊF$ñÁFVw&Fñˆ‰V÷ñ¬Áf«VRÁG&ñ“Çí¿¢6∆VÊF%ˆÊ÷S¶6∆VÊF$ñÁFVw&Fñˆ‰6∆VÊF"Áf«VRÁG&ñ“Çí∆WFÖˆ÷ˆFS¶÷ˆFR«&V÷˜FUˆ6∆VÊF%ˆñC¶6∆VÊF$ñÁFVw&FñˆÂ&V÷˜FTñBÁf«VRÁG&ñ“Çí¿¢ñ75˜W&√¶6∆VÊF$ñÁFVw&Fñˆ‰ñ72Áf«VRÁG&ñ“Çí∆6∆ñVÁEˆñC¶6∆VÊF$ñÁFVw&Fñˆ‰6∆ñVÁDñBÁf«VRÁG&ñ“Çí∆6∆ñVÁE˜6V7&WC¶6∆VÊF$ñÁFVw&Fñˆ‰6∆ñVÁE6V7&WBÁf«VR¿¢WFÖ˜W6W&Ê÷S¶6∆VÊF$ñÁFVw&Fñˆ‰&6ñ5W6W"Áf«VRÁG&ñ“Çí∆WFÖ˜77v˜&C¶6∆VÊF$ñÁFVw&Fñˆ‰&6ñ577v˜&BÁf«VR¿¢VÊ&∆VCßG'VR«7ñÊ5ˆñÁFW'f≈ˆ÷ñÁWFW3§ÁV÷&W"Ü6∆VÊF$ñÁFVw&Fñˆ‰ñÁFW'f¬Áf«VW«√3ó”∞¢G'ó∞¢6ˆÁ7B&W7V«C÷vóBß6ˆ‚Çrˆí˜cˆ6∆VÊF"ˆñÁFVw&FñˆÁ2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∞¢6∆VÊF$ñÁFVw&Fñˆ‰ñ72Áf«VS“rs∂6∆VÊF$ñÁFVw&Fñˆ‰6∆ñVÁE6V7&WBÁf«VS“rs∂6∆VÊF$ñÁFVw&Fñˆ‰Ê÷RÁf«VS“rs∂6∆VÊF$ñÁFVw&Fñˆ‰6∆VÊF"Áf«VS“rs∞¢vóB∆ˆD6∆VÊF"Çì∞¢ñbá&W7V«BÊÊVVG5ˆWFÜ˜&ó¶Fñˆ‚ñvóB6ˆÊÊV7D6∆VÊF$ñÁFVw&Fñˆ‚á&W7V«BÊñBì∞¢V«6RvóB7ñÊ46∆VÊF$ñÁFVw&Fñˆ‚á&W7V«BÊñBì∞¢÷6F6ÇÜW'"ó∂6∆VÊF$ñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6fR6∆VÊF"ñÁFVw&Fñˆ„¢r∂W'"Ê÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚6ˆÊÊV7D6∆VÊF$ñÁFVw&Fñˆ‚ÜñBó∞¢G'ó∞¢6ˆÁ7B&W7V«C÷vóBß6ˆ‚Çrˆí˜cˆ6∆VÊF"ˆñÁFVw&FñˆÁ2Úr∂ñB≤rˆˆWFÇ˜7F'Br«∂÷WFÜˆC¢uı5Bw“ì∞¢6ˆÁ7B˜W◊vñÊF˜rÊ˜V‚á&W7V«BÊWFÜ˜&ó¶FñˆÂ˜W&¬¬vvˆG6WñT6∆VÊF$ÙWFÇr¬wvñGFÉ”c#∆ÜVñváC”sc«&W6ó¶&∆S◊ñW2«67&ˆ∆∆&'3◊ñW2rì∞¢ñbÇ˜WóFá&˜rÊWrW'&˜"Çt'&˜w6W"&∆ˆ6∂VBFÜRWFÜ˜&ó¶Fñˆ‚vñÊF˜rrì∞¢÷6F6ÇÜW'"ó∂∆W'BÇt6˜V∆BÊ˜B7F'B6∆VÊF"WFÜ˜&ó¶Fñˆ„¢r∂W'"Ê÷W76vRó–ß–ßvñÊF˜rÊFDWfVÁD∆ó7FVÊW"Çv÷W76vRr∆7ñÊ2WfVÁC”Á∞¢ñbÜWfVÁBÊ˜&ñvñ‚”◊vñÊF˜rÊ∆ˆ6Fñˆ‚Ê˜&ñvñÁ«∆WfVÁBÊFFÚÁGóR”“vvˆG6WñR÷6∆VÊF"÷6ˆÊÊV7FVBró&WGW&„∞¢vóB∆ˆD6∆VÊF"Çì∞¢&VÊFW$6∆VÊF$ñÁFVw&FñˆÁ2Çì∞ß“ì∞¶7ñÊ2gVÊ7Fñˆ‚7ñÊ46∆VÊF$ñÁFVw&Fñˆ‚ÜñBó∞¢G'ó∞¢vóBß6ˆ‚Çrˆí˜cˆ6∆VÊF"ˆñÁFVw&FñˆÁ2Úr∂ñB≤r˜7ñÊ2r«∂÷WFÜˆC¢uı5Bw“ì∞¢vóB∆ˆD6∆VÊF"Çì∞¢÷6F6ÇÜW'"ó∂∆W'BÇt6∆VÊF"7ñÊ2fñ∆VC¢r∂W'"Ê÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚&V÷˜fT6∆VÊF$ñÁFVw&Fñˆ‚ÜñBó∞¢ñbÇ6ˆÊfó&“Çu&V÷˜fRFÜó26∆VÊF"ñÁFVw&Fñˆ‚ÊBóG27ñÊ6á&ˆÊó¶VBˆñÁF÷VÁG3Úríó&WGW&„∞¢vóBß6ˆ‚Çrˆí˜cˆ6∆VÊF"ˆñÁFVw&FñˆÁ2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆD6∆VÊF"Çì∞ß–¶gVÊ7Fñˆ‚&VÊFW$6∆VÊF$ñÁFVw&FñˆÁ2Çó∞¢6ˆÁ7B&ˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆VÊF$ñÁFVw&Fñˆ‰∆ó7Brì∂ñbÇ&ˆ˜Bó&WGW&„∞¢&ˆ˜BÊñÊÊW$ÖD‘√‘4ƒT‰D%ÙîÂDTu$DîÙÂ2Ê∆VÊwFÉÙ4ƒT‰D%ÙîÂDTu$DîÙÂ2Ê÷Üì”Á∞¢6ˆÁ7BˆWFÉ÷íÊWFÖˆ÷ˆFS””“vˆWFÇs∞¢6ˆÁ7B&˜fñFW#÷íÁ&˜fñFW#””“vvˆˆv∆RsÚtvˆˆv∆R6∆VÊF"s¢t÷ñ7&˜6ˆgB3cRÚ˜WF∆ˆˆ≤s∞¢6ˆÁ7B7FGW3÷ˆWFÉÚÜíÊ6ˆÊÊV7FVCÚuGvÚ◊ví6ˆÊÊV7FVBs¢tWFÜ˜&ó¶Fñˆ‚&WVó&VBrì¢tî52&VB÷ˆÊ«ís∞¢&WGW&‚∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚◊&˜r#‡¢«7‚6∆73“&6∆VÊF"◊&˜fñFW"÷ñ6ˆ‚#‚G∂íÁ&˜fñFW#””“vvˆˆv∆RsÚtrs¢t“w”¬˜7„‡¢∆Fóc„∆#‚G∂W62ÜíÊÊ÷Ró”¬ˆ#„«6÷∆√‚G∑&˜fñFW'“+rG∑7FGW7“+rG∂W62ÜíÊ6∆VÊF%ˆÊ÷W«∆íÊ66˜VÁEˆV÷ñ««∆íÁ&V÷˜FUˆ6∆VÊF%ˆñG«¬t6∆VÊF"ró“G∂íÊ∆7E˜7ñÊ5ˆCÚr+rr∂ÊWrFFRÜíÊ∆7E˜7ñÊ5ˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì¢rw”¬˜6÷∆√„¬ˆFóc‡¢∆Fób6∆73“&7FñˆÁ2F÷ñ‚÷ˆÊ«í#‚G∂ˆWFÇbbíÊ6ˆÊÊV7FVCˆ∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“&6ˆÊÊV7D6∆VÊF$ñÁFVw&Fñˆ‚ÇG∂íÊñG“í#‰6ˆÊÊV7C¬ˆ'WGFˆ„Ê¢rw”∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'7ñÊ46∆VÊF$ñÁFVw&Fñˆ‚ÇG∂íÊñG“í#Â7ñÊ3¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&FÊvW""ˆÊ6∆ñ6≥“'&V÷˜fT6∆VÊF$ñÁFVw&Fñˆ‚ÇG∂íÊñG“í#Â&V÷˜fS¬ˆ'WGFˆ„„¬ˆFóc‡¢¬ˆFócÊ∞¢“íÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚWáFW&Ê¬6∆VÊF"ñÁFVw&FñˆÁ26ˆÊfñwW&VB„¬ˆFóc‚s∞ß–†¶∆WBT‘î≈ÙîÂDTu$DîÙÂ3’µ”∞¶∆WBT‘î≈ÙdÙƒDU%3’µ”∞¶∆WBT‘î≈Ù‘U54tU3’µ”∞¶∆WBT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ„÷ÁV∆√∞¶∆WBT‘î≈ı4TƒT5DTEÙdÙƒDU#÷ÁV∆√∞¶∆WBT‘î≈ı4TƒT5DTEÙ‘U54tS÷ÁV∆√∞¶∆WBT‘î≈ıTî4µÙ5DîÙ„◊∂ñC¶ÁV∆¬∆7Fñˆ„¶ÁV∆«”∞†¶gVÊ7Fñˆ‚V÷ñ≈7∆óDFG&W76W2áf«VRó∞¢&WGW&‚7G&ñÊráf«VW«¬rríÁ7∆óBÇı≥≤≈“ÚíÊ÷áÉ”ÁÇÁG&ñ“ÇííÊfñ«FW"Ñ&ˆˆ∆V‚ì∞ß–¶gVÊ7Fñˆ‚V÷ñƒ6ˆÊÊV7FVDñÁFVw&FñˆÁ2Çó∞¢&WGW&‚T‘î≈ÙîÂDTu$DîÙÂ2Êfñ«FW"áÉ”ÁÇÊ6ˆÊÊV7FVBì∞ß–¶gVÊ7Fñˆ‚&VÊFW$V÷ñƒ66˜VÁD6&G2Çó∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒ66˜VÁD6&G2rì∂ñbÇV¬ó&WGW&„∂6ˆÁ7BóFV◊3‘T‘î≈ÙîÂDTu$DîÙÂ7«≈µ”∂6ˆÁ7B'ï&˜fñFW#◊”ÊóFV◊2ÊfñÊBáÉ”ÁÇÁ&˜fñFW#””◊ì∂6ˆÁ7B6&C“á∆∆&V¬∆∆ˆvÚ∆6«3“rrì”Á∂6ˆÁ7BÉ÷'ï&˜fñFW"áì∑&WGW&‚∆'WGFˆ‚6∆73“'cC3÷V÷ñ¬÷66˜VÁB÷6&B"ˆÊ6∆ñ6≥“"G∑Éˆ6V∆V7DV÷ñƒ66˜VÁBÇrG∑ÇÊñG“rì∂∆ˆDV÷ñ¬Çñ¢v˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çíw“#„«7‚6∆73“'cC3÷÷ñ¬÷∆ˆvÚG∂6«7“#‚G∂∆ˆv˜”¬˜7„„∆Fóc„∆#‚G∂∆&V«”¬ˆ#„«6÷∆√‚G∂W62áÉÚÊ66˜VÁEˆV÷ñ«««ÉÚÊÊ÷W«¬t6ˆÊÊV7B66˜VÁBró”¬˜6÷∆√„∆ì‚G∑ÉÚáÇÊ6ˆÊÊV7FVCÚ~)xÚ6ˆÊÊV7FVBs¢~)x≤WFÜ˜&ó¶Fñˆ‚&WVó&VBrì¢~˚»≤FB66˜VÁBw”¬ˆì„¬ˆFóc„∆V”Ó(£¬ˆV”„¬ˆ'WGFˆ„Ê”∂V¬ÊñÊÊW$ÖD‘√÷6&BÇvv÷ñ¬r¬tv÷ñ¬r¬trrí∂6&BÇv÷ñ7&˜6ˆgC3cRr¬t÷ñ7&˜6ˆgB3cRr¬tÚr¬v◊2rí∂∆'WGFˆ‚6∆73“'cC3÷V÷ñ¬÷66˜VÁB÷6&B&V∆í"ˆÊ6∆ñ6≥“&˜V‰6&EvRÇvñÁFVw&FñˆÁ2rí#„«7‚6∆73“'cC3÷÷ñ¬÷∆ˆvÚ#Ó)»ì¬˜7„„∆Fóc„∆#Â4’E&V∆ì¬ˆ#„«6÷∆√‰∆W'BFV∆ófW'ì¬˜6÷∆√„∆ì‰6ˆÊfñwW&Rñ‚ñÁFVw&FñˆÁ3¬ˆì„¬ˆFóc„∆V”Ó(£¬ˆV”„¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'cC3÷V÷ñ¬÷66˜VÁB÷6&B&V∆í"ˆÊ6∆ñ6≥“&˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çí#„«7‚6∆73“'cC3÷÷ñ¬÷∆ˆvÚ#Ó)©ì¬˜7„„∆Fóc„∆#‰66˜VÁB6WGFñÊw3¬ˆ#„«6÷∆√‰÷ÊvR6ˆÊÊV7FVB÷ñ∆&˜ÜW3¬˜6÷∆√„∆ì‚G∂óFV◊2Ê∆VÊwFá“6ˆÊfñwW&VC¬ˆì„¬ˆFóc„∆V”Ó(£¬ˆV”„¬ˆ'WGFˆ„Ê–¶gVÊ7Fñˆ‚&VÊFW$V÷ñƒ66˜VÁE6V∆V7G2Çó∞¢6ˆÁ7B6ˆÊÊV7FVC÷V÷ñƒ6ˆÊÊV7FVDñÁFVw&FñˆÁ2Çì∞¢6ˆÁ7B˜FñˆÁ3÷6ˆÊÊV7FVBÊ÷áÉ”Ê∆˜Fñˆ‚f«VS“"G∑ÇÊñG“#‚G∂W62áÇÊÊ÷Ró“+rG∑ÇÁ&˜fñFW#””“vv÷ñ¬sÚtv÷ñ¬s¢t÷ñ7&˜6ˆgB3cRw”¬ˆ˜Fñˆ„ÊíÊ¶ˆñ‚Çrrì∞¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒ66˜VÁE6V∆V7Brí∆Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒ6ˆ◊˜6T66˜VÁBrí∆Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñ≈&W˜'D66˜VÁBrï“Êf˜$V6ÇÜV√”Á∞¢ñbÇV¬ó&WGW&„∞¢6ˆÁ7B7W'&VÁC÷V¬Áf«VS∞¢V¬ÊñÊÊW$ÖD‘√÷˜FñˆÁ7«¬s∆˜Fñˆ‚f«VS“"#‰ÊÚ6ˆÊÊV7FVB÷ñ∆&˜É¬ˆ˜Fñˆ„‚s∞¢ñbÜ7W'&VÁBbf6ˆÊÊV7FVBÁ6ˆ÷RáÉ”Â7G&ñÊráÇÊñBì””’7G&ñÊrÜ7W'&VÁBííñV¬Áf«VS÷7W'&VÁC∞¢V«6RñbÑT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚ñV¬Áf«VS’7G&ñÊrÑT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚ì∞¢“ì∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDV÷ñ¬Çó∞¢G'ó∞¢T‘î≈ÙîÂDTu$DîÙÂ3÷vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆñÁFVw&FñˆÁ2rì∞¢&VÊFW$V÷ñƒñÁFVw&FñˆÁ2Çì∞¢&VÊFW$V÷ñƒ66˜VÁE6V∆V7G2Çì∞¢&VÊFW$V÷ñƒ66˜VÁD6&G2Çì∞¢6ˆÁ7B6ˆÊÊV7FVC÷V÷ñƒ6ˆÊÊV7FVDñÁFVw&FñˆÁ2Çì∞¢ñbÇ6ˆÊÊV7FVBÊ∆VÊwFÇó∞¢T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ„÷ÁV∆√¥T‘î≈ı4TƒT5DTEÙdÙƒDU#÷ÁV∆√¥T‘î≈Ù‘U54tU3’µ”∞¢V÷ñƒfˆ∆FW$∆ó7BÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰ÊÚ6ˆÊÊV7FVB÷ñ¬66˜VÁB‚W6R÷ñ¬66˜VÁG2FÚ6ˆÊÊV7Bv÷ñ¬˜"÷ñ7&˜6ˆgB3cR„¬ˆFóc‚s∞¢V÷ñƒ÷W76vT∆ó7BÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰ÊÚ÷ñ∆&˜Ç6ˆÊÊV7FVB„¬ˆFóc‚s∞¢V÷ñƒ∆ó7D÷WFÁFWáD6ˆÁFVÁC“tÊÚ÷ñ∆&˜Ç6V∆V7FVB‚s∞¢V÷ñ≈&VFW%ÊRÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V÷ñ¬◊&VFW"÷V◊Gí#„∆Fób6∆73“&V÷ñ¬◊&VFW"÷V◊Gí÷ñ6ˆ‚#Ó)»ì¬ˆFóc„∆#‰6ˆÊÊV7B÷ñ¬66˜VÁC¬ˆ#„«7„‰v÷ñ¬ÊB÷ñ7&˜6ˆgB3cR&R7W˜'FVBFá&˜VvÇÙWFÇ„¬˜7„„¬ˆFóc‚s∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∑&WGW&„∞¢–¢ñbÇT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙÁ«¬6ˆÊÊV7FVBÁ6ˆ÷RáÉ”ÁÇÊñC””‘T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚íîT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ„÷6ˆÊÊV7FVE≥“ÊñC∞¢V÷ñƒ66˜VÁE6V∆V7BÁf«VS’7G&ñÊrÑT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚ì∞¢vóB∆ˆDV÷ñƒfˆ∆FW'2Çì∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞¢÷6F6ÇÜRó∞¢V÷ñƒfˆ∆FW$∆ó7BÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰V÷ñ¬VÊfñ∆&∆S¢r∂W62ÜRÊ÷W76vRí≤s¬ˆFóc‚s∞¢–ß–¶7ñÊ2gVÊ7Fñˆ‚6V∆V7DV÷ñƒ66˜VÁBáf«VRó∞¢T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ„‘ÁV÷&W"áf«VRó«∆ÁV∆√¥T‘î≈ı4TƒT5DTEÙdÙƒDU#÷ÁV∆√¥T‘î≈ı4TƒT5DTEÙ‘U54tS÷ÁV∆√∞¢vóB∆ˆDV÷ñƒfˆ∆FW'2Çì∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDV÷ñƒfˆ∆FW'2Çó∞¢ñbÇT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚ó&WGW&„∞¢T‘î≈ÙdÙƒDU%3÷vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆfˆ∆FW'3ˆñÁFVw&FñˆÂˆñC“r¥T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚ì∞¢6ˆÁ7BñÊ&˜É‘T‘î≈ÙdÙƒDU%2ÊfñÊBáÉ”Â7G&ñÊráÇÊÊ÷W«¬rríÁFÙ∆˜vW$66RÇì””“vñÊ&˜Çw«≈7G&ñÊráÇÊñG«¬rríÁFÙ∆˜vW$66RÇì””“vñÊ&˜Çrì∞¢ñbÇT‘î≈ı4TƒT5DTEÙdÙƒDU'«¬T‘î≈ÙdÙƒDU%2Á6ˆ÷RáÉ”Â7G&ñÊráÇÊñBì””’7G&ñÊrÑT‘î≈ı4TƒT5DTEÙdÙƒDU"ííîT‘î≈ı4TƒT5DTEÙdÙƒDU#÷ñÊ&˜ÉÚÊñG«ƒT‘î≈ÙdÙƒDU%5≥”ÚÊñG«¬vñÊ&˜Çs∞¢&VÊFW$V÷ñƒfˆ∆FW'2Çì∞¢vóB∆ˆDV÷ñƒ÷W76vW2Çì∞ß–¶gVÊ7Fñˆ‚&VÊFW$V÷ñƒfˆ∆FW'2Çó∞¢V÷ñƒfˆ∆FW$∆ó7BÊñÊÊW$ÖD‘√‘T‘î≈ÙdÙƒDU%2Ê∆VÊwFÉÙT‘î≈ÙdÙƒDU%2Ê÷Üc”Ê∆'WGFˆ‚6∆73“&V÷ñ¬÷fˆ∆FW"÷'F‚Gµ7G&ñÊrÜbÊñBì””’7G&ñÊrÑT‘î≈ı4TƒT5DTEÙdÙƒDU"ìÚv7FófRs¢rw“"ˆÊ6∆ñ6≥“'6V∆V7DV÷ñƒfˆ∆FW"ÇrG∂W62Ö7G&ñÊrÜbÊñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“rí#„«7„‚G∂W62ÜbÊÊ÷W«∆bÊñBó”¬˜7„„«7‚6∆73“&V÷ñ¬÷fˆ∆FW"÷6˜VÁB#‚G¥ÁV÷&W"ÜbÁVÁ&VG«√ó”¬˜7„„¬ˆ'WGFˆ„ÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚ÷ñ¬fˆ∆FW'2&WGW&ÊVB„¬ˆFóc‚s∞ß–¶7ñÊ2gVÊ7Fñˆ‚6V∆V7DV÷ñƒfˆ∆FW"Üfˆ∆FW"ó∞¢T‘î≈ı4TƒT5DTEÙdÙƒDU#÷fˆ∆FW#¥T‘î≈ı4TƒT5DTEÙ‘U54tS÷ÁV∆√∑&VÊFW$V÷ñƒfˆ∆FW'2Çì∂vóB∆ˆDV÷ñƒ÷W76vW2Çì∞ß–¶gVÊ7Fñˆ‚V÷ñƒFFT∆&V¬áf«VRó∞¢ñbÇf«VRó&WGW&‚rs∞¢6ˆÁ7BC÷ÊWrFFRáf«VRì∞¢&WGW&‚ÁV÷&W"Êó4Ê‚ÜBÊvWEFñ÷RÇíì˜f«VS¶BÁFÙ∆ˆ6∆U7G&ñÊrÇì∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDV÷ñƒ÷W76vW2Çó∞¢ñbÇT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙÁ«¬T‘î≈ı4TƒT5DTEÙdÙƒDU"ó&WGW&„∞¢6ˆÁ7B“ÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñ≈6V&6ÇrìÚÁf«VW«¬rríÁG&ñ“Çì∞¢V÷ñƒ∆ó7D÷WFÁFWáD6ˆÁFVÁC“t∆ˆFñÊr÷W76vW>(
bs∞¢G'ó∞¢6ˆÁ7BFF÷vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆ÷W76vW3ˆñÁFVw&FñˆÂˆñC“r¥T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚≤rffˆ∆FW#“r∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÑT‘î≈ı4TƒT5DTEÙdÙƒDU"í≤rg“r∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBáíì∞¢T‘î≈Ù‘U54tU3÷FFÊ÷W76vW7«≈µ”∞¢6ˆÁ7Bfˆ∆FW#‘T‘î≈ÙdÙƒDU%2ÊfñÊBáÉ”Â7G&ñÊráÇÊñBì””’7G&ñÊrÑT‘î≈ı4TƒT5DTEÙdÙƒDU"íì∞¢V÷ñƒ∆ó7D÷WFÁFWáD6ˆÁFVÁC“Üfˆ∆FW#ÚÊÊ÷W«¬t÷ñ∆&˜Çrí≤r+rr¥T‘î≈Ù‘U54tU2Ê∆VÊwFÇ≤r÷W76vRr≤ÑT‘î≈Ù‘U54tU2Ê∆VÊwFÉ”””Úrs¢w2rí≤áÚr+r6V&6É¢r∑¢rrì∞¢V÷ñƒ÷W76vT∆ó7BÊñÊÊW$ÖD‘√‘T‘î≈Ù‘U54tU2Ê∆VÊwFÉÙT‘î≈Ù‘U54tU2Ê÷Ü””Ê∆Fób6∆73“&V÷ñ¬÷÷W76vR◊&˜rG∂“Êó5˜&VCÚrs¢wVÁ&VBw“G¥T‘î≈ı4TƒT5DTEÙ‘U54tS””÷“ÊñCÚv7FófRs¢rw“"ˆÊ6∆ñ6≥“&˜V‰V÷ñƒ÷W76vRÇrG∂W62Ö7G&ñÊrÜ“ÊñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“rí#‡¢∆'WGFˆ‚6∆73“&V÷ñ¬÷÷W76vR◊7F"G∂“Á7F'&VCÚw7F'&VBs¢rw“˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∑Fˆvv∆TV÷ñ≈7F"ÇrG∂W62Ö7G&ñÊrÜ“ÊñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“r¬G∂“Á7F'&VCÚvf«6Rs¢wG'VRw“í"FóF∆S“"G∂“Á7F'&VCÚuVÁ7F"s¢u7F"w“#‚G∂“Á7F'&VCÚ~)àRs¢~)àbw”¬ˆ'WGFˆ„‡¢∆Fóc„∆Fób6∆73“&V÷ñ¬÷÷W76vR÷g&ˆ“#„«7„‚G∂W62Ü“Êg&ˆ◊«¬uVÊ∂Ê˜v‚6VÊFW"ró”¬˜7„„«7‚6∆73“&V÷ñ¬÷÷W76vR÷FFR#‚G∂W62ÜV÷ñƒFFT∆&V¬Ü“ÊFFRíó”¬˜7„„¬ˆFóc„∆Fób6∆73“&V÷ñ¬÷÷W76vR◊7V&¶V7B#‚G∂W62Ü“Á7V&¶V7G«¬rÑÊÚ7V&¶V7Bíró”¬ˆFóc„∆Fób6∆73“&V÷ñ¬÷÷W76vR◊6ÊóWB#‚G∂“ÊÜ5ˆGF6Ü÷VÁG3Ú	˘8‚s¢rw“G∂W62Ü“Á6ÊóWG«¬rró”¬ˆFóc„¬ˆFóc‡¢¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚ÷W76vW2ñ‚FÜó2fˆ∆FW"„¬ˆFóc‚s∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞¢÷6F6ÇÜRó∞¢V÷ñƒ∆ó7D÷WFÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B∆ˆB÷W76vW2s∞¢V÷ñƒ÷W76vT∆ó7BÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‚r∂W62ÜRÊ÷W76vRí≤s¬ˆFóc‚s∞¢–ß–¶7ñÊ2gVÊ7Fñˆ‚˜V‰V÷ñƒ÷W76vRÜñBó∞¢T‘î≈ı4TƒT5DTEÙ‘U54tS÷ñC∂vóB∆ˆDV÷ñƒ÷W76vW2Çì∞¢G'ó∞¢6ˆÁ7B”÷vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆ÷W76vW2Úr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜñBí≤sˆñÁFVw&FñˆÂˆñC“r¥T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚ì∞¢6ˆÁ7BGF6Ü÷VÁG3“Ü“ÊGF6Ü÷VÁG7«≈µ“íÊ÷Ü”Ê∆6∆73“&V÷ñ¬÷GF6Ü÷VÁB÷6Üó"á&Vc“"ˆí˜cˆV÷ñ¬ˆ÷W76vW2ÚG∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜñBó“ˆGF6Ü÷VÁG2ÚG∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜÊñBó”ˆñÁFVw&FñˆÂˆñC“G¥T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙÁ“#Ô	˘8‚G∂W62ÜÊÊ÷W«¬tGF6Ü÷VÁBró“G∂Á6ó¶SˆÇG¥÷FÇÊ6Vñ¬ÜÁ6ó¶RÛ#Bó“¥"ñ¢rw”¬ˆÊíÊ¶ˆñ‚Çrrì∞¢V÷ñ≈&VFW%ÊRÊñÊÊW$ÖD‘√÷∆Fób6∆73“&V÷ñ¬◊&VFW"#‡¢∆Fób6∆73“&V÷ñ¬◊&VFW"÷ÜVB#„∆Fób6∆73“&V÷ñ¬◊&VFW"◊FóF∆R#„∆É#‚G∂W62Ü“Á7V&¶V7G«¬rÑÊÚ7V&¶V7Bíró”¬ˆÉ#„∆Fób6∆73“&V÷ñ¬◊&VFW"÷÷WF#„∆#‰g&ˆ”£¬ˆ#‚G∂W62Ü“Êg&ˆ◊«¬rró”∆'#„∆#ÂFÛ£¬ˆ#‚G∂W62Ü“ÁF˜«¬rró“G∂“Ê63Ús∆'#„∆#‰43£¬ˆ#‚r∂W62Ü“Ê62ì¢rw”∆'#‚G∂W62ÜV÷ñƒFFT∆&V¬Ü“ÊFFRíó”¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&V÷ñ¬◊&VFW"÷7FñˆÁ2˜W&FR÷ˆÊ«í#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&˜V‰V÷ñ≈Vñ6¥7Fñˆ‚Çw&W«ír¬rG∂W62Ö7G&ñÊrÜñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“rí#Â&W«ì¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&˜V‰V÷ñ≈Vñ6¥7Fñˆ‚Çw&W«í÷∆¬r¬rG∂W62Ö7G&ñÊrÜñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“rí#Â&W«í∆√¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&˜V‰V÷ñ≈Vñ6¥7Fñˆ‚Çvf˜'v&Br¬rG∂W62Ö7G&ñÊrÜñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“rí#‰f˜'v&C¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'6WDV÷ñ≈&VE7FFRÇrG∂W62Ö7G&ñÊrÜñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“r¬G∂“Êó5˜&VCÚvf«6Rs¢wG'VRw“í#‚G∂“Êó5˜&VCÚt÷&≤VÁ&VBs¢t÷&≤&VBw”¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'Fˆvv∆TV÷ñ≈7F"ÇrG∂W62Ö7G&ñÊrÜñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“r¬G∂“Á7F'&VCÚvf«6Rs¢wG'VRw“í#‚G∂“Á7F'&VCÚuVÁ7F"s¢u7F"w”¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&FÊvW""ˆÊ6∆ñ6≥“'G&6ÑV÷ñƒ÷W76vRÇrG∂W62Ö7G&ñÊrÜñBííÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“rí#ÂG&6É¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‡¢«&R6∆73“&V÷ñ¬◊&VFW"÷&ˆGí#‚G∂W62Ü“Ê&ˆGó«∆“Á6ÊóWG«¬rró”¬˜&S‡¢G∂GF6Ü÷VÁG3Ús∆Fób6∆73“&V÷ñ¬÷GF6Ü÷VÁG2#‚r∂GF6Ü÷VÁG2≤s¬ˆFóc‚s¢rw–¢¬ˆFócÊ∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞¢÷6F6ÇÜRó∂V÷ñ≈&VFW%ÊRÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V÷ñ¬◊&VFW"÷V◊Gí#„∆#‰6˜V∆BÊ˜B˜V‚÷W76vS¬ˆ#„«7„‚r∂W62ÜRÊ÷W76vRí≤s¬˜7„„¬ˆFóc‚w–ß–¶7ñÊ2gVÊ7Fñˆ‚6WDV÷ñ≈&VE7FFRÜñB∆ó5&VBó∞¢G'ó∂vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆ÷W76vW2Úr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜñBí≤r˜7FFRr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂ñÁFVw&FñˆÂˆñC§T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚∆ó5˜&VC¶ó5&VG“ó“ì∂vóB∆ˆDV÷ñƒ÷W76vW2Çì∂ñbÑT‘î≈ı4TƒT5DTEÙ‘U54tS””÷ñBñvóB˜V‰V÷ñƒ÷W76vRÜñBó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚Fˆvv∆TV÷ñ≈7F"ÜñB«7F'&VBó∞¢G'ó∂vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆ÷W76vW2Úr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜñBí≤r˜7FFRr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂ñÁFVw&FñˆÂˆñC§T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚«7F'&VG“ó“ì∂vóB∆ˆDV÷ñƒ÷W76vW2Çì∂ñbÑT‘î≈ı4TƒT5DTEÙ‘U54tS””÷ñBñvóB˜V‰V÷ñƒ÷W76vRÜñBó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚G&6ÑV÷ñƒ÷W76vRÜñBó∞¢ñbÇ6ˆÊfó&“Çt÷˜fRFÜó2÷W76vRFÚG&6ÇÚFV∆WFVBóFV◊3Úríó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆ÷W76vW2Úr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜñBí≤r˜G&6Çr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂ñÁFVw&FñˆÂˆñC§T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙÁ“ó“ì¥T‘î≈ı4TƒT5DTEÙ‘U54tS÷ÁV∆√∂V÷ñ≈&VFW%ÊRÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V÷ñ¬◊&VFW"÷V◊Gí#„∆Fób6∆73“&V÷ñ¬◊&VFW"÷V◊Gí÷ñ6ˆ‚#Ó)»ì¬ˆFóc„∆#‰÷W76vR÷˜fVBFÚG&6É¬ˆ#„¬ˆFóc‚s∂vóB∆ˆDV÷ñƒfˆ∆FW'2Çó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó–ß–¶gVÊ7Fñˆ‚˜V‰V÷ñ≈Vñ6¥7Fñˆ‚Ü7Fñˆ‚∆ñBó∞¢T‘î≈ıTî4µÙ5DîÙ„◊∂7Fñˆ‚∆ñG”∞¢V÷ñ≈Vñ6¥7FñˆÂFóF∆RÁFWáD6ˆÁFVÁC÷7Fñˆ„””“w&W«ísÚu&W«ís¶7Fñˆ„””“w&W«í÷∆¬sÚu&W«í∆¬s¢tf˜'v&Bs∞¢V÷ñ≈Vñ6¥7FñˆÂ7V'FóF∆RÁFWáD6ˆÁFVÁC÷7Fñˆ„””“vf˜'v&BsÚtVÁFW"&V6óñVÁBÊB÷W76vR‚s¢uw&óFRñ˜W"&W7ˆÁ6R‚s∞¢V÷ñ≈Vñ6¥7FñˆÂFıw&Á7Gñ∆RÊFó7∆ì÷7Fñˆ„””“vf˜'v&BsÚvf∆WÇs¢vÊˆÊRs∞¢V÷ñ≈Vñ6¥7FñˆÂFÚÁf«VS“rs∂V÷ñ≈Vñ6¥7Fñˆ‰&ˆGíÁf«VS“rs∂V÷ñ≈Vñ6¥7Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∞¢V÷ñ≈Vñ6¥7Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∞¢6WEFñ÷V˜WBÇÇì”Ê7Fñˆ„””“vf˜'v&BsˆV÷ñ≈Vñ6¥7FñˆÂFÚÊfˆ7W2Çì¶V÷ñ≈Vñ6¥7Fñˆ‰&ˆGíÊfˆ7W2Çí√#ì∞ß–¶gVÊ7Fñˆ‚6∆˜6TV÷ñ≈Vñ6¥7Fñˆ‚Çó∂V÷ñ≈Vñ6¥7Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚6VÊDV÷ñ≈Vñ6¥7Fñˆ‚Çó∞¢6ˆÁ7B∂7Fñˆ‚∆ñG”‘T‘î≈ıTî4µÙ5DîÙ„∂ñbÇ7FñˆÁ«¬ñBó&WGW&„∞¢6ˆÁ7B&ˆGì◊∂ñÁFVw&FñˆÂˆñC§T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ‚∆&ˆGì¶V÷ñ≈Vñ6¥7Fñˆ‰&ˆGíÁf«VR«FÛ¶7Fñˆ„””“vf˜'v&BsˆV÷ñ≈7∆óDFG&W76W2ÜV÷ñ≈Vñ6¥7FñˆÂFÚÁf«VRì•µ◊”∞¢V÷ñ≈Vñ6¥7Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∞¢G'ó∂vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆ÷W76vW2Úr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜñBí≤rÚr∂7Fñˆ‚«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂6∆˜6TV÷ñ≈Vñ6¥7Fñˆ‚Çì∂vóB∆ˆDV÷ñƒ÷W76vW2Çó÷6F6ÇÜRó∂V÷ñ≈Vñ6¥7Fñˆ‰W'"ÁFWáD6ˆÁFVÁC÷RÊ÷W76vW–ß–¶gVÊ7Fñˆ‚˜V‰V÷ñƒ6ˆ◊˜6RÇó∞¢6ˆÁ7B6ˆÊÊV7FVC÷V÷ñƒ6ˆÊÊV7FVDñÁFVw&FñˆÁ2Çì∂ñbÇ6ˆÊÊV7FVBÊ∆VÊwFÇó∂∆W'BÇt6ˆÊÊV7Bv÷ñ¬˜"÷ñ7&˜6ˆgB3cR66˜VÁBfó'7B‚rì∂˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çì∑&WGW&Á–¢&VÊFW$V÷ñƒ66˜VÁE6V∆V7G2Çì∞¢V÷ñƒ6ˆ◊˜6T66˜VÁBÁf«VS’7G&ñÊrÑT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙÁ«∆6ˆÊÊV7FVE≥“ÊñBì∞¢V÷ñƒ6ˆ◊˜6UFÚÁf«VS“rs∂V÷ñƒ6ˆ◊˜6T62Áf«VS“rs∂V÷ñƒ6ˆ◊˜6T&62Áf«VS“rs∂V÷ñƒ6ˆ◊˜6U7V&¶V7BÁf«VS“rs∂V÷ñƒ6ˆ◊˜6T&ˆGíÁf«VS“rs∂V÷ñƒ6ˆ◊˜6Tfñ∆W2Áf«VS“rs∂V÷ñƒ6ˆ◊˜6TW'"ÁFWáD6ˆÁFVÁC“rs∑&VÊFW$V÷ñƒGF6Ü÷VÁD∆ó7BÇì∞¢V÷ñƒ6ˆ◊˜6T÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑6WEFñ÷V˜WBÇÇì”ÊV÷ñƒ6ˆ◊˜6UFÚÊfˆ7W2Çí√#ì∞ß–¶gVÊ7Fñˆ‚6∆˜6TV÷ñƒ6ˆ◊˜6RÇó∂V÷ñƒ6ˆ◊˜6T÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶gVÊ7Fñˆ‚&VÊFW$V÷ñƒGF6Ü÷VÁD∆ó7BÇó∞¢6ˆÁ7Bfñ∆W3’≤‚‚‚ÜV÷ñƒ6ˆ◊˜6Tfñ∆W2Êfñ∆W7«≈µ“ï”∞¢V÷ñƒGF6Ü÷VÁD∆ó7BÁFWáD6ˆÁFVÁC÷fñ∆W2Ê∆VÊwFÉˆfñ∆W2Ê÷Üc”ÊG∂bÊÊ÷W“ÇG¥÷FÇÊ6Vñ¬ÜbÁ6ó¶RÛ#Bó“¥"ñíÊ¶ˆñ‚Çr+rrì¢tÊÚGF6Ü÷VÁG26V∆V7FVB‚s∞ß–¶gVÊ7Fñˆ‚fñ∆UFÙ&6ScBÜfñ∆Ró∞¢&WGW&‚ÊWr&ˆ÷ó6RÇá&W6ˆ«fR«&V¶V7Bì”Á∂6ˆÁ7B#÷ÊWrfñ∆U&VFW"Çì∑"ÊˆÊ∆ˆC“Çì”Á&W6ˆ«fRÖ7G&ñÊrá"Á&W7V«BíÁ7∆óBÇr¬rï≥◊«¬rrì∑"ÊˆÊW'&˜#◊&V¶V7C∑"Á&VD4FFU$¬Üfñ∆Ró“ì∞ß–¶7ñÊ2gVÊ7Fñˆ‚'Vñ∆DV÷ñƒ6ˆ◊˜6Uñ∆ˆBÇó∞¢6ˆÁ7Bfñ∆W3’≤‚‚‚ÜV÷ñƒ6ˆ◊˜6Tfñ∆W2Êfñ∆W7«≈µ“ï”∞¢6ˆÁ7BGF6Ü÷VÁG3’µ”∞¢f˜"Ü6ˆÁ7Bfñ∆Rˆbfñ∆W2Á6∆ñ6RÉ√#íñGF6Ü÷VÁG2ÁW6Çá∂Ê÷S¶fñ∆RÊÊ÷R∆6ˆÁFVÁE˜GóS¶fñ∆RÁGóW«¬v∆ñ6Fñˆ‚ˆˆ7FWB◊7G&V“r∆6ˆÁFVÁEˆ#cC¶vóBfñ∆UFÙ&6ScBÜfñ∆Ró“ì∞¢&WGW&‚∂ñÁFVw&FñˆÂˆñC§ÁV÷&W"ÜV÷ñƒ6ˆ◊˜6T66˜VÁBÁf«VRí«FÛ¶V÷ñ≈7∆óDFG&W76W2ÜV÷ñƒ6ˆ◊˜6UFÚÁf«VRí∆63¶V÷ñ≈7∆óDFG&W76W2ÜV÷ñƒ6ˆ◊˜6T62Áf«VRí∆&63¶V÷ñ≈7∆óDFG&W76W2ÜV÷ñƒ6ˆ◊˜6T&62Áf«VRí«7V&¶V7C¶V÷ñƒ6ˆ◊˜6U7V&¶V7BÁf«VR∆&ˆGì¶V÷ñƒ6ˆ◊˜6T&ˆGíÁf«VR∆GF6Ü÷VÁG7”∞ß–¶7ñÊ2gVÊ7Fñˆ‚6VÊDV÷ñƒ6ˆ◊˜6RÜRó∞¢RÁ&WfVÁDFVfV«BÇì∂V÷ñƒ6ˆ◊˜6TW'"ÁFWáD6ˆÁFVÁC“rs∞¢G'ó∂6ˆÁ7B&ˆGì÷vóB'Vñ∆DV÷ñƒ6ˆ◊˜6Uñ∆ˆBÇì∂vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬˜6VÊBr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂6∆˜6TV÷ñƒ6ˆ◊˜6RÇì∂vóB∆ˆDV÷ñƒ÷W76vW2Çó÷6F6ÇÜW'"ó∂V÷ñƒ6ˆ◊˜6TW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6VÊBV÷ñ√¢r∂W'"Ê÷W76vW–¢&WGW&‚f«6S∞ß–¶7ñÊ2gVÊ7Fñˆ‚6fTV÷ñƒG&gBÇó∞¢V÷ñƒ6ˆ◊˜6TW'"ÁFWáD6ˆÁFVÁC“rs∞¢G'ó∂6ˆÁ7B&ˆGì÷vóB'Vñ∆DV÷ñƒ6ˆ◊˜6Uñ∆ˆBÇì∂vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆG&gG2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂6∆˜6TV÷ñƒ6ˆ◊˜6RÇì∂vóB∆ˆDV÷ñƒfˆ∆FW'2Çó÷6F6ÇÜW'"ó∂V÷ñƒ6ˆ◊˜6TW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6fRG&gC¢r∂W'"Ê÷W76vW–ß–¶gVÊ7Fñˆ‚6V∆V7DV÷ñ≈&˜fñFW"á&˜fñFW"ó∞¢V÷ñ≈&˜fñFW"Áf«VS“v÷ñ7&˜6ˆgC3cRs∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂FF÷V÷ñ¬◊&˜fñFW%“ríÊf˜$V6ÇáÉ”ÁÇÊ6∆74∆ó7BÁFˆvv∆RÇv7FófRr«ÇÊFF6WBÊV÷ñ≈&˜fñFW#””“v÷ñ7&˜6ˆgC3cRríì∞¢≤vV÷ñƒ÷ñ∆&˜Ö77v˜&Ew&u“Êf˜$V6ÇÜñC”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬Á7Gñ∆RÊFó7∆ì“vf∆WÇw“ì∞¢≤vV÷ñƒñ÷Ü˜7Ew&r¬vV÷ñƒñ÷˜'Ew&r¬vV÷ñ≈6◊GÜ˜7Ew&r¬vV÷ñ≈6◊G˜'Ew&u“Êf˜$V6ÇÜñC”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRw“ì∞¢6ˆÁ7BFˆvv∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒ÷ÁV≈6WGFñÊw5Fˆvv∆Rrì∂ñbáFˆvv∆Ró∑Fˆvv∆RÁ7Gñ∆RÊFó7∆ì“vñÊ∆ñÊR÷f∆WÇs∑Fˆvv∆RÁFWáD6ˆÁFVÁC“uW6R÷ÁV¬6W'fW"6WGFñÊw2s∑–¢ñbÜV÷ñƒñÁFVw&Fñˆ‰÷ˆFTÊ˜FRñV÷ñƒñÁFVw&Fñˆ‰÷ˆFTÊ˜FRÁFWáD6ˆÁFVÁC“t˜WF∆ˆˆ≤◊7Gñ∆R6WGW¢VÁFW"ñ˜W"V÷ñ¬FG&W72ÊB77v˜&Bfó'7B‚tÙE4UîRWFˆ÷Fñ6∆«íFó66˜fW'2FÜRî‘ı4’E6WGFñÊw3≤÷ÁV¬6WGFñÊw2&Rfñ∆&∆RˆÊ«íñbFó66˜fW'ífñ«2‚s∞ß–¶gVÊ7Fñˆ‚Fˆvv∆TV÷ñƒ÷ÁV≈6WGFñÊw2Çó∞¢6ˆÁ7BñG3’≤vV÷ñƒñ÷Ü˜7Ew&r¬vV÷ñƒñ÷˜'Ew&r¬vV÷ñ≈6◊GÜ˜7Ew&r¬vV÷ñ≈6◊G˜'Ew&u”∞¢6ˆÁ7B6Ü˜s÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒñ÷Ü˜7Ew&rìÚÁ7Gñ∆RÊFó7∆í”“vf∆WÇs∞¢ñG2Êf˜$V6ÇÜñC”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬Á7Gñ∆RÊFó7∆ì◊6Ü˜sÚvf∆WÇs¢vÊˆÊRw“ì∞¢6ˆÁ7BFˆvv∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒ÷ÁV≈6WGFñÊw5Fˆvv∆Rrì∂ñbáFˆvv∆RóFˆvv∆RÁFWáD6ˆÁFVÁC◊6Ü˜sÚtÜñFR÷ÁV¬6W'fW"6WGFñÊw2s¢uW6R÷ÁV¬6W'fW"6WGFñÊw2s∞ß–¶gVÊ7Fñˆ‚˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çó∂V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑6V∆V7DV÷ñ≈&˜fñFW"Çv÷ñ7&˜6ˆgC3cRrì∑&VÊFW$V÷ñƒñÁFVw&FñˆÁ2Çó–¶gVÊ7Fñˆ‚6∆˜6TV÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çó∂V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚6fTV÷ñƒñÁFVw&Fñˆ‚Çó∞¢V÷ñƒñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∞¢6ˆÁ7B&ˆGì◊∑&˜fñFW#¢vñ÷˜6◊Gr∆Ê÷S¶V÷ñƒñÁFVw&Fñˆ‰Ê÷RÁf«VRÁG&ñ“Çí∆66˜VÁEˆV÷ñ√¶V÷ñƒñÁFVw&Fñˆ‰FG&W72Áf«VRÁG&ñ“Çí∆WFÖˆ÷ˆFS¢w77v˜&Br∆6∆ñVÁEˆñC¢rr∆6∆ñVÁE˜6V7&WC¢rr«W6W&Ê÷S¶V÷ñƒñÁFVw&Fñˆ‰FG&W72Áf«VRÁG&ñ“Çí«77v˜&C¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒñÁFVw&FñˆÂ77v˜&BrìÚÁf«VW«¬rr∆ñ÷ˆÜ˜7C¢rr∆ñ÷˜˜'C£ìì2«6◊GˆÜ˜7C¢rr«6◊G˜˜'C£SÉw”∞¢G'ó∞¢6ˆÁ7B&W7V«C÷vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆñÁFVw&FñˆÁ2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∞¢V÷ñƒñÁFVw&Fñˆ‰6∆ñVÁE6V7&WBÁf«VS“rs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒñÁFVw&FñˆÂ77v˜&BríÁf«VS“rs∂V÷ñƒñÁFVw&Fñˆ‰Ê÷RÁf«VS“rs∞¢vóB∆ˆDV÷ñ¬Çì∞¢ñbá&W7V«BÊÊVVG5ˆWFÜ˜&ó¶Fñˆ‚ñvóB6ˆÊÊV7DV÷ñƒñÁFVw&Fñˆ‚á&W7V«BÊñBì∞¢÷6F6ÇÜRó∂V÷ñƒñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6fR÷ñ¬66˜VÁC¢r∂RÊ÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚6ˆÊÊV7DV÷ñƒñÁFVw&Fñˆ‚ÜñBó∞¢G'ó∂6ˆÁ7B&W7V«C÷vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆñÁFVw&FñˆÁ2Úr∂ñB≤rˆˆWFÇ˜7F'Br«∂÷WFÜˆC¢uı5Bw“ì∂6ˆÁ7B˜W◊vñÊF˜rÊ˜V‚á&W7V«BÊWFÜ˜&ó¶FñˆÂ˜W&¬¬vvˆG6WñTV÷ñƒÙWFÇr¬wvñGFÉ”c#∆ÜVñváC”sc«&W6ó¶&∆S◊ñW2«67&ˆ∆∆&'3◊ñW2rì∂ñbÇ˜WóFá&˜rÊWrW'&˜"Çt'&˜w6W"&∆ˆ6∂VBFÜRWFÜ˜&ó¶Fñˆ‚vñÊF˜rró÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B7F'B÷ñ¬WFÜ˜&ó¶Fñˆ„¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚&V÷˜fTV÷ñƒñÁFVw&Fñˆ‚ÜñBó∞¢ñbÇ6ˆÊfó&“Çu&V÷˜fRFÜó26ˆÊÊV7FVB÷ñ¬66˜VÁBg&ˆ“tÙE4UîSÚríó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬ˆñÁFVw&FñˆÁ2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂ñbÑT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ„””÷ñBó¥T‘î≈ı4TƒT5DTEÙîÂDTu$DîÙ„÷ÁV∆√¥T‘î≈ı4TƒT5DTEÙdÙƒDU#÷ÁV∆«÷vóB∆ˆDV÷ñ¬Çó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó–ß–¶gVÊ7Fñˆ‚&VÊFW$V÷ñƒñÁFVw&FñˆÁ2Çó∞¢6ˆÁ7B&ˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvV÷ñƒñÁFVw&Fñˆ‰∆ó7Brì∂ñbÇ&ˆ˜Bó&WGW&„∞¢&ˆ˜BÊñÊÊW$ÖD‘√‘T‘î≈ÙîÂDTu$DîÙÂ2Ê∆VÊwFÉÙT‘î≈ÙîÂDTu$DîÙÂ2Ê÷Üì”Ê∆Fób6∆73“&6∆VÊF"÷ñÁFVw&Fñˆ‚◊&˜r#„«7‚6∆73“&6∆VÊF"◊&˜fñFW"÷ñ6ˆ‚#‚G∂íÁ&˜fñFW#””“vv÷ñ¬sÚtrs¢t“w”¬˜7„„∆Fóc„∆#‚G∂W62ÜíÊÊ÷Ró”¬ˆ#„«6÷∆√‚G∂íÁ&˜fñFW#””“vv÷ñ¬sÚtv÷ñ¬s¢t÷ñ7&˜6ˆgB3cRw“+rG∂íÊ6ˆÊÊV7FVCÚt6ˆÊÊV7FVBs¢tWFÜ˜&ó¶Fñˆ‚&WVó&VBw“+rG∂W62ÜíÊ66˜VÁEˆV÷ñ««¬t÷ñ∆&˜Çró”¬˜6÷∆√„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2F÷ñ‚÷ˆÊ«í#‚G≤íÊ6ˆÊÊV7FVCˆ∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“&6ˆÊÊV7DV÷ñƒñÁFVw&Fñˆ‚ÇG∂íÊñG“í#‰6ˆÊÊV7C¬ˆ'WGFˆ„Ê¢rw”∆'WGFˆ‚6∆73“&FÊvW""ˆÊ6∆ñ6≥“'&V÷˜fTV÷ñƒñÁFVw&Fñˆ‚ÇG∂íÊñG“í#Â&V÷˜fS¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚ÷ñ¬66˜VÁG26ˆÊfñwW&VB„¬ˆFóc‚s∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞ß–ßvñÊF˜rÊFDWfVÁD∆ó7FVÊW"Çv÷W76vRr∆7ñÊ2WfVÁC”Á∞¢ñbÜWfVÁBÊ˜&ñvñ‚”◊vñÊF˜rÊ∆ˆ6Fñˆ‚Ê˜&ñvñÁ«∆WfVÁBÊFFÚÁGóR”“vvˆG6WñR÷V÷ñ¬÷6ˆÊÊV7FVBró&WGW&„∞¢vóB∆ˆDV÷ñ¬Çì∑&VÊFW$V÷ñƒñÁFVw&FñˆÁ2Çì∞ß“ì∞¶gVÊ7Fñˆ‚˜V‰V÷ñ≈&W˜'D÷ˆF¬ÜñB«FóF∆Ró∞¢6ˆÁ7B6ˆÊÊV7FVC÷V÷ñƒ6ˆÊÊV7FVDñÁFVw&FñˆÁ2Çì∞¢ñbÇ6ˆÊÊV7FVBÊ∆VÊwFÇó∂∆W'BÇt6ˆÊÊV7Bv÷ñ¬˜"÷ñ7&˜6ˆgB3cR66˜VÁBfó'7B‚rì∂˜V‰V÷ñƒñÁFVw&Fñˆ‰÷ˆF¬Çì∑&WGW&Á–¢&VÊFW$V÷ñƒ66˜VÁE6V∆V7G2Çì∂V÷ñ≈&W˜'DñBÁf«VS÷ñC∂V÷ñ≈&W˜'D66˜VÁBÁf«VS’7G&ñÊrÑT‘î≈ı4TƒT5DTEÙîÂDTu$DîÙÁ«∆6ˆÊÊV7FVE≥“ÊñBì∂V÷ñ≈&W˜'EFóF∆T∆&V¬ÁFWáD6ˆÁFVÁC◊FóF∆W«¬tvVÊW&FVB&W˜'Bs∞¢V÷ñ≈&W˜'EFÚÁf«VS“rs∂V÷ñ≈&W˜'E7V&¶V7BÁf«VS“ttÙE4UîR&W˜'C¢r≤áFóF∆W«¬u&W˜'Brì∂V÷ñ≈&W˜'D&ˆGíÁf«VS“tGF6ÜVBó2tÙE4UîR&W˜'B‚s∂V÷ñ≈&W˜'DW'"ÁFWáD6ˆÁFVÁC“rs∂V÷ñ≈&W˜'D÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∞ß–¶gVÊ7Fñˆ‚6∆˜6TV÷ñ≈&W˜'D÷ˆF¬Çó∂V÷ñ≈&W˜'D÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚6VÊDV÷ñ≈&W˜'BÇó∞¢V÷ñ≈&W˜'DW'"ÁFWáD6ˆÁFVÁC“rs∞¢6ˆÁ7B&ˆGì◊∂ñÁFVw&FñˆÂˆñC§ÁV÷&W"ÜV÷ñ≈&W˜'D66˜VÁBÁf«VRí«&W˜'EˆñC§ÁV÷&W"ÜV÷ñ≈&W˜'DñBÁf«VRí«FÛ¶V÷ñ≈7∆óDFG&W76W2ÜV÷ñ≈&W˜'EFÚÁf«VRí∆63•µ“«7V&¶V7C¶V÷ñ≈&W˜'E7V&¶V7BÁf«VR∆&ˆGì¶V÷ñ≈&W˜'D&ˆGíÁf«VR∆f˜&÷C¶V÷ñ≈&W˜'Df˜&÷BÁf«VW”∞¢ñbÇ&ˆGíÁFÚÊ∆VÊwFÇó∂V÷ñ≈&W˜'DW'"ÁFWáD6ˆÁFVÁC“tVÁFW"B∆V7BˆÊR&V6óñVÁB‚s∑&WGW&Á–¢G'ó∂vóBß6ˆ‚Çrˆí˜cˆV÷ñ¬˜&W˜'Br«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂6∆˜6TV÷ñ≈&W˜'D÷ˆF¬Çó÷6F6ÇÜRó∂V÷ñ≈&W˜'DW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜BV÷ñ¬&W˜'C¢r∂RÊ÷W76vW–ß–†¶∆WBtî‰Dıu5ı4ıU$4U3’µ”∞¶∆WBtî‰Dıu5ÙtTÂE3’µ”∞¶∆WBUdTÂEÙdî‰Dî‰u3’µ”∞¶∆WBDî4¥UE3’µ”∞¶∆WBDî4¥UEÙ54ît‰TU3’µ”∞¶∆WB5U%$TÂEÙUdTÂEÙdî‰Dî‰s÷ÁV∆√∞¶∆WB5U%$TÂEıDî4¥UC÷ÁV∆√∞†¶gVÊ7Fñˆ‚˜VÂvñÊF˜w4vVÁD÷ˆF¬Çó∑vñÊF˜w4vVÁD÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∂∆ˆEvñÊF˜w4vVÁG2Çì∂∆ˆEvñÊF˜w4vVÁE6∂vU7FGW2Çó–¶gVÊ7Fñˆ‚6∆˜6UvñÊF˜w4vVÁD÷ˆF¬Çó∑vñÊF˜w4vVÁD÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚∆ˆEvñÊF˜w4vVÁG2Çó∞¢G'ó∞¢tî‰Dıu5ÙtTÂE3÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2rì∞¢&VÊFW%vñÊF˜w4vVÁG2Çì∞¢6ˆÁ7BˆÊ∆ñÊS’tî‰Dıu5ÙtTÂE2Êfñ«FW"áÉ”ÁÇÁ7FGW3””“vˆÊ∆ñÊRríÊ∆VÊwFÇ∆ˆff∆ñÊS’tî‰Dıu5ÙtTÂE2Êfñ«FW"áÉ”ÁÇÁ7FGW3””“vˆff∆ñÊRríÊ∆VÊwFÉ∞¢6ˆÁ7B7V÷÷'ì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvvVÁE7V÷÷'írì∂ñbá7V÷÷'íó7V÷÷'íÁFWáD6ˆÁFVÁC÷vVÁG3¢G∂ˆÊ∆ñÊW“ˆÊ∆ñÊRG∂ˆff∆ñÊSÚr+rr∂ˆff∆ñÊR≤rˆff∆ñÊRs¢rw“+rGµtî‰Dıu5ÙtTÂE2Ê∆VÊwFá“VÁ&ˆ∆∆VF∞¢÷6F6ÇÜRóµtî‰Dıu5ÙtTÂE3’µ”∑&VÊFW%vñÊF˜w4vVÁG2Çì∂6ˆÁ7B7V÷÷'ì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvvVÁE7V÷÷'írì∂ñbá7V÷÷'íó7V÷÷'íÁFWáD6ˆÁFVÁC“tvVÁG2VÊfñ∆&∆Rw–ß–¶gVÊ7Fñˆ‚&VÊFW%vñÊF˜w4vVÁG2Çó∞¢6ˆÁ7B&ˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwvñÊF˜w4vVÁD∆ó7Brì∂ñbÇ&ˆ˜Bó&WGW&„∞¢&ˆ˜BÊñÊÊW$ÖD‘√’tî‰Dıu5ÙtTÂE2Ê∆VÊwFÉıtî‰Dıu5ÙtTÂE2Ê÷áÉ”Á∞¢6ˆÁ7BV∆√◊ÇÊ∆7E˜V∆≈˜7FGW2bgÇÊ∆7E˜V∆≈˜7FGW2”“vÊWfW"sˆ+rV∆√¢G∂W62áÇÊ∆7E˜V∆≈˜7FGW2ó“G∑ÇÊ∆7E˜V∆≈ˆ6ˆ◊∆WFVEˆCÚrr∂W62ÜÊWrFFRáÇÊ∆7E˜V∆≈ˆ6ˆ◊∆WFVEˆBíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÇíì¢rw÷¢rs∞¢6ˆÁ7BV∆ƒ'F„◊ÇÁ&Wfˆ∂VEˆCÚrs¢áÇÁV∆≈ˆÊ˜u˜7W˜'FVCˆ∆'WGFˆ‚6∆73“'&ñ÷'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“'V∆≈vñÊF˜w4vVÁDÊ˜rÇG∑ÇÊñG“í#Ó)˚2V∆¬WfVÁG2Ê˜s¬ˆ'WGFˆ„Ê¶∆'WGFˆ‚6∆73“'6V6ˆÊF'í"Fó6&∆VBFóF∆S“$ñÁ7F∆¬FÜRW&÷ÊVÁBÉcBvVÁBác"„„˜"ÊWvW"í#ÂWFFRvVÁBf˜"V∆¬Ê˜s¬ˆ'WGFˆ„Êì∞¢∆WBWFFT'F„“rs∞¢ñbÇÇÁ&Wfˆ∂VEˆBbgÇÁWFFUˆfñ∆&∆Ró∞¢WFFT'F„◊ÇÁWw&FU˜7W˜'FVCˆ∆'WGFˆ‚6∆73“'&ñ÷'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“'Ww&FUvñÊF˜w4vVÁBÇG∑ÇÊñG“í#Ó(iWw&FRFÚG∂W62áÇÊfñ∆&∆U˜fW'6ñˆ‚ó”¬ˆ'WGFˆ„Ê¶∆'WGFˆ‚6∆73“'6V6ˆÊF'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&F˜vÊ∆ˆEvñÊF˜w4vVÁE6∂vRÇí"FóF∆S“$vVÁB"„ÁÇÊVVG2ˆÊR÷ÁV¬&6V∆ñÊRWw&FS≤VÁ&ˆ∆∆÷VÁBó2&W6W'fVB‚#Ó(i2÷ÁV¬WFFRFÚG∂W62áÇÊfñ∆&∆U˜fW'6ñˆ‚ó”¬ˆ'WGFˆ„Ê∞¢÷V«6RñbÇÇÁ&Wfˆ∂VEˆBbgÇÊfñ∆&∆U˜fW'6ñˆ‚ó∑WFFT'F„÷∆'WGFˆ‚6∆73“'6V6ˆÊF'í"Fó6&∆VCÓ)…2WFÚFFS¬ˆ'WGFˆ„Ê–¢6ˆÁ7BWFFUFWáC◊ÇÊfñ∆&∆U˜fW'6ñˆ„ÚáÇÁWFFUˆfñ∆&∆Sˆ+rWFFRfñ∆&∆S¢G∂W62áÇÊfñ∆&∆U˜fW'6ñˆ‚ó“G∑ÇÁWw&FU˜7W˜'FVCÚrs¢rÜˆÊR÷ÁV¬&6V∆ñÊRWFFR&WVó&VBíw÷¶+r∆FW7C¢G∂W62áÇÊfñ∆&∆U˜fW'6ñˆ‚ó÷ì¢rs∞¢&WGW&‚∆Fób6∆73“'vñÊF˜w2÷vVÁB◊&˜r#„«7‚6∆73“'vñÊF˜w2÷vVÁB÷ñ6ˆ‚#Âs¬˜7„„∆Fóc„∆#‚G∂W62áÇÊ6ˆ◊WFW%ˆÊ÷W««ÇÊÜ˜7FÊ÷W«¬uvñÊF˜w2vVÁBró”¬ˆ#„«6÷∆√„«7‚6∆73“&vVÁB◊7FGW2G∂W62áÇÁ7FGW7«¬vVÁ&ˆ∆∆VBró“#„«7‚6∆73“&vVÁB◊7FGW2÷F˜B#„¬˜7„‚G∂W62áÇÁ7FGW7«¬vVÁ&ˆ∆∆VBró”¬˜7„‚+rG∂W62áÇÊóˆFG&W77«¬vÊÚïró“+rG∂W62áÇÊ˜5˜fW'6ñˆÁ«¬uvñÊF˜w2ró“+rvVÁBG∂W62áÇÊvVÁE˜fW'6ñˆÁ«¬~(	Bró“+rG∑ÇÊ˜VÂˆfñÊFñÊw7«√“˜V‚fñÊFñÊrá2íG∑WFFUFWáG”¬˜6÷∆√„«6÷∆√‰∆7BÜV'F&VC¢G∑ÇÊ∆7EˆÜV'F&VEˆCˆW62ÜÊWrFFRáÇÊ∆7EˆÜV'F&VEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢vÊWfW"w“+r6ÜÊÊV«3¢G≤áÇÊ6ÜÊÊV«7«≈µ“íÊ÷ÜW62íÊ¶ˆñ‚Çr¬ró“+rWfW'íG∑ÇÁˆ∆≈ˆñÁFW'f≈˜6V6ˆÊG7«√c◊2G∑V∆«“G∑ÇÊ∆7EˆW'&˜#Úr+rr∂W62áÇÊ∆7EˆW'&˜"ì¢rw”¬˜6÷∆√„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“'66‰÷ñ7&˜6ˆgEvñÊF˜w5WFFW2ÇG∑ÇÊñG“í#Â66‚÷ñ7&˜6ˆgBWFFW3¬ˆ'WGFˆ„‚G∑WFFT'FÁ“G∑V∆ƒ'FÁ“G∑ÇÁ&Wfˆ∂VEˆCˆ∆'WGFˆ‚6∆73“&FÊvW"F÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“'W&vUvñÊF˜w4vVÁBÇG∑ÇÊñG“í#Â&V÷˜fRW&÷ÊVÁF«ì¬ˆ'WGFˆ„Ê¶∆'WGFˆ‚6∆73“'6V6ˆÊF'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&6ˆÊfñwW&UvñÊF˜w4vVÁBÇG∑ÇÊñG“í#‰6ˆÊfñwW&S¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&FÊvW"F÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“'&Wfˆ∂UvñÊF˜w4vVÁBÇG∑ÇÊñG“í#Â&Wfˆ∂S¬ˆ'WGFˆ„Ê”¬ˆFóc„¬ˆFócÊ ¢“íÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚvñÊF˜w2vVÁG2VÁ&ˆ∆∆VB„¬ˆFóc‚s∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞ß–¶7ñÊ2gVÊ7Fñˆ‚66‰÷ñ7&˜6ˆgEvñÊF˜w5WFFW2ÜñBó∞¢6ˆÁ7B&˜É÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwvñÊF˜w5WFFW5&W7V«G2rì∂ñbÜ&˜Çñ&˜ÇÁFWáD6ˆÁFVÁC“u66ÊÊñÊr÷ñ7&˜6ˆgBvñÊF˜w2WFF^(
bs∞¢G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB≤r˜vñÊF˜w2◊WFFW2˜66‚r«∂÷WFÜˆC¢uı5Bw“ì∂vóBˆ∆ƒ÷ñ7&˜6ˆgEvñÊF˜w5WFFT6ˆ÷÷ÊBá"Ê6ˆ÷÷ÊEˆñB∆ñBó÷6F6ÇÜRó∂ñbÜ&˜Çñ&˜ÇÁFWáD6ˆÁFVÁC“uvñÊF˜w2WFFR66‚fñ∆VC¢r∂RÊ÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚ˆ∆ƒ÷ñ7&˜6ˆgEvñÊF˜w5WFFT6ˆ÷÷ÊBÜ6ˆ÷÷ÊDñB∆vVÁDñBó∞¢6ˆÁ7B&˜É÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwvñÊF˜w5WFFW5&W7V«G2rì∞¢f˜"Ü∆WBì”∂ì√C∂í≤≤ó∂vóBÊWr&ˆ÷ó6Rá#”Á6WEFñ÷V˜WBá"√Síì∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2ˆ6ˆ÷÷ÊG2Úr∂6ˆ÷÷ÊDñBì∞¢ñbá"Á7FGW3””“v6ˆ◊∆WFVBw««"Á7FGW3””“vfñ∆VBró∂6ˆÁ7BWFFW3◊"Á&W7V«CÚÁWFFW7«≈µ”∂ñbá"Á7FGW3””“vfñ∆VBw««"Á&W7V«CÚÊˆ≥””÷f«6Ró∂ñbÜ&˜Çñ&˜ÇÁFWáD6ˆÁFVÁC“uvñÊF˜w2WFFRfñ∆VC¢r≤á"Á&W7V«CÚÊFWFñ«7«¬vvVÁBW'&˜"rì∑&WGW&Á–¢ñbÇWFFW2Ê∆VÊwFÇó∂ñbÜ&˜Çñ&˜ÇÁFWáD6ˆÁFVÁC“t÷ñ7&˜6ˆgBvñÊF˜w2&W˜'G2ÊÚ÷ó76ñÊrWFFW2‚s∑&WGW&Á–¢ñbÜ&˜Çñ&˜ÇÊñÊÊW$ÖD‘√◊WFFW2Ê÷ÇáR∆íì”‚s∆∆&V¬7Gñ∆S“&Fó7∆ì¶&∆ˆ6≥∂÷&vñ„£gÇ#„∆ñÁWBGóS“&6ÜV6∂&˜Ç"6∆73“'vñÊF˜w2◊WFFR÷6Üˆñ6R"FF÷vVÁC“"r∂vVÁDñB≤r"f«VS“"r∂W62Ö7G&ñÊráRÊñG««RÁWFFUˆñG«¬rríí≤r#‚r∂W62áRÁFóF∆W««RÊÊ÷W««RÊ∂'«≈7G&ñÊráRÊñG«¬uvñÊF˜w2WFFRríí≤s¬ˆ∆&V√‚ríÊ¶ˆñ‚Çrrí≤s∆'WGFˆ‚6∆73“'&ñ÷'í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“&ñÁ7F∆≈6V∆V7FVD÷ñ7&˜6ˆgEWFFW2Çr∂vVÁDñB≤rí#‰ñÁ7F∆¬6V∆V7FVBWFFW3¬ˆ'WGFˆ„‚s∑&WGW&Á–¢–¢ñbÜ&˜Çñ&˜ÇÁFWáD6ˆÁFVÁC“uvñÊF˜w2WFFR66‚ó27Fñ∆¬'VÊÊñÊr‚&Vg&W6Ç6Ü˜'F«í‚s∞ß–¶7ñÊ2gVÊ7Fñˆ‚ñÁ7F∆≈6V∆V7FVD÷ñ7&˜6ˆgEWFFW2ÜvVÁDñBó∞¢6ˆÁ7BñG3’≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁvñÊF˜w2◊WFFR÷6Üˆñ6U∂FF÷vVÁC“"r∂vVÁDñB≤r%”¶6ÜV6∂VBrï“Ê÷áÉ”ÁÇÁf«VRíÊfñ«FW"Ñ&ˆˆ∆V‚ì∞¢ñbÇñG2Ê∆VÊwFÇó∂∆W'BÇu6V∆V7BB∆V7BˆÊRvñÊF˜w2WFFR‚rì∑&WGW&Á–¢G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂vVÁDñB≤r˜vñÊF˜w2◊WFFW2ˆñÁ7F∆¬r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑WFFUˆñG3¶ñG7“ó“ì∂vóBˆ∆ƒ÷ñ7&˜6ˆgEvñÊF˜w5WFFT6ˆ÷÷ÊBá"Ê6ˆ÷÷ÊEˆñB∆vVÁDñBó÷6F6ÇÜRó∂∆W'BÇuvñÊF˜w2WFFRñÁ7F∆∆Fñˆ‚fñ∆VC¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚6ÜV6µvñÊF˜w4vVÁEWFFW2Çó∞¢G'ó∞¢6ˆÁ7BñÊfÛ÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2˜WFFR÷ñÊfÚrì∂vóB∆ˆEvñÊF˜w4vVÁG2Çì∞¢6ˆÁ7BWFFW3’tî‰Dıu5ÙtTÂE2Êfñ«FW"áÉ”ÁÇÁWFFUˆfñ∆&∆Rí∆WFˆ÷Fñ3◊WFFW2Êfñ«FW"áÉ”ÁÇÁWw&FU˜7W˜'FVBí∆÷ÁV√◊WFFW2Êfñ«FW"áÉ”‚ÇÁWw&FU˜7W˜'FVBì∞¢∆W'BÜ∆FW7BvñÊF˜w2vVÁC¢G∂ñÊfÚÁfW'6ñˆÁ“‚G∑WFFW2Ê∆VÊwFá“VÁ&ˆ∆∆VBvVÁBG∑WFFW2Ê∆VÊwFÉ”””Úrs¢w2w“ÊVVB‚WFFR‚G∂WFˆ÷Fñ2Ê∆VÊwFÉÚrr∂WFˆ÷Fñ2Ê∆VÊwFÇ≤r6‚Ww&FRFó&V7F«íg&ˆ“tÙE4UîR‚s¢rw“G∂÷ÁV¬Ê∆VÊwFÉÚrr∂÷ÁV¬Ê∆VÊwFÇ≤rÊVVBFÜRˆÊR◊Fñ÷R"„„&6V∆ñÊRñÁ7F∆∆W"fó'7B‚s¢rw÷ì∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B6ÜV6≤vñÊF˜w2vVÁBWFFW3¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚Ww&FUvñÊF˜w4vVÁBÜñBó∞¢6ˆÁ7BÉ’tî‰Dıu5ÙtTÂE2ÊfñÊBÜ”ÊÊñC””÷ñBì∂ñbÇÇó&WGW&„∞¢ñbÇ6ˆÊfó&“ÜWw&FRG∑ÇÊ6ˆ◊WFW%ˆÊ÷W«¬wFÜó2vñÊF˜w2vVÁBw“g&ˆ“G∑ÇÊvVÁE˜fW'6ñˆÁ«¬wVÊ∂Ê˜v‚w“FÚG∑ÇÊfñ∆&∆U˜fW'6ñˆÁ«¬wFÜR∆FW7BfW'6ñˆ‚w”ÚVÁ&ˆ∆∆÷VÁB¬í∂Wí¬&ˆˆ∂÷&∑2¬VWVR¬ÊB6ˆÊfñwW&Fñˆ‚vñ∆¬&R&W6W'fVBÊíó&WGW&„∞¢G'ó∞¢6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB≤r˜Ww&FRr«∂÷WFÜˆC¢uı5Bw“ì∂∆W'Bá"Ê÷W76vW«¬uvñÊF˜w2vVÁBWw&FRVWVVB‚rì∂vóB∆ˆEvñÊF˜w4vVÁG2Çì∞¢6WEFñ÷V˜WBÜ∆ˆEvñÊF˜w4vVÁG2√Sì∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BWw&FRvñÊF˜w2vVÁC¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚7&VFUvñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁBÇó∞¢6ˆÁ7B∆&V√◊&ˆ◊BÇtVÁ&ˆ∆∆÷VÁB∆&V¬Üf˜"WÜ◊∆RdîƒU4U%dU#ì¢r¬uvñÊF˜w2vVÁBrì∂ñbÜ∆&V√””÷ÁV∆¬ó&WGW&„∞¢G'ó∞¢6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2ˆVÁ&ˆ∆∆÷VÁB◊Fˆ∂VÁ2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂∆&V√¶∆&V¬ÁG&ñ“Çó«¬uvñÊF˜w2vVÁBr∆Wáó&W5ˆ÷ñÁWFW3£3“ó“ì∞¢vñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁBÁ7Gñ∆RÊFó7∆ì“vw&ñBs∑vñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁEFˆ∂V‚ÁFWáD6ˆÁFVÁC◊"ÊVÁ&ˆ∆∆÷VÁE˜Fˆ∂V„∑vñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁDWáó'íÁFWáD6ˆÁFVÁC“tWáó&W2r∂ÊWrFFRá"ÊWáó&W5ˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì∞¢vñÊF˜w4vVÁDñÁ7F∆ƒ6ˆ÷÷ÊBÁFWáD6ˆÁFVÁC÷‚6∆ñ6≤F˜vÊ∆ˆBÉcBñÁ7F∆∆W"&˜fRÂ∆„"‚'V‚tÙE4UîR’vñÊF˜w2‘vVÁB◊ÉcB’6WGWÊWÜR2F÷ñÊó7G&F˜"Â∆„2‚tÙE4UîRU$√¢G∂∆ˆ6Fñˆ‚Ê˜&ñvñÁ’∆„B‚7FRFÜRˆÊR◊Fñ÷RFˆ∂V‚6Ü˜v‚&˜fRÂ∆Â∆‰WÜó7FñÊrVÁ&ˆ∆∆VBvVÁG26‚'V‚ÊWvW"6WGWfW'6ñˆÁ2vóFÜ˜WBÊWrFˆ∂V‚Ê∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B7&VFRVÁ&ˆ∆∆÷VÁBFˆ∂V„¢r∂RÊ÷W76vRó–ß–¶gVÊ7Fñˆ‚6˜îvVÁDVÁ&ˆ∆∆÷VÁEFˆ∂V‚Çó∂6ˆÁ7Bf«VS◊vñÊF˜w4vVÁDVÁ&ˆ∆∆÷VÁEFˆ∂V‚ÁFWáD6ˆÁFVÁG«¬rs∂ñbÇf«VRó&WGW&„∂ÊfñvF˜"Ê6∆ó&ˆ&CÚÁw&óFUFWáBáf«VRíÁFÜV‚ÇÇì”Ê∆W'BÇtVÁ&ˆ∆∆÷VÁBFˆ∂V‚6˜ñVB‚rííÊ6F6ÇÇÇì”Á&ˆ◊BÇt6˜íFÜó2VÁ&ˆ∆∆÷VÁBFˆ∂V„¢r«f«VRíó–¶7ñÊ2gVÊ7Fñˆ‚∆ˆEvñÊF˜w4vVÁE6∂vU7FGW2Çó∞¢6ˆÁ7BÊ˜FS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwvñÊF˜w4vVÁE6∂vU7FGW2rí∆'WGFˆ„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwvñÊF˜w4vVÁDF˜vÊ∆ˆD'F‚rì∞¢G'ó∞¢6ˆÁ7BñÊfÛ÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2˜6∂vR◊7FGW2rì∞¢ñbÜÊ˜FRñÊ˜FRÁFWáD6ˆÁFVÁC÷ñÊfÚÊ÷W76vW«¬rs∞¢ñbÜ'WGFˆ‚ó∂'WGFˆ‚ÊFó6&∆VC“ñÊfÚÊfñ∆&∆S∂'WGFˆ‚ÁFWáD6ˆÁFVÁC÷ñÊfÚÊfñ∆&∆SÚ~(i2F˜vÊ∆ˆBvVÁBr∂ñÊfÚÁfW'6ñˆ„¢tñÁ7F∆∆W"r∂ñÊfÚÁfW'6ñˆ‚≤r'Vñ∆BVÊFñÊrs∂'WGFˆ‚ÁFóF∆S÷ñÊfÚÊfñ∆&∆SÚtF˜vÊ∆ˆBFÜR6ñvÊVBÉcBñÁ7F∆∆W"s¶ñÊfÚÊ÷W76vW–¢÷6F6ÇÜRó∂ñbÜÊ˜FRñÊ˜FRÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6ÜV6≤ñÁ7F∆∆W"fñ∆&ñ∆óGì¢r∂RÊ÷W76vS∂ñbÜ'WGFˆ‚ñ'WGFˆ‚ÊFó6&∆VC◊G'VW–ß–¶7ñÊ2gVÊ7Fñˆ‚F˜vÊ∆ˆEvñÊF˜w4vVÁE6∂vRÇó∞¢G'ó∞¢6ˆÁ7B&W7ˆÁ6S÷vóBfWF6ÇÇrˆí˜c˜vñÊF˜w2÷vVÁG2˜6∂vS˜c”"„B„Bfg&W6É“r¥FFRÊÊ˜rÇí«∂7&VFVÁFñ«3¢w6÷R÷˜&ñvñ‚r∆66ÜS¢vÊÚ◊7F˜&Rw“ì∞¢ñbÇ&W7ˆÁ6RÊˆ≤ó∂∆WB÷W76vS“uvñÊF˜w2vVÁBñÁ7F∆∆W"ó2VÊfñ∆&∆R‚s∑G'ó∂÷W76vS“ÜvóB&W7ˆÁ6RÊß6ˆ‚ÇííÊFWFñ««∆÷W76vW÷6F6ÇÖÚó∑◊Fá&˜rÊWrW'&˜"Ü÷W76vRó–¢6ˆÁ7B&∆ˆ#÷vóB&W7ˆÁ6RÊ&∆ˆ"Çí«W&√’U$¬Ê7&VFTˆ&¶V7EU$¬Ü&∆ˆ"í∆∆ñÊ≥÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇvrì∂∆ñÊ≤Êá&Vc◊W&√∂∆ñÊ≤ÊF˜vÊ∆ˆC“ttÙE4UîR’vñÊF˜w2‘vVÁB◊ÉcB’6WGW”"„B„BÊWÜRs∂Fˆ7V÷VÁBÊ&ˆGíÊVÊD6Üñ∆BÜ∆ñÊ≤ì∂∆ñÊ≤Ê6∆ñ6≤Çì∂∆ñÊ≤Á&V÷˜fRÇì∑6WEFñ÷V˜WBÇÇì”ÂU$¬Á&Wfˆ∂Tˆ&¶V7EU$¬áW&¬í√3ì∞¢÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vW«¬uvñÊF˜w2vVÁBñÁ7F∆∆W"ó2VÊfñ∆&∆R‚rì∂vóB∆ˆEvñÊF˜w4vVÁE6∂vU7FGW2Çó–ß–¶7ñÊ2gVÊ7Fñˆ‚V∆≈vñÊF˜w4vVÁDÊ˜rÜñBó∞¢6ˆÁ7BÉ’tî‰Dıu5ÙtTÂE2ÊfñÊBÜ”ÊÊñC””÷ñBì∂ñbÇÇó&WGW&„∞¢G'ó∞¢6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB≤r˜V∆¬÷Ê˜rr«∂÷WFÜˆC¢uı5Bw“ì∞¢∆W'Bá"Ê÷W76vW«∆V∆¬WfVÁG2Ê˜rVWVVBf˜"G∑ÇÊ6ˆ◊WFW%ˆÊ÷W«¬uvñÊF˜w2vVÁBw“Êì∞¢vóB∆ˆEvñÊF˜w4vVÁG2Çì∞¢6WEFñ÷V˜WBÜ7ñÊ2Çì”Á∂vóB∆ˆEvñÊF˜w4vVÁG2Çì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çó“√#ì∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B&WVW7BvVÁBWfVÁBV∆√¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚V∆ƒ∆≈vñÊF˜w4vVÁG4Ê˜rÇó∞¢vóB∆ˆEvñÊF˜w4vVÁG2Çì∞¢6ˆÁ7BF&vWG3’tî‰Dıu5ÙtTÂE2Êfñ«FW"áÉ”‚ÇÁ&Wfˆ∂VEˆBbgÇÊVÊ&∆VBbgÇÁV∆≈ˆÊ˜u˜7W˜'FVBbgÇÁ7FGW2”“vˆff∆ñÊRrì∞¢ñbÇF&vWG2Ê∆VÊwFÇó∂∆W'BÇtÊÚ6ˆ◊Fñ&∆RˆÊ∆ñÊRvñÊF˜w2vVÁG2&Rfñ∆&∆R‚ñÁ7F∆¬˜"Ww&FRFÚFÜRW&÷ÊVÁBÉcBvVÁBñbÊVVFVB‚rì∑&WGW&Á–¢∆WBVWVVC”∆fñ∆VC”∞¢f˜"Ü6ˆÁ7BÇˆbF&vWG2ó∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∑ÇÊñB≤r˜V∆¬÷Ê˜rr«∂÷WFÜˆC¢uı5Bw“ì∑VWVVB≤∑÷6F6ÇÜRó∂fñ∆VB≤∑◊–¢∆W'BÜV∆¬WfVÁG2Ê˜rVWVVBf˜"G∑VWVVG“vñÊF˜w2vVÁBG∑VWVVC”””Úrs¢w2w“G∂fñ∆VCˆ≤G∂fñ∆VG“fñ∆VF¢rw“‚vVÁG26ÜV6≤f˜"6ˆ÷÷ÊG2WfW'í6V6ˆÊG2Êì∞¢vóB∆ˆEvñÊF˜w4vVÁG2Çì∑6WEFñ÷V˜WBÜ7ñÊ2Çì”Á∂vóB∆ˆEvñÊF˜w4vVÁG2Çì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çó“√#ì∞ß–¶7ñÊ2gVÊ7Fñˆ‚6ˆÊfñwW&UvñÊF˜w4vVÁBÜñBó∞¢6ˆÁ7BÉ’tî‰Dıu5ÙtTÂE2ÊfñÊBÜ”ÊÊñC””÷ñBì∂ñbÇÇó&WGW&„∞¢6ˆÁ7B6ÜÊÊV«3◊&ˆ◊BÇtWfVÁB∆ˆr6ÜÊÊV«2¬6ˆ÷÷6W&FVC¢r¬áÇÊ6ÜÊÊV«7«≈≤u7ó7FV“r¬t∆ñ6Fñˆ‚u“íÊ¶ˆñ‚Çr¬ríì∂ñbÜ6ÜÊÊV«3””÷ÁV∆¬ó&WGW&„∞¢6ˆÁ7BñÁFW'f√◊&ˆ◊BÇt6ˆ∆∆V7Fñˆ‚ñÁFW'f¬ñ‚6V6ˆÊG2É3”3cì¢r≈7G&ñÊráÇÁˆ∆≈ˆñÁFW'f≈˜6V6ˆÊG7«√cíì∂ñbÜñÁFW'f√””÷ÁV∆¬ó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂6ÜÊÊV«3¶6ÜÊÊV«2Á7∆óBÇr¬ríÊ÷ác”ÁbÁG&ñ“ÇííÊfñ«FW"Ñ&ˆˆ∆V‚í«ˆ∆≈ˆñÁFW'f≈˜6V6ˆÊG3§ÁV÷&W"ÜñÁFW'f««√cí∆VÊ&∆VCßG'VW“ó“ì∂vóB∆ˆEvñÊF˜w4vVÁG2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BWFFRvñÊF˜w2vVÁC¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚&Wfˆ∂UvñÊF˜w4vVÁBÜñBó∞¢6ˆÁ7BÉ’tî‰Dıu5ÙtTÂE2ÊfñÊBÜ”ÊÊñC””÷ñBì∂ñbÇ6ˆÊfó&“Ü&Wfˆ∂RG∑ÉÚÊ6ˆ◊WFW%ˆÊ÷W«¬wFÜó2vñÊF˜w2vVÁBw”ÚFÜRñÁ7F∆∆VBvVÁBvñ∆¬ÊÚ∆ˆÊvW"&R&∆RFÚW∆ˆBWfVÁG2Êíó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆEvñÊF˜w4vVÁG2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B&Wfˆ∂RvñÊF˜w2vVÁC¢r∂RÊ÷W76vRó–ß–†¶7ñÊ2gVÊ7Fñˆ‚W&vUvñÊF˜w4vVÁBÜñBó∞¢6ˆÁ7BÉ’tî‰Dıu5ÙtTÂE2ÊfñÊBÜ”ÊÊñC””÷ñBì∂ñbÇÇó&WGW&„∞¢ñbÇÇÁ&Wfˆ∂VEˆBbgÇÁ7FGW2”“w&Wfˆ∂VBró∂∆W'BÇu&Wfˆ∂RFÜó2vñÊF˜w2vVÁB&Vf˜&R&V÷˜fñÊróBW&÷ÊVÁF«í‚rì∑&WGW&Á–¢ñbÇ6ˆÊfó&“ÜW&÷ÊVÁF«í&V÷˜fRG∑ÇÊ6ˆ◊WFW%ˆÊ÷W««ÇÊÜ˜7FÊ÷W«¬wFÜó26ˆ◊WFW"w“g&ˆ“tÙE4UîSı∆Â∆ÂFÜó2&V÷˜fW2FÜR&Wfˆ∂VBvVÁB&V6˜&B¬óG2WfVÁBfñÊFñÊw2¬&V÷˜FR◊6W76ñˆ‚Üó7F˜'í¬VWVVB6ˆ÷÷ÊG2¬ÊB&V6ÜV6∑2‚∆ñÊ∂VBFñ6∂WG2&V÷ñ‚2Üó7F˜'í‚FÜó26ÊÊ˜B&RVÊFˆÊRÊíó&WGW&„∞¢G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB≤r˜W&vRr«∂÷WFÜˆC¢tDTƒUDRw“ì∂∆W'BÜ&V÷˜fVBG∑"Ê6ˆ◊WFW%ˆÊ÷W«¬v6ˆ◊WFW"w“g&ˆ“tÙE4UîR‚G∑"ÊfñÊFñÊw5ˆFV∆WFVG«√“WfVÁBfñÊFñÊrá2í&V÷˜fVBÊì∂vóB∆ˆEvñÊF˜w4vVÁG2Çì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çì∂ñbáGóVˆb∆ˆE&V÷˜FT66W73””“vgVÊ7Fñˆ‚rñvóB∆ˆE&V÷˜FT66W72Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BW&÷ÊVÁF«í&V÷˜fRvñÊF˜w2vVÁC¢r∂RÊ÷W76vRó–ß–†¶7ñÊ2gVÊ7Fñˆ‚∆ˆEvñÊF˜w56˜W&6W2Çó∞¢G'óµtî‰Dıu5ı4ıU$4U3÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷WfVÁB◊6˜W&6W2rì∑&VÊFW%vñÊF˜w56˜W&6W2Çó÷6F6ÇÜRóµtî‰Dıu5ı4ıU$4U3’µ”∑&VÊFW%vñÊF˜w56˜W&6W2Çó–ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDWfVÁDfñÊFñÊw2Çó∞¢6ˆÁ7B7FGW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊu7FGW4fñ«FW"rìÚÁf«VW«¬rs∞¢6ˆÁ7B6WfW&óGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊu6WfW&óGîfñ«FW"rìÚÁf«VW«¬rs∞¢6ˆÁ7B÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊu6V&6ÇrìÚÁf«VRÁG&ñ“Çó«¬rs∞¢G'ó∞¢6ˆÁ7B∑&˜w2∆∆ƒ˜V‚«&W6ˆ«fVE”÷vóB&ˆ÷ó6RÊ∆¬Ö∞¢ß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw3Úr∂ÊWrU$≈6V&6Ö&◊2á∑7FGW2«6WfW&óGí«“íÁFı7G&ñÊrÇíí¿¢ß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw3˜7FGW3÷˜V‚rí¿¢ß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw3˜7FGW3◊&W6ˆ«fVBrê¢“ì∞¢UdTÂEÙdî‰Dî‰u3◊&˜w7«≈µ”∞¢WfVÁDfñÊFñÊt˜V‚ÁFWáD6ˆÁFVÁC÷∆ƒ˜V‚Ê∆VÊwFÉ∞¢WfVÁDfñÊFñÊu&W6ˆ«fVBÁFWáD6ˆÁFVÁC◊&W6ˆ«fVBÊ∆VÊwFÉ∞¢WfVÁDfñÊFñÊt7&óFñ6¬ÁFWáD6ˆÁFVÁC÷∆ƒ˜V‚Êfñ«FW"áÉ”ÁÇÁ6WfW&óGì””“v7&óFñ6¬ríÊ∆VÊwFÉ∞¢WfVÁDfñÊFñÊtÜ&Gv&RÁFWáD6ˆÁFVÁC÷∆ƒ˜V‚Êfñ«FW"áÉ”Â≤u7F˜&vRr¬tÜ&Gv&Ru“ÊñÊ6«VFW2áÇÊ6FVv˜'íííÊ∆VÊwFÉ∞¢6ˆÁ7B&FvS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊt&FvRrì∂ñbÜ&FvRñ&FvRÁFWáD6ˆÁFVÁC÷∆ƒ˜V‚Ê∆VÊwFÉ∞¢WfVÁDfñÊFñÊu&˜w2ÊñÊÊW$ÖD‘√‘UdTÂEÙdî‰Dî‰u2Ê∆VÊwFÉÙUdTÂEÙdî‰Dî‰u2Ê÷áÉ”Ê«G#‡¢«FB6∆73“&F÷ñ‚÷ˆÊ«í#„∆ñÁWB6∆73“&WfVÁB÷fñÊFñÊr÷6ÜV6≤"GóS“&6ÜV6∂&˜Ç"f«VS“"G∑ÇÊñG“"ˆÊ6ÜÊvS“'WFFTWfVÁDfñÊFñÊtFV∆WFU6V∆V7Fñˆ‚Çí"&ñ÷∆&V√“%6V∆V7BfñÊFñÊrG∑ÇÊñG“#„¬˜FC‡¢«FC„«7‚6∆73“'7FGW2÷&FvR6WfW&óGí“G∂W62áÇÁ6WfW&óGó«¬vñÊfÚró“#‚G∂W62áÇÁ6WfW&óGó«¬tñÊfÚró”¬˜7„„¬˜FC‡¢«FC„∆Fób6∆73“&Ê÷R#‚G∂W62áÇÊ6ˆ◊WFW%ˆÊ÷Ró”¬ˆFóc„∆Fób6∆73“&◊WFVB#‚G∂W62áÇÊ6ÜÊÊV¬ó”¬ˆFóc„¬˜FC‡¢«FC„∆Fób6∆73“&Ê÷R#‚G∂W62áÇÁFóF∆Ró”¬ˆFóc„∆Fób6∆73“&◊WFVB#‚G∂W62áÇÊ6FVv˜'íó“+rG∂W62áÇÁ&V6ˆ÷÷VÊFFñˆÁ«¬rró”¬ˆFóc„¬˜FC‡¢«FC„∆#‚G∂W62áÇÁ&˜fñFW"ó”¬ˆ#„∆Fób6∆73“&◊WFVB#‰WfVÁBG∑ÇÊWfVÁEˆñG“+rG∂W62áÇÊ∆WfV¬ó”¬ˆFóc„¬˜FC‡¢«FC‚G∑ÇÊˆ67W'&VÊ6Uˆ6˜VÁG”¬˜FC‡¢«FC‚G∑ÇÊ∆7E˜6VV„ˆW62ÜÊWrFFRáÇÊ∆7E˜6VV‚íÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC‡¢«FC„«7‚6∆73“'7FGW2÷&FvR#‚G∂W62áÇÁ7FGW2ó”¬˜7„„¬˜FC‡¢«FC„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&˜V‰WfVÁDfñÊFñÊrÇG∑ÇÊñG“í#‰˜V„¬ˆ'WGFˆ„‚G∑ÇÁ7FGW3””“v˜V‚sˆ∆'WGFˆ‚6∆73“&∆ñÊ≤˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“'&V6ÜV6¥WfVÁDfñÊFñÊrÇG∑ÇÊñG“í#Â&V6ÜV6≥¬ˆ'WGFˆ„‚∆'WGFˆ‚6∆73“&∆ñÊ≤˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&7&VFUFñ6∂WDg&ˆ‘WfVÁDfñÊFñÊrÇG∑ÇÊñG“í#‰7&VFRFñ6∂WC¬ˆ'WGFˆ„Ê¢rw“∆'WGFˆ‚6∆73“&∆ñÊ≤FV∆WFR÷∆ñÊ≤F÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&FV∆WFTWfVÁDfñÊFñÊrÇG∑ÇÊñG“í#‰FV∆WFS¬ˆ'WGFˆ„„¬˜FC‡¢¬˜G#ÊíÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#í"6∆73“&V◊Gí#‰ÊÚWfVÁBfñÊFñÊw2÷F6ÇFÜó2fñ«FW"„¬˜FC„¬˜G#‚s∞¢6ˆÁ7Bf3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊufó6ñ&∆T6˜VÁBrì∂ñbáf2óf2ÁFWáD6ˆÁFVÁC÷ÇG¥UdTÂEÙdî‰Dî‰u2Ê∆VÊwFá“ñ∞¢6ˆÁ7BgC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊtfˆ˜FW%FWáBrì∂ñbÜgBñgBÁFWáD6ˆÁFVÁC÷6Ü˜vñÊrG¥UdTÂEÙdî‰Dî‰u2Ê∆VÊwFá“fñÊFñÊrG¥UdTÂEÙdî‰Dî‰u2Ê∆VÊwFÉ”””Úrs¢w2w÷∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr7fñWr÷WfVÁB÷fñÊFñÊw2FÜVBñÁWE∑GóS÷6ÜV6∂&˜Ö“¬6WfVÁDfñÊFñÊu6V∆V7D∆¬ríÊf˜$V6ÇáÉ”ÁÇÊ6ÜV6∂VC÷f«6Rì∞¢WFFTWfVÁDfñÊFñÊtFV∆WFU6V∆V7Fñˆ‚Çì∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞¢vóB&ˆ÷ó6RÊ∆¬Ö∂∆ˆEvñÊF˜w4vVÁG2Çí∆∆ˆEvñÊF˜w56˜W&6W2Çï“ì∞¢÷6F6ÇÜRó∂WfVÁDfñÊFñÊu&˜w2ÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#í"6∆73“&V◊Gí#‰WfVÁBfñÊFñÊw2VÊfñ∆&∆S¢r∂W62ÜRÊ÷W76vRí≤s¬˜FC„¬˜G#‚w–ß–¶gVÊ7Fñˆ‚6V∆V7FVDWfVÁDfñÊFñÊtñG2Çó∑&WGW&‚≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊWfVÁB÷fñÊFñÊr÷6ÜV6≥¶6ÜV6∂VBrï“Ê÷áÉ”‰ÁV÷&W"áÇÁf«VRííÊfñ«FW"Ñ&ˆˆ∆V‚ó–¶gVÊ7Fñˆ‚WFFTWfVÁDfñÊFñÊtFV∆WFU6V∆V7Fñˆ‚Çó∂6ˆÁ7BñG3◊6V∆V7FVDWfVÁDfñÊFñÊtñG2Çì∂6ˆÁ7B'F„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊtFV∆WFU6V∆V7FVBrì∂6ˆÁ7B6˜VÁC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊu6V∆V7FVD6˜VÁBrì∂ñbÜ'F‚ñ'F‚ÊFó6&∆VC“ñG2Ê∆VÊwFÉ∂ñbÜ6˜VÁBñ6˜VÁBÁFWáD6ˆÁFVÁC÷G∂ñG2Ê∆VÊwFá“6V∆V7FVF–¶gVÊ7Fñˆ‚Fˆvv∆T∆ƒWfVÁDfñÊFñÊw2Ü6ÜV6∂VBó∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊWfVÁB÷fñÊFñÊr÷6ÜV6≤ríÊf˜$V6ÇáÉ”ÁÇÊ6ÜV6∂VC“6ÜV6∂VBì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr7fñWr÷WfVÁB÷fñÊFñÊw2FÜVBñÁWE∑GóS÷6ÜV6∂&˜Ö“¬6WfVÁDfñÊFñÊu6V∆V7D∆¬ríÊf˜$V6ÇáÉ”ÁÇÊ6ÜV6∂VC“6ÜV6∂VBì∑WFFTWfVÁDfñÊFñÊtFV∆WFU6V∆V7Fñˆ‚Çó–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFTWfVÁDfñÊFñÊrÜñBó∂6ˆÁ7BÉ‘UdTÂEÙdî‰Dî‰u2ÊfñÊBác”ÁbÊñC””÷ñBì∂ñbÇ6ˆÊfó&“ÜFV∆WFRFÜó2vñÊF˜w2WfVÁBfñÊFñÊsı∆Â∆‚G∑ÉÚÁFóF∆W«¬tfñÊFñÊr2r∂ñG’∆Â∆‰∆ñÊ∂VBFñ6∂WG2vñ∆¬&R&W6W'fVB2Üó7F˜&ñ6¬Fñ6∂WG2‚FÜó26ÊÊ˜B&RVÊFˆÊRÊíó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂ñbÑ5U%$TÂEÙUdTÂEÙdî‰Dî‰sÚÊñC””÷ñBñ6∆˜6TWfVÁDfñÊFñÊt÷ˆF¬Çì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFRWfVÁBfñÊFñÊs¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFU6V∆V7FVDWfVÁDfñÊFñÊw2Çó∂6ˆÁ7BñG3◊6V∆V7FVDWfVÁDfñÊFñÊtñG2Çì∂ñbÇñG2Ê∆VÊwFÇó&WGW&„∂ñbÇ6ˆÊfó&“ÜFV∆WFRG∂ñG2Ê∆VÊwFá“6V∆V7FVBvñÊF˜w2WfVÁBfñÊFñÊrG∂ñG2Ê∆VÊwFÉ”””Úrs¢w2w”ı∆Â∆‰∆ñÊ∂VBFñ6∂WG2vñ∆¬&R&W6W'fVB‚FÜó26ÊÊ˜B&RVÊFˆÊRÊíó&WGW&„∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw2ˆ'V∆≤÷FV∆WFRr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂fñÊFñÊuˆñG3¶ñG7“ó“ì∂∆W'BÜFV∆WFVBG∑"ÊFV∆WFVG“WfVÁBfñÊFñÊrG∑"ÊFV∆WFVC”””Úrs¢w2w“Êì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFR6V∆V7FVBWfVÁBfñÊFñÊw3¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFTˆ∆DWfVÁDfñÊFñÊw2Çó∂6ˆÁ7BFó3‘ÁV÷&W"ÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊtˆ∆DFó2rìÚÁf«VW«√3ì∂ñbÇ6ˆÊfó&“ÜFV∆WFR&W6ˆ«fVBvñÊF˜w2WfVÁBfñÊFñÊw2ˆ∆FW"FÜ‚G∂Fó7“Fó3ı∆Â∆‰˜V‚fñÊFñÊw2vñ∆¬Ê˜B&RFV∆WFVB‚∆ñÊ∂VBFñ6∂WG2vñ∆¬&R&W6W'fVBÊíó&WGW&„∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw2ˆFV∆WFR÷ˆ∆Br«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂ˆ∆FW%˜FÜÂˆFó3¶Fó7“ó“ì∂∆W'BÜFV∆WFVBG∑"ÊFV∆WFVG“ˆ∆B&W6ˆ«fVBWfVÁBfñÊFñÊrG∑"ÊFV∆WFVC”””Úrs¢w2w“Êì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFRˆ∆BWfVÁBfñÊFñÊw3¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚˜V‰WfVÁDfñÊFñÊrÜñBó∞¢G'ó∞¢5U%$TÂEÙUdTÂEÙdî‰Dî‰s÷vóBß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw2Úr∂ñBì∞¢6ˆÁ7BÉ‘5U%$TÂEÙUdTÂEÙdî‰Dî‰s∞¢WfVÁDfñÊFñÊt÷ˆF≈FóF∆RÁFWáD6ˆÁFVÁC◊ÇÁFóF∆S∞¢WfVÁDfñÊFñÊt÷ˆF≈7V'FóF∆RÁFWáD6ˆÁFVÁC÷G∑ÇÊ6ˆ◊WFW%ˆÊ÷W“+rG∑ÇÁ&˜fñFW'“+rWfVÁBG∑ÇÊWfVÁEˆñG÷∞¢6ˆÁ7B7FñˆÁ3“áÇÁ7VvvW7FVEˆ7FñˆÁ7«≈µ“íÊ÷ÇÜ∆íì”Ê∆Fób6∆73“&WfVÁB÷fóÇ÷óFV“#„«7‚6∆73“&WfVÁB÷fóÇ÷ÁV“#‚G∂í≥”¬˜7„„«7„‚G∂W62Üó”¬˜7„„¬ˆFócÊíÊ¶ˆñ‚Çrrì∞¢6ˆÁ7B∆ñÊ∂VC“áÇÁFñ6∂WG7«≈µ“íÊ÷áC”Ê∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TWfVÁDfñÊFñÊt÷ˆF¬Çì∑6Ü˜ufñWrÇwFñ6∂WG2r«G'VRì∑6WEFñ÷V˜WBÇÇì”Ê˜VÂFñ6∂WDVFóF˜"ÇG∑BÊñG“í√Sí#‚G∂W62áBÁFñ6∂WEˆÁV÷&W"ó“+rG∂W62áBÁ7FGW2ó”¬ˆ'WGFˆ„ÊíÊ¶ˆñ‚Çrrì∞¢WfVÁDfñÊFñÊt÷ˆFƒ&ˆGíÊñÊÊW$ÖD‘√÷∆Fób6∆73“&WfVÁB÷FWFñ¬÷w&ñB#‡¢∆Fób6∆73“&WfVÁB÷FWFñ¬÷6V∆¬#„∆Fób6∆73“&≤#Â6WfW&óGì¬ˆFóc„∆Fób6∆73“'b#‚G∂W62áÇÁ6WfW&óGíó”¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&WfVÁB÷FWFñ¬÷6V∆¬#„∆Fób6∆73“&≤#‰6FVv˜'ì¬ˆFóc„∆Fób6∆73“'b#‚G∂W62áÇÊ6FVv˜'íó”¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&WfVÁB÷FWFñ¬÷6V∆¬#„∆Fób6∆73“&≤#‰ˆ67W'&VÊ6W3¬ˆFóc„∆Fób6∆73“'b#‚G∑ÇÊˆ67W'&VÊ6Uˆ6˜VÁG”¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&WfVÁB÷FWFñ¬÷6V∆¬#„∆Fób6∆73“&≤#‰6ˆ◊WFW#¬ˆFóc„∆Fób6∆73“'b#‚G∂W62áÇÊ6ˆ◊WFW%ˆÊ÷Ró”¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&WfVÁB÷FWFñ¬÷6V∆¬#„∆Fób6∆73“&≤#‰6ÜÊÊV√¬ˆFóc„∆Fób6∆73“'b#‚G∂W62áÇÊ6ÜÊÊV¬ó”¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&WfVÁB÷FWFñ¬÷6V∆¬#„∆Fób6∆73“&≤#‰∆7B6VV„¬ˆFóc„∆Fób6∆73“'b#‚G∑ÇÊ∆7E˜6VV„ˆW62ÜÊWrFFRáÇÊ∆7E˜6VV‚íÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬ˆFóc„¬ˆFóc‡¢∆Fób6∆73“&WfVÁB÷FWFñ¬÷6V∆¬#„∆Fób6∆73“&≤#‰6ˆ∆∆V7Fñˆ„¬ˆFóc„∆Fób6∆73“'b#‚G∑ÇÊvVÁEˆñCÚuvñÊF˜w2vVÁBs¢áÇÁ6˜W&6UˆñCÚuvñÂ$“s¢tñ◊˜'FVBró”¬ˆFóc„¬ˆFóc‡¢¬ˆFóc‡¢∆Fóc„∆É3ÂvñÊF˜w2WfVÁB÷W76vS¬ˆÉ3„∆Fób6∆73“&WfVÁB÷÷W76vR÷&˜Ç#‚G∂W62áÇÊ÷W76vW«¬tÊÚWfVÁB÷W76vR&WGW&ÊVB‚ró”¬ˆFóc„¬ˆFóc‡¢∆Fóc„∆É3Â7VvvW7FVBfóÉ¬ˆÉ3„«6∆73“&◊WFVB#‚G∂W62áÇÁ&V6ˆ÷÷VÊFFñˆÁ«¬rró”¬˜„∆Fób6∆73“&WfVÁB÷fóÇ÷∆ó7B#‚G∂7FñˆÁ7”¬ˆFóc„¬ˆFóc‡¢G∂∆ñÊ∂VCÚs∆Fóc„∆É3‰∆ñÊ∂VBFñ6∂WG3¬ˆÉ3„∆Fób6∆73“&7FñˆÁ2#‚r∂∆ñÊ∂VB≤s¬ˆFóc„¬ˆFóc‚s¢rw–¢∆Fób6∆73“&÷ˆF¬÷7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“'&V6ÜV6¥WfVÁDfñÊFñÊrÇG∑ÇÊñG“í#Â&V6ÜV6≥¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'&ñ÷'í˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&7&VFUFñ6∂WDg&ˆ‘WfVÁDfñÊFñÊrÇG∑ÇÊñG“í#‰7&VFRFñ6∂WC¬ˆ'WGFˆ„‚G∑ÇÁ7FGW3””“v˜V‚sˆ∆'WGFˆ‚6∆73“&FÊvW"˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“'&W6ˆ«fTWfVÁDfñÊFñÊrÇG∑ÇÊñG“í#Â&W6ˆ«fS¬ˆ'WGFˆ„Ê¢rw”∆'WGFˆ‚6∆73“&FÊvW"F÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&FV∆WFTWfVÁDfñÊFñÊrÇG∑ÇÊñG“í#‰FV∆WFS¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&6∆˜6TWfVÁDfñÊFñÊt÷ˆF¬Çí#‰6∆˜6S¬ˆ'WGFˆ„„¬ˆFócÊ∞¢WfVÁDfñÊFñÊt÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∂«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B˜V‚WfVÁBfñÊFñÊs¢r∂RÊ÷W76vRó–ß–¶gVÊ7Fñˆ‚6∆˜6TWfVÁDfñÊFñÊt÷ˆF¬Çó∂WfVÁDfñÊFñÊt÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚&V6ÜV6¥WfVÁDfñÊFñÊrÜñBó∞¢G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw2Úr∂ñB≤r˜&V6ÜV6≤r«∂÷WFÜˆC¢uı5Bw“ì∂∆W'Bá"Ê÷W76vW«¬u&V6ÜV6≤6ˆ◊∆WFVB‚rì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çì∂ñbÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁDfñÊFñÊt÷ˆF¬ríÁ7Gñ∆RÊFó7∆ì””“vw&ñBrñvóB˜V‰WfVÁDfñÊFñÊrÜñBó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B&V6ÜV6≤WfVÁBfñÊFñÊs¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚&W6ˆ«fTWfVÁDfñÊFñÊrÜñBó∞¢ñbÇ6ˆÊfó&“Çt÷&≤FÜó2WfVÁBfñÊFñÊr&W6ˆ«fVCÚríó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw2Úr∂ñB≤r˜&W6ˆ«fRr«∂÷WFÜˆC¢uı5Bw“ì∂6∆˜6TWfVÁDfñÊFñÊt÷ˆF¬Çì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B&W6ˆ«fRWfVÁBfñÊFñÊs¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚7&VFUFñ6∂WDg&ˆ‘WfVÁDfñÊFñÊrÜñBó∞¢G'ó∞¢6ˆÁ7BFñ6∂WC÷vóBß6ˆ‚Çrˆí˜cˆWfVÁB÷fñÊFñÊw2Úr∂ñB≤rˆ7&VFR◊Fñ6∂WBr«∂÷WFÜˆC¢uı5Bw“ì∞¢6∆˜6TWfVÁDfñÊFñÊt÷ˆF¬Çì∑6Ü˜ufñWrÇwFñ6∂WG2r«G'VRì∂vóB∆ˆEFñ6∂WG2Çì∂˜VÂFñ6∂WDVFóF˜"áFñ6∂WBÊñBì∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B7&VFRFñ6∂WC¢r∂RÊ÷W76vRó–ß–¶gVÊ7Fñˆ‚˜VÂvñÊF˜w56˜W&6T÷ˆF¬Çó∑vñÊF˜w56˜W&6T÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑&W6WEvñÊF˜w56˜W&6Tf˜&“Çì∂∆ˆEvñÊF˜w56˜W&6W2Çó–¶gVÊ7Fñˆ‚6∆˜6UvñÊF˜w56˜W&6T÷ˆF¬Çó∑vñÊF˜w56˜W&6T÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶gVÊ7Fñˆ‚&W6WEvñÊF˜w56˜W&6Tf˜&“Çó∞¢vñÊF˜w56˜W&6TñBÁf«VS“rs∑vñÊF˜w56˜W&6TÊ÷RÁf«VS“rs∑vñÊF˜w56˜W&6TÜ˜7BÁf«VS“rs∑vñÊF˜w56˜W&6U˜'BÁf«VS“sSìÉbs∑vñÊF˜w56˜W&6UG&Á7˜'BÁf«VS“vÁF∆“s∑vñÊF˜w56˜W&6UW6W&Ê÷RÁf«VS“rs∑vñÊF˜w56˜W&6U77v˜&BÁf«VS“rs∑vñÊF˜w56˜W&6TñÁFW'f¬Áf«VS“sRs∑vñÊF˜w56˜W&6UfW&ñgïF«2Ê6ÜV6∂VC◊G'VS∑vñÊF˜w56˜W&6T6ÜÊÊV«2Áf«VS“u7ó7FV“¬∆ñ6Fñˆ‚s∑vñÊF˜w56˜W&6TW'"ÁFWáD6ˆÁFVÁC“rs∞ß–¶gVÊ7Fñˆ‚VFóEvñÊF˜w56˜W&6RÜñBó∞¢6ˆÁ7BÉ’tî‰Dıu5ı4ıU$4U2ÊfñÊBá3”Á2ÊñC””÷ñBì∂ñbÇÇó&WGW&„∞¢vñÊF˜w56˜W&6TñBÁf«VS◊ÇÊñC∑vñÊF˜w56˜W&6TÊ÷RÁf«VS◊ÇÊÊ÷S∑vñÊF˜w56˜W&6TÜ˜7BÁf«VS◊ÇÊÜ˜7FÊ÷S∑vñÊF˜w56˜W&6U˜'BÁf«VS◊ÇÁ˜'C∑vñÊF˜w56˜W&6UG&Á7˜'BÁf«VS◊ÇÁG&Á7˜'C∑vñÊF˜w56˜W&6UW6W&Ê÷RÁf«VS◊ÇÁW6W&Ê÷W«¬rs∑vñÊF˜w56˜W&6U77v˜&BÁf«VS“rs∑vñÊF˜w56˜W&6TñÁFW'f¬Áf«VS’7G&ñÊráÇÁˆ∆≈ˆñÁFW'f≈ˆ÷ñÁWFW7«√Rì∑vñÊF˜w56˜W&6UfW&ñgïF«2Ê6ÜV6∂VC“ÇÁfW&ñgï˜F«3∑vñÊF˜w56˜W&6T6ÜÊÊV«2Áf«VS“áÇÊ6ÜÊÊV«7«≈µ“íÊ¶ˆñ‚Çr¬rì∑vñÊF˜w56˜W&6TW'"ÁFWáD6ˆÁFVÁC“rs∞ß–¶7ñÊ2gVÊ7Fñˆ‚6fUvñÊF˜w56˜W&6RÇó∞¢6ˆÁ7BñC◊vñÊF˜w56˜W&6TñBÁf«VS∞¢6ˆÁ7B&ˆGì◊∂Ê÷SßvñÊF˜w56˜W&6TÊ÷RÁf«VRÁG&ñ“Çí∆Ü˜7FÊ÷SßvñÊF˜w56˜W&6TÜ˜7BÁf«VRÁG&ñ“Çí«˜'C§ÁV÷&W"ávñÊF˜w56˜W&6U˜'BÁf«VW«√SìÉbí«G&Á7˜'CßvñÊF˜w56˜W&6UG&Á7˜'BÁf«VR«W6W&Ê÷SßvñÊF˜w56˜W&6UW6W&Ê÷RÁf«VRÁG&ñ“Çí«77v˜&CßvñÊF˜w56˜W&6U77v˜&BÁf«VR«fW&ñgï˜F«3ßvñÊF˜w56˜W&6UfW&ñgïF«2Ê6ÜV6∂VB∆VÊ&∆VCßG'VR«ˆ∆≈ˆñÁFW'f≈ˆ÷ñÁWFW3§ÁV÷&W"ávñÊF˜w56˜W&6TñÁFW'f¬Áf«VW«√Rí∆6ÜÊÊV«3ßvñÊF˜w56˜W&6T6ÜÊÊV«2Áf«VRÁ7∆óBÇr¬ríÊ÷áÉ”ÁÇÁG&ñ“ÇííÊfñ«FW"Ñ&ˆˆ∆V‚ó”∞¢vñÊF˜w56˜W&6TW'"ÁFWáD6ˆÁFVÁC“rs∞¢G'ó∂vóBß6ˆ‚ÜñCÚrˆí˜c˜vñÊF˜w2÷WfVÁB◊6˜W&6W2Úr∂ñC¢rˆí˜c˜vñÊF˜w2÷WfVÁB◊6˜W&6W2r«∂÷WFÜˆC¶ñCÚuUBs¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∑&W6WEvñÊF˜w56˜W&6Tf˜&“Çì∂vóB∆ˆEvñÊF˜w56˜W&6W2Çó÷6F6ÇÜRó∑vñÊF˜w56˜W&6TW'"ÁFWáD6ˆÁFVÁC÷RÊ÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚ˆ∆≈vñÊF˜w56˜W&6RÜñBó∞¢G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷WfVÁB◊6˜W&6W2Úr∂ñB≤r˜ˆ∆¬r«∂÷WFÜˆC¢uı5Bw“ì∂∆W'BÜV∆∆VBG∑"ÊWfVÁG7“÷F6ÜñÊrvñÊF˜w2WfVÁBá2ì≤G∑"ÊÊWuˆfñÊFñÊw7“ÊWrWfVÁBfñÊFñÊrá2íÊì∂vóB∆ˆEvñÊF˜w56˜W&6W2Çì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çó÷6F6ÇÜRó∂∆W'BÇuvñÊF˜w2WfVÁBV∆¬fñ∆VC¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚ˆ∆ƒ∆≈vñÊF˜w56˜W&6W2Çó∞¢vóB∆ˆEvñÊF˜w56˜W&6W2Çì∞¢ñbÇtî‰Dıu5ı4ıU$4U2Ê∆VÊwFÇó∂∆W'BÇt6ˆÊfñwW&RB∆V7BˆÊRvñÊF˜w2WfVÁB6˜W&6Rfó'7B‚rì∂˜VÂvñÊF˜w56˜W&6T÷ˆF¬Çì∑&WGW&Á–¢∆WBˆ≥”∆fñ∆VC”«F˜F√”∞¢f˜"Ü6ˆÁ7BÇˆbtî‰Dıu5ı4ıU$4U2Êfñ«FW"áÉ”ÁÇÊVÊ&∆VBíó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷WfVÁB◊6˜W&6W2Úr∑ÇÊñB≤r˜ˆ∆¬r«∂÷WFÜˆC¢uı5Bw“ì∂ˆ≤≤≥∑F˜F¬≥◊"ÊWfVÁG7«√÷6F6ÇÜRó∂fñ∆VB≤∑◊–¢∆W'BÜvñÊF˜w2WfVÁBV∆¬6ˆ◊∆WFS¢G∂ˆ∑“Ü˜7Bá2í7V66VVFVB¬G∂fñ∆VG“fñ∆VB¬G∑F˜F«“WfVÁBá2í&ˆ6W76VBÊì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çì∞ß–¶7ñÊ2gVÊ7Fñˆ‚&V÷˜fUvñÊF˜w56˜W&6RÜñBó∞¢ñbÇ6ˆÊfó&“Çu&V÷˜fRFÜó2vñÊF˜w2WfVÁB6˜W&6SÚWÜó7FñÊrWfVÁBfñÊFñÊw2vñ∆¬&R∂WB‚ríó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷WfVÁB◊6˜W&6W2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆEvñÊF˜w56˜W&6W2Çó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó–ß–¶gVÊ7Fñˆ‚&VÊFW%vñÊF˜w56˜W&6W2Çó∞¢6ˆÁ7B&ˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwvñÊF˜w56˜W&6T∆ó7Brì∂ñbÇ&ˆ˜Bó&WGW&„∞¢&ˆ˜BÊñÊÊW$ÖD‘√’tî‰Dıu5ı4ıU$4U2Ê∆VÊwFÉıtî‰Dıu5ı4ıU$4U2Ê÷áÉ”Ê∆Fób6∆73“'vñÊF˜w2◊6˜W&6R◊&˜r#„«7‚6∆73“'vñÊF˜w2◊6˜W&6R÷ñ6ˆ‚#Âs¬˜7„„∆Fóc„∆#‚G∂W62áÇÊÊ÷Ró”¬ˆ#„«6÷∆√‚G∂W62áÇÊÜ˜7FÊ÷Ró”¢G∑ÇÁ˜'G“+rG∂W62áÇÁG&Á7˜'BÁFıWW$66RÇíó“+rWfW'íG∑ÇÁˆ∆≈ˆñÁFW'f≈ˆ÷ñÁWFW7“÷ñ‚+rG∂W62áÇÊ∆7E˜7FGW7«¬vÊWfW"ró“G∑ÇÊ∆7E˜ˆ∆≈ˆCÚr+rr∂ÊWrFFRáÇÊ∆7E˜ˆ∆≈ˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì¢rw“G∑ÇÊ∆7EˆW'&˜#Úr+rr∂W62áÇÊ∆7EˆW'&˜"ì¢rw”¬˜6÷∆√„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'ˆ∆≈vñÊF˜w56˜W&6RÇG∑ÇÊñG“í#ÂV∆¬Ê˜s¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&VFóEvñÊF˜w56˜W&6RÇG∑ÇÊñG“í#‰VFóC¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&FÊvW"F÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“'&V÷˜fUvñÊF˜w56˜W&6RÇG∑ÇÊñG“í#Â&V÷˜fS¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚvñÊF˜w2WfVÁB6˜W&6W26ˆÊfñwW&VB„¬ˆFóc‚s∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞ß–†¶gVÊ7Fñˆ‚6V∆V7FVEFñ6∂WDñG2Çó∑&WGW&‚≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁFñ6∂WB◊&˜r÷6ÜV6≥¶6ÜV6∂VBrï“Ê÷áÉ”‰ÁV÷&W"áÇÁf«VRííÊfñ«FW"Ñ&ˆˆ∆V‚ó–¶gVÊ7Fñˆ‚WFFUFñ6∂WDFV∆WFU6V∆V7Fñˆ‚Çó∞¢6ˆÁ7BñG3◊6V∆V7FVEFñ6∂WDñG2Çí∆'F„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFñ6∂WDFV∆WFU6V∆V7FVBrí∆6˜VÁC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFñ6∂WE6V∆V7FVD6˜VÁBrì∞¢ñbÜ'F‚ó∂'F‚ÊFó6&∆VC“ñG2Ê∆VÊwFÉ∂'F‚ÁFWáD6ˆÁFVÁC÷ñG2Ê∆VÊwFÉˆ	˘yFV∆WFR6V∆V7FVBÇG∂ñG2Ê∆VÊwFá“ñ¢	˘yFV∆WFR6V∆V7FVBw–¢ñbÜ6˜VÁBñ6˜VÁBÁFWáD6ˆÁFVÁC÷G∂ñG2Ê∆VÊwFá“6V∆V7FVF∞¢6ˆÁ7B&˜ÜW3’≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁFñ6∂WB◊&˜r÷6ÜV6≤rï”∞¢6ˆÁ7B∆√÷&˜ÜW2Ê∆VÊwFÉ„bf&˜ÜW2ÊWfW'íáÉ”ÁÇÊ6ÜV6∂VBì∞¢≤wFñ6∂WE6V∆V7D∆¬r¬wFñ6∂WDÜVFW%6V∆V7D∆¬u“Êf˜$V6ÇÜñC”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ó∂V¬Ê6ÜV6∂VC÷∆√∂V¬ÊñÊFWFW&÷ñÊFS÷ñG2Ê∆VÊwFÉ„bb∆«◊“ì∞ß–¶gVÊ7Fñˆ‚Fˆvv∆T∆≈Fñ6∂WG2Ü6ÜV6∂VBó∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁFñ6∂WB◊&˜r÷6ÜV6≤ríÊf˜$V6ÇáÉ”ÁÇÊ6ÜV6∂VC÷6ÜV6∂VBì∑WFFUFñ6∂WDFV∆WFU6V∆V7Fñˆ‚Çó–¶7ñÊ2gVÊ7Fñˆ‚∆ˆEFñ6∂WD76ñvÊVW2á6V∆V7FVC“rró∞¢G'ó∞¢Dî4¥UEÙ54ît‰TU3÷vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WB÷76ñvÊVW2rì∞¢÷6F6ÇÜRóµDî4¥UEÙ54ît‰TU3’µ◊–¢6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFñ6∂WD76ñvÊVRrì∂ñbÇV¬ó&WGW&„∞¢6ˆÁ7B7W'&VÁC◊6V∆V7FVG«∆V¬Áf«VW«¬rs∞¢6ˆÁ7B˜FñˆÁ3’≤s∆˜Fñˆ‚f«VS“"#ÂVÊ76ñvÊVC¬ˆ˜Fñˆ„‚r¬‚‚ÂDî4¥UEÙ54ît‰TU2Ê÷áS”Á∞¢6ˆÁ7B∆&V√“áRÊFó7∆ïˆÊ÷W«¬rríÁG&ñ“ÇìˆG∑RÊFó7∆ïˆÊ÷W“ÇG∑RÁW6W&Ê÷W“ñßRÁW6W&Ê÷S∞¢&WGW&‚∆˜Fñˆ‚f«VS“"G∂W62áRÁW6W&Ê÷Ró“#‚G∂W62Ü∆&V¬ó“+rG∂W62áRÁ&ˆ∆Ró”¬ˆ˜Fñˆ„Ê∞¢“ï”∞¢ñbÜ7W'&VÁBbbDî4¥UEÙ54ît‰TU2Á6ˆ÷RáS”ÁRÁW6W&Ê÷S””÷7W'&VÁBíó∞¢˜FñˆÁ2ÁW6ÇÜ∆˜Fñˆ‚f«VS“"G∂W62Ü7W'&VÁBó“#‚G∂W62Ü7W'&VÁBó“+r∆Vv7í76ñvÊ÷VÁC¬ˆ˜Fñˆ„Êì∞¢–¢V¬ÊñÊÊW$ÖD‘√÷˜FñˆÁ2Ê¶ˆñ‚Çrrì∂V¬Áf«VS÷7W'&VÁC∞ß–¶gVÊ7Fñˆ‚Fñ6∂WD76ñvÊVT∆&V¬áW6W&Ê÷Ró∞¢ñbÇW6W&Ê÷Ró&WGW&‚uVÊ76ñvÊVBs∞¢6ˆÁ7BS’Dî4¥UEÙ54ît‰TU2ÊfñÊBáÉ”ÁÇÁW6W&Ê÷S””◊W6W&Ê÷Rì∞¢&WGW&‚RbgRÊFó7∆ïˆÊ÷SˆG∑RÊFó7∆ïˆÊ÷W“ÇG∑RÁW6W&Ê÷W“ñßW6W&Ê÷S∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆEFñ6∂WG2Çó∞¢G'ó∞¢vóB∆ˆEFñ6∂WD76ñvÊVW2Çrrì∞¢6ˆÁ7B∆√÷vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2rì∞¢Dî4¥UE3÷∆««≈µ”∞¢6ˆÁ7B6V∆V7FVC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFñ6∂WE7FGW4fñ«FW"rìÚÁf«VW«¬rs∞¢6ˆÁ7B&˜w3◊6V∆V7FVCıDî4¥UE2Êfñ«FW"áÉ”ÁÇÁ7FGW3””◊6V∆V7FVBì•Dî4¥UE3∞¢Fñ6∂WD˜V‚ÁFWáD6ˆÁFVÁC’Dî4¥UE2Êfñ«FW"áÉ”Â≤v˜V‚r¬v76ñvÊVBr¬wvóFñÊru“ÊñÊ6«VFW2áÇÁ7FGW2ííÊ∆VÊwFÉ∞¢Fñ6∂WDñÂ&ˆw&W72ÁFWáD6ˆÁFVÁC’Dî4¥UE2Êfñ«FW"áÉ”ÁÇÁ7FGW3””“vñÂ˜&ˆw&W72ríÊ∆VÊwFÉ∞¢Fñ6∂WE66ÜVGV∆VBÁFWáD6ˆÁFVÁC’Dî4¥UE2Êfñ«FW"áÉ”ÁÇÊ6∆VÊF%ˆWfVÁEˆñBbb≤v6∆˜6VBu“ÊñÊ6«VFW2áÇÁ7FGW2ííÊ∆VÊwFÉ∞¢Fñ6∂WD6∆˜6VBÁFWáD6ˆÁFVÁC’Dî4¥UE2Êfñ«FW"áÉ”ÁÇÁ7FGW3””“v6∆˜6VBríÊ∆VÊwFÉ∞¢6ˆÁ7B&FvS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFñ6∂WD&FvRrì∂ñbÜ&FvRñ&FvRÁFWáD6ˆÁFVÁC’Dî4¥UE2Êfñ«FW"áÉ”‚≤w&W6ˆ«fVBr¬v6∆˜6VBu“ÊñÊ6«VFW2áÇÁ7FGW2ííÊ∆VÊwFÉ∞¢6ˆÁ7Bfó6ñ&∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFñ6∂WEfó6ñ&∆T6˜VÁBrì∂ñbáfó6ñ&∆Rófó6ñ&∆RÁFWáD6ˆÁFVÁC÷ÇG∑&˜w2Ê∆VÊwFá“ñ∞¢Fñ6∂WE&˜w2ÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷áC”Ê«G#„«FB6∆73“&F÷ñ‚÷ˆÊ«í#„∆ñÁWB6∆73“'Fñ6∂WB◊&˜r÷6ÜV6≤Fñ6∂WB÷6ÜV6≤"GóS“&6ÜV6∂&˜Ç"f«VS“"G∑BÊñG“"ˆÊ6ÜÊvS“'WFFUFñ6∂WDFV∆WFU6V∆V7Fñˆ‚Çí"&ñ÷∆&V√“%6V∆V7BG∂W62áBÁFñ6∂WEˆÁV÷&W'«¬wFñ6∂WBró“#„¬˜FC„«FC„«7‚6∆73“'Fñ6∂WB÷ÁV÷&W"#‚G∂W62áBÁFñ6∂WEˆÁV÷&W'«¬uDµBró”¬˜7„„¬˜FC„«FC„«7‚6∆73“'7FGW2÷&FvR6WfW&óGí“G∑BÁ&ñ˜&óGì””“v7&óFñ6¬sÚv7&óFñ6¬sßBÁ&ñ˜&óGì””“vÜñvÇsÚvÜñvÇs¢v÷VFóV“w“#‚G∂W62áBÁ&ñ˜&óGíó”¬˜7„„¬˜FC„«FC„∆Fób6∆73“&Ê÷R#‚G∂W62áBÁFóF∆Ró”¬ˆFóc„∆Fób6∆73“&◊WFVB#‚G∂W62ÇáBÊFW67&óFñˆÁ«¬rríÁ6∆ñ6RÉ√#íó”¬ˆFóc„¬˜FC„«FC‚G∂W62áBÊFWfñ6UˆÊ÷W«¬~(	Bró”¬˜FC„«FC‚G∂W62áFñ6∂WD76ñvÊVT∆&V¬áBÊ76ñvÊVRíó”¬˜FC„«FC„«7‚6∆73“'7FGW2÷&FvR7FGW2◊Fñ6∂WB“G∂W62áBÁ7FGW2ó“#‚G∂W62áBÁ7FGW2Á&W∆6RÇuÚr¬rríó”¬˜7„„¬˜FC„«FC‚G∑BÊ6∆VÊF%ˆWfVÁEˆñCˆ«7‚6∆73“'Fñ6∂WB÷GVR#Ó)jbG∑BÊGVUˆCˆW62ÜÊWrFFRáBÊGVUˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢u66ÜVGV∆VBw”¬˜7„Ê¢áBÊGVUˆCˆW62ÜÊWrFFRáBÊGVUˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bró”¬˜FC„«FC‚G∂W62ÜÊWrFFRáBÁWFFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíó”¬˜FC„«FC„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&˜VÂFñ6∂WDVFóF˜"ÇG∑BÊñG“í#‰˜V„¬ˆ'WGFˆ„‚∆'WGFˆ‚6∆73“&∆ñÊ≤Fñ6∂WB÷FV∆WFR÷∆ñÊ≤F÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&FV∆WFUFñ6∂WBÇG∑BÊñG“í#‰FV∆WFS¬ˆ'WGFˆ„„¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#"6∆73“&V◊Gí#‰ÊÚFñ6∂WG2÷F6ÇFÜó2fñ«FW"„¬˜FC„¬˜G#‚s∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∑WFFUFñ6∂WDFV∆WFU6V∆V7Fñˆ‚Çì∞¢÷6F6ÇÜRó∑Fñ6∂WE&˜w2ÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#"6∆73“&V◊Gí#ÂFñ6∂WB˜'F¬VÊfñ∆&∆S¢r∂W62ÜRÊ÷W76vRí≤s¬˜FC„¬˜G#‚w–ß–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFUFñ6∂WBÜñBó∞¢6ˆÁ7BC’Dî4¥UE2ÊfñÊBáÉ”ÁÇÊñC””÷ñBó«ƒ5U%$TÂEıDî4¥UC∞¢ñbÇ6ˆÊfó&“ÜFV∆WFRFÜó2Fñ6∂WCı∆Â∆‚G∑CÚÁFñ6∂WEˆÁV÷&W'«¬uFñ6∂WB2r∂ñG“+rG∑CÚÁFóF∆W«¬rw’∆Â∆Âv˜&≤Ê˜FW2ÊBóG2∆ñÊ∂VBtÙE4UîR6∆VÊF"ˆñÁF÷VÁBvñ∆¬«6Ú&RFV∆WFVB‚FÜR˜&ñvñÊ¬fñÊFñÊr¬ñbÁí¬vñ∆¬&R&W6W'fVB‚FÜó26ÊÊ˜B&RVÊFˆÊRÊíó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂ñbÑ5U%$TÂEıDî4¥UCÚÊñC””÷ñBñ6∆˜6UFñ6∂WDVFóF˜"Çì∂vóB∆ˆEFñ6∂WG2Çì∂vóB∆ˆD6∆VÊF"Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFRFñ6∂WC¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFU6V∆V7FVEFñ6∂WG2Çó∞¢6ˆÁ7BñG3◊6V∆V7FVEFñ6∂WDñG2Çì∂ñbÇñG2Ê∆VÊwFÇó&WGW&„∞¢ñbÇ6ˆÊfó&“ÜFV∆WFRG∂ñG2Ê∆VÊwFá“6V∆V7FVBFñ6∂WBG∂ñG2Ê∆VÊwFÉ”””Úrs¢w2w”ı∆Â∆ÂFÜVó"v˜&≤Ê˜FW2ÊB∆ñÊ∂VBtÙE4UîR6∆VÊF"ˆñÁF÷VÁG2vñ∆¬«6Ú&RFV∆WFVB‚∆ñÊ∂VBfñÊFñÊw2vñ∆¬&R&W6W'fVB‚FÜó26ÊÊ˜B&RVÊFˆÊRÊíó&WGW&„∞¢G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2ˆ'V∆≤÷FV∆WFRr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑Fñ6∂WEˆñG3¶ñG7“ó“ì∂∆W'BÜFV∆WFVBG∑"ÊFV∆WFVG“Fñ6∂WBG∑"ÊFV∆WFVC”””Úrs¢w2w“Êì∂vóB∆ˆEFñ6∂WG2Çì∂vóB∆ˆD6∆VÊF"Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFR6V∆V7FVBFñ6∂WG3¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFTˆ∆EFñ6∂WG2Çó∞¢6ˆÁ7BFó3‘ÁV÷&W"ÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFñ6∂WDˆ∆DFó2rìÚÁf«VW«√ìì∞¢ñbÇ6ˆÊfó&“ÜFV∆WFR6∆˜6VBÊB&W6ˆ«fVBFñ6∂WG2ˆ∆FW"FÜ‚G∂Fó7“Fó3ı∆Â∆‰˜V‚¬76ñvÊVB¬ñ‚◊&ˆw&W72¬ÊBvóFñÊrFñ6∂WG2vñ∆¬‰ıB&RFV∆WFVB‚v˜&≤Ê˜FW2ÊB∆ñÊ∂VBtÙE4UîR6∆VÊF"ˆñÁF÷VÁG2f˜"FV∆WFVBFñ6∂WG2vñ∆¬«6Ú&R&V÷˜fVBÊíó&WGW&„∞¢G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2ˆFV∆WFR÷ˆ∆Br«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂ˆ∆FW%˜FÜÂˆFó3¶Fó7“ó“ì∂∆W'BÜFV∆WFVBG∑"ÊFV∆WFVG“ˆ∆B6ˆ◊∆WFVBFñ6∂WBG∑"ÊFV∆WFVC”””Úrs¢w2w“Êì∂vóB∆ˆEFñ6∂WG2Çì∂vóB∆ˆD6∆VÊF"Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFRˆ∆BFñ6∂WG3¢r∂RÊ÷W76vRó–ß–¶gVÊ7Fñˆ‚FVfV«EFñ6∂WE66ÜVGV∆RÇó∞¢6ˆÁ7B7F'C÷ÊWrFFRÇì∑7F'BÁ6WE6V6ˆÊG2É√ì∑7F'BÁ6WD÷ñÁWFW2Ñ÷FÇÊ6Vñ¬á7F'BÊvWD÷ñÁWFW2ÇíÛ3í£3ì∞¢6ˆÁ7BVÊC÷ÊWrFFRá7F'BÊvWEFñ÷RÇí≥c£c£ì∞¢Fñ6∂WE66ÜVGV∆U7F'BÁf«VS÷6∆VÊF$ó6Ù∆ˆ6¬á7F'Bì∑Fñ6∂WE66ÜVGV∆TVÊBÁf«VS÷6∆VÊF$ó6Ù∆ˆ6¬ÜVÊBì∞ß–¶7ñÊ2gVÊ7Fñˆ‚˜VÂFñ6∂WDVFóF˜"ÜñC÷ÁV∆¬ó∞¢Fñ6∂WDVFóF˜$W'"ÁFWáD6ˆÁFVÁC“rs¥5U%$TÂEıDî4¥UC÷ÁV∆√∑Fñ6∂WDVFóF˜$ñBÁf«VS÷ñG«¬rs∞¢vóB∆ˆEFñ6∂WD76ñvÊVW2Çrrì∞¢ñbÇñBó∞¢Fñ6∂WDVFóF˜%FóF∆RÁFWáD6ˆÁFVÁC“tÊWrFñ6∂WBs∑Fñ6∂WDVFóF˜%7V'FóF∆RÁFWáD6ˆÁFVÁC“t7&VFRÊBG&6≤˜W&FñˆÊ¬v˜&≤‚s∑Fñ6∂WEFóF∆RÁf«VS“rs∑Fñ6∂WDFW67&óFñˆ‚Áf«VS“rs∑Fñ6∂WE&ñ˜&óGíÁf«VS“v÷VFóV“s∑Fñ6∂WE7FGW2Áf«VS“v˜V‚s∑Fñ6∂WD76ñvÊVRÁf«VS“rs∑Fñ6∂WDFWfñ6RÁf«VS“rs∑Fñ6∂WDó77VUGóRÁf«VS“t˜FÜW"s∑Fñ6∂WE&WVW7FW$Ê÷RÁf«VS“rs∑Fñ6∂WE&WVW7FW$FW'F÷VÁBÁf«VS“rs∑Fñ6∂WE&WVW7FW%ÜˆÊRÁf«VS“rs∑Fñ6∂WE&WVW7FW$V÷ñ¬Áf«VS“rs∑Fñ6∂WD∆ñÊ∂VDñÊfÚÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∑Fñ6∂WE66ÜVGV∆U6V7Fñˆ‚Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∑Fñ6∂WDÊ˜FW56V7Fñˆ‚Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∑Fñ6∂WD6∆˜6T'F‚Ê6∆74∆ó7BÊFBÇwFñ6∂WB÷ÜñFFV‚rì∑Fñ6∂WDFV∆WFT'F‚Ê6∆74∆ó7BÊFBÇwFñ6∂WB÷ÜñFFV‚rì∂FVfV«EFñ6∂WE66ÜVGV∆RÇì∞¢÷V«6W∞¢G'ó∞¢6ˆÁ7BC÷vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr∂ñBì¥5U%$TÂEıDî4¥UC◊C∑Fñ6∂WDVFóF˜%FóF∆RÁFWáD6ˆÁFVÁC◊BÁFñ6∂WEˆÁV÷&W"≤r+rr∑BÁFóF∆S∑Fñ6∂WDVFóF˜%7V'FóF∆RÁFWáD6ˆÁFVÁC“t7&VFVBr∂ÊWrFFRáBÊ7&VFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇí≤r+r∆7BWFFVBr∂ÊWrFFRáBÁWFFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì∑Fñ6∂WEFóF∆RÁf«VS◊BÁFóF∆S∑Fñ6∂WDFW67&óFñˆ‚Áf«VS◊BÊFW67&óFñˆÁ«¬rs∑Fñ6∂WE&ñ˜&óGíÁf«VS◊BÁ&ñ˜&óGì∑Fñ6∂WE7FGW2Áf«VS◊BÁ7FGW3∑Fñ6∂WD76ñvÊVRÁf«VS◊BÊ76ñvÊVW«¬rs∑Fñ6∂WDFWfñ6RÁf«VS◊BÊFWfñ6UˆÊ÷W«¬rs∑Fñ6∂WE66ÜVGV∆U6V7Fñˆ‚Á7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∑Fñ6∂WDÊ˜FW56V7Fñˆ‚Á7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∑Fñ6∂WD6∆˜6T'F‚Ê6∆74∆ó7BÁFˆvv∆RÇwFñ6∂WB÷ÜñFFV‚r«BÁ7FGW3””“v6∆˜6VBrì∑Fñ6∂WDFV∆WFT'F‚Ê6∆74∆ó7BÁ&V÷˜fRÇwFñ6∂WB÷ÜñFFV‚rì∞¢ñbáBÊ∆ñÊ∂VEˆfñÊFñÊró∑Fñ6∂WD∆ñÊ∂VDñÊfÚÁ7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∑Fñ6∂WD∆ñÊ∂VDñÊfÚÊñÊÊW$ÖD‘√÷∆ñÊ∂VBWfVÁBfñÊFñÊs¢∆#‚G∂W62áBÊ∆ñÊ∂VEˆfñÊFñÊrÁFóF∆Ró”¬ˆ#‚+rG∂W62áBÊ∆ñÊ∂VEˆfñÊFñÊrÊ6ˆ◊WFW%ˆÊ÷Ró“+rWfVÁBG∑BÊ∆ñÊ∂VEˆfñÊFñÊrÊWfVÁEˆñG“+rG∂W62áBÊ∆ñÊ∂VEˆfñÊFñÊrÁ7FGW2ó÷–¢V«6RñbáBÊ∆ñÊ∂VEˆÊWGv˜&µˆfñÊFñÊró∑Fñ6∂WD∆ñÊ∂VDñÊfÚÁ7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∑Fñ6∂WD∆ñÊ∂VDñÊfÚÊñÊÊW$ÖD‘√÷∆ñÊ∂VBÊWGv˜&≤fñÊFñÊs¢∆#‚G∂W62áBÊ∆ñÊ∂VEˆÊWGv˜&µˆfñÊFñÊrÁFóF∆Ró”¬ˆ#‚+rG∂W62áBÊ∆ñÊ∂VEˆÊWGv˜&µˆfñÊFñÊrÁF&vWG«¬rró“+rG∂W62áBÊ∆ñÊ∂VEˆÊWGv˜&µˆfñÊFñÊrÁ7FGW2ó÷–¢V«6RFñ6∂WD∆ñÊ∂VDñÊfÚÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∞¢Fñ6∂WDÊ˜FW4∆ó7BÊñÊÊW$ÖD‘√“áBÊÊ˜FW7«≈µ“íÊ∆VÊwFÉÚáBÊÊ˜FW7«≈µ“íÊ÷Ü„”Ê∆Fób6∆73“'Fñ6∂WB÷Ê˜FR#„∆#‚G∂W62Ü‚ÊWFÜ˜"ó”¬ˆ#„«6÷∆√‚G∂W62ÜÊWrFFRÜ‚Ê7&VFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíó”¬˜6÷∆√„«‚G∂W62Ü‚ÊÊ˜FRó”¬˜„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚv˜&≤Ê˜FW2ñWB„¬ˆFóc‚s∞¢ñbáBÊGVUˆBó∂6ˆÁ7BVÊC÷ÊWrFFRáBÊGVUˆBì∑Fñ6∂WE66ÜVGV∆TVÊBÁf«VS÷6∆VÊF$ó6Ù∆ˆ6¬ÜVÊBì∂6ˆÁ7B7F'C÷ÊWrFFRÜVÊBÊvWEFñ÷RÇí”c£c£ì∑Fñ6∂WE66ÜVGV∆U7F'BÁf«VS÷6∆VÊF$ó6Ù∆ˆ6¬á7F'Bó÷V«6RFVfV«EFñ6∂WE66ÜVGV∆RÇì∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B∆ˆBFñ6∂WC¢r∂RÊ÷W76vRì∑&WGW&Á–¢–¢Fñ6∂WDVFóF˜$÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∂«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞ß–¶gVÊ7Fñˆ‚6∆˜6UFñ6∂WDVFóF˜"Çó∑Fñ6∂WDVFóF˜$÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rs¥5U%$TÂEıDî4¥UC÷ÁV∆√∑Fñ6∂WDFV∆WFT'F‚Ê6∆74∆ó7BÊFBÇwFñ6∂WB÷ÜñFFV‚ró–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFT7W'&VÁEFñ6∂WBÇó∂6ˆÁ7BñC‘ÁV÷&W"áFñ6∂WDVFóF˜$ñBÁf«VRì∂ñbÜñBñvóBFV∆WFUFñ6∂WBÜñBó–¶7ñÊ2gVÊ7Fñˆ‚6fUFñ6∂WBÇó∞¢6ˆÁ7BñC◊Fñ6∂WDVFóF˜$ñBÁf«VS∞¢Fñ6∂WDVFóF˜$W'"ÁFWáD6ˆÁFVÁC“rs∞¢G'ó∞¢ñbÜñBó∞¢6ˆÁ7B&ˆGì◊∑FóF∆SßFñ6∂WEFóF∆RÁf«VRÁG&ñ“Çí∆FW67&óFñˆ„ßFñ6∂WDFW67&óFñˆ‚Áf«VRÁG&ñ“Çí«7FGW3ßFñ6∂WE7FGW2Áf«VR«&ñ˜&óGìßFñ6∂WE&ñ˜&óGíÁf«VR∆76ñvÊVSßFñ6∂WD76ñvÊVRÁf«VRÁG&ñ“Çí∆GVUˆC§5U%$TÂEıDî4¥UCÚÊGVUˆG«∆ÁV∆«”∞¢vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr∂ñB«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂6∆˜6UFñ6∂WDVFóF˜"Çì∂vóB∆ˆEFñ6∂WG2Çì∞¢÷V«6W∞¢6ˆÁ7B&ˆGì◊∑FóF∆S¢áFñ6∂WEFóF∆RÁf«VRÁG&ñ“Çó««Fñ6∂WDó77VUGóRÁf«VRí∆FW67&óFñˆ„ßFñ6∂WDFW67&óFñˆ‚Áf«VRÁG&ñ“Çí«&ñ˜&óGìßFñ6∂WE&ñ˜&óGíÁf«VR∆76ñvÊVSßFñ6∂WD76ñvÊVRÁf«VRÁG&ñ“Çí∆FWfñ6UˆÊ÷SßFñ6∂WDFWfñ6RÁf«VRÁG&ñ“Çí«&WVW7FW%ˆÊ÷SßFñ6∂WE&WVW7FW$Ê÷RÁf«VRÁG&ñ“Çí«&WVW7FW%ˆFW'F÷VÁCßFñ6∂WE&WVW7FW$FW'F÷VÁBÁf«VRÁG&ñ“Çí«&WVW7FW%˜ÜˆÊSßFñ6∂WE&WVW7FW%ÜˆÊRÁf«VRÁG&ñ“Çí«&WVW7FW%ˆV÷ñ√ßFñ6∂WE&WVW7FW$V÷ñ¬Áf«VRÁG&ñ“Çó”∞¢vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂6∆˜6UFñ6∂WDVFóF˜"Çì∂vóB∆ˆEFñ6∂WG2Çì∞¢–¢÷6F6ÇÜRó∑Fñ6∂WDVFóF˜$W'"ÁFWáD6ˆÁFVÁC÷RÊ÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚66ÜVGV∆T7W'&VÁEFñ6∂WBÇó∞¢6ˆÁ7BñC‘ÁV÷&W"áFñ6∂WDVFóF˜$ñBÁf«VRì∂ñbÇñBó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr∂ñB≤r˜66ÜVGV∆Rr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑7F'EˆC¶ÊWrFFRáFñ6∂WE66ÜVGV∆U7F'BÁf«VRíÁFÙï4ı7G&ñÊrÇí∆VÊEˆC¶ÊWrFFRáFñ6∂WE66ÜVGV∆TVÊBÁf«VRíÁFÙï4ı7G&ñÊrÇí∆∆≈ˆFì¶f«6W“ó“ì∂6∆˜6UFñ6∂WDVFóF˜"Çì∂vóB∆ˆEFñ6∂WG2Çì∂vóB∆ˆD6∆VÊF"Çì∂∆W'BÇuFñ6∂WB66ÜVGV∆VBˆ‚6∆VÊF"‚ró÷6F6ÇÜRó∑Fñ6∂WDVFóF˜$W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B66ÜVGV∆RFñ6∂WC¢r∂RÊ÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚FEFñ6∂WDÊ˜FRÇó∞¢6ˆÁ7BñC‘ÁV÷&W"áFñ6∂WDVFóF˜$ñBÁf«VRí∆Ê˜FS◊Fñ6∂WDÊ˜FUFWáBÁf«VRÁG&ñ“Çì∂ñbÇñG«¬Ê˜FRó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr∂ñB≤rˆÊ˜FW2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂Ê˜FW“ó“ì∑Fñ6∂WDÊ˜FUFWáBÁf«VS“rs∂6∆˜6UFñ6∂WDVFóF˜"Çì∂vóB∆ˆEFñ6∂WG2Çó÷6F6ÇÜRó∑Fñ6∂WDVFóF˜$W'"ÁFWáD6ˆÁFVÁC÷RÊ÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚6∆˜6T7W'&VÁEFñ6∂WBÇó∞¢6ˆÁ7BñC‘ÁV÷&W"áFñ6∂WDVFóF˜$ñBÁf«VRì∂ñbÇñBó&WGW&„∞¢6ˆÁ7BÊ˜FS◊&ˆ◊BÇt6∆˜6ñÊrÊ˜FRÜ˜FñˆÊ¬ì¢ró«¬rs∞¢6ˆÁ7B&W6ˆ«fT∆ñÊ∂VC“Ñ5U%$TÂEıDî4¥UCÚÊ∆ñÊ∂VEˆfñÊFñÊw«ƒ5U%$TÂEıDî4¥UCÚÊ∆ñÊ∂VEˆÊWGv˜&µˆfñÊFñÊríbf6ˆÊfó&“Çt«6Ú&W6ˆ«fRFÜR∆ñÊ∂VBfñÊFñÊsÚrì∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG2Úr∂ñB≤rˆ6∆˜6Rr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂Ê˜FR«&W6ˆ«fUˆ∆ñÊ∂VEˆfñÊFñÊsß&W6ˆ«fT∆ñÊ∂VG“ó“ì∂6∆˜6UFñ6∂WDVFóF˜"Çì∂vóB∆ˆEFñ6∂WG2Çì∂vóB∆ˆDWfVÁDfñÊFñÊw2Çì∂vóB∆ˆD6∆VÊF"Çó÷6F6ÇÜRó∑Fñ6∂WDVFóF˜$W'"ÁFWáD6ˆÁFVÁC÷RÊ÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆD6∆‘dvVÁG2Çó∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆÷dvVÁD∆ó7Brì∂ñbÇV¬ó&WGW&„∑G'ó∂6ˆÁ7B&˜w3÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2rì∂6ˆÁ7BvVÁG3‘'&íÊó4'&íá&˜w2ì˜&˜w3•µ”∂V¬ÊñÊÊW$ÖD‘√÷vVÁG2Ê∆VÊwFÉˆvVÁG2Ê÷Ü”Ê∆Fób6∆73“'ÊV¬"7Gñ∆S“&Fó7∆ì¶f∆WÉ∂∆ñv‚÷óFV◊3¶6VÁFW#∂ßW7Fñgí÷6ˆÁFVÁCß76R÷&WGvVV„∂v£'É∂÷&vñ„£áÇ#„∆Fóc„∆#‚G∂W62ÜÊ6ˆ◊WFW%ˆÊ÷W«∆ÊÜ˜7FÊ÷W«¬uvñÊF˜w2vVÁBró”¬ˆ#„∆Fób6∆73“&◊WFVB#‚G∂W62ÜÊvVÁE˜fW'6ñˆÁ«¬wVÊ∂Ê˜v‚ró“+rG∂ÊˆÊ∆ñÊSÚtˆÊ∆ñÊRs¢tˆff∆ñÊRw“+r6∆‘b'VÁ2∆ˆ6∆«ì¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“'&ñ÷'í"G∂ÊˆÊ∆ñÊSÚrs¢vFó6&∆VBw“ˆÊ6∆ñ6≥“'VWVT6∆‘e66‚ÇG∂ÊñG“í#Â66‚vóFÇ6∆‘c¬ˆ'WGFˆ„„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚVÁ&ˆ∆∆VBvñÊF˜w2vVÁG2„¬ˆFóc‚w÷6F6ÇÜRó∂V¬ÁFWáD6ˆÁFVÁC“uVÊ&∆RFÚ∆ˆBvñÊF˜w2vVÁG3¢r∂RÊ÷W76vW◊–¶7ñÊ2gVÊ7Fñˆ‚VWVT6∆‘e66‚ÜñBó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB≤rˆ6∆÷b◊66‚r«∂÷WFÜˆC¢uı5Bw“ì∂∆W'Bá"Ê÷W76vW«¬t6∆‘b66‚VWVVB‚ró÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BVWVR6∆‘b66„¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚∆ˆD÷ñ7&˜6ˆgEvñÊF˜w5WFFW5fñWrÇó∞¢6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷ñ7&˜6ˆgEvñÊF˜w5WFFW4∆ó7Brì∂ñbÇV¬ó&WGW&„∞¢G'ó∂6ˆÁ7BvVÁG3÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2rì∂V¬ÊñÊÊW$ÖD‘√÷vVÁG2Ê∆VÊwFÉˆvVÁG2Ê÷Ü”‚s∆Fób6∆73“'vñÊF˜w2÷vVÁB◊&˜r#„«7‚6∆73“'vñÊF˜w2÷vVÁB÷ñ6ˆ‚#Âs¬˜7„„∆Fóc„∆#‚r∂W62ÜÊ6ˆ◊WFW%ˆÊ÷W«∆ÊÜ˜7FÊ÷W«¬uvñÊF˜w26ˆ◊WFW"rí≤s¬ˆ#„«6÷∆√‚r∂W62ÜÊ˜5˜fW'6ñˆÁ«¬uvñÊF˜w2rí≤r+rr∂W62ÜÁ7FGW7«¬wVÊ∂Ê˜v‚rí≤r+rvVÁBr∂W62ÜÊvVÁE˜fW'6ñˆÁ«¬~(	Brí≤s¬˜6÷∆√„∆FóbñC“&◊7wR◊7FGW2“r∂ÊñB≤r"6∆73“&◊WFVB#Â&VGíFÚ66‚„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“'66ÂvñÊF˜w5WFFW5fñWrÇr∂ÊñB≤rí#Â66‚÷ñ7&˜6ˆgBWFFW3¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFóc‚ríÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚVÁ&ˆ∆∆VBvñÊF˜w26ˆ◊WFW'2„¬ˆFóc‚w÷6F6ÇÜRó∂V¬ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰6˜V∆BÊ˜B∆ˆBvñÊF˜w26ˆ◊WFW'3¢r∂W62ÜRÊ÷W76vRí≤s¬ˆFóc‚w–ß–¶7ñÊ2gVÊ7Fñˆ‚66ÂvñÊF˜w5WFFW5fñWrÜñBó∞¢6ˆÁ7B˜WC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv◊7wR◊7FGW2“r∂ñBì∂ñbÜ˜WBñ˜WBÁFWáD6ˆÁFVÁC“u66ÊÊñÊr÷ñ7&˜6ˆgBvñÊF˜w2WFF^(
bs∞¢G'ó∂6ˆÁ7B÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB≤r˜vñÊF˜w2◊WFFW2˜66‚r«∂÷WFÜˆC¢uı5Bw“ì∂f˜"Ü∆WBì”∂ì√C∂í≤≤ó∂vóBÊWr&ˆ÷ó6Rá#”Á6WEFñ÷V˜WBá"√Síì∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2ˆ6ˆ÷÷ÊG2Úr∑Ê6ˆ÷÷ÊEˆñBì∂ñbá"Á7FGW3””“v6ˆ◊∆WFVBw««"Á7FGW3””“vfñ∆VBró∂ñbá"Á7FGW3””“vfñ∆VBw««"Á&W7V«CÚÊˆ≥””÷f«6Ró∂˜WBÁFWáD6ˆÁFVÁC“u66‚fñ∆VC¢r≤á"Á&W7V«CÚÊFWFñ«7«¬vvVÁBW'&˜"rì∑&WGW&Á÷6ˆÁ7BWFFW3◊"Á&W7V«CÚÁWFFW7«≈µ”∂ñbÇWFFW2Ê∆VÊwFÇó∂˜WBÁFWáD6ˆÁFVÁC“t÷ñ7&˜6ˆgBvñÊF˜w2&W˜'G2ÊÚ÷ó76ñÊrWFFW2‚s∑&WGW&Á÷˜WBÊñÊÊW$ÖD‘√◊WFFW2Ê÷áS”‚s∆∆&V¬7Gñ∆S“&Fó7∆ì¶&∆ˆ6≥∂÷&vñ„£GÇ#„∆ñÁWBGóS“&6ÜV6∂&˜Ç"6∆73“&◊7wR÷6Üˆñ6R“r∂ñB≤r"f«VS“"r∂W62Ö7G&ñÊráRÊñG««RÁWFFUˆñG«¬rríí≤r#‚r∂W62áRÁFóF∆W««RÊÊ÷W««RÊ∂'«≈7G&ñÊráRÊñG«¬uvñÊF˜w2WFFRríí≤s¬ˆ∆&V√‚ríÊ¶ˆñ‚Çrrí≤s∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“&ñÁ7F∆≈vñÊF˜w5WFFW5fñWrÇr∂ñB≤rí#‰ñÁ7F∆¬6V∆V7FVC¬ˆ'WGFˆ„‚s∑&WGW&Á◊÷˜WBÁFWáD6ˆÁFVÁC“u66‚ó27Fñ∆¬'VÊÊñÊs≤&Vg&W6Ç6Ü˜'F«í‚w÷6F6ÇÜRó∂ñbÜ˜WBñ˜WBÁFWáD6ˆÁFVÁC“u66‚fñ∆VC¢r∂RÊ÷W76vW–ß–¶7ñÊ2gVÊ7Fñˆ‚ñÁ7F∆≈vñÊF˜w5WFFW5fñWrÜñBó∞¢6ˆÁ7B˜WC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv◊7wR◊7FGW2“r∂ñBí∆ñG3’≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ◊7wR÷6Üˆñ6R“r∂ñB≤s¶6ÜV6∂VBrï“Ê÷áÉ”ÁÇÁf«VRíÊfñ«FW"Ñ&ˆˆ∆V‚ì∂ñbÇñG2Ê∆VÊwFÇó∂∆W'BÇu6V∆V7BB∆V7BˆÊRWFFR‚rì∑&WGW&Á÷˜WBÁFWáD6ˆÁFVÁC“tñÁ7F∆∆ñÊr6V∆V7FVB÷ñ7&˜6ˆgBWFFW>(
bs∑G'ó∂6ˆÁ7B÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2Úr∂ñB≤r˜vñÊF˜w2◊WFFW2ˆñÁ7F∆¬r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑WFFUˆñG3¶ñG7“ó“ì∂f˜"Ü∆WBì”∂ì√É∂í≤≤ó∂vóBÊWr&ˆ÷ó6Rá#”Á6WEFñ÷V˜WBá"√Síì∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜vñÊF˜w2÷vVÁG2ˆ6ˆ÷÷ÊG2Úr∑Ê6ˆ÷÷ÊEˆñBì∂ñbá"Á7FGW3””“v6ˆ◊∆WFVBw««"Á7FGW3””“vfñ∆VBró∂˜WBÁFWáD6ˆÁFVÁC◊"Á7FGW3””“v6ˆ◊∆WFVBsÚt÷ñ7&˜6ˆgBvñÊF˜w2WFFRñÁ7F∆∆Fñˆ‚6ˆ◊∆WFVB‚s¢ÇtñÁ7F∆¬fñ∆VC¢r≤á"Á&W7V«CÚÊFWFñ«7«¬vvVÁBW'&˜"ríì∑&WGW&Á◊÷˜WBÁFWáD6ˆÁFVÁC“tñÁ7F∆∆Fñˆ‚ó27Fñ∆¬'VÊÊñÊs≤&Vg&W6Ç6Ü˜'F«í‚w÷6F6ÇÜRó∂˜WBÁFWáD6ˆÁFVÁC“tñÁ7F∆¬fñ∆VC¢r∂RÊ÷W76vW–ß–¶6ˆÁ7B5î$U%ıDÙÙ≈Ù‰‘U3◊∂ÊWGv˜&µˆWá˜7W&S¢tÊWGv˜&≤Wá˜7W&Rr∆VÊGˆñÁE˜˜7GW&S¢tVÊGˆñÁB˜7GW&Rr«vV%˜F«3¢uvV"bD≈2r∆÷«v&Uˆñˆ3¢t÷«v&RbîÙ2r∆FÁ5ˆV÷ñ√¢tDÂ2bV÷ñ¬r∆∆ñÁWÖˆVFóC¢t∆ñÁWÇVFóBr«Fá&VEˆFWFV7Fñˆ„¢uFá&VBFWFV7Fñˆ‚r∆WfñFVÊ6Uˆ6GW&S¢tWfñFVÊ6R6GW&Rw”∞¶6ˆÁ7B5î$U%Ùƒ5Eı%T„◊∑”∞¶gVÊ7Fñˆ‚7ñ&W$ñÁWBÜñBó∑&WGW&‚ÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBìÚÁf«VW«¬rríÁG&ñ“Çó–¶7ñÊ2gVÊ7Fñˆ‚7ñ&W$fñ∆Uñ∆ˆBÇó∂6ˆÁ7Bfñ∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7ñ&W"÷÷«v&R÷fñ∆RrìÚÊfñ∆W3ÚÂ≥”∂ñbÇfñ∆Ró&WGW&Á∑”∂ñbÜfñ∆RÁ6ó¶S„£#B£#BóFá&˜rÊWrW'&˜"ÇuFÜRfñ∆R◊W7B&R‘"˜"6÷∆∆W"‚rì∂6ˆÁ7BVÊ6ˆFVC÷vóBÊWr&ˆ÷ó6RÇá&W6ˆ«fR«&V¶V7Bì”Á∂6ˆÁ7B&VFW#÷ÊWrfñ∆U&VFW"Çì∑&VFW"ÊˆÊ∆ˆC“Çì”Á&W6ˆ«fRÖ7G&ñÊrá&VFW"Á&W7V«BíÁ7∆óBÇr¬r√"ï≥◊«¬rrì∑&VFW"ÊˆÊW'&˜#“Çì”Á&V¶V7BÜÊWrW'&˜"Çt6˜V∆BÊ˜B&VBFÜR6V∆V7FVBfñ∆R‚ríì∑&VFW"Á&VD4FFU$¬Üfñ∆Ró“ì∑&WGW&Á∂fñ∆VÊ÷S¶fñ∆RÊÊ÷R∆fñ∆Uˆ&6ScC¶VÊ6ˆFVG◊–¶7ñÊ2gVÊ7Fñˆ‚7ñ&W%Fˆˆ≈ñ∆ˆBáFˆˆ¬ó∞¢ñbáFˆˆ√””“vÊWGv˜&µˆWá˜7W&Rró&WGW&Á∑Fˆˆ¬«F&vWC¶7ñ&W$ñÁWBÇv7ñ&W"÷ÊWGv˜&≤◊F&vWBrí«&ˆfñ∆S¶7ñ&W$ñÁWBÇv7ñ&W"÷ÊWGv˜&≤◊&ˆfñ∆Rrí∆˜FñˆÁ3ß∑◊”∞¢ñbáFˆˆ√””“vVÊGˆñÁE˜˜7GW&Rró&WGW&Á∑Fˆˆ¬«F&vWC¢t∆¬VÁ&ˆ∆∆VBVÊGˆñÁG2r«&ˆfñ∆S¢w7FÊF&Br∆˜FñˆÁ3ß∑◊”∞¢ñbáFˆˆ√””“wvV%˜F«2ró&WGW&Á∑Fˆˆ¬«F&vWC¶7ñ&W$ñÁWBÇv7ñ&W"◊vV"◊F&vWBrí«&ˆfñ∆S¶7ñ&W$ñÁWBÇv7ñ&W"◊vV"◊&ˆfñ∆Rrí∆˜FñˆÁ3ß∑◊”∞¢ñbáFˆˆ√””“v÷«v&Uˆñˆ2ró&WGW&Á∑Fˆˆ¬«F&vWC¶7ñ&W$ñÁWBÇv7ñ&W"÷÷«v&R◊F&vWBrí«&ˆfñ∆S¢w7FÊF&Br∆˜FñˆÁ3¶vóB7ñ&W$fñ∆Uñ∆ˆBÇó”∞¢ñbáFˆˆ√””“vFÁ5ˆV÷ñ¬ró&WGW&Á∑Fˆˆ¬«F&vWC¶7ñ&W$ñÁWBÇv7ñ&W"÷FÁ2◊F&vWBrí«&ˆfñ∆S¢w7FÊF&Br∆˜FñˆÁ3ß∑6V∆V7F˜#¶7ñ&W$ñÁWBÇv7ñ&W"÷FÁ2◊6V∆V7F˜"ró«¬vFVfV«Bw◊”∞¢ñbáFˆˆ√””“v∆ñÁWÖˆVFóBró&WGW&Á∑Fˆˆ¬«F&vWC¢ttÙE4UîR∆ñÊ6Rr«&ˆfñ∆S¶7ñ&W$ñÁWBÇv7ñ&W"÷∆ñÁWÇ◊&ˆfñ∆Rrí∆˜FñˆÁ3ß∑◊”∞¢ñbáFˆˆ√””“wFá&VEˆFWFV7Fñˆ‚ró&WGW&Á∑Fˆˆ¬«F&vWC¢u7W&ñ6FUdRr«&ˆfñ∆S¶7ñ&W$ñÁWBÇv7ñ&W"◊Fá&VB◊&ˆfñ∆Rrí∆˜FñˆÁ3ß∑◊”∞¢ñbáFˆˆ√””“vWfñFVÊ6Uˆ6GW&Rró&WGW&Á∑Fˆˆ¬«F&vWC¶7ñ&W$ñÁWBÇv7ñ&W"÷WfñFVÊ6R◊F&vWBrí«&ˆfñ∆S¢w7FÊF&Br∆˜FñˆÁ3ß∂ñÁFW&f6S¶7ñ&W$ñÁWBÇv7ñ&W"÷WfñFVÊ6R÷ñÁFW&f6Rrí«6V6ˆÊG3§ÁV÷&W"Ü7ñ&W$ñÁWBÇv7ñ&W"÷WfñFVÊ6R◊6V6ˆÊG2ró«√í«6∂WEˆ6˜VÁC§ÁV÷&W"Ü7ñ&W$ñÁWBÇv7ñ&W"÷WfñFVÊ6R÷6˜VÁBró«√ó◊”∞¢Fá&˜rÊWrW'&˜"ÇuVÊ∂Ê˜v‚7ñ&W"Fˆˆ¬‚rì∞ß–¶gVÊ7Fñˆ‚7ñ&W%&W7V«EFWáBá'V‚ó∂∆WBFWFñ√‘•4Ù‚Á7G&ñÊvñgíá'V‚Á&W7V«G««∑“∆ÁV∆¬√"ì∂ñbÜFWFñ¬Ê∆VÊwFÉ„ñFWFñ√÷FWFñ¬Á6∆ñ6RÉ√í≤u∆Ó(
b&W7V«B6Ü˜'FVÊVBˆ‚67&VV„≤Wá˜'B&WFñÁ2FÜR7F˜&VB&W˜'B‚s∑&WGW&‚'V‚Á7V÷÷'í≤u∆Â∆‚r∂FWFñ«–¶gVÊ7Fñˆ‚&VÊFW$7ñ&W$7FñˆÁ2áFˆˆ¬«'V‚ó∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7ñ&W"÷7FñˆÁ2“r∑Fˆˆ¬ì∂ñbÇV¬ó&WGW&„¥5î$U%Ùƒ5Eı%TÂ∑Fˆˆ≈”◊'V„∂6ˆÁ7BF˜vÊ∆ˆC◊'V‚Á&W7V«CÚÊF˜vÊ∆ˆE˜W&√ˆ∆6∆73“'6V6ˆÊF'í"á&Vc“"G∂W62á'V‚Á&W7V«BÊF˜vÊ∆ˆE˜W&¬ó“#‰F˜vÊ∆ˆB4¬ˆÊ¢rs∂V¬ÊñÊÊW$ÖD‘√÷∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&7&VFT7ñ&W$fñÊFñÊrÇrG∑Fˆˆ«“rí#‰7&VFRfñÊFñÊs¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“&7&VFT7ñ&W%Fñ6∂WBÇrG∑Fˆˆ«“rí#‰7&VFRFñ6∂WC¬ˆ'WGFˆ„„∆6∆73“'6V6ˆÊF'í"á&Vc“"ˆí˜cˆ7ñ&W"◊Fˆˆ«2˜'VÁ2ÚG∑'V‚ÊñG“ˆWá˜'B#‰Wá˜'B•4Ù„¬ˆ‚G∂F˜vÊ∆ˆG÷∂V¬Ê6∆74∆ó7BÊFBÇwfó6ñ&∆Rró–¶7ñÊ2gVÊ7Fñˆ‚'V‰7ñ&W%Fˆˆ¬áFˆˆ¬ó∂6ˆÁ7B˜WC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7ñ&W"◊&W7V«B“r∑Fˆˆ¬í∆'WGFˆ„÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜"Ü∂FF÷7ñ&W"◊'V„“"G∑Fˆˆ«“%÷í∆&FvS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7ñ&W"÷6“r∑Fˆˆ¬ì∂ñbÜ˜WBó∂˜WBÊ6∆74Ê÷S“v7ñ&W"÷6&B◊&W7V«B'VÊÊñÊrs∂˜WBÁFWáD6ˆÁFVÁC“u'VÊÊñÊrr≤Ñ5î$U%ıDÙÙ≈Ù‰‘U5∑Fˆˆ≈◊««Fˆˆ¬í≤~(
bw÷ñbÜ'WGFˆ‚ñ'WGFˆ‚ÊFó6&∆VC◊G'VS∂ñbÜ&FvRó∂&FvRÊ6∆74Ê÷S“v7ñ&W"◊Fˆˆ¬◊7FGW2'VÊÊñÊrs∂&FvRÁFWáD6ˆÁFVÁC“u'VÊÊñÊrw◊G'ó∂6ˆÁ7Bñ∆ˆC÷vóB7ñ&W%Fˆˆ≈ñ∆ˆBáFˆˆ¬í«'V„÷vóBß6ˆ‚Çrˆí˜cˆ7ñ&W"◊Fˆˆ«2˜'V‚r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíáñ∆ˆBó“ì∂ñbÜ˜WBó∂˜WBÊ6∆74Ê÷S“v7ñ&W"÷6&B◊&W7V«Br≤á'V‚Á7FGW3””“vfñ∆VBsÚrfñ∆VBs¢rrì∂˜WBÁFWáD6ˆÁFVÁC÷7ñ&W%&W7V«EFWáBá'V‚ó◊&VÊFW$7ñ&W$7FñˆÁ2áFˆˆ¬«'V‚ì∂vóB∆ˆD7ñ&W$Üó7F˜'íÇó÷6F6ÇÜRó∂ñbÜ˜WBó∂˜WBÊ6∆74Ê÷S“v7ñ&W"÷6&B◊&W7V«Bfñ∆VBs∂˜WBÁFWáD6ˆÁFVÁC“u'V‚fñ∆VC¢r∂RÊ÷W76vW◊÷fñÊ∆«ó∂ñbÜ'WGFˆ‚ñ'WGFˆ‚ÊFó6&∆VC÷f«6S∂vóB∆ˆD7ñ&W$6&ñ∆óFñW2Çó◊–¶7ñÊ2gVÊ7Fñˆ‚7&VFT7ñ&W$fñÊFñÊráFˆˆ¬ó∂6ˆÁ7B'V„‘5î$U%Ùƒ5Eı%TÂ∑Fˆˆ≈”∂ñbÇ'V‚ó&WGW&„∑G'ó∂6ˆÁ7BfñÊFñÊs÷vóBß6ˆ‚Çrˆí˜cˆ7ñ&W"◊Fˆˆ«2˜'VÁ2Úr∑'V‚ÊñB≤rˆ7&VFR÷fñÊFñÊrr«∂÷WFÜˆC¢uı5Bw“ì∂∆W'BÇtfñÊFñÊr2r∂fñÊFñÊrÊñB≤r7&VFVB‚rì∂vóB∆ˆD7ñ&W$Üó7F˜'íÇó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B7&VFRfñÊFñÊs¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚7&VFT7ñ&W%Fñ6∂WBáFˆˆ¬ó∂6ˆÁ7B'V„‘5î$U%Ùƒ5Eı%TÂ∑Fˆˆ≈”∂ñbÇ'V‚ó&WGW&„∑G'ó∂6ˆÁ7BFñ6∂WC÷vóBß6ˆ‚Çrˆí˜cˆ7ñ&W"◊Fˆˆ«2˜'VÁ2Úr∑'V‚ÊñB≤rˆ7&VFR◊Fñ6∂WBr«∂÷WFÜˆC¢uı5Bw“ì∂∆W'BÇáFñ6∂WBÁFñ6∂WEˆÁV÷&W'«¬uFñ6∂WBrí≤r7&VFVB‚rì∂vóB∆ˆD7ñ&W$Üó7F˜'íÇó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B7&VFRFñ6∂WC¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚66ÜVGV∆T7ñ&W%Fˆˆ¬áFˆˆ¬ó∑G'ó∂6ˆÁ7Bñ∆ˆC÷vóB7ñ&W%Fˆˆ≈ñ∆ˆBáFˆˆ¬í«f«VS◊&ˆ◊BÇu'V‚WfW'íÜ˜r÷Áí÷ñÁWFW3Ú÷ñÊñ◊V“R‚r¬sCCrì∂ñbáf«VS””÷ÁV∆¬ó&WGW&„∂6ˆÁ7BñÁFW'f√‘ÁV÷&W"áf«VRì∂ñbÇÁV÷&W"Êó4fñÊóFRÜñÁFW'f¬ó«∆ñÁFW'f√√Ró∂∆W'BÇtVÁFW"R÷ñÁWFW2˜"÷˜&R‚rì∑&WGW&Á◊ñ∆ˆBÊñÁFW'f≈ˆ÷ñÁWFW3‘÷FÇÁ&˜VÊBÜñÁFW'f¬ì∂6ˆÁ7B&˜s÷vóBß6ˆ‚Çrˆí˜cˆ7ñ&W"◊Fˆˆ«2˜66ÜVGV∆W2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíáñ∆ˆBó“ì∂∆W'BÇu66ÜVGV∆R7&VFVB‚ÊWáB'V„¢r∂ÊWrFFRá&˜rÊÊWáE˜'VÂˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì∂vóB∆ˆD7ñ&W%66ÜVGV∆W2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B7&VFR66ÜVGV∆S¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFT7ñ&W%66ÜVGV∆RÜñBó∂ñbÇ6ˆÊfó&“ÇtFV∆WFRFÜó2&V7W'&ñÊr7ñ&W"Fˆˆ¬66ÜVGV∆SÚríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆ7ñ&W"◊Fˆˆ«2˜66ÜVGV∆W2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆD7ñ&W%66ÜVGV∆W2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFR66ÜVGV∆S¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚∆ˆD7ñ&W$6&ñ∆óFñW2Çó∑G'ó∂6ˆÁ7B63÷vóBß6ˆ‚Çrˆí˜cˆ7ñ&W"◊Fˆˆ«2ˆ6&ñ∆óFñW2rì¥ˆ&¶V7BÊVÁG&ñW2Ü62íÊf˜$V6ÇÇÖ∑Fˆˆ¬∆6“ì”Á∂6ˆÁ7B&FvS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7ñ&W"÷6“r∑Fˆˆ¬í∆'WGFˆ„÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜"Ü∂FF÷7ñ&W"◊'V„“"G∑Fˆˆ«“%÷ì∂ñbÜ&FvRó∂&FvRÁFWáD6ˆÁFVÁC÷6Êfñ∆&∆SÚÜ6ÊVÊvñÊW«¬tfñ∆&∆Rrì¢u6WGW&WVó&VBs∂&FvRÁFóF∆S÷6Á6˜W&6W«∆6ÊVÊvñÊW«¬rs∂&FvRÊ6∆74Ê÷S“v7ñ&W"◊Fˆˆ¬◊7FGW2r≤Ü6Êfñ∆&∆SÚw&VGís¢wVÊfñ∆&∆Rró÷ñbÜ'WGFˆ‚ñ'WGFˆ‚ÊFó6&∆VC“6Êfñ∆&∆S∂ñbáFˆˆ√””“vWfñFVÊ6Uˆ6GW&Rró∂6ˆÁ7B6V∆V7C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7ñ&W"÷WfñFVÊ6R÷ñÁFW&f6Rrí∆7W'&VÁC◊6V∆V7CÚÁf«VS∂ñbá6V∆V7Bó∂6ˆÁ7BñÁFW&f6W3÷6ÊñÁFW&f6W7«≈µ”∑6V∆V7BÊñÊÊW$ÖD‘√÷ñÁFW&f6W2Ê∆VÊwFÉˆñÁFW&f6W2Ê÷áÉ”Ê∆˜Fñˆ‚f«VS“"G∂W62áÇó“#‚G∂W62áÇó”¬ˆ˜Fñˆ„ÊíÊ¶ˆñ‚Çrrì¢s∆˜Fñˆ‚f«VS“"#‰ÊÚñÁFW&f6W2f˜VÊC¬ˆ˜Fñˆ„‚s∂ñbÜ7W'&VÁBbfñÁFW&f6W2ÊñÊ6«VFW2Ü7W'&VÁBíó6V∆V7BÁf«VS÷7W'&VÁG◊◊“ó÷6F6ÇÜRó∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂ñE„“&7ñ&W"÷6“%“ríÊf˜$V6ÇáÉ”Á∑ÇÁFWáD6ˆÁFVÁC“uVÊfñ∆&∆Rs∑ÇÊ6∆74Ê÷S“v7ñ&W"◊Fˆˆ¬◊7FGW2VÊfñ∆&∆Rw“ó◊–¶7ñÊ2gVÊ7Fñˆ‚∆ˆD7ñ&W$Üó7F˜'íÇó∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7ñ&W$Üó7F˜'írì∂ñbÇV¬ó&WGW&„∑G'ó∂6ˆÁ7B&˜w3÷vóBß6ˆ‚Çrˆí˜cˆ7ñ&W"◊Fˆˆ«2˜'VÁ3ˆ∆ñ÷óC”3rì∂V¬ÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷á'V„”Ê∆Fób6∆73“&7ñ&W"÷Üó7F˜'í◊&˜r#„∆Fóc„∆Fób6∆73“&7ñ&W"÷Üó7F˜'í◊Fˆˆ¬#‚G∂W62Ñ5î$U%ıDÙÙ≈Ù‰‘U5∑'V‚ÁFˆˆ≈◊««'V‚ÁFˆˆ¬ó”¬ˆFóc„∆Fób6∆73“&7ñ&W"÷Üó7F˜'í÷÷WF#‚G∂ÊWrFFRá'V‚Ê6ˆ◊∆WFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇó”¬ˆFóc„¬ˆFóc„∆Fóc„∆#‚G∂W62á'V‚Á7V÷÷'ó«¬t6ˆ◊∆WFVBró”¬ˆ#„∆Fób6∆73“&7ñ&W"÷Üó7F˜'í÷÷WF#‚G∂W62á'V‚ÁF&vWG«¬ttÙE4UîR∆ñÊ6Rró“+rG∂W62á'V‚Á&ˆfñ∆Ró”¬ˆFóc„¬ˆFóc„∆Fób6∆73“&7FñˆÁ2#„«7‚6∆73“&7ñ&W"÷Üó7F˜'í◊7FFRG∑'V‚Á7FGW3””“vfñ∆VBsÚvfñ∆VBs¢rw“#‚G∂W62á'V‚Á7FGW2ó”¬˜7„„∆6∆73“'6V6ˆÊF'í"á&Vc“"ˆí˜cˆ7ñ&W"◊Fˆˆ«2˜'VÁ2ÚG∑'V‚ÊñG“ˆWá˜'B#‰Wá˜'C¬ˆ„¬ˆFóc„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚ7ñ&W"Fˆˆ¬'VÁ2ñWB„¬ˆFóc‚w÷6F6ÇÜRó∂V¬ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰6˜V∆BÊ˜B∆ˆB66‚Üó7F˜'ì¢r∂W62ÜRÊ÷W76vRí≤s¬ˆFóc‚w◊–¶7ñÊ2gVÊ7Fñˆ‚∆ˆD7ñ&W%66ÜVGV∆W2Çó∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7ñ&W%66ÜVGV∆W2rì∂ñbÇV¬ó&WGW&„∑G'ó∂6ˆÁ7B&˜w3÷vóBß6ˆ‚Çrˆí˜cˆ7ñ&W"◊Fˆˆ«2˜66ÜVGV∆W2rì∂V¬ÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷á&˜s”Ê∆Fób6∆73“&7ñ&W"◊66ÜVGV∆R◊&˜r#„∆Fóc„∆#‚G∂W62Ñ5î$U%ıDÙÙ≈Ù‰‘U5∑&˜rÁFˆˆ≈◊««&˜rÁFˆˆ¬ó”¬ˆ#„∆Fób6∆73“&7ñ&W"÷Üó7F˜'í÷÷WF#‰WfW'íG∑&˜rÊñÁFW'f≈ˆ÷ñÁWFW7“÷ñ‚+rÊWáBG∂ÊWrFFRá&˜rÊÊWáE˜'VÂˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇó”¬ˆFóc„¬ˆFóc„∆'WGFˆ‚6∆73“&FÊvW""ˆÊ6∆ñ6≥“&FV∆WFT7ñ&W%66ÜVGV∆RÇG∑&˜rÊñG“í#‰FV∆WFS¬ˆ'WGFˆ„„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚ&V7W'&ñÊr6ÜV6∑266ÜVGV∆VB„¬ˆFóc‚w÷6F6ÇÜRó∂V¬ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰6˜V∆BÊ˜B∆ˆB66ÜVGV∆W3¢r∂W62ÜRÊ÷W76vRí≤s¬ˆFóc‚w◊–¶7ñÊ2gVÊ7Fñˆ‚∆ˆD7ñ&W%Fˆˆ«2Çó∂vóB&ˆ÷ó6RÊ∆¬Ö∂∆ˆD7ñ&W$6&ñ∆óFñW2Çí∆∆ˆD7ñ&W$Üó7F˜'íÇí∆∆ˆD7ñ&W%66ÜVGV∆W2Çï“ó–¶6ˆÁ7BdîUuÙƒÙDU%3◊∞¢˜fW'fñWs¢Çì”Ê∆ˆDF6Ü&ˆ&BÇí¿¢FWfñ6W3¢Çì”Ê∆ˆDñÁfVÁF˜'íÇí¿¢ÊWGv˜&≥¢Çì”Ê∆ˆDÊWGv˜&≤Çí¿¢÷ˆÊóF˜&ñÊs¢Çì”Ê∆ˆD÷ˆÊóF˜&ñÊrÇí¿¢fñÊFñÊw3¢Çì”Ê∆ˆDfñÊFñÊw2Çí¿¢ñÁFVw&FñˆÁ3¢Çì”Ê∆ˆDñÁFVw&FñˆÁ2Çí¿¢&W˜'G3¢Çì”Ê∆ˆE&W˜'G2Çí¿¢6∆VÊF#¢Çì”Ê∆ˆD6∆VÊF"Çí¿¢V÷ñ√¢Çì”Ê∆ˆDV÷ñ¬Çí¿¢vWfVÁB÷fñÊFñÊw2s¢Çì”Ê∆ˆDWfVÁDfñÊFñÊw2Çí¿¢w&V÷˜FR÷66W72s¢Çì”Ê∆ˆE&V÷˜FT66W72Çí¿¢ÁFófó'W3¢Çì”Ê∆ˆD6∆‘dvVÁG2Çí¿¢v7ñ&W"◊Fˆˆ«2s¢Çì”Ê∆ˆD7ñ&W%Fˆˆ«2Çí¿¢Fñ6∂WG3¢Çì”Ê∆ˆEFñ6∂WG2Çí¿¢ÜV«FÉ¢Çì”Ê∆ˆDÜV«FÇÇí¿¢W6W'3¢Çì”Ê∆ˆEW6W'2Çí¿¢VFóC¢Çì”Ê∆ˆDVFóBÇí¿¢'V∆W3¢Çì”Ê∆ˆE'V∆W2Çí¿¢6V7W&óGì¢Çì”Ê∆ˆE6V7W&óGíÇí¿¢7FófóGì¢Çì”Ê∆ˆDWfVÁG2Çêß”∞¶∆WBD4Ñ$Ù$EÙE$îƒƒDıt„÷f«6S∞¶∆WB4$Eı$UEU$Âı5DDS÷ÁV∆√∞¶∆WB‰UEtı$µı§ÙÙ””∞¶gVÊ7Fñˆ‚6WDF6Ü&ˆ&E&WGW&Âfó6ñ&∆Rá6Ü˜ró∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂FF÷F6Ü&ˆ&B◊&WGW&Â“ríÊf˜$V6ÇÜ#”Ê"Á7Gñ∆RÊFó7∆ì◊6Ü˜sÚvñÊ∆ñÊR÷f∆WÇs¢vÊˆÊRró–¶gVÊ7Fñˆ‚˜V‰6&EvRáF&vWB∆fñ«FW#÷ÁV∆¬ó∞¢6ˆÁ7B6˜W&6S÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜"ÇrÁfñWu∂&ñ÷ÜñFFV„“&f«6R%“rìÚÊñBÁ&W∆6RÇıÁfñWr“Ú¬rró«¬v˜fW'fñWrs∞¢ñbá6˜W&6R”◊F&vWBî4$Eı$UEU$Âı5DDS◊∑6˜W&6R«67&ˆ∆√ßvñÊF˜rÁ67&ˆ∆≈í∆ñÁfVÁF˜'ï7FGW3¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï7FGW2rìÚÁf«VW«¬rr∆ñÁfVÁF˜'ï7V'FóF∆S¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TñÁfVÁF˜'ï7V'FóF∆RrìÚÁFWáD6ˆÁFVÁG«¬rw”∞¢6ˆÁ7B7FGW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï7FGW2rì∂ñbáF&vWC””“vFWfñ6W2rbg7FGW2bffñ«FW"”÷ÁV∆¬ó7FGW2Áf«VS÷fñ«FW#∞¢6Ü˜ufñWráF&vWB«G'VRì∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁcC3÷6&B◊&WGW&‚ríÊf˜$V6ÇÜ#”Ê"Á&V÷˜fRÇíì∞¢ñbÑ4$Eı$UEU$Âı5DDRó∞¢6ˆÁ7BfñWs÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwfñWr“r∑F&vWBí∆Ê6Ü˜#◊fñWsÚÁVW'ï6V∆V7F˜"Çsß66˜R‚ÊÜW&Ú¬Ê6∆VÊF"÷ÜW&Ú¬ÊV÷ñ¬÷ÜW&Úró««fñWsÚÊfó'7DV∆V÷VÁD6Üñ∆C∞¢ñbÜÊ6Ü˜"ó∂6ˆÁ7B&6≥÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇv'WGFˆ‚rì∂&6≤ÁGóS“v'WGFˆ‚s∂&6≤Ê6∆74Ê÷S“wcC3÷6&B◊&WGW&‚s∂&6≤ÁFWáD6ˆÁFVÁC“~(i&6≤FÚr≤á∂˜fW'fñWs¢tF6Ü&ˆ&Br∆FWfñ6W3¢tFWfñ6W2r∆ÜV«FÉ¢u7ó7FV“ÜV«FÇr∆6∆VÊF#¢t6∆VÊF"r∆V÷ñ√¢tV÷ñ¬w’¥4$Eı$UEU$Âı5DDRÁ6˜W&6U◊«¬w&Wfñ˜W2vRrì∂&6≤ÊˆÊ6∆ñ6≥÷6∆˜6T6&EvS∂Ê6Ü˜"Ê&Vf˜&RÜ&6≤ó–¢–¢vñÊF˜rÁ67&ˆ∆≈FÚÉ√ì∞ß–¶gVÊ7Fñˆ‚6∆˜6T6&EvRÇó∞¢6ˆÁ7B&Wfñ˜W3‘4$Eı$UEU$Âı5DDS∂ñbÇ&Wfñ˜W2ó&WGW&„∞¢4$Eı$UEU$Âı5DDS÷ÁV∆√∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁcC3÷6&B◊&WGW&‚ríÊf˜$V6ÇÜ#”Ê"Á&V÷˜fRÇíì∞¢6ˆÁ7B7FGW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï7FGW2rí«7V'FóF∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TñÁfVÁF˜'ï7V'FóF∆Rrì∂ñbá7FGW2ó7FGW2Áf«VS◊&Wfñ˜W2ÊñÁfVÁF˜'ï7FGW3∂ñbá7V'FóF∆Ró7V'FóF∆RÁFWáD6ˆÁFVÁC◊&Wfñ˜W2ÊñÁfVÁF˜'ï7V'FóF∆S∞¢6Ü˜ufñWrá&Wfñ˜W2Á6˜W&6R«G'VRì∑&WVW7DÊñ÷Fñˆ‰g&÷RÇÇì”ÁvñÊF˜rÁ67&ˆ∆≈FÚÉ«&Wfñ˜W2Á67&ˆ∆¬íì∞ß–¶gVÊ7Fñˆ‚˜V‰F6Ü&ˆ&E7V÷÷'íÜ∂ñÊBó∞¢D4Ñ$Ù$EÙE$îƒƒDıt„◊G'VS∑6WDF6Ü&ˆ&E&WGW&Âfó6ñ&∆RÜf«6Rì∞¢6ˆÁ7B7V'FóF∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TñÁfVÁF˜'ï7V'FóF∆Rrì∞¢ñbÜ∂ñÊC””“vˆÊ∆ñÊRró∂˜V‰6&EvRÇvFWfñ6W2r¬vˆÊ∆ñÊRrì∂ñbá7V'FóF∆Ró7V'FóF∆RÁFWáD6ˆÁFVÁC“tFWfñ6W27W'&VÁF«íˆÊ∆ñÊRˆ‚ñ˜W"ÊWGv˜&≤s∑&WGW&Á–¢ñbÜ∂ñÊC””“vFWfñ6W2ró∂˜V‰6&EvRÇvFWfñ6W2r¬rrì∂ñbá7V'FóF∆Ró7V'FóF∆RÁFWáD6ˆÁFVÁC“t∆¬Fó66˜fW&VBFWfñ6W2ˆ‚ñ˜W"ÊWGv˜&≤s∑&WGW&Á–¢ñbÜ∂ñÊC””“vó77VW2ró∂˜V‰6&EvRÇvfñÊFñÊw2rì∑&WGW&Á–¢ñbÜ∂ñÊC””“v÷ˆÊóF˜'2ró∂˜V‰6&EvRÇv÷ˆÊóF˜&ñÊrrì∑&WGW&Á–ß–¶gVÊ7Fñˆ‚&6µFÙF6Ü&ˆ&BÇó∞¢D4Ñ$Ù$EÙE$îƒƒDıt„÷f«6S∑6WDF6Ü&ˆ&E&WGW&Âfó6ñ&∆RÜf«6Rì∞¢6ˆÁ7B7FGW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï7FGW2rí«7V'FóF∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TñÁfVÁF˜'ï7V'FóF∆Rrì∂ñbá7FGW2ó7FGW2Áf«VS“rs∂ñbá7V'FóF∆Ró7V'FóF∆RÁFWáD6ˆÁFVÁC“t∆¬Fó66˜fW&VBFWfñ6W2ˆ‚ñ˜W"ÊWGv˜&≤s∞¢ñbÑ4$Eı$UEU$Âı5DDRñ6∆˜6T6&EvRÇì∂V«6R6Ü˜ufñWrÇv˜fW'fñWrr«G'VRì∞ß–ßvñÊF˜rÊ˜V‰F6Ü&ˆ&E7V÷÷'ì÷˜V‰F6Ü&ˆ&E7V÷÷'ì∑vñÊF˜rÊ&6µFÙF6Ü&ˆ&C÷&6µFÙF6Ü&ˆ&C∑vñÊF˜rÊ˜V‰6&EvS÷˜V‰6&EvS∑vñÊF˜rÊ6∆˜6T6&EvS÷6∆˜6T6&EvS∞¶∆WBdÙ5U5ı$UdîıU5ÙTƒT‘TÂC÷ÁV∆¬ƒîÂdTÂDı%ïÙƒ≈Ùƒï5C’µ“ƒƒ5EÙÑT≈DÖÙ4ÑT4µ3’µ”∞¶gVÊ7Fñˆ‚˜V‰6&Dfˆ7W2áFóF∆R«6˜W&6S“ttÙE4UîRró∞¢6ˆÁ7BFñ∆ˆs÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC36&Dfˆ7W2rì∂ñbÇFñ∆ˆró&WGW&‚ÁV∆√∞¢dÙ5U5ı$UdîıU5ÙTƒT‘TÂC÷Fˆ7V÷VÁBÊ7FófTV∆V÷VÁC∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3fˆ7W5FóF∆RríÁFWáD6ˆÁFVÁC◊FóF∆S∞¢Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3fˆ7W56˜W&6RríÁFWáD6ˆÁFVÁC◊6˜W&6S∞¢6ˆÁ7B&ˆGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3fˆ7W4&ˆGírì∂&ˆGíÁ&W∆6T6Üñ∆G&V‚Çì∂Fñ∆ˆrÊÜñFFV„÷f«6S∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∂Fñ∆ˆrÁVW'ï6V∆V7F˜"ÇvÜVFW"'WGFˆ‚rìÚÊfˆ7W2Çì∑&WGW&‚&ˆGì∞ß–¶gVÊ7Fñˆ‚6∆˜6T6&Dfˆ7W2Çó∂6ˆÁ7BFñ∆ˆs÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC36&Dfˆ7W2rì∂ñbÇFñ∆ˆw«∆Fñ∆ˆrÊÜñFFV‚ó&WGW&„∂Fñ∆ˆrÊÜñFFV„◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3fˆ7W4&ˆGíríÁ&W∆6T6Üñ∆G&V‚Çì∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rs¥dÙ5U5ı$UdîıU5ÙTƒT‘TÂCÚÊfˆ7W3Ú‚Çó–¶gVÊ7Fñˆ‚˜V‰FWfñ6U7V÷÷'íÜ∂ñÊBó∞¢6ˆÁ7B∆&V«3◊∂∆√¢uF˜F¬FWfñ6W2r∆ˆÊ∆ñÊS¢tˆÊ∆ñÊRFWfñ6W2r∆ˆff∆ñÊS¢tˆff∆ñÊRFWfñ6W2r∆ÊWs¢tÊWv«íFó66˜fW&VBFWfñ6W2w”∞¢6ˆÁ7B&ˆGì÷˜V‰6&Dfˆ7W2Ü∆&V«5∂∂ñÊE◊«¬tFWfñ6W2r¬tFWfñ6W2rì∂ñbÇ&ˆGíó&WGW&„∞¢6ˆÁ7B&˜w3‘îÂdTÂDı%ïÙƒ≈Ùƒï5BÊfñ«FW"áÉ”Ê∂ñÊC””“v∆¬w«¬Ü∂ñÊC””“vÊWrsı7G&ñÊráÇÊ6∆76ñfñ6FñˆÁ«¬vÊWrríÁFÙ∆˜vW$66RÇì””“vÊWrs•7G&ñÊráÇÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇíÊñÊ6«VFW2Ü∂ñÊBííì∞¢6ˆÁ7B∆VC÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇwrì∂∆VBÊ6∆74Ê÷S“wcC3÷fˆ7W2÷∆VFRs∂∆VBÁFWáD6ˆÁFVÁC÷G∑&˜w2Ê∆VÊwFá“ˆbG¥îÂdTÂDı%ïÙƒ≈Ùƒï5BÊ∆VÊwFá“FWfñ6W2‚6V∆V7BFWfñ6RFÚ˜V‚óG2gV∆¬&V6˜&BÊ∂&ˆGíÊVÊD6Üñ∆BÜ∆VBì∞¢ñbÇ&˜w2Ê∆VÊwFÇó∂6ˆÁ7BV◊Gì÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇvFóbrì∂V◊GíÊ6∆74Ê÷S“wcC3÷fˆ7W2÷V◊Gís∂V◊GíÁFWáD6ˆÁFVÁC“tÊÚ÷F6ÜñÊrFWfñ6W2ñ‚FÜó2ñÁfVÁF˜'í‚s∂&ˆGíÊVÊD6Üñ∆BÜV◊Gíì∑&WGW&Á–¢f˜"Ü6ˆÁ7BÇˆb&˜w2ó∂6ˆÁ7B'WGFˆ„÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇv'WGFˆ‚rì∂'WGFˆ‚ÁGóS“v'WGFˆ‚s∂'WGFˆ‚Ê6∆74Ê÷S“wcC3÷fˆ7W2◊&˜rs∂f˜"Ü6ˆÁ7BfñV∆Bˆb∑ÇÊÊ÷W««ÇÊÜ˜7FÊ÷W«¬uVÊ∂Ê˜v‚FWfñ6Rr«ÇÊó«¬~(	Br«ÇÊFWfñ6U˜GóW«¬~(	Br«ÇÁ7FGW7«¬wVÊ∂Ê˜v‚rƒ4ƒ55Ùƒ$T≈∑ÇÊ6∆76ñfñ6FñˆÂ◊««ÇÊ6∆76ñfñ6FñˆÁ«¬tÊWru“ó∂6ˆÁ7B7„÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇw7‚rì∑7‚ÁFWáD6ˆÁFVÁC÷fñV∆C∂'WGFˆ‚ÊVÊD6Üñ∆Bá7‚ó÷'WGFˆ‚ÊˆÊ6∆ñ6≥“Çì”Á∂6∆˜6T6&Dfˆ7W2Çì∂vÙFWfñ6RáÇÊñBó”∂&ˆGíÊVÊD6Üñ∆BÜ'WGFˆ‚ó–ß–¶gVÊ7Fñˆ‚˜V‰ÜV«FÑ6&BÜ6&Bó∞¢6ˆÁ7BFóF∆S÷6&BÁVW'ï6V∆V7F˜"Çw6÷∆¬rìÚÁFWáD6ˆÁFVÁG«¬u7ó7FV“ÜV«FÇr«f«VS÷6&BÁVW'ï6V∆V7F˜"Çv"rìÚÁFWáD6ˆÁFVÁG«¬~(	Bs∞¢6ˆÁ7B&ˆGì÷˜V‰6&Dfˆ7W2áFóF∆R¬u7ó7FV“ÜV«FÇrì∂ñbÇ&ˆGíó&WGW&„∞¢6ˆÁ7B∆VC÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇwrì∂∆VBÊ6∆74Ê÷S“wcC3÷fˆ7W2÷∆VFRs∂∆VBÁFWáD6ˆÁFVÁC÷7W'&VÁB7FGW3¢G∑f«VW“‚FÜR6ÜV6∑2&V∆˜r6ˆ÷Rg&ˆ“FÜR∆ñÊ6RÜV«FÇ&W˜'BÊ∂&ˆGíÊVÊD6Üñ∆BÜ∆VBì∞¢6ˆÁ7BFW&”◊FóF∆RÁFÙ∆˜vW$66RÇíÁ7∆óBÇrrï≥“∆6ÜV6∑3‘ƒ5EÙÑT≈DÖÙ4ÑT4µ2Êfñ«FW"áÉ”ÁFóF∆S””“t∆ñÊ6RÜV«FÇw«≈7G&ñÊráÇÊÊ÷W«¬rríÁFÙ∆˜vW$66RÇíÊñÊ6«VFW2áFW&“íì∞¢ñbÇ6ÜV6∑2Ê∆VÊwFÇó∂6ˆÁ7BV◊Gì÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇvFóbrì∂V◊GíÊ6∆74Ê÷S“wcC3÷fˆ7W2÷V◊Gís∂V◊GíÁFWáD6ˆÁFVÁC“tÊÚFFóFñˆÊ¬6ÜV6≤FWFñ«2&Rfñ∆&∆Rf˜"FÜó26ˆ◊ˆÊVÁB‚s∂&ˆGíÊVÊD6Üñ∆BÜV◊Gíì∑&WGW&Á–¢f˜"Ü6ˆÁ7BÇˆb6ÜV6∑2ó∂6ˆÁ7B&˜s÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇvFóbrì∑&˜rÊ6∆74Ê÷S“wcC3÷fˆ7W2◊&˜rs∂f˜"Ü6ˆÁ7BFWáBˆb∑ÇÊÊ÷W«¬t6ÜV6≤r«ÇÁ7FGW7«¬wVÊ∂Ê˜v‚r«ÇÊFWFñ««¬~(	Bu“ó∂6ˆÁ7B7„÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇw7‚rì∑7‚ÁFWáD6ˆÁFVÁC◊FWáC∑&˜rÊVÊD6Üñ∆Bá7‚ó÷&ˆGíÊVÊD6Üñ∆Bá&˜ró–ß–¶gVÊ7Fñˆ‚˜V‰6∆VÊF%7FFó7Fñ2Ü∂ñÊBó∞¢6ˆÁ7BFóF∆W3◊∑F˜F√¢uF˜F¬WfVÁG2r∆÷ñÁFVÊÊ6S¢t÷ñÁFVÊÊ6Rr«Fñ6∂WG3¢uFñ6∂WG2r∆÷VWFñÊw3¢t÷VWFñÊw2w“∆&ˆGì÷˜V‰6&Dfˆ7W2áFóF∆W5∂∂ñÊE◊«¬t6∆VÊF"WfVÁG2r¬t6∆VÊF"rì∂ñbÇ&ˆGíó&WGW&„∞¢6ˆÁ7B&˜w3‘4ƒT‰D%ÙUdTÂE2Êfñ«FW"ÜS”Á∂6ˆÁ7BC÷ÊWrFFRÜRÁ7F'EˆBì∂ñbÜBÊvWDgV∆≈ñV"Çí”‘4ƒT‰D%ÙDDRÊvWDgV∆≈ñV"Çó«∆BÊvWD÷ˆÁFÇÇí”‘4ƒT‰D%ÙDDRÊvWD÷ˆÁFÇÇíó&WGW&‚f«6S∂ñbÜ∂ñÊC””“wF˜F¬ró&WGW&‚G'VS∂ñbÜ∂ñÊC””“v÷ñÁFVÊÊ6Rró&WGW&‚ˆ÷ñÁFVÊÊ6W«Ww&FW«F6á∆&6∑W∆fó&◊v&RˆíÁFW7BÜRÁFóF∆W«¬rrì∂ñbÜ∂ñÊC””“wFñ6∂WG2ró&WGW&‚RÁFñ6∂WEˆñG«¬˜Fñ6∂WG«F∑B“ˆíÁFW7BÜRÁFóF∆W«¬rrì∑&WGW&‚ˆ÷VWFñÊw«&WfñWw«7ñÊ2ˆíÁFW7BÜRÁFóF∆W«¬rró“ì∞¢ñbÇ&˜w2Ê∆VÊwFÇó∂&ˆGíÊñÊÊW$ÖD‘√“s∆Fób6∆73“'cC3÷fˆ7W2÷V◊Gí#‰ÊÚWfVÁG2ñ‚FÜó26FVv˜'íf˜"FÜR6V∆V7FVB÷ˆÁFÇ„¬ˆFóc‚s∑&WGW&Á–¢f˜"Ü6ˆÁ7BRˆb&˜w2ó∂6ˆÁ7B'WGFˆ„÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇv'WGFˆ‚rì∂'WGFˆ‚ÁGóS“v'WGFˆ‚s∂'WGFˆ‚Ê6∆74Ê÷S“wcC3÷fˆ7W2◊&˜rs∂f˜"Ü6ˆÁ7Bf«VRˆb∂RÁFóF∆W«¬tWfVÁBr∆ÊWrFFRÜRÁ7F'EˆBíÁFÙ∆ˆ6∆TFFU7G&ñÊrÇí∆ÊWrFFRÜRÁ7F'EˆBíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“¬∂Ü˜W#¢vÁV÷W&ñ2r∆÷ñÁWFS¢s"÷FñvóBw“í∆RÁ6˜W&6S””“v∆ˆ6¬sÚttÙE4UîRs¢t6ˆÊÊV7FVB6∆VÊF"u“ó∂6ˆÁ7B7„÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇw7‚rì∑7‚ÁFWáD6ˆÁFVÁC◊f«VS∂'WGFˆ‚ÊVÊD6Üñ∆Bá7‚ó÷'WGFˆ‚ÊˆÊ6∆ñ6≥“Çì”Á∂6∆˜6T6&Dfˆ7W2Çì∂˜V‰6∆VÊF$WfVÁD÷ˆF¬ÑÁV÷&W"ÜRÊñBíó”∂&ˆGíÊVÊD6Üñ∆BÜ'WGFˆ‚ó–ß–¶gVÊ7Fñˆ‚˜VÂÊVƒfˆ7W2áÊV¬«F&vWBó∞¢6ˆÁ7BFóF∆S◊ÊV¬ÁVW'ï6V∆V7F˜"ÇvÉ"rìÚÁFWáD6ˆÁFVÁCÚÁG&ñ“Çó«¬tFWFñ«2r«6˜W&6S◊ÊV¬Ê6∆˜6W7BÇrÁfñWrrìÚÊñC””“wfñWr÷ÜV«FÇsÚu7ó7FV“ÜV«FÇs¢tF6Ü&ˆ&Bs∞¢6ˆÁ7B&ˆGì÷˜V‰6&Dfˆ7W2áFóF∆R«6˜W&6Rì∂ñbÇ&ˆGíó&WGW&„∞¢6ˆÁ7B6∆ˆÊS◊ÊV¬Ê6∆ˆÊTÊˆFRáG'VRì∂6∆ˆÊRÊ6∆74∆ó7BÊFBÇwcC3÷fˆ7W2◊ÊV¬rì∂6∆ˆÊRÁ&V÷˜fTGG&ñ'WFRÇwF&ñÊFWÇrì∞¢6∆ˆÊRÁVW'ï6V∆V7F˜$∆¬Çu∂ñE“ríÊf˜$V6ÇÜ„”Ê‚Á&V÷˜fTGG&ñ'WFRÇvñBríì∞¢6∆ˆÊRÁVW'ï6V∆V7F˜$∆¬Çu∂ˆÊ6∆ñ6µ“≈∂ˆÊ∂WñF˜vÂ“∆'WGFˆ‚∆ríÊf˜$V6ÇÜ„”Á∂‚Á&V÷˜fTGG&ñ'WFRÇvˆÊ6∆ñ6≤rì∂‚Á&V÷˜fTGG&ñ'WFRÇvˆÊ∂WñF˜v‚rì∂ñbÜ‚Ê÷F6ÜW2Çv'WGFˆ‚∆ríó∂‚Á6WDGG&ñ'WFRÇwF&ñÊFWÇr¬r”rì∂‚Á7Gñ∆RÁˆñÁFW$WfVÁG3“vÊˆÊRw◊“ì∞¢&ˆGíÊVÊD6Üñ∆BÜ6∆ˆÊRì∞¢ñbáF&vWBó∂6ˆÁ7B'WGFˆ„÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇv'WGFˆ‚rì∂'WGFˆ‚ÁGóS“v'WGFˆ‚s∂'WGFˆ‚Ê6∆74Ê÷S“w&ñ÷'ís∂'WGFˆ‚ÁFWáD6ˆÁFVÁC“t˜V‚gV∆¬r∑FóF∆R≤rFFs∂'WGFˆ‚ÊˆÊ6∆ñ6≥“Çì”Á∂6∆˜6T6&Dfˆ7W2Çì∂˜V‰6&EvRáF&vWBó”∂&ˆGíÊVÊD6Üñ∆BÜ'WGFˆ‚ó–ß–¶gVÊ7Fñˆ‚ñÁ7F∆ƒ6&Dfˆ7W4ÊfñvFñˆ‚Çó∞¢6ˆÁ7BF&vWG3’≤v÷ˆÊóF˜&ñÊrr¬vFWfñ6W2r¬vÜV«FÇr¬vfñÊFñÊw2r¬v÷ˆÊóF˜&ñÊrr¬wFñ6∂WG2r¬vÊWGv˜&≤r¬v7FófóGír∆ÁV∆≈”∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr7fñWr÷˜fW'fñWrÊF6Ü&ˆ&B÷w&ñBÁÊV¬ríÊf˜$V6ÇÇáÊV¬∆ñÊFWÇì”Á∞¢ÊV¬ÁF$ñÊFWÉ”∑ÊV¬Á6WDGG&ñ'WFRÇv&ñ÷∆&V¬r¬t˜V‚r≤áÊV¬ÁVW'ï6V∆V7F˜"ÇvÉ"rìÚÁFWáD6ˆÁFVÁG«¬v6&Brí≤rFWFñ«2rì∞¢6ˆÁ7B7FófFS÷S”Á∂ñbÜRÁF&vWBÊ6∆˜6W7BÇv'WGFˆ‚∆∆ñÁWB«6V∆V7B«FWáF&Vríó&WGW&„∂˜VÂÊVƒfˆ7W2áÊV¬«F&vWG5∂ñÊFWÖ“ó”∞¢ÊV¬ÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆7FófFRì∞¢ÊV¬ÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÜRÁF&vWC””◊ÊV¬bbÜRÊ∂Wì””“tVÁFW"w«∆RÊ∂Wì””“rríó∂RÁ&WfVÁDFVfV«BÇì∂˜VÂÊVƒfˆ7W2áÊV¬«F&vWG5∂ñÊFWÖ“ó◊“ì∞¢“ì∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr7fñWr÷ÜV«FÇÁcC3÷ÜV«FÇ÷6&BríÊf˜$V6ÇÜ6&C”Á∂6&BÁF$ñÊFWÉ”∂6&BÁ6WDGG&ñ'WFRÇw&ˆ∆Rr¬v'WGFˆ‚rì∂6&BÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r¬Çì”Ê˜V‰ÜV«FÑ6&BÜ6&Bíì∂6&BÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÜRÊ∂Wì””“tVÁFW"w«∆RÊ∂Wì””“rró∂RÁ&WfVÁDFVfV«BÇì∂˜V‰ÜV«FÑ6&BÜ6&Bó◊“ó“ì∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr7fñWr÷ÜV«FÇÁcC3÷ÜV«FÇ÷÷WG&ñ72ÁÊV¬¬7fñWr÷ÜV«FÇÁcC3÷ÜV«FÇ◊6V6ˆÊF'íÁÊV¬¬7fñWr÷ÜV«FÇÁcC3÷ÜV«FÇ÷˜W&FñˆÊ¬÷w&ñBÁÊV¬ríÊf˜$V6ÇáÊV√”Á∑ÊV¬ÁF$ñÊFWÉ”∑ÊV¬ÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆S”Á∂ñbÇRÁF&vWBÊ6∆˜6W7BÇv'WGFˆ‚∆∆ñÁWB«6V∆V7Bríñ˜VÂÊVƒfˆ7W2áÊV¬∆ÁV∆¬ó“ì∑ÊV¬ÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÜRÁF&vWC””◊ÊV¬bbÜRÊ∂Wì””“tVÁFW"w«∆RÊ∂Wì””“rríó∂RÁ&WfVÁDFVfV«BÇì∂˜VÂÊVƒfˆ7W2áÊV¬∆ÁV∆¬ó◊“ó“ì∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁcC3÷6∆VÊF"◊7FB÷w&ñCÊFóbríÊf˜$V6ÇÇÜ6&B∆ñÊFWÇì”Á∂6&BÁF$ñÊFWÉ”∂6&BÁ6WDGG&ñ'WFRÇw&ˆ∆Rr¬v'WGFˆ‚rì∂6ˆÁ7B∂ñÊG3’≤wF˜F¬r¬v÷ñÁFVÊÊ6Rr¬wFñ6∂WG2r¬v÷VWFñÊw2u”∂6&BÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r¬Çì”Ê˜V‰6∆VÊF%7FFó7Fñ2Ü∂ñÊG5∂ñÊFWÖ“íì∂6&BÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÜRÊ∂Wì””“tVÁFW"w«∆RÊ∂Wì””“rró∂RÁ&WfVÁDFVfV«BÇì∂˜V‰6∆VÊF%7FFó7Fñ2Ü∂ñÊG5∂ñÊFWÖ“ó◊“ó“ì∞¢Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÜRÊ∂Wì””“tW66Rrñ6∆˜6T6&Dfˆ7W2Çó“ì∞ß–¶ñÁ7F∆ƒ6&Dfˆ7W4ÊfñvFñˆ‚Çì∞¶gVÊ7Fñˆ‚FV6˜&FTÊfñvFñˆ‰ñ6ˆÁ2Çó∞¢6ˆÁ7Bñ6ˆÂFá3◊∞¢˜fW'fñWs¢s«FÇC“&”2í”ríwcÉ7¢"Û„«FÇC“$”í#b”vÉgcr"Û‚r¿¢FWfñ6W3¢s«&V7BÉ“#B"ì“#B"vñGFÉ“#b"ÜVñváC“#r"'É“#"Û„«&V7BÉ“#B"ì“#2"vñGFÉ“#b"ÜVñváC“#r"'É“#"Û„«FÇC“$”rÜÇ„”rvÇ„"Û‚r¿¢ÊWGv˜&≥¢s∆6ó&6∆R7É“#""7ì“#B"#“#""Û„∆6ó&6∆R7É“#B"7ì“#í"#“#""Û„∆6ó&6∆R7É“##"7ì“#í"#“#""Û„«FÇC“$”bRt”2f√b”bñÉ""Û‚r¿¢÷ˆÊóF˜&ñÊs¢s«FÇC“$”2ïcT”2ñÉÑ”bF√2”B22B”r2B"Û‚r¿¢fñÊFñÊw3¢s∆6ó&6∆R7É“#"7ì“#"#“#Ç"Û„«FÇC“$”rv√BD”wcT”VÇ„"Û‚r¿¢Fˆˆ«3¢s«FÇC“$”BF√bd”Rñ√R”T”B√R”T”Bv√2”4”r#√2”2"Û‚r¿¢ñÁFVw&FñˆÁ3¢s«&V7BÉ“#2"ì“#2"vñGFÉ“#b"ÜVñváC“#b"'É“#"Û„«&V7BÉ“#R"ì“#2"vñGFÉ“#b"ÜVñváC“#b"'É“#"Û„«&V7BÉ“#2"ì“#R"vñGFÉ“#b"ÜVñváC“#b"'É“#"Û„«FÇC“$”ÇGcÑ”BÜÉÇ"Û‚r¿¢&W˜'G3¢s«FÇC“$”R&Éñ√RWcTÉW§”B'cVÉT”Ç&ÉÑ”ÇfÉÇ"Û‚r¿¢6∆VÊF#¢s«&V7BÉ“#2"ì“#R"vñGFÉ“#Ç"ÜVñváC“#b"'É“#""Û„«FÇC“$”r'cd”r'cd”2ÉÇ"Û‚r¿¢V÷ñ√¢s«&V7BÉ“#""ì“#R"vñGFÉ“##"ÜVñváC“#B"'É“#""Û„«FÇC“&”2rírí”r"Û‚r¿¢&WfVÁB÷fñÊFñÊw2#¢s«&V7BÉ“#2"ì“#2"vñGFÉ“#Ç"ÜVñváC“#Ç"'É“#""Û„«FÇC“&”r"22r”r"Û‚r¿¢'&V÷˜FR÷66W72#¢s«&V7BÉ“#""ì“#B"vñGFÉ“##"ÜVñváC“#B"'É“#""Û„«FÇC“$”Ç#&ÉÑ”"ácB"Û‚r¿¢ÁFófó'W3¢s«FÇC“$”"2#gcV3R”2„RÇ„R”Ç”B„R”„R”Ç”R”Ç”cg¢"Û„«FÇC“&”Ç""„R"„T√bí"Û‚r¿¢Fñ6∂WG3¢s«FÇC“$”BFÉgc$ÉÜ¬”BG¢"Û„«FÇC“$”rñÉ”r&Ér"Û‚r¿¢ÜV«FÉ¢s«FÇC“$”"#32R2ñRRí”2RRí63b”í"”í'¢"Û„«FÇC“$”"áct”Ç„R„VÉr"Û‚r¿¢'V∆W3¢s«FÇC“&”"2ÑÉ'§”"ócT”"vÇ„"Û‚r¿¢W6W'3¢s∆6ó&6∆R7É“#í"7ì“#Ç"#“#2"Û„«FÇC“$”2#b”&bb"c$”rf22d”rVRRBR"Û‚r¿¢VFóC¢s«FÇC“$”R&É√BGcdÉW§”R'cVÉD”Ç&ÉÑ”ÇfÉÇ"Û‚r¿¢6V7W&óGì¢s∆6ó&6∆R7É“#""7ì“#""#“#B"Û„«FÇC“$”"'c4”"óc4”"&É4”í&É4”RV√"$”rv√"$”íV¬”"$”rv¬”"""Û‚p¢”∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊÊfóFV’∂FF◊fñWu“ríÊf˜$V6ÇÜ'WGFˆ„”Á∂6ˆÁ7B7„÷'WGFˆ‚ÁVW'ï6V∆V7F˜"ÇrÊÊfñ6ˆ‚rí«Fá3÷ñ6ˆÂFá5∂'WGFˆ‚ÊFF6WBÁfñWu”∂ñbá7‚bgFá2ó7‚ÊñÊÊW$ÖD‘√÷«7frfñWt&˜É“##B#B"vñGFÉ“#Ç"ÜVñváC“#Ç"fñ∆√“&ÊˆÊR"7G&ˆ∂S“&7W'&VÁD6ˆ∆˜""7G&ˆ∂R◊vñGFÉ“#„r"7G&ˆ∂R÷∆ñÊV6“'&˜VÊB"7G&ˆ∂R÷∆ñÊV¶ˆñ„“'&˜VÊB"&ñ÷ÜñFFV„“'G'VR#‚G∑Fá7”¬˜7fsÊ“ì∞ß–¶FV6˜&FTÊfñvFñˆ‰ñ6ˆÁ2Çì∞ßvñÊF˜rÊ˜V‰FWfñ6U7V÷÷'ì÷˜V‰FWfñ6U7V÷÷'ì∑vñÊF˜rÊ6∆˜6T6&Dfˆ7W3÷6∆˜6T6&Dfˆ7W3∞¶gVÊ7Fñˆ‚v∆ˆ&≈6V&6Ñ∂WíÜWfVÁBó∞¢ñbÜWfVÁBÊ∂Wí”“tVÁFW"ró&WGW&„∞¢6ˆÁ7B“ÜWfVÁBÊ7W'&VÁEF&vWCÚÁf«VW«¬rríÁG&ñ“Çì∞¢6Ü˜ufñWrÇvFWfñ6W2r«G'VRì∞¢6ˆÁ7BñÁfVÁF˜'ì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï6V&6Çrì∞¢ñbÜñÁfVÁF˜'íó∂ñÁfVÁF˜'íÁf«VS◊∂∆ˆDñÁfVÁF˜'íÇó–ß–¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆WfVÁC”Á∞¢ñbÇÜWfVÁBÊ7G&ƒ∂Wó«∆WfVÁBÊ÷WF∂Wííbe7G&ñÊrÜWfVÁBÊ∂WííÁFÙ∆˜vW$66RÇì””“v≤ró∞¢WfVÁBÁ&WfVÁDFVfV«BÇì∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvv∆ˆ&≈6V&6ÇrìÚÊfˆ7W2Çì∞¢–ß“ì∞¶gVÊ7Fñˆ‚6Ü˜ufñWrÜÊ÷R«WFFTÜ6É◊G'VRó∞¢6ˆÁ7BF&vWC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwfñWr“r∂Ê÷Rì∞¢ñbÇF&vWBó∂6ˆÁ6ˆ∆RÊW'&˜"ÇttÙE4UîRÊfñvFñˆ‚F&vWB÷ó76ñÊs¢r∆Ê÷Rì∑&WGW&‚f«6W–¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁfñWrríÊf˜$V6Çác”Á∑bÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∑bÁ6WDGG&ñ'WFRÇv&ñ÷ÜñFFV‚r¬wG'VRró“ì∞¢F&vWBÁ7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∑F&vWBÁ6WDGG&ñ'WFRÇv&ñ÷ÜñFFV‚r¬vf«6Rrì∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊÊfóFV’∂FF◊fñWu“ríÊf˜$V6ÇÜ#”Á∂"Ê6∆74∆ó7BÁ&V÷˜fRÇv7FófRrì∂"Á&V÷˜fTGG&ñ'WFRÇv&ñ÷7W'&VÁBró“ì∞¢6ˆÁ7B'F„÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜"ÇrÊÊfóFV’∂FF◊fñWs“"r∂Ê÷R≤r%“rì∞¢ñbÜ'F‚ó∂'F‚Ê6∆74∆ó7BÊFBÇv7FófRrì∂'F‚Á6WDGG&ñ'WFRÇv&ñ÷7W'&VÁBr¬wvRró–¢6ˆÁ7BvUFóF∆W3◊∂˜fW'fñWs¢tF6Ü&ˆ&Br∆FWfñ6W3¢tFWfñ6W2r∆ÊWGv˜&≥¢tÊWGv˜&≤÷r∆÷ˆÊóF˜&ñÊs¢t÷ˆÊóF˜&ñÊrr∆fñÊFñÊw3¢tfñÊFñÊw2r«Fˆˆ«3¢uFˆˆ«2r¬v7ñ&W"◊Fˆˆ«2s¢t7ñ&W"Fˆˆ«2r¬wvñÊF˜w2◊WFFW2s¢t÷ñ7&˜6ˆgBvñÊF˜w2WFFW2r∆ñÁFVw&FñˆÁ3¢tñÁFVw&FñˆÁ2r«&W˜'G3¢u&W˜'G2r∆6∆VÊF#¢t6∆VÊF"r∆V÷ñ√¢tV÷ñ¬r¬vWfVÁB÷fñÊFñÊw2s¢tWfVÁBfñÊFñÊw2r¬w&V÷˜FR÷66W72s¢u&V÷˜FR66W72r∆ÁFófó'W3¢tÁFófó'W2r«Fñ6∂WG3¢uFñ6∂WB˜'F¬r∆ÜV«FÉ¢u7ó7FV“ÜV«FÇr«6V7W&óGì¢u6WGFñÊw2r«'V∆W3¢t∆W'B'V∆W2r«W6W'3¢uW6W'2r∆VFóC¢tVFóB∆ˆrr∆7FófóGì¢t7FófóGíw”∂6ˆÁ7BvUFóF∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3vUFóF∆Rrì∂ñbávUFóF∆RóvUFóF∆RÁFWáD6ˆÁFVÁC◊vUFóF∆W5∂Ê÷U◊«¬ttÙE4UîRs∞¢ñbáWFFTÜ6Çbb∆ˆ6Fñˆ‚ÊÜ6Ç”“r2r∂Ê÷Ró∂Üó7F˜'íÁ&W∆6U7FFRÜÁV∆¬¬rr¬r2r∂Ê÷Ró–¢ñbáWFFTÜ6ÇóvñÊF˜rÁ67&ˆ∆≈FÚÉ√ì∞¢6ˆÁ7B∆ˆFW#’dîUuÙƒÙDU%5∂Ê÷U”∞¢ñbÜ∆ˆFW"óµ&ˆ÷ó6RÁ&W6ˆ«fRÇíÁFÜV‚Ü∆ˆFW"íÊ6F6ÇÜS”Ê6ˆÁ6ˆ∆RÊW'&˜"ÇttÙE4UîRfñWr∆ˆBfñ∆VC¢r∆Ê÷R∆Ríó–¢&WGW&‚G'VPß–ßvñÊF˜rÁ6Ü˜ufñWs◊6Ü˜ufñWs∞¶gVÊ7Fñˆ‚ñÁ7F∆≈6ñFV&$ÊfñvFñˆ‚Çó∞¢6ˆÁ7BÊc÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜"ÇrÊÊf∆ó7Brì∞¢ñbÇÊbó&WGW&„∞¢ÊbÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆S”Á∞¢6ˆÁ7B'F„÷RÁF&vWBÊ6∆˜6W7BÇrÊÊfóFV’∂FF◊fñWu“rì∞¢ñbÇ'F‚«¬ÊbÊ6ˆÁFñÁ2Ü'F‚íó&WGW&„∞¢RÁ&WfVÁDFVfV«BÇì∂RÁ7F˜&˜vFñˆ‚Çì¥D4Ñ$Ù$EÙE$îƒƒDıt„÷f«6S¥4$Eı$UEU$Âı5DDS÷ÁV∆√∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁcC3÷6&B◊&WGW&‚ríÊf˜$V6ÇÜ#”Ê"Á&V÷˜fRÇíì∑6WDF6Ü&ˆ&E&WGW&Âfó6ñ&∆RÜf«6Rì∑6Ü˜ufñWrÜ'F‚ÊFF6WBÁfñWr«G'VRì∞¢“ì∞¢vñÊF˜rÊFDWfVÁD∆ó7FVÊW"ÇvÜ6Ü6ÜÊvRr¬Çì”Á∞¢6ˆÁ7BÊ÷S“Ü∆ˆ6Fñˆ‚ÊÜ6á«¬r6˜fW'fñWrríÁ6∆ñ6RÉì∞¢ñbÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwfñWr“r∂Ê÷Ríó6Ü˜ufñWrÜÊ÷R∆f«6Rì∞¢“ì∞ß–¶ñÁ7F∆≈6ñFV&$ÊfñvFñˆ‚Çì∞¶7ñÊ2gVÊ7Fñˆ‚FÙ∆ˆvñ‚ÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BW'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv∆ˆvñ‰W'"rì∂W'"ÁFWáD6ˆÁFVÁC“rs∑G'ó∂∆WB#÷vóBfWF6ÇÇrˆí˜cˆWFÇˆ∆ˆvñ‚r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑W6W&Ê÷S¶∆ˆvñÂW6W"Áf«VR«77v˜&C¶∆ˆvñÂ72Áf«VW“ó“ì∂ñbá"Á7FGW3”””C#2ó∂W'"ÁFWáD6ˆÁFVÁC“t66˜VÁBFV◊˜&&ñ«í∆ˆ6∂VBGVRFÚ&WVFVBfñ∆VB∆ˆvñÁ2‚G'ívñ‚∆FW"‚s∑&WGW&‚f«6W÷ñbÇ"Êˆ≤ó∂W'"ÁFWáD6ˆÁFVÁC“tñÁf∆ñBW6W&Ê÷R˜"77v˜&Bs∑&WGW&‚f«6W÷∆WBFF÷vóB"Êß6ˆ‚Çì∂ñbÜFFÊ÷f˜&WVó&VBóµT‰Dî‰uÙ‘dıDÙ¥T„÷FFÁVÊFñÊu˜Fˆ∂V„∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWFÑ˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f∆ˆvñ‰˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vw&ñBs∑&WGW&‚f«6W÷ñbÜFFÊ◊W7Eˆ6ÜÊvU˜77v˜&Bó∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWFÑ˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwt˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vw&ñBs∑&WGW&‚f«6W÷vóB&ˆ˜BÇó÷6F6ÇÜRó∂W'"ÁFWáD6ˆÁFVÁC“u6ñv‚÷ñ‚fñ∆VBw◊&WGW&‚f«6W–¶7ñÊ2gVÊ7Fñˆ‚FÙ÷ffW&ñgíÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BW'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f∆ˆvñ‰W'"rì∂W'"ÁFWáD6ˆÁFVÁC“rs∑G'ó∂∆WB#÷vóBfWF6ÇÇrˆí˜cˆWFÇˆ÷f˜fW&ñgír«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑VÊFñÊu˜Fˆ∂V„•T‰Dî‰uÙ‘dıDÙ¥T‚∆6ˆFS¶÷f6ˆFRÁf«VRÁG&ñ“Çó“ó“ì∂ñbÇ"Êˆ≤ó∂W'"ÁFWáD6ˆÁFVÁC“tñÁf∆ñB6ˆFRs∑&WGW&‚f«6W÷∆WBFF÷vóB"Êß6ˆ‚ÇìµT‰Dî‰uÙ‘dıDÙ¥T„÷ÁV∆√∂ñbÜFFÊ◊W7Eˆ6ÜÊvU˜77v˜&Bó∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f∆ˆvñ‰˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwt˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vw&ñBs∑&WGW&‚f«6W÷vóB&ˆ˜BÇó÷6F6ÇÜRó∂W'"ÁFWáD6ˆÁFVÁC“ufW&ñfñ6Fñˆ‚fñ∆VBw◊&WGW&‚f«6W–¶gVÊ7Fñˆ‚˜V‰6ÜÊvU77v˜&BÇó∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwt˜fW&∆íríÁ7Gñ∆RÊFó7∆ì“vw&ñBw–¶7ñÊ2gVÊ7Fñˆ‚FÙ6ÜÊvU77v˜&BÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BW'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwtW'"rì∂W'"ÁFWáD6ˆÁFVÁC“rs∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆWFÇˆ6ÜÊvR◊77v˜&Br«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂7W'&VÁE˜77v˜&C¶7W%72Áf«VR∆ÊWu˜77v˜&C¶ÊWu72Áf«VW“ó“ì∂vóB&ˆ˜BÇó÷6F6ÇÜRó∂W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6ÜÊvR77v˜&B(	B6ÜV6≤ñ˜W"7W'&VÁB77v˜&Bw◊&WGW&‚f«6W–¶7ñÊ2gVÊ7Fñˆ‚∆ˆv˜WBÇó∂vóBfWF6ÇÇrˆí˜cˆWFÇˆ∆ˆv˜WBr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤uÇ‘55$b’Fˆ∂V‚s¶vWD6ˆˆ∂ñRÇvvˆG6WñUˆ77&bró«¬rw◊“ì∑6Ü˜t∆ˆvñ‚Çó–¶gVÊ7Fñˆ‚77&eFˆ∂V‚Çó∑&WGW&‚vWD6ˆˆ∂ñRÇvvˆG6WñUˆ77&bró«¬rw–¶7ñÊ2gVÊ7Fñˆ‚∆ˆEW6W'2Çó∞¢6ˆÁ7BÊV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwW6W'5ÊV¬rí«F&ˆGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwW6W'2rì∞¢ñbÇ‘W«ƒ‘RÁ&ˆ∆R”“vF÷ñ‚ró∂ñbáÊV¬óÊV¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∑&WGW&Á–¢ñbáÊV¬óÊV¬Á7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∞¢G'ó∞¢6ˆÁ7B&˜w3÷vóBß6ˆ‚Çrˆí˜c˜W6W'2rì∞¢ñbáF&ˆGíóF&ˆGíÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷áÉ”Á∞¢6ˆÁ7BFVF∆ñÊS◊ÇÊ◊W7Eˆ6ÜÊvU˜77v˜&CÚáÇÊ◊W7Eˆ6ÜÊvU˜77v˜&Eˆ'ìˆñW2¬'íG∂W62ÜÊWrFFRáÇÊ◊W7Eˆ6ÜÊvU˜77v˜&Eˆ'ííÁFÙ∆ˆ6∆TFFU7G&ñÊrÇíó÷¢uñW2rì¢tÊÚs∞¢&WGW&‚«G#„«FC‚G∂W62áÇÊFó7∆ïˆÊ÷W«¬~(	Bró”¬˜FC„«FC‚G∂W62áÇÁW6W&Ê÷Ró”¬˜FC„«FC„«7‚6∆73“'ñ∆¬#‚G∂W62áÇÁ&ˆ∆Ró”¬˜7„„¬˜FC„«FC‚G∑ÇÊ7&VFVEˆCˆW62ÜÊWrFFRáÇÊ7&VFVEˆBíÁFÙ∆ˆ6∆TFFU7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC‚G∑ÇÊ∆7Eˆ∆ˆvñÂˆCˆW62ÜÊWrFFRáÇÊ∆7Eˆ∆ˆvñÂˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢tÊWfW"w”¬˜FC„«FC‚G∑ÇÁ77v˜&Eˆ6ÜÊvVEˆCˆW62ÜÊWrFFRáÇÁ77v˜&Eˆ6ÜÊvVEˆBíÁFÙ∆ˆ6∆TFFU7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC‚G∂FVF∆ñÊW”¬˜FC„«FC‚G∑ÇÊ÷fˆVÊ&∆VCÚuñW2s¢tÊÚw”¬˜FC„«FC‚G∑ÇÁW6W&Ê÷S””‘‘RÁW6W&Ê÷SÚrs¶∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“'&V÷˜fUW6W"ÇG∑ÇÊñG“¬rG∂W62áÇÁW6W&Ê÷Ró“rí#Â&V÷˜fS¬ˆ'WGFˆ„‚G∑ÇÊ÷fˆVÊ&∆VCˆ∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“'&W6WEW6W$÷fÇG∑ÇÊñG“¬rG∂W62áÇÁW6W&Ê÷Ró“rí#Â&W6WB‘d¬ˆ'WGFˆ„Ê¢rw÷”¬˜FC„¬˜G#Ê∞¢“íÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#í"6∆73“&V◊Gí#‰ÊÚW6W'2f˜VÊB„¬˜FC„¬˜G#‚s∞¢÷6F6ÇÜRó∂ñbáF&ˆGíóF&ˆGíÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#í"6∆73“&V◊Gí#ÂVÊ&∆RFÚ∆ˆBW6W'2„¬˜FC„¬˜G#‚w–ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDVFóBÇó∞¢6ˆÁ7BÊV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvVFóEÊV¬rí«F&ˆGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvVFóE&˜w2rì∞¢ñbÇ‘W«¬≤vF÷ñ‚r¬vVFóF˜"u“ÊñÊ6«VFW2Ñ‘RÁ&ˆ∆Ríó∂ñbáÊV¬óÊV¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∑&WGW&Á–¢ñbáÊV¬óÊV¬Á7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∞¢G'ó∞¢6ˆÁ7B&˜w3÷vóBß6ˆ‚Çrˆí˜cˆVFóCˆ∆ñ÷óC”Srì∞¢ñbáF&ˆGíóF&ˆGíÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷áÉ”Á∂6ˆÁ7B&˜FV7FVDÊ˜s◊ÇÁ&˜FV7FVE˜VÁFñ¬bfÊWrFFRáÇÁ&˜FV7FVE˜VÁFñ¬ìÊÊWrFFRÇì∑&WGW&‚«G"6∆73“"G∑&˜FV7FVDÊ˜sÚw&˜FV7FVB÷VFóBs¢rw“#„«FC‚G∑ÇÊ7&VFVEˆCˆW62ÜÊWrFFRáÇÊ7&VFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC‚G∂W62áÇÊ7F˜"ó”¬˜FC„«FC„«7‚6∆73“'ñ∆¬#‚G∂W62áÇÊ7Fñˆ‚ó”¬˜7„‚G∑&˜FV7FVDÊ˜sÚr«7‚6∆73“'ñ∆¬v&ÊñÊr#Â&˜FV7FVBrFó3¬˜7„‚s¢rw”¬˜FC„«FC‚G∂W62áÇÁF&vWG«¬~(	Bró”¬˜FC„«FC‚G∂W62áÇÊFWFñ«7«¬rró”¬˜FC„«FC‚G∂W62áÇÊó«¬~(	Bró”¬˜FC„¬˜G#Ê“íÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#b"6∆73“&V◊Gí#‰ÊÚVFóBVÁG&ñW2ñWB„¬˜FC„¬˜G#‚s∞¢÷6F6ÇÜRó∂ñbáF&ˆGíóF&ˆGíÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#b"6∆73“&V◊Gí#ÂVÊ&∆RFÚ∆ˆBVFóB∆ˆr„¬˜FC„¬˜G#‚w–ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆE6V7W&óGíÇó∞¢6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f7FGW2rì∂ñbÇV««¬‘Ró&WGW&„∞¢ñbÑ‘RÊ÷fˆVÊ&∆VBó∞¢V¬ÊñÊÊW$ÖD‘√÷∆Fób6∆73“&◊WFVB#ÂGvÚ÷f7F˜"WFÜVÁFñ6Fñˆ‚ó2∆"7Gñ∆S“&6ˆ∆˜#¢3Ü3Sr#ÊVÊ&∆VC¬ˆ#‚ˆ‚FÜó266˜VÁB„¬ˆFóc„∆'WGFˆ‚6∆73“&∆ñÊ≤"7Gñ∆S“&÷&vñ‚◊F˜£Ç"ˆÊ6∆ñ6≥“'7F'D÷fFó6&∆RÇí#‰Fó6&∆R‘d¬ˆ'WGFˆ„Ê∞¢÷V«6W∞¢V¬ÊñÊÊW$ÖD‘√÷∆Fób6∆73“&◊WFVB#ÂGvÚ÷f7F˜"WFÜVÁFñ6Fñˆ‚ó2∆"7Gñ∆S“&6ˆ∆˜#¢6#ÉsS#ÊÊ˜BVÊ&∆VC¬ˆ#‚‚FBóBf˜"6V6ˆÊB∆ñW"ˆb&˜FV7Fñˆ‚„¬ˆFóc„∆'WGFˆ‚6∆73“'&ñ÷'í"7Gñ∆S“&÷&vñ‚◊F˜£Ç"ˆÊ6∆ñ6≥“'7F'D÷f6WGWÇí#Â6WBW‘d¬ˆ'WGFˆ„Ê∞¢–ß–¶gVÊ7Fñˆ‚WFFU'V∆TfñV∆G2Çó∞¢6ˆÁ7BGóS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆UGóRrìÚÁf«VS∞¢6ˆÁ7Bw&˜W3◊∑'V∆TfñV∆G4'W'7CßGóS””“vÊWuˆFWfñ6Uˆ'W'7Br«'V∆TfñV∆G4ˆff∆ñÊSßGóS””“vˆff∆ñÊUˆGW&Fñˆ‚r«'V∆TfñV∆G4WfVÁD'W'7C•≤vóˆ6ÜÊvUˆ'W'7Br¬w&V6ˆÊÊV7Eˆ'W'7Bu“ÊñÊ6«VFW2áGóRí«'V∆TfñV∆G4ˆff∆ñÊT6˜VÁCßGóS””“vˆff∆ñÊUˆ6˜VÁBr«'V∆TfñV∆G566ÊÊW#ßGóS””“w66ÊÊW%˜7F∆Rr«'V∆TfñV∆G46∆76ñfñ6Fñˆ„ßGóS””“v6∆76ñfñ6FñˆÂˆ6˜VÁBw”∞¢ˆ&¶V7BÊVÁG&ñW2Üw&˜W2íÊf˜$V6ÇÇÖ∂ñB«6Ü˜u“ì”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬Á7Gñ∆RÊFó7∆ì◊6Ü˜sÚvf∆WÇs¢vÊˆÊRw“ì∞ß–¶gVÊ7Fñˆ‚'V∆T6ˆÊFóFñˆ‚áGóR«ó∞¢ñbáGóS””“vÊWuˆFWfñ6Uˆ'W'7Bró&WGW&‚G∑Ê6˜VÁG«√“≤ÊWrFWfñ6W2ñ‚G∑ÁvñÊF˜uˆ÷ñÁWFW7«√÷÷∞¢ñbáGóS””“vˆff∆ñÊUˆGW&Fñˆ‚ró&WGW&‚ˆff∆ñÊRG∑Ê÷ñÁWFW7«√÷“≤ÇG≤ÇáÊ6∆76ñfñ6FñˆÁ2bgÊ6∆76ñfñ6FñˆÁ2Ê∆VÊwFÇì˜Ê6∆76ñfñ6FñˆÁ3•≤vÁíu“íÊ¶ˆñ‚Çr¬ró“ñ∞¢ñbáGóS””“vóˆ6ÜÊvUˆ'W'7Bró&WGW&‚G∑Ê6˜VÁG«√“≤ï6ÜÊvW2ñ‚G∑ÁvñÊF˜uˆ÷ñÁWFW7«√÷÷∞¢ñbáGóS””“w&V6ˆÊÊV7Eˆ'W'7Bró&WGW&‚G∑Ê6˜VÁG«√“≤&V6ˆÊÊV7G2ñ‚G∑ÁvñÊF˜uˆ÷ñÁWFW7«√÷÷∞¢ñbáGóS””“vˆff∆ñÊUˆ6˜VÁBró&WGW&‚G∑Ê6˜VÁG«√“≤FWfñ6W2ˆff∆ñÊRÜ6ˆˆ∆F˜v‚G∑Ê6ˆˆ∆F˜vÂˆ÷ñÁWFW7«√W÷“ñ∞¢ñbáGóS””“w66ÊÊW%˜7F∆Rró&WGW&‚ÊÚ7V66W76gV¬66‚f˜"G∑Ê÷ñÁWFW7«√÷÷∞¢ñbáGóS””“v6∆76ñfñ6FñˆÂˆ6˜VÁBró&WGW&‚G∑Ê6˜VÁG«√“≤FWfñ6W26∆76ñfñVBG≤ÇáÊ6∆76ñfñ6FñˆÁ7«≈µ“íÊ¶ˆñ‚Çr¬ró«¬w6V∆V7FVBró“Ü6ˆˆ∆F˜v‚G∑Ê6ˆˆ∆F˜vÂˆ÷ñÁWFW7«√W÷“ñ∞¢&WGW&‚•4Ù‚Á7G&ñÊvñgíá««∑“ì∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆE'V∆W2Çó∞¢6ˆÁ7BÊV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆W5ÊV¬rí«F&ˆGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆W2rì∞¢ñbÇ‘W«ƒ‘RÁ&ˆ∆R”“vF÷ñ‚ró∂ñbáÊV¬óÊV¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∑&WGW&Á–¢ñbáÊV¬óÊV¬Á7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∞¢G'ó∞¢6ˆÁ7B&˜w3÷vóBß6ˆ‚Çrˆí˜c˜'V∆W2rì∞¢ñbáF&ˆGíóF&ˆGíÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷áÉ”Á∞¢∆WB&◊3◊∑”∑G'ó∑&◊3‘•4Ù‚Á'6RáÇÁ&◊7«¬w∑“ró÷6F6ÇÖÚó∑–¢6ˆÁ7B6ˆÊFóFñˆ„◊'V∆T6ˆÊFóFñˆ‚áÇÁ'V∆U˜GóR«&◊2ì∞¢&WGW&‚«G#„«FC‚G∂W62áÇÊÊ÷Ró”¬˜FC„«FC‚G∂W62áÇÁ'V∆U˜GóRó”¬˜FC„«FC‚G∂W62Ü6ˆÊFóFñˆ‚ó”¬˜FC„«FC„«7‚6∆73“'ñ∆¬#‚G∂W62áÇÁ6WfW&óGíó”¬˜7„„¬˜FC„«FC‚G∑ÇÊ∆7E˜G&ñvvW&VEˆCˆW62ÜÊWrFFRáÇÊ∆7E˜G&ñvvW&VEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢tÊWfW"w”¬˜FC„«FC„∆ñÁWBGóS“&6ÜV6∂&˜Ç"G∑ÇÊVÊ&∆VCÚv6ÜV6∂VBs¢rw“ˆÊ6ÜÊvS“'Fˆvv∆U'V∆RÇG∑ÇÊñG“«FÜó2Ê6ÜV6∂VBí#„¬˜FC„«FC„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“'&V÷˜fU'V∆RÇG∑ÇÊñG“¬rG∂W62áÇÊÊ÷Ró“rí#Â&V÷˜fS¬ˆ'WGFˆ„„¬˜FC„¬˜G#Ê∞¢“íÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#r"6∆73“&V◊Gí#‰ÊÚ'V∆W26ˆÊfñwW&VBñWB„¬˜FC„¬˜G#‚s∞¢÷6F6ÇÜRó∂ñbáF&ˆGíóF&ˆGíÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#r"6∆73“&V◊Gí#ÂVÊ&∆RFÚ∆ˆB∆W'B'V∆W2„¬˜FC„¬˜G#‚w–ß–¶7ñÊ2gVÊ7Fñˆ‚7&VFU'V∆RÜRó∞¢RÁ&WfVÁDFVfV«BÇì∞¢6ˆÁ7BGóS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆UGóRríÁf«VS∞¢6ˆÁ7BÊ÷S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆TÊ÷RríÁf«VRÁG&ñ“Çì∞¢6ˆÁ7B6WfW&óGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆U6WfW&óGíríÁf«VS∞¢∆WB&◊3∞¢ñbáGóS””“vÊWuˆFWfñ6Uˆ'W'7Bró∞¢&◊3◊∂6˜VÁC¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆T'W'7D6˜VÁBríÁf«VR«vñÊF˜uˆ÷ñÁWFW3¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆T'W'7EvñÊF˜rríÁf«VW”∞¢÷V«6RñbáGóS””“vˆff∆ñÊUˆGW&Fñˆ‚ró∞¢&◊3◊∂÷ñÁWFW3¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆Tˆff∆ñÊT÷ñÁWFW2ríÁf«VW”∞¢6ˆÁ7B&s÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆Tˆff∆ñÊT6∆76W2ríÁf«VRÁG&ñ“Çì∞¢ñbá&ró&◊2Ê6∆76ñfñ6FñˆÁ3◊&rÁ7∆óBÇr¬ríÊ÷ác”ÁbÁG&ñ“ÇííÊfñ«FW"Ñ&ˆˆ∆V‚ì∞¢÷V«6RñbÖ≤vóˆ6ÜÊvUˆ'W'7Br¬w&V6ˆÊÊV7Eˆ'W'7Bu“ÊñÊ6«VFW2áGóRíó∞¢&◊3◊∂6˜VÁC¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆TWfVÁD6˜VÁBríÁf«VR«vñÊF˜uˆ÷ñÁWFW3¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆TWfVÁEvñÊF˜rríÁf«VW”∞¢÷V«6RñbáGóS””“vˆff∆ñÊUˆ6˜VÁBró∞¢&◊3◊∂6˜VÁC¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆Tˆff∆ñÊT6˜VÁBríÁf«VR∆6ˆˆ∆F˜vÂˆ÷ñÁWFW3¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆Tˆff∆ñÊT6˜VÁD6ˆˆ∆F˜v‚ríÁf«VW”∞¢÷V«6RñbáGóS””“w66ÊÊW%˜7F∆Rró∞¢&◊3◊∂÷ñÁWFW3¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆U66ÊÊW$÷ñÁWFW2ríÁf«VW”∞¢÷V«6RñbáGóS””“v6∆76ñfñ6FñˆÂˆ6˜VÁBró∞¢&◊3◊∂6˜VÁC¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆T6∆746˜VÁBríÁf«VR∆6∆76ñfñ6FñˆÁ3¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆T6∆76W2ríÁf«VRÁ7∆óBÇr¬ríÊ÷ác”ÁbÁG&ñ“ÇííÊfñ«FW"Ñ&ˆˆ∆V‚í∆6ˆˆ∆F˜vÂˆ÷ñÁWFW3¢∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆T6∆746ˆˆ∆F˜v‚ríÁf«VW”∞¢–¢G'ó∞¢vóBß6ˆ‚Çrˆí˜c˜'V∆W2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂Ê÷R«'V∆U˜GóSßGóR«&◊2«6WfW&óGó“ó“ì∞¢Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw'V∆TÊ÷RríÁf«VS“rs∂vóB∆ˆE'V∆W2Çì∞¢÷6F6ÇÜW'"ó∂∆W'BÇt6˜V∆BÊ˜B7&VFR'V∆S¢r∂W'"Ê÷W76vRó–¢&WGW&‚f«6S∞ß–¶7ñÊ2gVÊ7Fñˆ‚Fˆvv∆U'V∆RÜñB∆VÊ&∆VBó∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜'V∆W2Úr∂ñB«∂÷WFÜˆC¢uD4Çr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂VÊ&∆VG“ó“ì∂vóB∆ˆE'V∆W2Çó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚&V÷˜fU'V∆RÜñB∆Ê÷Ró∂ñbÇ6ˆÊfó&“Çu&V÷˜fR'V∆R"r∂Ê÷R≤r#Úríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜'V∆W2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆE'V∆W2Çó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚7F'D÷f6WGWÇó∞¢G'ó∞¢6ˆÁ7BFF÷vóBß6ˆ‚Çrˆí˜cˆWFÇˆ÷f˜6WGWr«∂÷WFÜˆC¢uı5Bw“í∆V√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f7FGW2rì∞¢V¬ÊñÊÊW$ÖD‘√÷∆Fób6∆73“&◊WFVB#‰VÁFW"FÜó26WGW∂Wíñ‚ñ˜W"DıEWFÜVÁFñ6F˜#£¬ˆFóc„∆Fób7Gñ∆S“&fˆÁB÷f÷ñ«ì¶÷ˆÊ˜76S∂fˆÁB◊6ó¶S£WÉ∂&6∂w&˜VÊC¢6cfcñf3∂&˜&FW#£Ç6ˆ∆ñB6F6Sfc∂&˜&FW"◊&FóW3£gÉ∑FFñÊs£É∂÷&vñ„£Ç∑v˜&B÷'&V≥¶'&V≤÷∆¬#‚G∂W62ÜFFÁ6V7&WBó”¬ˆFóc„∆Fób6∆73“&◊WFVB"7Gñ∆S“&fˆÁB◊6ó¶S£É∑v˜&B÷'&V≥¶'&V≤÷∆¬#‚G∂W62ÜFFÊ˜GWFÖ˜W&íó”¬ˆFóc„∆f˜&“ˆÁ7V&÷óC“'&WGW&‚6ˆÊfó&‘÷f6WGWÜWfVÁBí"7Gñ∆S“&÷&vñ‚◊F˜£GÉ∂Fó7∆ì¶f∆WÉ∂v£áÉ∂f∆WÇ◊w&ßw&#„∆ñÁWB6∆73“&ñÁWB"ñC“&÷f6ˆÊfó&‘6ˆFR"∆6VÜˆ∆FW#“$VÁFW"b÷FñvóB6ˆFR"&WVó&VB7Gñ∆S“&f∆WÉ£∂÷ñ‚◊vñGFÉ£ÉÇ#„∆'WGFˆ‚6∆73“'&ñ÷'í"GóS“'7V&÷óB#‰6ˆÊfó&”¬ˆ'WGFˆ„„¬ˆf˜&”„∆Fób6∆73“&W'""ñC“&÷f6WGWW'"#„¬ˆFócÊ∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B7F'B‘d6WGW¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚6ˆÊfó&‘÷f6WGWÜRó∞¢RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BW'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f6WGWW'"rì∂ñbÜW'"ñW'"ÁFWáD6ˆÁFVÁC“rs∞¢G'ó∞¢6ˆÁ7B6ˆFS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f6ˆÊfó&‘6ˆFRríÁf«VRÁG&ñ“Çì∞¢6ˆÁ7BFF÷vóBß6ˆ‚Çrˆí˜cˆWFÇˆ÷fˆ6ˆÊfó&“r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂6ˆFW“ó“ì∞¢6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f7FGW2rì∞¢V¬ÊñÊÊW$ÖD‘√÷∆Fób6∆73“&◊WFVB"7Gñ∆S“&6ˆ∆˜#¢3Ü3Sr#‰‘dVÊ&∆VB‚6fRFÜW6R&6∑W6ˆFW26ˆ÷WvÜW&R6fS£¬ˆFóc„∆Fób7Gñ∆S“&fˆÁB÷f÷ñ«ì¶÷ˆÊ˜76S∂&6∂w&˜VÊC¢6cfcñf3∂&˜&FW#£Ç6ˆ∆ñB6F6Sfc∂&˜&FW"◊&FóW3£gÉ∑FFñÊs£É∂÷&vñ„£Ç#‚G≤ÜFFÊ&6∑Wˆ6ˆFW7«≈µ“íÊ÷ÜW62íÊ¶ˆñ‚Çs∆'#‚ró”¬ˆFóc„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“&&ˆ˜BÇí#‰FˆÊS¬ˆ'WGFˆ„Ê∞¢‘S÷vóBß6ˆ‚Çrˆí˜cˆWFÇˆ÷Rrì∞¢÷6F6ÇÜWÇó∂ñbÜW'"ñW'"ÁFWáD6ˆÁFVÁC“tñÊ6˜'&V7B6ˆFR(	BG'ívñ‚w–¢&WGW&‚f«6S∞ß–¶gVÊ7Fñˆ‚7F'D÷fFó6&∆RÇó∞¢6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷f7FGW2rì∞¢V¬ÊñÊÊW$ÖD‘√÷∆f˜&“ˆÁ7V&÷óC“'&WGW&‚6ˆÊfó&‘÷fFó6&∆RÜWfVÁBí"7Gñ∆S“&Fó7∆ì¶f∆WÉ∂f∆WÇ÷Fó&V7Fñˆ„¶6ˆ«V÷„∂v£áÉ∂÷Ç◊vñGFÉ£3#Ç#„∆ñÁWB6∆73“&ñÁWB"ñC“&÷fFó6&∆Ur"GóS“'77v˜&B"∆6VÜˆ∆FW#“$7W'&VÁB77v˜&B"&WVó&VC„∆ñÁWB6∆73“&ñÁWB"ñC“&÷fFó6&∆T6ˆFR"∆6VÜˆ∆FW#“#b÷FñvóB6ˆFR˜"&6∑W6ˆFR"&WVó&VC„∆'WGFˆ‚6∆73“&FÊvW""GóS“'7V&÷óB#‰Fó6&∆R‘d¬ˆ'WGFˆ„„∆Fób6∆73“&W'""ñC“&÷fFó6&∆TW'"#„¬ˆFóc„¬ˆf˜&”Ê∞ß–¶7ñÊ2gVÊ7Fñˆ‚6ˆÊfó&‘÷fFó6&∆RÜRó∞¢RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BW'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷fFó6&∆TW'"rì∂ñbÜW'"ñW'"ÁFWáD6ˆÁFVÁC“rs∞¢G'ó∞¢vóBß6ˆ‚Çrˆí˜cˆWFÇˆ÷fˆFó6&∆Rr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂7W'&VÁE˜77v˜&C¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷fFó6&∆UrríÁf«VR∆6ˆFS¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷fFó6&∆T6ˆFRríÁf«VRÁG&ñ“Çó“ó“ì∞¢‘S÷vóBß6ˆ‚Çrˆí˜cˆWFÇˆ÷Rrì∂vóB∆ˆE6V7W&óGíÇì∞¢÷6F6ÇÜWÇó∂ñbÜW'"ñW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜BFó6&∆R‘d(	B6ÜV6≤77v˜&BÊB6ˆFRw–¢&WGW&‚f«6S∞ß–¶7ñÊ2gVÊ7Fñˆ‚&W6WEW6W$÷fÜñB«W6W&Ê÷Ró∂ñbÇ6ˆÊfó&“Çu&W6WB‘df˜""r∑W6W&Ê÷R≤r#Úríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜W6W'2Úr∂ñB≤rˆ÷f˜&W6WBr«∂÷WFÜˆC¢uı5Bw“ì∂vóB∆ˆEW6W'2Çó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚7&VFUW6W"ÜRó∞¢RÁ&WfVÁDFVfV«BÇì∞¢G'ó∞¢vóBß6ˆ‚Çrˆí˜c˜W6W'2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∞¢Fó7∆ïˆÊ÷S¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWuW6W$Fó7∆îÊ÷RríÁf«VRÁG&ñ“Çí¿¢W6W&Ê÷S¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWuW6W&Ê÷RríÁf«VRÁG&ñ“Çí¿¢77v˜&C¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWuW6W%77v˜&BríÁf«VR¿¢&ˆ∆S¶Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWuW6W%&ˆ∆RríÁf«VP¢“ó“ì∞¢Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWuW6W$Fó7∆îÊ÷RríÁf«VS“rs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWuW6W&Ê÷RríÁf«VS“rs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWuW6W%77v˜&BríÁf«VS“rs∂vóB∆ˆEW6W'2Çì∞¢÷6F6ÇÜW'"ó∂∆W'BÇt6˜V∆BÊ˜B7&VFRW6W#¢r∂W'"Ê÷W76vRó–¢&WGW&‚f«6S∞ß–¶7ñÊ2gVÊ7Fñˆ‚&V÷˜fUW6W"ÜñB«W6W&Ê÷Ró∂ñbÇ6ˆÊfó&“Çu&V÷˜fRW6W""r∑W6W&Ê÷R≤r#Úríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜W6W'2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆEW6W'2Çó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDFWfñ6W2Çó∞¢6ˆÁ7BF&ˆGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6W2rì∂ñbÇF&ˆGíó&WGW&„∞¢G'ó∂6ˆÁ7B÷ÊWrU$≈6V&6Ö&◊2Çí«6S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw6V&6Çrí«7C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw7FGW2rí∆6√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆76ñfñ6Fñˆ‚rì∂ñbá6SÚÁf«VRóÁ6WBÇw6V&6Çr«6RÁf«VRì∂ñbá7CÚÁf«VRóÁ6WBÇw7FGW2r«7BÁf«VRì∂ñbÜ6√ÚÁf«VRóÁ6WBÇv6∆76ñfñ6Fñˆ‚r∆6¬Áf«VRì∂6ˆÁ7B&W7ˆÁ6S÷vóBß6ˆ‚Çrˆí˜cˆFWfñ6W3Úr∑ÁFı7G&ñÊrÇíí∆C‘'&íÊó4'&íá&W7ˆÁ6Rì˜&W7ˆÁ6S•µ“«&˜w3÷BÁ6∆ñ6RÉ√"ì∑F&ˆGíÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷áÉ”Ê«G"ˆÊ6∆ñ6≥“&vÙFWfñ6RÇG∑ÇÊñG“í"7Gñ∆S“&7W'6˜#ßˆñÁFW"#„«FB6∆73“"G∂W62áÇÁ7FGW2ó“#„«7‚6∆73“&F˜B#Ó)xÛ¬˜7„‚G∂W62ÇáÇÁ7FGW7«¬wVÊ∂Ê˜v‚ríÁ&W∆6RÇuÚr¬rríó”¬˜FC„«FC„∆Fób6∆73“&FWfñ6R÷Ê÷R#‚G∂FWfñ6Tñ6ˆ‰áF÷¬áÇó”∆Fóc„∆'WGFˆ‚6∆73“&FWfñ6R÷∆ñÊ≤"ˆÊ6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∂vÙFWfñ6RÇG∑ÇÊñG“í#‚G∂W62áÇÊÊ÷W««ÇÊÜ˜7FÊ÷W«¬uVÊ∂Ê˜v‚FWfñ6Rró”¬ˆ'WGFˆ„„∆Fób6∆73“&◊WFVB#‚G∂W62áÇÊFWfñ6U˜GóW«¬uVÊ6∆76ñfñVBró”¬ˆFóc„¬ˆFóc„¬ˆFóc„¬˜FC„«FC‚G∂W62áÇÊó«¬~(	Bró”¬˜FC„«FC‚G∂W62áÇÊ÷7«¬~(	Bró”¬˜FC„«FC‚G∂W62áÇÁfVÊF˜'«¬~(	Bró”¬˜FC„«FC‚G∂W62áÇÊFWfñ6U˜GóW«¬~(	Bró”¬˜FC„«FC‚G∑ÇÊ∆7E˜6VV„ˆW62ÜÊWrFFRáÇÊ∆7E˜6VV‚íÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#r"6∆73“&V◊Gí#‰ÊÚFWfñ6W2Fó66˜fW&VBñWB‚6∆ñ6≤66‚Ê˜rFÚFó66˜fW"FÜRÊWGv˜&≤„¬˜FC„¬˜G#‚s∂«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∑&WGW&‚G÷6F6ÇÜRó∑F&ˆGíÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#r"6∆73“&V◊Gí#ÂVÊ&∆RFÚ∆ˆBFWfñ6W3¢r∂W62ÜRÊ÷W76vRí≤s¬˜FC„¬˜G#‚s∑&WGW&‚µ◊–ß–¶7ñÊ2gVÊ7Fñˆ‚7ñ6∆T6∆72ÜñB∆7W'&VÁBó∂vóBß6ˆ‚Çrˆí˜cˆFWfñ6W2Úr∂ñB«∂÷WFÜˆC¢uD4Çr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂6∆76ñfñ6Fñˆ„§4ƒ55Ù5î4ƒU∂7W'&VÁE◊«¬vÊWrw“ó“ì∂∆ˆBÇó–¶gVÊ7Fñˆ‚6WE66Â7FGW2Ü÷W76vR«7FFS“rró∞¢6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw66Â7FGW2rì∞¢ñbÜV¬ó∂V¬ÁFWáD6ˆÁFVÁC÷÷W76vW«¬rs∂V¬Ê6∆74Ê÷S“w66‚◊7FGW2r≤á7FFSÚrr∑7FFS¢rró–¢6ˆÁ7BF6É÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvF6Ö&Vg&W6Ö7FFRrì∂ñbÜF6Çbf÷W76vRñF6ÇÁFWáD6ˆÁFVÁC÷÷W76vS∞ß–¶gVÊ7Fñˆ‚f˜&÷DWfVÁEFñ÷Ráf«VRó∑G'ó∑&WGW&‚ÊWrFFRáf«VRíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“¬∂Ü˜W#¢vÁV÷W&ñ2r∆÷ñÁWFS¢s"÷FñvóBw“ó÷6F6ÇÖÚó∑&WGW&‚~(	Bw◊–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDWfVÁG2Çó∞¢6ˆÁ7BF&∆S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvWfVÁG2rí∆∆ó7C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv7FófóGî∆ó7Brì∞¢G'ó∞¢6ˆÁ7B&˜w3÷vóBß6ˆ‚Çrˆí˜cˆWfVÁG3ˆ∆ñ÷óC”3rì∞¢ñbáF&∆RóF&∆RÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷áÉ”Ê«G#„«FC‚G∑ÇÊ7&VFVEˆCˆW62ÜÊWrFFRáÇÊ7&VFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC„«7‚6∆73“'ñ∆¬#‚G∂W62áÇÊWfVÁE˜GóW«¬vWfVÁBró”¬˜7„„¬˜FC„«FC‚G∂W62áÇÊ÷7«¬~(	Bró”¬˜FC„«FC‚G∂W62áÇÊó«¬~(	Bró”¬˜FC„«FC‚G∂W62áÇÊFWFñ«7«¬rró”¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#R"6∆73“&V◊Gí#‰ÊÚ7FófóGíñWB„¬˜FC„¬˜G#‚s∞¢ñbÜ∆ó7Bñ∆ó7BÊñÊÊW$ÖD‘√◊&˜w2Á6∆ñ6RÉ√bíÊ÷ÇáÇ∆íì”Ê∆Fób6∆73“&7FófóGí◊&˜r#„«7‚6∆73“&7FófóGí÷F˜BG∂íS3”””Úvw&VV‚s¢rw“#„¬˜7„„∆Fóc„∆Fób6∆73“&7FófóGí◊FóF∆R#‚G∂W62ÇáÇÊWfVÁE˜GóW«¬tÊWGv˜&≤7FófóGíríÁ&W∆6T∆¬ÇuÚr¬rríó”¬ˆFóc„∆Fób6∆73“&7FófóGí◊7V"#‚G∂W62áÇÊó««ÇÊ÷7«¬tÊWGv˜&≤ró“G∑ÇÊFWFñ«3Ú|+rr∂W62áÇÊFWFñ«2ì¢rw”¬ˆFóc„¬ˆFóc„«7‚6∆73“&7FófóGí◊Fñ÷R#‚G∂f˜&÷DWfVÁEFñ÷RáÇÊ7&VFVEˆBó”¬˜7„„¬ˆFócÊíÊ¶ˆñ‚Çrró«¬s∆Fób6∆73“&V◊Gí#‰ÊÚ&V6VÁB7FófóGí„¬ˆFóc‚s∞¢&WGW&‚&˜w3∞¢÷6F6ÇÜRó∞¢ñbáF&∆RóF&∆RÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#R"6∆73“&V◊Gí#ÂVÊ&∆RFÚ∆ˆB7FófóGí„¬˜FC„¬˜G#‚s∞¢ñbÜ∆ó7Bñ∆ó7BÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#ÂVÊ&∆RFÚ∆ˆB&V6VÁB7FófóGí„¬ˆFóc‚s∞¢&WGW&‚µ”∞¢–ß–†¶gVÊ7Fñˆ‚cC36WD÷WFW"ÜñB«f«VR«7VffóÉ“rRró∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBí∆&#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñB≤t&"rì∂ñbÜV¬ñV¬ÁFWáD6ˆÁFVÁC“áf«VS”÷ÁV∆√Ú~(	Bs§÷FÇÁ&˜VÊBáf«VRí∑7VffóÇì∂ñbÜ&"ñ&"Á7Gñ∆RÁvñGFÉ‘÷FÇÊ÷ÇÉƒ÷FÇÊ÷ñ‚ÉƒÁV÷&W"áf«VRó«√íí≤rRw–¶gVÊ7Fñˆ‚cC37UW&6VÁBÜ6ÜV6≤ó∂6ˆÁ7BFWáC’7G&ñÊrÜ6ÜV6≥ÚÊFWFñ««¬rrì∂6ˆÁ7BW&6VÁC◊FWáBÊ÷F6ÇÇÚÖ≥”ï“≤ÉÛ•¬Â≥”ï“≤ìÚï«2¢RÚì∂ñbáW&6VÁBó&WGW&‚ÁV÷&W"áW&6VÁE≥“ì∂6ˆÁ7B&s‘ÁV÷&W"Ü6ÜV6≥ÚÁf«VRì∂ñbÇÁV÷&W"Êó4fñÊóFRá&ríó&WGW&‚ÁV∆√∂6ˆÁ7B6˜&W3“áGóVˆbÊfñvF˜"”“wVÊFVfñÊVBrbdÁV÷&W"ÜÊfñvF˜"ÊÜ&Gv&T6ˆÊ7W'&VÊ7ííó«√∑&WGW&‚÷FÇÊ÷ÇÉƒ÷FÇÊ÷ñ‚É«&rˆ6˜&W2£íó–¶gVÊ7Fñˆ‚cC3ÜV«FÑFWFñ¬Ü6ÜV6≤ó∂6ˆÁ7BÊ÷S’7G&ñÊrÜ6ÜV6≥ÚÊÊ÷W«¬rríÁFÙ∆˜vW$66RÇí∆FWFñ√’7G&ñÊrÜ6ÜV6≥ÚÊFWFñ««¬rrì∂ñbÇÊ÷RÊñÊ6«VFW2ÇwFV◊W&GW&Rríó&WGW&‚FWFñ√∑&WGW&‚FWFñ¬Á&W∆6RÇÚÇ”ı≥”ï“≤ÉÛ•¬Â≥”ï“≤ìÚï«2¨+ˆ2ˆñr¬ÖÚ«f«VRì”‚ÇÑÁV÷&W"áf«VRí£íÛRí≥3"íÁFÙfóÜVBÉí≤r+bró–¶gVÊ7Fñˆ‚cC3ÜV«FÑ÷WG&ñ72Ü∆ñÊ6Ró∂6ˆÁ7B6ÜV6∑3‘'&íÊó4'&íÜ∆ñÊ6SÚÊ6ÜV6∑2ìˆ∆ñÊ6RÊ6ÜV6∑3•µ”∂6ˆÁ7BfñÊC“áv˜&G2ì”Ê6ÜV6∑2ÊfñÊBÜ3”Áv˜&G2Á6ˆ÷Rás”Â7G&ñÊrÜ2ÊÊ÷W«¬rríÁFÙ∆˜vW$66RÇíÊñÊ6«VFW2árííì∂6ˆÁ7B7C“Ü2ì”Á∂6ˆÁ7BC’7G&ñÊrÜ3ÚÊFWFñ««¬rrì∂6ˆÁ7B”◊BÊ÷F6ÇÇÚÖ≥”ï“≤ÉÛ•¬Â≥”ï“≤ìÚï«2¢RÚì∑&WGW&‚”Ú∂’≥”¶ÁV∆«”∂6ˆÁ7BFV◊“Ü2ì”Á∂6ˆÁ7BC’7G&ñÊrÜ3ÚÊFWFñ««¬rrì∂6ˆÁ7B”◊BÊ÷F6ÇÇÚÖ≥”ï“≤ÉÛ•¬Â≥”ï“≤ìÚï«2¨+ˆ2ˆíì∑&WGW&‚”Ú∂’≥”¶ÁV∆«”∑cC36WD÷WFW"ÇwcC37Rr«cC37UW&6VÁBÜfñÊBÖ≤v7Rr¬v∆ˆBu“ííì∑cC36WD÷WFW"ÇwcC3÷V“r«7BÜfñÊBÖ≤v÷V÷˜'ír¬w&“u“ííì∑cC36WD÷WFW"ÇwcC3Fó6≤r«7BÜfñÊBÖ≤vFó6≤r¬w7F˜&vRu“ííì∂6ˆÁ7BGc◊FV◊ÜfñÊBÖ≤wFV◊W&GW&Rr¬wFÜW&÷¬u“íí«FS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3FV◊rí«F#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3FV◊&"rì∂ñbáFRóFRÁFWáD6ˆÁFVÁC◊Gc”÷ÁV∆√Ú~(	Bs¢ÇáGb£íÛRí≥3"íÁFÙfóÜVBÉí≤|+bs∂ñbáF"óF"Á7Gñ∆RÁvñGFÉ‘÷FÇÊ÷ñ‚É¬áGg«√íÛÉR£í≤rRw–¶gVÊ7Fñˆ‚cC3&VÊFW%6W'fñ6W2á6WGFñÊw2∆6ÜV6∑2ó∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC36W'fñ6W2rì∂ñbÇV¬ó&WGW&„∂6ˆÁ7B'#‘'&íÊó4'&íá6WGFñÊw2ì˜6WGFñÊw3•µ”∂6ˆÁ7B&V6VÁC‘'&íÊó4'&íÜ6ÜV6∑2ìˆ6ÜV6∑3•µ”∂ñbÇ'"Ê∆VÊwFÇó∂V¬ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰ÊÚ÷ˆÊóF˜'26ˆÊfñwW&VB„¬ˆFóc‚s∑&WGW&Á÷V¬ÊñÊÊW$ÖD‘√÷'"Á6∆ñ6RÉ√bíÊ÷Ü””Á∂6ˆÁ7BÜóC◊&V6VÁBÊfñÊBÜ3”Â7G&ñÊrÜ2Ê÷ˆÊóF˜%ˆñG«∆2Á6WGFñÊuˆñG«¬rrì””’7G&ñÊrÜ“ÊñG«¬rríó««&V6VÁBÊfñÊBÜ3”‚2Ê÷ˆÊóF˜%ˆñBbb2Á6WGFñÊuˆñBbe7G&ñÊrÜ2Ê∂ñÊG«¬rrì””’7G&ñÊrÜ“Ê∂ñÊG«¬rríbe7G&ñÊrÜ2ÁF&vWG«¬rrì””’7G&ñÊrÜ“ÁF&vWG«¬rríì∂6ˆÁ7B7FFS’7G&ñÊrÜÜóCÚÁ7FGW7«¬wVÊ∂Ê˜v‚ríÁFÙ∆˜vW$66RÇì∂6ˆÁ7Bˆ≥÷ÜóCı≤wWr¬vˆ≤r¬vÜV«Fáír¬vˆÊ∆ñÊRr¬w'VÊÊñÊrr¬w7V66W72u“ÊñÊ6«VFW2á7FFRì¶“ÊVÊ&∆VB”÷f«6S∑&WGW&‚∆Fób6∆73“'cC3◊6W'fñ6R◊&˜r#„«7„‚G∂W62Ü“ÊÊ÷W«∆“ÁF&vWG«∆“Ê6ÜV6µ˜GóW«¬t÷ˆÊóF˜"ró”¬˜7„„«7„„∆í6∆73“'cC3÷∆ófR÷F˜B"7Gñ∆S“&&6∂w&˜VÊC¢G∂ˆ≥Úr3CFfs¢r6fcSìcÇw“#„¬ˆì‚G∂ˆ≥Úu'VÊÊñÊrs¢tGFVÁFñˆ‚w”¬˜7„„«7„‚G∂W62Ü“Ê6ÜV6µ˜GóW«¬t6ÜV6≤ró”¬˜7„„¬ˆFócÊ“íÊ¶ˆñ‚Çrró–¶7ñÊ2gVÊ7Fñˆ‚cC3&VÊFW%Fñ6∂WG2Çó∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3Fñ6∂WG2rì∂ñbÇV¬ó&WGW&„∑G'ó∂6ˆÁ7B&˜w3÷vóBß6ˆ‚Çrˆí˜c˜Fñ6∂WG3ˆ∆ñ÷óC”RríÊ6F6ÇÇÇì”Âµ“í∆'#‘'&íÊó4'&íá&˜w2ì˜&˜w3¢á&˜w3ÚÊóFV◊7«≈µ“ì∂V¬ÊñÊÊW$ÖD‘√÷'"Ê∆VÊwFÉˆ'"Á6∆ñ6RÉ√RíÊ÷áC”Ê∆Fób6∆73“'cC3◊Fñ6∂WB◊&˜r#„∆#‚G∂W62áBÁFñ6∂WEˆÁV÷&W'«¬ÇuDµB“rµ7G&ñÊráBÊñG«¬rríÁE7F'BÉB¬srííó”¬ˆ#„«7„‚G∂W62áBÁFóF∆W«¬uFñ6∂WBró”¬˜7„„«7‚6∆73“'cC3◊Fñ6∂WB◊7FFRGµ7G&ñÊráBÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇó“#‚G∂W62áBÁ7FGW7«¬t˜V‚ró”¬˜7„„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚ&V6VÁBFñ6∂WG2„¬ˆFóc‚w÷6F6ÇÖÚó∂V¬ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰ÊÚ&V6VÁBFñ6∂WG2„¬ˆFóc‚w◊–¶gVÊ7Fñˆ‚cC3WFFT6∆ˆ6≤Çó∂6ˆÁ7BC÷ÊWrFFRÇí∆FFS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3FFRrí∆6∆ˆ6≥÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC36∆ˆ6≤rì∂ñbÜFFRñFFRÁFWáD6ˆÁFVÁC÷BÁFÙ∆ˆ6∆TFFU7G&ñÊrÖµ“¬∂÷ˆÁFÉ¢w6Ü˜'Br∆Fì¢vÁV÷W&ñ2r«ñV#¢vÁV÷W&ñ2w“ì∂ñbÜ6∆ˆ6≤ñ6∆ˆ6≤ÁFWáD6ˆÁFVÁC÷BÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“¬∂Ü˜W#¢vÁV÷W&ñ2r∆÷ñÁWFS¢s"÷FñvóBw“ó–¶gVÊ7Fñˆ‚6WDF6Ü&ˆ&D÷÷ˆFRÜ÷ˆFR∆WfVÁBó∂WfVÁCÚÁ&WfVÁDFVfV«BÇì∂WfVÁCÚÁ7F˜&˜vFñˆ‚Çì∂6ˆÁ7BÊWáC÷÷ˆFS””“wF˜ˆ∆ˆwísÚwF˜ˆ∆ˆwís¢wv˜&∆Bs∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂FF÷÷◊fñWu“ríÊf˜$V6ÇáÉ”ÁÇÊ6∆74∆ó7BÁFˆvv∆RÇv7FófRr«ÇÊFF6WBÊ÷fñWs””÷ÊWáBíì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂FF÷÷÷÷ˆFU“ríÊf˜$V6ÇáÉ”ÁÇÊ6∆74∆ó7BÁFˆvv∆RÇv7FófRr«ÇÊFF6WBÊ÷÷ˆFS””÷ÊWáBíì∑G'ó∂∆ˆ6≈7F˜&vRÁ6WDóFV“ÇvvˆG6WñU˜cC3ˆF6Ü&ˆ&Eˆ÷ˆ÷ˆFRr∆ÊWáBó÷6F6ÇÖÚó∑◊–¶gVÊ7Fñˆ‚ñÊóDF6Ü&ˆ&D÷÷ˆFRÇó∂∆WB÷ˆFS“wv˜&∆Bs∑G'ó∂÷ˆFS÷∆ˆ6≈7F˜&vRÊvWDóFV“ÇvvˆG6WñU˜cC3ˆF6Ü&ˆ&Eˆ÷ˆ÷ˆFRró«¬wv˜&∆Bw÷6F6ÇÖÚó∑◊6WDF6Ü&ˆ&D÷÷ˆFRÜ÷ˆFRó–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDF6Ü&ˆ&BÇó∞¢ñÊóDF6Ü&ˆ&D÷÷ˆFRÇì∞¢6ˆÁ7B&Vg&W6É÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvF6Ö&Vg&W6Ö7FFRrì∂ñbá&Vg&W6Çó&Vg&W6ÇÁFWáD6ˆÁFVÁC“u&Vg&W6ÜñÊ~(
bs∞¢6ˆÁ7BF6∑3÷vóB&ˆ÷ó6RÊ∆≈6WGF∆VBÖ∞¢ß6ˆ‚Çrˆí˜cˆÜV«FÇrí¿¢ß6ˆ‚Çrˆí˜cˆ∆ñÊ6RˆÜV«FÇríÊ6F6ÇÇÇì”ÊÁV∆¬í¿¢∆ˆDFWfñ6W2Çí¿¢∆ˆEG&ffñ2Çí¿¢∆ˆDWfVÁG2Çí¿¢ß6ˆ‚Çrˆí˜cˆ÷ˆÊóF˜&ñÊr˜6WGFñÊw2ríÊ6F6ÇÇÇì”Âµ“í¿¢ß6ˆ‚Çrˆí˜cˆ÷ˆÊóF˜&ñÊrˆ6ÜV6∑2ríÊ6F6ÇÇÇì”Âµ“ê¢“ì∞¢6ˆÁ7BÜV«FÖ&W7V«C◊F6∑5≥”∞¢ñbÜÜV«FÖ&W7V«BÁ7FGW3””“vgV∆fñ∆∆VBró∞¢6ˆÁ7BÉ÷ÜV«FÖ&W7V«BÁf«VS∞¢6ˆÁ7BF˜FƒV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwF˜F¬rí∆ˆÊ∆ñÊTV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvˆÊ∆ñÊRrí∆ó77VTV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwVÊ∂Ê˜v‚rì∞¢ñbáF˜FƒV¬óF˜FƒV¬ÁFWáD6ˆÁFVÁC÷ÇÁF˜F√ÛÛ∞¢ñbÜˆÊ∆ñÊTV¬ñˆÊ∆ñÊTV¬ÁFWáD6ˆÁFVÁC÷ÇÊˆÊ∆ñÊSÛÛ∞¢ñbÜó77VTV¬ñó77VTV¬ÁFWáD6ˆÁFVÁC÷ÇÊÊVVG5˜&WfñWsÛˆÇÁVÊ∂Ê˜v„ÛÛ∞¢6ˆÁ7BG#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvˆÊ∆ñÊUG&VÊBrì∂ñbáG"óG"ÁFWáD6ˆÁFVÁC÷ÇÁF˜F√Ù÷FÇÁ&˜VÊBÇÜÇÊˆÊ∆ñÊRˆÇÁF˜F¬í£í≤rRs¢sRs∞¢6ˆÁ7BF˜F√‘ÁV÷&W"ÜÇÁF˜F««√í∆ˆÊ∆ñÊS‘ÁV÷&W"ÜÇÊˆÊ∆ñÊW«√í«&WfñWs‘ÁV÷&W"ÜÇÊÊVVG5˜&WfñWsÛˆÇÁVÊ∂Ê˜v„ÛÛí∆ˆff∆ñÊS‘÷FÇÊ÷ÇÉ«F˜F¬÷ˆÊ∆ñÊRí∆FWfñ6U&˜w3◊F6∑5≥%“Á7FGW3””“vgV∆fñ∆∆VBrbd'&íÊó4'&íáF6∑5≥%“Áf«VRì˜F6∑5≥%“Áf«VS•µ“«6óFW3÷ÊWr6WBÜFWfñ6U&˜w2Ê÷ÜñÁfVÁF˜'ï6óFTÊ÷RíÊfñ«FW"Ñ&ˆˆ∆V‚ííÁ6ó¶S∂6ˆÁ7BFˆÁWC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3FWfñ6TFˆÁWBrì∂ñbÜFˆÁWBó∂6ˆÁ7BˆÂ7C◊F˜F√ˆˆÊ∆ñÊR˜F˜F¬££∆ˆfe7C◊F˜F√ˆˆff∆ñÊR˜F˜F¬££∂FˆÁWBÁ7Gñ∆RÊ&6∂w&˜VÊC÷6ˆÊñ2÷w&FñVÁBÇ3CFfG∂ˆÂ7G“R¬6fcSìcÇG∂ˆÂ7G“RG∂ˆÂ7B∂ˆfe7G“R¬6ff3CCrG∂ˆÂ7B∂ˆfe7G“RRñ÷f˜"Ü6ˆÁ7B∂ñB«f≈“ˆbµ≤wcC3FˆÁWEF˜F¬r«F˜F≈“≈≤wcC3∆VvVÊDˆÊ∆ñÊRr∆ˆÊ∆ñÊU“≈≤wcC3∆VvVÊDˆff∆ñÊRr∆ˆff∆ñÊU“≈≤wcC3∆VvVÊE&WfñWrr«&WfñWu“≈≤wcC3÷6óFW2r«6óFW5“≈≤wcC3÷FWfñ6W2r«F˜F≈“≈≤wcC3÷ˆff∆ñÊRr∆ˆff∆ñÊU“≈≤wcC3÷∆W'G2r«&WfñWu’“ó∂6ˆÁ7BS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜRñRÁFWáD6ˆÁFVÁC◊f«÷6ˆÁ7BG3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwcC3FWfñ6U7V"rì∂ñbÜG2ñG2ÁFWáD6ˆÁFVÁC◊&WfñWs˜&WfñWr≤rÊVVB&WfñWrs¢tñÁfVÁF˜'íÜV«Fáís∞¢6ˆÁ7B66ÊÊW#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvF6Ö66ÊÊW%7FFRrì∞¢ñbá66ÊÊW"ó∑66ÊÊW"ÁFWáD6ˆÁFVÁC÷ÇÁ66ÊÊW#ÚÊÜV«FáìÚu66ÊÊW"ÜV«Fáís¢ÜÇÁ66ÊÊW#ÚÊFWFñ««¬u66ÊÊW"vóFñÊrrì∑66ÊÊW"Ê6∆74∆ó7BÁFˆvv∆RÇwv&‚r¬ÇÁ66ÊÊW#ÚÊÜV«Fáíó–¢6ˆÁ7BÜ#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÜ&"rì∞¢ñbÜÜ"ó∂ñbÜÇÁ66ÊÊW#ÚÊÜV«Fáíó∂Ü"Á7Gñ∆RÊFó7∆ì“vÊˆÊRw÷V«6W∂Ü"Á7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∂Ü"Ê6∆74Ê÷S“vÜV«FÜ&"&Bs∂Ü"ÁFWáD6ˆÁFVÁC“~)™66ÊÊW#¢r≤ÜÇÁ66ÊÊW#ÚÊFWFñ««¬vÊ˜B&W˜'FñÊrró◊–¢÷V«6W∞¢6ˆÁ7B66ÊÊW#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvF6Ö66ÊÊW%7FFRrì∂ñbá66ÊÊW"ó∑66ÊÊW"ÁFWáD6ˆÁFVÁC“tF6Ü&ˆ&BíVÊfñ∆&∆Rs∑66ÊÊW"Ê6∆74∆ó7BÊFBÇwv&‚ró–¢–¢6ˆÁ7B∆ñÊ6TÜV«FÉ◊F6∑5≥“Á7FGW3””“vgV∆fñ∆∆VBs˜F6∑5≥“Áf«VS¶ÁV∆√∞¢6ˆÁ7B7ó7FV’7FFS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw7ó7FV‘ÜV«FÖ7FFRrí«7ó7FV’G&VÊC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw7ó7FV‘ÜV«FÖG&VÊBrì∞¢ñbá7ó7FV’7FFRó∞¢6ˆÁ7B˜fW&∆√’7G&ñÊrÜ∆ñÊ6TÜV«FÉÚÊ˜fW&∆««¬wVÊ∂Ê˜v‚ríÁFÙ∆˜vW$66RÇì∞¢7ó7FV’7FFRÁFWáD6ˆÁFVÁC÷˜fW&∆√””“vˆ≤w«∆˜fW&∆√””“vÜV«FáísÚtÜV«Fáís¶˜fW&∆√””“wVÊ∂Ê˜v‚sÚt6ÜV6∂ñÊ~(
bs¢tGFVÁFñˆ‚s∞¢7ó7FV’7FFRÊ6∆74∆ó7BÁFˆvv∆RÇvÜV«FÇ÷vˆˆBr∆˜fW&∆√””“vˆ≤w«∆˜fW&∆√””“vÜV«Fáírì∞¢7ó7FV’7FFRÊ6∆74∆ó7BÁFˆvv∆RÇvÜV«FÇ÷&Br¬≤vˆ≤r¬vÜV«Fáír¬wVÊ∂Ê˜v‚u“ÊñÊ6«VFW2Ü˜fW&∆¬íì∞¢–¢cC3ÜV«FÑ÷WG&ñ72Ü∆ñÊ6TÜV«FÇì∑cC3WFFT6∆ˆ6≤Çì∞¢ñbá7ó7FV’G&VÊBó∞¢6ˆÁ7B6ÜV6∑3‘'&íÊó4'&íÜ∆ñÊ6TÜV«FÉÚÊ6ÜV6∑2ìˆ∆ñÊ6TÜV«FÇÊ6ÜV6∑3•µ”∞¢6ˆÁ7BVÊÜV«Fáì÷6ÜV6∑2Êfñ«FW"áÉ”‚≤vˆ≤r¬vÜV«Fáír¬w'VÊÊñÊru“ÊñÊ6«VFW2Ö7G&ñÊráÇÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇíííÊ∆VÊwFÉ∞¢7ó7FV’G&VÊBÁFWáD6ˆÁFVÁC◊VÊÜV«Fáì˜VÊÜV«Fáí≤róFV“r≤áVÊÜV«Fáì”””Úrs¢w2rí≤rÊVVB&WfñWrs¢ufñWrFWFñ«2(i"s∞¢–¢6ˆÁ7B6WGFñÊw3◊F6∑5≥U“Á7FGW3””“vgV∆fñ∆∆VBsÚáF6∑5≥U“Áf«VW«≈µ“ì•µ”∞¢6ˆÁ7B6ÜV6∑3◊F6∑5≥e“Á7FGW3””“vgV∆fñ∆∆VBsÚáF6∑5≥e“Áf«VW«≈µ“ì•µ”∞¢cC3&VÊFW%6W'fñ6W2á6WGFñÊw2∆6ÜV6∑2ì∑cC3&VÊFW%Fñ6∂WG2Çì∞¢ñbá&Vg&W6Çó&Vg&W6ÇÁFWáD6ˆÁFVÁC“t∆7B&Vg&W6ÜVBr∂ÊWrFFRÇíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÇì∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆBÇó∑&WGW&‚∆ˆDF6Ü&ˆ&BÇó–¶7ñÊ2gVÊ7Fñˆ‚66‚Çó∞¢6ˆÁ7B'F„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw66‰'F‚rì∞¢ñbÜ'F‚ó∂'F‚ÊFó6&∆VC◊G'VS∂'F‚ÁFWáD6ˆÁFVÁC“~)˚266ÊÊñÊ~(
bw–¢6WE66Â7FGW2ÇuVWVñÊr66Ó(
br¬v'W7írì∞¢G'ó∞¢6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜66‚r«∂÷WFÜˆC¢uı5Bw“ì∞¢6WE66Â7FGW2Çu66‚VWVVB(	BvóFñÊrf˜"66ÊÊW.(
br¬v'W7írì∞¢∆WBGFV◊G3”∞¢6ˆÁ7Bˆ∆√÷7ñÊ2Çì”Á∞¢GFV◊G2≤≥∞¢G'ó∞¢6ˆÁ7B7C÷vóBß6ˆ‚Çrˆí˜c˜66‚˜7FGW2rì∂6ˆÁ7B&W◊7BÁ&WVW7C∞¢ñbá&Wbb&WÊñC””◊"Á&WVW7EˆñBbb&WÁ7FGW3””“v6ˆ◊∆WFVBró∞¢6WE66Â7FGW2Çu66‚6ˆ◊∆WFR(	Br≤á&WÊFWfñ6W5ˆf˜VÊCÛÛí≤rFWfñ6W2f˜VÊBr¬vˆ≤rì∞¢ñbÜ'F‚ó∂'F‚ÊFó6&∆VC÷f«6S∂'F‚ÁFWáD6ˆÁFVÁC“~)˚266‚Ê˜rw–¢vóB&ˆ÷ó6RÊ∆≈6WGF∆VBÖ∂∆ˆDF6Ü&ˆ&BÇí∆∆ˆDñÁfVÁF˜'íÇï“ì∞¢&WGW&„∞¢–¢ñbá&Wbb&WÊñC””◊"Á&WVW7EˆñBbb&WÁ7FGW3””“vfñ∆VBró∞¢6WE66Â7FGW2Çu66‚fñ∆VC¢r≤á&WÊW'&˜'«¬wVÊ∂Ê˜v‚66ÊÊW"W'&˜"rí¬v&Brì∞¢ñbÜ'F‚ó∂'F‚ÊFó6&∆VC÷f«6S∂'F‚ÁFWáD6ˆÁFVÁC“~)˚266‚Ê˜rw–¢&WGW&„∞¢–¢÷6F6ÇÜRó∂6ˆÁ6ˆ∆RÁv&‚Çw66‚7FGW2ˆ∆¬fñ∆VBr∆Ró–¢ñbÜGFV◊G3√CRó∑6WEFñ÷V˜WBáˆ∆¬√ó–¢V«6W∞¢6WE66Â7FGW2Çu66‚ó27Fñ∆¬VWVVB(	B6ÜV6≤7ó7FV“ÜV«FÇñbFÜó2W'6ó7G2‚r¬v&Brì∞¢ñbÜ'F‚ó∂'F‚ÊFó6&∆VC÷f«6S∂'F‚ÁFWáD6ˆÁFVÁC“~)˚266‚Ê˜rw–¢–¢”∞¢ˆ∆¬Çì∞¢÷6F6ÇÜRó∞¢6WE66Â7FGW2ÇuVÊ&∆RFÚVWVR66„¢r∂RÊ÷W76vR¬v&Brì∞¢ñbÜ'F‚ó∂'F‚ÊFó6&∆VC÷f«6S∂'F‚ÁFWáD6ˆÁFVÁC“~)˚266‚Ê˜rw–¢–ß–†¶gVÊ7Fñˆ‚vÙFWfñ6RÜñBó∂ñbÇñBó&WGW&„∑vñÊF˜rÊ∆ˆ6Fñˆ‚Ê76ñv‚ÇrˆFWfñ6RÚr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜñBíó–¶gVÊ7Fñˆ‚˜V‰6∆V$FFÜ∂ñÊBó∂ñbÇ‘W«ƒ‘RÁ&ˆ∆R”“vF÷ñ‚ró&WGW&„∂6ˆÁ7B÷ˆF√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆V$FF÷ˆF¬rì∂ñbÇ÷ˆF¬ó&WGW&„∂6∆V$FF∂ñÊBÁf«VS÷∂ñÊC∂6∆V$FF&V6ˆ‚Áf«VS“rs∂6∆V$FFW'"ÁFWáD6ˆÁFVÁC“rs∂ñbÜ∂ñÊC””“vVFóBró∂6∆V$FFFóF∆RÁFWáD6ˆÁFVÁC“t6∆V"VFóB∆ˆrs∂6∆V$FFÜV«ÁFWáD6ˆÁFVÁC“t&V6ˆ‚ó2÷ÊFF˜'í‚tÙE4UîRvñ∆¬7&VFRÊWrVFóBWfVÁBÊ÷ñÊrñ˜R2FÜRW6W"vÜÚ6∆V&VBFÜR∆ˆr‚s∂6∆V$FFv&ÊñÊrÁFWáD6ˆÁFVÁC“uFÜRÊWrVFóEˆ∆ˆuˆ6∆V&VBWfVÁBó2&˜FV7FVBÊB6ÊÊ˜B&R&V÷˜fVBf˜"rFó2‚s∂6∆V$FF6ˆÊfó&“ÁFWáD6ˆÁFVÁC“t6∆V"VFóB∆ˆrw÷V«6W∂6∆V$FFFóF∆RÁFWáD6ˆÁFVÁC“t6∆V"6∆ñVÁBbVW'íÊ«óFñ72s∂6∆V$FFÜV«ÁFWáD6ˆÁFVÁC“t&V6ˆ‚ó2÷ÊFF˜'íÊBvñ∆¬&Rw&óGFV‚FÚFÜRVFóB∆ˆrvóFÇñ˜W"W6W&Ê÷R‚s∂6∆V$FFv&ÊñÊrÁFWáD6ˆÁFVÁC“uFÜó2&V÷˜fW2&WFñÊVBñÁFVw&Fñˆ‚Ê«óFñ726Ê6Ü˜G2‚FWfñ6RñÁfVÁF˜'íÊBFó66˜fW'í&V6˜&G2&RÊ˜BFV∆WFVB‚s∂6∆V$FF6ˆÊfó&“ÁFWáD6ˆÁFVÁC“t6∆V"Ê«óFñ72w÷÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∑6WEFñ÷V˜WBÇÇì”Ê6∆V$FF&V6ˆ‚Êfˆ7W2Çí√#ó–¶gVÊ7Fñˆ‚6∆˜6T6∆V$FFÇó∂6ˆÁ7B÷ˆF√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆V$FF÷ˆF¬rì∂ñbÜ÷ˆF¬ñ÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRw–¶7ñÊ2gVÊ7Fñˆ‚7V&÷óD6∆V$FFÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7B∂ñÊC÷6∆V$FF∂ñÊBÁf«VR«&V6ˆ„÷6∆V$FF&V6ˆ‚Áf«VRÁG&ñ“Çì∂6∆V$FFW'"ÁFWáD6ˆÁFVÁC“rs∂ñbá&V6ˆ‚Ê∆VÊwFÉ√Ró∂6∆V$FFW'"ÁFWáD6ˆÁFVÁC“u∆V6RVÁFW"&V6ˆ‚ˆbB∆V7BR6Ü&7FW'2‚s∑&WGW&‚f«6W÷6ˆÁ7BFÉ÷∂ñÊC””“vVFóBsÚrˆí˜cˆVFóBˆ6∆V"s¢rˆí˜cˆÊ«óFñ72ˆ6∆V"s∑G'ó∂6ˆÁ7B&W7V«C÷vóBß6ˆ‚áFÇ«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑&V6ˆÁ“ó“ì∂6∆˜6T6∆V$FFÇì∂ñbÜ∂ñÊC””“vVFóBrñvóB∆ˆDVFóBÇì∂V«6RvóB∆ˆDñÁFVw&FñˆÁ2Çì∂∆W'BÇÜ∂ñÊC””“vVFóBsÚtVFóB∆ˆrs¢tÊ«óFñ72rí≤r6∆V&VB'ír∑&W7V«BÊ6∆V&VEˆ'í≤r‚r∑&W7V«BÊFV∆WFVB≤r&V6˜&Bá2í&V÷˜fVB‚ró÷6F6ÇÜW'"ó∂6∆V$FFW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6∆V"FF¢r∂W'"Ê÷W76vW◊&WGW&‚f«6W–¶gVÊ7Fñˆ‚6˜'Ef«VRáFWáBó∂6ˆÁ7Bc“áFWáG«¬rríÁG&ñ“Çì∂6ˆÁ7Bó◊bÊ÷F6ÇÇı‚Ö∆G≥√7“ï¬‚Ö∆G≥√7“ï¬‚Ö∆G≥√7“ï¬‚Ö∆G≥√7“íBÚì∂ñbÜóó&WGW&‚∂∂ñÊC¢vÁV“r«f«VS¶óÁ6∆ñ6RÉíÁ&VGV6RÇÜ‚«Çì”Ê‚£#Sb¥ÁV÷&W"áÇí√ó”∂6ˆÁ7B„‘ÁV÷&W"ábÁ&W∆6RÇÚ¬ˆr¬rríì∂ñbáb”“rrbdÁV÷&W"Êó4fñÊóFRÜ‚íó&WGW&‚∂∂ñÊC¢vÁV“r«f«VS¶Á”∂6ˆÁ7BC‘FFRÁ'6Rábì∂ñbÇı≤“Û•◊∆◊«“ˆíÁFW7BábíbdÁV÷&W"Êó4fñÊóFRáBíó&WGW&‚∂∂ñÊC¢vÁV“r«f«VSßG”∑&WGW&‚∂∂ñÊC¢wFWáBr«f«VSßbÁFÙ∆˜vW$66RÇó◊–¶gVÊ7Fñˆ‚6˜'EF&∆T'îÜVFW"áFÇó∂6ˆÁ7BF&∆S◊FÇÊ6∆˜6W7BÇwF&∆Rrí«F&ˆGì◊F&∆RbgF&∆RÁD&ˆFñW2bgF&∆RÁD&ˆFñW5≥”∂ñbÇF&ˆGíó&WGW&„∂6ˆÁ7BñGÉ‘'&íÊg&ˆ“áFÇÁ&VÁDV∆V÷VÁBÊ6Üñ∆G&V‚íÊñÊFWÑˆbáFÇì∂6ˆÁ7B&˜w3‘'&íÊg&ˆ“áF&ˆGíÁ&˜w2íÊfñ«FW"á#”‚"ÁVW'ï6V∆V7F˜"ÇrÊV◊Gíríì∂ñbá&˜w2Ê∆VÊwFÉ√"ó&WGW&„∂6ˆÁ7B63“FÇÊ6∆74∆ó7BÊ6ˆÁFñÁ2Çw6˜'B÷62rì∑FÇÁ&VÁDV∆V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇwFÇríÊf˜$V6ÇÜÉ”ÊÇÊ6∆74∆ó7BÁ&V÷˜fRÇw6˜'B÷62r¬w6˜'B÷FW62ríì∑FÇÊ6∆74∆ó7BÊFBÜ63Úw6˜'B÷62s¢w6˜'B÷FW62rì∑&˜w2Á6˜'BÇÜ∆"ì”Á∂6ˆÁ7Bc◊6˜'Ef«VRÜÊ6V∆«5∂ñGÖ”ÚÊñÊÊW%FWáG«¬rrí∆'c◊6˜'Ef«VRÜ"Ê6V∆«5∂ñGÖ”ÚÊñÊÊW%FWáG«¬rrì∂∆WB6◊∂ñbÜbÊ∂ñÊC””“vÁV“rbf'bÊ∂ñÊC””“vÁV“rñ6◊÷bÁf«VR÷'bÁf«VS∂V«6R6◊’7G&ñÊrÜbÁf«VRíÊ∆ˆ6∆T6ˆ◊&RÖ7G&ñÊrÜ'bÁf«VRí«VÊFVfñÊVB«∂ÁV÷W&ñ3ßG'VR«6VÁ6óFófóGì¢v&6Rw“ì∑&WGW&‚63ˆ6◊¢÷6◊“ì∑&˜w2Êf˜$V6Çá#”ÁF&ˆGíÊVÊD6Üñ∆Bá"íó–¶gVÊ7Fñˆ‚VÊ&∆U6˜'F&∆UF&∆W2Çó∂ñbÇvñÊF˜rÂıˆvˆG6WñU6˜'F&∆T&˜VÊBó∂Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆S”Á∂6ˆÁ7BFÉ÷RÁF&vWBÊ6∆˜6W7BÇwFÇÁ6˜'F&∆R÷ÜVBrì∂ñbáFÇó6˜'EF&∆T'îÜVFW"áFÇó“ì∑vñÊF˜rÂıˆvˆG6WñU6˜'F&∆T&˜VÊC◊G'VW÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇwF&∆RFÜVBFÇríÊf˜$V6ÇáFÉ”Á∂6ˆÁ7B∆&V√“áFÇÁFWáD6ˆÁFVÁG«¬rríÁG&ñ“ÇíÁFÙ∆˜vW$66RÇì∂ñbÇ≤v7Fñˆ‚r¬v7FñˆÁ2r¬ru“ÊñÊ6«VFW2Ü∆&V¬íó∑FÇÊ6∆74∆ó7BÊFBÇw6˜'F&∆R÷ÜVBrì∑FÇÁFóF∆S“t6∆ñ6≤FÚ6˜'Bw◊“ó–¶gVÊ7Fñˆ‚˜VÂ&VÊ÷TFWfñ6RÜñB∆7W'&VÁDÊ÷R∆ñFVÁFóGíó∂6ˆÁ7B”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&VÊ÷TFWfñ6T÷ˆF¬rì∂ñbÇ“ó&WGW&„∑&VÊ÷TFWfñ6TñBÁf«VS÷ñC∑&VÊ÷TFWfñ6TÊ÷RÁf«VS÷7W'&VÁDÊ÷W«¬rs∑&VÊ÷TFWfñ6TñFVÁFóGíÁFWáD6ˆÁFVÁC÷ñFVÁFóGó«¬rs∑&VÊ÷TFWfñ6TW'"ÁFWáD6ˆÁFVÁC“rs∂“Á7Gñ∆RÊFó7∆ì“vw&ñBs∑6WEFñ÷V˜WBÇÇì”Á∑&VÊ÷TFWfñ6TÊ÷RÊfˆ7W2Çì∑&VÊ÷TFWfñ6TÊ÷RÁ6V∆V7BÇó“√#ó–¶gVÊ7Fñˆ‚˜VÂ&VÊ÷TFWfñ6Tg&ˆ‘'WGFˆ‚Ü'F‚ó∂˜VÂ&VÊ÷TFWfñ6RÑÁV÷&W"Ü'F‚ÊFF6WBÁ&VÊ÷TñBí∆'F‚ÊFF6WBÁ&VÊ÷TÊ÷W«¬rr∆'F‚ÊFF6WBÁ&VÊ÷TñFVÁFóGó«¬rró–¶gVÊ7Fñˆ‚6∆˜6U&VÊ÷TFWfñ6RÇó∂6ˆÁ7B”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&VÊ÷TFWfñ6T÷ˆF¬rì∂ñbÜ“ñ“Á7Gñ∆RÊFó7∆ì“vÊˆÊRw–¶7ñÊ2gVÊ7Fñˆ‚7V&÷óE&VÊ÷TFWfñ6RÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BñC‘ÁV÷&W"á&VÊ÷TFWfñ6TñBÁf«VRí∆Ê÷S◊&VÊ÷TFWfñ6TÊ÷RÁf«VRÁG&ñ“Çì∑&VÊ÷TFWfñ6TW'"ÁFWáD6ˆÁFVÁC“rs∂ñbÇñG«¬Ê÷Ró∑&VÊ÷TFWfñ6TW'"ÁFWáD6ˆÁFVÁC“tVÁFW"FWfñ6RÊ÷R‚s∑&WGW&‚f«6W◊G'ó∂vóBß6ˆ‚Çrˆí˜cˆFWfñ6W2Úr∂ñB«∂÷WFÜˆC¢uD4Çr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂Ê÷W“ó“ì∂6∆˜6U&VÊ÷TFWfñ6RÇì∂vóB&ˆ÷ó6RÊ∆≈6WGF∆VBÖ∂∆ˆDñÁfVÁF˜'íÇí∆∆ˆDFWfñ6W2Çí∆∆ˆDF6Ü&ˆ&BÇï“ó÷6F6ÇÜW'"ó∑&VÊ÷TFWfñ6TW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6fRFWfñ6RÊ÷S¢r∂W'"Ê÷W76vW◊&WGW&‚f«6W–¶gVÊ7Fñˆ‚˜V‰6∆76ñgîFWfñ6RÜñB«GóR∆6∆76ñfñ6Fñˆ‚∆ñFVÁFóGíó∂6∆76ñgîFWfñ6TñBÁf«VS÷ñC∂6∆76ñgîFWfñ6UGóRÁf«VS◊GóW«¬rs∂6∆76ñgîFWfñ6T6∆72Áf«VS÷6∆76ñfñ6FñˆÁ«¬vÊWrs∂6∆76ñgîFWfñ6TñFVÁFóGíÁFWáD6ˆÁFVÁC÷ñFVÁFóGó«¬rs∂6∆76ñgîFWfñ6TW'"ÁFWáD6ˆÁFVÁC“rs∂6∆76ñgîFWfñ6T÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∑6WEFñ÷V˜WBÇÇì”Ê6∆76ñgîFWfñ6UGóRÊfˆ7W2Çí√#ó–¶gVÊ7Fñˆ‚˜V‰6∆76ñgîFWfñ6Tg&ˆ‘'WGFˆ‚Ü'F‚ó∂˜V‰6∆76ñgîFWfñ6RÑÁV÷&W"Ü'F‚ÊFF6WBÊ6∆76ñgîñBí∆'F‚ÊFF6WBÊ6∆76ñgïGóW«¬rr∆'F‚ÊFF6WBÊ6∆76ñgî6∆77«¬vÊWrr∆'F‚ÊFF6WBÊ6∆76ñgîñFVÁFóGó«¬rró–¶gVÊ7Fñˆ‚6∆˜6T6∆76ñgîFWfñ6RÇó∂6∆76ñgîFWfñ6T÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRw–¶7ñÊ2gVÊ7Fñˆ‚7V&÷óD6∆76ñgîFWfñ6RÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BñC‘ÁV÷&W"Ü6∆76ñgîFWfñ6TñBÁf«VRí∆FWfñ6U˜GóS÷6∆76ñgîFWfñ6UGóRÁf«VRÁG&ñ“Çí∆6∆76ñfñ6Fñˆ„÷6∆76ñgîFWfñ6T6∆72Áf«VS∂6∆76ñgîFWfñ6TW'"ÁFWáD6ˆÁFVÁC“rs∂ñbÇñBó∂6∆76ñgîFWfñ6TW'"ÁFWáD6ˆÁFVÁC“tFWfñ6Ró2÷ó76ñÊr‚s∑&WGW&‚f«6W◊G'ó∂vóBß6ˆ‚Çrˆí˜cˆFWfñ6W2Úr∂ñB«∂÷WFÜˆC¢uD4Çr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂FWfñ6U˜GóR∆6∆76ñfñ6FñˆÁ“ó“ì∂6∆˜6T6∆76ñgîFWfñ6RÇì∂vóB&ˆ÷ó6RÊ∆≈6WGF∆VBÖ∂∆ˆDñÁfVÁF˜'íÇí∆∆ˆDFWfñ6W2Çí∆∆ˆDF6Ü&ˆ&BÇï“ó÷6F6ÇÜW'"ó∂6∆76ñgîFWfñ6TW'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6fR6∆76ñfñ6Fñˆ„¢r∂W'"Ê÷W76vW◊&WGW&‚f«6W–¶gVÊ7Fñˆ‚&VÊFW$FWfñ6Tñ6ˆÂñ6∂W"á6V∆V7FVBó∂6ˆÁ7B÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6Tñ6ˆÂñ6∂W"rì∂ñbÇó&WGW&„∂6ˆÁ7B∂Wó3‘DUdî4UÙî4ÙÂÙ¥Uï2Êfñ«FW"Ü≥”‰5DïdUÙDUdî4UÙî4ÙÂÙ4DTtı%ì””“v∆¬w«ƒDUdî4UÙî4ÙÂÙ4DTtı$îU5∂µ”””‘5DïdUÙDUdî4UÙî4ÙÂÙ4DTtı%íì∑ÊñÊÊW$ÖD‘√÷∂Wó2Ê÷Ü≥”Ê∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FWfñ6R÷ñ6ˆ‚÷6Üˆñ6RG∂≥””◊6V∆V7FVCÚw6V∆V7FVBs¢rw“"FF÷ñ6ˆ‚÷∂Wì“"G∂∑“"ˆÊ6∆ñ6≥“'6V∆V7DFWfñ6Tñ6ˆ‚ÇrG∂∑“rí#„∆ñ÷r7&3“"G∂FWfñ6Tñ6ˆ‰76WBÜ≥””“vWFÚsÚv˜FÜW"s¶≤ó“"«C“"G∂W62ÑDUdî4UÙî4ÙÂÙƒ$T≈5∂µ“ó“ñ6ˆ‚"ˆÊW'&˜#“'FÜó2Á7&3“rG∂FWfñ6Tñ6ˆ‰76WBÇv˜FÜW"ró“r#„«7„‚G∂W62ÑDUdî4UÙî4ÙÂÙƒ$T≈5∂µ“ó”¬˜7„„¬ˆ'WGFˆ„ÊíÊ¶ˆñ‚Çrró–¶gVÊ7Fñˆ‚6WDFWfñ6Tñ6ˆ‰6FVv˜'íÜ6FVv˜'íó¥5DïdUÙDUdî4UÙî4ÙÂÙ4DTtı%ì÷6FVv˜'ì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr6FWfñ6Tñ6ˆÂF'2ÊFWfñ6R÷ñ6ˆ‚◊F"ríÊf˜$V6ÇÜ#”Ê"Ê6∆74∆ó7BÁFˆvv∆RÇv7FófRr∆"ÊFF6WBÊñ6ˆ‰6FVv˜'ì””÷6FVv˜'ííì∑&VÊFW$FWfñ6Tñ6ˆÂñ6∂W"ÜFWfñ6Tñ6ˆ‰∂WíÁf«VRó–¶gVÊ7Fñˆ‚WFFTFWfñ6Tñ6ˆÂ7V÷÷'íÇó∂6ˆÁ7B∂Wì÷FWfñ6Tñ6ˆ‰∂WíÁf«VW«¬vWFÚs∂6ˆÁ7Bñ÷s÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6Tñ6ˆ‰7W'&VÁE&WfñWrrì∂ñbÇñ÷ró&WGW&„∂ñ÷rÁ7&3÷FWfñ6Tñ6ˆ‰FFÁf«VW«∆FWfñ6Tñ6ˆ‰76WBÜ∂Wì””“vWFÚsÚv˜FÜW"s¶∂Wíó–¶gVÊ7Fñˆ‚6V∆V7DFWfñ6Tñ6ˆ‚Ü∂Wíó∂FWfñ6Tñ6ˆ‰∂WíÁf«VS÷∂Wì∂FWfñ6Tñ6ˆ‰FFÁf«VS“rs∂FWfñ6Tñ6ˆÂ&WfñWrÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂FWfñ6Tñ6ˆ‰fñ∆RÁf«VS“rs∑&VÊFW$FWfñ6Tñ6ˆÂñ6∂W"Ü∂Wíì∑WFFTFWfñ6Tñ6ˆÂ7V÷÷'íÇó–¶gVÊ7Fñˆ‚˜V‰FWfñ6Tñ6ˆ‰g&ˆ‘'WGFˆ‚Ü'F‚ó∂FWfñ6Tñ6ˆ‰ñBÁf«VS÷'F‚ÊFF6WBÊñ6ˆ‰ñC∂FWfñ6Tñ6ˆ‰∂WíÁf«VS÷'F‚ÊFF6WBÊñ6ˆ‰∂Wó«¬vWFÚs∂FWfñ6Tñ6ˆ‰FFÁf«VS“rs∂FWfñ6Tñ6ˆ‰Ê÷RÁFWáD6ˆÁFVÁC÷'F‚ÊFF6WBÊñ6ˆ‰Ê÷W«¬tFWfñ6Rs∂FWfñ6Tñ6ˆ‰ñFVÁFóGíÁFWáD6ˆÁFVÁC’∂'F‚ÊFF6WBÊñ6ˆ‰ó∆'F‚ÊFF6WBÊñ6ˆÂGóU“Êfñ«FW"Ñ&ˆˆ∆V‚íÊ¶ˆñ‚Çr+rrì∂FWfñ6Tñ6ˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∂FWfñ6Tñ6ˆ‰fñ∆RÁf«VS“rs∂FWfñ6Tñ6ˆÂ&WfñWrÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂6ˆÁ7B6V∆V7FVC÷FWfñ6Tñ6ˆ‰∂WíÁf«VS¥5DïdUÙDUdî4UÙî4ÙÂÙ4DTtı%ì“v∆¬s∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr6FWfñ6Tñ6ˆÂF'2ÊFWfñ6R÷ñ6ˆ‚◊F"ríÊf˜$V6ÇÜ#”Ê"Ê6∆74∆ó7BÁFˆvv∆RÇv7FófRr∆"ÊFF6WBÊñ6ˆ‰6FVv˜'ì””‘5DïdUÙDUdî4UÙî4ÙÂÙ4DTtı%ííì∑&VÊFW$FWfñ6Tñ6ˆÂñ6∂W"á6V∆V7FVBì∑WFFTFWfñ6Tñ6ˆÂ7V÷÷'íÇì∂FWfñ6Tñ6ˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚w–¶gVÊ7Fñˆ‚6∆˜6TFWfñ6Tñ6ˆ‚Çó∂FWfñ6Tñ6ˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÜRÊ∂Wì””“tW66RrbfFWfñ6Tñ6ˆ‰÷ˆF¬bfFWfñ6Tñ6ˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆í”“vÊˆÊRrñ6∆˜6TFWfñ6Tñ6ˆ‚Çó“ê¶gVÊ7Fñˆ‚&WfñWt7W7Fˆ‘FWfñ6Tñ6ˆ‚ÜñÁWBó∂6ˆÁ7Bc÷ñÁWBÊfñ∆W2bfñÁWBÊfñ∆W5≥”∂FWfñ6Tñ6ˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∂ñbÇbó&WGW&„∂ñbÇ≤vñ÷vR˜Êrr¬vñ÷vRˆßVrr¬vñ÷vR˜vV'u“ÊñÊ6«VFW2ÜbÁGóRíó∂FWfñ6Tñ6ˆ‰W'"ÁFWáD6ˆÁFVÁC“t6Üˆ˜6R‰r¬•Tr¬˜"vV%ñ÷vR‚s∂ñÁWBÁf«VS“rs∑&WGW&Á÷ñbÜbÁ6ó¶S„#c#CBó∂FWfñ6Tñ6ˆ‰W'"ÁFWáD6ˆÁFVÁC“t7W7Fˆ“ñ6ˆ‚◊W7B&R#Sb¥"˜"6÷∆∆W"‚s∂ñÁWBÁf«VS“rs∑&WGW&Á÷6ˆÁ7B#÷ÊWrfñ∆U&VFW"Çì∑"ÊˆÊ∆ˆC“Çì”Á∂FWfñ6Tñ6ˆ‰FFÁf«VS’7G&ñÊrá"Á&W7V«G«¬rrì∂FWfñ6Tñ6ˆ‰∂WíÁf«VS“v˜FÜW"s∂FWfñ6Tñ6ˆÂ&WfñWrÁ7&3÷FWfñ6Tñ6ˆ‰FFÁf«VS∂FWfñ6Tñ6ˆÂ&WfñWrÁ7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∑WFFTFWfñ6Tñ6ˆÂ7V÷÷'íÇì∑&VÊFW$FWfñ6Tñ6ˆÂñ6∂W"Çuıˆ7W7Fˆ’ıÚró”∑"ÊˆÊW'&˜#“Çì”Á∂FWfñ6Tñ6ˆ‰W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B&VBFÜRñ÷vR‚w”∑"Á&VD4FFU$¬Übó–¶7ñÊ2gVÊ7Fñˆ‚7V&÷óDFWfñ6Tñ6ˆ‚ÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BñC‘ÁV÷&W"ÜFWfñ6Tñ6ˆ‰ñBÁf«VRí∆ñ6ˆÂˆ∂Wì÷FWfñ6Tñ6ˆ‰∂WíÁf«VW«¬vWFÚr∆ñ6ˆÂˆFF÷FWfñ6Tñ6ˆ‰FFÁf«VW«∆ÁV∆√∂FWfñ6Tñ6ˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∂ñbÇñBó∂FWfñ6Tñ6ˆ‰W'"ÁFWáD6ˆÁFVÁC“tFWfñ6Ró2÷ó76ñÊr‚s∑&WGW&‚f«6W◊G'ó∂vóBß6ˆ‚Çrˆí˜cˆFWfñ6W2Úr∂ñB«∂÷WFÜˆC¢uD4Çr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂ñ6ˆÂˆ∂Wí∆ñ6ˆÂˆFF“ó“ì∂6∆˜6TFWfñ6Tñ6ˆ‚Çì∂vóB&ˆ÷ó6RÊ∆≈6WGF∆VBÖ∂∆ˆDñÁfVÁF˜'íÇí∆∆ˆDFWfñ6W2Çí∆∆ˆDF6Ü&ˆ&BÇï“ó÷6F6ÇÜW'"ó∂FWfñ6Tñ6ˆ‰W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6fRFWfñ6Rñ6ˆ„¢r∂W'"Ê÷W76vW◊&WGW&‚f«6W–¶gVÊ7Fñˆ‚˜V‰FDFWfñ6RÇó∂6ˆÁ7B”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T÷ˆF¬rì∂“Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑6WEFñ÷V˜WBÇÇì”ÊFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TÊ÷RrìÚÊfˆ7W2Çí√ó–¶gVÊ7Fñˆ‚6∆˜6TFDFWfñ6RÇó∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T÷ˆF¬ríÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚7V&÷óDFDFWfñ6RÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BW'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFDW'"rì∂W'"ÁFWáD6ˆÁFVÁC“rs∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆFWfñ6W2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂Ê÷S¶FWfñ6TÊ÷RÁf«VRÁG&ñ“Çí∆ó¶FWfñ6TóÁf«VRÁG&ñ“Çó«∆ÁV∆¬∆÷3¶FWfñ6T÷2Áf«VRÁG&ñ“Çí«fVÊF˜#¶FWfñ6UfVÊF˜"Áf«VRÁG&ñ“Çó«∆ÁV∆¬∆FWfñ6U˜GóS¶FWfñ6UGóRÁf«VRÁG&ñ“Çó«¬wVÊ∂Ê˜v‚r∆6∆76ñfñ6Fñˆ„¶FWfñ6T6∆72Áf«VR∆Ê˜FW3¶FWfñ6TÊ˜FW2Áf«VRÁG&ñ“Çó“ó“ì∂6∆˜6TFDFWfñ6RÇì∂RÁF&vWBÁ&W6WBÇì∂FWfñ6T6∆72Áf«VS“v∂Ê˜v‚s∂vóB∆ˆBÇì∂ñbÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwfñWr÷FWfñ6W2ríÁ7Gñ∆RÊFó7∆í”“vÊˆÊRrñvóB∆ˆDñÁfVÁF˜'íÇó÷6F6ÇÜRó∂W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜BFBFWfñ6S¢r∂RÊ÷W76vW◊&WGW&‚f«6W–†¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÜRÊ∂Wí”“tW66Rró&WGW&„∂ñbÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW÷ˆF¬rìÚÁ7Gñ∆RÊFó7∆ì””“vw&ñBrñ6∆˜6TFWfñ6T6∆VÁWÇì∂ñbÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFT÷ˆF¬rìÚÁ7Gñ∆RÊFó7∆ì””“vw&ñBrñ6∆˜6TFV∆WFTFWfñ6RÇó“ì∞¶gVÊ7Fñˆ‚˜V‰FWfñ6T6∆VÁWÇó∂6ˆÁ7B”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW÷ˆF¬rì∂ñbÇ“ó&WGW&„∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW&V6ˆ‚ríÁf«VS“rs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁWW'"ríÁFWáD6ˆÁFVÁC“rs∂“Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑WFFTFWfñ6T6∆VÁWfñV∆G2Çì∑6WEFñ÷V˜WBÇÇì”ÊFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW÷ˆFRrìÚÊfˆ7W2Çí√ó–¶gVÊ7Fñˆ‚6∆˜6TFWfñ6T6∆VÁWÇó∂6ˆÁ7B”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW÷ˆF¬rì∂ñbÜ“ñ“Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶gVÊ7Fñˆ‚WFFTFWfñ6T6∆VÁWfñV∆G2Çó∂6ˆÁ7Bˆ∆C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW÷ˆFRrìÚÁf«VS””“vˆ∆Bs∂6ˆÁ7B&˜s÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁWFó4∆&V¬rì∂ñbá&˜ró&˜rÁ7Gñ∆RÊFó7∆ì÷ˆ∆CÚvw&ñBs¢vÊˆÊRw–¶7ñÊ2gVÊ7Fñˆ‚7V&÷óDFWfñ6T6∆VÁWÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7B÷ˆFS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW÷ˆFRríÁf«VR∆ˆ∆FW%˜FÜÂˆFó3“∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁWFó2ríÁf«VR«&V6ˆ„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW&V6ˆ‚ríÁf«VRÁG&ñ“Çí∆W'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁWW'"rì∂ñbÜW'"ñW'"ÁFWáD6ˆÁFVÁC“rs∂ñbá&V6ˆ‚Ê∆VÊwFÉ√2ó∂W'"ÁFWáD6ˆÁFVÁC“tVÁFW"&V6ˆ‚f˜"FÜó26∆VÁW‚s∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T6∆VÁW&V6ˆ‚ríÊfˆ7W2Çì∑&WGW&‚f«6W◊G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆFWfñ6W2ˆ6∆VÁWr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂÷ˆFR∆ˆ∆FW%˜FÜÂˆFó2«&V6ˆÁ“ó“ì∂6∆˜6TFWfñ6T6∆VÁWÇì∂vóB&ˆ÷ó6RÊ∆≈6WGF∆VBÖ∂∆ˆDñÁfVÁF˜'íÇí∆∆ˆDF6Ü&ˆ&BÇí∆∆ˆDÊWGv˜&≤Çí∆∆ˆDVFóBÇï“ì∂∆W'BÜFV∆WFVBG∑"ÊFV∆WFVG«√“FWfñ6Rá2í‚FÜR7Fñˆ‚v2&V6˜&FVBñ‚FÜRVFóB∆ˆrÊó÷6F6ÇÜWÇó∂ñbÜW'"ñW'"ÁFWáD6ˆÁFVÁC“t6∆VÁWfñ∆VC¢r∂WÇÊ÷W76vW◊&WGW&‚f«6W–¶gVÊ7Fñˆ‚FV∆WFTñÁfVÁF˜'îFWfñ6RÜñB∆Ê÷R«7FGW2ó∂6ˆÁ7B”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFT÷ˆF¬rì∂ñbÇ“ó&WGW&„∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFTñBríÁf«VS’7G&ñÊrÜñBì∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFTñFVÁFóGíríÁFWáD6ˆÁFVÁC÷G∂Ê÷W«¬tFWfñ6Rw“+rG∑7FGW7«¬wVÊ∂Ê˜v‚w“7FGW6∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFU&V6ˆ‚ríÁf«VS“rs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFTW'"ríÁFWáD6ˆÁFVÁC“rs∂“Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑6WEFñ÷V˜WBÇÇì”ÊFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFU&V6ˆ‚rìÚÊfˆ7W2Çí√ó–¶gVÊ7Fñˆ‚˜V‰FV∆WFTFWfñ6Tg&ˆ‘'WGFˆ‚Ü'F‚ó∂ñbÇ'F‚ó&WGW&„∂FV∆WFTñÁfVÁF˜'îFWfñ6RÑÁV÷&W"Ü'F‚ÊFF6WBÊFV∆WFTñBí∆'F‚ÊFF6WBÊFV∆WFTÊ÷W«¬tFWfñ6Rr∆'F‚ÊFF6WBÊFV∆WFU7FGW7«¬wVÊ∂Ê˜v‚ró–¶gVÊ7Fñˆ‚6∆˜6TFV∆WFTFWfñ6RÇó∂6ˆÁ7B”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFT÷ˆF¬rì∂ñbÜ“ñ“Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚7V&÷óDFV∆WFTFWfñ6RÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BñC‘ÁV÷&W"ÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFTñBríÁf«VRí«&V6ˆ„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFU&V6ˆ‚ríÁf«VRÁG&ñ“Çí∆W'#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFTW'"rì∂W'"ÁFWáD6ˆÁFVÁC“rs∂ñbÇñBó∂W'"ÁFWáD6ˆÁFVÁC“tFWfñ6Ró2÷ó76ñÊr‚s∑&WGW&‚f«6W÷ñbá&V6ˆ‚Ê∆VÊwFÉ√2ó∂W'"ÁFWáD6ˆÁFVÁC“tVÁFW"&V6ˆ‚f˜"FV∆WFñÊrFÜó2FWfñ6R‚s∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6TFV∆WFU&V6ˆ‚ríÊfˆ7W2Çì∑&WGW&‚f«6W◊G'ó∂vóBß6ˆ‚Çrˆí˜cˆFWfñ6W2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑&V6ˆÁ“ó“ì∂6∆˜6TFV∆WFTFWfñ6RÇì∂vóB&ˆ÷ó6RÊ∆≈6WGF∆VBÖ∂∆ˆDñÁfVÁF˜'íÇí∆∆ˆDF6Ü&ˆ&BÇí∆∆ˆDÊWGv˜&≤Çí∆∆ˆDVFóBÇï“ì∂∆W'BÇtFWfñ6RFV∆WFVB‚FÜR&V6ˆ‚ÊBF÷ñÊó7G&F˜"vW&R&V6˜&FVBñ‚FÜRVFóB∆ˆr‚ró÷6F6ÇÜWÇó∂W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜BFV∆WFRFWfñ6S¢r∂WÇÊ÷W76vW◊&WGW&‚f«6W–†¶∆WB4TƒT5DTEÙîÂdTÂDı%ïÙîC÷ÁV∆¬¬îÂdTÂDı%ïÙDUdî4UÙƒï5C’µ“¬îÂdTÂDı%ïıtS”∞¶gVÊ7Fñˆ‚ñÁfVÁF˜'ï∆Ff˜&‘Ê÷RáÇó∑&WGW&‚7G&ñÊráÇÊ˜5˜∆Ff˜&◊««ÇÊ˜7««ÇÁ∆Ff˜&◊««ÇÊ˜W&FñÊu˜7ó7FV◊««ÇÊFWfñ6U˜GóW«¬uVÊ∂Ê˜v‚ró–¶gVÊ7Fñˆ‚ñÁfVÁF˜'ï6óFTÊ÷RáÇó∑&WGW&‚7G&ñÊráÇÁ6óFW««ÇÊ∆ˆ6FñˆÁ«¬tFVfV«Bró–¶gVÊ7Fñˆ‚6WDñÁfVÁF˜'ïvRávRó¥îÂdTÂDı%ïıtS‘÷FÇÊ÷ÇÉƒÁV÷&W"ávRó«√ì∂∆ˆDñÁfVÁF˜'íÇó–¶gVÊ7Fñˆ‚6V∆V7DñÁfVÁF˜'îFWfñ6RÜñBó∞¢4TƒT5DTEÙîÂdTÂDı%ïÙîC÷ñC∂6ˆÁ7BÉ‘îÂdTÂDı%ïÙDUdî4UÙƒï5BÊfñÊBÜC”ÊBÊñC””÷ñBí∆&ˆGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï6V∆V7FVD&ˆGírí∆˜V„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï6V∆V7FVD˜V‚rì∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr6ñÁfVÁF˜'ï&˜w2G%∂FF÷ñÁfVÁF˜'í÷ñE“ríÊf˜$V6Çá&˜s”Á&˜rÊ6∆74∆ó7BÁFˆvv∆RÇw6V∆V7FVBrƒÁV÷&W"á&˜rÊFF6WBÊñÁfVÁF˜'îñBì””÷ñBíì∞¢ñbÇ&ˆGó«¬˜V‚ó&WGW&„∞¢6ˆÁ7B7FófóGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï6V∆V7FVD7FófóGírì∞¢ñbÇÇó∂&ˆGíÁFWáD6ˆÁFVÁC“u6V∆V7BFWfñ6RFÚ6VRóG2FWFñ«2‚s∂˜V‚ÊÜñFFV„◊G'VS∂ñbÜ7FófóGíñ7FófóGíÁFWáD6ˆÁFVÁC“u6V∆V7BFWfñ6RFÚfñWróG27FófóGí‚s∑&WGW&Á–¢6ˆÁ7BfñV∆C“Ü∆&V¬«f«VRì”Ê∆Fóc„«7„‚G∂∆&V«”¬˜7„„∆#‚G∂W62áf«VW«¬~(	Bró”¬ˆ#„¬ˆFócÊ∞¢&ˆGíÊñÊÊW$ÖD‘√÷∆Fób6∆73“'cC3◊6V∆V7FVB÷ÜVFñÊr#‚G∂FWfñ6Tñ6ˆ‰áF÷¬áÇó”∆Fóc„«7G&ˆÊs‚G∂W62áÇÊÊ÷W««ÇÊÜ˜7FÊ÷W«¬uVÊ∂Ê˜v‚FWfñ6Rró”¬˜7G&ˆÊs„«7„‚G∂W62áÇÊFWfñ6U˜GóW«¬uVÊ6∆76ñfñVBró“+rG∂W62áÇÁfVÊF˜'«¬uVÊ∂Ê˜v‚fVÊF˜"ró”¬˜7„„¬ˆFóc„«7‚6∆73“'cC3÷FWfñ6R◊7FFRGµ7G&ñÊráÇÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇì””“vˆÊ∆ñÊRsÚvˆÊ∆ñÊRs¢vˆff∆ñÊRw“#‚G∂W62áÇÁ7FGW7«¬wVÊ∂Ê˜v‚ró”¬˜7„„¬ˆFóc„∆Fób6∆73“'cC3◊6V∆V7FVB÷fñV∆G2#‚G∂fñV∆BÇtïFG&W72r«ÇÊóó“G∂fñV∆BÇt‘2FG&W72r«ÇÊ÷2ó“G∂fñV∆BÇt6∆76ñfñ6Fñˆ‚rƒ4ƒ55Ùƒ$T≈∑ÇÊ6∆76ñfñ6FñˆÂ◊««ÇÊ6∆76ñfñ6Fñˆ‚ó“G∂fñV∆BÇtÜ˜7FÊ÷Rr«ÇÊÜ˜7FÊ÷Ró“G∂fñV∆BÇtfó'7B6VV‚r«ÇÊfó'7E˜6VV„ˆÊWrFFRáÇÊfó'7E˜6VV‚íÁFÙ∆ˆ6∆U7G&ñÊrÇì¢rró“G∂fñV∆BÇt∆7B6VV‚r«ÇÊ∆7E˜6VV„ˆÊWrFFRáÇÊ∆7E˜6VV‚íÁFÙ∆ˆ6∆U7G&ñÊrÇì¢rró”¬ˆFócÊ∞¢˜V‚ÊÜñFFV„÷f«6S∂˜V‚ÊˆÊ6∆ñ6≥“Çì”ÊvÙFWfñ6RÜñBì∞¢ñbÜ7FófóGíó∂7FófóGíÁFWáD6ˆÁFVÁC“t∆ˆFñÊr7FófóGû(
bs∂ß6ˆ‚Çrˆí˜cˆFWfñ6W2Úr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBÜñBí≤rˆWfVÁG3ˆ∆ñ÷óC”RríÁFÜV‚á&˜w3”Á∂ñbÖ4TƒT5DTEÙîÂdTÂDı%ïÙîB”÷ñBó&WGW&„∂7FófóGíÊñÊÊW$ÖD‘√‘'&íÊó4'&íá&˜w2íbg&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷ÜS”Ê∆Fóc„«7‚6∆73“'cC3÷∆ófR÷F˜B#„¬˜7„„«Fñ÷S‚G∂W62ÜRÊ7&VFVEˆCˆÊWrFFRÜRÊ7&VFVEˆBíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“¬∂Ü˜W#¢vÁV÷W&ñ2r∆÷ñÁWFS¢s"÷FñvóBw“ì¢~(	Bró”¬˜Fñ÷S„«7„‚G∂W62Ö7G&ñÊrÜRÊWfVÁE˜GóW«¬tWfVÁBríÁ&W∆6T∆¬ÇuÚr¬rríó“G∂RÊFWFñ«3Úr+rr∂W62ÜRÊFWFñ«2ì¢rw”¬˜7„„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fóc‰ÊÚ&V6VÁB7FófóGíf˜"FÜó2FWfñ6R„¬ˆFóc‚w“íÊ6F6ÇÇÇì”Á∂ñbÖ4TƒT5DTEÙîÂdTÂDı%ïÙîC””÷ñBñ7FófóGíÁFWáD6ˆÁFVÁC“tFWfñ6R7FófóGíó2VÊfñ∆&∆R‚w“ó–ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDñÁfVÁF˜'íÇó∞¢6ˆÁ7B6S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï6V&6Çrí«7C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï7FGW2rí∆6S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'î6˜VÁBrí«F&ˆGì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï&˜w2rì∂ñbÇF&ˆGíó&WGW&„∞¢G'ó∂6ˆÁ7B÷ÊWrU$≈6V&6Ö&◊2Çì∂ñbá6SÚÁf«VRóÁ6WBÇw6V&6Çr«6RÁf«VRì∂ñbá7CÚÁf«VRóÁ6WBÇw7FGW2r«7BÁf«VRì∂6ˆÁ7B∑&W7ˆÁ6R∆∆≈&W7ˆÁ6U”÷vóB&ˆ÷ó6RÊ∆¬Ö∂ß6ˆ‚Çrˆí˜cˆFWfñ6W3Úr∑ÁFı7G&ñÊrÇíí∆ß6ˆ‚Çrˆí˜cˆFWfñ6W2rï“ì∂6ˆÁ7B∆√‘'&íÊó4'&íÜ∆≈&W7ˆÁ6Rìˆ∆≈&W7ˆÁ6S•µ“«GóW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ïGóRrí∆6∆76W3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'î6∆72rí«∆Ff˜&◊3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï∆Ff˜&“rí«6óFW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ï6óFRrì∞¢ñbáGóW2ó∂6ˆÁ7B&Wfñ˜W3◊GóW2Áf«VR«f«VW3’≤‚‚ÊÊWr6WBÜ∆¬Ê÷áÉ”Â7G&ñÊráÇÊFWfñ6U˜GóW«¬rríÁG&ñ“ÇííÊfñ«FW"Ñ&ˆˆ∆V‚íï“Á6˜'BÇÜ∆"ì”ÊÊ∆ˆ6∆T6ˆ◊&RÜ"íì∑GóW2Á&W∆6T6Üñ∆G&V‚ÜÊWr˜Fñˆ‚Çt∆¬GóW2r¬rrí¬‚‚Áf«VW2Ê÷ác”ÊÊWr˜Fñˆ‚áb«bííì∑GóW2Áf«VS◊f«VW2ÊñÊ6«VFW2á&Wfñ˜W2ì˜&Wfñ˜W3¢rw–¢ñbá∆Ff˜&◊2ó∂6ˆÁ7B&Wfñ˜W3◊∆Ff˜&◊2Áf«VR«f«VW3’≤‚‚ÊÊWr6WBÜ∆¬Ê÷ÜñÁfVÁF˜'ï∆Ff˜&‘Ê÷RíÊfñ«FW"Ñ&ˆˆ∆V‚íï“Á6˜'BÇÜ∆"ì”ÊÊ∆ˆ6∆T6ˆ◊&RÜ"íì∑∆Ff˜&◊2Á&W∆6T6Üñ∆G&V‚ÜÊWr˜Fñˆ‚Çt∆¬ı2ı∆Ff˜&“r¬rrí¬‚‚Áf«VW2Ê÷ác”ÊÊWr˜Fñˆ‚áb«bííì∑∆Ff˜&◊2Áf«VS◊f«VW2ÊñÊ6«VFW2á&Wfñ˜W2ì˜&Wfñ˜W3¢rw–¢ñbá6óFW2ó∂6ˆÁ7B&Wfñ˜W3◊6óFW2Áf«VR«f«VW3’≤‚‚ÊÊWr6WBÜ∆¬Ê÷ÜñÁfVÁF˜'ï6óFTÊ÷RíÊfñ«FW"Ñ&ˆˆ∆V‚íï“Á6˜'BÇÜ∆"ì”ÊÊ∆ˆ6∆T6ˆ◊&RÜ"íì∑6óFW2Á&W∆6T6Üñ∆G&V‚ÜÊWr˜Fñˆ‚Çt∆¬6óFW2r¬rrí¬‚‚Áf«VW2Ê÷ác”ÊÊWr˜Fñˆ‚áb«bííì∑6óFW2Áf«VS◊f«VW2ÊñÊ6«VFW2á&Wfñ˜W2ì˜&Wfñ˜W3¢rw–¢6ˆÁ7BC“Ñ'&íÊó4'&íá&W7ˆÁ6Rì˜&W7ˆÁ6S•µ“íÊfñ«FW"áÉ”‚ÇGóW3ÚÁf«VW««ÇÊFWfñ6U˜GóS””◊GóW2Áf«VRíbbÇ6∆76W3ÚÁf«VW«≈7G&ñÊráÇÊ6∆76ñfñ6FñˆÁ«¬vÊWrríÁFÙ∆˜vW$66RÇì””÷6∆76W2Áf«VRíbbÇ∆Ff˜&◊3ÚÁf«VW«∆ñÁfVÁF˜'ï∆Ff˜&‘Ê÷RáÇì””◊∆Ff˜&◊2Áf«VRíbbÇ6óFW3ÚÁf«VW«∆ñÁfVÁF˜'ï6óFTÊ÷RáÇì””◊6óFW2Áf«VRíì¥îÂdTÂDı%ïÙƒ≈Ùƒï5C÷∆√¥îÂdTÂDı%ïÙDUdî4UÙƒï5C÷C∞¢6ˆÁ7BF˜F√÷∆¬Ê∆VÊwFÇ∆ˆÊ∆ñÊS÷∆¬Êfñ«FW"áÉ”Â7G&ñÊráÇÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇì””“vˆÊ∆ñÊRríÊ∆VÊwFÇ∆ˆff∆ñÊS÷∆¬Êfñ«FW"áÉ”Â7G&ñÊráÇÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇíÊñÊ6«VFW2Çvˆff∆ñÊRrííÊ∆VÊwFÇ∆ÊWt6˜VÁC÷∆¬Êfñ«FW"áÉ”Â7G&ñÊráÇÊ6∆76ñfñ6FñˆÁ«¬vÊWrríÁFÙ∆˜vW$66RÇì””“vÊWrríÊ∆VÊwFÉ∞¢6ˆÁ7B6WC“ÜñB«f«VRì”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬ÁFWáD6ˆÁFVÁC◊f«VW”∑6WBÇvñÁfVÁF˜'ïF˜F≈7V÷÷'ír«F˜F¬ì∑6WBÇvñÁfVÁF˜'îˆÊ∆ñÊU7V÷÷'ír∆ˆÊ∆ñÊRì∑6WBÇvñÁfVÁF˜'îˆff∆ñÊU7V÷÷'ír∆ˆff∆ñÊRì∑6WBÇvñÁfVÁF˜'îÊWu7V÷÷'ír∆ÊWt6˜VÁBì∑6WBÇvñÁfVÁF˜'îˆÊ∆ñÊUW&6VÁBr«F˜F√Ù÷FÇÁ&˜VÊBÜˆÊ∆ñÊR£˜F˜F¬í≤rRˆbF˜F¬s¢sRrì∑6WBÇvñÁfVÁF˜'îˆff∆ñÊUW&6VÁBr«F˜F√Ù÷FÇÁ&˜VÊBÜˆff∆ñÊR£˜F˜F¬í≤rRˆbF˜F¬s¢sRrì∞¢6ˆÁ7BvU6ó¶S”«vT6˜VÁC‘÷FÇÊ÷ÇÉƒ÷FÇÊ6Vñ¬ÜBÊ∆VÊwFÇ˜vU6ó¶Ríì¥îÂdTÂDı%ïıtS‘÷FÇÊ÷ñ‚ÑîÂdTÂDı%ïıtR«vT6˜VÁBì∂6ˆÁ7B7F'C“ÑîÂdTÂDı%ïıtR”íßvU6ó¶R«fó6ñ&∆S÷BÁ6∆ñ6Rá7F'B«7F'B∑vU6ó¶Rí«vW#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁfVÁF˜'ïvW"rì∂ñbÜ6Rñ6RÁFWáD6ˆÁFVÁC÷BÊ∆VÊwFÉˆ6Ü˜vñÊrG∑7F'B≥ﬁ(	2G∑7F'B∑fó6ñ&∆RÊ∆VÊwFá“ˆbG∂BÊ∆VÊwFá“FWfñ6W6¢u6Ü˜vñÊrFWfñ6W2s∞¢ñbávW"ó∂6ˆÁ7BvT'WGFˆÁ3‘'&íÊg&ˆ“á∂∆VÊwFÉ§÷FÇÊ÷ñ‚ávT6˜VÁB√Ró“¬ÖÚ∆íì”Êí≥íÊ÷á”Ê∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“"G∑””‘îÂdTÂDı%ïıtSÚv7FófRs¢rw“"ˆÊ6∆ñ6≥“'6WDñÁfVÁF˜'ïvRÇG∑“í#‚G∑”¬ˆ'WGFˆ„ÊíÊ¶ˆñ‚Çrrì∑vW"ÊñÊÊW$ÖD‘√÷∆'WGFˆ‚GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'6WDñÁfVÁF˜'ïvRÇG¥îÂdTÂDı%ïıtR”“í"G¥îÂdTÂDı%ïıtS√”ÚvFó6&∆VBs¢rw”Ó(ì¬ˆ'WGFˆ„‚G∑vT'WGFˆÁ7“G∑vT6˜VÁC„Sˆ«7„Ó(
c¬˜7„„∆'WGFˆ‚GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'6WDñÁfVÁF˜'ïvRÇG∑vT6˜VÁG“í#‚G∑vT6˜VÁG”¬ˆ'WGFˆ„Ê¢rw”∆'WGFˆ‚GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'6WDñÁfVÁF˜'ïvRÇG¥îÂdTÂDı%ïıtR≥“í"G¥îÂdTÂDı%ïıtS„◊vT6˜VÁCÚvFó6&∆VBs¢rw”Ó(£¬ˆ'WGFˆ„„«7‚6∆73“'cC3◊vR◊6ó¶R#„Úv^(»C¬˜7„Ê–¢F&ˆGíÊñÊÊW$ÖD‘√◊fó6ñ&∆RÊ∆VÊwFÉ˜fó6ñ&∆RÊ÷áÉ”Á∂6ˆÁ7B7FGW3’7G&ñÊráÇÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇí∆ÊVVG5&WfñWs’≤vÊWrr¬vñÁfW7FñvFRu“ÊñÊ6«VFW2Ö7G&ñÊráÇÊ6∆76ñfñ6FñˆÁ«¬vÊWrríÁFÙ∆˜vW$66RÇíì∑&WGW&‚«G"FF÷ñÁfVÁF˜'í÷ñC“"G∑ÇÊñG“"F&ñÊFWÉ“#"ˆÊ6∆ñ6≥“'6V∆V7DñÁfVÁF˜'îFWfñ6RÇG∑ÇÊñG“í"ˆÊ∂WñF˜v„“&ñbÜWfVÁBÊ∂Wì””“tVÁFW"w«∆WfVÁBÊ∂Wì””“rró∂WfVÁBÁ&WfVÁDFVfV«BÇì∑6V∆V7DñÁfVÁF˜'îFWfñ6RÇG∑ÇÊñG“ó“#„«FC„∆ñÁWBGóS“&6ÜV6∂&˜Ç"&ñ÷∆&V√“%6V∆V7BG∂W62áÇÊÊ÷W««ÇÊÜ˜7FÊ÷W«¬vFWfñ6Rró“"ˆÊ6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çí#„¬˜FC„«FC„∆Fób6∆73“&FWfñ6R÷Ê÷R#‚G∂FWfñ6Tñ6ˆ‰áF÷¬áÇó”∆'WGFˆ‚6∆73“&∆ñÊ≤Ê÷R"ˆÊ6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∂vÙFWfñ6RÇG∑ÇÊñG“í#‚G∂W62áÇÊÊ÷W««ÇÊÜ˜7FÊ÷W«¬uVÊ∂Ê˜v‚FWfñ6Rró”¬ˆ'WGFˆ„„¬ˆFóc„¬˜FC„«FB6∆73“'cC3÷ó#‚G∂W62áÇÊó«¬~(	Bró”¬˜FC„«FC„«7‚6∆73“'cC3◊GóR÷6V∆¬#‚G∂FWfñ6Tñ6ˆ‰áF÷¬áÇó“G∂W62áÇÊFWfñ6U˜GóW«¬uVÊ6∆76ñfñVBró”¬˜7„„¬˜FC„«FC„«7‚6∆73“'cC3÷6V∆¬◊&ñ÷'í#‚G∂W62áÇÊ÷7«¬~(	Bró”¬˜7„„«6÷∆√‚G∂W62áÇÁfVÊF˜'«¬uVÊ∂Ê˜v‚fVÊF˜"ró”¬˜6÷∆√„¬˜FC„«FC„«7‚6∆73“'cC3÷FWfñ6R◊7FFRG∑7FGW3””“vˆÊ∆ñÊRsÚvˆÊ∆ñÊRs¢vˆff∆ñÊRw“#‚G∂W62áÇÁ7FGW7«¬wVÊ∂Ê˜v‚ró”¬˜7„„¬˜FC„«FC‚G∂W62ÜñÁfVÁF˜'ï∆Ff˜&‘Ê÷RáÇíó”¬˜FC„«FC‚G∑ÇÊ∆7E˜6VV„ˆW62ÜÊWrFFRáÇÊ∆7E˜6VV‚íÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC„«7‚6∆73“'cC3÷fñÊFñÊr÷6˜VÁBG∂ÊVVG5&WfñWsÚv&Bs¢vvˆˆBw“#‚G∂ÊVVG5&WfñWsÚrs¢~)…2w“fÊ'7≤G∂ÊVVG5&WfñWsÚss¢sw”¬˜7„„¬˜FC„«FB6∆73“'cC3◊&˜r÷7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'ícC3÷ñ6ˆ‚÷7Fñˆ‚"FóF∆S“%fñWrFWfñ6R"&ñ÷∆&V√“%fñWrFWfñ6R"ˆÊ6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∂vÙFWfñ6RÇG∑ÇÊñG“í#Ó)xì¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'ícC3÷ñ6ˆ‚÷7Fñˆ‚"FóF∆S“%&VÊ÷RFWfñ6R"&ñ÷∆&V√“%&VÊ÷RFWfñ6R"FF◊&VÊ÷R÷ñC“"G∑ÇÊñG“"FF◊&VÊ÷R÷Ê÷S“"G∂W62áÇÊÊ÷W«¬rró“"FF◊&VÊ÷R÷ñFVÁFóGì“"G∂W62Ö∑ÇÊÜ˜7FÊ÷R«ÇÊó«ÇÊ÷5“Êfñ«FW"Ñ&ˆˆ∆V‚íÊ¶ˆñ‚Çr+rríó“"ˆÊ6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çì∂˜VÂ&VÊ÷TFWfñ6Tg&ˆ‘'WGFˆ‚áFÜó2í#Ó)»„¬ˆ'WGFˆ„„∆FWFñ«26∆73“'cC3◊&˜r÷÷VÁR"ˆÊ6∆ñ6≥“&WfVÁBÁ7F˜&˜vFñˆ‚Çí#„«7V÷÷'íFóF∆S“$÷˜&R7FñˆÁ2#Ó(
.(
.(
#¬˜7V÷÷'ì„∆Fóc„∆'WGFˆ‚GóS“&'WGFˆ‚"FF÷6∆76ñgí÷ñC“"G∑ÇÊñG“"FF÷6∆76ñgí◊GóS“"G∂W62áÇÊFWfñ6U˜GóW«¬rró“"FF÷6∆76ñgí÷6∆73“"G∂W62áÇÊ6∆76ñfñ6FñˆÁ«¬vÊWrró“"FF÷6∆76ñgí÷ñFVÁFóGì“"G∂W62Ö∑ÇÊÊ÷W««ÇÊÜ˜7FÊ÷R«ÇÊó«ÇÊ÷5“Êfñ«FW"Ñ&ˆˆ∆V‚íÊ¶ˆñ‚Çr+rríó“"ˆÊ6∆ñ6≥“&˜V‰6∆76ñgîFWfñ6Tg&ˆ‘'WGFˆ‚áFÜó2í#‰6∆76ñgì¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"FF÷ñ6ˆ‚÷ñC“"G∑ÇÊñG“"FF÷ñ6ˆ‚÷∂Wì“"G∂W62áÇÊñ6ˆÂˆ∂Wó«¬vWFÚró“"FF÷ñ6ˆ‚÷Ê÷S“"G∂W62áÇÊÊ÷W««ÇÊÜ˜7FÊ÷W«¬uVÊ∂Ê˜v‚FWfñ6Rró“"FF÷ñ6ˆ‚÷ó“"G∂W62áÇÊó««ÇÊ÷7«¬rró“"FF÷ñ6ˆ‚◊GóS“"G∂W62áÇÊFWfñ6U˜GóW«¬uVÊ6∆76ñfñVBró“"ˆÊ6∆ñ6≥“&˜V‰FWfñ6Tñ6ˆ‰g&ˆ‘'WGFˆ‚áFÜó2í#‰6ÜÊvRñ6ˆ„¬ˆ'WGFˆ„„∆'WGFˆ‚GóS“&'WGFˆ‚"6∆73“&FÊvW"F÷ñ‚÷ˆÊ«í"FF÷FV∆WFR÷ñC“"G∑ÇÊñG“"FF÷FV∆WFR÷Ê÷S“"G∂W62áÇÊÊ÷W««ÇÊÜ˜7FÊ÷W««ÇÊ÷7«¬tFWfñ6Rró“"FF÷FV∆WFR◊7FGW3“"G∂W62áÇÁ7FGW7«¬wVÊ∂Ê˜v‚ró“"ˆÊ6∆ñ6≥“&˜V‰FV∆WFTFWfñ6Tg&ˆ‘'WGFˆ‚áFÜó2í#‰FV∆WFS¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFWFñ«3„¬˜FC„¬˜G#Ê“íÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#"6∆73“&V◊Gí#‰ÊÚ÷F6ÜñÊrFWfñ6W2‚FßW7BFÜRfñ«FW'2˜"Fó66˜fW"FÜRÊWGv˜&≤„¬˜FC„¬˜G#‚s∂«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∑6V∆V7DñÁfVÁF˜'îFWfñ6RÜBÁ6ˆ÷RáÉ”ÁÇÊñC””’4TƒT5DTEÙîÂdTÂDı%ïÙîBìı4TƒT5DTEÙîÂdTÂDı%ïÙîC¶E≥”ÚÊñCÛˆÁV∆¬ó÷6F6ÇÜRó∑F&ˆGíÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#"6∆73“&V◊Gí#ÂVÊ&∆RFÚ∆ˆBFWfñ6W3¢r∂W62ÜRÊ÷W76vRí≤s¬˜FC„¬˜G#‚s¥îÂdTÂDı%ïÙDUdî4UÙƒï5C’µ”∑6V∆V7DñÁfVÁF˜'îFWfñ6RÜÁV∆¬ó–ß–††¶∆WB‰UEtı$µÙDD◊∂ÊˆFW3•µ“∆∆ñÊ∑3•µ“∆'îñCß∑◊”∂∆WB‰UEtı$µÙƒîıUC“vWFÚs∂∆WB‰UEtı$µÙdî≈DU#“v∆¬s∂∆WB4TƒT5DTEÙ‘Ùî‰DUÉ“”∞¶gVÊ7Fñˆ‚÷ÊˆFT6∆72Ü‚ó∂6ˆÁ7B7FGW3’7G&ñÊrÜ‚Á7FGW7«¬rríÁFÙ∆˜vW$66RÇì∂ñbá7FGW2ÊñÊ6«VFW2Çvˆff∆ñÊRríó&WGW&‚vˆff∆ñÊRs∂ñbá7FGW2ÊñÊ6«VFW2ÇvˆÊ∆ñÊRríó&WGW&‚vˆÊ∆ñÊRs∑&WGW&‚wVÊ∂Ê˜v‚w–¶gVÊ7Fñˆ‚÷FWfñ6Tñ6ˆ‰∂WíÜ‚ó∂ñbÜ‚bf‚Êñ6ˆÂˆ∂Wíbf‚Êñ6ˆÂˆ∂Wí”“vWFÚró&WGW&‚‚Êñ6ˆÂˆ∂Wì∂6ˆÁ7BC’7G&ñÊrÜ‚bf‚ÁGóW«¬rríÁFÙ∆˜vW$66RÇì∂ñbáC””“vñÁFW&ÊWBró&WGW&‚vñÁFW&ÊWBs∑&WGW&‚ñÊfW'&VDFWfñ6Tñ6ˆ‚áBó–¶gVÊ7Fñˆ‚÷FWfñ6Tñ6ˆÂ7&2Ü‚ó∂ñbÜ‚bf‚Êñ6ˆÂˆFFó&WGW&‚‚Êñ6ˆÂˆFF∂6ˆÁ7B∂Wì÷÷FWfñ6Tñ6ˆ‰∂WíÜ‚ì∑&WGW&‚∂Wì””“vñÁFW&ÊWBsÚrs¶FWfñ6Tñ6ˆ‰76WBÜ∂Wíó–¶gVÊ7Fñˆ‚ó4ñÊg&7G'V7GW&TÊˆFRÜ‚ó∂6ˆÁ7BC’7G&ñÊrÜ„ÚÁGóW«¬rríÁFÙ∆˜vW$66RÇì∑&WGW&‚ˆvFWvó«&˜WFW'«7vóF6á∆66W77«vñfó∆fó&Wv∆«∆÷ˆFV◊∆Ê7«7F˜&vW«6W'fW'«F6ÇÚÁFW7BáBó–¶gVÊ7Fñˆ‚ó5vó&V∆W74∆ñÊ≤Ü¬ó∂6ˆÁ7BÉ“Ö7G&ñÊrÜ√ÚÊ∆ñÊµ˜GóW«¬rrí≤rrµ7G&ñÊrÜ√ÚÊFWFñ«3ÚÁ6˜W&6W«¬rrííÁFÙ∆˜vW$66RÇì∑&WGW&‚˜vñfó«vó&V∆W77«v∆‚ÚÁFW7BáÇó–¶gVÊ7Fñˆ‚6ˆ◊WFTÊWGv˜&µ˜6óFñˆÁ2ÜÊˆFW2∆∆ñÊ∑2∆∆ñ˜WBó∂6ˆÁ7Bs”ƒÉ”s#«˜3◊∑”∂6ˆÁ7B'îñC‘‰UEtı$µÙDDÊ'îñC∂6ˆÁ7BñÁFW&ÊWC÷ÊˆFW2ÊfñÊBÜ„”Ê‚ÊñC””“vñÁFW&ÊWBrí∆vFWvì÷ÊˆFW2ÊfñÊBÜ„”Ê‚ÊñC””“Ñ‰UEtı$µÙDDÊvFWvó«¬vvFWvíríó«∆ÊˆFW2ÊfñÊBÜ„”Â7G&ñÊrÜ‚ÁGóRíÁFÙ∆˜vW$66RÇì””“vvFWvírì∂ñbÜ∆ñ˜WC””“v6ó&7V∆"ró∂6ˆÁ7B6VÁFW#÷vFWvó«∆ñÁFW&ÊWG«∆ÊˆFW5≥”∂ñbÜ6VÁFW"ó˜5∂6VÁFW"ÊñE”◊∑É£SS«ì£3S”∂6ˆÁ7B&ñÊs÷ÊˆFW2Êfñ«FW"Ü„”‚6VÁFW'«∆‚ÊñB”÷6VÁFW"ÊñBì∑&ñÊrÊf˜$V6ÇÇÜ‚∆íì”Á∂6ˆÁ7B“Ñ÷FÇÂí£"¶íÙ÷FÇÊ÷ÇÉ«&ñÊrÊ∆VÊwFÇíí‘÷FÇÂíÛ#∑˜5∂‚ÊñE”◊∑É£SS≥3ì§÷FÇÊ6˜2Üí«ì£3S≥#s§÷FÇÁ6ñ‚Üó◊“ì∂ñbÜñÁFW&ÊWBbf6VÁFW"bfñÁFW&ÊWBÊñB”÷6VÁFW"ÊñBó˜5∂ñÁFW&ÊWBÊñE”◊∑É£SS«ì£s”∑&WGW&‚˜7–¢6ˆÁ7B6Üñ∆G&V„◊∑”∂∆ñÊ∑2Êf˜$V6ÇÜ√”‚Ü6Üñ∆G&VÂ∂¬Á&VÁE◊«¬Ü6Üñ∆G&VÂ∂¬Á&VÁE”’µ“ííÁW6ÇÜ¬Ê6Üñ∆Bíì∂6ˆÁ7B&ˆ˜C÷ñÁFW&ÊWCÚÊñG«∆vFWvìÚÊñG«∆ÊˆFW5≥”ÚÊñC∂6ˆÁ7BFWFÉ◊∑“«◊&ˆ˜Cı∑&ˆ˜E”•µ”∂ñbá&ˆ˜BñFWFÖ∑&ˆ˜E””∑vÜñ∆RáÊ∆VÊwFÇó∂6ˆÁ7BñC◊Á6ÜñgBÇì∂f˜"Ü6ˆÁ7B6Çˆb6Üñ∆G&VÂ∂ñE◊«≈µ“ó∂ñbÜFWFÖ∂6Ö”””◊VÊFVfñÊVBó∂FWFÖ∂6Ö”÷FWFÖ∂ñE“≥∑ÁW6ÇÜ6Çó◊◊÷ÊˆFW2Êf˜$V6ÇÜ„”Á∂ñbÜFWFÖ∂‚ÊñE”””◊VÊFVfñÊVBñFWFÖ∂‚ÊñE”÷vFWvíbf‚ÊñB”÷vFWvíÊñCÛ#£“ì∂ñbÜ∆ñ˜WC””“vWFÚrbfñÁFW&ÊWBbfvFWvíó∑˜5∂ñÁFW&ÊWBÊñE”◊∑É£SS«ì£cW”∑˜5∂vFWvíÊñE”◊∑É£SS«ì£#CW”∂6ˆÁ7B&V÷ñÊñÊs÷ÊˆFW2Êfñ«FW"Ü„”Ê‚ÊñB”÷ñÁFW&ÊWBÊñBbf‚ÊñB”÷vFWvíÊñBì∂6ˆÁ7BñÊg&◊&V÷ñÊñÊrÊfñ«FW"Üó4ñÊg&7G'V7GW&TÊˆFRí∆6∆ñVÁG3◊&V÷ñÊñÊrÊfñ«FW"Ü„”‚ó4ñÊg&7G'V7GW&TÊˆFRÜ‚íì∂ñÊg&Êf˜$V6ÇÇÜ‚∆íì”Á∂6ˆÁ7B6∆˜G3‘÷FÇÊ÷ÇÉ∆ñÊg&Ê∆VÊwFÇì∑˜5∂‚ÊñE”◊∑É£É≤ÉsC¢Üí≤„Rí˜6∆˜G2í«ì£C◊“ì∂6∆ñVÁG2Êf˜$V6ÇÇÜ‚∆íì”Á∂6ˆÁ7B6ˆ«3‘÷FÇÊ÷ñ‚Érƒ÷FÇÊ÷ÇÉ∆6∆ñVÁG2Ê∆VÊwFÇíì∂6ˆÁ7B&˜s‘÷FÇÊf∆ˆ˜"Üíˆ6ˆ«2í∆6ˆ√÷íV6ˆ«3∑˜5∂‚ÊñE”◊∑É£ìR≤Éì¢Ü6ˆ¬≤„Ríˆ6ˆ«2í«ì£SsR∑&˜r£'◊“ì∑&WGW&‚˜7–¢6ˆÁ7B∆WfV«3◊∑”∂ÊˆFW2Êf˜$V6ÇÜ„”‚Ü∆WfV«5∂FWFÖ∂‚ÊñE’◊«¬Ü∆WfV«5∂FWFÖ∂‚ÊñE’”’µ“ííÁW6ÇÜ‚íì¥ˆ&¶V7BÊ∂Wó2Ü∆WfV«2íÊ÷ÑÁV÷&W"íÁ6˜'BÇÜ∆"ì”Ê÷"íÊf˜$V6ÇÜC”Á∂6ˆÁ7B÷∆WfV«5∂E“«ì”s∂B£CS∂Êf˜$V6ÇÇÜ‚∆íì”Á˜5∂‚ÊñE”◊∑É£ÉR≤Éì3¢Üí≤„RíˆÊ∆VÊwFÇí«ó“ó“ì∑&WGW&‚˜7–¶gVÊ7Fñˆ‚VFvUFÇÜ∆"ó∂6ˆÁ7B÷ñC“ÜÁí∂"ÁííÛ#∑&WGW&Ê“G∂Áá“G∂Áí≥#g“2G∂Áá“G∂÷ñG“¬G∂"Áá“G∂÷ñG“¬G∂"Áá“G∂"Áí”3'÷–¶gVÊ7Fñˆ‚÷ÊˆFUfó6ñ&∆RÜ‚ó∂6ˆÁ7B7C÷÷ÊˆFT6∆72Ü‚ì∑&WGW&‚‰UEtı$µÙdî≈DU#””“v∆¬w«ƒ‰UEtı$µÙdî≈DU#””◊7G–¶gVÊ7Fñˆ‚&VÊFW$ÊWGv˜&¥w&ÇÇó∂6ˆÁ7B6Áf3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWGv˜&¥6Áf2rí«7fs÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷VFvT∆ñW"rì∂ñbÇ6Áf7«¬7fró&WGW&„∂6ˆÁ7BÊˆFW3‘‰UEtı$µÙDDÊÊˆFW7«≈µ“∆∆ñÊ∑3‘‰UEtı$µÙDDÊ∆ñÊ∑7«≈µ“«˜3÷6ˆ◊WFTÊWGv˜&µ˜6óFñˆÁ2ÜÊˆFW2∆∆ñÊ∑2ƒ‰UEtı$µÙƒîıUBì∂6ˆÁ7Bfó6ñ&∆S÷ÊWr6WBÜÊˆFW2Êfñ«FW"Ü÷ÊˆFUfó6ñ&∆RíÊ÷Ü„”Ê‚ÊñBíì∑7frÊñÊÊW$ÖD‘√÷∆ñÊ∑2Êfñ«FW"Ü√”Á˜5∂¬Á&VÁE“bg˜5∂¬Ê6Üñ∆E“bgfó6ñ&∆RÊÜ2Ü¬Á&VÁBíbgfó6ñ&∆RÊÜ2Ü¬Ê6Üñ∆BííÊ÷Ü√”Ê«FÇ6∆73“'F˜ˆ∆ˆwí÷VFvRG∂ó5vó&V∆W74∆ñÊ≤Ü¬ìÚwvó&V∆W72s¢rw“G∂¬ÊFWFñ«3ÚÁ6˜W&6S””“vñÊfW'&VBsÚvñÊfW'&VBs¢rw“"C“"G∂VFvUFÇá˜5∂¬Á&VÁE“«˜5∂¬Ê6Üñ∆E“ó“#„¬˜FÉÊíÊ¶ˆñ‚Çrrì∂6Áf2ÊñÊÊW$ÖD‘√÷ÊˆFW2Êfñ«FW"Ü÷ÊˆFUfó6ñ&∆RíÊ÷ÇÜ‚∆íì”Á∂6ˆÁ7B◊˜5∂‚ÊñE◊««∑É£SS«ì£3S“«7C÷÷ÊˆFT6∆72Ü‚í∆ñ6ˆ„÷‚ÁGóS””“vñÁFW&ÊWBsÚs∆Fób6∆73“&ñÁFW&ÊWB÷v∆ˆ&R#Ô	¯…¬ˆFóc‚s¶∆ñ÷r7&3“"G∂W62Ü÷FWfñ6Tñ6ˆÂ7&2Ü‚íó“"«C“"G∂W62Ü‚ÁGóW«¬tFWfñ6Rró“ñ6ˆ‚#Ê∂6ˆÁ7B˜&ñvñÊƒñÊFWÉ÷ÊˆFW2ÊñÊFWÑˆbÜ‚ì∑&WGW&Ê∆Fób6∆73“'F˜ˆ∆ˆwí÷ÊˆFRFWfñ6R÷6∆ñ6∂&∆RG∂‚ÁGóS””“vñÁFW&ÊWBsÚvñÁFW&ÊWBs¢rw“G∂˜&ñvñÊƒñÊFWÉ””’4TƒT5DTEÙ‘Ùî‰DUÉÚw6V∆V7FVBs¢rw“"FF÷÷÷ñÊFWÉ“"G∂˜&ñvñÊƒñÊFWá“"FF◊6V&6É“"G∂W62Ö∂‚Ê∆&V¬∆‚Êó∆‚Ê÷2∆‚ÁfVÊF˜"∆‚ÁGóR∆‚Ê6∆76ñfñ6FñˆÂ“Êfñ«FW"Ñ&ˆˆ∆V‚íÊ¶ˆñ‚ÇrríÁFÙ∆˜vW$66RÇíó“"7Gñ∆S“&∆VgC¢G∑Áá◊É∑F˜¢G∑Áó◊Ç"ˆÊ6∆ñ6≥“'6V∆V7D÷ÊˆFT'îñÊFWÇÇG∂˜&ñvñÊƒñÊFWá“í#„∆Fób6∆73“'F˜ˆ∆ˆwí÷'B#‚G∂ñ6ˆÁ”«7‚6∆73“'F˜ˆ∆ˆwí◊7FGW2÷F˜BG∑7G“#„¬˜7„„¬ˆFóc„∆Fób6∆73“'F˜ˆ∆ˆwí÷Ê÷R#‚G∂W62Ü‚Ê∆&V««∆‚ÊñBó”¬ˆFóc„∆Fób6∆73“'F˜ˆ∆ˆwí÷ó#‚G∂W62Ü‚Êó«∆‚ÁGóW«¬rró”¬ˆFóc„∆Fób6∆73“'F˜ˆ∆ˆwí◊fVÊF˜"#‚G∂W62Ü‚ÁfVÊF˜'«¬rró”¬ˆFóc„¬ˆFócÊ“íÊ¶ˆñ‚Çrró«¬s∆Fób6∆73“&÷÷V◊Gí#‰ÊÚFWfñ6W2÷F6ÇFÜó2fñ«FW"„¬ˆFóc‚s∂fñ«FW$÷ÊˆFW2Çì∑&VÊFW%6V∆V7FVD÷ÊV¬Çì∑6WEFñ÷V˜WBÇÇì”Á∂6ˆÁ7B7FvS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWGv˜&µ7FvRrì∂ñbá7FvRó∂6ˆÁ7B÷Öì‘÷FÇÊ÷ÇÉs#¬‚‚‰ˆ&¶V7BÁf«VW2á˜2íÊ÷á”ÁÁí≥íì∑7FvRÁ7Gñ∆RÊÜVñváC÷÷Öí≤wÇs∑7frÁ6WDGG&ñ'WFRÇvÜVñváBr∆÷Öíì∑7frÁ7Gñ∆RÊÜVñváC÷÷Öí≤wÇw◊“√ó–¶gVÊ7Fñˆ‚6WD÷fñ«FW"Üfñ«FW"ó¥‰UEtı$µÙdî≈DU#÷fñ«FW#∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊÊWGv˜&≤÷fñ«FW"ríÊf˜$V6ÇÜ#”Ê"Ê6∆74∆ó7BÁFˆvv∆RÇv7FófRr∆"ÊFF6WBÊ÷fñ«FW#””÷fñ«FW"íì∑&VÊFW$ÊWGv˜&¥w&ÇÇó–¶gVÊ7Fñˆ‚6WDÊWGv˜&¥∆ñ˜WBÜ∆ñ˜WBó¥‰UEtı$µÙƒîıUC÷∆ñ˜WC∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ÷÷∆ñ˜WB÷'F‚ríÊf˜$V6ÇÜ#”Ê"Ê6∆74∆ó7BÁFˆvv∆RÇv7FófRr∆"ÊFF6WBÊ∆ñ˜WC””÷∆ñ˜WBíì∑&VÊFW$ÊWGv˜&¥w&ÇÇì∑6WEFñ÷V˜WBÜfóDÊWGv˜&¥÷√3ó–¶gVÊ7Fñˆ‚fñ«FW$÷ÊˆFW2Çó∂6ˆÁ7B“ÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷6V&6ÇrìÚÁf«VW«¬rríÁG&ñ“ÇíÁFÙ∆˜vW$66RÇì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çr6ÊWGv˜&¥6Áf2ÁF˜ˆ∆ˆwí÷ÊˆFU∂FF◊6V&6Ö“ríÊf˜$V6ÇÜ„”Á∂6ˆÁ7B÷F6É“«∆‚ÊFF6WBÁ6V&6ÇÊñÊ6«VFW2áì∂‚Ê6∆74∆ó7BÁFˆvv∆RÇvFñ÷÷VBr¬÷F6Çó“ó–¶gVÊ7Fñˆ‚«îÊWGv˜&µ¶ˆˆ“Çó∂6ˆÁ7B7FvS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWGv˜&µ7FvRrì∂ñbá7FvRó7FvRÁ7Gñ∆RÁG&Á6f˜&”“w66∆RÇr¥‰UEtı$µı§ÙÙ“≤ríw–¶gVÊ7Fñˆ‚¶ˆˆ‘ÊWGv˜&≤ÜFV«Fó¥‰UEtı$µı§ÙÙ”‘÷FÇÊ÷ÇÇ„SRƒ÷FÇÊ÷ñ‚É„CRƒ÷FÇÁ&˜VÊBÇÑ‰UEtı$µı§ÙÙ“∂FV«Fí£íÛíì∂«îÊWGv˜&µ¶ˆˆ“Çó–¶gVÊ7Fñˆ‚fóDÊWGv˜&¥÷Çó∂6ˆÁ7Bg÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWGv˜&µfñWw˜'Brí«7FvS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWGv˜&µ7FvRrì∂ñbÇg«¬7FvRó&WGW&„¥‰UEtı$µı§ÙÙ”‘÷FÇÊ÷ÇÇ„SRƒ÷FÇÊ÷ñ‚É¬ágÊ6∆ñVÁEvñGFÇ”ÇíÛíì∂«îÊWGv˜&µ¶ˆˆ“Çì∑gÁ67&ˆ∆≈FÚá∂∆VgC£«F˜£∆&VÜfñ˜#¢w6÷ˆ˜FÇw“ó–¶gVÊ7Fñˆ‚6VÁFW%6V∆V7FVD÷ÊˆFRÇó∂6ˆÁ7Bg÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWGv˜&µfñWw˜'Brí∆ÊˆFS÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜"ÇrÁF˜ˆ∆ˆwí÷ÊˆFRÁ6V∆V7FVBrì∂ñbÇg«¬ÊˆFRó&WGW&„∑gÁ67&ˆ∆≈FÚá∂∆VgC§÷FÇÊ÷ÇÉ∆ÊˆFRÊˆfg6WD∆VgB§‰UEtı$µı§ÙÙ“◊gÊ6∆ñVÁEvñGFÇÛ"í«F˜§÷FÇÊ÷ÇÉ∆ÊˆFRÊˆfg6WEF˜§‰UEtı$µı§ÙÙ“◊gÊ6∆ñVÁDÜVñváBÛ"í∆&VÜfñ˜#¢w6÷ˆ˜FÇw“ó–¶gVÊ7Fñˆ‚6V∆V7D÷ÊˆFT'îñÊFWÇÜíóµ4TƒT5DTEÙ‘Ùî‰DUÉ‘ÁV÷&W"Üíì∑&VÊFW$ÊWGv˜&¥w&ÇÇì∑6WEFñ÷V˜WBÜ6VÁFW%6V∆V7FVD÷ÊˆFR√ó–¶gVÊ7Fñˆ‚6ˆÊÊV7FVDÊˆFW4f˜"Ü‚ó∂ñbÇ‚ó&WGW&Âµ”∂6ˆÁ7BñG3’µ”∂f˜"Ü6ˆÁ7B¬ˆb‰UEtı$µÙDDÊ∆ñÊ∑7«≈µ“ó∂ñbÜ¬Á&VÁC””÷‚ÊñBññG2ÁW6ÇÜ¬Ê6Üñ∆Bì∂V«6RñbÜ¬Ê6Üñ∆C””÷‚ÊñBññG2ÁW6ÇÜ¬Á&VÁBó◊&WGW&Â≤‚‚ÊÊWr6WBÜñG2ï“Ê÷ÜñC”‰‰UEtı$µÙDDÊ'îñE∂ñE“íÊfñ«FW"Ñ&ˆˆ∆V‚ó–¶gVÊ7Fñˆ‚&VÊFW%6V∆V7FVD÷ÊV¬Çó∂6ˆÁ7BÊV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷6V∆V7FVEÊV¬rí∆∆ó7C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷6ˆÊÊV7FVDFWfñ6W2rí∆6˜VÁC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷6ˆÊÊV7FVD6˜VÁBrì∂ñbÇÊV««¬∆ó7Bó&WGW&„∂6ˆÁ7B„“Ñ‰UEtı$µÙDDÊÊˆFW7«≈µ“ïµ4TƒT5DTEÙ‘Ùî‰DUÖ”∂ñbÇ‚ó∑ÊV¬ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&ÊWGv˜&≤÷V◊Gí◊6ñFR#Â6V∆V7BFWfñ6Rˆ‚FÜR÷FÚfñWróG2FWFñ«2„¬ˆFóc‚s∂∆ó7BÊñÊÊW$ÖD‘√“s∆Fób6∆73“&ÊWGv˜&≤÷V◊Gí◊6ñFR#‰ÊÚFWfñ6R6V∆V7FVB„¬ˆFóc‚s∂ñbÜ6˜VÁBñ6˜VÁBÁFWáD6ˆÁFVÁC“ss∑&WGW&Á÷6ˆÁ7Bñ6ˆ„÷‚ÁGóS””“vñÁFW&ÊWBsÚs∆Fób6∆73“&ñÁFW&ÊWB÷v∆ˆ&R#Ô	¯…¬ˆFóc‚s¶∆ñ÷r7&3“"G∂W62Ü÷FWfñ6Tñ6ˆÂ7&2Ü‚íó“"«C“"#Ê∑ÊV¬ÊñÊÊW$ÖD‘√÷∆Fób6∆73“&ÊWGv˜&≤÷FWfñ6R÷ÜVB#‚G∂ñ6ˆÁ”∆Fóc„∆Fób6∆73“&ÊWGv˜&≤÷FWfñ6R◊FóF∆R#‚G∂W62Ü‚Ê∆&V««∆‚ÊñBó”¬ˆFóc„∆Fób6∆73“'7FGW2÷&FvR#Ó)xÚG∂W62Ü÷ÊˆFT6∆72Ü‚íó”¬ˆFóc„∆Fób6∆73“&ÊWGv˜&≤÷FWfñ6R◊7V"#‚G∂W62Ü‚ÁfVÊF˜'«∆‚ÁGóW«¬tÊWGv˜&≤ÊˆFRró”¬ˆFóc„¬ˆFóc„¬ˆFóc„∆Fób6∆73“&ÊWGv˜&≤÷∑b#„∆Fób6∆73“&≤#‰ïFG&W73¬ˆFóc„∆Fób6∆73“'b#‚G∂W62Ü‚Êó«¬~(	Bró”¬ˆFóc„∆Fób6∆73“&≤#‰‘2FG&W73¬ˆFóc„∆Fób6∆73“'b#‚G∂W62Ü‚Ê÷7«¬~(	Bró”¬ˆFóc„∆Fób6∆73“&≤#ÂGóS¬ˆFóc„∆Fób6∆73“'b#‚G∂W62Ü‚ÁGóW«¬~(	Bró”¬ˆFóc„∆Fób6∆73“&≤#‰6∆76ñfñ6Fñˆ„¬ˆFóc„∆Fób6∆73“'b#‚G∂W62Ü‚Ê6∆76ñfñ6FñˆÁ«¬~(	Bró”¬ˆFóc„∆Fób6∆73“&≤#Â7FGW3¬ˆFóc„∆Fób6∆73“'b#‚G∂W62Ü‚Á7FGW7«¬wVÊ∂Ê˜v‚ró”¬ˆFóc„¬ˆFóc„∆Fób6∆73“&ÊWGv˜&≤÷FWfñ6R÷7FñˆÁ2#‚G∂‚ÊFWfñ6UˆñCˆ∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“&vÙFWfñ6RÇG¥ÁV÷&W"Ü‚ÊFWfñ6UˆñBó“í#ÂfñWrFWFñ«3¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'6Ü˜ufñWrÇvFWfñ6W2rí#‰VFóBFWfñ6S¬ˆ'WGFˆ„Ê¢rw”∆6∆73“'6V6ˆÊF'í"á&Vc“"˜Fˆˆ«26FñvÊ˜7Fñ72"7Gñ∆S“'FWáB÷FV6˜&Fñˆ„¶ÊˆÊR#ÂñÊs¬ˆ„¬ˆFócÊ∂6ˆÁ7B6ˆÊÊV7FVC÷6ˆÊÊV7FVDÊˆFW4f˜"Ü‚íÊfñ«FW"áÉ”ÁÇÊñB”“vñÁFW&ÊWBrì∂ñbÜ6˜VÁBñ6˜VÁBÁFWáD6ˆÁFVÁC’7G&ñÊrÜ6ˆÊÊV7FVBÊ∆VÊwFÇì∂∆ó7BÊñÊÊW$ÖD‘√÷6ˆÊÊV7FVBÊ∆VÊwFÉˆ6ˆÊÊV7FVBÁ6∆ñ6RÉ√"íÊ÷áÉ”Á∂6ˆÁ7B7C÷÷ÊˆFT6∆72áÇí«7&3◊ÇÁGóS””“vñÁFW&ÊWBsÚrs¶÷FWfñ6Tñ6ˆÂ7&2áÇì∑&WGW&Ê∆Fób6∆73“&6ˆÊÊV7FVB÷FWfñ6R◊&˜r"ˆÊ6∆ñ6≥“'6V∆V7D÷ÊˆFT'îñÊFWÇÇG¥‰UEtı$µÙDDÊÊˆFW2ÊñÊFWÑˆbáÇó“í#„∆Fóc‚G∑ÇÁGóS””“vñÁFW&ÊWBsÚ	¯…s¶∆ñ÷r7&3“"G∂W62á7&2ó“"«C“"#Ê”¬ˆFóc„«7‚6∆73“&F˜BG∑7G“#„¬˜7„„∆Fóc„∆Fób6∆73“&6ˆÊÊV7FVB÷Ê÷R#‚G∂W62áÇÊ∆&V«««ÇÊñBó”¬ˆFóc„∆Fób6∆73“&6ˆÊÊV7FVB◊GóR#‚G∂W62áÇÁGóW«¬tFWfñ6Rró”¬ˆFóc„¬ˆFóc„∆Fób6∆73“&6ˆÊÊV7FVB÷ó#‚G∂W62áÇÊó«¬rró”¬ˆFóc„¬ˆFócÊ“íÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&ÊWGv˜&≤÷V◊Gí◊6ñFR#‰ÊÚFó&V7F«í6ˆÊÊV7FVBFWfñ6W2„¬ˆFóc‚w–¢Ú¢∆Vv7íÊfñvFñˆ‚6ˆÁG&7C¢vÙFWfñ6RÇG¥ÁV÷&W"Ü‚ÊFWfñ6UˆñBó“í¢ßvñÊF˜rÊfñ«FW$÷ÊˆFW3÷fñ«FW$÷ÊˆFW3∑vñÊF˜rÁ¶ˆˆ‘ÊWGv˜&≥◊¶ˆˆ‘ÊWGv˜&≥∑vñÊF˜rÊfóDÊWGv˜&¥÷÷fóDÊWGv˜&¥÷∑vñÊF˜rÁ6WD÷fñ«FW#◊6WD÷fñ«FW#∑vñÊF˜rÁ6WDÊWGv˜&¥∆ñ˜WC◊6WDÊWGv˜&¥∆ñ˜WC∑vñÊF˜rÁ6V∆V7D÷ÊˆFT'îñÊFWÉ◊6V∆V7D÷ÊˆFT'îñÊFWÉ∑vñÊF˜rÊ6VÁFW%6V∆V7FVD÷ÊˆFS÷6VÁFW%6V∆V7FVD÷ÊˆFS∞¶7ñÊ2gVÊ7Fñˆ‚∆ˆDÊWGv˜&≤Çó∂6ˆÁ7B6Áf3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊWGv˜&¥6Áf2rì∂ñbÇ6Áf2ó&WGW&„∂6ˆÁ7B7FGW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷7FGW2rì∂ñbá7FGW2ó7FGW2ÁFWáD6ˆÁFVÁC“u&Vg&W6ÜñÊrF˜ˆ∆ˆwû(
bs∑G'ó∂6ˆÁ7BC÷vóBß6ˆ‚Çrˆí˜cˆñÁFV∆∆ñvVÊ6R˜F˜ˆ∆ˆwíˆ∆ófRrí∆ÊˆFW3◊BÊÊˆFW7«≈µ“∆∆ñÊ∑3◊BÊ∆ñÊ∑7«≈µ“∆'îñC◊∑”∂ÊˆFW2Êf˜$V6ÇÜ„”Ê'îñE∂‚ÊñE”÷‚ì¥‰UEtı$µÙDD◊≤‚‚ÁB∆ÊˆFW2∆∆ñÊ∑2∆'îñB∆vFWvìßBÊvFWvó«¬vvFWvíw”∂6ˆÁ7Bws÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷vFWvírí∆Ê3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷ÊˆFW2rí∆∆3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷∆ñÊ∑2rí«W÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷WFFVBrì∂ñbÜwrñwrÁFWáD6ˆÁFVÁC◊BÊvFWvó«¬uVÊ∂Ê˜v‚s∂ñbÜÊ2ñÊ2ÁFWáD6ˆÁFVÁC÷ÊˆFW2Êfñ«FW"Ü„”Ê‚ÁGóR”“vñÁFW&ÊWBríÊ∆VÊwFÉ∂ñbÜ∆2ñ∆2ÁFWáD6ˆÁFVÁC÷∆ñÊ∑2Ê∆VÊwFÉ∂ñbáWóWÁFWáD6ˆÁFVÁC÷ÊWrFFRáBÊvVÊW&FVEˆG«ƒFFRÊÊ˜rÇííÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“¬∂Ü˜W#¢vÁV÷W&ñ2r∆÷ñÁWFS¢s"÷FñvóBw“ì∂6ˆÁ7B∆√÷ÊˆFW2Êfñ«FW"Ü„”Ê‚ÁGóR”“vñÁFW&ÊWBrí∆ˆÊ∆ñÊS÷∆¬Êfñ«FW"Ü„”Ê÷ÊˆFT6∆72Ü‚ì””“vˆÊ∆ñÊRríÊ∆VÊwFÇ∆ˆff∆ñÊS÷∆¬Êfñ«FW"Ü„”Ê÷ÊˆFT6∆72Ü‚ì””“vˆff∆ñÊRríÊ∆VÊwFÇ«VÊ∂Ê˜v„‘÷FÇÊ÷ÇÉ∆∆¬Ê∆VÊwFÇ÷ˆÊ∆ñÊR÷ˆff∆ñÊRì∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷∆ƒ6˜VÁBríÁFWáD6ˆÁFVÁC÷∆¬Ê∆VÊwFÉ∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷ˆÊ∆ñÊT6˜VÁBríÁFWáD6ˆÁFVÁC÷ˆÊ∆ñÊS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷ˆff∆ñÊT6˜VÁBríÁFWáD6ˆÁFVÁC÷ˆff∆ñÊS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷VÊ∂Ê˜v‰6˜VÁBríÁFWáD6ˆÁFVÁC◊VÊ∂Ê˜v„∂ñbá7FGW2ó7FGW2ÁFWáD6ˆÁFVÁC÷ÊˆFW2Ê∆VÊwFÇ≤rÊˆFW2+rr∂∆ñÊ∑2Ê∆VÊwFÇ≤r&V∆FñˆÁ6Üó2+rr∂ÊWrFFRáBÊvVÊW&FVEˆG«ƒFFRÊÊ˜rÇííÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“¬∂Ü˜W#¢vÁV÷W&ñ2r∆÷ñÁWFS¢s"÷FñvóBw“ì∂6ˆÁ7BWfñFVÊ6S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷WfñFVÊ6Rrì∂ñbÜWfñFVÊ6Ró∂6ˆÁ7B6˜W&6W3’≤‚‚ÊÊWr6WBÜ∆ñÊ∑2Ê÷Ü√”Ê¬ÊFWFñ«3ÚÁ6˜W&6RíÊfñ«FW"Ñ&ˆˆ∆V‚íï”∂WfñFVÊ6RÁFWáD6ˆÁFVÁC◊6˜W&6W2Ê∆VÊwFÉÚtWfñFVÊ6R6˜W&6W3¢r∑6˜W&6W2Ê¶ˆñ‚Çr¬rí≤r‚6ˆ∆ñBFá2&Rvó&VB˜VÁ7V6ñfñVC≤F6ÜVBFá2&Rvó&V∆W72‚s¢uFá2vóFÜ˜WBFó&V7B6ˆÁG&ˆ∆∆W"WfñFVÊ6R&R6Ü˜v‚6ˆÁ6W'fFófV«í‚w÷ñbÖ4TƒT5DTEÙ‘Ùî‰DUÉ√«≈4TƒT5DTEÙ‘Ùî‰DUÉ„÷ÊˆFW2Ê∆VÊwFÇï4TƒT5DTEÙ‘Ùî‰DUÉ‘÷FÇÊ÷ÇÉ∆ÊˆFW2ÊfñÊDñÊFWÇÜ„”Ê‚ÊñC””◊BÊvFWvó«≈7G&ñÊrÜ‚ÁGóRíÁFÙ∆˜vW$66RÇì””“vvFWvíríì∑&VÊFW$ÊWGv˜&¥w&ÇÇì∑6WEFñ÷V˜WBÜfóDÊWGv˜&¥÷√Có÷6F6ÇÜRó∂6Áf2ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&÷÷V◊Gí#ÂF˜ˆ∆ˆwíó2Ê˜Bfñ∆&∆RñWB„∆'#„«7‚6∆73“&◊WFVB#‚r∂W62ÜRÊ÷W76vRí≤s¬˜7„„∆'#„∆'#„∆'WGFˆ‚6∆73“'&ñ÷'í"ˆÊ6∆ñ6≥“''V‰gV∆ƒFó66˜fW'íÇí#Â'V‚gV∆¬Fó66˜fW'ì¬ˆ'WGFˆ„„¬ˆFóc‚s∂ñbá7FGW2ó7FGW2ÁFWáD6ˆÁFVÁC“uF˜ˆ∆ˆwíVÊfñ∆&∆Rw◊–¶7ñÊ2gVÊ7Fñˆ‚'V‰gV∆ƒFó66˜fW'íÇó∂ÊWGv˜&¥6Áf2ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#Â'VÊÊñÊr%¬Ê÷¬ÊVñvÜ&˜'2¬‘DÂ2¬ÊWD$îı2¬DÑ5ÊB6ˆÊfñwW&VBñÁFVw&Fñˆ‚Fó66˜fW'û(
c¬ˆFóc‚s∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆFó66˜fW'íˆgV∆¬r«∂÷WFÜˆC¢uı5Bw“ì∂vóB∆ˆDÊWGv˜&≤Çì∂6ˆÁ7B'G3‘ˆ&¶V7BÊVÁG&ñW2á"Á6˜W&6W7««∑“íÊ÷ÇÖ∂≤«e“ì”Ê≤≤s¢r∑bÊ6˜VÁBíÊ¶ˆñ‚Çr+rrì∂∆W'BÇtgV∆¬Fó66˜fW'í6ˆ◊∆WFR‚r∑"ÁF˜F≈ˆˆ'6W'fFñˆÁ2≤r6˜'&V∆FVBˆ'6W'fFñˆÁ2Â∆‚r∑'G2ó÷6F6ÇÜRó∂ÊWGv˜&¥6Áf2ÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#‰gV∆¬Fó66˜fW'ífñ∆VC¢r∂W62ÜRÊ÷W76vRí≤s¬ˆFóc‚w◊–¶∆WB‘Ù‰ïDı%3’µ”∂∆WBTDïEÙ‘Ù‰ïDı%ÙîC÷ÁV∆√∞¶7ñÊ2gVÊ7Fñˆ‚∆ˆD÷ˆÊóF˜&ñÊrÇó∑G'ó∂6ˆÁ7B∑6WGFñÊw2∆6ÜV6∑5”÷vóB&ˆ÷ó6RÊ∆¬Ö∂ß6ˆ‚Çrˆí˜cˆ÷ˆÊóF˜&ñÊr˜6WGFñÊw2rí∆ß6ˆ‚Çrˆí˜cˆ÷ˆÊóF˜&ñÊrˆ6ÜV6∑2rï“ì¥‘Ù‰ïDı%3◊6WGFñÊw3∂6ˆÁ7B∆FW7C◊∑”∂f˜"Ü6ˆÁ7B2ˆb6ÜV6∑2ó∂ñbÜ2Ê÷ˆÊóF˜%ˆñBbb∆FW7E∂2Ê÷ˆÊóF˜%ˆñE“ñ∆FW7E∂2Ê÷ˆÊóF˜%ˆñE”÷7÷∆WBÜV«Fáì”∆fñ∆ñÊs”∆Fó6&∆VC”∂f˜"Ü6ˆÁ7BÇˆb6WGFñÊw2ó∂ñbÇÇÊVÊ&∆VBó∂Fó6&∆VB≤≥∂6ˆÁFñÁVW÷6ˆÁ7B3÷∆FW7E∑ÇÊñE”∂6ˆÁ7B7C÷3ı7G&ñÊrÜ2Á7FGW7«¬wVÊ∂Ê˜v‚ríÁFÙ∆˜vW$66RÇì¢wVÊ∂Ê˜v‚s∂ñbÖ≤wWr¬vˆ≤r¬vÜV«Fáír¬vˆÊ∆ñÊRr¬w7V66W72u“ÊñÊ6«VFW2á7BíñÜV«Fáí≤≥∂V«6RñbÖ≤vF˜v‚r¬vfñ∆VBr¬vW'&˜"r¬vˆff∆ñÊRu“ÊñÊ6«VFW2á7Bíñfñ∆ñÊr≤∑÷6ˆÁ7B6WEFWáC“ÜñB«bì”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬ÁFWáD6ˆÁFVÁC◊g”∑6WEFWáBÇv÷ˆÊóF˜%F˜F≈7V÷÷'ír«6WGFñÊw2Ê∆VÊwFÇì∑6WEFWáBÇv÷ˆÊóF˜$ÜV«Fáï7V÷÷'ír∆ÜV«Fáíì∑6WEFWáBÇv÷ˆÊóF˜$fñ∆ñÊu7V÷÷'ír∆fñ∆ñÊrì∑6WEFWáBÇv÷ˆÊóF˜$Fó6&∆VE7V÷÷'ír∆Fó6&∆VBì∂÷ˆÊóF˜%&˜w2ÊñÊÊW$ÖD‘√◊6WGFñÊw2Ê∆VÊwFÉ˜6WGFñÊw2Ê÷áÉ”Á∂6ˆÁ7B3÷∆FW7E∑ÇÊñE”∂6ˆÁ7B7C÷3ˆ2Á7FGW3¢áÇÊVÊ&∆VCÚwVÊ∂Ê˜v‚s¢vFó6&∆VBrì∑&WGW&‚«G#„«FC„∆Fób6∆73“&Ê÷R#‚G∂W62áÇÊÊ÷Ró”¬ˆFóc„¬˜FC„«FC„«7‚6∆73“&÷ˆÊóF˜"◊GóR÷&FvR#‚G∂W62Ö7G&ñÊráÇÊ∂ñÊG«¬rríÁ&W∆6RÇuÚr¬rríó”¬˜7„„¬˜FC„«FC„«7‚6∆73“&÷ˆÊóF˜"◊F&vWB#‚G∂W62áÇÁF&vWG«¬~(	Bró”¬˜7„„¬˜FC„«FC‚G∂W62áÇÊñÁFW'f≈˜6V6ˆÊG2ó“6V3¬˜FC„«FC„«7‚6∆73“'7FGW2÷&FvRG∑7C””“vF˜v‚w««7C””“vfñ∆VBw««7C””“vW'&˜"sÚw6WfW&óGí÷ÜñvÇs¢rw“#‚G∂W62á7Bó”¬˜7„„¬˜FC„«FC‚G∂3ˆW62ÜÊWrFFRÜ2Ê∆7Eˆ6ÜV6∂VBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC‚G∂2bf2Ê∆FVÊ7ïˆ◊2÷ÁV∆√ˆW62Ü2Ê∆FVÊ7ïˆ◊2í≤r◊2s¢~(	Bw”¬˜FC„«FC„∆Fób6∆73“&÷ˆÊóF˜"÷7FñˆÁ2#„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“''V‰÷ˆÊóF˜"ÇG∑ÇÊñG“í#Â'V„¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&˜V‰÷ˆÊóF˜$VFóF˜"ÇG∑ÇÊñG“í#‰VFóC¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&FV∆WFT÷ˆÊóF˜"ÇG∑ÇÊñG“í#‰FV∆WFS¬ˆ'WGFˆ„„¬ˆFóc„¬˜FC„¬˜G#Ê“íÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#Ç#„∆Fób6∆73“&÷ˆÊóF˜"÷V◊Gí#„∆#‰ÊÚ÷ˆÊóF˜'26ˆÊfñwW&VBñWC¬ˆ#‰6∆ñ6≤FB÷ˆÊóF˜"FÚ7&VFRñ˜W"fó'7BÊWGv˜&≤ÜV«FÇ6ÜV6≤„¬ˆFóc„¬˜FC„¬˜G#‚w÷6F6ÇÜRó∂÷ˆÊóF˜%&˜w2ÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#Ç"6∆73“&V◊Gí#‰÷ˆÊóF˜&ñÊrFFVÊfñ∆&∆S¢r∂W62ÜRÊ÷W76vRí≤s¬˜FC„¬˜G#‚w◊–¶7ñÊ2gVÊ7Fñˆ‚'V‰÷ˆÊóF˜'2Çó∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆ÷ˆÊóF˜&ñÊr˜'V‚r«∂÷WFÜˆC¢uı5Bw“ì∂vóB∆ˆD÷ˆÊóF˜&ñÊrÇì∂vóB∆ˆDfñÊFñÊw2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B'V‚÷ˆÊóF˜'3¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚'V‰÷ˆÊóF˜"ÜñBó∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆ÷ˆÊóF˜&ñÊr˜6WGFñÊw2Úr∂ñB≤r˜'V‚r«∂÷WFÜˆC¢uı5Bw“ì∂vóB∆ˆD÷ˆÊóF˜&ñÊrÇì∂vóB∆ˆDfñÊFñÊw2Çó÷6F6ÇÜRó∂∆W'BÇt÷ˆÊóF˜"fñ∆VC¢r∂RÊ÷W76vRó◊–¶gVÊ7Fñˆ‚˜V‰÷ˆÊóF˜$VFóF˜"ÜñC÷ÁV∆¬ó¥TDïEÙ‘Ù‰ïDı%ÙîC÷ñC∂6ˆÁ7BÉ÷ñCÙ‘Ù‰ïDı%2ÊfñÊBÜ””Ê“ÊñC””÷ñBì¶ÁV∆√∂÷ˆÊóF˜$÷ˆF≈FóF∆RÁFWáD6ˆÁFVÁC◊ÉÚtVFóB÷ˆÊóF˜"s¢tFB÷ˆÊóF˜"s∂÷ˆ‰Ê÷RÁf«VS◊ÉÚÊÊ÷W«¬rs∂÷ˆ‰∂ñÊBÁf«VS◊ÉÚÊ∂ñÊG«¬wvV'6óFRs∂÷ˆÂF&vWBÁf«VS◊ÉÚÁF&vWC””“rÜWFÚísÚrs¢áÉÚÁF&vWG«¬rrì∂÷ˆ‰ñÁFW'f¬Áf«VS◊ÉÚÊñÁFW'f≈˜6V6ˆÊG7«√3∂÷ˆ‰VÊ&∆VBÁf«VS◊ÉÚáÇÊVÊ&∆VCÚss¢srì¢ss∑G'ó∂÷ˆ‰˜FñˆÁ2Áf«VS‘•4Ù‚Á7G&ñÊvñgíÑ•4Ù‚Á'6RáÉÚÊ˜FñˆÁ5ˆß6ˆÁ«¬w∑“rí∆ÁV∆¬√"ó÷6F6ÇÖÚó∂÷ˆ‰˜FñˆÁ2Áf«VS“w∑“w÷÷ˆÊóF˜$VFóF˜$˜WBÁFWáD6ˆÁFVÁC“rs∂÷ˆÊóF˜$÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑6WEFñ÷V˜WBÇÇì”Ê÷ˆ‰Ê÷SÚÊfˆ7W2Çí√ó–¶gVÊ7Fñˆ‚6∆˜6T÷ˆÊóF˜$VFóF˜"Çó∂÷ˆÊóF˜$÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚6fT÷ˆÊóF˜"Çó∑G'ó∂∆WB˜FñˆÁ3◊∑”∑G'ó∂˜FñˆÁ3‘•4Ù‚Á'6RÜ÷ˆ‰˜FñˆÁ2Áf«VW«¬w∑“ró÷6F6ÇÖÚó∑Fá&˜rÊWrW'&˜"Çt˜FñˆÁ2◊W7B&Rf∆ñB•4Ù‚ró÷6ˆÁ7B&ˆGì◊∂Ê÷S¶÷ˆ‰Ê÷RÁf«VRÁG&ñ“Çí∆∂ñÊC¶÷ˆ‰∂ñÊBÁf«VR«F&vWC¶÷ˆÂF&vWBÁf«VRÁG&ñ“Çí∆ñÁFW'f≈˜6V6ˆÊG3¢∂÷ˆ‰ñÁFW'f¬Áf«VR∆VÊ&∆VC¶÷ˆ‰VÊ&∆VBÁf«VS””“sr∆˜FñˆÁ7”∂6ˆÁ7BW&√‘TDïEÙ‘Ù‰ïDı%ÙîCÚrˆí˜cˆ÷ˆÊóF˜&ñÊr˜6WGFñÊw2Úr¥TDïEÙ‘Ù‰ïDı%ÙîC¢rˆí˜cˆ÷ˆÊóF˜&ñÊr˜6WGFñÊw2s∂vóBß6ˆ‚áW&¬«∂÷WFÜˆC§TDïEÙ‘Ù‰ïDı%ÙîCÚuUBs¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂6∆˜6T÷ˆÊóF˜$VFóF˜"Çì∂vóB∆ˆD÷ˆÊóF˜&ñÊrÇó÷6F6ÇÜRó∂÷ˆÊóF˜$VFóF˜$˜WBÁFWáD6ˆÁFVÁC÷RÊ÷W76vW◊–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFT÷ˆÊóF˜"ÜñBó∂ñbÇ6ˆÊfó&“ÇtFV∆WFRFÜó2÷ˆÊóF˜"ÊBóG26ÜV6≤Üó7F˜'ìÚríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆ÷ˆÊóF˜&ñÊr˜6WGFñÊw2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆD÷ˆÊóF˜&ñÊrÇó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFR÷ˆÊóF˜#¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDfñÊFñÊw2Çó∑G'ó∂∆WB˜V„÷vóBß6ˆ‚Çrˆí˜cˆñÁFV∆∆ñvVÊ6Rˆó77VW3˜7FGW3÷˜V‚rì∂∆WB&W6ˆ«fVC÷vóBß6ˆ‚Çrˆí˜cˆñÁFV∆∆ñvVÊ6Rˆó77VW3˜7FGW3◊&W6ˆ«fVBrì∂∆WB∆√÷˜V‚Ê6ˆÊ6Bá&W6ˆ«fVBì∂fñÊFñÊt˜V‚ÁFWáD6ˆÁFVÁC÷˜V‚Ê∆VÊwFÉ∂fñÊFñÊu&W6ˆ«fVBÁFWáD6ˆÁFVÁC◊&W6ˆ«fVBÊ∆VÊwFÉ∂fñÊFñÊt∆¬ÁFWáD6ˆÁFVÁC÷∆¬Ê∆VÊwFÉ∂fñÊFñÊt7&óFñ6¬ÁFWáD6ˆÁFVÁC÷∆¬Êfñ«FW"áÉ”Â≤v7&óFñ6¬r¬vÜñvÇu“ÊñÊ6«VFW2ÇáÇÁ6WfW&óGó«¬rríÁFÙ∆˜vW$66RÇíííÊ∆VÊwFÉ∂∆WB&FvS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvfñÊFñÊt&FvRrì∂ñbÜ&FvRñ&FvRÁFWáD6ˆÁFVÁC÷˜V‚Ê∆VÊwFÉ∂fñÊFñÊu&˜w2ÊñÊÊW$ÖD‘√÷∆¬Ê∆VÊwFÉˆ∆¬Ê÷áÉ”Ê«G#„«FC„«7‚6∆73“'7FGW2÷&FvR6WfW&óGí“G∂W62ÇáÇÁ6WfW&óGó«¬vñÊfÚríÁFÙ∆˜vW$66RÇíó“#‚G∂W62áÇÁ6WfW&óGó«¬tñÊfÚró”¬˜7„„¬˜FC„«FC„∆Fób6∆73“&Ê÷R#‚G∂W62áÇÁFóF∆W««ÇÊó77VU˜GóW«¬tfñÊFñÊrró”¬ˆFóc„∆Fób6∆73“&◊WFVB#‚G∂W62áÇÁ&V6ˆ÷÷VÊFFñˆÁ«¬rró”¬ˆFóc„¬˜FC„«FC‚G∂W62áÇÁF&vWG«¬~(	Bró”¬˜FC„«FC‚G∑ÇÊfó'7E˜6VV„ˆW62ÜÊWrFFRáÇÊfó'7E˜6VV‚íÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC„«7‚6∆73“'7FGW2÷&FvR#‚G∂W62áÇÁ7FGW7«¬v˜V‚ró”¬˜7„„¬˜FC„«FC‚G∑ÇÁ7FGW3””“v˜V‚sˆ∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“'6Ü˜u7VvvW7FVDfóÇÇG∑ÇÊñG“í#Â7VvvW7FVBfóÉ¬ˆ'WGFˆ„‚∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“'&V6ÜV6¥fñÊFñÊrÇG∑ÇÊñG“í#Â&V6ÜV6≥¬ˆ'WGFˆ„‚∆'WGFˆ‚6∆73“&∆ñÊ≤˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&7&VFUFñ6∂WDg&ˆ‘ÊWGv˜&¥fñÊFñÊrÇG∑ÇÊñG“í#‰7&VFRFñ6∂WC¬ˆ'WGFˆ„‚∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“'&W6ˆ«fTfñÊFñÊrÇG∑ÇÊñG“í#Â&W6ˆ«fS¬ˆ'WGFˆ„Ê¢~(	Bw”¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#b"6∆73“&V◊Gí#‰ÊÚfñÊFñÊw2ñWB„¬˜FC„¬˜G#‚w÷6F6ÇÜRó∂fñÊFñÊu&˜w2ÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#b"6∆73“&V◊Gí#‰fñÊFñÊw2VÊfñ∆&∆S¢r∂W62ÜRÊ÷W76vRí≤s¬˜FC„¬˜G#‚w◊–¶7ñÊ2gVÊ7Fñˆ‚6Ü˜u7VvvW7FVDfóÇÜñBó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆñÁFV∆∆ñvVÊ6Rˆó77VW2Úr∂ñB≤r˜7VvvW7FVB÷fóÇrì∂∆W'Bá"ÁFóF∆R≤u∆Â∆‚r≤á"Á&V6ˆ÷÷VÊFFñˆÁ«¬rrí≤u∆Â∆‚r≤á"Ê7FñˆÁ7«≈µ“íÊ÷ÇáÇ∆íì”‚Üí≥í≤r‚r∑ÇíÊ¶ˆñ‚Çu∆‚ríó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B∆ˆB7VvvW7FVBfóÉ¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚&V6ÜV6¥fñÊFñÊrÜñBó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆñÁFV∆∆ñvVÊ6Rˆó77VW2Úr∂ñB≤r˜&V6ÜV6≤r«∂÷WFÜˆC¢uı5Bw“ì∂∆W'Bá"Êˆ≥Úu&V6ÜV6≤6ˆ◊∆WFVB7V66W76gV∆«í‚s¢u&V6ÜV6≤6ˆ◊∆WFVC≤FÜR6ˆÊFóFñˆ‚÷í7Fñ∆¬&R&W6VÁB‚rì∂vóB∆ˆDfñÊFñÊw2Çì∂vóB∆ˆD÷ˆÊóF˜&ñÊrÇì∂vóB∆ˆDñÁfVÁF˜'íÇó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B&V6ÜV6≤fñÊFñÊs¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚&W6ˆ«fTfñÊFñÊrÜñBó∂ñbÇ6ˆÊfó&“Çt÷&≤FÜó2fñÊFñÊr&W6ˆ«fVCÚríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆñÁFV∆∆ñvVÊ6Rˆó77VW2Úr∂ñB≤r˜&W6ˆ«fRr«∂÷WFÜˆC¢uı5Bw“ì∂vóB∆ˆDfñÊFñÊw2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B&W6ˆ«fRfñÊFñÊs¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚7&VFUFñ6∂WDg&ˆ‘ÊWGv˜&¥fñÊFñÊrÜñBó∑G'ó∂6ˆÁ7BFñ6∂WC÷vóBß6ˆ‚Çrˆí˜cˆñÁFV∆∆ñvVÊ6Rˆó77VW2Úr∂ñB≤rˆ7&VFR◊Fñ6∂WBr«∂÷WFÜˆC¢uı5Bw“ì∑6Ü˜ufñWrÇwFñ6∂WG2r«G'VRì∂vóB∆ˆEFñ6∂WG2Çì∂˜VÂFñ6∂WDVFóF˜"áFñ6∂WBÊñBó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B7&VFRFñ6∂WC¢r∂RÊ÷W76vRó◊–††¶∆WBîÂDTu$DîÙÂ3’µ“ƒ‰≈ïDî55ÙïDT’3’µ“ƒ5U%$TÂEÙ‰≈ïDî53÷ÁV∆√∞¶gVÊ7Fñˆ‚ñÁFVw&Fñˆ‰∂ñÊD∆&V¬Ü≤ó∑&WGW&‚≥””“wñÜˆ∆RsÚuí÷Üˆ∆Rs¶≥””“wVÊñfísÚuVÊîfís¢u4‰’w–¶gVÊ7Fñˆ‚ñÁFVw&Fñˆ‰ñ6ˆ‚Ü≤ó∑&WGW&‚≥””“wñÜˆ∆RsÚ|¯s¶≥””“wVÊñfísÚuRs¢u2w–¶gVÊ7Fñˆ‚ñÁFVw&Fñˆ‰6&BÜ2ó∂6ˆÁ7B7FFS÷2Ê∆7E˜7ñÊ5˜7FGW7«¬vÊWfW"s∑&WGW&‚∆Fób6∆73“&ñÁFVw&Fñˆ‚÷6&B#„∆Fób6∆73“&ñÁFVw&Fñˆ‚÷6&B÷ÜVB#„∆Fób7Gñ∆S“&Fó7∆ì¶f∆WÉ∂v£óÉ∂∆ñv‚÷óFV◊3¶6VÁFW"#„∆Fób6∆73“'Fˆˆ¬÷ñ6ˆ‚"7Gñ∆S“'vñGFÉ£3GÉ∂ÜVñváC£3GÉ∂÷&vñ„£#‚G∂ñÁFVw&Fñˆ‰ñ6ˆ‚Ü2Ê∂ñÊBó”¬ˆFóc„∆Fóc„∆#‚G∂W62Ü2ÊÊ÷W«∆ñÁFVw&Fñˆ‰∂ñÊD∆&V¬Ü2Ê∂ñÊBíó”¬ˆ#„∆Fóc„«7‚6∆73“&ñÁFVw&Fñˆ‚÷&FvR#‚G∂ñÁFVw&Fñˆ‰∂ñÊD∆&V¬Ü2Ê∂ñÊBó”¬˜7„„¬ˆFóc„¬ˆFóc„¬ˆFóc„«7‚6∆73“&ñÁFVw&Fñˆ‚◊7FFRG∑7FFW“#‚G∂W62á7FFRó”¬˜7„„¬ˆFóc„∆Fób6∆73“&ñÁFVw&Fñˆ‚÷÷WF#„∆Fóc„∆#ÂF&vWC£¬ˆ#‚G∂W62Ü2ÁF&vWG«¬~(	Bró”¬ˆFóc„∆Fóc„∆#‰∆7B7ñÊ3£¬ˆ#‚G∂2Ê∆7E˜7ñÊ5ˆCˆÊWrFFRÜ2Ê∆7E˜7ñÊ5ˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì¢tÊWfW"w”¬ˆFóc‚G∂2Ê∆7E˜7ñÊ5ˆW'&˜#ˆ∆Fób7Gñ∆S“&6ˆ∆˜#¢63s63S#‚G∂W62Ü2Ê∆7E˜7ñÊ5ˆW'&˜"ó”¬ˆFócÊ¢rw”∆Fóc‚G∂2ÊVÊ&∆VCÚ~)xÚVÊ&∆VBs¢~)x≤Fó6&∆VBw“+rWfW'íG∂2Á7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG7«√3◊2G∂2ÊÜ5˜6V7&WCÚ|+r7&VFVÁFñ¬6fVBs¢rw”¬ˆFóc„¬ˆFóc„∆Fób6∆73“&ñÁFVw&Fñˆ‚÷7FñˆÁ2#„∆'WGFˆ‚6∆73“'6V6ˆÊF'í"ˆÊ6∆ñ6≥“'7ñÊ4ñÁFVw&Fñˆ‚ÇG∂2ÊñG“í#ÂFW7Bb7ñÊ3¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“'6V6ˆÊF'íF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜V‰ñÁFVw&Fñˆ‰÷ˆF¬ÇG∂2ÊñG“í#‰VFóC¬ˆ'WGFˆ„„∆'WGFˆ‚6∆73“&ñÁFVw&Fñˆ‚◊&V÷˜fRF÷ñ‚÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜V‰FV∆WFTñÁFVw&Fñˆ‰÷ˆF¬ÇG∂2ÊñG“í"FóF∆S“%&V÷˜fRFÜó2ñÁFVw&Fñˆ‚#Â&V÷˜fS¬ˆ'WGFˆ„„¬ˆFóc„¬ˆFócÊ–¶gVÊ7Fñˆ‚Ê«óFñ746&BÜó∂6ˆÁ7BC÷ÊÊ«óFñ77««∑”∂∆WB÷ñ„“~(	Br∆∆&V√“t∆FW7B6Ê6Ü˜Bs∂ñbÜÁ6˜W&6S””“wñÜˆ∆Rró∂÷ñ„÷BÁVW&ñW3ÛˆBÁF˜F≈˜VW&ñW3ÛÚ~(	Bs∂∆&V√“tDÂ2VW&ñW2w÷V«6RñbÜÁ6˜W&6S””“wVÊñfíró∂÷ñ„÷BÊ7FófUˆ6∆ñVÁG3ÛÚ~(	Bs∂∆&V√“t7FófR6∆ñVÁG2w÷V«6RñbÜÁ6˜W&6S””“w6Ê◊ró∂÷ñ„÷BÊÊVñvÜ&˜'3ÛÚ~(	Bs∂∆&V√“tÊVñvÜ&˜'2w◊&WGW&‚∆'WGFˆ‚6∆73“&Ê«óFñ72÷6&B"ˆÊ6∆ñ6≥“&˜V‰Ê«óFñ72ÇG∂ÊñÁFVw&FñˆÂˆñG“í#„∆Fób7Gñ∆S“&Fó7∆ì¶f∆WÉ∂ßW7Fñgí÷6ˆÁFVÁCß76R÷&WGvVV„∂v£áÇ#„∆#‚G∂W62ÜÊñÁFVw&FñˆÂˆÊ÷W«∆ñÁFVw&Fñˆ‰∂ñÊD∆&V¬ÜÁ6˜W&6Ríó”¬ˆ#„«7‚6∆73“&ñÁFVw&Fñˆ‚÷&FvR#‚G∂ñÁFVw&Fñˆ‰∂ñÊD∆&V¬ÜÁ6˜W&6Ró”¬˜7„„¬ˆFóc„∆Fób6∆73“&÷WG&ñ2#‚G∂W62Ü÷ñ‚ó”¬ˆFóc„∆Fób6∆73“'7V"#‚G∂∆&V«“+rG∂Ê6GW&VEˆCˆÊWrFFRÜÊ6GW&VEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì¢tÊÚFñ÷W7F◊w”¬ˆFóc„∆Fób6∆73“'7V"#‰6∆ñ6≤f˜"gV∆¬Ê«óFñ73¬ˆFóc„¬ˆ'WGFˆ„Ê–¶gVÊ7Fñˆ‚«ï&ˆ∆Ufó6ñ&ñ∆óGíÇó∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊF÷ñ‚÷ˆÊ«íríÊf˜$V6ÇÜV√”ÊV¬Ê6∆74∆ó7BÁFˆvv∆RÇvF÷ñ‚◊fó6ñ&∆Rr¬‘Rbd‘RÁ&ˆ∆S””“vF÷ñ‚ríì∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ˜W&FR÷ˆÊ«íríÊf˜$V6ÇÜV√”ÊV¬Ê6∆74∆ó7BÁFˆvv∆RÇv˜W&FR◊fó6ñ&∆Rr¬‘Rbe≤vF÷ñ‚r¬v˜W&F˜"u“ÊñÊ6«VFW2Ñ‘RÁ&ˆ∆Rííì∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDñÁFVw&FñˆÁ2Çó∑G'ó∂6ˆÁ7B∑"∆∆Â”÷vóB&ˆ÷ó6RÊ∆¬Ö∂ß6ˆ‚Çrˆí˜cˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2rí∆ß6ˆ‚Çrˆí˜cˆÊ«óFñ72ˆ6∆ñVÁG2rí∆ß6ˆ‚Çrˆí˜cˆÊ˜Fñfñ6FñˆÁ2ˆ6ˆÊfñrríÊ6F6ÇÇÇì”ÊÁV∆¬ï“ì¥îÂDTu$DîÙÂ3◊"Ê6ˆÊfñw7«≈µ”¥‰≈ïDî55ÙïDT’3÷ÊñÁFVw&FñˆÂˆÊ«óFñ77«≈µ”∂ñÁFVw&FñˆÂ7V÷÷'íÁFWáD6ˆÁFVÁC‘îÂDTu$DîÙÂ2Ê∆VÊwFÇ≤r6ˆÊfñwW&VBñÁFVw&Fñˆ‚r≤ÑîÂDTu$DîÙÂ2Ê∆VÊwFÉ”””Úrs¢w2rí≤r+rr¥îÂDTu$DîÙÂ2Êfñ«FW"áÉ”ÁÇÊVÊ&∆VBíÊ∆VÊwFÇ≤rVÊ&∆VBs∂ñÁFVw&Fñˆ‰∆ó7BÊñÊÊW$ÖD‘√‘îÂDTu$DîÙÂ2Ê∆VÊwFÉÙîÂDTu$DîÙÂ2Ê÷ÜñÁFVw&Fñˆ‰6&BíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“'ÊV¬V◊Gí"7Gñ∆S“&w&ñB÷6ˆ«V÷„£Ú”#‰ÊÚñÁFVw&FñˆÁ26ˆÊfñwW&VB‚FBñ˜W"fó'7Bí÷Üˆ∆R¬VÊîfí¬˜"4‰’6ˆ∆∆V7F˜"„¬ˆFóc‚s∂ñÁFVw&Fñˆ‰Ê«óFñ72ÊñÊÊW$ÖD‘√‘‰≈ïDî55ÙïDT’2Ê∆VÊwFÉÙ‰≈ïDî55ÙïDT’2Ê÷ÜÊ«óFñ746&BíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí"7Gñ∆S“&w&ñB÷6ˆ«V÷„£Ú”#‰ÊÚ&WFñÊVB6∆ñVÁB˜VW'íÊ«óFñ72‚'V‚‚ñÁFVw&Fñˆ‚7ñÊ2FÚ6ˆ∆∆V7BÊ«óFñ72„¬ˆFóc‚s∂«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∂ñbÜ‚ó∂Ê˜FñgïvV&Üˆˆ≤Áf«VS÷‚ÁvV&Üˆˆµ˜W&««¬rs∂Ê˜FñgîÁFgï6W'fW"Áf«VS÷‚ÊÁFgï˜6W'fW'«¬váGG3¢ÚˆÁFgíÁ6Çs∂Ê˜FñgîÁFgíÁf«VS÷‚ÊÁFgï˜F˜ñ7«¬rs∂Ê˜Fñgï6◊GÜ˜7BÁf«VS÷‚Á6◊GˆÜ˜7G«¬rs∂Ê˜Fñgï6◊G˜'BÁf«VS÷‚Á6◊G˜˜'G«√SÉs∂Ê˜Fñgï6◊GW6W"Áf«VS÷‚Á6◊G˜W6W'«¬rs∂Ê˜Fñgï6◊Gg&ˆ“Áf«VS÷‚Á6◊Gˆg&ˆ◊«¬rs∂Ê˜FñgîV÷ñ¬Áf«VS÷‚Á6◊G˜F˜«¬rs∂Ê˜Fñgï6◊G72Á∆6VÜˆ∆FW#÷‚ÊÜ5˜6◊G˜77v˜&CÚu4’E77v˜&B6fVB(	B&∆Ê≤∂VW2óBs¢u4’E77v˜&Bs∂Ê˜Fñgï6WfW&óGíÁf«VS÷‚Ê÷ñÂ˜6WfW&óGó«¬wv&ÊñÊrw◊÷6F6ÇÜRó∂ñÁFVw&Fñˆ‰∆ó7BÊñÊÊW$ÖD‘√“s∆Fób6∆73“'ÊV¬V◊Gí"7Gñ∆S“&w&ñB÷6ˆ«V÷„£Ú”#‰ñÁFVw&FñˆÁ2VÊfñ∆&∆S¢r∂W62ÜRÊ÷W76vRí≤s¬ˆFóc‚w◊–¶gVÊ7Fñˆ‚WFFTñÁFVw&Fñˆ‰fñV∆G2Çó∂6ˆÁ7B≥÷ñÁFVw&Fñˆ‰∂ñÊBÁf«VS∂ñÁFVw&FñˆÂW6W%w&Á7Gñ∆RÊFó7∆ì÷≥””“wVÊñfísÚvf∆WÇs¢vÊˆÊRs∂ñÁFVw&FñˆÂ6óFUw&Á7Gñ∆RÊFó7∆ì÷≥””“wVÊñfísÚvf∆WÇs¢vÊˆÊRs∂ñÁFVw&FñˆÂF«2Á&VÁDV∆V÷VÁBÁ7Gñ∆RÊFó7∆ì÷≥””“w6Ê◊sÚvÊˆÊRs¢vf∆WÇs∂ñÁFVw&FñˆÂ6V7&WBÁ∆6VÜˆ∆FW#÷≥””“wñÜˆ∆RsÚt∆ñ6Fñˆ‚77v˜&BÚí7&VFVÁFñ¬s¶≥””“wVÊñfísÚt6ˆÁG&ˆ∆∆W"77v˜&Bs¢u4‰’6ˆ÷◊VÊóGíw–¶gVÊ7Fñˆ‚˜V‰ñÁFVw&Fñˆ‰÷ˆF¬ÜñC÷ÁV∆¬ó∂6ˆÁ7B3÷ñCÙîÂDTu$DîÙÂ2ÊfñÊBáÉ”ÁÇÊñC””÷ñBì¶ÁV∆√∂ñÁFVw&Fñˆ‰ñBÁf«VS÷3ÚÊñG«¬rs∂ñÁFVw&Fñˆ‰÷ˆF≈FóF∆RÁFWáD6ˆÁFVÁC÷3ÚtVFóBñÁFVw&Fñˆ‚s¢tFBñÁFVw&Fñˆ‚s∂ñÁFVw&Fñˆ‰Ê÷RÁf«VS÷3ÚÊÊ÷W«¬rs∂ñÁFVw&Fñˆ‰∂ñÊBÁf«VS÷3ÚÊ∂ñÊG«¬wñÜˆ∆Rs∂ñÁFVw&Fñˆ‰∂ñÊBÊFó6&∆VC“3∂ñÁFVw&FñˆÂF&vWBÁf«VS÷3ÚÁF&vWG«¬rs∂ñÁFVw&FñˆÂW6W"Áf«VS÷3ÚÁW6W&Ê÷W«¬rs∂ñÁFVw&FñˆÂ6V7&WBÁf«VS“rs∂ñÁFVw&FñˆÂ6óFRÁf«VS“vFVfV«Bs∑G'ó∂ñbÜ3ÚÊ˜FñˆÁ5ˆß6ˆ‚ññÁFVw&FñˆÂ6óFRÁf«VS‘•4Ù‚Á'6RÜ2Ê˜FñˆÁ5ˆß6ˆ‚íÁ6óFW«¬vFVfV«Bw÷6F6ÇÖÚó∑÷ñÁFVw&Fñˆ‰ñÁFW'f¬Áf«VS÷3ÚÁ7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG7«√3∂ñÁFVw&Fñˆ‰VÊ&∆VBÊ6ÜV6∂VC÷3Ú2ÊVÊ&∆VCßG'VS∂ñÁFVw&FñˆÂF«2Ê6ÜV6∂VC÷3Ú2ÁfW&ñgï˜F«3ßG'VS∂ñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∑WFFTñÁFVw&Fñˆ‰fñV∆G2Çì∂ñÁFVw&Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑6WEFñ÷V˜WBÇÇì”ÊñÁFVw&Fñˆ‰Ê÷RÊfˆ7W2Çí√#ó–¶gVÊ7Fñˆ‚6∆˜6TñÁFVw&Fñˆ‰÷ˆF¬Çó∂ñÁFVw&Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rs∂ñÁFVw&Fñˆ‰∂ñÊBÊFó6&∆VC÷f«6W–¶7ñÊ2gVÊ7Fñˆ‚7V&÷óDñÁFVw&Fñˆ‚ÜRó∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BñC÷ñÁFVw&Fñˆ‰ñBÁf«VS∂6ˆÁ7B∂ñÊC÷ñÁFVw&Fñˆ‰∂ñÊBÁf«VS∂6ˆÁ7B&ˆGì◊∂Ê÷S¶ñÁFVw&Fñˆ‰Ê÷RÁf«VRÁG&ñ“Çí∆∂ñÊB∆VÊ&∆VC¶ñÁFVw&Fñˆ‰VÊ&∆VBÊ6ÜV6∂VB«F&vWC¶ñÁFVw&FñˆÂF&vWBÁf«VRÁG&ñ“Çí«W6W&Ê÷S¶ñÁFVw&FñˆÂW6W"Áf«VRÁG&ñ“Çí«6V7&WC¶ñÁFVw&FñˆÂ6V7&WBÁf«VW«∆ÁV∆¬«fW&ñgï˜F«3¶ñÁFVw&FñˆÂF«2Ê6ÜV6∂VB«7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG3¢∂ñÁFVw&Fñˆ‰ñÁFW'f¬Áf«VW«√3∆˜FñˆÁ3ß∑6óFS¶ñÁFVw&FñˆÂ6óFRÁf«VRÁG&ñ“Çó«¬vFVfV«Bw◊”∑G'ó∂vóBß6ˆ‚ÜñCÚrˆí˜cˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2Úr∂ñC¢rˆí˜cˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2r«∂÷WFÜˆC¶ñCÚuUBs¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂6∆˜6TñÁFVw&Fñˆ‰÷ˆF¬Çì∂vóB∆ˆDñÁFVw&FñˆÁ2Çó÷6F6ÇÜW'"ó∂ñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC÷W'"Ê÷W76vW◊&WGW&‚f«6W–¶∆WBDTƒUDUÙîÂDTu$DîÙÂÙîC÷ÁV∆√∞¶gVÊ7Fñˆ‚˜V‰FV∆WFTñÁFVw&Fñˆ‰÷ˆF¬ÜñBó∂6ˆÁ7B3‘îÂDTu$DîÙÂ2ÊfñÊBáÉ”ÁÇÊñC””÷ñBì∂ñbÇ2ó&WGW&„¥DTƒUDUÙîÂDTu$DîÙÂÙîC÷ñC∂FV∆WFTñÁFVw&Fñˆ‰6ˆÊfó&“Áf«VS“rs∂FV∆WFTñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∂FV∆WFTñÁFVw&FñˆÂ7V÷÷'íÊñÊÊW$ÖD‘√“s∆#‚r∂W62Ü2ÊÊ÷W«∆ñÁFVw&Fñˆ‰∂ñÊD∆&V¬Ü2Ê∂ñÊBíí≤s¬ˆ#„∆'#‚r∂W62ÜñÁFVw&Fñˆ‰∂ñÊD∆&V¬Ü2Ê∂ñÊBíí≤r+rr∂W62Ü2ÁF&vWG«¬tÊÚF&vWBrí≤s∆'#„∆'#ÂFÜó2&V÷˜fW2FÜR6fVBñÁFVw&Fñˆ‚¬óG27ñÊ2Üó7F˜'í¬ÊBóG2&WFñÊVBÊ«óFñ72‚FWfñ6RñÁfVÁF˜'íÊBFÜRVFóB∆ˆr&R&W6W'fVB‚s∂FV∆WFTñÁFVw&Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚s∑6WEFñ÷V˜WBÇÇì”ÊFV∆WFTñÁFVw&Fñˆ‰6ˆÊfó&“Êfˆ7W2Çí√#ó–¶gVÊ7Fñˆ‚6∆˜6TFV∆WFTñÁFVw&Fñˆ‰÷ˆF¬Çó∂FV∆WFTñÁFVw&Fñˆ‰÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs¥DTƒUDUÙîÂDTu$DîÙÂÙîC÷ÁV∆√∂FV∆WFTñÁFVw&Fñˆ‰6ˆÊfó&“Áf«VS“rs∂FV∆WFTñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rw–¶7ñÊ2gVÊ7Fñˆ‚6ˆÊfó&‘FV∆WFTñÁFVw&Fñˆ‚Çó∂ñbÇDTƒUDUÙîÂDTu$DîÙÂÙîBó&WGW&„∂ñbÜFV∆WFTñÁFVw&Fñˆ‰6ˆÊfó&“Áf«VRÁG&ñ“Çí”“u$T‘ıdRró∂FV∆WFTñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“uGóR$T‘ıdRWÜ7F«íFÚ6ˆÁFñÁVR‚s∂FV∆WFTñÁFVw&Fñˆ‰6ˆÊfó&“Êfˆ7W2Çì∑&WGW&Á÷FV∆WFTñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“rs∂FV∆WFTñÁFVw&Fñˆ‰'F‚ÊFó6&∆VC◊G'VS∂FV∆WFTñÁFVw&Fñˆ‰'F‚ÁFWáD6ˆÁFVÁC“u&V÷˜fñÊ~(
bs∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2Úr¥DTƒUDUÙîÂDTu$DîÙÂÙîB«∂÷WFÜˆC¢tDTƒUDRw“ì∂6∆˜6TFV∆WFTñÁFVw&Fñˆ‰÷ˆF¬Çì∂vóB∆ˆDñÁFVw&FñˆÁ2Çó÷6F6ÇÜRó∂FV∆WFTñÁFVw&Fñˆ‰W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B&V÷˜fRñÁFVw&Fñˆ„¢r∂RÊ÷W76vW÷fñÊ∆«ó∂FV∆WFTñÁFVw&Fñˆ‰'F‚ÊFó6&∆VC÷f«6S∂FV∆WFTñÁFVw&Fñˆ‰'F‚ÁFWáD6ˆÁFVÁC“u&V÷˜fRñÁFVw&Fñˆ‚w◊–¶7ñÊ2gVÊ7Fñˆ‚7ñÊ4ñÁFVw&Fñˆ‚ÜñBó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2Úr∂ñB≤r˜7ñÊ2r«∂÷WFÜˆC¢uı5Bw“ì∂∆W'BÇá"Êˆ≥Úu7ñÊ26ˆ◊∆WFRs¢u7ñÊ2fñ∆VBrí≤r+rr∑"Êˆ'6W'fFñˆÁ2≤rˆ'6W'fFñˆÁ2r≤á"ÊW'&˜#Úu∆‚r∑"ÊW'&˜#¢rríì∂vóB∆ˆDñÁFVw&FñˆÁ2Çì∂ñbá"Êˆ≤ñvóB∆ˆDÊWGv˜&≤Çó÷6F6ÇÜRó∂∆W'BÇu7ñÊ2fñ∆VC¢r∂RÊ÷W76vRó◊–¶gVÊ7Fñˆ‚˜V‰Ê«óFñ72ÜñBó¥5U%$TÂEÙ‰≈ïDî53‘‰≈ïDî55ÙïDT’2ÊfñÊBáÉ”ÁÇÊñÁFVw&FñˆÂˆñC””÷ñBì∂ñbÇ5U%$TÂEÙ‰≈ïDî52ó&WGW&„∂6ˆÁ7BC‘5U%$TÂEÙ‰≈ïDî52ÊÊ«óFñ77««∑”∂Ê«óFñ75FóF∆RÁFWáD6ˆÁFVÁC‘5U%$TÂEÙ‰≈ïDî52ÊñÁFVw&FñˆÂˆÊ÷W«∆ñÁFVw&Fñˆ‰∂ñÊD∆&V¬Ñ5U%$TÂEÙ‰≈ïDî52Á6˜W&6Rì∂Ê«óFñ757V'FóF∆RÁFWáD6ˆÁFVÁC÷ñÁFVw&Fñˆ‰∂ñÊD∆&V¬Ñ5U%$TÂEÙ‰≈ïDî52Á6˜W&6Rí≤r+r6GW&VBr≤Ñ5U%$TÂEÙ‰≈ïDî52Ê6GW&VEˆCˆÊWrFFRÑ5U%$TÂEÙ‰≈ïDî52Ê6GW&VEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì¢wVÊ∂Ê˜v‚rì∂6ˆÁ7B÷WG&ñ73’µ”∂ñbÜBÁVW&ñW2÷ÁV∆¬ñ÷WG&ñ72ÁW6ÇÖ≤uVW&ñW2r∆BÁVW&ñW5“ì∂ñbÜBÊ&∆ˆ6∂VB÷ÁV∆¬ñ÷WG&ñ72ÁW6ÇÖ≤t&∆ˆ6∂VBr∆BÊ&∆ˆ6∂VE“ì∂ñbÜBÊ6∆ñVÁG2÷ÁV∆¬ñ÷WG&ñ72ÁW6ÇÖ≤t6∆ñVÁG2r∆BÊ6∆ñVÁG5“ì∂ñbÜBÊ7FófUˆ6∆ñVÁG2÷ÁV∆¬ñ÷WG&ñ72ÁW6ÇÖ≤t7FófR6∆ñVÁG2r∆BÊ7FófUˆ6∆ñVÁG5“ì∂ñbÜBÁvñfïˆ6∆ñVÁG2÷ÁV∆¬ñ÷WG&ñ72ÁW6ÇÖ≤uví‘fí6∆ñVÁG2r∆BÁvñfïˆ6∆ñVÁG5“ì∂ñbÜBÊÊVñvÜ&˜'2÷ÁV∆¬ñ÷WG&ñ72ÁW6ÇÖ≤tÊVñvÜ&˜'2r∆BÊÊVñvÜ&˜'5“ì∂Ê«óFñ757V÷÷'íÊñÊÊW$ÖD‘√“Ü÷WG&ñ72Á6∆ñ6RÉ√2íÊ÷áÉ”Ê∆Fóc„∆#‚G∂W62áÖ≥“ó”¬ˆ#„«7„‚G∂W62áÖ≥“ó”¬˜7„„¬ˆFócÊíÊ¶ˆñ‚Çrró«¬s∆Fóc„∆#Ó)…3¬ˆ#„«7„‰Ê«óFñ726Ê6Ü˜C¬˜7„„¬ˆFóc‚rì∂Ê«óFñ74FWFñ¬ÁFWáD6ˆÁFVÁC‘•4Ù‚Á7G&ñÊvñgíÜB∆ÁV∆¬√"ì∂Ê«óFñ746∆V%&V6ˆ‚Áf«VS“rs∂Ê«óFñ746∆V$W'"ÁFWáD6ˆÁFVÁC“rs∂Ê«óFñ74÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“vÜñFFV‚w–¶gVÊ7Fñˆ‚6∆˜6TÊ«óFñ74÷ˆF¬Çó∂Ê«óFñ74÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊ&ˆGíÁ7Gñ∆RÊ˜fW&f∆˜s“rs¥5U%$TÂEÙ‰≈ïDî53÷ÁV∆«–¶gVÊ7Fñˆ‚6∆V$7W'&VÁDÊ«óFñ72Çó∂ñbÇ5U%$TÂEÙ‰≈ïDî52ó&WGW&„∂6ˆÁ7B&V6ˆ„÷Ê«óFñ746∆V%&V6ˆ‚Áf«VRÁG&ñ“Çì∂Ê«óFñ746∆V$W'"ÁFWáD6ˆÁFVÁC“rs∂ñbá&V6ˆ‚Ê∆VÊwFÉ√Ró∂Ê«óFñ746∆V$W'"ÁFWáD6ˆÁFVÁC“u∆V6R&˜fñFR&V6ˆ‚ˆbB∆V7BR6Ü&7FW'2‚s∂Ê«óFñ746∆V%&V6ˆ‚Êfˆ7W2Çì∑&WGW&Á÷6∆V$ˆÊTÊ«óFñ74'F‚ÊFó6&∆VC◊G'VS∂ß6ˆ‚Çrˆí˜cˆÊ«óFñ72ˆ6∆V"Úr¥5U%$TÂEÙ‰≈ïDî52ÊñÁFVw&FñˆÂˆñB«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑&V6ˆÁ“ó“íÁFÜV‚á#”Á∂6∆˜6TÊ«óFñ74÷ˆF¬Çì∂∆ˆDñÁFVw&FñˆÁ2Çì∂∆W'BÇtÊ«óFñ726∆V&VB'ír∑"Ê6∆V&VEˆ'í≤r‚r∑"ÊFV∆WFVB≤r&V6˜&Bá2í&V÷˜fVB‚ró“íÊ6F6ÇÜS”Á∂Ê«óFñ746∆V$W'"ÁFWáD6ˆÁFVÁC“t6˜V∆BÊ˜B6∆V"Ê«óFñ73¢r∂RÊ÷W76vW“íÊfñÊ∆«íÇÇì”Á∂6∆V$ˆÊTÊ«óFñ74'F‚ÊFó6&∆VC÷f«6W“ó–¶7ñÊ2gVÊ7Fñˆ‚6fTÊ˜Fñfñ6FñˆÁ2Çó∑G'ó∂6ˆÁ7B&ˆGì◊∑vV&ÜˆˆµˆVÊ&∆VC¢Ê˜FñgïvV&Üˆˆ≤Áf«VRÁG&ñ“Çí«vV&Üˆˆµ˜W&√¶Ê˜FñgïvV&Üˆˆ≤Áf«VRÁG&ñ“Çí∆ÁFgïˆVÊ&∆VC¢Ê˜FñgîÁFgíÁf«VRÁG&ñ“Çí∆ÁFgï˜6W'fW#¶Ê˜FñgîÁFgï6W'fW"Áf«VRÁG&ñ“Çó«¬váGG3¢ÚˆÁFgíÁ6Çr∆ÁFgï˜F˜ñ3¶Ê˜FñgîÁFgíÁf«VRÁG&ñ“Çí«6◊GˆVÊ&∆VC¢ÜÊ˜Fñgï6◊GÜ˜7BÁf«VRÁG&ñ“ÇíbfÊ˜Fñgï6◊Gg&ˆ“Áf«VRÁG&ñ“ÇíbfÊ˜FñgîV÷ñ¬Áf«VRÁG&ñ“Çíí«6◊GˆÜ˜7C¶Ê˜Fñgï6◊GÜ˜7BÁf«VRÁG&ñ“Çí«6◊G˜˜'C¢∂Ê˜Fñgï6◊G˜'BÁf«VW«√SÉr«6◊G˜W6W#¶Ê˜Fñgï6◊GW6W"Áf«VRÁG&ñ“Çí«6◊G˜77v˜&C¶Ê˜Fñgï6◊G72Áf«VW«∆ÁV∆¬«6◊Gˆg&ˆ”¶Ê˜Fñgï6◊Gg&ˆ“Áf«VRÁG&ñ“Çí«6◊G˜FÛ¶Ê˜FñgîV÷ñ¬Áf«VRÁG&ñ“Çí∆÷ñÂ˜6WfW&óGì¶Ê˜Fñgï6WfW&óGíÁf«VW”∂vóBß6ˆ‚Çrˆí˜cˆÊ˜Fñfñ6FñˆÁ2ˆ6ˆÊfñrr«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂Ê˜Fñgï6◊G72Áf«VS“rs∂Ê˜Fñgî˜WBÁFWáD6ˆÁFVÁC“u6fVB‚w÷6F6ÇÜRó∂Ê˜Fñgî˜WBÁFWáD6ˆÁFVÁC÷RÊ÷W76vW◊–¶7ñÊ2gVÊ7Fñˆ‚FW7DÊ˜Fñfñ6FñˆÁ2Çó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆÊ˜Fñfñ6FñˆÁ2˜FW7Br«∂÷WFÜˆC¢uı5Bw“ì∂Ê˜Fñgî˜WBÁFWáD6ˆÁFVÁC“uFW7BGFV◊FVC¢r∑"Á6VÁB≤r6ÜÊÊV¬á2í6VÁBr≤á"ÊW'&˜'3ÚÊ∆VÊwFÉÚr+rr∑"ÊW'&˜'2Ê¶ˆñ‚Çs≤rì¢rró÷6F6ÇÜRó∂Ê˜Fñgî˜WBÁFWáD6ˆÁFVÁC÷RÊ÷W76vW◊–¶gVÊ7Fñˆ‚f◊D'óFW2ábó∑c‘ÁV÷&W"ág«√ì∂ñbác√#Bó&WGW&‚b≤r"s∂ñbác√CÉSsbó&WGW&‚ábÛ#BíÁFÙfóÜVBÉí≤r¥"s∂ñbác√s3sCÉ#Bó&WGW&‚ábÛCÉSsbíÁFÙfóÜVBÉí≤r‘"s∑&WGW&‚ábÛs3sCÉ#BíÁFÙfóÜVBÉ"í≤rt"w–¶gVÊ7Fñˆ‚f◊E&FRábó∑c‘ÁV÷&W"ág«√ì∂ñbác√ó&WGW&‚÷FÇÁ&˜VÊBábí≤r'2s∂ñbác√ó&WGW&‚ábÛíÁFÙfóÜVBÉí≤r∂'2s∂ñbác√ó&WGW&‚ábÛíÁFÙfóÜVBÉí≤r÷'2s∑&WGW&‚ábÛíÁFÙfóÜVBÉ"í≤rv'2w–¶∆WBG&ffñ46ˆÊfñuñ∆ˆC÷ÁV∆√∞¶gVÊ7Fñˆ‚6V∆V7EG&ffñ4÷ˆFRÜ÷ˆFRó∞¢G&ffñ4÷ˆFRÁf«VS÷÷ˆFS∞¢6ˆÁ7BñÁG3“áG&ffñ46ˆÊfñuñ∆ˆCÚÊñÁFVw&FñˆÁ7«≈µ“íÊfñ«FW"áÉ”ÁÇÊ∂ñÊC””÷÷ˆFRì∞¢G&ffñ4ñÁFVw&Fñˆ‚ÊñÊÊW$ÖD‘√÷ñÁG2Ê÷áÉ”Ê∆˜Fñˆ‚f«VS“"G∑ÇÊñG“#‚G∂W62áÇÊÊ÷Ró“(	BG∂W62áÇÁF&vWBó”¬ˆ˜Fñˆ„ÊíÊ¶ˆñ‚Çrró«¬s∆˜Fñˆ‚f«VS“"#‰ÊÚ÷F6ÜñÊrñÁFVw&Fñˆ‚6ˆÊfñwW&VC¬ˆ˜Fñˆ„‚s∞¢&VÊFW%G&ffñ4÷ˆFTfñV∆G2Çì∞ß–¶gVÊ7Fñˆ‚&VÊFW%G&ffñ4÷ˆFTfñV∆G2Çó∞¢6ˆÁ7B÷ˆFS◊G&ffñ4÷ˆFRÁf«VS∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁG&ffñ2◊6˜W&6R÷6&BríÊf˜$V6ÇÜV√”ÊV¬Ê6∆74∆ó7BÁFˆvv∆RÇv7FófRr∆V¬ÊFF6WBÁG&ffñ4÷ˆFS””÷÷ˆFRíì∞¢G&ffñ4ñÁFVw&FñˆÂw&Á7Gñ∆RÊFó7∆ì“Ü÷ˆFS””“wVÊñfíw«∆÷ˆFS””“w6Ê◊rìÚrs¢vÊˆÊRs∞¢G&ffñ4ñÁFW&f6Uw&Á7Gñ∆RÊFó7∆ì“Ü÷ˆFS””“w7‚w«∆÷ˆFS””“vñÊ∆ñÊRrìÚrs¢vÊˆÊRs∞¢ñbáG&ffñ46ˆÊfñuñ∆ˆBó∞¢6ˆÁ7B6◊G&ffñ46ˆÊfñuñ∆ˆBÊ÷ˆFUˆ6&ñ∆óFñW3ÚÂ∂÷ˆFU◊««∑”∞¢6ˆÁ7B∆&V√◊G&ffñ46ˆÊfñuñ∆ˆBÊ÷ˆFW3ÚÂ∂÷ˆFU◊«∆÷ˆFS∞¢G&ffñ4÷ˆFTÜV«FóF∆RÁFWáD6ˆÁFVÁC÷∆&V√∞¢G&ffñ4÷ˆFTÜV«ÁFWáD6ˆÁFVÁC÷6ÊFW67&óFñˆÁ«¬tÊÚ6˜W&6RFW67&óFñˆ‚fñ∆&∆R‚s∞¢G&ffñ4÷ˆFU&WVó&RÁFWáD6ˆÁFVÁC“Ü6Á&WVó&W3Úu&WVó&W3¢r∂6Á&WVó&W2≤rs¢rrí≤ttÙE4UîR&V6˜&G2FÜó26˜W&6RÊB6ˆÊfñFVÊ6RvóFÇWfW'íFWfñ6R6◊∆R‚s∞¢–ß–¶gVÊ7Fñˆ‚&VÊFW%G&ffñ46ˆ∆∆V7Fñˆ‚áñ∆ˆB«W6vRó∞¢G&ffñ46ˆÊfñuñ∆ˆC◊ñ∆ˆC∂6ˆÁ7B3◊ñ∆ˆBÊ6ˆÊfñw««∑”∑G&ffñ4÷ˆFRÁf«VS÷2Ê÷ˆFW«¬wVÊñfís∑G&ffñ4VÊ&∆VBÁf«VS÷2ÊVÊ&∆VCÚss¢ss∑G&ffñ4ñÁFW'f¬Áf«VS÷2Á6◊∆UˆñÁFW'f≈˜6V6ˆÊG7«√3∞¢6ˆÁ7BñÁG3“áñ∆ˆBÊñÁFVw&FñˆÁ7«≈µ“íÊfñ«FW"áÉ”ÁÇÊ∂ñÊC””◊G&ffñ4÷ˆFRÁf«VRì∑G&ffñ4ñÁFVw&Fñˆ‚ÊñÊÊW$ÖD‘√÷ñÁG2Ê÷áÉ”Ê∆˜Fñˆ‚f«VS“"G∑ÇÊñG“#‚G∂W62áÇÊÊ÷Ró“(	BG∂W62áÇÁF&vWBó”¬ˆ˜Fñˆ„ÊíÊ¶ˆñ‚Çrró«¬s∆˜Fñˆ‚f«VS“"#‰ÊÚ÷F6ÜñÊrñÁFVw&Fñˆ‚6ˆÊfñwW&VC¬ˆ˜Fñˆ„‚s∂ñbÜ2ÊñÁFVw&FñˆÂˆñBóG&ffñ4ñÁFVw&Fñˆ‚Áf«VS’7G&ñÊrÜ2ÊñÁFVw&FñˆÂˆñBì∞¢G&ffñ4ñÁFW&f6RÊñÊÊW$ÖD‘√“áñ∆ˆBÊñÁFW&f6W7«≈µ“íÊ÷áÉ”Ê∆˜Fñˆ‚f«VS“"G∂W62áÇó“#‚G∂W62áÇó”¬ˆ˜Fñˆ„ÊíÊ¶ˆñ‚Çrró«¬s∆˜Fñˆ‚f«VS“"#‰ÊÚñÁFW&f6W2f˜VÊC¬ˆ˜Fñˆ„‚s∂ñbÜ2ÊñÁFW&f6RóG&ffñ4ñÁFW&f6RÁf«VS÷2ÊñÁFW&f6S∞¢6ˆÁ7B7FFS÷2ÊVÊ&∆VCÚÜ2Ê∆7E˜7FGW7«¬v6ˆÊfñwW&VBrì¢vFó6&∆VBs∞¢G&ffñ46ˆ∆∆V7FñˆÂ7FFRÁFWáD6ˆÁFVÁC◊7FFRÁ&W∆6T∆¬ÇuÚr¬rríÁFıWW$66RÇì∑G&ffñ46ˆ∆∆V7FñˆÂ7FFRÊ6∆74Ê÷S“wG&ffñ2◊7FFRr∑7FFS∞¢G&ffñ56˜W&6T∆&V¬ÁFWáD6ˆÁFVÁC◊ñ∆ˆBÊ÷ˆFW3ÚÂ∂2Ê÷ˆFU◊«∆2Ê÷ˆFW«¬tÊ˜B6ˆÊfñwW&VBs∞¢G&ffñ56˜W&6U7V"ÁFWáD6ˆÁFVÁC÷2ÊVÊ&∆VCÚt6ˆ∆∆V7Fñˆ‚VÊ&∆VBs¢t6ˆ∆∆V7Fñˆ‚Fó6&∆VBs∞¢G&ffñ3#E'ÇÁFWáD6ˆÁFVÁC÷f◊D'óFW2áW6vRÁF˜F≈˜'Öˆ'óFW7«√ì∑G&ffñ3#EGÇÁFWáD6ˆÁFVÁC÷f◊D'óFW2áW6vRÁF˜F≈˜GÖˆ'óFW7«√ì∞¢6ˆÁ7B&˜w3◊W6vRÊFWfñ6W7«≈µ”∑G&ffñ4FWfñ6T6˜VÁBÁFWáD6ˆÁFVÁC’7G&ñÊrá&˜w2Ê∆VÊwFÇì∞¢6ˆÁ7B∆FW7C◊&˜w2Ê÷áÉ”ÁÇÊ∆7E˜6◊∆RíÊfñ«FW"Ñ&ˆˆ∆V‚íÁ6˜'BÇíÊBÇ”ì∞¢G&ffñ4∆7E6◊∆RÁFWáD6ˆÁFVÁC÷∆FW7CÚt∆FW7Br∂ÊWrFFRÜ∆FW7BíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÖµ“«∂Ü˜W#¢s"÷FñvóBr∆÷ñÁWFS¢s"÷FñvóBw“ì¢tÊÚ6◊∆W2ñWBs∞¢G&ffñ46ˆ∆∆V7Fñˆ‰÷WFÁFWáD6ˆÁFVÁC÷2Ê∆7Eˆ6ˆ∆∆V7FVEˆCÚt∆7B'V‚r∂ÊWrFFRÜ2Ê∆7Eˆ6ˆ∆∆V7FVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì¢Ü2Ê∆7EˆW'&˜'«¬rrì∞¢&VÊFW%G&ffñ4÷ˆFTfñV∆G2Çì∞¢G&ffñ4FWfñ6U&˜w2ÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷áÉ”Ê«G#„«FC„«7‚6∆73“'G&ffñ2÷FWfñ6R÷Ê÷R#‚G∂W62áÇÊ∆&V¬ó”¬˜7„„∆Fób6∆73“&◊WFVB#‚G∂W62áÇÊó««ÇÊ÷7«¬rró”¬ˆFóc„¬˜FC„«FC„«7‚6∆73“'G&ffñ2◊6˜W&6R÷6Üó#‚G∂W62áÇÁ6˜W&6Uˆ÷ˆFRó“+rG∂W62áÇÊ6ˆÊfñFVÊ6Ró”¬˜7„„¬˜FC„«FC„«7G&ˆÊs‚G∂f◊D'óFW2áÇÁ'Öˆ'óFW2ó”¬˜7G&ˆÊs„¬˜FC„«FC„«7G&ˆÊs‚G∂f◊D'óFW2áÇÁGÖˆ'óFW2ó”¬˜7G&ˆÊs„¬˜FC„«FC‚G∂f◊E&FRáÇÁVµ˜'Öˆ'2ó”¬˜FC„«FC‚G∂f◊E&FRáÇÁVµ˜GÖˆ'2ó”¬˜FC„«FC‚G∑ÇÊ∆7E˜6◊∆SˆW62ÜÊWrFFRáÇÊ∆7E˜6◊∆RíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#r"6∆73“&V◊GíG&ffñ2÷V◊Gí#„«7‚6∆73“'G&ffñ2÷V◊Gí÷ñ6ˆ‚#Ó(xS¬˜7„‰ÊÚ÷V7W&VBW"÷FWfñ6RG&ffñ2ñWB„∆'#„«7‚6∆73“&◊WFVB#‰6Üˆ˜6R6˜W&6R&˜fRÊB'V‚6ˆ∆∆V7Fñˆ‚7ñ6∆R„¬˜7„„¬˜FC„¬˜G#‚s∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞ß–¶7ñÊ2gVÊ7Fñˆ‚6fUG&ffñ46ˆ∆∆V7Fñˆ‚Çó∑G'ó∂6ˆÁ7B&ˆGì◊∂VÊ&∆VCßG&ffñ4VÊ&∆VBÁf«VS””“sr∆÷ˆFSßG&ffñ4÷ˆFRÁf«VR∆ñÁFVw&FñˆÂˆñC¢áG&ffñ4÷ˆFRÁf«VS””“wVÊñfíw««G&ffñ4÷ˆFRÁf«VS””“w6Ê◊rìÚÇ∑G&ffñ4ñÁFVw&Fñˆ‚Áf«VW«∆ÁV∆¬ì¶ÁV∆¬∆ñÁFW&f6S¢áG&ffñ4÷ˆFRÁf«VS””“w7‚w««G&ffñ4÷ˆFRÁf«VS””“vñÊ∆ñÊRrì˜G&ffñ4ñÁFW&f6RÁf«VS¢rr«6◊∆UˆñÁFW'f≈˜6V6ˆÊG3¢∑G&ffñ4ñÁFW'f¬Áf«VR∆˜FñˆÁ3ß∑◊”∂vóBß6ˆ‚Çrˆí˜c˜G&ffñ2ˆ6ˆÊfñrr«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂vóB∆ˆE&W˜'G2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜B6fRG&ffñ26˜W&6S¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚6ˆ∆∆V7EG&ffñ4Ê˜rÇó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜G&ffñ2ˆ6ˆ∆∆V7B÷Ê˜rr«∂÷WFÜˆC¢uı5Bw“ì∂∆W'BÇuG&ffñ26ˆ∆∆V7Fñˆ„¢r≤á"Á7FGW7«¬wVÊ∂Ê˜v‚rí≤á"ÊFWfñ6W5˜6◊∆VB÷ÁV∆√Úr+rr∑"ÊFWfñ6W5˜6◊∆VB≤rFWfñ6Rá2í6◊∆VBs¢rrí≤á"ÊÊ˜FSÚr+rr∑"ÊÊ˜FS¢rrí≤á"ÊW'&˜#Úr+rr∑"ÊW'&˜#¢rríì∂vóB∆ˆE&W˜'G2Çó÷6F6ÇÜRó∂∆W'BÇuG&ffñ26ˆ∆∆V7Fñˆ‚fñ∆VC¢r∂RÊ÷W76vRó◊–ßG&ffñ4÷ˆFSÚÊFDWfVÁD∆ó7FVÊW#Ú‚Çv6ÜÊvRr¬Çì”Á6V∆V7EG&ffñ4÷ˆFRáG&ffñ4÷ˆFRÁf«VRíì∞¶gVÊ7Fñˆ‚6V∆V7E&W˜'EGóRáGóRó∞¢6ˆÁ7B6V√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&W˜'DvVÊW&FUGóRrì∂ñbá6V¬ó6V¬Áf«VS◊GóS∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁ&W˜'B◊GóR÷6&BríÊf˜$V6ÇÜV√”ÊV¬Ê6∆74∆ó7BÁFˆvv∆RÇv7FófRr∆V¬ÊFF6WBÁ&W˜'EGóS””◊GóRíì∞ß–¶gVÊ7Fñˆ‚&W˜'EGóT∆&V¬áBó∑&WGW&‚á∂ÊWGv˜&µ˜7V÷÷'ì¢tÊWGv˜&≤7V÷÷'ír∆FWfñ6UˆñÁfVÁF˜'ì¢tFWfñ6RñÁfVÁF˜'ír«6V7W&óGïˆfñÊFñÊw3¢u6V7W&óGífñÊFñÊw2r∆fñ∆&ñ∆óGïˆ÷ˆÊóF˜&ñÊs¢tfñ∆&ñ∆óGíb÷ˆÊóF˜&ñÊrr∆ñÁFVw&FñˆÁ5ˆÜV«FÉ¢tñÁFVw&FñˆÁ2ÜV«FÇr«G&ffñ5˜W6vS¢uG&ffñ2W6vRr∆VFóEˆ7FófóGì¢tVFóB7FófóGír∆FWfñ6Uˆ6ÜÊvW3¢tFWfñ6R6ÜÊvW2w“ï∑E◊««G«¬u&W˜'Bw–¶gVÊ7Fñˆ‚&W˜'D÷WG&ñ5FWáBáÇó∂6ˆÁ7B3◊ÇÁ7V÷÷'ó««∑”∑&WGW&‚ˆ&¶V7BÊVÁG&ñW2á2íÊfñ«FW"ÇÖ∂≤«e“ì”‚'&íÊó4'&íábíbgGóVˆbb”“vˆ&¶V7BríÁ6∆ñ6RÉ√2íÊ÷ÇÖ∂≤«e“ì”Ê≤Á&W∆6T∆¬ÇuÚr¬rrí≤s¢r∑bíÊ¶ˆñ‚Çr+rró«¬~(	Bw–¶7ñÊ2gVÊ7Fñˆ‚∆ˆE&W˜'G2Çó∑G'ó∑6V∆V7E&W˜'EGóRá&W˜'DvVÊW&FUGóSÚÁf«VW«¬vÊWGv˜&µ˜7V÷÷'írì∂6ˆÁ7B∑2«62∆Ç«F2«GU”÷vóB&ˆ÷ó6RÊ∆¬Ö∂ß6ˆ‚Çrˆí˜c˜&W˜'G2˜7V÷÷'írí∆ß6ˆ‚Çrˆí˜c˜&W˜'G2˜66ÜVGV∆W2rí∆ß6ˆ‚Çrˆí˜c˜&W˜'G2ˆÜó7F˜'írí∆ß6ˆ‚Çrˆí˜c˜G&ffñ2ˆ6ˆÊfñrrí∆ß6ˆ‚Çrˆí˜c˜G&ffñ2ˆFWfñ6W3ˆÜ˜W'3”#Bf∆ñ÷óC”#Rrï“ì∑&VÊFW%G&ffñ46ˆ∆∆V7Fñˆ‚áF2«GRì∑&W˜'E7V÷÷'íÁFWáD6ˆÁFVÁC◊2Ê&ˆGï˜FWáC∞ß&W˜'DvVÊW&FVD6˜VÁBÁFWáD6ˆÁFVÁC’7G&ñÊrÜÇÊ∆VÊwFá«√ì∞ß&W˜'E66ÜVGV∆T6˜VÁBÁFWáD6ˆÁFVÁC’7G&ñÊrá62Ê∆VÊwFá«√ì∞¶ñbÜÇÊ∆VÊwFÇó∑&W˜'D∆FW7EGóRÁFWáD6ˆÁFVÁC◊&W˜'EGóT∆&V¬ÜÖ≥“Á&W˜'E˜GóRì∑&W˜'D∆FW7EFñ÷RÁFWáD6ˆÁFVÁC÷ÊWrFFRÜÖ≥“ÊvVÊW&FVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇó÷V«6W∑&W˜'D∆FW7EGóRÁFWáD6ˆÁFVÁC“~(	Bs∑&W˜'D∆FW7EFñ÷RÁFWáD6ˆÁFVÁC“tÊ˜FÜñÊrvVÊW&FVBñWBw”∑&W˜'E66ÜVGV∆W2ÊñÊÊW$ÖD‘√◊62Ê∆VÊwFÉ˜62Ê÷áÉ”Ê«G#„«FC‚G∂W62áÇÊÊ÷Ró”¬˜FC„«FC‚G∂W62á&W˜'EGóT∆&V¬áÇÁ&W˜'E˜GóRíó”¬˜FC„«FC‚G∂W62áÇÊ6FVÊ6Ró”¬˜FC„«FC‚G∑ÇÊÊWáE˜'VÂˆCˆW62ÜÊWrFFRáÇÊÊWáE˜'VÂˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC‚G∑ÇÊ∆7E˜'VÂˆCˆW62ÜÊWrFFRáÇÊ∆7E˜'VÂˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíì¢~(	Bw”¬˜FC„«FC„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“&FV∆WFU&W˜'E66ÜVGV∆RÇG∑ÇÊñG“í#‰FV∆WFS¬ˆ'WGFˆ„„¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#b"6∆73“&V◊Gí#‰ÊÚ66ÜVGV∆VB&W˜'G2„¬˜FC„¬˜G#‚s∑&W˜'DÜó7F˜'íÊñÊÊW$ÖD‘√÷ÇÊ∆VÊwFÉˆÇÊ÷áÉ”Ê«G"FF◊&W˜'B÷ñC“"G∑ÇÊñG“#„«FB6∆73“&F÷ñ‚÷ˆÊ«í#„∆ñÁWBGóS“&6ÜV6∂&˜Ç"6∆73“'&W˜'B◊6V∆V7B"f«VS“"G∑ÇÊñG“"ˆÊ6ÜÊvS“'WFFU&W˜'DFV∆WFU6V∆V7Fñˆ‚Çí"&ñ÷∆&V√“%6V∆V7BG∂W62áÇÁFóF∆Ró“#„¬˜FC„«FC‚G∂W62ÜÊWrFFRáÇÊvVÊW&FVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíó”¬˜FC„«FC‚G∂W62á&W˜'EGóT∆&V¬áÇÁ&W˜'E˜GóRíó”¬˜FC„«FC‚G∂W62áÇÁFóF∆Ró”¬˜FC„«FC‚G∂W62á&W˜'D÷WG&ñ5FWáBáÇíó”¬˜FC„«FC„∆6∆73“&∆ñÊ≤"á&Vc“"ˆí˜c˜&W˜'G2ÚG∑ÇÊñG“ˆWá˜'BÁFb#ÂDc¬ˆ‚+r∆6∆73“&∆ñÊ≤"á&Vc“"ˆí˜c˜&W˜'G2ÚG∑ÇÊñG“ˆWá˜'BÊ77b#‰55c¬ˆ„¬˜FC„«FC„∆'WGFˆ‚6∆73“&∆ñÊ≤˜W&FR÷ˆÊ«í"ˆÊ6∆ñ6≥“&˜V‰V÷ñ≈&W˜'D÷ˆF¬ÇG∑ÇÊñG“¬rG∂W62áÇÁFóF∆RíÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“rí#‰V÷ñ√¬ˆ'WGFˆ„‚«7‚6∆73“&F÷ñ‚÷ˆÊ«í#Ï+r∆'WGFˆ‚6∆73“&∆ñÊ≤FÊvW"÷∆ñÊ≤"ˆÊ6∆ñ6≥“&FV∆WFU&W˜'BÇG∑ÇÊñG“¬rG∂W62áÇÁFóF∆RíÁ&W∆6RÇÚrˆr¬"b33ì≤"ó“rí#‰FV∆WFS¬ˆ'WGFˆ„„¬˜7„„¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrrì¢s«G#„«FB6ˆ«7„“#r"6∆73“&V◊Gí#‰ÊÚ&W˜'G2vVÊW&FVBñWB„¬˜FC„¬˜G#‚s∑WFFU&W˜'DFV∆WFU6V∆V7Fñˆ‚Çó÷6F6ÇÜRó∑&W˜'E7V÷÷'íÁFWáD6ˆÁFVÁC“u&W˜'G2VÊfñ∆&∆S¢r∂RÊ÷W76vW◊–¶7ñÊ2gVÊ7Fñˆ‚vVÊW&FU&W˜'BÇó∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜&W˜'G2ˆvVÊW&FS˜&W˜'E˜GóS“r∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBá&W˜'DvVÊW&FUGóRÁf«VRí«∂÷WFÜˆC¢uı5Bw“ì∂vóB∆ˆE&W˜'G2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BvVÊW&FR&W˜'C¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚FE&W˜'E66ÜVGV∆RÇó∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜&W˜'G2˜66ÜVGV∆W2r«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂Ê÷Sß&W˜'DÊ÷RÁf«VRÁG&ñ“Çí«&W˜'E˜GóSß&W˜'E66ÜVGV∆UGóRÁf«VR∆VÊ&∆VCßG'VR∆6FVÊ6Sß&W˜'D6FVÊ6RÁf«VR∆Ü˜W%˜WF3¢∑&W˜'DÜ˜W"Áf«VR«vVV∂Fì£∆Ê˜FñgìßG'VW“ó“ì∑&W˜'DÊ÷RÁf«VS“rs∂vóB∆ˆE&W˜'G2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFB&W˜'B66ÜVGV∆S¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFU&W˜'E66ÜVGV∆RÜñBó∂ñbÇ6ˆÊfó&“ÇtFV∆WFRFÜó2&W˜'B66ÜVGV∆SÚríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜&W˜'G2˜66ÜVGV∆W2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆE&W˜'G2Çó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶gVÊ7Fñˆ‚WFFU&W˜'DFV∆WFU6V∆V7Fñˆ‚Çó∞¢6ˆÁ7B&˜ÜW3’≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁ&W˜'B◊6V∆V7Brï”∞¢6ˆÁ7B6V∆V7FVC÷&˜ÜW2Êfñ«FW"áÉ”ÁÇÊ6ÜV6∂VBì∞¢6ˆÁ7B'F„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFV∆WFU6V∆V7FVE&W˜'G4'F‚rì∞¢ñbÜ'F‚ó∂'F‚ÊFó6&∆VC◊6V∆V7FVBÊ∆VÊwFÉ”””∂'F‚ÁFWáD6ˆÁFVÁC◊6V∆V7FVBÊ∆VÊwFÉˆFV∆WFR6V∆V7FVBÇG∑6V∆V7FVBÊ∆VÊwFá“ñ¢tFV∆WFR6V∆V7FVBw–¢6ˆÁ7B∆√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&W˜'E6V∆V7D∆¬rì∞¢ñbÜ∆¬ó∂∆¬Ê6ÜV6∂VC÷&˜ÜW2Ê∆VÊwFÉ„bg6V∆V7FVBÊ∆VÊwFÉ””÷&˜ÜW2Ê∆VÊwFÉ∂∆¬ÊñÊFWFW&÷ñÊFS◊6V∆V7FVBÊ∆VÊwFÉ„bg6V∆V7FVBÊ∆VÊwFÉ∆&˜ÜW2Ê∆VÊwFá–ß–¶gVÊ7Fñˆ‚Fˆvv∆T∆≈&W˜'G2Ü6ÜV6∂VBó∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁ&W˜'B◊6V∆V7BríÊf˜$V6ÇáÉ”ÁÇÊ6ÜV6∂VC÷6ÜV6∂VBì∞¢WFFU&W˜'DFV∆WFU6V∆V7Fñˆ‚Çì∞ß–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFU&W˜'BÜñB«FóF∆Ró∞¢ñbÇ6ˆÊfó&“ÜFV∆WFR"G∑FóF∆W“"g&ˆ“&W˜'BÜó7F˜'ìÚFÜó26ÊÊ˜B&RVÊFˆÊRÊíó&WGW&„∞¢G'ó∂vóBß6ˆ‚Çrˆí˜c˜&W˜'G2Úr∂ñB«∂÷WFÜˆC¢tDTƒUDRw“ì∂vóB∆ˆE&W˜'G2Çó÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFR&W˜'C¢r∂RÊ÷W76vRó–ß–¶7ñÊ2gVÊ7Fñˆ‚FV∆WFU6V∆V7FVE&W˜'G2Çó∞¢6ˆÁ7BñG3’≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁ&W˜'B◊6V∆V7C¶6ÜV6∂VBrï“Ê÷áÉ”‰ÁV÷&W"áÇÁf«VRíì∞¢ñbÇñG2Ê∆VÊwFÇó&WGW&„∞¢ñbÇ6ˆÊfó&“ÜFV∆WFRG∂ñG2Ê∆VÊwFá“6V∆V7FVB&W˜'BG∂ñG2Ê∆VÊwFÉ”””Úrs¢w2w”ÚFÜó26ÊÊ˜B&RVÊFˆÊRÊíó&WGW&„∞¢G'ó∞¢vóBß6ˆ‚Çrˆí˜c˜&W˜'G2ˆ'V∆≤÷FV∆WFRr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∑&W˜'EˆñG3¶ñG7“ó“ì∞¢vóB∆ˆE&W˜'G2Çì∞¢÷6F6ÇÜRó∂∆W'BÇt6˜V∆BÊ˜BFV∆WFR6V∆V7FVB&W˜'G3¢r∂RÊ÷W76vRó–ß–†¶gVÊ7Fñˆ‚f◊D&óG2ábó∑c‘ÁV÷&W"ág«√ì∂ñbác„”Síó&WGW&‚ábÛSííÁFÙfóÜVBÉí≤rv'2s∂ñbác„”Sbó&WGW&‚ábÛSbíÁFÙfóÜVBÉí≤r÷'2s∂ñbác„”S2ó&WGW&‚ábÛS2íÁFÙfóÜVBÉí≤r∂'2s∑&WGW&‚÷FÇÁ&˜VÊBábí≤r'2w–¶7ñÊ2gVÊ7Fñˆ‚∆ˆEG&ffñ2Çó∞¢6ˆÁ7BÊ˜tV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwG&ffñ4Ê˜rrí∆fˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwG&ffñ4fˆ˜Brí∆∆&V«3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwG&ffñ4∆&V«2rí«'É÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwG&ffñ5'Çrí«GÉ÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwG&ffñ5GÇrí∆6∆ñVÁC÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆ñVÁD&'2rí∆Ê˜FS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv6∆ñVÁD÷WG&ñ4Ê˜FRrì∞¢G'ó∞¢6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆÊ«óFñ72˜G&ffñ3ˆ÷ñÁWFW3”crì∂6ˆÁ7B◊"Á6◊∆W7«≈µ”∞¢ñbÜÊ∆VÊwFÇó∂6ˆÁ7B÷É‘÷FÇÊ÷ÇÉ¬‚‚ÊÊf∆D÷áÉ”Â¥ÁV÷&W"áÇÁ'Öˆ'2ó«√ƒÁV÷&W"áÇÁGÖˆ'2ó«√“íì∂6ˆÁ7BG3“Ü∂Wíì”ÊÊ÷ÇáÇ∆íì”Á∂6ˆÁ7BáÉ”CR≤És¢ÜíÙ÷FÇÊ÷ÇÉ∆Ê∆VÊwFÇ”ííì∂6ˆÁ7Bóì”cR“É3R¢ÇÑÁV÷&W"áÖ∂∂Wï“ó«√íˆ÷Çíì∑&WGW&‚áÇÁFÙfóÜVBÉí≤r¬r∑óíÁFÙfóÜVBÉó“íÊ¶ˆñ‚Çrrì∑'ÇÁ6WDGG&ñ'WFRÇwˆñÁG2r«G2Çw'Öˆ'2ríì∑GÇÁ6WDGG&ñ'WFRÇwˆñÁG2r«G2ÇwGÖˆ'2ríì∂6ˆÁ7B∆7C÷∂Ê∆VÊwFÇ””∂Ê˜tV¬ÁFWáD6ˆÁFVÁC÷f◊D&óG2Ü∆7BÁ'Öˆ'2í≤r(i2+rr∂f◊D&óG2Ü∆7BÁGÖˆ'2í≤r(is∂fˆ˜BÁFWáD6ˆÁFVÁC“Ü∆7BÊñÁFW&f6W«¬vñÁFW&f6Rrí≤r+rr∂Ê∆VÊwFÇ≤r6◊∆W2+r∆7Br∂ÊWrFFRÜ∆7BÊ6GW&VEˆBíÁFÙ∆ˆ6∆UFñ÷U7G&ñÊrÇì∂ñbÜ∆&V«2ñ∆&V«2ÊñÊÊW$ÖD‘√÷«FWáBÉ“#B"ì“##í"6∆73“'G&ffñ2÷Üó2#‚G∂W62Üf◊D&óG2Ü÷Çíó”¬˜FWáC„«FWáBÉ“#b"ì“#cÇ"6∆73“'G&ffñ2÷Üó2#„¬˜FWáCÊ–¢V«6W∑'ÇÁ6WDGG&ñ'WFRÇwˆñÁG2r¬rrì∑GÇÁ6WDGG&ñ'WFRÇwˆñÁG2r¬rrì∂Ê˜tV¬ÁFWáD6ˆÁFVÁC“wvóFñÊrf˜"G&ffñ26◊∆W2s∂fˆ˜BÁFWáD6ˆÁFVÁC“tÊÚ6◊∆W2ñWB‚FÜR6ˆ∆∆V7F˜"&V6˜&G2&6V∆ñÊRfó'7B¬FÜV‚6∆7V∆FW2&FW2ˆ‚FÜRÊWáB6◊∆R‚w–¢6ˆÁ7B3◊"Ê6∆ñVÁG7««∑”∂Ê˜FRÁFWáD6ˆÁFVÁC÷2ÊÊ˜FW«¬tˆ'6W'fVB7FófóGí'íFWfñ6Rs∂6ˆÁ7B&˜w3÷2Ê6∆ñVÁG7«≈µ“∆◊É‘÷FÇÊ÷ÇÉ¬‚‚Á&˜w2Ê÷áÉ”‰ÁV÷&W"áÇÊ7FófóGïˆWfVÁG2ó«√íì∂6∆ñVÁBÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Á6∆ñ6RÉ√íÊ÷áÉ”Ê∆Fób6∆73“&6∆ñVÁB◊&˜r#„∆'WGFˆ‚6∆73“&FWfñ6R÷∆ñÊ≤"ˆÊ6∆ñ6≥“&vÙFWfñ6RÇG∑ÇÊñG“í#‚G∂W62áÇÊ∆&V«««ÇÊó««ÇÊ÷7«¬uVÊ∂Ê˜v‚ró”¬ˆ'WGFˆ„„∆Fób6∆73“&6∆ñVÁB÷&"#„«7‚7Gñ∆S“'vñGFÉ¢G¥÷FÇÊ÷ÇÉ"¬ÑÁV÷&W"áÇÊ7FófóGïˆWfVÁG2ó«√íˆ◊Ç£ó“R#„¬˜7„„¬ˆFóc„∆Fób6∆73“&◊WFVB#‚G¥ÁV÷&W"áÇÊ7FófóGïˆWfVÁG2ó«√”¬ˆFóc„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fób6∆73“&V◊Gí#‰ÊÚ6∆ñVÁB7FófóGíÜ2&VV‚ˆ'6W'fVBñWB„¬ˆFóc‚s∞¢÷6F6ÇÜRó∂ñbÜÊ˜tV¬ñÊ˜tV¬ÁFWáD6ˆÁFVÁC“wG&ffñ2VÊfñ∆&∆Rs∂ñbÜfˆ˜Bñfˆ˜BÁFWáD6ˆÁFVÁC÷RÊ÷W76vS∂ñbÜ6∆ñVÁBñ6∆ñVÁBÊñÊÊW$ÖD‘√“s∆Fób6∆73“&V◊Gí#ÂVÊ&∆RFÚ∆ˆB6∆ñVÁB7FófóGí„¬ˆFóc‚w–ß–¶gVÊ7Fñˆ‚cC3&VÊFW$ÜV«FÖvRÜÇ∆&6∑W2«&ˆBó∂6ˆÁ7B6ÜV6∑3‘'&íÊó4'&íÜÉÚÊ6ÜV6∑2ìˆÇÊ6ÜV6∑3•µ”∂6ˆÁ7BfñÊC“áv˜&G2ì”Ê6ÜV6∑2ÊfñÊBÜ3”Áv˜&G2Á6ˆ÷Rás”Â7G&ñÊrÜ2ÊÊ÷W«¬rríÁFÙ∆˜vW$66RÇíÊñÊ6«VFW2árííì∂6ˆÁ7B7C“Ü2ì”Á∂6ˆÁ7B”’7G&ñÊrÜ3ÚÊFWFñ««¬rríÊ÷F6ÇÇÚÖ≥”ï“≤ÉÛ•¬Â≥”ï“≤ìÚï«2¢RÚì∑&WGW&‚”Ú∂’≥”¶ÁV∆«”∂6ˆÁ7BFV◊“Ü2ì”Á∂6ˆÁ7B”’7G&ñÊrÜ3ÚÊFWFñ««¬rríÊ÷F6ÇÇÚÖ≥”ï“≤ÉÛ•¬Â≥”ï“≤ìÚï«2¨+ˆ2ˆíì∑&WGW&‚”Ú∂’≥”¶ÁV∆«”∂6ˆÁ7B7S◊cC37UW&6VÁBÜfñÊBÖ≤v7Rr¬v∆ˆBu“íí∆÷V”◊7BÜfñÊBÖ≤v÷V÷˜'ír¬w&“u“íí∆Fó6≥◊7BÜfñÊBÖ≤vFó6≤r¬w7F˜&vRu“íí«G◊FV◊ÜfñÊBÖ≤wFV◊W&GW&Rr¬wFÜW&÷¬u“íì∂f˜"Ü6ˆÁ7B∂ñB«f≈“ˆbµ≤vÜV«FÑ7Rr∆7U“≈≤vÜV«FÑ÷V“r∆÷V’“≈≤vÜV«FÑFó6≤r∆Fó6µ’“ó∂6ˆÁ7BS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜRñRÁFWáD6ˆÁFVÁC◊f√”÷ÁV∆√Ú~(	Bs§÷FÇÁ&˜VÊBáf¬í≤rRw÷6ˆÁ7BFS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÖFV◊rì∂ñbáFRóFRÁFWáD6ˆÁFVÁC◊G”÷ÁV∆√Ú~(	Bs§÷FÇÁ&˜VÊBáG£íÛR≥3"í≤|+bs∂6ˆÁ7B66ÊÊW#÷fñÊBÖ≤w66ÊÊW"u“í∆F#÷fñÊBÖ≤vFF&6Rr¬w7∆óFRu“í∆ñÁFVs÷fñÊBÖ≤vñÁFVw&Fñˆ‚u“ì∂6ˆÁ7B6WC“ÜñB«FWáB∆vˆˆC◊G'VRì”Á∂6ˆÁ7BS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜRó∂RÁFWáD6ˆÁFVÁC◊FWáC∂RÊ6∆74∆ó7BÁFˆvv∆RÇv&Br¬vˆˆBó◊”∑6WBÇwcC3ÜV«FÖ66ÊÊW"r«66ÊÊW#ı7G&ñÊrá66ÊÊW"Á7FGW7«¬rríÁFÙ∆˜vW$66RÇì””“vˆ≤sÚu'VÊÊñÊrs¢tGFVÁFñˆ‚s¢u'VÊÊñÊrr¬66ÊÊW'«≈7G&ñÊrá66ÊÊW"Á7FGW7«¬rríÁFÙ∆˜vW$66RÇì””“vˆ≤rì∑6WBÇwcC3ÜV«FÑF"r∆F#ı7G&ñÊrÜF"Á7FGW7«¬rríÁFÙ∆˜vW$66RÇì””“vˆ≤sÚtÜV«Fáís¢tGFVÁFñˆ‚s¢tÜV«Fáír¬F'«≈7G&ñÊrÜF"Á7FGW7«¬rríÁFÙ∆˜vW$66RÇì””“vˆ≤rì∑6WBÇwcC3ÜV«FÑñÁFVw&FñˆÁ2r∆ñÁFVsı7G&ñÊrÜñÁFVrÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇì””“vˆ≤sÚtÜV«Fáís¢tGFVÁFñˆ‚s¢tÜV«Fáír¬ñÁFVw«≈7G&ñÊrÜñÁFVrÁ7FGW7«¬rríÁFÙ∆˜vW$66RÇì””“vˆ≤rì∑6WBÇwcC3ÜV«FÑ&6∑Wrƒ'&íÊó4'&íÜ&6∑W2íbf&6∑W2Ê∆VÊwFÉÚtÜV«Fáís¢u&VGír«G'VRì∑6WBÇwcC3ÜV«FÖWFFRr≈7G&ñÊrá&ˆCÚÁWFFUˆ6ÜÊÊV««¬w7F&∆RríÁ&W∆6RÇı‚‚Ú∆3”Ê2ÁFıWW$66RÇíí«G'VRì∂6ˆÁ7BW÷fñÊBÖ≤wWFñ÷Ru“ì∂6ˆÁ7BVS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÖWFñ÷Rrì∂ñbáVRóVRÁFWáD6ˆÁFVÁC◊WÚÊFWFñ««¬u'VÊÊñÊrw–¶gVÊ7Fñˆ‚&VÊFW$ÜV«FÖ7V÷÷'íÜÇ«&WFVÁFñˆ‚∆&6∑W2«6WGFñÊw2∆Ê˜Fñfñ6FñˆÁ2ó∞¢6ˆÁ7BWC“ÜñB«f«VRì”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬ÁFWáD6ˆÁFVÁC◊f«VW”∞¢6ˆÁ7BFó6≥÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑFó6≤rìÚÁFWáD6ˆÁFVÁG«¬~(	Bs∑WBÇvÜV«FÖ7F˜&vUW6vRr∆Fó6≤ì∂6ˆÁ7B7C◊'6Tf∆ˆBÜFó6≤ì∂6ˆÁ7B&#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÖ7F˜&vT&"rì∂ñbÜ&"ñ&"Á7Gñ∆RÁvñGFÉ‘ÁV÷&W"Êó4fñÊóFRá7BìÙ÷FÇÊ÷ñ‚Éƒ÷FÇÊ÷ÇÉ«7Bíí≤rRs¢sRs∞¢6ˆÁ7B6fVC‘'&íÊó4'&íÜ&6∑W2ìˆ&6∑W3•µ”∑WBÇvÜV«FÑ&6∑W6˜VÁBr«6fVBÊ∆VÊwFÇì∑WBÇvÜV«FÑ∆7D&6∑Wr«6fVBÊ∆VÊwFÉˆÊWrFFRá6fVE≥“Ê7&VFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇì¢tÊÚ&6∑W2ñWBrì∑WBÇvÜV«FÑÊWáD&6∑Wr«6WGFñÊw3ÚÊWFıˆ&6∑WˆVÊ&∆VCÚu66ÜVGV∆VBBrµ7G&ñÊrá6WGFñÊw2Ê&6∑WˆÜ˜W%˜WF3ÛÛ2íÁE7F'BÉ"¬srí≤s£UD2s¢tÊ˜B66ÜVGV∆VBrì∞¢WBÇvÜV«FÖG&ffñ5&WFVÁFñˆ‚r«&WFVÁFñˆ„ÚÁG&ffñ5˜&WFVÁFñˆÂˆFó2÷ÁV∆√˜&WFVÁFñˆ‚ÁG&ffñ5˜&WFVÁFñˆÂˆFó2≤rFó2s¢~(	Brì∑WBÇvÜV«FÑWfVÁE&WFVÁFñˆ‚r«&WFVÁFñˆ„ÚÊWfVÁE˜&WFVÁFñˆÂˆFó2÷ÁV∆√˜&WFVÁFñˆ‚ÊWfVÁE˜&WFVÁFñˆÂˆFó2≤rFó2s¢~(	Brì∑WBÇvÜV«FÑ&6∑W&WFVÁFñˆ‚r«6WGFñÊw3ÚÊ&6∑Wˆ∂VWˆ6˜VÁB÷ÁV∆√˜6WGFñÊw2Ê&6∑Wˆ∂VWˆ6˜VÁB≤r6˜ñW2s¢~(	Brì∑WBÇvÜV«FÖWFFT6ÜÊÊV¬r«6WGFñÊw3ÚÁWFFUˆ6ÜÊÊV««¬u7F&∆Rrì∞¢6ˆÁ7B6ÜV6∑3‘'&íÊó4'&íÜÉÚÊ6ÜV6∑2ìˆÇÊ6ÜV6∑3•µ”∂6ˆÁ7B6W'fñ6S÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÖ6W'fñ6U7V÷÷'írì∂ñbá6W'fñ6Ró6W'fñ6RÊñÊÊW$ÖD‘√÷6ÜV6∑2Ê∆VÊwFÉˆ6ÜV6∑2Á6∆ñ6RÉ√RíÊ÷áÉ”Ê∆Fóc„«7„‚G∂W62áÇÊÊ÷W«¬t6ÜV6≤ró”¬˜7„„∆#‚G∂W62áÇÁ7FGW7«¬wVÊ∂Ê˜v‚ró”¬ˆ#„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fóc‰ÊÚÜV«FÇ6ÜV6∑2fñ∆&∆R„¬ˆFóc‚s∞¢6ˆÁ7BWfVÁG3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑWfVÁE7V÷÷'írí∆Ê˜FW3‘'&íÊó4'&íÜÊ˜Fñfñ6FñˆÁ2ìˆÊ˜Fñfñ6FñˆÁ3•µ”∂ñbÜWfVÁG2ñWfVÁG2ÊñÊÊW$ÖD‘√÷Ê˜FW2Ê∆VÊwFÉˆÊ˜FW2Á6∆ñ6RÉ√RíÊ÷áÉ”Ê∆Fóc„«7„‚G∂W62áÇÊWfVÁE˜GóW«¬tFV∆ófW'író”¬˜7„„∆#‚G∂W62áÇÁ7FGW7«¬wVÊ∂Ê˜v‚ró”¬ˆ#„¬ˆFócÊíÊ¶ˆñ‚Çrrì¢s∆Fóc‰ÊÚ&V6VÁB7ó7FV“WfVÁG2„¬ˆFóc‚s∞¢ß6ˆ‚Çrˆí˜cˆÊ«óFñ72˜G&ffñ3ˆ÷ñÁWFW3”críÁFÜV‚á#”Á∂6ˆÁ7B∆7C“á"Á6◊∆W7«≈µ“íÊBÇ”ì∂ñbÜ∆7Bó∑WBÇvÜV«FÑÊWGv˜&µ&FRr∆f◊D&óG2Ü∆7BÁ'Öˆ'2í≤r(i2+rr∂f◊D&óG2Ü∆7BÁGÖˆ'2í≤r(irì∑WBÇvÜV«FÑÊWGv˜&¥ñÁFW&f6Rr∆∆7BÊñÁFW&f6W«¬tÊWGv˜&≤ñÁFW&f6Rrì∂6ˆÁ7BÊWF&#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜV«FÑÊWGv˜&¥&"rì∂ñbÜÊWF&"ñÊWF&"Á7Gñ∆RÁvñGFÉ‘÷FÇÊ÷ñ‚Éƒ÷FÇÊ÷ÇÉBƒÁV÷&W"Ü∆7BÁ'Öˆ'7«√íÛSríí≤rRw◊“íÊ6F6ÇÇÇì”Á∑“ì∞ß–¶7ñÊ2gVÊ7Fñˆ‚∆ˆDÜV«FÇÇó∑G'ó∂6ˆÁ7B∂Ç«"∆"««F«2∆ÊÖ”÷vóB&ˆ÷ó6RÊ∆¬Ö∂ß6ˆ‚Çrˆí˜cˆ∆ñÊ6RˆÜV«FÇrí∆ß6ˆ‚Çrˆí˜cˆ∆ñÊ6R˜&WFVÁFñˆ‚ríÊ6F6ÇÇÇì”ÊÁV∆¬í∆ß6ˆ‚Çrˆí˜cˆ∆ñÊ6Rˆ&6∑W2ríÊ6F6ÇÇÇì”Âµ“í∆ß6ˆ‚Çrˆí˜cˆ∆ñÊ6R˜&ˆGV7Fñˆ‚◊6WGFñÊw2ríÊ6F6ÇÇÇì”ÊÁV∆¬í∆ß6ˆ‚Çrˆí˜cˆ∆ñÊ6RˆáGG2ríÊ6F6ÇÇÇì”ÊÁV∆¬í∆ß6ˆ‚Çrˆí˜cˆÊ˜Fñfñ6FñˆÁ2ˆÜó7F˜'íríÊ6F6ÇÇÇì”Âµ“ï“ì¥ƒ5EÙÑT≈DÖÙ4ÑT4µ3‘'&íÊó4'&íÜÇÊ6ÜV6∑2ìˆÇÊ6ÜV6∑3•µ”∂ÜV«FÑ˜fW&∆¬ÁFWáD6ˆÁFVÁC“ÜÇÊ˜fW&∆««¬wVÊ∂Ê˜v‚ríÁFıWW$66RÇì∂ÜV«FÑÜ˜7BÁFWáD6ˆÁFVÁC÷ÇÊÜ˜7FÊ÷W«¬~(	Bs∂ÜV«FÑ∂W&ÊV¬ÁFWáD6ˆÁFVÁC÷ÇÊ∂W&ÊV««¬~(	Bs∑cC3&VÊFW$ÜV«FÖvRÜÇ∆"«ì∑&VÊFW$ÜV«FÖ7V÷÷'íÜÇ«"∆"«∆ÊÇì∂ÜV«FÑ6ÜV6∑2ÊñÊÊW$ÖD‘√“ÜÇÊ6ÜV6∑7«≈µ“íÊ÷áÉ”Ê«G#„«FC‚G∂W62áÇÊÊ÷Ró”¬˜FC„«FC„«7‚6∆73“'ñ∆¬G∑ÇÁ7FGW3””“vˆ≤sÚvˆÊ∆ñÊRsßÇÁ7FGW3””“v7&óFñ6¬sÚvˆff∆ñÊRs¢rw“#‚G∂W62áÇÁ7FGW2ó”¬˜7„„¬˜FC„«FC‚G∂W62ácC3ÜV«FÑFWFñ¬áÇíó”¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrrì∂ñbá"ó∑&WEG&ffñ2Áf«VS◊"ÁG&ffñ5˜&WFVÁFñˆÂˆFó3∑&WDWfVÁG2Áf«VS◊"ÊWfVÁE˜&WFVÁFñˆÂˆFó3∑&WDVFóBÁf«VS◊"ÊVFóE˜&WFVÁFñˆÂˆFó3∑&WE&W˜'G2Áf«VS◊"Á&W˜'E˜&WFVÁFñˆÂˆFó3∑&WE7ñÊ2Áf«VS◊"Á7ñÊ5˜&WFVÁFñˆÂˆFó3∑&WDÊ˜FñgíÁf«VS◊"ÊÊ˜Fñfñ6FñˆÂ˜&WFVÁFñˆÂˆFó7÷&6∑W&˜w2ÊñÊÊW$ÖD‘√“Ü'«≈µ“íÊ÷áÉ”Ê«G#„«FC‚G∂W62ÜÊWrFFRáÇÊ7&VFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíó”¬˜FC„«FC‚G∂W62áÇÊfñ∆VÊ÷Ró”¬˜FC„«FC‚G≤áÇÁ6ó¶Uˆ'óFW2Û#BÛ#BíÁFÙfóÜVBÉ"ó“‘#¬˜FC„«FC‚G∂W62áÇÊÊ˜FW«¬rró”¬˜FC„«FC„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“'&W7F˜&T&6∑WÇrG∂W62áÇÊfñ∆VÊ÷Ró“rí#Â&W7F˜&S¬ˆ'WGFˆ„„¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrró«¬s«G#„«FB6ˆ«7„“#R"6∆73“&V◊Gí#‰ÊÚ&6∑W2ñWB„¬˜FC„¬˜G#‚s∂ñbáó∑&ˆDWFÙ&6∑WÁf«VS◊ÊWFıˆ&6∑WˆVÊ&∆VCÚss¢ss∑&ˆD&6∑WÜ˜W"Áf«VS◊Ê&6∑WˆÜ˜W%˜WF3∑&ˆD&6∑W∂VWÁf«VS◊Ê&6∑Wˆ∂VWˆ6˜VÁC∑&ˆEWFFT6ÜÊÊV¬Áf«VS◊ÁWFFUˆ6ÜÊÊV««¬w7F&∆Rw÷ñbáF«2ó∑F«57FGW2ÁFWáD6ˆÁFVÁC◊F«2Ê6ˆÊfñwW&VCÚtÖEE26W'Fñfñ6FRó2ñÁ7F∆∆VBˆ‚FÜó2∆ñÊ6R‚s¢tÖEE26W'Fñfñ6FRó2Ê˜B6ˆÊfñwW&VBñWB‚s∂áGG4˜WBÁFWáD6ˆÁFVÁC◊F«2ÊÜV«W'«¬rw÷Ê˜Fñfñ6Fñˆ‰Üó7F˜'ï&˜w2ÊñÊÊW$ÖD‘√“ÜÊá«≈µ“íÊ÷áÉ”Ê«G#„«FC‚G∂W62ÜÊWrFFRáÇÊ7&VFVEˆBíÁFÙ∆ˆ6∆U7G&ñÊrÇíó”¬˜FC„«FC‚G∂W62áÇÊWfVÁE˜GóRó”¬˜FC„«FC‚G∂W62áÇÁ6WfW&óGíó”¬˜FC„«FC‚G∂W62áÇÁ7FGW2ó”¬˜FC„«FC‚G∑ÇÊGFV◊G7«√”¬˜FC„«FC„∆'WGFˆ‚6∆73“&∆ñÊ≤"ˆÊ6∆ñ6≥“'&WG'îÊ˜Fñfñ6Fñˆ‚ÇG∑ÇÊñG“í#Â&WG'ì¬ˆ'WGFˆ„„¬˜FC„¬˜G#ÊíÊ¶ˆñ‚Çrró«¬s«G#„«FB6ˆ«7„“#b"6∆73“&V◊Gí#‰ÊÚÊ˜Fñfñ6Fñˆ‚Üó7F˜'í„¬˜FC„¬˜G#‚w÷6F6ÇÜRó∂ÜV«FÑ6ÜV6∑2ÊñÊÊW$ÖD‘√“s«G#„«FB6ˆ«7„“#2#‚r∂W62ÜRÊ÷W76vRí≤s¬˜FC„¬˜G#‚w◊–¶7ñÊ2gVÊ7Fñˆ‚7&VFT&6∑WÇó∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆ∆ñÊ6Rˆ&6∑W2r«∂÷WFÜˆC¢uı5Bw“ì∂vóB∆ˆDÜV«FÇÇó÷6F6ÇÜRó∂∆W'BÇt&6∑Wfñ∆VC¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚&W7F˜&T&6∑WÜÊ÷Ró∂ñbÇ6ˆÊfó&“Çu&W7F˜&Rr∂Ê÷R≤sÚtÙE4UîRvñ∆¬7&VFR6fWGí&6∑Wfó'7B‚6W'fñ6R&W7F'Bó2&V6ˆ÷÷VÊFVBgFW"&W7F˜&R‚ríó&WGW&„∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆ∆ñÊ6Rˆ&6∑W2˜&W7F˜&Rr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂fñ∆VÊ÷S¶Ê÷W“ó“ì∂∆W'BÇu&W7F˜&R6ˆ◊∆WFR‚6fWGí&6∑W¢r∑"Á6fWGïˆ&6∑W≤u∆Â&W7F'BtÙE4UîR6W'fñ6W2vÜV‚6ˆÁfVÊñVÁB‚rì∂vóB∆ˆDÜV«FÇÇó÷6F6ÇÜRó∂∆W'BÇu&W7F˜&Rfñ∆VC¢r∂RÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚&˜FFT÷WG&ñ74∂WíÇó∂ñbÇ6ˆÊfó&“Çu&˜FFRFÜR&ˆ÷WFÜWW2í∂WìÚÁíWÜó7FñÊr&ˆ÷WFÜWW26ˆÊfñwW&Fñˆ‚vñ∆¬7F˜v˜&∂ñÊrVÁFñ¬WFFVB‚ríó&WGW&„∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆ∆ñÊ6R˜&ˆ÷WFÜWW2÷∂Wír«∂÷WFÜˆC¢uı5Bw“ì∂÷WG&ñ74∂Wî˜WBÁFWáD6ˆÁFVÁC“tí∂Wíá6Ü˜v‚ˆÊ6Rì•∆‚r∑"Êïˆ∂Wí≤u∆Â∆Â&ˆ÷WFÜWW2ÜVFW#•∆‰WFÜ˜&ó¶Fñˆ„¢&V&W"r∑"Êïˆ∂Wó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–†¶∆WB5DtTEıUDDS÷ÁV∆√∞¶7ñÊ2gVÊ7Fñˆ‚6fU&ˆGV7FñˆÂ6WGFñÊw2Çó∑G'ó∂vóBß6ˆ‚Çrˆí˜cˆ∆ñÊ6R˜&ˆGV7Fñˆ‚◊6WGFñÊw2r«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂WFıˆ&6∑WˆVÊ&∆VCß&ˆDWFÙ&6∑WÁf«VS””“sr∆&6∑Wˆ6FVÊ6S¢vFñ«ír∆&6∑WˆÜ˜W%˜WF3¢∑&ˆD&6∑WÜ˜W"Áf«VR∆&6∑Wˆ∂VWˆ6˜VÁC¢∑&ˆD&6∑W∂VWÁf«VR∆áGG5ˆ÷ˆFS¢vˆfbr∆áGG5ˆÜ˜7FÊ÷S¢rr«WFFUˆ6ÜÊÊV√ß&ˆEWFFT6ÜÊÊV¬Áf«VW“ó“ì∂∆W'BÇu&ˆGV7Fñˆ‚∆ñÊ6R6WGFñÊw26fVB‚rì∂vóB∆ˆDÜV«FÇÇó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚7FvUWFFRÇó∂6ˆÁ7Bc◊WFFTfñ∆RÊfñ∆W5≥”∂ñbÇbó∂∆W'BÇt6Üˆ˜6RtÙE4UîR§ï6∂vRfó'7B‚rì∑&WGW&Á◊WFFT˜WBÁFWáD6ˆÁFVÁC“uW∆ˆFñÊrÊB'VÊÊñÊr&Vf∆ñváN(
bs∑G'ó∂6ˆÁ7B#÷vóBfWF6ÇÇrˆí˜c˜WFFW2˜7FvRr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤uÇ‘55$b’Fˆ∂V‚s¶77&eFˆ∂V‚Çí¬uÇ‘fñ∆VÊ÷Rs¶bÊÊ÷W“∆&ˆGì¶vóBbÊ'&î'VffW"Çó“ì∂6ˆÁ7BC÷vóB"Êß6ˆ‚Çì∂ñbÇ"Êˆ≤óFá&˜rÊWrW'&˜"ÜBÊFWFñ««¬u7FvRfñ∆VBrìµ5DtTEıUDDS÷C∑WFFT˜WBÁFWáD6ˆÁFVÁC‘•4Ù‚Á7G&ñÊvñgíÜB∆ÁV∆¬√"ì∂«ïWFFT'F‚Á7Gñ∆RÊFó7∆ì÷BÁ&Vf∆ñváCÚÊˆ≥ÚvñÊ∆ñÊR÷&∆ˆ6≤s¢vÊˆÊRw÷6F6ÇÜRó∑WFFT˜WBÁFWáD6ˆÁFVÁC÷RÊ÷W76vW◊–¶7ñÊ2gVÊ7Fñˆ‚«ïWFFRÇó∂ñbÇ5DtTEıUDDRó&WGW&„∂6ˆÁ7BFWáC◊&ˆ◊BÇuFÜó27&VFW26fWGí&6∑W&Vf˜&R«ññÊrFÜR7FvVB&V∆V6R‚GóRWÜ7F«ì¢≈ítÙE4UîRUDDRrì∂ñbáFWáB”“t≈ítÙE4UîRUDDRró&WGW&„∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜WFFW2ˆ«ír«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂fñ∆VÊ÷S•5DtTEıUDDRÊfñ∆VÊ÷R«6Ü#Sc•5DtTEıUDDRÁ6Ü#Sb∆6ˆÊfó&”ßFWáG“ó“ì∑WFFT˜WBÁFWáD6ˆÁFVÁC‘•4Ù‚Á7G&ñÊvñgíá"∆ÁV∆¬√"ó÷6F6ÇÜRó∑WFFT˜WBÁFWáD6ˆÁFVÁC÷RÊ÷W76vW◊–¶7ñÊ2gVÊ7Fñˆ‚&WG'îÊ˜Fñfñ6Fñˆ‚ÜñBó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆÊ˜Fñfñ6FñˆÁ2˜&WG'ír«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂FV∆ófW'ïˆñC¶ñG“ó“ì∂∆W'BÇu&WG'í6ˆ◊∆WFS¢r¥•4Ù‚Á7G&ñÊvñgíá"íì∂vóB∆ˆDÜV«FÇÇó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶7ñÊ2gVÊ7Fñˆ‚'VÂ&V÷VFñFñˆ‚Çó∂6ˆÁ7B7Fñˆ„◊&V÷VFñFñˆ‰7Fñˆ‚Áf«VR«F&vWC◊&V÷VFñFñˆÂF&vWBÁf«VRÁG&ñ“Çì∂ñbÇF&vWBó∂∆W'BÇtVÁFW"F&vWB‚rì∑&WGW&Á÷6ˆÁ7B6ˆÊfó&’FWáC“t4Ù‰dï$“r∂7Fñˆ‚ÁFıWW$66RÇí≤rr∑F&vWC∂6ˆÁ7BGóVC◊&ˆ◊BÇuFÜó26ÜÊvW2ñ˜W"6ˆÊfñwW&VBÊWGv˜&≤6W'fñ6R‚GóRWÜ7F«ì•∆‚r∂6ˆÊfó&’FWáBì∂ñbáGóVB”÷6ˆÊfó&’FWáBó&WGW&„∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜&V÷VFñFñˆ‚ˆWÜV7WFRr«∂÷WFÜˆC¢uı5Br∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂7Fñˆ‚«F&vWB∆6ˆÊfó&”ßGóVG“ó“ì∑&V÷VFñFñˆ‰˜WBÁFWáD6ˆÁFVÁC◊"Êˆ≥Út7Fñˆ‚6ˆ◊∆WFVB‚s¢t7Fñˆ‚fñ∆VC¢r≤á"ÊW'&˜'«¬wVÊ∂Ê˜v‚W'&˜"ró÷6F6ÇÜRó∑&V÷VFñFñˆ‰˜WBÁFWáD6ˆÁFVÁC÷RÊ÷W76vW◊–¶7ñÊ2gVÊ7Fñˆ‚6fU&WFVÁFñˆ‚Çó∑G'ó∂6ˆÁ7B&ˆGì◊∑G&ffñ5˜&WFVÁFñˆÂˆFó3¢∑&WEG&ffñ2Áf«VR∆WfVÁE˜&WFVÁFñˆÂˆFó3¢∑&WDWfVÁG2Áf«VR∆VFóE˜&WFVÁFñˆÂˆFó3¢∑&WDVFóBÁf«VR«&W˜'E˜&WFVÁFñˆÂˆFó3¢∑&WE&W˜'G2Áf«VR«7ñÊ5˜&WFVÁFñˆÂˆFó3¢∑&WE7ñÊ2Áf«VR∆Ê˜Fñfñ6FñˆÂ˜&WFVÁFñˆÂˆFó3¢∑&WDÊ˜FñgíÁf«VW”∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜cˆ∆ñÊ6R˜&WFVÁFñˆ‚r«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíÜ&ˆGíó“ì∂∆W'BÇu&WFVÁFñˆ‚6fVB‚'VÊVC¢r¥•4Ù‚Á7G&ñÊvñgíá"ÊFV∆WFVBíì∂vóB∆ˆDÜV«FÇÇó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–††¶∆WBTïÙƒîıUE3◊∑”∞¶∆WBƒîıUEÙTDïDî‰s÷f«6S∞¶∆WBƒîıUEÙE$ttTC÷ÁV∆√∞¶∆WBƒîıUEı4dUıDî‘U#÷ÁV∆√∞¶6ˆÁ7BƒîıUEı§Ù‰Uı4TƒT5Dı%3’≤rÊ6&G2r¬rÊF6Ü&ˆ&B÷w&ñBr¬rÁFˆˆ¬÷w&ñBr¬rÁ&W˜'B◊GóR÷w&ñBr¬rÁ&W˜'B÷∑í÷w&ñBr¬rÁ&W˜'B÷w&ñB◊GvÚr¬rÁG&ffñ2◊6˜W&6R÷w&ñBr¬rÁG&ffñ2÷6ˆÊfñr÷6&B÷w&ñBr¬rÊÊ«óFñ72÷w&ñBr¬rÊÊ˜Fñgí÷w&ñBr¬rÊ÷ˆÊóF˜"◊7V÷÷'ír¬rÊ÷◊7V÷÷'ír¬rÊñÁFVw&Fñˆ‚÷∆ó7Br¬rÁG&ffñ2◊7FB÷w&ñBr¬rÊñÁFV¬÷w&ñBr¬rÊ6ˆÊÊV7FVB÷w&ñBr¬rÁ&W˜'B÷Üó7F˜'í÷w&ñBr¬rÊÜV«FÇ÷w&ñBr¬rÁcC3÷ÜV«FÇ÷˜W&FñˆÊ¬÷w&ñBr¬rÁcC3÷6∆VÊF"◊7FB÷w&ñBr¬rÊ6∆VÊF"◊&˜fñFW"÷w&ñBr¬rÁcC3÷V÷ñ¬÷66˜VÁB÷6&G2u”∞¶gVÊ7Fñˆ‚∆ñ˜WE6«Vráf«VRó∑&WGW&‚7G&ñÊráf«VW«¬vóFV“ríÁG&ñ“ÇíÁFÙ∆˜vW$66RÇíÁ&W∆6RÇıµÊ◊£”ï“≤ˆr¬r“ríÁ&W∆6RÇı‚◊¬“Bˆr¬rríÁ6∆ñ6RÉ√Éó«¬vóFV“w–¶gVÊ7Fñˆ‚7W'&VÁD∆ñ˜WEvRÇó∂6ˆÁ7Bfó6ñ&∆S’≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁfñWrrï“ÊfñÊBác”ÁbÁ7Gñ∆RÊFó7∆í”“vÊˆÊRrì∑&WGW&‚fó6ñ&∆SÚÊñCÚÁ&W∆6RÇıÁfñWr“Ú¬rró«¬v˜fW'fñWrw–¶gVÊ7Fñˆ‚∆ñ˜WDóFV‘∂WíÜV¬∆ñÊFWÇó∂ñbÜV¬ÊFF6WBÊ∆ñ˜WD∂Wíó&WGW&‚V¬ÊFF6WBÊ∆ñ˜WD∂Wì∂∆WB∂Wì÷V¬ÊñG«∆V¬ÊFF6WBÁ&W˜'EGóW«∆V¬ÊFF6WBÁG&ffñ4÷ˆFW«∆V¬ÊFF6WBÊñÁFVw&Fñˆ‰ñG«∆V¬ÁVW'ï6V∆V7F˜"ÇvÉ∆É"∆É2¬Á&W˜'B◊GóR÷Ê÷R¬ÁG&ffñ2◊6˜W&6R÷Ê÷R¬ÊÊ«óFñ72◊FóF∆R¬Ê∆&V¬¬Ê≤rìÚÁFWáD6ˆÁFVÁG«¬Çv6&B“r∂ñÊFWÇì∂∂Wì÷∆ñ˜WE6«VrÜ∂Wíì∂V¬ÊFF6WBÊ∆ñ˜WD∂Wì÷∂Wì∑&WGW&‚∂Wó–¶gVÊ7Fñˆ‚&Vvó7FW$∆ñ˜WE¶ˆÊW2Çó∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁfñWrríÊf˜$V6ÇáfñWs”Á∞¢6ˆÁ7BvS◊fñWrÊñBÁ&W∆6RÇıÁfñWr“Ú¬rrì∂∆WB¶ˆÊTñÊFWÉ”∞¢ƒîıUEı§Ù‰Uı4TƒT5Dı%2Êf˜$V6Çá6V∆V7F˜#”ÁfñWrÁVW'ï6V∆V7F˜$∆¬á6V∆V7F˜"íÊf˜$V6Çá¶ˆÊS”Á∞¢ñbá¶ˆÊRÊ6∆˜6W7BÇrÊ÷ˆF¬ríó&WGW&„∞¢¶ˆÊRÊ6∆74∆ó7BÊFBÇv∆ñ˜WB◊¶ˆÊRrì∑¶ˆÊRÊFF6WBÊ∆ñ˜WE¶ˆÊS◊¶ˆÊRÊFF6WBÊ∆ñ˜WE¶ˆÊW«∆G∑vW““G∂∆ñ˜WE6«Vrá6V∆V7F˜"ó““G∑¶ˆÊTñÊFWÇ≤∑÷∞¢≤‚‚Á¶ˆÊRÊ6Üñ∆G&VÂ“Êf˜$V6ÇÇÜV¬∆íì”Á∂ñbÜV¬Ê÷F6ÜW2ÇrÊV◊Gí«67&óB«7Gñ∆Rríó&WGW&„∂V¬Ê6∆74∆ó7BÊFBÇv∆ñ˜WB÷÷˜f&∆Rrì∂∆ñ˜WDóFV‘∂WíÜV¬∆íó“ì∞¢“íì∞¢6ˆÁ7BFó&V7EÊV«3’≤‚‚ÁfñWrÊ6Üñ∆G&VÂ“Êfñ«FW"ÜV√”ÊV¬Ê6∆74∆ó7BÊ6ˆÁFñÁ2ÇwÊV¬ríì∞¢ñbÜFó&V7EÊV«2Ê∆VÊwFÉ„ó∂Fó&V7EÊV«2Êf˜$V6ÇÇÜV¬∆íì”Á∂V¬Ê6∆74∆ó7BÊFBÇv∆ñ˜WB÷÷˜f&∆Rrì∂∆ñ˜WDóFV‘∂WíÜV¬∆íó“ì∑fñWrÊFF6WBÊ∆ñ˜WD∆ˆ˜6U¶ˆÊS÷G∑vW“◊ÊV«6∑fñWrÊ6∆74∆ó7BÊFBÇv∆ñ˜WB÷∆ˆ˜6R◊¶ˆÊRró–¢VÁ7W&T∆ñ˜WEFˆˆ∆&"áfñWr«vRì∞¢“ì∞¢«î∆≈6fVD∆ñ˜WG2Çì∞¢7ñÊ4∆ñ˜WDG&vv&∆RÇì∞ß–¶gVÊ7Fñˆ‚VÁ7W&T∆ñ˜WEFˆˆ∆&"áfñWr«vRó∞¢Ú¢∆ñ˜WB6ˆÁG&ˆ«2∆ófRñ‚FÜR&ˆfñ∆R÷VÁR6ÚWfW'ívR÷7FÜVB7Fó2∆ñvÊVB‚¢¢fñWrÁVW'ï6V∆V7F˜$∆¬Çsß66˜R‚ÊÜW&Ú‚Ê∆ñ˜WB÷F÷ñ‚◊Fˆˆ«2ríÊf˜$V6ÇÜÊˆFS”ÊÊˆFRÁ&V÷˜fRÇíì∞ß–¶gVÊ7Fñˆ‚¶ˆÊTf˜$V∆V÷VÁBÜV¬ó∑&WGW&‚V¬Ê6∆˜6W7BÇrÊ∆ñ˜WB◊¶ˆÊRró«∆V¬Ê6∆˜6W7BÇrÊ∆ñ˜WB÷∆ˆ˜6R◊¶ˆÊRró–¶gVÊ7Fñˆ‚¶ˆÊT∂Wíá¶ˆÊRó∑&WGW&‚¶ˆÊRÊFF6WBÊ∆ñ˜WE¶ˆÊW««¶ˆÊRÊFF6WBÊ∆ñ˜WD∆ˆ˜6U¶ˆÊW–¶gVÊ7Fñˆ‚÷˜f&∆T6Üñ∆G&V‚á¶ˆÊRó∑&WGW&‚¶ˆÊRÊ6∆74∆ó7BÊ6ˆÁFñÁ2Çv∆ñ˜WB÷∆ˆ˜6R◊¶ˆÊRrìı≤‚‚Á¶ˆÊRÊ6Üñ∆G&VÂ“Êfñ«FW"áÉ”ÁÇÊ6∆74∆ó7BÊ6ˆÁFñÁ2Çv∆ñ˜WB÷÷˜f&∆Rríì•≤‚‚Á¶ˆÊRÊ6Üñ∆G&VÂ“Êfñ«FW"áÉ”ÁÇÊ6∆74∆ó7BÊ6ˆÁFñÁ2Çv∆ñ˜WB÷÷˜f&∆Rríó–¶gVÊ7Fñˆ‚«ï¶ˆÊT˜&FW"á¶ˆÊR∆˜&FW"ó∂ñbÇ'&íÊó4'&íÜ˜&FW"ó«¬˜&FW"Ê∆VÊwFÇó&WGW&„∂6ˆÁ7BóFV◊3÷÷˜f&∆T6Üñ∆G&V‚á¶ˆÊRí∆÷÷ÊWr÷ÜóFV◊2Ê÷ÇÜV¬∆íì”Â∂∆ñ˜WDóFV‘∂WíÜV¬∆íí∆V≈“íì∂˜&FW"Êf˜$V6ÇÜ∂Wì”Á∂6ˆÁ7BV√÷÷ÊvWBÜ∂Wíì∂ñbÜV¬ó¶ˆÊRÊVÊD6Üñ∆BÜV¬ó“ó–¶gVÊ7Fñˆ‚«î∆≈6fVD∆ñ˜WG2Çó∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ∆ñ˜WB◊¶ˆÊR¬Ê∆ñ˜WB÷∆ˆ˜6R◊¶ˆÊRríÊf˜$V6Çá¶ˆÊS”Á∂6ˆÁ7BvS“á¶ˆÊRÊ6∆˜6W7BÇrÁfñWrrìÚÊñG«¬wfñWr÷˜fW'fñWrríÁ&W∆6RÇıÁfñWr“Ú¬rrì∂6ˆÁ7B˜&FW#’TïÙƒîıUE5∑vU”ÚÊ∆ñ˜WCÚÂ∑¶ˆÊT∂Wíá¶ˆÊRï”∂«ï¶ˆÊT˜&FW"á¶ˆÊR∆˜&FW"ó“ó–¶gVÊ7Fñˆ‚vT∆ñ˜WE6Ê6Ü˜BávRó∂6ˆÁ7BfñWs÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwfñWr“r∑vRì∂6ˆÁ7B˜WC◊∑”∂ñbÇfñWró&WGW&‚˜WC∑fñWrÁVW'ï6V∆V7F˜$∆¬ÇrÊ∆ñ˜WB◊¶ˆÊR¬Ê∆ñ˜WB÷∆ˆ˜6R◊¶ˆÊRríÊf˜$V6Çá¶ˆÊS”Á∂6ˆÁ7B∂Wì◊¶ˆÊT∂Wíá¶ˆÊRì∂ñbÜ∂Wíñ˜WE∂∂Wï”÷÷˜f&∆T6Üñ∆G&V‚á¶ˆÊRíÊ÷ÇÜV¬∆íì”Ê∆ñ˜WDóFV‘∂WíÜV¬∆ííó“ì∑&WGW&‚˜WG–¶7ñÊ2gVÊ7Fñˆ‚∆ˆETî∆ñ˜WG2Çó∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜Víˆ∆ñ˜WG2rìµTïÙƒîıUE3◊"Ê∆ñ˜WG7««∑◊÷6F6ÇÜRóµTïÙƒîıUE3◊∑◊◊&Vvó7FW$∆ñ˜WE¶ˆÊW2Çì∂ñÊóE6ñFV&$∆ñ˜WBÇó–¶gVÊ7Fñˆ‚7ñÊ4∆ñ˜WDG&vv&∆RÇó∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ∆ñ˜WB÷÷˜f&∆RríÊf˜$V6ÇÜV√”Á∂V¬ÊG&vv&∆S“ÑƒîıUEÙTDïDî‰rbd‘Ró“ó–¶gVÊ7Fñˆ‚Fˆvv∆T∆ñ˜WDVFóFñÊrÜWfVÁBó∂WfVÁCÚÁ&WfVÁDFVfV«BÇì∂ñbÇ‘Ró&WGW&„¥ƒîıUEÙTDïDî‰s“ƒîıUEÙTDïDî‰s∂Fˆ7V÷VÁBÊ&ˆGíÊ6∆74∆ó7BÁFˆvv∆RÇv∆ñ˜WB÷VFóFñÊrrƒƒîıUEÙTDïDî‰rì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ∆ñ˜WB÷'&ÊvR÷'F‚ríÊf˜$V6ÇÜ#”Ê"ÊñÊÊW$ÖD‘√‘ƒîıUEÙTDïDî‰sÚ	˘I"fñÊó6Ç&V˜&FW&ñÊrs¢~(iR&V˜&FW"vRrì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ∆ñ˜WB÷'&ÊvR÷∆&V¬ríÊf˜$V6ÇáÉ”ÁÇÁFWáD6ˆÁFVÁC‘ƒîıUEÙTDïDî‰sÚtfñÊó6Ç&V˜&FW&ñÊrs¢u&V˜&FW"vRrì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ∆ñ˜WB◊6fR◊7FFRríÊf˜$V6ÇáÉ”ÁÇÁFWáD6ˆÁFVÁC‘ƒîıUEÙTDïDî‰sÚtG&r6&G2FÚ÷˜fR(	B6ÜÊvW26fRWFˆ÷Fñ6∆«ís¢rrì∑&Vvó7FW$∆ñ˜WE¶ˆÊW2Çì∑7ñÊ4∆ñ˜WDG&vv&∆RÇó–¶gVÊ7Fñˆ‚∆ñ˜WDG&˜ñÊFWÇá¶ˆÊR«Ç«í∆G&vvVBó∂6ˆÁ7BóFV◊3÷÷˜f&∆T6Üñ∆G&V‚á¶ˆÊRíÊfñ«FW"ÜV√”ÊV¬”÷G&vvVBì∂ñbÇóFV◊2Ê∆VÊwFÇó&WGW&‚ÁV∆√∂∆WB&W7C÷ÁV∆¬∆&W7DFó7FÊ6S‘ñÊfñÊóGì∂f˜"Ü6ˆÁ7BV¬ˆbóFV◊2ó∂6ˆÁ7B#÷V¬ÊvWD&˜VÊFñÊt6∆ñVÁE&V7BÇí∆7É◊"Ê∆VgB∑"ÁvñGFÇÛ"∆7ì◊"ÁF˜∑"ÊÜVñváBÛ"∆C‘÷FÇÊáó˜BáÇ÷7Ç«í÷7íì∂ñbÜC∆&W7DFó7FÊ6Ró∂&W7DFó7FÊ6S÷C∂&W7C◊∂V¬∆&Vf˜&S¢Ñ÷FÇÊ'2áí÷7íì‰÷FÇÊ'2áÇ÷7Çíì˜ì∆7ìßÉ∆7á◊◊◊&WGW&‚&W7G–¶gVÊ7Fñˆ‚6∆V$∆ñ˜WEF&vWG2Çó∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊ∆ñ˜WB÷G&˜◊F&vWBríÊf˜$V6ÇáÉ”ÁÇÊ6∆74∆ó7BÁ&V÷˜fRÇv∆ñ˜WB÷G&˜◊F&vWBríó–¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇvG&w7F'Br∆S”Á∂6ˆÁ7BV√÷RÁF&vWBÊ6∆˜6W7CÚ‚ÇrÊ∆ñ˜WB÷÷˜f&∆Rrì∂ñbÇƒîıUEÙTDïDî‰w«¬V««¬‘Ró&WGW&„∂RÁ7F˜&˜vFñˆ‚Çì¥ƒîıUEÙE$ttTC÷V√∂V¬Ê6∆74∆ó7BÊFBÇv∆ñ˜WB÷G&vvñÊrrì∂RÊFFG&Á6fW"ÊVffV7D∆∆˜vVC“v÷˜fRs∂RÊFFG&Á6fW"Á6WDFFÇwFWáB˜∆ñ‚r∆V¬ÊFF6WBÊ∆ñ˜WD∂Wó«¬v6&Bró“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇvG&v˜fW"r∆S”Á∂ñbÇƒîıUEÙE$ttTBó&WGW&„∂6ˆÁ7B¶ˆÊS◊¶ˆÊTf˜$V∆V÷VÁBÜRÁF&vWBì∂ñbÇ¶ˆÊW««¶ˆÊR”◊¶ˆÊTf˜$V∆V÷VÁBÑƒîıUEÙE$ttTBíó&WGW&„∂RÁ&WfVÁDFVfV«BÇì∂RÊFFG&Á6fW"ÊG&˜VffV7C“v÷˜fRs∂6∆V$∆ñ˜WEF&vWG2Çì∂6ˆÁ7BÜóC÷∆ñ˜WDG&˜ñÊFWÇá¶ˆÊR∆RÊ6∆ñVÁEÇ∆RÊ6∆ñVÁEíƒƒîıUEÙE$ttTBì∂ÜóCÚÊV¬Ê6∆74∆ó7BÊFBÇv∆ñ˜WB÷G&˜◊F&vWBró“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇvG&˜r∆S”Á∂ñbÇƒîıUEÙE$ttTBó&WGW&„∂6ˆÁ7B¶ˆÊS◊¶ˆÊTf˜$V∆V÷VÁBÜRÁF&vWBì∂ñbÇ¶ˆÊW««¶ˆÊR”◊¶ˆÊTf˜$V∆V÷VÁBÑƒîıUEÙE$ttTBíó&WGW&„∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BÜóC÷∆ñ˜WDG&˜ñÊFWÇá¶ˆÊR∆RÊ6∆ñVÁEÇ∆RÊ6∆ñVÁEíƒƒîıUEÙE$ttTBì∂ñbÜÜóCÚÊV¬ó¶ˆÊRÊñÁ6W'D&Vf˜&RÑƒîıUEÙE$ttTB∆ÜóBÊ&Vf˜&SˆÜóBÊV√¶ÜóBÊV¬ÊÊWáE6ñ&∆ñÊrì∂6∆V$∆ñ˜WEF&vWG2Çì∑VWVT∆ñ˜WE6fRÜ7W'&VÁD∆ñ˜WEvRÇíó“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇvG&vVÊBr¬Çì”Á∂ñbÑƒîıUEÙE$ttTBîƒîıUEÙE$ttTBÊ6∆74∆ó7BÁ&V÷˜fRÇv∆ñ˜WB÷G&vvñÊrrì¥ƒîıUEÙE$ttTC÷ÁV∆√∂6∆V$∆ñ˜WEF&vWG2Çó“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆S”Á∂ñbÑƒîıUEÙTDïDî‰rbfRÁF&vWBÊ6∆˜6W7BÇrÊ∆ñ˜WB÷÷˜f&∆RríbbRÁF&vWBÊ6∆˜6W7BÇrÊ∆ñ˜WB÷F÷ñ‚◊Fˆˆ«2ríó∂RÁ&WfVÁDFVfV«BÇì∂RÁ7F˜&˜vFñˆ‚Çó◊“«G'VRì∞¶gVÊ7Fñˆ‚VWVT∆ñ˜WE6fRávRó∂6∆V%Fñ÷V˜WBÑƒîıUEı4dUıDî‘U"ì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂FF÷∆ñ˜WB◊7FFU“ríÊf˜$V6ÇáÉ”ÁÇÁFWáD6ˆÁFVÁC“u6fñÊ~(
brì¥ƒîıUEı4dUıDî‘U#◊6WEFñ÷V˜WBÇÇì”Á6fUvT∆ñ˜WBávRí√#Só–¶7ñÊ2gVÊ7Fñˆ‚6fUvT∆ñ˜WBávRó∂ñbÇ‘Ró&WGW&„∂6ˆÁ7B∆ñ˜WC◊vT∆ñ˜WE6Ê6Ü˜BávRì∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜Víˆ∆ñ˜WG2Úr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBávRí≤r˜W'6ˆÊ¬r«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂∆ñ˜WG“ó“ìµTïÙƒîıUE5∑vU”◊∂∆ñ˜WB«WFFVEˆ'ì§‘RÁW6W&Ê÷R«WFFVEˆCß"ÁWFFVEˆB«66˜S¢wW'6ˆÊ¬w”∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂FF÷∆ñ˜WB◊7FFU“ríÊf˜$V6ÇáÉ”ÁÇÁFWáD6ˆÁFVÁC“u6fVBf˜"r¥‘RÁW6W&Ê÷Ró÷6F6ÇÜRó∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬Çu∂FF÷∆ñ˜WB◊7FFU“ríÊf˜$V6ÇáÉ”ÁÇÁFWáD6ˆÁFVÁC“u6fRfñ∆VBró◊–¶7ñÊ2gVÊ7Fñˆ‚&W6WEvT∆ñ˜WBÜWfVÁBó∂WfVÁCÚÁ&WfVÁDFVfV«BÇì∂6ˆÁ7BvS÷7W'&VÁD∆ñ˜WEvRÇì∂ñbÇ‘Ró&WGW&„∂ñbÇ6ˆÊfó&“Çu&W6WBñ˜W"6&B˜6óFñˆÁ2ˆ‚FÜó2vRFÚFÜRtÙE4UîRFVfV«B∆ñ˜WCÚríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜Víˆ∆ñ˜WG2Úr∂VÊ6ˆFUU$î6ˆ◊ˆÊVÁBávRí≤r˜W'6ˆÊ¬r«∂÷WFÜˆC¢tDTƒUDRw“ì∂FV∆WFRTïÙƒîıUE5∑vU”∂∆ˆ6Fñˆ‚Á&V∆ˆBÇó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶∆WB4îDT$%ÙTDïDî‰s÷f«6S∞¶∆WB4îDT$%ÙE$ttTC÷ÁV∆√∞¶∆WB4îDT$%ı4dUıDî‘U#÷ÁV∆√∞¶gVÊ7Fñˆ‚6ñFV&%6V7Fñˆ‰∂WíÜÜVFñÊró∑&WGW&‚∆ñ˜WE6«VrÜÜVFñÊsÚÁFWáD6ˆÁFVÁG«¬w6ñFV&"ró–¶gVÊ7Fñˆ‚6ñFV&$ÜVFñÊw2Çó∑&WGW&‚≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊÊf∆ó7B‚ÊÊg6V7Fñˆ‚rï◊–¶gVÊ7Fñˆ‚6ñFV&$óFV◊2Çó∑&WGW&‚≤‚‚ÊFˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊÊf∆ó7B‚ÊÊfóFV’∂FF◊fñWu“rï“Êfñ«FW"áÉ”ÁÇÊFF6WBÁfñWr”“v˜fW'fñWrró–¶gVÊ7Fñˆ‚76ñvÂ6ñFV&%6V7FñˆÁ2Çó∂∆WB6V7Fñˆ„“rs∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÊÊf∆ó7B‚¢ríÊf˜$V6ÇÜV√”Á∂ñbÜV¬Ê6∆74∆ó7BÊ6ˆÁFñÁ2ÇvÊg6V7Fñˆ‚ríó6V7Fñˆ„◊6ñFV&%6V7Fñˆ‰∂WíÜV¬ì∂V«6RñbÜV¬Ê÷F6ÜW2ÇrÊÊfóFV’∂FF◊fñWu“ríbfV¬ÊFF6WBÁfñWr”“v˜fW'fñWrrbbV¬ÊFF6WBÁ6ñFV&%6V7Fñˆ‚ñV¬ÊFF6WBÁ6ñFV&%6V7Fñˆ„◊6V7FñˆÁ“ó–¶gVÊ7Fñˆ‚6ñFV&$VÊD÷&∂W"á6V7Fñˆ‚ó∂6ˆÁ7BÜVFñÊw3◊6ñFV&$ÜVFñÊw2Çí∆ñÊFWÉ÷ÜVFñÊw2ÊfñÊDñÊFWÇÜÉ”Á6ñFV&%6V7Fñˆ‰∂WíÜÇì””◊6V7Fñˆ‚ì∑&WGW&‚ñÊFWÉ„”ˆÜVFñÊw5∂ñÊFWÇ≥◊«∆ÁV∆√¶ÁV∆«–¶gVÊ7Fñˆ‚«ï6ñFV&$∆ñ˜WBÇó∂76ñvÂ6ñFV&%6V7FñˆÁ2Çì∂6ˆÁ7B6fVC’TïÙƒîıUE2Á6ñFV&#ÚÊ∆ñ˜WG««∑“∆óFV◊3◊6ñFV&$óFV◊2Çí∆÷÷ÊWr÷ÜóFV◊2Ê÷áÉ”Â∑ÇÊFF6WBÁfñWr«Ö“íì¥ˆ&¶V7BÊVÁG&ñW2á6fVBíÊf˜$V6ÇÇÖ∑6V7Fñˆ‚∆∂Wó5“ì”Á∂ñbÑ'&íÊó4'&íÜ∂Wó2íñ∂Wó2Êf˜$V6ÇÜ∂Wì”Á∂6ˆÁ7BóFV”÷÷ÊvWBÜ∂Wíì∂ñbÜóFV“ñóFV“ÊFF6WBÁ6ñFV&%6V7Fñˆ„◊6V7FñˆÁ“ó“ì∑6ñFV&$ÜVFñÊw2ÇíÊf˜$V6ÇÜÜVFñÊs”Á∂6ˆÁ7B6V7Fñˆ„◊6ñFV&%6V7Fñˆ‰∂WíÜÜVFñÊrí∆VÊC◊6ñFV&$VÊD÷&∂W"á6V7Fñˆ‚í∆˜&FW&VC“Ñ'&íÊó4'&íá6fVE∑6V7FñˆÂ“ì˜6fVE∑6V7FñˆÂ”•µ“íÊ÷Ü∂Wì”Ê÷ÊvWBÜ∂WíííÊfñ«FW"Ñ&ˆˆ∆V‚í«&V÷ñÊñÊs÷óFV◊2Êfñ«FW"áÉ”ÁÇÊFF6WBÁ6ñFV&%6V7Fñˆ„””◊6V7Fñˆ‚bb˜&FW&VBÊñÊ6«VFW2áÇíìµ≤‚‚Ê˜&FW&VB¬‚‚Á&V÷ñÊñÊu“Êf˜$V6ÇÜóFV””ÊÜVFñÊrÁ&VÁDÊˆFRÊñÁ6W'D&Vf˜&RÜóFV“∆VÊBíó“ó–¶gVÊ7Fñˆ‚6ñFV&$∆ñ˜WE6Ê6Ü˜BÇó∂6ˆÁ7B˜WC◊∑”∑6ñFV&$ÜVFñÊw2ÇíÊf˜$V6ÇÜÉ”Ê˜WE∑6ñFV&%6V7Fñˆ‰∂WíÜÇï”’µ“ì∑6ñFV&$óFV◊2ÇíÊf˜$V6ÇÜóFV””Á∂6ˆÁ7B6V7Fñˆ„÷óFV“ÊFF6WBÁ6ñFV&%6V7Fñˆ„∂ñbÜ˜WE∑6V7FñˆÂ“ñ˜WE∑6V7FñˆÂ“ÁW6ÇÜóFV“ÊFF6WBÁfñWró“ì∑&WGW&‚˜WG–¶gVÊ7Fñˆ‚ñÊóE6ñFV&$∆ñ˜WBÇó∂«ï6ñFV&$∆ñ˜WBÇì∑6ñFV&$óFV◊2ÇíÊf˜$V6ÇÜóFV””ÊóFV“ÊG&vv&∆S’4îDT$%ÙTDïDî‰ró–¶gVÊ7Fñˆ‚Fˆvv∆U6ñFV&$VFóFñÊrÜWfVÁBó∂WfVÁCÚÁ&WfVÁDFVfV«BÇì∂ñbÇ‘Ró&WGW&„µ4îDT$%ÙTDïDî‰s“4îDT$%ÙTDïDî‰s∂Fˆ7V÷VÁBÊ&ˆGíÊ6∆74∆ó7BÁFˆvv∆RÇw6ñFV&"÷'&ÊvñÊrr≈4îDT$%ÙTDïDî‰rì∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁ6ñFV&"÷'&ÊvR÷∆&V¬ríÊf˜$V6ÇáÉ”ÁÇÁFWáD6ˆÁFVÁC’4îDT$%ÙTDïDî‰sÚtfñÊó6Ç6ñFV&"&V˜&FW"s¢u&V˜&FW"6ñFV&"rì∂ñÊóE6ñFV&$∆ñ˜WBÇó–¶gVÊ7Fñˆ‚6ñFV&$G&˜F&vWBáF&vWBó∂6ˆÁ7BóFV”◊F&vWBÊ6∆˜6W7CÚ‚ÇrÊÊfóFV’∂FF◊6ñFV&"◊6V7FñˆÂ“rì∂ñbÜóFV“ó&WGW&‚∂óFV“«6V7Fñˆ„¶óFV“ÊFF6WBÁ6ñFV&%6V7FñˆÁ”∂6ˆÁ7BÜVFñÊs◊F&vWBÊ6∆˜6W7CÚ‚ÇrÊÊg6V7Fñˆ‚rì∑&WGW&‚ÜVFñÊs˜∂óFV”¶ÁV∆¬∆ÜVFñÊr«6V7Fñˆ„ß6ñFV&%6V7Fñˆ‰∂WíÜÜVFñÊró”¶ÁV∆«–¶gVÊ7Fñˆ‚6∆V%6ñFV&%F&vWG2Çó∂Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁ6ñFV&"÷G&˜◊F&vWBríÊf˜$V6ÇáÉ”ÁÇÊ6∆74∆ó7BÁ&V÷˜fRÇw6ñFV&"÷G&˜◊F&vWBríó–¶gVÊ7Fñˆ‚VWVU6ñFV&%6fRÇó∂6∆V%Fñ÷V˜WBÖ4îDT$%ı4dUıDî‘U"ì∂6ˆÁ7B7FFS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw6ñFV&%6fU7FFRrì∂ñbá7FFRó7FFRÁFWáD6ˆÁFVÁC“u6fñÊ~(
bsµ4îDT$%ı4dUıDî‘U#◊6WEFñ÷V˜WBá6fU6ñFV&$∆ñ˜WB√##ó–¶7ñÊ2gVÊ7Fñˆ‚6fU6ñFV&$∆ñ˜WBÇó∂ñbÇ‘Ró&WGW&„∂6ˆÁ7B∆ñ˜WC◊6ñFV&$∆ñ˜WE6Ê6Ü˜BÇì∑G'ó∂6ˆÁ7B#÷vóBß6ˆ‚Çrˆí˜c˜Víˆ∆ñ˜WG2˜6ñFV&"˜W'6ˆÊ¬r«∂÷WFÜˆC¢uUBr∆ÜVFW'3ß≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚w“∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂∆ñ˜WG“ó“ìµTïÙƒîıUE2Á6ñFV&#◊∂∆ñ˜WB«WFFVEˆ'ì§‘RÁW6W&Ê÷R«WFFVEˆCß"ÁWFFVEˆB«66˜S¢wW'6ˆÊ¬w”∂6ˆÁ7B7FFS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw6ñFV&%6fU7FFRrì∂ñbá7FFRó7FFRÁFWáD6ˆÁFVÁC“u6fVBf˜"r¥‘RÁW6W&Ê÷W÷6F6ÇÜRó∂6ˆÁ7B7FFS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw6ñFV&%6fU7FFRrì∂ñbá7FFRó7FFRÁFWáD6ˆÁFVÁC“u6fRfñ∆VC¢r∂RÊ÷W76vW◊–¶7ñÊ2gVÊ7Fñˆ‚&W6WE6ñFV&$∆ñ˜WBÜWfVÁBó∂WfVÁCÚÁ&WfVÁDFVfV«BÇì∂ñbÇ‘W«¬6ˆÊfó&“Çu&W6WBFÜR6ñFV&"FÚFÜRtÙE4UîRFVfV«B˜&FW#Úríó&WGW&„∑G'ó∂vóBß6ˆ‚Çrˆí˜c˜Víˆ∆ñ˜WG2˜6ñFV&"˜W'6ˆÊ¬r«∂÷WFÜˆC¢tDTƒUDRw“ì∂FV∆WFRTïÙƒîıUE2Á6ñFV&#∂∆ˆ6Fñˆ‚Á&V∆ˆBÇó÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vRó◊–¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇvG&w7F'Br∆S”Á∂6ˆÁ7BóFV”÷RÁF&vWBÊ6∆˜6W7CÚ‚ÇrÊÊfóFV’∂FF◊6ñFV&"◊6V7FñˆÂ“rì∂ñbÇ4îDT$%ÙTDïDî‰w«¬óFV“ó&WGW&„∂RÁ7F˜&˜vFñˆ‚Çìµ4îDT$%ÙE$ttTC÷óFV”∂óFV“Ê6∆74∆ó7BÊFBÇw6ñFV&"÷G&vvñÊrrì∂RÊFFG&Á6fW"ÊVffV7D∆∆˜vVC“v÷˜fRs∂RÊFFG&Á6fW"Á6WDFFÇwFWáB˜∆ñ‚r∆óFV“ÊFF6WBÁfñWró“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇvG&v˜fW"r∆S”Á∂ñbÇ4îDT$%ÙE$ttTBó&WGW&„∂6ˆÁ7BÜóC◊6ñFV&$G&˜F&vWBÜRÁF&vWBì∂ñbÇÜóBó&WGW&„∂RÁ&WfVÁDFVfV«BÇì∂RÁ7F˜&˜vFñˆ‚Çì∂6∆V%6ñFV&%F&vWG2Çì≤ÜÜóBÊóFV◊«∆ÜóBÊÜVFñÊrìÚÊ6∆74∆ó7BÊFBÇw6ñFV&"÷G&˜◊F&vWBró“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇvG&˜r∆S”Á∂ñbÇ4îDT$%ÙE$ttTBó&WGW&„∂6ˆÁ7BÜóC◊6ñFV&$G&˜F&vWBÜRÁF&vWBì∂ñbÇÜóBó&WGW&„∂RÁ&WfVÁDFVfV«BÇì∂RÁ7F˜&˜vFñˆ‚Çì∂6ˆÁ7B∆ó7C÷Fˆ7V÷VÁBÁVW'ï6V∆V7F˜"ÇrÊÊf∆ó7Brìµ4îDT$%ÙE$ttTBÊFF6WBÁ6ñFV&%6V7Fñˆ„÷ÜóBÁ6V7Fñˆ„∂ñbÜÜóBÊóFV“bfÜóBÊóFV“”’4îDT$%ÙE$ttTBó∂6ˆÁ7B#÷ÜóBÊóFV“ÊvWD&˜VÊFñÊt6∆ñVÁE&V7BÇì∂∆ó7BÊñÁ6W'D&Vf˜&RÖ4îDT$%ÙE$ttTB∆RÊ6∆ñVÁEì«"ÁF˜∑"ÊÜVñváBÛ#ˆÜóBÊóFV”¶ÜóBÊóFV“ÊÊWáE6ñ&∆ñÊró÷V«6RñbÜÜóBÊÜVFñÊró∂∆ó7BÊñÁ6W'D&Vf˜&RÖ4îDT$%ÙE$ttTB∆ÜóBÊÜVFñÊrÊÊWáE6ñ&∆ñÊró÷6∆V%6ñFV&%F&vWG2Çì∑VWVU6ñFV&%6fRÇó“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇvG&vVÊBr¬Çì”Á∂ñbÖ4îDT$%ÙE$ttTBï4îDT$%ÙE$ttTBÊ6∆74∆ó7BÁ&V÷˜fRÇw6ñFV&"÷G&vvñÊrrìµ4îDT$%ÙE$ttTC÷ÁV∆√∂6∆V%6ñFV&%F&vWG2Çó“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆S”Á∂ñbÖ4îDT$%ÙTDïDî‰rbfRÁF&vWBÊ6∆˜6W7BÇrÊÊfóFV’∂FF◊6ñFV&"◊6V7FñˆÂ“ríó∂RÁ&WfVÁDFVfV«BÇì∂RÁ7F˜&˜vFñˆ‚Çó◊“«G'VRì∞¶6ˆÁ7B∆ñ˜WDˆ'6W'fW#÷ÊWr◊WFFñˆ‰ˆ'6W'fW"ÇÇì”Á∂ñbÇƒîıUEÙTDïDî‰ró∂6∆V%Fñ÷V˜WBávñÊF˜rÂıˆ∆ñ˜WE&Vg&W6Çì∑vñÊF˜rÂıˆ∆ñ˜WE&Vg&W6É◊6WEFñ÷V˜WBá&Vvó7FW$∆ñ˜WE¶ˆÊW2√#ó◊“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇtDÙ‘6ˆÁFVÁD∆ˆFVBr¬Çì”Á∂6ˆÁ7B÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvrì∂ñbÜñ∆ñ˜WDˆ'6W'fW"Êˆ'6W'fRÜ«∂6Üñ∆D∆ó7CßG'VR«7V'G&VSßG'VW“ó“ì∞†¶gVÊ7Fñˆ‚«ïFÜV÷RáFÜV÷R«W'6ó7C◊G'VRó∞¢6ˆÁ7BÊWáC◊FÜV÷S””“vF&≤sÚvF&≤s¢v∆ñváBs∞¢Fˆ7V÷VÁBÊFˆ7V÷VÁDV∆V÷VÁBÊFF6WBÁFÜV÷S÷ÊWáC∞¢Fˆ7V÷VÁBÊ&ˆGìÚÁ6WDGG&ñ'WFRÇvFF◊FÜV÷Rr∆ÊWáBì∞¢6ˆÁ7Bñ6ˆ„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFÜV÷Tñ6ˆ‚rí∆∆&V√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFÜV÷T∆&V¬rí∆'WGFˆ„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwFÜV÷UFˆvv∆Rrì∞¢ñbÜñ6ˆ‚ññ6ˆ‚ÁFWáD6ˆÁFVÁC÷ÊWáC””“vF&≤sÚ~)às¢~)ã‚s∞¢ñbÜ∆&V¬ñ∆&V¬ÁFWáD6ˆÁFVÁC÷ÊWáC””“vF&≤sÚt∆ñváBs¢tF&≤s∞¢ñbÜ'WGFˆ‚ó∞¢'WGFˆ‚ÁFóF∆S÷ÊWáC””“vF&≤sÚu7vóF6ÇFÚ∆ñváB÷ˆFRs¢u7vóF6ÇFÚF&≤÷ˆFRs∞¢'WGFˆ‚Á6WDGG&ñ'WFRÇv&ñ÷∆&V¬r∆'WGFˆ‚ÁFóF∆Rì∞¢'WGFˆ‚Á6WDGG&ñ'WFRÇv&ñ◊&W76VBr∆ÊWáC””“vF&≤sÚwG'VRs¢vf«6Rrì∞¢–¢ñbáW'6ó7Bó∑G'ó∂∆ˆ6≈7F˜&vRÁ6WDóFV“ÇvvˆG6WñU˜FÜV÷Rr∆ÊWáBó÷6F6ÇÜRó∑◊–ß–¶gVÊ7Fñˆ‚Fˆvv∆UFÜV÷RÇó∂«ïFÜV÷RÜFˆ7V÷VÁBÊFˆ7V÷VÁDV∆V÷VÁBÊFF6WBÁFÜV÷S””“vF&≤sÚv∆ñváBs¢vF&≤ró–¶gVÊ7Fñˆ‚ñÊóFñ∆ó¶UFÜV÷RÇó∞¢∆WB6fVC÷ÁV∆√∞¢G'ó∑6fVC÷∆ˆ6≈7F˜&vRÊvWDóFV“ÇvvˆG6WñU˜FÜV÷Rró÷6F6ÇÜRó∑–¢ñbá6fVB”“vF&≤rbg6fVB”“v∆ñváBró∞¢6fVC“vF&≤s∞¢–¢«ïFÜV÷Rá6fVB∆f«6Rì∞ß–†¶gVÊ7Fñˆ‚ÜVFW$ÜV«FWáDf˜"Ü6ˆÁFñÊW"ó∞¢6ˆÁ7BÊˆFW3’µ”∞¢ñbÜ6ˆÁFñÊW"Ê6∆74∆ó7BÊ6ˆÁFñÁ2ÇvÜW&Úríó∞¢6ˆÁFñÊW"ÁVW'ï6V∆V7F˜$∆¬Çsß66˜R‚Fób‚Ê◊WFVB¬ß66˜R‚Fób‚ríÊf˜$V6ÇÜ„”ÊÊˆFW2ÁW6ÇÜ‚íì∞¢÷V«6W∞¢6ˆÁFñÊW"ÁVW'ï6V∆V7F˜$∆¬Çsß66˜R‚Ê◊WFVB¬ß66˜R‚Fób‚Ê◊WFVB¬ß66˜R‚Fób‚ríÊf˜$V6ÇÜ„”ÊÊˆFW2ÁW6ÇÜ‚íì∞¢–¢6ˆÁ7BFWáG3’µ”∞¢ÊˆFW2Êf˜$V6ÇÜ„”Á∞¢6ˆÁ7BFWáC“Ü‚ÁFWáD6ˆÁFVÁG«¬rríÁG&ñ“Çì∞¢ñbáFWáBbbFWáG2ÊñÊ6«VFW2áFWáBíóFWáG2ÁW6ÇáFWáBì∞¢‚Ê6∆74∆ó7BÊFBÇvÜVFW"÷ÜV«÷6˜írì∞¢ñbÇ6ˆÁFñÊW"Ê6∆74∆ó7BÊ6ˆÁFñÁ2ÇvÜW&Úríñ‚Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∞¢“ì∞¢&WGW&‚FWáG2Ê¶ˆñ‚Çu∆Â∆‚rì∞ß–¶gVÊ7Fñˆ‚FV6˜&FTÜVFW$ÜV«Çó∞¢Fˆ7V÷VÁBÁVW'ï6V∆V7F˜$∆¬ÇrÁfñWrÊÜW&Ú¬ÁfñWrÁF&∆R÷ÜVBríÊf˜$V6ÇÜ6ˆÁFñÊW#”Á∞¢ñbÜ6ˆÁFñÊW"ÊFF6WBÊÜVFW$ÜV«&VGì””“sró&WGW&„∞¢6ˆÁ7BÜVFñÊs÷6ˆÁFñÊW"ÁVW'ï6V∆V7F˜"ÇvÉ∆É"rì∞¢ñbÇÜVFñÊró&WGW&„∞¢6ˆÁ7BFWáC÷ÜVFW$ÜV«FWáDf˜"Ü6ˆÁFñÊW"ì∞¢ñbÇFWáBó&WGW&„∞¢ñbÜ6ˆÁFñÊW"Ê6∆74∆ó7BÊ6ˆÁFñÁ2ÇvÜW&Úríó∂6ˆÁFñÊW"ÊFF6WBÊÜVFW$ÜV«&VGì“ss∑&WGW&Á–¢6ˆÁ7Bw&W#÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇw7‚rì∞¢w&W"Ê6∆74Ê÷S“vÜVFW"÷ÜV«◊FóF∆Rs∞¢ÜVFñÊrÁ&VÁDÊˆFRÊñÁ6W'D&Vf˜&Ráw&W"∆ÜVFñÊrì∞¢w&W"ÊVÊD6Üñ∆BÜÜVFñÊrì∞¢6ˆÁ7B'F„÷Fˆ7V÷VÁBÊ7&VFTV∆V÷VÁBÇv'WGFˆ‚rì∞¢'F‚ÁGóS“v'WGFˆ‚s∞¢'F‚Ê6∆74Ê÷S“vÜVFW"÷ÜV«÷'F‚s∞¢'F‚ÁFWáD6ˆÁFVÁC“sÚs∞¢'F‚ÁFóF∆S“t÷˜&RñÊf˜&÷Fñˆ‚s∞¢'F‚Á6WDGG&ñ'WFRÇv&ñ÷∆&V¬r¬t÷˜&RñÊf˜&÷Fñˆ‚&˜WBr≤ÜÜVFñÊrÁFWáD6ˆÁFVÁG«¬wFÜó26V7Fñˆ‚ríÁG&ñ“Çíì∞¢'F‚ÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆WfVÁC”Á∞¢WfVÁBÁ&WfVÁDFVfV«BÇì∞¢WfVÁBÁ7F˜&˜vFñˆ‚Çì∞¢6ˆÁ7BWáG&3’≤‚‚‚Ü6ˆÁFñÊW"Ê6∆˜6W7BÇrÁÊV¬rìÚÁVW'ï6V∆V7F˜$∆¬ÇrÊÜVFW"÷ÜV«÷WáG&ró«≈µ“ï–¢Ê÷Ü„”‚Ü‚ÁFWáD6ˆÁFVÁG«¬rríÁG&ñ“ÇííÊfñ«FW"Ñ&ˆˆ∆V‚ì∞¢6ˆÁ7BÜV«FWáC’∑FWáB¬‚‚ÊWáG&5“Êfñ«FW"Ñ&ˆˆ∆V‚íÊ¶ˆñ‚Çu∆Â∆‚rì∞¢˜V‰ÜVFW$ÜV«ÇÜÜVFñÊrÁFWáD6ˆÁFVÁG«¬tñÊf˜&÷Fñˆ‚ríÁG&ñ“Çí∆ÜV«FWáBì∞¢“ì∞¢w&W"ÊVÊD6Üñ∆BÜ'F‚ì∞¢6ˆÁFñÊW"ÊFF6WBÊÜVFW$ÜV«&VGì“ss∞¢“ì∞ß–¶gVÊ7Fñˆ‚˜V‰ÜVFW$ÜV«áFóF∆R«FWáBó∞¢6ˆÁ7B÷ˆF√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜVFW$ÜV«÷ˆF¬rì∞¢ñbÇ÷ˆF¬ó&WGW&„∞¢Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜVFW$ÜV«÷ˆF≈FóF∆RríÁFWáD6ˆÁFVÁC◊FóF∆W«¬tñÊf˜&÷Fñˆ‚s∞¢Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜVFW$ÜV«÷ˆFƒ&ˆGíríÁFWáD6ˆÁFVÁC◊FWáG«¬rs∞¢÷ˆF¬Á7Gñ∆RÊFó7∆ì“vw&ñBs∞¢÷ˆF¬ÁVW'ï6V∆V7F˜"ÇrÊÜVFW"÷ÜV«÷6∆˜6RrìÚÊfˆ7W2Çì∞ß–¶gVÊ7Fñˆ‚6∆˜6TÜVFW$ÜV«Çó∞¢6ˆÁ7B÷ˆF√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜVFW$ÜV«÷ˆF¬rì∞¢ñbÜ÷ˆF¬ñ÷ˆF¬Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∞ß–¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆WfVÁC”Á∂ñbÜWfVÁBÊ∂Wì””“tW66Rrñ6∆˜6TÜVFW$ÜV«Çó“ì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆WfVÁC”Á∞¢6ˆÁ7B÷ˆF√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÜVFW$ÜV«÷ˆF¬rì∞¢ñbÜ÷ˆF¬bf÷ˆF¬Á7Gñ∆RÊFó7∆í”“vÊˆÊRrbfWfVÁBÁF&vWC””÷÷ˆF¬ñ6∆˜6TÜVFW$ÜV«Çì∞ß“ì∞¶7ñÊ2gVÊ7Fñˆ‚&ˆ˜BÇó∂FV6˜&FTÜVFW$ÜV«Çì∞¢ñÊóFñ∆ó¶UFÜV÷RÇì∞¢G'ó∞¢ñbÇvWD6ˆˆ∂ñRÇvvˆG6WñUˆ77&bríñvóBfWF6ÇÇrˆí˜cˆWFÇˆ77&brì∞¢‘S÷vóBß6ˆ‚Çrˆí˜cˆWFÇˆ÷Rrì∞¢÷6F6ÇÜRó∑6Ü˜t∆ˆvñ‚Çì∑&WGW&Á–¢6ˆÁ7BvÜÛ÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwvÜˆ÷írì∂ñbávÜÚóvÜÚÁFWáD6ˆÁFVÁC‘‘RÁW6W&Ê÷R≤rÇr¥‘RÁ&ˆ∆R≤rís∞¢6ˆÁ7BGS÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwF˜W6W"rì∂ñbáGRóGRÁFWáD6ˆÁFVÁC‘‘RÁW6W&Ê÷S∞¢6ˆÁ7Bw&VWFñÊs÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvF6Ü&ˆ&Dw&VWFñÊrrì∞¢ñbÜw&VWFñÊró∞¢6ˆÁ7BÜ˜W#÷ÊWrFFRÇíÊvWDÜ˜W'2Çí«'C÷Ü˜W#√#ÚtvˆˆB÷˜&ÊñÊrs¶Ü˜W#√ÉÚtvˆˆBgFW&Êˆˆ‚s¢tvˆˆBWfVÊñÊrs∞¢6ˆÁ7BÊ÷S“Ñ‘RÊFó7∆ïˆÊ÷W«ƒ‘RÁW6W&Ê÷W«¬vF÷ñ‚ríÁG&ñ“Çì∞¢w&VWFñÊrÁFWáD6ˆÁFVÁC◊'B≤r¬r∂Ê÷S∞¢–¢6ˆÁ7B6#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw66‰'F‚rì∂ñbá6"ó6"Á7Gñ∆RÊFó7∆ì’≤vF÷ñ‚r¬v˜W&F˜"u“ÊñÊ6«VFW2Ñ‘RÁ&ˆ∆RìÚvñÊ∆ñÊR÷&∆ˆ6≤s¢vÊˆÊRs∞¢≤vÊe'V∆W2r¬vÊeW6W'2u“Êf˜$V6ÇÜñC”Á∂6ˆÁ7B„÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜ‚ñ‚Á7Gñ∆RÊFó7∆ì‘‘RÁ&ˆ∆S””“vF÷ñ‚sÚrs¢vÊˆÊRw“ì∞¢6ˆÁ7BVFóDÊc÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊdVFóBrì∂ñbÜVFóDÊbñVFóDÊbÁ7Gñ∆RÊFó7∆ì’≤vF÷ñ‚r¬vVFóF˜"u“ÊñÊ6«VFW2Ñ‘RÁ&ˆ∆RìÚrs¢vÊˆÊRs∞¢«ï&ˆ∆Ufó6ñ&ñ∆óGíÇì∞¢vóB∆ˆETî∆ñ˜WG2Çì∞¢VÊ&∆U6˜'F&∆UF&∆W2Çì∞¢6ˆÁ7Bt&#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwu&V÷ñÊFW$&"rì∞¢ñbát&"ó∞¢ñbÑ‘RÁ77v˜&Eˆ6ÜÊvU˜&V÷ñÊFW%ˆFó2”◊VÊFVfñÊVBó∞¢t&"ÁFWáD6ˆÁFVÁC“~)™6WBÊWr77v˜&BvóFÜñ‚r¥‘RÁ77v˜&Eˆ6ÜÊvU˜&V÷ñÊFW%ˆFó2≤rFíá2í(	B6∆ñ6≤ÜW&RFÚFÚóBÊ˜r‚s∞¢t&"Á7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∞¢÷V«6Rt&"Á7Gñ∆RÊFó7∆ì“vÊˆÊRs∞¢–¢6Ü˜tÇì∞¢6ˆÁ7B&tÜ6É“Ü∆ˆ6Fñˆ‚ÊÜ6á«¬r6˜fW'fñWrríÁ6∆ñ6RÉì∞¢6Ü˜ufñWrÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwfñWr“r∑&tÜ6Çì˜&tÜ6É¢v˜fW'fñWrr∆f«6Rì∞¢&ˆ÷ó6RÊ∆≈6WGF∆VBÖ∞¢∆ˆDfñÊFñÊw2Çí¿¢‘RÁ&ˆ∆S””“vF÷ñ‚sˆ∆ˆEW6W'2Çì•&ˆ÷ó6RÁ&W6ˆ«fRÇí¿¢≤vF÷ñ‚r¬vVFóF˜"u“ÊñÊ6«VFW2Ñ‘RÁ&ˆ∆Rìˆ∆ˆDVFóBÇì•&ˆ÷ó6RÁ&W6ˆ«fRÇí¿¢∆ˆE6V7W&óGíÇí¿¢‘RÁ&ˆ∆S””“vF÷ñ‚sˆ∆ˆE'V∆W2Çì•&ˆ÷ó6RÁ&W6ˆ«fRÇê¢“ì∞¢6WDñÁFW'f¬ÇÇì”Á∞¢6ˆÁ7B˜c÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇwfñWr÷˜fW'fñWrrì∞¢ñbÜ˜bbf˜bÁ7Gñ∆RÊFó7∆í”“vÊˆÊRrñ∆ˆDF6Ü&ˆ&BÇì∞¢“√ì∞ß–¶6ÜV6¥ñÊóFñ≈6WGWÇíÁFÜV‚á&WVó&VC”Á∂ñbÇ&WVó&VBñ&ˆ˜BÇó“ì∞†¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÜRÊ∂Wí”“tW66Rró&WGW&„∂6ˆÁ7Bñ”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvñÁFVw&Fñˆ‰÷ˆF¬rí∆”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvÊ«óFñ74÷ˆF¬rí«&ñ”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFV∆WFTñÁFVw&Fñˆ‰÷ˆF¬rí∆F”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvFWfñ6T÷ˆF¬rí∆÷”÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇv÷ˆÊóF˜$÷ˆF¬rì∂ñbá&ñ“bg&ñ“Á7Gñ∆RÊFó7∆í”“vÊˆÊRró∂6∆˜6TFV∆WFTñÁFVw&Fñˆ‰÷ˆF¬Çì∑&WGW&Á÷ñbÜ“bf“Á7Gñ∆RÊFó7∆í”“vÊˆÊRró∂6∆˜6TÊ«óFñ74÷ˆF¬Çì∑&WGW&Á÷ñbÜñ“bfñ“Á7Gñ∆RÊFó7∆í”“vÊˆÊRró∂6∆˜6TñÁFVw&Fñˆ‰÷ˆF¬Çì∑&WGW&Á÷ñbÜ÷“bf÷“Á7Gñ∆RÊFó7∆í”“vÊˆÊRró∂6∆˜6T÷ˆÊóF˜$VFóF˜"Çì∑&WGW&Á÷ñbÜF“bfF“Á7Gñ∆RÊFó7∆í”“vÊˆÊRró∂6∆˜6TFDFWfñ6RÇì∑&WGW&Á◊“ì∞†¶6ˆÁ7BÜVFW$ÜV«ˆ'6W'fW#÷ÊWr◊WFFñˆ‰ˆ'6W'fW"ÇÇì”ÊFV6˜&FTÜVFW$ÜV«Çíì∞¶Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇtDÙ‘6ˆÁFVÁD∆ˆFVBr¬Çì”Á∞¢FV6˜&FTÜVFW$ÜV«Çì∞¢6ˆÁ7B&ˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇvrì∞¢ñbÜ&ˆ˜BñÜVFW$ÜV«ˆ'6W'fW"Êˆ'6W'fRÜ&ˆ˜B«∂6Üñ∆D∆ó7CßG'VR«7V'G&VSßG'VW“ì∞ß“ì∞†¶∆WB$T‘ıDUÙtTÂE3’µ”∞¶∆WB$T‘ıDUı4U54îÙ„÷ÁV∆√∞¶∆WB$T‘ıDUıÙƒ≈ıDî‘U#÷ÁV∆√∞¶∆WB$T‘ıDUÙe$‘Uı4U”∞¶∆WB$T‘ıDUÙ‘ıdUÙC”∞†¶gVÊ7Fñˆ‚&V÷˜FT77&bÇó∂6ˆÁ7B&s“ÜFˆ7V÷VÁBÊ6ˆˆ∂ñRÊ÷F6ÇÇrÉÛ•Á√≤ñvˆG6WñUˆ77&c“Öµ„µ“¢író«≈µ“ï≥◊«¬rs∑&WGW&‚FV6ˆFUU$î6ˆ◊ˆÊVÁBá&ró–¶7ñÊ2gVÊ7Fñˆ‚&V÷˜FTíáW&¬∆˜C◊∑“ó∞¢6ˆÁ7B˜FñˆÁ3◊≤‚‚Ê˜G”∂˜FñˆÁ2ÊÜVFW'3◊¥66WC¢v∆ñ6Fñˆ‚ˆß6ˆ‚r¬‚‚‚Ü˜BÊÜVFW'7««∑“ó”∂6ˆÁ7B÷WFÜˆC’7G&ñÊrÜ˜FñˆÁ2Ê÷WFÜˆG«¬ttUBríÁFıWW$66RÇì∞¢ñbÜ÷WFÜˆB”“ttUBrbf÷WFÜˆB”“tÑTBró∂˜FñˆÁ2ÊÜVFW'5≤uÇ‘55$b’Fˆ∂V‚u”◊&V÷˜FT77&bÇì∂ñbÜ˜FñˆÁ2Ê&ˆGíbb˜FñˆÁ2ÊÜVFW'5≤t6ˆÁFVÁB’GóRu“ñ˜FñˆÁ2ÊÜVFW'5≤t6ˆÁFVÁB’GóRu”“v∆ñ6Fñˆ‚ˆß6ˆ‚w–¢6ˆÁ7B#÷vóBfWF6ÇáW&¬∆˜FñˆÁ2ì∂6ˆÁ7BFWáC÷vóB"ÁFWáBÇì∂ñbá"Á7FGW3”””Có∂∆ˆ6Fñˆ‚Á&V∆ˆBÇì∑Fá&˜rÊWrW'&˜"Çu6ñv‚ñ‚&WVó&VBró÷ñbÇ"Êˆ≤óFá&˜rÊWrW'&˜"áFWáG«¬Çu&WVW7Bfñ∆VC¢r∑"Á7FGW2íì∂ñbÇFWáBó&WGW&Á∑”∑G'ó∑&WGW&‚•4Ù‚Á'6RáFWáBó÷6F6ÇÖÚó∑&WGW&Á∑FWáG◊–ß–†¶7ñÊ2gVÊ7Fñˆ‚∆ˆE&V÷˜FT66W72Çó∞¢G'óµ$T‘ıDUÙtTÂE3÷vóB&V÷˜FTíÇrˆí˜c˜vñÊF˜w2÷vVÁG2rì∑&VÊFW%&V÷˜FTvVÁG2Çì∑–¢6F6ÇÜRó∂6ˆÁ7B&ˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FTvVÁD∆ó7Brì∂ñbá&ˆ˜Bó&ˆ˜BÊñÊÊW$ÖD‘√÷∆Fób6∆73“&V◊Gí#‚G∂W62ÜRÊ÷W76vW«∆Ró”¬ˆFócÊ∑–ß–¶gVÊ7Fñˆ‚&VÊFW%&V÷˜FTvVÁG2Çó∞¢6ˆÁ7B&ˆ˜C÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FTvVÁD∆ó7Brì∂ñbÇ&ˆ˜Bó&WGW&„∞¢6ˆÁ7B“ÜFˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU6V&6ÇrìÚÁf«VW«¬rríÁG&ñ“ÇíÁFÙ∆˜vW$66RÇì∞¢6ˆÁ7B&˜w3’$T‘ıDUÙtTÂE2Êfñ«FW"Ü”‚«≈7G&ñÊrÜÊ6ˆ◊WFW%ˆÊ÷W«¬rríÁFÙ∆˜vW$66RÇíÊñÊ6«VFW2áó«≈7G&ñÊrÜÊÜ˜7FÊ÷W«¬rríÁFÙ∆˜vW$66RÇíÊñÊ6«VFW2áó«≈7G&ñÊrÜÊóˆFG&W77«¬rríÁFÙ∆˜vW$66RÇíÊñÊ6«VFW2áíì∞¢6ˆÁ7BˆÊ∆ñÊS’$T‘ıDUÙtTÂE2Êfñ«FW"Ü”ÊÁ7FGW3””“vˆÊ∆ñÊRríÊ∆VÊwFÉ∞¢6ˆÁ7B6WC“ÜñB«bì”Á∂6ˆÁ7BV√÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÜñBì∂ñbÜV¬ñV¬ÁFWáD6ˆÁFVÁC◊g”∑6WBÇw&V÷˜FTˆÊ∆ñÊT6˜VÁBr∆ˆÊ∆ñÊRì∑6WBÇw&V÷˜FTˆff∆ñÊT6˜VÁBrƒ÷FÇÊ÷ÇÉ≈$T‘ıDUÙtTÂE2Ê∆VÊwFÇ÷ˆÊ∆ñÊRíì∑6WBÇw&V÷˜FUF˜Fƒ6˜VÁBr≈$T‘ıDUÙtTÂE2Ê∆VÊwFÇì∞¢&ˆ˜BÊñÊÊW$ÖD‘√◊&˜w2Ê∆VÊwFÉ˜&˜w2Ê÷Ü”Á∂6ˆÁ7Bˆ„÷Á7FGW3””“vˆÊ∆ñÊRs∂6ˆÁ7B7W˜'FVC“Á&V÷˜FU˜7W˜'FVC∂∆WB7Fñˆ„“rs∂ñbÜˆ‚bg7W˜'FVBñ7Fñˆ„÷∆'WGFˆ‚6∆73“'&ñ÷'í&V÷˜FR÷6ˆÊÊV7B"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'7F'E&V÷˜FU6W76ñˆ‚ÇG∂ÊñG“í#‰6ˆÊÊV7C¬ˆ'WGFˆ„Ê∂V«6RñbÇ7W˜'FVBñ7Fñˆ„÷∆'WGFˆ‚6∆73“'6V6ˆÊF'í&V÷˜FR÷6ˆÊÊV7B"GóS“&'WGFˆ‚"Fó6&∆VBFóF∆S“%Ww&FRFÚvVÁB"„B„B#ÂWw&FRvVÁC¬ˆ'WGFˆ„Ê∂V«6R7Fñˆ„÷∆'WGFˆ‚6∆73“'6V6ˆÊF'í&V÷˜FR÷6ˆÊÊV7B"GóS“&'WGFˆ‚"Fó6&∆VC‰ˆff∆ñÊS¬ˆ'WGFˆ„Ê∂ñbÜÁ&Wfˆ∂VEˆG«∆Á7FGW3””“w&Wfˆ∂VBrñ7Fñˆ„÷∆'WGFˆ‚6∆73“&FÊvW"F÷ñ‚÷ˆÊ«í"GóS“&'WGFˆ‚"ˆÊ6∆ñ6≥“'W&vUvñÊF˜w4vVÁBÇG∂ÊñG“í#Â&V÷˜fS¬ˆ'WGFˆ„Ê∑&WGW&‚∆Fób6∆73“'&V÷˜FR÷vVÁB◊&˜r#„∆Fób6∆73“'&V÷˜FR÷vVÁB÷÷ñ‚#„∆Fób6∆73“'&V÷˜FR÷vVÁB÷Ê÷R#„«7‚6∆73“'&V÷˜FR÷F˜BG∂ˆ„ÚvˆÊ∆ñÊRs¢vˆff∆ñÊRw“#„¬˜7„‚G∂W62ÜÊ6ˆ◊WFW%ˆÊ÷W«∆ÊÜ˜7FÊ÷W«¬ÇtvVÁBr∂ÊñBíó”¬ˆFóc„∆Fób6∆73“'&V÷˜FR÷vVÁB◊7V"#‚G∂W62ÜÊóˆFG&W77«¬tÊÚïró“+rvVÁBG∂W62ÜÊvVÁE˜fW'6ñˆÁ«¬wVÊ∂Ê˜v‚ró“+rG∂W62ÜÊ˜5˜fW'6ñˆÁ«¬uvñÊF˜w2ró”¬ˆFóc„¬ˆFóc‚G∂7FñˆÁ”¬ˆFócÊ“íÊ¶ˆñ‚Çrrì¶∆Fób6∆73“&V◊Gí#‰ÊÚ÷F6ÜñÊrvñÊF˜w2vVÁG2„¬ˆFócÊ∞ß–¶7ñÊ2gVÊ7Fñˆ‚7F'E&V÷˜FU6W76ñˆ‚ÜvVÁDñBó∞¢G'ó∞¢6ˆÁ7B#÷vóB&V÷˜FTíÇrˆí˜c˜&V÷˜FR÷66W72˜6W76ñˆÁ2r«∂÷WFÜˆC¢uı5Br∆&ˆGì§•4Ù‚Á7G&ñÊvñgíá∂vVÁEˆñC¶vVÁDñG“ó“ìµ$T‘ıDUı4U54îÙ„◊"Á6W76ñˆ„µ$T‘ıDUÙe$‘Uı4U”∞¢6ˆÁ7B’$T‘ıDUÙtTÂE2ÊfñÊBáÉ”ÁÇÊñC””÷vVÁDñBó««∑”∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU6W76ñˆÂFóF∆RríÁFWáD6ˆÁFVÁC“u&V÷˜FR6W76ñˆ‚(	Br≤ÜÊ6ˆ◊WFW%ˆÊ÷W«¬uvñÊF˜w2vVÁBrì∞¢Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU6W76ñˆÂ7FGW2ríÁFWáD6ˆÁFVÁC“uvóFñÊrf˜"FÜR6ñvÊVB÷ñ‚vñÊF˜w2W6W"FÚ&˜fR66W7>(
bs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU6W76ñˆÂ7FGW2ríÊ6∆74∆ó7BÊFBÇw&V÷˜FR◊vóFñÊrrì∞¢Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FTFó66ˆÊÊV7D'F‚ríÊFó6&∆VC÷f«6S∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VVÂw&ríÊfˆ7W2Çì∑ˆ∆≈&V÷˜FU6W76ñˆ‚Çì∞¢÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vW«∆Rì∑–ß–¶gVÊ7Fñˆ‚&V÷˜FU7FFT÷W76vRá7FFR∆∆7DW'&˜#“rró∞¢6ˆÁ7B÷W76vW3◊∞¢&WVW7FVC¢u&V÷˜FR&WVW7BVWVVBf˜"FÜRvñÊF˜w2vVÁN(
br¿¢vóFñÊuˆf˜%˜G&ì¢uvóFñÊrf˜"FÜRtÙE4UîRG&íñ‚FÜR6ñvÊVB÷ñ‚vñÊF˜w26W76ñˆÓ(
br¿¢G&ï˜&VGì¢ttÙE4UîRG&íó2&VGí‚&W&ñÊr∆ˆ6¬&˜fŒ(
br¿¢vóFñÊuˆf˜%˜W6W#¢uvóFñÊrf˜"FÜR6ñvÊVB÷ñ‚vñÊF˜w2W6W"FÚ6∆ñ6≤∆∆˜r˜"FVÁû(
br¿¢&˜fVC¢uW6W"&˜fVB66W72‚&W&ñÊr67&VV‚6GW&^(
br¿¢6GW&U˜7F'FVC¢u67&VV‚6GW&R7F'FVB‚vóFñÊrf˜"FÜRfó'7BfW&ñfñVB•Trg&÷^(
br¿¢7FófS¢t6ˆÊÊV7FVB+rñÁFW&7FófR7W˜'B6W76ñˆ‚7FófRr¿¢FVÊñVC¢uFÜR6ñvÊVB÷ñ‚vñÊF˜w2W6W"FVÊñVBFÜó2&V÷˜FR&WVW7B‚r¿¢fñ∆VC¢t6ˆÊÊV7Fñˆ‚fñ∆VC¢r≤Ü∆7DW'&˜'«¬vFW6∑F˜6GW&R˜"vVÁB6ˆ÷◊VÊñ6Fñˆ‚fñ∆VBrí¿¢VÊFVC¢u&V÷˜FR6W76ñˆ‚VÊFVB‚p¢”∞¢&WGW&‚÷W76vW5∑7FFU◊«¬Çu&V÷˜FR6W76ñˆ„¢rµ7G&ñÊrá7FFW«¬wVÊ∂Ê˜v‚ríÁ&W∆6T∆¬ÇuÚr¬rríì∞ß–¶7ñÊ2gVÊ7Fñˆ‚ˆ∆≈&V÷˜FU6W76ñˆ‚Çó∞¢ñbÇ$T‘ıDUı4U54îÙ‚ó&WGW&„∂6∆V%Fñ÷V˜WBÖ$T‘ıDUıÙƒ≈ıDî‘U"ì∞¢G'ó∞¢6ˆÁ7B3÷vóB&V÷˜FTíÜˆí˜c˜&V÷˜FR÷66W72˜6W76ñˆÁ2ÚGµ$T‘ıDUı4U54îÙ‚ÊñG÷ìµ$T‘ıDUı4U54îÙ„◊3∞¢6ˆÁ7B7FGW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU6W76ñˆÂ7FGW2rì∂6ˆÁ7Bñ÷s÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VV‚rì∂6ˆÁ7BV◊Gì÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FTV◊Gírì∞¢6ˆÁ7BVÊFñÊs’≤w&WVW7FVBr¬wvóFñÊuˆf˜%˜G&ír¬wG&ï˜&VGír¬wvóFñÊuˆf˜%˜W6W"r¬v&˜fVBr¬v6GW&U˜7F'FVBu“ÊñÊ6«VFW2á2Á7FGW2ì∞¢6ˆÁ7BFW&÷ñÊ√’≤vFVÊñVBr¬vfñ∆VBr¬vVÊFVBu“ÊñÊ6«VFW2á2Á7FGW2ì∞¢7FGW2Ê6∆74∆ó7BÁFˆvv∆RÇw&V÷˜FR◊vóFñÊrr«VÊFñÊrì∑7FGW2ÁFWáD6ˆÁFVÁC◊&V÷˜FU7FFT÷W76vRá2Á7FGW2«2Ê∆7EˆW'&˜'«¬rrì∞¢ñbá2Á7FGW3””“v7FófRró∞¢V◊GíÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂ñ÷rÁ7Gñ∆RÊFó7∆ì“v&∆ˆ6≤s∂6ˆÁ7Bg&÷UvñGFÉ‘ÁV÷&W"á2Ê∆7E˜vñGFá«√í∆g&÷TÜVñváC‘ÁV÷&W"á2Ê∆7EˆÜVñváG«√ì∂ñbÜg&÷UvñGFÉ„bfg&÷TÜVñváC„ó∂ñ÷rÁvñGFÉ÷g&÷UvñGFÉ∂ñ÷rÊÜVñváC÷g&÷TÜVñváC∂ñ÷rÊFF6WBÁ&V÷˜FUvñGFÉ’7G&ñÊrÜg&÷UvñGFÇì∂ñ÷rÊFF6WBÁ&V÷˜FTÜVñváC’7G&ñÊrÜg&÷TÜVñváBì∑÷6ˆÁ7Bg&÷U6W‘ÁV÷&W"á2Êg&÷U˜6W«√ì∂ñbÜg&÷U6W„bfg&÷U6W”’$T‘ıDUÙe$‘Uı4Uóµ$T‘ıDUÙe$‘Uı4U÷g&÷U6W∂ñ÷rÁ7&3÷G∑2Êg&÷U˜W&«”˜C“G¥FFRÊÊ˜rÇó÷∑÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VVÁ6Ü˜D'F‚ríÊFó6&∆VC÷f«6S∂6ˆÁ7B6#÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FT6ˆÁG&ˆƒ'F‚rì∂6"ÊFó6&∆VC“≤wfñWuˆˆÊ«ír¬vFVÊñVBu“ÊñÊ6«VFW2á2Ê6ˆÁG&ˆ≈˜7FGW2ì∂6"ÁFWáD6ˆÁFVÁC◊2Ê6ˆÁG&ˆ≈˜7FGW3””“w&WVW7FVBsÚuvóFñÊrf˜"6ˆÁG&ˆ¬&˜fŒ(
bsß2Ê6ˆÁG&ˆ≈˜7FGW3””“v&˜fVBsÚt6ˆÁG&ˆ¬&˜fVBs¢u&WVW7B6ˆÁG&ˆ¬s∞¢÷V«6RñbáVÊFñÊró∞¢ñ÷rÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂V◊GíÁ7Gñ∆RÊFó7∆ì“vf∆WÇs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VVÁ6Ü˜D'F‚ríÊFó6&∆VC◊G'VS∞¢÷V«6RñbáFW&÷ñÊ¬ó∞¢ñ÷rÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂V◊GíÁ7Gñ∆RÊFó7∆ì“vf∆WÇs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FTFó66ˆÊÊV7D'F‚ríÊFó6&∆VC◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VVÁ6Ü˜D'F‚ríÊFó6&∆VC◊G'VSµ$T‘ıDUı4U54îÙ„÷ÁV∆√∞¢–¢6ˆÁ7B&˜fVC’≤v&˜fVBr¬v6GW&U˜7F'FVBr¬v7FófRu“ÊñÊ6«VFW2á2Á7FGW2ì∞¢6ˆÁ7B6ˆÁG&ˆ√’7G&ñÊrá2Ê6ˆÁG&ˆ≈˜7FGW7«¬wfñWuˆˆÊ«íríÁ&W∆6T∆¬ÇuÚr¬rrì∂6ˆÁ7B÷WF÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU6W76ñˆ‰÷WFrì∂ñbÜ÷WFñ÷WFÊñÊÊW$ÖD‘√÷«7„‰6ˆ◊WFW#¢∆#‚G∂W62á2Ê6ˆ◊WFW%ˆÊ÷W«¬~(	Bró”¬ˆ#„¬˜7„„«7„Â67&VV‚6Ü&ñÊs¢∆#‚G∂&˜fVCÚt&˜fVBs¢á2Á7FGW3””“vFVÊñVBsÚtFVÊñVBs¢uVÊFñÊrró”¬ˆ#„¬˜7„„«7„‰6ˆÁG&ˆ√¢∆#‚G∂W62Ü6ˆÁG&ˆ¬ó”¬ˆ#„¬˜7„„«7„Â7FGW3¢∆#‚G∂W62Ö7G&ñÊrá2Á7FGW7«¬wVÊ∂Ê˜v‚ríÁ&W∆6T∆¬ÇuÚr¬rríó”¬ˆ#„¬˜7„Ê∞¢ñbáFW&÷ñÊ¬ó&WGW&„∞¢÷6F6ÇÜRó∂6ˆÁ7B7FGW3÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU6W76ñˆÂ7FGW2rì∂ñbá7FGW2ó7FGW2ÁFWáD6ˆÁFVÁC“u&V÷˜FR7FGW26ÜV6≤fñ∆VC≤&WG'ññÊ~(
bs∑–¢ñbÖ$T‘ıDUı4U54îÙ‚ï$T‘ıDUıÙƒ≈ıDî‘U#◊6WEFñ÷V˜WBáˆ∆≈&V÷˜FU6W76ñˆ‚√cSì∞ß–¶7ñÊ2gVÊ7Fñˆ‚7F˜&V÷˜FU6W76ñˆ‚Çó∂ñbÇ$T‘ıDUı4U54îÙ‚ó&WGW&„∑G'ó∂vóB&V÷˜FTíÜˆí˜c˜&V÷˜FR÷66W72˜6W76ñˆÁ2ÚGµ$T‘ıDUı4U54îÙ‚ÊñG“˜7F˜«∂÷WFÜˆC¢uı5Br∆&ˆGì¢w∑“w“ì∑÷6F6ÇÜRó∑÷6∆V%Fñ÷V˜WBÖ$T‘ıDUıÙƒ≈ıDî‘U"ìµ$T‘ıDUı4U54îÙ„÷ÁV∆√µ$T‘ıDUÙe$‘Uı4U”∂6ˆÁ7Bñ÷s÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VV‚rì∂ñ÷rÁ7Gñ∆RÊFó7∆ì“vÊˆÊRs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FTV◊GíríÁ7Gñ∆RÊFó7∆ì“vf∆WÇs∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FTFó66ˆÊÊV7D'F‚ríÊFó6&∆VC◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VVÁ6Ü˜D'F‚ríÊFó6&∆VC◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU6W76ñˆÂ7FGW2ríÁFWáD6ˆÁFVÁC“u6W76ñˆ‚VÊFVBs∑–¶7ñÊ2gVÊ7Fñˆ‚&WVW7E&V÷˜FT6ˆÁG&ˆ¬Çó∂ñbÇ$T‘ıDUı4U54îÙÁ«≈$T‘ıDUı4U54îÙ‚Á7FGW2”“v7FófRró&WGW&„∑G'ó∂vóB&V÷˜FTíÜˆí˜c˜&V÷˜FR÷66W72˜6W76ñˆÁ2ÚGµ$T‘ıDUı4U54îÙ‚ÊñG“ˆ6ˆÁG&ˆ¬˜&WVW7F«∂÷WFÜˆC¢uı5Br∆&ˆGì¢w∑“w“ì∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FT6ˆÁG&ˆƒ'F‚ríÊFó6&∆VC◊G'VS∂Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FT6ˆÁG&ˆƒ'F‚ríÁFWáD6ˆÁFVÁC“uvóFñÊrf˜"6ˆÁG&ˆ¬&˜fŒ(
bs∑÷6F6ÇÜRó∂∆W'BÜRÊ÷W76vW«∆Ró◊–¶gVÊ7Fñˆ‚˜VÂ&V÷˜FU67&VVÁ6Ü˜BÇó∂ñbÖ$T‘ıDUı4U54îÙ‚óvñÊF˜rÊ˜V‚Üˆí˜c˜&V÷˜FR÷66W72˜6W76ñˆÁ2ÚGµ$T‘ıDUı4U54îÙ‚ÊñG“ˆg&÷S˜C“G¥FFRÊÊ˜rÇó÷¬uˆ&∆Ê≤rì∑–¶7ñÊ2gVÊ7Fñˆ‚6VÊE&V÷˜FTñÁWBáñ∆ˆBó∂ñbÇ$T‘ıDUı4U54îÙÁ«≈$T‘ıDUı4U54îÙ‚Á7FGW2”“v7FófRw«≈$T‘ıDUı4U54îÙ‚Ê6ˆÁG&ˆ≈˜7FGW2”“v&˜fVBró&WGW&„∑G'ó∂vóB&V÷˜FTíÜˆí˜c˜&V÷˜FR÷66W72˜6W76ñˆÁ2ÚGµ$T‘ıDUı4U54îÙ‚ÊñG“ˆñÁWF«∂÷WFÜˆC¢uı5Br∆&ˆGì§•4Ù‚Á7G&ñÊvñgíáñ∆ˆBó“ì∑÷6F6ÇÜRó∑◊–¶gVÊ7Fñˆ‚&V÷˜FUˆñÁFW%ñ∆ˆBÜWb∆7Fñˆ‚ó∂6ˆÁ7Bñ÷s÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VV‚rì∂ñbÇñ÷w«∆ñ÷rÁ7Gñ∆RÊFó7∆ì””“vÊˆÊRró&WGW&‚ÁV∆√∂6ˆÁ7B#÷ñ÷rÊvWD&˜VÊFñÊt6∆ñVÁE&V7BÇì∂ñbÇ"ÁvñGFá«¬"ÊÜVñváG«∆WbÊ6∆ñVÁEÉ«"Ê∆VgG«∆WbÊ6∆ñVÁEÉÁ"Á&ñváG«∆WbÊ6∆ñVÁEì«"ÁF˜«∆WbÊ6∆ñVÁEìÁ"Ê&˜GFˆ“ó&WGW&‚ÁV∆√∂6ˆÁ7B#÷WbÊ'WGFˆ„”””#Úw&ñváBs¶WbÊ'WGFˆ„”””Úv÷ñFF∆Rs¢v∆VgBs∑&WGW&‚∂∂ñÊC¢wˆñÁFW"r∆7Fñˆ‚«É§÷FÇÊ÷ÇÉƒ÷FÇÊ÷ñ‚É¬ÜWbÊ6∆ñVÁEÇ◊"Ê∆VgBí˜"ÁvñGFÇíí«ì§÷FÇÊ÷ÇÉƒ÷FÇÊ÷ñ‚É¬ÜWbÊ6∆ñVÁEí◊"ÁF˜í˜"ÊÜVñváBíí∆'WGFˆ„¶'”∑–¢ÜgVÊ7Fñˆ‚Çó∞¢6ˆÁ7B&ñÊC“Çì”Á∂6ˆÁ7Bw&÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VVÂw&rì∂6ˆÁ7Bñ÷s÷Fˆ7V÷VÁBÊvWDV∆V÷VÁD'îñBÇw&V÷˜FU67&VV‚rì∂ñbÇw&«¬ñ÷w««w&ÊFF6WBÁ&V÷˜FT&˜VÊBó&WGW&„∑w&ÊFF6WBÁ&V÷˜FT&˜VÊC“ss∑w&ÊFDWfVÁD∆ó7FVÊW"Çv6ˆÁFWáF÷VÁRr∆S”ÊRÁ&WfVÁDFVfV«BÇíì∂ñ÷rÊFDWfVÁD∆ó7FVÊW"Çv÷˜W6V÷˜fRr∆S”Á∂6ˆÁ7B„‘FFRÊÊ˜rÇì∂ñbÜ‚’$T‘ıDUÙ‘ıdUÙC√Só&WGW&„µ$T‘ıDUÙ‘ıdUÙC÷„∂6ˆÁ7B◊&V÷˜FUˆñÁFW%ñ∆ˆBÜR¬v÷˜fRrì∂ñbáó6VÊE&V÷˜FTñÁWBáó“ì∂ñ÷rÊFDWfVÁD∆ó7FVÊW"Çv÷˜W6VF˜v‚r∆S”Á∂RÁ&WfVÁDFVfV«BÇì∑w&Êfˆ7W2Çì∂6ˆÁ7B◊&V÷˜FUˆñÁFW%ñ∆ˆBÜR¬vF˜v‚rì∂ñbáó6VÊE&V÷˜FTñÁWBáó“ì∂ñ÷rÊFDWfVÁD∆ó7FVÊW"Çv÷˜W6WWr∆S”Á∂RÁ&WfVÁDFVfV«BÇì∂6ˆÁ7B◊&V÷˜FUˆñÁFW%ñ∆ˆBÜR¬wWrì∂ñbáó6VÊE&V÷˜FTñÁWBáó“ì∑w&ÊFDWfVÁD∆ó7FVÊW"ÇwvÜVV¬r∆S”Á∂ñbÇ$T‘ıDUı4U54îÙ‚ó&WGW&„∂RÁ&WfVÁDFVfV«BÇì∑6VÊE&V÷˜FTñÁWBá∂∂ñÊC¢wvÜVV¬r∆FV«F¶RÊFV«Fì√Û#¢”#“ó“«∑76ófS¶f«6W“ì∑w&ÊFDWfVÁD∆ó7FVÊW"Çv∂WñF˜v‚r∆S”Á∂ñbÇ$T‘ıDUı4U54îÙÁ«≈$T‘ıDUı4U54îÙ‚Á7FGW2”“v7FófRró&WGW&„∂ñbÖ≥b√#5“ÊñÊ6«VFW2ÜRÊ∂Wî6ˆFRíó&WGW&„∂RÁ&WfVÁDFVfV«BÇì∑6VÊE&V÷˜FTñÁWBá∂∂ñÊC¢v∂Wñ&ˆ&Br∆7Fñˆ„¢vF˜v‚r«f≥¶RÊ∂Wî6ˆFW“ó“ì∑w&ÊFDWfVÁD∆ó7FVÊW"Çv∂WóWr∆S”Á∂ñbÇ$T‘ıDUı4U54îÙÁ«≈$T‘ıDUı4U54îÙ‚Á7FGW2”“v7FófRró&WGW&„∂RÁ&WfVÁDFVfV«BÇì∑6VÊE&V÷˜FTñÁWBá∂∂ñÊC¢v∂Wñ&ˆ&Br∆7Fñˆ„¢wWr«f≥¶RÊ∂Wî6ˆFW“ó“ì∑”∞¢ñbÜFˆ7V÷VÁBÁ&VGï7FFS””“v∆ˆFñÊrrñFˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"ÇtDÙ‘6ˆÁFVÁD∆ˆFVBr∆&ñÊBì∂V«6R6WEFñ÷V˜WBÜ&ñÊB√ì∞¢Fˆ7V÷VÁBÊFDWfVÁD∆ó7FVÊW"Çv6∆ñ6≤r∆S”Á∂6ˆÁ7BÊc÷RÁF&vWBÊ6∆˜6W7BbfRÁF&vWBÊ6∆˜6W7BÇu∂FF◊fñWs“'&V÷˜FR÷66W72%“rì∂ñbÜÊbó6WEFñ÷V˜WBÜ∆ˆE&V÷˜FT66W72√ó“ì∞ß“íÇì∞£¬˜67&óC„¬ˆ&ˆGì„¬ˆáF÷√‚rrp††¢2“““7ñ&W"Fˆˆ«2˜W&FñˆÁ26ˆÁ6ˆ∆R“““““““““““““““““““““““““““““““““““““““–¶6∆727ñ&W%Fˆˆ≈'VÂ&WVW7BÑ&6T÷ˆFV¬ì†¢Fˆˆ√¢7G ¢F&vWC¢7G"“" ¢&ˆfñ∆S¢7G"“'7FÊF&B ¢˜FñˆÁ3¢Fñ7B“∑–†¶6∆727ñ&W%Fˆˆ≈66ÜVGV∆U&WVW7BÑ7ñ&W%Fˆˆ≈'VÂ&WVW7Bì†¢ñÁFW'f≈ˆ÷ñÁWFW3¢ñÁB“CC †§5î$U%ıDÙÙ≈ıDïDƒU3◊≤&ÊWGv˜&µˆWá˜7W&R#¢$ÊWGv˜&≤Wá˜7W&R66‚"¬&VÊGˆñÁE˜˜7GW&R#¢$VÊGˆñÁB6V7W&óGí˜7GW&R"¬'vV%˜F«2#¢%vV"ÊBD≈2VFóB"¬&÷«v&Uˆñˆ2#¢$÷«v&RÊBîÙ266‚"¬&FÁ5ˆV÷ñ¬#¢$DÂ2ÊBV÷ñ¬6V7W&óGíVFóB"¬&∆ñÁWÖˆVFóB#¢$∆ñÁWÇ6V7W&óGíVFóB"¬'Fá&VEˆFWFV7Fñˆ‚#¢$ÊWGv˜&≤Fá&VBFWFV7Fñˆ‚&WfñWr"¬&WfñFVÊ6Uˆ6GW&R#¢$ÊWGv˜&≤WfñFVÊ6R6GW&R'–†¶FVbˆ7ñ&W%ˆfñÊFñÊrÜ2«&˜rì†¢ñb&˜u≤&fñÊFñÊuˆñB%”†¢f˜VÊC÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“ÊWGv˜&µˆó77VW2tÑU$RñC”Ú"¬á&˜u≤&fñÊFñÊuˆñB%“¬ííÊfWF6ÜˆÊRÇê¢ñbf˜VÊCß&WGW&‚f˜VÊ@¢G'ìß&W7V«C÷ß6ˆ‚Ê∆ˆG2á&˜u≤'&W7V«Eˆß6ˆ‚%“˜"'∑“"ê¢WÜ6WBWÜ6WFñˆ„ß&W7V«C◊∑–¢6WfW&S“á&˜u≤'Fˆˆ¬%””“&÷«v&Uˆñˆ2"ÊBÊ˜B&W7V«BÊvWBÇ&ˆ≤"íí˜"á&˜u≤'Fˆˆ¬%””“'Fá&VEˆFWFV7Fñˆ‚"ÊBñÁBá&W7V«BÊvWBÇ&ÜñvÖ˜&ñ˜&óGïˆ6˜VÁB"í˜"ì„ê¢6WfW&óGì“&7&óFñ6¬"ñb6WfW&RV«6RÇ&ÜñvÇ"ñbÊ˜B&W7V«BÊvWBÇ&ˆ≤"íV«6R'v&ÊñÊr"ê¢&V6ˆ÷÷VÊFFñˆÁ3◊≤&ÊWGv˜&µˆWá˜7W&R#¢$6ˆÊfó&“V6ÇWá˜6VB6W'fñ6Ró2&WVó&VB¬F6ÜVB¬ÊB&W7G&ñ7FVB'ífó&Wv∆¬'V∆W2‚"¬&VÊGˆñÁE˜˜7GW&R#¢$'&ñÊrˆff∆ñÊRvVÁG2ˆÊ∆ñÊRÊB&WfñWrvñÊF˜w2WFFRÊB÷«v&R◊66‚&W7V«G2‚"¬'vV%˜F«2#¢$VÊ&∆RÖEE2ÊB÷ó76ñÊr'&˜w6W"6V7W&óGíÜVFW'2gFW"6ˆ◊Fñ&ñ∆óGíFW7FñÊr‚"¬&÷«v&Uˆñˆ2#¢$ó6ˆ∆FRFÜRffV7FVBVÊGˆñÁBÊBfˆ∆∆˜rFÜR&˜fVBñÊ6ñFVÁB◊&W7ˆÁ6R&ˆ6W72‚"¬&FÁ5ˆV÷ñ¬#¢%V&∆ó6ÇÊBf∆ñFFR÷ó76ñÊrDÂ2ÊBV÷ñ¬WFÜVÁFñ6Fñˆ‚6ˆÁG&ˆ«2‚"¬&∆ñÁWÖˆVFóB#¢%&WfñWr«ñÊó2v&ÊñÊw2ÊB«í6ÜÊvW2Fá&˜VvÇÊ˜&÷¬6ÜÊvR6ˆÁG&ˆ¬‚"¬'Fá&VEˆFWFV7Fñˆ‚#¢%f∆ñFFRFÜR7W&ñ6F∆W'BÊBffV7FVB76WG2&Vf˜&R6ˆÁFñÊ÷VÁB‚"¬&WfñFVÊ6Uˆ6GW&R#¢%&W6W'fRFÜR4vóFÇFÜR66RÊB&WfñWróBW6ñÊrWFÜ˜&ó¶VBÊ«ó6ó2Fˆˆ«2‚'–¢G3÷Ê˜rÇì∑FóF∆S÷b'¥5î$U%ıDÙÙ≈ıDïDƒU2ÊvWBá&˜u≤wFˆˆ¬u“¬t7ñ&W"Fˆˆ¬&W7V«Bró”¢∑&˜u≤wF&vWBu“˜"ttÙE4UîR∆ñÊ6Rw“%≥£#C”∂WfñFVÊ6S÷ß6ˆ‚ÊGV◊2á≤&7ñ&W%˜'VÂˆñB#ß&˜u≤&ñB%“¬'Fˆˆ¬#ß&˜u≤'Fˆˆ¬%“¬'7V÷÷'í#ß&˜u≤'7V÷÷'í%“¬'&W7V«B#ß&W7V«G“∆FVfV«C◊7G"ï≥£#–¢fñC÷2ÊWÜV7WFRÇ$îÂ4U%BîÂDÚÊWGv˜&µˆó77VW2Üó77VU˜GóR«6WfW&óGí«F&vWB«FóF∆R∆WfñFVÊ6R«&V6ˆ÷÷VÊFFñˆ‚«7FGW2∆fó'7E˜6VV‚∆∆7E˜6VV‚íd≈TU2Çv7ñ&W%˜Fˆˆ¬r√Ú√Ú√Ú√Ú√Ú¬v˜V‚r√Ú√Úí"¬á6WfW&óGí«&˜u≤'F&vWB%’≥£#SU“«FóF∆R∆WfñFVÊ6R«&V6ˆ÷÷VÊFFñˆÁ2ÊvWBá&˜u≤'Fˆˆ¬%“¬%&WfñWrÊB&V÷VFñFRFá&˜VvÇ&˜fVB6ÜÊvR6ˆÁG&ˆ¬‚"í«G2«G2ííÊ∆7G&˜vñ@¢2ÊWÜV7WFRÇ%UDDR7ñ&W%˜Fˆˆ≈˜'VÁ24UBfñÊFñÊuˆñC”ÚtÑU$RñC”Ú"¬ÜfñB«&˜u≤&ñB%“íì∑&WGW&‚2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“ÊWGv˜&µˆó77VW2tÑU$RñC”Ú"¬ÜfñB¬ííÊfWF6ÜˆÊRÇê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2ˆ6&ñ∆óFñW2"ê¶FVb7ñ&W%˜Fˆˆ≈ˆ6&ñ∆óFñW2áW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íìß&WGW&‚7ñ&W%ˆ6&ñ∆óFñW2ÑD%ıDÇÁ&VÁBê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2˜'V‚"ê¶FVb7ñ&W%˜Fˆˆ≈˜'V‚á&W¢7ñ&W%Fˆˆ≈'VÂ&WVW7B«&WVW7C¢&WVW7B«W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢G'ì†¢vóFÇF"Çí23†¢VÁ7W&Uˆ7ñ&W%˜66ÜV÷Ü2ì∑&W7V«C÷WÜV7WFUˆ7ñ&W%˜Fˆˆ¬á&WÁFˆˆ¬Á7G&óÇí«&WÁF&vWBÁ7G&óÇí«&WÁ&ˆfñ∆RÁ7G&óÇí«&WÊ˜FñˆÁ2˜"∑“ƒD%ıDÇÁ&VÁB∆2ì∑&˜s◊&V6˜&Eˆ7ñ&W%˜'V‚Ü2«&WÁFˆˆ¬Á7G&óÇí«&WÁF&vWBÁ7G&óÇí«&WÁ&ˆfñ∆RÁ7G&óÇí«&W7V«B«W6W%≤'W6W&Ê÷R%“∆7ñ&W%˜WF6Ê˜rÇíì∂VFóBÜ2«W6W%≤'W6W&Ê÷R%“¬&7ñ&W%˜Fˆˆ≈˜'V‚"«7G"á&˜u≤&ñB%“í∆ß6ˆ‚ÊGV◊2á≤'Fˆˆ¬#ß&WÁFˆˆ¬¬'F&vWB#ß&WÁF&vWB¬&ˆ≤#¶&ˆˆ¬á&W7V«BÊvWBÇ&ˆ≤"íó“í∆6∆ñVÁEˆóá&WVW7Bíì∑&WGW&‚&˜p¢WÜ6WBf«VTW'&˜"2WÜ3ß&ó6RÖEEWÜ6WFñˆ‚ÉC«7G"ÜWÜ2íê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2˜'VÁ2"ê¶FVb7ñ&W%˜Fˆˆ≈˜'VÁ2Ü∆ñ÷óC¶ñÁC”S«Fˆˆ√ß7G#“""«W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆ7ñ&W%˜66ÜV÷Ü2ì∑&˜w3÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“7ñ&W%˜Fˆˆ≈˜'VÁ2tÑU$RFˆˆ√”Úı$DU"%íñBDU42ƒî‘ïBÚ"¬áFˆˆ¬∆÷ÇÉ∆÷ñ‚Ü∆ñ÷óB√#ííííÊfWF6Ü∆¬ÇíñbFˆˆ¬V«6R2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“7ñ&W%˜Fˆˆ≈˜'VÁ2ı$DU"%íñBDU42ƒî‘ïBÚ"¬Ü÷ÇÉ∆÷ñ‚Ü∆ñ÷óB√#íí¬ííÊfWF6Ü∆¬Çê¢&WGW&Â∑V&∆ñ5ˆ7ñ&W%˜'V‚á"íf˜""ñ‚&˜w5–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2˜'VÁ2˜∑∑'VÂˆñG◊“ˆWá˜'B"ê¶FVb7ñ&W%˜Fˆˆ≈ˆWá˜'Bá'VÂˆñC¶ñÁB«W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆ7ñ&W%˜66ÜV÷Ü2ì∑&˜s÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“7ñ&W%˜Fˆˆ≈˜'VÁ2tÑU$RñC”Ú"¬á'VÂˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜sß&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$7ñ&W"Fˆˆ¬'V‚Ê˜Bf˜VÊB"ê¢ñ∆ˆC÷ß6ˆ‚ÊGV◊2áV&∆ñ5ˆ7ñ&W%˜'V‚á&˜rí∆ñÊFVÁC”"∆FVfV«C◊7G"íÊVÊ6ˆFRÇê¢&WGW&‚&W7ˆÁ6Ráñ∆ˆB∆÷VFñ˜GóS“&∆ñ6Fñˆ‚ˆß6ˆ‚"∆ÜVFW'3◊≤$6ˆÁFVÁB‘Fó7˜6óFñˆ‚#¶bvGF6Ü÷VÁC≤fñ∆VÊ÷S“&vˆG6WñR÷7ñ&W"◊'V‚◊∑'VÂˆñG“Êß6ˆ‚"w“ê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2˜'VÁ2˜∑∑'VÂˆñG◊“ˆ7&VFR÷fñÊFñÊr"ê¶FVb7ñ&W%˜Fˆˆ≈ˆ7&VFUˆfñÊFñÊrá'VÂˆñC¶ñÁB«&WVW7C•&WVW7B«W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢vóFÇF"Çí23†¢VÁ7W&Uˆ7ñ&W%˜66ÜV÷Ü2ì∑&˜s÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“7ñ&W%˜Fˆˆ≈˜'VÁ2tÑU$RñC”Ú"¬á'VÂˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜sß&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$7ñ&W"Fˆˆ¬'V‚Ê˜Bf˜VÊB"ê¢f˜VÊC’ˆ7ñ&W%ˆfñÊFñÊrÜ2«&˜rì∂VFóBÜ2«W6W%≤'W6W&Ê÷R%“¬&7ñ&W%ˆfñÊFñÊuˆ7&VFVB"«7G"Üf˜VÊE≤&ñB%“í∆ß6ˆ‚ÊGV◊2á≤''VÂˆñB#ß'VÂˆñG“í∆6∆ñVÁEˆóá&WVW7Bíì∑&WGW&‚Fñ7BÜf˜VÊBê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2˜'VÁ2˜∑∑'VÂˆñG◊“ˆ7&VFR◊Fñ6∂WB"ê¶FVb7ñ&W%˜Fˆˆ≈ˆ7&VFU˜Fñ6∂WBá'VÂˆñC¶ñÁB«&WVW7C•&WVW7B«W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢vóFÇF"Çí23†¢VÁ7W&Uˆ7ñ&W%˜66ÜV÷Ü2ì∑&˜s÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“7ñ&W%˜Fˆˆ≈˜'VÁ2tÑU$RñC”Ú"¬á'VÂˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜sß&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$7ñ&W"Fˆˆ¬'V‚Ê˜Bf˜VÊB"ê¢ñb&˜u≤'Fñ6∂WEˆñB%”†¢WÜó7FñÊs÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“Fñ6∂WG2tÑU$RñC”Ú"¬á&˜u≤'Fñ6∂WEˆñB%“¬ííÊfWF6ÜˆÊRÇê¢ñbWÜó7FñÊsß&WGW&‚Fñ7BÜWÜó7FñÊrê¢f˜VÊC’ˆ7ñ&W%ˆfñÊFñÊrÜ2«&˜rì∑&ñ˜&óGì“&7&óFñ6¬"ñbf˜VÊE≤'6WfW&óGí%””“&7&óFñ6¬"V«6RÇ&ÜñvÇ"ñbf˜VÊE≤'6WfW&óGí%””“&ÜñvÇ"V«6R&÷VFóV“"ì∑G3÷Ê˜rÇì∑FñC÷2ÊWÜV7WFRÇ$îÂ4U%BîÂDÚFñ6∂WG2áFóF∆R∆FW67&óFñˆ‚«7FGW2«&ñ˜&óGí∆76ñvÊVR∆∆ñÊ∂VE˜GóR∆∆ñÊ∂VEˆñB∆FWfñ6UˆÊ÷R∆7&VFVEˆ'í∆7&VFVEˆB«WFFVEˆBíd≈TU2ÉÚ√Ú¬v˜V‚r√Ú¬rr¬vÊWGv˜&µˆfñÊFñÊrr√Ú√Ú√Ú¬Ú√Úí"¬Üf˜VÊE≤'FóF∆R%“∆f˜VÊE≤'&V6ˆ÷÷VÊFFñˆ‚%“«&ñ˜&óGí∆f˜VÊE≤&ñB%“«&˜u≤'F&vWB%’≥£#SU“«W6W%≤'W6W&Ê÷R%“«G2«G2ííÊ∆7G&˜vñC∂ÁV÷&W#÷b%DµB◊∑FñC£VG“#∂2ÊWÜV7WFRÇ%UDDRFñ6∂WG24UBFñ6∂WEˆÁV÷&W#”ÚtÑU$RñC”Ú"¬ÜÁV÷&W"«FñBíì∂2ÊWÜV7WFRÇ%UDDR7ñ&W%˜Fˆˆ≈˜'VÁ24UBFñ6∂WEˆñC”ÚtÑU$RñC”Ú"¬áFñB«'VÂˆñBíì∂VFóBÜ2«W6W%≤'W6W&Ê÷R%“¬'Fñ6∂WEˆ7&VFVEˆg&ˆ’ˆ7ñ&W%˜Fˆˆ¬"∆ÁV÷&W"∆ß6ˆ‚ÊGV◊2á≤''VÂˆñB#ß'VÂˆñG“í∆6∆ñVÁEˆóá&WVW7Bíì∑&WGW&‚Fñ7BÜ2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“Fñ6∂WG2tÑU$RñC”Ú"¬áFñB¬ííÊfWF6ÜˆÊRÇíê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2˜66ÜVGV∆W2"ê¶FVb7ñ&W%˜Fˆˆ≈˜66ÜVGV∆W2áW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23¶VÁ7W&Uˆ7ñ&W%˜66ÜV÷Ü2ì∑&˜w3÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“7ñ&W%˜Fˆˆ≈˜66ÜVGV∆W2ı$DU"%íVÊ&∆VBDU42∆ÊWáE˜'VÂˆB∆ñB"íÊfWF6Ü∆¬Çê¢˜WC’µ–¢f˜""ñ‚&˜w3†¢C÷Fñ7Bá"ê¢G'ì¶E≤&˜FñˆÁ2%”÷ß6ˆ‚Ê∆ˆG2ÜBÁ˜Ç&˜FñˆÁ5ˆß6ˆ‚"í˜"'∑“"ê¢WÜ6WBWÜ6WFñˆ„¶E≤&˜FñˆÁ2%”◊∑–¢E≤&VÊ&∆VB%”÷&ˆˆ¬ÜE≤&VÊ&∆VB%“ì∂˜WBÊVÊBÜBê¢&WGW&‚˜W@†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2˜66ÜVGV∆W2"ê¶FVb7ñ&W%˜Fˆˆ≈˜66ÜVGV∆Uˆ7&VFRá&W§7ñ&W%Fˆˆ≈66ÜVGV∆U&WVW7B«&WVW7C•&WVW7B«W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢Fˆˆ√◊&WÁFˆˆ¬Á7G&óÇì∑&ˆfñ∆S◊&WÁ&ˆfñ∆RÁ7G&óÇì∂ñÁFW'f√÷÷ÇÉR∆÷ñ‚ÜñÁBá&WÊñÁFW'f≈ˆ÷ñÁWFW2í√C3#íê¢ñbFˆˆ¬Ê˜Bñ‚44ÑTETƒ$ƒUıDÙÙ≈3ß&ó6RÖEEWÜ6WFñˆ‚ÉC¬%FÜó27ñ&W"Fˆˆ¬6ÊÊ˜B&R66ÜVGV∆VB"ê¢ñb&ˆfñ∆RÊ˜BñÁ≤'Vñ6≤"¬'7FÊF&B"¬&FVW'”ß&ó6RÖEEWÜ6WFñˆ‚ÉC¬$ñÁf∆ñB&ˆfñ∆R"ê¢G3÷7ñ&W%˜WF6Ê˜rÇì∂ÁáC“ÜGBÊFFWFñ÷RÊÊ˜rÜGBÁFñ÷W¶ˆÊRÁWF2í∂GBÁFñ÷VFV«FÜ÷ñÁWFW3÷ñÁFW'f¬ííÊó6ˆf˜&÷BÇê¢vóFÇF"Çí23¶VÁ7W&Uˆ7ñ&W%˜66ÜV÷Ü2ì∑6ñC÷2ÊWÜV7WFRÇ$îÂ4U%BîÂDÚ7ñ&W%˜Fˆˆ≈˜66ÜVGV∆W2áFˆˆ¬«F&vWB«&ˆfñ∆R∆˜FñˆÁ5ˆß6ˆ‚∆ñÁFW'f≈ˆ÷ñÁWFW2∆VÊ&∆VB∆7&VFVEˆ'í∆7&VFVEˆB«WFFVEˆB∆ÊWáE˜'VÂˆBíd≈TU2ÉÚ√Ú√Ú√Ú√Ú√√Ú√Ú√Ú√Úí"¬áFˆˆ¬«&WÁF&vWBÁ7G&óÇï≥£#CÖ“«&ˆfñ∆R∆ß6ˆ‚ÊGV◊2á&WÊ˜FñˆÁ2˜"∑“«6W&F˜'3“Çr¬r¬s¢ríí∆ñÁFW'f¬«W6W%≤'W6W&Ê÷R%“«G2«G2∆ÁáBííÊ∆7G&˜vñC∂VFóBÜ2«W6W%≤'W6W&Ê÷R%“¬&7ñ&W%˜66ÜVGV∆Uˆ7&VFVB"«7G"á6ñBí∆ß6ˆ‚ÊGV◊2á≤'Fˆˆ¬#ßFˆˆ¬¬&ñÁFW'f¬#¶ñÁFW'f«“í∆6∆ñVÁEˆóá&WVW7Bíì∑&WGW&‚Fñ7BÜ2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“7ñ&W%˜Fˆˆ≈˜66ÜVGV∆W2tÑU$RñC”Ú"¬á6ñB¬ííÊfWF6ÜˆÊRÇíê†§ÊFV∆WFRÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2˜66ÜVGV∆W2˜∑∑66ÜVGV∆UˆñG◊“"ê¶FVb7ñ&W%˜Fˆˆ≈˜66ÜVGV∆UˆFV∆WFRá66ÜVGV∆UˆñC¶ñÁB«&WVW7C•&WVW7B«W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢vóFÇF"Çí23†¢VÁ7W&Uˆ7ñ&W%˜66ÜV÷Ü2ì∑&˜s÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“7ñ&W%˜Fˆˆ≈˜66ÜVGV∆W2tÑU$RñC”Ú"¬á66ÜVGV∆UˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜sß&ó6RÖEEWÜ6WFñˆ‚ÉCB¬%66ÜVGV∆RÊ˜Bf˜VÊB"ê¢2ÊWÜV7WFRÇ$DTƒUDRe$Ù“7ñ&W%˜Fˆˆ≈˜66ÜVGV∆W2tÑU$RñC”Ú"¬á66ÜVGV∆UˆñB¬íì∂VFóBÜ2«W6W%≤'W6W&Ê÷R%“¬&7ñ&W%˜66ÜVGV∆UˆFV∆WFVB"«7G"á66ÜVGV∆UˆñBí«&˜u≤'Fˆˆ¬%“∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&Á≤&ˆ≤#•G'VW–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ7ñ&W"◊Fˆˆ«2ˆWfñFVÊ6R˜∑∂fñ∆VÊ÷W◊“"ê¶FVb7ñ&W%˜Fˆˆ≈ˆWfñFVÊ6RÜfñ∆VÊ÷Sß7G"«W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢ñbÊ˜B&RÊgV∆∆÷F6Çá"&6GW&R’¥’¶◊£”ïE¢’“µ¬Á6"∆fñ∆VÊ÷Rìß&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$WfñFVÊ6Rfñ∆RÊ˜Bf˜VÊB"ê¢&ˆ˜C“ÑD%ıDÇÁ&VÁBÚ&7ñ&W"÷WfñFVÊ6R"íÁ&W6ˆ«fRÇì∑FÉ“á&ˆ˜Bˆfñ∆VÊ÷RíÁ&W6ˆ«fRÇê¢ñbFÇÁ&VÁB◊&ˆ˜B˜"Ê˜BFÇÊó5ˆfñ∆RÇìß&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$WfñFVÊ6Rfñ∆RÊ˜Bf˜VÊB"ê¢&WGW&‚fñ∆U&W7ˆÁ6RáFÇ∆÷VFñ˜GóS“&∆ñ6Fñˆ‚˜fÊBÁF7GV◊Á6"∆fñ∆VÊ÷S÷fñ∆VÊ÷R∆ÜVFW'3◊≤$66ÜR‘6ˆÁG&ˆ¬#¢&ÊÚ◊7F˜&R'“ê†¢2“““ÊWGv˜&≤Fˆˆ¬VÊGˆñÁG2“““““““““““““““““““““““““““““““““““““““““““““““–¶6∆72Fˆˆ≈F&vWE&WVW7BÑ&6T÷ˆFV¬ì†¢Ü˜7C¢7G †¶6∆72˜'E66Â&WVW7BÑ&6T÷ˆFV¬ì†¢Ü˜7C¢7G ¢˜'G3¢7G"“##"√S2√É√CC2√CCR√33Éí√ÉÉ√ÉCC2 †¶6∆72G&6U&WVW7BÑ&6T÷ˆFV¬ì†¢Ü˜7C¢7G ¢÷ÖˆÜ˜3¢ñÁB“ †§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜Fˆˆ«2˜ñÊr"ê¶FVbFˆˆ≈˜ñÊrá&W¢Fˆˆ≈F&vWE&WVW7B¬W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢g&ˆ“ÁFˆˆ«2ñ◊˜'BñÊp¢&WGW&‚ñÊrá&WÊÜ˜7Bê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜Fˆˆ«2˜G&6W&˜WFR"ê¶FVbFˆˆ≈˜G&6W&˜WFRá&W¢G&6U&WVW7B¬W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢g&ˆ“ÁFˆˆ«2ñ◊˜'BG&6W&˜WFP¢G'ì†¢&WGW&‚G&6W&˜WFRá&WÊÜ˜7B¬&WÊ÷ÖˆÜ˜2ê¢WÜ6WBf«VTW'&˜"2WÜ3†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬7G"ÜWÜ2íê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜Fˆˆ«2ˆFÁ2"ê¶FVbFˆˆ≈ˆFÁ2á&W¢Fˆˆ≈F&vWE&WVW7B¬W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢g&ˆ“ÁFˆˆ«2ñ◊˜'BFÁ0¢&WGW&‚FÁ2á&WÊÜ˜7Bê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜Fˆˆ«2˜˜'B◊66‚"ê¶FVbFˆˆ≈˜˜'E˜66‚á&W¢˜'E66Â&WVW7B¬W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢g&ˆ“ÁFˆˆ«2ñ◊˜'B˜'E˜66‡¢G'ì†¢&WGW&‚˜'E˜66‚á&WÊÜ˜7B¬&WÁ˜'G2ê¢WÜ6WBf«VTW'&˜"2WÜ3†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬7G"ÜWÜ2íê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜Fˆˆ«2ˆFWfñ6R÷ñÊfÚ"ê¶FVbFˆˆ≈ˆFWfñ6UˆñÊfÚá&W¢Fˆˆ≈F&vWE&WVW7B¬W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢g&ˆ“ÁFˆˆ«2ñ◊˜'BFWfñ6UˆñÊf¢G'ì†¢&WGW&‚FWfñ6UˆñÊfÚá&WÊÜ˜7Bê¢WÜ6WBf«VTW'&˜"2WÜ3†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬7G"ÜWÜ2íê†¢2“““ÊFófRñÁFVw&Fñˆ‚VÊGˆñÁG2““““““““““““““““““““““““““““““““““““““““–¢2FÜW6R&RñÁFVÁFñˆÊ∆«íñ◊∆V÷VÁFVBñ‚FÜR6÷Rf7Dí&ˆ6W726ÚtÙE4UîP¢2&V÷ñÁ26ñ◊∆R&7&W''íí∆ñÊ6R‚7&VFVÁFñ«2&RÊWfW"W'6ó7FVB‡¶6∆72ñÁFVw&FñˆÂU$≈&WVW7BÑ&6T÷ˆFV¬ì†¢W&√¢7G ¢Fñ÷V˜WC¢f∆ˆB“Ä¢fW&ñgï˜F«3¢&ˆˆ¬“G'VP¢7&VFVÁFñ√¢7G"¬ÊˆÊR“ÊˆÊP†¶6∆72VÊîfï&WVW7BÑ&6T÷ˆFV¬ì†¢W&√¢7G ¢W6W&Ê÷S¢7G ¢77v˜&C¢7G ¢fW&ñgï˜F«3¢&ˆˆ¬“G'VP†¶6∆724‰’&WVW7BÑ&6T÷ˆFV¬ì†¢Ü˜7C¢7G ¢6ˆ÷◊VÊóGì¢7G"¬ÊˆÊR“ÊˆÊP†¶6∆72tÙ≈&WVW7BÑ&6T÷ˆFV¬ì†¢÷3¢7G ¢'&ˆF67C¢7G"“##SR„#SR„#SR„#SR ¢˜'C¢ñÁB“ê†¶6∆726∆V%&V6ˆÂ&WVW7BÑ&6T÷ˆFV¬ì†¢&V6ˆ„¢7G †¢FVb6∆VÂ˜&V6ˆ‚á6V∆bí”‚7G#†¢&V6ˆ‚“á6V∆bÁ&V6ˆ‚˜"""íÁ7G&óÇê¢ñb∆V‚á&V6ˆ‚í¬S†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬$&V6ˆ‚ˆbB∆V7BR6Ü&7FW'2ó2&WVó&VB"ê¢ñb∆V‚á&V6ˆ‚í‚S†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬%&V6ˆ‚◊W7B&RS6Ü&7FW'2˜"fWvW""ê¢&WGW&‚&V6ˆ‡†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ÷ˆÊóF˜"˜vV'6óFR"ê¶FVb÷ˆÊóF˜%˜vV'6óFRá&W¢ñÁFVw&FñˆÂU$≈&WVW7B¬W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&˜W&FR"ííì†¢g&ˆ“ÊñÁFVw&FñˆÁ2ñ◊˜'BvV'6óFUˆ6ÜV6∞¢&WGW&‚vV'6óFUˆ6ÜV6≤á&WÁW&¬¬&WÁFñ÷V˜WBê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2˜ñÜˆ∆R˜FW7B"ê¶FVbñÁFVw&FñˆÂ˜ñÜˆ∆Rá&W¢ñÁFVw&FñˆÂU$≈&WVW7B¬F÷ñ„‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢g&ˆ“ÊñÁFVw&FñˆÁ2ñ◊˜'BñÜˆ∆U˜FW7@¢&WGW&‚ñÜˆ∆U˜FW7Bá&WÁW&¬¬&WÁFñ÷V˜WB¬&WÊ7&VFVÁFñ¬¬&WÁfW&ñgï˜F«2ê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2˜VÊñfí˜FW7B"ê¶FVbñÁFVw&FñˆÂ˜VÊñfíá&W¢VÊîfï&WVW7B¬F÷ñ„‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢g&ˆ“ÊñÁFVw&FñˆÁ2ñ◊˜'BVÊñfïˆ∆ˆvñ‡¢&WGW&‚VÊñfïˆ∆ˆvñ‚á&WÁW&¬¬&WÁW6W&Ê÷R¬&WÁ77v˜&B¬&WÁfW&ñgï˜F«2ê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2˜6Ê◊˜FW7B"ê¶FVbñÁFVw&FñˆÂ˜6Ê◊á&W¢4‰’&WVW7B¬F÷ñ„‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢g&ˆ“ÊñÁFVw&FñˆÁ2ñ◊˜'B6Ê◊˜FW7@¢&WGW&‚6Ê◊˜FW7Bá&WÊÜ˜7B¬&WÊ6ˆ÷◊VÊóGíê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜Fˆˆ«2˜vˆ¬"ê¶FVbñÁFVw&FñˆÂ˜vˆ¬á&W¢tÙ≈&WVW7B¬F÷ñ„‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢g&ˆ“ÊñÁFVw&FñˆÁ2ñ◊˜'Bv∂UˆˆÂˆ∆‡¢G'ì†¢&WGW&‚v∂UˆˆÂˆ∆‚á&WÊ÷2¬&WÊ'&ˆF67B¬&WÁ˜'Bê¢WÜ6WBf«VTW'&˜"2WÜ3†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬7G"ÜWÜ2íê†¢2“““ñÁFVw&FñˆÁ2≤&W˜'FñÊrc„B“““““““““““““““““““““““““““““““““““““““–¶6∆726fVDñÁFVw&FñˆÂ&WVW7BÑ&6T÷ˆFV¬ì†¢Ê÷S¢7G"“" ¢∂ñÊC¢7G"“'ñÜˆ∆R ¢VÊ&∆VC¢&ˆˆ¬“G'VP¢F&vWC¢7G ¢W6W&Ê÷S¢7G"“" ¢6V7&WC¢7G"¬ÊˆÊR“ÊˆÊP¢fW&ñgï˜F«3¢&ˆˆ¬“G'VP¢7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG3¢ñÁB“3 ¢˜FñˆÁ3¢Fñ7B“∑–†¶6∆72&W˜'E66ÜVGV∆U&WVW7BÑ&6T÷ˆFV¬ì†¢Ê÷S¢7G ¢&W˜'E˜GóS¢7G"“&ÊWGv˜&µ˜7V÷÷'í ¢VÊ&∆VC¢&ˆˆ¬“G'VP¢6FVÊ6S¢7G"“&Fñ«í ¢Ü˜W%˜WF3¢ñÁB“ ¢vVV∂Fì¢ñÁB“ ¢Ê˜Fñgì¢&ˆˆ¬“G'VP†¶6∆72G&ffñ46ˆ∆∆V7FñˆÂ&WVW7BÑ&6T÷ˆFV¬ì†¢VÊ&∆VC¢&ˆˆ¬“f«6P¢÷ˆFS¢7G"“'VÊñfí ¢ñÁFVw&FñˆÂˆñC¢ñÁB¬ÊˆÊR“ÊˆÊP¢ñÁFW&f6S¢7G"“" ¢6◊∆UˆñÁFW'f≈˜6V6ˆÊG3¢ñÁB“3 ¢˜FñˆÁ3¢Fñ7B“∑–†¶6∆72G&ffñ56◊∆U&WVW7BÑ&6T÷ˆFV¬ì†¢÷3¢7G"“" ¢ó¢7G"“" ¢'Öˆ'óFW3¢ñÁB“ ¢GÖˆ'óFW3¢ñÁB“ ¢ñÁFW'f≈˜6V6ˆÊG3¢f∆ˆB¬ÊˆÊR“ÊˆÊP¢6ˆÊfñFVÊ6S¢7G"“&÷V7W&VB ¢FWFñ«3¢Fñ7B“∑–†¶6∆72G&ffñ4ñÊvW7E&WVW7BÑ&6T÷ˆFV¬ì†¢÷ˆFS¢7G ¢6˜W&6U˜&Vc¢7G"“" ¢6GW&VEˆC¢7G"¬ÊˆÊR“ÊˆÊP¢6˜VÁFW%ˆ÷ˆFS¢7G"“&FV«F ¢6◊∆W3¢∆ó7EµG&ffñ56◊∆U&WVW7E““µ–††¶6∆72Ê˜Fñfñ6Fñˆ‰6ˆÊfñu&WVW7BÑ&6T÷ˆFV¬ì†¢vV&ÜˆˆµˆVÊ&∆VC¢&ˆˆ¬“f«6P¢vV&Üˆˆµ˜W&√¢7G"“" ¢ÁFgïˆVÊ&∆VC¢&ˆˆ¬“f«6P¢ÁFgï˜6W'fW#¢7G"“&áGG3¢ÚˆÁFgíÁ6Ç ¢ÁFgï˜F˜ñ3¢7G"“" ¢6◊GˆVÊ&∆VC¢&ˆˆ¬“f«6P¢6◊GˆÜ˜7C¢7G"“" ¢6◊G˜˜'C¢ñÁB“SÉp¢6◊G˜W6W#¢7G"“" ¢6◊G˜77v˜&C¢7G"¬ÊˆÊR“ÊˆÊP¢6◊Gˆg&ˆ”¢7G"“" ¢6◊G˜FÛ¢7G"“" ¢÷ñÂ˜6WfW&óGì¢7G"“'v&ÊñÊr †§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2"ê¶FVbvWE˜6fVEˆñÁFVw&FñˆÁ2áW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ê¢&˜w3÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2ı$DU"%í∂ñÊB∆Ê÷R∆ñB"íÊfWF6Ü∆¬Çê¢∆FW7C◊∑–¢f˜""ñ‚2ÊWÜV7WFRÇ%4TƒT5B‚¢e$Ù“Ê«óFñ75˜6Ê6Ü˜G2§Ùî‚Ö4TƒT5BñÁFVw&FñˆÂˆñBƒ‘ÇÜñBí÷ñBe$Ù“Ê«óFñ75˜6Ê6Ü˜G2tÑU$RñÁFVw&FñˆÂˆñBï2‰ıBÂTƒ¬u$ıU%íñÁFVw&FñˆÂˆñBíÇÙ‚ÊñC◊ÇÊ÷ñB"ì†¢∆FW7E∑7G"á%≤vñÁFVw&FñˆÂˆñBu“ï”÷ß6ˆ‚Ê∆ˆG2á%≤vFFˆß6ˆ‚u“ê¢&WGW&‚≤&6ˆÊfñw2#•∑6fUˆ6ˆÊfñrá"íf˜""ñ‚&˜w5“¬&Ê«óFñ72#¶∆FW7G–†¶FVb˜6fUˆñÁFVw&FñˆÂˆñÁ7FÊ6RÜ2¬&W¬W6W"¬&WVW7B¬ñÁFVw&FñˆÂˆñC‘ÊˆÊRì†¢∂ñÊC◊&WÊ∂ñÊBÊ∆˜vW"Çê¢ñbñÁFVw&FñˆÂˆñBó2Ê˜BÊˆÊS†¢WÜó7FñÊs÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$RñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜BWÜó7FñÊs¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$ñÁFVw&Fñˆ‚Ê˜B6ˆÊfñwW&VB"ê¢∂ñÊC÷WÜó7FñÊu≤v∂ñÊBu–¢V«6S†¢∂ñÊC“Ü∂ñÊB˜"&WÊ∂ñÊB˜"rríÊ∆˜vW"Çê¢ñb∂ñÊBÊ˜Bñ‚≤'ñÜˆ∆R"¬'VÊñfí"¬'6Ê◊'”¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬%7W˜'FVBñÁFVw&FñˆÁ2&RñÜˆ∆R¬VÊñfí¬6Ê◊"ê¢ñbÊ˜B&WÁF&vWBÁ7G&óÇì¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬%F&vWBó2&WVó&VB"ê¢ñb&WÁ7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG2¬3¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬%7ñÊ2ñÁFW'f¬◊W7B&RB∆V7B36V6ˆÊG2"ê¢7F◊÷Ê˜rÇì≤Ê÷S“á&WÊÊ÷R˜"rríÁ7G&óÇê¢ñbÊ˜BÊ÷S†¢„÷2ÊWÜV7WFRÇ%4TƒT5B4ıTÂBÇ¢íe$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$R∂ñÊC”Ú"¬Ü∂ñÊB¬ííÊfWF6ÜˆÊRÇï≥“≥¢Ê÷S÷b'∂∂ñÊBÁ&W∆6RÇwñÜˆ∆Rr¬uí÷Üˆ∆RríÁ&W∆6RÇwVÊñfír¬uVÊîfíríÁ&W∆6RÇw6Ê◊r¬u4‰’ró“∂Á“ ¢GW÷2ÊWÜV7WFRÇ%4TƒT5BñBe$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$R∆˜vW"ÜÊ÷Rì÷∆˜vW"ÉÚí‰BÉÚï2ÂTƒ¬ı"ñC√„Úí"¬ÜÊ÷R∆ñÁFVw&FñˆÂˆñB∆ñÁFVw&FñˆÂˆñBííÊfWF6ÜˆÊRÇê¢ñbGW¢&ó6RÖEEWÜ6WFñˆ‚ÉCí¬$‚ñÁFVw&Fñˆ‚vóFÇFÜBÊ÷R«&VGíWÜó7G2"ê¢ˆ∆C÷2ÊWÜV7WFRÇ%4TƒT5B6V7&WBe$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$RñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬ííÊfWF6ÜˆÊRÇíñbñÁFVw&FñˆÂˆñBV«6RÊˆÊP¢6V7&WC÷VÊ7'óE˜6V7&WBá&WÁ6V7&WBíñb&WÁ6V7&WBó2Ê˜BÊˆÊRV«6RÜˆ∆E≤w6V7&WBu“ñbˆ∆BV«6Rrrê¢˜FñˆÁ3÷Fñ7Bá&WÊ˜FñˆÁ2˜"∑“ê¢ñbñÁFVw&FñˆÂˆñC†¢2ÊWÜV7WFRÇ""%UDDRñÁFVw&FñˆÂˆ6ˆÊfñw24UBÊ÷S”Ú∆VÊ&∆VC”Ú«F&vWC”Ú«W6W&Ê÷S”Ú«6V7&WC”Ú«fW&ñgï˜F«3”Ú«7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG3”Ú∆˜FñˆÁ5ˆß6ˆ„”Ú«WFFVEˆC”ÚtÑU$RñC”Ú"""¬ÜÊ÷R∆ñÁBá&WÊVÊ&∆VBí«&WÁF&vWBÁ7G&óÇí«&WÁW6W&Ê÷RÁ7G&óÇí«6V7&WB∆ñÁBá&WÁfW&ñgï˜F«2í«&WÁ7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG2∆ß6ˆ‚ÊGV◊2Ü˜FñˆÁ2í«7F◊∆ñÁFVw&FñˆÂˆñBíê¢ññC÷ñÁFVw&FñˆÂˆñ@¢V«6S†¢ññC÷2ÊWÜV7WFRÇ""$îÂ4U%BîÂDÚñÁFVw&FñˆÂˆ6ˆÊfñw2ÜÊ÷R∆∂ñÊB∆VÊ&∆VB«F&vWB«W6W&Ê÷R«6V7&WB«fW&ñgï˜F«2«7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG2∆˜FñˆÁ5ˆß6ˆ‚∆7&VFVEˆB«WFFVEˆBíd≈TU2ÉÚ√Ú√Ú√Ú√Ú√Ú√Ú√Ú√Ú√Ú√Úí"""¬ÜÊ÷R∆∂ñÊB∆ñÁBá&WÊVÊ&∆VBí«&WÁF&vWBÁ7G&óÇí«&WÁW6W&Ê÷RÁ7G&óÇí«6V7&WB∆ñÁBá&WÁfW&ñgï˜F«2í«&WÁ7ñÊ5ˆñÁFW'f≈˜6V6ˆÊG2∆ß6ˆ‚ÊGV◊2Ü˜FñˆÁ2í«7F◊«7F◊ííÊ∆7G&˜vñ@¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬vñÁFVw&FñˆÂˆ6ˆÊfñu˜6fVBr«7G"ÜññBí∆bw∂∂ñÊG”≤Ê÷S◊∂Ê÷W”≤VÊ&∆VC◊∑&WÊVÊ&∆VG”≤F&vWC◊∑&WÁF&vWG“r∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚6fUˆ6ˆÊfñrÜ2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$RñC”Ú"¬ÜññB¬ííÊfWF6ÜˆÊRÇíê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2"ê¶FVb7&VFUˆñÁFVw&Fñˆ‚á&W¢6fVDñÁFVw&FñˆÂ&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤&WGW&‚˜6fUˆñÁFVw&FñˆÂˆñÁ7FÊ6RÜ2«&W«W6W"«&WVW7BƒÊˆÊRê†§ÁWBÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2˜∑∂ñÁFVw&FñˆÂˆñG◊“"ê¶FVbWFFUˆñÁFVw&Fñˆ‚ÜñÁFVw&FñˆÂˆñC¢ñÁB¬&W¢6fVDñÁFVw&FñˆÂ&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤&WGW&‚˜6fUˆñÁFVw&FñˆÂˆñÁ7FÊ6RÜ2«&W«W6W"«&WVW7B∆ñÁFVw&FñˆÂˆñBê†§ÊFV∆WFRÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2˜∑∂ñÁFVw&FñˆÂˆñG◊“"ê¶FVbFV∆WFUˆñÁFVw&Fñˆ‚ÜñÁFVw&FñˆÂˆñC¢ñÁB¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤&˜s÷2ÊWÜV7WFRÇ%4TƒT5BÊ÷R∆∂ñÊBe$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$RñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜s¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$ñÁFVw&Fñˆ‚Ê˜B6ˆÊfñwW&VB"ê¢Ê«óFñ75ˆFV∆WFVC÷2ÊWÜV7WFRÇ$DTƒUDRe$Ù“Ê«óFñ75˜6Ê6Ü˜G2tÑU$RñÁFVw&FñˆÂˆñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬ííÁ&˜v6˜VÁ@¢7ñÊ5˜'VÁ5ˆFV∆WFVC÷2ÊWÜV7WFRÇ$DTƒUDRe$Ù“ñÁFVw&FñˆÂ˜7ñÊ5˜'VÁ2tÑU$RñÁFVw&FñˆÂˆñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬ííÁ&˜v6˜VÁ@¢2ÊWÜV7WFRÇ$DTƒUDRe$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$RñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬íê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬vñÁFVw&FñˆÂˆ6ˆÊfñuˆFV∆WFVBr«7G"ÜñÁFVw&FñˆÂˆñBí∆b'∑&˜u≤v∂ñÊBu◊“∑&˜u≤vÊ÷Ru◊”≤Ê«óFñ75ˆFV∆WFVC◊∂Ê«óFñ75ˆFV∆WFVG”≤7ñÊ5˜'VÁ5ˆFV∆WFVC◊∑7ñÊ5˜'VÁ5ˆFV∆WFVG“"∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ˆ≤#•G'VR¬&Ê«óFñ75ˆFV∆WFVB#¶Ê«óFñ75ˆFV∆WFVB¬'7ñÊ5˜'VÁ5ˆFV∆WFVB#ß7ñÊ5˜'VÁ5ˆFV∆WFVG–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2ˆ6ˆÊfñw2˜∑∂ñÁFVw&FñˆÂˆñG◊“˜7ñÊ2"ê¶FVb7ñÊ5˜6fVEˆñÁFVw&Fñˆ‚ÜñÁFVw&FñˆÂˆñC¢ñÁB¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç&ñÁFVw&FñˆÁ2Á7ñÊ2"ííì†¢÷ÊvW#÷vWFGG"ÜÁ7FFR¬vñÁFVw&FñˆÂ˜&W˜'FñÊuˆ÷ÊvW"rƒÊˆÊRê¢ñb÷ÊvW"ó2ÊˆÊS¢&ó6RÖEEWÜ6WFñˆ‚ÉS2¬$ñÁFVw&Fñˆ‚÷ÊvW"ó2Ê˜B'VÊÊñÊr"ê¢G'ì¢&W7V«C÷÷ÊvW"Á'VÂ˜7ñÊ2ÜñÁFVw&FñˆÂˆñBê¢WÜ6WB∂WîW'&˜#¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$ñÁFVw&Fñˆ‚Ê˜B6ˆÊfñwW&VB"ê¢vóFÇF"Çí23¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬vñÁFVw&FñˆÂ˜7ñÊ2r«7G"ÜñÁFVw&FñˆÂˆñBí∆ß6ˆ‚ÊGV◊2á∂≥ßbf˜"≤«bñ‚&W7V«BÊóFV◊2Çíñb≤“vÊ«óFñ72w“ï≥£“∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚&W7V«@†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆñÁFVw&FñˆÁ2˜7ñÊ2◊'VÁ2"ê¶FVbñÁFVw&FñˆÂ˜7ñÊ5˜'VÁ2Ü∆ñ÷óC¢ñÁC”S¬W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤&˜w3÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“ñÁFVw&FñˆÂ˜7ñÊ5˜'VÁ2ı$DU"%íñBDU42ƒî‘ïBÚ"¬Ü÷ÇÉ∆÷ñ‚Ü∆ñ÷óB√#íí¬ííÊfWF6Ü∆¬Çê¢&WGW&‚∂Fñ7Bá"íf˜""ñ‚&˜w5–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆÊ«óFñ72ˆ6∆ñVÁG2"ê¶FVb6∆ñVÁEˆÊ«óFñ72áW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ê¢'ï˜6˜W&6S’∂Fñ7Bá"íf˜""ñ‚2ÊWÜV7WFRÇ%4TƒT5B6˜W&6Rƒ4ıTÂBÑDï5Dî‰5B÷2íFWfñ6W2ƒ‘ÇÜ∆7E˜6VV‚í∆7E˜6VV‚e$Ù“FWfñ6U˜6˜W&6W2u$ıU%í6˜W&6Rı$DU"%íFWfñ6W2DU42"ï–¢F˜’∂Fñ7Bá"íf˜""ñ‚2ÊWÜV7WFRÇ%4TƒT5B÷2ƒ4ÙƒU44RÜÊ÷R∆Ü˜7FÊ÷R«fVÊF˜"∆÷2í∆&V¬∆ó«7FGW2∆∆7E˜6VV‚e$Ù“FWfñ6W2ı$DU"%í∆7E˜6VV‚DU42ƒî‘ïBS"ï–¢6Ê6Ü˜G3’µ–¢f˜""ñ‚2ÊWÜV7WFRÇ""%4TƒT5B‚¢e$Ù“Ê«óFñ75˜6Ê6Ü˜G2§Ùî‚Ö4TƒT5BñÁFVw&FñˆÂˆñBƒ‘ÇÜñBí÷ñBe$Ù“Ê«óFñ75˜6Ê6Ü˜G2tÑU$RñÁFVw&FñˆÂˆñBï2‰ıBÂTƒ¬u$ıU%íñÁFVw&FñˆÂˆñBíÇÙ‚ÊñC◊ÇÊ÷ñBı$DU"%íÊñBDU42"""ì†¢C÷Fñ7Bá"ì≤E≤vÊ«óFñ72u”÷ß6ˆ‚Ê∆ˆG2ÜBÁ˜ÇvFFˆß6ˆ‚rí˜"w∑“rì≤6Ê6Ü˜G2ÊVÊBÜBê¢&WGW&‚≤&'ï˜6˜W&6R#¶'ï˜6˜W&6R¬&6∆ñVÁG2#ßF˜¬&ñÁFVw&FñˆÂˆÊ«óFñ72#ß6Ê6Ü˜G7–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆÊ«óFñ72ˆ6∆V"˜∑∂ñÁFVw&FñˆÂˆñG◊“"ê¶FVb6∆V%ˆñÁFVw&FñˆÂˆÊ«óFñ72ÜñÁFVw&FñˆÂˆñC¢ñÁB¬&W¢6∆V%&V6ˆÂ&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢&V6ˆ„◊&WÊ6∆VÂ˜&V6ˆ‚Çê¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ê¢6fs÷2ÊWÜV7WFRÇ%4TƒT5BÊ÷R∆∂ñÊBe$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$RñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬ííÊfWF6ÜˆÊRÇê¢∆&V√“Ü6fu≤vÊ÷Ru“ñb6frV«6RbvñÁFVw&Fñˆ‚∂ñÁFVw&FñˆÂˆñG“rê¢6˜VÁC÷2ÊWÜV7WFRÇ%4TƒT5B4ıTÂBÇ¢íe$Ù“Ê«óFñ75˜6Ê6Ü˜G2tÑU$RñÁFVw&FñˆÂˆñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬ííÊfWF6ÜˆÊRÇï≥–¢2ÊWÜV7WFRÇ$DTƒUDRe$Ù“Ê«óFñ75˜6Ê6Ü˜G2tÑU$RñÁFVw&FñˆÂˆñC”Ú"¬ÜñÁFVw&FñˆÂˆñB¬íê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬vñÁFVw&FñˆÂˆÊ«óFñ75ˆ6∆V&VBr«7G"ÜñÁFVw&FñˆÂˆñBí∆bvÊ÷S◊∂∆&V«”≤FV∆WFVC◊∂6˜VÁG”≤&V6ˆ„◊∑&V6ˆÁ“r∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ˆ≤#•G'VR¬&FV∆WFVB#¶6˜VÁB¬&6∆V&VEˆ'í#ßW6W%≤wW6W&Ê÷Ru“¬&ñÁFVw&FñˆÂˆñB#¶ñÁFVw&FñˆÂˆñB¬&Ê÷R#¶∆&V«–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆÊ«óFñ72ˆ6∆V""ê¶FVb6∆V%ˆ6∆ñVÁE˜VW'ïˆÊ«óFñ72á&W¢6∆V%&V6ˆÂ&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢&V6ˆ„◊&WÊ6∆VÂ˜&V6ˆ‚Çê¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ê¢6˜VÁC÷2ÊWÜV7WFRÇ%4TƒT5B4ıTÂBÇ¢íe$Ù“Ê«óFñ75˜6Ê6Ü˜G2"íÊfWF6ÜˆÊRÇï≥–¢2ÊWÜV7WFRÇ$DTƒUDRe$Ù“Ê«óFñ75˜6Ê6Ü˜G2"ê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬v6∆ñVÁE˜VW'ïˆÊ«óFñ75ˆ6∆V&VBr¬vÊ«óFñ72r∆bw&V6ˆ„◊∑&V6ˆÁ”≤FV∆WFVC◊∂6˜VÁG“r∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ˆ≤#•G'VR¬&FV∆WFVB#¶6˜VÁB¬&6∆V&VEˆ'í#ßW6W%≤wW6W&Ê÷Ru“¬'&V6ˆ‚#ß&V6ˆÁ–†¶FVbˆ÷WG&ñ75ˆWFÜ˜&ó¶VBá&WVW7C¢&WVW7B¬2ì†¢WFÉ◊&WVW7BÊÜVFW'2ÊvWBÇ&WFÜ˜&ó¶Fñˆ‚"¬""ê¢∂Wì◊&WVW7BÊÜVFW'2ÊvWBÇ'Ç÷í÷∂Wí"í˜"ÜWFÖ≥s•“ñbWFÇÊ∆˜vW"ÇíÁ7F'G7vóFÇÇ&&V&W""íV«6R""ê¢ñbfW&ñgï˜&ˆ÷WFÜWW5ˆ∂WíÜ2∆∂Wíì¢&WGW&‚G'VP¢Fˆ∂V„◊&WVW7BÊ6ˆˆ∂ñW2ÊvWBÖ4U54îÙÂÙ4ÙÙ¥îRê¢ñbFˆ∂V„†¢&˜s÷2ÊWÜV7WFRÇ%4TƒT5B2ÊWáó&W5ˆB«RÊñBe$Ù“6W76ñˆÁ22§Ùî‚W6W'2RÙ‚RÊñC◊2ÁW6W%ˆñBtÑU$R2ÁFˆ∂V„”Ú"¬áFˆ∂V‚¬ííÊfWF6ÜˆÊRÇê¢ñb&˜s†¢G'ì¢&WGW&‚GBÊFFWFñ÷RÊg&ˆ÷ó6ˆf˜&÷Bá&˜u≤vWáó&W5ˆBu“ìÊGBÊFFWFñ÷RÊÊ˜rÜGBÁFñ÷W¶ˆÊRÁWF2ê¢WÜ6WBWÜ6WFñˆ„¢70¢&WGW&‚f«6P†§ÊvWBÇ"ˆ÷WG&ñ72"¬&W7ˆÁ6Uˆ6∆73’∆ñÂFWáE&W7ˆÁ6Rê¶FVb÷WG&ñ72á&WVW7C¢&WVW7Bì†¢vóFÇF"Çí23†¢VÁ7W&UˆÜ&FVÊñÊu˜66ÜV÷Ü2ê¢ñbÊ˜Bˆ÷WG&ñ75ˆWFÜ˜&ó¶VBá&WVW7B∆2ì†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬$÷WG&ñ72WFÜVÁFñ6Fñˆ‚&WVó&VB"ê¢&WGW&‚∆ñÂFWáE&W7ˆÁ6Rá&ˆ÷WFÜWW5ˆ÷WG&ñ72Ü2í∆÷VFñ˜GóS“'FWáB˜∆ñ„≤fW'6ñˆ„”„„C≤6Ü'6WC◊WFb”Ç"ê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜G&ffñ2ˆ6ˆÊfñr"ê¶FVbvWE˜G&ffñ5ˆ6ˆ∆∆V7FñˆÂˆ6ˆÊfñráW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢VÁ7W&UˆFWfñ6U˜G&ffñ5˜66ÜV÷Ü2ê¢6fs◊G&ffñ5ˆ6ˆ∆∆V7FñˆÂ˜6WGFñÊw2Ü2ê¢ñÁFVw&FñˆÁ3’∑6fUˆ6ˆÊfñrá"íf˜""ñ‚2ÊWÜV7WFRÄ¢%4TƒT5B¢e$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$R∂ñÊBî‚ÇwVÊñfír¬w6Ê◊ríı$DU"%í∂ñÊB∆Ê÷R ¢íÊfWF6Ü∆¬Çï–¢&WGW&‚≤&6ˆÊfñr#¶6fr¬&÷ˆFW2#•E$ddî5Ù‘ÙDU2¬&÷ˆFUˆ6&ñ∆óFñW2#ß∂≥ßG&ffñ5ˆ÷ˆFUˆ6&ñ∆óFñW2Ü≤íf˜"≤ñ‚E$ddî5Ù‘ÙDU7“¬&ñÁFVw&FñˆÁ2#¶ñÁFVw&FñˆÁ2¬&ñÁFW&f6W2#ßG&ffñ5ˆñÁFW&f6W2Çó–†§ÁWBÜb'∑&˜WFW%˜&Vfóá“˜G&ffñ2ˆ6ˆÊfñr"ê¶FVbWE˜G&ffñ5ˆ6ˆ∆∆V7FñˆÂˆ6ˆÊfñrá&W¢G&ffñ46ˆ∆∆V7FñˆÂ&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&UˆFWfñ6U˜G&ffñ5˜66ÜV÷Ü2ê¢G'ì†¢6fs◊6fU˜G&ffñ5ˆ6ˆ∆∆V7FñˆÂ˜6WGFñÊw2Ü2«&WÊ÷ˆFV≈ˆGV◊Çíê¢WÜ6WBf«VTW'&˜"2WÜ3†¢&ó6RÖEEWÜ6WFñˆ‚ÉC«7G"ÜWÜ2íê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬wG&ffñ5ˆ6ˆ∆∆V7FñˆÂˆ6ˆÊfñu˜WFFVBr∆6fu≤v÷ˆFRu“¿¢b&VÊ&∆VC◊∂6fu≤vVÊ&∆VBu◊”≤ñÁFVw&FñˆÂˆñC◊∂6frÊvWBÇvñÁFVw&FñˆÂˆñBró”≤ñÁFW&f6S◊∂6frÊvWBÇvñÁFW&f6Rró”≤ñÁFW'f√◊∂6fu≤w6◊∆UˆñÁFW'f≈˜6V6ˆÊG2u◊“"¿¢6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚6fp†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜G&ffñ2ˆñÊvW7B"ê¶FVbG&ffñ5ˆñÊvW7Bá&W¢G&ffñ4ñÊvW7E&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢÷ˆFS◊&WÊ÷ˆFRÊ∆˜vW"Çê¢ñb÷ˆFRÊ˜Bñ‚≤'7‚"¬&ñÊ∆ñÊR"¬'VÊñfí"¬'6Ê◊'”†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬%VÁ7W˜'FVBG&ffñ26˜W&6R÷ˆFR"ê¢ñb&WÊ6˜VÁFW%ˆ÷ˆFRÊ˜Bñ‚≤&FV«F"¬&7V◊V∆FófR'”†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬&6˜VÁFW%ˆ÷ˆFR◊W7B&RFV«F˜"7V◊V∆FófR"ê¢vóFÇF"Çí23†¢VÁ7W&UˆFWfñ6U˜G&ffñ5˜66ÜV÷Ü2ê¢7W'&VÁC◊G&ffñ5ˆ6ˆ∆∆V7FñˆÂ˜6WGFñÊw2Ü2ê¢ñb÷ˆFRñ‚≤'7‚"¬&ñÊ∆ñÊR'“ÊB7W'&VÁE≤&÷ˆFR%“÷÷ˆFS†¢&ó6RÖEEWÜ6WFñˆ‚ÉCí∆b%G&ffñ26ˆ∆∆V7Fñˆ‚ó26ˆÊfñwW&VBf˜"∂7W'&VÁE≤v÷ˆFRu◊“¬Ê˜B∂÷ˆFW“"ê¢6˜VÁC÷ñÊvW7EˆFWfñ6U˜G&ffñ5˜6◊∆W2Ä¢2∆÷ˆFR≈∑ÇÊ÷ˆFV≈ˆGV◊Çíf˜"Çñ‚&WÁ6◊∆W5“¿¢6˜W&6U˜&Vc◊&WÁ6˜W&6U˜&Vb∆6GW&VEˆC◊&WÊ6GW&VEˆB¿¢6˜VÁFW%ˆ÷ˆFS◊&WÊ6˜VÁFW%ˆ÷ˆFR∆6ˆÊfñFVÊ6S“&÷V7W&VB"¿¢ê¢7F◊÷Ê˜rÇê¢2ÊWÜV7WFRÇ%UDDRG&ffñ5ˆ6ˆ∆∆V7FñˆÂ˜6WGFñÊw24UB∆7Eˆ6ˆ∆∆V7FVEˆC”Ú∆∆7E˜7FGW3“w7V66W72r∆∆7EˆW'&˜#“rr«WFFVEˆC”ÚtÑU$RñC”"¬á7F◊«7F◊íê¢2Ê6ˆ÷÷óBÇê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬wG&ffñ5˜6◊∆W5ˆñÊvW7FVBr∆÷ˆFR¿¢b'6˜W&6U˜&Vc◊∑&WÁ6˜W&6U˜&Vg”≤6˜VÁFW%ˆ÷ˆFS◊∑&WÊ6˜VÁFW%ˆ÷ˆFW”≤6◊∆W3◊∂6˜VÁG“"∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ˆ≤#•G'VR¬&÷ˆFR#¶÷ˆFR¬'6◊∆W5ˆñÊvW7FVB#¶6˜VÁG–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜G&ffñ2ˆ6ˆ∆∆V7B÷Ê˜r"ê¶FVbG&ffñ5ˆ6ˆ∆∆V7EˆÊ˜rá&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢&W7V«C÷6ˆ∆∆V7EˆFWfñ6U˜G&ffñ5ˆˆÊ6RÜ2ê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬wG&ffñ5ˆ6ˆ∆∆V7FñˆÂ˜'V‚r«&W7V«BÊvWBÇv÷ˆFRr¬rrí¿¢b'7FGW3◊∑&W7V«BÊvWBÇw7FGW2ró”≤FWfñ6W5˜6◊∆VC◊∑&W7V«BÊvWBÇvFWfñ6W5˜6◊∆VBr√ó”≤W'&˜#◊∑&W7V«BÊvWBÇvW'&˜"rí˜"&W7V«BÊvWBÇvÊ˜FRr¬rró“"¿¢6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚&W7V«@†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜G&ffñ2ˆFWfñ6W2"ê¶FVbG&ffñ5ˆFWfñ6W2ÜÜ˜W'3¢ñÁC”#B¬∆ñ÷óC¢ñÁC”¬W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢&WGW&‚FWfñ6U˜G&ffñ5˜W6vRÜ2∆Ü˜W'2∆∆ñ÷óBê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2˜7V÷÷'í"ê¶FVb&W˜'E˜7V÷÷'íáW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢7V÷÷'í∆&ˆGì÷'Vñ∆EˆÊWGv˜&µ˜&W˜'BÜ2ê¢&WGW&‚≤&vVÊW&FVEˆB#¶Ê˜rÇí¬'7V÷÷'í#ß7V÷÷'í¬&&ˆGï˜FWáB#¶&ˆGó–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2ˆvVÊW&FR"ê¶FVb&W˜'EˆvVÊW&FRá&WVW7C¢&WVW7B¬&W˜'E˜GóS¢7G"“&ÊWGv˜&µ˜7V÷÷'í"¬W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚Ç'&W˜'G2ÊvVÊW&FR"ííì†¢ñb&W˜'E˜GóRÊ˜Bñ‚$Uı%EıEïU3¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬%VÁ7W˜'FVB&W˜'BGóR"ê¢vóFÇF"Çí23†¢&W÷vVÊW&FU˜&W˜'BÜ2«&W˜'E˜GóRê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬w&W˜'EˆvVÊW&FVBr«7G"á&W≤vñBu“í«&W≤wFóF∆Ru“∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚&W †¶6∆72&W˜'D'V∆¥FV∆WFU&WVW7BÑ&6T÷ˆFV¬ì†¢&W˜'EˆñG3¢∆ó7E∂ñÁE–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2ˆÜó7F˜'í"ê¶FVb&W˜'EˆÜó7F˜'íÜ∆ñ÷óC¢ñÁC”S¬W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤&˜w3÷2ÊWÜV7WFRÇ%4TƒT5BñB«66ÜVGV∆UˆñB«&W˜'E˜GóR«FóF∆R∆vVÊW&FVEˆB«7V÷÷'ïˆß6ˆ‚∆&ˆGï˜FWáBe$Ù“vVÊW&FVE˜&W˜'G2ı$DU"%íñBDU42ƒî‘ïBÚ"¬Ü÷ÇÉ∆÷ñ‚Ü∆ñ÷óB√#íí¬ííÊfWF6Ü∆¬Çê¢˜WC’µ–¢f˜""ñ‚&˜w3†¢C÷Fñ7Bá"ì≤E≤w7V÷÷'íu”÷ß6ˆ‚Ê∆ˆG2ÜBÁ˜Çw7V÷÷'ïˆß6ˆ‚rí˜"w∑“rì≤˜WBÊVÊBÜBê¢&WGW&‚˜W@†§ÊFV∆WFRÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2˜∑∑&W˜'EˆñG◊“"ê¶FVb&W˜'EˆFV∆WFRá&W˜'EˆñC¢ñÁB¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ê¢&˜s÷2ÊWÜV7WFRÇ%4TƒT5BñB«FóF∆R«&W˜'E˜GóRe$Ù“vVÊW&FVE˜&W˜'G2tÑU$RñC”Ú"¬á&W˜'EˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜s†¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬%&W˜'BÊ˜Bf˜VÊB"ê¢2ÊWÜV7WFRÇ$DTƒUDRe$Ù“vVÊW&FVE˜&W˜'G2tÑU$RñC”Ú"¬á&W˜'EˆñB¬íê¢VFóBÜ2«W6W%≤'W6W&Ê÷R%“¬'&W˜'EˆFV∆WFVB"«7G"á&W˜'EˆñBí∆ß6ˆ‚ÊGV◊2á≤'FóF∆R#ß&˜u≤'FóF∆R%“¬'&W˜'E˜GóR#ß&˜u≤'&W˜'E˜GóR%◊“í∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ˆ≤#•G'VR¬&FV∆WFVB#£–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2ˆ'V∆≤÷FV∆WFR"ê¶FVb&W˜'Eˆ'V∆µˆFV∆WFRá&W¢&W˜'D'V∆¥FV∆WFU&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢ñG3◊6˜'FVBá∂ñÁBáÇíf˜"Çñ‚&WÁ&W˜'EˆñG2ñbñÁBáÇì„“ê¢ñbÊ˜BñG3†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬$ÊÚ&W˜'G26V∆V7FVB"ê¢ñb∆V‚ÜñG2ì„#†¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬%FˆÚ÷Áí&W˜'G26V∆V7FVB"ê¢∆6VÜˆ∆FW'3“"¬"Ê¶ˆñ‚Ç#Ú"f˜"Úñ‚ñG2ê¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ê¢&˜w3÷2ÊWÜV7WFRÜb%4TƒT5BñB«FóF∆R«&W˜'E˜GóRe$Ù“vVÊW&FVE˜&W˜'G2tÑU$RñBî‚á∑∆6VÜˆ∆FW'7“í"∆ñG2íÊfWF6Ü∆¬Çê¢ñbÊ˜B&˜w3†¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬$ÊÚ6V∆V7FVB&W˜'G2vW&Rf˜VÊB"ê¢f˜VÊC’∑%≤&ñB%“f˜""ñ‚&˜w5–¢É“"¬"Ê¶ˆñ‚Ç#Ú"f˜"Úñ‚f˜VÊBê¢2ÊWÜV7WFRÜb$DTƒUDRe$Ù“vVÊW&FVE˜&W˜'G2tÑU$RñBî‚á∑á“í"∆f˜VÊBê¢VFóBÜ2«W6W%≤'W6W&Ê÷R%“¬'&W˜'G5ˆ'V∆µˆFV∆WFVB"¬'&W˜'G2"∆ß6ˆ‚ÊGV◊2á≤'&W˜'EˆñG2#¶f˜VÊB¬&6˜VÁB#¶∆V‚Üf˜VÊBó“í∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ˆ≤#•G'VR¬&FV∆WFVB#¶∆V‚Üf˜VÊBí¬'&W˜'EˆñG2#¶f˜VÊG–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2˜66ÜVGV∆W2"ê¶FVb&W˜'E˜66ÜVGV∆W2áW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤&WGW&‚∂Fñ7Bá"íf˜""ñ‚2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“&W˜'E˜66ÜVGV∆W2ı$DU"%íÊ÷R"ï–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2˜66ÜVGV∆W2"ê¶FVb7&VFU˜&W˜'E˜66ÜVGV∆Rá&W¢&W˜'E66ÜVGV∆U&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢ñb&WÊ6FVÊ6RÊ˜Bñ‚≤vÜ˜W&«ír¬vFñ«ír¬wvVV∂«íw”¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬$6FVÊ6R◊W7B&RÜ˜W&«í¬Fñ«í¬˜"vVV∂«í"ê¢ñb&WÁ&W˜'E˜GóRÊ˜Bñ‚$Uı%EıEïU3¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬%VÁ7W˜'FVB&W˜'BGóR"ê¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤7F◊÷Ê˜rÇì≤ÁáC÷ÊWáE˜&W˜'E˜Fñ÷Rá&WÊ6FVÊ6R«&WÊÜ˜W%˜WF2«&WÁvVV∂Fíê¢G'ì¢&ñC÷2ÊWÜV7WFRÇ$îÂ4U%BîÂDÚ&W˜'E˜66ÜVGV∆W2ÜÊ÷R«&W˜'E˜GóR∆VÊ&∆VB∆6FVÊ6R∆Ü˜W%˜WF2«vVV∂Fí∆Ê˜Fñgí∆ÊWáE˜'VÂˆB∆7&VFVEˆB«WFFVEˆBíd≈TU2ÉÚ√Ú√Ú√Ú√Ú√Ú√Ú√Ú√Ú√Úí"¬á&WÊÊ÷R«&WÁ&W˜'E˜GóR∆ñÁBá&WÊVÊ&∆VBí«&WÊ6FVÊ6R∆÷ÇÉ∆÷ñ‚É#2«&WÊÜ˜W%˜WF2íí«&WÁvVV∂FíSr∆ñÁBá&WÊÊ˜Fñgíí∆ÁáB«7F◊«7F◊ííÊ∆7G&˜vñ@¢WÜ6WB7∆óFS2‰ñÁFVw&óGîW'&˜#¢&ó6RÖEEWÜ6WFñˆ‚ÉCí¬$&W˜'B66ÜVGV∆RvóFÇFÜBÊ÷R«&VGíWÜó7G2"ê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬w&W˜'E˜66ÜVGV∆Uˆ7&VFVBr«7G"á&ñBí«&WÊÊ÷R∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚Fñ7BÜ2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“&W˜'E˜66ÜVGV∆W2tÑU$RñC”Ú"¬á&ñB¬ííÊfWF6ÜˆÊRÇíê†§ÊFV∆WFRÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2˜66ÜVGV∆W2˜∑∑66ÜVGV∆UˆñG◊“"ê¶FVbFV∆WFU˜&W˜'E˜66ÜVGV∆Rá66ÜVGV∆UˆñC¢ñÁB¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤7W#÷2ÊWÜV7WFRÇ$DTƒUDRe$Ù“&W˜'E˜66ÜVGV∆W2tÑU$RñC”Ú"¬á66ÜVGV∆UˆñB¬íê¢ñbÊ˜B7W"Á&˜v6˜VÁC¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬%66ÜVGV∆RÊ˜Bf˜VÊB"ê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬w&W˜'E˜66ÜVGV∆UˆFV∆WFVBr«7G"á66ÜVGV∆UˆñBí¬rr∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ˆ≤#•G'VW–††¢2“““F6Ü&ˆ&Bfó7V∆ó¶Fñˆ‚≤∆ñÊ6RÜ&FVÊñÊrc„R““““““““““““““““““–¶6∆72&WFVÁFñˆÂ&WVW7BÑ&6T÷ˆFV¬ì†¢G&ffñ5˜&WFVÁFñˆÂˆFó3¢ñÁB“p¢WfVÁE˜&WFVÁFñˆÂˆFó3¢ñÁB“ì ¢VFóE˜&WFVÁFñˆÂˆFó3¢ñÁB“3cP¢&W˜'E˜&WFVÁFñˆÂˆFó3¢ñÁB“3cP¢7ñÊ5˜&WFVÁFñˆÂˆFó3¢ñÁB“ì ¢Ê˜Fñfñ6FñˆÂ˜&WFVÁFñˆÂˆFó3¢ñÁB“ì †¶6∆72&6∑W&W7F˜&U&WVW7BÑ&6T÷ˆFV¬ì†¢fñ∆VÊ÷S¢7G †§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆÊ«óFñ72˜G&ffñ2"ê¶FVbG&ffñ5ˆÊ«óFñ72Ü÷ñÁWFW3¢ñÁC”c¬W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢&WGW&‚∞¢'6◊∆W2#ßG&ffñ5ˆÜó7F˜'íÜ2∆÷ñÁWFW2í¿¢&6∆ñVÁG2#¶6∆ñVÁEˆ&ÊGvñGFÖˆW7Fñ÷FW2Ü2í¿¢&FWfñ6U˜W6vR#¶FWfñ6U˜G&ffñ5˜W6vRÜ2∆÷ÇÉ¬Ü÷ñÁWFW2≥SííÚÛcí√í¿¢–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6RˆÜV«FÇ"ê¶FVbvWEˆ∆ñÊ6UˆÜV«FÇáW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢&WGW&‚∆ñÊ6UˆÜV«FÇÑD%ıDÇê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6R˜&WFVÁFñˆ‚"ê¶FVbvWE˜&WFVÁFñˆ‚áW6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23¢&WGW&‚&WFVÁFñˆÂˆ6ˆÊfñrÜ2ê†§ÁWBÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6R˜&WFVÁFñˆ‚"ê¶FVbWE˜&WFVÁFñˆ‚á&W¢&WFVÁFñˆÂ&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢6fs◊6fU˜&WFVÁFñˆ‚Ü2«&WÊ÷ˆFV≈ˆGV◊Çíì≤FV∆WFVC÷«ï˜&WFVÁFñˆ‚Ü2ê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬w&WFVÁFñˆÂ˜ˆ∆ñ7ï˜6fVBr¬v∆ñÊ6Rr∆ß6ˆ‚ÊGV◊2ÜFV∆WFVBí∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&6ˆÊfñr#¶6fr¬&FV∆WFVB#¶FV∆WFVG–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6R˜&WFVÁFñˆ‚˜'V‚"ê¶FVb'VÂ˜&WFVÁFñˆ‚á&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢FV∆WFVC÷«ï˜&WFVÁFñˆ‚Ü2ì≤VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬w&WFVÁFñˆÂ˜'V‚r¬v∆ñÊ6Rr∆ß6ˆ‚ÊGV◊2ÜFV∆WFVBí∆6∆ñVÁEˆóá&WVW7Bíì≤&WGW&‚≤&FV∆WFVB#¶FV∆WFVG–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6Rˆ&6∑W2"ê¶FVb&6∑W2áW6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23¢&WGW&‚∆ó7Eˆ&6∑W2Ü2ê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6Rˆ&6∑W2"ê¶FVb÷∂Uˆ&6∑Wá&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢FÉ÷7&VFUˆ&6∑WÑD%ıDÇ¬v÷ÁV¬rê¢vóFÇF"Çí23†¢VÁ7W&UˆÜ&FVÊñÊu˜66ÜV÷Ü2ê¢2ÊWÜV7WFRÇ$îÂ4U%Bı"ît‰ı$RîÂDÚ&6∑W˜'VÁ2Üfñ∆VÊ÷R∆7&VFVEˆB«6ó¶Uˆ'óFW2«7FGW2∆Ê˜FRíd≈TU2ÉÚ√Ú√Ú√Ú√Úí"¬áFÇÊÊ÷R∆Ê˜rÇí«FÇÁ7FBÇíÁ7E˜6ó¶R¬v6ˆ◊∆WFRr¬v÷ÁV¬ríê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬v&6∑Wˆ7&VFVBr«FÇÊÊ÷R«7G"áFÇÁ7FBÇíÁ7E˜6ó¶Rí∆6∆ñVÁEˆóá&WVW7Bíì≤2Ê6ˆ÷÷óBÇê¢&WGW&‚≤&ˆ≤#•G'VR¬&fñ∆VÊ÷R#ßFÇÊÊ÷R¬'6ó¶Uˆ'óFW2#ßFÇÁ7FBÇíÁ7E˜6ó¶W–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6Rˆ&6∑W2˜&W7F˜&R"ê¶FVb&W7F˜&UˆWÜó7FñÊuˆ&6∑Wá&W¢&6∑W&W7F˜&U&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢27&VFR6fWGí&6∑Wñ÷÷VFñFV«í&Vf˜&R&W7F˜&R6ÚFÜR˜W&Fñˆ‚ó2&WfW'6ñ&∆R‡¢6fWGì÷7&VFUˆ&6∑WÑD%ıDÇ¬w&R◊&W7F˜&Rrê¢G'ì¢&W7V«C◊&W7F˜&Uˆ&6∑WÑD%ıDÇ«&WÊfñ∆VÊ÷Rê¢WÜ6WBÖf«VTW'&˜"ƒfñ∆TÊ˜Df˜VÊDW'&˜"≈'VÁFñ÷TW'&˜"í2WÜ3¢&ó6RÖEEWÜ6WFñˆ‚ÉC«7G"ÜWÜ2íê¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤VÁ7W&UˆÜ&FVÊñÊu˜66ÜV÷Ü2ì≤÷ñw&FU˜∆ñÁFWáE˜6V7&WG2Ü2ê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬v&6∑W˜&W7F˜&VBr«&WÊfñ∆VÊ÷R∆bw&R◊&W7F˜&S◊∑6fWGíÊÊ÷W“r∆6∆ñVÁEˆóá&WVW7Bíì≤2Ê6ˆ÷÷óBÇê¢&WGW&‚≤¢ß&W7V«B¬'6fWGïˆ&6∑W#ß6fWGíÊÊ÷R¬'&W7F'E˜&V6ˆ÷÷VÊFVB#•G'VW–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6R˜&ˆ÷WFÜWW2÷∂Wí"ê¶FVb&˜FFU˜&ˆ÷WFÜWW5ˆ∂Wíá&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢∂Wì÷vVÊW&FU˜&ˆ÷WFÜWW5ˆ∂WíÜ2ì≤VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬w&ˆ÷WFÜWW5ˆ∂Wï˜&˜FFVBr¬v÷WG&ñ72r¬rr∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ïˆ∂Wí#¶∂Wí¬'v&ÊñÊr#¢%FÜó2∂Wíó26Ü˜v‚ˆÊ6R‚7F˜&RóBñ‚ñ˜W"&ˆ÷WFÜWW26ˆÊfñwW&Fñˆ‚‚'–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2˜∑∑&W˜'EˆñG◊“ˆWá˜'BÊ77b"ê¶FVbWá˜'E˜&W˜'Eˆ77bá&W˜'EˆñC¢ñÁB¬W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢&˜s÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“vVÊW&FVE˜&W˜'G2tÑU$RñC”Ú"¬á&W˜'EˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜s¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬%&W˜'BÊ˜Bf˜VÊB"ê¢C÷Fñ7Bá&˜rì≤E≤w7V÷÷'íu”÷ß6ˆ‚Ê∆ˆG2ÜBÊvWBÇw7V÷÷'ïˆß6ˆ‚rí˜"w∑“rê¢&WGW&‚&W7ˆÁ6RÜ6ˆÁFVÁC◊&W˜'Eˆ77eˆ'óFW2ÜBí∆÷VFñ˜GóS“wFWáBˆ77c≤6Ü'6WC◊WFb”Çr∆ÜVFW'3◊≤t6ˆÁFVÁB‘Fó7˜6óFñˆ‚s¶bvGF6Ü÷VÁC≤fñ∆VÊ÷S“&vˆG6WñR◊&W˜'B◊∑&W˜'EˆñG“Ê77b"w“ê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜&W˜'G2˜∑∑&W˜'EˆñG◊“ˆWá˜'BÁFb"ê¶FVbWá˜'E˜&W˜'E˜Fbá&W˜'EˆñC¢ñÁB¬W6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢vóFÇF"Çí23†¢&˜s÷2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“vVÊW&FVE˜&W˜'G2tÑU$RñC”Ú"¬á&W˜'EˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜s¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬%&W˜'BÊ˜Bf˜VÊB"ê¢C÷Fñ7Bá&˜rì≤E≤w7V÷÷'íu”÷ß6ˆ‚Ê∆ˆG2ÜBÊvWBÇw7V÷÷'ïˆß6ˆ‚rí˜"w∑“rê¢&WGW&‚&W7ˆÁ6RÜ6ˆÁFVÁC◊&W˜'E˜Feˆ'óFW2ÜBí∆÷VFñ˜GóS“v∆ñ6Fñˆ‚˜Fbr∆ÜVFW'3◊≤t6ˆÁFVÁB‘Fó7˜6óFñˆ‚s¶bvGF6Ü÷VÁC≤fñ∆VÊ÷S“&vˆG6WñR◊&W˜'B◊∑&W˜'EˆñG“ÁFb"w“ê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆÊ˜Fñfñ6FñˆÁ2ˆ6ˆÊfñr"ê¶FVbvWEˆÊ˜Fñfñ6FñˆÂˆ6ˆÊfñráW6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤C÷Fñ7BÜ2ÊWÜV7WFRÇ%4TƒT5B¢e$Ù“Ê˜Fñfñ6FñˆÂˆ6ˆÊfñw2tÑU$RñC”"íÊfWF6ÜˆÊRÇíê¢E≤vÜ5˜6◊G˜77v˜&Bu”÷&ˆˆ¬ÜBÊvWBÇw6◊G˜77v˜&Bríì≤BÁ˜Çw6◊G˜77v˜&BrƒÊˆÊRì≤&WGW&‚@†§ÁWBÜb'∑&˜WFW%˜&Vfóá“ˆÊ˜Fñfñ6FñˆÁ2ˆ6ˆÊfñr"ê¶FVb6fUˆÊ˜Fñfñ6FñˆÂˆ6ˆÊfñrá&W¢Ê˜Fñfñ6Fñˆ‰6ˆÊfñu&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢ñb&WÊ÷ñÂ˜6WfW&óGíÊ˜Bñ‚dƒîEı4UdU$ïDîU3¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬$ñÁf∆ñB÷ñÊñ◊V“6WfW&óGí"ê¢vóFÇF"Çí23†¢VÁ7W&Uˆó%˜66ÜV÷Ü2ì≤ˆ∆C÷2ÊWÜV7WFRÇ%4TƒT5B6◊G˜77v˜&Be$Ù“Ê˜Fñfñ6FñˆÂˆ6ˆÊfñw2tÑU$RñC”"íÊfWF6ÜˆÊRÇì≤s÷VÊ7'óE˜6V7&WBá&WÁ6◊G˜77v˜&Bíñb&WÁ6◊G˜77v˜&Bó2Ê˜BÊˆÊRV«6RÜˆ∆E≤w6◊G˜77v˜&Bu“ñbˆ∆BV«6Rrrê¢2ÊWÜV7WFRÇ""%UDDRÊ˜Fñfñ6FñˆÂˆ6ˆÊfñw24UBvV&ÜˆˆµˆVÊ&∆VC”Ú«vV&Üˆˆµ˜W&√”Ú∆ÁFgïˆVÊ&∆VC”Ú∆ÁFgï˜6W'fW#”Ú∆ÁFgï˜F˜ñ3”Ú«6◊GˆVÊ&∆VC”Ú«6◊GˆÜ˜7C”Ú«6◊G˜˜'C”Ú«6◊G˜W6W#”Ú«6◊G˜77v˜&C”Ú«6◊Gˆg&ˆ””Ú«6◊G˜FÛ”Ú∆÷ñÂ˜6WfW&óGì”Ú«WFFVEˆC”ÚtÑU$RñC”"""¿¢ÜñÁBá&WÁvV&ÜˆˆµˆVÊ&∆VBí«&WÁvV&Üˆˆµ˜W&¬∆ñÁBá&WÊÁFgïˆVÊ&∆VBí«&WÊÁFgï˜6W'fW"«&WÊÁFgï˜F˜ñ2∆ñÁBá&WÁ6◊GˆVÊ&∆VBí«&WÁ6◊GˆÜ˜7B«&WÁ6◊G˜˜'B«&WÁ6◊G˜W6W"«r«&WÁ6◊Gˆg&ˆ“«&WÁ6◊G˜FÚ«&WÊ÷ñÂ˜6WfW&óGí∆Ê˜rÇííê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬vÊ˜Fñfñ6FñˆÂˆ6ˆÊfñu˜6fVBr¬vÊ˜Fñfñ6FñˆÁ2r¬rr∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚≤&ˆ≤#•G'VW–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆÊ˜Fñfñ6FñˆÁ2˜FW7B"ê¶FVbFW7EˆÊ˜Fñfñ6Fñˆ‚á&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢&W7V«C◊6VÊEˆÊ˜Fñfñ6Fñˆ‚Ü2¬wFW7Br¬wv&ÊñÊrr¬ttÙE4UîRFW7BÊ˜Fñfñ6Fñˆ‚r¬uñ˜W"tÙE4UîRÊ˜Fñfñ6Fñˆ‚6ˆÊfñwW&Fñˆ‚ó2v˜&∂ñÊr‚r∆FVGWUˆ∂Wì‘ÊˆÊRê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬vÊ˜Fñfñ6FñˆÂ˜FW7Br¬vÊ˜Fñfñ6FñˆÁ2r∆ß6ˆ‚ÊGV◊2á&W7V«Bí∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚&W7V«@††¢2“““&ˆGV7Fñˆ‚∆ñÊ6R÷ÊvV÷VÁB≤WFˆ÷FVB&W7ˆÁ6Rc„b““““““““““–¶6∆72&ˆGV7FñˆÂ6WGFñÊw5&WVW7BÑ&6T÷ˆFV¬ì†¢WFıˆ&6∑WˆVÊ&∆VC¢&ˆˆ√’G'VP¢&6∑Wˆ6FVÊ6S¢7G#“vFñ«íp¢&6∑WˆÜ˜W%˜WF3¢ñÁC”0¢&6∑Wˆ∂VWˆ6˜VÁC¢ñÁC”@¢áGG5ˆ÷ˆFS¢7G#“vˆfbp¢áGG5ˆÜ˜7FÊ÷S¢7G#“rp¢WFFUˆ6ÜÊÊV√¢7G#“w7F&∆Rp†¶6∆726ˆÊfñtñ◊˜'E&WVW7BÑ&6T÷ˆFV¬ì†¢6ˆÊfñs¢Fñ7@†¶6∆72WFFT«ï&WVW7BÑ&6T÷ˆFV¬ì†¢fñ∆VÊ÷S¢7G ¢6Ü#Sc¢7G ¢6ˆÊfó&”¢7G †¶6∆72Ê˜Fñfñ6FñˆÂ&WG'ï&WVW7BÑ&6T÷ˆFV¬ì†¢FV∆ófW'ïˆñC¢ñÁ@†¶6∆72&V÷VFñFñˆÂ&WVW7BÑ&6T÷ˆFV¬ì†¢7Fñˆ„¢7G ¢F&vWC¢7G ¢6ˆÊfó&”¢7G †§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆWFÇ˜W&÷ó76ñˆÁ2"ê¶FVbW&÷ó76ñˆÁ2áW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì†¢W&◊3’$ÙƒUıU$‘ï54îÙÂ2ÊvWBáW6W%≤w&ˆ∆Ru“«6WBÇíê¢&WGW&‚≤w&ˆ∆RsßW6W%≤w&ˆ∆Ru“¬wW&÷ó76ñˆÁ2sß6˜'FVBáW&◊2ó–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6R˜&ˆGV7Fñˆ‚◊6WGFñÊw2"ê¶FVbvWE˜&ˆGV7FñˆÂ˜6WGFñÊw2áW6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23ß&WGW&‚&ˆGV7FñˆÂ˜6WGFñÊw2Ü2ê†§ÁWBÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6R˜&ˆGV7Fñˆ‚◊6WGFñÊw2"ê¶FVbWE˜&ˆGV7FñˆÂ˜6WGFñÊw2á&W¢&ˆGV7FñˆÂ6WGFñÊw5&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢ñb&WÊ&6∑Wˆ6FVÊ6RÊ˜Bñ‚≤vFñ«íw”¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬tˆÊ«íFñ«íWFˆ÷Fñ2&6∑Wó27W'&VÁF«í7W˜'FVBrê¢ñb&WÊáGG5ˆ÷ˆFRÊ˜Bñ‚≤vˆfbr¬w6V∆b◊6ñvÊVBr¬v∆WG6VÊ7'óBw”¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬tñÁf∆ñBÖEE2÷ˆFRrê¢ñb&WÁWFFUˆ6ÜÊÊV¬Ê˜Bñ‚≤w7F&∆Rr¬v&WFw”¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬tñÁf∆ñBWFFR6ÜÊÊV¬rê¢vóFÇF"Çí23†¢#◊6fU˜&ˆGV7FñˆÂ˜6WGFñÊw2Ü2«≤¢ß&WÊ÷ˆFV≈ˆGV◊Çí¬vWFıˆ&6∑WˆVÊ&∆VBs¶ñÁBá&WÊWFıˆ&6∑WˆVÊ&∆VBí¬v&6∑WˆÜ˜W%˜WF2s¶÷ÇÉ∆÷ñ‚É#2«&WÊ&6∑WˆÜ˜W%˜WF2íí¬v&6∑Wˆ∂VWˆ6˜VÁBs¶÷ÇÉ∆÷ñ‚É«&WÊ&6∑Wˆ∂VWˆ6˜VÁBíó“ê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬w&ˆGV7FñˆÂ˜6WGFñÊw5˜6fVBr¬v∆ñÊ6Rr¬rr∆6∆ñVÁEˆóá&WVW7Bíì∑&WGW&‚ †§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ∆ñÊ6RˆáGG2"ê¶FVbvWEˆáGG5˜7FGW2áW6W#‘FWVÊG2ÜvWEˆ7W'&VÁE˜W6W"íì¢&WGW&‚áGG5˜7FGW2Çê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆ6ˆÊfñrˆWá˜'B"ê¶FVbWá˜'Eˆ6ˆÊfñwW&Fñˆ‚á&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢ñ∆ˆC÷6ˆÊfñuˆWá˜'BÜ2ì≤VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬v6ˆÊfñuˆWá˜'FVBr¬v6ˆÊfñwW&Fñˆ‚r¬w6V7&WG2WÜ6«VFVBr∆6∆ñVÁEˆóá&WVW7Bíê¢&WGW&‚&W7ˆÁ6RÜ6ˆÁFVÁC÷ß6ˆ‚ÊGV◊2áñ∆ˆB∆ñÊFVÁC”"í∆÷VFñ˜GóS“v∆ñ6Fñˆ‚ˆß6ˆ‚r∆ÜVFW'3◊≤t6ˆÁFVÁB‘Fó7˜6óFñˆ‚s¢vGF6Ü÷VÁC≤fñ∆VÊ÷S“&vˆG6WñR÷6ˆÊfñrÊß6ˆ‚"w“ê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆ6ˆÊfñrˆñ◊˜'B"ê¶FVbñ◊˜'Eˆ6ˆÊfñwW&Fñˆ‚á&W¢6ˆÊfñtñ◊˜'E&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢G'ìß#÷6ˆÊfñuˆñ◊˜'BÜ2«&WÊ6ˆÊfñrê¢WÜ6WBf«VTW'&˜"2S¢&ó6RÖEEWÜ6WFñˆ‚ÉC«7G"ÜRíê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬v6ˆÊfñuˆñ◊˜'FVBr¬v6ˆÊfñwW&Fñˆ‚r«"ÊvWBÇvÊ˜FRr¬rrí∆6∆ñVÁEˆóá&WVW7Bíì∑&WGW&‚ †§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆVFóB˜6V&6Ç"ê¶FVb6V&6ÖˆVFóBÜ7F˜#ß7G#“rr∆7Fñˆ„ß7G#“rr«F&vWCß7G#“rr«7F'Cß7G#“rr∆VÊCß7G#“rr∆∆ñ÷óC¶ñÁC”#«W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚ÇvVFóBÁ&VBrííì†¢vóFÇF"Çí23ß&WGW&‚VFóE˜VW'íÜ2∆7F˜#÷7F˜"∆7Fñˆ„÷7Fñˆ‚«F&vWC◊F&vWB«7F'C◊7F'B∆VÊC÷VÊB∆∆ñ÷óC÷∆ñ÷óBê†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆVFóBˆWá˜'BÊ77b"ê¶FVbWá˜'EˆVFóBÜ7F˜#ß7G#“rr∆7Fñˆ„ß7G#“rr«F&vWCß7G#“rr«7F'Cß7G#“rr∆VÊCß7G#“rr∆∆ñ÷óC¶ñÁC”#«W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚ÇvVFóBÁ&VBrííì†¢vóFÇF"Çí23¢&˜w3÷VFóE˜VW'íÜ2∆7F˜#÷7F˜"∆7Fñˆ„÷7Fñˆ‚«F&vWC◊F&vWB«7F'C◊7F'B∆VÊC÷VÊB∆∆ñ÷óC÷∆ñ÷óBê¢&WGW&‚&W7ˆÁ6RÜ6ˆÁFVÁC÷VFóEˆ77bá&˜w2í∆÷VFñ˜GóS“wFWáBˆ77br∆ÜVFW'3◊≤t6ˆÁFVÁB‘Fó7˜6óFñˆ‚s¢vGF6Ü÷VÁC≤fñ∆VÊ÷S“&vˆG6WñR÷VFóBÊ77b"w“ê†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆVFóBˆ6∆V""ê¶FVb6∆V%ˆVFóEˆ∆ˆrá&W¢6∆V%&V6ˆÂ&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢&V6ˆ„◊&WÊ6∆VÂ˜&V6ˆ‚Çê¢7F◊÷GBÊFFWFñ÷RÊÊ˜rÜGBÁFñ÷W¶ˆÊRÁWF2ê¢&˜FV7FVE˜VÁFñ√“á7F◊∂GBÁFñ÷VFV«FÜFó3”rííÊó6ˆf˜&÷BÇê¢vóFÇF"Çí23†¢2&W6W'fRÁí&˜FV7FVBVFóB÷6∆V"÷&∂W'2FÜB&R7Fñ∆¬ñÁ6ñFRFÜVó"r÷FíÜˆ∆BvñÊF˜r‡¢&W6W'fVC÷2ÊWÜV7WFRÇ%4TƒT5B4ıTÂBÇ¢íe$Ù“VFóEˆ∆ˆrtÑU$R&˜FV7FVE˜VÁFñ¬ï2‰ıBÂTƒ¬‰B&˜FV7FVE˜VÁFñ¬‚Ú"¬á7F◊Êó6ˆf˜&÷BÇí¬ííÊfWF6ÜˆÊRÇï≥–¢FV∆WFVC÷2ÊWÜV7WFRÇ$DTƒUDRe$Ù“VFóEˆ∆ˆrtÑU$R&˜FV7FVE˜VÁFñ¬ï2ÂTƒ¬ı"&˜FV7FVE˜VÁFñ¬√“Ú"¬á7F◊Êó6ˆf˜&÷BÇí¬ííÁ&˜v6˜VÁ@¢2ÊWÜV7WFRÇ$îÂ4U%BîÂDÚVFóEˆ∆ˆrÜ7F˜"∆7Fñˆ‚«F&vWB∆FWFñ«2∆ó∆7&VFVEˆB«&˜FV7FVE˜VÁFñ¬íd≈TU2ÉÚ√Ú√Ú√Ú√Ú√Ú√Úí"¿¢áW6W%≤wW6W&Ê÷Ru“¬vVFóEˆ∆ˆuˆ6∆V&VBr¬vVFóEˆ∆ˆrr∆bw&V6ˆ„◊∑&V6ˆÁ”≤FV∆WFVC◊∂FV∆WFVG”≤&W6W'fVE˜&˜FV7FVC◊∑&W6W'fVG“r∆6∆ñVÁEˆóá&WVW7Bí«7F◊Êó6ˆf˜&÷BÇí«&˜FV7FVE˜VÁFñ¬íê¢&WGW&‚≤&ˆ≤#•G'VR¬&FV∆WFVB#¶FV∆WFVB¬'&W6W'fVE˜&˜FV7FVB#ß&W6W'fVB¬&6∆V&VEˆ'í#ßW6W%≤wW6W&Ê÷Ru“¬'&V6ˆ‚#ß&V6ˆ‚¬'&˜FV7FVE˜VÁFñ¬#ß&˜FV7FVE˜VÁFñ«–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“ˆÊ˜Fñfñ6FñˆÁ2ˆÜó7F˜'í"ê¶FVbÊ˜Fñfñ6FñˆÂˆÜó7F˜'íÜ∆ñ÷óC¶ñÁC”«W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚ÇvÊ˜Fñfñ6FñˆÁ2Á&WG'írííì†¢vóFÇF"Çí23†¢VÁ7W&U˜&ˆGV7FñˆÂ˜66ÜV÷Ü2ì≤&WGW&‚∂Fñ7Bá"íf˜""ñ‚2ÊWÜV7WFRÇu4TƒT5B¢e$Ù“Ê˜Fñfñ6FñˆÂˆFV∆ófW&ñW2ı$DU"%íñBDU42ƒî‘ïBÚr¬Ü÷ÇÉ∆÷ñ‚Ü∆ñ÷óB√Síí¬ííÊfWF6Ü∆¬Çï–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“ˆÊ˜Fñfñ6FñˆÁ2˜&WG'í"ê¶FVbÊ˜Fñfñ6FñˆÂ˜&WG'íá&W¢Ê˜Fñfñ6FñˆÂ&WG'ï&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&U˜W&÷ó76ñˆ‚ÇvÊ˜Fñfñ6FñˆÁ2Á&WG'írííì†¢vóFÇF"Çí23†¢VÁ7W&U˜&ˆGV7FñˆÂ˜66ÜV÷Ü2ì≤&˜s÷2ÊWÜV7WFRÇu4TƒT5B¢e$Ù“Ê˜Fñfñ6FñˆÂˆFV∆ófW&ñW2tÑU$RñC”Úr¬á&WÊFV∆ófW'ïˆñB¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B&˜s¢&ó6RÖEEWÜ6WFñˆ‚ÉCB¬tÊ˜Fñfñ6Fñˆ‚FV∆ófW'íÊ˜Bf˜VÊBrê¢C÷Fñ7Bá&˜rì≤&W7V«C◊6VÊEˆÊ˜Fñfñ6Fñˆ‚Ü2∆E≤vWfVÁE˜GóRu“∆E≤w6WfW&óGíu“∆BÊvWBÇwFóF∆Rrí˜"ttÙE4UîRÊ˜Fñfñ6Fñˆ‚&WG'ír∆BÊvWBÇv&ˆGírí˜"BÊvWBÇvFWFñ«2rí˜"rr«F&vWC÷BÊvWBÇwF&vWBrí∆FVGWUˆ∂Wì‘ÊˆÊR∆f˜&6S’G'VRê¢2ÊWÜV7WFRÇuUDDRÊ˜Fñfñ6FñˆÂˆFV∆ófW&ñW24UBGFV◊G3÷GFV◊G2≥∆∆7EˆGFV◊EˆC”ÚtÑU$RñC”Úr¬ÜÊ˜rÇí«&WÊFV∆ófW'ïˆñBíì≤VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬vÊ˜Fñfñ6FñˆÂ˜&WG&ñVBr«7G"á&WÊFV∆ófW'ïˆñBí∆ß6ˆ‚ÊGV◊2á&W7V«Bï≥£“∆6∆ñVÁEˆóá&WVW7Bíì∂2Ê6ˆ÷÷óBÇì∑&WGW&‚&W7V«@†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜WFFW2˜7FvR"ê¶7ñÊ2FVb7FvU˜WFFRá&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢fñ∆VÊ÷S◊&WVW7BÊÜVFW'2ÊvWBÇwÇ÷fñ∆VÊ÷Rr¬vvˆG6WñR◊WFFRÁ¶órì≤FF÷vóB&WVW7BÊ&ˆGíÇê¢G'ìß«6Ü«c◊7FvU˜WFFUˆ'óFW2ÜFF∆fñ∆VÊ÷Rê¢WÜ6WBf«VTW'&˜"2S¢&ó6RÖEEWÜ6WFñˆ‚ÉC«7G"ÜRíê¢vóFÇF"Çí23†¢VÁ7W&U˜&ˆGV7FñˆÂ˜66ÜV÷Ü2ì≤2ÊWÜV7WFRÇtîÂ4U%BîÂDÚWFFU˜'VÁ2Üfñ∆VÊ÷R«6Ü#Sb«fW'6ñˆ‚«7FGW2«&Vf∆ñváEˆß6ˆ‚∆7F˜"∆7&VFVEˆBíd≈TU2ÉÚ√Ú√Ú√Ú√Ú√Ú√Úír¬áÊÊ÷R«6Ü«bÊvWBÇwfW'6ñˆ‚rí¬w&Vf∆ñváE˜76VBrñbbÊvWBÇvˆ≤ríV«6Rw&Vf∆ñváEˆfñ∆VBr∆ß6ˆ‚ÊGV◊2ábí«W6W%≤wW6W&Ê÷Ru“∆Ê˜rÇííì≤VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬wWFFU˜7FvVBr«ÊÊ÷R«6Ü∆6∆ñVÁEˆóá&WVW7Bíì∂2Ê6ˆ÷÷óBÇê¢&WGW&‚≤vfñ∆VÊ÷RsßÊÊ÷R¬w6Ü#Sbsß6Ü¬w&Vf∆ñváBsßg–†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜WFFW2ˆÜó7F˜'í"ê¶FVbWFFUˆÜó7F˜'íÜ∆ñ÷óC¶ñÁC”S«W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&U˜&ˆGV7FñˆÂ˜66ÜV÷Ü2ì∑&WGW&‚∂Fñ7Bá"íf˜""ñ‚2ÊWÜV7WFRÇu4TƒT5B¢e$Ù“WFFU˜'VÁ2ı$DU"%íñBDU42ƒî‘ïBÚr¬Ü÷ÇÉ∆÷ñ‚Ü∆ñ÷óB√#íí¬ííÊfWF6Ü∆¬Çï–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜WFFW2ˆ«í"ê¶FVb«ï˜WFFRá&W¢WFFT«ï&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢ñb&WÊ6ˆÊfó&““t≈ítÙE4UîRUDDRs¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬tWÜ7B6ˆÊfó&÷Fñˆ‚FWáB&WVó&VC¢≈ítÙE4UîRUDDRrê¢6fWGì÷7&VFUˆ&6∑WÑD%ıDÇ¬w&R◊WFFRrê¢vóFÇF"Çí23†¢G'ìß#÷«ï˜7FvVE˜WFFRÜ2«&WÊfñ∆VÊ÷R«&WÁ6Ü#Sb«W6W%≤wW6W&Ê÷Ru“ê¢WÜ6WBÖf«VTW'&˜"ƒfñ∆TÊ˜Df˜VÊDW'&˜"í2S¢&ó6RÖEEWÜ6WFñˆ‚ÉC«7G"ÜRíê¢VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬wWFFUˆ«ï˜&WVW7FVBr«&WÊfñ∆VÊ÷R∆bw6fWGïˆ&6∑W◊∑6fWGíÊÊ÷W”≤7FGW3◊∑"ÊvWBÇ'7FGW2"ó“r∆6∆ñVÁEˆóá&WVW7Bíì∑&WGW&‚≤¢ß"¬w6fWGïˆ&6∑Wsß6fWGíÊÊ÷W–†§Á˜7BÜb'∑&˜WFW%˜&Vfóá“˜&V÷VFñFñˆ‚ˆWÜV7WFR"ê¶FVbWÜV7WFU˜&V÷VFñFñˆ‚á&W¢&V÷VFñFñˆÂ&WVW7B¬&WVW7C¢&WVW7B¬W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢7Fñˆ„◊&WÊ7Fñˆ‚Ê∆˜vW"Çì≤F&vWC◊&WÁF&vWBÁ7G&óÇê¢WáV7FVC÷bt4Ù‰dï$“∂7Fñˆ‚ÁWW"Çó“∑F&vWG“p¢ñb&WÊ6ˆÊfó&“÷WáV7FVC¢&ó6RÖEEWÜ6WFñˆ‚ÉC∆btWÜ7B6ˆÊfó&÷Fñˆ‚&WVó&VC¢∂WáV7FVG“rê¢ñb7Fñˆ‚Ê˜Bñ‚≤wVÊñfï˜V&ÁFñÊRr¬wñÜˆ∆Uˆ&∆ˆ6µˆFˆ÷ñ‚w”¢&ó6RÖEEWÜ6WFñˆ‚ÉC¬uVÁ7W˜'FVB&V÷VFñFñˆ‚7Fñˆ‚rê¢vóFÇF"Çí23†¢VÁ7W&U˜&ˆGV7FñˆÂ˜66ÜV÷Ü2ì≤6fs÷2ÊWÜV7WFRÇu4TƒT5B¢e$Ù“ñÁFVw&FñˆÂˆ6ˆÊfñw2tÑU$R∂ñÊC”Ú‰BVÊ&∆VC”ı$DU"%íñBƒî‘ïBr¬ÇwVÊñfírñb7Fñˆ„”“wVÊñfï˜V&ÁFñÊRrV«6RwñÜˆ∆Rr¬ííÊfWF6ÜˆÊRÇê¢ñbÊ˜B6fs¢&ó6RÖEEWÜ6WFñˆ‚ÉCí¬u&WVó&VBñÁFVw&Fñˆ‚ó2Ê˜B6ˆÊfñwW&VBrê¢&ñC÷2ÊWÜV7WFRÇtîÂ4U%BîÂDÚ&V÷VFñFñˆÂˆ7FñˆÁ2Ü7FñˆÂ˜GóR«F&vWB«&WVW7FVEˆ'í∆6ˆÊfó&÷Fñˆ‚«7FGW2∆7&VFVEˆBíd≈TU2ÉÚ√Ú√Ú√Ú√Ú√Úír¬Ü7Fñˆ‚«F&vWB«W6W%≤wW6W&Ê÷Ru“«&WÊ6ˆÊfó&“¬w&WVW7FVBr∆Ê˜rÇíííÊ∆7G&˜vñ@¢2FV∆ñ&W&FV«í6∆¬ˆÊ«íFÜR6ˆÊfñwW&VB∆ˆ6¬6ˆÁG&ˆ∆∆W"ıí÷Üˆ∆R‚ÊÚ&&óG&'íVÊGˆñÁBó266WFVBÜW&R‡¢&W7V«C◊≤vˆ≤s§f«6R¬v7Fñˆ‚s¶7Fñˆ‚¬wF&vWBsßF&vWG–¢G'ì†¢ñb7Fñˆ„”“wñÜˆ∆Uˆ&∆ˆ6µˆFˆ÷ñ‚s†¢ñbÊ˜B&RÊgV∆∆÷F6Çá"rÉÛ“Á≥√#S7“BíÉÛ•¥’¶◊£”ï“ÉÛ•¥’¶◊£”í’◊≥√c’¥’¶◊£”ï“ìı¬‚íµ¥’¶◊•◊≥"√c7“r«F&vWBì¢&ó6Rf«VTW'&˜"ÇuF&vWB◊W7B&Rf∆ñBFˆ÷ñ‚Ê÷Rrê¢6V7&WC÷FV7'óE˜6V7&WBÜ6fu≤w6V7&WBu“íñb6fu≤w6V7&WBu“V«6Rrp¢&6S÷6fu≤wF&vWBu“Á'7G&óÇrÚrì≤&ˆGì÷ß6ˆ‚ÊGV◊2á≤wGóRs¢vFVÁír¬v∂ñÊBs¢vWÜ7Br¬v6ˆ÷÷VÁBs¢t&∆ˆ6∂VB'ítÙE4UîRF÷ñÊó7G&F˜"w“íÊVÊ6ˆFRÇì≤ÜVFW'3◊≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚r¬uW6W"‘vVÁBs¢ttÙE4UîRÛ„bw–¢ñb6V7&WC¢ÜVFW'5≤uÇ‘eD¬’4îBu”◊6V7&WC≤ÜVFW'5≤tWFÜ˜&ó¶Fñˆ‚u”“t&V&W"r∑6V7&W@¢W'&˜'3’µ”≤6VÁC‘f«6P¢2í÷Üˆ∆Rcbíf&ñÁG2fó'7B¬FÜV‚FÜR∆Vv7ícRF÷ñ‚í‡¢f˜"W&¬∆÷WFÜˆB∆FFñ‚∞¢Ü&6R≤rˆíˆFˆ÷ñÁ2ˆFVÁíˆWÜ7BÚr∑W&∆∆ñ"Á'6RÁV˜FRáF&vWB«6fS“rrí¬uı5Br∆&ˆGíí¿¢Ü&6R≤rˆíˆFˆ÷ñÁ2Úr∑W&∆∆ñ"Á'6RÁV˜FRáF&vWB«6fS“rrí¬uı5Br∆&ˆGíí¿¢Ü&6R≤rˆF÷ñ‚ˆíÁáÚr∑W&∆∆ñ"Á'6RÁW&∆VÊ6ˆFRá≤v∆ó7Bs¢v&∆6≤r¬vFBsßF&vWB¬vWFÇsß6V7&WG“í¬ttUBrƒÊˆÊRí¿¢”†¢G'ì†¢'◊W&∆∆ñ"Á&WVW7BÂ&WVW7BáW&¬∆FF÷FF∆ÜVFW'3÷ÜVFW'2∆÷WFÜˆC÷÷WFÜˆBì≤W&∆∆ñ"Á&WVW7BÁW&∆˜V‚á'«Fñ÷V˜WC”ÇíÁ&VBÇì≤6VÁC’G'VS≤'&V∞¢WÜ6WBWÜ6WFñˆ‚2WÉ¢W'&˜'2ÊVÊBá7G"ÜWÇíê¢ñbÊ˜B6VÁC¢&ó6R'VÁFñ÷TW'&˜"Çuí÷Üˆ∆R&∆ˆ6≤&WVW7Bfñ∆VC¢r≤s≤rÊ¶ˆñ‚ÜW'&˜'2ï≤”#•“ê¢&W7V«C◊≤vˆ≤s•G'VR¬v7Fñˆ‚s¶7Fñˆ‚¬wF&vWBsßF&vWG–¢V«6S†¢ñbÊ˜B&RÊgV∆∆÷F6Çá"rÉÛ•≥”î‘f÷e◊≥'”¢ó≥W’≥”î‘f÷e◊≥'“r«F&vWBì¢&ó6Rf«VTW'&˜"ÇuVÊîfíV&ÁFñÊRF&vWB◊W7B&R‘2FG&W72rê¢26ˆˆ∂ñR◊&W6W'fñÊrVÊîfí∆ˆvñ‚¬7W˜'FñÊr&˜FÇVÊîfíı2ÊB∆Vv7í6ˆÁG&ˆ∆∆W"Fá2‡¢ñ◊˜'B76¬2˜76¿¢g&ˆ“áGGÊ6ˆˆ∂ñV¶"ñ◊˜'B6ˆˆ∂ñT¶ ¢&6S÷6fu≤wF&vWBu“Á'7G&óÇrÚrì≤6óFS÷ß6ˆ‚Ê∆ˆG2Ü6fu≤v˜FñˆÁ5ˆß6ˆ‚u“˜"w∑“ríÊvWBÇw6óFRr¬vFVfV«Brì≤77v˜&C÷FV7'óE˜6V7&WBÜ6fu≤w6V7&WBu“íñb6fu≤w6V7&WBu“V«6Rrs≤W6W&Ê÷S÷6fu≤wW6W&Ê÷Ru“˜"rp¢6ˆÁFWáC‘ÊˆÊRñb6fu≤wfW&ñgï˜F«2u“V«6R˜76¬Âˆ7&VFU˜VÁfW&ñfñVEˆ6ˆÁFWáBÇì≤¶#‘6ˆˆ∂ñT¶"Çì≤˜VÊW#◊W&∆∆ñ"Á&WVW7BÊ'Vñ∆Eˆ˜VÊW"áW&∆∆ñ"Á&WVW7B‰ÖEE6ˆˆ∂ñU&ˆ6W76˜"Ü¶"í«W&∆∆ñ"Á&WVW7B‰ÖEE4ÜÊF∆W"Ü6ˆÁFWáC÷6ˆÁFWáBíê¢∆ˆvvVC‘f«6S≤∆7EˆW'&˜#“rp¢f˜"∆ˆvñÂ˜FÇñ‚≤rˆíˆWFÇˆ∆ˆvñ‚r¬rˆíˆ∆ˆvñ‚u”†¢G'ì†¢«#◊W&∆∆ñ"Á&WVW7BÂ&WVW7BÜ&6R∂∆ˆvñÂ˜FÇ∆FF÷ß6ˆ‚ÊGV◊2á≤wW6W&Ê÷RsßW6W&Ê÷R¬w77v˜&Bsß77v˜&G“íÊVÊ6ˆFRÇí∆ÜVFW'3◊≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚r¬uW6W"‘vVÁBs¢ttÙE4UîRÛ„bw“∆÷WFÜˆC“uı5Brì≤˜VÊW"Ê˜V‚Ü«"«Fñ÷V˜WC”íÁ&VBÇì≤∆ˆvvVC’G'VS≤'&V∞¢WÜ6WBWÜ6WFñˆ‚2WÉ¢∆7EˆW'&˜#◊7G"ÜWÇê¢ñbÊ˜B∆ˆvvVC¢&ó6R'VÁFñ÷TW'&˜"ÇuVÊîfí∆ˆvñ‚fñ∆VC¢r∂∆7EˆW'&˜"ê¢ñ∆ˆC÷ß6ˆ‚ÊGV◊2á≤v6÷Bs¢v&∆ˆ6≤◊7Fr¬v÷2sßF&vWBÊ∆˜vW"Çó“íÊVÊ6ˆFRÇì≤6VÁC‘f«6S≤W'&˜'3’µ–¢f˜"FÇñ‚∂br˜&˜áíˆÊWGv˜&≤ˆí˜2˜∑W&∆∆ñ"Á'6RÁV˜FRá6óFRó“ˆ6÷B˜7F÷w"r∆brˆí˜2˜∑W&∆∆ñ"Á'6RÁV˜FRá6óFRó“ˆ6÷B˜7F÷w"u”†¢G'ì†¢'◊W&∆∆ñ"Á&WVW7BÂ&WVW7BÜ&6R∑FÇ∆FF◊ñ∆ˆB∆ÜVFW'3◊≤t6ˆÁFVÁB’GóRs¢v∆ñ6Fñˆ‚ˆß6ˆ‚r¬uW6W"‘vVÁBs¢ttÙE4UîRÛ„bw“∆÷WFÜˆC“uı5Brì≤˜VÊW"Ê˜V‚á'«Fñ÷V˜WC”íÁ&VBÇì≤6VÁC’G'VS≤'&V∞¢WÜ6WBWÜ6WFñˆ‚2WÉ¢W'&˜'2ÊVÊBá7G"ÜWÇíê¢ñbÊ˜B6VÁC¢&ó6R'VÁFñ÷TW'&˜"ÇuVÊîfíV&ÁFñÊR&WVW7Bfñ∆VC¢r≤s≤rÊ¶ˆñ‚ÜW'&˜'2ï≤”#•“ê¢&W7V«C◊≤vˆ≤s•G'VR¬v7Fñˆ‚s¶7Fñˆ‚¬wF&vWBsßF&vWG–¢WÜ6WBWÜ6WFñˆ‚2S¢&W7V«C◊≤vˆ≤s§f«6R¬v7Fñˆ‚s¶7Fñˆ‚¬wF&vWBsßF&vWB¬vW'&˜"sß7G"ÜRó–¢2ÊWÜV7WFRÇuUDDR&V÷VFñFñˆÂˆ7FñˆÁ24UB7FGW3”Ú«&W7V«Eˆß6ˆ„”Ú∆6ˆ◊∆WFVEˆC”ÚtÑU$RñC”Úr¬Çv6ˆ◊∆WFVBrñb&W7V«E≤vˆ≤u“V«6Rvfñ∆VBr∆ß6ˆ‚ÊGV◊2á&W7V«Bí∆Ê˜rÇí«&ñBíì≤VFóBÜ2«W6W%≤wW6W&Ê÷Ru“¬w&V÷VFñFñˆÂÚr∂7Fñˆ‚«F&vWB∆ß6ˆ‚ÊGV◊2á&W7V«Bï≥£“∆6∆ñVÁEˆóá&WVW7Bíì∂2Ê6ˆ÷÷óBÇì∑&WGW&‚&W7V«@†§ÊvWBÜb'∑&˜WFW%˜&Vfóá“˜&V÷VFñFñˆ‚ˆÜó7F˜'í"ê¶FVb&V÷VFñFñˆÂˆÜó7F˜'íÜ∆ñ÷óC¶ñÁC”«W6W#‘FWVÊG2á&WVó&UˆF÷ñ‚íì†¢vóFÇF"Çí23†¢VÁ7W&U˜&ˆGV7FñˆÂ˜66ÜV÷Ü2ì≤&WGW&‚∂Fñ7Bá"íf˜""ñ‚2ÊWÜV7WFRÇu4TƒT5B¢e$Ù“&V÷VFñFñˆÂˆ7FñˆÁ2ı$DU"%íñBDU42ƒî‘ïBÚr¬Ü÷ÇÉ∆÷ñ‚Ü∆ñ÷óB√Síí¬ííÊfWF6Ü∆¬Çï–