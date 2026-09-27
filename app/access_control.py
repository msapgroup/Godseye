"""Sidebar permissions shared by the UI and API boundary."""
import json

PAGES = {
    "overview": "Dashboard", "devices": "Devices", "network": "Network Map",
    "sites": "Sites", "crm": "CRM", "monitoring": "Monitoring",
    "findings": "Findings", "tools": "Tools", "cyber-tools": "Cyber Tools",
    "integrations": "Integrations", "reports": "Reports", "calendar": "Calendar",
    "email": "Email", "event-findings": "Event Findings",
    "remote-access": "Remote Access", "windows-updates": "Windows Updates",
    "windows-agent": "Windows Agent", "antivirus": "Antivirus",
    "tickets": "Ticket Portal", "health": "System Health",
    "rules": "Alert Rules", "audit": "Audit Log", "security": "Settings",
    "about": "About",
}
GROUPS = {
    "Monitoring": ["overview", "devices", "network", "sites", "crm", "monitoring", "findings"],
    "Operations": ["tools", "cyber-tools", "integrations", "reports", "calendar", "email", "event-findings", "remote-access", "windows-updates", "windows-agent", "antivirus", "tickets"],
    "Administration": ["health", "rules", "audit", "security", "about"],
}
API_PREFIXES = (
    ("/sites", "sites"), ("/customers", "crm"),
    ("/crm", "crm"), ("/devices", "devices"),
    ("/network", "network"), ("/topology", "network"),
    ("/scan", "devices"), ("/discovery", "network"),
    ("/intelligence", "findings"), ("/findings", "findings"),
    ("/monitor", "monitoring"), ("/cyber", "cyber-tools"),
    ("/tools", "tools"), ("/integrations", "integrations"),
    ("/reports", "reports"), ("/calendar", "calendar"),
    ("/email", "email"), ("/event-findings", "event-findings"),
    ("/windows-events", "event-findings"),
    ("/windows-agent", "windows-agent"),
    ("/windows-remote", "remote-access"),
    ("/windows-updates", "windows-updates"),
    ("/antivirus", "antivirus"), ("/tickets", "tickets"),
    ("/appliance", "health"), ("/rules", "rules"),
    ("/audit", "audit"), ("/config", "health"),
    ("/traffic", "monitoring"),
)


def page_for_path(path):
    if not path.startswith("/api/v1/"):
        return None
    suffix = path[len("/api/v1"):]
    for prefix, page in API_PREFIXES:
        if suffix == prefix or suffix.startswith(prefix + "/"):
            return page
    return None


def ensure_schema(c):
    c.execute("""CREATE TABLE IF NOT EXISTS role_page_permissions (
        role TEXT NOT NULL, page TEXT NOT NULL, access TEXT NOT NULL,
        PRIMARY KEY(role, page))""")


def default_access(role, page):
    if role == "admin":
        return "full"
    if role == "operator":
        if page in {"rules", "remote-access", "windows-agent"}:
            return "none"
        return "read" if page in {"audit", "security"} else "full"
    if role == "auditor":
        return "none" if page in {"rules", "remote-access", "windows-agent", "security"} else "read"
    if role == "readonly":
        return "none" if page in {"rules", "remote-access", "windows-agent", "security", "cyber-tools"} else "read"
    return "none"


def access(c, role, page):
    if role == "admin":
        return "full"
    row = c.execute("SELECT access FROM role_page_permissions WHERE role=? AND page=?", (role, page)).fetchone()
    return row[0] if row else default_access(role, page)


def matrix(c):
    return {role: {page: access(c, role, page) for page in PAGES}
            for role in ("operator", "auditor", "readonly")}
