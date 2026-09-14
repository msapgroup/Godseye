"""Device-centric intelligence helpers for GODSEYE.

This module deliberately keeps the intelligence deterministic and explainable.
It summarizes existing scanner, event, source, IP-history, and issue evidence
without inventing facts that are not present in the database.
"""
from __future__ import annotations

import datetime as dt
import json


def _parse_iso(value: str | None):
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value)
    except Exception:
        return None


def _loads(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _severity_weight(severity: str | None) -> int:
    sev = (severity or "info").lower()
    return {"critical": 35, "high": 30, "warning": 20, "medium": 18, "low": 8, "info": 3}.get(sev, 5)


def build_device_intelligence(c, device_id: int) -> dict | None:
    device = c.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not device:
        return None
    d = dict(device)
    mac = (d.get("mac") or "").lower()
    ip = d.get("ip")

    events = [dict(r) for r in c.execute(
        "SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT 100", (mac,)
    )]
    sources = [dict(r) for r in c.execute(
        "SELECT * FROM device_sources WHERE mac=? ORDER BY last_seen DESC", (mac,)
    )]
    ip_history = [dict(r) for r in c.execute(
        "SELECT * FROM device_ip_history WHERE mac=? ORDER BY last_seen DESC", (mac,)
    )]
    issues = [dict(r) for r in c.execute(
        "SELECT * FROM network_issues WHERE target IN (?,?) ORDER BY last_seen DESC LIMIT 100",
        (mac, ip or ""),
    )]

    open_issues = [x for x in issues if x.get("status") == "open"]
    risk = sum(_severity_weight(x.get("severity")) for x in open_issues)
    if d.get("status") == "offline":
        risk += 30
    elif d.get("status") == "suspected_offline":
        risk += 15
    if d.get("classification") == "investigate":
        risk += 20
    elif d.get("classification") == "new":
        risk += 8
    risk = min(100, risk)

    source_names = sorted({x.get("source") for x in sources if x.get("source")})
    if not source_names:
        source_names = ["inventory"]

    recommendations = []
    if d.get("status") == "offline":
        recommendations.append("Run Recheck to confirm reachability, then verify device power, Wi-Fi/Ethernet link, and DHCP state.")
    elif d.get("status") == "suspected_offline":
        recommendations.append("The device missed recent discovery cycles. Recheck it before treating it as offline.")
    if d.get("classification") in {"new", "investigate"}:
        recommendations.append("Review the device identity, vendor, and expected ownership before marking it Known.")
    if len({x.get("ip") for x in ip_history if x.get("ip")}) > 1:
        recommendations.append("This device has used multiple IP addresses. Consider a DHCP reservation if a stable address is important.")
    if not d.get("hostname"):
        recommendations.append("Hostname is unknown. Run Device Info or DNS Lookup to attempt local name enrichment.")
    if open_issues:
        recommendations.append("Review the open findings below and re-run diagnostics after remediation.")
    if not recommendations:
        recommendations.append("No immediate device-specific action is required. Continue normal monitoring.")

    first_seen = _parse_iso(d.get("first_seen"))
    last_seen = _parse_iso(d.get("last_seen"))
    now = dt.datetime.now(dt.timezone.utc)
    age_days = None
    seconds_since_seen = None
    if first_seen:
        age_days = max(0, int((now - first_seen).total_seconds() // 86400))
    if last_seen:
        seconds_since_seen = max(0, int((now - last_seen).total_seconds()))

    event_counts = {}
    for event in events:
        kind = event.get("event_type") or "unknown"
        event_counts[kind] = event_counts.get(kind, 0) + 1

    return {
        "device": d,
        "summary": {
            "risk_score": risk,
            "open_issue_count": len(open_issues),
            "source_count": len(source_names),
            "sources": source_names,
            "known_ip_count": len({x.get("ip") for x in ip_history if x.get("ip")}) or (1 if ip else 0),
            "event_count": len(events),
            "age_days": age_days,
            "seconds_since_seen": seconds_since_seen,
        },
        "events": events,
        "event_counts": event_counts,
        "sources": sources,
        "ip_history": ip_history,
        "issues": issues,
        "recommendations": recommendations,
        "actions": {
            "diagnose": bool(ip),
            "recheck": bool(ip),
            "port_scan": bool(ip),
            "wake_on_lan": bool(mac),
        },
    }
