from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
import threading
from pathlib import Path

from .appliance_hardening import decrypt_secret
from .discovery_intelligence import unifi_client_observations, normalize_mac

TRAFFIC_MODES = {
    "unifi": "UniFi / Controller",
    "snmp": "SNMP",
    "span": "SPAN / Mirror",
    "inline": "Inline / Gateway",
}

def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def ensure_schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS traffic_collection_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        enabled INTEGER NOT NULL DEFAULT 0,
        mode TEXT NOT NULL DEFAULT 'unifi',
        integration_id INTEGER,
        interface TEXT NOT NULL DEFAULT '',
        sample_interval_seconds INTEGER NOT NULL DEFAULT 30,
        options_json TEXT NOT NULL DEFAULT '{}',
        last_collected_at TEXT,
        last_status TEXT NOT NULL DEFAULT 'disabled',
        last_error TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS device_traffic_samples (
        id INTEGER PRIMARY KEY,
        captured_at TEXT NOT NULL,
        device_id INTEGER,
        mac TEXT NOT NULL DEFAULT '',
        ip TEXT NOT NULL DEFAULT '',
        source_mode TEXT NOT NULL,
        source_ref TEXT NOT NULL DEFAULT '',
        rx_bytes INTEGER NOT NULL DEFAULT 0,
        tx_bytes INTEGER NOT NULL DEFAULT 0,
        rx_delta_bytes INTEGER NOT NULL DEFAULT 0,
        tx_delta_bytes INTEGER NOT NULL DEFAULT 0,
        rx_bps REAL NOT NULL DEFAULT 0,
        tx_bps REAL NOT NULL DEFAULT 0,
        confidence TEXT NOT NULL DEFAULT 'measured',
        details_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_device_traffic_time ON device_traffic_samples(captured_at DESC);
    CREATE INDEX IF NOT EXISTS idx_device_traffic_device ON device_traffic_samples(device_id,captured_at DESC);
    CREATE INDEX IF NOT EXISTS idx_device_traffic_mac ON device_traffic_samples(mac,captured_at DESC);
    CREATE TABLE IF NOT EXISTS traffic_collection_runs (
        id INTEGER PRIMARY KEY,
        mode TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL,
        devices_sampled INTEGER NOT NULL DEFAULT 0,
        error TEXT NOT NULL DEFAULT ''
    );
    """)
    c.execute(
        "INSERT OR IGNORE INTO traffic_collection_settings(id,updated_at) VALUES(1,?)",
        (utcnow(),),
    )
    c.commit()

def get_settings(c):
    ensure_schema(c)
    row = dict(c.execute("SELECT * FROM traffic_collection_settings WHERE id=1").fetchone())
    try:
        row["options"] = json.loads(row.pop("options_json") or "{}")
    except Exception:
        row["options"] = {}
    row["enabled"] = bool(row["enabled"])
    row["mode_label"] = TRAFFIC_MODES.get(row["mode"], row["mode"])
    row["capabilities"] = mode_capabilities(row["mode"])
    return row

def mode_capabilities(mode):
    if mode == "unifi":
        return {
            "collection": "automatic",
            "description": "Reads cumulative client byte counters exposed by the selected UniFi controller.",
            "requires": "An enabled UniFi integration that returns client byte counters.",
        }
    if mode == "snmp":
        return {
            "collection": "profile",
            "description": "Normalizes device counters from SNMP when a device/OID profile is supplied.",
            "requires": "An enabled SNMP integration plus per-device counter OID mappings for the network hardware.",
        }
    if mode == "span":
        return {
            "collection": "sensor",
            "description": "Accepts measured per-device interval counters from a privileged SPAN/mirror sensor.",
            "requires": "A switch mirror/SPAN port connected to the selected Raspberry Pi interface and the traffic sensor.",
        }
    if mode == "inline":
        return {
            "collection": "sensor",
            "description": "Accepts measured per-device interval counters while GODSEYE is positioned inline/gateway.",
            "requires": "Traffic must actually traverse the Raspberry Pi and the privileged traffic sensor must be enabled.",
        }
    return {"collection":"unknown","description":"","requires":""}

def list_interfaces():
    root = Path("/sys/class/net")
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir() if p.name != "lo")

def save_settings(c, values):
    ensure_schema(c)
    mode = str(values.get("mode", "unifi")).lower()
    if mode not in TRAFFIC_MODES:
        raise ValueError("Traffic mode must be unifi, snmp, span, or inline")
    enabled = 1 if values.get("enabled") else 0
    integration_id = values.get("integration_id")
    if integration_id in ("", None):
        integration_id = None
    else:
        integration_id = int(integration_id)
    interface = str(values.get("interface") or "").strip()
    interval = max(10, min(int(values.get("sample_interval_seconds", 30)), 3600))
    options = values.get("options") if isinstance(values.get("options"), dict) else {}
    if mode in ("unifi", "snmp") and integration_id is None:
        raise ValueError(f"{TRAFFIC_MODES[mode]} mode requires an integration")
    if mode in ("span", "inline") and not interface:
        raise ValueError(f"{TRAFFIC_MODES[mode]} mode requires a capture interface")
    if interface and interface not in list_interfaces():
        # Preserve portability for config imports, but reject impossible runtime saves.
        raise ValueError(f"Network interface {interface} is not present")
    if integration_id is not None:
        row = c.execute("SELECT id,kind,enabled FROM integration_configs WHERE id=?", (integration_id,)).fetchone()
        if not row:
            raise ValueError("Selected integration no longer exists")
        expected = "unifi" if mode == "unifi" else "snmp" if mode == "snmp" else None
        if expected and row["kind"] != expected:
            raise ValueError(f"Selected integration must be {expected}")
    c.execute(
        """UPDATE traffic_collection_settings
           SET enabled=?,mode=?,integration_id=?,interface=?,sample_interval_seconds=?,
               options_json=?,last_status=?,last_error='',updated_at=? WHERE id=1""",
        (enabled, mode, integration_id, interface, interval, json.dumps(options),
         "configured" if enabled else "disabled", utcnow()),
    )
    c.commit()
    return get_settings(c)

def _device_for(c, mac, ip):
    mac = normalize_mac(mac) or ""
    if mac:
        row = c.execute("SELECT id FROM devices WHERE lower(mac)=lower(?)", (mac,)).fetchone()
        if row:
            return row["id"], mac
    if ip:
        row = c.execute("SELECT id,mac FROM devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
        if row:
            return row["id"], normalize_mac(row["mac"]) or mac
    return None, mac

def _previous(c, device_id, mac, mode, source_ref):
    if device_id:
        return c.execute(
            """SELECT * FROM device_traffic_samples
               WHERE device_id=? AND source_mode=? AND source_ref=?
               ORDER BY id DESC LIMIT 1""", (device_id, mode, source_ref)
        ).fetchone()
    if mac:
        return c.execute(
            """SELECT * FROM device_traffic_samples
               WHERE mac=? AND source_mode=? AND source_ref=?
               ORDER BY id DESC LIMIT 1""", (mac, mode, source_ref)
        ).fetchone()
    return None

def ingest_samples(c, mode, samples, *, source_ref="", captured_at=None, counter_mode="cumulative",
                   confidence="measured"):
    """Normalize collector/sensor data into the per-device traffic store.

    cumulative: rx_bytes/tx_bytes are monotonic source counters; deltas are derived.
    delta: rx_bytes/tx_bytes are bytes observed during this interval.
    """
    ensure_schema(c)
    if mode not in TRAFFIC_MODES:
        raise ValueError("Unsupported traffic source")
    stamp = captured_at or utcnow()
    inserted = 0
    for item in samples or []:
        mac = normalize_mac(item.get("mac")) or ""
        ip = str(item.get("ip") or "")
        device_id, mac = _device_for(c, mac, ip)
        if device_id is None and not mac and not ip:
            continue
        rx = max(0, int(item.get("rx_bytes") or 0))
        tx = max(0, int(item.get("tx_bytes") or 0))
        prev = _previous(c, device_id, mac, mode, source_ref)
        rx_delta = tx_delta = 0
        elapsed = 0.0
        if counter_mode == "delta":
            rx_delta, tx_delta = rx, tx
            if item.get("interval_seconds"):
                elapsed = max(0.001, float(item["interval_seconds"]))
        elif prev:
            # Counter resets/wraps do not create negative traffic.
            rx_delta = max(0, rx - int(prev["rx_bytes"]))
            tx_delta = max(0, tx - int(prev["tx_bytes"]))
            try:
                elapsed = max(
                    0.001,
                    (dt.datetime.fromisoformat(stamp) - dt.datetime.fromisoformat(prev["captured_at"])).total_seconds(),
                )
            except Exception:
                elapsed = 0.0
        rx_bps = (rx_delta * 8 / elapsed) if elapsed else float(item.get("rx_bps") or 0)
        tx_bps = (tx_delta * 8 / elapsed) if elapsed else float(item.get("tx_bps") or 0)
        c.execute(
            """INSERT INTO device_traffic_samples(
                 captured_at,device_id,mac,ip,source_mode,source_ref,
                 rx_bytes,tx_bytes,rx_delta_bytes,tx_delta_bytes,rx_bps,tx_bps,confidence,details_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                stamp, device_id, mac, ip, mode, source_ref,
                rx, tx, rx_delta, tx_delta, rx_bps, tx_bps,
                str(item.get("confidence") or confidence),
                json.dumps(item.get("details") or {})[:10000],
            ),
        )
        inserted += 1
    c.commit()
    return inserted

def _pick_counter(row, names):
    for name in names:
        value = row.get(name)
        if value is None:
            continue
        try:
            return max(0, int(float(value)))
        except (TypeError, ValueError):
            continue
    return None

def collect_unifi(c, cfg):
    try:
        opts = json.loads(cfg.get("options_json") or "{}")
    except Exception:
        opts = {}
    result = unifi_client_observations(
        cfg["target"], cfg.get("username") or "", decrypt_secret(cfg.get("secret") or ""),
        bool(cfg.get("verify_tls")), opts.get("site", "default")
    )
    if not result.get("ok"):
        raise RuntimeError(result.get("error") or "UniFi client collection failed")
    samples = []
    missing = 0
    for observation in result.get("observations") or []:
        raw = observation.get("details") or {}
        # UniFi controller generations use several names for the same cumulative counters.
        rx = _pick_counter(raw, ("rx_bytes", "bytes-r", "rx_bytes-r", "down", "download_bytes"))
        tx = _pick_counter(raw, ("tx_bytes", "bytes-s", "tx_bytes-r", "up", "upload_bytes"))
        if rx is None or tx is None:
            missing += 1
            continue
        samples.append({
            "mac": observation.get("mac"), "ip": observation.get("ip"),
            "rx_bytes": rx, "tx_bytes": tx, "confidence": "controller",
            "details": {"controller_endpoint": result.get("endpoint"), "counter_source": "unifi-client"},
        })
    count = ingest_samples(c, "unifi", samples, source_ref=str(cfg["id"]), counter_mode="cumulative",
                           confidence="controller")
    note = ""
    if not count and result.get("observations"):
        note = "Controller returned clients but no recognized byte-counter fields."
    elif missing:
        note = f"{missing} client(s) did not expose recognized byte counters."
    return {"status": "success" if count or not result.get("observations") else "partial",
            "devices_sampled": count, "note": note}

def _snmp_value(host, community, oid):
    binary = shutil.which("snmpget")
    if not binary:
        raise RuntimeError("snmpget is not installed")
    cp = subprocess.run(
        [binary, "-v2c", "-c", community, "-Oqv", host, oid],
        capture_output=True, text=True, timeout=8,
    )
    if cp.returncode:
        raise RuntimeError(cp.stderr.strip() or "snmpget failed")
    m = __import__("re").search(r"(-?\d+)", cp.stdout)
    if not m:
        raise RuntimeError(f"Non-numeric SNMP counter returned for {oid}")
    return max(0, int(m.group(1)))

def collect_snmp(c, cfg):
    try:
        opts = json.loads(cfg.get("options_json") or "{}")
    except Exception:
        opts = {}
    mappings = opts.get("traffic_oids") or []
    if not isinstance(mappings, list) or not mappings:
        return {
            "status": "waiting_profile", "devices_sampled": 0,
            "note": "SNMP has no universal per-client byte table. Add device traffic_oids mappings to this SNMP integration profile.",
        }
    community = decrypt_secret(cfg.get("secret") or "") or "public"
    samples = []
    errors = []
    for item in mappings[:256]:
        if not isinstance(item, dict) or not item.get("rx_oid") or not item.get("tx_oid"):
            continue
        try:
            samples.append({
                "mac": item.get("mac"), "ip": item.get("ip"),
                "rx_bytes": _snmp_value(cfg["target"], community, item["rx_oid"]),
                "tx_bytes": _snmp_value(cfg["target"], community, item["tx_oid"]),
                "confidence": "snmp-profile",
                "details": {"rx_oid": item["rx_oid"], "tx_oid": item["tx_oid"]},
            })
        except Exception as exc:
            errors.append(str(exc))
    count = ingest_samples(c, "snmp", samples, source_ref=str(cfg["id"]), counter_mode="cumulative",
                           confidence="snmp-profile")
    return {
        "status": "success" if count and not errors else "partial" if count else "failed",
        "devices_sampled": count,
        "note": "; ".join(errors[:3]),
    }

def collect_once(c):
    ensure_schema(c)
    settings = get_settings(c)
    if not settings["enabled"]:
        return {"status": "disabled", "devices_sampled": 0, "mode": settings["mode"]}
    mode = settings["mode"]
    started = utcnow()
    run_id = c.execute(
        "INSERT INTO traffic_collection_runs(mode,started_at,status) VALUES(?,?,?)",
        (mode, started, "running"),
    ).lastrowid
    c.commit()
    try:
        if mode in ("unifi", "snmp"):
            cfg = c.execute("SELECT * FROM integration_configs WHERE id=?", (settings["integration_id"],)).fetchone()
            if not cfg:
                raise RuntimeError("Selected integration no longer exists")
            cfg = dict(cfg)
            result = collect_unifi(c, cfg) if mode == "unifi" else collect_snmp(c, cfg)
        else:
            # SPAN/inline packet capture runs in the privileged sensor process.  The
            # normalized database/API is ready now; web service itself never gains
            # raw-packet privileges.
            result = {
                "status": "awaiting_sensor",
                "devices_sampled": 0,
                "note": f"{TRAFFIC_MODES[mode]} is configured on {settings['interface']}; awaiting privileged sensor samples.",
            }
        completed = utcnow()
        c.execute(
            "UPDATE traffic_collection_runs SET completed_at=?,status=?,devices_sampled=?,error=? WHERE id=?",
            (completed, result["status"], result.get("devices_sampled", 0), result.get("note", ""), run_id),
        )
        c.execute(
            """UPDATE traffic_collection_settings
               SET last_collected_at=?,last_status=?,last_error=?,updated_at=? WHERE id=1""",
            (completed, result["status"], result.get("note", ""), completed),
        )
        c.commit()
        return {"mode": mode, **result, "completed_at": completed}
    except Exception as exc:
        completed = utcnow()
        error = str(exc)
        c.execute(
            "UPDATE traffic_collection_runs SET completed_at=?,status='failed',error=? WHERE id=?",
            (completed, error, run_id),
        )
        c.execute(
            """UPDATE traffic_collection_settings
               SET last_collected_at=?,last_status='failed',last_error=?,updated_at=? WHERE id=1""",
            (completed, error, completed),
        )
        c.commit()
        return {"mode": mode, "status": "failed", "devices_sampled": 0, "error": error, "completed_at": completed}

def device_usage(c, hours=24, limit=100):
    ensure_schema(c)
    hours = max(1, min(int(hours), 24 * 90))
    limit = max(1, min(int(limit), 500))
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).isoformat()
    rows = c.execute(
        """SELECT
             COALESCE(s.device_id,0) device_id,
             COALESCE(NULLIF(d.name,''),NULLIF(d.hostname,''),NULLIF(s.ip,''),NULLIF(s.mac,''),'Unknown') label,
             MAX(s.mac) mac, MAX(s.ip) ip, MAX(s.source_mode) source_mode,
             MAX(s.confidence) confidence, MAX(s.captured_at) last_sample,
             SUM(s.rx_delta_bytes) rx_bytes, SUM(s.tx_delta_bytes) tx_bytes,
             MAX(s.rx_bps) peak_rx_bps, MAX(s.tx_bps) peak_tx_bps
           FROM device_traffic_samples s
           LEFT JOIN devices d ON d.id=s.device_id
           WHERE s.captured_at>=?
           GROUP BY COALESCE(s.device_id,-s.id)
           ORDER BY (SUM(s.rx_delta_bytes)+SUM(s.tx_delta_bytes)) DESC
           LIMIT ?""",
        (cutoff, limit),
    ).fetchall()
    items = [dict(r) for r in rows]
    return {
        "hours": hours,
        "devices": items,
        "total_rx_bytes": sum(int(r["rx_bytes"] or 0) for r in items),
        "total_tx_bytes": sum(int(r["tx_bytes"] or 0) for r in items),
        "mode": get_settings(c),
    }

class TrafficIntelligenceCollector:
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, name="godseye-device-traffic", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)

    def _loop(self):
        while not self.stop_event.is_set():
            wait_for = 30
            try:
                with self.db_factory() as c:
                    cfg = get_settings(c)
                    wait_for = max(10, int(cfg.get("sample_interval_seconds") or 30))
                    if cfg["enabled"] and cfg["mode"] in ("unifi", "snmp"):
                        collect_once(c)
            except Exception as exc:
                print("[GODSEYE] device traffic collector:", exc)
            self.stop_event.wait(wait_for)
