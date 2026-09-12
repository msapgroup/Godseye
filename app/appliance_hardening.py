from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


DATA_DIR = Path(os.environ.get("GODSEYE_DATA_DIR", "/var/lib/godseye"))
KEY_PATH = Path(os.environ.get("GODSEYE_SECRET_KEY_FILE", str(DATA_DIR / "secret.key")))
BACKUP_DIR = Path(os.environ.get("GODSEYE_BACKUP_DIR", str(DATA_DIR / "backups")))


def ensure_schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS appliance_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        traffic_retention_days INTEGER NOT NULL DEFAULT 7,
        event_retention_days INTEGER NOT NULL DEFAULT 90,
        audit_retention_days INTEGER NOT NULL DEFAULT 365,
        report_retention_days INTEGER NOT NULL DEFAULT 365,
        sync_retention_days INTEGER NOT NULL DEFAULT 90,
        notification_retention_days INTEGER NOT NULL DEFAULT 90,
        prometheus_key_hash TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS traffic_samples (
        id INTEGER PRIMARY KEY,
        captured_at TEXT NOT NULL,
        interface TEXT NOT NULL,
        rx_bytes INTEGER NOT NULL,
        tx_bytes INTEGER NOT NULL,
        rx_bps REAL NOT NULL DEFAULT 0,
        tx_bps REAL NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_traffic_captured ON traffic_samples(captured_at DESC);
    CREATE TABLE IF NOT EXISTS backup_runs (
        id INTEGER PRIMARY KEY,
        filename TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'complete',
        note TEXT NOT NULL DEFAULT ''
    );
    """)
    c.execute("INSERT OR IGNORE INTO appliance_settings(id,updated_at) VALUES(1,?)", (utcnow(),))


def _ensure_key() -> bytes:
    env_key = os.environ.get("GODSEYE_SECRET_KEY", "").strip()
    if env_key:
        return env_key.encode()
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        key = KEY_PATH.read_bytes().strip()
        Fernet(key)  # validate
        return key
    key = Fernet.generate_key()
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key + b"\n")
    finally:
        os.close(fd)
    return key


def encrypt_secret(value: str | None) -> str:
    if not value:
        return ""
    if value.startswith("enc:v1:"):
        return value
    token = Fernet(_ensure_key()).encrypt(value.encode()).decode()
    return "enc:v1:" + token


def decrypt_secret(value: str | None) -> str:
    if not value:
        return ""
    if not value.startswith("enc:v1:"):
        return value
    try:
        return Fernet(_ensure_key()).decrypt(value[7:].encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Encrypted credential cannot be decrypted with this appliance key") from exc


def migrate_plaintext_secrets(c):
    """Encrypt legacy v14 secrets in-place. Safe to call repeatedly."""
    changed = 0
    try:
        rows = c.execute("SELECT id,secret FROM integration_configs WHERE secret<>''").fetchall()
        for r in rows:
            if not r["secret"].startswith("enc:v1:"):
                c.execute("UPDATE integration_configs SET secret=? WHERE id=?", (encrypt_secret(r["secret"]), r["id"]))
                changed += 1
        row = c.execute("SELECT smtp_password FROM notification_configs WHERE id=1").fetchone()
        if row and row["smtp_password"] and not row["smtp_password"].startswith("enc:v1:"):
            c.execute("UPDATE notification_configs SET smtp_password=? WHERE id=1", (encrypt_secret(row["smtp_password"]),))
            changed += 1
        if changed:
            c.commit()
    except sqlite3.OperationalError:
        pass
    return changed


def default_interface():
    try:
        p = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
        parts = p.stdout.strip().split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def read_interface_bytes(interface: str):
    for line in Path("/proc/net/dev").read_text().splitlines():
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        if name.strip() == interface:
            cols = data.split()
            return int(cols[0]), int(cols[8])
    raise RuntimeError(f"Interface {interface} not present in /proc/net/dev")


class TrafficCollector:
    def __init__(self, db_factory, interval=10):
        self.db_factory = db_factory
        self.interval = max(5, int(interval))
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="godseye-traffic", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def sample_once(self):
        interface = default_interface()
        rx, tx = read_interface_bytes(interface)
        stamp = utcnow()
        with self.db_factory() as c:
            ensure_schema(c)
            prev = c.execute("SELECT captured_at,rx_bytes,tx_bytes FROM traffic_samples WHERE interface=? ORDER BY id DESC LIMIT 1", (interface,)).fetchone()
            rx_bps = tx_bps = 0.0
            if prev:
                try:
                    elapsed = max(0.001, (dt.datetime.fromisoformat(stamp) - dt.datetime.fromisoformat(prev["captured_at"])).total_seconds())
                    rx_bps = max(0.0, (rx - prev["rx_bytes"]) * 8 / elapsed)
                    tx_bps = max(0.0, (tx - prev["tx_bytes"]) * 8 / elapsed)
                except Exception:
                    pass
            c.execute("INSERT INTO traffic_samples(captured_at,interface,rx_bytes,tx_bytes,rx_bps,tx_bps) VALUES(?,?,?,?,?,?)", (stamp, interface, rx, tx, rx_bps, tx_bps))
            c.commit()
        return {"captured_at": stamp, "interface": interface, "rx_bps": rx_bps, "tx_bps": tx_bps}

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.sample_once()
            except Exception as exc:
                print("[GODSEYE] traffic collector:", exc)
            self._stop.wait(self.interval)


def traffic_history(c, minutes=60, limit=360):
    ensure_schema(c)
    minutes = max(1, min(int(minutes), 24 * 60))
    limit = max(2, min(int(limit), 2000))
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)).isoformat()
    return [dict(r) for r in c.execute("SELECT captured_at,interface,rx_bps,tx_bps FROM traffic_samples WHERE captured_at>=? ORDER BY id ASC LIMIT ?", (cutoff, limit))]


def client_bandwidth_estimates(c, limit=12):
    """Best available client activity chart from observed evidence.

    GODSEYE does not pretend per-client byte counters exist when the underlying
    integration did not provide them. Prefer UniFi/Pi-hole numeric analytics;
    otherwise return recent-event activity counts and label the metric clearly.
    """
    rows = c.execute("""SELECT d.id,COALESCE(NULLIF(d.name,''),NULLIF(d.hostname,''),d.ip,d.mac) label,
                       d.ip,d.mac,COUNT(e.id) activity_events
                       FROM devices d LEFT JOIN events e ON (e.mac=d.mac OR (e.ip=d.ip AND d.ip<>''))
                       GROUP BY d.id ORDER BY activity_events DESC,d.last_seen DESC LIMIT ?""", (max(1, min(int(limit), 50)),)).fetchall()
    return {"metric": "observed_activity_events", "note": "Per-device byte counters require a controller/integration that exposes them.", "clients": [dict(r) for r in rows]}


def generate_prometheus_key(c):
    ensure_schema(c)
    raw = "gse_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    c.execute("UPDATE appliance_settings SET prometheus_key_hash=?,updated_at=? WHERE id=1", (digest, utcnow()))
    c.commit()
    return raw


def verify_prometheus_key(c, key: str | None):
    ensure_schema(c)
    row = c.execute("SELECT prometheus_key_hash FROM appliance_settings WHERE id=1").fetchone()
    stored = row["prometheus_key_hash"] if row else ""
    if not stored or not key:
        return False
    return secrets.compare_digest(stored, hashlib.sha256(key.encode()).hexdigest())


def retention_config(c):
    ensure_schema(c)
    return dict(c.execute("SELECT * FROM appliance_settings WHERE id=1").fetchone())


def save_retention(c, values):
    ensure_schema(c)
    allowed = ["traffic_retention_days", "event_retention_days", "audit_retention_days", "report_retention_days", "sync_retention_days", "notification_retention_days"]
    cleaned = {k: max(1, min(int(values[k]), 3650)) for k in allowed if k in values}
    if cleaned:
        assignments = ",".join(f"{k}=?" for k in cleaned)
        c.execute(f"UPDATE appliance_settings SET {assignments},updated_at=? WHERE id=1", (*cleaned.values(), utcnow()))
        c.commit()
    return retention_config(c)


def apply_retention(c):
    cfg = retention_config(c)
    now_dt = dt.datetime.now(dt.timezone.utc)
    rules = [
        ("traffic_samples", "captured_at", cfg["traffic_retention_days"]),
        ("device_traffic_samples", "captured_at", cfg["traffic_retention_days"]),
        ("traffic_collection_runs", "started_at", cfg["traffic_retention_days"]),
        ("events", "created_at", cfg["event_retention_days"]),
        ("audit_log", "created_at", cfg["audit_retention_days"]),
        ("generated_reports", "generated_at", cfg["report_retention_days"]),
        ("integration_sync_runs", "started_at", cfg["sync_retention_days"]),
        ("analytics_snapshots", "captured_at", cfg["sync_retention_days"]),
        ("notification_deliveries", "created_at", cfg["notification_retention_days"]),
    ]
    deleted = {}
    for table, column, days in rules:
        cutoff = (now_dt - dt.timedelta(days=days)).isoformat()
        try:
            cur = c.execute(f"DELETE FROM {table} WHERE {column}<?", (cutoff,))
            deleted[table] = cur.rowcount
        except sqlite3.OperationalError:
            deleted[table] = 0
    c.commit()
    return deleted


def create_backup(db_path: Path, note=""):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = BACKUP_DIR / f"godseye-{stamp}.db"
    src = sqlite3.connect(str(db_path))
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
            chk = dst.execute("PRAGMA integrity_check").fetchone()[0]
            if chk != "ok":
                raise RuntimeError(f"Backup integrity check failed: {chk}")
        finally:
            dst.close()
    finally:
        src.close()
    os.chmod(dest, 0o600)
    # Preserve the appliance encryption key beside the DB so an encrypted
    # backup can be restored onto replacement hardware. Both files remain
    # root/service-directory protected and mode 0600.
    if KEY_PATH.exists():
        sidecar=BACKUP_DIR/(dest.name+'.key')
        shutil.copy2(KEY_PATH,sidecar); os.chmod(sidecar,0o600)
    return dest


def list_backups(c):
    ensure_schema(c)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    known = {r["filename"] for r in c.execute("SELECT filename FROM backup_runs")}
    for p in BACKUP_DIR.glob("godseye-*.db"):
        if p.name not in known:
            c.execute("INSERT OR IGNORE INTO backup_runs(filename,created_at,size_bytes,status,note) VALUES(?,?,?,?,?)", (p.name, dt.datetime.fromtimestamp(p.stat().st_mtime, dt.timezone.utc).isoformat(), p.stat().st_size, "complete", "discovered on disk"))
    c.commit()
    return [dict(r) for r in c.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 100")]


def restore_backup(db_path: Path, filename: str):
    if Path(filename).name != filename or not filename.startswith("godseye-") or not filename.endswith(".db"):
        raise ValueError("Invalid backup filename")
    src_path = BACKUP_DIR / filename
    if not src_path.exists():
        raise FileNotFoundError(filename)
    key_sidecar=BACKUP_DIR/(filename+'.key')
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
    try:
        chk = src.execute("PRAGMA integrity_check").fetchone()[0]
        if chk != "ok":
            raise RuntimeError(f"Backup integrity check failed: {chk}")
        dst = sqlite3.connect(str(db_path), timeout=30)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    if key_sidecar.exists():
        KEY_PATH.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(key_sidecar,KEY_PATH); os.chmod(KEY_PATH,0o600)
    return {"ok": True, "filename": filename, "encryption_key_restored": key_sidecar.exists()}


def _read_meminfo():
    data = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            try:
                data[k] = int(v.strip().split()[0]) * 1024
            except Exception:
                pass
    return data


def appliance_health(db_path: Path):
    checks = []
    def add(name, status, detail, value=None):
        checks.append({"name": name, "status": status, "detail": detail, "value": value})
    try:
        load1, load5, load15 = os.getloadavg()
        cpus = os.cpu_count() or 1
        add("CPU load", "ok" if load1 < cpus * 1.5 else "warning", f"1m {load1:.2f} · 5m {load5:.2f} · 15m {load15:.2f}", load1)
    except Exception as exc: add("CPU load", "unknown", str(exc))
    temp_path = Path("/sys/class/thermal/thermal_zone0/temp")
    if temp_path.exists():
        try:
            temp = int(temp_path.read_text().strip()) / 1000
            add("CPU temperature", "ok" if temp < 75 else "warning" if temp < 85 else "critical", f"{temp:.1f} °C", temp)
        except Exception as exc: add("CPU temperature", "unknown", str(exc))
    else: add("CPU temperature", "unknown", "Thermal sensor not exposed on this host")
    try:
        mem = _read_meminfo(); total = mem.get("MemTotal", 0); avail = mem.get("MemAvailable", 0); used_pct = 100 * (1 - avail / total) if total else 0
        add("Memory", "ok" if used_pct < 85 else "warning" if used_pct < 95 else "critical", f"{used_pct:.1f}% used", used_pct)
    except Exception as exc: add("Memory", "unknown", str(exc))
    try:
        usage = shutil.disk_usage(DATA_DIR if DATA_DIR.exists() else db_path.parent); used_pct = usage.used / usage.total * 100
        add("Data disk", "ok" if used_pct < 85 else "warning" if used_pct < 95 else "critical", f"{used_pct:.1f}% used · {usage.free/1024**3:.1f} GiB free", used_pct)
    except Exception as exc: add("Data disk", "unknown", str(exc))
    try:
        c = sqlite3.connect(str(db_path)); chk = c.execute("PRAGMA quick_check").fetchone()[0]; c.close()
        add("Database", "ok" if chk == "ok" else "critical", chk)
    except Exception as exc: add("Database", "critical", str(exc))
    for service in ("godseye-web.service", "godseye-scanner.service"):
        try:
            p = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, timeout=3)
            state = p.stdout.strip() or p.stderr.strip() or "unknown"
            add(service.replace(".service", ""), "ok" if state == "active" else "warning", state)
        except Exception as exc: add(service.replace(".service", ""), "unknown", str(exc))
    try:
        iface = default_interface(); rx, tx = read_interface_bytes(iface)
        add("Network interface", "ok", f"{iface} · RX {rx/1024**2:.1f} MiB · TX {tx/1024**2:.1f} MiB")
    except Exception as exc: add("Network interface", "critical", str(exc))
    overall = "critical" if any(x["status"] == "critical" for x in checks) else "warning" if any(x["status"] in {"warning", "unknown"} for x in checks) else "ok"
    return {"overall": overall, "checked_at": utcnow(), "hostname": os.uname().nodename, "kernel": os.uname().release, "checks": checks}


def report_csv_bytes(report):
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["GODSEYE Network Report", report.get("title", "")])
    w.writerow(["Generated", report.get("generated_at", "")]); w.writerow([])
    w.writerow(["Metric", "Value"])
    for k, v in (report.get("summary") or {}).items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v, separators=(",", ":"))
        w.writerow([k, v])
    return out.getvalue().encode("utf-8-sig")


def report_pdf_bytes(report):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    buf = io.BytesIO(); pdf = canvas.Canvas(buf, pagesize=letter)
    width, height = letter; y = height - 54
    pdf.setTitle(report.get("title") or "GODSEYE Network Report")
    pdf.setFont("Helvetica-Bold", 16); pdf.drawString(54, y, report.get("title") or "GODSEYE Network Report"); y -= 24
    pdf.setFont("Helvetica", 9); pdf.drawString(54, y, "Generated: " + str(report.get("generated_at", ""))); y -= 22
    pdf.setFont("Helvetica-Bold", 11); pdf.drawString(54, y, "Network summary"); y -= 18
    pdf.setFont("Helvetica", 9)
    for k, v in (report.get("summary") or {}).items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v, separators=(",", ":"))
        line = f"{k.replace('_',' ').title()}: {v}"
        while len(line) > 100:
            pdf.drawString(64, y, line[:100]); line = line[100:]; y -= 13
        pdf.drawString(64, y, line); y -= 13
        if y < 60:
            pdf.showPage(); y = height - 54; pdf.setFont("Helvetica", 9)
    pdf.save(); return buf.getvalue()
