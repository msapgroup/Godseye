#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "GODSEYE installer failed at line $LINENO. Command: $BASH_COMMAND"; exit 1' ERR

APP_USER="godseye"
APP_GROUP="godseye"
INSTALL_DIR="/opt/godseye"
DATA_DIR="/var/lib/godseye"
ENV_FILE="/etc/godseye.env"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$DATA_DIR/install-backups"
MODE="auto"

usage() {
  cat <<'USAGE'
GODSEYE installer / upgrader

Usage:
  sudo ./install.sh              Auto-detect fresh install or in-place upgrade
  sudo ./install.sh --upgrade    Require an existing GODSEYE install, then upgrade it
  sudo ./install.sh --fresh      Require no existing GODSEYE install, then install it
  sudo ./install.sh --doctor     Show install/service diagnostics

Upgrades preserve /var/lib/godseye, /etc/godseye.env, TLS material, backups,
and the existing SQLite database. A pre-upgrade SQLite backup is created.
USAGE
}

case "${1:-}" in
  "") ;;
  --upgrade) MODE="upgrade" ;;
  --fresh) MODE="fresh" ;;
  --doctor)
    echo "GODSEYE installer diagnostics"
    command -v python3 || true
    python3 --version || true
    echo "Installed version: $(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo 'not installed')"
    echo "Release version:   $(cat "$SRC_DIR/VERSION" 2>/dev/null || echo 'unknown')"
    ls -ld "$INSTALL_DIR" 2>/dev/null || true
    ls -ld "$DATA_DIR" 2>/dev/null || true
    ls -l "$DATA_DIR/godseye.db" 2>/dev/null || true
    cat "$ENV_FILE" 2>/dev/null || true
    echo "--- tool availability ---"
    for bin in arp-scan nmap ip ping dig avahi-browse nbtscan snmpget snmpwalk traceroute sqlite3 wakeonlan mosquitto_pub curl jq; do
      if command -v "$bin" >/dev/null 2>&1; then echo "OK   $bin -> $(command -v "$bin")"; else echo "MISS $bin"; fi
    done
    systemctl --no-pager --full status godseye-web.service 2>/dev/null || true
    systemctl --no-pager --full status godseye-scanner.service 2>/dev/null || true
    exit 0
    ;;
  -h|--help) usage; exit 0 ;;
  *) echo "Unknown option: $1"; usage; exit 2 ;;
esac

[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
[[ -f "$SRC_DIR/app/main.py" && -f "$SRC_DIR/requirements.txt" && -f "$SRC_DIR/VERSION" ]] || {
  echo "This does not look like a complete GODSEYE release directory."; exit 1;
}

EXISTING=0
if [[ -f "$INSTALL_DIR/VERSION" || -f /etc/systemd/system/godseye-web.service || -f "$DATA_DIR/godseye.db" ]]; then
  EXISTING=1
fi
if [[ "$MODE" == "upgrade" && $EXISTING -eq 0 ]]; then
  echo "--upgrade was requested, but no existing GODSEYE installation was found."; exit 1
fi
if [[ "$MODE" == "fresh" && $EXISTING -eq 1 ]]; then
  echo "--fresh was requested, but an existing GODSEYE installation was found. Use --upgrade or no flag."; exit 1
fi

if [[ $EXISTING -eq 1 ]]; then
  echo "GODSEYE existing installation detected — performing in-place upgrade."
  echo "Installed: $(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo 'unknown')"
  echo "Target:    $(cat "$SRC_DIR/VERSION")"
else
  echo "No existing GODSEYE installation detected — performing full install."
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-venv python3-pip ca-certificates \
  iproute2 iputils-ping nmap arp-scan dnsutils avahi-utils avahi-daemon nbtscan \
  snmp wakeonlan traceroute curl jq sqlite3 net-tools ethtool iw wireless-tools mosquitto-clients nginx openssl certbot python3-certbot-nginx rsync unzip sudo

for bin in python3 ip ping nmap arp-scan dig traceroute avahi-browse nbtscan snmpget snmpwalk sqlite3 rsync; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Required program missing after install: $bin"; exit 1; }
done

getent group "$APP_GROUP" >/dev/null 2>&1 || groupadd --system "$APP_GROUP"
id "$APP_USER" >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin -g "$APP_GROUP" "$APP_USER"
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$BACKUP_DIR"

# On upgrade, stop services and create a database + version snapshot first.
if [[ $EXISTING -eq 1 ]]; then
  systemctl stop godseye-web.service 2>/dev/null || true
  systemctl stop godseye-scanner.service 2>/dev/null || true
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  oldver="$(tr -cs 'A-Za-z0-9._-' '_' < "$INSTALL_DIR/VERSION" 2>/dev/null || echo unknown)"
  if [[ -f "$DATA_DIR/godseye.db" ]]; then
    sqlite3 "$DATA_DIR/godseye.db" ".backup '$BACKUP_DIR/godseye-pre-upgrade-${stamp}.db'"
    cp -a "$DATA_DIR/secret.key" "$BACKUP_DIR/secret.key-${stamp}" 2>/dev/null || true
  fi
  cp -a "$INSTALL_DIR/VERSION" "$BACKUP_DIR/VERSION-${oldver}-${stamp}" 2>/dev/null || true
fi

# Deploy application code without touching persistent data. If install.sh is being
# run from /opt/godseye itself, the source is already in place and rsync is skipped.
if [[ "$(readlink -f "$SRC_DIR")" != "$(readlink -f "$INSTALL_DIR")" ]]; then
  rsync -a --delete \
    --exclude '.venv/' \
    --exclude '__pycache__/' \
    --exclude '.pytest_cache/' \
    --exclude '.git/' \
    "$SRC_DIR/" "$INSTALL_DIR/"
fi
rm -rf "$INSTALL_DIR/__pycache__" "$INSTALL_DIR/app/__pycache__" "$INSTALL_DIR/.pytest_cache"

# Rebuild the isolated Python environment to make upgrades deterministic.
rm -rf "$INSTALL_DIR/.venv"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Persistent runtime data belongs to the service account. Application code is
# readable by the service but remains owned by root after deployment.
chown -R "$APP_USER:$APP_GROUP" "$DATA_DIR"
chmod 750 "$DATA_DIR"
chown -R root:"$APP_GROUP" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
find "$INSTALL_DIR" -type d -exec chmod 750 {} +
chmod 750 "$INSTALL_DIR/install.sh" "$INSTALL_DIR/godseye-apply-update" "$INSTALL_DIR/godseye-https-setup" "$INSTALL_DIR/godseye-release-audit" 2>/dev/null || true

# Preserve an existing environment file. Only seed required values when absent.
touch "$ENV_FILE"
grep -q '^GODSEYE_DB=' "$ENV_FILE" || echo "GODSEYE_DB=$DATA_DIR/godseye.db" >> "$ENV_FILE"
grep -q '^GODSEYE_DATA_DIR=' "$ENV_FILE" || echo "GODSEYE_DATA_DIR=$DATA_DIR" >> "$ENV_FILE"
chown root:"$APP_GROUP" "$ENV_FILE"
chmod 640 "$ENV_FILE"

# Importing the app performs idempotent schema migrations before services start.
runuser -u "$APP_USER" -- env GODSEYE_DB="$DATA_DIR/godseye.db" GODSEYE_DATA_DIR="$DATA_DIR" "$INSTALL_DIR/.venv/bin/python" -c 'from app.main import app; print("GODSEYE application import / migration: PASS")'
runuser -u "$APP_USER" -- env GODSEYE_DB="$DATA_DIR/godseye.db" "$INSTALL_DIR/.venv/bin/python" -c 'import sqlite3, os; p=os.environ["GODSEYE_DB"]; c=sqlite3.connect(p); c.execute("CREATE TABLE IF NOT EXISTS _godseye_write_test(x INTEGER)"); c.commit(); print("SQLite integrity:", c.execute("PRAGMA integrity_check").fetchone()[0]); c.close()'

cat > /etc/systemd/system/godseye-web.service <<EOF2
[Unit]
Description=GODSEYE Web
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF2

install -m 0644 "$INSTALL_DIR/godseye-scanner.service" /etc/systemd/system/godseye-scanner.service

# Production appliance helpers are refreshed during both fresh installs and upgrades.
install -m 0755 "$INSTALL_DIR/godseye-apply-update" /usr/local/sbin/godseye-apply-update
install -m 0755 "$INSTALL_DIR/godseye-https-setup" /usr/local/sbin/godseye-https-setup
install -m 0755 "$INSTALL_DIR/godseye-release-audit" /usr/local/sbin/godseye-release-audit
cat >/etc/sudoers.d/godseye-production <<'EOF2'
godseye ALL=(root) NOPASSWD: /usr/local/sbin/godseye-apply-update *
EOF2
chmod 0440 /etc/sudoers.d/godseye-production
mkdir -p "$DATA_DIR/updates" "$DATA_DIR/config-exports" "$DATA_DIR/tls" "$BACKUP_DIR"
chown -R "$APP_USER:$APP_GROUP" "$DATA_DIR/updates" "$DATA_DIR/config-exports" "$BACKUP_DIR"
chmod 0750 "$DATA_DIR/updates" "$DATA_DIR/config-exports" "$BACKUP_DIR"
chmod 0700 "$DATA_DIR/tls"

systemctl daemon-reload
systemctl enable godseye-web.service godseye-scanner.service
systemctl restart godseye-web.service
systemctl restart godseye-scanner.service
sleep 2
systemctl is-active --quiet godseye-web.service || {
  echo "GODSEYE web service failed. Recent logs:"
  journalctl -u godseye-web.service -n 80 --no-pager
  exit 1
}
systemctl is-active --quiet godseye-scanner.service || {
  echo "GODSEYE scanner service failed. Recent logs:"
  journalctl -u godseye-scanner.service -n 80 --no-pager
  exit 1
}

echo
echo "GODSEYE $([[ $EXISTING -eq 1 ]] && echo upgrade || echo installation) completed."
echo "Version:  $(cat "$INSTALL_DIR/VERSION")"
echo "Database: $DATA_DIR/godseye.db"
if [[ $EXISTING -eq 1 ]]; then echo "Pre-upgrade backups: $BACKUP_DIR"; fi
echo "Web: http://$(hostname -I | awk '{print $1}'):8080"
if [[ $EXISTING -eq 0 ]]; then echo "First login: admin — create your password on the setup screen."; fi
