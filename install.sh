#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "GODSEYE installer failed at line $LINENO. Command: $BASH_COMMAND"; exit 1' ERR

APP_USER="godseye"
APP_GROUP="godseye"
INSTALL_DIR="/opt/godseye"
DATA_DIR="/var/lib/godseye"
ENV_FILE="/etc/godseye.env"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--doctor" ]]; then
  echo "GODSEYE installer diagnostics"
  command -v python3 || true
  python3 --version || true
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
fi

[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-venv python3-pip ca-certificates \
  iproute2 iputils-ping nmap arp-scan dnsutils avahi-utils avahi-daemon nbtscan \
  snmp wakeonlan traceroute curl jq sqlite3 net-tools ethtool iw wireless-tools mosquitto-clients nginx openssl certbot python3-certbot-nginx rsync unzip sudo

for bin in python3 ip ping nmap arp-scan dig traceroute avahi-browse nbtscan snmpget snmpwalk; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Required program missing after install: $bin"; exit 1; }
done

getent group "$APP_GROUP" >/dev/null 2>&1 || groupadd --system "$APP_GROUP"
id "$APP_USER" >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin -g "$APP_GROUP" "$APP_USER"

mkdir -p "$INSTALL_DIR" "$DATA_DIR"
cp -a "$SRC_DIR"/. "$INSTALL_DIR"/
rm -rf "$INSTALL_DIR/__pycache__" "$INSTALL_DIR"/app/__pycache__ "$INSTALL_DIR/.pytest_cache"

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Critical SQLite fix: runtime files and DB belong to the service account.
chown -R "$APP_USER:$APP_GROUP" "$INSTALL_DIR" "$DATA_DIR"
chmod 750 "$INSTALL_DIR" "$DATA_DIR"

cat > "$ENV_FILE" <<EOF
GODSEYE_DB=$DATA_DIR/godseye.db
GODSEYE_DATA_DIR=$DATA_DIR
EOF
chown root:"$APP_GROUP" "$ENV_FILE"
chmod 640 "$ENV_FILE"

runuser -u "$APP_USER" -- env GODSEYE_DB="$DATA_DIR/godseye.db" "$INSTALL_DIR/.venv/bin/python" -c 'from app.main import app; print("GODSEYE application import: PASS")'
runuser -u "$APP_USER" -- env GODSEYE_DB="$DATA_DIR/godseye.db" "$INSTALL_DIR/.venv/bin/python" -c 'import sqlite3, os; p=os.environ["GODSEYE_DB"]; c=sqlite3.connect(p); c.execute("CREATE TABLE IF NOT EXISTS _godseye_write_test(x INTEGER)"); c.commit(); c.close(); print("SQLite write test: PASS")'

cat > /etc/systemd/system/godseye-web.service <<EOF
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
EOF

install -m 0644 "$INSTALL_DIR/godseye-scanner.service" /etc/systemd/system/godseye-scanner.service
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

echo
echo "GODSEYE installation completed."
echo "Database: $DATA_DIR/godseye.db"
echo "Web: http://$(hostname -I | awk '{print $1}'):8080"
echo "First login: admin — create your password on the setup screen."

# Production appliance helpers
install -m 0755 "$SRC_DIR/godseye-apply-update" /usr/local/sbin/godseye-apply-update
install -m 0755 "$SRC_DIR/godseye-https-setup" /usr/local/sbin/godseye-https-setup
cat >/etc/sudoers.d/godseye-production <<'EOF'
godseye ALL=(root) NOPASSWD: /usr/local/sbin/godseye-apply-update *
EOF
chmod 0440 /etc/sudoers.d/godseye-production
mkdir -p /var/lib/godseye/updates /var/lib/godseye/config-exports /var/lib/godseye/tls
chown -R godseye:godseye /var/lib/godseye/updates /var/lib/godseye/config-exports
chmod 0750 /var/lib/godseye/updates /var/lib/godseye/config-exports
chmod 0700 /var/lib/godseye/tls
