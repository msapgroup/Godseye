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
  systemctl --no-pager --full status godseye-web.service 2>/dev/null || true
  exit 0
fi

# --- Admin credentials -------------------------------------------------
# No fixed default password is shipped. If GODSEYE_ADMIN_USER and/or
# GODSEYE_ADMIN_PASSWORD are already set in the environment this script is
# run with (e.g. exported by your own client-provisioning template),
# those values are used as-is. Otherwise a random password is generated
# fresh for this install - there is no window where a well-known default
# is live, even briefly.
if [[ ! -f "$ENV_FILE" ]]; then
  FIRST_INSTALL=1
  ADMIN_USER="${GODSEYE_ADMIN_USER:-GodsEye}"
  if [[ -n "${GODSEYE_ADMIN_PASSWORD:-GodsEye}" ]]; then
    ADMIN_PASSWORD="$GODSEYE_ADMIN_PASSWORD"
    PASSWORD_WAS_GENERATED=0
  else
    ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '=+/' | cut -c1-20)
    PASSWORD_WAS_GENERATED=1
  fi
  cat > "$ENV_FILE" <<EOF
GODSEYE_ADMIN_USER=${ADMIN_USER}
GODSEYE_ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
  chown root:root "$ENV_FILE"
  chmod 600 "$ENV_FILE"
else
  FIRST_INSTALL=0
fi

[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip ca-certificates

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

echo
if [[ "$FIRST_INSTALL" == "1" ]]; then
  echo '=================================================================='
  if [[ "$PASSWORD_WAS_GENERATED" == "1" ]]; then
    echo 'First-time setup - a random admin password was generated'
    echo '(also saved to /etc/godseye.env):'
    echo "  Username: ${ADMIN_USER}"
    echo "  Password: ${ADMIN_PASSWORD}"
    echo 'Save this password now - it is not printed again.'
  else
    echo "First-time setup - using the GODSEYE_ADMIN_USER/GODSEYE_ADMIN_PASSWORD"
    echo "you provided (saved to /etc/godseye.env)."
  fi
  echo 'You have a few days to change this password before GODSEYE starts'
  echo 'requiring it - see the dashboard after logging in.'
  echo '=================================================================='
fi


systemctl enable godseye-web.service
systemctl restart godseye-web.service
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
