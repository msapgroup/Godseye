#!/usr/bin/env bash
set -Eeuo pipefail

APP_USER="godseye"
APP_GROUP="godseye"
INSTALL_DIR="/opt/godseye"
DATA_DIR="/var/lib/godseye"
ENV_FILE="/etc/godseye.env"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$DATA_DIR/install-backups"
MODE="auto"
STAGE_DIR="/opt/.godseye-stage.$$"
ROLLBACK_DIR=""
SWAPPED=0
SUCCESS=0
EXISTING=0
SERVICES_STOPPED=0

usage() {
  cat <<'USAGE'
GODSEYE V4.28 installer

Install from the extracted release directory; no git clone is required.

Usage:
  sudo bash ./install.sh --fresh      Fresh installation
  sudo bash ./install.sh --upgrade    Clean in-place application upgrade, preserving data
  sudo bash ./install.sh              Auto-detect fresh install vs upgrade
  sudo bash ./install.sh --doctor     Installation diagnostics
USAGE
}

rollback_on_error() {
  local rc=$?
  if [[ $SUCCESS -eq 0 ]]; then
    if [[ -n "$ROLLBACK_DIR" && -d "$ROLLBACK_DIR" ]]; then
      echo "Installer failed; restoring previous GODSEYE application files..." >&2
      systemctl stop godseye-web.service godseye-scanner.service 2>/dev/null || true
      [[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR"
      mv "$ROLLBACK_DIR" "$INSTALL_DIR"
      SWAPPED=0
    fi
    if [[ $EXISTING -eq 1 && $SERVICES_STOPPED -eq 1 ]]; then
      systemctl daemon-reload 2>/dev/null || true
      systemctl restart godseye-web.service godseye-scanner.service 2>/dev/null || true
    fi
  fi
  rm -rf "$STAGE_DIR" 2>/dev/null || true
  echo "GODSEYE installer failed with exit code $rc." >&2
  exit "$rc"
}
trap rollback_on_error ERR

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
    [[ -x "$INSTALL_DIR/doctor.sh" ]] && exec "$INSTALL_DIR/doctor.sh"
    for svc in godseye-web.service godseye-scanner.service; do systemctl --no-pager --full status "$svc" 2>/dev/null || true; done
    exit 0
    ;;
  -h|--help) usage; exit 0 ;;
  *) echo "Unknown option: $1"; usage; exit 2 ;;
esac

[[ $EUID -eq 0 ]] || { echo "Run this installer with sudo."; exit 1; }
[[ -f "$SRC_DIR/app/main.py" && -f "$SRC_DIR/requirements.txt" && -f "$SRC_DIR/VERSION" && -f "$SRC_DIR/scripts/validate_release.py" ]] || {
  echo "This is not a complete GODSEYE V4.28 release directory."; exit 1;
}

python3 "$SRC_DIR/scripts/validate_release.py" "$SRC_DIR"

if [[ -d "$INSTALL_DIR" || -f /etc/systemd/system/godseye-web.service || -f "$DATA_DIR/godseye.db" ]]; then EXISTING=1; fi
if [[ "$MODE" == "upgrade" && $EXISTING -eq 0 ]]; then echo "--upgrade requested, but GODSEYE is not installed."; exit 1; fi
if [[ "$MODE" == "fresh" && $EXISTING -eq 1 ]]; then echo "--fresh requested, but an existing GODSEYE installation was found. Use --upgrade to preserve its data."; exit 1; fi

TARGET_VERSION="$(tr -d '\r\n' < "$SRC_DIR/VERSION")"
if [[ $EXISTING -eq 1 ]]; then
  echo "GODSEYE clean upgrade: $(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo unknown) -> $TARGET_VERSION"
else
  echo "GODSEYE fresh installation: $TARGET_VERSION"
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-venv python3-pip ca-certificates \
  iproute2 iputils-ping nmap arp-scan dnsutils avahi-utils avahi-daemon nbtscan \
  snmp wakeonlan traceroute curl jq sqlite3 net-tools ethtool iw wireless-tools \
  mosquitto-clients nginx openssl certbot python3-certbot-nginx rsync unzip sudo

for bin in python3 ip ping nmap arp-scan dig traceroute avahi-browse nbtscan snmpget snmpwalk sqlite3 rsync; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Required program missing after package installation: $bin"; exit 1; }
done

getent group "$APP_GROUP" >/dev/null 2>&1 || groupadd --system "$APP_GROUP"
id "$APP_USER" >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin -g "$APP_GROUP" "$APP_USER"
mkdir -p "$DATA_DIR" "$BACKUP_DIR"

# Build a clean application stage from an allow-list. Historical patch/release debris
# is intentionally not copied into the installed application directory.
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
rsync -a --delete "$SRC_DIR/app/" "$STAGE_DIR/app/"
rsync -a --delete "$SRC_DIR/windows/" "$STAGE_DIR/windows/"
rsync -a --delete "$SRC_DIR/docs/" "$STAGE_DIR/docs/"
mkdir -p "$STAGE_DIR/scripts"
install -m 0644 "$SRC_DIR/requirements.txt" "$SRC_DIR/VERSION" "$SRC_DIR/RELEASE_MANIFEST.json" "$SRC_DIR/README.md" "$SRC_DIR/INSTALL.txt" "$STAGE_DIR/"
install -m 0755 "$SRC_DIR/install.sh" "$SRC_DIR/doctor.sh" "$SRC_DIR/godseye-apply-update" "$SRC_DIR/godseye-https-setup" "$SRC_DIR/godseye-release-audit" "$STAGE_DIR/"
install -m 0644 "$SRC_DIR/godseye-scanner.service" "$SRC_DIR/godseye-web.service" "$STAGE_DIR/"
install -m 0644 "$SRC_DIR/scripts/validate_release.py" "$STAGE_DIR/scripts/validate_release.py"
python3 -m compileall -q "$STAGE_DIR/app"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ $EXISTING -eq 1 ]]; then
  systemctl stop godseye-web.service godseye-scanner.service 2>/dev/null || true
  SERVICES_STOPPED=1
  if [[ -f "$DATA_DIR/godseye.db" ]]; then
    sqlite3 "$DATA_DIR/godseye.db" ".backup '$BACKUP_DIR/godseye-pre-upgrade-${stamp}.db'"
    cp -a "$DATA_DIR/secret.key" "$BACKUP_DIR/secret.key-${stamp}" 2>/dev/null || true
  fi
  cp -a "$INSTALL_DIR/VERSION" "$BACKUP_DIR/VERSION-${stamp}" 2>/dev/null || true
  ROLLBACK_DIR="/opt/.godseye-rollback-${stamp}"
  rm -rf "$ROLLBACK_DIR"
  if [[ -d "$INSTALL_DIR" ]]; then mv "$INSTALL_DIR" "$ROLLBACK_DIR"; fi
fi

mv "$STAGE_DIR" "$INSTALL_DIR"
SWAPPED=1

# Recreate the virtual environment at its final absolute path.
rm -rf "$INSTALL_DIR/.venv"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

chown -R root:"$APP_GROUP" "$INSTALL_DIR"
find "$INSTALL_DIR" -path "$INSTALL_DIR/.venv" -prune -o -type d -exec chmod 0750 {} +
find "$INSTALL_DIR" -path "$INSTALL_DIR/.venv" -prune -o -type f -exec chmod 0640 {} +
chmod 0750 "$INSTALL_DIR/install.sh" "$INSTALL_DIR/doctor.sh" "$INSTALL_DIR/godseye-apply-update" "$INSTALL_DIR/godseye-https-setup" "$INSTALL_DIR/godseye-release-audit"
chmod -R g+rX,o-rwx "$INSTALL_DIR/.venv"

chown -R "$APP_USER:$APP_GROUP" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

touch "$ENV_FILE"
grep -q '^GODSEYE_DB=' "$ENV_FILE" || echo "GODSEYE_DB=$DATA_DIR/godseye.db" >> "$ENV_FILE"
grep -q '^GODSEYE_DATA_DIR=' "$ENV_FILE" || echo "GODSEYE_DATA_DIR=$DATA_DIR" >> "$ENV_FILE"
chown root:"$APP_GROUP" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

# Idempotent application import runs database migrations. Set cwd and PYTHONPATH
# explicitly so validation is independent of the shell location used to run install.sh.
(
  cd "$INSTALL_DIR"
  runuser -u "$APP_USER" -- env \
    PYTHONPATH="$INSTALL_DIR" \
    GODSEYE_DB="$DATA_DIR/godseye.db" \
    GODSEYE_DATA_DIR="$DATA_DIR" \
    "$INSTALL_DIR/.venv/bin/python" -c 'from app.main import app; print("GODSEYE application import / migration: PASS")'
)
runuser -u "$APP_USER" -- env GODSEYE_DB="$DATA_DIR/godseye.db" "$INSTALL_DIR/.venv/bin/python" -c 'import os,sqlite3; p=os.environ["GODSEYE_DB"]; c=sqlite3.connect(p); print("SQLite integrity:",c.execute("PRAGMA integrity_check").fetchone()[0]); c.close()'

install -m 0644 "$INSTALL_DIR/godseye-web.service" /etc/systemd/system/godseye-web.service
install -m 0644 "$INSTALL_DIR/godseye-scanner.service" /etc/systemd/system/godseye-scanner.service
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

systemctl is-active --quiet godseye-web.service || { journalctl -u godseye-web.service -n 100 --no-pager; false; }
systemctl is-active --quiet godseye-scanner.service || { journalctl -u godseye-scanner.service -n 100 --no-pager; false; }

SUCCESS=1
if [[ -n "$ROLLBACK_DIR" && -d "$ROLLBACK_DIR" ]]; then rm -rf "$ROLLBACK_DIR"; fi
trap - ERR

echo
echo "GODSEYE installation completed successfully."
echo "Version:  $(cat "$INSTALL_DIR/VERSION")"
echo "Database: $DATA_DIR/godseye.db"
echo "Web:      http://$(hostname -I | awk '{print $1}'):8080"
if [[ $EXISTING -eq 1 ]]; then echo "Pre-upgrade database backup: $BACKUP_DIR"; else echo "First login: admin — create the administrator password on the setup screen."; fi
