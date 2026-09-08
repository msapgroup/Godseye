#!/usr/bin/env bash
set -Eeuo pipefail
trap 'rc=$?; echo; echo "GODSEYE installer failed (exit $rc) at line $LINENO."; echo "Run: sudo bash install.sh --doctor"; exit $rc' ERR

APP_DIR="${GODSEYE_APP_DIR:-/opt/godseye}"
APP_USER="godseye"
ENV_FILE="/etc/godseye.env"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then echo "Run as root: sudo bash install.sh"; exit 1; fi
if [[ "${1:-}" == "--doctor" ]]; then exec "${SOURCE_DIR}/doctor.sh"; fi
if [[ -e "$APP_DIR" ]]; then
  echo "ERROR: $APP_DIR already exists. This installer is for a NEW installation."
  echo "Choose another directory with GODSEYE_APP_DIR=/some/path or intentionally remove the old install."
  exit 2
fi

echo "== GODSEYE fresh installer =="
echo "Source: $SOURCE_DIR"
echo "Target: $APP_DIR"

if [[ ! -r /etc/os-release ]]; then echo "Cannot identify Linux distribution."; exit 3; fi
. /etc/os-release
echo "OS: ${PRETTY_NAME:-unknown}"

PYTHON_BIN="$(command -v python3 || true)"
if [[ -z "$PYTHON_BIN" ]]; then
  echo "python3 is not installed; installing it first."
fi

echo "Updating APT metadata..."
apt-get update

REQUIRED_PKGS=(python3 python3-venv python3-pip openssl iproute2 iputils-ping nmap arp-scan ca-certificates)
apt-get install -y "${REQUIRED_PKGS[@]}"

PYTHON_BIN="$(command -v python3)"
PYVER="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,9) else 1)'; then
  echo "ERROR: GODSEYE requires Python 3.9 or newer; found $PYVER."
  echo "Use Raspberry Pi OS Bookworm (recommended) or install Python 3.9+."
  exit 4
fi
echo "Python: $PYVER"

OPTIONAL_PKGS=(snmp nbtscan avahi-utils dnsutils ethtool iw mosquitto-clients wakeonlan git)
for pkg in "${OPTIONAL_PKGS[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    apt-get install -y "$pkg" || echo "WARNING: optional package '$pkg' could not be installed."
  else
    echo "WARNING: optional package '$pkg' is not available in this APT repository."
  fi
done

if ! command -v systemctl >/dev/null; then echo "ERROR: systemctl is required."; exit 5; fi

echo "Installing application files..."
install -d -m 0755 "$APP_DIR"
cp -a "$SOURCE_DIR"/. "$APP_DIR"/
rm -rf "$APP_DIR/.git" "$APP_DIR/.pytest_cache" "$APP_DIR/__pycache__"

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi
install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$APP_DIR/data"

# Build an isolated environment with the same python used for validation.
"$PYTHON_BIN" -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
"$APP_DIR/.venv/bin/python" -m pip install --disable-pip-version-check -r "$APP_DIR/requirements.txt"

cd "$APP_DIR"
PYTHONPATH="$APP_DIR" "$APP_DIR/.venv/bin/python" -m compileall -q app
# Capture the real import traceback instead of hiding it behind the shell trap.
if ! PYTHONPATH="$APP_DIR" "$APP_DIR/.venv/bin/python" -c 'from app.main import app; print(f"GODSEYE application import OK: {len(app.routes)} routes")'; then
  echo "ERROR: GODSEYE application import failed."
  echo "Python: $($APP_DIR/.venv/bin/python --version)"
  echo "Requirements:"
  "$APP_DIR/.venv/bin/python" -m pip show fastapi pydantic uvicorn || true
  exit 6
fi

ADMIN_USER="${GODSEYE_ADMIN_USER:-GodsEye}"
if [[ -n "${GODSEYE_ADMIN_PASSWORD:-}" ]]; then ADMIN_PASSWORD="$GODSEYE_ADMIN_PASSWORD"; GENERATED=0; else ADMIN_PASSWORD="$(openssl rand -hex 18)"; GENERATED=1; fi
umask 077
cat > "$ENV_FILE" <<ENVEOF
GODSEYE_ADMIN_USER=${ADMIN_USER}
GODSEYE_ADMIN_PASSWORD=${ADMIN_PASSWORD}
GODSEYE_DB=${APP_DIR}/data/godseye.db
ENVEOF
chmod 600 "$ENV_FILE"

install -m 0644 "$APP_DIR/godseye-web.service" /etc/systemd/system/godseye-web.service
install -m 0644 "$APP_DIR/godseye-scanner.service" /etc/systemd/system/godseye-scanner.service
install -d /etc/systemd/system/godseye-web.service.d /etc/systemd/system/godseye-scanner.service.d
printf '[Service]\nEnvironmentFile=-%s\n' "$ENV_FILE" > /etc/systemd/system/godseye-web.service.d/env.conf
printf '[Service]\nEnvironmentFile=-%s\n' "$ENV_FILE" > /etc/systemd/system/godseye-scanner.service.d/env.conf
systemctl daemon-reload
systemctl enable godseye-scanner godseye-web
systemctl start godseye-scanner
sleep 2
systemctl start godseye-web
sleep 2

if ! systemctl is-active --quiet godseye-scanner; then journalctl -u godseye-scanner -n 50 --no-pager || true; exit 7; fi
if ! systemctl is-active --quiet godseye-web; then journalctl -u godseye-web -n 50 --no-pager || true; exit 8; fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "============================================================"
echo "GODSEYE fresh installation complete."
echo "Open: http://${IP:-YOUR-PI-IP}:8080"
echo "Web:     sudo systemctl status godseye-web"
echo "Scanner: sudo systemctl status godseye-scanner"
echo "Logs:    sudo journalctl -u godseye-web -n 100 --no-pager"
if [[ "$GENERATED" == "1" ]]; then echo "Initial admin user: $ADMIN_USER"; echo "Initial admin password: $ADMIN_PASSWORD"; fi
echo "============================================================"
