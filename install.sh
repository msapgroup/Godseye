#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo; echo "GODSEYE installer failed at line $LINENO."; echo "Run: sudo bash install.sh --doctor for diagnostics."; exit 1' ERR

APP_DIR="${GODSEYE_APP_DIR:-/opt/godseye}"
APP_USER="godseye"
ENV_FILE="/etc/godseye.env"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"
  exit 1
fi

if [[ "${1:-}" == "--doctor" ]]; then
  exec "${SOURCE_DIR}/doctor.sh"
fi

if [[ -e "$APP_DIR" ]]; then
  echo "ERROR: $APP_DIR already exists. This is a NEW-install installer."
  echo "To avoid destroying an existing installation, it will not continue."
  echo "Choose another directory with GODSEYE_APP_DIR=/some/path or remove the old install intentionally."
  exit 2
fi

echo "== GODSEYE fresh installer =="
echo "Source: $SOURCE_DIR"
echo "Target: $APP_DIR"

echo "Checking operating system..."
if [[ ! -r /etc/os-release ]]; then echo "Cannot identify Linux distribution."; exit 3; fi
. /etc/os-release
echo "OS: ${PRETTY_NAME:-unknown}"

if [[ "$(uname -m)" != "aarch64" && "$(uname -m)" != "armv7l" && "$(uname -m)" != "armv6l" && "$(uname -m)" != "armhf" ]]; then
  echo "WARNING: This installer targets Raspberry Pi ARM systems; detected $(uname -m)."
fi

echo "Updating APT metadata..."
apt-get update

REQUIRED_PKGS=(python3 python3-venv python3-pip openssl iproute2 iputils-ping nmap arp-scan ca-certificates)
apt-get install -y "${REQUIRED_PKGS[@]}"

OPTIONAL_PKGS=(snmp nbtscan avahi-utils dnsutils ethtool iw mosquitto-clients wakeonlan git)
for pkg in "${OPTIONAL_PKGS[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    apt-get install -y "$pkg" || echo "WARNING: optional package '$pkg' could not be installed."
  else
    echo "WARNING: optional package '$pkg' is not available in this APT repository."
  fi
done

if ! command -v python3 >/dev/null || ! command -v systemctl >/dev/null; then
  echo "Required commands are missing after package installation."; exit 4
fi

# Copy the checked-out repository instead of cloning it again. This fixes the
# common failure where the new GitHub repository has not been made public yet,
# or the install script is being run from an uploaded ZIP/local checkout.
echo "Installing application files..."
install -d -m 0755 "$APP_DIR"
cp -a "$SOURCE_DIR"/. "$APP_DIR"/
rm -rf "$APP_DIR/.git" "$APP_DIR/.pytest_cache" "$APP_DIR/__pycache__"

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$APP_DIR/data"

python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install --disable-pip-version-check -r "$APP_DIR/requirements.txt"

# Validate imports before installing systemd services.
cd "$APP_DIR"
PYTHONPATH="$APP_DIR" "$APP_DIR/.venv/bin/python" -m compileall -q app
PYTHONPATH="$APP_DIR" "$APP_DIR/.venv/bin/python" - <<'PY'
from app.main import app
print(f"GODSEYE application import OK: {len(app.routes)} routes")
PY

ADMIN_USER="${GODSEYE_ADMIN_USER:-GodsEye}"
if [[ -n "${GODSEYE_ADMIN_PASSWORD:-}" ]]; then
  ADMIN_PASSWORD="$GODSEYE_ADMIN_PASSWORD"
  GENERATED=0
else
  ADMIN_PASSWORD="$(openssl rand -hex 18)"
  GENERATED=1
fi

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

if ! systemctl is-active --quiet godseye-scanner; then
  journalctl -u godseye-scanner -n 50 --no-pager || true
  exit 5
fi
if ! systemctl is-active --quiet godseye-web; then
  journalctl -u godseye-web -n 50 --no-pager || true
  exit 6
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "============================================================"
echo "GODSEYE fresh installation complete."
echo "Open: http://${IP:-YOUR-PI-IP}:8080"
echo "Web:     sudo systemctl status godseye-web"
echo "Scanner: sudo systemctl status godseye-scanner"
echo "Logs:    sudo journalctl -u godseye-web -n 100 --no-pager"
echo "         sudo journalctl -u godseye-scanner -n 100 --no-pager"
echo "============================================================"
echo "Username: $ADMIN_USER"
if [[ "$GENERATED" == "1" ]]; then
  echo "Password: $ADMIN_PASSWORD"
  echo "Credentials are also stored in $ENV_FILE (mode 600)."
else
  echo "Password: supplied through GODSEYE_ADMIN_PASSWORD"
fi
