#!/usr/bin/env bash
set -u
APP_DIR="${GODSEYE_APP_DIR:-/opt/godseye}"
PASS=0; WARN=0; FAIL=0
ok(){ echo "[PASS] $1"; PASS=$((PASS+1)); }
warn(){ echo "[WARN] $1"; WARN=$((WARN+1)); }
bad(){ echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

echo "GODSEYE installation diagnostics"
echo "================================="
for c in python3 systemctl ip ping nmap arp-scan; do command -v "$c" >/dev/null 2>&1 && ok "command: $c" || bad "missing command: $c"; done
[[ -d "$APP_DIR" ]] && ok "application directory: $APP_DIR" || bad "missing application directory: $APP_DIR"
[[ -x "$APP_DIR/.venv/bin/python" ]] && ok "Python virtual environment" || bad "missing virtual environment"
[[ -f "$APP_DIR/requirements.txt" ]] && ok "requirements.txt" || bad "missing requirements.txt"
if [[ -x "$APP_DIR/.venv/bin/python" ]]; then
  (cd "$APP_DIR" && PYTHONPATH="$APP_DIR" "$APP_DIR/.venv/bin/python" - <<'PY'
from app.main import app
print('routes', len(app.routes))
PY
  ) && ok "application import" || bad "application import failed"
fi
for s in godseye-scanner godseye-web; do
  if systemctl is-active --quiet "$s" 2>/dev/null; then ok "service active: $s"; else warn "service not active: $s"; journalctl -u "$s" -n 20 --no-pager 2>/dev/null || true; fi
done
if [[ -f /etc/godseye.env ]]; then ok "/etc/godseye.env exists"; else warn "/etc/godseye.env missing"; fi

echo
echo "Summary: PASS=$PASS WARN=$WARN FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
