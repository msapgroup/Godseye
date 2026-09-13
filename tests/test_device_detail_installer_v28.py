from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app" / "main.py").read_text()
INSTALL = (ROOT / "install.sh").read_text()


def test_device_detail_page_defines_icon_asset_helper_before_load():
    page = MAIN.split("DEVICE_DETAIL_PAGE = r'''", 1)[1].split("'''", 1)[0]
    helper = "function deviceIconAsset(key)"
    assert helper in page
    assert page.index(helper) < page.index("async function load()")
    assert "deviceIconAsset(effectiveDetailIcon(d))" in page


def test_device_detail_icon_helper_has_safe_other_fallback():
    page = MAIN.split("DEVICE_DETAIL_PAGE = r'''", 1)[1].split("'''", 1)[0]
    assert "String(key||'other')" in page
    assert "DEVICE_ICON_ASSET_VERSION='27'" in page


def test_installer_auto_detects_upgrade_and_preserves_persistent_data():
    assert 'MODE="auto"' in INSTALL
    assert 'performing in-place upgrade' in INSTALL
    assert 'performing full install' in INSTALL
    assert 'sqlite3 "$DATA_DIR/godseye.db" ".backup' in INSTALL
    assert "--exclude '.venv/'" in INSTALL
    assert 'grep -q \'^GODSEYE_DB=\'' in INSTALL
    assert 'grep -q \'^GODSEYE_DATA_DIR=\'' in INSTALL
    assert 'rm -rf "$INSTALL_DIR/.venv"' in INSTALL
    assert 'systemctl restart godseye-web.service' in INSTALL
    assert 'systemctl restart godseye-scanner.service' in INSTALL


def test_installer_supports_explicit_fresh_upgrade_and_doctor_modes():
    assert '--upgrade' in INSTALL
    assert '--fresh' in INSTALL
    assert '--doctor' in INSTALL
    assert 'Use --upgrade or no flag.' in INSTALL
