from pathlib import Path


def test_v27_icon_picker_shows_all_realistic_icons_and_busts_cache():
    source = Path('app/main.py').read_text()
    assert "DEVICE_ICON_ASSET_VERSION='27'" in source
    assert ">All Icons</button>" in source
    assert "ACTIVE_DEVICE_ICON_CATEGORY='all'" in source
    assert "ACTIVE_DEVICE_ICON_CATEGORY==='all'" in source
    assert "no-cache, max-age=0, must-revalidate" in source
    assert "onerror=\"this.src='${deviceIconAsset('other')}'\"" in source


def test_realistic_icon_library_is_complete():
    icon_dir = Path('app/assets/device-icons')
    required = {
        'router','switch','access-point','firewall','modem','nas','network-storage',
        'patch-panel','server','pc','laptop','camera','printer','phone','voip-phone',
        'tablet','tv','game-console','iot','other'
    }
    present = {p.stem for p in icon_dir.glob('*.svg')}
    assert required <= present


def test_version_is_v27_or_later():
    v = Path('VERSION').read_text().strip()
    assert v.startswith(('2.7.0-', '2.8.0-', '2.9.0-', '3.0.0-', '3.1.0-', '3.2.0-', '3.3.0-', '3.4.0-', '3.5.0-', '3.6.0-', '3.7.0-', '3.8.0-', '3.9.0-', '4.0.0-', '4.1.0-', '4.2.0-', '4.3.0-', '4.4.0-', '4.5.0-', '4.6.0-', '4.7.0-', '4.8.0-'))
