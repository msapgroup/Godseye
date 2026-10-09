"""Local realistic device artwork; existing classification keys remain compatible."""
import base64
from functools import lru_cache
from pathlib import Path

DEVICE_CELLS = {"switch": ("devices", 0), "nas": ("devices", 1),
                "network-storage": ("devices", 1), "pc": ("devices", 2),
                "access-point": ("devices", 3), "raspberry-pi": ("devices", 4),
                "voip-phone": ("devices", 5), "conference-phone": ("devices", 5),
                "apple-tv": ("devices", 6), "firewall": ("devices", 7),
                "router": ("devices-business", 0), "modem": ("devices-business", 0),
                "server": ("devices-business", 1), "laptop": ("devices-business", 2),
                "camera": ("devices-business", 3), "printer": ("devices-business", 4),
                "phone": ("devices-business", 5), "tablet": ("devices-business", 6),
                "fire-tv-stick": ("devices-business", 7),
                "roku": ("devices-home", 0), "smart-plug": ("devices-home", 1),
                "video-doorbell": ("devices-home", 2), "ring-doorbell": ("devices-home", 2),
                "smart-speaker": ("devices-home", 3), "home-hub": ("devices-home", 3),
                "thermostat": ("devices-home", 4), "smart-lock": ("devices-home", 5),
                "ups": ("devices-home", 6), "pos-terminal": ("devices-home", 7)}

@lru_cache(maxsize=4)
def _atlas(name):
    return base64.b64encode((Path(__file__).parent / "assets" / "visual" / (name + ".png")).read_bytes()).decode("ascii")

@lru_cache(maxsize=40)
def device_svg(key):
    atlas, cell = DEVICE_CELLS[key]
    x, y = (cell % 4) * 443.5, (cell // 4) * 443.5
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x} {y} 443.5 443.5">'
            f'<image width="1774" height="887" href="data:image/png;base64,{_atlas(atlas)}"/></svg>')
