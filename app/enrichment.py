"""GODSEYE device enrichment and correlation helpers."""
from __future__ import annotations
import re

OUI = {
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "3c5ab4": "Google", "f4f5d8": "Amazon", "acbc32": "Apple",
    "a483e7": "Apple", "28cfe9": "Apple"
}

def normalize_mac(mac: str | None) -> str | None:
    if not mac: return None
    m = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(m) != 12: return None
    return ":".join(m[i:i+2] for i in range(0, 12, 2))

def vendor_for_mac(mac: str | None) -> str | None:
    m = normalize_mac(mac)
    if not m: return None
    return OUI.get(m.replace(":", "")[:6])

def merge_observation(device: dict, observation: dict, source: str) -> dict:
    out = dict(device or {})
    out["mac"] = normalize_mac(observation.get("mac") or out.get("mac"))
    for key in ("ip", "hostname", "vendor", "device_type"):
        value = observation.get(key)
        if value and not out.get(key): out[key] = value
    sources = list(out.get("sources") or [])
    if source not in sources: sources.append(source)
    out["sources"] = sources
    out.setdefault("vendor", vendor_for_mac(out.get("mac")))
    return out
