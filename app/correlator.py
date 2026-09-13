"""GODSEYE network intelligence correlation engine."""
from __future__ import annotations
from collections import defaultdict
from .enrichment import normalize_mac, vendor_for_mac

class Correlator:
    """In-memory correlation engine suitable for scheduled DB-backed collectors."""
    def __init__(self):
        self.devices: dict[str, dict] = {}
        self.issues: dict[str, dict] = {}

    def identity_key(self, obs: dict) -> str:
        mac=normalize_mac(obs.get("mac"))
        if mac: return f"mac:{mac}"
        ip=obs.get("ip")
        return f"ip:{ip}" if ip else "unknown"

    def ingest(self, source: str, observations: list[dict]) -> list[dict]:
        changed=[]
        for obs in observations:
            key=self.identity_key(obs)
            if key=="unknown": continue
            d=self.devices.setdefault(key, {"id":key,"sources":[],"ips":[],"hostnames":[]})
            if source not in d["sources"]: d["sources"].append(source)
            mac=normalize_mac(obs.get("mac"))
            if mac: d["mac"]=mac; d["vendor"]=d.get("vendor") or vendor_for_mac(mac)
            for field in ("ip","hostname","device_type"):
                value=obs.get(field)
                if value and value not in d[field+"s" if field=="ip" else field+"s"]:
                    d[field+"s" if field=="ip" else field+"s"].append(value)
            d["last_seen_source"]=source
            changed.append(d)
        return changed

    def snapshot(self):
        return list(self.devices.values())
