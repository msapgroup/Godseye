from __future__ import annotations
"""Service facade for persistence, correlation and topology."""
from .correlator import Correlator
from .intelligence_rules import analyze_device
from .intelligence_store import IntelligenceStore
from .topology import infer_from_observation
class IntelligenceService:
    def __init__(self,db_path): self.store=IntelligenceStore(db_path); self.correlator=Correlator()
    def ingest(self,source,observations):
        devices=self.correlator.ingest(source,observations)
        for d in devices:
            self.store.upsert_device(d)
            for obs in observations:
                self.store.add_observation(d["id"],source,obs)
                for link in infer_from_observation({**obs,"device_id":d["id"],"source":source}): self.store.upsert_link(**link)
            for finding in analyze_device(d): self.store.add_finding(d["id"],finding)
        return devices
    def snapshot(self): return {"devices":self.store.devices(),"findings":self.store.findings(),"topology":self.store.topology()}
