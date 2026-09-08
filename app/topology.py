"""Explainable topology inference for GODSEYE."""
def infer_from_observation(obs):
    links=[]; device=obs.get("device_id") or obs.get("mac") or obs.get("ip")
    gateway=obs.get("gateway"); parent=obs.get("parent_id"); ap=obs.get("access_point_id")
    if device and gateway: links.append({"source_id":gateway,"target_id":device,"relation":"gateway_path","evidence":{"source":obs.get("source","unknown")}})
    if parent and device: links.append({"source_id":parent,"target_id":device,"relation":"attached","evidence":{"source":obs.get("source","unknown")}})
    if ap and device: links.append({"source_id":ap,"target_id":device,"relation":"wifi_client","evidence":{"source":obs.get("source","unknown")}})
    return links
