"""Evidence-based GODSEYE root-cause rules."""
from __future__ import annotations

def analyze_device(device: dict) -> list[dict]:
    findings=[]
    sources=set(device.get("sources",[]))
    if len(device.get("ips",[])) > 1:
        findings.append({"type":"ip_change","severity":"info",
                         "title":"Device has used multiple IP addresses",
                         "recommendation":"Check DHCP reservations or static-IP settings if the address should remain stable."})
    if "dhcp" in sources and "nmap" not in sources and "arp" not in sources and "neighbor" not in sources:
        findings.append({"type":"presence","severity":"info",
                         "title":"Device is known from DHCP but not from active discovery",
                         "recommendation":"The device may be asleep, isolated, or blocking discovery traffic; run a targeted ping/scan."})
    if "unifi" in sources and "dhcp" in sources:
        findings.append({"type":"correlated","severity":"info",
                         "title":"Controller and DHCP evidence agree",
                         "recommendation":"Use the controller association and DHCP lease as corroborating identity evidence."})
    return findings
