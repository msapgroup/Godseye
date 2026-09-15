# GODSEYE Intelligence Engine

The next major block adds an evidence-based correlation engine.

## Identity
MAC addresses are the preferred stable identity. IP addresses are observations and can change.

## Evidence
Collectors can ingest observations from ARP, Nmap, NDP/neighbors, DHCP, mDNS/DNS, Pi-hole, UniFi, and SNMP.

## Findings
The rules engine produces explainable findings such as IP changes, DHCP-only presence, and corroborating controller/DHCP evidence.

The engine is intentionally deterministic and explainable. An AI assistant can consume these findings later without replacing the underlying evidence.
