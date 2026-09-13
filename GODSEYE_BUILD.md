# GODSEYE 1.0.0 GitHub Build

Consolidated Raspberry Pi build for the new `Godseye` GitHub repository.

Included:
- Authentication and MFA
- Device inventory and event history
- ARP, Nmap, and IPv4/IPv6 neighbor discovery
- DNS/hostname enrichment
- MAC-first device correlation
- Persistent SQLite intelligence
- Findings and issue tracking
- Topology relationship storage
- Diagnostics and troubleshooting foundations
- Website, DHCP, and public-IP monitoring foundations
- Pi-hole, UniFi, and SNMP integration foundations
- Wake-on-LAN
- Plugin architecture and scheduler
- Responsive sidebar navigation
- Raspberry Pi native installer/systemd support
- Docker-free deployment
- Documentation and feature registry

## Raspberry Pi

```bash
sudo bash install.sh
```

Do not commit `.env`, secrets, databases, runtime logs, or generated caches.
