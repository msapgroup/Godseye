# GODSEYE native dependency matrix

The fresh installer installs the native Linux programs used by the implemented Docker-free discovery, diagnostics, and network-tool paths.

| Capability | Native program | Installed |
|---|---|---:|
| ARP discovery | arp-scan | yes |
| Nmap discovery | nmap | yes |
| IPv4/IPv6 neighbors | iproute2 (`ip`) | yes |
| Ping | iputils-ping | yes |
| Traceroute | traceroute | yes |
| DNS | dnsutils (`dig`) | yes |
| mDNS | avahi-utils | yes |
| NetBIOS | nbtscan | yes |
| SNMP | net-snmp (`snmpget`) | yes |
| Wake-on-LAN | wakeonlan | yes |
| MQTT client tooling | mosquitto-clients | yes |
| Wi-Fi inspection | iw / wireless-tools | yes |
| Troubleshooting | curl / jq | yes |

The broader plugin manifest contains NetAlertX-inspired capability entries. A manifest entry is not treated as proof that a third-party connector is production-complete; those connectors must be implemented and tested separately.
