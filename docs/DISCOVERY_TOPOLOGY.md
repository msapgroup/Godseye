# GODSEYE Full Discovery + Topology Intelligence

GODSEYE now correlates network observations from multiple local and configured sources into one device identity and live topology.

## Discovery sources

- ARP (`arp-scan`) — primary same-LAN MAC/IP discovery
- Nmap (`nmap -sn`) — active host discovery
- Linux neighbor table (`ip -j neigh`) — kernel ARP/NDP evidence
- mDNS (`avahi-browse`) — Bonjour/Avahi names and services
- NetBIOS (`nbtscan`) — legacy Windows/SMB names
- DHCP — reads dnsmasq lease files when available
- Reverse DNS — fills unresolved hostnames
- Pi-hole — optional client/network observations when a Pi-hole monitor is configured
- UniFi — optional active client/AP observations when controller credentials are configured
- SNMP — optional router/switch ARP-table observations when an SNMP monitor is configured

A missing optional tool or unavailable integration does not fail the primary ARP scan.

## Identity correlation

MAC address is the preferred identity key. IP-only observations from mDNS/NetBIOS are correlated against known inventory addresses when possible. Every contributing source is retained in `device_sources`, while changing addresses are retained in `device_ip_history`.

## Topology

GODSEYE discovers the default gateway from Linux routing data and stores evidence-backed relationships in `topology_links`. UniFi AP/client evidence creates `wifi_client` links; controller/SNMP parent evidence creates `attached` links; other known devices receive a conservative `gateway_path` relationship.

The live API is:

```text
GET  /api/v1/intelligence/topology/live
GET  /api/v1/discovery/status
POST /api/v1/discovery/full
```

`POST /api/v1/discovery/full` is administrator-only and runs the complete best-effort discovery pipeline.

## Integration options

Pi-hole monitor options can include `token` or `api_token`.

UniFi monitor options can include:

```json
{
  "username": "godseye",
  "password": "...",
  "site": "default",
  "verify_tls": false
}
```

SNMP monitor options can include:

```json
{ "community": "public" }
```

Use read-only/local credentials wherever possible.
