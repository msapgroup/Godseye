# GODSEYE v13 — Full Discovery + Topology Intelligence

This release adds a unified multi-source discovery pipeline and live network-map data model.

Implemented sources: ARP, Nmap, Linux neighbors, mDNS, NetBIOS, DHCP, reverse DNS, configured Pi-hole, configured UniFi, and configured SNMP.

The scanner performs full enrichment on every manual Scan Now request and periodically on scheduled scans. Optional discovery failures are isolated from primary ARP scanning.
