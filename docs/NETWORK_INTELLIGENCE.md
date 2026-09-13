# GODSEYE Network Intelligence

The intelligence layer correlates observations from ARP/neighbor discovery, Nmap, DHCP, hostname resolution and integrations into a single device identity.

## Correlation rules
- MAC address is the strongest local identity key.
- IP addresses are historical attributes, not permanent identities.
- Multiple sources contribute evidence to the same device.
- Conflicting observations should be retained as history rather than silently overwriting data.
- Vendor enrichment is offline-first and can be expanded with an OUI database updater.

## Network map
Topology links are persisted independently of devices so router, switch, AP and client relationships can be enriched as integrations are added.

## Issues
Connectivity and public-IP changes become persistent issues with evidence and resolution state.
