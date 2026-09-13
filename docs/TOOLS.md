# GODSEYE Network Tools

This release completes the first major working Tools block.

## Tools

- Ping — reachability, packet loss, and latency
- Traceroute — bounded route tracing to private/link-local targets
- DNS Lookup — hostname resolution
- Port Scan — bounded TCP connect scan using Nmap
- Device Information — reverse DNS, Linux neighbor state, and ping
- Network Discovery — Nmap host discovery and Linux neighbor table
- Wake-on-LAN — administrator-only magic packet
- Gateway / Internet checks
- Website / service availability test

## Safety boundaries

Active network diagnostics are restricted to private/link-local targets where appropriate. Port scanning is TCP connect mode with a bounded port list. No shell command is built from raw user input; subprocesses use argument arrays.

## Raspberry Pi packages

The installer installs:

- `nmap`
- `traceroute`
- `iproute2`
- `iputils-ping`
- `dnsutils`
- `arp-scan`
- `avahi-utils`
- `nbtscan`
- `snmp`
- `wakeonlan`
- `curl`
- `jq`
- `iw`
- `wireless-tools`
- `mosquitto-clients`

Use `sudo bash install.sh --doctor` to verify the runtime dependencies.
