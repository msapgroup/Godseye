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

## Cyber Tools operations console

Cyber Tools adds eight independent operational cards. Each card owns its inputs, engine availability, run state, result, and post-run actions:

- Network Exposure Scan — bounded Nmap discovery or service inventory for private/link-local targets only.
- Endpoint Security Posture — enrolled Windows Agent reachability, version, errors, update checks, and malware-scan state.
- Web & TLS Audit — HTTPS negotiation, certificate details, redirects, and browser security headers.
- Malware & IOC Scan — local indicator classification plus optional ClamAV and YARA file scanning (10 MB maximum).
- DNS & Email Security — A/AAAA, MX, SPF, DMARC, DKIM selector, CAA, and DNSSEC checks.
- Linux Security Audit — read-only Lynis appliance assessment.
- Network Threat Detection — recent alert summaries from an existing Suricata `eve.json` feed.
- Evidence Capture — a validated interface, 15-second maximum, and 500-packet maximum PCAP capture.

Every run is retained in scan history. An operator can create a linked Finding, create a Ticket, export the stored JSON result, or schedule supported checks. Malware file uploads and packet captures are deliberately excluded from recurring schedules.

The installer also provides `clamav`, `yara`, `lynis`, and `tcpdump`, plus a root-owned evidence-capture helper with strict interface, duration, packet-count, IP-filter, and output-path validation. Suricata is intentionally connected through its EVE log rather than automatically enabling an IDS interface; point `GODSEYE_SURICATA_EVE` at the authorized Suricata feed when it is not at `/var/log/suricata/eve.json`.
