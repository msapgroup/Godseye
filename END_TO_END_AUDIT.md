# GODSEYE v17 End-to-End Raspberry Pi Release Audit

This release is an audit/hardening release, not a feature release.

## Fixed during audit

- Active network tools (ping, traceroute, Nmap discovery, port scan, device diagnostics, website checks) now require the `operate` permission. Read-only and auditor accounts can no longer initiate those network operations.
- Added explicit automated permission tests for admin, operator, auditor, and read-only roles.
- Added `godseye-release-audit`, installed to `/usr/local/sbin/godseye-release-audit`, for native dependency, service, SQLite, route, real ARP/Nmap, Nginx/TLS, and optional Pi-hole/UniFi/SNMP checks on the Raspberry Pi.

## Run on the actual Raspberry Pi

```bash
sudo godseye-release-audit
```

Optional live integration checks can be enabled only for systems you administer:

```bash
sudo env \
  GODSEYE_AUDIT_PIHOLE_URL='http://pihole.local' \
  GODSEYE_AUDIT_UNIFI_URL='https://unifi.local' \
  GODSEYE_AUDIT_SNMP_HOST='192.168.1.1' \
  GODSEYE_AUDIT_SNMP_COMMUNITY='your-community' \
  godseye-release-audit
```

The audit helper does not perform destructive remediation. Pi-hole/UniFi checks are reachability checks; SNMP is a read-only sysDescr query. Real ARP and Nmap discovery are restricted to the Pi's directly connected local network.

## Build-environment result

The source test suite, Python compilation, shell syntax, and archive validation pass. The build environment does not contain the full Raspberry Pi discovery stack or your private Pi-hole/UniFi/SNMP services, so those live checks cannot truthfully be certified here. Run the installed audit helper on the target Pi before declaring production readiness.
