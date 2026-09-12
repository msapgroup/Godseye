# Production Appliance Management

GODSEYE v1.6 adds production-management controls under **System Health**.

## Roles
- **Admin**: full appliance/configuration/user/update/remediation access.
- **Operator**: operational scans, device rechecks, finding resolution, monitor runs, integration sync and on-demand reports.
- **Auditor**: audit-log access and export, plus normal read access.
- **Read-only**: inventory/dashboard/report viewing without operational or administrative actions.

## Updates
Upload a GODSEYE ZIP in System Health. The web service stores it only in `/var/lib/godseye/updates`, validates required release files, verifies ZIP integrity and returns SHA-256. Applying requires the exact confirmation `APPLY GODSEYE UPDATE`; GODSEYE creates a database safety backup and invokes `/usr/local/sbin/godseye-apply-update` with the staged path and expected digest. The root helper rejects files outside the staging directory and rechecks the digest.

## Configuration portability
Configuration export intentionally excludes passwords, API tokens, SNMP communities and encryption keys. Import restores non-secret configuration and requires secrets to be re-entered.

## Automatic backups
Daily automatic backups can be enabled with a UTC hour and retained-backup count. They use the same SQLite online backup mechanism as manual backups.

## HTTPS
`godseye-https-setup` configures Nginx as a reverse proxy. Use `self-signed` for a LAN-only appliance or `letsencrypt` when a real DNS name and certificate challenge are available.

## Remediation
Supported actions are deliberately narrow:
- Pi-hole exact domain deny/block.
- UniFi station quarantine/block by MAC address.

Both require an administrator, CSRF validation, an exact action+target confirmation string, a configured integration, and an audit record. GODSEYE does not provide arbitrary command execution or arbitrary controller URLs.
