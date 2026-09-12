# GODSEYE v1.6.0 — Production Appliance Management + Automated Response

This release adds production appliance controls on top of v1.5.

## New capabilities
- Controlled offline ZIP updates: stage, SHA-256 verify, ZIP integrity/preflight, safety backup, explicit APPLY confirmation, root-owned apply helper, update history.
- Non-secret configuration export/import for integrations, monitors, rules, report schedules, notification endpoints, retention and production settings.
- Scheduled daily SQLite backups with configurable UTC hour and retained backup count.
- Notification delivery history and retry actions.
- HTTPS helper using Nginx with self-signed TLS or Let's Encrypt.
- Role-aware permissions: admin, operator, auditor and read-only. Operators can run scans/rechecks/monitor runs/integration sync/report generation; auditors can access audit data; security/configuration/remediation remain admin-only.
- Rich audit search and CSV export.
- Explicit-confirmation remediation actions limited to configured local integrations: Pi-hole domain deny and UniFi client quarantine.

## Safety model
Remediation never accepts an arbitrary controller URL. It uses only saved GODSEYE integration targets and requires an exact confirmation phrase that includes the action and target. Software updates require an admin session, CSRF protection, a staged ZIP, preflight, matching SHA-256, an automatic pre-update DB backup, and a fixed privileged helper.

## HTTPS
Run on the Raspberry Pi as root after installation:

    sudo godseye-https-setup godseye.local self-signed

For a public DNS name that resolves to the appliance:

    sudo godseye-https-setup godseye.example.com letsencrypt

## Important interoperability note
Pi-hole and UniFi have multiple API generations. GODSEYE v1.6 tries common Pi-hole v6/v5 deny-list variants and UniFi OS/legacy login and station-manager variants. Controller policy, API version, permissions, and TLS settings can still affect whether the remote action succeeds.
