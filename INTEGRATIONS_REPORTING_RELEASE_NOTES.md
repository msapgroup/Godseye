# GODSEYE v14 — Integrations + Reporting

This release adds persistent Pi-hole, UniFi and SNMP configuration, automatic background synchronization, integration/client analytics, Prometheus metrics, scheduled network reports, and database-configured notifications.

## Integrations
- Saved Pi-hole URL and optional API token/SID.
- Saved UniFi controller URL, local username/password, site and TLS verification preference.
- Saved SNMP host/community.
- Secrets are never returned through the API after saving. They are stored locally in the GODSEYE SQLite database, which is protected by the appliance service/data directory permissions; they are not application-level encrypted in this release.
- Background synchronization runs independently for each enabled integration and records success/failure history.
- Manual **Sync Now** is available from the Integrations screen.
- Successful observations are fed into the same device correlation/topology engine introduced in v13.

## Analytics
- Latest per-integration analytics snapshots.
- Discovery-source device counts.
- Pi-hole summary-query support is best-effort across common v5/v6 endpoints because Pi-hole API shape depends on deployed version/authentication.
- UniFi active client and Wi-Fi client counts.
- SNMP neighbor counts.

## Prometheus
`GET /metrics` exposes count-only Prometheus text metrics for device state, findings, monitors and integration health. It intentionally does not expose credentials, IP addresses or MAC addresses.

## Reports
- Live network summary API/UI.
- Generate-now reports retained in SQLite.
- Hourly, daily and weekly report schedules.
- Scheduled reports can be delivered through configured notification channels.

## Notifications
- Generic JSON webhook.
- ntfy.
- SMTP email with STARTTLS.
- Findings are deduplicated by finding ID.
- New topology devices learned through an integration sync can emit a topology-change notification.
- Scheduled reports use the configured channels even when the normal event severity threshold is higher than informational.

## Validation
- Existing regression suite plus v14 tests.
- Python compile checks.
- Bash installer syntax check.
- Dashboard JavaScript syntax check with Node.
