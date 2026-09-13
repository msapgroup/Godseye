# Integrations + Reporting

## Saved integrations
Open **Integrations** in GODSEYE and configure Pi-hole, UniFi, or SNMP. Each enabled integration has its own synchronization interval (minimum 30 seconds). Background sync runs inside the unprivileged GODSEYE web service and writes observations into the shared SQLite device-intelligence store.

### Pi-hole
Provide the Pi-hole base URL and, where required, an API token/session ID. GODSEYE attempts common Pi-hole v6/v5 summary and client/network endpoints. API compatibility varies by Pi-hole release, so the latest sync result shows endpoint/authentication errors rather than hiding them.

### UniFi
Provide the controller URL, local controller username/password, site (usually `default`), and TLS verification preference. For self-signed local controllers, TLS verification may be disabled explicitly.

### SNMP
Provide the router/switch IP or hostname and SNMPv2c community. `snmpwalk` is installed by the fresh installer. Prefer a read-only community restricted to the GODSEYE Raspberry Pi address.

## Credential storage
Integration and SMTP secrets are stored in `/var/lib/godseye/godseye.db`. API responses only report whether a secret exists; they never return it. v14 does not implement application-level encryption of these local secrets. Protect Raspberry Pi root access and backups accordingly.

## Prometheus
Scrape `http://GODSEYE:8080/metrics`. Metrics are aggregate/count-only. The endpoint is intentionally suitable for local Prometheus scraping and contains no device identifiers.

## Scheduled reports
The Reports screen can create hourly, daily, or weekly network-summary schedules. The background reporting manager generates reports into SQLite and optionally delivers them using the notification channels.

## Notifications
The Integrations screen can configure webhook, ntfy, and SMTP/STARTTLS channels. Finding alerts are deduplicated. Integration-driven discovery of previously unknown devices produces a topology-change warning. Scheduled report delivery bypasses the normal event severity filter so report delivery is not accidentally suppressed.
