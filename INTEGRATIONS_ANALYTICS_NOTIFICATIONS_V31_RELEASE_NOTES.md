# GODSEYE v3.1.0 — Integrations, Analytics & Notifications UI

## Highlights
- Multiple saved Pi-hole, UniFi, and SNMP integrations are now supported.
- Existing single-integration databases migrate in place without wiping credentials or sync history.
- Each integration instance has its own name, target, enabled state, sync interval, status, sync action, and retained analytics.
- Client & Query Analytics are now presented as clickable cards. Each card opens a focused analytics dialog with metrics, raw synchronized data, and a reason-required clear action for only that integration.
- Legacy analytics/sync history is attached to the matching migrated integration when possible.
- Notifications are reorganized into clearly described Webhook, ntfy, and Email/SMTP channel cards with shared severity and test/save controls.
- Existing global analytics clearing and audit accountability remain available.

## Compatibility
- Fresh installs create the multi-instance integration schema directly.
- Upgrades migrate the prior unique-by-kind integration table automatically.
- Existing device discovery, topology, reporting, remediation, retention, and notification functionality is retained.
