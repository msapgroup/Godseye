# GODSEYE v3.2 — Integration Removal

- Adds a clearly visible **Remove** action to every saved Pi-hole, UniFi, and SNMP integration card for administrators.
- Adds a dedicated confirmation modal showing the integration name, type, and target.
- Requires typing `REMOVE` before deletion to prevent accidental removal.
- Removing an integration now deletes its saved configuration, retained analytics snapshots, and integration sync history.
- Device inventory and the audit log are intentionally preserved.
- Records the removed integration and deleted-history counts in the audit log.
- Supports backdrop, Cancel, X, and Escape dismissal before confirmation.
