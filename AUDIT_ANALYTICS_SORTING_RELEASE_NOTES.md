# GODSEYE v2.2 — Protected Audit Clearing, Analytics Clearing, and Sortable Lists

## What changed

- Admins can clear **Client & Query Analytics** only after providing a reason. The actor, reason, and number of deleted analytics snapshots are written to the audit log.
- Admins can clear the **Audit Log** only after providing a reason. GODSEYE preserves any still-protected audit-clear records, deletes eligible records, then writes a fresh `audit_log_cleared` event containing the username and reason.
- Every new `audit_log_cleared` record receives a 7-day `protected_until` hold and cannot be removed by another clear operation until that hold expires.
- Audit-clear rows are visually highlighted in the UI while protected.
- Device inventory, findings, monitoring, audit, reports, users, and other tabular lists now support click-to-sort column headers. IPv4 values sort numerically instead of alphabetically. Dates and numeric values also receive numeric sorting when detected.
- Destructive clear controls are admin-only. Auditor accounts remain read-only.

## Data safety

Clearing Client & Query Analytics deletes retained integration analytics snapshots only. It does not delete the device inventory, discovery records, findings, or integration configuration.

## Audit retention guarantee

The audit clear operation excludes rows whose `protected_until` value is still in the future. The newly created audit clear event is protected for exactly 7 days from the clear operation.
