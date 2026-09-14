# GODSEYE v4.19 — Event Finding Cleanup

## Windows Event Findings
- Adds an admin-only checkbox column to Windows Event Findings.
- Adds **Select All** and **Delete Selected** with confirmation.
- Adds an admin-only **Delete** action on every finding row and in the Event Finding detail modal.
- Adds **Delete Old Findings** for resolved findings older than 7, 30, 90, 180, or 365 days. Open findings are never removed by age cleanup.
- Adds Event Finding search across computer, provider, title, message, category, and Event ID.
- Adds Refresh and visible/selected counts.
- Linked Ticket Portal records are preserved when a finding is deleted. Their source is marked `event_finding_deleted` so ticket history remains intact.
- Pending Windows Agent recheck rows for deleted findings are removed.
- Single, bulk, and age-based deletion actions are written to the audit log.

## Permissions
Deletion is **administrator-only**. Operators can continue to Recheck, Create Ticket, and Resolve according to existing permissions, but cannot delete findings.

## Screenshot
`docs/screenshots/dark-event-findings.png` is refreshed to show the new selection and delete controls.
