# GODSEYE v4.20 — Event Finding + Ticket Cleanup

## Windows Event Findings
Carries forward the v4.19 administrator cleanup controls: single delete, Delete Selected, and age-based cleanup of resolved Event Findings. Linked tickets remain preserved when their source finding is deleted.

## Ticket Portal cleanup
- Adds administrator-only selection checkboxes to Ticket Portal.
- Adds **Delete Selected** for intentional bulk cleanup.
- Adds an administrator-only **Delete** action on each ticket and **Delete Ticket** inside the ticket editor.
- Adds **Delete Old Tickets** with 7, 30, 90, 180, and 365 day choices.
- Age cleanup deletes only `resolved` and `closed` tickets older than the selected age. Open, assigned, in-progress, and waiting tickets are never removed by age cleanup.
- Deleting a ticket removes its ticket notes and linked local GODSEYE ticket-calendar appointment.
- Linked Network Findings and Windows Event Findings are preserved.
- Single, selected, and old-ticket cleanup operations are written to the audit log.
- Bulk delete is capped at 200 tickets per request.

## Permissions
All destructive cleanup controls are administrator-only.

## Screenshots
The dark Ticket Portal screenshot is refreshed to show selection, Delete Selected, Delete Old Tickets, per-row Delete, and the completed-ticket cleanup workflow. The dark screenshot overview is refreshed as well.
