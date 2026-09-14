# GODSEYE v4.17 — Windows Event Findings + Ticket Portal

## Windows Event Findings
- Adds **Event Findings** under Management.
- Adds agentless Windows Event Log collection over **WinRM HTTPS** for 64-bit Windows workstations and Windows Server.
- Queries only Event Log levels 1, 2, and 3: Critical, Error, and Warning.
- Saves a per-host, per-channel Event Record ID bookmark so later pulls request only newer events.
- Default channels are System and Application; additional channels can be configured per host.
- Stores WinRM passwords encrypted at rest with the GODSEYE appliance key.
- Defaults to TLS certificate verification and supports NTLM or Basic authentication over HTTPS.
- Adds automatic polling plus **Pull Events Now** for on-demand collection.
- Repeated matching events increase an Event Finding occurrence counter instead of creating endless duplicates.
- Reopens a resolved Event Finding if the same problem occurs again.
- Adds rule-based classification and remediation guidance for storage/disk, NTFS/storage timeouts, WHEA hardware faults, unexpected shutdown/power, Windows services, Windows Update, Microsoft Defender, VSS/backup, and application errors.
- Event Findings include Suggested Fix, Recheck, Resolve, Create Ticket, raw event message, event ID, provider, channel, computer, severity, occurrence count, and timestamps.
- Recheck performs a fresh source pull and reports whether another matching event occurred.
- Includes `windows/GODSEYE-WinRM-EventLog-Setup.ps1` and `docs/WINDOWS_EVENT_FINDINGS.md`.

## Ticket Portal
- Adds **Ticket Portal** under Management.
- Supports manual tickets plus ticket creation from Network Findings and Event Findings.
- Ticket fields include ticket number, title, description, priority, assignee, linked source, affected system/device, status, due time, created/updated timestamps, and work notes.
- Statuses: Open, Assigned, In Progress, Waiting, Resolved, Closed.
- Priorities: Low, Medium, High, Critical.
- Tickets can be scheduled onto GODSEYE Calendar.
- Ticket calendar events stay linked to the ticket; changing the calendar time updates the ticket due time.
- Linked ticket events show a ticket marker on Calendar.
- Calendar appointment popups provide Open Ticket, Add Work Note, Resolve, and Close Ticket actions.
- Closing a ticket can optionally resolve its linked Event Finding or Network Finding.
- Closed/resolved ticket events are shown green and marked complete on Calendar.
- Ticket actions are audited.

## Screenshots
- Adds `docs/screenshots/dark-event-findings.png`.
- Adds `docs/screenshots/dark-ticket-portal.png`.
- Refreshes `docs/screenshots/dark-calendar.png` with the linked-ticket workflow.
- Refreshes the dark-mode overview montage.

## Security / validation note
Real Windows hosts and WinRM hardware/network conditions are not available in the build container. Automated tests validate filtering, bookmarks, event classification, finding deduplication, ticket/calendar workflow, encryption plumbing, API/UI integration, and regression behavior. A first live Windows pull should be validated on the target Raspberry Pi and trusted Windows LAN.
