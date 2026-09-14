# GODSEYE v4.16 — Report Management + Email Client

## Report History
- Adds an administrator-only Delete action to each generated report.
- Adds row selection, Select All, and Delete Selected for bulk cleanup.
- Report deletion is audited with report IDs, titles, report type, and actor.
- Adds Email Report so generated PDF or CSV reports can be sent directly through a connected mailbox.

## Email under Management
- Adds Email directly below Calendar in the Management sidebar for admin/operator roles.
- Supports Gmail through Gmail API OAuth.
- Supports Microsoft 365 / Outlook through Microsoft Graph OAuth.
- OAuth client secrets, access tokens, and refresh tokens are encrypted at rest.
- Supports Inbox/folder browsing, unread counts where exposed by the provider, search, message reading, attachments, unread/read state, stars/flags, Trash/Deleted Items, Compose, Save Draft, Reply, Reply All, and Forward.
- Compose supports To, CC, BCC, subject, body, and file attachments.
- Gmail send/draft uses RFC 2822 MIME encoded through the Gmail API.
- Microsoft 365 send/draft uses Microsoft Graph mail endpoints.
- Generated reports can be attached and emailed as PDF or CSV without downloading them first.
- Mailbox access is limited to administrator/operator roles; mail account configuration remains administrator-only.
- `GODSEYE_PUBLIC_URL` is supported for OAuth callback URL generation behind HTTPS/reverse proxy.

## Screenshots
- Adds `docs/screenshots/dark-email.png`.
- Refreshes `docs/screenshots/dark-reports.png` to show report deletion and Email Report.
- Refreshes the dark-mode overview montage.

## Validation
- Automated tests cover schema, OAuth/security plumbing, Report History deletion, Gmail/Microsoft endpoints, dark UI, and report-email attachment generation.
- Live Gmail and Microsoft 365 account authorization is not performed in the build container.
