# GODSEYE v4.21 — Ticket Assignee User Picker

## Ticket Portal
- Replaces the free-text Assignee field with a dropdown populated from users configured in GODSEYE.
- Shows `Display Name (username) · role` when a display name exists.
- Falls back to the username for existing accounts without a display name.
- Includes an explicit Unassigned option.
- Operators can use the picker without receiving access to password hashes, MFA data, or other sensitive user-management fields.
- New ticket assignments are validated server-side against existing GODSEYE users.
- Existing legacy free-text ticket assignments remain visible and can be preserved until reassigned.

## User administration
- Adds an optional Display Name field when creating a GODSEYE user.
- Adds display names to the Users table.
- Existing databases are migrated with a nullable-equivalent empty display name default; no account recreation is required.

## UI / screenshots
- Keeps the dark screenshot documentation synchronized.

## Security
- The ticket assignee directory exposes only user ID, username, display name, and role.
- User-management permissions remain unchanged.

Historical screenshots from this release were retired during the v4.31 branding refresh. See `docs/SCREENSHOTS.md` for the current image gallery.
