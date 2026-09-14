# GODSEYE v4.14 — Two-Way Calendar OAuth

- Removes the practical read-only limitation for Google Calendar and Microsoft 365 by adding OAuth-based two-way synchronization.
- Google Calendar uses the Calendar API with edit scope.
- Microsoft 365 / Outlook uses Microsoft Graph with delegated Calendars.ReadWrite access.
- Connected provider events can be created, edited and deleted from GODSEYE and changes are sent back to the provider.
- Provider-side changes are synchronized back into GODSEYE on demand and by the automatic calendar sync manager.
- Event creation can target the local GODSEYE calendar or any connected writable calendar.
- OAuth client secrets, access tokens and refresh tokens are encrypted at rest.
- OAuth state is persisted with a short expiration to protect the authorization callback.
- `GODSEYE_PUBLIC_URL` can be used when the appliance is behind HTTPS/reverse proxy so the OAuth redirect URI is externally reachable.
- Private ICS subscription mode remains available as a read-only fallback.
- The dark-mode calendar screenshot pack is refreshed to show a two-way connected calendar.
