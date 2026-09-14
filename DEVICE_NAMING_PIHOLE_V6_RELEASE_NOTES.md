# GODSEYE v2.1 — Device Naming + Pi-hole v6 Authentication

## Device naming

- Discovered devices with no friendly name now show a **Name** action in Device Inventory.
- Already named devices show **Rename**.
- Naming uses the existing persistent `devices.name` field, so scanner refreshes do not overwrite the friendly name.
- The dedicated Device Details page now includes **Rename Device**.
- Device names are trimmed, required to be non-blank, capped at 120 characters, and changes are written through the audited device update API.

## Pi-hole

Pi-hole v6 uses session-based API authentication. Static API-token-as-bearer authentication does not work for normal v6 protected endpoints.

GODSEYE now:

1. Treats the configured Pi-hole credential as a v6 Application Password or web password first.
2. POSTs it to `/api/auth` and receives a short-lived SID.
3. Uses that SID via `X-FTL-SID` for API requests.
4. Falls back to direct SID and legacy v5 `auth=` token behavior for older installations.
5. Supports disabling TLS verification for Pi-hole instances using a self-signed HTTPS certificate.
6. Shows clearer Pi-hole configuration text and uses **Test & Sync** in Integrations.

For Pi-hole v6, create an **Application Password** in Pi-hole Settings and paste that value into GODSEYE's Pi-hole credential field.

## Validation

- 42 automated tests pass.
- Added API test for naming and renaming a discovered device.
- Added Pi-hole v6 Application Password → SID exchange test.
- Added Pi-hole legacy-token fallback test.
- Python, JavaScript, shell-helper, and ZIP integrity checks are part of release packaging.
