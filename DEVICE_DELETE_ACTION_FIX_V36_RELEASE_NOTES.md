# GODSEYE v3.6 — Device Delete Action Fix

Fixes the visible-but-nonfunctional Device Inventory Delete button introduced in v3.5.

## Root cause
The dynamically rendered Delete button embedded JSON-quoted device names/status values directly inside a double-quoted HTML `onclick` attribute. A normal device name produced nested quotes, causing the browser to parse a broken/truncated click handler.

## Fix
- Delete buttons now carry device identity in escaped `data-delete-*` attributes.
- A dedicated `openDeleteDeviceFromButton()` handler reads those values safely.
- The existing reason-required delete modal and audit trail are retained.
- Successful deletion now gives explicit UI confirmation.
- Admin visibility is still reapplied after each inventory render.
