# GODSEYE v3.5 — Device Delete Visibility + Audit Reason

## Device Inventory delete fix
- Re-applies admin-role visibility after the Device Inventory table is dynamically rendered.
- The per-device **Delete** button is now visible to administrators after every inventory refresh/filter/search.
- Clicking Delete opens a centered confirmation modal instead of using a browser confirm dialog.

## Required deletion reason
- Individual device deletion now requires a reason (3–500 characters).
- Bulk device cleanup also requires a reason.
- Audit entries retain the actor, device/cleanup target, reason, relevant device metadata, and deleted count.

## Safety filters removed as requested
- Removed the “Keep Known and Managed devices” exclusion.
- Old-device cleanup no longer excludes currently-online devices.
- `old` cleanup deletes any inventory record whose `last_seen` is older than the selected cutoff.
- `offline` cleanup deletes all devices currently marked offline.

## Audit behavior
- Device-owned event/source/IP history is deleted with the inventory record.
- The administrative Audit Log remains preserved and records the deletion reason.
- A rediscovered device may be added to inventory again later.
