# GODSEYE v2.4 — Device Icons

This release replaces the generic inventory dot with recognizable device icons and adds a per-device icon picker.

## Device icon picker
- Presets: Router, Switch, Access Point, PC, Laptop, Server, NAS, Camera, Printer, Phone, Tablet, TV, Game Console, IoT, and Other.
- Auto mode infers the icon from the saved device Type.
- Administrators can override the inferred icon from Device Inventory using the new **Icon** action.
- Optional custom icons support PNG, JPEG, and WebP images up to 256 KB.
- Custom images are stored with the device record and can be replaced by selecting any preset icon.

## Where icons appear
- Device Inventory rows.
- Dashboard device list.
- Dedicated Device Details header.

## Security and persistence
- Icon changes use the existing admin-only device PATCH API and are included in the audit trail.
- Custom image MIME types and decoded size are validated server-side.
- SVG presets are shipped locally with GODSEYE; no third-party image services are used.
- Existing databases receive additive `icon_key` and `icon_data` columns automatically.
