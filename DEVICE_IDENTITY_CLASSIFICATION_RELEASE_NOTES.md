# GODSEYE v2.3 — Device Identity & Classification

This release makes device identity directly manageable from Device Inventory and the dedicated Device Details page.

## Device Inventory
- Adds a visible **Classification** column.
- Adds a **Classify** action for every discovered device.
- Classify editor supports device type such as Router, PC, Laptop, Camera, Switch, Access Point, Phone, Tablet, Printer, Server, NAS, TV / Media, IoT, Smart Home, Game Console, or a custom value.
- Lifecycle classification now supports **New → Investigate → Known → Managed**, with **Ignored** retained for devices intentionally excluded from normal review.

## Device Details → Identity
- Hostname is now editable.
- Device Type is now editable with common device-type suggestions while still allowing a custom value.
- Classification is now a dropdown with New, Investigate, Known, Managed, and Ignored.
- **Save Identity** updates all three fields together.
- IP address, MAC address, vendor, first-seen, and last-seen remain read-only discovery facts.

## API
`PATCH /api/v1/devices/{id}` now accepts `hostname` in addition to name, type, classification, and notes. Hostname/type length validation is enforced and all changes continue to be recorded in the audit log.
