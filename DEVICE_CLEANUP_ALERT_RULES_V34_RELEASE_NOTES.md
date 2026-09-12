# GODSEYE v3.4 — Device Cleanup + Expanded Alert Rules

## Device Inventory cleanup
- Added an admin-only Delete action to each inventory row.
- Added a Clean Up Devices modal with two modes: delete matching offline devices, or delete old devices not seen for a chosen number of days.
- Old-device cleanup never removes currently-online devices.
- "Keep Known and Managed devices" is enabled by default for bulk cleanup.
- Device-owned event/source/IP history and direct topology/issue evidence are cleaned with the device; audit history is preserved.
- Deleted devices can be rediscovered later if they return to the network.

## Alert Rules
Expanded from 2 rule types to 7:
- New device burst
- Offline duration
- IP address changes
- Device reconnects
- Offline device count
- Scanner not reporting
- Classification count

Count/burst rules include cooldown behavior to avoid repeated alerts every scanner cycle while a condition remains true.
