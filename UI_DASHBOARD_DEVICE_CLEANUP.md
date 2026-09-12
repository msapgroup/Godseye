# GODSEYE v1.8.0 — Dashboard + Device Page Cleanup

This release fixes live dashboard widgets and restructures device navigation.

## Dashboard
- Live Network Traffic now has independent error handling, live rate labels, sample state and interface details.
- Recent Activity loads independently from traffic and health.
- Client Activity is populated from observed per-device activity evidence and links into the device page.
- Devices on the dashboard are clickable and use the correct seven-column layout.
- Monitor totals are queried from saved monitor settings instead of a hard-coded value.

## Device workflow
Clicking a device opens a dedicated in-app page. The page includes a Back to Devices arrow/button, identity, risk, evidence sources, recent events, IP history, findings and recommendations. Diagnostics and recheck stay on that device page.

## UI cleanup
The legacy device modal was removed from the rendered document. This prevents the prior Device Intelligence block from appearing formatted at the bottom of pages. The overall interaction pattern is inspired by NetAlertX's dense network-management UI, without copying its source or branding.
