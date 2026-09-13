# GODSEYE v1.9.0 — UI Stability / Screenshot Match

This release is a focused repair pass after the v18 front-end regression.

## Fixed runtime failures

- Restored the dashboard `load()`/`loadDashboard()` path that v18 boot expected.
- Removed the stale `updated.textContent` reference that could leave **Scan Now** disabled after a click.
- Restored missing Users, Audit, Security, Alert Rules and MFA JavaScript functions.
- Removed recursive device-view routing that could lock the UI.
- Device rows now navigate to a dedicated `/device/{id}` page instead of injecting a hidden global detail panel.
- Removed the old hidden device-detail block from the dashboard document so it cannot appear formatted at the bottom of other pages.
- Dashboard widgets load independently so one failed API does not blank the rest of the page.

## Screenshot-matched UI

- Dark navy GODSEYE sidebar, light workspace, blue active navigation and compact cards/tables.
- Mountain-scene login page with centered eye logo and white sign-in card.
- Dashboard traffic, recent activity, client activity and devices use the compact layout from the reference mockups.
- Dedicated device page includes a **← Back to Devices** control.

## Validation

- 36 pytest tests passed.
- Browser runtime smoke test passed for all 13 sidebar views, dashboard boot, traffic/activity/client widgets, Scan Now completion, device-row navigation, and dedicated device rendering.
- Python and inline JavaScript syntax checks passed.
- Installer and helper shell syntax checks passed.
- Scan API was exercised through FastAPI TestClient: setup → login → CSRF → queue scan → read pending scan status.

Real Raspberry Pi ARP/Nmap/systemd and external Pi-hole/UniFi/SNMP behavior still require the on-device `godseye-release-audit` because this build environment is not the user's LAN.
