# GODSEYE v20 — Dashboard Drill-down + Network Map UI

## Dashboard summary navigation

The four dashboard summary cards are now interactive:

- **Total Devices** opens the complete Device Inventory.
- **Online** opens Device Inventory pre-filtered to online devices.
- **Issues** opens Network Findings.
- **Monitors** opens Monitoring.

Views entered from a dashboard summary card show a **← Back to Dashboard** action. Manual sidebar navigation clears the dashboard-return state so normal navigation stays predictable.

## Network Map redesign

The topology view was rebuilt as an operator-friendly GUI with:

- Gateway, discovered-node, relationship, and last-updated summary cards.
- Search/highlight by device name, IP, MAC, vendor, type, or status.
- Fit, zoom-in, and zoom-out controls.
- Clickable discovered-client nodes that open device details.
- Status- and type-aware node styling.
- Relationship/evidence badges.
- Legend, usage help, and evidence-source panel.
- Responsive layout and a scrollable topology viewport for larger networks.

## Validation

- Full pytest suite: 38 passed.
- Python syntax/compile checks: passed.
- Dashboard inline JavaScript: passed `node --check` for all script blocks.
- Installer/release helper shell syntax: passed.
- GitHub Actions workflow includes the `httpx` test dependency required by FastAPI/Starlette TestClient.

Live Raspberry Pi topology and discovery still require validation on the target appliance because this build environment cannot run against the user's physical LAN.
