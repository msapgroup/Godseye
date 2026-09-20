# GODSEYE v4.30.0

GODSEYE v4.30 keeps the proven GODSEYE application as its functional base and improves the areas that needed the most work: the visual experience, user-customizable dashboards, Windows Agent packaging, and Remote Access.

## Interface refresh

- Updated dark GODSEYE visual system with the familiar sidebar and navigation hierarchy.
- Refreshed Dashboard, Devices, Calendar, Email, System Health, Remote Access, and administration surfaces while retaining the established workflows underneath.
- Dashboard uses truthful live appliance/device data rather than placeholder values.
- Dashboard and supported card grids are drag-and-drop customizable per user.
- Layout changes persist per user and include Lock/Unlock and Reset to Default controls.
- The main dashboard panel grid is movable in addition to the summary cards.

## Authentication and upgrades

- Fresh installations keep the built-in `admin` username but ship with no usable default password; the administrator creates the password during first-run setup.
- Existing users, password hashes, enrollment/configuration data, and application data remain upgrade-preserved through the existing migration/backup path.

## Remote Access and Windows Agent 2.3

- Remote support keeps mandatory local Allow/Deny consent in the signed-in Windows user session.
- Explicit session phases: requested, waiting for tray, tray ready, waiting for user, approved, capture started, active, denied/failed/ended.
- The server never accepts an Agent's `active` claim as proof of a working screen stream; a session becomes active only after the server validates the first real JPEG frame.
- JPEG frames are decoded and validated before atomic storage and sequence publication.
- Browser mouse, wheel, and keyboard events are accepted only during an active session and are delivered once in order.
- Tray consent dialogs are marshalled onto the WinForms UI thread for reliable display.
- Screen capture and pointer mapping use the Windows virtual desktop for multi-monitor support.
- Agent 2.3 is a native x64 self-contained .NET 8 Windows service/tray package.
- The guided installer stops the service, writes enrollment configuration, and restarts the service so first installation immediately uses the new server/token settings.
- The Windows build workflow produces MSI/Setup artifacts without committing generated binaries to the source repository.

## Safety and packaging

- The Agent update manifest remains `pending_build` until a genuine 2.3.0 MSI exists and its SHA-256 is verified; old 2.2.x binaries are not relabeled or reused.
- Server release packaging excludes runtime databases, caches, temporary screenshots, and generated test output.
- GitHub is intentionally not modified by this build; the release files are intended for local testing first.
