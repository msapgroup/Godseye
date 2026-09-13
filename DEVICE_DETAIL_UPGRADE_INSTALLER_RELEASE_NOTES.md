# GODSEYE v2.8.0 — Device Detail Fix + Unified Installer/Updater

## Device detail crash fixed

The dedicated `/device/{id}` page referenced the dashboard-only `deviceIconAsset()` JavaScript helper. Opening a device could therefore fail with:

`Unable to load device: deviceIconAsset is not defined`

The device detail page now defines its own icon asset helper before device data is loaded, including the same icon cache-busting behavior used by Device Inventory.

## One installer for fresh installs and upgrades

`install.sh` now auto-detects whether GODSEYE already exists:

- No existing install: performs the complete Raspberry Pi installation.
- Existing install: performs an in-place upgrade without requiring a reinstall.
- `--fresh` and `--upgrade` are available when an explicit mode is desired.
- `--doctor` remains available for installation diagnostics.

Upgrade behavior:

- Stops the web/scanner services safely.
- Creates a pre-upgrade SQLite backup under `/var/lib/godseye/install-backups`.
- Preserves `/var/lib/godseye`, the database, encryption key, backups, TLS material, staged updates, and exported configuration.
- Preserves an existing `/etc/godseye.env` instead of overwriting custom settings.
- Replaces application code with the new release while excluding the virtual environment and transient caches.
- Rebuilds the Python virtual environment from the release requirements.
- Runs application import/schema migrations and SQLite integrity/write checks.
- Refreshes systemd units and production helper scripts.
- Restarts and verifies both GODSEYE services.

## Validation

- Full automated pytest suite passes.
- Dedicated device detail icon helper regression coverage added.
- Unified installer behavior regression coverage added.
- Python, JavaScript, and shell syntax checks pass.
