# GODSEYE v4.24.0

GODSEYE v4.24 packages the current GODSEYE application as a complete install-or-upgrade release.

## Installation modes

The same release directory supports both deployment paths:

- Fresh installation: `sudo bash ./install.sh --fresh`
- Existing installation upgrade: `sudo bash ./install.sh --upgrade`
- Auto-detect: `sudo bash ./install.sh`

Upgrades preserve `/var/lib/godseye`, `/etc/godseye.env`, the existing SQLite database, appliance secrets, TLS material, backups, configuration, users, Windows Agent enrollment state, and other persistent runtime data. The installer creates a pre-upgrade SQLite backup before replacing application files.

## Included in v4.24

- All GODSEYE functionality present on the v4.23 release line
- Dark-mode operator interface
- Remote Access workspace with the `api is not defined` client-side failure corrected
- Windows Agent 2.2.1 remote desktop support for authorized sessions
- GODSEYE Windows Agent system-tray icon, status window, portal shortcut, and visible approval dialog
- Windows Agent MSI and guided Setup EXE packages
- Windows Agent self-update support
- Existing production management, backups, retention, diagnostics, integrations, reporting, ticketing, calendar, event findings, and network visibility features

## Server update package

The v4.24 release workflow creates a full server ZIP containing the complete source release plus the generated Windows Agent 2.2.1 binaries. The ZIP can be extracted and installed with `install.sh`, and is also suitable for GODSEYE's staged ZIP updater on installations that already expose that update UI.

A SHA-256 checksum is generated alongside the ZIP.
