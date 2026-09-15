# GODSEYE release audit

Audited failure modes from previous builds:

- Shared SQLite database path: `/var/lib/godseye/godseye.db`.
- Web and scanner use the same database.
- Scanner runs as root for ARP discovery and has write access to the shared data directory.
- Manual Scan Now uses the SQLite `scan_requests` queue and scanner polling.
- Add Device uses a real POST endpoint with MAC validation.
- Browser mutating API calls use the CSRF helper.
- First-login account is exactly `admin` with a user-created password.
- The eye logo is inline SVG and appears on the login/sidebar/tool/monitoring screens without a static-file dependency.
- Native discovery and diagnostic programs are installed by the fresh installer and checked before services start.
- `install.sh --doctor` reports native tool and service availability.

This audit does **not** claim that every plugin-manifest connector is complete. Unsupported connectors remain explicitly non-production until implemented and tested.
