# GODSEYE v2.9.0 — Dynamic Version Display

The login screen now reads its displayed version directly from the installed `VERSION` file at runtime instead of using a hard-coded release number.

This means future fresh installs and in-place upgrades automatically show the newly installed release version after the web service restarts.

## Upgrade behavior
- `install.sh` continues to copy the release `VERSION` file into `/opt/godseye`.
- The web app reads `/opt/godseye/VERSION` at process startup.
- The login footer renders that runtime version.
- No separate UI version string needs to be edited in future releases.
