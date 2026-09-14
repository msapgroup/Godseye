# GODSEYE Installer Fix

This build fixes the installer failure around the application import check.

- Supports Python 3.9+ (the app modules use future annotations).
- Validates Python before creating the virtual environment.
- Captures and prints the real application import error.
- Installs from the checked-out/extracted files; it does not clone the repository again.
- Keeps optional APT packages from aborting the installation.

Recommended OS: Raspberry Pi OS Bookworm.
