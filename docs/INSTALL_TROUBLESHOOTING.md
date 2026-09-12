# GODSEYE SQLite installation fix

GODSEYE runtime data is stored in `/var/lib/godseye`, not inside the application source directory.

The web service runs as the `godseye` user, and the installer explicitly assigns ownership of both `/opt/godseye` and `/var/lib/godseye` to that account.

Use:

```bash
sudo bash install.sh --doctor
sudo journalctl -u godseye-web.service -n 100 --no-pager
```

If a previous failed installation left an old database with incorrect ownership, remove the old installation before a fresh install:

```bash
sudo systemctl disable --now godseye-web.service 2>/dev/null || true
sudo rm -rf /opt/godseye /var/lib/godseye /etc/godseye.env
```

Then run the installer again.
