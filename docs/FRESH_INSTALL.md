# Fresh installation

V4.28 is distributed as a complete release ZIP. It does not require cloning a previous GODSEYE repository.

```bash
unzip GODSEYE-V4.28.zip
cd GODSEYE-V4.28
sudo bash ./install.sh --fresh
```

The installer validates the release before deployment, installs required Raspberry Pi OS packages, creates the service account, deploys the current application allow-list to `/opt/godseye`, builds the virtual environment, initializes the database, installs the systemd services, and confirms both services are active.

Persistent data is stored in `/var/lib/godseye` rather than in the application directory.
