# GODSEYE Fresh Install

This repository is a **new-install distribution**, not an upgrade package.

The installer copies the repository you are running into `/opt/godseye`; it does **not** clone the GitHub repository a second time. This makes installation work from a fresh Git checkout or an extracted release ZIP even before the GitHub repository is public.

## Install

```bash
sudo apt update
sudo apt install -y git
sudo git clone https://github.com/msapgroup/Godseye.git /tmp/godseye-install
cd /tmp/godseye-install
sudo bash install.sh
```

If installation fails, run:

```bash
sudo bash install.sh --doctor
```

For service logs:

```bash
sudo journalctl -u godseye-web -n 100 --no-pager
sudo journalctl -u godseye-scanner -n 100 --no-pager
```

## Fresh-install behavior

The installer refuses to touch an existing `/opt/godseye` directory. It creates a fresh SQLite database and service account and installs two systemd services.

## First login

The installer generates a random administrator password unless `GODSEYE_ADMIN_USER` and `GODSEYE_ADMIN_PASSWORD` are supplied.
