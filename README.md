# GODSEYE V4.28

GODSEYE is a self-hosted network visibility and security appliance designed for Raspberry Pi. It combines Windows event intelligence, ticketing, diagnostics, reporting, and day-to-day network operations in one local interface.

![GODSEYE dark mode overview](docs/screenshots/godseye-dark-mode-overview.png)

## V4.28 release model

V4.28 is a **clean release package**, not a patch bundle and not a repository clone workflow. Extract the ZIP on the Raspberry Pi and run the included installer. Historical patch scripts, old release-note stacks, and the legacy endpoint-compiled Windows Agent are not carried in this release.

The server release and Windows Agent are intentionally versioned independently:

- GODSEYE server: **4.28.0**
- Windows Agent source: **2.2.11 x64**; download the current guided installer from **Event Findings → Windows Agents** or the verified [Windows Agent releases](https://github.com/msapgroup/Godseye/releases)

A GODSEYE server update does not by itself require reinstalling the Windows Agent. The permanent Windows Agent uses the stable GODSEYE Windows Agent API and Windows Installer owns its future upgrade lifecycle.

## Main capabilities

GODSEYE includes device discovery/inventory, topology, monitoring, network findings, Windows Event Findings, Windows Agents, Remote Access with user approval, Ticket Portal, Calendar, Gmail/Microsoft 365 email, reports, Pi-hole/UniFi/SNMP integrations, network tools, notifications, audit history, MFA, backups, retention, HTTPS support, and production update management.

Windows Event Findings can be collected through the permanent x64 Windows Agent or through optional WinRM. The agent is the recommended path because Windows endpoints initiate the HTTPS connection outbound to GODSEYE.

## Fresh Raspberry Pi installation

Copy `GODSEYE-V4.28.zip` to the Raspberry Pi, then:

```bash
unzip GODSEYE-V4.28.zip
cd GODSEYE-V4.28
sudo bash ./install.sh --fresh
```

No `git clone` is required.

The installer installs required Raspberry Pi OS packages, creates the `godseye` service identity, deploys a clean application tree to `/opt/godseye`, creates the Python virtual environment, initializes/migrates SQLite, installs systemd units, validates the application, and starts the services.

On first login, use `admin` and create the administrator password on the setup screen. GODSEYE does not ship with a fixed default password.

## Upgrade an existing GODSEYE appliance

Extract V4.28 to a temporary directory and run:

```bash
sudo bash ./install.sh --upgrade
```

The upgrade preserves `/var/lib/godseye`, `/etc/godseye.env`, the SQLite database, appliance secret, backups, TLS material, users, integrations, Windows Agent enrollment, Event Findings, tickets, and other persistent runtime data. A SQLite backup is created before application replacement.

The V4.28 installer stages only the current release allow-list and replaces the installed application tree cleanly, so obsolete patch/release files from older builds are not retained under `/opt/godseye`.

## Calendar and maintenance planning

GODSEYE includes local maintenance scheduling plus two-way **Google Calendar** and **Microsoft 365** calendar integration through OAuth. Tickets can be scheduled onto the calendar, opened from a calendar appointment, updated with work notes, resolved, and closed while preserving the linked ticket workflow.

## Windows Agent

For Windows workstations and Windows Server, open **Event Findings → Windows Agents** in GODSEYE, create a one-time enrollment token, and download:

`GODSEYE-Windows-Agent-x64-Setup.exe`

Run the installer as Administrator. It installs the real x64 MSI-owned service:

`C:\Program Files\GODSEYE Agent\GODSEYE.Agent.exe`

Persistent identity/configuration remains under:

`C:\ProgramData\GODSEYE\Agent\`

Future agent packages upgrade the same Windows Installer product in place and preserve enrollment. The server also supports hash-verified agent self-update for compatible agent versions.

See `docs/WINDOWS_AGENT.md`.

## Security model

The web application runs as the unprivileged `godseye` account, while privileged network scanning remains isolated in the scanner service. Authentication includes CSRF protection, security headers, account lockout, password controls, TOTP MFA, backup codes, RBAC, and audit logging. Protected integration credentials are encrypted at rest using the appliance key.

Use GODSEYE on trusted LAN/VPN networks. HTTPS is recommended, particularly for Windows Agent enrollment and management.

## Diagnostics

```bash
sudo bash ./install.sh --doctor
sudo /opt/godseye/doctor.sh
sudo systemctl status godseye-web
sudo systemctl status godseye-scanner
```

## Development validation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pytest httpx
python scripts/validate_release.py .
PYTHONPATH=. pytest -q
python -m compileall app
```

Real Raspberry Pi/systemd behavior and real Windows service installation should still be validated on target systems. The V4.28 release validator additionally verifies that the bundled Windows Agent service is x86-64 and that the MSI/update manifest/checksums and build sources use one canonical package naming scheme.
