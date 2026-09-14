# GODSEYE

GODSEYE is a self-hosted network visibility and security appliance designed for Raspberry Pi. It gives administrators a single local dashboard for discovering devices, monitoring availability, investigating changes, reviewing security findings, collecting network evidence, and operating common diagnostic tools without sending the network inventory to a cloud service.

![GODSEYE dark mode overview](docs/screenshots/godseye-dark-mode-overview.png)

## What GODSEYE is for

GODSEYE helps a home, small business, lab, or managed network answer practical security questions: What is connected right now? What device just appeared? Which known device changed IP addresses? What systems have gone offline? Are important websites and services responding? Are DNS, packet loss, or reachability problems recurring? Which findings need investigation? What changed while nobody was watching?

It is designed as an operator-facing network appliance rather than a passive device list. Discovery, monitoring, findings, diagnostics, integrations, reporting, audit history, and controlled administrative actions are brought together in one interface.

## Network security capabilities

- **Device discovery and inventory** — discovers local devices and tracks first/last seen state, IP history, status, identity, classification, device type, friendly names, and icons.
- **Change detection** — records new-device, disconnect, reconnect, IP-change, and related network events so unexpected changes can be investigated.
- **Device intelligence** — correlates discovery evidence, history, findings, diagnostics, topology, and risk information around each device.
- **Monitoring and findings** — continuously checks configured services and turns repeated failures, packet loss, DNS problems, offline devices, and service failures into actionable findings.
- **Alert rules** — supports rules for device bursts, offline duration, IP changes, reconnect activity, scanner health, classification counts, and other operational conditions.
- **Network topology** — combines available discovery evidence into a network map showing devices and observed relationships.
- **Per-device traffic infrastructure** — supports explicitly configured UniFi/controller, SNMP, SPAN/mirror, and inline/gateway traffic sources. GODSEYE only reports per-device byte accounting when the selected source can actually observe or provide those counters.
- **Integrations** — supports multiple Pi-hole, UniFi, and SNMP configurations with synchronization and health information.
- **Network tools** — provides authenticated Ping, Traceroute, DNS Lookup, Port Scan, Device Information, Network Discovery, Wake-on-LAN, gateway checks, Internet checks, and website monitoring.
- **Calendar and maintenance planning** — provides a Google Calendar-inspired month view for appointments, maintenance windows, reviews, reminders, and network-security work, with local CRUD plus two-way Google Calendar and Microsoft 365 synchronization through OAuth. Private ICS subscriptions remain available as a read-only fallback. Double-click any date in the month grid, including past dates, to open a new appointment already set to that day.
- **Email client** — adds a Management-side Gmail and Microsoft 365 mailbox client with OAuth, inbox/folder browsing, search, message reading, unread/star controls, attachments, compose, drafts, reply/reply-all/forward, trash, and direct emailing of generated GODSEYE reports.
- **Windows Event Findings** — the recommended GODSEYE Windows Agent reads only Critical, Error, and Warning records locally on 64-bit Windows workstations and Windows Server, queues them durably, and sends them outbound to GODSEYE over HTTPS. WinRM remains available as an agentless fallback. Repeated events are grouped into findings with Suggested Fix, Recheck, Resolve, and Create Ticket workflows.
- **Ticket Portal** — tracks manual, Network Finding, and Event Finding work with priority, assignee, status, notes, linked systems, calendar scheduling, and closure. Ticket assignees are selected from GODSEYE application users, with optional display names shown in the picker. Scheduled tickets appear on Calendar and can be opened, noted, resolved, or closed directly from the calendar appointment.

- **Reporting** — generates Network Summary, Device Inventory, Security Findings, Availability & Monitoring, Integrations Health, Traffic Usage, Audit Activity, and Device Changes reports with CSV/PDF export.
- **Notifications** — supports webhook, ntfy, and SMTP delivery for important events and findings.
- **Audit and administration** — provides role-based access, audit history, MFA, controlled cleanup actions, backups, retention settings, configuration portability, and staged updates.

## Security model

GODSEYE is local-first. The web application runs as the unprivileged `godseye` service account. Privileged network collection is separated into services that receive only the permissions needed for their job. Integration credentials and other protected secrets are encrypted at rest with the appliance key.

Authentication includes session protection, CSRF defenses, security headers, account lockout, password controls, TOTP MFA with backup codes, and role-based permissions for `admin`, `operator`, `auditor`, and `readonly` users.

GODSEYE is intended for trusted LAN or VPN access. Do not expose the application directly to the public Internet. HTTPS can be configured through the included Nginx helper. For Windows Event collection, prefer the GODSEYE Windows Agent over outbound HTTPS. If WinRM is used as the agentless fallback, use WinRM over HTTPS with a dedicated least-privilege Event Log Readers account and do not expose WinRM directly to the public Internet.

## Raspberry Pi installation

GODSEYE is installed directly on Raspberry Pi OS; Docker is not required.

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/msapgroup/Godseye.git /tmp/godseye-install
cd /tmp/godseye-install
sudo bash ./install.sh
```

For an existing installation:

```bash
sudo bash ./install.sh --upgrade
```

Useful maintenance commands:

```bash
sudo bash ./install.sh --doctor
sudo systemctl status godseye-web
sudo systemctl status godseye-scanner
```

The installer creates the service account and data directories, installs required packages and the Python environment, initializes or migrates SQLite, installs systemd services, validates the application, and starts the appliance. The first-login workflow creates the administrator password; GODSEYE does not ship with a fixed default password.

## Using GODSEYE for network security

Start with **Devices** to classify known equipment and investigate anything unfamiliar. Use **Network Map** to understand observed relationships, **Monitoring** to watch important infrastructure and services, and **Findings** to work recurring failures or suspicious changes.

Use **Alert Rules** for conditions that should receive attention automatically. **Event Findings** extends that workflow to Windows computers and servers. The recommended **GODSEYE Windows Agent** runs locally as a Windows service, reads selected Critical/Error/Warning Event Log records, keeps per-channel Event Record ID bookmarks, queues unsent batches during outages, and sends them outbound to GODSEYE over HTTPS. Recurring hardware, disk, WHEA, service, update, Defender, VSS, and application errors become explainable findings. WinRM remains available as an agentless fallback. Findings can be rechecked, resolved, or converted into **Ticket Portal** work items.

**Ticket Portal** tracks operational work from discovery through closure. Administrators can delete individual or selected tickets and clean up old resolved/closed tickets by age; linked findings are preserved while the deleted ticket's work notes and local ticket-calendar appointment are removed. Tickets can be created manually or from Network Findings and Event Findings, assigned, given priorities, documented with work notes, and scheduled directly onto **Calendar**. Calendar appointments linked to tickets can add work notes, mark the ticket resolved, or close it after the work is complete. **Calendar** also supports OAuth-connected Google Calendar and Microsoft 365 calendars, while ICS subscriptions remain available for read-only imports. **Integrations** can add controller, DNS, switch, or router context. **Reports** provide inventory, security, availability, traffic, audit, and change records for periodic review. Generated Report History entries can be emailed through a connected mailbox or deleted individually/in bulk by an administrator. **System Health** covers the GODSEYE appliance itself, including backups, retention, diagnostics, metrics security, and production management.

For traffic visibility, choose a source that can actually see the traffic. A normal Raspberry Pi connected as an ordinary LAN client cannot automatically see traffic between every other client and the router. Controller counters, attributable SNMP data, a mirrored switch port, or an inline/gateway deployment can provide the required visibility.

## Windows Agent

For most Windows workstations and servers, use the **GODSEYE Windows Agent** instead of WinRM. In Event Findings, open **Windows Agents**, create a one-time enrollment token, download the embedded agent package, copy it to the Windows computer, and run the PowerShell installer as Administrator.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-GODSEYEAgent.ps1 -ServerUrl "https://godseye.example.local" -EnrollmentToken "gse_..."
```

The installer compiles and installs the 64-bit `GODSEYEWindowsAgent` Windows service using the built-in .NET Framework C# compiler. The agent makes outbound HTTPS requests only; no inbound WinRM listener is required. Its long-term machine API key is protected with Windows DPAPI LocalMachine and the local data directory is ACL-restricted to SYSTEM and Administrators. See `docs/WINDOWS_AGENT.md`.

## Built-in network tools

The authenticated Network Tools workspace includes Ping, Traceroute, DNS Lookup, bounded TCP Port Scan, Device Information, Network Discovery, Wake-on-LAN, gateway and Internet checks, and website monitoring. Network scanning functions are constrained to appropriate local/private targets where applicable.

## Data and backups

The primary database is stored at `/var/lib/godseye/godseye.db`. GODSEYE uses SQLite WAL mode and supports integrity-checked backups. A restore automatically creates a pre-restore safety backup. Application secrets use the protected appliance key stored under the GODSEYE data directory.

## Updates and production operation

GODSEYE supports staged ZIP updates with SHA-256 verification and preflight checks. Production controls include scheduled backups, retention policies, configuration export/import, notification delivery history, HTTPS setup, audit search/export, and confirmation-gated remediation actions.

Upgrades preserve the GODSEYE data directory and configuration and create a safety backup before application files are replaced.

## Development and testing

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. pytest -q
python -m compileall app
```

Hardware-dependent behavior should also be validated on the target Raspberry Pi, particularly privileged packet collection, systemd state, thermal information, and real Pi-hole, UniFi, or SNMP integrations.

## Screenshots

Current release packages carry the current dark-mode screenshot set under `docs/screenshots/`. See `docs/SCREENSHOTS.md` for the screenshot index. Older light-mode promotional images are not carried forward in new builds.

## Documentation

Key documentation is under `docs/`, including installation/usage guidance, appliance hardening, discovery/topology, integrations/reporting, production management, and the current screenshot set.

## Authorized use

Deploy GODSEYE only on networks you own or are authorized to administer and monitor. Review the repository license before redistribution.
