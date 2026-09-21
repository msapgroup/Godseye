# GODSEYE v4.31

**Local network intelligence, security monitoring, operations, and remote support — in one self-hosted appliance.**

GODSEYE v4.31 keeps the v4.30 interface and adds a redesigned Quick Assist-style Remote Access handshake. The Windows Agent retains token enrollment and Event Findings collection while handing approved screen sharing to a dedicated interactive-session helper. Remote sessions begin view-only and require a separate local-user approval before mouse or keyboard control is enabled.

![GODSEYE v4.30 Dashboard](docs/screenshots/v430-dashboard.png)

## v4.31 interface

The v4.30 interface uses the dark GODSEYE visual system across the real application. The five approved visual references are kept in `docs/design-reference/`; the images embedded here were captured from the running application with demonstration data. The shared masthead, navigation, summary cards, tools, reports, calendar, email, traffic, and health workspaces use a consistent outlined icon set. Page layouts are constrained to the viewport so normal desktop use does not require a page-level horizontal scrollbar.

The application and authentication screens use the angular GODSEYE “G” mark with the current build number. Every authentication screen carries the footer attribution **Powered By: MSAPGROUP.LLC**.

The Dashboard Network Map Overview matches the geographic reference card and defaults to a detailed world silhouette with recognizable coastlines, route lines, colored site markers, and live Sites, Devices, Offline, and Active Alerts totals. The map sits left while the compact statistics and full-map action occupy the right column. Use the subtle **Topology / World** switch inside the map to change views; GODSEYE remembers the selection.

### Devices and inventory

![GODSEYE v4.30 Devices](docs/screenshots/v430-devices.png)

Discover, identify, classify, rename, and investigate devices while preserving the original GODSEYE inventory and discovery behavior. Filter by status, type, and classification; select a row to see its live device details.

### Calendar and maintenance planning

![GODSEYE v4.30 Calendar](docs/screenshots/v430-calendar.png)

Plan maintenance, tickets, reviews, and operational work from the built-in calendar, with Google Calendar and Microsoft 365 integrations available when configured.

### Email workspace

![GODSEYE v4.30 Email](docs/screenshots/v430-email.png)

Connect Gmail or Microsoft 365 and work with operational mail, attachments, replies, drafts, and generated GODSEYE reports without leaving the appliance UI.

### System Health

![GODSEYE v4.30 System Health](docs/screenshots/v430-system-health.png)

System Health brings appliance status, resource usage, diagnostics, backups, retention, updates, HTTPS, metrics security, and remediation controls into the same v4.30 interface.

### Remote Access

![GODSEYE v4.30 Remote Access](docs/screenshots/v430-remote-access.png)

Remote Access is rebuilt around explicit local user approval. A session moves through request, approval, tray/capture readiness, and validated JPEG delivery before GODSEYE marks it active. The browser remote console includes the defined pointer, keyboard, wheel, screenshot, and disconnect controls without exposing an arbitrary remote shell.

## Movable dashboard cards

Dashboard and supported workspace cards can be rearranged per user. Choose **Unlock Layout**, drag cards within a layout zone, and GODSEYE saves that arrangement automatically for the signed-in account. **Reset My Layout** restores the GODSEYE default without affecting another user's layout.

Click a Dashboard card to open its detail or full data page. **Back to Dashboard** returns to the original page and scroll position. Devices, Calendar statistics, and System Health cards open focused data with a **Back to page** control. Focused card views retain the dark GODSEYE masthead without introducing a light strip. Selecting a device opens its full record; **Close Device Details and Return** takes you back to the page you came from. Buttons inside cards continue to perform their own labeled actions.

Persistent controls at the bottom of the sidebar provide **Reorder Page**, **Reorder Sidebar**, **Reset Page**, and **Reset Sidebar** on every screen. Reorder Page supports the Dashboard plus Devices, Calendar, Email, Reports, traffic, integration, monitoring, and System Health card grids. Reorder Sidebar lets you drag navigation items into a new order or move them between Monitoring, Operations, and Administration. Both layouts save automatically for the signed-in user and reset independently.

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
- **Windows Event Findings** — the recommended GODSEYE Windows Agent reads only Critical, Error, and Warning records locally on 64-bit Windows workstations and Windows Server, queues them durably, and sends them outbound to GODSEYE over HTTPS. WinRM remains available as an agentless fallback. Repeated events are grouped into findings with Suggested Fix, Recheck, Resolve, and Create Ticket workflows. Agent v1.1 also supports operator-triggered **Pull Events Now** requests and checks GODSEYE for defined commands every 10 seconds.
- **Ticket Portal** — tracks manual, Network Finding, and Event Finding work with priority, assignee, status, notes, linked systems, calendar scheduling, and closure. Ticket assignees are selected from GODSEYE application users, with optional display names shown in the picker. Scheduled tickets appear on Calendar and can be opened, noted, resolved, or closed directly from the calendar appointment.

- **Reporting** — generates Network Summary, Device Inventory, Security Findings, Availability & Monitoring, Integrations Health, Traffic Usage, Audit Activity, and Device Changes reports with CSV/PDF export.
- **Notifications** — supports webhook, ntfy, and SMTP delivery for important events and findings.
- **Audit and administration** — provides role-based access, audit history, MFA, controlled cleanup actions, backups, retention settings, configuration portability, and staged updates.

## Security model

GODSEYE is local-first. The web application runs as the unprivileged `godseye` service account. Privileged network collection is separated into services that receive only the permissions needed for their job. Integration credentials and other protected secrets are encrypted at rest with the appliance key.

Authentication includes session protection, CSRF defenses, security headers, account lockout, password controls, TOTP MFA with backup codes, and role-based permissions for `admin`, `operator`, `auditor`, and `readonly` users.

GODSEYE is intended for trusted LAN or VPN access. Do not expose the application directly to the public Internet. HTTPS can be configured through the included Nginx helper. For Windows Event collection, prefer the GODSEYE Windows Agent over outbound HTTPS. If WinRM is used as the agentless fallback, use WinRM over HTTPS with a dedicated least-privilege Event Log Readers account and do not expose WinRM directly to the public Internet.

## Installation

GODSEYE v4.31 is installed directly on Raspberry Pi OS, Debian, or Ubuntu-style Linux with `systemd`; Docker is not required. The release ZIP contains the application and installer.

### Fresh install from the release ZIP

```bash
mkdir -p ~/godseye-v431
unzip GODSEYE-v4.31.0-server-candidate.zip -d ~/godseye-v431
cd ~/godseye-v431
chmod +x install.sh
sudo ./install.sh --fresh
```

When installation completes, open:

```text
http://YOUR-GODSEYE-IP:8080
```

The built-in username is `admin`. GODSEYE ships with **no default admin password**; the first-run setup page requires you to create it.

### Upgrade an existing GODSEYE appliance

Extract the new release ZIP into a temporary directory and run:

```bash
chmod +x install.sh
sudo ./install.sh --upgrade
```

The upgrade path preserves the GODSEYE data/configuration directories and performs the migration/backup checks before starting the new application.

Useful maintenance commands:

```bash
sudo ./install.sh --doctor
sudo systemctl status godseye-web
sudo systemctl status godseye-scanner
sudo journalctl -u godseye-web -n 100 --no-pager
```

The web service listens on **port 8080** by default. HTTPS can be placed in front of it with the included Nginx helper.

## Using GODSEYE for network security

Start with **Devices** to classify known equipment and investigate anything unfamiliar. Use **Network Map** to understand observed relationships, **Monitoring** to watch important infrastructure and services, and **Findings** to work recurring failures or suspicious changes.

Use **Alert Rules** for conditions that should receive attention automatically. **Event Findings** extends that workflow to Windows computers and servers. The recommended **GODSEYE Windows Agent** runs locally as a Windows service, reads selected Critical/Error/Warning Event Log records, keeps per-channel Event Record ID bookmarks, queues unsent batches during outages, and sends them outbound to GODSEYE over HTTPS. **Pull Events Now (Agents)** can request an immediate fresh collection from one or all online Agent v1.1 endpoints. Recurring hardware, disk, WHEA, service, update, Defender, VSS, and application errors become explainable findings. WinRM remains available as an agentless fallback. Findings can be rechecked, resolved, or converted into **Ticket Portal** work items.

**Ticket Portal** tracks operational work from discovery through closure. Administrators can delete individual or selected tickets and clean up old resolved/closed tickets by age; linked findings are preserved while the deleted ticket's work notes and local ticket-calendar appointment are removed. Tickets can be created manually or from Network Findings and Event Findings, assigned, given priorities, documented with work notes, and scheduled directly onto **Calendar**. Calendar appointments linked to tickets can add work notes, mark the ticket resolved, or close it after the work is complete. **Calendar** also supports OAuth-connected Google Calendar and Microsoft 365 calendars, while ICS subscriptions remain available for read-only imports. **Integrations** can add controller, DNS, switch, or router context. **Reports** provide inventory, security, availability, traffic, audit, and change records for periodic review. Generated Report History entries can be emailed through a connected mailbox or deleted individually/in bulk by an administrator. **System Health** covers the GODSEYE appliance itself, including backups, retention, diagnostics, metrics security, and production management.

For traffic visibility, choose a source that can actually see the traffic. A normal Raspberry Pi connected as an ordinary LAN client cannot automatically see traffic between every other client and the router. Controller counters, attributable SNMP data, a mirrored switch port, or an inline/gateway deployment can provide the required visibility.

## Windows Agent

For Windows workstations and servers, **GODSEYE Windows Agent 2.4.3** is the intended path. This v4.31 candidate contains the compiled x64 guided Setup EXE, and the authenticated **Download x64 Installer** button serves the uniquely named, cache-safe 2.4.3 file directly. In **Event Findings → Windows Agents**, create a one-time enrollment token, then run the Setup EXE as Administrator on the Windows computer and enter the GODSEYE URL and token. The separate MSI used by agent self-update is produced by the Windows-native release pipeline and must pass clean-install, uninstall, and 2.4.2-to-2.4.3 upgrade tests before release.

Agent 2.4.0 is a self-contained x64 .NET 8 service installed under `C:\Program Files\GODSEYE Agent\`. Enrollment identity, the DPAPI-protected API key, Event Log bookmarks, queued events and configuration remain under `C:\ProgramData\GODSEYE\Agent\` so reinstall and upgrade preserve the enrolled computer.

Remote Access in 2.4.0 uses a persistent tray application plus a dedicated helper in the signed-in Windows session. Every screen-sharing session requires a local **Allow/Deny** decision, and remote control requires a second approval. Sessions start view-only. GODSEYE does not mark the session active until the server has received and validated the first real JPEG frame. The remote channel accepts only the defined screen, pointer, keyboard and wheel operations; it does not expose a remote shell or arbitrary process execution.

The older PowerShell-installed Agent package is retained only as a legacy migration path. New deployments should use the x64 Setup/MSI. See `docs/WINDOWS_AGENT.md`.

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

The screenshots shown above are captured from the actual v4.30 application using a disposable demonstration database. The current captures are under `docs/screenshots/` and the approved visual targets are under `docs/design-reference/`. Demonstration records are illustrative and are not installed with GODSEYE. Email shows the honest unconnected state until you configure a mailbox; Remote Access shows the honest empty state until an Agent is enrolled. See `docs/SCREENSHOTS.md` for the gallery and capture notes.

## Documentation

Key documentation is under `docs/`, including installation/usage guidance, appliance hardening, discovery/topology, integrations/reporting, production management, and the current screenshot set.

## Authorized use

Deploy GODSEYE only on networks you own or are authorized to administer and monitor. Review the repository license before redistribution.


## Permanent x64 Windows Agent
GODSEYE includes a self-contained x64 Windows Agent installer. First install uses a one-time enrollment token; later installer versions upgrade in place and preserve the enrolled identity.
