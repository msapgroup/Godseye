# GODSEYE v4.31

**Local network intelligence, security monitoring, operations, and remote support — in one self-hosted appliance.**

GODSEYE v4.31 keeps the v4.30 interface and adds a redesigned Quick Assist-style Remote Access handshake. The Windows Agent retains token enrollment and Event Findings collection while handing approved screen sharing to a dedicated interactive-session helper. Remote sessions begin view-only and require a separate local-user approval before mouse or keyboard control is enabled.

## See GODSEYE in action

These images show the dark v4.31 workspaces. Dashboard and Network Map are running-app captures. The Devices, Calendar, Email, System Health, and Remote Access images are documentation previews rebuilt from earlier v4.31 captures with the approved G logo; they preserve the pictured controls and sample states. Windows Event Findings is an illustrative preview based on a user-provided capture, showing the new Suggested Fix action and guide panel. The Cyber Tools images are UI previews, and their example result is illustrative. Data and availability on your appliance will differ. Current navigation also includes the separate Cyber Tools workspace.

### Dashboard

![GODSEYE v4.31 Dashboard](docs/screenshots/v431-dashboard-map-logo.png)

**How it works:** Start here to see device and security totals, traffic, recent findings, monitored services, tickets, and appliance health. Select a summary or card to open its full page or a focused detail; use **Back to Dashboard** to return. The Network Map Overview offers **Topology** and **World** views and a button to open the full map. The image uses disposable demonstration records, which are not installed with GODSEYE.

### Devices and inventory

![GODSEYE Devices inventory preview](docs/screenshots/v431-devices-guide.png)

**How it works:** Search by device or address, then narrow the inventory by type, status, platform, or site. Select a row to review its identity, classification, first and last seen times, and recent activity; **Open Device Details** shows the full record. Use **Add Device** for an item discovery has not found, and investigate anything unfamiliar before classifying it as managed or known.

### Network Map

![GODSEYE Network Map overview](docs/screenshots/v431-network-map-card.png)

**How it works:** Open **Network Map** from the sidebar or the Dashboard map card. Switch the Dashboard preview between the geographic World view and Topology; the full page shows observed devices and relationships. Select a device to investigate its inventory details. Map links are based on collected evidence and can change as GODSEYE learns about the network.

### Calendar and maintenance planning

![GODSEYE Calendar preview](docs/screenshots/v431-calendar-guide.png)

**How it works:** Choose Month, Week, Day, or List. Double-click a date to create an appointment there, or choose **Create Event** and set its time and details. Use the side panel for upcoming work and monthly totals. Calendar can include local events and, after authorization, Google Calendar or Microsoft 365; ticket appointments can lead back to their related work item.

### Email workspace

![GODSEYE Email preview with no mailbox connected](docs/screenshots/v431-email-guide.png)

**How it works:** Open **Mail Accounts** and authorize Gmail or Microsoft 365 before reading or sending mail. Choose a connected account and folder, search messages, then compose, reply, forward, or attach a generated report. SMTP Relay in Integrations is for alert delivery. This image deliberately shows the unconnected setup state rather than invented mailbox contents.

### System Health

![GODSEYE System Health preview](docs/screenshots/v431-system-health-guide.png)

**How it works:** Check the appliance, scanner, database, backups, update channel, and integrations at the top. Inspect CPU, memory, disk, storage growth, network I/O, temperature, and uptime below. Open the detailed backup, retention, service, and update panels to investigate issues; use **Run Health Check**, **Create Backup**, **View Logs**, or **Check for Updates** as appropriate. Metrics shown here are sample capture values.

### Remote Access

![GODSEYE Remote Access setup preview](docs/screenshots/v431-remote-access-guide.png)

**How it works:** In **Event Findings → Windows Agents**, create a one-time enrollment token and install Agent 2.4.4 on the Windows computer. Select an online enrolled computer in **Remote Access** and request a session. The person at that computer must approve screen sharing; the session starts view-only after the first validated frame. **Request Control** requires a separate approval before pointer or keyboard input. Disconnect from the portal or use **Stop Sharing** locally to end it. The image shows the honest empty state before an Agent is enrolled.

### Windows Event Findings

![GODSEYE Windows Event Findings Suggested Fix preview](docs/screenshots/v431-event-findings-guide.png)

**How it works:** Enroll a Windows Agent or configure a WinRM source to collect selected Critical, Error, and Warning events. GODSEYE groups repeat events into a finding and prepares a suggested action list as the event arrives. Select **Suggested Fix** on a row to see the event message, tailored steps, and clickable Microsoft Learn guidance. An additional Google link searches Microsoft Learn for that specific provider and event ID; it sends no computer name or event message. Review the full event before making changes, then use **Recheck** to confirm the result or **Create Ticket** to assign the work. The image is an illustrative UI preview of the new flow, not a live result from an enrolled computer.

### Cyber Tools

![GODSEYE Cyber Tools card overview](docs/screenshots/v431-cyber-tools-overview.png)

**How it works:** Open **Cyber Tools** from Operations. Each of the eight cards owns its target, profile, availability badge, run button, and result. Enter only systems you administer; engine availability depends on the software configured on the appliance.

| Card | What to enter and run |
| --- | --- |
| Network Exposure Scan | Enter a private host or network, choose Quick, Standard, or Deep, then run bounded Nmap discovery. |
| Endpoint Security Posture | Enroll a Windows Agent, then review reachability, version, updates, errors, and malware scan state. |
| Web & TLS Audit | Enter a website URL and profile to inspect HTTPS, certificate, redirects, and headers. |
| Malware & IOC Scan | Enter a hash, IP, or domain; optionally select a file up to 10 MB for ClamAV and YARA. |
| DNS & Email Security | Enter a domain and optional DKIM selector to inspect address, MX, SPF, DMARC, DKIM, CAA, and DNSSEC records. |
| Linux Security Audit | Choose a profile and run a read-only Lynis assessment of the appliance. |
| Network Threat Detection | Choose the number of alerts to review from an existing Suricata EVE feed. |
| Evidence Capture | Choose a validated interface and optional host IP; set up to 15 seconds and 500 packets for the PCAP. |

After a run, review the card's structured result and **Scan history**. Where supported, create a linked Finding or Ticket, export JSON, or schedule a repeat check. File uploads and packet capture cannot be scheduled. See [Cyber Tools configuration](docs/TOOLS.md) for dependencies and limits.

![Illustrative Cyber Tools result and workflow preview](docs/screenshots/v431-cyber-tools-working.png)

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

### Storage recommendation

GODSEYE runs best when the appliance boots from an SSD or NVMe drive. Faster, lower-latency storage improves database activity, dashboard response, log processing, report generation, updates, backups, and packet/evidence capture—especially as monitoring history grows. HDD and SD-card installations remain supported, but for continuous monitoring use, place the operating system and `/var/lib/godseye` data directory on SSD-class storage when possible.

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

For Windows workstations and servers, **GODSEYE Windows Agent 2.4.4** is the intended path. This v4.31 candidate contains the compiled x64 guided Setup EXE, and the authenticated **Download x64 Installer** button serves the uniquely named, cache-safe 2.4.4 file directly. In **Event Findings → Windows Agents**, create a one-time enrollment token, then run the Setup EXE as Administrator on the Windows computer and enter the GODSEYE URL and token. The separate MSI used by agent self-update is produced by the Windows-native release pipeline and must pass clean-install, uninstall, and 2.4.2-to-2.4.4 upgrade tests before release.

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

The complete screen gallery and capture notes are in [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md). The README above includes the Dashboard, Devices, Network Map, Calendar, Email, System Health, Remote Access, Windows Event Findings, and both Cyber Tools views with instructions for each. Documentation examples are not installed as live records.

## Documentation

Key documentation is under `docs/`, including installation/usage guidance, appliance hardening, discovery/topology, integrations/reporting, production management, and the current screenshot set.

## Authorized use

Deploy GODSEYE only on networks you own or are authorized to administer and monitor. Review the repository license before redistribution.


## Permanent x64 Windows Agent
GODSEYE includes a self-contained x64 Windows Agent installer. First install uses a one-time enrollment token; later installer versions upgrade in place and preserve the enrolled identity.
