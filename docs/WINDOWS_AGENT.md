# GODSEYE Windows Agent 2.5.2

The **GODSEYE Windows Agent 2.5.2** is the recommended Windows integration for Event Findings, management commands, optional EDR scans, and user-approved Remote Access. It is a self-contained x64 .NET 8 application with a native guided installer.

## Install and enroll

1. In GODSEYE, open **Event Findings → Windows Agents**.
2. Select **Create Enrollment Token**. The token is one-time use and normally expires after 30 minutes.
3. Select **Download x64 Installer**.
4. Run `GODSEYE-Windows-Agent-x64-Setup.exe` as Administrator on the Windows computer.
5. Enter the GODSEYE server URL and the one-time enrollment token.
6. Keep TLS verification enabled for production. The installer can allow a lab-only self-signed setup when explicitly selected.

The v4.31 guided Setup EXE installs and registers the service directly. The Windows-native release pipeline additionally builds the MSI used for authenticated in-product agent self-update.

## Installed locations

Application files:

`C:\Program Files\GODSEYE Agent\`

Persistent state:

`C:\ProgramData\GODSEYE\Agent\`

Persistent state includes `agent.json`, the DPAPI-protected API key, Event Log bookmarks, pending event batches, local status, and logs. Reinstall and upgrade do not replace that directory.

## Windows service and tray

- Service: `GODSEYEWindowsAgent`
- Startup: Automatic
- Service account: LocalSystem
- Tray application: starts in each signed-in user's interactive session after sign-in; guided Setup also launches it immediately
- Remote Access: local approval for viewing and a separate approval for control

The service and tray communicate through a per-session named pipe. The service cannot approve Remote Access on behalf of the user.

If the service is running but the tray icon is missing, look under **Show hidden icons** in the Windows notification area. You can start it without reinstalling:

```powershell
Start-Process 'C:\Program Files\GODSEYE Agent\GODSEYE.Agent.exe' -ArgumentList '--tray'
```

Run that command in the signed-in user's PowerShell window, not a service or SYSTEM prompt. The tray should appear for that user and Remote Access should reach the approval prompt. The MSI registers a Windows sign-in startup entry for future sessions. If the tray still does not start, check `C:\ProgramData\GODSEYE\Agent\agent.log` for “Could not launch tray helper” or “Could not obtain the signed-in user's tray token.”

## Remote Access state flow

GODSEYE tracks explicit session phases:

`requested → waiting_for_tray → tray_ready → waiting_for_user → approved → capture_started → active`

`active` is server-controlled. The server promotes a session to active only after it receives a JPEG frame, decodes it successfully, verifies it with Pillow, records the real frame dimensions, and stores it atomically. A malformed image cannot activate the session.

The current agent captures the Windows virtual desktop, including multi-monitor layouts, through the signed-in user's tray session. Pointer coordinates are mapped to that same virtual desktop. Browser mouse, keyboard, and wheel events are accepted only after the user separately approves control and are delivered once in order.

There is no arbitrary remote shell, PowerShell command, unrestricted process execution, registry command, or unrestricted file command in the Remote Access channel.

## Event collection

The agent reads configured Windows Event Log channels locally and selects Critical, Error and Warning records. Each channel keeps a Record ID bookmark. Pending uploads are written durably before transmission, and bookmarks advance only after GODSEYE acknowledges the batch.

**Pull Events Now** uses the existing authenticated outbound management heartbeat. It flushes any pending batch, collects from the current bookmarks, uploads the new events, and returns counts to GODSEYE.

## Upgrades

Existing Agent 2.1+ installations can use GODSEYE's authenticated Agent update command after the validated 2.5.2 MSI has been installed on the server. The service downloads only GODSEYE's fixed MSI endpoint, verifies the advertised SHA-256, and invokes Windows Installer. The update payload cannot provide an arbitrary URL or command.

The guided Setup EXE detects an existing `agent.json` and skips enrollment pages. Existing enrollment, API key, configuration, bookmarks and pending queues are preserved.

## Service maintenance

```powershell
Get-Service GODSEYEWindowsAgent
Restart-Service GODSEYEWindowsAgent
Get-Content C:\ProgramData\GODSEYE\Agent\agent.log -Tail 50
```

## Legacy Agent and WinRM

New endpoints should use the current x64 Setup. WinRM remains available when installing an agent is not desired; both sources feed the same Event Findings and Ticket Portal workflows.
