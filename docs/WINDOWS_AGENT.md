# GODSEYE Windows Agent 2.4.0

The **GODSEYE Windows Agent 2.4.0** is the recommended Windows integration for Event Findings, management commands, and user-approved Remote Access. It is a self-contained x64 .NET 8 application with a native guided installer.

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
- Tray application: runs in the active signed-in user's interactive session
- Remote Access: local approval for viewing and a separate approval for control

The service and tray communicate through a per-session named pipe. The service cannot approve Remote Access on behalf of the user.

## Remote Access state flow

GODSEYE tracks explicit session phases:

`requested → waiting_for_tray → tray_ready → waiting_for_user → approved → capture_started → active`

`active` is server-controlled. The server promotes a session to active only after it receives a JPEG frame, decodes it successfully, verifies it with Pillow, records the real frame dimensions, and stores it atomically. A malformed image cannot activate the session.

Agent 2.4.0 captures the Windows virtual desktop, including multi-monitor layouts, through a dedicated per-session helper in the signed-in user's session. Pointer coordinates are mapped to that same virtual desktop. Browser mouse, keyboard, and wheel events are accepted only after the user separately approves control and are delivered once in order.

There is no arbitrary remote shell, PowerShell command, unrestricted process execution, registry command, or unrestricted file command in the Remote Access channel.

## Event collection

The agent reads configured Windows Event Log channels locally and selects Critical, Error and Warning records. Each channel keeps a Record ID bookmark. Pending uploads are written durably before transmission, and bookmarks advance only after GODSEYE acknowledges the batch.

**Pull Events Now** uses the existing authenticated outbound management heartbeat. It flushes any pending batch, collects from the current bookmarks, uploads the new events, and returns counts to GODSEYE.

## Upgrades

Existing Agent 2.1+ installations can use GODSEYE's authenticated Agent update command after a validated 2.4.0 MSI has been installed on the server. The service downloads only GODSEYE's fixed MSI endpoint, verifies the advertised SHA-256, and invokes Windows Installer. The update payload cannot provide an arbitrary URL or command.

The guided Setup EXE detects an existing `agent.json` and skips enrollment pages. Existing enrollment, API key, configuration, bookmarks and pending queues are preserved.

## Service maintenance

```powershell
Get-Service GODSEYEWindowsAgent
Restart-Service GODSEYEWindowsAgent
Get-Content C:\ProgramData\GODSEYE\Agent\agent.log -Tail 50
```

## Legacy Agent and WinRM

The pre-2.x PowerShell package remains available only as a legacy migration path. New endpoints should use the 2.4.0 x64 Setup. WinRM remains available when installing an agent is not desired; both sources feed the same Event Findings and Ticket Portal workflows.
