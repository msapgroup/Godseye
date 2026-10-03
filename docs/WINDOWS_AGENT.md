# GODSEYE Windows Agent 2.4.5 integrated

The [GODSEYE Agent 2.4.5 release](https://github.com/msapgroup/Godseye/releases/tag/v4.31.0-agent-2.4.5) is the single current download. This build combines user-approved Remote Access, Cyber Tools endpoint commands, and optional EDR scanning. Its source is in `windows/agent-x64`; no legacy agent is included in the full app ZIP. The original 2.4.5 Remote Access path is retained, but validate the integrated build on a signed-in Windows desktop before broad deployment.

## Install and enroll

1. In GODSEYE, open **Event Findings → Windows Agents**.
2. Select **Create Enrollment Token**. The token is one-time use and normally expires after 30 minutes.
3. Download the 2.4.5 Setup EXE from GODSEYE or the linked release above.
4. Run `GODSEYE-Windows-Agent-x64-Setup.exe` as Administrator on the Windows computer.
5. Enter the GODSEYE server URL and the one-time enrollment token.
6. Keep TLS verification enabled for production. The installer can allow a lab-only self-signed setup when explicitly selected.

The v4.31 guided Setup EXE installs and registers the service directly. The Windows-native release pipeline additionally builds the MSI used for authenticated in-product agent self-update. An original 2.4.5 endpoint needs the integrated guided Setup once: the same version number does not trigger the in-app self-update command.

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

Run that command in the signed-in user's PowerShell window, not a service or SYSTEM prompt. The tray should appear for that user and Remote Access should reach the approval prompt. The integrated MSI registers a Windows sign-in startup entry for future sessions. If the tray still does not start, check `C:\ProgramData\GODSEYE\Agent\agent.log` for “Could not launch tray helper” or “Could not obtain the signed-in user's tray token.”

For a 2.4.5 package with a running service but a missing tray, [start-tray-2.4.5.ps1](../windows/agent-x64/start-tray-2.4.5.ps1) checks the installed file version, starts the tray in your signed-in session, and adds a startup entry for your Windows account without changing the service binary. If you already installed 2.5.x, run the current integrated 2.4.5 Setup directly to replace it in place. Keep `C:\ProgramData\GODSEYE\Agent\` intact so enrollment and bookmarks remain available.

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

Existing Agent 2.1+ installations can use GODSEYE's authenticated Agent update command after the validated integrated 2.4.5 MSI has been installed on the server. The service downloads only GODSEYE's fixed MSI endpoint, verifies the advertised SHA-256, and invokes Windows Installer. The update payload cannot provide an arbitrary URL or command.

The guided Setup EXE detects an existing `agent.json` and skips enrollment pages. Existing enrollment, API key, configuration, bookmarks and pending queues are preserved.

## Service maintenance

```powershell
Get-Service GODSEYEWindowsAgent
Restart-Service GODSEYEWindowsAgent
Get-Content C:\ProgramData\GODSEYE\Agent\agent.log -Tail 50
```

## Legacy Agent and WinRM

New endpoints should use the current x64 Setup. WinRM remains available when installing an agent is not desired; both sources feed the same Event Findings and Ticket Portal workflows.

### Matching server and agent packages

Update the server using the full application ZIP from the current release, then run the Agent 2.4.5 Setup on affected Windows computers. Updating only the Windows installer does not update an older server UI. The server verifies local installer checksums and rejects stale update manifests. A computer reporting 2.5.x displays **Install current 2.4.5** until the repaired agent sends a new heartbeat; its observed version is never relabeled. Healthy enrollment skips token entry. If connection settings are damaged but the protected key is valid, enter the server URL without a new token. Otherwise enter a current enrollment token.

### New installation and connection repair

A saved token is pending enrollment, not proof that the server accepted it. New installs ask for the server URL and a current enrollment token. An existing protected enrollment key skips token entry by default. Enrolled upgrades can choose **Change server connection or TLS settings** to correct the URL or certificate setting while keeping their key. Certificate verification stays enabled by default. A trusted LAN with a self-signed server certificate has an explicit alternative on the TLS page. Do not select it for an untrusted connection.

Setup checks the tray's readiness in the installing Windows session after launch. An installed service alone is not evidence of a connected agent: confirm a new heartbeat in Windows Agents. SSL failures now include the underlying cause in agent.log.
