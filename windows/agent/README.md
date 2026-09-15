# GODSEYE Windows Agent v1.1.1

The Windows Agent is the recommended Event Findings collection method for 64-bit Windows workstations and Windows Server.

It runs as the **GODSEYE Windows Agent** Windows service under LocalSystem, reads the configured Windows Event Log channels locally, and sends only **Critical, Error, and Warning** records outbound to GODSEYE. No inbound WinRM port is required.

## Pull Events Now

GODSEYE can queue a **Pull Events Now** command for one agent or all online agents. The agent checks for management commands every 10 seconds, immediately reads new matching Event Log records, uploads them, advances its bookmarks only after GODSEYE acknowledges the batch, and reports the number of events/new findings back to the appliance.

The 10-second command heartbeat is separate from the normal configured event collection interval, so a 5-minute collection interval can still respond quickly to an operator-initiated pull.

## New installation

1. In GODSEYE, open **Event Findings → Windows Agents → Create Enrollment Token**.
2. Copy this agent folder to the Windows computer.
3. Open 64-bit PowerShell as Administrator.
4. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-GODSEYEAgent.ps1 -ServerUrl "https://godseye.example.local" -EnrollmentToken "gse_..."
```

For a temporary lab test with a self-signed GODSEYE certificate:

```powershell
.\Install-GODSEYEAgent.ps1 -ServerUrl "https://192.168.1.20" -EnrollmentToken "gse_..." -SkipTlsVerify
```

Use `-SkipTlsVerify` only temporarily. Production deployments should trust the GODSEYE HTTPS certificate.

## Upgrade an already-enrolled agent

Agent v1.0/v1.1 can be upgraded to v1.1.1 without generating a new enrollment token.

The v1.1.1 installer fixes the upgrade path by compiling to a staging executable first, waiting for the old Windows service process to fully release the current executable, then replacing it. It also preserves the current GODSEYE URL and TLS verification setting unless you explicitly override them.

The simplest upgrade is now:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-GODSEYEAgent.ps1
```

If you want to change the GODSEYE URL during the upgrade:

```powershell
.\Install-GODSEYEAgent.ps1 -ServerUrl "https://godseye.example.local"
```

If this endpoint intentionally uses temporary certificate bypass and you want to change that setting, explicitly include:

```powershell
.\Install-GODSEYEAgent.ps1 -SkipTlsVerify
```

The installer:
- requires Administrator PowerShell;
- preserves `agent.json`, agent UUID, bookmarks, durable event queue, and the DPAPI-protected `agent.key`;
- stops the service and waits for its process to fully exit;
- compiles the new executable to a staging file;
- leaves the previous executable unchanged if compilation fails;
- keeps a backup executable during replacement;
- restarts the service and prints recent `agent.log` lines if startup fails.

## Security

- Outbound HTTPS only; Windows does not need TCP 5986/WinRM opened for agent collection.
- One-time enrollment token for new installations.
- Unique per-machine API key.
- Server stores only a SHA-256 hash of the agent API key.
- Windows stores the long-term API key protected with DPAPI LocalMachine.
- Agent data ACL is restricted to SYSTEM and local Administrators.
- The agent is read-only: it reads Event Logs and handles defined GODSEYE commands such as event pull/recheck; it does not accept arbitrary PowerShell or command execution.
- Event batches are persisted before upload. Bookmarks advance only after GODSEYE acknowledges the batch, reducing event loss during network outages.

## Local files

`C:\ProgramData\GODSEYE\Agent`

- `agent.json` — non-secret configuration after enrollment.
- `agent.key` — DPAPI-protected API key.
- `state.json` — per-channel Event Record ID bookmarks.
- `pending-events.json` — durable outbound batch while GODSEYE is unreachable.
- `agent.log` — small rotating operational log.

## Service commands

```powershell
Get-Service GODSEYEWindowsAgent
Restart-Service GODSEYEWindowsAgent
Get-Content C:\ProgramData\GODSEYE\Agent\agent.log -Tail 50
```

## Uninstall

```powershell
.\Uninstall-GODSEYEAgent.ps1
```

To remove the local agent data too:

```powershell
.\Uninstall-GODSEYEAgent.ps1 -RemoveData
```
