# GODSEYE Windows Agent v1.0

The Windows Agent is the recommended Event Findings collection method for 64-bit Windows workstations and Windows Server.

It runs as the **GODSEYE Windows Agent** Windows service under LocalSystem, reads the configured Windows Event Log channels locally, and sends only **Critical, Error, and Warning** records outbound to GODSEYE. No inbound WinRM port is required.

## Install

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

## Security

- Outbound HTTPS only; Windows does not need TCP 5986/WinRM opened for agent collection.
- One-time enrollment token.
- Unique per-machine API key.
- Server stores only a SHA-256 hash of the agent API key.
- Windows stores the long-term API key protected with DPAPI LocalMachine.
- Agent data ACL is restricted to SYSTEM and local Administrators.
- The agent is read-only: it reads Event Logs and handles targeted rechecks; it does not accept arbitrary PowerShell or command execution.
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
