# GODSEYE Windows Agent

The **GODSEYE Windows Agent** is the recommended Windows Event Findings collection method in v4.18. It is designed for 64-bit Windows workstations and Windows Server.

## Why use the agent

The agent removes the need to configure inbound WinRM, TCP 5986, Windows listener certificates, short-name DNS resolution, or remote Event Log permissions from the Raspberry Pi. The Windows computer makes an outbound connection to GODSEYE instead.

## Collection behavior

The agent reads configured Windows Event Log channels locally with `System.Diagnostics.Eventing.Reader`. It selects only levels 1, 2, and 3: **Critical, Error, and Warning**. The default channels are `System` and `Application`.

Each channel has an Event Record ID bookmark. On first enrollment the agent limits collection to the previous 24 hours. After successful upload, it advances the bookmark. A batch is written to `pending-events.json` before transmission; bookmarks are not advanced until GODSEYE acknowledges the upload. This allows the agent to retry after temporary network or GODSEYE outages without silently skipping the pending batch.

## Enrollment

1. In GODSEYE, open **Event Findings → Windows Agents**.
2. Select **Create Enrollment Token**. The token is one-time use and expires after 30 minutes by default.
3. Select **Download Agent** and copy the package to the Windows computer.
4. Open 64-bit PowerShell as Administrator.
5. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-GODSEYEAgent.ps1 -ServerUrl "https://godseye.example.local" -EnrollmentToken "gse_..."
```

If GODSEYE is using a temporary self-signed certificate, `-SkipTlsVerify` is available for lab validation. It should not be left enabled for production. HTTP is rejected by default; `-AllowHttp` exists only for isolated lab testing.

## Security design

- One-time enrollment token; GODSEYE stores only its SHA-256 hash.
- Unique long-term API key per enrolled Windows computer; GODSEYE stores only the SHA-256 hash.
- Windows protects the long-term key with DPAPI `LocalMachine`.
- `C:\ProgramData\GODSEYE\Agent` is restricted to SYSTEM and local Administrators.
- Outbound HTTP requests use bearer authentication and should use HTTPS.
- The service reads Event Logs and performs targeted Event Finding rechecks only. It does **not** expose arbitrary command, PowerShell, or shell execution.
- Revoking an agent in GODSEYE immediately prevents its API key from being accepted.

## Recheck

When **Recheck** is selected on an Event Finding that originated from a Windows Agent, GODSEYE queues a recheck request for that agent. On the next heartbeat, the agent checks its local log for a newer event from the same channel, provider, and Event ID. The result is returned to GODSEYE. A successful recheck does not automatically mark the finding resolved; resolution remains an operator decision.

## Local files

The service uses `C:\ProgramData\GODSEYE\Agent`:

- `agent.json` — server URL, agent UUID, channels, interval, and non-secret settings.
- `agent.key` — DPAPI-protected machine API key.
- `state.json` — Event Record ID bookmarks and last error.
- `pending-events.json` — durable batch waiting for GODSEYE acknowledgement.
- `agent.log` — rotating agent operational log.

## Service maintenance

```powershell
Get-Service GODSEYEWindowsAgent
Restart-Service GODSEYEWindowsAgent
Get-Content C:\ProgramData\GODSEYE\Agent\agent.log -Tail 50
```

To remove the service:

```powershell
.\Uninstall-GODSEYEAgent.ps1
```

To also delete its local data:

```powershell
.\Uninstall-GODSEYEAgent.ps1 -RemoveData
```

## WinRM fallback

The v4.17 WinRM collector is retained. Use **WinRM Sources** when an installed agent is not desired. Agent and WinRM findings feed the same Event Findings and Ticket Portal workflow.
