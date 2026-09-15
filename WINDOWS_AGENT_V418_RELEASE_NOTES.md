# GODSEYE v4.18 — Windows Agent

## Windows Agent
- Adds the recommended **GODSEYE Windows Agent** collection mode for Event Findings.
- Targets 64-bit Windows workstations and Windows Server.
- Runs as the `GODSEYEWindowsAgent` Windows service under LocalSystem.
- Installer compiles the service locally with the built-in 64-bit .NET Framework C# compiler, then installs it with the Windows Service Control Manager.
- Reads Event Logs locally with the Windows Event Log API and selects only Critical, Error, and Warning entries.
- Default channels are System and Application; channels and collection interval can be changed from GODSEYE.
- Uses per-channel Event Record ID bookmarks. Initial collection is limited to the prior 24 hours.
- Persists a pending batch before upload and advances bookmarks only after GODSEYE acknowledges the events.
- Makes outbound connections to GODSEYE; no inbound Windows WinRM listener is needed.
- WinRM remains available as the agentless fallback.

## Enrollment and authentication
- Admins create one-time enrollment tokens from Event Findings → Windows Agents.
- Enrollment tokens expire and are stored server-side only as SHA-256 hashes.
- Successful enrollment creates a unique long-term machine API key.
- GODSEYE stores only the SHA-256 API-key hash.
- Windows stores the long-term API key with DPAPI LocalMachine.
- Agent directory ACL is restricted to SYSTEM and local Administrators.
- Agent revocation disables the key immediately.
- HTTPS is required by the installer by default; explicit lab-only switches exist for HTTP or certificate-verification bypass.

## Event Findings integration
- Agent events use the existing Event Findings classification and Suggested Fix rules.
- Event Findings record whether collection came from a Windows Agent or WinRM.
- Recheck is agent-aware: GODSEYE queues a targeted request and the local agent checks for a newer event from the same channel, provider, and Event ID.
- Recheck requests are redelivered until acknowledged, so a service/network interruption does not strand them.
- Event Findings still feed Ticket Portal, Calendar scheduling, notes, Resolve, and Close workflows.

## Management UI
- Adds **Windows Agents** as the primary Event Findings collection control.
- Shows online/offline/revoked status, IP, OS, agent version, open findings, last heartbeat, channels, and collection interval.
- Adds one-time enrollment-token generation and an embedded agent-package download.
- Adds Configure and Revoke controls.
- Relabels WinRM controls as the agentless fallback.

## Packaged files
- `windows/agent/GODSEYE-Windows-Agent.zip`
- `windows/agent/Install-GODSEYEAgent.ps1`
- `windows/agent/Uninstall-GODSEYEAgent.ps1`
- `windows/agent/src/GodseyeAgentService.cs`
- `docs/WINDOWS_AGENT.md`

## Validation boundary
The GODSEYE server/API/UI, database migration, token lifecycle, event ingestion, agent linkage, recheck queue, security contracts, package integrity, JavaScript, Python, and regression suite are validated in the build environment. The Windows service cannot be installed or run inside the Linux build container, so a first live v4.18 agent should be validated on an actual 64-bit Windows computer and the target Raspberry Pi.
