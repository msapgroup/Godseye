# GODSEYE v4.22 — Windows Agent Pull Events Now

## Pull Events Now
- Adds **Pull Events Now (Agents)** to Event Findings.
- Adds **Pull All Online** to the Windows Agents management dialog.
- Adds a per-agent **Pull Events Now** action for Windows Agent v1.1.0 and newer.
- GODSEYE queues a signed-in operator request; the Windows agent receives it over the existing outbound HTTPS heartbeat.
- No inbound Windows port, WinRM listener, reverse connection, or arbitrary remote command execution is introduced.
- Duplicate pending pull requests are coalesced so repeatedly clicking the button does not create a command storm.
- Agent rows report the most recent pull state and completion time.
- Pull completion reports uploaded event count and new Event Finding count back to GODSEYE.
- Pull requests and command completion are written to the audit log.

## Windows Agent v1.1
- Agent version updated to **1.1.0**.
- Management heartbeat now checks GODSEYE every 10 seconds for defined commands/rechecks.
- The normal Event Log collection interval remains independently configurable from 30–3600 seconds.
- A Pull Events Now command first flushes any durable pending batch, then performs a fresh bookmark-based collection so the operator receives current events.
- The agent remains read-only and does not implement generic shell, PowerShell, or arbitrary process execution.
- Existing durable queue and Event Record ID bookmark protections remain in place.

## Agent upgrade
- The v1.1 installer now recognizes an already-enrolled GODSEYE agent.
- Existing agent UUID, configuration, and DPAPI-protected API key are preserved.
- An already-enrolled agent can be upgraded without generating a new enrollment token.
- New installations still require a one-time enrollment token.

Example upgrade on the Windows endpoint:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-GODSEYEAgent.ps1 -ServerUrl "https://your-godseye-host"
```

If the endpoint currently uses the temporary `-SkipTlsVerify` setting, include that option again until proper GODSEYE certificate trust is installed.

## Compatibility
Windows Agent v1.0 continues normal scheduled event upload and recheck behavior, but GODSEYE intentionally disables Pull Events Now for v1.0 agents and prompts for an agent update.

## Validation caveat
The Windows service source, installer, command queue, heartbeat protocol, event upload workflow, UI, and API are automated-tested in the build environment. A real Windows service/endpoint was not available for live service installation or live Event Log pull validation during this build.
