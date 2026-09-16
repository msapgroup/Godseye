# GODSEYE Windows Agent

GODSEYE V4.28 uses the permanent x64 Windows Agent as the recommended Windows Event Findings collector. The old endpoint-compiled PowerShell/C# agent is not shipped in this release.

## Installation

Open **Event Findings → Windows Agents**, create a one-time enrollment token, and select **Download x64 Installer**. Run `GODSEYE-Windows-Agent-x64-Setup.exe` as Administrator on the Windows workstation or server and enter the GODSEYE URL plus the one-time token.

The guided setup installs a real x64 MSI-owned Windows service. It does not require a C# compiler or separate .NET runtime on the endpoint.

## Installed locations

- Program files: `C:\Program Files\GODSEYE Agent\`
- Service executable: `C:\Program Files\GODSEYE Agent\GODSEYE.Agent.exe`
- Persistent state: `C:\ProgramData\GODSEYE\Agent\`
- Windows service: `GODSEYEWindowsAgent`

The ProgramData directory contains enrollment identity, the DPAPI-protected API key, configuration, Event Log bookmarks, the durable event queue, and agent logs. Installer upgrades replace Program Files without deleting this state.

## Server-independent lifecycle

The Windows Agent is versioned independently from the GODSEYE appliance. Future GODSEYE server versions continue using the stable Windows Agent API; the agent is not expected to be reinstalled for every server release.

When a newer agent version is published, administrators can use **Check for Updates / Upgrade Agent**. The service downloads the fixed authenticated MSI endpoint, validates the published SHA-256, and launches Windows Installer. A new enrollment token is not required for an already enrolled computer.

## Collection behavior

The agent reads the configured Windows Event Log channels locally, selecting Critical, Error, and Warning events. The defaults are `System` and `Application`. Event Record ID bookmarks prevent rereading old records, and pending batches are stored locally until GODSEYE acknowledges them.

**Pull Events Now** queues an immediate collection request. Targeted Event Finding rechecks use the same authenticated outbound connection. WinRM remains available only as an optional agentless fallback.

## Security

- One-time enrollment tokens are stored hashed on GODSEYE.
- Each enrolled endpoint receives a unique machine API key; GODSEYE stores its hash.
- Windows protects the local long-term key with DPAPI LocalMachine.
- Use HTTPS for the GODSEYE URL.
- Persistent agent state is stored under ProgramData and restricted to SYSTEM/local Administrators by the installer.
- Remote Access requires the signed-in Windows user's approval before desktop viewing/control starts.
- The Windows Agent does not provide a general command shell.

## Troubleshooting

```powershell
Get-Service GODSEYEWindowsAgent
Get-CimInstance Win32_Service -Filter "Name='GODSEYEWindowsAgent'" |
  Select-Object Name, State, StartMode, ProcessId, PathName
Get-Content "C:\ProgramData\GODSEYE\Agent\agent.log" -Tail 100
```

If an update is offered but fails, verify that the GODSEYE server contains a matching `update-manifest.json` and `GODSEYE-Windows-Agent-x64.msi`. V4.28 validates that pair before installation and before packaged updates are accepted.


## Independent agent release channel

The x64 Windows Agent has its own release lifecycle. GODSEYE server releases do not need to rebuild or reinstall the Windows Agent unless the stable Agent API contract changes.

Large Windows packages are published as GitHub Release assets under tags such as `windows-agent-v2.2.9`. Only the small `update-manifest.json` and SHA-256 metadata are refreshed on the main branch. This keeps MSI/EXE files out of normal Git pushes and avoids GitHub's 100 MB per-file Git limit.

When an administrator downloads the guided installer, or when an enrolled agent performs **Upgrade Agent**, the GODSEYE server:

1. reads the canonical release manifest;
2. accepts only release URLs for `msapgroup/Godseye` whose tag matches the manifest version and whose filename is canonical;
3. uses an already-packaged local file only when its SHA-256 matches the current manifest;
4. otherwise downloads the release asset into the GODSEYE data cache;
5. verifies SHA-256 before serving the package; and
6. serves agents only through the fixed GODSEYE package endpoint, never through an arbitrary command-supplied URL.

The cache lives beside the GODSEYE database under `windows-agent-cache`, so normal application upgrades do not need to re-download the current installer.
