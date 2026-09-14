# GODSEYE Windows Agent x64 v2.2.6

GODSEYE Windows Agent 2.x is a standalone x64 Windows service with its own installer lifecycle and versioning. It is designed to remain compatible with future GODSEYE server releases through the stable Windows Agent API rather than being rebuilt for every server release.

## Packaging model

- `GODSEYE.WindowsAgent.exe` is a compiled .NET 8 self-contained x64 Windows service executable.
- `GODSEYE-Windows-Agent-x64.msi` is the authoritative Windows Installer package.
- `GODSEYE-Windows-Agent-x64-Setup.exe` is the guided x64 bootstrapper.
- Windows Installer owns service registration, repair, upgrade, rollback and uninstall.
- 32-bit Windows is not supported.

## Installed locations

Application binaries are installed under:

`C:\Program Files\GODSEYE Agent\`

Persistent agent data is stored separately under:

`C:\ProgramData\GODSEYE\Agent\`

The ProgramData directory contains enrollment identity, the DPAPI-protected API key, configuration, Event Log bookmarks, queued events and logs. MSI upgrades replace application binaries without replacing this persistent state.

## Windows service

- Service name: `GODSEYEWindowsAgent`
- Display name: `GODSEYE Windows Agent`
- Startup: Automatic
- Account: `LocalSystem`
- Service installation/removal is authored natively in WiX with Windows Installer `ServiceInstall` and `ServiceControl`.
- Failure recovery is configured by the installer to restart the service after failures.

## First installation

On a new computer, run the guided Setup EXE. It asks for the GODSEYE server URL and a one-time Windows Agent enrollment token, installs the MSI, configures the agent, starts the Windows service, and waits for the DPAPI-protected API key to be created before considering enrollment complete.

For trusted production environments, keep TLS certificate verification enabled. The Setup EXE also offers an explicit untrusted/self-signed certificate mode for controlled LAN testing.

## Upgrade and repair behavior

If `%ProgramData%\GODSEYE\Agent\agent.json` already exists, Setup now shows three choices instead of silently assuming the old enrollment is healthy:

1. **Keep existing enrollment** — normal binary upgrade; preserves identity and API key.
2. **Repair / re-enroll this computer** — preserves the existing agent UUID/bookmarks/queue, clears the old DPAPI API key, accepts a fresh server URL and one-time token, and re-enrolls the same computer identity. Before using this mode, revoke the old offline Windows Agent entry in GODSEYE so the existing UUID can be re-keyed.
3. **Reset enrollment and register as a new agent identity** — clears the old enrollment identity/API key but preserves Event Log bookmarks, pending queue and logs. This is the fallback if the old GODSEYE agent record cannot be repaired; the old offline row can be revoked afterward.

The guided installer stops the service before changing enrollment state, restarts it after configuration, and waits up to 45 seconds for enrollment to complete. If enrollment fails, it points to `%ProgramData%\GODSEYE\Agent\agent.log` and gives a specific message when the existing identity is still active on the server.

## Compatibility model

The agent communicates through the stable GODSEYE Windows Agent API:

`GODSEYE Agent 2.x -> stable Windows Agent API -> future GODSEYE server releases`

Server upgrades should not require reinstalling the Windows Agent. Agent releases have their own independent version numbers.

## Pull Events Now and updates

The existing Pull Events Now command channel remains supported. GODSEYE exposes current agent/update information in the Windows Agents view. Administrators can check for and install compatible agent updates while preserving ProgramData state.

## Build validation

GitHub Actions builds the service and installer packages on `windows-latest` and performs an MSI lifecycle smoke test verifying service creation, x64 Program Files installation, automatic LocalSystem startup, clean uninstall, and ProgramData preservation.

## Code signing

The MSI and Setup EXE are not yet Authenticode-signed by this build pipeline. Production signing should be added using an MSAPGROUP code-signing certificate or managed signing service stored outside the repository. Do not commit a private signing key to GitHub.
