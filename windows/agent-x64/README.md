# GODSEYE Windows Agent x64 v2.2.7

GODSEYE Windows Agent 2.x is a standalone x64 Windows service with its own installer lifecycle and versioning. It is designed to remain compatible with future GODSEYE server releases through the stable Windows Agent API rather than being rebuilt for every server release.

## Packaging model

- `GODSEYE.WindowsAgent.exe` is a compiled .NET 8 self-contained x64 Windows service executable.
- `GODSEYE-Windows-Agent-x64.msi` is the authoritative Windows Installer package.
- `GODSEYE-Windows-Agent-x64-Setup.exe` is the guided x64 bootstrapper. It collects first-install enrollment information and delegates installation to the MSI.
- Windows Installer owns service registration, repair, upgrade, rollback and uninstall. The supported installer path does not use PowerShell or `sc.exe` to create the service.
- 32-bit Windows is not supported.

## Installed locations

Application binaries are installed under:

`C:\Program Files\GODSEYE Agent\`

Persistent agent data is stored separately under:

`C:\ProgramData\GODSEYE\Agent\`

The ProgramData directory contains enrollment identity, the DPAPI-protected API key, configuration, Event Log bookmarks, queued events and logs. MSI upgrades replace application binaries without replacing this persistent state. Uninstall removes the Windows service and installed application files but intentionally preserves the ProgramData state so reinstall or upgrade does not destroy the enrolled identity.

## Windows service

- Service name: `GODSEYEWindowsAgent`
- Display name: `GODSEYE Windows Agent`
- Startup: Automatic
- Account: `LocalSystem`
- Service installation/removal is authored natively in WiX with Windows Installer `ServiceInstall` and `ServiceControl`.
- Failure recovery is configured by the installer to restart the service after failures.

## Enrollment and upgrades

On a new computer, the guided Setup EXE asks for the GODSEYE server URL and a one-time Windows Agent enrollment token. It installs the native MSI and then runs the agent's built-in configuration mode.

If `%ProgramData%\GODSEYE\Agent\agent.json` already exists, the guided installer treats the computer as an existing installation and skips the enrollment pages. MSI upgrades therefore do not require the server address or a new enrollment token.

The agent communicates through the stable GODSEYE Windows Agent API and keeps the existing Pull Events Now command channel. The intended compatibility model is:

`GODSEYE Agent 2.x -> stable Windows Agent API -> future GODSEYE server releases`

## Build validation

GitHub Actions builds the service and installer packages on `windows-latest`. The Windows pipeline also performs an MSI lifecycle smoke test that:

- installs the MSI silently;
- verifies `GODSEYEWindowsAgent` exists;
- verifies automatic startup under `LocalSystem`;
- verifies the service executable is installed from `Program Files`;
- uninstalls the MSI;
- verifies the Windows service is removed; and
- verifies ProgramData state survives uninstall.

The workflow publishes SHA-256 files for both the MSI and guided Setup EXE and updates the generated packages on `main` after a successful build.

## Code signing

The MSI and Setup EXE are not yet Authenticode-signed by this build pipeline. Production signing should be added using an MSAPGROUP code-signing certificate or managed signing service stored outside the repository. Do not commit a private signing key to GitHub.

## Agent updates

Version 2.2.7 is the packaged v4.25 agent baseline; self-update support began with 2.1.0. GODSEYE exposes the current agent version and SHA-256 manifest in the Windows Agents view. An administrator can use **Check for Updates** and, for agents already on 2.1.0 or newer, **Upgrade Agent**. The service downloads only the fixed authenticated GODSEYE MSI endpoint, verifies the published SHA-256, and starts Windows Installer silently. The update payload cannot supply an arbitrary URL, executable, shell, or command.

Agents on 2.0.x require one manual upgrade using the current x64 Setup/MSI before self-update is available. That baseline upgrade preserves `%ProgramData%\GODSEYE\Agent`, including enrollment, DPAPI-protected API key, bookmarks, pending queue, logs, and configuration. After that baseline, future agent releases can be upgraded from GODSEYE without another enrollment token.
