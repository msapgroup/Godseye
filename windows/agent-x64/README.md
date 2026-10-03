# GODSEYE Windows Agent x64 v2.4.5

GODSEYE Windows Agent 2.x is a standalone x64 Windows service with its own installer lifecycle and versioning. It is designed to remain compatible with future GODSEYE server releases through the stable Windows Agent API rather than being rebuilt for every server release.

## Packaging model

- `GODSEYE.Agent.exe` is a compiled .NET 8 self-contained x64 Windows service executable.
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

Configuration saves use a flushed atomic replacement and retain `agent.json.bak`. If the main file is damaged, the agent restores a valid backup while preserving the damaged file as `agent.json.corrupt-*`. It does not invent a new identity or overwrite an unrecoverable configuration. Logs identify whether invalid JSON came from the configuration, pending event file, or a server response. An elevated `GODSEYE.Agent.exe --check-config` checks configuration and attempts recovery from an existing valid backup without contacting the server.

If Setup fails, its detailed MSI log is saved to `C:\ProgramData\GODSEYE\Agent\setup-msi.log`. Run the current Setup directly over an existing 2.4.5 or mismatched 2.5.x installation. Setup stops the old service and tray, replaces the package, and restarts the service. Healthy enrollment is retained; missing or invalid enrollment opens the connection settings. Keep ProgramData intact.

## Windows service

- Service name: `GODSEYEWindowsAgent`
- Display name: `GODSEYE Windows Agent`
- Startup: Automatic
- Account: `LocalSystem`
- Service installation/removal is authored natively in WiX with Windows Installer `ServiceInstall` and `ServiceControl`.
- Failure recovery is configured by the installer to restart the service after failures.

## Enrollment and upgrades

Run **GODSEYE-Windows-Agent-x64-Setup-2.4.5.exe**. After Welcome, the first choice screen is **Optional Godseye EDR**: select **Install Godseye EDR scanner (YARA-X)** or **Agent only (skip Godseye EDR scanner)**, then click Next. This screen also appears on enrolled computers. Agent only is the default for a new installation; an existing EDR installation defaults to keeping EDR. Both choices retain the core agent, Cyber Tools integration, and consent-based Remote Access. Direct MSI installs do not show the guided choice screen.

On a new computer, the following screens ask for the GODSEYE server URL and a one-time Windows Agent enrollment token. Setup installs the native MSI and then runs the agent's built-in configuration mode.

If `%ProgramData%\GODSEYE\Agent\agent.json` already exists, the guided installer treats the computer as an existing installation and skips the enrollment pages. MSI upgrades therefore do not require the server address or a new enrollment token.

The agent communicates through the stable GODSEYE Windows Agent API and keeps the existing Pull Events Now command channel. The intended compatibility model is:

`GODSEYE Agent 2.x -> stable Windows Agent API -> future GODSEYE server releases`

## Local Windows build

A local Windows x64 machine can build and validate the same Agent packages without changing GitHub. From an elevated PowerShell prompt in the repository, run:

```powershell
.\windows\agent-x64\build-local.ps1
```

Requirements are the .NET 8 SDK and Inno Setup 6. The WiX 6 SDK is restored by the installer project through `dotnet build`. By default the script publishes `GODSEYE.Agent.exe`, builds the MSI, performs an install/uninstall lifecycle smoke test, verifies service identity and ProgramData preservation, builds the guided Setup EXE, writes SHA-256 files, and changes `update-manifest.json` to `ready` only after the MSI has been built and hashed. Use `-SkipInstallSmoke` only when intentionally doing a compile-only developer build.

## Build validation

GitHub Actions builds the service and installer packages on `windows-latest`. The Windows pipeline also performs an MSI lifecycle smoke test that:

- installs the MSI silently;
- verifies `GODSEYEWindowsAgent` exists;
- verifies automatic startup under `LocalSystem`;
- verifies the service executable is installed from `Program Files`;
- uninstalls the MSI;
- verifies the Windows service is removed; and
- verifies ProgramData state survives uninstall.

The workflow publishes SHA-256 files for both the MSI and guided Setup EXE as downloadable CI artifacts. After a successful build publishes the validated release, **Sync validated Windows installers** downloads and verifies the published SHA-256 digests, then updates the Setup EXE, MSI, checksum files, and manifests in this folder on main. The standalone service EXE remains a release asset because it exceeds GitHub's normal file-size limit.

## Code signing

The MSI and Setup EXE are not yet Authenticode-signed by this build pipeline. Production signing should be added using an MSAPGROUP code-signing certificate or managed signing service stored outside the repository. Do not commit a private signing key to GitHub.

## Agent updates

Version 2.4.5 is the current v4.31 remote-support release. Agents on 2.1.x and newer remain eligible for authenticated self-update once a signed/validated 2.4.5 MSI is installed on the GODSEYE server. GODSEYE exposes the current agent version and SHA-256 manifest in the Windows Agents view. An administrator can use **Check for Updates** and, for agents already on 2.1.0 or newer, **Upgrade Agent**. The service downloads only the fixed authenticated GODSEYE MSI endpoint, verifies the published SHA-256, and starts Windows Installer silently. The update payload cannot supply an arbitrary URL, executable, shell, or command.

Agents on 2.0.x require one manual upgrade to 2.1.0 using the current x64 Setup/MSI. That baseline upgrade preserves `%ProgramData%\GODSEYE\Agent`, including enrollment, DPAPI-protected API key, bookmarks, pending queue, logs, and configuration. After that baseline, future agent releases can be upgraded from GODSEYE without another enrollment token.


## Endpoint malware response and optional EDR in 2.4.5

The existing consent-based remote support and tray workflow remain in this agent build. The integrated installer adds per-user tray startup and optional YARA-X EDR scans with an explicit heartbeat capability flag; Microsoft Defender handles real-time protection and signature updates. Cyber Tools can ask the enrolled agent to review Microsoft Defender status and detections, run a quick scan, and (after an exact PC-name confirmation by a GODSEYE admin) ask Defender to remove active threats. ClamAV can update its signatures with FreshClam and scan Windows user profiles as a second opinion when it is installed on that PC. No arbitrary script or shell command is accepted from the server.

## Remote support in 2.4.5

Remote support consent, capture, and approved input are owned by the persistent tray application in the signed-in Windows user's active interactive session. The Windows service cannot approve a session on the user's behalf. The server tracks `requested -> waiting_for_tray -> tray_ready -> waiting_for_user -> approved -> capture_started`, and only changes the session to `active` after it receives and validates the first real JPEG frame. Sessions begin view-only. Mouse and keyboard input is accepted only after the operator requests control and the Windows user separately approves it.

The source tree contains only the current x64 agent under `windows/agent-x64`. Older agent files and generated build outputs are excluded from the full app package. A 2.4.5 update manifest is valid only when its canonical `GODSEYE-Windows-Agent-x64.msi` exists and its SHA-256 matches the manifest.
