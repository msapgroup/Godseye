# GODSEYE Windows Agent x64 — 2.2.10 source

The GODSEYE Windows Agent is a compiled, self-contained **64-bit Windows service** with an installer lifecycle independent from the GODSEYE server release number.

## Recommended installer

For a normal first installation, download the current package from **Event Findings → Windows Agents** or the [Windows Agent GitHub Release](https://github.com/msapgroup/Godseye/releases), then use:

`GODSEYE-Windows-Agent-x64-Setup.exe`

The guided setup asks for the GODSEYE server URL and a one-time enrollment token, then installs the authoritative x64 MSI.

For software deployment systems, the authoritative package is:

`GODSEYE-Windows-Agent-x64.msi`

The MSI installs without enrollment prompts. For a first installation on a workstation, run the guided Setup EXE. If the MSI was installed before enrollment, run Setup afterward; it will ask for the server URL and a token.

The installed service binary is:

`C:\Program Files\GODSEYE Agent\GODSEYE.Agent.exe`

Persistent enrollment and runtime state is stored separately under:

`C:\ProgramData\GODSEYE\Agent\`

## Upgrade model

The Windows Agent has its own version number. A future GODSEYE server build does **not** require reinstalling the agent just because the server version changed.

The stable contract is:

`Windows Agent 2.x -> GODSEYE Windows Agent API v1 -> GODSEYE server`

The MSI uses a stable Windows Installer UpgradeCode and Windows Installer owns service stop/start, repair, replacement, rollback, and uninstall. ProgramData is intentionally not owned by the MSI, so upgrades and uninstall/reinstall do not delete enrollment identity, the DPAPI-protected API key, Event Log bookmarks, queued events, or agent configuration.

Agents at the self-update baseline can also be upgraded from **Event Findings → Windows Agents → Upgrade Agent**. The Windows Agent is distributed through a dedicated GitHub Release channel that is independent from the GODSEYE server build number. GODSEYE reads the small signed-by-hash release manifest, downloads the canonical MSI into a local cache when needed, verifies SHA-256, and then serves only the fixed MSI endpoint to enrolled agents. The agent verifies that same MSI SHA-256 again before starting `msiexec.exe`.

Large MSI/EXE/service binaries are **not stored in the repository file list**. The installer and MSI live as GitHub Release assets tagged `windows-agent-vX.Y.Z`; the service executable is included in the workflow artifact and installer. Do not download an installer from an old commit in Git history.

## Windows service

- Service name: `GODSEYEWindowsAgent`
- Display name: `GODSEYE Windows Agent`
- Architecture: x64
- Runtime: self-contained .NET 8; no separate .NET runtime install is required
- Account: LocalSystem
- Startup: Automatic
- Installed binaries: `C:\Program Files\GODSEYE Agent\`
- Persistent data: `C:\ProgramData\GODSEYE\Agent\`

## Event collection

The service reads configured Windows Event Log channels locally and sends only selected Critical, Error, and Warning records to GODSEYE. It maintains Event Record ID bookmarks and a durable pending queue so a temporary network or GODSEYE outage does not silently discard the current batch.

Supported management operations include heartbeat/status, **Pull Events Now**, targeted Event Finding recheck, server-managed channel/interval configuration, agent update, and user-approved Remote Access. The agent does not expose a general shell or arbitrary PowerShell execution endpoint.

## First installation

1. In GODSEYE, open **Event Findings → Windows Agents**.
2. Create a one-time enrollment token.
3. Download the x64 installer.
4. Run `GODSEYE-Windows-Agent-x64-Setup.exe` as Administrator.
5. Enter the GODSEYE URL and enrollment token.

HTTPS is recommended. If a private CA or self-signed certificate is used, deploy that CA/certificate to Windows trust rather than leaving TLS verification disabled.

## Future upgrades

Run a newer guided Setup EXE or MSI on the same computer. Existing `%ProgramData%\GODSEYE\Agent\agent.json` and `agent.key` are preserved, so no new enrollment token is required. A configuration file without an enrolled key is treated as an incomplete installation and the guided Setup asks for a new token.

## Build pipeline

`.github/workflows/build-windows-agent.yml` is the single Windows Agent build definition. It:

- publishes the `win-x64` self-contained `GODSEYE.Agent.exe`;
- verifies the produced PE machine type is x86-64;
- builds `GODSEYE-Windows-Agent-x64.msi` with WiX;
- installs, repairs, and uninstalls the MSI on a Windows runner;
- verifies the Windows service and preserved ProgramData state;
- verifies that tray startup is registered and removed on uninstall;
- builds the guided Setup EXE;
- generates SHA-256 files and `update-manifest.json`;
- uploads the full package set as a workflow artifact;
- publishes the MSI and guided Setup EXE as durable GitHub Release assets under `windows-agent-vX.Y.Z`;
- refreshes only the small release manifest/hash metadata on `main`; and
- checks that package names, release URLs, and hashes agree before publication.

This validation prevents filename/version drift while keeping large binaries out of normal Git pushes.

## Code signing

The supplied package is not Authenticode-signed unless the release artifact explicitly states otherwise. A production signing certificate should be added to the Windows workflow using a protected signing service or secret-backed certificate; never commit a private signing key to the repository.
