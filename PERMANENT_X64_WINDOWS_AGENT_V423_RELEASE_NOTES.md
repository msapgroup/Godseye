# GODSEYE v4.23 — Permanent x64 Windows Agent Installer

## New permanent Windows Agent model
- Replaces the PowerShell/C# compile-on-endpoint packaging model with a real Windows Setup EXE.
- Installs a real x64 Windows service executable built as a self-contained .NET 8 single-file application.
- Does not require a C# compiler on the Windows endpoint.
- Does not require a separate .NET runtime installation.
- Windows service name remains `GODSEYEWindowsAgent`, preserving GODSEYE server compatibility.
- Agent data remains in `%ProgramData%\GODSEYE\Agent` and is preserved across upgrades.
- Existing v1 enrollment, DPAPI-protected API key, bookmarks, pending event queue, and configuration are preserved when migrating to v2.
- A stable installer AppId makes future v2+ Setup packages upgrade the installed agent in place.
- First installation prompts for GODSEYE URL and a one-time enrollment token.
- Future installer upgrades detect the existing configuration and do not ask for a new enrollment token.
- HTTPS is recommended. HTTP is allowed only after an explicit trusted-LAN warning.

## Existing capabilities retained
- Critical/Error/Warning Windows Event Log collection.
- Event Record ID bookmarks.
- Durable offline event queue.
- Agent heartbeat and status.
- Event Findings integration.
- Pull Events Now.
- Targeted Event Finding rechecks.
- Server-side channel and collection interval configuration.
- DPAPI LocalMachine protection for the agent API key.

## Build pipeline
- Added a Windows GitHub Actions build on `windows-latest`.
- Builds the service with .NET 8 for `win-x64`.
- Builds the Setup EXE with Inno Setup.
- Publishes the Setup EXE, raw x64 service executable, README, and SHA-256 checksum as a workflow artifact.

## Validation boundary
The Windows build pipeline completed successfully on a real Windows GitHub Actions runner. The produced service executable is PE32+ x86-64. The Setup EXE was successfully compiled by Inno Setup. Installation on a user Windows endpoint remains the final live validation of Service Control Manager behavior, local Event Log permissions, enrollment, and network connectivity to the user's GODSEYE appliance.
