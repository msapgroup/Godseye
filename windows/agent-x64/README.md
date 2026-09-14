# GODSEYE Windows Agent x64 v2.0.1

This is the permanent Windows Agent packaging model for GODSEYE.

- Real x64 Windows service executable.
- .NET 8 self-contained single-file build: no local C# compiler and no separate .NET runtime installation required.
- Real 64-bit Windows Setup EXE built with Inno Setup.
- Stable installer AppId so newer setup packages upgrade older v2 releases in place.
- Migrates the existing v1 service by preserving `%ProgramData%\GODSEYE\Agent` enrollment, DPAPI key, bookmarks, event queue, logs, and configuration.
- First installation asks only for the GODSEYE HTTPS URL and a one-time enrollment token.
- Future upgrades require no enrollment token and preserve configuration.
- Windows service name remains `GODSEYEWindowsAgent`, keeping GODSEYE server compatibility.
- Uses the existing stable GODSEYE Windows Agent API and Pull Events Now command channel.

Version 2.0.1 rebuilds the x64 installer with corrected `sc.exe create` service-path quoting so the installer no longer passes the malformed command line that caused Windows error 1639.

The installer intentionally preserves `%ProgramData%\GODSEYE\Agent` on uninstall so reinstall/upgrade does not destroy the enrolled identity.
