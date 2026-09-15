# GODSEYE v4.22.1 — Windows Agent Upgrade Hotfix

## Why this hotfix
The first v1.1 upgrade path could fail while replacing the running Windows service executable or could unintentionally change the existing TLS-verification setting when the upgrade command omitted `-SkipTlsVerify`.

## Windows Agent v1.1.1
- Existing enrolled agents can now upgrade with simply:
  `./Install-GODSEYEAgent.ps1`
- `ServerUrl` is reused from the current `agent.json` when omitted during an upgrade.
- Existing agent UUID, DPAPI-protected API key, bookmarks, pending event queue, configured channels, polling interval, and TLS setting are preserved.
- The installer now checks that it is running in an elevated Administrator PowerShell session.
- The old service is stopped and its process is confirmed released before replacement.
- The new executable is compiled to a staging file instead of compiling directly over the installed executable.
- A backup executable is retained during replacement.
- Compilation failure leaves the previously installed executable unchanged.
- Service startup is verified after the upgrade.
- If startup fails, recent `agent.log` lines are printed to help diagnose the failure.

## Pull Events Now
All v4.22 Pull Events Now functionality is retained. Agent v1.1.1 remains compatible with the existing v4.22 command API.

## Validation
Automated tests cover upgrade-preservation behavior, staging/replace protections, TLS-setting preservation, service restart validation, Pull Events Now server compatibility, and prior GODSEYE regressions.

A real Windows service could not be upgraded inside the Linux build container, so the first Windows endpoint upgrade remains the live validation of Windows Service Control Manager behavior.
