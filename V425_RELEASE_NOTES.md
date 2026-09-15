# GODSEYE v4.25.0 — Consolidated Stable Build

GODSEYE v4.25.0 consolidates the current server application, Windows Event Findings, Ticket Portal, Calendar/Email/Reports management, Remote Access, Windows Agent management, and the latest validated x64 Windows Agent installer artifact into one full install/upgrade package.

## Windows Agent included

The release includes Windows Agent **2.2.7** as a compiled self-contained x64 Windows executable plus a native Windows Installer MSI and guided Setup EXE. The agent is independently versioned from the GODSEYE server and uses the stable `/api/v1/windows-agents/...` contract so normal future GODSEYE server releases do not require reinstalling the Windows agent.

The agent supports Windows Event Findings collection, Pull Events Now, durable event state, heartbeat/enrollment, hash-verified MSI self-update for supported 2.x agents, and user-approved Remote Access. Remote Access does not expose an arbitrary shell or PowerShell execution channel.

Application binaries install under `C:\Program Files\GODSEYE Agent\`; persistent enrollment/configuration/bookmarks/queue state remains under `C:\ProgramData\GODSEYE\Agent\` across MSI upgrades.

## Server upgrade

Use `sudo bash ./install.sh --upgrade` for an existing appliance. The Linux installer preserves `/var/lib/godseye`, the SQLite database, secrets/configuration, `/etc/godseye.env`, and creates a pre-upgrade database backup before deploying v4.25.

## Validation boundary

The GODSEYE Python/server regression suite, application import/migrations, JavaScript syntax, shell syntax, packaged Windows binary structure, MSI/update-manifest hashes, archive integrity, and agent/server API contracts are validated in this build environment. The included Agent 2.2.7 executable/MSI/Setup are previously produced Windows build artifacts; this Linux environment cannot itself perform a new Windows Service Control Manager install or an interactive Remote Access session. Those Windows-specific behaviors require the Windows CI/host smoke test.
