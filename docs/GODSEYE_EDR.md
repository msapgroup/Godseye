# Godseye EDR integration status

The Godseye EDR sidebar provides per-agent opt in, server-side rule validation,
versioned rule packs, rollback, queued quick/full scans, and reported results.
Existing Windows Agent remote access and the separate ClamAV integration are
unchanged. New agents default to EDR excluded.

## Using the page

1. An administrator opens **Godseye EDR** and checks that the server validator
   shows ready. It requires the YARA-X `yr` CLI on the Godseye server.
2. Review the rule source and its redistribution license. Select a `.yar` or
   `.yara` file, provide the source notes, and choose **Validate and publish**.
   The server compiles the rules before activating them and records a SHA-256.
3. Enable EDR on a compatible endpoint. The core agent remains installed if
   EDR is excluded. Queue a quick or full scan; the command result appears in
   **Scan jobs and findings**. An administrator can reactivate an older rule
   pack to roll back.

## Release gate

The current Windows Agent 2.4.5 package does **not** contain the YARA-X
executable. Agent 2.5.0 builds on the 2.4.5 source, keeping its Defender,
ClamAV update, ticket, and user-approved remote access paths. The server
rejects EDR scans from agents older than 2.5.0. The updated service looks for
`C:\Program Files\GODSEYE Agent\EDR\yr.exe`, verifies the server rule pack
version and SHA-256, and reports scan errors rather than a clean result.

The optional component is selected in the guided Setup; a core-only MSI install
omits YARA-X. The Windows build retrieves YARA-X v1.21.0 from its official
release and verifies the published SHA-256 before packaging it. Validate the
Windows MSI upgrade from 2.4.5 and the EDR tray GUI before rollout. This
release provides **on-demand YARA scanning**; continuous behavior protection
and quarantine remain future work. An endpoint selected in the sidebar is not
described as protected solely on that basis.
