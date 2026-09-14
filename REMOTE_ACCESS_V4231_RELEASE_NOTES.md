# GODSEYE v4.23.1 — Remote Access

- Adds an administrator-only **Remote Access** workspace listing enrolled Windows Agents.
- Windows Agent 2.2.0 launches a consent prompt in the signed-in user session before remote support begins.
- Remote sessions stream JPEG desktop frames over the existing authenticated Agent API and accept only whitelisted pointer/keyboard events.
- No remote shell, arbitrary process execution, registry command, or unrestricted file command is exposed by the Remote Access channel.
- Session start/stop is written to the GODSEYE audit log.
- Existing Agent enrollment and ProgramData state are preserved by MSI upgrades.
