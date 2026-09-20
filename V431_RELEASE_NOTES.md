# GODSEYE v4.31 Remote Support Candidate

GODSEYE v4.31 retains the v4.30 visual rebuild and introduces Windows Agent 2.4.0 for a more reliable, Quick Assist-style remote-support workflow.

## Remote connection fix

- The persistent Windows tray application now owns consent and status only.
- After the signed-in user selects **Share Screen**, the service starts a unique per-session helper inside that same interactive Windows desktop.
- The service waits up to 20 seconds for a verified helper readiness response before entering capture state.
- The server marks a session active only after validating the first complete JPEG frame.
- Active-console changes restart the tray in the correct Windows session instead of retaining a stale tray process from a previous sign-in.
- The session helper displays a topmost sharing banner with **Stop Sharing** so the local user can end access immediately.

## Separate control permission

Sessions begin view-only. The operator must select **Request Control**, and the signed-in Windows user receives a second prompt for mouse and keyboard access. The server rejects and does not deliver input unless that decision is approved.

## Existing agent behavior retained

The installer still accepts the one-time enrollment token and preserves the existing ProgramData identity/configuration during upgrades. Windows Event Findings collection, durable event queues, bookmarks, heartbeat, Pull Events Now, and authenticated self-update remain in the same service.

## Candidate build status

The server protocol and source-level agent contracts are tested in Linux. A signed native Windows MSI/Setup executable must be produced by the included Windows GitHub Actions workflow (or `build-local.ps1`) and smoke-tested on Windows before production deployment.
