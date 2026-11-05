# GODSEYE security maintenance review

## Scope and current access

The server's Python dependency manifest is `requirements.txt` at the repository root. `.github/dependabot.yml` checks that manifest **weekly, Monday at 09:00 America/New_York**, and proposes up to three version-update pull requests for maintainer review. Changes are **not auto-merged** and must pass the existing protected-`main` checks.

The Windows-agent source, installer assets and `.github/workflows/build-windows-agent.yml` are **not targeted** by this Dependabot configuration. No agent rebuild is requested.

## Review procedures

1. Review [Dependabot alerts](https://github.com/msapgroup/Godseye/security/dependabot) in an authenticated GitHub session. Prioritize critical and high alerts, and investigate affected direct and transitive packages and reachable code.
2. Review [Code scanning alerts](https://github.com/msapgroup/Godseye/security/code-scanning), identify affected files, exploitability, and remediation; avoid dismissing alerts without recorded justification.
3. Review [Secret scanning alerts](https://github.com/msapgroup/Godseye/security/secret-scanning), if available. Revoke and rotate any genuine exposed credentials before adjusting history, and avoid copying secrets into issues.
4. Review [Dependabot pull requests](https://github.com/msapgroup/Godseye/pulls?q=is%3Apr+author%3Aapp%2Fdependabot). Confirm changes, license compatibility, and passing server regression and CodeQL checks. Watch for major-version compatibility changes.
5. Never auto-merge security fixes solely on a version number. If the Windows agent requires an update, handle it as an **explicitly approved separate change**.

## GitHub administrative settings

**Important:** The Dependabot configuration schedules version update PRs; it does **not** independently enable security alerts or security update PRs. A repository administrator must confirm Dependabot alerts, Dependabot security updates, and dependency graph are enabled in Settings → Advanced Security (location labels may vary by GitHub plan and UI).

The connected GitHub tool used for this maintenance does not expose the authenticated private alert APIs, so absence of returned alerts must **not** be taken to mean there are zero vulnerabilities. Security-alert status must be confirmed in the authenticated GitHub UI.

## Reporting

Maintain a record of alert identifier, severity, affected package and version, fixed version, evidence, pull request, CI result, and final disposition. Record a reason for dismissing false positives or accepted risk. Do not count the intentionally failing branch-protection test PR as a production failure.
