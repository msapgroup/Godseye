# GODSEYE repository protection configuration

**Administrative setup required.** This document records recommended GitHub Rulesets, but adding it and CODEOWNERS does NOT automatically activate repository rules. The GitHub connector used to create these files does not have repository administration permission. Configure and save the rulesets in the official GitHub web UI. See https://github.com/msapgroup/Godseye/settings/rules .

## Main branch ruleset

Create a **branch ruleset** named `Protect GODSEYE main`, targeting the default branch (`main`), with enforcement **Active**.

Recommended rules:
- Restrict deletions; block force pushes.
- Require a pull request before merging (at least one approval, or more if there are multiple independent reviewers).
- Require review by code owners (CODEOWNERS assigns the `@msapgroup` account to all files and especially the signing keys and workflows).
- Dismiss stale pull request approvals on changes; require approval of the most recent reviewable push where supported.
- Require conversation resolution.
- Require status checks from consistently successful jobs, e.g. maintained server tests, copyright verification and CodeQL **after confirming exact check names in GitHub Actions**. Avoid selecting intermittent workflow names or untriggered path-filtered jobs as universally required.
- Do not enable broad bypass permissions; keep a documented emergency recovery process.

**Important:** GitHub generally does not allow a PR author to approve their own PR. With only one maintainer, requiring independent approvals may block all merges. Add a second trusted reviewer before enforcing approvals, or choose a less strict policy temporarily. A CODEOWNERS entry alone does not stop direct pushes or give legal ownership.

## Server release tag ruleset

Create a **tag ruleset** named `Protect GODSEYE server release tags`, targeting `server-v*` (not the existing Windows-agent tags), with enforcement **Active**.

Recommended rules:
- Restrict tag creation to designated maintainers only.
- Restrict updates and deletions and prevent other actors from replacing published tags.
- Avoid broadly granting bypass.
- Use the manual [signature verification workflow](https://github.com/msapgroup/Godseye/actions/workflows/verify-server-release-tag.yml) after creating a tag. A GitHub tag ruleset by itself does **not** cryptographically verify the signer; the fail-closed GPG verifier checks the trusted MSAP public key.
- Do not force-update `server-v4.31.0`, which is already published and signature-verified.

For consistency, tag protection should use the exact `server-v*` namespace, rather than blocking unrelated tag names used by the Windows agent. Test the tag patterns in GitHub's rule preview where available.

## Trusted signing key and workflow protection

The CODEOWNERS policy identifies who should review files under `docs/release-signing/`, verification scripts and workflows. Enforce it through `main` ruleset PR review requirements. Any key rotation should be independently verified against the new fingerprint on an MSAP-controlled computer.

## Verify enforcement after saving

- Confirm GitHub shows both rulesets as **Active** at repository Settings → Rules → Rulesets.
- Verify an ordinary user cannot force-push to `main`, and unreviewed pull requests cannot merge (without trying a destructive push).
- Check that editing a trusted signing key on a pull request requests the specified code owner.
- Confirm legitimate CI status checks are green and that new server tags are correctly permission-restricted.
- Document the maintainer emergency recovery procedure and ensure the second reviewer account is secured with MFA.

These protections affect repository governance only; they do not edit, build, or publish Windows-agent binaries. They do not prohibit GPL-compliant forks, nor do they make copyright claims impossible to falsify.
