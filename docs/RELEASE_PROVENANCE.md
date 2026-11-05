# Verify official GODSEYE server packages

This guide covers **server-only source ZIPs** produced by the GODSEYE tests workflow. It does **not** sign, package, change, or rebuild the Windows Agent.

## Source of trust

Only use a ZIP downloaded from the official [msapgroup/Godseye Actions runs](https://github.com/msapgroup/Godseye/actions/workflows/test.yml) for a successful `main` commit. The workflow first runs the maintained tests, packages the server-only source ZIP, and then runs a separate provenance job with restricted attestation permissions. Pull requests cannot mint official build attestations in this workflow.

GitHub's short-lived keyless Sigstore identity binds the ZIP's digest to the source repository and build workflow. This provides independently verifiable **build provenance**, not legal proof of copyright ownership and not an MSAP-owned long-term code-signing key.

## Download and verify

1. Open the successful `GODSEYE tests` run for the desired `main` commit.
2. Download both Actions artifacts: `GODSEYE-server-4.31.0-no-agent` (contains the ZIP) and `GODSEYE-server-4.31.0-no-agent-sha256` (contains the checksum).
3. Extract the two artifacts into the same directory. Compare checksum using:

   ```bash
   sha256sum -c GODSEYE-server-4.31.0-no-agent.zip.sha256
   ```

   On Windows, PowerShell: `Get-FileHash .\GODSEYE-server-4.31.0-no-agent.zip -Algorithm SHA256`; compare the digest to the checksum file.

4. Install the official [GitHub CLI](https://cli.github.com/) and verify the signed build attestation while connected to GitHub:

   ```bash
   gh attestation verify GODSEYE-server-4.31.0-no-agent.zip --repo msapgroup/Godseye
   ```

   Check that the reported source repository, commit, and workflow match the trusted `main` run you selected. A matching checksum alone is **not** proof that a package came from MSAP Group LLC.

If attestation verification fails, the run has no attestation, or the digest does not match, **do not install the ZIP**. GitHub Actions artifacts are retained for a limited time (currently 30 days); long-term public releases should separately publish the checksum and attested archive.

## Signed Git tags (maintainer setup)

The repository now includes a fail-closed, manually triggered verifier for **MSAP-controlled server release tags**. See [RELEASE_SIGNING.md](RELEASE_SIGNING.md) for key enrollment, Windows/desktop setup, signing steps, and independent verification. No public signing key has been enrolled yet, so no MSAP tag signature is claimed. Existing agent tags are not changed.


Build attestations use GitHub's workflow identity. If MSAP Group LLC also wants a personally signed release tag, a maintainer must configure a verified signing key in their GitHub account and create the signed tag with that key. Do not copy or commit the private key, and do not claim a tag is signed until GitHub verifies it.

For example, after configuring Git signing locally, release maintainers can use `git tag -s <release-tag> -m "Official GODSEYE release"`, push that exact tag, and verify it with `git tag -v <release-tag>`. The tag's signature verifies the maintainer's signing key, distinct from the build attestation's workflow identity.

## Limitations

The ZIP is the tested server-only source archive, **not** a separately signed Windows executable or a published GitHub Release. A third party can still fork GPL-covered code, remove nonmandatory descriptive text, or distribute modified versions in compliance with applicable law. Preserve copyright notices required by the licenses. Source commits, hashes, signature verification, and workflow attestations support provenance claims; they cannot physically prevent copying.
