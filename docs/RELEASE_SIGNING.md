# MSAP-controlled signed GODSEYE server release tags

**Status: MSAP public signing key enrolled; first signed server release tag pending.** A release is **not** MSAP-signed until the MSAP-controlled private key signs an annotated server release tag and the verification workflow passes. The repository's existing GitHub/Sigstore build attestations are separate from maintainer signatures.

This process applies only to **server** release tags named `server-vMAJOR.MINOR.PATCH` (optionally followed by a suffix), and does not build, change, or sign Windows-agent installers. Do not reuse existing `*-agent*` tags.

## 1. Create and safeguard an MSAP-controlled signing key

Perform these steps **on a trusted MSAP-owned computer**, never in GitHub Actions or a public chat. Install Gpg4win (Windows) or GnuPG (Linux/macOS).

```bash
gpg --full-generate-key
gpg --list-secret-keys --keyid-format LONG --with-fingerprint
```

Use a dedicated release-signing identity controlled by MSAP Group LLC, a strong passphrase, and a secure offline recovery backup. Record the full fingerprint independently. Keep the **private** key and passphrase out of GitHub, source ZIPs, and chat messages.

Export **only the public key**:

```bash
gpg --armor --export YOUR_FULL_KEY_FINGERPRINT > MSAP_RELEASE_PUBLIC.asc
```

The public key is enrolled at `docs/release-signing/trusted-keys/msap-release.asc`. Its primary fingerprint is `5EFDDA68D70FF90FB42085878F67C9511E989B46` (MSAP Group LLC, info@msapgroupllc.com). Independently compare that fingerprint with Kleopatra on the MSAP-controlled computer. Inspect the fingerprint in the PR against the independent MSAP-controlled record. Public-key enrollment establishes the trusted signer set; the verifier still rejects unsigned or unapproved tags. Rotate keys by reviewing/removing trusted public keys and recording the transition.

In GitHub account **Settings → SSH and GPG keys → New GPG key**, enroll the same **public** GPG key so GitHub can display verified tags. This requires a signed-in account owner and cannot be done by editing the repository.

## 2. Sign a server-only release tag locally

After enrolling the key, configure signing locally:

```bash
git config --global user.signingkey YOUR_FULL_KEY_FINGERPRINT
git config --global tag.gpgSign true
git fetch origin main --tags
git switch main
git pull --ff-only origin main
git tag -s server-v4.31.1 -m "MSAP Group official GODSEYE server release"
git verify-tag server-v4.31.1
git push origin refs/tags/server-v4.31.1
```

Replace the example version with the actual intended server release. **Do not execute the example tag command for an unapproved release.** The tag must point to a reviewed commit already reachable from official `main`.

A tag signature authenticates a release tag, **not** the copyright ownership of every file and not a Windows Agent package.

## 3. Verify release tags

Run the manual [Verify MSAP server release tag](https://github.com/msapgroup/Godseye/actions/workflows/verify-server-release-tag.yml) workflow, entering the existing `server-v...` tag. It uses only the public keys committed to `docs/release-signing/trusted-keys/`, checks the annotated tag's GPG signature and requires the target commit to be in official `main` history.

Or locally, after fetching tags and main:

```bash
git fetch origin main --tags
bash scripts/verify_signed_release_tag.sh server-v4.31.1
```

This check refuses missing keys, lightweight tags, invalid signatures, unknown signer keys, incorrect tag names, and commits not present in `main`. Public key files are trust anchors and should require maintainer review.

For the actual tested server ZIP, separately verify the checksum and GitHub/Sigstore build attestation in [RELEASE_PROVENANCE.md](RELEASE_PROVENANCE.md). A valid Git tag **does not** mean an arbitrary downloaded ZIP was generated from that tag.

## 4. Recommended GitHub settings

Repository administrators should protect `main` and release tags using repository rulesets and limit who can modify `docs/release-signing/trusted-keys/` and the verification workflow (e.g., CODEOWNERS plus required reviews). These account/repository settings are **not automatically enabled** by this documentation.

The private signing key is intentionally never stored by this repository or generated on a GitHub runner.
