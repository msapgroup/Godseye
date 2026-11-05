#!/usr/bin/env bash
# Verify a signed server release tag against trusted, repository-reviewed public keys.
# No private keys, credentials, network key servers, or Windows agent changes required.
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "Usage: bash scripts/verify_signed_release_tag.sh server-vX.Y.Z" >&2
  exit 2
fi
tag="$1"
if [[ ! "$tag" =~ ^server-v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.-]*)?$ ]]; then
  echo "ERROR: Only server-vX.Y.Z release tags are permitted" >&2
  exit 1
fi
root="$(git rev-parse --show-toplevel)"
cd "$root"
shopt -s nullglob
keys=(docs/release-signing/trusted-keys/*.asc)
if (( ${#keys[@]} == 0 )); then
  echo "ERROR: No trusted MSAP release public keys enrolled. See docs/RELEASE_SIGNING.md" >&2
  exit 1
fi
if ! git rev-parse --verify --quiet "refs/tags/${tag}^{tag}" >/dev/null; then
  echo "ERROR: Tag is missing or is lightweight rather than annotated" >&2
  exit 1
fi
if ! git show-ref --verify --quiet refs/remotes/origin/main; then
  echo "ERROR: origin/main is unavailable; fetch the official repository first" >&2
  exit 1
fi
commit="$(git rev-list -n 1 "refs/tags/$tag")"
if ! git merge-base --is-ancestor "$commit" refs/remotes/origin/main; then
  echo "ERROR: Release tag does not point to a commit in official main history" >&2
  exit 1
fi

# Use only public keys reviewed into this repository, never a caller's keyring.
temporary_home="$(mktemp -d)"
trap 'rm -rf "$temporary_home"' EXIT
chmod 700 "$temporary_home"
export GNUPGHOME="$temporary_home"
gpg --batch --quiet --import "${keys[@]}" >/dev/null 2>&1 || {
  echo "ERROR: Unable to import trusted public keys" >&2
  exit 1
}
verification="$(mktemp)"
trap 'rm -rf "$temporary_home"; rm -f "$verification"' EXIT
if ! git verify-tag --raw "$tag" >"$verification" 2>&1; then
  echo "ERROR: Invalid or untrusted signed tag" >&2
  cat "$verification" >&2
  exit 1
fi
if ! grep -q '^\[GNUPG:\] VALIDSIG ' "$verification"; then
  echo "ERROR: No valid GPG signature reported" >&2
  exit 1
fi
echo "Verified signed server release tag: $tag"
echo "Official main commit: $commit"
grep '^\[GNUPG:\] VALIDSIG ' "$verification" | awk '{print "Signer fingerprint: " $3}'
