"""Verify the integrated release before deploying server files (stdlib only)."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

VERSION = "2.4.5"
ROOT = Path(__file__).resolve().parents[1]


def verify(root: Path = ROOT, optional: bool = False) -> bool:
    folder = root / "windows" / "agent-x64"
    setup = folder / f"GODSEYE-Windows-Agent-x64-Setup-{VERSION}.exe"
    msi = folder / "GODSEYE-Windows-Agent-x64.msi"
    if optional and not any(folder.glob("*.exe")) and not msi.exists():
        print("Source checkout: agent installers will be downloaded from the current release.")
        return False
    for manifest, artifact in [("update-manifest.json", msi), ("setup-manifest.json", setup)]:
        data = json.loads((folder / manifest).read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict) or data.get("version") != VERSION or data.get("filename") != artifact.name:
            raise ValueError(f"{manifest}: expected Agent {VERSION} and {artifact.name}")
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != str(data.get("sha256", "")).lower():
            raise ValueError(f"{artifact.name}: checksum mismatch")
    alias = folder / "GODSEYE-Windows-Agent-x64-Setup.exe"
    if hashlib.sha256(alias.read_bytes()).digest() != hashlib.sha256(setup.read_bytes()).digest():
        raise ValueError("Generic and versioned Setup installers do not match")
    if (root / "VERSION").read_text().strip() != "4.31.0":
        raise ValueError("Server release must be 4.31.0")
    if not (root / "app" / "main.py").is_file() or not (root / "install.sh").is_file():
        raise ValueError("Full server application is missing")
    print(f"Server 4.31.0 / Agent {VERSION}: matching installer manifests and checksums verified.")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--optional", action="store_true", help="Permit a source checkout without compiled installers")
    args = parser.parse_args()
    try:
        verify(optional=args.optional)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"GODSEYE package verification failed: {exc}\n")
