#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
import zlib
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"RELEASE VALIDATION FAILED: {message}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def pe_machine(path: Path) -> int:
    data = path.read_bytes()[:4096]
    if data[:2] != b"MZ" or len(data) < 0x40:
        fail(f"{path.name} is not a PE executable")
    peoff = struct.unpack_from("<I", data, 0x3C)[0]
    if peoff + 6 > len(data):
        with path.open("rb") as f:
            f.seek(peoff)
            hdr = f.read(6)
    else:
        hdr = data[peoff:peoff + 6]
    if hdr[:4] != b"PE\0\0":
        fail(f"{path.name} has an invalid PE header")
    return struct.unpack_from("<H", hdr, 4)[0]




def validate_png(path: Path) -> None:
    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        fail(f"invalid PNG signature: {path.relative_to(path.parents[2]) if len(path.parents) > 2 else path.name}")
    pos = 8
    saw_iend = False
    while pos + 12 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        ctype = data[pos + 4:pos + 8]
        end = pos + 12 + length
        if end > len(data):
            fail(f"truncated PNG chunk in {path.name}")
        payload = data[pos + 8:pos + 8 + length]
        stored_crc = struct.unpack_from(">I", data, pos + 8 + length)[0]
        actual_crc = zlib.crc32(ctype)
        actual_crc = zlib.crc32(payload, actual_crc) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            fail(f"PNG CRC mismatch in {path.name} ({ctype.decode('latin1')})")
        pos = end
        if ctype == b"IEND":
            saw_iend = True
            break
    if not saw_iend:
        fail(f"PNG IEND chunk missing: {path.name}")

def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    required = [
        "VERSION", "README.md", "INSTALL.txt", "RELEASE_MANIFEST.json",
        "requirements.txt", "install.sh", "app/main.py", "app/windows_agent.py",
        "windows/agent-x64/GODSEYE-Windows-Agent-x64.msi.sha256",
        "windows/agent-x64/GODSEYE-Windows-Agent-x64-Setup.exe.sha256",
        "windows/agent-x64/update-manifest.json",
    ]
    for rel in required:
        if not (root / rel).is_file():
            fail(f"missing required release file: {rel}")

    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?", version):
        fail(f"invalid VERSION value: {version!r}")
    release_manifest = json.loads((root / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    if release_manifest.get("version") != version:
        fail("RELEASE_MANIFEST.json version does not match VERSION")

    old_notes = [x.name for x in root.glob("*RELEASE_NOTES*.md") if x.name != "V4.28_RELEASE_NOTES.md"]
    if old_notes:
        fail("historical root release-note files are present: " + ", ".join(sorted(old_notes)))
    if (root / ".github/scripts").exists():
        fail("historical patch scripts must not be shipped under .github/scripts")
    if (root / "windows/agent").exists():
        fail("legacy script-built Windows agent directory must not be shipped")

    agent_dir = root / "windows/agent-x64"
    sys.path.insert(0, str(root))
    from app.windows_agent import load_update_manifest
    try:
        manifest = load_update_manifest(agent_dir / "update-manifest.json")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        fail(f"Windows Agent release manifest is invalid: {exc}")
    agent_version = manifest["version"]
    if not manifest.get("url") or not manifest.get("setup_url"):
        fail("Windows Agent manifest must identify both verified GitHub Release assets")
    expected = manifest["sha256"]

    checksum_file = (agent_dir / "GODSEYE-Windows-Agent-x64.msi.sha256").read_text().strip().split()[0].upper()
    if checksum_file != expected:
        fail("Windows Agent MSI .sha256 file does not match release manifest")
    setup_expected = (agent_dir / "GODSEYE-Windows-Agent-x64-Setup.exe.sha256").read_text().strip().split()[0].upper()
    if setup_expected != manifest["setup_sha256"]:
        fail("Windows Agent Setup .sha256 file does not match release manifest")

    # Release packages live on GitHub Releases. Locally built packages must
    # still match the manifest; stale binaries must never pass validation.
    for filename, digest in ((manifest["filename"], expected),
                             (manifest["setup_filename"], setup_expected)):
        package = agent_dir / filename
        if package.exists() and sha256(package) != digest:
            fail(f"Windows Agent {filename} differs from its release manifest")
    service = agent_dir / "GODSEYE.Agent.exe"
    if service.exists() and pe_machine(service) != 0x8664:
        fail("GODSEYE.Agent.exe is not an x86-64 PE executable")

    csproj = (agent_dir / "src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text(encoding="utf-8")
    for marker in ("<RuntimeIdentifier>win-x64</RuntimeIdentifier>", "<PlatformTarget>x64</PlatformTarget>", "<SelfContained>true</SelfContained>", "<AssemblyName>GODSEYE.Agent</AssemblyName>"):
        if marker not in csproj:
            fail(f"Windows Agent project is missing {marker}")
    m = re.search(r"<Version>([^<]+)</Version>", csproj)
    if not m or not re.fullmatch(r"\d+\.\d+\.\d+", m.group(1).strip()):
        fail("Windows Agent project version is invalid")
    if tuple(map(int, m.group(1).split("."))) < tuple(map(int, agent_version.split("."))):
        fail("Windows Agent project version is older than the published release")

    wix = (agent_dir / "installer/msi/Package.wxs").read_text(encoding="utf-8")
    for marker in ("ProgramFiles64Folder", "GODSEYEWindowsAgent", "GODSEYE.Agent.exe", "UpgradeCode"):
        if marker not in wix:
            fail(f"WiX package is missing {marker}")

    iss = (agent_dir / "installer/GODSEYE-Agent-x64.iss").read_text(encoding="utf-8")
    for marker in ('#define MyMsiName "GODSEYE-Windows-Agent-x64.msi"', 'OutputBaseFilename=GODSEYE-Windows-Agent-x64-Setup', 'ArchitecturesInstallIn64BitMode=x64compatible'):
        if marker not in iss:
            fail(f"guided Setup source is missing {marker}")

    main_py = (root / "app/main.py").read_text(encoding="utf-8")
    if '"GODSEYE-Windows-Agent-x64-Setup.exe"' not in main_py:
        fail("server Windows Agent download route does not use the canonical Setup filename")
    if "/windows-agents/package/legacy" in main_py:
        fail("legacy Windows Agent package route is still present")

    workflow = (root / ".github/workflows/build-windows-agent.yml").read_text(encoding="utf-8")
    if "GODSEYE.Agent.exe" not in workflow or "GODSEYE.WindowsAgent.exe" in workflow:
        fail("Windows build workflow and project AssemblyName are inconsistent")
    if "v4.23" in workflow or "2.2.0 packages" in workflow:
        fail("Windows build workflow still contains historical release-specific packaging")

    screenshots = sorted((root / "docs/screenshots").glob("*.png"))
    if not screenshots:
        fail("dark screenshot pack is missing")
    for screenshot in screenshots:
        validate_png(screenshot)

    print(f"GODSEYE release validation: PASS ({version}; Windows Agent {agent_version}; {len(screenshots)} screenshots)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
