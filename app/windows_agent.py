from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import re
import urllib.request
from pathlib import Path
from typing import Any


def token_hash(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def new_enrollment_token() -> str:
    return "gse_" + secrets.token_urlsafe(32)


def new_agent_key() -> str:
    return "gsa_" + secrets.token_urlsafe(40)


def verify_token(value: str, expected_hash: str) -> bool:
    if not value or not expected_hash:
        return False
    return hmac.compare_digest(token_hash(value), expected_hash)


def normalize_channels(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["System", "Application"]
    out: list[str] = []
    for item in value:
        name = str(item or "").strip()
        if not name or len(name) > 180 or name in out:
            continue
        out.append(name)
        if len(out) >= 20:
            break
    return out or ["System", "Application"]


def public_agent(row) -> dict:
    d = dict(row)
    d.pop("api_key_hash", None)
    try:
        d["channels"] = json.loads(d.pop("channels_json") or "[]")
    except Exception:
        d["channels"] = []
    d["enabled"] = bool(d.get("enabled"))
    return d

_RELEASE_URL_RE = re.compile(
    r"^https://github\.com/msapgroup/Godseye/releases/download/"
    r"windows-agent-v(?P<version>\d+\.\d+\.\d+)/(?P<filename>[A-Za-z0-9_.-]+)$"
)
_MSI_FILENAME = "GODSEYE-Windows-Agent-x64.msi"
_SETUP_FILENAME = "GODSEYE-Windows-Agent-x64-Setup.exe"
_MAX_PACKAGE_BYTES = 600 * 1024 * 1024


def _validate_release_url(value: str, version: str, filename: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    match = _RELEASE_URL_RE.fullmatch(value)
    if not match or match.group("version") != version or match.group("filename") != filename:
        raise ValueError("Windows Agent update manifest has an unexpected release URL")
    return value


def load_update_manifest(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    version = str(data.get("version") or "").strip()
    sha256 = str(data.get("sha256") or "").strip().upper()
    filename = str(data.get("filename") or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Windows Agent update manifest has an invalid version")
    if not re.fullmatch(r"[0-9A-F]{64}", sha256):
        raise ValueError("Windows Agent update manifest has an invalid SHA-256")
    if filename != _MSI_FILENAME:
        raise ValueError("Windows Agent update manifest has an unexpected filename")

    result = {"version": version, "sha256": sha256, "filename": filename}
    url = _validate_release_url(data.get("url"), version, filename)
    if url:
        result["url"] = url

    setup_filename = str(data.get("setup_filename") or "").strip()
    setup_sha256 = str(data.get("setup_sha256") or "").strip().upper()
    setup_url_raw = str(data.get("setup_url") or "").strip()
    if setup_filename or setup_sha256 or setup_url_raw:
        if setup_filename != _SETUP_FILENAME:
            raise ValueError("Windows Agent update manifest has an unexpected setup filename")
        if not re.fullmatch(r"[0-9A-F]{64}", setup_sha256):
            raise ValueError("Windows Agent update manifest has an invalid setup SHA-256")
        setup_url = _validate_release_url(setup_url_raw, version, setup_filename)
        if not setup_url:
            raise ValueError("Windows Agent update manifest is missing the setup release URL")
        result.update(
            {
                "setup_filename": setup_filename,
                "setup_sha256": setup_sha256,
                "setup_url": setup_url,
            }
        )
    return result


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _download_verified_release_asset(url: str, destination: Path, expected_sha256: str) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".download")
    temporary.unlink(missing_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "GODSEYE-Windows-Agent-Release/1"})
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as out:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_PACKAGE_BYTES:
                    raise ValueError("Windows Agent release asset exceeds the maximum package size")
                out.write(chunk)
        actual = _file_sha256(temporary)
        if actual != expected_sha256:
            raise ValueError("Windows Agent release asset SHA-256 verification failed")
        os.replace(temporary, destination)
        return destination
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def resolve_update_asset(manifest: dict, package_root: Path, cache_dir: Path, kind: str) -> Path:
    """Return a verified local Windows Agent asset.

    Current installs may still contain a tracked baseline package. When the
    release manifest points at a newer package, the server downloads that
    GitHub Release asset once, verifies its SHA-256, and serves the cached
    copy to agents/admins. Agent commands never receive an arbitrary URL.
    """
    if kind == "msi":
        filename = manifest["filename"]
        expected_sha256 = manifest["sha256"]
        url = manifest.get("url", "")
    elif kind == "setup":
        filename = manifest.get("setup_filename") or _SETUP_FILENAME
        expected_sha256 = manifest.get("setup_sha256", "")
        url = manifest.get("setup_url", "")
    else:
        raise ValueError("Unknown Windows Agent package kind")

    local = Path(package_root) / filename
    if local.exists():
        if not expected_sha256 or _file_sha256(local) == expected_sha256:
            return local

    if not url:
        raise FileNotFoundError(f"Windows Agent {filename} is not installed and no release URL is available")

    cache = Path(cache_dir) / f"{manifest['version']}-{filename}"
    if cache.exists() and _file_sha256(cache) == expected_sha256:
        return cache
    cache.unlink(missing_ok=True)
    return _download_verified_release_asset(url, cache, expected_sha256)

