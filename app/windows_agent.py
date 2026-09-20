from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import re
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

def load_update_manifest(path: Path) -> dict:
    manifest_path = Path(path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if str(data.get("status") or "ready").strip().lower() != "ready":
        raise ValueError("Windows Agent 2.3 package is not built and validated yet")
    version = str(data.get("version") or "").strip()
    sha256 = str(data.get("sha256") or "").strip().upper()
    filename = str(data.get("filename") or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Windows Agent update manifest has an invalid version")
    if not re.fullmatch(r"[0-9A-F]{64}", sha256):
        raise ValueError("Windows Agent update manifest has an invalid SHA-256")
    if filename != "GODSEYE-Windows-Agent-x64.msi":
        raise ValueError("Windows Agent update manifest has an unexpected filename")
    artifact = manifest_path.parent / filename
    if not artifact.is_file():
        raise ValueError("Windows Agent MSI is not installed")
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest().upper()
    if not hmac.compare_digest(actual, sha256):
        raise ValueError("Windows Agent MSI SHA-256 does not match the update manifest")
    return {"version": version, "sha256": sha256, "filename": filename}

