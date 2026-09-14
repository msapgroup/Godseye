from __future__ import annotations

import hashlib
import hmac
import json
import secrets
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
