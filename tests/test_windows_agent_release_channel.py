from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import app.main as main
from app import windows_agent


def _manifest_bytes(payload: bytes, version: str = "2.2.9") -> dict:
    digest = hashlib.sha256(payload).hexdigest().upper()
    return {
        "version": version,
        "filename": "GODSEYE-Windows-Agent-x64.msi",
        "sha256": digest,
        "url": f"https://github.com/msapgroup/Godseye/releases/download/windows-agent-v{version}/GODSEYE-Windows-Agent-x64.msi",
        "setup_filename": "GODSEYE-Windows-Agent-x64-Setup.exe",
        "setup_sha256": digest,
        "setup_url": f"https://github.com/msapgroup/Godseye/releases/download/windows-agent-v{version}/GODSEYE-Windows-Agent-x64-Setup.exe",
    }


def test_manifest_accepts_only_canonical_github_release_urls(tmp_path):
    payload = b"release-package"
    manifest = _manifest_bytes(payload)
    path = tmp_path / "update-manifest.json"
    path.write_text(json.dumps(manifest))
    loaded = windows_agent.load_update_manifest(path)
    assert loaded["url"] == manifest["url"]
    assert loaded["setup_url"] == manifest["setup_url"]

    manifest["url"] = "https://example.com/GODSEYE-Windows-Agent-x64.msi"
    path.write_text(json.dumps(manifest))
    try:
        windows_agent.load_update_manifest(path)
        assert False, "unexpected release host should be rejected"
    except ValueError:
        pass


def test_manifest_rejects_release_tag_version_mismatch(tmp_path):
    payload = b"release-package"
    manifest = _manifest_bytes(payload)
    manifest["url"] = manifest["url"].replace("windows-agent-v2.2.9", "windows-agent-v9.9.9")
    path = tmp_path / "update-manifest.json"
    path.write_text(json.dumps(manifest))
    try:
        windows_agent.load_update_manifest(path)
        assert False, "release tag mismatch should be rejected"
    except ValueError:
        pass


def test_resolve_asset_prefers_matching_local_package(tmp_path, monkeypatch):
    payload = b"matching-msi"
    manifest = _manifest_bytes(payload)
    package_root = tmp_path / "packages"
    package_root.mkdir()
    local = package_root / manifest["filename"]
    local.write_bytes(payload)

    def no_network(*args, **kwargs):
        raise AssertionError("network should not be used for a matching local package")

    monkeypatch.setattr(windows_agent.urllib.request, "urlopen", no_network)
    resolved = windows_agent.resolve_update_asset(manifest, package_root, tmp_path / "cache", "msi")
    assert resolved == local


def test_resolve_asset_downloads_verifies_and_caches_release(tmp_path, monkeypatch):
    payload = b"new-release-msi"
    manifest = _manifest_bytes(payload)
    package_root = tmp_path / "packages"
    package_root.mkdir()
    (package_root / manifest["filename"]).write_bytes(b"stale-package")

    class FakeResponse:
        def __init__(self, body):
            self.body = io.BytesIO(body)

        def read(self, size=-1):
            return self.body.read(size)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    calls = []

    def fake_urlopen(request, timeout=0):
        calls.append((request.full_url, timeout))
        return FakeResponse(payload)

    monkeypatch.setattr(windows_agent.urllib.request, "urlopen", fake_urlopen)
    cache = tmp_path / "cache"
    resolved = windows_agent.resolve_update_asset(manifest, package_root, cache, "msi")
    assert resolved.read_bytes() == payload
    assert resolved.parent == cache
    assert len(calls) == 1

    # A second request uses the verified cache without downloading again.
    resolved2 = windows_agent.resolve_update_asset(manifest, package_root, cache, "msi")
    assert resolved2 == resolved
    assert len(calls) == 1


def test_workflow_publishes_large_packages_as_release_assets_not_git_blobs():
    workflow = Path(".github/workflows/build-windows-agent.yml").read_text()
    assert "gh release create" in workflow
    assert "gh release upload" in workflow
    assert "Large packages live in GitHub Releases, not Git history." in workflow
    assert "git add -f windows/agent-x64/GODSEYE.Agent.exe" not in workflow
    assert "git add -f windows/agent-x64/GODSEYE-Windows-Agent-x64.msi" not in workflow
    assert "git add -f windows/agent-x64/GODSEYE-Windows-Agent-x64-Setup.exe" not in workflow
    assert "PublishReadyToRun=false" in workflow


def test_server_package_routes_use_verified_release_cache():
    source = Path("app/main.py").read_text()
    assert "def _resolve_windows_agent_package" in source
    assert 'DB_PATH.parent / "windows-agent-cache"' in source
    assert '_resolve_windows_agent_package(manifest,"msi")' in source
    assert '_resolve_windows_agent_package(manifest,"setup")' in source
