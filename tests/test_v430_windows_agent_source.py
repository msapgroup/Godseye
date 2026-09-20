from pathlib import Path
import hashlib, json
import pytest

from app.windows_agent import load_update_manifest

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "windows" / "agent-x64"
SRC = AGENT / "src" / "Godseye.WindowsAgent"


def test_v230_source_and_installer_contracts():
    csproj=(SRC / "Godseye.WindowsAgent.csproj").read_text(encoding="utf-8")
    service=(SRC / "GodseyeAgentService.cs").read_text(encoding="utf-8")
    tray=(SRC / "TrayApp.cs").read_text(encoding="utf-8")
    iss=(AGENT / "installer" / "GODSEYE-Agent-x64.iss").read_text(encoding="utf-8")
    wix=(AGENT / "installer" / "msi" / "Package.wxs").read_text(encoding="utf-8")

    assert '<Version>2.4.0</Version>' in csproj
    assert '<FileVersion>2.4.0.0</FileVersion>' in csproj
    assert '#define MyAppVersion "2.4.0"' in iss
    assert '#define MyMsiName "GODSEYE-Windows-Agent-x64.msi"' in iss
    assert 'Version="2.4.0"' in wix
    assert 'Local\\GODSEYE.WindowsAgent.Tray.2.4.0' in tray

    for state in ("waiting_for_tray", "tray_ready", "waiting_for_user", "approved", "capture_started"):
        assert f'{{"status","{state}"}}' in service
    assert '{{"kind","consent"}' in service
    assert 'TrayApp.ShowConsentDialog' in service
    # The service announces capture_started; the server alone promotes to active after JPEG validation.
    assert '{{"status","active"}}' not in service
    assert '"/api/v1/windows-agents/package/msi"' in service
    assert 'SHA256.Create()' in service
    assert 'cmd.exe' not in service.lower()
    assert 'powershell.exe' not in service.lower()


def test_pending_manifest_cannot_advertise_stale_agent():
    with pytest.raises(ValueError, match="not built and validated"):
        load_update_manifest(AGENT / "update-manifest.json")


def test_ready_manifest_requires_matching_canonical_msi(tmp_path):
    msi=tmp_path / "GODSEYE-Windows-Agent-x64.msi"
    msi.write_bytes(b"test-msi-payload")
    digest=hashlib.sha256(msi.read_bytes()).hexdigest().upper()
    manifest=tmp_path / "update-manifest.json"
    manifest.write_text(json.dumps({"status":"ready","version":"2.4.0","filename":msi.name,"sha256":digest}),encoding="utf-8")
    result=load_update_manifest(manifest)
    assert result == {"version":"2.4.0","filename":msi.name,"sha256":digest}
    msi.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="does not match"):
        load_update_manifest(manifest)


def test_local_windows_agent_build_script_is_safe_and_self_validating():
    source = (ROOT / "windows" / "agent-x64" / "build-local.ps1").read_text(encoding="utf-8")
    assert "if (-not $IsWindows)" in source
    assert "2.4.0" in source
    assert "& $dotnet publish" in source
    assert "GODSEYE-Windows-Agent-x64.msi" in source
    assert "GODSEYE-Windows-Agent-x64-Setup.exe" in source
    assert "Get-FileHash" in source
    assert "GODSEYEWindowsAgent" in source
    assert "LocalSystem" in source
    assert "status = 'ready'" in source
    assert "git push" not in source.lower()
