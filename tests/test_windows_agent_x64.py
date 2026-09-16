from pathlib import Path
import app.main as main
from app.windows_agent import load_update_manifest

def test_released_setup_is_available_to_installer_endpoint():
    manifest=load_update_manifest(Path("windows/agent-x64/update-manifest.json"))
    assert manifest['setup_url'].endswith('/'+manifest['setup_filename'])
    assert len(manifest['setup_sha256'])==64

def test_download_api_serves_setup_exe():
    source=Path("app/main.py").read_text()
    assert '_resolve_windows_agent_package(manifest,"setup")' in source
    assert 'manifest.get("setup_filename") or "GODSEYE-Windows-Agent-x64-Setup.exe"' in source
    assert 'media_type="application/vnd.microsoft.portable-executable"' in source

def test_windows_agent_ui_uses_permanent_installer():
    html=main.DASHBOARD
    assert 'Download x64 Installer' in html
    assert 'Future agent upgrades preserve enrollment automatically' in html
    assert 'Existing enrolled agents can run newer Setup versions without a new token.' in html

def test_agent_x64_source_is_self_contained():
    csproj=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    iss=Path("windows/agent-x64/installer/GODSEYE-Agent-x64.iss").read_text()
    wix=Path("windows/agent-x64/installer/msi/Package.wxs").read_text()
    assert '<RuntimeIdentifier>win-x64</RuntimeIdentifier>' in csproj
    assert '<SelfContained>true</SelfContained>' in csproj
    assert '<PublishSingleFile>true</PublishSingleFile>' in csproj
    assert 'Assembly.GetName().Version' in src
    assert '<Version>2.2.10</Version>' in csproj
    assert 'GODSEYEWindowsAgent' in wix
    assert '<ServiceInstall' in wix and '<ServiceControl' in wix
    assert 'ArchitecturesInstallIn64BitMode=x64compatible' in iss
    assert 'ExistingConfig' in iss

def test_v1_data_location_preserved_for_migration():
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    assert 'CommonApplicationData' in src
    assert '"GODSEYE", "Agent"' in src
    assert 'agent.key' in src and 'pending-events.json' in src and 'state.json' in src

def test_installer_screenshot_documented():
    assert Path("docs/screenshots/dark-windows-agent-installer.png").exists()
    assert 'dark-windows-agent-installer.png' in Path("docs/SCREENSHOTS.md").read_text()
