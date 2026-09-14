from pathlib import Path
import app.main as main

def test_version_v423():
    assert Path("VERSION").read_text().strip()=="4.23.0-permanent-x64-windows-agent"

def test_real_x64_installer_is_packaged():
    setup=Path("windows/agent-x64/GODSEYE-Windows-Agent-x64-Setup.exe")
    agent=Path("windows/agent-x64/GODSEYE.WindowsAgent.exe")
    project=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj")
    source=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs")
    assert setup.exists() and setup.stat().st_size > 10_000_000
    # The standalone agent EXE is a release artifact built by the Windows
    # workflow; source CI must not require a large generated binary in git.
    if agent.exists():
        assert agent.stat().st_size > 20_000_000
        assert agent.read_bytes()[:2] == b"MZ"
    else:
        assert project.exists() and source.exists()
        csproj=project.read_text()
        assert '<RuntimeIdentifier>win-x64</RuntimeIdentifier>' in csproj
        assert '<SelfContained>true</SelfContained>' in csproj
        assert '<PublishSingleFile>true</PublishSingleFile>' in csproj

def test_download_api_serves_setup_exe():
    source=Path("app/main.py").read_text()
    assert 'windows" / "agent-x64" / "GODSEYE-Windows-Agent-x64-Setup.exe"' in source
    assert 'filename="GODSEYE-Windows-Agent-x64-Setup.exe"' in source
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
    assert '<Version>2.2.5</Version>' in csproj
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
