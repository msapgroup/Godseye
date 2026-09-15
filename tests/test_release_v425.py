from pathlib import Path
import hashlib, json
import app.main as main
from app import windows_agent


def test_v425_release_version():
    assert Path('VERSION').read_text().strip() == '4.25.0'


def test_packaged_agent_227_manifest_and_hash_are_consistent():
    root=Path('windows/agent-x64')
    manifest=windows_agent.load_update_manifest(root/'update-manifest.json')
    assert manifest['version']=='2.2.7'
    msi=root/manifest['filename']
    assert msi.exists() and msi.stat().st_size > 10_000_000
    actual=hashlib.sha256(msi.read_bytes()).hexdigest().upper()
    assert actual==manifest['sha256']
    assert (root/'GODSEYE-Windows-Agent-x64.msi.sha256').read_text().strip().upper()==actual


def test_packaged_agent_and_setup_are_real_windows_binaries():
    root=Path('windows/agent-x64')
    agent=root/'GODSEYE.WindowsAgent.exe'
    setup=root/'GODSEYE-Windows-Agent-x64-Setup.exe'
    assert agent.stat().st_size > 100_000_000
    assert setup.stat().st_size > 10_000_000
    assert agent.read_bytes()[:2]==b'MZ'
    assert setup.read_bytes()[:2]==b'MZ'
    assert b'PE\x00\x00' in agent.read_bytes()[:512]


def test_server_keeps_stable_agent_api_for_event_findings_and_remote_access():
    paths={getattr(r,'path',None) for r in main.app.routes}
    required={
      '/api/v1/windows-agents/enroll',
      '/api/v1/windows-agents/heartbeat',
      '/api/v1/windows-agents/events',
      '/api/v1/windows-agents/{agent_id}/pull-now',
      '/api/v1/windows-agents/{agent_id}/upgrade',
      '/api/v1/windows-agents/package/msi',
      '/api/v1/remote-access/sessions',
      '/api/v1/remote-access/sessions/{session_id}',
      '/api/v1/remote-access/sessions/{session_id}/frame',
      '/api/v1/remote-access/sessions/{session_id}/input',
    }
    assert required <= paths


def test_agent_source_contract_has_event_logs_self_update_and_remote_support():
    src=Path('windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs').read_text()
    assert 'EventLogQuery' in src and 'Level=1 or Level=2 or Level=3' in src
    assert 'pull_events' in src and 'upgrade_agent' in src
    assert '/api/v1/windows-agents/package/msi' in src
    assert 'remote_session_start' in src and 'remote_session_stop' in src
    assert 'CopyFromScreen' in src and 'SetCursorPos' in src and 'keybd_event' in src
    assert 'cmd.exe' not in src.lower() and 'powershell.exe' not in src.lower()


def test_installer_lifecycle_is_native_windows_installer():
    wix=Path('windows/agent-x64/installer/msi/Package.wxs').read_text()
    csproj=Path('windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj').read_text()
    assert 'ProgramFiles64Folder' in wix
    assert '<ServiceInstall' in wix and '<ServiceControl' in wix
    assert 'CommonAppDataFolder' in wix and 'NeverOverwrite="yes"' in wix
    assert '<RuntimeIdentifier>win-x64</RuntimeIdentifier>' in csproj
    assert '<SelfContained>true</SelfContained>' in csproj


def test_linux_installer_preserves_state_and_sets_import_path():
    src=Path("install.sh").read_text()
    assert 'sqlite3 "$DATA_DIR/godseye.db" ".backup' in src
    assert "--exclude '.venv/'" in src
    assert 'PYTHONPATH="$INSTALL_DIR" GODSEYE_DB="$DATA_DIR/godseye.db"' in src
    assert 'touch "$ENV_FILE"' in src
    assert 'systemctl restart godseye-web.service' in src

def test_management_features_are_present_in_consolidated_build():
    html=main.DASHBOARD
    for label in ("Event Findings","Ticket Portal","Calendar","Email","Reports","Remote Access","Windows Agents"):
        assert label in html
    src=Path("app/main.py").read_text()
    assert '/event-findings/{{finding_id}}/create-ticket' in src
    assert '/tickets/{{ticket_id}}/schedule' in src
    assert '/windows-agents/{{agent_id}}/pull-now' in src
