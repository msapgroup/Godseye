from pathlib import Path
import app.main as main


def test_v423_remote_access_release_marker():
    assert Path("VERSION").read_text().strip()=="4.23.0-permanent-x64-windows-agent"

def test_remote_access_routes_and_ui_present():
    src=Path("app/main.py").read_text()
    html=main.DASHBOARD
    assert "/remote-access/sessions" in src
    assert "/windows-agents/remote/sessions/" in src
    assert 'data-view="remote-access"' in html
    assert "Remote Access" in html and "signed-in user approves each remote-control session" in html
    assert "remote_session_start" in src and "remote_session_stop" in src

def test_remote_agent_has_full_desktop_control_after_approval_and_no_shell():
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    cs=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    assert '<Version>2.2.3</Version>' in cs
    assert 'WTSSendMessage' in src and 'RequestRemoteConsent' in src
    assert 'WTSQueryUserToken' in src and 'CreateProcessAsUser' in src
    assert 'NamedPipeServerStream' in src and 'CopyFromScreen' in src
    assert 'SetCursorPos' in src and 'mouse_event' in src and 'keybd_event' in src
    assert 'MOUSEEVENTF_WHEEL' in src
    assert 'CreateEnvironmentBlock' in src and 'CreateProcessWithTokenW' in src
    assert 'WaitForRemoteHelperReady' in src and '"kind","ping"' in src
    assert 'cmd.exe' not in src.lower()
    assert 'powershell.exe' not in src.lower()
    assert 'remote_session_start' in src


def test_windows_agent_tray_app_present():
    tray=Path("windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs").read_text()
    wix=Path("windows/agent-x64/installer/msi/Package.wxs").read_text()
    assert "NotifyIcon" in tray and "Agent Status..." in tray
    assert "GODSEYE Remote Access" in tray and "Allow" in tray and "Deny" in tray
    assert "--tray" in wix and "CurrentVersion\\Run" in wix
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    assert "EnsureTrayProcess" in src and "WriteTrayStatus" in src


def test_remote_access_has_self_contained_api_helper():
    html=main.DASHBOARD
    assert "async function remoteApi" in html
    assert "await remoteApi('/api/v1/windows-agents')" in html
    assert "Remote Access Features" in html
