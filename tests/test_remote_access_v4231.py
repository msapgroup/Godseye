from pathlib import Path
import re
import app.main as main


def test_v423_remote_access_release_marker():
    assert Path("VERSION").read_text().strip() in {"4.23.0-permanent-x64-windows-agent","4.24.0","4.25.0"}

def test_remote_access_routes_and_ui_present():
    src=Path("app/main.py").read_text()
    html=main.DASHBOARD
    assert "/remote-access/sessions" in src
    assert "/windows-agents/remote/sessions/" in src
    assert 'data-view="remote-access"' in html
    assert "Remote Access" in html and "signed-in Windows user must approve" in html
    assert "remote_session_start" in src and "remote_session_stop" in src

def test_remote_agent_has_full_desktop_control_after_approval_and_no_shell():
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    cs=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    assert re.search(r'<Version>2\.2\.[0-9]+</Version>', cs)
    assert 'MessageBox' in src and 'Allow screen viewing and mouse/keyboard control' in src
    assert 'WTSQueryUserToken' in src and 'CreateProcessAsUser' in src
    assert 'NamedPipeServerStream' in src and 'CopyFromScreen' in src
    assert 'SetCursorPos' in src and 'mouse_event' in src and 'keybd_event' in src
    assert 'MOUSEEVENTF_WHEEL' in src
    assert 'cmd.exe' not in src.lower()
    assert 'powershell.exe' not in src.lower()
    assert 'remote_session_start' in src
