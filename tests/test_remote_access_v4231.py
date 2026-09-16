from pathlib import Path
import app.main as main


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
    assert '<Version>2.2.11</Version>' in cs
    assert 'MessageBox' in src and 'requesting to view and control this computer' in src
    assert 'WTSQueryUserToken' in src and 'CreateProcessAsUser' in src
    assert 'NamedPipeServerStream' in src and 'CopyFromScreen' in src
    assert 'SetCursorPos' in src and 'mouse_event' in src and 'keybd_event' in src
    assert 'MOUSEEVENTF_WHEEL' in src
    assert 'cmd.exe' not in src.lower()
    assert 'powershell.exe' not in src.lower()
    assert 'remote_session_start' in src
