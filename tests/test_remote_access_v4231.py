from pathlib import Path
import app.main as main


def test_v4231_remote_access_release_marker():
    assert Path("VERSION").read_text().strip()=="4.23.1-remote-access"

def test_remote_access_routes_and_ui_present():
    src=Path("app/main.py").read_text()
    html=main.DASHBOARD
    assert "/remote-access/sessions" in src
    assert "/windows-agents/remote/sessions/" in src
    assert 'data-view="remote-access"' in html
    assert "Remote Access" in html and "signed-in Windows user must approve" in html
    assert "remote_session_start" in src and "remote_session_stop" in src

def test_remote_agent_is_consent_aware_and_not_a_shell():
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    cs=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    assert '<Version>2.2.0</Version>' in cs
    assert 'MessageBox' in src and 'Allow screen viewing and mouse/keyboard control' in src
    assert 'WTSQueryUserToken' in src and 'CreateProcessAsUser' in src
    assert 'NamedPipeServerStream' in src and 'CopyFromScreen' in src
    assert 'cmd.exe' not in src.lower()
    assert 'powershell.exe' not in src.lower()
    assert 'remote_session_start' in src
