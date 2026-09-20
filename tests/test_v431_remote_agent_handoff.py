from pathlib import Path


def test_v431_versions_and_installer_keep_token_enrollment():
    assert Path("VERSION").read_text().strip() == "4.31.0"
    project = Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    installer = Path("windows/agent-x64/installer/GODSEYE-Agent-x64.iss").read_text()
    assert "<Version>2.4.0</Version>" in project
    assert '#define MyAppVersion "2.4.0"' in installer
    assert "Enrollment token:" in installer
    assert "--enrollment-token" in installer


def test_v431_uses_dedicated_helper_after_screen_share_consent():
    service = Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    assert 'string sessionPipe="GODSEYE-Remote-"+sessionId' in service
    assert "LaunchRemoteHelper(sessionPipe,requestedBy,windowsSessionId)" in service
    assert "WaitForRemoteHelperReady(sessionPipe,20000)" in service
    assert 'remotePipeName=sessionPipe' in service
    assert '"control-consent"' in service
    assert '"/control/decision"' in service


def test_v431_windows_user_can_stop_sharing_and_control_is_separate():
    tray = Path("windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs").read_text()
    server = Path("app/main.py").read_text()
    assert "Share Screen" in tray
    assert "Stop Sharing" in tray
    assert "ShowControlConsentDialog" in tray
    assert "control_status TEXT NOT NULL DEFAULT 'view_only'" in server
    assert "/control/request" in server
    assert "The signed-in Windows user has not approved remote control" in server

