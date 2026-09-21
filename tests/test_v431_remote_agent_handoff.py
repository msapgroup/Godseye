from pathlib import Path


def test_v431_versions_and_installer_keep_token_enrollment():
    assert Path("VERSION").read_text().strip() == "4.31.0"
    project = Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    installer = Path("windows/agent-x64/installer/GODSEYE-Agent-x64.iss").read_text()
    assert "<Version>2.4.3</Version>" in project
    assert '#define MyAppVersion "2.4.3"' in installer
    assert 'OutputBaseFilename=GODSEYE-Windows-Agent-x64-Setup-2.4.3' in installer
    assert "GetVersionNumbersString(ExePath, InstalledVersion)" in installer
    assert "GODSEYE Windows Agent 2.4.3 was installed and verified successfully" in installer
    assert "Enrollment token:" in installer
    assert "--enrollment-token" in installer


def test_v431_keeps_capture_in_the_verified_tray_after_consent():
    service = Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    start = service.split("void StartRemoteSession", 1)[1].split("void StopRemoteSession", 1)[0]
    assert 'remotePipeName="GODSEYE-Tray-"+windowsSessionId' in start
    assert '{{"kind","sharing-start"}' in start
    assert "LaunchRemoteHelper(" not in start
    assert 'string sessionPipe="GODSEYE-Remote-"+sessionId' not in start
    assert '"control-consent"' in service
    assert '"/control/decision"' in service


def test_v431_targets_the_active_interactive_or_rdp_session():
    service = Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    assert "WTSEnumerateSessions" in service
    assert "WTS_CONNECTSTATE_CLASS.WTSActive" in service
    assert "GetActiveInteractiveSessionId()" in service
    assert service.count("GetActiveInteractiveSessionId()") >= 3


def test_v431_windows_user_can_stop_sharing_and_control_is_separate():
    tray = Path("windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs").read_text()
    server = Path("app/main.py").read_text()
    assert "Share Screen" in tray
    assert "Stop Sharing" in tray
    assert "ShowControlConsentDialog" in tray
    assert "StopSharingBanner" in tray
    assert "control_status TEXT NOT NULL DEFAULT 'view_only'" in server
    assert "/control/request" in server
    assert "The signed-in Windows user has not approved remote control" in server
