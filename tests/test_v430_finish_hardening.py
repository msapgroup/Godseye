from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v430_navigation_dashboard_and_remote_copy_are_current():
    source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert '<div class="navsection">Monitoring</div>' in source
    assert '<div class="navsection">Operations</div>' in source
    assert '<div class="navsection">Administration</div>' in source
    administration = source.split('<div class="navsection">Administration</div>', 1)[1]
    assert 'data-view="health"' in administration
    assert 'data-view="security"' in administration
    assert 'id="dashboardGreeting"' in source
    assert "Good morning" in source and "Good afternoon" in source and "Good evening" in source
    assert 'id="systemHealthState"' in source
    assert "json('/api/v1/appliance/health').catch(()=>null)" in source
    assert "Windows Agent 2.4.0 or newer" in source
    assert "Windows Agent 2.2.0 or newer" not in source


def test_tray_consent_is_dispatched_to_ui_thread_and_capture_supports_virtual_desktop():
    tray = (ROOT / "windows" / "agent-x64" / "src" / "Godseye.WindowsAgent" / "TrayApp.cs").read_text(encoding="utf-8")
    service = (ROOT / "windows" / "agent-x64" / "src" / "Godseye.WindowsAgent" / "GodseyeAgentService.cs").read_text(encoding="utf-8")
    assert "static Control? _uiDispatcher;" in tray
    assert "dispatcher.InvokeRequired" in tray
    assert "dispatcher.Invoke(new Func<string, bool>(ShowConsentDialogCore), requestedBy)" in tray
    assert "uiDispatcher.CreateControl();" in tray
    assert "SystemInformation.VirtualScreen" in service
    assert "CopyFromScreen(bounds.Left,bounds.Top" in service
    assert "bounds.Left+(int)(nx*Math.Max(1,bounds.Width-1))" in service
    assert "GetSystemMetrics" not in service


def test_guided_agent_setup_restarts_service_after_first_time_configuration():
    iss = (ROOT / "windows" / "agent-x64" / "installer" / "GODSEYE-Agent-x64.iss").read_text(encoding="utf-8")
    configure_at = iss.index("--configure --server-url")
    stop_at = iss.index("stop GODSEYEWindowsAgent /y")
    start_at = iss.index("start GODSEYEWindowsAgent")
    assert stop_at < configure_at < start_at
    assert "configured, but the service could not be restarted" in iss


def test_windows_agent_workflow_builds_230_without_writing_back_to_github():
    workflow = (ROOT / ".github" / "workflows" / "build-windows-agent.yml").read_text(encoding="utf-8")
    assert "GODSEYE.Agent.exe" in workflow
    assert "GODSEYE-Windows-Agent-x64-2.4.3" in workflow
    assert "GODSEYE-v4.31.0-with-agent.zip" in workflow
    assert "status = 'ready'" in workflow
    assert "contents: write" in workflow
    assert "git push" not in workflow
    assert "Build GODSEYE v4.23" not in workflow
    assert "2.2.0" not in workflow


def test_remote_view_loader_and_dashboard_grid_are_layout_enabled():
    text = Path("app/main.py").read_text(encoding="utf-8")
    assert "'remote-access':()=>loadRemoteAccess()" in text
    assert "'.dashboard-grid'" in text
