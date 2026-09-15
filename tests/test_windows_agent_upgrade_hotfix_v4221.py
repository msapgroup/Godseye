from pathlib import Path

def test_hotfix_version():
    assert Path("VERSION").read_text().strip() in {"4.22.1-windows-agent-upgrade-hotfix","4.23.0-permanent-x64-windows-agent"}

def test_agent_is_v111():
    src=Path("windows/agent/src/GodseyeAgentService.cs").read_text()
    assert 'AgentVersion = "1.1.1"' in src

def test_upgrade_can_reuse_existing_server_url_and_enrollment():
    ps=Path("windows/agent/Install-GODSEYEAgent.ps1").read_text()
    assert '[string]$ServerUrl = ""' in ps
    assert '$existingEnrollment' in ps
    assert '$ServerUrl = [string]$existingConfig.ServerUrl' in ps
    assert 'No new enrollment token was required' in ps

def test_upgrade_stages_binary_before_replace():
    ps=Path("windows/agent/Install-GODSEYEAgent.ps1").read_text()
    assert "GODSEYE.WindowsAgent.exe.new" in ps
    assert "Replace-AgentBinary" in ps
    assert "Wait-ServiceStopped" in ps
    assert "The previous agent executable was left unchanged" in ps

def test_upgrade_preserves_tls_setting_unless_explicitly_changed():
    ps=Path("windows/agent/Install-GODSEYEAgent.ps1").read_text()
    assert "$PSBoundParameters.ContainsKey('SkipTlsVerify')" in ps
    assert "$config.SkipTlsVerify = [bool]$SkipTlsVerify" in ps

def test_upgrade_requires_admin_and_verifies_restart():
    ps=Path("windows/agent/Install-GODSEYEAgent.ps1").read_text()
    assert "Assert-Administrator" in ps
    assert "Service status is" in ps
    assert "Recent agent log:" in ps

def test_agent_upgrade_docs_have_no_token_command():
    readme=Path("windows/agent/README.md").read_text()
    assert ".\\Install-GODSEYEAgent.ps1" in readme
    assert "without generating a new enrollment token" in readme
