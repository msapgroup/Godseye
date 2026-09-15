from pathlib import Path
import re


def test_remote_support_v2_is_loopback_only_and_authenticated():
    src=Path('windows/agent-x64/src/Godseye.WindowsAgent/RemoteSupportV2.cs').read_text()
    assert 'TcpListener(IPAddress.Loopback, 0)' in src
    assert 'RandomNumberGenerator.GetBytes(32)' in src
    assert 'FixedTimeEquals' in src
    assert 'IPAddress.Any' not in src


def test_remote_support_v2_reports_approval_before_first_frame():
    src=Path('windows/agent-x64/src/Godseye.WindowsAgent/RemoteSupportV2.cs').read_text()
    active=src.index('{ "status", "active" }')
    capture=src.index('{ "kind", "capture" }', active)
    assert active < capture
    assert 'The local Windows user denied remote support.' in src
    assert 'Timed out waiting for the approved Windows desktop helper to connect.' in src


def test_remote_support_v2_uses_persistent_duplex_connection():
    src=Path('windows/agent-x64/src/Godseye.WindowsAgent/RemoteSupportV2.cs').read_text()
    assert 'AcceptTcpClient()' in src
    assert 'RemoteHelperV2Request(writer, reader' in src
    assert 'client.NoDelay = true' in src


def test_patch_switches_command_dispatch_to_v2():
    patch=Path('.github/scripts/apply_remote_v2_transport.py').read_text()
    assert 'StartRemoteSessionV2' in patch
    assert '--remote-helper-v2' in patch
    assert 'partial class GodseyeAgentService' in patch


def test_agent_version_bumped_for_real_installer_upgrade():
    project=Path('windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj').read_text()
    assert re.search(r'<Version>2\.2\.(?:[89]|[1-9][0-9]+)</Version>', project)
    assert '<RuntimeIdentifier>win-x64</RuntimeIdentifier>' in project
    assert '<SelfContained>true</SelfContained>' in project
