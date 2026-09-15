from pathlib import Path

# Regression coverage for the v4.26 two-step revoke -> permanent-remove lifecycle.
def test_v426_version_and_revoked_agent_purge_contract():
    assert Path("VERSION").read_text().strip()=="4.26.0"
    src=Path("app/main.py").read_text()
    assert 'windows-agents/{{agent_id}}/purge' in src
    assert 'def windows_agent_purge' in src
    assert 'Revoke the Windows Agent before removing it permanently' in src
    assert 'DELETE FROM windows_remote_sessions WHERE agent_id=?' in src
    assert 'DELETE FROM windows_agent_rechecks WHERE agent_id=?' in src
    assert 'DELETE FROM windows_agent_commands WHERE agent_id=?' in src
    assert '_delete_event_findings(c,finding_ids)' in src
    assert 'windows_agent_purged' in src

def test_v426_ui_exposes_permanent_remove_in_both_agent_portals():
    src=Path("app/main.py").read_text()
    assert 'async function purgeWindowsAgent(id)' in src
    assert 'Remove Permanently' in src
    assert 'onclick=\"purgeWindowsAgent(${a.id})\">Remove</button>' in src
    assert 'await loadEventFindings()' in src
    assert "if(typeof loadRemoteAccess==='function')await loadRemoteAccess()" in src
