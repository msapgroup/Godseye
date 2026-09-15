from pathlib import Path


def test_remote_access_uses_defined_json_helper_not_stale_api_helper():
    src = Path('app/main.py').read_text()
    start = src.index('async function loadRemoteAccess(){')
    end = src.index('\n(function(){', start)
    block = src[start:end]
    assert "api('/api/v1/" not in block
    assert 'api(`/api/v1/' not in block
    assert "await json('/api/v1/windows-agents')" in block
    assert "await json('/api/v1/remote-access/sessions'" in block
    assert 'await json(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}`)' in block
    assert 'await json(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/input`' in block
