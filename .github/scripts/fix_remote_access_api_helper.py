from pathlib import Path

p=Path('app/main.py')
s=p.read_text(encoding='utf-8')
start=s.index('async function loadRemoteAccess(){')
end=s.index('\n(function(){', start)
block=s[start:end]
if "api('/api/v1/" not in block and 'api(`/api/v1/' not in block:
    raise SystemExit('Remote Access block no longer contains the broken api helper; refusing unexpected patch')
block=block.replace("await api('/api/v1/", "await json('/api/v1/")
block=block.replace('await api(`/api/v1/', 'await json(`/api/v1/')
s=s[:start]+block+s[end:]
p.write_text(s,encoding='utf-8',newline='\n')

# Regression test makes this rebuild-safe: Remote Access must use the app-wide json() helper.
t=Path('tests/test_v426_remote_access_api_helper.py')
t.write_text("""from pathlib import Path\n\ndef test_remote_access_uses_defined_json_helper_not_stale_api_helper():\n    src=Path('app/main.py').read_text()\n    start=src.index('async function loadRemoteAccess(){')\n    end=src.index('\\n(function(){', start)\n    block=src[start:end]\n    assert \"api('/api/v1/\" not in block\n    assert 'api(`/api/v1/' not in block\n    assert \"await json('/api/v1/windows-agents')\" in block\n    assert \"await json('/api/v1/remote-access/sessions'\" in block\n    assert 'await json(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}`)' in block\n    assert 'await json(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/input`' in block\n""",encoding='utf-8',newline='\n')
print('Patched Remote Access to use the defined json() API helper and added regression coverage.')
