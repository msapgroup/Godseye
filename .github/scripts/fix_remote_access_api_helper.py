from pathlib import Path

p = Path('app/main.py')
s = p.read_text(encoding='utf-8')
start = s.index('async function loadRemoteAccess(){')
end = s.index('\n(function(){', start)
block = s[start:end]

# Repair every Remote Access call site to use the application-wide,
# authenticated and CSRF-aware json() helper. This script is deliberately
# idempotent so release/replacement builds can run it every time.
block = block.replace("await api('/api/v1/", "await json('/api/v1/")
block = block.replace('await api(`/api/v1/', 'await json(`/api/v1/')
s = s[:start] + block + s[end:]
p.write_text(s, encoding='utf-8', newline='\n')

# Keep a source-level regression test in the repository so future rebuilds
# cannot silently restore the undefined api() helper.
t = Path('tests/test_v426_remote_access_api_helper.py')
t.write_text("""from pathlib import Path


def test_remote_access_uses_defined_json_helper_not_stale_api_helper():
    src = Path('app/main.py').read_text()
    start = src.index('async function loadRemoteAccess(){')
    end = src.index('\\n(function(){', start)
    block = src[start:end]
    assert \"api('/api/v1/\" not in block
    assert 'api(`/api/v1/' not in block
    assert \"await json('/api/v1/windows-agents')\" in block
    assert \"await json('/api/v1/remote-access/sessions'\" in block
    assert 'await json(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}`)' in block
    assert 'await json(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/input`' in block
""", encoding='utf-8', newline='\n')

# Fail immediately if the repair did not produce the required source.
fixed = p.read_text(encoding='utf-8')
fixed_block = fixed[start:fixed.index('\n(function(){', start)]
if "api('/api/v1/" in fixed_block or 'api(`/api/v1/' in fixed_block:
    raise SystemExit('Remote Access still contains undefined api() calls')
if "await json('/api/v1/windows-agents')" not in fixed_block:
    raise SystemExit('Remote Access agent list is not using json()')

print('Remote Access API helper is correct and rebuild-safe.')
