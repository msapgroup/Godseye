from pathlib import Path


def replace_required(path, old, new):
    p = Path(path)
    text = p.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'expected text not found in {path}: {old!r}')
    p.write_text(text.replace(old, new), encoding='utf-8', newline='\n')

tray = 'windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs'
replace_required(tray,
    'using var mutex = new Mutex(true, @"Local\\GODSEYE.WindowsAgent.Tray", out bool created);',
    'using var mutex = new Mutex(true, @"Local\\GODSEYE.WindowsAgent.Tray.2.2.5", out bool created);')

# Bump release/install/test metadata so upgrades are explicit and the new tray host starts in the current login session.
for path in [
    'windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj',
    'windows/agent-x64/installer/msi/Package.wxs',
    'windows/agent-x64/installer/GODSEYE-Agent-x64.iss',
    'tests/test_permanent_x64_windows_agent_v423.py',
    'tests/test_remote_access_v4231.py',
    'tests/test_windows_agent_self_update.py',
    'V424_RELEASE_NOTES.md',
]:
    p = Path(path)
    text = p.read_text(encoding='utf-8')
    if '2.2.4' in text:
        text = text.replace('2.2.4', '2.2.5')
    p.write_text(text, encoding='utf-8', newline='\n')

p = Path('tests/test_remote_access_v4231.py')
text = p.read_text(encoding='utf-8')
extra = '''\n\ndef test_tray_mutex_is_versioned_so_upgrades_start_new_remote_host_immediately():\n    tray=Path("windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs").read_text()\n    assert 'Local\\\\GODSEYE.WindowsAgent.Tray.2.2.5' in tray\n'''
if 'test_tray_mutex_is_versioned_so_upgrades_start_new_remote_host_immediately' not in text:
    p.write_text(text + extra, encoding='utf-8', newline='\n')

print('Applied Agent 2.2.5 tray restart fix.')
