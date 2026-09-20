#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, stat, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
if VERSION != '4.30.0':
    raise SystemExit(f'Refusing release build: VERSION is {VERSION!r}, expected 4.30.0')

required = [
    'VERSION','README.md','RELEASE_MANIFEST.json','V430_RELEASE_NOTES.md','requirements.txt','install.sh',
    'app/main.py','app/windows_agent.py','windows/agent-x64/update-manifest.json',
    'windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj',
]
for rel in required:
    if not (ROOT / rel).is_file():
        raise SystemExit(f'Missing required release file: {rel}')

manifest = json.loads((ROOT/'windows/agent-x64/update-manifest.json').read_text(encoding='utf-8'))
# The source package must never masquerade as a built Agent package.
if manifest.get('status') == 'ready':
    msi = ROOT/'windows/agent-x64'/str(manifest.get('filename') or '')
    digest = str(manifest.get('sha256') or '').lower()
    if not msi.is_file() or len(digest) != 64:
        raise SystemExit('Agent manifest says ready but verified MSI metadata is missing')
    h=hashlib.sha256(msi.read_bytes()).hexdigest()
    if h != digest:
        raise SystemExit('Agent manifest SHA-256 does not match MSI')

out = Path(sys.argv[1] if len(sys.argv)>1 else ROOT.parent / f'GODSEYE-v{VERSION}-server-candidate.zip').resolve()
out.parent.mkdir(parents=True, exist_ok=True)

skip_parts = {'.git','.pytest_cache','__pycache__','.mypy_cache','.ruff_cache','.venv','venv','node_modules','screenshots-v430-actual'}
skip_suffixes = {'.pyc','.pyo','.log','.tmp','.swp'}
skip_names = {'godseye.db','godseye.db-shm','godseye.db-wal'}

files=[]
for p in ROOT.rglob('*'):
    if not p.is_file():
        continue
    rel=p.relative_to(ROOT)
    if any(part in skip_parts for part in rel.parts):
        continue
    if p.suffix.lower() in skip_suffixes or p.name in skip_names:
        continue
    # Do not ship test/runtime backup databases even if renamed.
    if p.suffix.lower()=='.db' and ('data' in rel.parts or 'backup' in p.name.lower()):
        continue
    files.append((p,rel))

with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p,rel in sorted(files,key=lambda x:str(x[1])):
        info=zipfile.ZipInfo(str(rel).replace(os.sep,'/'))
        info.date_time=(2026,9,18,0,0,0)
        mode = 0o755 if os.access(p,os.X_OK) or p.name in {'install.sh','doctor.sh','godseye-apply-update','godseye-https-setup','godseye-release-audit'} else 0o644
        info.external_attr=(stat.S_IFREG|mode)<<16
        z.writestr(info,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)

sha=hashlib.sha256(out.read_bytes()).hexdigest()
sha_path=out.with_suffix(out.suffix+'.sha256')
sha_path.write_text(f'{sha}  {out.name}\n',encoding='utf-8')
print(out)
print(sha_path)
print(sha)
print(f'{len(files)} files')
