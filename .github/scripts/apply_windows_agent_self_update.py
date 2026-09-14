from pathlib import Path

path = Path('app/main.py')
text = path.read_text(encoding='utf-8')
old = '@app.post(f"{router_prefix}/windows-agents/{agent_id}/upgrade")'
new = '@app.post(f"{router_prefix}/windows-agents/{{agent_id}}/upgrade")'
if old not in text:
    raise SystemExit('Broken Windows Agent upgrade route placeholder was not found.')
if text.count(old) != 1:
    raise SystemExit(f'Expected one broken upgrade route, found {text.count(old)}.')
path.write_text(text.replace(old, new, 1), encoding='utf-8')
print('Fixed Windows Agent upgrade route placeholder.')
