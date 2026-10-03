"""Exercise the report renderer with nested findings and untrusted endpoint text."""
import ast
from pathlib import Path
import shutil
import subprocess


def test_cyber_reports_are_readable_and_escape_remote_data():
    source = (Path(__file__).resolve().parents[1] / 'app/main.py').read_text()
    code = source[source.index('function cyberResultLabel('):source.index('function show(id,data)')]
    script = r'''
const assert=require('node:assert/strict');
const esc=v=>String(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
CODE
const out={};
renderCyberResult(out,{status:'completed',summary:'1/2 endpoints online',result:{ok:true,agent_count:2,online_count:1,offline_count:1,agents:[{computer_name:'<img src=x onerror=alert(1)>',online:false,agent_version:'2.4.5',last_error:'Connection refused',checks:{scan_windows_updates:{status:'completed',result:{updates:[]}},defender:{details:'{"AntivirusEnabled":true,"RecentDetections":[]}'}}}]}});
assert.ok(out.className.includes('cyber-report'));
assert.ok(out.innerHTML.includes('Online Count'));
assert.ok(out.innerHTML.includes('Agent Version'));
assert.ok(out.innerHTML.includes('AntivirusEnabled'));
assert.ok(out.innerHTML.includes('RecentDetections'));
assert.ok(out.innerHTML.includes('Connection refused'));
assert.ok(out.innerHTML.includes('No items reported'));
assert.ok(out.innerHTML.includes('&lt;img'));
assert.ok(!out.innerHTML.includes('<img'));
assert.ok(!out.innerHTML.includes('"agents":'));
renderCyberResult(out,{status:'failed',summary:'Scan unavailable',result:{error:'Engine missing'}});
assert.ok(out.className.includes('failed'));
assert.ok(out.innerHTML.includes('Engine missing'));
'''.replace('CODE', code)
    result = subprocess.run([shutil.which('node'), '-e', script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "renderCyberResult(out,run)" in source[source.index('async function runCyberTool('):]
    assert '<pre id="cyber-result-' not in source
    tools = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'tools_page')
    page = ast.literal_eval(next(n.value for n in tools.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'page' for t in n.targets)))
    assert code.strip() in page
    second = source[source.index('function cyberResultLabel(', source.index('function show(id,data)')):source.index('function renderCyberActions(')]
    assert code.strip() == second.strip()
