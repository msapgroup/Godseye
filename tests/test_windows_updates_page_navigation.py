"""Run the actual dashboard navigation JS against API success/error responses."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("mode", ["enrolled", "empty", "error"])
def test_opening_windows_updates_fetches_and_finishes_loading(mode):
    node = shutil.which("node")
    assert node, "Node is required for the dashboard JavaScript regression test"
    source = (ROOT / "app/main.py").read_text()
    loaders = source[source.index("const VIEW_LOADERS="):]
    loaders = loaders[:loaders.index("\n};") + 3]
    navigation = source[source.index("function showView(name,"):]
    navigation = navigation[:navigation.index("\nfunction ")]
    load = source[source.index("async function loadMicrosoftWindowsUpdatesView(){"):]
    load = load[:load.index("\nasync function scanWindowsUpdatesView(")]
    script = r'''
const assert = require('node:assert/strict');
const mode = MODE;
const box = {innerHTML:'Loading Windows computers…'};
const target = {style:{}, setAttribute(){}};
const title = {};
const document = {
 getElementById(id) {
  if(id==='microsoftWindowsUpdatesList')return box;
  if(id==='view-windows-updates')return target;
  if(id==='v430PageTitle')return title;
  return null;
 },
 querySelectorAll(){return []}, querySelector(){return null}
};
const ME = {role:'admin'};
const location = {hash:''};
const history = {replaceState(){}};
const window = {scrollTo(){}};
const esc = s => String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
let calls = 0;
async function json(url) {
 assert.equal(url,'/api/v1/windows-agents'); calls++;
 if(mode==='error')throw new Error('Server temporarily unavailable');
 return mode==='empty'?[]:[{id:2,computer_name:'GMRS',os_version:'Windows 10',status:'online',agent_version:'2.4.5'}];
}
CODE
(async()=>{
 assert.equal(showView('windows-updates'),true);
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(calls,1,'Opening the sidebar page must fetch agents automatically');
 assert.equal(target.style.display,'block');
 assert.equal(title.textContent,'Microsoft Windows Updates');
 assert.ok(!box.innerHTML.includes('Loading Windows computers'));
 if(mode==='enrolled') {
  assert.ok(box.innerHTML.includes('GMRS'));
  assert.ok(box.innerHTML.includes('online'));
  assert.ok(box.innerHTML.includes('2.4.5'));
  assert.ok(box.innerHTML.includes('Scan Microsoft Updates'));
 } else if(mode==='empty')assert.ok(box.innerHTML.includes('No enrolled Windows computers'));
 else assert.ok(box.innerHTML.includes('Could not load Windows computers: Server temporarily unavailable'));
})().catch(e=>{console.error(e);process.exitCode=1});
'''.replace("MODE", json.dumps(mode)).replace("CODE", load + loaders + navigation)
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
