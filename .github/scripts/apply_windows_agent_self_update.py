from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"Expected text not found in {path}: {old[:120]!r}")
    if text.count(old) != 1:
        raise SystemExit(f"Expected exactly one match in {path}, found {text.count(old)}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


def insert_before(path, marker, addition):
    replace_once(path, marker, addition + marker)


# Version 2.1.0 is the first updater-capable baseline.
csproj = "windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj"
for old, new in [
    ("<Version>2.0.1</Version>", "<Version>2.1.0</Version>"),
    ("<FileVersion>2.0.1.0</FileVersion>", "<FileVersion>2.1.0.0</FileVersion>"),
    ("<AssemblyVersion>2.0.1.0</AssemblyVersion>", "<AssemblyVersion>2.1.0.0</AssemblyVersion>"),
]:
    replace_once(csproj, old, new)
replace_once("windows/agent-x64/installer/msi/Package.wxs", 'Version="2.0.1"', 'Version="2.1.0"')
replace_once("windows/agent-x64/installer/GODSEYE-Agent-x64.iss", '#define MyAppVersion "2.0.1"', '#define MyAppVersion "2.1.0"')

# Agent: derive version from assembly and add a fixed, hash-verified MSI updater.
agent = "windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs"
replace_once(agent, "using System.Collections.Generic;\n", "using System.Collections.Generic;\nusing System.Diagnostics;\n")
replace_once(
    agent,
    '        const string AgentVersion = "2.0.0";\n',
    '        static readonly string AgentVersion = typeof(GodseyeAgentService).Assembly.GetName().Version?.ToString(3) ?? "2.1.0";\n',
)

updater_methods = r'''        string Sha256File(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
            {
                byte[] hash = sha.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        void DownloadAuthenticatedFile(AgentConfig cfg, string path, string destination)
        {
            string url = cfg.ServerUrl + path;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.Accept = "application/octet-stream";
            req.Timeout = 120000;
            req.ReadWriteTimeout = 120000;
            req.UserAgent = "GODSEYE-Windows-Agent/" + AgentVersion;
            string bearer = ReadApiKey();
            if (!String.IsNullOrWhiteSpace(bearer)) req.Headers[HttpRequestHeader.Authorization] = "Bearer " + bearer;
            try
            {
                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                using (Stream input = res.GetResponseStream())
                using (FileStream output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None))
                    input.CopyTo(output);
            }
            catch (WebException ex)
            {
                string detail = ex.Message;
                if (ex.Response != null) try { using (StreamReader sr = new StreamReader(ex.Response.GetResponseStream())) detail = sr.ReadToEnd(); } catch { }
                throw new Exception("GODSEYE agent update download failed: " + detail, ex);
            }
        }

        string StageAndLaunchUpgrade(AgentConfig cfg, Dictionary<string, object> payload)
        {
            if (payload == null) throw new Exception("Upgrade payload is missing.");
            string targetVersion = payload.ContainsKey("version") ? Convert.ToString(payload["version"]) : "";
            string expectedSha = payload.ContainsKey("sha256") ? Convert.ToString(payload["sha256"]).Trim().ToUpperInvariant() : "";
            Version current;
            Version target;
            if (!Version.TryParse(AgentVersion, out current)) throw new Exception("Current agent version is invalid: " + AgentVersion);
            if (!Version.TryParse(targetVersion, out target)) throw new Exception("Target agent version is invalid.");
            if (target <= current) return "Agent " + AgentVersion + " is already current; no upgrade was required.";
            if (expectedSha.Length != 64) throw new Exception("Upgrade SHA-256 is invalid.");
            foreach (char c in expectedSha) if (!Uri.IsHexDigit(c)) throw new Exception("Upgrade SHA-256 is invalid.");

            string updateDir = Path.Combine(BaseDir, "Updates");
            Directory.CreateDirectory(updateDir);
            string msiPath = Path.Combine(updateDir, "GODSEYE-Windows-Agent-x64-" + targetVersion + ".msi");
            string tempPath = msiPath + ".download";
            if (File.Exists(tempPath)) File.Delete(tempPath);
            DownloadAuthenticatedFile(cfg, "/api/v1/windows-agents/package/msi", tempPath);
            string actualSha = Sha256File(tempPath).ToUpperInvariant();
            if (!String.Equals(actualSha, expectedSha, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(tempPath);
                throw new Exception("Upgrade MSI SHA-256 verification failed.");
            }
            if (File.Exists(msiPath)) File.Delete(msiPath);
            File.Move(tempPath, msiPath);

            string msiexec = Path.Combine(Environment.SystemDirectory, "msiexec.exe");
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = msiexec,
                Arguments = "/i \"" + msiPath + "\" /qn /norestart REBOOT=ReallySuppress",
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = updateDir
            };
            Process process = Process.Start(psi);
            if (process == null) throw new Exception("Windows Installer could not be started.");
            Log("Verified and launched Windows Agent upgrade from " + AgentVersion + " to " + targetVersion + ".");
            return "Verified MSI and launched Windows Installer for agent " + targetVersion + ". The new version will be confirmed by its next heartbeat.";
        }

'''
insert_before(agent, "        void ProcessCommands(AgentConfig cfg, Dictionary<string, object> hb)\n", updater_methods)

old_command = '''                    if (String.Equals(type, "pull_events", StringComparison.OrdinalIgnoreCase))
                    {
                        Dictionary<string, object> pulled = PullEventsNow(cfg);
                        result["ok"] = true;
                        result["events"] = IntValue(pulled, "events");
                        result["new_findings"] = IntValue(pulled, "new_findings");
                        result["details"] = "Pull Events Now completed successfully.";
                        Log("Pull Events Now command completed: " + result["events"] + " event(s), " + result["new_findings"] + " new finding(s)");
                    }
                    else
'''
new_command = '''                    if (String.Equals(type, "pull_events", StringComparison.OrdinalIgnoreCase))
                    {
                        Dictionary<string, object> pulled = PullEventsNow(cfg);
                        result["ok"] = true;
                        result["events"] = IntValue(pulled, "events");
                        result["new_findings"] = IntValue(pulled, "new_findings");
                        result["details"] = "Pull Events Now completed successfully.";
                        Log("Pull Events Now command completed: " + result["events"] + " event(s), " + result["new_findings"] + " new finding(s)");
                    }
                    else if (String.Equals(type, "upgrade_agent", StringComparison.OrdinalIgnoreCase))
                    {
                        Dictionary<string, object> payload = entry.ContainsKey("payload") ? entry["payload"] as Dictionary<string, object> : null;
                        result["ok"] = true;
                        result["events"] = 0;
                        result["new_findings"] = 0;
                        result["details"] = StageAndLaunchUpgrade(cfg, payload);
                    }
                    else
'''
replace_once(agent, old_command, new_command)
replace_once(agent, '                    result["details"] = "Pull Events Now failed: " + ex.Message;\n', '                    result["details"] = "GODSEYE agent command failed: " + ex.Message;\n')

# Manifest helper lives outside the large app module and validates every field.
wa = "app/windows_agent.py"
replace_once(wa, "import secrets\n", "import secrets\nimport re\nfrom pathlib import Path\n")
manifest_helper = r'''

def load_update_manifest(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    version = str(data.get("version") or "").strip()
    sha256 = str(data.get("sha256") or "").strip().upper()
    filename = str(data.get("filename") or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Windows Agent update manifest has an invalid version")
    if not re.fullmatch(r"[0-9A-F]{64}", sha256):
        raise ValueError("Windows Agent update manifest has an invalid SHA-256")
    if filename != "GODSEYE-Windows-Agent-x64.msi":
        raise ValueError("Windows Agent update manifest has an unexpected filename")
    return {"version": version, "sha256": sha256, "filename": filename}
'''
wa_text = Path(wa).read_text(encoding="utf-8")
Path(wa).write_text(wa_text.rstrip() + manifest_helper + "\n", encoding="utf-8")

# Server endpoints and update-aware agent inventory.
main = "app/main.py"
version_marker = '''def _agent_version_tuple(value: str):
    try:
        parts=[int(x) for x in re.findall(r"\\d+",value or "")[:3]]
        return tuple((parts+[0,0,0])[:3])
    except Exception:
        return (0,0,0)


'''
update_server = r'''def _windows_agent_update_manifest():
    from .windows_agent import load_update_manifest
    path=BASE_DIR / "windows" / "agent-x64" / "update-manifest.json"
    try:
        return load_update_manifest(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(503,f"Windows Agent update manifest is unavailable: {exc}")


@app.get(f"{router_prefix}/windows-agents/update-info")
def windows_agent_update_info(user=Depends(get_current_user)):
    manifest=_windows_agent_update_manifest()
    return {"ok":True,**manifest,"self_update_baseline":"2.1.0"}


@app.post(f"{router_prefix}/windows-agents/{agent_id}/upgrade")
def windows_agent_upgrade(agent_id: int, request: Request, user=Depends(require_admin)):
    manifest=_windows_agent_update_manifest(); ts=now()
    target=manifest["version"]
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(agent_id,)).fetchone()
        if not agent: raise HTTPException(404,"Windows Agent not found")
        if not agent["enabled"] or agent["revoked_at"]: raise HTTPException(409,"Windows Agent is disabled or revoked")
        installed=agent["agent_version"] or "0.0.0"
        if _agent_version_tuple(installed) >= _agent_version_tuple(target):
            return {"ok":True,"queued":False,"update_available":False,"installed_version":installed,"available_version":target,"message":"This Windows Agent is already up to date."}
        if _agent_version_tuple(installed) < (2,1,0):
            raise HTTPException(409,f"Windows Agent {installed} requires one manual upgrade to 2.1.0 or newer before self-update is available. Download and run the current x64 installer once; enrollment is preserved.")
        existing=c.execute("SELECT * FROM windows_agent_commands WHERE agent_id=? AND command_type='upgrade_agent' AND status IN ('pending','delivered') ORDER BY id DESC LIMIT 1",(agent_id,)).fetchone()
        if existing:
            return {"ok":True,"queued":True,"command_id":existing["id"],"status":existing["status"],"installed_version":installed,"available_version":target,"message":"An Agent upgrade is already queued."}
        payload=json.dumps({"version":target,"sha256":manifest["sha256"]},separators=(",",":"))
        cur=c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'upgrade_agent',?,'pending',?,?)",(agent_id,payload,user["username"],ts))
        cid=cur.lastrowid
        audit(c,user["username"],"windows_agent_upgrade_requested",str(agent_id),json.dumps({"command_id":cid,"computer_name":agent["computer_name"],"installed_version":installed,"target_version":target}),client_ip(request))
    return {"ok":True,"queued":True,"command_id":cid,"status":"pending","installed_version":installed,"available_version":target,"message":f"Upgrade to Windows Agent {target} queued. The agent will verify the MSI and launch Windows Installer on its next heartbeat."}


'''
replace_once(main, version_marker, version_marker + update_server)

old_list_start = '''def windows_agent_list(user=Depends(get_current_user)):
    from .windows_agent import public_agent
    nowdt=dt.datetime.now(dt.timezone.utc); out=[]
'''
new_list_start = '''def windows_agent_list(user=Depends(get_current_user)):
    from .windows_agent import public_agent
    nowdt=dt.datetime.now(dt.timezone.utc); out=[]
    try: update_manifest=_windows_agent_update_manifest()
    except HTTPException: update_manifest=None
'''
replace_once(main, old_list_start, new_list_start)
old_pull_support = '''            d["pull_now_supported"]=_agent_version_tuple(d.get("agent_version") or "") >= (1,1,0)
            if pull:
'''
new_pull_support = '''            installed_version=d.get("agent_version") or "0.0.0"
            d["pull_now_supported"]=_agent_version_tuple(installed_version) >= (1,1,0)
            d["upgrade_supported"]=_agent_version_tuple(installed_version) >= (2,1,0)
            d["available_version"]=update_manifest["version"] if update_manifest else None
            d["update_available"]=bool(update_manifest and _agent_version_tuple(installed_version) < _agent_version_tuple(update_manifest["version"]))
            if pull:
'''
replace_once(main, old_pull_support, new_pull_support)

package_marker = '''@app.get(f"{router_prefix}/windows-agents/package")
def windows_agent_package(user=Depends(require_admin)):
'''
msi_endpoint = '''@app.get(f"{router_prefix}/windows-agents/package/msi")
def windows_agent_msi_package(agent=Depends(_agent_auth)):
    manifest=_windows_agent_update_manifest()
    path=BASE_DIR / "windows" / "agent-x64" / manifest["filename"]
    if not path.exists(): raise HTTPException(404,"Windows Agent x64 MSI is not installed")
    return FileResponse(path,media_type="application/octet-stream",filename=manifest["filename"],headers={"X-GODSEYE-Agent-Version":manifest["version"],"X-GODSEYE-SHA256":manifest["sha256"]})


'''
insert_before(main, package_marker, msi_endpoint)

# UI: add Check for Updates and update/upgrade actions per agent.
replace_once(
    main,
    '<div class="actions"><button class="primary operate-only" type="button" onclick="pullAllWindowsAgentsNow()">⟳ Pull All Online</button><button class="secondary admin-only" type="button" onclick="downloadWindowsAgentPackage()">↓ Download x64 Installer</button><button class="primary admin-only" type="button" onclick="createWindowsAgentEnrollment()">＋ Create Enrollment Token</button></div>',
    '<div class="actions"><button class="secondary" type="button" onclick="checkWindowsAgentUpdates()">↻ Check for Updates</button><button class="primary operate-only" type="button" onclick="pullAllWindowsAgentsNow()">⟳ Pull All Online</button><button class="secondary admin-only" type="button" onclick="downloadWindowsAgentPackage()">↓ Download x64 Installer</button><button class="primary admin-only" type="button" onclick="createWindowsAgentEnrollment()">＋ Create Enrollment Token</button></div>',
)
ui_start = "function renderWindowsAgents(){\n"
ui_end = "async function createWindowsAgentEnrollment(){\n"
text = Path(main).read_text(encoding="utf-8")
start = text.index(ui_start)
end = text.index(ui_end, start)
new_ui = r'''function renderWindowsAgents(){
 const root=document.getElementById('windowsAgentList');if(!root)return;
 root.innerHTML=WINDOWS_AGENTS.length?WINDOWS_AGENTS.map(x=>{
   const pull=x.last_pull_status&&x.last_pull_status!=='never'?` · Pull: ${esc(x.last_pull_status)}${x.last_pull_completed_at?' '+esc(new Date(x.last_pull_completed_at).toLocaleTimeString()):''}`:'';
   const pullBtn=x.revoked_at?'':(x.pull_now_supported?`<button class="primary operate-only" onclick="pullWindowsAgentNow(${x.id})">⟳ Pull Events Now</button>`:`<button class="secondary" disabled title="Install the permanent x64 agent (v2.0.0 or newer)">Update Agent for Pull Now</button>`);
   let updateBtn='';
   if(!x.revoked_at&&x.update_available){
     updateBtn=x.upgrade_supported?`<button class="primary admin-only" onclick="upgradeWindowsAgent(${x.id})">↑ Upgrade to ${esc(x.available_version)}</button>`:`<button class="secondary admin-only" onclick="downloadWindowsAgentPackage()" title="Agent 2.0.x needs one manual baseline upgrade; enrollment is preserved.">↓ Manual Update to ${esc(x.available_version)}</button>`;
   }else if(!x.revoked_at&&x.available_version){updateBtn=`<button class="secondary" disabled>✓ Up to date</button>`}
   const updateText=x.available_version?(x.update_available?` · Update available: ${esc(x.available_version)}${x.upgrade_supported?'':' (one manual baseline update required)'}`:` · Latest: ${esc(x.available_version)}`):'';
   return `<div class="windows-agent-row"><span class="windows-agent-icon">W</span><div><b>${esc(x.computer_name||x.hostname||'Windows Agent')}</b><small><span class="agent-status ${esc(x.status||'enrolled')}"><span class="agent-status-dot"></span>${esc(x.status||'enrolled')}</span> · ${esc(x.ip_address||'no IP')} · ${esc(x.os_version||'Windows')} · Agent ${esc(x.agent_version||'—')} · ${x.open_findings||0} open finding(s)${updateText}</small><small>Last heartbeat: ${x.last_heartbeat_at?esc(new Date(x.last_heartbeat_at).toLocaleString()):'never'} · Channels: ${(x.channels||[]).map(esc).join(', ')} · every ${x.poll_interval_seconds||60}s${pull}${x.last_error?' · '+esc(x.last_error):''}</small></div><div class="actions">${updateBtn}${pullBtn}${x.revoked_at?'':`<button class="secondary admin-only" onclick="configureWindowsAgent(${x.id})">Configure</button><button class="danger admin-only" onclick="revokeWindowsAgent(${x.id})">Revoke</button>`}</div></div>`
 }).join(''):'<div class="empty">No Windows Agents enrolled.</div>';
 applyRoleVisibility();
}
async function checkWindowsAgentUpdates(){
 try{
   const info=await json('/api/v1/windows-agents/update-info');await loadWindowsAgents();
   const updates=WINDOWS_AGENTS.filter(x=>x.update_available),automatic=updates.filter(x=>x.upgrade_supported),manual=updates.filter(x=>!x.upgrade_supported);
   alert(`Latest Windows Agent: ${info.version}. ${updates.length} enrolled agent${updates.length===1?'':'s'} need an update.${automatic.length?' '+automatic.length+' can upgrade directly from GODSEYE.':''}${manual.length?' '+manual.length+' need the one-time 2.1.0 baseline installer first.':''}`);
 }catch(e){alert('Could not check Windows Agent updates: '+e.message)}
}
async function upgradeWindowsAgent(id){
 const x=WINDOWS_AGENTS.find(a=>a.id===id);if(!x)return;
 if(!confirm(`Upgrade ${x.computer_name||'this Windows Agent'} from ${x.agent_version||'unknown'} to ${x.available_version||'the latest version'}? Enrollment, API key, bookmarks, queue, and configuration will be preserved.`))return;
 try{
   const r=await json('/api/v1/windows-agents/'+id+'/upgrade',{method:'POST'});alert(r.message||'Windows Agent upgrade queued.');await loadWindowsAgents();
   setTimeout(loadWindowsAgents,15000);
 }catch(e){alert('Could not upgrade Windows Agent: '+e.message)}
}
'''
Path(main).write_text(text[:start] + new_ui + text[end:], encoding="utf-8")

# Update build workflow to generate/publish the signed-by-hash manifest and v2.1.0 artifacts.
workflow = ".github/workflows/build-windows-agent.yml"
replace_once(workflow, "          Write-Host \"MSI SHA256: $msiHash\"\n", '''          Write-Host "MSI SHA256: $msiHash"

          [xml]$projectXml = Get-Content 'windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj'
          $agentVersion = [string]$projectXml.Project.PropertyGroup.Version
          if ([string]::IsNullOrWhiteSpace($agentVersion)) { throw 'Could not read Windows Agent version from the project.' }
          $manifest = [ordered]@{
            version = $agentVersion
            filename = 'GODSEYE-Windows-Agent-x64.msi'
            sha256 = $msiHash
          } | ConvertTo-Json
          Set-Content -Path 'windows/agent-x64/update-manifest.json' -Value $manifest -Encoding utf8
          Write-Host "Update manifest version: $agentVersion"
''')
replace_once(workflow, "          name: GODSEYE-Windows-Agent-x64-2.0.1\n", "          name: GODSEYE-Windows-Agent-x64-2.1.0\n")
replace_once(workflow, "            windows/agent-x64/GODSEYE-Windows-Agent-x64.msi.sha256\n", "            windows/agent-x64/GODSEYE-Windows-Agent-x64.msi.sha256\n            windows/agent-x64/update-manifest.json\n")
replace_once(workflow, "          git add -f windows/agent-x64/GODSEYE-Windows-Agent-x64.msi.sha256\n", "          git add -f windows/agent-x64/GODSEYE-Windows-Agent-x64.msi.sha256\n          git add -f windows/agent-x64/update-manifest.json\n")
replace_once(workflow, "          git commit -m 'Build Windows agent 2.0.1 packages [skip ci]'\n", "          git commit -m 'Build Windows agent 2.1.0 packages [skip ci]'\n")

# Existing packaging test should verify assembly-derived versioning now.
perm_test = "tests/test_permanent_x64_windows_agent_v423.py"
replace_once(perm_test, '    assert \'AgentVersion = "2.0.0"\' in src\n', '    assert \'Assembly.GetName().Version\' in src\n    assert \'<Version>2.1.0</Version>\' in csproj\n')

# Dedicated self-update tests.
Path("tests/test_windows_agent_self_update.py").write_text(r'''from pathlib import Path
from types import SimpleNamespace
import json
import app.main as main
import app.windows_agent as windows_agent


def req(ip="192.168.1.50"):
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers={})


def admin():
    return {"username":"admin","role":"admin"}


def make_agent(c, version="2.1.0"):
    ts=main.now()
    return c.execute("""INSERT INTO windows_agents(agent_uuid,api_key_hash,computer_name,agent_version,status,enabled,last_heartbeat_at,enrolled_at,updated_at)
                        VALUES('update-agent','hash','FILESERVER01',?,'online',1,?,?,?)""",(version,ts,ts,ts)).lastrowid


def manifest(version="2.2.0"):
    return {"version":version,"filename":"GODSEYE-Windows-Agent-x64.msi","sha256":"A"*64}


def test_manifest_validation(tmp_path):
    p=tmp_path/"update-manifest.json"
    p.write_text(json.dumps(manifest("2.1.0")))
    assert windows_agent.load_update_manifest(p)["version"]=="2.1.0"
    p.write_text(json.dumps({**manifest(),"filename":"evil.exe"}))
    try: windows_agent.load_update_manifest(p); assert False
    except ValueError: pass


def test_update_inventory_and_upgrade_queue(tmp_path, monkeypatch):
    db=tmp_path/"update.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db();monkeypatch.setattr(main,"audit",lambda *a,**k:None)
    monkeypatch.setattr(windows_agent,"load_update_manifest",lambda path:manifest("2.2.0"))
    with main.db() as c: aid=make_agent(c,"2.1.0")
    rows=main.windows_agent_list(admin());row=next(x for x in rows if x["id"]==aid)
    assert row["update_available"] is True and row["upgrade_supported"] is True and row["available_version"]=="2.2.0"
    queued=main.windows_agent_upgrade(aid,req(),admin())
    assert queued["queued"] and queued["available_version"]=="2.2.0"
    again=main.windows_agent_upgrade(aid,req(),admin())
    assert again["command_id"]==queued["command_id"]
    with main.db() as c:
        cmd=c.execute("SELECT * FROM windows_agent_commands WHERE id=?",(queued["command_id"],)).fetchone()
    assert cmd["command_type"]=="upgrade_agent"
    payload=json.loads(cmd["payload_json"])
    assert payload=={"version":"2.2.0","sha256":"A"*64}
    assert "url" not in payload and "command" not in payload


def test_pre_21_agent_requires_one_manual_baseline_update(tmp_path, monkeypatch):
    db=tmp_path/"baseline.db";monkeypatch.setattr(main,"DB_PATH",db);main.init_db();monkeypatch.setattr(main,"audit",lambda *a,**k:None)
    monkeypatch.setattr(windows_agent,"load_update_manifest",lambda path:manifest("2.1.0"))
    with main.db() as c: aid=make_agent(c,"2.0.1")
    try: main.windows_agent_upgrade(aid,req(),admin());assert False
    except main.HTTPException as exc:
        assert exc.status_code==409 and "manual upgrade" in str(exc.detail).lower()


def test_x64_agent_updater_is_fixed_hash_verified_msi_path():
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    csproj=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    assert '<Version>2.1.0</Version>' in csproj
    assert 'Assembly.GetName().Version' in src
    assert '"upgrade_agent"' in src
    assert '"/api/v1/windows-agents/package/msi"' in src
    assert 'SHA256.Create()' in src and 'Upgrade MSI SHA-256 verification failed.' in src
    assert 'Environment.SystemDirectory' in src and '"msiexec.exe"' in src
    assert 'cmd.exe' not in src.lower()
    assert 'powershell.exe' not in src.lower()
    assert 'payload.ContainsKey("url")' not in src


def test_update_ui_and_server_routes_present():
    source=Path("app/main.py").read_text()
    html=main.DASHBOARD
    assert '/windows-agents/package/msi' in source
    assert '/windows-agents/{agent_id}/upgrade' in source
    assert 'Check for Updates' in html
    assert 'checkWindowsAgentUpdates' in html
    assert 'upgradeWindowsAgent' in html
    assert 'one manual baseline update required' in html
''', encoding="utf-8")

# Seed a valid manifest for the branch; the Windows build replaces it with the 2.1.0 MSI hash.
Path("windows/agent-x64/update-manifest.json").write_text(json.dumps({
    "version":"2.0.1",
    "filename":"GODSEYE-Windows-Agent-x64.msi",
    "sha256":"56568BA85B100AB40AC74B7A3089398F7362ADA5C2595CB9E88178A5409695BC"
}, indent=2) + "\n", encoding="utf-8")

# Documentation.
readme = Path("windows/agent-x64/README.md")
r = readme.read_text(encoding="utf-8")
r = r.replace("# GODSEYE Windows Agent x64 v2.0.1", "# GODSEYE Windows Agent x64 v2.1.0", 1)
r += '''\n## Agent updates\n\nVersion 2.1.0 is the first self-update capable baseline. GODSEYE exposes the current agent version and SHA-256 manifest in the Windows Agents view. An administrator can use **Check for Updates** and, for agents already on 2.1.0 or newer, **Upgrade Agent**. The service downloads only the fixed authenticated GODSEYE MSI endpoint, verifies the published SHA-256, and starts Windows Installer silently. The update payload cannot supply an arbitrary URL, executable, shell, or command.\n\nAgents on 2.0.x require one manual upgrade to 2.1.0 using the current x64 Setup/MSI. That baseline upgrade preserves `%ProgramData%\\GODSEYE\\Agent`, including enrollment, DPAPI-protected API key, bookmarks, pending queue, logs, and configuration. After that baseline, future agent releases can be upgraded from GODSEYE without another enrollment token.\n'''
readme.write_text(r, encoding="utf-8")

print("Windows Agent self-update patch applied.")
