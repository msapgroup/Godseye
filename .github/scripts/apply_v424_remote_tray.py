from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"patch marker not found: {label}")
    return text.replace(old, new, 1)


# ---- Windows agent service / interactive tray integration -----------------
svc_path = Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs")
svc = svc_path.read_text(encoding="utf-8")
svc = replace_once(svc,
    'static readonly string AgentVersion = typeof(GodseyeAgentService).Assembly.GetName().Version?.ToString(3) ?? "2.2.0";',
    'static readonly string AgentVersion = typeof(GodseyeAgentService).Assembly.GetName().Version?.ToString(3) ?? "2.2.1";',
    "agent fallback version")
svc = replace_once(svc,
    '        int remoteHelperProcessId;\n',
    '        int remoteHelperProcessId;\n        int trayHelperProcessId;\n',
    "tray process field")
svc = replace_once(svc,
    '        static void Main(string[] args)\n        {\n            if (args.Length > 0 && args[0].Equals("--remote-helper", StringComparison.OrdinalIgnoreCase))',
    '        [STAThread]\n        static void Main(string[] args)\n        {\n            if (args.Length > 0 && args[0].Equals("--tray", StringComparison.OrdinalIgnoreCase))\n            {\n                Environment.ExitCode = TrayApp.Run();\n                return;\n            }\n            if (args.Length > 0 && args[0].Equals("--remote-helper", StringComparison.OrdinalIgnoreCase))',
    "tray entrypoint")
svc = replace_once(svc,
    '                    AgentConfig cfg = LoadConfig();\n                    if (cfg.SkipTlsVerify)',
    '                    AgentConfig cfg = LoadConfig();\n                    EnsureTrayProcess();\n                    if (cfg.SkipTlsVerify)',
    "ensure tray process")
svc = replace_once(svc,
    '                    Dictionary<string, object> hb = Heartbeat(cfg);\n                    ApplyServerConfig(cfg, hb);',
    '                    Dictionary<string, object> hb = Heartbeat(cfg);\n                    WriteTrayStatus(cfg);\n                    ApplyServerConfig(cfg, hb);',
    "tray status heartbeat")
insert_marker = '        const uint INVALID_SESSION_ID = 0xFFFFFFFF;\n'
methods = '''        void WriteTrayStatus(AgentConfig cfg)\n        {\n            try\n            {\n                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\\MSAPGROUP\\GODSEYE Agent\\Status", true))\n                {\n                    if (key == null) return;\n                    key.SetValue("ServerUrl", cfg.ServerUrl ?? "", RegistryValueKind.String);\n                    key.SetValue("Version", AgentVersion, RegistryValueKind.String);\n                    key.SetValue("LastCheckIn", DateTime.Now.ToString("g"), RegistryValueKind.String);\n                    key.SetValue("RemoteAccess", "Enabled (User Approval)", RegistryValueKind.String);\n                }\n            }\n            catch (Exception ex) { Log("Could not publish tray status: " + ex.Message); }\n        }\n\n        void EnsureTrayProcess()\n        {\n            try\n            {\n                if (trayHelperProcessId > 0)\n                {\n                    try { using (Process p = Process.GetProcessById(trayHelperProcessId)) { if (!p.HasExited) return; } }\n                    catch { }\n                    trayHelperProcessId = 0;\n                }\n                uint sessionId = WTSGetActiveConsoleSessionId();\n                if (sessionId == INVALID_SESSION_ID) return;\n                IntPtr token = IntPtr.Zero;\n                if (!WTSQueryUserToken(sessionId, out token) || token == IntPtr.Zero) return;\n                try\n                {\n                    string exe = Process.GetCurrentProcess().MainModule?.FileName ?? Environment.ProcessPath ?? "";\n                    if (String.IsNullOrWhiteSpace(exe)) return;\n                    STARTUPINFO si = new STARTUPINFO();\n                    si.cb = Marshal.SizeOf(typeof(STARTUPINFO));\n                    si.lpDesktop = @"winsta0\\default";\n                    PROCESS_INFORMATION pi;\n                    var cmd = new StringBuilder("\\\"" + exe + "\\\" --tray");\n                    if (CreateProcessAsUser(token, exe, cmd, IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero, Path.GetDirectoryName(exe), ref si, out pi))\n                    {\n                        trayHelperProcessId = unchecked((int)pi.dwProcessId);\n                        if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);\n                        if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);\n                    }\n                }\n                finally { CloseHandle(token); }\n            }\n            catch (Exception ex) { Log("Could not start tray helper: " + ex.Message); }\n        }\n\n'''
svc = replace_once(svc, insert_marker, methods + insert_marker, "tray service methods")
old_consent = '            int consent = MessageBox(IntPtr.Zero, "GODSEYE administrator \'" + requestedBy + "\' is requesting a remote support session.\\n\\nAllow screen viewing and mouse/keyboard control until the session is disconnected?", "GODSEYE Remote Support", MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST);\n            if (consent != IDYES) return 2;'
new_consent = '            if (!TrayApp.ShowConsentDialog(requestedBy)) return 2;'
svc = replace_once(svc, old_consent, new_consent, "remote approval dialog")
svc_path.write_text(svc, encoding="utf-8", newline="\n")


# ---- Server Remote Access UI ----------------------------------------------
main_path = Path("app/main.py")
main = main_path.read_text(encoding="utf-8")

css_start = main.index('/* v4.23.1 — consent-aware Windows Agent Remote Access */')
css_end = main.index('@media(max-width:1000px)', css_start)
css_end = main.index('\n', css_end) + 1
new_css = r'''/* v4.24 — Windows Agent Remote Access console */
.remote-hero{align-items:center;gap:18px}.remote-hero h1{margin-bottom:4px}.remote-stats{display:flex;gap:10px;flex-wrap:wrap}.remote-stats span{min-width:104px;padding:11px 14px;border:1px solid #dce6f0;border-radius:10px;background:#fff;color:#52677f;font-size:10px}.remote-stats b{font-size:19px;color:#1f344c;margin-right:5px}.remote-layout{display:grid;grid-template-columns:minmax(440px,46%) minmax(0,1fr);gap:14px}.remote-computers,.remote-session-panel{min-height:610px}.remote-filter{padding:0 14px 11px}.remote-filter input{width:100%}.remote-agent-list{padding:0 10px 14px}.remote-agent-table-head,.remote-agent-row{display:grid;grid-template-columns:minmax(120px,1.45fr) minmax(90px,1fr) 86px 70px 105px 92px;align-items:center;gap:10px}.remote-agent-table-head{padding:8px 10px;border-bottom:1px solid #dce6f0;color:#60758d;font-size:9px;font-weight:800}.remote-agent-row{padding:10px;border-bottom:1px solid #e5edf5;background:#fff;font-size:10px}.remote-agent-row:last-child{border-bottom:0}.remote-agent-name{font-weight:800;color:#20364e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.remote-agent-user,.remote-agent-version,.remote-agent-seen{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.remote-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:#9ba9b7}.remote-dot.online{background:#18c768}.remote-dot.offline{background:#ff4e57}.remote-status{font-weight:700;white-space:nowrap}.remote-session-head{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:0 0 12px}.remote-session-head h2{margin:0 0 3px}.remote-ready{display:flex;align-items:center;gap:6px;color:#21c96b;font-weight:800;font-size:10px}.remote-screen-wrap{height:430px;border-radius:9px;border:1px solid #cfdbe7;background:#06101b;display:grid;place-items:center;overflow:hidden;outline:none;position:relative}.remote-screen-wrap:focus{box-shadow:0 0 0 2px rgba(15,125,240,.35)}.remote-screen{width:100%;height:100%;object-fit:contain;user-select:none;cursor:default}.remote-screen-empty{display:flex;flex-direction:column;align-items:center;gap:7px;color:#9fb0c2;font-size:10px}.remote-screen-empty b{font-size:13px;color:#dfe9f4}.remote-monitor-icon{font-size:42px;color:#2388f2}.remote-session-meta{display:flex;gap:18px;flex-wrap:wrap;padding-top:11px;font-size:9px;color:#71869d}.remote-session-meta b{color:#263b53}.remote-connect{min-width:78px}.remote-waiting{color:#f0b94b!important}.remote-features{margin-top:12px;border:1px solid #d5e2ef;border-radius:10px;padding:14px 16px;background:#f8fbff}.remote-features h3{margin:0 0 9px;color:#178cf1;font-size:12px}.remote-features ul{list-style:none;padding:0;margin:0;display:grid;gap:7px}.remote-features li{font-size:10px;color:#4c6178}.remote-features li:before{content:'✓';display:inline-grid;place-items:center;width:16px;height:16px;border-radius:50%;margin-right:7px;background:#19bf68;color:white;font-weight:900}.remote-empty-error{padding:22px;color:#ff7182;text-align:center}.remote-table-empty{padding:30px 12px;text-align:center;color:#7b8fa5}
html[data-theme="dark"] .remote-stats span,html[data-theme="dark"] .remote-agent-row{background:#101923!important;border-color:#2d4056!important;color:#d8e3ef!important}html[data-theme="dark"] .remote-agent-table-head{border-color:#2d4056!important;color:#91a5bb!important}html[data-theme="dark"] .remote-stats b,html[data-theme="dark"] .remote-agent-name,html[data-theme="dark"] .remote-session-meta b{color:#fff!important}html[data-theme="dark"] .remote-session-meta{color:#98abc0!important}html[data-theme="dark"] .remote-screen-wrap{border-color:#31465e!important;background:#02070d!important}html[data-theme="dark"] .remote-features{background:#0d1b29!important;border-color:#29435c!important}html[data-theme="dark"] .remote-features li{color:#d7e3ef!important}
@media(max-width:1150px){.remote-layout{grid-template-columns:1fr}.remote-computers,.remote-session-panel{min-height:auto}.remote-screen-wrap{height:min(62vw,500px)}}@media(max-width:720px){.remote-agent-table-head{display:none}.remote-agent-row{grid-template-columns:1fr auto}.remote-agent-row>*:not(.remote-agent-name):not(.remote-agent-action){display:none}.remote-layout{grid-template-columns:1fr}}
'''
main = main[:css_start] + new_css + main[css_end:]

old_hero = '<div class="hero remote-hero"><div><h1>Remote Access</h1><div class="muted">Secure remote support for computers running GODSEYE Windows Agent 2.2.0 or newer. The signed-in Windows user must approve each session.</div></div><div class="remote-stats"><span><b id="remoteOnlineCount">0</b> Online</span><span><b id="remoteOfflineCount">0</b> Offline</span><span><b id="remoteTotalCount">0</b> Agents</span></div></div>'
new_hero = '<div class="hero remote-hero"><div><h1>Remote Access</h1><div class="muted">Connect to an online Windows computer with the GODSEYE Agent. The signed-in user approves each remote-control session.</div></div><div class="remote-stats"><span><b id="remoteOnlineCount">0</b> Online</span><span><b id="remoteOfflineCount">0</b> Offline</span><span><b id="remoteTotalCount">0</b> Agents</span></div></div>'
main = replace_once(main, old_hero, new_hero, "remote hero")
main = replace_once(main,
    '<div class="remote-session-head"><div><h2 id="remoteSessionTitle">Remote Session</h2><div class="muted" id="remoteSessionStatus">Select an online computer to begin.</div></div><div class="actions">',
    '<div class="remote-session-head"><div><h2 id="remoteSessionTitle">Remote Session</h2><div class="muted" id="remoteSessionStatus">Select an online computer to begin.</div></div><div class="actions"><span class="remote-ready"><span class="remote-dot online"></span>Ready</span>',
    "remote ready badge")
main = replace_once(main,
    '<div id="remoteSessionMeta" class="remote-session-meta"><span>Computer: <b>—</b></span><span>User approval: <b>Required</b></span><span>Agent: <b>—</b></span><span>Status: <b>Idle</b></span></div>',
    '<div id="remoteFeatureCard" class="remote-features"><h3>Remote Access Features</h3><ul><li>View and control the remote screen</li><li>Mouse and keyboard control</li><li>Works over the GODSEYE agent connection — no inbound RDP required</li><li>Signed-in Windows user approval is required</li></ul></div><div id="remoteSessionMeta" class="remote-session-meta"><span>Computer: <b>—</b></span><span>User approval: <b>Required</b></span><span>Agent: <b>—</b></span><span>Status: <b>Idle</b></span></div>',
    "remote features card")

js_anchor = 'let REMOTE_MOVE_AT=0;\n\n'
remote_api = r'''let REMOTE_MOVE_AT=0;

function remoteCsrf(){const raw=(document.cookie.match('(?:^|; )godseye_csrf=([^;]*)')||[])[1]||'';return decodeURIComponent(raw)}
async function remoteApi(url,opt={}){
 const options={...opt};options.headers={Accept:'application/json',...(opt.headers||{})};const method=String(options.method||'GET').toUpperCase();
 if(method!=='GET'&&method!=='HEAD'){options.headers['X-CSRF-Token']=remoteCsrf();if(options.body&&!options.headers['Content-Type'])options.headers['Content-Type']='application/json'}
 const r=await fetch(url,options);const text=await r.text();if(r.status===401){location.reload();throw new Error('Sign in required')}if(!r.ok)throw new Error(text||('Request failed: '+r.status));if(!text)return{};try{return JSON.parse(text)}catch(_){return{text}}
}

'''
main = replace_once(main, js_anchor, remote_api, "remote API helper")

render_start = main.index('function renderRemoteAgents(){', main.index('let REMOTE_AGENTS=[];'))
render_end = main.index('async function startRemoteSession(agentId){', render_start)
new_render = r'''function remoteAgo(v){if(!v)return'—';const t=new Date(v).getTime();if(!Number.isFinite(t))return'—';const s=Math.max(0,Math.floor((Date.now()-t)/1000));if(s<60)return s+' sec ago';if(s<3600)return Math.floor(s/60)+' min ago';if(s<86400)return Math.floor(s/3600)+' hr ago';return Math.floor(s/86400)+' day'+(s>=172800?'s':'')+' ago'}
function renderRemoteAgents(){
 const root=document.getElementById('remoteAgentList');if(!root)return;
 const q=(document.getElementById('remoteSearch')?.value||'').trim().toLowerCase();
 const rows=REMOTE_AGENTS.filter(a=>!q||[a.computer_name,a.hostname,a.ip_address,a.agent_version,a.username].some(v=>String(v||'').toLowerCase().includes(q)));
 const online=REMOTE_AGENTS.filter(a=>a.status==='online').length;
 const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v};set('remoteOnlineCount',online);set('remoteOfflineCount',Math.max(0,REMOTE_AGENTS.length-online));set('remoteTotalCount',REMOTE_AGENTS.length);
 const head='<div class="remote-agent-table-head"><span>Computer Name</span><span>User / IP</span><span>Status</span><span>Agent</span><span>Last Seen</span><span>Action</span></div>';
 const body=rows.length?rows.map(a=>{const on=a.status==='online';const supported=!!a.remote_supported;let action='';if(on&&supported)action=`<button class="primary remote-connect" type="button" onclick="startRemoteSession(${a.id})">Connect</button>`;else if(!supported)action=`<button class="secondary remote-connect" type="button" disabled title="Upgrade to Agent 2.2.0 or newer">Upgrade</button>`;else action=`<button class="secondary remote-connect" type="button" disabled>Offline</button>`;return `<div class="remote-agent-row"><div class="remote-agent-name">${esc(a.computer_name||a.hostname||('Agent '+a.id))}</div><div class="remote-agent-user">${esc(a.username||a.ip_address||'—')}</div><div class="remote-status"><span class="remote-dot ${on?'online':'offline'}"></span>${on?'Online':'Offline'}</div><div class="remote-agent-version">${esc(a.agent_version||'—')}</div><div class="remote-agent-seen">${esc(remoteAgo(a.last_heartbeat_at||a.last_seen_at))}</div><div class="remote-agent-action">${action}</div></div>`}).join(''):'<div class="remote-table-empty">No matching Windows Agents.</div>';
 root.innerHTML=head+body;
}
'''
main = main[:render_start] + new_render + main[render_end:]

# Remote Access originally called a page-local `api()` helper that only exists on
# another page. Use the self-contained helper above for every Remote Access call.
remote_block_start = main.index('let REMOTE_AGENTS=[];')
remote_block_end = main.index('</script></body></html>', remote_block_start)
block = main[remote_block_start:remote_block_end]
block = block.replace("await api(", "await remoteApi(")
main = main[:remote_block_start] + block + main[remote_block_end:]
main_path.write_text(main, encoding="utf-8", newline="\n")


# ---- Tests: retain v4.23 compatibility marker while validating 2.2.1 tray ----
test_path = Path("tests/test_remote_access_v4231.py")
test = test_path.read_text(encoding="utf-8")
test = test.replace("assert '<Version>2.2.0</Version>' in cs", "assert '<Version>2.2.1</Version>' in cs")
test = test.replace("assert 'MessageBox' in src and 'Allow screen viewing and mouse/keyboard control' in src", "assert 'TrayApp.ShowConsentDialog' in src")
if 'def test_windows_agent_tray_app_present()' not in test:
    test += '''\n\ndef test_windows_agent_tray_app_present():\n    tray=Path("windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs").read_text()\n    wix=Path("windows/agent-x64/installer/msi/Package.wxs").read_text()\n    assert "NotifyIcon" in tray and "Agent Status..." in tray\n    assert "GODSEYE Remote Access" in tray and "Allow" in tray and "Deny" in tray\n    assert "--tray" in wix and "CurrentVersion\\\\Run" in wix\n    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()\n    assert "EnsureTrayProcess" in src and "WriteTrayStatus" in src\n\n\ndef test_remote_access_has_self_contained_api_helper():\n    html=main.DASHBOARD\n    assert "async function remoteApi" in html\n    assert "await remoteApi('/api/v1/windows-agents')" in html\n    assert "Remote Access Features" in html\n'''
test_path.write_text(test, encoding="utf-8", newline="\n")

print("Applied v4.24 Remote Access + Windows tray UI patch")
