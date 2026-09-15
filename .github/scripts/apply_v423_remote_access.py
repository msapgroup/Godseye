from pathlib import Path
import re


def replace_once(path, old, new):
    p=Path(path); s=p.read_text(encoding='utf-8')
    if old not in s:
        raise SystemExit(f'marker not found in {path}: {old[:120]!r}')
    p.write_text(s.replace(old,new,1),encoding='utf-8')


def insert_before(path, marker, content):
    p=Path(path); s=p.read_text(encoding='utf-8')
    if marker not in s: raise SystemExit(f'marker not found in {path}: {marker[:120]!r}')
    p.write_text(s.replace(marker,content+marker,1),encoding='utf-8')

# ------------------------------------------------------------------
# App release version
# ------------------------------------------------------------------
Path('VERSION').write_text('4.23.1-remote-access\n',encoding='utf-8')

main='app/main.py'

# Remote session tables.
old='''        CREATE INDEX IF NOT EXISTS idx_windows_agent_commands_agent ON windows_agent_commands(agent_id,status,requested_at);\n        CREATE TABLE IF NOT EXISTS users ('''
new='''        CREATE INDEX IF NOT EXISTS idx_windows_agent_commands_agent ON windows_agent_commands(agent_id,status,requested_at);\n        CREATE TABLE IF NOT EXISTS windows_remote_sessions (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            agent_id INTEGER NOT NULL,\n            status TEXT NOT NULL DEFAULT 'connecting',\n            requested_by TEXT NOT NULL,\n            requested_at TEXT NOT NULL,\n            connected_at TEXT,\n            ended_at TEXT,\n            last_frame_at TEXT,\n            last_width INTEGER NOT NULL DEFAULT 0,\n            last_height INTEGER NOT NULL DEFAULT 0,\n            last_error TEXT DEFAULT ''\n        );\n        CREATE INDEX IF NOT EXISTS idx_windows_remote_sessions_agent ON windows_remote_sessions(agent_id,status,requested_at);\n        CREATE TABLE IF NOT EXISTS windows_remote_events (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            session_id INTEGER NOT NULL,\n            event_json TEXT NOT NULL,\n            created_at TEXT NOT NULL,\n            delivered_at TEXT\n        );\n        CREATE INDEX IF NOT EXISTS idx_windows_remote_events_session ON windows_remote_events(session_id,id);\n        CREATE TABLE IF NOT EXISTS users ('''
replace_once(main,old,new)

# Models used by browser/admin and agent remote APIs.
old='''class WindowsAgentEnrollmentRequest(BaseModel):\n    label: str = "Windows Agent"\n    expires_minutes: int = 30\n\n\ndef _agent_auth(request: Request):'''
new='''class WindowsAgentEnrollmentRequest(BaseModel):\n    label: str = "Windows Agent"\n    expires_minutes: int = 30\n\nclass WindowsRemoteStartRequest(BaseModel):\n    agent_id: int\n\nclass WindowsRemoteInputRequest(BaseModel):\n    kind: str\n    action: str = ""\n    x: float | None = None\n    y: float | None = None\n    button: str = "left"\n    vk: int = 0\n    delta: int = 0\n\nclass WindowsRemoteFrameRequest(BaseModel):\n    image_base64: str\n    width: int = 0\n    height: int = 0\n\nclass WindowsRemoteStateRequest(BaseModel):\n    status: str\n    error: str = ""\n\n\ndef _agent_auth(request: Request):'''
replace_once(main,old,new)

# Advertise remote support for updated agents.
old='''            d["upgrade_supported"]=_agent_version_tuple(installed_version) >= (2,1,0)\n            d["available_version"]=update_manifest["version"] if update_manifest else None'''
new='''            d["upgrade_supported"]=_agent_version_tuple(installed_version) >= (2,1,0)\n            d["remote_supported"]=_agent_version_tuple(installed_version) >= (2,2,0)\n            d["available_version"]=update_manifest["version"] if update_manifest else None'''
replace_once(main,old,new)

# Server/browser + agent remote-access API.
marker='''@app.put(f"{router_prefix}/windows-agents/{{agent_id}}")\ndef windows_agent_update'''
remote_api=r'''def _remote_frame_path(session_id: int):
    root=BASE_DIR / "data" / "remote-frames"
    root.mkdir(parents=True,exist_ok=True)
    return root / f"session-{int(session_id)}.jpg"


def _remote_session_public(row):
    if not row: return None
    d=dict(row)
    d["frame_url"]=f"{router_prefix}/remote-access/sessions/{d['id']}/frame"
    return d


@app.post(f"{router_prefix}/remote-access/sessions")
def windows_remote_start(req: WindowsRemoteStartRequest, request: Request, user=Depends(require_admin)):
    ts=now(); nowdt=dt.datetime.now(dt.timezone.utc)
    with db() as c:
        agent=c.execute("SELECT * FROM windows_agents WHERE id=?",(req.agent_id,)).fetchone()
        if not agent: raise HTTPException(404,"Windows Agent not found")
        if not agent["enabled"] or agent["revoked_at"]: raise HTTPException(409,"Windows Agent is disabled or revoked")
        if _agent_version_tuple(agent["agent_version"] or "") < (2,2,0):
            raise HTTPException(409,"Windows Agent 2.2.0 or newer is required for Remote Access. Upgrade this computer first.")
        if not agent["last_heartbeat_at"]: raise HTTPException(409,"Windows Agent is offline")
        try:
            hb=dt.datetime.fromisoformat(agent["last_heartbeat_at"]); hb=hb if hb.tzinfo else hb.replace(tzinfo=dt.timezone.utc)
            if (nowdt-hb).total_seconds()>180: raise HTTPException(409,"Windows Agent is offline")
        except HTTPException: raise
        except Exception: raise HTTPException(409,"Windows Agent heartbeat is invalid")
        existing=c.execute("SELECT * FROM windows_remote_sessions WHERE agent_id=? AND status IN ('connecting','active') ORDER BY id DESC LIMIT 1",(req.agent_id,)).fetchone()
        if existing: return {"ok":True,"session":_remote_session_public(existing),"message":"A remote support session is already open for this computer."}
        cur=c.execute("INSERT INTO windows_remote_sessions(agent_id,status,requested_by,requested_at) VALUES(?,'connecting',?,?)",(req.agent_id,user["username"],ts))
        sid=cur.lastrowid
        payload=json.dumps({"session_id":sid,"requested_by":user["username"]},separators=(",",":"))
        c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'remote_session_start',?,'pending',?,?)",(req.agent_id,payload,user["username"],ts))
        audit(c,user["username"],"windows_remote_session_requested",str(sid),json.dumps({"agent_id":req.agent_id,"computer_name":agent["computer_name"]}),client_ip(request))
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(sid,)).fetchone()
    return {"ok":True,"session":_remote_session_public(row),"message":"Remote support request sent. The signed-in Windows user must approve the connection."}


@app.get(f"{router_prefix}/remote-access/sessions/{{session_id}}")
def windows_remote_session(session_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT s.*,a.computer_name,a.hostname,a.ip_address,a.os_version,a.agent_version FROM windows_remote_sessions s JOIN windows_agents a ON a.id=s.agent_id WHERE s.id=?",(session_id,)).fetchone()
    if not row: raise HTTPException(404,"Remote support session not found")
    return _remote_session_public(row)


@app.post(f"{router_prefix}/remote-access/sessions/{{session_id}}/stop")
def windows_remote_stop(session_id: int, request: Request, user=Depends(require_admin)):
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] not in ("ended","failed"):
            c.execute("UPDATE windows_remote_sessions SET status='ended',ended_at=? WHERE id=?",(ts,session_id))
            c.execute("INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at) VALUES(?,'remote_session_stop',?,'pending',?,?)",(row["agent_id"],json.dumps({"session_id":session_id}),user["username"],ts))
            audit(c,user["username"],"windows_remote_session_stopped",str(session_id),"",client_ip(request))
    return {"ok":True}


@app.get(f"{router_prefix}/remote-access/sessions/{{session_id}}/frame")
def windows_remote_frame(session_id: int, user=Depends(get_current_user)):
    with db() as c:
        row=c.execute("SELECT id FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
    if not row: raise HTTPException(404,"Remote support session not found")
    path=_remote_frame_path(session_id)
    if not path.exists(): return Response(status_code=204,headers={"Cache-Control":"no-store"})
    return Response(content=path.read_bytes(),media_type="image/jpeg",headers={"Cache-Control":"no-store, max-age=0"})


@app.post(f"{router_prefix}/remote-access/sessions/{{session_id}}/input")
def windows_remote_input(session_id: int, req: WindowsRemoteInputRequest, request: Request, user=Depends(require_admin)):
    kind=(req.kind or "").lower(); action=(req.action or "").lower(); event={"kind":kind}
    if kind=="pointer":
        if action not in {"move","click","down","up"}: raise HTTPException(400,"Unsupported pointer action")
        if req.x is None or req.y is None: raise HTTPException(400,"Pointer coordinates are required")
        if req.button not in {"left","right","middle"}: raise HTTPException(400,"Unsupported pointer button")
        event.update({"action":action,"x":max(0.0,min(float(req.x),1.0)),"y":max(0.0,min(float(req.y),1.0)),"button":req.button})
    elif kind=="keyboard":
        if action not in {"down","up"} or not (8 <= int(req.vk) <= 255): raise HTTPException(400,"Unsupported keyboard event")
        event.update({"action":action,"vk":int(req.vk)})
    elif kind=="wheel":
        event.update({"delta":max(-1200,min(int(req.delta),1200))})
    else: raise HTTPException(400,"Unsupported remote input type")
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=?",(session_id,)).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] not in {"connecting","active"}: raise HTTPException(409,"Remote support session is not active")
        c.execute("INSERT INTO windows_remote_events(session_id,event_json,created_at) VALUES(?,?,?)",(session_id,json.dumps(event,separators=(",",":")),now()))
    return {"ok":True}


@app.post(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/frame")
def windows_remote_agent_frame(session_id: int, req: WindowsRemoteFrameRequest, agent=Depends(_agent_auth)):
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if row["status"] not in {"connecting","active"}: raise HTTPException(409,"Remote support session is closed")
        try: raw=base64.b64decode(req.image_base64,validate=True)
        except Exception: raise HTTPException(400,"Invalid remote frame encoding")
        if len(raw)<4 or len(raw)>5*1024*1024 or not raw.startswith(b"\xff\xd8"): raise HTTPException(400,"Invalid remote JPEG frame")
        path=_remote_frame_path(session_id); tmp=path.with_suffix('.tmp'); tmp.write_bytes(raw); tmp.replace(path)
        ts=now(); connected=row["connected_at"] or ts
        c.execute("UPDATE windows_remote_sessions SET status='active',connected_at=?,last_frame_at=?,last_width=?,last_height=?,last_error='' WHERE id=?",(connected,ts,max(0,min(req.width,10000)),max(0,min(req.height,10000)),session_id))
    return {"ok":True}


@app.get(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/events")
def windows_remote_agent_events(session_id: int, after: int=0, agent=Depends(_agent_auth)):
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        active=row["status"] in {"connecting","active"}
        events=c.execute("SELECT * FROM windows_remote_events WHERE session_id=? AND id>? ORDER BY id LIMIT 100",(session_id,max(0,int(after)))).fetchall() if active else []
        if events:
            ids=[r["id"] for r in events]; marks=','.join('?' for _ in ids)
            c.execute(f"UPDATE windows_remote_events SET delivered_at=? WHERE id IN ({marks})",[now()]+ids)
        out=[]
        for r in events:
            try: ev=json.loads(r["event_json"])
            except Exception: ev={}
            out.append({"event_id":r["id"],"event":ev})
    return {"ok":True,"active":active,"status":row["status"],"events":out}


@app.post(f"{router_prefix}/windows-agents/remote/sessions/{{session_id}}/state")
def windows_remote_agent_state(session_id: int, req: WindowsRemoteStateRequest, agent=Depends(_agent_auth)):
    status=(req.status or "").lower()
    if status not in {"active","failed","ended"}: raise HTTPException(400,"Invalid remote support state")
    ts=now()
    with db() as c:
        row=c.execute("SELECT * FROM windows_remote_sessions WHERE id=? AND agent_id=?",(session_id,agent["id"])).fetchone()
        if not row: raise HTTPException(404,"Remote support session not found")
        if status=="active": c.execute("UPDATE windows_remote_sessions SET status='active',connected_at=COALESCE(connected_at,?),last_error='' WHERE id=?",(ts,session_id))
        else: c.execute("UPDATE windows_remote_sessions SET status=?,ended_at=?,last_error=? WHERE id=?",(status,ts,req.error[:1000],session_id))
    return {"ok":True}


'''
insert_before(main,marker,remote_api)

# Sidebar entry.
old='''<button type="button" class="navitem" data-view="event-findings"><span class="navicon">⚠</span><span>Event Findings</span><span class="badge" id="eventFindingBadge">0</span></button>\n<button type="button" class="navitem" data-view="tickets">'''
new='''<button type="button" class="navitem" data-view="event-findings"><span class="navicon">⚠</span><span>Event Findings</span><span class="badge" id="eventFindingBadge">0</span></button>\n<button type="button" class="navitem admin-only" data-view="remote-access"><span class="navicon">▰</span><span>Remote Access</span></button>\n<button type="button" class="navitem" data-view="tickets">'''
replace_once(main,old,new)

# Remote Access page before System Health.
p=Path(main); s=p.read_text(encoding='utf-8')
view_marker='<div class="view" id="view-health" style="display:none">'
if view_marker not in s: raise SystemExit('view-health marker not found')
remote_view=r'''<div class="view" id="view-remote-access" style="display:none">
<div class="hero remote-hero"><div><h1>Remote Access</h1><div class="muted">Secure remote support for computers running GODSEYE Windows Agent 2.2.0 or newer. The signed-in Windows user must approve each session.</div></div><div class="remote-stats"><span><b id="remoteOnlineCount">0</b> Online</span><span><b id="remoteOfflineCount">0</b> Offline</span><span><b id="remoteTotalCount">0</b> Agents</span></div></div>
<div class="remote-layout">
<section class="panel remote-computers"><div class="table-head"><h2>Agent Computers</h2><button class="secondary" type="button" onclick="loadRemoteAccess()">↻ Refresh</button></div><div class="remote-filter"><input id="remoteSearch" class="input" placeholder="Search computers…" oninput="renderRemoteAgents()"></div><div id="remoteAgentList" class="remote-agent-list"><div class="empty">Loading Windows Agents…</div></div></section>
<section class="panel remote-session-panel">
<div class="remote-session-head"><div><h2 id="remoteSessionTitle">Remote Session</h2><div class="muted" id="remoteSessionStatus">Select an online computer to begin.</div></div><div class="actions"><button id="remoteScreenshotBtn" class="secondary" type="button" onclick="openRemoteScreenshot()" disabled>Take Screenshot</button><button id="remoteDisconnectBtn" class="danger" type="button" onclick="stopRemoteSession()" disabled>Disconnect</button></div></div>
<div id="remoteScreenWrap" class="remote-screen-wrap" tabindex="0"><div id="remoteEmpty" class="remote-screen-empty"><div class="remote-monitor-icon">▰</div><b>No active remote session</b><span>Select a computer and click Connect.</span></div><img id="remoteScreen" class="remote-screen" alt="Remote Windows desktop" draggable="false" style="display:none"></div>
<div id="remoteSessionMeta" class="remote-session-meta"><span>Computer: <b>—</b></span><span>User approval: <b>Required</b></span><span>Agent: <b>—</b></span><span>Status: <b>Idle</b></span></div>
</section></div></div>

'''
p.write_text(s.replace(view_marker,remote_view+view_marker,1),encoding='utf-8')

# CSS before the dashboard style closes.
p=Path(main); s=p.read_text(encoding='utf-8')
css=r'''
/* v4.23.1 — consent-aware Windows Agent Remote Access */
.remote-hero{align-items:center}.remote-stats{display:flex;gap:9px;flex-wrap:wrap}.remote-stats span{min-width:98px;padding:10px 13px;border:1px solid #dce6f0;border-radius:10px;background:#fff;color:#52677f;font-size:10px}.remote-stats b{font-size:18px;color:#1f344c;margin-right:5px}.remote-layout{display:grid;grid-template-columns:minmax(280px,38%) minmax(0,1fr);gap:14px}.remote-computers,.remote-session-panel{min-height:610px}.remote-filter{padding:0 14px 10px}.remote-agent-list{padding:0 8px 12px;display:grid;gap:5px}.remote-agent-row{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:10px;border:1px solid #e3eaf2;border-radius:9px;padding:9px 10px;background:#fff}.remote-agent-main{min-width:0}.remote-agent-name{font-weight:800;font-size:11px;color:#20364e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.remote-agent-sub{font-size:9px;color:#778ba1;margin-top:3px}.remote-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;background:#9ba9b7}.remote-dot.online{background:#27c76f}.remote-dot.offline{background:#e34b5e}.remote-session-head{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:0 0 12px}.remote-session-head h2{margin:0 0 3px}.remote-screen-wrap{height:500px;border-radius:9px;border:1px solid #cfdbe7;background:#06101b;display:grid;place-items:center;overflow:hidden;outline:none;position:relative}.remote-screen-wrap:focus{box-shadow:0 0 0 2px rgba(15,125,240,.35)}.remote-screen{width:100%;height:100%;object-fit:contain;user-select:none;cursor:default}.remote-screen-empty{display:flex;flex-direction:column;align-items:center;gap:7px;color:#9fb0c2;font-size:10px}.remote-screen-empty b{font-size:13px;color:#dfe9f4}.remote-monitor-icon{font-size:42px;color:#2388f2}.remote-session-meta{display:flex;gap:18px;flex-wrap:wrap;padding-top:11px;font-size:9px;color:#71869d}.remote-session-meta b{color:#263b53}.remote-connect{min-width:72px}.remote-waiting{color:#f0b94b!important}
html[data-theme="dark"] .remote-stats span,html[data-theme="dark"] .remote-agent-row{background:#101923!important;border-color:#2d4056!important;color:#d8e3ef!important}html[data-theme="dark"] .remote-stats b,html[data-theme="dark"] .remote-agent-name,html[data-theme="dark"] .remote-session-meta b{color:#fff!important}html[data-theme="dark"] .remote-agent-sub,html[data-theme="dark"] .remote-session-meta{color:#98abc0!important}html[data-theme="dark"] .remote-screen-wrap{border-color:#31465e!important;background:#02070d!important}
@media(max-width:1000px){.remote-layout{grid-template-columns:1fr}.remote-computers,.remote-session-panel{min-height:auto}.remote-screen-wrap{height:min(62vw,500px)}}
'''
pos=s.rfind('</style>')
if pos<0: raise SystemExit('style close marker not found')
s=s[:pos]+css+s[pos:]
p.write_text(s,encoding='utf-8')

# Remote-access browser client before the final dashboard script closes.
p=Path(main); s=p.read_text(encoding='utf-8')
js=r'''
let REMOTE_AGENTS=[];
let REMOTE_SESSION=null;
let REMOTE_POLL_TIMER=null;
let REMOTE_MOVE_AT=0;

async function loadRemoteAccess(){
 try{REMOTE_AGENTS=await api('/api/v1/windows-agents');renderRemoteAgents();}
 catch(e){const root=document.getElementById('remoteAgentList');if(root)root.innerHTML=`<div class="empty">${esc(e.message||e)}</div>`;}
}
function renderRemoteAgents(){
 const root=document.getElementById('remoteAgentList');if(!root)return;
 const q=(document.getElementById('remoteSearch')?.value||'').trim().toLowerCase();
 const rows=REMOTE_AGENTS.filter(a=>!q||String(a.computer_name||'').toLowerCase().includes(q)||String(a.hostname||'').toLowerCase().includes(q)||String(a.ip_address||'').toLowerCase().includes(q));
 const online=REMOTE_AGENTS.filter(a=>a.status==='online').length;
 const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v};set('remoteOnlineCount',online);set('remoteOfflineCount',Math.max(0,REMOTE_AGENTS.length-online));set('remoteTotalCount',REMOTE_AGENTS.length);
 root.innerHTML=rows.length?rows.map(a=>{const on=a.status==='online';const supported=!!a.remote_supported;let action='';if(on&&supported)action=`<button class="primary remote-connect" type="button" onclick="startRemoteSession(${a.id})">Connect</button>`;else if(!supported)action=`<button class="secondary remote-connect" type="button" disabled title="Upgrade to Agent 2.2.0 or newer">Upgrade Agent</button>`;else action=`<button class="secondary remote-connect" type="button" disabled>Offline</button>`;return `<div class="remote-agent-row"><div class="remote-agent-main"><div class="remote-agent-name"><span class="remote-dot ${on?'online':'offline'}"></span>${esc(a.computer_name||a.hostname||('Agent '+a.id))}</div><div class="remote-agent-sub">${esc(a.ip_address||'No IP')} · Agent ${esc(a.agent_version||'unknown')} · ${esc(a.os_version||'Windows')}</div></div>${action}</div>`}).join(''):`<div class="empty">No matching Windows Agents.</div>`;
}
async function startRemoteSession(agentId){
 try{
  const r=await api('/api/v1/remote-access/sessions',{method:'POST',body:JSON.stringify({agent_id:agentId})});REMOTE_SESSION=r.session;
  const a=REMOTE_AGENTS.find(x=>x.id===agentId)||{};document.getElementById('remoteSessionTitle').textContent='Remote Session — '+(a.computer_name||'Windows Agent');
  document.getElementById('remoteSessionStatus').textContent='Waiting for the signed-in Windows user to approve access…';document.getElementById('remoteSessionStatus').classList.add('remote-waiting');
  document.getElementById('remoteDisconnectBtn').disabled=false;document.getElementById('remoteScreenWrap').focus();pollRemoteSession();
 }catch(e){alert(e.message||e);}
}
async function pollRemoteSession(){
 if(!REMOTE_SESSION)return;clearTimeout(REMOTE_POLL_TIMER);
 try{
  const s=await api(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}`);REMOTE_SESSION=s;
  const status=document.getElementById('remoteSessionStatus');const img=document.getElementById('remoteScreen');const empty=document.getElementById('remoteEmpty');
  status.classList.toggle('remote-waiting',s.status==='connecting');
  if(s.status==='active'){
   status.textContent='Connected · interactive support session active';empty.style.display='none';img.style.display='block';img.src=`${s.frame_url}?t=${Date.now()}`;document.getElementById('remoteScreenshotBtn').disabled=false;
  }else if(s.status==='connecting'){status.textContent='Waiting for local user approval…';}
  else{status.textContent=(s.status==='failed'?'Connection failed: '+(s.last_error||'user declined or desktop unavailable'):'Session ended');img.style.display='none';empty.style.display='flex';document.getElementById('remoteDisconnectBtn').disabled=true;document.getElementById('remoteScreenshotBtn').disabled=true;REMOTE_SESSION=null;return;}
  const meta=document.getElementById('remoteSessionMeta');if(meta)meta.innerHTML=`<span>Computer: <b>${esc(s.computer_name||'—')}</b></span><span>User approval: <b>${s.connected_at?'Approved':'Pending'}</b></span><span>Agent: <b>${esc(s.agent_version||'—')}</b></span><span>Status: <b>${esc(s.status)}</b></span>`;
 }catch(e){}
 if(REMOTE_SESSION)REMOTE_POLL_TIMER=setTimeout(pollRemoteSession,650);
}
async function stopRemoteSession(){if(!REMOTE_SESSION)return;try{await api(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/stop`,{method:'POST',body:'{}'});}catch(e){}clearTimeout(REMOTE_POLL_TIMER);REMOTE_SESSION=null;const img=document.getElementById('remoteScreen');img.style.display='none';document.getElementById('remoteEmpty').style.display='flex';document.getElementById('remoteDisconnectBtn').disabled=true;document.getElementById('remoteScreenshotBtn').disabled=true;document.getElementById('remoteSessionStatus').textContent='Session ended';}
function openRemoteScreenshot(){if(REMOTE_SESSION)window.open(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/frame?t=${Date.now()}`,'_blank');}
async function sendRemoteInput(payload){if(!REMOTE_SESSION||REMOTE_SESSION.status!=='active')return;try{await api(`/api/v1/remote-access/sessions/${REMOTE_SESSION.id}/input`,{method:'POST',body:JSON.stringify(payload)});}catch(e){}}
function remotePointerPayload(ev,action){const img=document.getElementById('remoteScreen');if(!img||img.style.display==='none')return null;const r=img.getBoundingClientRect();if(!r.width||!r.height)return null;const b=ev.button===2?'right':ev.button===1?'middle':'left';return {kind:'pointer',action,x:Math.max(0,Math.min(1,(ev.clientX-r.left)/r.width)),y:Math.max(0,Math.min(1,(ev.clientY-r.top)/r.height)),button:b};}
(function(){
 const bind=()=>{const wrap=document.getElementById('remoteScreenWrap');const img=document.getElementById('remoteScreen');if(!wrap||!img||wrap.dataset.remoteBound)return;wrap.dataset.remoteBound='1';wrap.addEventListener('contextmenu',e=>e.preventDefault());img.addEventListener('mousemove',e=>{const n=Date.now();if(n-REMOTE_MOVE_AT<80)return;REMOTE_MOVE_AT=n;const p=remotePointerPayload(e,'move');if(p)sendRemoteInput(p)});img.addEventListener('mousedown',e=>{e.preventDefault();wrap.focus();const p=remotePointerPayload(e,'down');if(p)sendRemoteInput(p)});img.addEventListener('mouseup',e=>{e.preventDefault();const p=remotePointerPayload(e,'up');if(p)sendRemoteInput(p)});wrap.addEventListener('wheel',e=>{if(!REMOTE_SESSION)return;e.preventDefault();sendRemoteInput({kind:'wheel',delta:e.deltaY<0?120:-120})},{passive:false});wrap.addEventListener('keydown',e=>{if(!REMOTE_SESSION||REMOTE_SESSION.status!=='active')return;if([116,123].includes(e.keyCode))return;e.preventDefault();sendRemoteInput({kind:'keyboard',action:'down',vk:e.keyCode})});wrap.addEventListener('keyup',e=>{if(!REMOTE_SESSION||REMOTE_SESSION.status!=='active')return;e.preventDefault();sendRemoteInput({kind:'keyboard',action:'up',vk:e.keyCode})});};
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bind);else setTimeout(bind,0);
 document.addEventListener('click',e=>{const nav=e.target.closest&&e.target.closest('[data-view="remote-access"]');if(nav)setTimeout(loadRemoteAccess,0)});
})();
'''
pos=s.rfind('</script>')
if pos<0: raise SystemExit('script close marker not found')
s=s[:pos]+js+s[pos:]
p.write_text(s,encoding='utf-8')

# ------------------------------------------------------------------
# Windows Agent 2.2.0 interactive-session helper + broker
# ------------------------------------------------------------------
svc='windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs'
replace_once(svc,'using System.IO;\nusing System.Net;','using System.IO;\nusing System.IO.Pipes;\nusing System.Net;\nusing System.Drawing;\nusing System.Drawing.Imaging;\nusing System.Runtime.InteropServices;')
replace_once(svc,'?? "2.1.0";','?? "2.2.0";')
replace_once(svc,'DateTime nextScheduledCollectUtc = DateTime.MinValue;','''DateTime nextScheduledCollectUtc = DateTime.MinValue;\n        Thread remoteWorker;\n        volatile bool remoteStop;\n        long remoteSessionId;\n        string remotePipeName;\n        int remoteHelperProcessId;''')
replace_once(svc,'protected override void OnStop() { stopping = true; if (worker != null) worker.Join(10000); }','protected override void OnStop() { stopping = true; StopRemoteSession(); if (worker != null) worker.Join(10000); }')
replace_once(svc,'static void Main(string[] args)\n        {\n            if (args.Length > 0 && args[0].Equals("--configure", StringComparison.OrdinalIgnoreCase))','''static void Main(string[] args)\n        {\n            if (args.Length > 0 && args[0].Equals("--remote-helper", StringComparison.OrdinalIgnoreCase))\n            {\n                Environment.ExitCode = RemoteHelperMain(args);\n                return;\n            }\n            if (args.Length > 0 && args[0].Equals("--configure", StringComparison.OrdinalIgnoreCase))''')

agent_insert=r'''
        const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const uint MB_YESNO = 0x00000004;
        const uint MB_ICONINFORMATION = 0x00000040;
        const uint MB_TOPMOST = 0x00040000;
        const int IDYES = 6;
        const uint MOUSEEVENTF_LEFTDOWN = 0x0002, MOUSEEVENTF_LEFTUP = 0x0004, MOUSEEVENTF_RIGHTDOWN = 0x0008, MOUSEEVENTF_RIGHTUP = 0x0010, MOUSEEVENTF_MIDDLEDOWN = 0x0020, MOUSEEVENTF_MIDDLEUP = 0x0040, MOUSEEVENTF_WHEEL = 0x0800;
        const uint KEYEVENTF_KEYUP = 0x0002;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
        [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
        [DllImport("Wtsapi32.dll", SetLastError=true)] static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, System.Text.StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr hObject);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
        [DllImport("user32.dll")] static extern int GetSystemMetrics(int nIndex);
        [DllImport("user32.dll")] static extern bool SetCursorPos(int X, int Y);
        [DllImport("user32.dll")] static extern void mouse_event(uint dwFlags, uint dx, uint dy, int dwData, UIntPtr dwExtraInfo);
        [DllImport("user32.dll")] static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

        static int RemoteHelperMain(string[] args)
        {
            if (args.Length < 3) return 64;
            string pipeName = args[1]; string requestedBy = args[2];
            int consent = MessageBox(IntPtr.Zero, "GODSEYE administrator '" + requestedBy + "' is requesting a remote support session.\n\nAllow screen viewing and mouse/keyboard control until the session is disconnected?", "GODSEYE Remote Support", MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST);
            if (consent != IDYES) return 2;
            try
            {
                while (true)
                {
                    using (NamedPipeServerStream pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None))
                    {
                        pipe.WaitForConnection();
                        using (StreamReader reader = new StreamReader(pipe, Encoding.UTF8, false, 8192, true))
                        using (StreamWriter writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true })
                        {
                            string line = reader.ReadLine(); if (String.IsNullOrWhiteSpace(line)) continue;
                            Dictionary<string, object> request = Json.Deserialize<Dictionary<string, object>>(line);
                            string kind = request != null && request.ContainsKey("kind") ? Convert.ToString(request["kind"]) : "";
                            if (String.Equals(kind,"terminate",StringComparison.OrdinalIgnoreCase)) { writer.WriteLine(Json.Serialize(new Dictionary<string,object>{{"ok",true}})); return 0; }
                            Dictionary<string, object> response = HandleRemoteHelperRequest(request);
                            writer.WriteLine(Json.Serialize(response));
                        }
                    }
                }
            }
            catch { return 1; }
        }

        static Dictionary<string, object> HandleRemoteHelperRequest(Dictionary<string, object> request)
        {
            string kind = request != null && request.ContainsKey("kind") ? Convert.ToString(request["kind"]) : "";
            if (String.Equals(kind,"capture",StringComparison.OrdinalIgnoreCase))
            {
                int width=Math.Max(1,GetSystemMetrics(0)), height=Math.Max(1,GetSystemMetrics(1));
                using (Bitmap bmp=new Bitmap(width,height))
                using (Graphics g=Graphics.FromImage(bmp))
                using (MemoryStream ms=new MemoryStream())
                {
                    g.CopyFromScreen(0,0,0,0,new Size(width,height)); bmp.Save(ms,ImageFormat.Jpeg);
                    return new Dictionary<string,object>{{"ok",true},{"image_base64",Convert.ToBase64String(ms.ToArray())},{"width",width},{"height",height}};
                }
            }
            if (String.Equals(kind,"pointer",StringComparison.OrdinalIgnoreCase))
            {
                double nx=Convert.ToDouble(request["x"]), ny=Convert.ToDouble(request["y"]); int x=(int)(Math.Max(0,Math.Min(1,nx))*Math.Max(1,GetSystemMetrics(0)-1)), y=(int)(Math.Max(0,Math.Min(1,ny))*Math.Max(1,GetSystemMetrics(1)-1)); SetCursorPos(x,y);
                string action=Convert.ToString(request.ContainsKey("action")?request["action"]:"move"), button=Convert.ToString(request.ContainsKey("button")?request["button"]:"left");
                uint down=button=="right"?MOUSEEVENTF_RIGHTDOWN:button=="middle"?MOUSEEVENTF_MIDDLEDOWN:MOUSEEVENTF_LEFTDOWN; uint up=button=="right"?MOUSEEVENTF_RIGHTUP:button=="middle"?MOUSEEVENTF_MIDDLEUP:MOUSEEVENTF_LEFTUP;
                if(action=="down")mouse_event(down,0,0,0,UIntPtr.Zero); else if(action=="up")mouse_event(up,0,0,0,UIntPtr.Zero); else if(action=="click"){mouse_event(down,0,0,0,UIntPtr.Zero);mouse_event(up,0,0,0,UIntPtr.Zero);} return new Dictionary<string,object>{{"ok",true}};
            }
            if (String.Equals(kind,"keyboard",StringComparison.OrdinalIgnoreCase))
            {
                int vk=Convert.ToInt32(request["vk"]); if(vk<8||vk>255)throw new Exception("Invalid virtual key"); string action=Convert.ToString(request["action"]); keybd_event((byte)vk,0,action=="up"?KEYEVENTF_KEYUP:0,UIntPtr.Zero); return new Dictionary<string,object>{{"ok",true}};
            }
            if (String.Equals(kind,"wheel",StringComparison.OrdinalIgnoreCase)) { mouse_event(MOUSEEVENTF_WHEEL,0,0,Convert.ToInt32(request["delta"]),UIntPtr.Zero); return new Dictionary<string,object>{{"ok",true}}; }
            return new Dictionary<string,object>{{"ok",false},{"error","Unsupported remote helper request"}};
        }

        void LaunchRemoteHelper(string pipeName, string requestedBy)
        {
            uint sessionId=WTSGetActiveConsoleSessionId(); if(sessionId==INVALID_SESSION_ID)throw new Exception("No interactive Windows session is signed in.");
            IntPtr token=IntPtr.Zero; if(!WTSQueryUserToken(sessionId,out token))throw new Exception("Could not obtain the signed-in Windows user token ("+Marshal.GetLastWin32Error()+").");
            try
            {
                string exe=Environment.ProcessPath; if(String.IsNullOrWhiteSpace(exe))throw new Exception("Agent executable path is unavailable."); requestedBy=(requestedBy??"administrator").Replace("\"","'");
                var cmd=new System.Text.StringBuilder("\""+exe+"\" --remote-helper \""+pipeName+"\" \""+requestedBy+"\""); STARTUPINFO si=new STARTUPINFO();si.cb=Marshal.SizeOf(typeof(STARTUPINFO));si.lpDesktop=@"winsta0\default"; PROCESS_INFORMATION pi;
                if(!CreateProcessAsUser(token,exe,cmd,IntPtr.Zero,IntPtr.Zero,false,CREATE_UNICODE_ENVIRONMENT,IntPtr.Zero,Path.GetDirectoryName(exe),ref si,out pi))throw new Exception("Could not launch the interactive GODSEYE helper ("+Marshal.GetLastWin32Error()+").");
                remoteHelperProcessId=(int)pi.dwProcessId; CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
            }
            finally{if(token!=IntPtr.Zero)CloseHandle(token);}
        }

        Dictionary<string,object> RemoteHelperRequest(string pipeName, Dictionary<string,object> request, int timeout=3000)
        {
            using(NamedPipeClientStream pipe=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.None))
            { pipe.Connect(timeout); using(StreamReader reader=new StreamReader(pipe,Encoding.UTF8,false,8192,true)) using(StreamWriter writer=new StreamWriter(pipe,new UTF8Encoding(false),8192,true){AutoFlush=true}) { writer.WriteLine(Json.Serialize(request)); string line=reader.ReadLine(); if(String.IsNullOrWhiteSpace(line))throw new Exception("Remote helper returned no response."); return Json.Deserialize<Dictionary<string,object>>(line); } }
        }

        void StartRemoteSession(AgentConfig cfg, long sessionId, string requestedBy)
        {
            StopRemoteSession(); remoteStop=false; remoteSessionId=sessionId; remotePipeName="GODSEYE-Remote-"+sessionId+"-"+Guid.NewGuid().ToString("N"); LaunchRemoteHelper(remotePipeName,requestedBy);
            remoteWorker=new Thread(()=>RemoteSessionLoop(cfg,sessionId,remotePipeName)){IsBackground=true,Name="GODSEYE Remote Support"}; remoteWorker.Start();
        }

        void StopRemoteSession()
        {
            remoteStop=true;
            if(!String.IsNullOrWhiteSpace(remotePipeName)){try{RemoteHelperRequest(remotePipeName,new Dictionary<string,object>{{"kind","terminate"}},500);}catch{}}
            if(remoteHelperProcessId>0){try{Process p=Process.GetProcessById(remoteHelperProcessId);if(!p.HasExited)p.Kill();}catch{} remoteHelperProcessId=0;}
            if(remoteWorker!=null&&remoteWorker!=Thread.CurrentThread)try{remoteWorker.Join(3000);}catch{} remoteWorker=null; remoteSessionId=0;remotePipeName=null;
        }

        void RemoteSessionLoop(AgentConfig cfg,long sessionId,string pipeName)
        {
            long after=0; bool activeReported=false; DateTime consentDeadline=DateTime.UtcNow.AddSeconds(60);
            try
            {
                while(!remoteStop&&!stopping)
                {
                    Dictionary<string,object> frame=null;
                    try{frame=RemoteHelperRequest(pipeName,new Dictionary<string,object>{{"kind","capture"}},1500);}catch{if(DateTime.UtcNow>=consentDeadline)throw new Exception("The Windows user did not approve remote support or the interactive desktop is unavailable.");Thread.Sleep(700);continue;}
                    if(frame==null||!frame.ContainsKey("image_base64"))throw new Exception("Remote desktop capture failed.");
                    Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/frame",new Dictionary<string,object>{{"image_base64",frame["image_base64"]},{"width",frame["width"]},{"height",frame["height"]}},ReadApiKey());
                    if(!activeReported){Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/state",new Dictionary<string,object>{{"status","active"}},ReadApiKey());activeReported=true;}
                    Dictionary<string,object> poll=Get(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/events?after="+after,ReadApiKey());
                    if(poll.ContainsKey("active")&&!Convert.ToBoolean(poll["active"]))break;
                    object rawEvents;if(poll.TryGetValue("events",out rawEvents)&&rawEvents is IEnumerable list&&! (rawEvents is string))foreach(object o in list){Dictionary<string,object> e=o as Dictionary<string,object>;if(e==null)continue;after=Math.Max(after,Convert.ToInt64(e["event_id"]));Dictionary<string,object> ev=e["event"] as Dictionary<string,object>;if(ev!=null)try{RemoteHelperRequest(pipeName,ev,1500);}catch{}}
                    Thread.Sleep(450);
                }
                if(activeReported)try{Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/state",new Dictionary<string,object>{{"status","ended"}},ReadApiKey());}catch{}
            }
            catch(Exception ex){Log("Remote support session "+sessionId+" failed: "+ex.Message);try{Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/state",new Dictionary<string,object>{{"status","failed"},{"error",ex.Message}},ReadApiKey());}catch{}}
            finally{remoteStop=true;if(remoteSessionId==sessionId){try{if(remoteHelperProcessId>0){Process p=Process.GetProcessById(remoteHelperProcessId);if(!p.HasExited)p.Kill();}}catch{}remoteHelperProcessId=0;remoteSessionId=0;remotePipeName=null;}}
        }

'''
replace_once(svc,'        int IntValue(Dictionary<string, object> value, string key)\n',agent_insert+'        int IntValue(Dictionary<string, object> value, string key)\n')

# Add command handlers.
old='''                    else if (String.Equals(type, "upgrade_agent", StringComparison.OrdinalIgnoreCase))\n                    {\n                        Dictionary<string, object> payload = entry.ContainsKey("payload") ? entry["payload"] as Dictionary<string, object> : null;\n                        result["ok"] = true;\n                        result["events"] = 0;\n                        result["new_findings"] = 0;\n                        result["details"] = StageAndLaunchUpgrade(cfg, payload);\n                    }\n                    else'''
new='''                    else if (String.Equals(type, "upgrade_agent", StringComparison.OrdinalIgnoreCase))\n                    {\n                        Dictionary<string, object> payload = entry.ContainsKey("payload") ? entry["payload"] as Dictionary<string, object> : null;\n                        result["ok"] = true;\n                        result["events"] = 0;\n                        result["new_findings"] = 0;\n                        result["details"] = StageAndLaunchUpgrade(cfg, payload);\n                    }\n                    else if (String.Equals(type, "remote_session_start", StringComparison.OrdinalIgnoreCase))\n                    {\n                        Dictionary<string, object> payload = entry.ContainsKey("payload") ? entry["payload"] as Dictionary<string, object> : null;\n                        if(payload==null||!payload.ContainsKey("session_id"))throw new Exception("Remote support session payload is invalid.");\n                        StartRemoteSession(cfg,Convert.ToInt64(payload["session_id"]),payload.ContainsKey("requested_by")?Convert.ToString(payload["requested_by"]):"administrator");\n                        result["ok"]=true;result["events"]=0;result["new_findings"]=0;result["details"]="Remote support request displayed to the signed-in Windows user.";\n                    }\n                    else if (String.Equals(type, "remote_session_stop", StringComparison.OrdinalIgnoreCase))\n                    {\n                        StopRemoteSession(); result["ok"]=true;result["events"]=0;result["new_findings"]=0;result["details"]="Remote support session stopped.";\n                    }\n                    else'''
replace_once(svc,old,new)

# GET helper next to existing POST helper.
marker='''        Dictionary<string, object> Post(AgentConfig cfg, string path, object body, string bearer)\n        {'''
get_method=r'''        Dictionary<string, object> Get(AgentConfig cfg, string path, string bearer)
        {
            string url=cfg.ServerUrl+path; HttpWebRequest req=(HttpWebRequest)WebRequest.Create(url);req.Method="GET";req.Accept="application/json";req.Timeout=10000;req.ReadWriteTimeout=10000;req.UserAgent="GODSEYE-Windows-Agent/"+AgentVersion;if(!String.IsNullOrWhiteSpace(bearer))req.Headers[HttpRequestHeader.Authorization]="Bearer "+bearer;
            try{using(HttpWebResponse res=(HttpWebResponse)req.GetResponse())using(StreamReader sr=new StreamReader(res.GetResponseStream(),Encoding.UTF8)){string text=sr.ReadToEnd();return Json.Deserialize<Dictionary<string,object>>(text);}}
            catch(WebException ex){string detail=ex.Message;if(ex.Response!=null)try{using(StreamReader sr=new StreamReader(ex.Response.GetResponseStream()))detail=sr.ReadToEnd();}catch{}throw new Exception("GODSEYE API request failed: "+detail,ex);}
        }

'''
insert_before(svc,marker,get_method)

# Agent 2.2.0 metadata and drawing dependency.
csproj='windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj'
p=Path(csproj); s=p.read_text();s=s.replace('<Version>2.1.0</Version>','<Version>2.2.0</Version>').replace('<FileVersion>2.1.0.0</FileVersion>','<FileVersion>2.2.0.0</FileVersion>').replace('<AssemblyVersion>2.1.0.0</AssemblyVersion>','<AssemblyVersion>2.2.0.0</AssemblyVersion>')
s=s.replace('<PackageReference Include="System.Diagnostics.EventLog" Version="8.0.0" />','<PackageReference Include="System.Diagnostics.EventLog" Version="8.0.0" />\n    <PackageReference Include="System.Drawing.Common" Version="8.0.0" />')
p.write_text(s)

for path,oldv,newv in [
 ('windows/agent-x64/installer/GODSEYE-Agent-x64.iss','#define MyAppVersion "2.1.0"','#define MyAppVersion "2.2.0"'),
 ('windows/agent-x64/installer/msi/Package.wxs','Version="2.0.1"','Version="2.2.0"')]:
    p=Path(path);s=p.read_text();
    if oldv not in s: raise SystemExit(f'version marker missing in {path}')
    p.write_text(s.replace(oldv,newv,1))

# Release notes + tests.
Path('REMOTE_ACCESS_V4231_RELEASE_NOTES.md').write_text('''# GODSEYE v4.23.1 — Remote Access\n\n- Adds an administrator-only **Remote Access** workspace listing enrolled Windows Agents.\n- Windows Agent 2.2.0 launches a consent prompt in the signed-in user session before remote support begins.\n- Remote sessions stream JPEG desktop frames over the existing authenticated Agent API and accept only whitelisted pointer/keyboard events.\n- No remote shell, arbitrary process execution, registry command, or unrestricted file command is exposed by the Remote Access channel.\n- Session start/stop is written to the GODSEYE audit log.\n- Existing Agent enrollment and ProgramData state are preserved by MSI upgrades.\n''',encoding='utf-8')
Path('tests/test_remote_access_v4231.py').write_text('''from pathlib import Path\nimport app.main as main\n\n\ndef test_v4231_remote_access_release_marker():\n    assert Path("VERSION").read_text().strip()=="4.23.1-remote-access"\n\ndef test_remote_access_routes_and_ui_present():\n    src=Path("app/main.py").read_text()\n    html=main.DASHBOARD\n    assert "/remote-access/sessions" in src\n    assert "/windows-agents/remote/sessions/" in src\n    assert 'data-view="remote-access"' in html\n    assert "Remote Access" in html and "signed-in Windows user must approve" in html\n    assert "remote_session_start" in src and "remote_session_stop" in src\n\ndef test_remote_agent_is_consent_aware_and_not_a_shell():\n    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()\n    cs=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()\n    assert '<Version>2.2.0</Version>' in cs\n    assert 'MessageBox' in src and 'Allow screen viewing and mouse/keyboard control' in src\n    assert 'WTSQueryUserToken' in src and 'CreateProcessAsUser' in src\n    assert 'NamedPipeServerStream' in src and 'CopyFromScreen' in src\n    assert 'cmd.exe' not in src.lower()\n    assert 'powershell.exe' not in src.lower()\n    assert 'remote_session_start' in src\n''',encoding='utf-8')

print('v4.23.1 remote access patch applied')
