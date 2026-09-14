from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    text = p.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'expected text not found in {path}: {old[:80]!r}')
    p.write_text(text.replace(old, new, 1), encoding='utf-8', newline='\n')

svc = Path('windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs')
tray = Path('windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs')

# The tray process already lives in the signed-in interactive desktop. Reuse it
# as the persistent remote desktop host instead of spawning another helper after approval.
text = tray.read_text(encoding='utf-8')
text = text.replace('using System.Drawing;\n', 'using System.Drawing;\nusing System.IO;\nusing System.IO.Pipes;\nusing System.Text;\n')
text = text.replace('            readonly NotifyIcon notifyIcon;\n', '            readonly NotifyIcon notifyIcon;\n            readonly Thread remotePipeThread;\n            volatile bool remotePipeStop;\n')
needle = '                notifyIcon.BalloonTipText = "GODSEYE Windows Agent is running and connected for monitoring and approved remote support.";\n'
insert = needle + '''\n                remotePipeThread = new Thread(RemotePipeLoop)\n                {\n                    IsBackground = true,\n                    Name = "GODSEYE Tray Remote Host"\n                };\n                remotePipeThread.Start();\n'''
if needle not in text:
    raise SystemExit('tray constructor insertion point not found')
text = text.replace(needle, insert, 1)
needle = '            protected override void ExitThreadCore()\n            {\n                notifyIcon.Visible = false;\n'
insert = '''            void RemotePipeLoop()\n            {\n                string pipeName = "GODSEYE-Tray-" + Process.GetCurrentProcess().SessionId;\n                while (!remotePipeStop)\n                {\n                    try\n                    {\n                        using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None);\n                        pipe.WaitForConnection();\n                        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 8192, true);\n                        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true };\n                        string? line = reader.ReadLine();\n                        if (!String.IsNullOrWhiteSpace(line))\n                            writer.WriteLine(GodseyeAgentService.HandleTrayPipeLine(line));\n                    }\n                    catch\n                    {\n                        if (!remotePipeStop) Thread.Sleep(250);\n                    }\n                }\n            }\n\n            protected override void ExitThreadCore()\n            {\n                remotePipeStop = true;\n                notifyIcon.Visible = false;\n'''
if needle not in text:
    raise SystemExit('tray ExitThreadCore insertion point not found')
text = text.replace(needle, insert, 1)
tray.write_text(text, encoding='utf-8', newline='\n')

text = svc.read_text(encoding='utf-8')
text = text.replace('        static Dictionary<string, object> HandleRemoteHelperRequest(Dictionary<string, object> request)\n', '        internal static Dictionary<string, object> HandleRemoteHelperRequest(Dictionary<string, object> request)\n', 1)
needle = '        internal static Dictionary<string, object> HandleRemoteHelperRequest(Dictionary<string, object> request)\n'
helper = '''        internal static string HandleTrayPipeLine(string line)\n        {\n            try\n            {\n                Dictionary<string, object> request = Json.Deserialize<Dictionary<string, object>>(line);\n                Dictionary<string, object> response = HandleRemoteHelperRequest(request);\n                return Json.Serialize(response);\n            }\n            catch (Exception ex)\n            {\n                return Json.Serialize(new Dictionary<string, object>{{"ok", false}, {"error", ex.Message}});\n            }\n        }\n\n'''
if needle not in text:
    raise SystemExit('service handler insertion point not found')
text = text.replace(needle, helper + needle, 1)
old = '''            remoteStop=false; remoteSessionId=sessionId; remotePipeName="GODSEYE-Remote-"+sessionId+"-"+Guid.NewGuid().ToString("N");\n            try\n            {\n                LaunchRemoteHelper(remotePipeName,requestedBy,windowsSessionId);\n                WaitForRemoteHelperReady(remotePipeName);\n                Log("Remote support request "+sessionId+" approved; interactive helper is ready.");\n            }\n            catch(Exception ex)\n            {\n                try { Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/state",new Dictionary<string,object>{{"status","failed"},{"error",ex.Message}},ReadApiKey()); } catch {}\n                StopRemoteSession();\n                throw;\n            }\n            remoteWorker=new Thread(()=>RemoteSessionLoop(cfg,sessionId,remotePipeName)){IsBackground=true,Name="GODSEYE Remote Support"}; remoteWorker.Start();\n'''
new = '''            remoteStop=false; remoteSessionId=sessionId; remoteHelperProcessId=0;\n            remotePipeName="GODSEYE-Tray-"+windowsSessionId;\n            try\n            {\n                WaitForRemoteHelperReady(remotePipeName,15000);\n                Log("Remote support request "+sessionId+" approved; connected to persistent tray remote host in Windows session "+windowsSessionId+".");\n            }\n            catch(Exception ex)\n            {\n                try { Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/state",new Dictionary<string,object>{{"status","failed"},{"error","Approved, but the interactive tray remote host was unavailable: "+ex.Message}},ReadApiKey()); } catch {}\n                StopRemoteSession();\n                throw;\n            }\n            remoteWorker=new Thread(()=>RemoteSessionLoop(cfg,sessionId,remotePipeName)){IsBackground=true,Name="GODSEYE Remote Support"}; remoteWorker.Start();\n'''
if old not in text:
    raise SystemExit('StartRemoteSession helper-launch block not found')
text = text.replace(old, new, 1)
old = '            if(!String.IsNullOrWhiteSpace(remotePipeName)){try{RemoteHelperRequest(remotePipeName,new Dictionary<string,object>{{"kind","terminate"}},500);}catch{}}\n'
new = '            if(!String.IsNullOrWhiteSpace(remotePipeName) && remotePipeName.StartsWith("GODSEYE-Remote-", StringComparison.OrdinalIgnoreCase)){try{RemoteHelperRequest(remotePipeName,new Dictionary<string,object>{{"kind","terminate"}},500);}catch{}}\n'
if old not in text:
    raise SystemExit('StopRemoteSession pipe termination line not found')
text = text.replace(old, new, 1)
svc.write_text(text, encoding='utf-8', newline='\n')

# Bump all source/installer/test/release metadata to 2.2.4.
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
    t = p.read_text(encoding='utf-8')
    if '2.2.3' in t:
        t = t.replace('2.2.3', '2.2.4')
    elif path.endswith('.csproj') or path.endswith('Package.wxs') or path.endswith('.iss'):
        raise SystemExit(f'2.2.3 marker missing in {path}')
    p.write_text(t, encoding='utf-8', newline='\n')

# Strong regression checks for the new architecture.
test = Path('tests/test_remote_access_v4231.py')
t = test.read_text(encoding='utf-8')
extra = '''\n\ndef test_remote_access_reuses_persistent_interactive_tray_host():\n    svc=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()\n    tray=Path("windows/agent-x64/src/Godseye.WindowsAgent/TrayApp.cs").read_text()\n    assert 'GODSEYE-Tray-' in svc and 'GODSEYE-Tray-' in tray\n    assert 'HandleTrayPipeLine' in svc and 'RemotePipeLoop' in tray\n    assert 'persistent tray remote host' in svc\n    assert 'LaunchRemoteHelper(remotePipeName' not in svc\n'''
if 'test_remote_access_reuses_persistent_interactive_tray_host' not in t:
    test.write_text(t + extra, encoding='utf-8', newline='\n')

print('Applied Agent 2.2.4 persistent tray remote-host fix.')
