from pathlib import Path


def replace(path, old, new):
    p = Path(path)
    text = p.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'expected text not found in {path}')
    p.write_text(text.replace(old, new), encoding='utf-8', newline='\n')

svc = 'windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs'

replace(svc,
'''        [DllImport("Wtsapi32.dll", SetLastError=true)] static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);\n        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessAsUser''',
'''        [DllImport("Wtsapi32.dll", SetLastError=true)] static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);\n        [DllImport("Wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool WTSSendMessage(IntPtr hServer, int SessionId, string pTitle, int TitleLength, string pMessage, int MessageLength, int Style, int Timeout, out int pResponse, bool bWait);\n        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessAsUser''')

replace(svc,
'''            string pipeName = args[1]; string requestedBy = args[2];\n            if (!TrayApp.ShowConsentDialog(requestedBy)) return 2;''',
'''            string pipeName = args[1]; string requestedBy = args[2];\n            bool consentAlreadyGranted = args.Length > 3 && args[3].Equals("--consent-granted", StringComparison.OrdinalIgnoreCase);\n            if (!consentAlreadyGranted && !TrayApp.ShowConsentDialog(requestedBy)) return 2;''')

replace(svc,
'''        void LaunchRemoteHelper(string pipeName, string requestedBy)\n        {\n            uint sessionId=WTSGetActiveConsoleSessionId(); if(sessionId==INVALID_SESSION_ID)throw new Exception("No interactive Windows session is signed in.");\n            IntPtr token=IntPtr.Zero; if(!WTSQueryUserToken(sessionId,out token))throw new Exception("Could not obtain the signed-in Windows user token ("+Marshal.GetLastWin32Error()+").");''',
'''        bool RequestRemoteConsent(uint sessionId, string requestedBy)\n        {\n            string title = "GODSEYE Remote Access";\n            string who = String.IsNullOrWhiteSpace(requestedBy) ? "administrator" : requestedBy;\n            string message = "A GODSEYE administrator (" + who + ") is requesting to view and control this computer.\\r\\n\\r\\nSelect Yes to allow this remote session or No to deny it.";\n            int response;\n            bool sent = WTSSendMessage(IntPtr.Zero, unchecked((int)sessionId), title, title.Length * 2, message, message.Length * 2, unchecked((int)(MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST)), 60, out response, true);\n            if (!sent) throw new Exception("Could not display the GODSEYE approval prompt in the signed-in Windows session (" + Marshal.GetLastWin32Error() + ").");\n            Log("Remote support approval response from Windows session " + sessionId + ": " + response);\n            return response == IDYES;\n        }\n\n        void LaunchRemoteHelper(string pipeName, string requestedBy, uint sessionId)\n        {\n            IntPtr token=IntPtr.Zero; if(!WTSQueryUserToken(sessionId,out token))throw new Exception("Could not obtain the signed-in Windows user token ("+Marshal.GetLastWin32Error()+").");''')

replace(svc,
'''                var cmd=new System.Text.StringBuilder("\\\""+exe+"\\\" --remote-helper \\\""+pipeName+"\\\" \\\""+requestedBy+"\\\""); STARTUPINFO si=new STARTUPINFO();''',
'''                var cmd=new System.Text.StringBuilder("\\\""+exe+"\\\" --remote-helper \\\""+pipeName+"\\\" \\\""+requestedBy+"\\\" --consent-granted"); STARTUPINFO si=new STARTUPINFO();''')

replace(svc,
'''        void StartRemoteSession(AgentConfig cfg, long sessionId, string requestedBy)\n        {\n            StopRemoteSession(); remoteStop=false; remoteSessionId=sessionId; remotePipeName="GODSEYE-Remote-"+sessionId+"-"+Guid.NewGuid().ToString("N"); LaunchRemoteHelper(remotePipeName,requestedBy);\n            remoteWorker=new Thread(()=>RemoteSessionLoop(cfg,sessionId,remotePipeName)){IsBackground=true,Name="GODSEYE Remote Support"}; remoteWorker.Start();\n        }''',
'''        void StartRemoteSession(AgentConfig cfg, long sessionId, string requestedBy)\n        {\n            StopRemoteSession();\n            uint windowsSessionId = WTSGetActiveConsoleSessionId();\n            if (windowsSessionId == INVALID_SESSION_ID) throw new Exception("No interactive Windows session is signed in.");\n            Log("Remote support request " + sessionId + " targeting Windows session " + windowsSessionId + ".");\n            if (!RequestRemoteConsent(windowsSessionId, requestedBy))\n            {\n                try { Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/state",new Dictionary<string,object>{{"status","denied"},{"error","The signed-in Windows user denied remote access."}},ReadApiKey()); } catch {}\n                throw new Exception("The signed-in Windows user denied remote access.");\n            }\n            remoteStop=false; remoteSessionId=sessionId; remotePipeName="GODSEYE-Remote-"+sessionId+"-"+Guid.NewGuid().ToString("N");\n            LaunchRemoteHelper(remotePipeName,requestedBy,windowsSessionId);\n            remoteWorker=new Thread(()=>RemoteSessionLoop(cfg,sessionId,remotePipeName)){IsBackground=true,Name="GODSEYE Remote Support"}; remoteWorker.Start();\n        }''')

# Bump Agent 2.2.1 -> 2.2.2 in source/install/build/test metadata.
for path in [
    'windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj',
    'windows/agent-x64/installer/msi/Package.wxs',
    'windows/agent-x64/installer/GODSEYE-Agent-x64.iss',
    '.github/workflows/build-v424-release.yml',
    'tests/test_permanent_x64_windows_agent_v423.py',
]:
    p = Path(path)
    text = p.read_text(encoding='utf-8')
    if '2.2.1' not in text:
        raise SystemExit(f'2.2.1 marker not found in {path}')
    p.write_text(text.replace('2.2.1', '2.2.2'), encoding='utf-8', newline='\n')

print('Applied Windows Agent 2.2.2 reliable consent fix.')
