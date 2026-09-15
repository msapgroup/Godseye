from pathlib import Path

p=Path('windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs')
s=p.read_text(encoding='utf-8')

old='public class GodseyeAgentService : ServiceBase'
new='public partial class GodseyeAgentService : ServiceBase'
if old in s:
    s=s.replace(old,new,1)
elif new not in s:
    raise SystemExit('Could not locate GodseyeAgentService class declaration')

marker='''        static void Main(string[] args)\n        {\n'''
branch='''        static void Main(string[] args)\n        {\n            if (args.Length > 0 && args[0].Equals("--remote-helper-v2", StringComparison.OrdinalIgnoreCase))\n            {\n                Environment.ExitCode = RemoteHelperV2Main(args);\n                return;\n            }\n'''
if '--remote-helper-v2' not in s:
    if marker not in s: raise SystemExit('Could not locate Main()')
    s=s.replace(marker,branch,1)

oldcall='StartRemoteSession(cfg,Convert.ToInt64(payload["session_id"]),payload.ContainsKey("requested_by")?Convert.ToString(payload["requested_by"]):"administrator");'
newcall='StartRemoteSessionV2(cfg,Convert.ToInt64(payload["session_id"]),payload.ContainsKey("requested_by")?Convert.ToString(payload["requested_by"]):"administrator");'
if oldcall in s:
    s=s.replace(oldcall,newcall,1)
elif newcall not in s:
    raise SystemExit('Could not locate remote_session_start dispatch')

p.write_text(s,encoding='utf-8')
print('Applied GODSEYE Remote Support v2 loopback transport patch')
