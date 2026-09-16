using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Godseye.WindowsAgent
{
    public class AgentConfig
    {
        public string ServerUrl { get; set; }
        public string EnrollmentToken { get; set; }
        public string AgentUuid { get; set; }
        public bool SkipTlsVerify { get; set; }
        public int PollIntervalSeconds { get; set; }
        public List<string> Channels { get; set; }
    }

    public class AgentState
    {
        public Dictionary<string, long> Bookmarks { get; set; }
        public string LastError { get; set; }
        public AgentState() { Bookmarks = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase); }
    }

    public class PendingBatch
    {
        public List<Dictionary<string, object>> events { get; set; }
        public Dictionary<string, long> bookmarks { get; set; }
    }

    public sealed class JsonCompat
    {
        static readonly JsonSerializerOptions Options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = false
        };

        public string Serialize(object value) => JsonSerializer.Serialize(value, Options);

        public T Deserialize<T>(string json)
        {
            if (typeof(T) == typeof(Dictionary<string, object>))
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                object value = ConvertElement(doc.RootElement);
                return (T)value;
            }
            return JsonSerializer.Deserialize<T>(json, Options)!;
        }

        static object ConvertElement(JsonElement e)
        {
            switch (e.ValueKind)
            {
                case JsonValueKind.Object:
                    var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    foreach (var p in e.EnumerateObject()) dict[p.Name] = ConvertElement(p.Value);
                    return dict;
                case JsonValueKind.Array:
                    var list = new ArrayList();
                    foreach (var item in e.EnumerateArray()) list.Add(ConvertElement(item));
                    return list;
                case JsonValueKind.String: return e.GetString() ?? "";
                case JsonValueKind.Number:
                    if (e.TryGetInt64(out long l)) return l;
                    if (e.TryGetDouble(out double d)) return d;
                    return 0L;
                case JsonValueKind.True: return true;
                case JsonValueKind.False: return false;
                default: return null!;
            }
        }
    }

    public class GodseyeAgentService : ServiceBase
    {
        static readonly string AgentVersion = typeof(GodseyeAgentService).Assembly.GetName().Version?.ToString(3) ?? "2.2.1";
        static readonly JsonCompat Json = new JsonCompat();
        readonly string BaseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GODSEYE", "Agent");
        Thread worker;
        volatile bool stopping;
        DateTime nextScheduledCollectUtc = DateTime.MinValue;
        Thread remoteWorker;
        volatile bool remoteStop;
        long remoteSessionId;
        string remotePipeName;
        int remoteHelperProcessId;
        int trayHelperProcessId;

        string ConfigPath { get { return Path.Combine(BaseDir, "agent.json"); } }
        string StatePath { get { return Path.Combine(BaseDir, "state.json"); } }
        string KeyPath { get { return Path.Combine(BaseDir, "agent.key"); } }
        string PendingPath { get { return Path.Combine(BaseDir, "pending-events.json"); } }
        string LogPath { get { return Path.Combine(BaseDir, "agent.log"); } }

        public GodseyeAgentService()
        {
            ServiceName = "GODSEYEWindowsAgent";
            CanStop = true;
            CanShutdown = true;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            stopping = false;
            worker = new Thread(WorkerLoop);
            worker.IsBackground = true;
            worker.Name = "GODSEYE Windows Agent Worker";
            worker.Start();
        }

        protected override void OnStop() { stopping = true; StopRemoteSession(); if (worker != null) worker.Join(10000); }
        protected override void OnShutdown() { OnStop(); base.OnShutdown(); }

        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0].Equals("--tray", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = TrayApp.Run();
                return;
            }
            if (args.Length > 0 && args[0].Equals("--remote-helper", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = RemoteHelperMain(args);
                return;
            }
            if (args.Length > 0 && args[0].Equals("--configure", StringComparison.OrdinalIgnoreCase))
            {
                GodseyeAgentService svc = new GodseyeAgentService();
                svc.ConfigureFromArgs(args);
                return;
            }
            if (Environment.UserInteractive && args.Length > 0 && args[0].Equals("--console", StringComparison.OrdinalIgnoreCase))
            {
                GodseyeAgentService svc = new GodseyeAgentService();
                svc.stopping = false;
                svc.WorkerLoop();
                return;
            }
            ServiceBase.Run(new GodseyeAgentService());
        }

        void ConfigureFromArgs(string[] args)
        {
            bool reconnect = false;
            foreach (string arg in args)
                if (arg.Equals("--re-enroll", StringComparison.OrdinalIgnoreCase)) reconnect = true;
            if (!reconnect)
            {
                ConfigureFromArgsCore(args);
                return;
            }

            // The service writes its configuration at the end of each poll. Stop it
            // while changing identity so an in-flight poll cannot restore the old URL.
            using (ServiceController agent = new ServiceController("GODSEYEWindowsAgent"))
            {
                agent.Refresh();
                bool restart = agent.Status != ServiceControllerStatus.Stopped;
                try
                {
                    if (restart)
                    {
                        if (agent.Status == ServiceControllerStatus.StartPending)
                            agent.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                        agent.Refresh();
                        if (agent.Status == ServiceControllerStatus.StopPending)
                            agent.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        else if (agent.Status != ServiceControllerStatus.Stopped)
                        {
                            agent.Stop();
                            agent.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        }
                    }
                    ConfigureFromArgsCore(args);
                }
                finally
                {
                    if (restart)
                    {
                        agent.Refresh();
                        if (agent.Status == ServiceControllerStatus.Stopped)
                        {
                            agent.Start();
                            agent.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                        }
                    }
                }
            }
        }

        void ConfigureFromArgsCore(string[] args)
        {
            Directory.CreateDirectory(BaseDir);
            AgentConfig cfg;
            if (File.Exists(ConfigPath))
            {
                cfg = Json.Deserialize<AgentConfig>(File.ReadAllText(ConfigPath, Encoding.UTF8)) ?? new AgentConfig();
            }
            else
            {
                cfg = new AgentConfig
                {
                    AgentUuid = Guid.NewGuid().ToString(),
                    PollIntervalSeconds = 60,
                    Channels = new List<string>() { "System", "Application" },
                    SkipTlsVerify = false
                };
            }

            bool reEnroll = false;
            bool tokenSupplied = false;
            for (int i = 1; i < args.Length; i++)
            {
                string a = args[i];
                if (a.Equals("--server-url", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) cfg.ServerUrl = args[++i].TrimEnd('/');
                else if (a.Equals("--enrollment-token", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) { cfg.EnrollmentToken = args[++i]; tokenSupplied = true; }
                else if (a.Equals("--skip-tls-verify", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) cfg.SkipTlsVerify = Boolean.Parse(args[++i]);
                else if (a.Equals("--re-enroll", StringComparison.OrdinalIgnoreCase)) reEnroll = true;
            }

            if (String.IsNullOrWhiteSpace(cfg.ServerUrl)) throw new Exception("ServerUrl is required for first-time configuration.");
            if (reEnroll && (!tokenSupplied || String.IsNullOrWhiteSpace(cfg.EnrollmentToken))) throw new Exception("A new enrollment token is required to reconnect.");
            if (!File.Exists(KeyPath) && String.IsNullOrWhiteSpace(cfg.EnrollmentToken)) throw new Exception("EnrollmentToken is required for first-time enrollment.");
            if (String.IsNullOrWhiteSpace(cfg.AgentUuid)) cfg.AgentUuid = Guid.NewGuid().ToString();
            if (cfg.Channels == null || cfg.Channels.Count == 0) cfg.Channels = new List<string>() { "System", "Application" };
            if (cfg.PollIntervalSeconds < 30) cfg.PollIntervalSeconds = 60;
            if (reEnroll)
            {
                // Enroll before changing local files. A bad URL or token must leave the
                // previous connection usable, and an active UUID cannot enroll twice.
                cfg.AgentUuid = Guid.NewGuid().ToString();
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                if (cfg.SkipTlsVerify)
                    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                else
                    ServicePointManager.ServerCertificateValidationCallback = null;
                Enroll(cfg);
                Console.WriteLine("GODSEYE Windows Agent enrolled with " + cfg.ServerUrl);
                return;
            }
            SaveConfig(cfg);
            Console.WriteLine("GODSEYE Windows Agent configuration saved to " + ConfigPath);
        }

        void Log(string text)
        {
            try
            {
                Directory.CreateDirectory(BaseDir);
                File.AppendAllText(LogPath, DateTime.UtcNow.ToString("o") + " " + text + Environment.NewLine, Encoding.UTF8);
                FileInfo fi = new FileInfo(LogPath);
                if (fi.Exists && fi.Length > 2 * 1024 * 1024)
                {
                    string old = LogPath + ".1";
                    if (File.Exists(old)) File.Delete(old);
                    File.Move(LogPath, old);
                }
            }
            catch { }
        }

        void WorkerLoop()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            while (!stopping)
            {
                int wait = 60;
                try
                {
                    AgentConfig cfg = LoadConfig();
                    EnsureTrayProcess();
                    if (cfg.SkipTlsVerify)
                        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    else
                        ServicePointManager.ServerCertificateValidationCallback = null;

                    EnsureEnrolled(cfg);
                    Dictionary<string, object> hb = Heartbeat(cfg);
                    WriteTrayStatus(cfg);
                    ApplyServerConfig(cfg, hb);
                    ProcessCommands(cfg, hb);
                    ProcessRechecks(cfg, hb);
                    if (DateTime.UtcNow >= nextScheduledCollectUtc)
                    {
                        FlushOrCollect(cfg);
                        nextScheduledCollectUtc = DateTime.UtcNow.AddSeconds(Math.Max(30, Math.Min(cfg.PollIntervalSeconds, 3600)));
                    }
                    wait = 10;
                    SaveConfig(cfg);
                }
                catch (Exception ex)
                {
                    Log("ERROR " + ex.Message);
                    AgentState state = LoadState(); state.LastError = ex.Message; SaveState(state);
                    wait = 15;
                }
                for (int i = 0; i < wait && !stopping; i++) Thread.Sleep(1000);
            }
        }

        AgentConfig LoadConfig()
        {
            if (!File.Exists(ConfigPath)) throw new Exception("Agent configuration is missing: " + ConfigPath);
            AgentConfig cfg = Json.Deserialize<AgentConfig>(File.ReadAllText(ConfigPath, Encoding.UTF8));
            if (cfg == null || String.IsNullOrWhiteSpace(cfg.ServerUrl)) throw new Exception("ServerUrl is missing from agent configuration");
            cfg.ServerUrl = cfg.ServerUrl.TrimEnd('/');
            if (cfg.Channels == null || cfg.Channels.Count == 0) cfg.Channels = new List<string>() { "System", "Application" };
            if (cfg.PollIntervalSeconds < 30) cfg.PollIntervalSeconds = 60;
            return cfg;
        }

        void SaveConfig(AgentConfig cfg)
        {
            File.WriteAllText(ConfigPath, Json.Serialize(cfg), Encoding.UTF8);
        }

        AgentState LoadState()
        {
            try
            {
                if (File.Exists(StatePath))
                {
                    AgentState s = Json.Deserialize<AgentState>(File.ReadAllText(StatePath, Encoding.UTF8));
                    if (s != null) { if (s.Bookmarks == null) s.Bookmarks = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase); return s; }
                }
            }
            catch { }
            return new AgentState();
        }

        void SaveState(AgentState state) { File.WriteAllText(StatePath, Json.Serialize(state), Encoding.UTF8); }

        string MachineGuid()
        {
            try { using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography")) return Convert.ToString(k.GetValue("MachineGuid")); }
            catch { return ""; }
        }

        string OsVersion()
        {
            try { return Environment.OSVersion.VersionString; } catch { return "Windows"; }
        }

        string ReadApiKey()
        {
            if (!File.Exists(KeyPath)) return null;
            byte[] enc = File.ReadAllBytes(KeyPath);
            byte[] raw = ProtectedData.Unprotect(enc, null, DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(raw);
        }

        void StoreApiKey(string key)
        {
            byte[] raw = Encoding.UTF8.GetBytes(key);
            File.WriteAllBytes(KeyPath, ProtectedData.Protect(raw, null, DataProtectionScope.LocalMachine));
        }

        void EnsureEnrolled(AgentConfig cfg)
        {
            string key = ReadApiKey();
            if (!String.IsNullOrWhiteSpace(key)) return;
            Enroll(cfg);
        }

        void Enroll(AgentConfig cfg)
        {
            if (String.IsNullOrWhiteSpace(cfg.EnrollmentToken)) throw new Exception("Agent is not enrolled and no enrollment token is present");
            Dictionary<string, object> body = new Dictionary<string, object>();
            body["enrollment_token"] = cfg.EnrollmentToken;
            body["agent_uuid"] = cfg.AgentUuid;
            body["computer_name"] = Environment.MachineName;
            body["machine_guid"] = MachineGuid();
            body["hostname"] = Dns.GetHostName();
            body["os_version"] = OsVersion();
            body["architecture"] = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            body["agent_version"] = AgentVersion;
            Dictionary<string, object> result = Post(cfg, "/api/v1/windows-agents/enroll", body, null);
            if (!result.ContainsKey("api_key")) throw new Exception("Enrollment response did not contain an API key");
            StoreApiKey(Convert.ToString(result["api_key"]));
            cfg.EnrollmentToken = "";
            SaveConfig(cfg);
            Log("Enrolled agent with GODSEYE as agent ID " + Convert.ToString(result["agent_id"]));
        }

        Dictionary<string, object> Heartbeat(AgentConfig cfg)
        {
            AgentState state = LoadState();
            Dictionary<string, object> body = new Dictionary<string, object>();
            body["computer_name"] = Environment.MachineName;
            body["hostname"] = Dns.GetHostName();
            body["os_version"] = OsVersion();
            body["architecture"] = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            body["agent_version"] = AgentVersion;
            body["last_error"] = state.LastError ?? "";
            Dictionary<string, object> result = Post(cfg, "/api/v1/windows-agents/heartbeat", body, ReadApiKey());
            state.LastError = ""; SaveState(state);
            return result;
        }

        void ApplyServerConfig(AgentConfig cfg, Dictionary<string, object> hb)
        {
            object interval;
            if (hb.TryGetValue("poll_interval_seconds", out interval)) cfg.PollIntervalSeconds = Convert.ToInt32(interval);
            object channels;
            if (hb.TryGetValue("channels", out channels))
            {
                IEnumerable a = channels as IEnumerable;
                if (a != null && !(channels is string))
                {
                    List<string> updated = new List<string>();
                    foreach (object x in a) if (!String.IsNullOrWhiteSpace(Convert.ToString(x))) updated.Add(Convert.ToString(x));
                    if (updated.Count > 0) cfg.Channels = updated;
                }
            }
        }

        Dictionary<string, object> FlushOrCollect(AgentConfig cfg)
        {
            if (!File.Exists(PendingPath)) CreatePendingBatch(cfg);
            if (!File.Exists(PendingPath)) return new Dictionary<string, object>() { { "events", 0 }, { "new_findings", 0 } };
            PendingBatch batch = Json.Deserialize<PendingBatch>(File.ReadAllText(PendingPath, Encoding.UTF8));
            if (batch == null || batch.events == null || batch.events.Count == 0)
            {
                if (File.Exists(PendingPath)) File.Delete(PendingPath);
                return new Dictionary<string, object>() { { "events", 0 }, { "new_findings", 0 } };
            }
            Dictionary<string, object> body = new Dictionary<string, object>(); body["events"] = batch.events;
            Dictionary<string, object> response = Post(cfg, "/api/v1/windows-agents/events", body, ReadApiKey());
            AgentState state = LoadState();
            if (batch.bookmarks != null) foreach (KeyValuePair<string, long> kv in batch.bookmarks) state.Bookmarks[kv.Key] = kv.Value;
            state.LastError = ""; SaveState(state);
            File.Delete(PendingPath);
            Log("Uploaded " + batch.events.Count + " Windows event(s)");
            return response ?? new Dictionary<string, object>() { { "events", batch.events.Count }, { "new_findings", 0 } };
        }

        void CreatePendingBatch(AgentConfig cfg)
        {
            AgentState state = LoadState();
            PendingBatch batch = new PendingBatch(); batch.events = new List<Dictionary<string, object>>(); batch.bookmarks = new Dictionary<string, long>(state.Bookmarks, StringComparer.OrdinalIgnoreCase);
            foreach (string channel in cfg.Channels)
            {
                if (batch.events.Count >= 500) break;
                long bookmark = state.Bookmarks.ContainsKey(channel) ? state.Bookmarks[channel] : 0;
                bookmark = NormalizeBookmarkAfterLogClear(channel, bookmark);
                batch.bookmarks[channel] = bookmark;
                string query;
                if (bookmark > 0)
                    query = "*[System[(Level=1 or Level=2 or Level=3) and EventRecordID > " + bookmark + "]]";
                else
                    query = "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
                try
                {
                    EventLogQuery q = new EventLogQuery(channel, PathType.LogName, query); q.ReverseDirection = false;
                    using (EventLogReader reader = new EventLogReader(q))
                    {
                        EventRecord ev; int perChannel = 0;
                        while ((ev = reader.ReadEvent()) != null && perChannel < 250 && batch.events.Count < 500)
                        {
                            using (ev)
                            {
                                Dictionary<string, object> item = EventToDictionary(ev, channel);
                                batch.events.Add(item); perChannel++;
                                long rid = ev.RecordId.HasValue ? ev.RecordId.Value : 0;
                                if (rid > 0 && (!batch.bookmarks.ContainsKey(channel) || rid > batch.bookmarks[channel])) batch.bookmarks[channel] = rid;
                            }
                        }
                    }
                }
                catch (Exception ex) { Log("Channel " + channel + " read error: " + ex.Message); }
            }
            if (batch.events.Count > 0) File.WriteAllText(PendingPath, Json.Serialize(batch), Encoding.UTF8);
        }

        long NormalizeBookmarkAfterLogClear(string channel, long bookmark)
        {
            if (bookmark <= 0) return bookmark;
            try
            {
                EventLogQuery newestQuery = new EventLogQuery(channel, PathType.LogName, "*"); newestQuery.ReverseDirection = true;
                using (EventLogReader reader = new EventLogReader(newestQuery))
                using (EventRecord newest = reader.ReadEvent())
                {
                    if (newest != null && newest.RecordId.HasValue && newest.RecordId.Value < bookmark)
                    {
                        Log("Event Log " + channel + " appears to have been cleared/rolled over; resetting bookmark.");
                        return 0;
                    }
                }
            }
            catch { }
            return bookmark;
        }

        Dictionary<string, object> EventToDictionary(EventRecord ev, string channel)
        {
            Dictionary<string, object> item = new Dictionary<string, object>();
            item["computer_name"] = String.IsNullOrWhiteSpace(ev.MachineName) ? Environment.MachineName : ev.MachineName;
            item["channel"] = String.IsNullOrWhiteSpace(ev.LogName) ? channel : ev.LogName;
            item["provider"] = ev.ProviderName ?? "Windows";
            item["event_id"] = ev.Id;
            item["level"] = ev.LevelDisplayName ?? "Error";
            item["record_id"] = ev.RecordId.HasValue ? ev.RecordId.Value : 0;
            item["event_time"] = ev.TimeCreated.HasValue ? ev.TimeCreated.Value.ToUniversalTime().ToString("o") : DateTime.UtcNow.ToString("o");
            try { item["message"] = ev.FormatDescription() ?? ""; } catch { item["message"] = "Event message formatting unavailable on this host."; }
            return item;
        }


        void WriteTrayStatus(AgentConfig cfg)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\MSAPGROUP\GODSEYE Agent\Status", true))
                {
                    if (key == null) return;
                    key.SetValue("ServerUrl", cfg.ServerUrl ?? "", RegistryValueKind.String);
                    key.SetValue("Version", AgentVersion, RegistryValueKind.String);
                    key.SetValue("LastCheckIn", DateTime.Now.ToString("g"), RegistryValueKind.String);
                    key.SetValue("RemoteAccess", "Enabled (User Approval)", RegistryValueKind.String);
                }
            }
            catch (Exception ex) { Log("Could not publish tray status: " + ex.Message); }
        }

        void EnsureTrayProcess()
        {
            try
            {
                if (trayHelperProcessId > 0)
                {
                    try { using (Process p = Process.GetProcessById(trayHelperProcessId)) { if (!p.HasExited) return; } }
                    catch { }
                    trayHelperProcessId = 0;
                }
                uint sessionId = WTSGetActiveConsoleSessionId();
                if (sessionId == INVALID_SESSION_ID) return;
                IntPtr token = IntPtr.Zero;
                if (!WTSQueryUserToken(sessionId, out token) || token == IntPtr.Zero) return;
                try
                {
                    string exe = Process.GetCurrentProcess().MainModule?.FileName ?? Environment.ProcessPath ?? "";
                    if (String.IsNullOrWhiteSpace(exe)) return;
                    STARTUPINFO si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                    si.lpDesktop = @"winsta0\default";
                    PROCESS_INFORMATION pi;
                    var cmd = new StringBuilder("\"" + exe + "\" --tray");
                    if (CreateProcessAsUser(token, exe, cmd, IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero, Path.GetDirectoryName(exe), ref si, out pi))
                    {
                        trayHelperProcessId = unchecked((int)pi.dwProcessId);
                        if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                        if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                    }
                    else Log("Could not start tray helper (Windows error " + Marshal.GetLastWin32Error() + ").");
                }
                finally { CloseHandle(token); }
            }
            catch (Exception ex) { Log("Could not start tray helper: " + ex.Message); }
        }

        const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const uint LOGON_WITH_PROFILE = 0x00000001;
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
        [DllImport("Wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool WTSSendMessage(IntPtr hServer, int SessionId, string pTitle, int TitleLength, string pMessage, int MessageLength, int Style, int Timeout, out int pResponse, bool bWait);
        [DllImport("userenv.dll", SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
        [DllImport("userenv.dll", SetLastError=true)] static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, System.Text.StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, System.Text.StringBuilder lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
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
            bool consentAlreadyGranted = args.Length > 3 && args[3].Equals("--consent-granted", StringComparison.OrdinalIgnoreCase);
            if (!consentAlreadyGranted && !TrayApp.ShowConsentDialog(requestedBy)) return 2;
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

        internal static string HandleTrayPipeLine(string line)
        {
            try
            {
                Dictionary<string, object> request = Json.Deserialize<Dictionary<string, object>>(line);
                Dictionary<string, object> response = HandleRemoteHelperRequest(request);
                return Json.Serialize(response);
            }
            catch (Exception ex)
            {
                return Json.Serialize(new Dictionary<string, object>{{"ok", false}, {"error", ex.Message}});
            }
        }

        internal static Dictionary<string, object> HandleRemoteHelperRequest(Dictionary<string, object> request)
        {
            string kind = request != null && request.ContainsKey("kind") ? Convert.ToString(request["kind"]) : "";
            if (String.Equals(kind,"ping",StringComparison.OrdinalIgnoreCase)) return new Dictionary<string,object>{{"ok",true},{"ready",true}};
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

        bool RequestRemoteConsent(uint sessionId, string requestedBy)
        {
            string title = "GODSEYE Remote Access";
            string who = String.IsNullOrWhiteSpace(requestedBy) ? "administrator" : requestedBy;
            string message = "A GODSEYE administrator (" + who + ") is requesting to view and control this computer.\r\n\r\nSelect Yes to allow this remote session or No to deny it.";
            int response;
            bool sent = WTSSendMessage(IntPtr.Zero, unchecked((int)sessionId), title, title.Length * 2, message, message.Length * 2, unchecked((int)(MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST)), 60, out response, true);
            if (!sent) throw new Exception("Could not display the GODSEYE approval prompt in the signed-in Windows session (" + Marshal.GetLastWin32Error() + ").");
            Log("Remote support approval response from Windows session " + sessionId + ": " + response);
            return response == IDYES;
        }

        void LaunchRemoteHelper(string pipeName, string requestedBy, uint sessionId)
        {
            IntPtr token=IntPtr.Zero;
            if(!WTSQueryUserToken(sessionId,out token)) throw new Exception("Could not obtain the signed-in Windows user token ("+Marshal.GetLastWin32Error()+").");
            IntPtr environment=IntPtr.Zero;
            try
            {
                string exe=Environment.ProcessPath;
                if(String.IsNullOrWhiteSpace(exe)) throw new Exception("Agent executable path is unavailable.");
                requestedBy=(requestedBy??"administrator").Replace("\"","'");
                if(!CreateEnvironmentBlock(out environment,token,false))
                {
                    Log("Remote helper environment block could not be created ("+Marshal.GetLastWin32Error()+"); continuing with the Windows token environment.");
                    environment=IntPtr.Zero;
                }
                STARTUPINFO si=new STARTUPINFO();
                si.cb=Marshal.SizeOf(typeof(STARTUPINFO));
                si.lpDesktop=@"winsta0\default";
                PROCESS_INFORMATION pi;
                var cmd=new System.Text.StringBuilder("\""+exe+"\" --remote-helper \""+pipeName+"\" \""+requestedBy+"\" --consent-granted");
                bool created=CreateProcessAsUser(token,exe,cmd,IntPtr.Zero,IntPtr.Zero,false,CREATE_UNICODE_ENVIRONMENT,environment,Path.GetDirectoryName(exe),ref si,out pi);
                int createAsUserError=created?0:Marshal.GetLastWin32Error();
                if(!created)
                {
                    cmd=new System.Text.StringBuilder("\""+exe+"\" --remote-helper \""+pipeName+"\" \""+requestedBy+"\" --consent-granted");
                    created=CreateProcessWithTokenW(token,LOGON_WITH_PROFILE,exe,cmd,CREATE_UNICODE_ENVIRONMENT,environment,Path.GetDirectoryName(exe),ref si,out pi);
                }
                if(!created) throw new Exception("Could not launch the interactive GODSEYE helper. CreateProcessAsUser="+createAsUserError+", CreateProcessWithTokenW="+Marshal.GetLastWin32Error()+".");
                remoteHelperProcessId=(int)pi.dwProcessId;
                if(pi.hThread!=IntPtr.Zero)CloseHandle(pi.hThread);
                if(pi.hProcess!=IntPtr.Zero)CloseHandle(pi.hProcess);
                Log("Remote helper launched in Windows session "+sessionId+" as process "+remoteHelperProcessId+".");
            }
            finally
            {
                if(environment!=IntPtr.Zero)DestroyEnvironmentBlock(environment);
                if(token!=IntPtr.Zero)CloseHandle(token);
            }
        }

        Dictionary<string,object> RemoteHelperRequest(string pipeName, Dictionary<string,object> request, int timeout=3000)
        {
            using(NamedPipeClientStream pipe=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.None))
            { pipe.Connect(timeout); using(StreamReader reader=new StreamReader(pipe,Encoding.UTF8,false,8192,true)) using(StreamWriter writer=new StreamWriter(pipe,new UTF8Encoding(false),8192,true){AutoFlush=true}) { writer.WriteLine(Json.Serialize(request)); string line=reader.ReadLine(); if(String.IsNullOrWhiteSpace(line))throw new Exception("Remote helper returned no response."); return Json.Deserialize<Dictionary<string,object>>(line); } }
        }

        void WaitForRemoteHelperReady(string pipeName, int timeoutMs=15000)
        {
            DateTime deadline=DateTime.UtcNow.AddMilliseconds(timeoutMs);
            Exception last=null;
            while(DateTime.UtcNow<deadline)
            {
                if(remoteHelperProcessId>0)
                {
                    try
                    {
                        using(Process p=Process.GetProcessById(remoteHelperProcessId))
                        {
                            if(p.HasExited) throw new Exception("Interactive GODSEYE helper exited during startup with code "+p.ExitCode+".");
                        }
                    }
                    catch(ArgumentException){throw new Exception("Interactive GODSEYE helper exited before it became ready.");}
                }
                try
                {
                    Dictionary<string,object> pong=RemoteHelperRequest(pipeName,new Dictionary<string,object>{{"kind","ping"}},750);
                    if(pong!=null&&pong.ContainsKey("ok")&&Convert.ToBoolean(pong["ok"]))
                    {
                        Log("Remote helper readiness handshake completed.");
                        return;
                    }
                }
                catch(Exception ex){last=ex;}
                Thread.Sleep(250);
            }
            throw new Exception("Interactive GODSEYE helper did not become ready within "+timeoutMs+" ms"+(last==null?".":": "+last.Message));
        }

        void StartRemoteSession(AgentConfig cfg, long sessionId, string requestedBy)
        {
            StopRemoteSession();
            uint windowsSessionId = WTSGetActiveConsoleSessionId();
            if (windowsSessionId == INVALID_SESSION_ID) throw new Exception("No interactive Windows session is signed in.");
            Log("Remote support request " + sessionId + " targeting Windows session " + windowsSessionId + ".");
            if (!RequestRemoteConsent(windowsSessionId, requestedBy))
            {
                try { Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/state",new Dictionary<string,object>{{"status","denied"},{"error","The signed-in Windows user denied remote access."}},ReadApiKey()); } catch {}
                throw new Exception("The signed-in Windows user denied remote access.");
            }
            remoteStop=false; remoteSessionId=sessionId; remoteHelperProcessId=0;
            remotePipeName="GODSEYE-Tray-"+windowsSessionId;
            try
            {
                WaitForRemoteHelperReady(remotePipeName,15000);
                Log("Remote support request "+sessionId+" approved; connected to persistent tray remote host in Windows session "+windowsSessionId+".");
            }
            catch(Exception ex)
            {
                try { Post(cfg,"/api/v1/windows-agents/remote/sessions/"+sessionId+"/state",new Dictionary<string,object>{{"status","failed"},{"error","Approved, but the interactive tray remote host was unavailable: "+ex.Message}},ReadApiKey()); } catch {}
                StopRemoteSession();
                throw;
            }
            remoteWorker=new Thread(()=>RemoteSessionLoop(cfg,sessionId,remotePipeName)){IsBackground=true,Name="GODSEYE Remote Support"}; remoteWorker.Start();
        }

        void StopRemoteSession()
        {
            remoteStop=true;
            if(!String.IsNullOrWhiteSpace(remotePipeName) && remotePipeName.StartsWith("GODSEYE-Remote-", StringComparison.OrdinalIgnoreCase)){try{RemoteHelperRequest(remotePipeName,new Dictionary<string,object>{{"kind","terminate"}},500);}catch{}}
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

        int IntValue(Dictionary<string, object> value, string key)
        {
            object raw;
            if (value != null && value.TryGetValue(key, out raw))
            {
                try { return Convert.ToInt32(raw); } catch { }
            }
            return 0;
        }

        Dictionary<string, object> PullEventsNow(AgentConfig cfg)
        {
            // First flush any durable batch left from an earlier outage, then collect again
            // from the newly committed bookmarks so "Pull Now" truly reaches current events.
            Dictionary<string, object> first = FlushOrCollect(cfg);
            Dictionary<string, object> second = FlushOrCollect(cfg);
            int events = IntValue(first, "events") + IntValue(second, "events");
            int findings = IntValue(first, "new_findings") + IntValue(second, "new_findings");
            nextScheduledCollectUtc = DateTime.UtcNow.AddSeconds(Math.Max(30, Math.Min(cfg.PollIntervalSeconds, 3600)));
            return new Dictionary<string, object>() { { "events", events }, { "new_findings", findings } };
        }

        string Sha256File(string path)
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

        void ProcessCommands(AgentConfig cfg, Dictionary<string, object> hb)
        {
            object value; if (!hb.TryGetValue("commands", out value)) return;
            IEnumerable list = value as IEnumerable; if (list == null || value is string) return;
            foreach (object entryObj in list)
            {
                Dictionary<string, object> entry = entryObj as Dictionary<string, object>; if (entry == null) continue;
                long commandId = Convert.ToInt64(entry["command_id"]);
                string type = Convert.ToString(entry["type"] ?? "");
                Dictionary<string, object> result = new Dictionary<string, object>();
                try
                {
                    if (String.Equals(type, "pull_events", StringComparison.OrdinalIgnoreCase))
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
                    else if (String.Equals(type, "remote_session_start", StringComparison.OrdinalIgnoreCase))
                    {
                        Dictionary<string, object> payload = entry.ContainsKey("payload") ? entry["payload"] as Dictionary<string, object> : null;
                        if(payload==null||!payload.ContainsKey("session_id"))throw new Exception("Remote support session payload is invalid.");
                        StartRemoteSession(cfg,Convert.ToInt64(payload["session_id"]),payload.ContainsKey("requested_by")?Convert.ToString(payload["requested_by"]):"administrator");
                        result["ok"]=true;result["events"]=0;result["new_findings"]=0;result["details"]="Remote support request displayed to the signed-in Windows user.";
                    }
                    else if (String.Equals(type, "remote_session_stop", StringComparison.OrdinalIgnoreCase))
                    {
                        StopRemoteSession(); result["ok"]=true;result["events"]=0;result["new_findings"]=0;result["details"]="Remote support session stopped.";
                    }
                    else
                    {
                        result["ok"] = false; result["events"] = 0; result["new_findings"] = 0;
                        result["details"] = "Unsupported GODSEYE agent command: " + type;
                    }
                }
                catch (Exception ex)
                {
                    result["ok"] = false; result["events"] = 0; result["new_findings"] = 0;
                    result["details"] = "GODSEYE agent command failed: " + ex.Message;
                    Log("Command " + commandId + " failed: " + ex.Message);
                }
                result["completed_at"] = DateTime.UtcNow.ToString("o");
                try { Post(cfg, "/api/v1/windows-agents/commands/" + commandId + "/result", result, ReadApiKey()); }
                catch (Exception ex) { Log("Could not report command " + commandId + " result: " + ex.Message); }
            }
        }

        void ProcessRechecks(AgentConfig cfg, Dictionary<string, object> hb)
        {
            object value; if (!hb.TryGetValue("rechecks", out value)) return;
            IEnumerable list = value as IEnumerable; if (list == null || value is string) return;
            foreach (object entryObj in list)
            {
                Dictionary<string, object> entry = entryObj as Dictionary<string, object>; if (entry == null) continue;
                long recheckId = Convert.ToInt64(entry["recheck_id"]);
                Dictionary<string, object> finding = entry["finding"] as Dictionary<string, object>; if (finding == null) continue;
                string channel = Convert.ToString(finding["channel"]); int eventId = Convert.ToInt32(finding["event_id"]); long oldRecord = Convert.ToInt64(finding["record_id"] ?? 0);
                string provider = Convert.ToString(finding["provider"] ?? "");
                bool seenAgain = false; string details = "No newer matching provider/Event ID was found.";
                try
                {
                    string query = "*[System[(EventID=" + eventId + ") and EventRecordID > " + oldRecord + "]]";
                    EventLogQuery q = new EventLogQuery(channel, PathType.LogName, query); q.ReverseDirection = true;
                    using (EventLogReader reader = new EventLogReader(q))
                    {
                        EventRecord ev; int checkedCount = 0;
                        while ((ev = reader.ReadEvent()) != null && checkedCount < 50)
                        {
                            using (ev)
                            {
                                checkedCount++;
                                if (String.Equals(ev.ProviderName ?? "", provider, StringComparison.OrdinalIgnoreCase))
                                {
                                    seenAgain = true; details = "A newer matching event was found: record " + Convert.ToString(ev.RecordId); break;
                                }
                            }
                        }
                    }
                }
                catch (Exception ex) { details = "Recheck error: " + ex.Message; }
                Dictionary<string, object> result = new Dictionary<string, object>();
                result["seen_again"] = seenAgain; result["details"] = details; result["checked_at"] = DateTime.UtcNow.ToString("o");
                Post(cfg, "/api/v1/windows-agents/rechecks/" + recheckId + "/result", result, ReadApiKey());
            }
        }

        Dictionary<string, object> Get(AgentConfig cfg, string path, string bearer)
        {
            string url=cfg.ServerUrl+path; HttpWebRequest req=(HttpWebRequest)WebRequest.Create(url);req.Method="GET";req.Accept="application/json";req.Timeout=10000;req.ReadWriteTimeout=10000;req.UserAgent="GODSEYE-Windows-Agent/"+AgentVersion;if(!String.IsNullOrWhiteSpace(bearer))req.Headers[HttpRequestHeader.Authorization]="Bearer "+bearer;
            try{using(HttpWebResponse res=(HttpWebResponse)req.GetResponse())using(StreamReader sr=new StreamReader(res.GetResponseStream(),Encoding.UTF8)){string text=sr.ReadToEnd();return Json.Deserialize<Dictionary<string,object>>(text);}}
            catch(WebException ex){string detail=ex.Message;if(ex.Response!=null)try{using(StreamReader sr=new StreamReader(ex.Response.GetResponseStream()))detail=sr.ReadToEnd();}catch{}throw new Exception("GODSEYE API request failed: "+detail,ex);}
        }

        Dictionary<string, object> Post(AgentConfig cfg, string path, object body, string bearer)
        {
            string url = cfg.ServerUrl + path;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST"; req.ContentType = "application/json"; req.Accept = "application/json"; req.Timeout = 30000; req.ReadWriteTimeout = 30000;
            req.UserAgent = "GODSEYE-Windows-Agent/" + AgentVersion;
            if (!String.IsNullOrWhiteSpace(bearer)) req.Headers[HttpRequestHeader.Authorization] = "Bearer " + bearer;
            byte[] data = Encoding.UTF8.GetBytes(Json.Serialize(body)); req.ContentLength = data.Length;
            using (Stream s = req.GetRequestStream()) s.Write(data, 0, data.Length);
            try
            {
                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                using (StreamReader sr = new StreamReader(res.GetResponseStream(), Encoding.UTF8))
                {
                    string text = sr.ReadToEnd(); return Json.Deserialize<Dictionary<string, object>>(text);
                }
            }
            catch (WebException ex)
            {
                string detail = ex.Message;
                if (ex.Response != null) try { using (StreamReader sr = new StreamReader(ex.Response.GetResponseStream())) detail = sr.ReadToEnd(); } catch { }
                throw new Exception("GODSEYE API request failed: " + detail, ex);
            }
        }
    }
}
