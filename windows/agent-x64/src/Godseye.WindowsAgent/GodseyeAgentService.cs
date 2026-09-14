using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net;
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
        const string AgentVersion = "2.0.0";
        static readonly JsonCompat Json = new JsonCompat();
        readonly string BaseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GODSEYE", "Agent");
        Thread worker;
        volatile bool stopping;
        DateTime nextScheduledCollectUtc = DateTime.MinValue;

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

        protected override void OnStop() { stopping = true; if (worker != null) worker.Join(10000); }
        protected override void OnShutdown() { OnStop(); base.OnShutdown(); }

        static void Main(string[] args)
        {
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

            for (int i = 1; i < args.Length; i++)
            {
                string a = args[i];
                if (a.Equals("--server-url", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) cfg.ServerUrl = args[++i].TrimEnd('/');
                else if (a.Equals("--enrollment-token", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) cfg.EnrollmentToken = args[++i];
                else if (a.Equals("--skip-tls-verify", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) cfg.SkipTlsVerify = Boolean.Parse(args[++i]);
            }

            if (String.IsNullOrWhiteSpace(cfg.ServerUrl)) throw new Exception("ServerUrl is required for first-time configuration.");
            if (!File.Exists(KeyPath) && String.IsNullOrWhiteSpace(cfg.EnrollmentToken)) throw new Exception("EnrollmentToken is required for first-time enrollment.");
            if (String.IsNullOrWhiteSpace(cfg.AgentUuid)) cfg.AgentUuid = Guid.NewGuid().ToString();
            if (cfg.Channels == null || cfg.Channels.Count == 0) cfg.Channels = new List<string>() { "System", "Application" };
            if (cfg.PollIntervalSeconds < 30) cfg.PollIntervalSeconds = 60;
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
                    if (cfg.SkipTlsVerify)
                        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    else
                        ServicePointManager.ServerCertificateValidationCallback = null;

                    EnsureEnrolled(cfg);
                    Dictionary<string, object> hb = Heartbeat(cfg);
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
                ArrayList arr = channels as ArrayList;
                if (arr != null)
                {
                    List<string> list = new List<string>();
                    foreach (object x in arr) { string s = Convert.ToString(x); if (!String.IsNullOrWhiteSpace(s)) list.Add(s); }
                    if (list.Count > 0) cfg.Channels = list;
                }
            }
        }

        void ProcessCommands(AgentConfig cfg, Dictionary<string, object> hb)
        {
            object commandsObj;
            if (!hb.TryGetValue("commands", out commandsObj)) return;
            ArrayList commands = commandsObj as ArrayList;
            if (commands == null) return;
            foreach (object itemObj in commands)
            {
                Dictionary<string, object> item = itemObj as Dictionary<string, object>;
                if (item == null) continue;
                int commandId = Convert.ToInt32(item["id"]);
                string command = Convert.ToString(item["command"]);
                if (!command.Equals("pull_events", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    int before = CountPendingEvents();
                    FlushOrCollect(cfg);
                    int after = CountPendingEvents();
                    Dictionary<string, object> result = new Dictionary<string, object>();
                    result["ok"] = true;
                    result["events"] = Math.Max(before, after);
                    result["new_findings"] = 0;
                    result["details"] = "Manual Event Log pull completed.";
                    result["completed_at"] = DateTime.UtcNow.ToString("o");
                    Post(cfg, "/api/v1/windows-agents/commands/" + commandId + "/result", result, ReadApiKey());
                }
                catch (Exception ex)
                {
                    Dictionary<string, object> result = new Dictionary<string, object>();
                    result["ok"] = false;
                    result["events"] = 0;
                    result["new_findings"] = 0;
                    result["details"] = ex.Message;
                    result["completed_at"] = DateTime.UtcNow.ToString("o");
                    Post(cfg, "/api/v1/windows-agents/commands/" + commandId + "/result", result, ReadApiKey());
                }
            }
        }

        int CountPendingEvents()
        {
            try
            {
                if (!File.Exists(PendingPath)) return 0;
                PendingBatch batch = Json.Deserialize<PendingBatch>(File.ReadAllText(PendingPath, Encoding.UTF8));
                return batch != null && batch.events != null ? batch.events.Count : 0;
            }
            catch { return 0; }
        }

        void FlushOrCollect(AgentConfig cfg)
        {
            if (File.Exists(PendingPath)) FlushPending(cfg);
            PendingBatch batch = Collect(cfg);
            if (batch.events.Count > 0)
            {
                File.WriteAllText(PendingPath, Json.Serialize(batch), Encoding.UTF8);
                FlushPending(cfg);
            }
        }

        void FlushPending(AgentConfig cfg)
        {
            PendingBatch batch = Json.Deserialize<PendingBatch>(File.ReadAllText(PendingPath, Encoding.UTF8));
            if (batch == null || batch.events == null || batch.events.Count == 0) { File.Delete(PendingPath); return; }
            Dictionary<string, object> body = new Dictionary<string, object>(); body["events"] = batch.events;
            Post(cfg, "/api/v1/windows-agents/events", body, ReadApiKey());
            AgentState state = LoadState();
            if (batch.bookmarks != null) foreach (KeyValuePair<string, long> kv in batch.bookmarks) state.Bookmarks[kv.Key] = kv.Value;
            state.LastError = ""; SaveState(state); File.Delete(PendingPath);
        }

        PendingBatch Collect(AgentConfig cfg)
        {
            AgentState state = LoadState();
            PendingBatch batch = new PendingBatch(); batch.events = new List<Dictionary<string, object>>(); batch.bookmarks = new Dictionary<string, long>(state.Bookmarks, StringComparer.OrdinalIgnoreCase);
            foreach (string channel in cfg.Channels)
            {
                long last = state.Bookmarks.ContainsKey(channel) ? state.Bookmarks[channel] : 0;
                string query = last > 0 ? "*[System[(Level=1 or Level=2 or Level=3) and EventRecordID > " + last + "]]" : "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
                try
                {
                    EventLogQuery q = new EventLogQuery(channel, PathType.LogName, query); q.ReverseDirection = false;
                    using (EventLogReader reader = new EventLogReader(q))
                    {
                        EventRecord ev; int count = 0;
                        while ((ev = reader.ReadEvent()) != null && count < 500)
                        {
                            using (ev)
                            {
                                batch.events.Add(EventToDict(ev, channel));
                                if (ev.RecordId.HasValue) batch.bookmarks[channel] = Math.Max(batch.bookmarks.ContainsKey(channel) ? batch.bookmarks[channel] : 0, ev.RecordId.Value);
                                count++;
                            }
                        }
                    }
                }
                catch (EventLogNotFoundException) { Log("Channel not available: " + channel); }
                catch (Exception ex) { Log("Channel " + channel + " collection failed: " + ex.Message); }
            }
            return batch;
        }

        Dictionary<string, object> EventToDict(EventRecord ev, string channel)
        {
            Dictionary<string, object> item = new Dictionary<string, object>();
            item["computer_name"] = String.IsNullOrWhiteSpace(ev.MachineName) ? Environment.MachineName : ev.MachineName;
            item["channel"] = channel;
            item["provider"] = ev.ProviderName ?? "Windows";
            item["event_id"] = ev.Id;
            item["level"] = LevelName(ev.Level);
            item["record_id"] = ev.RecordId ?? 0;
            item["event_time"] = ev.TimeCreated.HasValue ? ev.TimeCreated.Value.ToUniversalTime().ToString("o") : DateTime.UtcNow.ToString("o");
            try { item["message"] = ev.FormatDescription() ?? ""; } catch { item["message"] = ""; }
            return item;
        }

        string LevelName(byte? level)
        {
            if (!level.HasValue) return "Error";
            switch (level.Value) { case 1: return "Critical"; case 2: return "Error"; case 3: return "Warning"; default: return "Information"; }
        }

        void ProcessRechecks(AgentConfig cfg, Dictionary<string, object> hb)
        {
            object rechecksObj;
            if (!hb.TryGetValue("rechecks", out rechecksObj)) return;
            ArrayList rechecks = rechecksObj as ArrayList;
            if (rechecks == null) return;
            foreach (object itemObj in rechecks)
            {
                Dictionary<string, object> item = itemObj as Dictionary<string, object>; if (item == null) continue;
                int recheckId = Convert.ToInt32(item["id"]);
                Dictionary<string, object> result = Recheck(item);
                Post(cfg, "/api/v1/windows-agents/rechecks/" + recheckId + "/result", result, ReadApiKey());
            }
        }

        Dictionary<string, object> Recheck(Dictionary<string, object> request)
        {
            string computer = Convert.ToString(request.ContainsKey("computer_name") ? request["computer_name"] : "");
            string provider = Convert.ToString(request.ContainsKey("provider") ? request["provider"] : "");
            string channel = Convert.ToString(request.ContainsKey("channel") ? request["channel"] : "System");
            int eventId = Convert.ToInt32(request.ContainsKey("event_id") ? request["event_id"] : 0);
            bool seen = false; string details = "No matching event was found during the recheck window.";
            try
            {
                DateTime since = DateTime.UtcNow.AddMinutes(-15);
                string query = "*[System[(Level=1 or Level=2 or Level=3) and EventID=" + eventId + " and TimeCreated[@SystemTime >= '" + since.ToString("o") + "']]]]";
                EventLogQuery q = new EventLogQuery(channel, PathType.LogName, query); q.ReverseDirection = true;
                using (EventLogReader reader = new EventLogReader(q))
                {
                    EventRecord ev = reader.ReadEvent();
                    if (ev != null)
                    {
                        using (ev)
                        {
                            bool providerOk = String.IsNullOrWhiteSpace(provider) || String.Equals(provider, ev.ProviderName, StringComparison.OrdinalIgnoreCase);
                            bool computerOk = String.IsNullOrWhiteSpace(computer) || String.Equals(computer, ev.MachineName, StringComparison.OrdinalIgnoreCase) || String.Equals(computer, Environment.MachineName, StringComparison.OrdinalIgnoreCase);
                            seen = providerOk && computerOk;
                            if (seen) details = "A matching Windows event occurred again during the recheck window.";
                        }
                    }
                }
            }
            catch (Exception ex) { details = "Recheck failed: " + ex.Message; }
            Dictionary<string, object> result = new Dictionary<string, object>(); result["seen_again"] = seen; result["details"] = details; result["checked_at"] = DateTime.UtcNow.ToString("o"); return result;
        }

        Dictionary<string, object> Post(AgentConfig cfg, string path, object body, string apiKey)
        {
            string url = cfg.ServerUrl.TrimEnd('/') + path;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST"; req.ContentType = "application/json"; req.Accept = "application/json"; req.Timeout = 30000; req.ReadWriteTimeout = 30000;
            if (!String.IsNullOrWhiteSpace(apiKey)) req.Headers[HttpRequestHeader.Authorization] = "Bearer " + apiKey;
            byte[] data = Encoding.UTF8.GetBytes(Json.Serialize(body)); req.ContentLength = data.Length;
            using (Stream st = req.GetRequestStream()) st.Write(data, 0, data.Length);
            try
            {
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (StreamReader sr = new StreamReader(resp.GetResponseStream()))
                {
                    string text = sr.ReadToEnd(); return Json.Deserialize<Dictionary<string, object>>(text);
                }
            }
            catch (WebException ex)
            {
                string detail = ex.Message;
                try { using (StreamReader sr = new StreamReader(ex.Response.GetResponseStream())) detail = sr.ReadToEnd(); } catch { }
                throw new Exception("GODSEYE API request failed: " + detail, ex);
            }
        }
    }
}
