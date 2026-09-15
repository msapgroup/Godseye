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
using System.Web.Script.Serialization;
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

    public class GodseyeAgentService : ServiceBase
    {
        const string AgentVersion = "1.1.1";
        static readonly JavaScriptSerializer Json = new JavaScriptSerializer() { MaxJsonLength = 8 * 1024 * 1024 };
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
            if (Environment.UserInteractive && args.Length > 0 && args[0].Equals("--console", StringComparison.OrdinalIgnoreCase))
            {
                GodseyeAgentService svc = new GodseyeAgentService();
                svc.stopping = false;
                svc.WorkerLoop();
                return;
            }
            ServiceBase.Run(new GodseyeAgentService());
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
                    else
                    {
                        result["ok"] = false; result["events"] = 0; result["new_findings"] = 0;
                        result["details"] = "Unsupported GODSEYE agent command: " + type;
                    }
                }
                catch (Exception ex)
                {
                    result["ok"] = false; result["events"] = 0; result["new_findings"] = 0;
                    result["details"] = "Pull Events Now failed: " + ex.Message;
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
