using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Godseye.WindowsAgent
{
    public partial class GodseyeAgentService
    {
        static int RemoteHelperV2Main(string[] args)
        {
            if (args.Length < 5) return 64;
            int port;
            if (!Int32.TryParse(args[1], out port) || port < 1 || port > 65535) return 64;
            string token = args[2];
            string requestedBy = args[3];
            string sessionLabel = args[4];

            int consent = MessageBox(IntPtr.Zero,
                "GODSEYE administrator '" + requestedBy + "' is requesting a remote support session.\n\n" +
                "Allow screen viewing and mouse/keyboard control until the session is disconnected?",
                "GODSEYE Remote Support", MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST);
            if (consent != IDYES) return 2;

            try
            {
                using (TcpClient client = new TcpClient(AddressFamily.InterNetwork))
                {
                    client.NoDelay = true;
                    client.Connect(IPAddress.Loopback, port);
                    using (NetworkStream stream = client.GetStream())
                    using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, false, 8192, true))
                    using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false), 8192, true) { AutoFlush = true })
                    {
                        writer.WriteLine(Json.Serialize(new Dictionary<string, object>
                        {
                            { "kind", "hello" }, { "token", token }, { "approved", true },
                            { "session", sessionLabel }, { "pid", Environment.ProcessId }
                        }));

                        while (true)
                        {
                            string line = reader.ReadLine();
                            if (String.IsNullOrWhiteSpace(line)) return 0;
                            Dictionary<string, object> request = Json.Deserialize<Dictionary<string, object>>(line);
                            string kind = request != null && request.ContainsKey("kind") ? Convert.ToString(request["kind"]) : "";
                            if (String.Equals(kind, "terminate", StringComparison.OrdinalIgnoreCase))
                            {
                                writer.WriteLine(Json.Serialize(new Dictionary<string, object> { { "ok", true } }));
                                return 0;
                            }
                            try { writer.WriteLine(Json.Serialize(HandleRemoteHelperRequest(request))); }
                            catch (Exception ex) { writer.WriteLine(Json.Serialize(new Dictionary<string, object> { { "ok", false }, { "error", ex.Message } })); }
                        }
                    }
                }
            }
            catch { return 1; }
        }

        void LaunchRemoteHelperV2(int port, string token, string requestedBy, long sessionId)
        {
            uint sessionIdWin = WTSGetActiveConsoleSessionId();
            if (sessionIdWin == INVALID_SESSION_ID) throw new Exception("No interactive Windows session is signed in.");
            IntPtr userToken = IntPtr.Zero;
            if (!WTSQueryUserToken(sessionIdWin, out userToken)) throw new Exception("Could not obtain the signed-in Windows user token (" + Marshal.GetLastWin32Error() + ").");
            try
            {
                string exe = Environment.ProcessPath;
                if (String.IsNullOrWhiteSpace(exe)) throw new Exception("Agent executable path is unavailable.");
                requestedBy = (requestedBy ?? "administrator").Replace("\"", "'");
                string args = "\"" + exe + "\" --remote-helper-v2 " + port + " \"" + token + "\" \"" + requestedBy + "\" \"" + sessionId + "\"";
                var cmd = new StringBuilder(args);
                STARTUPINFO si = new STARTUPINFO(); si.cb = Marshal.SizeOf(typeof(STARTUPINFO)); si.lpDesktop = @"winsta0\default";
                PROCESS_INFORMATION pi;
                if (!CreateProcessAsUser(userToken, exe, cmd, IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero, Path.GetDirectoryName(exe), ref si, out pi))
                    throw new Exception("Could not launch the interactive GODSEYE helper (" + Marshal.GetLastWin32Error() + ").");
                remoteHelperProcessId = (int)pi.dwProcessId; CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            }
            finally { if (userToken != IntPtr.Zero) CloseHandle(userToken); }
        }

        void StartRemoteSessionV2(AgentConfig cfg, long sessionId, string requestedBy)
        {
            StopRemoteSession(); remoteStop = false; remoteSessionId = sessionId; remotePipeName = null;
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(1);
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            LaunchRemoteHelperV2(port, token, requestedBy, sessionId);
            remoteWorker = new Thread(() => RemoteSessionLoopV2(cfg, sessionId, listener, token)) { IsBackground = true, Name = "GODSEYE Remote Support v2" };
            remoteWorker.Start();
            Log("Remote support session " + sessionId + " waiting for local approval using loopback IPC.");
        }

        void RemoteSessionLoopV2(AgentConfig cfg, long sessionId, TcpListener listener, string token)
        {
            long after = 0; bool activeReported = false; bool terminalReported = false; TcpClient client = null;
            try
            {
                DateTime deadline = DateTime.UtcNow.AddSeconds(90);
                while (!remoteStop && !stopping && DateTime.UtcNow < deadline)
                {
                    if (listener.Pending()) break;
                    if (remoteHelperProcessId > 0)
                    {
                        try
                        {
                            Process helper = Process.GetProcessById(remoteHelperProcessId);
                            if (helper.HasExited)
                            {
                                string status = helper.ExitCode == 2 ? "denied" : "failed";
                                string error = helper.ExitCode == 2 ? "The local Windows user denied remote support." : "The interactive remote helper exited before connecting.";
                                Post(cfg, "/api/v1/windows-agents/remote/sessions/" + sessionId + "/state", new Dictionary<string, object> { { "status", status }, { "error", error } }, ReadApiKey());
                                terminalReported = true; return;
                            }
                        }
                        catch { }
                    }
                    Thread.Sleep(150);
                }
                if (remoteStop || stopping) return;
                if (!listener.Pending()) throw new Exception("Timed out waiting for the approved Windows desktop helper to connect.");

                client = listener.AcceptTcpClient(); client.NoDelay = true;
                NetworkStream stream = client.GetStream(); stream.ReadTimeout = 10000; stream.WriteTimeout = 10000;
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, false, 8192, true))
                using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false), 8192, true) { AutoFlush = true })
                {
                    string helloLine = reader.ReadLine();
                    if (String.IsNullOrWhiteSpace(helloLine)) throw new Exception("Approved Windows helper did not send its handshake.");
                    Dictionary<string, object> hello = Json.Deserialize<Dictionary<string, object>>(helloLine);
                    if (hello == null || !hello.ContainsKey("token") || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Convert.ToString(hello["token"])), Encoding.UTF8.GetBytes(token)))
                        throw new Exception("Remote helper authentication failed.");

                    Post(cfg, "/api/v1/windows-agents/remote/sessions/" + sessionId + "/state", new Dictionary<string, object> { { "status", "active" } }, ReadApiKey());
                    activeReported = true;
                    Log("Remote support session " + sessionId + " approved; interactive helper connected.");

                    while (!remoteStop && !stopping)
                    {
                        Dictionary<string, object> frame = RemoteHelperV2Request(writer, reader, new Dictionary<string, object> { { "kind", "capture" } });
                        if (frame == null || !frame.ContainsKey("image_base64"))
                            throw new Exception(frame != null && frame.ContainsKey("error") ? Convert.ToString(frame["error"]) : "Remote desktop capture returned no image.");
                        Post(cfg, "/api/v1/windows-agents/remote/sessions/" + sessionId + "/frame", new Dictionary<string, object> { { "image_base64", frame["image_base64"] }, { "width", frame["width"] }, { "height", frame["height"] } }, ReadApiKey());

                        Dictionary<string, object> poll = Get(cfg, "/api/v1/windows-agents/remote/sessions/" + sessionId + "/events?after=" + after, ReadApiKey());
                        if (poll.ContainsKey("active") && !Convert.ToBoolean(poll["active"])) break;
                        object rawEvents;
                        if (poll.TryGetValue("events", out rawEvents) && rawEvents is System.Collections.IEnumerable list && !(rawEvents is string))
                            foreach (object o in list)
                            {
                                Dictionary<string, object> e = o as Dictionary<string, object>; if (e == null) continue;
                                after = Math.Max(after, Convert.ToInt64(e["event_id"]));
                                Dictionary<string, object> ev = e["event"] as Dictionary<string, object>;
                                if (ev != null) RemoteHelperV2Request(writer, reader, ev);
                            }
                        Thread.Sleep(250);
                    }
                    if (activeReported)
                    {
                        try { RemoteHelperV2Request(writer, reader, new Dictionary<string, object> { { "kind", "terminate" } }); } catch { }
                        try { Post(cfg, "/api/v1/windows-agents/remote/sessions/" + sessionId + "/state", new Dictionary<string, object> { { "status", "ended" } }, ReadApiKey()); terminalReported = true; } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Remote support v2 session " + sessionId + " failed: " + ex.Message);
                if (!terminalReported) try { Post(cfg, "/api/v1/windows-agents/remote/sessions/" + sessionId + "/state", new Dictionary<string, object> { { "status", "failed" }, { "error", ex.Message } }, ReadApiKey()); } catch { }
            }
            finally
            {
                try { client?.Close(); } catch { } try { listener.Stop(); } catch { }
                if (remoteSessionId == sessionId)
                {
                    try { if (remoteHelperProcessId > 0) { Process p = Process.GetProcessById(remoteHelperProcessId); if (!p.HasExited) p.Kill(); } } catch { }
                    remoteHelperProcessId = 0; remoteSessionId = 0; remotePipeName = null;
                }
            }
        }

        Dictionary<string, object> RemoteHelperV2Request(StreamWriter writer, StreamReader reader, Dictionary<string, object> request)
        {
            writer.WriteLine(Json.Serialize(request));
            string line = reader.ReadLine();
            if (String.IsNullOrWhiteSpace(line)) throw new Exception("Interactive remote helper disconnected.");
            Dictionary<string, object> response = Json.Deserialize<Dictionary<string, object>>(line);
            if (response == null) throw new Exception("Interactive remote helper returned an invalid response.");
            if (response.ContainsKey("ok") && !Convert.ToBoolean(response["ok"])) throw new Exception(response.ContainsKey("error") ? Convert.ToString(response["error"]) : "Interactive remote helper request failed.");
            return response;
        }
    }
}
