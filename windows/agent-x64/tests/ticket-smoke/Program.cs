using System.IO.Pipes;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Godseye.WindowsAgent;

namespace Godseye.AgentTicketTests;

internal static class Program
{
    static readonly JsonCompat Json = new();
    static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }

    sealed class NonPumpingContext : SynchronizationContext
    {
        public override void Post(SendOrPostCallback callback, object? state) { } // The caller blocks synchronously, as service/tray helpers can.
    }

    static async Task<int> Main()
    {
        string keyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GODSEYE", "Agent", "agent.key");
        string pipeName = "GODSEYE-Ticket-Test-" + Guid.NewGuid().ToString("N");
        if (File.Exists(keyPath) || File.Exists(TrayApp.PendingTicketPath)) throw new Exception("Ticket smoke requires a clean CI account; refusing to replace enrollment or a pending ticket.");
        Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
        File.WriteAllBytes(keyPath, ProtectedData.Protect(Encoding.UTF8.GetBytes("CI-TICKET-KEY"), null, DataProtectionScope.LocalMachine));
        using var stopping = new CancellationTokenSource();
        using var listener = new HttpListener();
        listener.Prefixes.Add("http://127.0.0.1:8091/");
        listener.Start();
        int requests = 0;
        var requestIds = new List<string>();
        Task api = Task.Run(async () => {
            while (!stopping.IsCancellationRequested)
            {
                HttpListenerContext context;
                try { context = await listener.GetContextAsync(); } catch when (stopping.IsCancellationRequested) { break; }
                using var reader = new StreamReader(context.Request.InputStream);
                var payload = Json.Deserialize<Dictionary<string, object>>(await reader.ReadToEndAsync());
                Check(context.Request.RawUrl == "/api/v1/windows-agents/tickets", "Wrong ticket endpoint");
                Check(context.Request.Headers["Authorization"] == "Bearer CI-TICKET-KEY", "Agent authentication was lost");
                Check(Convert.ToString(payload["issue_notes"]) == "Dock does not detect monitors", "Ticket content lost");
                requestIds.Add(Convert.ToString(payload["request_id"])!);
                requests++;
                string body;
                if (requests == 1) body = "{\"ok\":true}"; // An incomplete HTTP 200 must never clear the draft.
                else if (requests == 2) { context.Response.StatusCode = 503; body = "{\"detail\":\"Temporary ticket database outage\"}"; }
                else body = "{\"ok\":true,\"ticket_id\":45,\"ticket_number\":\"TKT-00045\"}";
                byte[] data = Encoding.UTF8.GetBytes(body);
                context.Response.ContentType = "application/json";
                context.Response.ContentLength64 = data.Length;
                await context.Response.OutputStream.WriteAsync(data);
                context.Response.Close();
            }
        });
        Task tray = Task.Run(async () => {
            while (!stopping.IsCancellationRequested)
            {
                using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                try {
                    await pipe.WaitForConnectionAsync(stopping.Token);
                    using var reader = new StreamReader(pipe, Encoding.UTF8, false, 8192, true);
                    using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true };
                    string? line = await reader.ReadLineAsync(stopping.Token);
                    if (line != null) await writer.WriteLineAsync(GodseyeAgentService.HandleTrayPipeLine(line));
                } catch (OperationCanceledException) when (stopping.IsCancellationRequested) { break; }
            }
        });
        try
        {
            string id = Guid.NewGuid().ToString("D");
            Check(TrayApp.QueueTicket(new Dictionary<string, object> {
                ["request_id"] = id, ["requester_name"] = "CI User", ["requester_department"] = "IT", ["requester_phone"] = "", ["requester_email"] = "ci@example.com", ["category"] = "Hardware", ["issue_notes"] = "Dock does not detect monitors"
            }), "Could not queue ticket");
            Check(File.Exists(TrayApp.PendingTicketPath), "Ticket was not persisted before queue confirmation");
            var field = typeof(TrayApp).GetField("_pendingTicket", BindingFlags.NonPublic | BindingFlags.Static)!;
            field.SetValue(null, null); // Simulate a tray process restart with the draft still on disk.
            TrayApp.RestorePendingTicket();
            Check(Convert.ToString(TrayApp.PeekPendingTicket()["request_id"]) == id, "Restart lost ticket identity");
            TrayApp.CompletePendingTicket("unrelated-request", "TKT-OTHER");
            Check(Convert.ToBoolean(TrayApp.PeekPendingTicket()["pending"]), "Stale acknowledgment cleared current draft");
            var cfg = new AgentConfig { ServerUrl = "http://127.0.0.1:8091" };
            var service = new GodseyeAgentService();
            service.DeliverTrayTicket(cfg, pipeName);
            Check(Convert.ToBoolean(TrayApp.PeekPendingTicket()["pending"]), "HTTP 200 without a ticket number was treated as submitted");
            service.DeliverTrayTicket(cfg, pipeName);
            Check(Convert.ToBoolean(TrayApp.PeekPendingTicket()["pending"]), "HTTP 503 lost pending ticket");
            Check(Convert.ToString(TrayApp.PeekPendingTicket()["last_error"])!.Contains("503"), "Delivery error was not sent back to the tray");
            service.DeliverTrayTicket(cfg, pipeName);
            Check(!Convert.ToBoolean(TrayApp.PeekPendingTicket()["pending"]), "Successful server receipt did not close queue");
            Check(!File.Exists(TrayApp.PendingTicketPath), "Confirmed ticket stayed on disk");
            Check(requestIds.Count == 3 && requestIds.All(x => x == id), "Retries changed request IDs and could create duplicates");

            string stalledName = pipeName + "-stalled";
            using var stalled = new NamedPipeServerStream(stalledName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            Task connected = stalled.WaitForConnectionAsync();
            var clock = System.Diagnostics.Stopwatch.StartNew();
            try { await GodseyeAgentService.RequestTrayPipeAsync(stalledName, new Dictionary<string, object> { ["kind"] = "ping" }, 250); throw new Exception("Stalled tray response did not time out"); }
            catch (OperationCanceledException) { }
            Check(clock.ElapsedMilliseconds < 2000, "Stalled pipe blocked agent delivery indefinitely");
            await connected;
            string contextName = pipeName + "-context";
            using var contextPipe = new NamedPipeServerStream(contextName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            Task contextConnected = contextPipe.WaitForConnectionAsync();
            Task blockedCaller = Task.Run(() => {
                SynchronizationContext.SetSynchronizationContext(new NonPumpingContext());
                try { GodseyeAgentService.TicketHelperRequest(contextName, new Dictionary<string, object> { ["kind"] = "ping" }, 250).GetAwaiter().GetResult(); throw new Exception("Synchronous helper did not time out"); }
                catch (OperationCanceledException) { }
                finally { SynchronizationContext.SetSynchronizationContext(null); }
            });
            Check(await Task.WhenAny(blockedCaller, Task.Delay(2000)) == blockedCaller, "Synchronous tray helper deadlocked a synchronization context");
            await blockedCaller;
            await contextConnected;
            Console.WriteLine("PASS: durable ticket restart, authenticated IPC/API delivery, incomplete reply and HTTP error retry, matching receipt, stable request ID and bounded pipe response.");
            return 0;
        }
        finally
        {
            stopping.Cancel(); listener.Stop();
            await Task.WhenAll(api, tray);
            File.Delete(keyPath);
            if (File.Exists(TrayApp.PendingTicketPath)) File.Delete(TrayApp.PendingTicketPath);
        }
    }
}
