using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Godseye.WindowsAgent
{
    internal static class TrayApp
    {
        const string ServiceName = "GODSEYEWindowsAgent";
        const string StatusKey = @"SOFTWARE\MSAPGROUP\GODSEYE Agent\Status";
        static Icon? _trayIcon;
        static Bitmap? _trayBitmap;
        static Control? _uiDispatcher;
        static volatile bool _sharingStopRequested;
        static Form? _sharingBanner;
        static Thread? _sharingBannerThread;
        static readonly object TicketLock = new object();
        static Dictionary<string, object>? _pendingTicket;
        static NotifyIcon? _notifyIcon;

        public static bool SharingStopRequested => _sharingStopRequested;

        public static Thread StartSharingBanner(string requestedBy)
        {
            StopSharingBanner();
            _sharingStopRequested = false;
            var thread = new Thread(() =>
            {
                Application.EnableVisualStyles();
                using var form = new Form
                {
                    Text = "GODSEYE Screen Sharing",
                    StartPosition = FormStartPosition.Manual,
                    TopMost = true,
                    FormBorderStyle = FormBorderStyle.FixedToolWindow,
                    ShowInTaskbar = true,
                    Width = 520,
                    Height = 78,
                    BackColor = Color.FromArgb(12, 28, 43),
                    ForeColor = Color.White
                };
                form.Location = new Point(Math.Max(0, (Screen.PrimaryScreen?.WorkingArea.Width ?? 520) / 2 - 260), 12);
                var label = new Label { Left = 16, Top = 15, Width = 350, Height = 30, Text = "Your screen is being shared with " + requestedBy, ForeColor = Color.White, Font = new Font("Segoe UI Semibold", 10f) };
                var stop = new Button { Left = 380, Top = 10, Width = 112, Height = 36, Text = "Stop Sharing", BackColor = Color.FromArgb(210, 55, 70), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
                stop.FlatAppearance.BorderSize = 0;
                stop.Click += (_, __) => { _sharingStopRequested = true; form.Close(); };
                form.FormClosed += (_, __) => { if (!_sharingStopRequested) _sharingStopRequested = true; };
                form.Controls.AddRange(new Control[] { label, stop });
                _sharingBanner = form;
                Application.Run(form);
                _sharingBanner = null;
                _sharingBannerThread = null;
            });
            thread.IsBackground = true;
            thread.SetApartmentState(ApartmentState.STA);
            thread.Name = "GODSEYE Screen Sharing Banner";
            _sharingBannerThread = thread;
            thread.Start();
            return thread;
        }

        public static void CloseSharingBanner()
        {
            Form? form = _sharingBanner;
            if (form != null && !form.IsDisposed)
            {
                try { form.BeginInvoke(new Action(form.Close)); } catch { }
            }
        }

        public static void StopSharingBanner()
        {
            _sharingStopRequested = true;
            CloseSharingBanner();
            Thread? thread = _sharingBannerThread;
            if (thread != null && thread != Thread.CurrentThread)
            {
                try { thread.Join(1500); } catch { }
            }
        }

        public static int Run()
        {
            using var mutex = new Mutex(true, @"Local\GODSEYE.WindowsAgent.Tray.2.4.4", out bool created);
            if (!created) return 0;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new GodseyeTrayContext());
            return 0;
        }

        internal static Dictionary<string, object> PeekPendingTicket()
        {
            lock (TicketLock)
            {
                if (_pendingTicket == null)
                    return new Dictionary<string, object>{{"ok",true},{"pending",false}};
                var result = new Dictionary<string, object>(_pendingTicket, StringComparer.OrdinalIgnoreCase);
                result["ok"] = true;
                result["pending"] = true;
                return result;
            }
        }

        internal static void CompletePendingTicket(string requestId, string ticketNumber)
        {
            bool completed = false;
            lock (TicketLock)
            {
                if (_pendingTicket != null && String.Equals(Convert.ToString(_pendingTicket["request_id"]), requestId, StringComparison.OrdinalIgnoreCase))
                {
                    _pendingTicket = null;
                    completed = true;
                }
            }
            if (!completed) return;
            Control? dispatcher = _uiDispatcher;
            Action notify = () =>
            {
                if (_notifyIcon == null) return;
                _notifyIcon.BalloonTipTitle = "GODSEYE Ticket Submitted";
                _notifyIcon.BalloonTipText = "Your support ticket " + ticketNumber + " was created successfully.";
                _notifyIcon.ShowBalloonTip(6000);
            };
            if (dispatcher != null && !dispatcher.IsDisposed && dispatcher.InvokeRequired) dispatcher.BeginInvoke(notify); else notify();
        }

        static bool QueueTicket(Dictionary<string, object> ticket)
        {
            lock (TicketLock)
            {
                if (_pendingTicket != null) return false;
                _pendingTicket = ticket;
                return true;
            }
        }

        public static bool ShowConsentDialog(string requestedBy)
        {
            Control? dispatcher = _uiDispatcher;
            if (dispatcher != null && !dispatcher.IsDisposed && dispatcher.InvokeRequired)
                return (bool)dispatcher.Invoke(new Func<string, bool>(ShowConsentDialogCore), requestedBy);
            return ShowConsentDialogCore(requestedBy);
        }

        static bool ShowConsentDialogCore(string requestedBy)
        {
            // The persistent tray host owns consent UI. Keeping the dialog on the
            // WinForms UI thread avoids the intermittent no-window/hung-dialog
            // behavior that occurs when ShowDialog is invoked from the pipe worker.
            if (_uiDispatcher == null)
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
            }
            using var form = new Form
            {
                Text = "GODSEYE Remote Access",
                StartPosition = FormStartPosition.CenterScreen,
                TopMost = true,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                ShowInTaskbar = true,
                Width = 520,
                Height = 250,
                BackColor = Color.FromArgb(13, 22, 33),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 10f)
            };

            var icon = new PictureBox { Left = 24, Top = 28, Width = 58, Height = 58, SizeMode = PictureBoxSizeMode.StretchImage, Image = CreateLogoBitmap(58) };
            var title = new Label { Left = 100, Top = 26, Width = 380, Height = 30, Text = "GODSEYE Remote Access", Font = new Font("Segoe UI Semibold", 14f), ForeColor = Color.White };
            var message = new Label { Left = 100, Top = 62, Width = 380, Height = 80, Text = "A GODSEYE administrator (" + requestedBy + ") is requesting to view your screen. Control requires a separate approval.\r\n\r\nShare your screen?", ForeColor = Color.Gainsboro };
            var allow = new Button { Text = "Share Screen", DialogResult = DialogResult.Yes, Left = 215, Top = 155, Width = 130, Height = 38, BackColor = Color.FromArgb(0, 190, 92), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            var deny = new Button { Text = "Deny", DialogResult = DialogResult.No, Left = 355, Top = 155, Width = 110, Height = 38, BackColor = Color.FromArgb(55, 65, 77), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            allow.FlatAppearance.BorderSize = 0;
            deny.FlatAppearance.BorderSize = 0;
            form.AcceptButton = allow;
            form.CancelButton = deny;
            form.Controls.AddRange(new Control[] { icon, title, message, allow, deny });
            return form.ShowDialog() == DialogResult.Yes;
        }

        public static bool ShowControlConsentDialog(string requestedBy)
        {
            Control? dispatcher = _uiDispatcher;
            if (dispatcher != null && !dispatcher.IsDisposed && dispatcher.InvokeRequired)
                return (bool)dispatcher.Invoke(new Func<string, bool>(ShowControlConsentDialogCore), requestedBy);
            return ShowControlConsentDialogCore(requestedBy);
        }

        static bool ShowControlConsentDialogCore(string requestedBy)
        {
            return MessageBox.Show(
                "The GODSEYE administrator (" + requestedBy + ") can already view your screen.\r\n\r\nAllow mouse and keyboard control? You can stop sharing from the GODSEYE tray at any time.",
                "GODSEYE Remote Control Permission",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2,
                MessageBoxOptions.ServiceNotification) == DialogResult.Yes;
        }

        internal static Icon CreateTrayIcon()
        {
            _trayBitmap?.Dispose();
            _trayBitmap = CreateLogoBitmap(32);
            _trayIcon = Icon.FromHandle(_trayBitmap.GetHicon());
            return _trayIcon;
        }

        static Bitmap CreateLogoBitmap(int size)
        {
            var bmp = new Bitmap(size, size);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var blue = new SolidBrush(Color.FromArgb(20, 137, 239));
            using var navy = new SolidBrush(Color.FromArgb(4, 45, 82));
            using var white = new SolidBrush(Color.White);
            using var black = new SolidBrush(Color.FromArgb(5, 15, 25));
            float s = size;
            g.FillEllipse(blue, s * .05f, s * .08f, s * .90f, s * .84f);
            g.FillPolygon(navy, new[] { new PointF(s * .10f, s * .28f), new PointF(s * .02f, s * .03f), new PointF(s * .30f, s * .14f) });
            g.FillPolygon(navy, new[] { new PointF(s * .90f, s * .28f), new PointF(s * .98f, s * .03f), new PointF(s * .70f, s * .14f) });
            g.FillEllipse(white, s * .18f, s * .28f, s * .28f, s * .30f);
            g.FillEllipse(white, s * .54f, s * .28f, s * .28f, s * .30f);
            g.FillEllipse(black, s * .29f, s * .38f, s * .08f, s * .10f);
            g.FillEllipse(black, s * .63f, s * .38f, s * .08f, s * .10f);
            g.FillPolygon(white, new[] { new PointF(s * .41f, s * .59f), new PointF(s * .59f, s * .59f), new PointF(s * .50f, s * .73f) });
            return bmp;
        }

        sealed class GodseyeTrayContext : ApplicationContext
        {
            readonly NotifyIcon notifyIcon;
            readonly Thread remotePipeThread;
            readonly Control uiDispatcher;
            volatile bool remotePipeStop;

            public GodseyeTrayContext()
            {
                uiDispatcher = new Control();
                uiDispatcher.CreateControl();
                _uiDispatcher = uiDispatcher;
                var menu = new ContextMenuStrip();
                var heading = new ToolStripMenuItem("GODSEYE Agent — Running") { Enabled = false };
                menu.Items.Add(heading);
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("Agent Status...", null, (_, __) => ShowStatus());
                menu.Items.Add("Submit Ticket...", null, (_, __) => ShowSubmitTicket());
                menu.Items.Add("Open GODSEYE Portal", null, (_, __) => OpenPortal());
                menu.Items.Add("Check for Updates", null, (_, __) => OpenPortal("/#windows-agents"));
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add(new ToolStripMenuItem("Remote Access: Enabled (User Approval)") { Enabled = false });
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("Exit Tray", null, (_, __) => ExitThread());

                notifyIcon = new NotifyIcon
                {
                    Icon = CreateTrayIcon(),
                    Text = "GODSEYE Agent — Running",
                    Visible = true,
                    ContextMenuStrip = menu
                };
                notifyIcon.DoubleClick += (_, __) => ShowStatus();
                _notifyIcon = notifyIcon;
                notifyIcon.BalloonTipTitle = "GODSEYE Agent";
                notifyIcon.BalloonTipText = "GODSEYE Windows Agent is running and connected for monitoring and approved remote support.";

                remotePipeThread = new Thread(RemotePipeLoop)
                {
                    IsBackground = true,
                    Name = "GODSEYE Tray Remote Host"
                };
                remotePipeThread.Start();
            }

            void RemotePipeLoop()
            {
                string pipeName = "GODSEYE-Tray-" + Process.GetCurrentProcess().SessionId;
                while (!remotePipeStop)
                {
                    try
                    {
                        using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None);
                        pipe.WaitForConnection();
                        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 8192, true);
                        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 8192, true) { AutoFlush = true };
                        string? line = reader.ReadLine();
                        if (!String.IsNullOrWhiteSpace(line))
                            writer.WriteLine(GodseyeAgentService.HandleTrayPipeLine(line));
                    }
                    catch
                    {
                        if (!remotePipeStop) Thread.Sleep(250);
                    }
                }
            }

            protected override void ExitThreadCore()
            {
                remotePipeStop = true;
                notifyIcon.Visible = false;
                notifyIcon.Dispose();
                if (ReferenceEquals(_notifyIcon, notifyIcon)) _notifyIcon = null;
                if (ReferenceEquals(_uiDispatcher, uiDispatcher)) _uiDispatcher = null;
                uiDispatcher.Dispose();
                base.ExitThreadCore();
            }

            static string ReadStatus(string name, string fallback = "—")
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(StatusKey, false);
                    return Convert.ToString(key?.GetValue(name)) ?? fallback;
                }
                catch { return fallback; }
            }

            static bool ServiceRunning()
            {
                try
                {
                    using var svc = new ServiceController(ServiceName);
                    return svc.Status == ServiceControllerStatus.Running;
                }
                catch { return false; }
            }

            static void OpenPortal(string suffix = "")
            {
                var server = ReadStatus("ServerUrl", "");
                if (String.IsNullOrWhiteSpace(server))
                {
                    MessageBox.Show("The GODSEYE server address is not available yet. Wait for the agent's next check-in and try again.", "GODSEYE Agent", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                try
                {
                    Process.Start(new ProcessStartInfo(server.TrimEnd('/') + suffix) { UseShellExecute = true });
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Could not open the GODSEYE portal: " + ex.Message, "GODSEYE Agent", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }

            static void ShowStatus()
            {
                using var form = new Form
                {
                    Text = "GODSEYE Agent",
                    StartPosition = FormStartPosition.CenterScreen,
                    FormBorderStyle = FormBorderStyle.FixedDialog,
                    MaximizeBox = false,
                    MinimizeBox = false,
                    Width = 510,
                    Height = 315,
                    Font = new Font("Segoe UI", 10f)
                };
                var logo = new PictureBox { Left = 24, Top = 24, Width = 64, Height = 64, SizeMode = PictureBoxSizeMode.StretchImage, Image = CreateLogoBitmap(64) };
                var status = new Label { Left = 115, Top = 30, Width = 340, Height = 28, Text = "Status:  " + (ServiceRunning() ? "Running" : "Stopped"), ForeColor = ServiceRunning() ? Color.Green : Color.Firebrick, Font = new Font("Segoe UI Semibold", 11f) };
                var version = new Label { Left = 115, Top = 65, Width = 340, Height = 24, Text = "Version:  " + ReadStatus("Version", "unknown") };
                var server = new Label { Left = 115, Top = 98, Width = 340, Height = 42, Text = "Server:  " + ReadStatus("ServerUrl") };
                var checkin = new Label { Left = 115, Top = 140, Width = 340, Height = 24, Text = "Last Check-In:  " + ReadStatus("LastCheckIn") };
                var remote = new Label { Left = 115, Top = 174, Width = 340, Height = 30, Text = "Remote Access:  Enabled (User Approval)" };
                var close = new Button { Left = 350, Top = 220, Width = 105, Height = 36, Text = "Close", DialogResult = DialogResult.OK };
                form.AcceptButton = close;
                form.Controls.AddRange(new Control[] { logo, status, version, server, checkin, remote, close });
                form.ShowDialog();
            }

            static void ShowSubmitTicket()
            {
                lock (TicketLock)
                {
                    if (_pendingTicket != null)
                    {
                        MessageBox.Show("A support ticket is already queued and will be submitted at the next agent check-in.", "GODSEYE Submit Ticket", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        return;
                    }
                }
                using var form = new Form
                {
                    Text = "Submit a GODSEYE Support Ticket",
                    StartPosition = FormStartPosition.CenterScreen,
                    FormBorderStyle = FormBorderStyle.FixedDialog,
                    MaximizeBox = false,
                    MinimizeBox = false,
                    Width = 650,
                    Height = 590,
                    Font = new Font("Segoe UI", 10f)
                };
                var title = new Label { Left = 24, Top = 20, Width = 575, Height = 30, Text = "Tell your support team what you need help with.", Font = new Font("Segoe UI Semibold", 12f) };
                var nameLabel = new Label { Left = 24, Top = 66, Width = 180, Text = "Name *" };
                var name = new TextBox { Left = 220, Top = 62, Width = 380 };
                var departmentLabel = new Label { Left = 24, Top = 106, Width = 180, Text = "Department" };
                var department = new TextBox { Left = 220, Top = 102, Width = 380 };
                var phoneLabel = new Label { Left = 24, Top = 146, Width = 180, Text = "Phone" };
                var phone = new TextBox { Left = 220, Top = 142, Width = 380 };
                var emailLabel = new Label { Left = 24, Top = 186, Width = 180, Text = "Email" };
                var email = new TextBox { Left = 220, Top = 182, Width = 380 };
                var categoryLabel = new Label { Left = 24, Top = 226, Width = 180, Text = "Category *" };
                var category = new ComboBox { Left = 220, Top = 222, Width = 380, DropDownStyle = ComboBoxStyle.DropDownList };
                category.Items.AddRange(new object[] { "Email", "Internet", "Phone", "Hardware", "Software", "Security", "Other" });
                category.SelectedItem = "Other";
                var notesLabel = new Label { Left = 24, Top = 270, Width = 180, Text = "Issue notes *" };
                var notes = new TextBox { Left = 220, Top = 266, Width = 380, Height = 180, Multiline = true, ScrollBars = ScrollBars.Vertical, AcceptsReturn = true };
                var submit = new Button { Left = 365, Top = 475, Width = 112, Height = 38, Text = "Submit Ticket", BackColor = Color.FromArgb(20, 137, 239), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
                var cancel = new Button { Left = 488, Top = 475, Width = 112, Height = 38, Text = "Cancel", DialogResult = DialogResult.Cancel };
                submit.FlatAppearance.BorderSize = 0;
                submit.Click += (_, __) =>
                {
                    if (String.IsNullOrWhiteSpace(name.Text)) { MessageBox.Show("Enter your name.", "GODSEYE Submit Ticket", MessageBoxButtons.OK, MessageBoxIcon.Warning); name.Focus(); return; }
                    if (String.IsNullOrWhiteSpace(notes.Text)) { MessageBox.Show("Describe the issue you need help with.", "GODSEYE Submit Ticket", MessageBoxButtons.OK, MessageBoxIcon.Warning); notes.Focus(); return; }
                    var ticket = new Dictionary<string, object>
                    {
                        {"request_id", Guid.NewGuid().ToString("D")},
                        {"requester_name", name.Text.Trim()},
                        {"requester_department", department.Text.Trim()},
                        {"requester_phone", phone.Text.Trim()},
                        {"requester_email", email.Text.Trim()},
                        {"category", Convert.ToString(category.SelectedItem) ?? "Other"},
                        {"issue_notes", notes.Text.Trim()}
                    };
                    if (!QueueTicket(ticket))
                    {
                        MessageBox.Show("A support ticket is already queued.", "GODSEYE Submit Ticket", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        return;
                    }
                    form.DialogResult = DialogResult.OK;
                    form.Close();
                    MessageBox.Show("Your ticket is queued and will be submitted within a few seconds.", "GODSEYE Submit Ticket", MessageBoxButtons.OK, MessageBoxIcon.Information);
                };
                form.AcceptButton = submit;
                form.CancelButton = cancel;
                form.Controls.AddRange(new Control[] { title, nameLabel, name, departmentLabel, department, phoneLabel, phone, emailLabel, email, categoryLabel, category, notesLabel, notes, submit, cancel });
                form.ShowDialog();
            }
        }
    }
}
