using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

// The CI harness passes only processes it created for this test.
internal static class ParentFixture {
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo {
        public int cb;
        public IntPtr reserved, desktop, title;
        public int x, y, xSize, ySize, xChars, yChars, fill, flags;
        public short show, reservedBytes;
        public IntPtr reservedData, input, output, error;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx {
        public StartupInfo startup;
        public IntPtr attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInfo {
        public IntPtr process, thread;
        public uint pid, tid;
    }

    [DllImport("kernel32", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32")]
    private static extern uint GetCurrentProcessId();
    [DllImport("kernel32", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr,
        ref IntPtr value, IntPtr size, IntPtr previous, IntPtr returnedSize);
    [DllImport("kernel32")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool CreateProcessW(string image, StringBuilder commandLine, IntPtr processSecurity,
        IntPtr threadSecurity, bool inherit, uint flags, IntPtr env, IntPtr cwd,
        ref StartupInfoEx startup, out ProcessInfo process);
    [DllImport("kernel32", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr handle, uint code);
    [DllImport("kernel32", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr handle, out uint code);

    private static void Require(bool ok) {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private static int Main(string[] args) {
        const uint ProcessCreateProcess = 0x0080;
        const int ProcThreadAttributeParentProcess = 0x00020000;
        const uint ExtendedStartupInfoPresent = 0x00080000;
        const uint CreateSuspended = 0x00000004;
        const uint CreateNewConsole = 0x00000010;
        const uint WaitTimeout = 0x00000102;
        const int StartfUseShowWindow = 0x00000001;
        const short SwHide = 0;
        var suspend = args[0] == "suspend";
        var mode = !suspend && args.Length > 2 ? args[2] : "chrome-parent";
        bool useParent = !suspend && mode != "no-parent";
        bool useDesktop = mode == "chrome-desktop" || mode == "chrome-desktop-new-console";
        bool useNewConsole = mode == "chrome-new-console" || mode == "chrome-desktop-new-console";
        if (mode != "chrome-parent" && mode != "no-parent" && mode != "self-parent" && !useDesktop && !useNewConsole) {
            Console.Error.WriteLine("Unknown launch mode: {0}", mode);
            return 1;
        }
        var image = args[1];
        var line = "\"" + image + "\"";
        if (!suspend) {
            const string tailVariable = "CK_IMAGE_TEST_WINDOWS_CHILD_TAIL";
            var tail = Environment.GetEnvironmentVariable(tailVariable);
            if (tail == null) {
                Console.Error.WriteLine("Missing {0}.", tailVariable);
                return 1;
            }
            Environment.SetEnvironmentVariable(tailVariable, null);
            line += " " + tail;
        }
        var startup = new StartupInfoEx();
        var process = new ProcessInfo();
        var parent = IntPtr.Zero;
        var list = IntPtr.Zero;
        var initialized = false;
        uint flags = suspend ? CreateSuspended : 0u;
        try {
            startup.startup.cb = Marshal.SizeOf(typeof(StartupInfo));
            if (useParent) {
                var pid = mode == "self-parent" ? GetCurrentProcessId() : UInt32.Parse(args[0]);
                Console.Error.WriteLine("{0}: synthetic parent PID {1}", mode, pid);
                parent = OpenProcess(ProcessCreateProcess, false, pid);
                Require(parent != IntPtr.Zero);
                var size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                list = Marshal.AllocHGlobal(size);
                Require(InitializeProcThreadAttributeList(list, 1, 0, ref size));
                initialized = true;
                Require(UpdateProcThreadAttribute(list, 0, new IntPtr(ProcThreadAttributeParentProcess),
                    ref parent, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
                startup.startup.cb = Marshal.SizeOf(typeof(StartupInfoEx));
                startup.attributes = list;
                flags |= ExtendedStartupInfoPresent;
            }
            if (useDesktop) startup.startup.desktop = Marshal.StringToHGlobalUni(@"winsta0\default");
            if (useNewConsole) flags |= CreateNewConsole;
            if (!suspend) {
                // Chrome sets start_hidden for cmd and direct console hosts, which
                // sets STARTF_USESHOWWINDOW with SW_HIDE, not CREATE_NO_WINDOW.
                // https://github.com/chromium/chromium/blob/main/chrome/browser/extensions/api/messaging/launch_context_win.cc#L260-L285
                // https://github.com/chromium/chromium/blob/main/base/process/launch_win.cc#L360-L386
                startup.startup.flags = StartfUseShowWindow;
                startup.startup.show = SwHide;
                Console.Error.WriteLine("{0}: CreateProcessW command line: {1}", mode, line);
            }
            Require(CreateProcessW(image, new StringBuilder(line), IntPtr.Zero, IntPtr.Zero, false,
                flags, IntPtr.Zero, IntPtr.Zero, ref startup, out process));
            if (suspend) {
                File.WriteAllText(args[2], process.pid.ToString());
                Console.ReadLine();
                return 0;
            }
            // Return in time for the Rust harness to collect the result and try the next mode.
            uint waited = WaitForSingleObject(process.process, 10000);
            if (waited == WaitTimeout) {
                Console.Error.WriteLine("Child PID {0} did not exit within 10 seconds", process.pid);
                return 1;
            }
            Require(waited == 0);
            uint status;
            Require(GetExitCodeProcess(process.process, out status));
            Console.Error.WriteLine("Child PID {0} exit code: 0x{1:X8}", process.pid, status);
            return unchecked((int)status);
        } catch (Win32Exception error) {
            Console.Error.WriteLine("Could not launch or wait for {0}: Win32 error {1}: {2}",
                image, error.NativeErrorCode, error.Message);
            return 1;
        } finally {
            if (process.thread != IntPtr.Zero) CloseHandle(process.thread);
            if (process.process != IntPtr.Zero) {
                if (WaitForSingleObject(process.process, 0) != 0) {
                    TerminateProcess(process.process, 1);
                    WaitForSingleObject(process.process, 1000);
                }
                CloseHandle(process.process);
            }
            if (initialized) DeleteProcThreadAttributeList(list);
            if (list != IntPtr.Zero) Marshal.FreeHGlobal(list);
            if (parent != IntPtr.Zero) CloseHandle(parent);
            if (startup.startup.desktop != IntPtr.Zero) Marshal.FreeHGlobal(startup.startup.desktop);
        }
    }
}
