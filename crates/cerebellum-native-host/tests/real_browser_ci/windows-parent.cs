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
        var suspend = args[0] == "suspend";
        var image = args[1];
        var commandLine = new StringBuilder("\"" + image + "\" " + (suspend ? "" : args[2]));
        var startup = new StartupInfoEx();
        var process = new ProcessInfo();
        var parent = IntPtr.Zero;
        var list = IntPtr.Zero;
        var initialized = false;
        try {
            if (suspend) {
                startup.startup.cb = Marshal.SizeOf(typeof(StartupInfo));
            } else {
                parent = OpenProcess(ProcessCreateProcess, false, UInt32.Parse(args[0]));
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
            }
            Require(CreateProcessW(image, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                suspend ? CreateSuspended : ExtendedStartupInfoPresent, IntPtr.Zero, IntPtr.Zero,
                ref startup, out process));
            if (suspend) {
                File.WriteAllText(args[2], process.pid.ToString());
                Console.ReadLine();
                return 0;
            }
            Require(WaitForSingleObject(process.process, 20000) == 0);
            uint status;
            Require(GetExitCodeProcess(process.process, out status));
            return (int)status;
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
        }
    }
}
