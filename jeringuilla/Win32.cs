using System;
using System.Runtime.InteropServices;

namespace jeringuilla
{
    internal class Win32
    {
        ///////////////// FUNCTION DELEGATES ///////////////// 
        public delegate IntPtr OpenProcessDelegate(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        public delegate bool OpenProcessTokenDelegate(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        public delegate bool CloseHandleDelegate(
            IntPtr hObject);

        public delegate IntPtr VirtualAllocExDelegate(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        public delegate bool WriteProcessMemoryDelegate(
            IntPtr hProcess, 
            IntPtr lpBaseAddress, 
            byte[] lpBuffer, 
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        public delegate IntPtr CreateRemoteThreadDelegate(
            IntPtr hProcess, 
            IntPtr lpThreadAttributes, 
            uint dwStackSize, 
            IntPtr lpStartAddress, 
            IntPtr lpParameter, 
            uint dwCreationFlags, 
            IntPtr lpThreadId);

        public delegate bool CreateProcessDelegate(
            string lpApplicationName,
            string lpCommandLine, 
            IntPtr lpProcessAttributes, 
            IntPtr lpThreadAttributes, 
            bool bInheritHandles, 
            uint dwCreationFlags, 
            IntPtr lpEnvironment, 
            string lpCurrentDirectory, 
            ref STARTUPINFO lpStartupInfo, 
            out PROCESS_INFORMATION lpProcessInformation);

        public delegate uint QueueUserAPCDelegate(
            IntPtr pfnAPC, 
            IntPtr hThread, 
            uint dwData);

        public delegate uint ResumeThreadDelegate(
            IntPtr hThread);

        public delegate IntPtr OpenThreadDelegate(
            uint dwDesiredAccess, 
            bool bInheritHandle, 
            uint dwThreadId);


        //////////////////// FUNCTIONS //////////////////// 
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr pbi,
            uint processInformationLength,
            out IntPtr returnLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern bool NtReadVirtualMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );


        ////////////////////// STRUCTS ////////////////////// 
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }


        //////////////////// CONSTANTS //////////////////// 
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    }
}
