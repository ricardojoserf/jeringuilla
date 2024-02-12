using System;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Principal;

using static jeringuilla.Win32;
using static jeringuilla.HelperFunctions;


namespace jeringuilla
{
    internal class ProcessFunctions
    {
        private static string getProcessOwner(Process process)
        {
            IntPtr k32 = GetLibAddress("1GAd1/G7gM4sph/yC0uQLg==");
            IntPtr a32 = GetLibAddress("9dOYL40gX4b0hNu/qgaXgA==");
            OpenProcessTokenDelegate auxOpenProcessToken = (OpenProcessTokenDelegate)GetFuncDelegate(a32, "sF3ICi5AMd+hES18ADsvonBk3cp8AKV1ZyuKqaotGS8=", typeof(OpenProcessTokenDelegate));
            CloseHandleDelegate auxCloseHandle = (CloseHandleDelegate)GetFuncDelegate(k32, "raaWfwu7TWCs4mgnq8Pytg==", typeof(CloseHandleDelegate));
            
            IntPtr processHandle = IntPtr.Zero;
            try
            {
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
                    auxCloseHandle(processHandle);
                }
            }
        }


        public static Dictionary<string, string> getProcessPids(String process_name)
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


        public static void listInfo(Dictionary<string, string> processPIDs)
        {
            Console.WriteLine("{0,40} | {1,10} | {2,20}", "Process Name", "PID", "Process Owner");
            Console.WriteLine(string.Concat(Enumerable.Repeat("-", 80)));
            foreach (KeyValuePair<string, string> kvp in processPIDs)
            {
                Console.WriteLine("{0,40} | {1,10} | {2,20}", Process.GetProcessById(Int32.Parse(kvp.Key)).ProcessName, kvp.Key, kvp.Value);
            }
        }
    }
}
