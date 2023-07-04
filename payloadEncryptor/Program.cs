using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;


namespace payloadEncryptor
{
    internal class Program
    {
        static String payload_aes_password = "ricardojoserf123ricardojoserf123";
        static String payload_aes_iv = "jeringa1jeringa1";

        static String EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(encrypted);
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


        public static byte[] ToByteArray(String hexString)
        {
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }


        static void getHelp()
        {
            Console.WriteLine("\n[*] To encrypt a HEX payload:");
            Console.WriteLine("payloadEncryptor.exe hex HEXADECIMAL_PAYLOAD");
            Console.WriteLine("[*] Example:");
            Console.WriteLine("payloadEncryptor.exe hex fc4883e4f0e8...");

            Console.WriteLine("\n[*] To encrypt a RAW payload:");
            Console.WriteLine("payloadEncryptor.exe raw INPUTFILE OUTPUTFILE");
            Console.WriteLine("[*] Example:");
            Console.WriteLine("payloadEncryptor.exe raw payload.bin payload_encrypted.bin");

            System.Environment.Exit(0);
        }


        static String encryptText(byte[] payloadBytes)
        {
            String payloadBase64 = Convert.ToBase64String(payloadBytes);
            RijndaelManaged myRijndael = new RijndaelManaged();
            String encrypted = EncryptStringToBytes(payloadBase64, Encoding.ASCII.GetBytes(payload_aes_password), Encoding.ASCII.GetBytes(payload_aes_iv));
            return encrypted;
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
                Console.WriteLine("[-] It was not possible to decrypt the payload - Probably not using AES encryption.");
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
                Console.WriteLine("[+] It was possible to decrypt the file.");
                return decryptedBytes;
            }
            catch
            {
                Console.WriteLine("[-] It was not possible to decrypt the file - Probably not using AES encryption.");
                return encryptedBytes;

            }
        }


        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                getHelp();
            }

            String option = args[0];
            String payload = args[1];

            if (option == "hex")
            {
                byte[] bytesPayload = ToByteArray(payload);
                String encryptedPayload = encryptText(bytesPayload);
                Console.WriteLine(encryptedPayload);
            }

            else if (option == "raw")
            {
                String outputfile = args[2];
                byte[] bytesPayload = File.ReadAllBytes(payload);
                String encryptedPayload = encryptText(bytesPayload);
                byte[] encryptedBytes = Convert.FromBase64String(encryptedPayload);
                Console.WriteLine("\n[+] Creating file: " + outputfile);
                File.WriteAllBytes(outputfile, encryptedBytes);
            }

            else if (option == "decrypt-hex")
            {
                byte[] decryptedBytes = tryToDecryptString(payload);
                Console.WriteLine("\nRaw bytes: \n" + Encoding.UTF8.GetString(decryptedBytes));
                Console.WriteLine("\nBase64:    \n" + Convert.ToBase64String(decryptedBytes));
            }

            else if (option == "decrypt-raw")
            {
                byte[] encryptedBytes = File.ReadAllBytes(payload);
                byte[] decryptedBytes = tryToDecryptFile(encryptedBytes);
                Console.WriteLine("\nRaw bytes: \n" + Encoding.UTF8.GetString(decryptedBytes));
                Console.WriteLine("\nBase64:    \n" + Convert.ToBase64String(decryptedBytes));
            }

            else
            {
                getHelp();
            }


        }
    }
}
