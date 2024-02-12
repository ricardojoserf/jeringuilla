using System;

namespace jeringuilla
{
    internal class Configuration
    {
        // If you change any of these 2 values you will have to change the AES-encrypted DLL and function names
        public static String strings_aes_password = "ricardojoserf   ";
        public static String strings_aes_iv = "jeringa jeringa ";
        // If you update any of these 2 values, update it in payloadEncryptor
        public static String payload_aes_password = "ricardojoserf123ricardojoserf123";
        public static String payload_aes_iv = "jeringa1jeringa1";
    }
}
