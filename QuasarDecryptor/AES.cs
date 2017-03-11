using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace QuasarDecryptor
{
    // Token: 0x020000CC RID: 204
    public static class AES
    {
        // Token: 0x060004EF RID: 1263 RVA: 0x0000D274 File Offset: 0x0000B474
        public static void SetDefaultKey(string key)
        {
            using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(key, AES.Salt, 50000))
            {
                AES._defaultKey = rfc2898DeriveBytes.GetBytes(16);
                AES._defaultAuthKey = rfc2898DeriveBytes.GetBytes(64);
            }
        }

        // Token: 0x060004F0 RID: 1264 RVA: 0x0000D2C8 File Offset: 0x0000B4C8
        public static void SetDefaultKey(string key, string authKey)
        {
            AES._defaultKey = Convert.FromBase64String(key);
            AES._defaultAuthKey = Convert.FromBase64String(authKey);
        }

        // Token: 0x060004F1 RID: 1265 RVA: 0x0000D2E0 File Offset: 0x0000B4E0
        public static string Encrypt(string input, string key)
        {
            return Convert.ToBase64String(AES.Encrypt(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(key)));
        }

        // Token: 0x060004F2 RID: 1266 RVA: 0x0000D304 File Offset: 0x0000B504
        public static string Encrypt(string input)
        {
            return Convert.ToBase64String(AES.Encrypt(Encoding.UTF8.GetBytes(input)));
        }

        // Token: 0x060004F3 RID: 1267 RVA: 0x0000D31C File Offset: 0x0000B51C
        public static byte[] Encrypt(byte[] input)
        {
            if (AES._defaultKey == null || AES._defaultKey.Length == 0)
            {
                throw new Exception("Key can not be empty.");
            }
            if (input == null || input.Length == 0)
            {
                throw new ArgumentException("Input can not be empty.");
            }
            byte[] result = new byte[0];
            try
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Position = 32L;
                    using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
                    {
                        aesCryptoServiceProvider.KeySize = 128;
                        aesCryptoServiceProvider.BlockSize = 128;
                        aesCryptoServiceProvider.Mode = CipherMode.CBC;
                        aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;
                        aesCryptoServiceProvider.Key = AES._defaultKey;
                        aesCryptoServiceProvider.GenerateIV();
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesCryptoServiceProvider.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            memoryStream.Write(aesCryptoServiceProvider.IV, 0, aesCryptoServiceProvider.IV.Length);
                            cryptoStream.Write(input, 0, input.Length);
                            cryptoStream.FlushFinalBlock();
                            using (HMACSHA256 hMACSHA = new HMACSHA256(AES._defaultAuthKey))
                            {
                                byte[] array = hMACSHA.ComputeHash(memoryStream.ToArray(), 32, memoryStream.ToArray().Length - 32);
                                memoryStream.Position = 0L;
                                memoryStream.Write(array, 0, array.Length);
                            }
                        }
                    }
                    result = memoryStream.ToArray();
                }
            }
            catch
            {
            }
            return result;
        }

        // Token: 0x060004F4 RID: 1268 RVA: 0x0000D4A0 File Offset: 0x0000B6A0
        public static byte[] Encrypt(byte[] input, byte[] key)
        {
            if (key == null || key.Length == 0)
            {
                throw new Exception("Key can not be empty.");
            }
            byte[] bytes;
            using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(key, AES.Salt, 50000))
            {
                key = rfc2898DeriveBytes.GetBytes(16);
                bytes = rfc2898DeriveBytes.GetBytes(64);
            }
            byte[] result = new byte[0];
            try
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Position = 32L;
                    using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
                    {
                        aesCryptoServiceProvider.KeySize = 128;
                        aesCryptoServiceProvider.BlockSize = 128;
                        aesCryptoServiceProvider.Mode = CipherMode.CBC;
                        aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;
                        aesCryptoServiceProvider.Key = key;
                        aesCryptoServiceProvider.GenerateIV();
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesCryptoServiceProvider.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            memoryStream.Write(aesCryptoServiceProvider.IV, 0, aesCryptoServiceProvider.IV.Length);
                            cryptoStream.Write(input, 0, input.Length);
                            cryptoStream.FlushFinalBlock();
                            using (HMACSHA256 hMACSHA = new HMACSHA256(bytes))
                            {
                                byte[] array = hMACSHA.ComputeHash(memoryStream.ToArray(), 32, memoryStream.ToArray().Length - 32);
                                memoryStream.Position = 0L;
                                memoryStream.Write(array, 0, array.Length);
                            }
                        }
                    }
                    result = memoryStream.ToArray();
                }
            }
            catch
            {
            }
            return result;
        }

        // Token: 0x060004F5 RID: 1269 RVA: 0x0000D69C File Offset: 0x0000B89C
        public static string Decrypt(string input)
        {
            return Encoding.UTF8.GetString(AES.Decrypt(Convert.FromBase64String(input)));
        }

        // Token: 0x060004F6 RID: 1270 RVA: 0x0000D6B4 File Offset: 0x0000B8B4
        public static byte[] Decrypt(byte[] input)
        {
            if (AES._defaultKey == null || AES._defaultKey.Length == 0)
            {
                throw new Exception("Key can not be empty.");
            }
            if (input == null || input.Length == 0)
            {
                throw new ArgumentException("Input can not be empty.");
            }
            byte[] array = new byte[0];
            try
            {
                using (MemoryStream memoryStream = new MemoryStream(input))
                {
                    using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
                    {
                        aesCryptoServiceProvider.KeySize = 128;
                        aesCryptoServiceProvider.BlockSize = 128;
                        aesCryptoServiceProvider.Mode = CipherMode.CBC;
                        aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;
                        aesCryptoServiceProvider.Key = AES._defaultKey;
                        using (HMACSHA256 hMACSHA = new HMACSHA256(AES._defaultAuthKey))
                        {
                            byte[] arg_AE_0 = hMACSHA.ComputeHash(memoryStream.ToArray(), 32, memoryStream.ToArray().Length - 32);
                            byte[] array2 = new byte[32];
                            memoryStream.Read(array2, 0, array2.Length);
                            if (!AreEqual(arg_AE_0, array2))
                            {
                                return array;
                            }
                        }
                        byte[] array3 = new byte[16];
                        memoryStream.Read(array3, 0, 16);
                        aesCryptoServiceProvider.IV = array3;
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesCryptoServiceProvider.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            byte[] array4 = new byte[memoryStream.Length - 16L + 1L];
                            array = new byte[cryptoStream.Read(array4, 0, array4.Length)];
                            Buffer.BlockCopy(array4, 0, array, 0, array.Length);
                        }
                    }
                }
            }
            catch
            {
            }
            return array;
        }

        // Token: 0x060004F7 RID: 1271 RVA: 0x0000D898 File Offset: 0x0000BA98
        static AES()
        {
            // Note: this type is marked as 'beforefieldinit'.
        }

        public static bool AreEqual(byte[] a1, byte[] a2)
        {
            bool result = true;
            for (int i = 0; i < a1.Length; i++)
            {
                if (a1[i] != a2[i])
                {
                    result = false;
                }
            }
            return result;
        }

        // Token: 0x04000253 RID: 595
        private const int IvLength = 16;

        // Token: 0x04000254 RID: 596
        private const int HmacSha256Length = 32;

        // Token: 0x04000255 RID: 597
        private static byte[] _defaultKey;

        // Token: 0x04000256 RID: 598
        private static byte[] _defaultAuthKey;

        // Token: 0x04000257 RID: 599
        public static readonly byte[] Salt = new byte[]
        {
            191,
            235,
            30,
            86,
            251,
            205,
            151,
            59,
            178,
            25,
            2,
            36,
            48,
            165,
            120,
            67,
            0,
            61,
            86,
            68,
            210,
            30,
            98,
            185,
            212,
            241,
            128,
            231,
            230,
            195,
            57,
            65
        };
    }



}
