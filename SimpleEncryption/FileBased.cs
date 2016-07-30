using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption
{
    public class FileBased
    {
        private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes("Enc-v1");

        private const int IvLength = 128 >> 3;

        public static void Decrypt(string pwd, string fileIn, string fileOut)
        {
            var keys = GetKeys(pwd);

            byte[] magicBytes = new byte[MagicBytes.Length];
            byte[] hmacHash = new byte[MacLength];
            byte[] newHmacHash;
            byte[] iv = new byte[IvLength];

            using (FileStream encryptedStream = new FileStream(fileIn, FileMode.Open, FileAccess.Read))
            {
                encryptedStream.Read(magicBytes, 0, MagicBytes.Length);
                encryptedStream.Read(iv, 0, IvLength);
                encryptedStream.Read(hmacHash, 0, MacLength);
            }

            if (!MagicBytes.SequenceEqual(magicBytes))
            {
                File.Delete(fileOut);
                throw new CryptographicException("MagicBytes are corrupt");
            }

            try
            {
                using (var aesManaged = CreateAesManaged(iv, keys.Item1))
                {
                    var encryptor = aesManaged.CreateDecryptor(aesManaged.Key, aesManaged.IV);
                    var hmacsha512 = new HMACSHA512(keys.Item2);

                    using (var plainStream = File.OpenWrite(fileOut))
                    {
                        using (var aesStream = new CryptoStream(plainStream, encryptor, CryptoStreamMode.Write))
                        {
                            using (var hmacStream = new CryptoStream(aesStream, hmacsha512, CryptoStreamMode.Write))
                            {
                                using (var encryptedStream = File.OpenRead(fileIn))
                                {
                                    var offset = MagicBytes.Length + IvLength + MacLength;
                                    encryptedStream.Position = offset;
                                    encryptedStream.CopyTo(hmacStream);
                                }
                            }
                        }
                    }
                    newHmacHash = hmacsha512.Hash;
                }
            }
            catch (Exception)
            {
                File.Delete(fileOut);
                throw;
            }

            if (!hmacHash.SequenceEqual(newHmacHash))
            {
                File.Delete(fileOut);
                throw new CryptographicException("HMAC hash is corrupt");
            }
        }

        public static void Encrypt(string pwd, string fileIn, string fileOut)
        {
            var keys = GetKeys(pwd);

            var iv = new byte[IvLength];
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(iv);
            }

            byte[] hmacHash;
            using (var aesManaged = CreateAesManaged(iv, keys.Item1))
            {
                var encryptor = aesManaged.CreateEncryptor(aesManaged.Key, aesManaged.IV);
                var hmacsha512 = new HMACSHA512(keys.Item2);

                using (var encryptedStream = File.OpenWrite(fileOut))
                {
                    var offset = MagicBytes.Length + IvLength + MacLength;
                    encryptedStream.SetLength(offset);
                    encryptedStream.Position = offset;

                    using (var hmacStream = new CryptoStream(encryptedStream, hmacsha512, CryptoStreamMode.Write))
                    {
                        using (var aesStream = new CryptoStream(hmacStream, encryptor, CryptoStreamMode.Write))
                        {
                            using (var plainStream = File.OpenRead(fileIn))
                            {
                                plainStream.CopyTo(aesStream);
                            }
                        }
                    }
                }
                hmacHash = hmacsha512.Hash;
            }

            using (var encryptedStream = File.OpenWrite(fileOut))
            {
                new MemoryStream(MagicBytes).CopyTo(encryptedStream);
                new MemoryStream(iv).CopyTo(encryptedStream);
                new MemoryStream(hmacHash).CopyTo(encryptedStream);
            }
        }


        private const int AesKeyLength = 256 >> 3;
        private const int MacLength = 512 >> 3;

#if DEBUG
        private const int Iterations = 1000;
#else
        private const int Iterations = 100000; // around 5s on an i7
#endif

        private static readonly byte[] Salt = Guid.Parse("{28BF78E1-D011-4AA1-B046-500F19DF5139}").ToByteArray();

        private static Tuple<byte[], byte[]> GetKeys(string pwd)
        {
            var deriveBytes = new Rfc2898DeriveBytes(pwd, Salt, Iterations).GetBytes(AesKeyLength + MacLength);
            var aesKey = deriveBytes.Skip(0).Take(AesKeyLength).ToArray();
            var hmacKey = deriveBytes.Skip(AesKeyLength).Take(MacLength).ToArray();

            return new Tuple<byte[], byte[]>(aesKey, hmacKey);
        }


        private static AesManaged CreateAesManaged(byte[] iv, byte[] aesKey)
        {
            var aesManaged = new AesManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,
                KeySize = 256,
                IV = iv,
                Key = aesKey
            };

            return aesManaged;
        }
    }
}