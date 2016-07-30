using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace SimpleEncryption.Test
{
    [TestFixture]
    public class BlackBoxTest
    {
        [SetUp]
        public void SetUpAttribute()
        {
            fileIn = Path.GetTempFileName();
            fileOut = Path.GetTempFileName();
            fileAssert = Path.GetTempFileName();

            File.WriteAllText(fileIn, "Hello World");
        }

        [TearDown]
        public void TearDownAttribute()
        {
            Console.Out.WriteLine("in:     " + (File.Exists(fileIn) ? BitConverter.ToString(File.ReadAllBytes(fileIn)) : "not found"));
            Console.Out.WriteLine("out:    " + (File.Exists(fileOut) ? BitConverter.ToString(File.ReadAllBytes(fileOut)): "not found"));
            Console.Out.WriteLine("assert: " + (File.Exists(fileAssert) ? BitConverter.ToString(File.ReadAllBytes(fileAssert)): "not found"));

            foreach (var file in new[] {fileIn, fileOut, fileAssert})
            {
                try
                {
                    File.Delete(file);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
        }

        [Test]
        public void Sucess()
        {
            FileBased.Encrypt("qwert", fileIn, fileOut);
            FileBased.Decrypt("qwert", fileOut, fileAssert);

            FileAssert.AreEqual(fileIn, fileAssert);
        }

        [Test]
        public void BadPassword()
        {
            FileBased.Encrypt("qwert", fileIn, fileOut);

            Assert.Throws<CryptographicException>(() => FileBased.Decrypt("password", fileOut, fileAssert));

            FileAssert.DoesNotExist(fileAssert);
        }

        private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes("Enc-v1");
        private string fileIn;
        private string fileOut;
        private string fileAssert;
        private const int MacLength = 512 >> 3;
        private const int IvLength = 128 >> 3;

        [Test]
        public void BadHmac()
        {
            FileBased.Encrypt("qwert", fileIn, fileOut);

            using (var fileWriter = new BinaryWriter(File.Open(fileOut, FileMode.Open)))
            {
                fileWriter.BaseStream.Position = MagicBytes.Length + IvLength + (MacLength/2)+1;
                fileWriter.Write(0);
                fileWriter.BaseStream.Position = MagicBytes.Length + IvLength + (MacLength/2) + 2;
                fileWriter.Write(0);
            }
            Assert.Throws<CryptographicException>(() => FileBased.Decrypt("qwert", fileOut, fileAssert));

            FileAssert.DoesNotExist(fileAssert);
        }

        [Test]
        public void BadEncryptedFile()
        {
            FileBased.Encrypt("qwert", fileIn, fileOut);

            using (var fileWriter = new BinaryWriter(File.Open(fileOut, FileMode.Open)))
            {
                fileWriter.BaseStream.Position = MagicBytes.Length + IvLength + MacLength + 1;
                fileWriter.Write(0);
                fileWriter.BaseStream.Position = MagicBytes.Length + IvLength + MacLength + 2;
                fileWriter.Write(0);
            }
            Assert.Throws<CryptographicException>(() => FileBased.Decrypt("qwert", fileOut, fileAssert));

            FileAssert.DoesNotExist(fileAssert);
        }

        [Test]
        public void BadIV()
        {
            FileBased.Encrypt("qwert", fileIn, fileOut);

            using (var fileWriter = new BinaryWriter(File.Open(fileOut, FileMode.Open)))
            {
                fileWriter.BaseStream.Position = MagicBytes.Length + IvLength/2 + 1;
                fileWriter.Write(0);
                fileWriter.BaseStream.Position = MagicBytes.Length + IvLength/2+ 2;
                fileWriter.Write(0);
            }
            Assert.Throws<CryptographicException>(() => FileBased.Decrypt("qwert", fileOut, fileAssert));

            FileAssert.DoesNotExist(fileAssert);
        }

        [Test]
        public void BadMagicBytes()
        {
            FileBased.Encrypt("qwert", fileIn, fileOut);

            using (var fileWriter = new BinaryWriter(File.Open(fileOut, FileMode.Open)))
            {
                fileWriter.BaseStream.Position = MagicBytes.Length/2 + 1;
                fileWriter.Write(0);
                fileWriter.BaseStream.Position = MagicBytes.Length/2 + 2;
                fileWriter.Write(0);
            }
            Assert.Throws<CryptographicException>(() => FileBased.Decrypt("qwert", fileOut, fileAssert));

            FileAssert.DoesNotExist(fileAssert);
        }
    }
}