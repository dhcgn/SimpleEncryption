using System;
using System.Dynamic;
using System.IO;

namespace SimpleEncryption.Sample
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var filePlain = "file.txt";
            var fileEncrypted = "file.txt.enc";
            var fileDecrypted = "file.txt.org";

            var msg = "Hello World";
            File.WriteAllText(filePlain, msg);
            Console.Out.WriteLine("Will encrypt: " + msg);

            FileBased.Encrypt("qwert", filePlain, fileEncrypted);
            Console.Out.WriteLine("Encrypted: " + Convert.ToBase64String(File.ReadAllBytes(fileEncrypted)));

            FileBased.Decrypt("qwert", fileEncrypted, fileDecrypted);
            Console.Out.WriteLine("Decrypted: "+File.ReadAllText(fileDecrypted));
            
            Console.Out.WriteLine("Any key ...");
            Console.ReadKey();
        }
    }
}