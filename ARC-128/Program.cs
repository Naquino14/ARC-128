#define deez_nuts
using System;
using c = System.Console;
using ADIS;
using System.Security.Cryptography;
using System.Security;
using System.Text;
using System.Drawing;

namespace Sandbox
{
#pragma warning disable CA1416
    public class Program
    {
        //readonly static byte[] iv = new byte[16] { 0x2F, 0x31, 0x46, 0xF2, 0xA3, 0xAC, 0x4A, 0x6F, 0x85, 0x0, 0xB7, 0xD3, 0xF1, 0x12, 0x34, 0x58 };

        public static void Main(string[] vs)
        {
            var arc = new ARC128();
            c.Write("IV: ");
            var iv = arc.GenerateIV();
            foreach (var x in iv)
                c.Write(x.ToString("X"));
            c.WriteLine($" Size: {iv.Length} bytes");

            c.Write(" K: ");
            var key = arc.GenerateKey();
            foreach (var y in key)
                c.Write(y.ToString("X"));
            c.WriteLine($" Size: {key.Length} bytes");

            #region expirimental sandboxes

            //c.WriteLine("Enter an input path:");
            //var path = c.ReadLine();
            //if (path == null)
            //    throw new ArgumentNullException();

            //c.WriteLine("Enter an output path:");
            //var output = c.ReadLine();
            //if (output == null)
            //    throw new ArgumentNullException("output");

            //var toEncImg = Image.FromFile(path);

            //var encBytes = imageToByteArray(toEncImg);

            //var encImg = arc.Encrypt(encBytes, key, iv);

            //var outImg = byteArrayToImage(encImg);

            //outImg.Save(path);

            #endregion

            #region old sandboxes

            //c.WriteLine("\nIteration 0 test:");
            c.WriteLine("Enter string to encrypt:");
            var testData = c.ReadLine();
            //c.WriteLine($"Test Data: {testData}\nTest Data length: {testData.Length}");
            c.WriteLine($"String to encrypt: {testData}");

            var enc = arc.Encrypt(testData ??= "nul", key, iv);

            ARC128.PrintArray(enc, "Encryption result");
            c.WriteLine($"Encrypted data size (bytes): {enc.Length}");

            c.WriteLine("Attempting decryption...");

            var dec = arc.Decrypt(enc, key, iv);

            ARC128.PrintArray(dec, "Raw decrypted data");
            var sData = Encoding.ASCII.GetString(dec);
            c.WriteLine($"Decrypted data size (bytes): {dec.Length} | Data: {sData}");

            c.WriteLine($"Encryption and decryption {(String.Equals(testData, sData) ? "Success!" : "Fail!")}");

            //byte[] tst = new byte[] { 0x0, 0x35, 0x37, 0xff, 0xd6, 0x0, 0x0, 0x0, 0x0 };
            //var arc = new ARC128();
            //var o = arc.REMED(tst);
            //arc.PrintArray(o);



            //c.WriteLine("\nIteration 1 test:");
            //var result2 = arc.Encrypt(testData, key, iv);

            //arc.PrintArray(result2, "Encryption result");
            //c.WriteLine($"Encrypted data size (bytes): {result2.Length}");

            //c.WriteLine(Enumerable.SequenceEqual(result1, result2) ? "Encryption psdRandom Gen success." : "Encryption psdRandom fail.");

            #region lookup table generation

            //var funcSB = ARCLT.GenerateSBLT();
            //c.WriteLine($"SBLT: {funcSB.msg}\n");

            //var funcMB = ARCLT.GenerateMBLT();
            //c.WriteLine($"MBLT: {funcMB.msg}\n");

            //var funcKS = ARCLT.GenerateKSLT();
            //c.WriteLine($"KSLT: {funcKS.msg}");

            #endregion

            //var schedule = arc.Schedule(key, iv, 0);

            #region MF testing

            //var arc = new ARC128(key, iv);
            //var mf0 = arc.ARCMF(iv, arc.Schedule(key, iv, 1));
            //arc.PrintArray(mf0, "Main Function Iteration 0 Results");
            //var mf1 = arc.ARCMF(iv, arc.Schedule(key, iv, 1));
            //arc.PrintArray(mf1, "Main Function Iteration 1 Results");
            //c.WriteLine(Enumerable.SequenceEqual(mf0, mf1) ? "MF Gen success." : "MF Gen fail.");

            #endregion
            ; // this is here bc breakpoint?

            #endregion
        }

        //public static byte[] imageToByteArray(Image imageIn)
        //{
        //    MemoryStream ms = new MemoryStream();
        //    imageIn.Save(ms, System.Drawing.Imaging.ImageFormat.Gif);
        //    return ms.ToArray();
        //}

        //public static Image byteArrayToImage(byte[] byteArrayIn)
        //{
        //    MemoryStream ms = new MemoryStream(byteArrayIn);
        //    Image returnImage = Image.FromStream(ms);
        //    return returnImage;
        //}
    }
}