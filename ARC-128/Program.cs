#define deez_nuts
using System;
using c = System.Console;
using ARC;
using System.Security.Cryptography;
using System.Security;
using System.Text;


namespace Sandbox
{
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

            //c.WriteLine("\nIteration 0 test:");

            var testData = "This is random data lol eyufucbgfkuyvjsbgdfuikxkhfvbaskiuzghszdkfighawoieuskjghrfpiWUGEPI7FGwyWP9YUERP98SYGPIAHYEPSRDGYUAPEIHY";
            //c.WriteLine($"Test Data: {testData}\nTest Data length: {testData.Length}");

            var enc = arc.Encrypt(testData, key, iv);

            arc.PrintArray(enc, "Encryption result");
            c.WriteLine($"Encrypted data size (bytes): {enc.Length}");

            c.WriteLine("Attemting decryption...");

            

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
        }
    }
}