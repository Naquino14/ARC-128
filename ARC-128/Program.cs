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
        public static void Main(string[] vs)
        {
            //using (Aes aes = Aes.Create())
            //{
            //    aes.Key = Encoding.ASCII.GetBytes("funnie key moment");
            //    // nah this is inconvenient to use
            //}

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

            arc.Encrypt("This is random data loleyufucbgfkuyvjsbgdfuikxkhfvbaskiuzghszdkfighawoieuskjghrfpiWUGEPI7FGwyWP9YUERP98SYGPIAHYEPSRDGYUAPEIHY", key, iv);
        }
    }
}