#pragma skideeSkidoo wowie
// Copyright 2022 Nathaniel Aquino, All rights reserved.
// ARC128 version 1

using System.Text;
using c = System.Console;

namespace ARC
{
    public class ARC128
    {
        #region properties
        
        /// <summary>
        /// The data property of ARC-128. This is what gets encrypted unless data is supplied as a parameter.
        /// </summary>
        public byte[]? data { get; set; } // i didnt want to work with nullables, but im gonna try anyway
        public byte[]? key { get; private set; } // ok that wasnt so bad
        public byte[]? iv { get; private set; }

        #endregion

        #region constants

        private const string dEx = "Data is null! (Did you supply data in the constructor or as a parameter?)";
        private const string kEx = "Key is null! (Did you supply a key in the constructor or as a parameter?)";

        private const int readCount = 16;

        #endregion

        #region constructors
#pragma warning disable IDE0003

        /// <summary>
        /// Default constructor for ARC, Creates a new instance of ARC128 and leaves all properties null;
        /// </summary>
        public ARC128(){}

        /// <summary>
        /// Creates a new instance of ARC128(). Leaves data null, and any arguments unused also null.
        /// </summary>
        /// <param name="key">The key used when encrypting with ARC-128.This property is randomly generated if the parameter is null at the time ARC128() is called. Keys that are smaller than 16 bytes will be padded, and Keys larger than 16 bytes will be compressed into 16 bytes</param>
        /// <param name="iv">The IV string used when encrypting with ARC-128. This propery is randomly generated if the parameter is null at the time ARC128() is called. IVs that are smaller than 16 bytes will be padded, and IVs larger than 16 bytes will be compressed into 16 bytes.</param>
        public ARC128(byte[]? key = null, byte[]? iv = null)
        {
            this.key = key;
            this.iv = iv;
        }

        /// <summary>
        /// Creates a new instance of ARC128, and allows for arguments to be passed in. 
        /// </summary>
        /// <param name="data">The data to be encrypted with ARC-128. All data gets transformed into an array of bytes before being encrypted.</param>
        /// <param name="key">The key used when encrypting with ARC-128.This property is randomly generated if the parameter is null at the time ARC128() is called. Keys that are smaller than 16 bytes will be padded, and Keys larger than 16 bytes will be compressed into 16 bytes</param>
        /// <param name="iv">The Initialization Vector used when encrypting with ARC-128. This property is randomly generated if the parameter is null at the time ARC128() is called. IVs that are smaller than 16 bytes will be padded, and IVs larger than 16 bytes will be compressed into 16 bytes</param>
        public ARC128(byte[] data, byte[]? key = null, byte[]? iv = null) : this(key, iv) => this.data = data;

        /// <summary>
        /// Creates a new instance of ARC128, and allows for string representations of arguments to be passed in.
        /// </summary>
        /// <param name="data">The data string to be encrypted with ARC-128. All data gets transformed into an array of bytes before being encrypted.</param>
        /// <param name="key">The key string used when encrypting with ARC-128.This property is randomly generated if the parameter is null at the time ARC128() is called. Keys that are smaller than 16 bytes will be padded, and Keys larger than 16 bytes will be compressed into 16 bytes</param>
        /// <param name="iv">The IV string used when encrypting with ARC-128. This propery is randomly generated if the parameter is null at the time ARC128() is called. IVs that are smaller than 16 bytes will be padded, and IVs larger than 16 bytes will be compressed into 16 bytes.</param>
        public ARC128(string data, string? key = null, string? iv = null)
        {
            if (!ReferenceEquals(key, null))
                this.key = Encoding.ASCII.GetBytes(key);
            else
                this.key = GenerateKey();
            if (!ReferenceEquals(iv, null))
                this.iv = Encoding.ASCII.GetBytes(iv);
            else
                this.iv = GenerateIV();
            this.data = Encoding.ASCII.GetBytes(data);
        }

#pragma warning restore IDE0003
        #endregion


        #region encryption
        #pragma warning disable IDE0003

        #region overloads

        /// <summary>
        /// Encrypts supplied data using a supplied key and a supplied or auto-generated initialization vector.
        /// </summary>
        /// <returns>Data encrypted using ARC-128.</returns>
        /// <exception cref="ArgumentNullException">Exception thrown when data or the key property is empty.</exception>
        public byte[] Encrypt() /* => */{ return _Encrypt(this.data ?? throw new ArgumentNullException(dEx), this.key ?? throw new ArgumentNullException(kEx), this.iv ??= GenerateIV()); } // lambda in spirit 😔

        /// <summary>
        /// Encrypts the supplied string using a supplied key and a supplied or auto-generated initialization vector.
        /// </summary>
        /// <param name="message">The string to be encrypted using ARC-128.</param>
        /// <returns>Data encrypted using ARC-128.</returns>
        /// <exception cref="ArgumentNullException">Exception thrown when data or the key property is empty.</exception>
        public byte[] Encrypt(string message)
        { return _Encrypt(S2B(message), this.key ?? throw new ArgumentNullException(kEx), this.iv ??= GenerateIV()); }

        /// <summary>
        /// Encrypts the supplied string using the supplied key and the supplied initialization vector.
        /// </summary>
        /// <param name="message">The string to be encrypted using ARC-128.</param>
        /// <param name="key">The key to be used when encrypting the data with ARC-128. Throws an exeption when both the parameter and property are null.</param>
        /// <param name="iv">The initialization vector to be used when encrypting the data with ARC-128. Gets auto-generated when both the parameter and property are null.</param>
        /// <returns>Data encrypted using ARC-128.</returns>
        /// <exception cref="ArgumentNullException">Exception thrown when data or the key property is empty.</exception>
        public byte[] Encrypt(string message, byte[]? key = null, byte[]? iv = null)
        { return _Encrypt(S2B(message), key ?? this.key ?? throw new ArgumentNullException(kEx), iv ?? (this.iv ??= GenerateIV())); }

        public byte[] Encrypt(string message, string? key = null, string? iv = null)
        {
            byte[] _key = new byte[16], _iv = new byte[16];
            if (!ReferenceEquals(key, null))
            {
                var tocopy = Encoding.ASCII.GetBytes(key);
                tocopy = ModComp(16, tocopy);
                Array.Copy(tocopy, 0, _key, 0, 16);
                this.key = _key;
            }
            if (!ReferenceEquals(iv, null))
            {
                Array.Copy(ModComp(16, Encoding.ASCII.GetBytes(iv)), 0, _iv, 0, 16);
                this.iv = _iv;
            }
            return _Encrypt(S2B(message), this.key ?? throw new ArgumentNullException(kEx), this.iv ??= GenerateIV());
        }

        public byte[] Encrypt(byte[] data)
        { return _Encrypt(data, this.key ?? throw new ArgumentNullException(), this.iv ??= GenerateIV()); }

        /// <summary>
        /// Encrypts supplied data using a supplied key and a supplied or auto-generated initialization vector.
        /// </summary>
        /// <param name="data">The data to be encrypted using ARC-128.</param>
        /// <param name="key">The key to be used when encrypting the data with ARC-128. Throws an exeption when both the parameter and property are null.</param>
        /// <param name="iv">The initialization vector to be used when encrypting the data with ARC-128. Gets auto-generated when both the parameter and property are null.</param>
        /// <returns>Data encrypted using ARC-128.</returns>
        /// <exception cref="ArgumentNullException">Exception thrown when data or the key property is empty.</exception>
        public byte[] Encrypt(byte[] data, byte[]? key = null, byte[]? iv = null)
        { return _Encrypt(data, key ?? this.key ?? throw new ArgumentNullException(kEx), iv ?? (this.iv ??= GenerateIV())); }

        #endregion

        private byte[] _Encrypt(in byte[] data, in byte[] key, in byte[] iv) // cfb type encryption
        {
            // TODO: Pad data with 0x0?
            int fb = (data.Length / 16 * 16) + 1;
            var output = new byte[fb]; // tRuSt Me GuYs ItS sUpPoSeD tO dO tHiS

            /// for cfb, the IV gets tossed into the encryption first.
            /// the plaintext gets modded with the output, and then gets tossed into another encryption, 
            /// gets modded with the next block in the data, and the process repeats.
            /// im pretty sure as well that the IV, and each subblock can be ciphered multiple times before moving onto the next subblock. 
            /// obv thats computationally expensive but safer? i guess
            /// IV => ARC() => mod(out, subblock 1) => ARC() => mod(out, subblock 2) => ARC() => mod(out, subblock 3) => ect....
            /// regarding a previous comment abt multiple ciphers, yes, its allowed, and it will be done 9 times...
            /// I also just realized I forgot completely about key scheduling.... thats kind of a problem, but im gonna focus on it a little bit later.
            /// 

            /// I started drafing some sub-functions as well.
            /// Start: GetBlock(), can be either the IV or the previous contextual block
            /// start 9x loop
            /// ARCSBLT(a) := Sub Bytes Lookup Table => b | Confusion
            /// ARCBMGR(b) := Byte Merry Go Round    => c | Diffusion
            /// ARCPMB(c)  := Permutate Bytes        => d | Diffusion
            /// OTPArray(d, scheduledKey)            => f | Mix Key
            /// repeat                               => a

            PrintArray(data, "Incoming data");

            c.WriteLine($"Data size: {data.Length} | Total FB: {Math.Ceiling((double)(data.Length / 16))}");

            byte[] prevCtx = new byte[readCount], mf;
            var keys = Schedule(key);

            #region major compute loop

            int computationIteration = 0;
            bool computeFlag = true;

            while (computeFlag)
            {
                #region context block read and setup

                // get next block

                var ctx = GetBlock(data, computationIteration, ref computeFlag); // heads up, this auto-pads the incoming context with 0x0

                //PrintArray(ctx, $"Pre otp CTX for round {computationIteration} | Length: {ctx.Length}");

                // otp iv at ci 0 with uhe ctx i think?
                if (computationIteration != 0)
                    ctx = OTPArray(ctx, prevCtx);
                else
                    ctx = OTPArray(ctx, iv);

                #endregion

                //PrintArray(ctx, $"Post CTX for round {computationIteration} | Length: {ctx.Length}");

                // get MF results
                mf = ARCMF(ctx, keys); // TODO: replaced with scheduled key

                // otp results with data ctx, and toss it into the output
                Array.Copy(OTPArray(ctx, mf), 0, output, computationIteration * 16, 16); 

                prevCtx = ctx;
                computationIteration++;
            }

            #endregion

            return output;
        }

        #pragma warning restore IDE0003
        #endregion

        #region decryption
        //#pragma warning disable IDE0003

        //public byte[] Decrypt()

        //#pragma warning restore IDE0003
        #endregion


        #region generators

        public byte[] GenerateIV()
        {
            Random random = new Random();
            byte[] iv = new byte[16];
            random.NextBytes(iv);
            return iv;
        }

        public byte[] GenerateKey()
        { return GenerateIV(); }

        #endregion

        #region methods and funcs

        private byte[] ARCMF(in byte[] state, in byte[][] keys)
        {
            throw new NotImplementedException(); // TODO: this
        }

        private byte[][] Schedule(in byte[] key)
        {
            byte[][] schedule = new byte[9][];
            for (int i = 0; i < 9; i++)
            {
                throw new NotImplementedException(); // TODO: key scheduling algorithm
            }
            return schedule;
        }

        private byte[] GetBlock(byte[] data, int ci, ref bool computeFlag)
        {
            int targetIndex = ci * readCount,
                    toRead = data.Length - readCount * ci,
                    targetLength;
            var ctx = new byte[readCount];
            if (toRead < readCount)
            {
                targetLength = toRead;
                computeFlag = false;
            }
            else
                targetLength = readCount;
            Array.Copy(data, targetIndex, ctx, 0, readCount - (readCount - targetLength));
            return ctx;
        }

        internal byte[] ModComp(int s, byte[] a)
        {
            var o = new byte[s];

            if (a.Length < s)
            {
                int r = s - a.Length;
                var pad = CreatePadArray(0x0, r);
                o = AddArray(a, pad);
            } else if (a.Length != s)
            {
                var fb = a.Length / s;
                var resSbs = new byte[fb][];
                for (var i = 0; i <= (fb - 1); i++)
                    resSbs[i] = FCArray(a, i * s, s);

                bool s1fo = true;
                o = resSbs[0];
                foreach (var sb in resSbs)
                {
                    if (!s1fo)
                        o = OTPArray(o, sb);
                    else
                        s1fo = false;
                }
            }
            return o;
        }

        private byte[] S2B(string a)
        { return Encoding.ASCII.GetBytes(a); }

        #region Array Funcs

        private byte[] FCArray(byte[] input, int s, int c)
        {
            byte[] result = new byte[c];
            Array.Copy(input, s, result, 0, c);
            return result;
        }

        private byte[] AddArray(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            a.CopyTo(result, 0);
            b.CopyTo(result, a.Length);
            return result;
        }

        private byte[] OTPArray(byte[] input, byte[] key)
        {
            byte[] result = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                result[i] = (byte)(input[i] ^ key[i]);
            return result;
        }

        internal void PrintArray(byte[] array, string name = "")
        {
            if (name != "")
                Console.Write($"{name}: ");
            foreach (byte byt in array)
                Console.Write(byt.ToString("X"));
            Console.WriteLine();
        }

        private byte[] CreatePadArray(byte b, int c)
        {
            byte[] result = new byte[c];
            for (int i = 0; i < c; i++)
                result[i] = b;
            return result;
        }

        private byte[] RotRight(byte[] a, int amount)
        { return a.Skip(a.Length - amount).Concat(a.Take(a.Length - amount)).ToArray(); }

        private byte[] RotLeft(byte[] a, int amount)
        { return a.Skip(amount).Concat(a.Take(amount)).ToArray(); }

        #endregion

        #endregion
    }
}
