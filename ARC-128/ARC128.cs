﻿#define ARC_DEBUG
// Copyright 2022 Nathaniel Aquino, All rights reserved.
// ARC128 version 1

using System.Security.Cryptography;
using System.Text;
using c = System.Console;

namespace ADIS
{
    public class ARC128
    {
        #region properties
        
        /// <summary>
        /// The data property of ARC-128. This is what gets encrypted unless data is supplied as a parameter.
        /// </summary>
        public byte[]? Data { get; set; } // i didnt want to work with nullables, but im gonna try anyway
        public byte[]? Key { get; private set; } // ok that wasnt so bad
        public byte[]? IV { get; private set; }
        public bool removeExtraneousData = true;

        #endregion

        #region constants

        private const string dEx = "Data is null! (Did you supply data in the constructor or as a parameter?)";
        private const string kEx = "Key is null! (Did you supply a key in the constructor or as a parameter?)";

        private const int readCount = 16;

        private const byte KSRcon1 = 0x05,
            KSRcon2 = 0x07,
            KSRcon3 = 0x0A,
            KSRcon4 = 0x3D,
            KSRcon5 = 0x4F,
            KSRcon6 = 0x5D,
            KSRcon7 = 0xAB,
            KSRcon8 = 0xEF,
            KSRcon9 = 0xAB;

        private readonly byte[] KSRcon = new byte[] { KSRcon1, KSRcon2, KSRcon3, KSRcon4, KSRcon5, KSRcon6, KSRcon7, KSRcon8, KSRcon9 };

        private readonly byte[] extreneous = new byte[16] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

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
            this.Key = key;
            this.IV = iv;
        }

        /// <summary>
        /// Creates a new instance of ARC128, and allows for arguments to be passed in. 
        /// </summary>
        /// <param name="data">The data to be encrypted with ARC-128. All data gets transformed into an array of bytes before being encrypted.</param>
        /// <param name="key">The key used when encrypting with ARC-128.This property is randomly generated if the parameter is null at the time ARC128() is called. Keys that are smaller than 16 bytes will be padded, and Keys larger than 16 bytes will be compressed into 16 bytes</param>
        /// <param name="iv">The Initialization Vector used when encrypting with ARC-128. This property is randomly generated if the parameter is null at the time ARC128() is called. IVs that are smaller than 16 bytes will be padded, and IVs larger than 16 bytes will be compressed into 16 bytes</param>
        public ARC128(byte[] data, byte[]? key = null, byte[]? iv = null) : this(key, iv) => this.Data = data;

        /// <summary>
        /// Creates a new instance of ARC128, and allows for string representations of arguments to be passed in.
        /// </summary>
        /// <param name="data">The data string to be encrypted with ARC-128. All data gets transformed into an array of bytes before being encrypted.</param>
        /// <param name="key">The key string used when encrypting with ARC-128.This property is randomly generated if the parameter is null at the time ARC128() is called. Keys that are smaller than 16 bytes will be padded, and Keys larger than 16 bytes will be compressed into 16 bytes</param>
        /// <param name="iv">The IV string used when encrypting with ARC-128. This propery is randomly generated if the parameter is null at the time ARC128() is called. IVs that are smaller than 16 bytes will be padded, and IVs larger than 16 bytes will be compressed into 16 bytes.</param>
        public ARC128(string data, string? key = null, string? iv = null)
        {
            if (key is not null)
                this.Key = Encoding.ASCII.GetBytes(key);
            else
                this.Key = GenerateKey();
            if (iv is not null)
                this.IV = Encoding.ASCII.GetBytes(iv);
            else
                this.IV = GenerateIV();
            this.Data = Encoding.ASCII.GetBytes(data);
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
        public byte[] Encrypt()
            => InternalEncrypt(this.Data ?? throw new ArgumentNullException(dEx), this.Key ?? throw new ArgumentNullException(nameof(Key), kEx), this.IV ??= GenerateIV());

        /// <summary>
        /// Encrypts the supplied string using a supplied key and a supplied or auto-generated initialization vector.
        /// </summary>
        /// <param name="message">The string to be encrypted using ARC-128.</param>
        /// <returns>Data encrypted using ARC-128.</returns>
        /// <exception cref="ArgumentNullException">Exception thrown when data or the key property is empty.</exception>
        public byte[] Encrypt(string message)
            => InternalEncrypt(S2B(message), this.Key ?? throw new ArgumentNullException(nameof(Key), kEx), this.IV ??= GenerateIV());

        /// <summary>
        /// Encrypts the supplied string using the supplied key and the supplied initialization vector.
        /// </summary>
        /// <param name="message">The string to be encrypted using ARC-128.</param>
        /// <param name="key">The key to be used when encrypting the data with ARC-128. Throws an exeption when both the parameter and property are null.</param>
        /// <param name="iv">The initialization vector to be used when encrypting the data with ARC-128. Gets auto-generated when both the parameter and property are null.</param>
        /// <returns>Data encrypted using ARC-128.</returns>
        /// <exception cref="ArgumentNullException">Exception thrown when data or the key property is empty.</exception>
        public byte[] Encrypt(string message, byte[]? key = null, byte[]? iv = null)
            => InternalEncrypt(S2B(message), key ?? this.Key ?? throw new ArgumentNullException(nameof(key), kEx), iv ?? (this.IV ??= GenerateIV()));

        public byte[] Encrypt(string message, string? key = null, string? iv = null)
        {
            byte[] _key = new byte[16], _iv = new byte[16];
            if (key is not null)
            {
                Array.Copy(BlockComp(16, Encoding.ASCII.GetBytes(key)), 0, _key, 0, 16);
                this.Key = _key;
            }
            if (iv is not null)
            {
                Array.Copy(BlockComp(16, Encoding.ASCII.GetBytes(iv)), 0, _iv, 0, 16);
                this.IV = _iv;
            }
            return Encrypt(message);
        }

        public byte[] Encrypt(byte[] data)
            => InternalEncrypt(data, this.Key ?? throw new ArgumentNullException(nameof(Key), kEx), this.IV ??= GenerateIV());

        /// <summary>
        /// Encrypts supplied data using a supplied key and a supplied or auto-generated initialization vector.
        /// </summary>
        /// <param name="data">The data to be encrypted using ARC-128.</param>
        /// <param name="key">The key to be used when encrypting the data with ARC-128. Throws an exeption when both the parameter and property are null.</param>
        /// <param name="iv">The initialization vector to be used when encrypting the data with ARC-128. Gets auto-generated when both the parameter and property are null.</param>
        /// <returns>Data encrypted using ARC-128.</returns>
        /// <exception cref="ArgumentNullException">Exception thrown when data or the key property is empty.</exception>
        public byte[] Encrypt(byte[] data, byte[]? key = null, byte[]? iv = null)
            => InternalEncrypt(data, key ?? this.Key ?? throw new ArgumentNullException(nameof(Key), kEx), iv ?? (this.IV ??= GenerateIV()));
        
        #endregion

        private byte[] InternalEncrypt(in byte[] data, in byte[] key, in byte[] iv) // cfb type encryption
        {
            // TODO: Pad data with 0x0?
            int fbpp = (int)Math.Ceiling((double)(data.Length / 16)) + 1;
            var output = new byte[fbpp * readCount];

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

            #if ARC_DEBUG
            PrintArray(data, "Incoming data");

            c.WriteLine($"Data size: {data.Length} | Total FB: {(int)Math.Ceiling((double)(data.Length / 16))}");
            #endif
            byte[]? prevCtx = null;
            byte[] mf;
            

            #region major compute loop

            int computationIteration = 0;
            bool computeFlag = true;

            while (computeFlag)
            {
                #region context block read and setup

                // get next block

                var ctx = GetBlock(data, computationIteration, ref computeFlag); // auto pads with 0x0? i dont think i told it to do that

                if (!computeFlag && Enumerable.SequenceEqual(ctx, extreneous))
                    break;
                #if ARC_DEBUG
                PrintArray(ctx, $"CTX for round {computationIteration} | Length: {ctx.Length}");
                #endif
                // get keys
                var keys = Schedule(key, iv, computationIteration);
                //for (int i = 0; i < keys.Length; i++)
                //    PrintArray(keys[i], $"Scheduled key {i + 1}");

                #endregion

                // get MF results
                mf = ARCMF(prevCtx ?? iv, keys, computationIteration); // at CI 0, prevCtx is null, so it defaults to iv like its supposed to...

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
        #pragma warning disable IDE0003

        // ok so decryption is just encryption but with an added step of removing extraneous bytes

        /// <summary>
        /// TODO: comments
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public byte[] Decrypt() { return REMED(InternalEncrypt(this.Data ?? throw new ArgumentNullException(dEx), this.Key ?? throw new ArgumentNullException(nameof(Key), kEx), this.IV ??= GenerateIV())); }

        /// <summary>
        /// TODO: comments
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public byte[] Decrypt(string message) 
        { return REMED(InternalEncrypt(S2B(message), this.Key ?? throw new ArgumentNullException(nameof(Key), kEx), this.IV ??= GenerateIV())); }

        /// <summary>
        /// TODO: comments
        /// </summary>
        /// <param name="message"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public byte[] Decrypt(string message, byte[]? key = null, byte[]? iv = null)
        { return REMED(InternalEncrypt(S2B(message), key ?? this.Key ?? throw new ArgumentException(kEx), iv ?? (this.IV ??= GenerateIV()))); }

        /// <summary>
        /// TODO: comments
        /// </summary>
        /// <param name="message"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public byte[] Decrypt(string message, string? key = null, string? iv = null)
        {
            byte[] _key = new byte[16], _iv = new byte[16];
            if (key is not null)
            {
                Array.Copy(BlockComp(16, Encoding.ASCII.GetBytes(key)), 0, _key, 0, 16);
                this.Key = _key;
            }
            if (iv is not null)
            {
                Array.Copy(BlockComp(16, Encoding.ASCII.GetBytes(iv)), 0, _iv, 0, 16);
                this.IV = _iv;
            }
            return Decrypt(message);
        }

        /// <summary>
        /// TODO: comments
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public byte[] Decrypt(byte[] data)
        { return REMED(InternalEncrypt(data, this.Key ?? throw new ArgumentNullException(nameof(Key), kEx), this.IV ??= GenerateIV())); }

        public byte[] Decrypt(byte[] data, byte[]? key = null, byte[]? iv = null)
        { return REMED(InternalEncrypt(data, key ?? this.Key ?? throw new ArgumentNullException(nameof(Key), kEx), iv ?? (this.IV ??= GenerateIV()))); }

        /// <summary>
        /// Remove extraneous data.
        /// </summary>
        private byte[] REMED(in byte[] uData)
        {
            if (removeExtraneousData)
            {
                int count = uData.Length;
                byte[] o;
                for (int i = uData.Length - 1; i >= 0; i--)
                    if (uData[i] == 0x0)
                        count--;
                    else
                        break;
                o = new byte[count];
                Array.Copy(uData, o, count);

                return o;
            }
            else
                return uData;
        }

        #pragma warning restore IDE0003
        #endregion

        #region generators

        public static byte[] GenerateIV()
        {
            byte[] iv;
            using (var random = RandomNumberGenerator.Create()) {
                iv = new byte[16];
                random.GetBytes(iv);
            }
            return iv;
        }

        public static byte[] GenerateKey() => GenerateIV();

        #endregion

        #region methods and funcs

        /// <summary>
        /// Main Function
        /// </summary>
        /// <param name="state">Initial state, is either the IV or the previous contextual block.</param>
        /// <param name="keys"></param>
        /// <returns></returns>
        private static byte[] ARCMF(in byte[] state, in byte[][] keys, int ci)
        {
            var output = new byte[state.Length];
            state.CopyTo(output, 0);
            for (int i = 0; i < 9; i++)
            {
                ARCLT.Permutate(ref output, ARCLT.MBLTv1, i);
                //output = BlockRaise(output, ci);
                ARCBMGR(ref output);
                ARCLT.Permutate(ref output, ARCLT.SBLTv1, i);
                output = OTPArray(output, keys[i]);
            }
            #if ARC_DEBUG
            PrintArray(output, "MF Results");
            #endif
            return output; 
        }

        /// <summary>
        /// Byte Merry Go Round
        /// </summary>
        /// <param name="a"></param>
        private static void ARCBMGR(ref byte[] a)
        {
            var b = new byte[a.Length];
            Array.Copy(a, 0, b, 0, a.Length);
            a[0] = b[1];
            a[1] = b[2];
            a[2] = b[3];
            a[3] = b[7];
            a[4] = b[0];
            a[5] = b[9];
            a[6] = b[5];
            a[7] = b[11];
            a[8] = b[4];
            a[9] = b[10];
            a[10] = b[6];
            a[11] = b[15];
            a[12] = b[8];
            a[13] = b[12];
            a[14] = b[13];
            a[15] = b[14];
        }

        private static byte[] BlockRaise(byte[] a, int ci)
        {
            var result = new byte[a.Length];
            int mod = ci * 8723 % 1109;
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(EBSMK(a[i], (i + 1 >= a.Length) ? a[i - 1] : a[i + 1], (mod == 0) ? 101 : mod) % 255);
            return result;
        }

        #region Keygen stuff

        /// <summary>
        /// Key Scheduler.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <param name="iv">Initialization Vector.</param>
        /// <param name="ci">Computation Iteration.</param>
        /// <returns></returns>
        private byte[][] Schedule(in byte[] key, in byte[] iv, int ci)
        {
            var schedule = new byte[9][];
            byte[]? prevCtx = null;
            schedule[0] = key;
            for (int i = 1; i <= 8; i++)
            {
                /// key scheduling must use: 
                /// KSRcon# (Key Scheduling Round Constant)
                /// CI (Computation Iteration)
                /// 2 unique? functions, 
                /// here ill use 1 byte left rotation like AES
                /// and a new function Key Scheduling Column Rotator, 
                /// which from here on out i will call KSRC(). They will
                /// be called in reverse respective order.
                /// The sutucture is as follows:
                /// The inverted IV gets otped with the first key, which is, also key 0
                /// and gets thrown in KSRC() thru ci % 4 iterations. Then <<< 1.
                /// After that, the whole scheduled pre-key gets tossed into an irreversible lookup table.

                schedule[i] = OTPArray(prevCtx ?? ReverseArray(iv), key);
                KSCR(ref schedule[i], ci % 4);
                schedule[i] = RotLeft(schedule[i], 1);
                ARCLT.Permutate(ref schedule[i], ARCLT.KSLTv1, ci * KSRcon[i]);
                prevCtx = schedule[i];
            }
            return schedule;
        }

        /// <summary>
        /// Key Schedule Column Rotator.
        /// </summary>
        /// <param name="sk">Subkey.</param>
        /// <param name="c">Count.</param>
        private static void KSCR(ref byte[] sk, int c)
        {
            var skc = new byte[sk.Length];
            for (var i = 1; i <= c; i++)
            {
                Array.Copy(sk, 0, skc, 0, sk.Length);
                sk[0] = skc[9];
                sk[1] = skc[10];
                sk[2] = skc[3];
                sk[3] = skc[12];
                sk[4] = skc[14];
                sk[5] = skc[7];
                sk[6] = skc[0];
                sk[7] = skc[13];
                sk[8] = skc[11];
                sk[9] = skc[4];
                sk[10] = skc[1];
                sk[11] = skc[2];
                sk[12] = skc[8];
                sk[13] = skc[5];
                sk[14] = skc[6];
                sk[15] = skc[15];
            }
        }

        #endregion

        private static byte[] GetBlock(byte[] data, int ci, ref bool computeFlag)
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

        /// <summary>
        /// Block Compressor.
        /// </summary>
        /// <param name="s">Size. (Must be non-zero)</param>
        /// <param name="a">Block.</param>
        /// <returns></returns>
        private static byte[] BlockComp(int s, byte[] a)
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
                    if (!s1fo)
                        o = OTPArray(o, sb);
                    else
                        s1fo = false;
            }
            return o;
        }

        private static byte[] S2B(string a) // String 2 Byte
        { return Encoding.ASCII.GetBytes(a); }

        #region Array Funcs

        private static byte[] ReverseArray(in byte[] a) // for some reason this is modifying a
        {
            var o = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                o[a.Length - 1 - i] = a[i];
            return o;
        }

        /// <summary>
        /// Fast Copy array.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="s"></param>
        /// <param name="c"></param>
        /// <returns></returns>
        private static byte[] FCArray(byte[] input, int s, int c)
        {
            byte[] result = new byte[c];
            Array.Copy(input, s, result, 0, c);
            return result;
        }

        private static byte[] AddArray(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            a.CopyTo(result, 0);
            b.CopyTo(result, a.Length);
            return result;
        }

        /// <summary>
        /// One Time Pad Array.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private static byte[] OTPArray(byte[] input, byte[] key)
        {
            byte[] result = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                result[i] = (byte)(input[i] ^ key[i]);
            return result;
        }

        internal static void PrintArray(byte[] array, string name = "")
        {
            if (name != "")
                Console.Write($"{name}: ");
            foreach (byte byt in array)
                Console.Write(byt.ToString("X"));
            Console.WriteLine();
        }

        private static byte[] CreatePadArray(byte b, int c)
        {
            byte[] result = new byte[c];
            for (int i = 0; i < c; i++)
                result[i] = b;
            return result;
        }

        private static byte[] RotLeft(byte[] a, int amount)
        { return a.Skip(amount).Concat(a.Take(amount)).ToArray(); }

        #endregion

        #region other functions

        /// <summary>
        /// Exponentation By Squaring Mod K
        /// </summary>
        public static int EBSMK(int x, int n, int k)
        {
            int res = 1;
            x %= k;
            if (x == 0)
                return 0;
            while (n > 0)
            {
                if ((n & 1) != 0)
                    res = res * x % k;
                n >>= 1;
                x = x * x % k;
            }
            return res;
        }

        #endregion

        #endregion
    }
}
