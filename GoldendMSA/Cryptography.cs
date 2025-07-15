using GoldendMSA;
using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    public class MD4 : HashAlgorithm
    {
        private uint[] _state = new uint[4];
        private byte[] _buffer = new byte[64];
        private int _bufferLength;
        private long _totalLength;

        public MD4()
        {
            Initialize();
        }

        public override void Initialize()
        {
            _state[0] = 0x67452301;
            _state[1] = 0xEFCDAB89;
            _state[2] = 0x98BADCFE;
            _state[3] = 0x10325476;
            _bufferLength = 0;
            _totalLength = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _totalLength += cbSize;

            while (cbSize > 0)
            {
                int bytesToCopy = Math.Min(cbSize, 64 - _bufferLength);
                Array.Copy(array, ibStart, _buffer, _bufferLength, bytesToCopy);

                _bufferLength += bytesToCopy;
                ibStart += bytesToCopy;
                cbSize -= bytesToCopy;

                if (_bufferLength == 64)
                {
                    ProcessBlock(_buffer);
                    _bufferLength = 0;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            _buffer[_bufferLength] = 0x80;
            _bufferLength++;

            if (_bufferLength > 56)
            {
                while (_bufferLength < 64)
                {
                    _buffer[_bufferLength] = 0;
                    _bufferLength++;
                }
                ProcessBlock(_buffer);
                _bufferLength = 0;
            }

            while (_bufferLength < 56)
            {
                _buffer[_bufferLength] = 0;
                _bufferLength++;
            }

            long bitLength = _totalLength * 8;
            for (int i = 0; i < 8; i++)
            {
                _buffer[56 + i] = (byte)(bitLength >> (i * 8));
            }

            ProcessBlock(_buffer);

            byte[] result = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                result[i * 4] = (byte)(_state[i]);
                result[i * 4 + 1] = (byte)(_state[i] >> 8);
                result[i * 4 + 2] = (byte)(_state[i] >> 16);
                result[i * 4 + 3] = (byte)(_state[i] >> 24);
            }

            return result;
        }

        private void ProcessBlock(byte[] block)
        {
            uint[] x = new uint[16];
            for (int i = 0; i < 16; i++)
            {
                x[i] = (uint)(block[i * 4] | (block[i * 4 + 1] << 8) |
                              (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24));
            }

            uint a = _state[0], b = _state[1], c = _state[2], d = _state[3];

            a = FF(a, b, c, d, x[0], 3); d = FF(d, a, b, c, x[1], 7);
            c = FF(c, d, a, b, x[2], 11); b = FF(b, c, d, a, x[3], 19);
            a = FF(a, b, c, d, x[4], 3); d = FF(d, a, b, c, x[5], 7);
            c = FF(c, d, a, b, x[6], 11); b = FF(b, c, d, a, x[7], 19);
            a = FF(a, b, c, d, x[8], 3); d = FF(d, a, b, c, x[9], 7);
            c = FF(c, d, a, b, x[10], 11); b = FF(b, c, d, a, x[11], 19);
            a = FF(a, b, c, d, x[12], 3); d = FF(d, a, b, c, x[13], 7);
            c = FF(c, d, a, b, x[14], 11); b = FF(b, c, d, a, x[15], 19);

            // Round 2
            a = GG(a, b, c, d, x[0], 3); d = GG(d, a, b, c, x[4], 5);
            c = GG(c, d, a, b, x[8], 9); b = GG(b, c, d, a, x[12], 13);
            a = GG(a, b, c, d, x[1], 3); d = GG(d, a, b, c, x[5], 5);
            c = GG(c, d, a, b, x[9], 9); b = GG(b, c, d, a, x[13], 13);
            a = GG(a, b, c, d, x[2], 3); d = GG(d, a, b, c, x[6], 5);
            c = GG(c, d, a, b, x[10], 9); b = GG(b, c, d, a, x[14], 13);
            a = GG(a, b, c, d, x[3], 3); d = GG(d, a, b, c, x[7], 5);
            c = GG(c, d, a, b, x[11], 9); b = GG(b, c, d, a, x[15], 13);

            a = HH(a, b, c, d, x[0], 3); d = HH(d, a, b, c, x[8], 9);
            c = HH(c, d, a, b, x[4], 11); b = HH(b, c, d, a, x[12], 15);
            a = HH(a, b, c, d, x[2], 3); d = HH(d, a, b, c, x[10], 9);
            c = HH(c, d, a, b, x[6], 11); b = HH(b, c, d, a, x[14], 15);
            a = HH(a, b, c, d, x[1], 3); d = HH(d, a, b, c, x[9], 9);
            c = HH(c, d, a, b, x[5], 11); b = HH(b, c, d, a, x[13], 15);
            a = HH(a, b, c, d, x[3], 3); d = HH(d, a, b, c, x[11], 9);
            c = HH(c, d, a, b, x[7], 11); b = HH(b, c, d, a, x[15], 15);

            _state[0] += a;
            _state[1] += b;
            _state[2] += c;
            _state[3] += d;
        }

        private static uint FF(uint a, uint b, uint c, uint d, uint x, int s)
        {
            return RotateLeft(a + F(b, c, d) + x, s);
        }

        private static uint GG(uint a, uint b, uint c, uint d, uint x, int s)
        {
            return RotateLeft(a + G(b, c, d) + x + 0x5A827999, s);
        }

        private static uint HH(uint a, uint b, uint c, uint d, uint x, int s)
        {
            return RotateLeft(a + H(b, c, d) + x + 0x6ED9EBA1, s);
        }

        private static uint F(uint x, uint y, uint z)
        {
            return (x & y) | (~x & z);
        }

        private static uint G(uint x, uint y, uint z)
        {
            return (x & y) | (x & z) | (y & z);
        }

        private static uint H(uint x, uint y, uint z)
        {
            return x ^ y ^ z;
        }

        private static uint RotateLeft(uint value, int shift)
        {
            return (value << shift) | (value >> (32 - shift));
        }
    }

    public class AES256
    {
        private const int AES128_SEEDSIZE = 16;
        private const int AES128_KEYSIZE = 16;
        private const int AES256_SEEDSIZE = 32;
        private const int AES256_KEYSIZE = 32;
        private const int BLOCKSIZE = 16;
        private const int DEFAULT_ITERATIONS = 4096;

        public byte[] StringToKeyAES256(byte[] password, string salt, byte[] parameters = null)
        {
            return StringToKey(password, salt, AES256_SEEDSIZE, AES256_KEYSIZE, parameters);
        }

        public byte[] StringToKeyAES128(byte[] password, string salt, byte[] parameters = null)
        {
            return StringToKey(password, salt, AES128_SEEDSIZE, AES128_KEYSIZE, parameters);
        }

        private byte[] StringToKey(byte[] password, string salt, int seedSize, int keySize, byte[] parameters = null)
        {
            int iterations = DEFAULT_ITERATIONS;
            if (parameters != null && parameters.Length >= 4)
            {
                iterations = BitConverter.ToInt32(parameters, 0);
                if (BitConverter.IsLittleEndian)
                {
                    iterations = ((iterations & 0xFF) << 24) |
                               (((iterations >> 8) & 0xFF) << 16) |
                               (((iterations >> 16) & 0xFF) << 8) |
                               ((iterations >> 24) & 0xFF);
                }
            }

            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            byte[] seed;
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, iterations, HashAlgorithmName.SHA1))
            {
                seed = pbkdf2.GetBytes(seedSize);
            }

            byte[] tempKey = new byte[keySize];
            Array.Copy(seed, tempKey, keySize);

            byte[] kerberosConstant = Encoding.UTF8.GetBytes("kerberos");
            byte[] finalKey = Derive(tempKey, kerberosConstant, seedSize, keySize);

            return finalKey;
        }

        private byte[] Derive(byte[] key, byte[] constant, int seedSize, int keySize)
        {
            byte[] plaintext = NFold(constant, BLOCKSIZE);

            byte[] rndseed = new byte[0];
            while (rndseed.Length < seedSize)
            {
                byte[] ciphertext = BasicEncrypt(key, plaintext);
                byte[] newRndseed = new byte[rndseed.Length + ciphertext.Length];
                Array.Copy(rndseed, newRndseed, rndseed.Length);
                Array.Copy(ciphertext, 0, newRndseed, rndseed.Length, ciphertext.Length);
                rndseed = newRndseed;
                plaintext = ciphertext;
            }

            byte[] finalKey = new byte[keySize];
            Array.Copy(rndseed, finalKey, keySize);
            return finalKey;
        }

        private byte[] BasicEncrypt(byte[] key, byte[] plaintext)
        {
            int paddedLength = ((plaintext.Length + 15) / 16) * 16;
            byte[] paddedPlaintext = new byte[paddedLength];
            Array.Copy(plaintext, paddedPlaintext, plaintext.Length);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = new byte[16];
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(paddedPlaintext, 0, paddedPlaintext.Length);
                }
            }
        }
        private  byte[] NFold(byte[] input, int nbytes)
        {
            int inputLen = input.Length;
            int lcm = Lcm(nbytes, inputLen);

            byte[] bigstr = new byte[lcm];
            for (int i = 0; i < lcm / inputLen; i++)
            {
                byte[] rotated = RotateRight(input, 13 * i);
                Array.Copy(rotated, 0, bigstr, i * inputLen, inputLen);
            }

            // Add slices together with ones' complement arithmetic
            byte[] result = new byte[nbytes];
            for (int i = 0; i < lcm; i += nbytes)
            {
                byte[] slice = new byte[nbytes];
                Array.Copy(bigstr, i, slice, 0, nbytes);
                result = AddOnesComplement(result, slice);
            }

            return result;
        }

        private byte[] RotateRight(byte[] data, int nbits)
        {
            byte[] result = new byte[data.Length];
            int nbytes = (nbits / 8) % data.Length;
            int remain = nbits % 8;

            for (int i = 0; i < data.Length; i++)
            {
                int sourceIndex = (i - nbytes + data.Length) % data.Length;
                int prevIndex = (sourceIndex - 1 + data.Length) % data.Length;

                result[i] = (byte)((data[sourceIndex] >> remain) |
                                  ((data[prevIndex] << (8 - remain)) & 0xFF));
            }

            return result;
        }

        private byte[] AddOnesComplement(byte[] a, byte[] b)
        {
            int[] result = new int[a.Length];

            for (int i = 0; i < a.Length; i++)
            {
                result[i] = a[i] + b[i];
            }

            bool hasCarry;
            do
            {
                hasCarry = false;
                for (int i = 0; i < result.Length; i++)
                {
                    if (result[i] > 0xFF)
                    {
                        hasCarry = true;
                        int nextIndex = (i + 1) % result.Length;
                        result[nextIndex] += result[i] >> 8;
                        result[i] &= 0xFF;
                    }
                }
            } while (hasCarry);

            byte[] final = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                final[i] = (byte)result[i];
            }

            return final;
        }

        private int Gcd(int a, int b)
        {
            while (b != 0)
            {
                int temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        private int Lcm(int a, int b)
        {
            return (a * b) / Gcd(a, b);
        }

    }

    public class CryptoActions
    {

        public static byte[] KerberosDecrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;


            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Decrypt pCSystemDecrypt = (Interop.KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Decrypt, typeof(Interop.KERB_ECRYPT_Decrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            status = pCSystemDecrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output.Take(outputSize).ToArray();
        }


        public static byte[] KerberosEncrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Encrypt pCSystemEncrypt = (Interop.KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Encrypt, typeof(Interop.KERB_ECRYPT_Encrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            status = pCSystemEncrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output;
        }

    }
}


