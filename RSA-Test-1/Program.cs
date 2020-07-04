using System;
using System.Collections;
using System.Linq;
using System.Numerics;
using System.Text;

namespace RSA_Test_1
{
    class Program
    {
        static void Main(string[] args)
        {
            var p = GeneratePrime(128);
            var q = GeneratePrime(128);
            var n = p * q;

            var lambdaN = TotientOfProduct(p, q);

            BigInteger e = 65537;
            (_, BigInteger d, _) = ExtendedEuclideanAlgorithm(e, lambdaN);

            //var plainIntBefore = TextToBigInt("Hello");
            var m = TextToBigInt("ABCDEFGHIJKLMNOPQRSTUVWXYZ÷");

            var c = RsaEncrypt(n, e, m); // encrypts using public key
            var plainIntAfter = RsaDecrypt(n, d, c); // decrypts using private key
            var plainText = BigIntToText(plainIntAfter);

            Console.WriteLine(plainText);
        }

        private static BigInteger TextToBigInt(string inText)
        {
            var myBytes = Encoding.UTF8.GetBytes(inText);
            return BytesToBigInt(myBytes);
        }

        private static string BigIntToText(BigInteger inBigInt)
        {
            var myBytes = BigIntToBytes(inBigInt);
            return Encoding.UTF8.GetString(myBytes);
        }

        // Calculates the totient of p*q, i.e. the totient of n
        private static BigInteger TotientOfProduct(BigInteger p, BigInteger q)
        {
            BigInteger pMinus1 = p - 1;
            BigInteger qMinus1 = q - 1;

            BigInteger lcm = (pMinus1 * qMinus1) / BigInteger.GreatestCommonDivisor(pMinus1, qMinus1);

            return lcm; // due to magic properties of p and q, the lcm as generated above is also the totient of n
        }

        private static (BigInteger, BigInteger, BigInteger) ExtendedEuclideanAlgorithm(BigInteger e, BigInteger nTotient)
        {
            BigInteger rOld = nTotient;
            BigInteger rNew = e;

            BigInteger dOld = 0;
            BigInteger dNew = 1;

            BigInteger tOld = 1;
            BigInteger tNew = 0;

            while(rNew > 0)
            {
                var a = BigInteger.Divide(rOld, rNew);

                var tempR = rOld - a * rNew;
                rOld = rNew;
                rNew = tempR;

                var tempD = dOld - a * dNew;
                dOld = dNew;
                dNew = tempD;

                var tempT = tOld - a * tNew;
                tOld = tNew;
                tNew = tempT;
            }

            BigInteger outD = dOld % nTotient;
            
            if(outD < 0)
            {
                outD += nTotient;
            }

            BigInteger outT = tOld % nTotient;

            if (outT < 0)
            {
                outT += nTotient;
            }

            return (rOld, outD, outT);
        }

        // Implementation of Miller-Rabin prime probability test
        private static bool IsPrime(BigInteger candidate, int numRounds)
        {
            var bytes = new byte[BigIntByteCount(candidate)];

            var rng = new Random();

            for (int i = 0; i < numRounds; i++)
            {
                BigInteger a;
                do // find random integer a in range [2, candidate - 2]
                {
                    rng.NextBytes(bytes);
                    a = BytesToBigInt(bytes);
                } while (a > candidate - 2 || a < 2);

                (int r, BigInteger d) = DecomposeCandidate(candidate);

                var x = BigInteger.ModPow(a, d, candidate);

                if (x == 1 || x == candidate - 1)
                    continue;

                bool continueFlag = false;
                for (int j = 0; j < r - 1; j++)
                {
                    x = BigInteger.ModPow(x, 2, candidate);

                    if (x == candidate - 1)
                    {
                        continueFlag = true;
                        break;
                    }
                }

                if (continueFlag)
                    continue;

                return false;
            }

            return true;
        }

        // decomposes a candidate prime into the format (2^r)*d + 1, returning r and d as a tuple
        private static (int, BigInteger) DecomposeCandidate(BigInteger candidate)
        {
            int r = 0;
            BigInteger d = candidate - 1;

            BigInteger rem = 0;

            while(rem == 0)
            {
                var tempQ = BigInteger.DivRem(d, 2, out BigInteger innerRem);
                rem = innerRem;

                if(rem == 0)
                {
                    r++;
                    d = tempQ;
                }
            }

            return (r, d);
        }

        private static BigInteger GeneratePrime(int numBytes)
        {
            var inArr = new byte[numBytes]; // includes space for a final null-byte

            var rng = new Random();
            BigInteger a;
            do
            {
                rng.NextBytes(inArr);

                inArr[0] |= 0x01; // guarantees an odd value; the uniformity of the distribution is unchanged
                inArr[^2] |= 0x80; // guarantees the most significant bit is always set to 1

                a = BytesToBigInt(inArr);
            } while (!IsPrime(a, 100));

            return a;
        }

        // outputs ciphertext representative c
        private static BigInteger RsaEncrypt(BigInteger n, BigInteger e, BigInteger m)
        {
            if (m < 0 || m > n - 1)
                throw new Exception("message representative out of range");

            return BigInteger.ModPow(m, e, n);
        }

        // outputs message representative m
        // RsaDecrypt currently does not support (p, q, dP, dQ, qInv), {(r_i, d_i, t_i), i = 3, ..., u} format
        private static BigInteger RsaDecrypt(BigInteger n, BigInteger d, BigInteger c)
        {
            if (c < 0 || c > n - 1)
                throw new Exception("ciphertext representative out of range");

            return BigInteger.ModPow(c, d, n);
        }

        // fills the role of RFC8017's I2OSP (integer to octet stream primitive); little-endian
        private static byte[] BigIntToBytes(BigInteger x, int? xLen = null)
        {
            var byteArr = x.ToByteArray();
            
            if(byteArr[^1] == 0x00) // if the most-significant-byte is a null byte
            {
                byteArr = byteArr.Take(byteArr.Length - 1).ToArray(); // remove the null byte from the array
            }

            if(xLen.HasValue)
            {
                if (byteArr.Length > xLen)
                {
                    throw new Exception("integer too large");
                }
                else if (byteArr.Length < xLen)
                {
                    byteArr = byteArr.Concat(new byte[xLen.Value - byteArr.Length]).ToArray();
                }
            }

            return byteArr;
        }

        // fills the role of RFC8017's OS2IP (octet stream to integer primitive); little-endian
        private static BigInteger BytesToBigInt(byte[] x)
        {
            if(x[^1] >= 0x80) // if the most-significant-bit is 1
            {
                x = x.Concat(new byte[] { 0x00 }).ToArray(); // add a null byte to the array
            }

            return new BigInteger(x);
        }

        private static int BigIntByteCount(BigInteger x)
        {
            var bytes = x.ToByteArray();
            var byteCount = bytes.Length;

            if (bytes[^1] == 0x00) // if the most-significant-byte is a null byte
            {
                byteCount -= 1;
            }

            return byteCount;
        }
    }
}
