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
            var p = GeneratePrime(129);
            var q = GeneratePrime(129);
            var n = p * q; // n.GetByteCount() == p.GetByteCount() + q.GetByteCount(); usually...

            var nTotient = TotientOfProduct(p, q);

            BigInteger e = 65537;
            (_, BigInteger d, _) = ExtendedEuclideanAlgorithm(e, nTotient);

            //var plainIntBefore = TextToBigInt("Hello");
            var plainIntBefore = TextToBigInt("ABCDEFGHIJKLMNOPQRSTUVWXYZ");

            var cypherInt = BigInteger.ModPow(plainIntBefore, e, n); // encrypts using public key
            var plainIntAfter = BigInteger.ModPow(cypherInt, d, n); // decrypts using private key
            var plainText = BigIntToText(plainIntAfter);

            Console.WriteLine(plainText);
        }

        private static BigInteger TextToBigInt(string inText)
        {
            var myBytes = Encoding.UTF8.GetBytes(inText);
            return new BigInteger(myBytes);
        }

        private static string BigIntToText(BigInteger inBigInt)
        {
            var myBytes = inBigInt.ToByteArray();
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
            var bytes = new byte[candidate.GetByteCount()];

            var rng = new Random();

            for (int i = 0; i < numRounds; i++)
            {
                BigInteger a;
                do // find random integer a in range [2, candidate - 2]
                {
                    rng.NextBytes(bytes);
                    a = new BigInteger(bytes);
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
            // We must include space for an additional byte (0x00) at the end
            //  of the array so that the generated BigInteger is positive
            var inArr = new byte[numBytes];

            var rng = new Random();
            BigInteger a;
            do
            {
                rng.NextBytes(inArr);

                inArr[0] |= 0x01; // guarantees an odd value
                inArr[^2] |= 0x80; // guarantees the most significant bit is always set to 1
                inArr[^1] = 0x00; // guarantees a positive value; without this, the value would always be negative

                a = new BigInteger(inArr);
            } while (!IsPrime(a, 100));

            return a;
        }
    }
}
