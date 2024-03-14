using Org.BouncyCastle.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using System.Text;
using System;

namespace Org.BouncyCastle.Crypto.Hpke
{
    public class HKDF
    {
        private static readonly string versionLabel = "HPKE-v1";
        private readonly HkdfBytesGenerator kdf;
        private readonly int hashLength;

        public HKDF(short kdfId)
        {
            IDigest hash;
            switch (kdfId)
            {
                case HPKE.kdf_HKDF_SHA256:
                    hash = new Sha256Digest();
                    break;
                case HPKE.kdf_HKDF_SHA384:
                    hash = new Sha384Digest();
                    break;
                case HPKE.kdf_HKDF_SHA512:
                    hash = new Sha512Digest();
                    break;
                default:
                    throw new ArgumentException("invalid kdf id");
            }

            kdf = new HkdfBytesGenerator(hash);
            hashLength = hash.GetDigestSize();
        }

        public virtual int GetHashSize()
        {
            return hashLength;
        }

        // todo remove suiteID
        public virtual byte[] LabeledExtract(byte[] salt, byte[] suiteID, string label, byte[] ikm)
        {
            if (salt == null)
            {
                salt = new byte[hashLength];
            }

            byte[] labeledIKM = Arrays.ConcatenateAll(Encoding.UTF8.GetBytes(versionLabel), suiteID, Encoding.UTF8.GetBytes(label), ikm);
            return kdf.Extract(salt, labeledIKM).GetKey();
        }

        public virtual byte[] LabeledExpand(byte[] prk, byte[] suiteID, string label, byte[] info, int L)
        {
            if (L > (1 << 16))
            {
                throw new ArgumentException("Expand length cannot be larger than 2^16");
            }

            byte[] labeledInfo = Arrays.ConcatenateAll(Pack.ShortToBigEndian((short)L), Encoding.UTF8.GetBytes(versionLabel), suiteID, Encoding.UTF8.GetBytes(label));
            kdf.Init(HkdfParameters.SkipExtractParameters(prk, Arrays.Concatenate(labeledInfo, info)));
            byte[] rv = new byte[L];
            kdf.GenerateBytes(rv, 0, rv.Length);
            return rv;
        }

        public virtual byte[] Extract(byte[] salt, byte[] ikm)
        {
            if (salt == null)
            {
                salt = new byte[hashLength];
            }

            return kdf.Extract(salt, ikm).GetKey();
        }

        public virtual byte[] Expand(byte[] prk, byte[] info, int L)
        {
            if (L > (1 << 16))
            {
                throw new ArgumentException("Expand length cannot be larger than 2^16");
            }

            kdf.Init(HkdfParameters.SkipExtractParameters(prk, info));
            byte[] rv = new byte[L];
            kdf.GenerateBytes(rv, 0, rv.Length);
            return rv;
        }
    }
}