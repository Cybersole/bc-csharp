using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Crypto.Hpke
{
    public class HPKEContext
    {
        public readonly AEAD aead;
        public readonly HKDF hkdf;
        public readonly byte[] exporterSecret;
        public readonly byte[] suiteId;

        public HPKEContext(AEAD aead, HKDF hkdf, byte[] exporterSecret, byte[] suiteId)
        {
            this.aead = aead;
            this.hkdf = hkdf;
            this.exporterSecret = exporterSecret;
            this.suiteId = suiteId;
        }

        public virtual byte[] Export(byte[] exportContext, int L)
        {
            return hkdf.LabeledExpand(exporterSecret, suiteId, "sec", exportContext, L);
        }

        public virtual byte[] Seal(byte[] aad, byte[] message)
        {
            return aead.Seal(aad, message);
        }

        public virtual byte[] Seal(byte[] aad, byte[] pt, int ptOffset, int ptLength)
        {
            return aead.Seal(aad, pt, ptOffset, ptLength);
        }

        public virtual byte[] Open(byte[] aad, byte[] ct)
        {
            return aead.Open(aad, ct);
        }

        public virtual byte[] Open(byte[] aad, byte[] ct, int ctOffset, int ctLength)
        {
            return aead.Open(aad, ct, ctOffset, ctLength);
        }

        public virtual byte[] Extract(byte[] salt, byte[] ikm)
        {
            return hkdf.Extract(salt, ikm);
        }

        public virtual byte[] Expand(byte[] prk, byte[] info, int L)
        {
            return hkdf.Expand(prk, info, L);
        }
    }
}