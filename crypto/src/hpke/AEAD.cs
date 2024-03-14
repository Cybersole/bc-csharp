using Org.BouncyCastle.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Hpke
{
    public class AEAD
    {
        private readonly short aeadId;
        private readonly byte[] key;
        private readonly byte[] baseNonce;
        private long seq = 0; // todo throw exception if overflow
        private IAeadCipher cipher;

        public AEAD(short aeadId, byte[] key, byte[] baseNonce)
        {
            this.key = key;
            this.baseNonce = baseNonce;
            this.aeadId = aeadId;
            seq = 0;

            switch (aeadId)
            {
                case HPKE.aead_AES_GCM128:
                case HPKE.aead_AES_GCM256:
                    cipher = new GcmBlockCipher(new AesEngine());
                    break;
                case HPKE.aead_CHACHA20_POLY1305:
                    cipher = new ChaCha20Poly1305();
                    break;
                case HPKE.aead_EXPORT_ONLY:
                    break;
            }
        }

        // used by Sender
        public virtual byte[] Seal(byte[] aad, byte[] pt, int ptOffset, int ptLength)
        {
            if (ptOffset < 0 || ptOffset > pt.Length)
            {
                throw new IndexOutOfRangeException("Invalid offset");
            }

            if (ptOffset + ptLength > pt.Length)
            {
                throw new IndexOutOfRangeException("Invalid length");
            }

            ICipherParameters param;

            switch (aeadId)
            {
                case HPKE.aead_AES_GCM128:
                case HPKE.aead_AES_GCM256:
                case HPKE.aead_CHACHA20_POLY1305:
                    param = new ParametersWithIV(new KeyParameter(key), ComputeNonce());
                    break;
                case HPKE.aead_EXPORT_ONLY:
                default:
                    throw new InvalidOperationException("Export only mode, cannot be used to seal/open");
            }

            cipher.Init(true, param);
            cipher.ProcessAadBytes(aad, 0, aad.Length);
            byte[] ct = new byte[cipher.GetOutputSize(ptLength)];
            int len = cipher.ProcessBytes(pt, ptOffset, ptLength, ct, 0);
            cipher.DoFinal(ct, len);
            seq++;

            return ct;
        }

        // used by Sender
        public virtual byte[] Seal(byte[] aad, byte[] pt)
        {
            return this.Seal(aad, pt, 0, pt.Length);
        }

        // used by Receiver
        public virtual byte[] Open(byte[] aad, byte[] ct, int ctOffset, int ctLength)
        {
            if (ctOffset < 0 || ctOffset > ct.Length)
            {
                throw new IndexOutOfRangeException("Invalid offset");
            }

            if (ctOffset + ctLength > ct.Length)
            {
                throw new IndexOutOfRangeException("Invalid length");
            }

            ICipherParameters param;

            switch (aeadId)
            {
                case HPKE.aead_AES_GCM128:
                case HPKE.aead_AES_GCM256:
                case HPKE.aead_CHACHA20_POLY1305:
                    param = new ParametersWithIV(new KeyParameter(key), ComputeNonce());
                    break;
                case HPKE.aead_EXPORT_ONLY:
                default:
                    throw new InvalidOperationException("Export only mode, cannot be used to seal/open");
            }

            cipher.Init(false, param);
            cipher.ProcessAadBytes(aad, 0, aad.Length);
            byte[] pt = new byte[cipher.GetOutputSize(ctLength)];
            int len = cipher.ProcessBytes(ct, ctOffset, ctLength, pt, 0);
            len += cipher.DoFinal(pt, len);
            seq++;
            return pt;
        }

        // used by Receiver
        public virtual byte[] Open(byte[] aad, byte[] ct)
        {
            return this.Open(aad, ct, 0, ct.Length);
        }

        private byte[] ComputeNonce()
        {
            byte[] seq_bytes = Pack.LongToBigEndian(seq);
            int Nn = baseNonce.Length;
            byte[] nonce = Arrays.Clone(baseNonce);

            //xor
            for (int i = 0; i < 8; i++)
            {
                nonce[Nn - 8 + i] ^= seq_bytes[i];
            }

            return nonce;
        }
    }
}